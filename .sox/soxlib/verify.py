"""Attestation verification with signer-identity pinning (evidence spec 2.4, decisions F4).

Order of checks for every bundle, all against the trust policy read from main:
  1. Parse the leaf certificate ourselves and check every Fulcio identity extension
     (issuer, repository URI and numeric ID, owner ID, signer workflow URI, source ref, runner,
     trigger, build config URI, SAN). Nothing in the predicate is consulted for identity.
  2. Cryptographic verification with `gh attestation verify --bundle`, constrained by the same
     identity (--repo, --cert-identity <exact SAN @refs/heads/main>, --source-ref, --cert-oidc-issuer,
     --deny-self-hosted-runners, --predicate-type). Its parsed certificate must agree with step 1
     and its verified statement must equal the payload we decoded.
  3. Subject keys are recomputed from their names; the Rekor time must exist and agree with
     the predicate's observedAt within the policy skew.
  4. Only then are predicate fields read, and binding to API-derived values is checked by callers.
Anything that fails 1-2 is a forgery-attempt. Nothing here trusts a predicate's own claims about
who signed it.
"""
import base64
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import tempfile

from . import der, subject as subj
from .policy import Policy

OID = {
    "issuer": "1.3.6.1.4.1.57264.1.8",
    "buildSignerURI": "1.3.6.1.4.1.57264.1.9",
    "runnerEnvironment": "1.3.6.1.4.1.57264.1.11",
    "sourceRepositoryURI": "1.3.6.1.4.1.57264.1.12",
    "sourceRepositoryDigest": "1.3.6.1.4.1.57264.1.13",
    "sourceRepositoryRef": "1.3.6.1.4.1.57264.1.14",
    "sourceRepositoryIdentifier": "1.3.6.1.4.1.57264.1.15",
    "sourceRepositoryOwnerIdentifier": "1.3.6.1.4.1.57264.1.17",
    "buildConfigURI": "1.3.6.1.4.1.57264.1.18",
    "buildTrigger": "1.3.6.1.4.1.57264.1.20",
    "runInvocationURI": "1.3.6.1.4.1.57264.1.21",
    "legacyTrigger": "1.3.6.1.4.1.57264.1.2",
    "legacyRef": "1.3.6.1.4.1.57264.1.6",
    "legacyIssuer": "1.3.6.1.4.1.57264.1.1",
}
SAN_OID = "2.5.29.17"
REQUIRED = ("issuer", "buildSignerURI", "runnerEnvironment", "sourceRepositoryURI",
            "sourceRepositoryRef", "sourceRepositoryIdentifier",
            "sourceRepositoryOwnerIdentifier", "buildConfigURI", "buildTrigger")


class Rejection(Exception):
    def __init__(self, reason, category="forgery-attempt", identity=None, statement=None,
                 digest=None, integrated_time=None):
        super().__init__(reason)
        self.reason = reason
        self.category = category
        self.identity = identity or {}
        self.statement = statement
        self.digest = digest
        self.integrated_time = integrated_time

    def to_json(self):
        st = self.statement or {}
        return {"category": self.category, "reason": self.reason, "digest": self.digest,
                "predicateType": st.get("predicateType"),
                "subjects": [s.get("name") for s in st.get("subject", []) if isinstance(s, dict)],
                "certificate": self.identity, "integratedTime": _iso(self.integrated_time)}


class VerifierUnavailable(RuntimeError):
    """The cryptographic verifier could not run. Callers must fail closed."""


class Attestation:
    def __init__(self, name, statement, digest, identity, integrated_time, bundle):
        self.name = name
        self.statement = statement
        self.predicate = statement.get("predicate") or {}
        self.digest = digest
        self.identity = identity
        self.integrated_time = integrated_time
        self.bundle = bundle

    @property
    def subjects(self):
        out = []
        for s in self.statement.get("subject", []):
            p = subj.parse_name(s.get("name"))
            if p:
                out.append(p)
        return out

    def has_subject(self, kind, ident):
        if kind == "image":
            want = str(ident).split(":", 1)[-1]
            return any(subj.parse_name(s.get("name")) is None
                       and (s.get("digest") or {}).get("sha256") == want
                       for s in self.statement.get("subject", []))
        return (kind, str(ident)) in self.subjects

    @property
    def time_iso(self):
        return _iso(self.integrated_time)

    def to_json(self):
        return {"predicate": self.name, "digest": self.digest, "integratedTime": self.time_iso,
                "signer": self.identity.get("buildSignerURI"),
                "trigger": self.identity.get("buildTrigger"),
                "run": self.identity.get("runInvocationURI"),
                "codeSha": self.identity.get("sourceRepositoryDigest")}


def _iso(epoch):
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(s):
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    t = dt.datetime.fromisoformat(s)
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t.timestamp()


def normalize_bundle(obj):
    """Accept a raw Sigstore bundle, an attestations-API record, or {'bundle': ...}."""
    if isinstance(obj, (bytes, str)):
        obj = json.loads(obj)
    if isinstance(obj, dict) and "bundle" in obj and isinstance(obj["bundle"], dict):
        obj = obj["bundle"]
    if not isinstance(obj, dict) or not str(obj.get("mediaType", "")).startswith(
            "application/vnd.dev.sigstore.bundle"):
        raise Rejection("not a Sigstore bundle", category="malformed")
    if "dsseEnvelope" not in obj:
        raise Rejection("bundle has no DSSE envelope", category="malformed")
    return obj


def leaf_certificate(bundle):
    vm = bundle.get("verificationMaterial") or {}
    if "certificate" in vm:
        raw = vm["certificate"].get("rawBytes")
    else:
        chain = (vm.get("x509CertificateChain") or {}).get("certificates") or []
        raw = chain[0].get("rawBytes") if chain else None
    if not raw:
        raise Rejection("bundle has no signing certificate", category="malformed")
    return base64.b64decode(raw)


def certificate_identity(cert_der):
    exts = der.certificate_extensions(cert_der)
    ident = {}
    for name, oid in OID.items():
        if oid in exts:
            ident[name] = der.fulcio_string(exts[oid], oid)
    ident["san"] = der.san_uris(exts[SAN_OID]) if SAN_OID in exts else []
    return ident


def decode_statement(bundle):
    env = bundle["dsseEnvelope"]
    if env.get("payloadType") != "application/vnd.in-toto+json":
        raise Rejection("DSSE payload is not an in-toto statement", category="malformed")
    payload = base64.b64decode(env["payload"])
    try:
        st = json.loads(payload)
    except ValueError:
        raise Rejection("DSSE payload is not JSON", category="malformed")
    if st.get("_type") != "https://in-toto.io/Statement/v1":
        raise Rejection("statement is not in-toto v1", category="malformed")
    return st, "sha256:" + hashlib.sha256(payload).hexdigest()


def check_identity(policy, name, ident):
    """Return the matching signer entry, or raise Rejection. Certificate data only."""
    spec = policy.predicate(name)
    d = policy.data
    missing = [k for k in REQUIRED if not ident.get(k)]
    if missing:
        raise Rejection(f"certificate lacks identity extensions {missing}", identity=ident)
    problems = []
    if ident["issuer"] != d["oidcIssuer"]:
        problems.append(f"issuer {ident['issuer']!r}")
    if ident["sourceRepositoryURI"] != d["repositoryUri"]:
        problems.append(f"repository {ident['sourceRepositoryURI']!r}")
    if ident["sourceRepositoryIdentifier"] != str(spec["repositoryId"]):
        problems.append(f"repository id {ident['sourceRepositoryIdentifier']!r}")
    if ident["sourceRepositoryOwnerIdentifier"] != str(d["ownerId"]):
        problems.append(f"owner id {ident['sourceRepositoryOwnerIdentifier']!r}")
    if ident["sourceRepositoryRef"] != spec["sourceRef"]:
        problems.append(f"source ref {ident['sourceRepositoryRef']!r} is not {spec['sourceRef']}")
    if ident["runnerEnvironment"] != d.get("runnerEnvironment", "github-hosted"):
        problems.append(f"runner {ident['runnerEnvironment']!r}")
    if "legacyTrigger" in ident and ident["legacyTrigger"] != ident["buildTrigger"]:
        problems.append("legacy and v2 trigger extensions disagree")
    if "legacyRef" in ident and ident["legacyRef"] != ident["sourceRepositoryRef"]:
        problems.append("legacy and v2 ref extensions disagree")
    signer = None
    for s in spec["signers"]:
        if ident["buildSignerURI"] == policy.signer_uri(s["workflow"]):
            signer = s
    if signer is None:
        problems.append(f"signer {ident['buildSignerURI']!r} is not pinned for {name}")
    else:
        if ident["buildConfigURI"] != ident["buildSignerURI"]:
            problems.append("build config URI differs from signer (reusable or nested workflow)")
        if ident["san"] != [ident["buildSignerURI"]]:
            problems.append(f"SAN {ident['san']!r} differs from signer URI")
        if ident["buildTrigger"] not in signer["allowedTriggers"]:
            problems.append(f"trigger {ident['buildTrigger']!r} not allowed for {name}")
    if problems:
        raise Rejection("certificate identity rejected: " + "; ".join(problems), identity=ident)
    return signer


def gh_binary():
    for cand in (os.environ.get("SOX_GH_BIN"), "/usr/bin/gh", shutil.which("gh")):
        if cand and os.path.exists(cand):
            return cand
    raise VerifierUnavailable("gh CLI not found; cannot verify signatures")


def gh_verify_args(policy, name, signer, subject_file, bundle_file):
    d = policy.data
    uri = policy.signer_uri(signer["workflow"])
    return ["attestation", "verify", subject_file, "--bundle", bundle_file,
            "--repo", d["repo"],
            # Exact SAN, which includes @refs/heads/main. gh treats --cert-identity and
            # --signer-workflow as mutually exclusive, and --signer-workflow alone does not pin
            # the ref, so --source-ref is passed as well.
            "--cert-identity", uri,
            "--source-ref", policy.predicate(name)["sourceRef"],
            "--cert-oidc-issuer", d["oidcIssuer"],
            "--deny-self-hosted-runners",
            "--predicate-type", policy.predicate_type(name),
            "--format", "json"]


def run_gh(args, timeout=120):
    env = {k: v for k, v in os.environ.items()
           if k not in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN")}
    env["GH_PROMPT_DISABLED"] = "1"
    env.setdefault("GH_CONFIG_DIR", os.path.join(tempfile.gettempdir(), "sox-gh-verify"))
    try:
        p = subprocess.run([gh_binary()] + args, capture_output=True, text=True,
                           timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise VerifierUnavailable("gh attestation verify timed out")
    return p.returncode, p.stdout, p.stderr


class Verifier:
    # Indirection so tests can replace the crypto step and prove the identity checks stand alone.
    gh_args = staticmethod(gh_verify_args)
    gh_run = staticmethod(run_gh)

    def __init__(self, policy):
        self.policy = policy
        self._cache = {}

    @classmethod
    def load(cls, path):
        return cls(Policy.load(path))

    def verify(self, raw, predicate=None, expect=None):
        """Verify one bundle. Returns an Attestation or raises Rejection / VerifierUnavailable.

        expect: iterable of (kind, id) subject bindings that must all be present.
        """
        bundle = normalize_bundle(raw)
        statement, digest = decode_statement(bundle)
        cached = self._cache.get(digest + json.dumps(bundle.get("verificationMaterial"),
                                                     sort_keys=True))
        if cached is None:
            cached = self._verify_uncached(bundle, statement, digest)
            self._cache[digest + json.dumps(bundle.get("verificationMaterial"),
                                            sort_keys=True)] = cached
        if isinstance(cached, Rejection):
            raise cached
        att = cached
        if predicate and att.name != predicate:
            raise Rejection(f"predicate {att.name} where {predicate} was expected",
                            category="binding-mismatch", identity=att.identity,
                            statement=statement, digest=digest)
        for kind, ident in expect or ():
            if not att.has_subject(kind, ident):
                raise Rejection(f"not bound to {kind}:{ident}", category="binding-mismatch",
                                identity=att.identity, statement=statement, digest=digest,
                                integrated_time=att.integrated_time)
        return att

    def _verify_uncached(self, bundle, statement, digest):
        policy = self.policy
        try:
            ptype = statement.get("predicateType")
            name = policy.predicate_types.get(ptype)
            ident = {}
            try:
                ident = certificate_identity(leaf_certificate(bundle))
            except der.DERError as e:
                raise Rejection(f"certificate unreadable: {e}", statement=statement, digest=digest)
            if name is None:
                raise Rejection(f"predicate type {ptype!r} is not in the trust policy",
                                identity=ident, statement=statement, digest=digest)
            try:
                signer = check_identity(policy, name, ident)
            except Rejection as r:
                r.statement, r.digest = statement, digest
                raise
            sox_subjects = []
            for s in statement.get("subject") or []:
                parsed = subj.parse_name(s.get("name"))
                if parsed is None:
                    continue
                try:
                    want = subj.key(policy.repo, *parsed)
                except ValueError as e:
                    raise Rejection(f"bad subject name {s.get('name')!r}: {e}",
                                    category="malformed", identity=ident, statement=statement,
                                    digest=digest)
                if (s.get("digest") or {}).get("sha256") != want:
                    raise Rejection(f"subject {s.get('name')} digest is not its derived key",
                                    category="malformed", identity=ident, statement=statement,
                                    digest=digest)
                sox_subjects.append(parsed)
            if not sox_subjects:
                raise Rejection("no sox:<kind>:<id> subject to verify against",
                                category="malformed", identity=ident, statement=statement,
                                digest=digest)
            with tempfile.TemporaryDirectory(prefix="soxv-") as tmp:
                sf = os.path.join(tmp, "subject")
                bf = os.path.join(tmp, "bundle.json")
                with open(sf, "wb") as f:
                    f.write(subj.preimage(policy.repo, *sox_subjects[0]))
                with open(bf, "w") as f:
                    json.dump(bundle, f)
                rc, out, err = self.gh_run(self.gh_args(policy, name, signer, sf, bf))
            if rc != 0:
                msg = (err or out).strip().splitlines()
                raise Rejection("signature/identity verification failed: " +
                                (msg[-1] if msg else f"exit {rc}"), identity=ident,
                                statement=statement, digest=digest)
            try:
                results = json.loads(out)
                vr = results[0]["verificationResult"]
            except (ValueError, KeyError, IndexError, TypeError):
                raise VerifierUnavailable("gh produced no verification result")
            gh_cert = (vr.get("signature") or {}).get("certificate") or {}
            for k in ("sourceRepositoryIdentifier", "sourceRepositoryOwnerIdentifier",
                      "sourceRepositoryRef", "buildSignerURI", "buildTrigger",
                      "runnerEnvironment", "issuer"):
                if str(gh_cert.get(k)) != str(ident.get(k)):
                    raise Rejection(f"certificate field {k} differs between verifiers",
                                    identity=ident, statement=statement, digest=digest)
            if vr.get("statement") != statement:
                raise Rejection("verified statement differs from the decoded payload",
                                identity=ident, statement=statement, digest=digest)
            times = [parse_time(t.get("timestamp")) for t in vr.get("verifiedTimestamps") or []
                     if t.get("timestamp")]
            if not times:
                raise Rejection("no verified transparency-log or TSA timestamp",
                                identity=ident, statement=statement, digest=digest)
            itime = min(times)
            pred = statement.get("predicate") or {}
            if not ptype.startswith("https://slsa.dev/"):
                if pred.get("repo") != policy.repo:
                    raise Rejection(f"predicate repo {pred.get('repo')!r} is not {policy.repo}",
                                    category="binding-mismatch", identity=ident,
                                    statement=statement, digest=digest, integrated_time=itime)
                obs = parse_time(pred.get("observedAt")) if pred.get("observedAt") else None
                if obs is None or abs(obs - itime) > policy.data.get("maxClockSkewSeconds", 300):
                    raise Rejection("observedAt missing or more than the allowed skew from the "
                                    "transparency-log time", category="stale", identity=ident,
                                    statement=statement, digest=digest, integrated_time=itime)
            return Attestation(name, statement, digest, ident, itime, bundle)
        except Rejection as r:
            return r

    # ---------- fetching from the attestations API ----------

    def fetch(self, api, kind, ident, predicate=None, workers=4):
        """All attestations for a subject key, split into (verified, rejected).

        Only verified ones may be used for decisions or loop counts. Rejected ones are reported.
        """
        key = subj.lookup_digest(self.policy.repo, kind, ident)
        path = f"/repos/{self.policy.repo}/attestations/sha256:{key}?per_page=100"
        if predicate:
            path += "&predicate_type=" + self.policy.predicate_type(predicate)
        records = api.paginate_attestations(path)
        verified, rejected = [], []

        def one(rec):
            try:
                return self.verify(rec, predicate=None, expect=[(kind, str(ident))])
            except Rejection as r:
                return r

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for res in ex.map(one, records):
                if isinstance(res, Attestation):
                    if predicate is None or res.name == predicate:
                        verified.append(res)
                else:
                    rejected.append(res)
        seen, uniq = set(), []
        for a in sorted(verified, key=lambda a: (a.integrated_time, a.digest)):
            if a.digest not in seen:
                seen.add(a.digest)
                uniq.append(a)
        return uniq, rejected

    def count_rounds(self, api, story_key, predicate="review-verdict",
                     outcome="changes_requested", since=None):
        verified, rejected = self.fetch(api, "jira", story_key, predicate)
        n = [a for a in verified if a.predicate.get("outcome") == outcome
             and (since is None or a.integrated_time > since)]
        return len(n), n, rejected
