"""Verifier tests against real Sigstore bundles. Run: python3 -m unittest discover -s .sox/tests -t .sox"""
import base64
import copy
import json
import os
import shutil
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SOX = os.path.dirname(HERE)
sys.path.insert(0, SOX)

from soxlib import der, subject as subj  # noqa: E402
from soxlib.policy import Policy, PolicyError  # noqa: E402
from soxlib.verify import (Attestation, Rejection, Verifier, certificate_identity, check_identity,  # noqa: E402
                           leaf_certificate, normalize_bundle, gh_verify_args)

POLICY = os.path.join(SOX, "trust-policy.yaml")
FORGERY = os.path.join(SOX, "testdata", "branch-minted-review-verdict.bundle.json")
GOOD = os.path.join(SOX, "testdata", "good-review-verdict.bundle.json")
PROBE = os.path.join(HERE, "fixtures", "probe-main-workflow-dispatch.bundle.json")
HAVE_GH = any(os.path.exists(p) for p in ("/usr/bin/gh",)) or shutil.which("gh")


def load(path):
    with open(path) as f:
        return json.load(f)


def probe_policy():
    """A policy that pins the (now removed) probe workflow, so a real main-signed bundle exists
    for positive crypto tests. The production loader refuses probe workflows."""
    d = json.loads(open(POLICY, "rb").read())
    d["predicates"] = {"platform-probe": {
        "repository": d["repo"], "repositoryId": d["repositoryId"], "sourceRef": "refs/heads/main",
        "signers": [{"workflow": ".github/workflows/sox-platform-probe.yml",
                     "allowedTriggers": ["workflow_dispatch"]}]}}

    class TestPolicy(Policy):
        FORBIDDEN_WORKFLOW_WORDS = ()
        SIGNER_WORKFLOWS = Policy.SIGNER_WORKFLOWS | {".github/workflows/sox-platform-probe.yml"}
    return TestPolicy(json.dumps(d).encode())


class FakeGh:
    """Stands in for gh and reports success for anything, to prove the identity checks do not
    depend on gh's flags."""
    def __init__(self, statement, ident):
        self.statement, self.ident, self.calls = statement, ident, []

    def __call__(self, args, timeout=120):
        self.calls.append(args)
        cert = {k: self.ident.get(k) for k in ("sourceRepositoryIdentifier",
                "sourceRepositoryOwnerIdentifier", "sourceRepositoryRef", "buildSignerURI",
                "buildTrigger", "runnerEnvironment", "issuer")}
        return 0, json.dumps([{"verificationResult": {"signature": {"certificate": cert},
                               "statement": self.statement,
                               "verifiedTimestamps": [{"type": "Tlog",
                                                       "timestamp": "2026-11-10T19:38:00Z"}]}}]), ""


class TestPolicyLoading(unittest.TestCase):
    def test_real_policy_pins_every_predicate(self):
        p = Policy.load(POLICY)
        for name, spec in p.data["predicates"].items():
            self.assertEqual(spec["sourceRef"], "refs/heads/main", name)
            self.assertEqual(spec["repositoryId"], 1453102476, name)
            for s in spec["signers"]:
                self.assertTrue(s["workflow"].startswith(".github/workflows/sox-"), name)
                self.assertNotIn("probe", s["workflow"])
                self.assertNotIn("pull_request", s["allowedTriggers"])
                self.assertNotIn("push", s["allowedTriggers"])

    def _mutated(self, fn):
        d = json.loads(open(POLICY, "rb").read())
        fn(d)
        return json.dumps(d).encode()

    def test_rejects_pull_request_trigger(self):
        raw = self._mutated(lambda d: d["predicates"]["review-verdict"]["signers"][0]
                            ["allowedTriggers"].append("pull_request"))
        with self.assertRaises(PolicyError):
            Policy(raw)

    def test_rejects_pull_request_target(self):
        raw = self._mutated(lambda d: d["predicates"]["human-approval"]["signers"][0]
                            ["allowedTriggers"].append("pull_request_target"))
        with self.assertRaises(PolicyError):
            Policy(raw)

    def test_rejects_probe_or_generic_signer(self):
        for wf in (".github/workflows/sox-platform-probe.yml", ".github/workflows/ci.yml",
                   ".github/workflows/../workflows/sox-gate.yml"):
            raw = self._mutated(lambda d: d["predicates"]["human-approval"]["signers"][0]
                                .__setitem__("workflow", wf))
            with self.assertRaises(PolicyError, msg=wf):
                Policy(raw)

    def test_rejects_relay_and_observer_signers(self):
        """BP-53b: relays and the observer are dispatch-only and can never be signers."""
        for wf in (".github/workflows/sox-observer-relay.yml", ".github/workflows/sox-gate-relay.yml",
                   ".github/workflows/sox-review-relay.yml", ".github/workflows/sox-gates-ci.yml"):
            raw = self._mutated(lambda d: d["predicates"]["review-verdict"]["signers"].append(
                {"workflow": wf, "allowedTriggers": ["workflow_dispatch"]}))
            with self.assertRaises(PolicyError, msg=wf):
                Policy(raw)

    def test_rejects_non_main_ref(self):
        raw = self._mutated(lambda d: d["predicates"]["qa-result"].__setitem__("sourceRef", "refs/heads/dev"))
        with self.assertRaises(PolicyError):
            Policy(raw)

    def test_rejects_push_trigger(self):
        raw = self._mutated(lambda d: d["predicates"]["qa-result"]["signers"][0]
                            ["allowedTriggers"].append("push"))
        with self.assertRaises(PolicyError):
            Policy(raw)

    def test_gate_predicates_are_dispatch_only(self):
        for extra in ("schedule", "check_run"):
            raw = self._mutated(lambda d: d["predicates"]["gate-decision"]["signers"][0]
                                ["allowedTriggers"].append(extra))
            with self.assertRaises(PolicyError, msg=extra) as cm:
                Policy(raw)
            self.assertIn("workflow_dispatch", str(cm.exception))

    def test_rejects_never_approver_in_any_role_list(self):
        for role in ("releaseApprovers", "controlOwners", "ecab", "techLeads", "developers"):
            raw = self._mutated(lambda d: d["humans"][role].append("factory-ryan-lauderback"))
            with self.assertRaises(PolicyError, msg=role) as cm:
                Policy(raw)
            self.assertIn("neverApprovers", str(cm.exception))
        raw = self._mutated(lambda d: d.setdefault("regulated", {}).setdefault(
            "domainApprovers", {}).__setitem__("all", ["factory-ryan-lauderback"]))
        with self.assertRaises(PolicyError):
            Policy(raw)
        # platformAdmins legitimately names the owner
        Policy(self._mutated(lambda d: None))

    def test_rejects_repo_mismatch(self):
        raw = self._mutated(lambda d: d["predicates"]["qa-result"].__setitem__("repositoryId", 1))
        with self.assertRaises(PolicyError):
            Policy(raw)


class TestSubjectKeys(unittest.TestCase):
    def test_known_key(self):
        self.assertEqual(subj.key("factory-ryan-lauderback/sox-sdlc-sandbox", "pr", 0),
                         "8f0af752b7d7d89a880a09622f93fe9fdf44a91a0b2334f596863dbd8880c871")

    def test_invalid_ids(self):
        for k, i in (("commit", "abc"), ("pr", "-1"), ("jira", "frq-1"), ("pr", "1\nx")):
            with self.assertRaises(ValueError):
                subj.key("a/b", k, i)


class TestCertificateParsing(unittest.TestCase):
    def test_forgery_cert_fields(self):
        ident = certificate_identity(leaf_certificate(load(FORGERY)))
        self.assertEqual(ident["sourceRepositoryRef"], "refs/heads/redteam-testdata/branch-mint")
        self.assertEqual(ident["buildTrigger"], "push")
        self.assertEqual(ident["legacyTrigger"], "push")
        self.assertEqual(ident["sourceRepositoryIdentifier"], "1453102476")
        self.assertEqual(ident["sourceRepositoryOwnerIdentifier"], "344896283")

    def test_probe_cert_fields(self):
        ident = certificate_identity(leaf_certificate(load(PROBE)))
        self.assertEqual(ident["sourceRepositoryRef"], "refs/heads/main")
        self.assertEqual(ident["buildTrigger"], "workflow_dispatch")
        self.assertEqual(ident["runnerEnvironment"], "github-hosted")

    def test_truncated_cert(self):
        with self.assertRaises(der.DERError):
            der.certificate_extensions(leaf_certificate(load(PROBE))[:200])


class TestForgeryRejected(unittest.TestCase):
    """BP-31e and the red team's gh finding: the branch-minted bundle must be refused even if
    gh is called without --source-ref (gh then accepts it) or replaced by a yes-man."""

    def test_identity_check_alone_rejects_forgery(self):
        p = Policy.load(POLICY)
        ident = certificate_identity(leaf_certificate(load(FORGERY)))
        with self.assertRaises(Rejection) as cm:
            check_identity(p, "review-verdict", ident)
        self.assertIn("source ref", cm.exception.reason)
        self.assertIn("trigger", cm.exception.reason + " trigger") 

    def test_forgery_rejected_with_permissive_gh(self):
        v = Verifier.load(POLICY)
        b = load(FORGERY)
        st = json.loads(base64.b64decode(b["dsseEnvelope"]["payload"]))
        fake = FakeGh(st, certificate_identity(leaf_certificate(b)))
        v.gh_run = fake

        def no_ref_args(policy, name, signer, sf, bf):
            args = gh_verify_args(policy, name, signer, sf, bf)
            out, skip = [], False
            for a in args:
                if skip:
                    skip = False
                    continue
                if a in ("--source-ref", "--cert-identity"):
                    skip = True
                    continue
                out.append(a)
            return out
        v.gh_args = no_ref_args
        with self.assertRaises(Rejection) as cm:
            v.verify(b)
        self.assertEqual(cm.exception.category, "forgery-attempt")
        self.assertIn("refs/heads/redteam-testdata/branch-mint", cm.exception.reason)
        self.assertEqual(fake.calls, [], "identity must be rejected before any crypto call")

    def test_predicate_claims_are_ignored(self):
        b = load(FORGERY)
        st = json.loads(base64.b64decode(b["dsseEnvelope"]["payload"]))
        self.assertEqual(st["predicate"]["attestor"]["ref"], "refs/heads/main")  # the lie
        with self.assertRaises(Rejection):
            Verifier.load(POLICY).verify(b)

    @unittest.skipUnless(HAVE_GH, "gh CLI not installed")
    def test_gh_without_source_ref_accepts_but_we_reject(self):
        """Documents the gh behaviour the red team found, and that it does not matter here."""
        import subprocess
        import tempfile
        b = load(FORGERY)
        with tempfile.TemporaryDirectory() as tmp:
            sf = os.path.join(tmp, "s")
            with open(sf, "wb") as f:
                f.write(subj.preimage("factory-ryan-lauderback/sox-sdlc-sandbox", "pr", "0"))
            env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN")}
            env["GH_CONFIG_DIR"] = tmp
            p = subprocess.run(["/usr/bin/gh" if os.path.exists("/usr/bin/gh") else "gh",
                                "attestation", "verify", sf, "--bundle", FORGERY,
                                "--repo", "factory-ryan-lauderback/sox-sdlc-sandbox",
                                "--signer-workflow", "factory-ryan-lauderback/sox-sdlc-sandbox/.github/workflows/sox-review-agent.yml",
                                "--predicate-type", "https://acme-lending.example/sox/review-verdict/v1"],
                               capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(p.returncode, 0, "gh behaviour changed; re-check the red team note")
        with self.assertRaises(Rejection):
            Verifier.load(POLICY).verify(b)


@unittest.skipUnless(HAVE_GH, "gh CLI not installed")
class TestRealCrypto(unittest.TestCase):
    def test_probe_passes_crypto_then_fails_freshness(self):
        """A genuine main-signed bundle clears identity and signature; it then fails only
        because the probe predicate has no observedAt (so crypto really ran and passed)."""
        v = Verifier(probe_policy())
        with self.assertRaises(Rejection) as cm:
            v.verify(load(PROBE))
        self.assertEqual(cm.exception.category, "stale", cm.exception.reason)

    def test_tampered_payload_fails_signature(self):
        """BP-16b: change the bound SHA inside the signed payload; signature must fail."""
        b = copy.deepcopy(load(PROBE))
        st = json.loads(base64.b64decode(b["dsseEnvelope"]["payload"]))
        st["predicate"]["headSha"] = "0" * 40
        b["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
        v = Verifier(probe_policy())
        with self.assertRaises(Rejection) as cm:
            v.verify(b)
        self.assertEqual(cm.exception.category, "forgery-attempt")
        self.assertIn("verification failed", cm.exception.reason)

    def test_tampered_subject_fails(self):
        b = copy.deepcopy(load(PROBE))
        st = json.loads(base64.b64decode(b["dsseEnvelope"]["payload"]))
        sha = "1" * 40
        st["subject"][0] = {"name": f"sox:commit:{sha}", "digest": {"sha256": subj.key(
            "factory-ryan-lauderback/sox-sdlc-sandbox", "commit", sha)}}
        b["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
        with self.assertRaises(Rejection) as cm:
            Verifier(probe_policy()).verify(b)
        self.assertEqual(cm.exception.category, "forgery-attempt")

    def test_main_cert_on_forged_envelope(self):
        """Forged envelope (signed on a branch) presented with a genuine main certificate: the
        identity check passes on the borrowed cert, so the signature check must catch it."""
        b = copy.deepcopy(load(PROBE))
        forged_env = load(FORGERY)["dsseEnvelope"]
        st = json.loads(base64.b64decode(forged_env["payload"]))
        st["predicateType"] = "https://acme-lending.example/sox/platform-probe/v1"
        b["dsseEnvelope"] = {"payload": base64.b64encode(json.dumps(st).encode()).decode(),
                             "payloadType": forged_env["payloadType"],
                             "signatures": forged_env["signatures"]}
        with self.assertRaises(Rejection) as cm:
            Verifier(probe_policy()).verify(b)
        self.assertIn("verification failed", cm.exception.reason)

    @unittest.skipUnless(os.path.exists(GOOD), "good review-verdict bundle not committed yet")
    def test_good_review_verdict_verifies(self):
        att = Verifier.load(POLICY).verify(load(GOOD), predicate="review-verdict")
        self.assertEqual(att.identity["sourceRepositoryRef"], "refs/heads/main")


class TestImageSubjects(unittest.TestCase):
    """release-approval and build-provenance are looked up by image digest (image:sha256:<hex>).
    The signature check still runs on the sox subject; the image digest must be in the signed
    statement."""
    IMG = "sha256:" + "ab" * 32

    def _bundle(self):
        b = copy.deepcopy(load(PROBE))
        st = json.loads(base64.b64decode(b["dsseEnvelope"]["payload"]))
        st["subject"].append({"name": "ghcr.io/factory-ryan-lauderback/api@" + self.IMG,
                              "digest": {"sha256": self.IMG.split(":")[1]}})
        st["predicate"] = {"repo": "factory-ryan-lauderback/sox-sdlc-sandbox",
                           "observedAt": "2026-11-10T19:37:30Z"}
        b["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
        return b, st

    def test_parse_ref(self):
        self.assertEqual(subj.parse_ref("image:" + self.IMG), ("image", self.IMG))
        for bad in ("image:ab" * 1, "image:sha256:XYZ", "image:sha512:" + "a" * 64):
            with self.assertRaises(ValueError):
                subj.parse_ref(bad)

    def test_fetch_by_image_digest(self):
        b, st = self._bundle()
        v = Verifier(probe_policy())
        v.gh_run = FakeGh(st, certificate_identity(leaf_certificate(b)))

        class Api:
            paths = []

            def paginate_attestations(self, path):
                self.paths.append(path)
                return [{"bundle": b}]
        api = Api()
        ok, bad = v.fetch(api, "image", self.IMG)
        self.assertEqual((len(ok), len(bad)), (1, 0), [r.reason for r in bad])
        self.assertIn("/attestations/" + self.IMG + "?", api.paths[0])
        other = "sha256:" + "cd" * 32
        ok, bad = v.fetch(api, "image", other)
        self.assertEqual(ok, [])
        self.assertEqual(bad[0].category, "binding-mismatch")

    def test_sox_subject_named_like_image_does_not_match(self):
        """A sox:<kind> subject never satisfies an image lookup, even with the same digest."""
        b, st = self._bundle()
        key = st["subject"][0]["digest"]["sha256"]
        v = Verifier(probe_policy())
        v.gh_run = FakeGh(st, certificate_identity(leaf_certificate(b)))
        att = v.verify(b)
        self.assertFalse(att.has_subject("image", "sha256:" + key))
        self.assertTrue(att.has_subject("image", self.IMG))

class TestRoundCounting(unittest.TestCase):
    """F11/BP-41b: a round is a distinct head with a verified changes_requested verdict."""

    def _count(self, items, **kw):
        v = Verifier.load(POLICY)
        v.fetch = lambda api, kind, ident, predicate=None: (items, [])
        return v.count_rounds(None, "FRQ-1", **kw)[0]

    @staticmethod
    def _att(i, head, outcome="changes_requested"):
        st = {"subject": [{"name": f"sox:commit:{head}"}, {"name": "sox:jira:FRQ-1"}],
              "predicate": {"outcome": outcome, "headSha": head}}
        return Attestation("review-verdict", st, f"sha256:{i:064x}", {}, 1_800_000_000 + i, {})

    def test_redispatch_on_one_head_is_one_round(self):
        self.assertEqual(self._count([self._att(i, "a" * 40) for i in range(3)]), 1)

    def test_distinct_heads_count(self):
        self.assertEqual(self._count([self._att(i, c * 40) for i, c in enumerate("bcd")]), 3)

    def test_passes_and_since_excluded(self):
        items = [self._att(0, "a" * 40), self._att(1, "b" * 40, "pass"), self._att(5, "c" * 40)]
        self.assertEqual(self._count(items), 2)
        self.assertEqual(self._count(items, since=1_800_000_002), 1)


class TestBundleForms(unittest.TestCase):
    def test_api_record_wrapper(self):
        rec = {"repository_id": "1453102476", "bundle": load(PROBE)}
        self.assertIn("dsseEnvelope", normalize_bundle(rec))

    def test_not_a_bundle(self):
        with self.assertRaises(Rejection):
            normalize_bundle({"mediaType": "application/json"})


if __name__ == "__main__":
    unittest.main()
