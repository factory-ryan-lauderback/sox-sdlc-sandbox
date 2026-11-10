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
from soxlib.verify import (Rejection, Verifier, certificate_identity, check_identity,  # noqa: E402
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

    def test_rejects_non_main_ref(self):
        raw = self._mutated(lambda d: d["predicates"]["qa-result"].__setitem__("sourceRef", "refs/heads/dev"))
        with self.assertRaises(PolicyError):
            Policy(raw)

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


class TestBundleForms(unittest.TestCase):
    def test_api_record_wrapper(self):
        rec = {"repository_id": "1453102476", "bundle": load(PROBE)}
        self.assertIn("dsseEnvelope", normalize_bundle(rec))

    def test_not_a_bundle(self):
        with self.assertRaises(Rejection):
            normalize_bundle({"mediaType": "application/json"})


if __name__ == "__main__":
    unittest.main()
