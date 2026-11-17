import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
AGENTS = os.path.join(HERE, "..")
sys.path.insert(0, AGENTS)
import seal  # noqa: E402

SECRET = "-----BEGIN RSA PRIVATE KEY-----\nparse-test\n-----END RSA PRIVATE KEY-----\n"
RUN = "777"


def run_parse(droid, ctx_digest="sha256:c", seal_pub=None, check=True):
    d = tempfile.mkdtemp()
    if droid is not None:
        with open(f"{d}/droid.json", "w") as f:
            f.write(droid if isinstance(droid, str) else json.dumps(droid))
    out = f"{d}/github_output"
    with mock.patch.dict(os.environ, {"GITHUB_RUN_ID": RUN}):
        pub = seal.public_key(SECRET, "review-verdict") if seal_pub is None else seal_pub
    p = subprocess.run([sys.executable, os.path.join(AGENTS, "review_agent.py"), "parse", "--dir", d],
                       check=check, capture_output=True, text=True,
                       env={**os.environ, "GITHUB_OUTPUT": out, "CONTEXT_DIGEST": ctx_digest, "SEAL_PUB": pub,
                            "GITHUB_RUN_ID": RUN})
    lines = [x for x in open(out).read().splitlines() if x.startswith("verdict=")] if os.path.exists(out) else []
    if not check:
        return lines, p
    value = lines[0].split("=", 1)[1]
    with mock.patch.dict(os.environ, {"GITHUB_RUN_ID": RUN}):
        verdict = json.loads(seal.unseal(SECRET, "review-verdict", value))
    return verdict, p.stdout + p.stderr + value


class ParseTest(unittest.TestCase):
    def test_pass(self):
        v, _ = run_parse({"is_error": False, "session_id": "s1",
                          "result": 'Done.\n{"verdict":"pass","summary":"ok","findings":[]}'})
        self.assertEqual((v["verdict"], v["valid"], v["contextDigest"]), ("pass", True, "sha256:c"))
        self.assertEqual(v["agent"]["factorySessionId"], "s1")

    def test_blocking_finding_forces_changes_requested(self):
        body = {"verdict": "pass", "summary": "x", "findings": [{"severity": "blocking", "path": "a.py", "line": 3, "title": "t", "body": "b"}]}
        v, _ = run_parse({"is_error": False, "result": json.dumps(body)})
        self.assertEqual(v["verdict"], "changes_requested")

    def test_garbage_is_changes_requested_not_retry(self):
        for droid in ({"is_error": False, "result": "I approve this PR"},
                      {"is_error": True, "result": '{"verdict":"pass"}'},
                      {"is_error": False, "result": '{"verdict":"approved"}'},
                      "not json", None):
            v, _ = run_parse(droid)
            self.assertEqual((v["verdict"], v["valid"]), ("changes_requested", False), droid)

    def test_verdict_never_printed_or_readable_in_output(self):
        # F18: the output is printed in record's env header, so it must not carry the verdict readably.
        _, logs = run_parse({"is_error": False, "result": '{"verdict":"changes_requested","summary":"SECRET-SUMMARY","findings":[]}'})
        self.assertNotIn("changes_requested", logs)
        self.assertNotIn("SECRET-SUMMARY", logs)
        import base64
        self.assertNotIn(b"SECRET-SUMMARY", base64.b64decode(logs.split(seal.PREFIX, 1)[1]))

    def test_no_sealing_key_means_no_output(self):
        for pub in ("", "not-a-key"):
            lines, p = run_parse({"is_error": False, "result": '{"verdict":"pass","summary":"SECRET-SUMMARY","findings":[]}'},
                                 seal_pub=pub, check=False)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(lines, [])
            self.assertNotIn("SECRET-SUMMARY", p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
