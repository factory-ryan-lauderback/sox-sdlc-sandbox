import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
AGENTS = os.path.join(HERE, "..")


def run_parse(droid, ctx_digest="sha256:c"):
    d = tempfile.mkdtemp()
    if droid is not None:
        with open(f"{d}/droid.json", "w") as f:
            f.write(droid if isinstance(droid, str) else json.dumps(droid))
    out = f"{d}/github_output"
    p = subprocess.run([sys.executable, os.path.join(AGENTS, "review_agent.py"), "parse", "--dir", d],
                       check=True, capture_output=True, text=True,
                       env={**os.environ, "GITHUB_OUTPUT": out, "CONTEXT_DIGEST": ctx_digest})
    line = [x for x in open(out).read().splitlines() if x.startswith("verdict=")][0]
    return json.loads(base64.b64decode(line.split("=", 1)[1])), p.stdout + p.stderr


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

    def test_verdict_never_printed(self):
        _, logs = run_parse({"is_error": False, "result": '{"verdict":"changes_requested","summary":"SECRET-SUMMARY","findings":[]}'})
        self.assertNotIn("changes_requested", logs)
        self.assertNotIn("SECRET-SUMMARY", logs)


if __name__ == "__main__":
    unittest.main()
