import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
AGENTS = os.path.join(HERE, "..")


def run_parse(ctx, droid):
    d = tempfile.mkdtemp()
    with open(f"{d}/context.json", "w") as f:
        json.dump(ctx, f)
    if droid is not None:
        with open(f"{d}/droid.json", "w") as f:
            f.write(droid if isinstance(droid, str) else json.dumps(droid))
    subprocess.run([sys.executable, os.path.join(AGENTS, "review_agent.py"), "parse", "--dir", d],
                   check=True, capture_output=True)
    with open(f"{d}/verdict.json") as f:
        return json.load(f)


class ParseTest(unittest.TestCase):
    def test_pass(self):
        v = run_parse({"mode": "llm"}, {"is_error": False, "session_id": "s1",
                                         "result": 'Done.\n{"verdict":"pass","summary":"ok","findings":[]}'})
        self.assertEqual(v["verdict"], "pass")
        self.assertEqual(v["agent"]["factorySessionId"], "s1")

    def test_blocking_finding_forces_changes_requested(self):
        body = {"verdict": "pass", "summary": "x", "findings": [{"severity": "blocking", "path": "a.py", "line": 3, "title": "t", "body": "b"}]}
        v = run_parse({"mode": "llm"}, {"is_error": False, "result": json.dumps(body)})
        self.assertEqual(v["verdict"], "changes_requested")

    def test_garbage_is_error_not_pass(self):
        for droid in ({"is_error": False, "result": "I approve this PR"},
                      {"is_error": True, "result": '{"verdict":"pass"}'},
                      {"is_error": False, "result": '{"verdict":"approved"}'},
                      "not json", None):
            self.assertEqual(run_parse({"mode": "llm"}, droid)["verdict"], "error", droid)

    def test_too_large_is_changes_requested(self):
        self.assertEqual(run_parse({"mode": "too-large"}, None)["verdict"], "changes_requested")


if __name__ == "__main__":
    unittest.main()
