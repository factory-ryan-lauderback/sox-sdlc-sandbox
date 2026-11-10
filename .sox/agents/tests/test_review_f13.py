"""F13: which review outcomes may create a check run, and how."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import checks  # noqa: E402
import review_agent  # noqa: E402

HEAD = "a" * 40
PR = {"number": 7, "head": {"sha": HEAD, "ref": "story/FRQ-5-x"}, "base": {"sha": "b" * 40, "ref": "release/r1"},
      "user": {"login": "acme-dev-agent[bot]", "type": "Bot"}, "title": "t", "body": ""}
DIFF = b"diff --git a/x b/x\n"


def run(state=None, verdict="pass", existing=None, prior=(), env_app=42):
    d, out = tempfile.mkdtemp(), tempfile.mkdtemp()
    ctx = {"pr": 7, "headSha": HEAD, "baseRef": "refs/heads/release/r1",
           "diffDigest": "sha256:" + review_agent.sha256_hex(DIFF)}
    json.dump(ctx, open(f"{d}/context.json", "w"))
    json.dump({"verdict": verdict, "summary": "s", "findings": [], "agent": {}}, open(f"{d}/verdict.json", "w"))
    runs = state or []
    gh = mock.Mock()
    gh.pr.return_value, gh.pr_diff.return_value, gh.pr_files.return_value = PR, DIFF, [{"filename": "services/api/app.py"}]
    with mock.patch.object(review_agent, "GitHub", return_value=gh), \
         mock.patch.object(review_agent.checks, "app_runs", return_value=runs), \
         mock.patch.object(review_agent.rounds, "verdict_for_head", return_value=existing), \
         mock.patch.object(review_agent.rounds, "failing_heads", return_value=(set(prior), 0)), \
         mock.patch.object(review_agent.rounds, "latest_plan_digest", return_value=None), \
         mock.patch.object(review_agent, "_jira_context", return_value=(["FRQ-5"], "")), \
         mock.patch.object(review_agent, "_app_id_for_login", return_value=99), \
         mock.patch.dict(os.environ, {"REVIEWER_APP_ID": str(env_app), "GITHUB_OUTPUT": os.devnull}):
        review_agent.record(mock.Mock(dir=d, out=out))
    return json.load(open(f"{out}/plan.json"))


class F13(unittest.TestCase):
    def test_head_state(self):
        self.assertEqual(checks.head_state([]), "none")
        self.assertEqual(checks.head_state([{"status": "completed", "conclusion": "success"}]), "passed")
        self.assertEqual(checks.head_state([{"status": "in_progress"}]), "open")
        for c in ("failure", "cancelled", "neutral", "skipped", "timed_out"):
            self.assertEqual(checks.head_state([{"status": "completed", "conclusion": "success"},
                                                {"status": "completed", "conclusion": c}]), "burned")

    def test_model_error_opens_no_check(self):
        p = run(verdict="error")
        self.assertEqual(p["action"], "none")
        self.assertFalse(p["attest"])

    def test_verdict_attests(self):
        p = run(verdict="changes_requested")
        self.assertEqual((p["action"], p["attest"], p["conclusion"]), ("attest", True, "failure"))

    def test_burned_head_is_not_judged_again(self):
        for st in ([{"id": 1, "status": "completed", "conclusion": "cancelled"}], [{"id": 1, "status": "in_progress"}]):
            p = run(state=st)
            self.assertEqual(p["action"], "none", st)
            self.assertFalse(p["attest"])

    def test_heal_stale_run_of_attested_verdict(self):
        ex = mock.Mock(predicate={"outcome": "pass", "round": 1, "checkRunId": 5}, digest="sha256:x", identity={})
        p = run(state=[{"id": 5, "status": "in_progress"}], existing=ex)
        self.assertEqual((p["action"], p["checkRunId"], p["conclusion"]), ("heal", 5, "success"))

    def test_existing_verdict_already_posted_is_noop(self):
        ex = mock.Mock(predicate={"outcome": "changes_requested", "round": 2, "checkRunId": 5}, digest="sha256:x", identity={})
        p = run(state=[{"id": 5, "status": "completed", "conclusion": "failure"}], existing=ex)
        self.assertEqual(p["action"], "none")
        self.assertFalse(p["attest"])

    def test_loop_exhausted_posts_one_completed_failure(self):
        p = run(prior=[str(i) * 40 for i in range(10)])
        self.assertEqual((p["action"], p["attest"], p["conclusion"]), ("post", False, "failure"))


class FinishTest(unittest.TestCase):
    def _finish(self, plan, env):
        out = tempfile.mkdtemp()
        json.dump(plan, open(f"{out}/plan.json", "w"))
        gh = mock.Mock()
        with mock.patch.object(review_agent, "GitHub", return_value=gh), \
             mock.patch.object(review_agent.checks, "complete") as complete, \
             mock.patch.dict(os.environ, {"APP_TOKEN": "t", **env}):
            review_agent.check_finish(mock.Mock(out=out))
        return complete

    def test_unopened_attest_creates_nothing(self):
        c = self._finish({"action": "attest", "pr": 7, "headSha": HEAD, "conclusion": "success", "title": "t", "summary": ""}, {})
        c.assert_not_called()

    def test_failed_attest_completes_failure(self):
        c = self._finish({"action": "attest", "checkRunId": 9, "pr": 7, "headSha": HEAD, "conclusion": "success",
                          "title": "t", "summary": ""}, {"ATTEST_OUTCOME": "failure", "ATTESTATION_URL": ""})
        self.assertEqual(c.call_args.args[3], "failure")
        self.assertEqual(c.call_args.kwargs["run_id"], 9)


if __name__ == "__main__":
    unittest.main()
