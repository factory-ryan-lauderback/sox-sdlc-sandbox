"""F13/F17: the binding check run opens before the model, and only an attested pass succeeds."""
import base64
import contextlib
import hashlib
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
APP = 42
PR = {"number": 7, "state": "open", "head": {"sha": HEAD, "ref": "story/FRQ-5-x"}, "base": {"sha": "b" * 40, "ref": "release/r1"},
      "user": {"login": "acme-dev-agent[bot]", "type": "Bot"}, "title": "t", "body": ""}
DIFF = b"diff --git a/x b/x\n"


def fake_gh(check_run=None):
    gh = mock.Mock()
    gh.pr.return_value, gh.pr_diff.return_value, gh.pr_files.return_value = PR, DIFF, [{"filename": "services/api/app.py"}]
    gh.get.return_value = check_run or {"id": 9, "app": {"id": APP}, "head_sha": HEAD, "name": review_agent.CHECK_NAME,
                                        "status": "in_progress"}
    return gh


@contextlib.contextmanager
def patched(gh, runs=(), existing=None, prior=()):
    with mock.patch.object(review_agent, "GitHub", return_value=gh), \
         mock.patch.object(review_agent.checks, "app_runs", return_value=list(runs)), \
         mock.patch.object(review_agent.checks, "start", return_value=9) as start, \
         mock.patch.object(review_agent.checks, "complete") as complete, \
         mock.patch.object(review_agent.rounds, "verdict_for_head", return_value=existing), \
         mock.patch.object(review_agent.rounds, "failing_heads", return_value=(set(prior), 0)), \
         mock.patch.object(review_agent.rounds, "latest_plan_digest", return_value=None), \
         mock.patch.object(review_agent, "_jira_context", return_value=(["FRQ-5"], "")), \
         mock.patch.object(review_agent, "_app_id_for_login", return_value=99), \
         mock.patch.dict(os.environ, {"REVIEWER_APP_ID": str(APP), "APP_TOKEN": "t", "GITHUB_OUTPUT": os.devnull,
                                      "GITHUB_RUN_ID": "1234"}):
        yield start, complete


def do_open(**kw):
    out = tempfile.mkdtemp()
    with patched(fake_gh(), **kw) as (start, complete):
        review_agent.open_(mock.Mock(pr="7", out=out))
    ctx = os.path.join(out, "context.json")
    return start, complete, (json.load(open(ctx)) if os.path.exists(ctx) else None), out


def do_record(verdict=None, result="success", existing=None, check_status="in_progress", tamper=False, head_moved=False):
    _, _, _, ctxdir = do_open()
    raw = open(f"{ctxdir}/context.json", "rb").read()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if tamper:
        digest = "sha256:" + "0" * 64
    env = {"REVIEW_RESULT": result, "OPEN_CONTEXT_DIGEST": digest}
    if verdict is not None:
        verdict = {**verdict, "contextDigest": "sha256:" + hashlib.sha256(raw).hexdigest()}
        env["VERDICT_B64"] = base64.b64encode(json.dumps(verdict).encode()).decode()
    out = tempfile.mkdtemp()
    gh = fake_gh({"id": 9, "app": {"id": APP}, "head_sha": HEAD, "name": review_agent.CHECK_NAME, "status": check_status})
    if head_moved:
        gh.pr.return_value = {**PR, "head": {**PR["head"], "sha": "c" * 40}}
    with patched(gh, existing=existing), mock.patch.dict(os.environ, env):
        review_agent.record(mock.Mock(ctx=ctxdir, out=out))
    plan = json.load(open(f"{out}/plan.json"))
    pred = json.load(open(f"{out}/predicate.json")) if os.path.exists(f"{out}/predicate.json") else None
    return plan, pred


class OpenTest(unittest.TestCase):
    def test_head_state(self):
        self.assertEqual(checks.head_state([]), "none")
        self.assertEqual(checks.head_state([{"status": "completed", "conclusion": "success"}]), "passed")
        self.assertEqual(checks.head_state([{"status": "in_progress"}]), "open")
        for c in ("failure", "cancelled", "neutral", "skipped", "timed_out"):
            self.assertEqual(checks.head_state([{"status": "completed", "conclusion": "success"},
                                                {"status": "completed", "conclusion": c}]), "burned")

    def test_opens_binding_run_before_model_with_run_id(self):
        start, complete, ctx, _ = do_open()
        start.assert_called_once()
        self.assertEqual(start.call_args.args[3], "1234")
        self.assertEqual((ctx["checkRunId"], ctx["mode"]), (9, "llm"))
        complete.assert_not_called()

    def test_judged_or_blocked_head_is_not_reopened(self):
        for runs in ([{"id": 1, "status": "completed", "conclusion": "cancelled"}], [{"id": 1, "status": "in_progress"}],
                     [{"id": 1, "status": "completed", "conclusion": "success"}]):
            start, complete, ctx, _ = do_open(runs=runs)
            start.assert_not_called(); complete.assert_not_called()
            self.assertIsNone(ctx)

    def test_heal_stale_run_of_attested_verdict(self):
        ex = mock.Mock(predicate={"outcome": "pass", "round": 1, "checkRunId": 5}, digest="sha256:x", identity={})
        start, complete, _, _ = do_open(runs=[{"id": 5, "status": "in_progress"}], existing=ex)
        start.assert_not_called()
        self.assertEqual((complete.call_args.args[3], complete.call_args.kwargs.get("run_id")), ("success", 5))

    def test_loop_exhausted_posts_completed_failure_and_escalates(self):
        start, complete, _, out = do_open(prior=[str(i) * 40 for i in range(10)])
        start.assert_not_called()
        self.assertEqual(complete.call_args.args[3], "failure")
        ops = json.load(open(f"{out}/jira-ops.json"))
        self.assertEqual(ops[0]["to"], "Blocked - Human Escalation")


class RecordTest(unittest.TestCase):
    PASS = {"verdict": "pass", "valid": True, "summary": "ok", "findings": [], "agent": {}}

    def test_pass_attests_with_check_run_id(self):
        plan, pred = do_record(self.PASS)
        self.assertEqual((plan["attest"], plan["conclusion"]), (True, "success"))
        self.assertEqual((pred["outcome"], pred["checkRunId"], pred["verdictValid"]), ("pass", 9, True))

    def test_failed_llm_job_attests_changes_requested(self):
        for kw in ({"verdict": None, "result": "failure"}, {"verdict": None, "result": "cancelled"},
                   {"verdict": {**PASS, "valid": False}}, {"verdict": {"verdict": "approve"}}):
            plan, pred = do_record(**kw)
            self.assertEqual((plan["attest"], plan["conclusion"], pred["outcome"]), (True, "failure", "changes_requested"), kw)

    def test_existing_verdict_is_never_resigned(self):
        ex = mock.Mock(predicate={"outcome": "changes_requested"}, digest="sha256:x", identity={})
        plan, pred = do_record(self.PASS, existing=ex)
        self.assertEqual((plan["attest"], plan["conclusion"]), (False, "failure"))
        self.assertIsNone(pred)

    def test_completed_run_is_left_alone(self):
        plan, _ = do_record(self.PASS, check_status="completed")
        self.assertTrue(plan["closed"])
        self.assertFalse(plan["attest"])

    def test_moved_head_completes_failure_without_attest(self):
        plan, _ = do_record(self.PASS, head_moved=True)
        self.assertEqual((plan["attest"], plan["conclusion"]), (False, "failure"))

    def test_tampered_context_refused(self):
        with self.assertRaises(SystemExit):
            do_record(self.PASS, tamper=True)


PASS = RecordTest.PASS


class FinishTest(unittest.TestCase):
    def _finish(self, plan, env, status="in_progress"):
        out = tempfile.mkdtemp()
        if plan is not None:
            json.dump(plan, open(f"{out}/plan.json", "w"))
        gh = mock.Mock()
        gh.get.return_value = {"id": 9, "head_sha": HEAD, "status": status}
        with mock.patch.object(review_agent, "GitHub", return_value=gh), \
             mock.patch.object(review_agent.checks, "complete") as complete, \
             mock.patch.dict(os.environ, {"APP_TOKEN": "t", "CHECK_RUN_ID": "9", **env}):
            review_agent.finish(mock.Mock(out=out))
        return complete, gh

    def test_no_plan_completes_failure(self):
        c, _ = self._finish(None, {})
        self.assertEqual((c.call_args.args[3], c.call_args.kwargs["run_id"]), ("failure", 9))

    def test_failed_attest_completes_failure(self):
        c, gh = self._finish({"attest": True, "pr": 7, "conclusion": "success", "title": "t", "summary": ""},
                             {"ATTEST_OUTCOME": "failure", "ATTESTATION_URL": ""})
        self.assertEqual(c.call_args.args[3], "failure")
        gh.request.assert_not_called()  # no reasoning published without an attestation

    def test_attested_pass_succeeds_and_publishes(self):
        c, gh = self._finish({"attest": True, "pr": 7, "conclusion": "success", "title": "t", "summary": "s"},
                             {"ATTEST_OUTCOME": "success", "ATTESTATION_URL": "https://x"})
        self.assertEqual(c.call_args.args[3], "success")
        gh.request.assert_called_once()

    def test_already_completed_untouched(self):
        c, _ = self._finish({"attest": True, "pr": 7, "conclusion": "success", "title": "t", "summary": ""},
                            {"ATTEST_OUTCOME": "success", "ATTESTATION_URL": "https://x"}, status="completed")
        c.assert_not_called()


if __name__ == "__main__":
    unittest.main()
