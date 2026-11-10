"""QA Agent: selection from verified evidence, binding check run order (F13/F16), runtests, and a
qa-result predicate that satisfies the gate's SDLC-08 rule."""
import contextlib
import json
import os
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", ".."))
import qa_agent  # noqa: E402
from planning_agent import dir_digest  # noqa: E402
from soxlib import gate  # noqa: E402

HEAD, BASE = "a" * 40, "b" * 40
APP = 77
SLUG = "r1"
ENV_D, MAN_D, PLAN_D = "sha256:" + "e" * 64, "sha256:" + "f" * 64, "sha256:" + "c" * 64
REQ = ["services.api.test_e2e_pay.PayE2E.test_pay", "services.api.test_app.T.test_unit"]
PR = {"number": 12, "state": "open", "draft": False, "head": {"sha": HEAD, "ref": f"release/{SLUG}",
      "repo": {"full_name": qa_agent.REPO, "owner": {"login": qa_agent.REPO.split("/")[0]}}},
      "base": {"sha": BASE, "ref": "main"}}


def att(pred, t=1, digest="sha256:" + "0" * 64):
    return mock.Mock(predicate=pred, integrated_time=t, digest=digest)


def env_att(outcome="pass", t=5, digest=ENV_D, pr=12):
    return att({"headSha": HEAD, "environment": "qa", "outcome": outcome, "prNumber": pr, "envId": "rel-r1",
                "images": [{"service": "api", "digest": "sha256:" + "1" * 64}, {"service": "db", "digest": "sha256:" + "2" * 64}]},
               t, digest)


def make_fetch(envs=None, plans=None):
    envs = [env_att()] if envs is None else envs
    story_plan = att({"epicKey": "FRQ-1", "stories": [{"key": "FRQ-2", "requiredTests": REQ[:1]},
                                                       {"key": "FRQ-3", "requiredTests": REQ[1:]}]}, 3, PLAN_D)
    plans = [story_plan] if plans is None else plans

    def fetch(kind, ident, pred):
        if pred == "env-deploy":
            return envs, []
        if pred == "release-manifest":
            return [att({"release": SLUG, "stories": [{"key": "FRQ-2"}, "FRQ-3"]}, 2, MAN_D)], []
        if pred == "techlead-plan":
            return plans, []
        return [], []
    return fetch


def outputs(path):
    return dict(line.rstrip("\n").split("=", 1) for line in open(path) if "=" in line)


def fake_gh(check_run=None, pr=PR, runs=()):
    gh = mock.Mock()
    gh.pr.return_value = pr
    gh.paginate.side_effect = lambda path, **kw: [pr] if "state=open" in path else []
    gh.pr_files.return_value = []

    def get(path):
        if "/check-runs/" in path:
            return check_run or {"id": 9, "app": {"id": APP}, "head_sha": HEAD, "name": qa_agent.CHECK_NAME,
                                 "status": "in_progress"}
        return {"check_runs": list(runs), "total_count": len(runs)}
    gh.get.side_effect = get
    return gh


@contextlib.contextmanager
def patched(gh, fetch=None, runs=(), existing=None, prior=(), env=None):
    out = tempfile.mktemp()
    with mock.patch.object(qa_agent, "GitHub", return_value=gh), \
         mock.patch.object(qa_agent.rounds, "fetch", side_effect=fetch or make_fetch()), \
         mock.patch.object(qa_agent.checks, "app_runs", return_value=list(runs)), \
         mock.patch.object(qa_agent.checks, "start", return_value=9) as start, \
         mock.patch.object(qa_agent.checks, "complete") as complete, \
         mock.patch.object(qa_agent.rounds, "verdict_for_head", return_value=existing), \
         mock.patch.object(qa_agent.rounds, "failing_heads", return_value=(set(prior), 0)), \
         mock.patch.dict(os.environ, {"QA_APP_ID": str(APP), "APP_TOKEN": "t", "GITHUB_OUTPUT": out,
                                      "GITHUB_RUN_ID": "4321", "GITHUB_REF": "refs/heads/main", **(env or {})}):
        yield start, complete, out


def do_select(**kw):
    ctx = tempfile.mkdtemp()
    with patched(fake_gh(runs=kw.pop("runs", ())), **kw) as (_, _, out):
        qa_agent.select(mock.Mock(out=ctx, pr=""))
        o = outputs(out) if os.path.exists(out) else {}
    return ctx, o


class SelectTest(unittest.TestCase):
    def test_writes_context_from_verified_evidence(self):
        ctx, o = do_select()
        self.assertEqual((o["pr"], o["head"]), ("12", HEAD))
        self.assertEqual(o["context_digest"], dir_digest(ctx))
        c = json.load(open(f"{ctx}/context.json"))
        self.assertEqual((c["envDeploy"], c["manifest"], c["stories"]), (ENV_D, MAN_D, ["FRQ-2", "FRQ-3"]))
        self.assertEqual(c["requiredTests"], sorted(REQ))
        spec = json.load(open(f"{ctx}/env-spec.json"))
        self.assertEqual(spec["envId"], "rel-r1")
        self.assertTrue(all(i["ref"].endswith("@" + i["digest"]) for i in spec["images"]))

    def test_needs_latest_env_deploy_to_pass(self):
        for envs in ([], [env_att("fail")], [env_att("pass", 1, "sha256:" + "3" * 64), env_att("fail", 9)],
                     [env_att(pr=99)]):
            _, o = do_select(fetch=make_fetch(envs=envs))
            self.assertEqual(o.get("pr"), "", envs)
        _, o = do_select(fetch=make_fetch(envs=[env_att("fail", 1, "sha256:" + "3" * 64), env_att("pass", 9)]))
        self.assertEqual(o["pr"], "12")

    def test_skips_head_with_qa_app_run_and_missing_plan(self):
        _, o = do_select(runs=[{"app": {"slug": "acme-qa-agent"}, "status": "completed"}])
        self.assertEqual(o.get("pr"), "")
        _, o = do_select(fetch=make_fetch(plans=[]))
        self.assertEqual(o.get("pr"), "")

    def test_uses_latest_epic_plan(self):
        newer = att({"epicKey": "FRQ-1", "stories": [{"key": "FRQ-2", "requiredTests": ["services.api.test_x.A.test_b"]},
                                                      {"key": "FRQ-3", "requiredTests": []}]}, 8, "sha256:" + "9" * 64)
        older = make_fetch()("jira", "FRQ-1", "techlead-plan")[0][0]
        ctx, _ = do_select(fetch=make_fetch(plans=[older, newer]))
        self.assertEqual(json.load(open(f"{ctx}/context.json"))["requiredTests"], ["services.api.test_x.A.test_b"])


def ctxdir():
    ctx, o = do_select()
    return ctx, o["context_digest"]


def do_open(runs=(), existing=None, prior=(), pr=PR):
    ctx, digest = ctxdir()
    out = tempfile.mkdtemp()
    with patched(fake_gh(pr=pr), runs=runs, existing=existing, prior=prior, env={"CONTEXT_DIGEST": digest}) as (s, c, o):
        qa_agent.open_(mock.Mock(ctx=ctx, out=out))
        res = outputs(o) if os.path.exists(o) else {}
    return s, c, res, out


class OpenTest(unittest.TestCase):
    def test_opens_binding_run_with_run_id(self):
        start, complete, o, _ = do_open()
        self.assertEqual(start.call_args.args[2:], (HEAD, "4321"))
        self.assertEqual((o["mode"], o["check_run_id"]), ("test", "9"))
        complete.assert_not_called()

    def test_tampered_context_refused(self):
        ctx, _ = ctxdir()
        with patched(fake_gh(), env={"CONTEXT_DIGEST": "sha256:" + "0" * 64}):
            with self.assertRaises(SystemExit):
                qa_agent.open_(mock.Mock(ctx=ctx, out=tempfile.mkdtemp()))

    def test_tested_or_burned_head_not_reopened(self):
        for runs in ([{"id": 1, "status": "completed", "conclusion": "failure"}], [{"id": 1, "status": "in_progress"}],
                     [{"id": 1, "status": "completed", "conclusion": "success"}]):
            start, complete, o, _ = do_open(runs=runs)
            start.assert_not_called(); complete.assert_not_called()
            self.assertEqual(o["mode"], "done")

    def test_moved_head_is_not_opened(self):
        start, _, o, _ = do_open(pr={**PR, "head": {**PR["head"], "sha": "c" * 40}})
        start.assert_not_called()
        self.assertEqual(o["mode"], "done")

    def test_existing_qa_result_reposted_not_retested(self):
        ex = mock.Mock(predicate={"outcome": "fail", "checkRunId": 5}, digest="sha256:x")
        start, complete, o, _ = do_open(runs=[{"id": 5, "status": "in_progress"}], existing=ex)
        start.assert_not_called()
        self.assertEqual((complete.call_args.args[3], complete.call_args.kwargs.get("run_id")), ("failure", 5))
        self.assertEqual(o["mode"], "done")

    def test_loop_q_exhausted_escalates(self):
        start, complete, o, out = do_open(prior=[str(i) * 40 for i in range(10)])
        start.assert_not_called()
        self.assertEqual((complete.call_args.args[3], complete.call_args.args[4]), ("failure", "loop-exhausted"))
        ops = json.load(open(f"{out}/jira-ops.json"))
        self.assertIn({"op": "transition", "key": "FRQ-2", "to": "Blocked - Human Escalation"}, ops)

    def test_nine_prior_failures_still_tests(self):
        start, _, o, _ = do_open(prior=[str(i) * 40 for i in range(9)])
        start.assert_called_once()


class RunTestsTest(unittest.TestCase):
    def test_statuses(self):
        root = tempfile.mkdtemp()
        os.makedirs(f"{root}/services/zq")
        for p in ("services/__init__.py", "services/zq/__init__.py"):
            open(f"{root}/{p}", "w").close()
        open(f"{root}/services/zq/test_e2e_mod.py", "w").write(textwrap.dedent("""
            import os, unittest
            class E(unittest.TestCase):
                def test_ok(self): pass
                def test_bad(self): self.fail("x")
                def test_err(self): raise RuntimeError("x")
                @unittest.skipUnless(os.environ.get("NOPE_URL"), "env")
                def test_skip(self): pass
        """))
        ids = [f"services.zq.test_e2e_mod.E.test_{n}" for n in ("ok", "bad", "err", "skip", "gone")] + \
              ["services.zq.test_none.E.test_x", "os.system"]
        idf, out = f"{root}/ids.json", f"{root}/res.json"
        json.dump(ids, open(idf, "w"))
        cwd, saved = os.getcwd(), dict(sys.modules)
        try:
            os.chdir(root)
            for m in [m for m in sys.modules if m == "services" or m.startswith("services.")]:
                del sys.modules[m]
            qa_agent.runtests(mock.Mock(ids=idf, out=out))
        finally:
            os.chdir(cwd)
            sys.path[:] = [p for p in sys.path if p != root]
            sys.modules.clear(); sys.modules.update(saved)
        got = [r["status"] for r in json.load(open(out))]
        self.assertEqual(got, ["passed", "failed", "error", "skipped", "missing", "missing", "invalid-id"])

    def test_encode_roundtrip(self):
        f = tempfile.mktemp()
        json.dump([{"id": "x", "status": "passed"}], open(f, "w"))
        self.assertEqual(qa_agent.decode_results(qa_agent.encode_results(f)), [{"id": "x", "status": "passed"}])


def do_record(statuses=None, result="success", existing=None, status="in_progress", head_moved=False,
              fetch=None, results_b64=None, prior=()):
    ctx, digest = ctxdir()
    statuses = statuses if statuses is not None else {t: "passed" for t in REQ}
    f = tempfile.mktemp()
    json.dump([{"id": k, "status": v} for k, v in statuses.items()], open(f, "w"))
    b64 = qa_agent.encode_results(f) if results_b64 is None else results_b64
    pr = {**PR, "head": {**PR["head"], "sha": "c" * 40}} if head_moved else PR
    gh = fake_gh({"id": 9, "app": {"id": APP}, "head_sha": HEAD, "name": qa_agent.CHECK_NAME, "status": status}, pr=pr)
    out = tempfile.mkdtemp()
    env = {"CONTEXT_DIGEST": digest, "CHECK_RUN_ID": "9", "TEST_RESULT": result, "RESULTS_B64": b64,
           "GITHUB_SHA": "d" * 40}
    with patched(gh, fetch=fetch, existing=existing, prior=prior, env=env):
        qa_agent.record(mock.Mock(ctx=ctx, out=out))
    load = lambda n: json.load(open(f"{out}/{n}")) if os.path.exists(f"{out}/{n}") else None  # noqa: E731
    subjects = open(f"{out}/subjects.txt").read() if os.path.exists(f"{out}/subjects.txt") else ""
    return load("plan.json"), load("predicate.json"), subjects, load("jira-ops.json")


def floats(v, path="$"):
    if isinstance(v, float):
        yield path
    elif isinstance(v, dict):
        for k, x in v.items():
            yield from floats(x, f"{path}.{k}")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from floats(x, f"{path}[{i}]")


def gate_sdlc08(q, env_digest=ENV_D, required=REQ):
    """The gate's SDLC-08 expression (gate.eval_release), applied to the signed predicate."""
    pd = mock.Mock(number=12, head=HEAD, base_ref="main")
    passed = {t.get("id") for t in q.get("tests", []) if t.get("status") in gate.PASSED}
    ed = q.get("envDeploy") or {}
    return (gate._base_ok(mock.Mock(predicate=q), pd) and q.get("outcome") == "pass" and q.get("requiredCoverage") in (1, 1.0)
            and not set(required) - passed and set(required) <= set(q.get("requiredTests") or [])
            and ed.get("headSha") == HEAD and ed.get("digest") == env_digest and q.get("mode") == "full"
            and bool(q.get("reportDigest")))


class RecordTest(unittest.TestCase):
    def test_pass_predicate_satisfies_gate(self):
        plan, pred, subjects, ops = do_record()
        self.assertEqual((plan["attest"], plan["conclusion"], plan["round"]), (True, "success", 1))
        self.assertTrue(gate_sdlc08(pred))
        self.assertEqual((pred["checkRunId"], pred["qaAppId"], pred["loopKey"]), (9, APP, f"release:{SLUG}"))
        self.assertFalse(list(floats(pred)), "canonical predicates carry no floats")
        for s in (f"sox:commit:{HEAD}", "sox:pr:12", f"sox:release:{SLUG}", "sox:jira:FRQ-2", "sox:jira:FRQ-3",
                  "sox:report:" + pred["reportDigest"]):
            self.assertIn(s, subjects)
        self.assertEqual(len(ops), 2)

    def test_any_non_pass_fails(self):
        for st in ("failed", "error", "skipped", "missing"):
            plan, pred, _, _ = do_record({REQ[0]: "passed", REQ[1]: st})
            self.assertEqual((plan["attest"], plan["conclusion"], pred["outcome"], pred["requiredCoverage"]),
                             (True, "failure", "fail", 0), st)
            self.assertFalse(gate_sdlc08(pred))
        plan, pred, _, _ = do_record({REQ[0]: "passed"})
        self.assertEqual(pred["outcome"], "fail")

    def test_extra_reported_passes_do_not_count(self):
        plan, pred, _, _ = do_record({REQ[0]: "passed", "services.api.test_app.T.other": "passed"})
        self.assertEqual(pred["outcome"], "fail")
        self.assertEqual([t["id"] for t in pred["tests"]], sorted(REQ))

    def test_test_job_failure_signs_nothing(self):
        for r in ("failure", "cancelled", "skipped", ""):
            plan, pred, _, _ = do_record(result=r)
            self.assertEqual((plan["attest"], plan["conclusion"]), (False, "failure"), r)
            self.assertIsNone(pred)

    def test_unreadable_results_sign_nothing(self):
        for b in ("not base64!", "aGVsbG8="):
            plan, pred, _, _ = do_record(results_b64=b)
            self.assertEqual((plan["attest"], plan["conclusion"]), (False, "failure"))

    def test_changed_env_or_moved_head_signs_nothing(self):
        plan, pred, _, _ = do_record(fetch=make_fetch(envs=[env_att(digest="sha256:" + "4" * 64)]))
        self.assertEqual((plan["attest"], plan["title"]), (False, "QA inputs changed"))
        plan, _, _, _ = do_record(head_moved=True)
        self.assertEqual((plan["attest"], plan["title"]), (False, "Superseded"))

    def test_existing_result_never_resigned(self):
        ex = mock.Mock(predicate={"outcome": "fail"}, digest="sha256:x")
        plan, pred, _, _ = do_record(existing=ex)
        self.assertEqual((plan["attest"], plan["conclusion"]), (False, "failure"))
        self.assertIsNone(pred)

    def test_completed_run_left_alone(self):
        plan, _, _, _ = do_record(status="completed")
        self.assertTrue(plan["closed"])

    def test_tenth_failing_round_escalates(self):
        plan, pred, _, ops = do_record({REQ[0]: "failed", REQ[1]: "passed"}, prior=[str(i) * 40 for i in range(9)])
        self.assertEqual(pred["round"], 10)
        self.assertIn("Blocked - Human Escalation", [o.get("to") for o in ops])


class FinishTest(unittest.TestCase):
    def _finish(self, plan, env, status="in_progress"):
        out = tempfile.mkdtemp()
        if plan is not None:
            json.dump(plan, open(f"{out}/plan.json", "w"))
        gh = mock.Mock()
        gh.get.return_value = {"id": 9, "head_sha": HEAD, "status": status}
        with mock.patch.object(qa_agent, "GitHub", return_value=gh), \
             mock.patch.object(qa_agent.checks, "complete") as complete, \
             mock.patch.dict(os.environ, {"APP_TOKEN": "t", "CHECK_RUN_ID": "9", **env}):
            qa_agent.finish(mock.Mock(out=out))
        return complete

    def test_no_plan_completes_failure(self):
        c = self._finish(None, {})
        self.assertEqual((c.call_args.args[3], c.call_args.kwargs["run_id"]), ("failure", 9))

    def test_attest_failure_completes_failure(self):
        c = self._finish({"attest": True, "conclusion": "success", "title": "t", "summary": ""},
                         {"ATTEST_OUTCOME": "failure", "ATTESTATION_URL": ""})
        self.assertEqual(c.call_args.args[3], "failure")

    def test_attested_pass_succeeds(self):
        c = self._finish({"attest": True, "conclusion": "success", "title": "t", "summary": "s"},
                         {"ATTEST_OUTCOME": "success", "ATTESTATION_URL": "https://x"})
        self.assertEqual(c.call_args.args[3], "success")
        self.assertIn("https://x", c.call_args.args[6])

    def test_existing_verified_pass_is_reposted(self):
        c = self._finish({"attest": False, "conclusion": "success", "title": "t", "summary": ""}, {})
        self.assertEqual(c.call_args.args[3], "success")

    def test_completed_untouched(self):
        c = self._finish({"attest": True, "conclusion": "success", "title": "t", "summary": ""},
                         {"ATTEST_OUTCOME": "success", "ATTESTATION_URL": "https://x"}, status="completed")
        c.assert_not_called()


if __name__ == "__main__":
    unittest.main()
