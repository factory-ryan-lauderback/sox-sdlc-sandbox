"""Dev Agent: work selection (build, LOOP-R rework, re-plan, burned heads), patch checks, push."""
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
AGENTS = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(AGENTS))
sys.path.insert(0, AGENTS)
import dev_agent as da  # noqa: E402

PLAN_SHA = "ab" * 32
REL = "frq-13-payoff-quote"
REL_SHA = "1" * 40
HEAD = "2" * 40
T0 = 1_800_000_000


def att(kind, pred, t, n=1):
    return types.SimpleNamespace(predicate=pred, digest=f"sha256:{kind}{n:058d}", integrated_time=t)


def story(key, status="Ready for Dev", summary="Add payoff amount to the API", rel=REL):
    return {"key": key, "type": {"name": "Story"}, "status": {"name": status}, "summary": summary,
            "description": "Return payoff_amount in cents.", "parent": "FRQ-14",
            "fixVersions": [{"name": rel, "released": False}] if rel else [], "properties": {}}


def issues(*stories, plan_sha=PLAN_SHA):
    epic = {"key": "FRQ-14", "type": {"name": "Epic"}, "status": {"name": "Plan Ready"}, "summary": "Payoff quote",
            "planMd": {"sha256": plan_sha, "text": "# plan"}, "fixVersions": [], "properties": {}}
    return {i["key"]: i for i in (epic,) + stories}


def plan(entries, t=T0, n=1):
    return att("techlead-plan", {"epicKey": "FRQ-14", "planDigest": f"sha256:{PLAN_SHA}", "stories": entries}, t, n)


def entry(key, typ="dev", deps=(), services=("api",)):
    return {"key": key, "type": typ, "dependsOn": list(deps), "services": list(services),
            "requiredTests": ["services.api.test_app.PayoffTest.test_payoff_amount"]}


class FakeRepo:
    def __init__(self, prs=(), branches=None, merged=(), first_push=None, runs=(), marks=(set(), 0), release_prs=()):
        self.prs, self.branches, self.merged = list(prs), dict({f"release/{REL}": REL_SHA} if branches is None else branches), set(merged)
        self.first, self.runs, self._marks, self.rprs = first_push, list(runs), marks, list(release_prs)

    def open_story_prs(self): return self.prs
    def open_release_prs(self): return self.rprs
    def branch_sha(self, b): return self.branches.get(b)
    def merged_story_keys(self, base): return self.merged
    def first_push_at(self, b): return self.first
    def review_runs(self, head): return self.runs
    def marks(self, n, bots): return self._marks
    def prs_for_head(self, b, state="all"): return []
    def free_branch(self, key, summary): return f"story/{key}-{da.slug(summary, 40)}"


def pr(key="FRQ-15", login="acme-dev-agent[bot]", head=HEAD):
    return {"number": 31, "head": {"sha": head, "ref": f"story/{key}-add-payoff", "repo": {"full_name": da.REPO}},
            "base": {"ref": f"release/{REL}"}, "user": {"login": login}}


def release_pr(head=REL_SHA):
    return {"number": 50, "head": {"sha": head, "ref": f"release/{REL}", "repo": {"full_name": da.REPO}},
            "base": {"ref": "main"}, "user": {"login": "acme-release-bundler[bot]"}}


def qa_fail(tests=(("services.api.test_app.PayoffTest.test_payoff_amount", "failed"),), keys=("FRQ-15",)):
    return att("qa-result", {"outcome": "fail", "jiraKeys": list(keys),
                             "tests": [{"id": i, "status": st} for i, st in tests]}, T0, 9)


def scan(iss, repo, plans, verdict=None, rounds_done=0, now=T0 + 100, qa=None, qa_rounds=0):
    fetch = lambda kind, ident, pred: ([p for p in plans if any(s["key"] == ident for s in p.predicate["stories"])], [])

    def vfh(head, base, predicate="review-verdict"):
        return qa if predicate == "qa-result" else verdict

    def fh(key, predicate="review-verdict"):
        return {str(i) for i in range(qa_rounds if predicate == "qa-result" else rounds_done)}, 0
    with mock.patch.object(da.rounds, "verdict_for_head", side_effect=vfh), \
         mock.patch.object(da.rounds, "failing_heads", side_effect=fh):
        return da.scan(iss, repo, fetch=fetch, now=now)


class SelectBuildTest(unittest.TestCase):
    def test_ready_story_with_verified_plan_builds_on_release_head(self):
        item, ops, log = scan(issues(story("FRQ-15")), FakeRepo(), [plan([entry("FRQ-15")])])
        self.assertEqual((item["mode"], item["role"], item["baseSha"], item["baseBranch"]),
                         ("build", "dev", REL_SHA, f"release/{REL}"))
        self.assertTrue(item["branch"].startswith("story/FRQ-15-"))
        self.assertEqual(ops, [])

    def test_waits_for_plan_attestation_of_current_plan_md(self):
        item, _, log = scan(issues(story("FRQ-15"), plan_sha="cd" * 32), FakeRepo(), [plan([entry("FRQ-15")])])
        self.assertIsNone(item)
        self.assertIn("not attested yet", "\n".join(log))
        item, _, log = scan(issues(story("FRQ-15")), FakeRepo(), [])
        self.assertIsNone(item)

    def test_waits_for_release_branch_and_dependencies(self):
        iss = issues(story("FRQ-15"), story("FRQ-16", summary="Payoff column"))
        plans = [plan([entry("FRQ-15", deps=["FRQ-16"]), entry("FRQ-16", "qa", services=["ui"])])]
        item, _, log = scan(iss, FakeRepo(branches={}), plans)
        self.assertIsNone(item)
        self.assertIn("does not exist yet", "\n".join(log))
        item, _, _ = scan(iss, FakeRepo(), plans)
        self.assertEqual((item["key"], item["role"]), ("FRQ-16", "qa"))  # FRQ-15 waits for FRQ-16
        item, _, _ = scan(issues(story("FRQ-15")), FakeRepo(merged={"FRQ-16"}), plans)
        self.assertEqual(item["key"], "FRQ-15")

    def test_plan_type_not_label_decides_role_and_bad_type_is_skipped(self):
        item, _, log = scan(issues(story("FRQ-15")), FakeRepo(), [plan([entry("FRQ-15", typ=None)])])
        self.assertIsNone(item)

    def test_merged_story_is_marked_done(self):
        item, ops, _ = scan(issues(story("FRQ-15", status="In Review")), FakeRepo(merged={"FRQ-15"}), [plan([entry("FRQ-15")])])
        self.assertIsNone(item)
        self.assertEqual(ops[0], {"op": "transition", "key": "FRQ-15", "to": "Done"})


class SelectLoopTest(unittest.TestCase):
    def setUp(self):
        self.iss = issues(story("FRQ-15", status="In Review"))
        self.plans = [plan([entry("FRQ-15")], t=T0 - 50)]
        self.cr = att("review-verdict", {"outcome": "changes_requested", "findings": [
            {"severity": "blocking", "path": "services/api/app.py", "line": 3, "title": "rounding", "body": "use cents"}]}, T0, 7)

    def test_changes_requested_head_gets_one_rework(self):
        item, _, _ = scan(self.iss, FakeRepo([pr()], first_push=T0 - 10), self.plans, verdict=self.cr, rounds_done=2)
        self.assertEqual((item["mode"], item["baseSha"], item["round"], item["pr"]), ("rework", HEAD, 3, 31))
        ctx, md = da._context(item, self.iss)
        self.assertEqual(ctx["findings"][0]["title"], "rounding")
        self.assertIn("use cents", md)
        # Already attempted without a change: never again for this head.
        item, _, _ = scan(self.iss, FakeRepo([pr()], first_push=T0 - 10, marks=({HEAD}, 0)), self.plans, verdict=self.cr)
        self.assertIsNone(item)

    def test_loop_exhausted_is_left_to_the_escalation(self):
        item, _, log = scan(self.iss, FakeRepo([pr()], first_push=T0 - 10), self.plans, verdict=self.cr, rounds_done=10)
        self.assertIsNone(item)
        self.assertIn("loop exhausted", "\n".join(log))

    def test_escalated_or_human_prs_are_left_alone(self):
        iss = issues(story("FRQ-15", status="Blocked - Human Escalation"))
        self.assertIsNone(scan(iss, FakeRepo([pr()], first_push=T0 - 10), self.plans, verdict=self.cr)[0])
        self.assertIsNone(scan(self.iss, FakeRepo([pr(login="factory-riya-bhivare")]), self.plans, verdict=self.cr)[0])

    def test_plan_newer_than_first_push_rebuilds_or_carries(self):
        newer = [plan([entry("FRQ-15")], t=T0 + 50)]
        item, _, _ = scan(self.iss, FakeRepo([pr()], first_push=T0), newer)
        self.assertEqual((item["mode"], item["baseSha"], item["oldBranch"]), ("carry", REL_SHA, "story/FRQ-15-add-payoff"))
        item, _, _ = scan(issues(story("FRQ-15")), FakeRepo([pr()], first_push=T0), newer)
        self.assertEqual(item["mode"], "rebuild")

    def test_burned_head_without_verdict_gets_fresh_commit_then_escalates(self):
        burned = [{"status": "completed", "conclusion": "failure"}]
        item, _, _ = scan(self.iss, FakeRepo([pr()], first_push=T0 - 10, runs=burned), self.plans)
        self.assertEqual(item["mode"], "rekick")
        item, ops, _ = scan(self.iss, FakeRepo([pr()], first_push=T0 - 10, runs=burned, marks=(set(), 3)), self.plans)
        self.assertIsNone(item)
        self.assertEqual(ops[0], {"op": "transition", "key": "FRQ-15", "to": "Blocked - Human Escalation"})
        hung = [{"status": "in_progress", "started_at": "2027-01-15T08:00:00Z"}]
        self.assertIsNone(scan(self.iss, FakeRepo([pr()], first_push=T0 - 10, runs=hung), self.plans,
                               now=da._time("2027-01-15T09:00:00Z"))[0])
        self.assertEqual(scan(self.iss, FakeRepo([pr()], first_push=T0 - 10, runs=hung), self.plans,
                              now=da._time("2027-01-15T11:00:00Z"))[0]["mode"], "rekick")


class SelectQaLoopTest(unittest.TestCase):
    def setUp(self):
        self.plans = [plan([entry("FRQ-15")], t=T0 - 50)]
        self.ok = att("review-verdict", {"outcome": "pass", "findings": []}, T0, 3)

    def test_failing_story_qa_result_gets_rework(self):
        iss = issues(story("FRQ-15", status="In Review"))
        item, _, log = scan(iss, FakeRepo([pr()], first_push=T0 - 10), self.plans, verdict=self.ok, qa=qa_fail(), qa_rounds=4)
        self.assertEqual((item["mode"], item["trigger"], item["round"], item["role"]), ("rework", "qa", 5, "dev"))
        ctx, md = da._context(item, iss)
        self.assertEqual(ctx["failingTests"], [{"id": "services.api.test_app.PayoffTest.test_payoff_amount", "status": "failed"}])
        self.assertIn("QA failures to fix", md)
        item, _, log = scan(iss, FakeRepo([pr()], first_push=T0 - 10), self.plans, verdict=self.ok, qa=qa_fail(), qa_rounds=10)
        self.assertIsNone(item)
        self.assertIn("loop exhausted", "\n".join(log))

    def test_failing_release_head_gets_one_qafix_by_the_qa_app(self):
        iss = issues(story("FRQ-15", status="Done"), story("FRQ-16", status="Done", summary="Payoff column"))
        e16 = {**entry("FRQ-16", "qa", services=["ui"]), "requiredTests": ["services.ui.test_e2e_payoff.E.test_column"]}
        plans = [plan([e16, entry("FRQ-15")], t=T0 - 50)]
        q = qa_fail(keys=("FRQ-16", "FRQ-15"))
        item, _, _ = scan(iss, FakeRepo(release_prs=[release_pr()]), plans, qa=q, qa_rounds=1)
        self.assertEqual((item["mode"], item["role"], item["key"], item["baseSha"], item["releasePr"], item["round"]),
                         ("qafix", "qa", "FRQ-15", REL_SHA, 50, 2))
        self.assertEqual(item["branch"], f"qa-fix/FRQ-15-qa-{REL_SHA[:10]}")
        ctx, md = da._context(item, iss)
        self.assertEqual((ctx["trigger"], ctx["services"], ctx["pr"]), ("qa", ["api"], None))
        self.assertIn("release PR #50", md)
        # Once per head; never while a qa-fix PR is open; never for an escalated story or exhausted loop.
        attempted = FakeRepo(release_prs=[release_pr()], branches={f"release/{REL}": REL_SHA, item["branch"]: "9" * 40})
        self.assertIsNone(scan(iss, attempted, plans, qa=q)[0])
        self.assertIsNone(scan(iss, FakeRepo(release_prs=[release_pr()], marks=({REL_SHA}, 0)), plans, qa=q)[0])
        open_fix = {**pr("FRQ-15"), "head": {**pr("FRQ-15")["head"], "ref": "qa-fix/FRQ-15-qa-1111111111"}}
        self.assertIsNone(scan(iss, FakeRepo([open_fix], release_prs=[release_pr()], first_push=T0), plans, qa=q)[0])
        esc = issues(story("FRQ-15", status="Blocked - Human Escalation"))
        self.assertIsNone(scan(esc, FakeRepo(release_prs=[release_pr()]), plans, qa=q)[0])
        self.assertIsNone(scan(iss, FakeRepo(release_prs=[release_pr()]), plans, qa=q, qa_rounds=10)[0])
        passing = att("qa-result", {"outcome": "pass", "jiraKeys": ["FRQ-15"], "tests": []}, T0, 9)
        self.assertIsNone(scan(iss, FakeRepo(release_prs=[release_pr()]), plans, qa=passing)[0])

    def test_qa_fix_pr_rework_is_pushed_by_the_qa_app(self):
        iss = issues(story("FRQ-15", status="In Review"))
        fix = {**pr("FRQ-15", login="acme-qa-agent[bot]"), "head": {**pr()["head"], "ref": "qa-fix/FRQ-15-qa-1111111111"}}
        cr = att("review-verdict", {"outcome": "changes_requested", "findings": []}, T0, 7)
        item, _, _ = scan(iss, FakeRepo([fix], first_push=T0 - 10), self.plans, verdict=cr)
        self.assertEqual((item["mode"], item["role"], item["branch"]), ("rework", "qa", "qa-fix/FRQ-15-qa-1111111111"))
        # A re-plan after the qa-fix branch: no rebuild onto a qa-fix branch.
        item, _, log = scan(iss, FakeRepo([fix], first_push=T0 - 100), self.plans, verdict=cr)
        self.assertIsNone(item)


class PathTest(unittest.TestCase):
    def test_paths(self):
        self.assertEqual(da.check_paths(["services/api/app.py"], ["api"]), [])
        for bad in (".github/workflows/x.yml", ".sox/trust-policy.yaml", "services/ui/app.py", "README.md",
                    "services/api/../../tools/x.py", "CODEOWNERS"):
            self.assertTrue(da.check_paths([bad], ["api"]), bad)

    def test_patch_symlink_and_mismatch(self):
        p = b"diff --git a/services/api/l b/services/api/l\nnew file mode 120000\n"
        self.assertIn("patch adds a symlink or submodule", da.patch_problems(p, ["services/api/l"], ["api"]))
        p = b"diff --git a/services/api/app.py b/services/api/app.py\n"
        self.assertIn("patch file list does not match its metadata", da.patch_problems(p, ["services/api/x.py"], ["api"]))


def git(cwd, *a):
    return subprocess.run(["git", "-C", cwd, *a], check=True, capture_output=True).stdout.decode().strip()


class PackagePushTest(unittest.TestCase):
    """Real git: package in the work tree, then push applies the patch onto a bare remote."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.remote = os.path.join(self.tmp, "remote.git")
        subprocess.run(["git", "init", "-q", "--bare", self.remote], check=True)
        self.work = os.path.join(self.tmp, "work")
        os.makedirs(f"{self.work}/services/api")
        git(self.work, "init", "-q")
        with open(f"{self.work}/services/api/app.py", "w") as f:
            f.write("def payoff():\n    return 0\n")
        git(self.work, "add", "-A")
        git(self.work, "-c", "user.name=t", "-c", "user.email=t@x", "commit", "-q", "-m", "base")
        self.base = git(self.work, "rev-parse", "HEAD")
        git(self.work, "push", "-q", self.remote, f"HEAD:refs/heads/release/{REL}")
        self.ctx = os.path.join(self.tmp, "ctx")
        os.makedirs(self.ctx)
        self.context = {"key": "FRQ-15", "role": "dev", "mode": "build", "branch": "story/FRQ-15-add-payoff",
                        "baseBranch": f"release/{REL}", "baseSha": self.base, "pr": None, "head": None,
                        "summary": "Add payoff", "services": ["api"], "requiredTests": ["services.api.test_app.T.t"],
                        "planAttestation": "sha256:p", "planDigest": "sha256:d", "reviewVerdict": None, "round": None}
        da.dump_json(f"{self.ctx}/context.json", self.context)

    def package(self):
        out = os.path.join(self.tmp, "patch")
        droid = os.path.join(self.tmp, "droid.json")
        with open(droid, "w") as f:
            json.dump({"result": '{"summary": "Adds payoff.", "tests": "ok"}', "is_error": False, "session_id": "s"}, f)
        env = {"CONTEXT_DIGEST": da.dir_digest(self.ctx), "GITHUB_OUTPUT": os.devnull}
        with mock.patch.dict(os.environ, env):
            da.package(types.SimpleNamespace(ctx=self.ctx, work=self.work, droid=droid, out=out))
        return out, da.load_json(f"{out}/meta.json")

    def push(self, patchdir, code_result="success", patch_digest=None):
        out = os.path.join(self.tmp, "out")
        gh, app = mock.Mock(), mock.Mock()
        gh.get.return_value = {"id": 777}
        app.request.return_value = {"number": 40, "html_url": "https://github.com/x/y/pull/40"}
        remote = self.remote
        repo = FakeRepo(branches={f"release/{REL}": self.base})

        def pusher(token, base, branch, patch, msg, author, allow_empty):
            return da.commit_and_push(token, base, branch, patch, msg, author, allow_empty, remote=remote)
        env = {"ROLE": "dev", "APP_TOKEN": "t", "CONTEXT_DIGEST": da.dir_digest(self.ctx), "CODE_RESULT": code_result,
               "PATCH_DIGEST": patch_digest or (da.dir_digest(patchdir) if os.path.isdir(patchdir) else "")}
        with mock.patch.dict(os.environ, env), mock.patch.object(da, "GitHub", side_effect=[gh, app]), \
             mock.patch.object(da, "Repo", return_value=repo):
            da.push(types.SimpleNamespace(ctx=self.ctx, patch=patchdir, out=out), pusher=pusher)
        return app, da.load_json(f"{out}/jira-ops.json")

    def test_change_is_applied_committed_as_app_and_pr_opened(self):
        with open(f"{self.work}/services/api/app.py", "a") as f:
            f.write("\n\ndef payoff_amount(p):\n    return p * 108 // 100\n")
        out, meta = self.package()
        self.assertEqual((meta["outcome"], meta["files"]), ("patch", ["services/api/app.py"]))
        app, ops = self.push(out)
        sha = git(self.remote, "rev-parse", "refs/heads/story/FRQ-15-add-payoff")
        self.assertEqual(git(self.remote, "rev-parse", f"{sha}^"), self.base)
        self.assertEqual(git(self.remote, "log", "-1", "--format=%an <%ae>", sha),
                         "acme-dev-agent[bot] <777+acme-dev-agent[bot]@users.noreply.github.com>")
        self.assertIn("payoff_amount", git(self.remote, "show", f"{sha}:services/api/app.py"))
        self.assertIn("Sox-Plan: sha256:p", git(self.remote, "log", "-1", "--format=%B", sha))
        pr_call = app.request.call_args_list[0]
        self.assertEqual(pr_call.args[:2], ("POST", f"/repos/{da.REPO}/pulls"))
        self.assertEqual((pr_call.args[2]["head"], pr_call.args[2]["base"]), ("story/FRQ-15-add-payoff", f"release/{REL}"))
        self.assertEqual(ops[0], {"op": "transition", "key": "FRQ-15", "to": "In Review"})

    def test_control_path_change_is_refused_and_escalated(self):
        os.makedirs(f"{self.work}/.github/workflows")
        with open(f"{self.work}/.github/workflows/evil.yml", "w") as f:
            f.write("on: push\n")
        out, meta = self.package()
        self.assertEqual(meta["outcome"], "rejected")
        app, ops = self.push(out)
        self.assertEqual(ops[0]["to"], "Blocked - Human Escalation")
        self.assertNotIn("story/FRQ-15-add-payoff", git(self.remote, "branch", "--list"))

    def test_no_change_escalates_and_tampered_patch_is_refused(self):
        out, meta = self.package()
        self.assertEqual(meta["outcome"], "empty")
        _, ops = self.push(out)
        self.assertEqual(ops[0]["to"], "Blocked - Human Escalation")
        with open(f"{self.work}/services/api/app.py", "a") as f:
            f.write("x = 1\n")
        out, _ = self.package()
        digest = da.dir_digest(out)
        with open(f"{out}/patch.diff", "ab") as f:
            f.write(b"diff --git a/.sox/x b/.sox/x\n")
        with self.assertRaises(SystemExit):
            self.push(out, patch_digest=digest)


class ReworkPushTest(PackagePushTest):
    def test_rework_fast_forwards_the_story_branch_and_rekick_adds_empty_commit(self):
        git(self.work, "push", "-q", self.remote, "HEAD:refs/heads/story/FRQ-15-add-payoff")
        self.context.update(mode="rework", pr=31, head=self.base, round=2, reviewVerdict="sha256:v")
        da.dump_json(f"{self.ctx}/context.json", self.context)
        with open(f"{self.work}/services/api/app.py", "a") as f:
            f.write("# fixed rounding\n")
        out, meta = self.package()
        cr = types.SimpleNamespace(predicate={"outcome": "changes_requested"})
        story_pr = {"state": "open", "head": {"sha": self.base, "ref": "story/FRQ-15-add-payoff"},
                    "user": {"login": "acme-dev-agent[bot]"}}
        with mock.patch.object(da.rounds, "verdict_for_head", return_value=cr), \
             mock.patch.object(da.rounds, "failing_heads", return_value=({"x"}, 0)), \
             mock.patch.object(mock.Mock, "pr", create=True, return_value=story_pr):
            app, ops = self.push(out)
        sha = git(self.remote, "rev-parse", "refs/heads/story/FRQ-15-add-payoff")
        self.assertEqual(git(self.remote, "rev-parse", f"{sha}^"), self.base)
        self.assertIn("Sox-Review-Verdict: sha256:v", git(self.remote, "log", "-1", "--format=%B", sha))
        self.assertFalse(any(c.args[1].endswith("/pulls") for c in app.request.call_args_list))
        self.assertIn("review round 2", ops[0]["body"])
        # The head moved (the push above): a stale rekick for the old head does nothing.
        self.context.update(mode="rekick")
        da.dump_json(f"{self.ctx}/context.json", self.context)
        with mock.patch.object(mock.Mock, "pr", create=True, return_value={**story_pr, "head": {**story_pr["head"], "sha": sha}}):
            _, ops = self.push(out)
        self.assertEqual(ops, [])
        self.context.update(head=sha, baseSha=sha)
        da.dump_json(f"{self.ctx}/context.json", self.context)
        with mock.patch.object(mock.Mock, "pr", create=True, return_value={**story_pr, "head": {**story_pr["head"], "sha": sha}}):
            app, ops = self.push(out)
        new = git(self.remote, "rev-parse", "refs/heads/story/FRQ-15-add-payoff")
        self.assertEqual(git(self.remote, "rev-parse", f"{new}^{{tree}}"), git(self.remote, "rev-parse", f"{sha}^{{tree}}"))
        self.assertIn(f"rekick head={sha}", app.request.call_args_list[0].args[2]["body"])


class QaFixPushTest(PackagePushTest):
    def push_as(self, role, patchdir, rpr, qa):
        out = os.path.join(self.tmp, "out")
        gh, app = mock.Mock(), mock.Mock()
        gh.get.return_value = {"id": 778}
        gh.pr.return_value = rpr
        app.request.return_value = {"number": 41, "html_url": "https://github.com/x/y/pull/41"}
        remote, repo = self.remote, FakeRepo(branches={f"release/{REL}": self.base})

        def pusher(token, base, branch, patch, msg, author, allow_empty):
            return da.commit_and_push(token, base, branch, patch, msg, author, allow_empty, remote=remote)
        env = {"ROLE": role, "APP_TOKEN": "t", "CONTEXT_DIGEST": da.dir_digest(self.ctx), "CODE_RESULT": "success",
               "PATCH_DIGEST": da.dir_digest(patchdir)}
        with mock.patch.dict(os.environ, env), mock.patch.object(da, "GitHub", side_effect=[gh, app]), \
             mock.patch.object(da, "Repo", return_value=repo), \
             mock.patch.object(da.rounds, "verdict_for_head", return_value=qa), \
             mock.patch.object(da.rounds, "failing_heads", return_value=({"x"}, 0)):
            da.push(types.SimpleNamespace(ctx=self.ctx, patch=patchdir, out=out), pusher=pusher)
        return app, da.load_json(f"{out}/jira-ops.json")

    def test_qafix_branch_from_release_head_and_pr_into_release(self):
        branch = f"qa-fix/FRQ-15-qa-{self.base[:10]}"
        self.context.update(role="qa", mode="qafix", branch=branch, head=self.base, releasePr=50, trigger="qa",
                            qaResult="sha256:q", round=2)
        da.dump_json(f"{self.ctx}/context.json", self.context)
        with open(f"{self.work}/services/api/app.py", "a") as f:
            f.write("# fix payoff rounding\n")
        out, meta = self.package()
        rpr = {"state": "open", "head": {"sha": self.base, "ref": f"release/{REL}"}}
        app, ops = self.push_as("qa", out, rpr, qa_fail())
        sha = git(self.remote, "rev-parse", f"refs/heads/{branch}")
        self.assertEqual(git(self.remote, "rev-parse", f"{sha}^"), self.base)
        self.assertEqual(git(self.remote, "log", "-1", "--format=%an", sha), "acme-qa-agent[bot]")
        self.assertIn("Sox-QA-Result: sha256:q", git(self.remote, "log", "-1", "--format=%B", sha))
        calls = app.request.call_args_list
        self.assertEqual(len(calls), 1)  # the PR only; the release PR is never closed
        self.assertEqual((calls[0].args[2]["head"], calls[0].args[2]["base"]), (branch, f"release/{REL}"))
        self.assertIn("QA fix for release PR #50", calls[0].args[2]["body"])
        # Release head moved since select: nothing pushed.
        self.context.update(branch=f"qa-fix/FRQ-15-qa-{'3' * 10}")
        da.dump_json(f"{self.ctx}/context.json", self.context)
        _, ops = self.push_as("qa", out, {**rpr, "head": {**rpr["head"], "sha": "3" * 40}}, qa_fail())
        self.assertEqual(ops, [])

    def test_qafix_refused_for_dev_role_and_story_modes_on_qa_fix_branches(self):
        out = os.path.join(self.tmp, "nopatch"); os.makedirs(out)
        rpr = {"state": "open", "head": {"sha": self.base, "ref": f"release/{REL}"}}
        self.context.update(role="dev", mode="qafix", branch=f"qa-fix/FRQ-15-qa-{self.base[:10]}", head=self.base, releasePr=50)
        da.dump_json(f"{self.ctx}/context.json", self.context)
        with self.assertRaises(SystemExit):
            self.push_as("dev", out, rpr, qa_fail())
        self.context.update(role="qa", mode="build")
        da.dump_json(f"{self.ctx}/context.json", self.context)
        with self.assertRaises(SystemExit):
            self.push_as("qa", out, rpr, qa_fail())
        self.context.update(role="qa", mode="qafix", branch="story/FRQ-15-add-payoff")
        da.dump_json(f"{self.ctx}/context.json", self.context)
        with self.assertRaises(SystemExit):
            self.push_as("qa", out, rpr, qa_fail())


class GuardTest(unittest.TestCase):
    def run_guard(self, event, allowed="services/api/"):
        env = {**os.environ, "SOX_WORK_DIR": "/w", "SOX_ALLOWED_PATHS": allowed}
        p = subprocess.run([sys.executable, os.path.join(ROOT, ".factory", "hooks", "guard.py")],
                           input=json.dumps(event).encode(), env=env, capture_output=True)
        return p.returncode

    def test_guard(self):
        self.assertEqual(self.run_guard({"tool_name": "Edit", "tool_input": {"file_path": "/w/services/api/app.py"}}), 0)
        self.assertEqual(self.run_guard({"tool_name": "Edit", "tool_input": {"file_path": "/w/.sox/trust-policy.yaml"}}), 2)
        self.assertEqual(self.run_guard({"tool_name": "Create", "tool_input": {"file_path": "/w/services/ui/app.py"}}), 2)
        self.assertEqual(self.run_guard({"tool_name": "ApplyPatch", "tool_input": {
            "input": "*** Begin Patch\n*** Update File: .github/workflows/ci.yml\n"}}), 2)
        self.assertEqual(self.run_guard({"tool_name": "Execute", "tool_input": {
            "command": 'python3 -m unittest discover -s services -p "test_*.py" -t .'}}), 0)
        for cmd in ("git push origin HEAD", "curl https://x", "cat /proc/self/environ", "env", "echo $FACTORY_API_KEY",
                    "sudo ls", "git commit -m x"):
            self.assertEqual(self.run_guard({"tool_name": "Execute", "tool_input": {"command": cmd}}), 2, cmd)


if __name__ == "__main__":
    unittest.main()
