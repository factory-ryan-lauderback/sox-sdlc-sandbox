"""Gate engine, records and CLI against a fake GitHub API, fake verified evidence and fake git.
Run: python3 -m unittest discover -s .sox/tests -p 'test_*.py'"""
import copy
import json
import os
import sys
import tempfile
import types
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
SOX = os.path.dirname(HERE)
sys.path.insert(0, SOX)

from soxlib import gate as G, jcs, records as R, subject as subj  # noqa: E402
from soxlib.policy import Policy  # noqa: E402
from soxlib.scope import ScopeMap  # noqa: E402

REPO = "factory-ryan-lauderback/sox-sdlc-sandbox"
T0 = 1_800_000_000
IDS = {"dev": 101, "qa": 102, "review": 103, "techlead": 104, "bundler": 105, "gate": 106,
       "reconciler": 107, "evidenceWriter": 108}
H10 = "1" * 40     # story PR head
S1 = "2" * 40      # squash of story PR 10 on release/autopay
R1 = "3" * 40      # release PR head
R2 = "4" * 40      # release PR head after a fix
M0 = "5" * 40      # main tip
B0 = "6" * 40      # merge base of release and main
MERGE = "7" * 40   # merge commit of the release PR
IMG = "sha256:" + "ab" * 32
DEV, QA, BUNDLER = "acme-dev-agent[bot]", "acme-qa-agent[bot]", "acme-release-bundler[bot]"
AMAN = {"login": "factory-aman", "id": 320644755}
RIYA = {"login": "factory-riya-bhivare", "id": 351550958}
OWNER = {"login": "factory-ryan-lauderback", "id": 344896283}
AMAN_J = "712020:ae7e6a76-96e0-4d91-a2ac-857b21c164cd"
SHARED_J = "712020:049f9e8f-c2c3-47f9-a0d0-bd0578d23457"
PO_J = "712020:00000000-0000-0000-0000-0000000000po"


def jira_entry(eid, at, account, items, account_type="atlassian"):
    return {"id": str(eid), "created": t(at), "author": {"accountId": account, "accountType": account_type},
            "items": items}


def to_status(status, frm="10070"):
    return {"field": "status", "fieldtype": "jira", "from": frm, "to": str(status)}


def edit(field="description"):
    return {"field": field, "fieldtype": "jira", "from": None, "to": None}


def req_approval(changelog, reporter=PO_J, creator=PO_J, at=10):
    return Att("requirement-approval", [("jira", "FRQ-1")],
               {"issueKey": "FRQ-1", "contentDigest": "sha256:req", "reporter": reporter,
                "creator": creator, "changelog": changelog}, at)


def approved_log():
    return [jira_entry(1, 2, PO_J, [edit()]), jira_entry(2, 5, AMAN_J, [to_status("10071")])]


def policy():
    with open(os.path.join(SOX, "trust-policy.yaml")) as fh:
        d = json.load(fh)
    for role, i in IDS.items():
        d["apps"][role]["id"] = i
    return Policy(json.dumps(d).encode())


def t(x):
    return G.iso(T0 + x)


def run_uri(run, attempt=1):
    return f"https://github.com/{REPO}/actions/runs/{run}/attempts/{attempt}"


class Att:
    def __init__(self, name, subjects, predicate, at, digest=None, run=None, attempt=1):
        self.name, self.subjects, self.predicate = name, subjects, predicate
        self.identity = {"runInvocationURI": run_uri(run, attempt)} if run is not None else {}
        self.integrated_time = T0 + at
        self.digest = digest or "sha256:" + jcs.digest([name, subjects, predicate, at])[7:]

    @property
    def time_iso(self):
        return G.iso(self.integrated_time)


class FakeEvidence:
    def __init__(self, atts):
        self.atts = atts

    def get(self, kind, ident, predicate=None, before=None):
        out = [a for a in self.atts if (kind, str(ident)) in a.subjects
               and (predicate is None or a.name == predicate)
               and (before is None or a.integrated_time <= before)]
        return sorted(out, key=lambda a: a.integrated_time)

    def latest(self, kind, ident, predicate, where=None, before=None):
        items = [a for a in self.get(kind, ident, predicate, before) if where is None or where(a)]
        return items[-1] if items else None

    def forgeries(self):
        return []


class FakeApi:
    def __init__(self, routes):
        self.routes, self.posted, self.patched, self.calls = routes, [], [], 0

    def _lookup(self, path):
        self.calls += 1
        base, _, q = path.partition("?")
        query = dict(urllib.parse.parse_qsl(q))
        if base not in self.routes:
            raise KeyError(f"unexpected API call {path}")
        v = self.routes[base]
        return copy.deepcopy(v(query) if callable(v) else v)

    def get(self, path):
        return self._lookup(path)

    def paginate(self, path, key=None, limit=100000):
        return self._lookup(path)

    def post(self, path, body):
        self.posted.append((path, body))
        return {"id": 9000 + len(self.posted)}

    def patch(self, path, body):
        self.patched.append((path, body))
        return {}


class FakeMirror:
    def __init__(self, chain, trees=None, parents=None):
        self.chain, self.trees, self._parents = chain, trees or {}, parents or {}

    def fetch_sha(self, sha):
        pass

    def merge_base(self, a, b):
        return B0

    def first_parent_range(self, base, head):
        return self.chain

    def parents(self, sha):
        return self._parents[sha]

    def tree(self, sha):
        return self.trees.get(sha, "t-" + sha[:4])

    def is_ancestor(self, a, b):
        return False

    def clean_merge_tree(self, a, b):
        return None


def push(actor, after, at):
    return {"activity_type": "push", "actor": {"login": actor}, "after": after, "timestamp": t(at)}


def check(name, app, at, run=None):
    """Check run id 'at', posted by workflow run 'run' (default: run id = check id)."""
    return {"name": name, "app": {"id": IDS[app], "slug": f"x-{app}"}, "conclusion": "success",
            "status": "completed", "started_at": t(at - 5), "completed_at": t(at), "id": at,
            "external_id": str(at if run is None else run)}


def paired_att(check_name, head, pr, check_id, run=None, at=None, **pred):
    """The attestation the check's own workflow run signs (spec 2.5)."""
    name = {"sox/review-agent": "review-verdict", "sox/qa-agent": "qa-result",
            "sox/evidence-gate": "gate-decision"}[check_name]
    p = {"prNumber": pr, "headSha": head, "checkRunId": check_id, "baseRef": "refs/heads/main",
         "verdict": "pass", "outcome": "pass", "conclusion": "success"}
    p.update(pred)
    return Att(name, [("commit", head), ("pr", str(pr))], p, (check_id if at is None else at) - 1,
               run=check_id if run is None else run)


class World:
    """One requirement FRQ-1 -> epic FRQ-5 -> story FRQ-6 -> release autopay (services: api)."""

    def __init__(self):
        self.pol = policy()
        self.story_merged = False
        self.release_head = R1
        self.release_reviews = []
        self.release_timeline = []
        self.release_files = [{"filename": "services/api/app.py"}]
        self.story_pusher = DEV
        self.other_release_prs = []
        self.other_releases = []
        self.shared = []
        self.release_merged = False
        self.release_at = {}
        self.release_push_at = 310
        self.workflow_runs = {"sox-review-agent.yml": [], "sox-qa-agent.yml": []}
        self.jobs = {}
        self.gate_runs = {H10: [check("sox/evidence-gate", "gate", 255)]}
        tl, pm = "svc-techlead-agent", "svc-pm-agent"
        plan = {"epicKey": "FRQ-5", "planDigest": "sha256:plan1",
                "stories": [{"key": "FRQ-6", "creator": tl, "type": "dev", "dependsOn": [],
                             "requiredTests": ["T-1", "T-2"]}]}
        self.atts = [
            req_approval(approved_log()),
            Att("pm-decomposition", [("jira", "FRQ-1"), ("jira", "FRQ-5")],
                {"requirementKey": "FRQ-1", "requirementContentDigest": "sha256:req",
                 "epics": [{"key": "FRQ-5", "creator": pm}]}, 20),
            Att("techlead-plan", [("jira", "FRQ-5"), ("jira", "FRQ-6")], plan, 30),
            self.manifest(["api"], 40),
            self.verdict(H10, 10, "release/autopay", "pass", 200, check_id=210),
            Att("gate-decision", [("pr", "10"), ("commit", H10)],
                {"headSha": H10, "conclusion": "success", "prNumber": 10, "checkRunId": 255}, 250,
                run=255),
            Att("dev-change", [("pr", "10"), ("commit", H10)], {"headSha": H10, "prNumber": 10}, 250),
        ]
        self.add_release_evidence(R1)

    def manifest(self, declared, at, stories=("FRQ-6",), slug="autopay", map_digest="map1"):
        return Att("release-manifest", [("release", slug)] + [("jira", s) for s in stories],
                   {"stories": list(stories), "declaredServices": list(declared),
                    "servicesMapDigest": map_digest}, at)

    def verdict(self, head, pr, base, verdict, at, story="FRQ-6", check_id=None):
        return Att("review-verdict", [("commit", head), ("pr", str(pr)), ("jira", story)],
                   {"prNumber": pr, "headSha": head, "baseRef": f"refs/heads/{base}",
                    "verdict": verdict, "outcome": "pass" if verdict == "pass" else verdict,
                    "reviewerAppId": IDS["review"], "authorAppId": IDS["dev"],
                    "checkRunId": check_id}, at, run=check_id)

    def add_release_evidence(self, head, at=400):
        self.release_at[head] = at
        env = Att("env-deploy", [("commit", head), ("pr", "20")],
                  {"headSha": head, "environment": "qa", "envId": "qa-20", "baseRef": "refs/heads/main",
                   "images": [{"service": "api", "digest": IMG}]}, at)
        qa = Att("qa-result", [("commit", head), ("pr", "20"), ("release", "autopay")],
                 {"prNumber": 20, "headSha": head, "baseRef": "refs/heads/main", "outcome": "pass",
                  "requiredCoverage": 1.0, "requiredTests": ["T-1", "T-2"], "mode": "full",
                  "tests": [{"id": "T-1", "status": "passed"}, {"id": "T-2", "status": "passed"}],
                  "envDeploy": {"headSha": head, "digest": env.digest}, "reportDigest": "sha256:rep",
                  "checkRunId": at + 110},
                 at + 100, run=at + 110)
        self.atts += [env, qa, self.verdict(head, 20, "main", "pass", at + 50, check_id=at + 60)]

    # ------------------------------------------------------------ API views
    def pr10(self):
        p = {"number": 10, "state": "closed" if self.story_merged else "open",
             "head": {"sha": H10, "ref": "story/FRQ-6-autopay", "repo": {"full_name": REPO}},
             "base": {"ref": "release/autopay", "sha": B0}, "user": {"login": DEV},
             "commits": 1, "changed_files": 1}
        if self.story_merged:
            p.update({"merged_at": t(300), "merge_commit_sha": S1, "merged_by": {"login": BUNDLER}})
        return p

    def pr20(self):
        p = {"number": 20, "state": "open",
             "head": {"sha": self.release_head, "ref": "release/autopay", "repo": {"full_name": REPO}},
             "base": {"ref": "main", "sha": M0}, "user": {"login": BUNDLER},
             "commits": 1, "changed_files": len(self.release_files)}
        if self.release_merged:
            p.update({"state": "closed", "merged_at": t(900), "merge_commit_sha": MERGE,
                      "merged_by": {"login": BUNDLER}})
        return p

    def api(self):
        r = f"/repos/{REPO}"
        heads = {H10: [self.pr10()], self.release_head: [self.pr20()]}
        routes = {
            f"{r}/pulls/10": self.pr10(),
            f"{r}/pulls/10/commits": [{"sha": H10, "author": {"login": DEV}, "committer": {"login": DEV}}],
            f"{r}/pulls/10/files": [{"filename": "services/api/app.py"}],
            f"{r}/pulls/10/reviews": [],
            f"{r}/issues/10/timeline": [],
            f"{r}/pulls/20": self.pr20(),
            f"{r}/pulls/20/commits": [{"sha": self.release_head, "author": {"login": BUNDLER},
                                       "committer": {"login": BUNDLER}}],
            f"{r}/pulls/20/files": self.release_files,
            f"{r}/pulls/20/reviews": self.release_reviews,
            f"{r}/issues/20/timeline": self.release_timeline,
            f"{r}/activity": lambda q: ([push(self.story_pusher, H10, 100)]
                                        if "story" in q["ref"] else [push(BUNDLER, self.release_head, self.release_push_at)]),
            f"{r}/commits/{H10}/check-runs": {"check_runs": [check("sox/review-agent", "review", 210)]
                                              + self.gate_runs.get(H10, [])},
            f"{r}/commits/{self.release_head}/check-runs": {"check_runs": [
                check("sox/review-agent", "review", self.release_at[self.release_head] + 60),
                check("sox/qa-agent", "qa", self.release_at[self.release_head] + 110)]
                + self.gate_runs.get(self.release_head, [])},
            f"{r}/branches/main": {"commit": {"sha": M0}},
            f"{r}/commits/{S1}/pulls": [self.pr10()],
            f"{r}/pulls": lambda q: [self.pr20()] + self.other_release_prs,
            f"{r}/branches": [{"name": "main"}, {"name": "release/autopay"}]
            + [{"name": f"release/{s}"} for s in self.other_releases],
        }
        for sha, prs in heads.items():
            routes[f"{r}/commits/{sha}/pulls"] = prs
        for wf, runs in self.workflow_runs.items():
            routes[f"{r}/actions/workflows/{wf}/runs"] = runs
        for rid, jobs in self.jobs.items():
            routes[f"{r}/actions/runs/{rid}/jobs"] = jobs
        for p in self.other_release_prs:
            routes[f"{r}/pulls/{p['number']}/reviews"] = p["_reviews"]
            routes[f"{r}/issues/{p['number']}/timeline"] = []
        routes.update(getattr(self, "extra_routes", {}))
        return FakeApi(routes)

    def ctx(self):
        self.story_merged = True if self._release else self.story_merged
        mirror = FakeMirror([(S1, [B0])], trees={MERGE: "tree-R", self.release_head: "tree-R"},
                            parents={MERGE: [M0, self.release_head]})
        services = {"api": {"paths": ["services/api/**"]}, "db": {"paths": ["services/db/**"]}}
        scope = ScopeMap(services, self.shared, self.pol, digest="map1")
        return G.Context(self.pol, self.api(), FakeEvidence(self.atts), mirror, scope)

    _release = False

    def evaluate(self, n, as_of=None):
        self._release = n == 20
        ctx = self.ctx()
        return G.evaluate(ctx, n, as_of=as_of), ctx

    def present_packet(self, at=600):
        ev, _ = self.evaluate(20)
        assert ev.facts.get("packetReady"), [r.to_json() for r in ev.reqs if not r.ok]
        self.atts.append(Att("gate-decision", [("pr", "20"), ("commit", self.release_head)],
                             {"headSha": self.release_head, "prNumber": 20,
                              "packetDigest": ev.facts["packetDigest"], "conclusion": "failure"}, at))
        return ev.facts["packetDigest"]

    def add_gate_success(self, head, at, pr=20, paired=True):
        """A completed sox/evidence-gate success run on head, with its gate-decision if paired."""
        self.gate_runs.setdefault(head, []).append(check("sox/evidence-gate", "gate", at))
        if paired:
            self.atts.append(Att("gate-decision", [("pr", str(pr)), ("commit", head)],
                                 {"headSha": head, "prNumber": pr, "conclusion": "success",
                                  "checkRunId": at}, at - 2, run=at))

    def review(self, user, state, at, commit=None, rid=None):
        self.release_reviews.append({"id": rid or 500 + len(self.release_reviews), "user": dict(user),
                                     "state": state, "commit_id": commit or self.release_head,
                                     "submitted_at": t(at), "body": "x"})


def failed(ev):
    return sorted(r.id for r in ev.reqs if not r.ok)


class TestStoryPR(unittest.TestCase):
    def test_happy_path(self):
        ev, _ = World().evaluate(10)
        self.assertEqual(ev.kind, "story")
        self.assertTrue(ev.ok, [r.to_json() for r in ev.reqs if not r.ok])

    def test_disallowed_pusher_fails(self):
        w = World()
        w.story_pusher = OWNER["login"]
        ev, _ = w.evaluate(10)
        self.assertEqual(failed(ev), ["SDLC-05.pushers#10"])

    def test_reroll_after_fail_blocks_head(self):
        """BP-41: a later pass on the same head does not outrank an earlier changes_requested."""
        w = World()
        w.atts.insert(4, w.verdict(H10, 10, "release/autopay", "changes_requested", 150))
        ev, _ = w.evaluate(10)
        self.assertIn("SDLC-06.review#10", failed(ev))

    def test_rounds_count_distinct_heads(self):
        w = World()
        for i in range(12):
            w.atts.append(w.verdict("9" * 40, 10, "release/autopay", "changes_requested", 50 + i))
        ev, _ = w.evaluate(10)
        self.assertEqual(ev.facts["rounds"]["FRQ-6"], 1)
        self.assertNotIn("LOOP-R#FRQ-6", failed(ev))

    def test_review_for_other_base_does_not_bind(self):
        w = World()
        w.atts = [a for a in w.atts if not (a.name == "review-verdict" and ("pr", "10") in a.subjects)]
        w.atts.append(w.verdict(H10, 10, "release/other", "pass", 200))
        ev, _ = w.evaluate(10)
        self.assertIn("SDLC-06.review#10", failed(ev))

    def test_missing_app_ids_fail_closed(self):
        w = World()
        d = json.loads(w.pol.raw)
        d["apps"]["review"]["id"] = None
        w.pol = Policy(json.dumps(d).encode())
        ev, _ = w.evaluate(10)
        self.assertIn("CC-02.check:sox/review-agent", failed(ev))
        self.assertIn("SDLC-06.review#10", failed(ev))

    def test_shared_head_fails(self):
        w = World()
        other = dict(w.pr10(), number=11)
        w.extra_routes = {f"/repos/{REPO}/commits/{H10}/pulls": [w.pr10(), other]}
        ev, _ = w.evaluate(10)
        self.assertIn("CC-02.unique-head", failed(ev))

    def test_story_branch_into_main_is_f5(self):
        w = World()
        pr = dict(w.pr10(), base={"ref": "main", "sha": M0})
        w.extra_routes = {f"/repos/{REPO}/pulls/10": pr}
        ev, _ = w.evaluate(10)
        self.assertEqual(ev.kind, "invalid-main")
        self.assertIn("F5.topology", failed(ev))


class TestReleasePR(unittest.TestCase):
    def test_awaiting_approval_presents_packet(self):
        w = World()
        ev, ctx = w.evaluate(20)
        self.assertEqual(failed(ev), ["SDLC-09.approval"])
        self.assertTrue(ev.facts["packetReady"])
        names = [e.name for e in R.plan_open(ev, ctx)]
        self.assertIn("gate-decision", names)
        gd = next(e for e in R.plan_open(ev, ctx) if e.name == "gate-decision")
        self.assertEqual(gd.predicate["packetDigest"], ev.facts["packetDigest"])
        self.assertEqual(gd.predicate["conclusion"], "failure")

    def test_approval_after_presentation_passes(self):
        w = World()
        w.present_packet(600)
        w.review(AMAN, "APPROVED", 700)
        ev, ctx = w.evaluate(20)
        self.assertTrue(ev.ok, failed(ev))
        ha = next(e for e in R.plan_open(ev, ctx) if e.name == "human-approval")
        self.assertEqual(ha.predicate["reviewer"]["id"], AMAN["id"])
        self.assertEqual(ha.predicate["packetDigest"], ev.facts["packetDigest"])
        self.assertIn(("release", "autopay"), ha.subjects)
        self.assertIn(("jira", "FRQ-5"), ha.subjects)

    def test_approval_before_presentation_fails(self):
        w = World()
        w.review(AMAN, "APPROVED", 550)
        w.present_packet(600)
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-09.approval", failed(ev))

    def test_owner_and_developer_approvals_do_not_count(self):
        for user in (OWNER, RIYA, dict(AMAN, id=1)):
            w = World()
            w.present_packet(600)
            w.review(user, "APPROVED", 700)
            ev, _ = w.evaluate(20)
            self.assertIn("SDLC-09.approval", failed(ev), user)

    def test_base_change_after_review_fails(self):
        w = World()
        w.present_packet(600)
        w.review(AMAN, "APPROVED", 700)
        w.release_timeline.append({"event": "base_ref_changed", "created_at": t(750)})
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-09.approval", failed(ev))

    def test_qa_any_fail_wins(self):
        w = World()
        w.atts.append(Att("qa-result", [("commit", R1), ("pr", "20")],
                          {"prNumber": 20, "headSha": R1, "baseRef": "refs/heads/main",
                           "outcome": "fail"}, 450))
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-08.qa-any-fail", failed(ev))

    def test_unexplained_release_commit_fails(self):
        w = World()
        ev, ctx = w.evaluate(20)
        ctx2 = w.ctx()
        ctx2.mirror.chain = [(S1, [B0]), ("8" * 40, [S1])]
        ctx2.api.routes[f"/repos/{REPO}/commits/{'8' * 40}/pulls"] = []
        ev = G.evaluate(ctx2, 20)
        self.assertIn("SDLC-10.release-commits", failed(ev))

    def test_control_path_needs_control_owner_and_marks_shortcut(self):
        w = World()
        w.release_files = [{"filename": "services/api/app.py"}, {"filename": ".sox/trust-policy.yaml"}]
        w.atts.append(w.manifest(["api", "controls"], 45))
        w.present_packet(600)
        w.review(AMAN, "APPROVED", 700)
        ev, ctx = w.evaluate(20)
        self.assertTrue(ev.ok, failed(ev))
        self.assertTrue(ev.facts["sodShortcut"])
        ha = next(e for e in R.plan_open(ev, ctx) if e.name == "human-approval")
        self.assertTrue(ha.predicate["controlChange"])
        self.assertTrue(ha.predicate["sodShortcut"])


class TestLoopH(unittest.TestCase):
    """BP-39: a human REQUEST_CHANGES binds the release until a new plan and a new head."""

    def _after_cr(self, dismiss=False, on_closed_pr=False):
        w = World()
        w.present_packet(600)
        if on_closed_pr:
            w.other_release_prs = [{"number": 19, "state": "closed", "head": {"sha": R1, "ref": "release/autopay"},
                                    "_reviews": [{"id": 77, "user": dict(AMAN), "state": "CHANGES_REQUESTED",
                                                  "commit_id": R1, "submitted_at": t(650)}]}]
        else:
            w.review(AMAN, "DISMISSED" if dismiss else "CHANGES_REQUESTED", 650, rid=77)
            if dismiss:
                w.release_timeline.append({"event": "review_dismissed", "created_at": t(660),
                                           "dismissed_review": {"review_id": 77, "state": "changes_requested"}})
        # a fix: new head with fresh evidence, packet presented and approved
        w.release_head = R2
        w.add_release_evidence(R2, 800)
        return w

    def _approve(self, w, at=1000):
        w.present_packet(at)
        w.review(AMAN, "APPROVED", at + 100, commit=R2)
        ev, ctx = w.evaluate(20)
        return ev, ctx

    def test_cr_without_replan_blocks(self):
        for kw in ({}, {"dismiss": True}, {"on_closed_pr": True}):
            w = self._after_cr(**kw)
            ev, _ = w.evaluate(20)
            self.assertIn("LOOP-H", failed(ev), kw)
            self.assertFalse(ev.facts["packetReady"], kw)

    def test_replan_with_new_digest_clears(self):
        w = self._after_cr()
        plan = copy.deepcopy(w.atts[2].predicate)
        plan["planDigest"] = "sha256:plan2"
        w.atts.append(Att("techlead-plan", [("jira", "FRQ-5"), ("jira", "FRQ-6")], plan, 700))
        ev, ctx = self._approve(w)
        self.assertTrue(ev.ok, failed(ev))
        self.assertEqual(ev.facts["packet"]["planDigests"], {"FRQ-5": "sha256:plan2"})

    def test_replan_reusing_old_digest_does_not_clear(self):
        w = self._after_cr()
        w.atts.append(Att("techlead-plan", [("jira", "FRQ-5"), ("jira", "FRQ-6")],
                          copy.deepcopy(w.atts[2].predicate), 700))
        ev, _ = w.evaluate(20)
        self.assertIn("LOOP-H", failed(ev))

    def test_cr_is_recorded_once(self):
        w = World()
        w.present_packet(600)
        w.review(AMAN, "CHANGES_REQUESTED", 650, rid=77)
        ev, ctx = w.evaluate(20)
        hcr = [e for e in R.plan_open(ev, ctx) if e.name == "human-changes-requested"]
        self.assertEqual(len(hcr), 1)
        self.assertIn(("release", "autopay"), hcr[0].subjects)
        w.atts.append(Att("human-changes-requested", hcr[0].subjects,
                          dict(hcr[0].predicate, prNumber=20), 655))
        ev, ctx = w.evaluate(20)
        self.assertEqual([e for e in R.plan_open(ev, ctx) if e.name == "human-changes-requested"], [])


class TestEveryCheckRunBinds(unittest.TestCase):
    """F13, BP-41d: every Review/QA App run on the head binds it; a newer success does not
    clear an earlier run that is in flight, cancelled, or failed before attesting."""

    def _eval(self, earlier, name="sox/review-agent", role="review", as_of=None, merged=False):
        w = World()
        w.release_merged = merged
        if merged:
            w.add_gate_success(R1, 880)
        runs = [check("sox/review-agent", "review", 460), check("sox/qa-agent", "qa", 510)]
        runs += [dict(check(name, role, at), **kw) for at, kw in earlier]
        for at, kw in earlier:
            # Successful extra runs attested like the agent would, so only F13 is under test here.
            if kw.get("conclusion", "success") == "success" and "app" not in kw:
                w.atts.append(paired_att(name, R1, 20, at))
        w.extra_routes = {f"/repos/{REPO}/commits/{R1}/check-runs":
                          {"check_runs": runs + w.gate_runs.get(R1, []), "total_count": len(runs)}}
        ev, _ = w.evaluate(20, as_of=as_of)
        return failed(ev)
    def test_earlier_unfinished_or_failed_run_blocks(self):
        for name, role in (("sox/review-agent", "review"), ("sox/qa-agent", "qa")):
            for kw in ({"status": "in_progress", "conclusion": None, "completed_at": None},
                       {"status": "completed", "conclusion": "cancelled"},
                       {"status": "completed", "conclusion": "failure"},
                       {"status": "completed", "conclusion": "neutral"},
                       {"status": "completed", "conclusion": "skipped"}):
                self.assertIn(f"CC-02.check:{name}", self._eval([(450, kw)], name, role), (name, kw))

    def test_all_success_passes(self):
        f = self._eval([(450, {"status": "completed"})])
        self.assertNotIn("CC-02.check:sox/review-agent", f)

    def test_later_failure_blocks(self):
        self.assertIn("CC-02.check:sox/review-agent",
                      self._eval([(470, {"status": "completed", "conclusion": "failure"})]))

    def test_same_name_from_other_app_is_ignored(self):
        other = {"status": "completed", "conclusion": "failure", "app": {"id": 999, "slug": "spoof"}}
        self.assertNotIn("CC-02.check:sox/review-agent", self._eval([(450, other)]))

    def test_as_of_merge(self):
        # Started after the merge: cannot have influenced it.
        late = {"status": "completed", "conclusion": "failure"}
        self.assertNotIn("CC-02.check:sox/review-agent",
                         self._eval([(950, late)], as_of=T0 + 900, merged=True))
        # Started before the merge, still running at the merge.
        running = {"status": "completed", "conclusion": "success", "completed_at": t(950)}
        self.assertIn("CC-02.check:sox/review-agent",
                      self._eval([(440, running)], as_of=T0 + 900, merged=True))

    def test_more_runs_than_one_page_fails_closed(self):
        w = World()
        w.extra_routes = {f"/repos/{REPO}/commits/{R1}/check-runs":
                          {"check_runs": [check("sox/review-agent", "review", 460)], "total_count": 101}}
        with self.assertRaises(RuntimeError):
            w.evaluate(20)


class TestLoopHBindsStoriesAndEpics(unittest.TestCase):
    """F14, BP-39g: a changes request on one release binds the stories and Epics it covered, so
    re-bundling them under another slug and branch still needs a re-plan."""

    def _world(self):
        w = World()
        w.atts.append(Att("human-changes-requested",
                          [("commit", "8" * 40), ("pr", "19"), ("release", "alpha"),
                           ("jira", "FRQ-5"), ("jira", "FRQ-6")],
                          {"prNumber": 19, "reviewId": 77, "commitId": "8" * 40,
                           "reviewer": dict(AMAN), "submittedAt": t(350)}, 355))
        return w

    def test_rebundle_without_replan_blocks(self):
        ev, _ = self._world().evaluate(20)
        self.assertIn("LOOP-H", failed(ev))
        self.assertEqual([c["pr"] for c in ev.facts["humanChangesRequested"]], [19])

    def test_rebundle_with_replan_clears(self):
        w = self._world()
        plan = copy.deepcopy(w.atts[2].predicate)
        plan["planDigest"] = "sha256:plan2"
        w.atts.append(Att("techlead-plan", [("jira", "FRQ-5"), ("jira", "FRQ-6")], plan, 370))
        w.present_packet(600)
        w.review(AMAN, "APPROVED", 700)
        ev, _ = w.evaluate(20)
        self.assertTrue(ev.ok, failed(ev))

class TestMergedRelease(unittest.TestCase):
    def _merged(self):
        w = World()
        w.present_packet(600)
        w.review(AMAN, "APPROVED", 700)
        w.add_gate_success(R1, 880)
        w.release_merged = True
        ev, ctx = w.evaluate(20)
        ha = Att("human-approval", [("commit", R1), ("pr", "20")],
                 {"prNumber": 20, "commitId": R1, "baseRef": "refs/heads/main",
                  "packetDigest": ev.facts["packetDigest"]}, 710)
        w.atts.append(ha)
        return w, ha

    def test_merge_record_and_release_approval(self):
        w, ha = self._merged()
        ev, ctx = w.evaluate(20, as_of=T0 + 900)
        self.assertTrue(ev.ok, failed(ev))
        emissions, existing = R.plan_merged(ev, ctx)
        self.assertIsNone(existing)
        mr = emissions[0]
        self.assertEqual(mr.name, "merge-record")
        self.assertTrue(mr.predicate["treeMatch"])
        self.assertEqual(mr.predicate["parents"], [M0, R1])
        ras, why = R.release_approvals(ev, ctx, "sha256:mr", mr.predicate)
        self.assertEqual(why, [])
        self.assertEqual(len(ras), 1)
        p = ras[0]["predicate"]
        self.assertEqual((p["service"], p["imageDigest"], p["humanApproval"], p["mergeRecord"],
                          p["environment"], p["mergeCommitSha"]),
                         ("api", IMG, ha.digest, "sha256:mr", "production", MERGE))
        self.assertEqual(ras[0]["image"], f"ghcr.io/{REPO}/api")
        lines = ras[0]["subjects"].splitlines()
        self.assertIn(f"{IMG.split(':')[1]}  ghcr.io/{REPO}/api", lines)
        self.assertIn(f"{subj.key(REPO, 'commit', MERGE)}  sox:commit:{MERGE}", lines)
        self.assertIn(f"{subj.key(REPO, 'release', 'autopay')}  sox:release:autopay", lines)

    def test_no_release_approval_without_tree_match_or_human_approval(self):
        w, ha = self._merged()
        ev, ctx = w.evaluate(20, as_of=T0 + 900)
        ras, why = R.release_approvals(ev, ctx, "sha256:mr", {"treeMatch": False})
        self.assertEqual(ras, [])
        self.assertTrue(any("treeMatch" in x for x in why))
        w.atts.remove(ha)
        ev, ctx = w.evaluate(20, as_of=T0 + 900)
        ras, why = R.release_approvals(ev, ctx, "sha256:mr", {"treeMatch": True})
        self.assertTrue(any("human-approval" in x for x in why))


class TestScope(unittest.TestCase):
    """BP-38: every changed path maps to a declared service through services.yaml on main."""

    def test_unmapped_path_fails_until_shared_maps_it(self):
        w = World()
        w.release_files = [{"filename": "services/api/app.py"}, {"filename": "README.md"}]
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-04.unmapped-path", failed(ev))
        w.shared = [{"path": "README.md", "services": ["api"]}]
        ev, _ = w.evaluate(20)
        self.assertNotIn("SDLC-04.unmapped-path", failed(ev))
        self.assertNotIn("SDLC-04.out-of-scope", failed(ev))

    def test_shared_path_maps_to_every_user(self):
        w = World()
        w.shared = [{"paths": ["libs/common/**"], "services": ["api", "db"]}]
        w.release_files = [{"filename": "libs/common/money.py"}]
        ev, _ = w.evaluate(20)
        self.assertEqual(ev.facts["servicesTouched"], ["api", "db"])
        self.assertIn("SDLC-04.out-of-scope", failed(ev))

    def test_control_path_needs_controls_declared(self):
        w = World()
        w.release_files = [{"filename": "services/api/app.py"}, {"filename": "tools/deploy_order.py"}]
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-04.out-of-scope", failed(ev))
        self.assertIn("controls", ev.facts["servicesTouched"])

    def test_manifest_stale(self):
        w = World()
        w.atts.append(w.manifest(["api"], 45, map_digest="old-map"))
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-04.manifest-stale", failed(ev))
        ev, _ = w.evaluate(10)
        self.assertIn("SDLC-04.manifest-stale", failed(ev))

    def test_story_not_in_manifest(self):
        w = World()
        w.atts.append(w.manifest(["api"], 45, stories=("FRQ-9",)))
        ev, _ = w.evaluate(10)
        self.assertIn("SDLC-04.story-not-in-manifest", failed(ev))

    def test_story_in_two_releases(self):
        w = World()
        w.other_releases = ["other"]
        w.atts.append(w.manifest(["api"], 45, slug="other"))
        ev, _ = w.evaluate(10)
        self.assertIn("SDLC-04.story-in-two-releases", failed(ev))
        w2 = World()
        w2.other_releases = ["other"]
        w2.atts.append(w2.manifest(["api"], 45, stories=("FRQ-77",), slug="other"))
        ev, _ = w2.evaluate(10)
        self.assertNotIn("SDLC-04.story-in-two-releases", failed(ev))


class TestApprovalStale(unittest.TestCase):
    """BP-38e: the packet binds the manifest; a newer manifest or plan voids the approval."""

    def test_packet_binds_manifest(self):
        w = World()
        ev, _ = w.evaluate(20)
        p = ev.facts["packet"]
        man = next(a for a in w.atts if a.name == "release-manifest")
        self.assertEqual(p["releaseManifest"], man.digest)
        self.assertEqual(p["declaredServices"], ["api"])
        self.assertEqual(p["stories"], ["FRQ-6"])

    def _approved(self):
        w = World()
        w.present_packet(600)
        w.review(AMAN, "APPROVED", 700)
        ev, _ = w.evaluate(20)
        self.assertTrue(ev.ok, failed(ev))
        return w

    def test_newer_manifest_makes_approval_stale(self):
        w = self._approved()
        w.atts.append(w.manifest(["api", "db"], 750))
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-09.approval-stale", failed(ev))
        self.assertIn("SDLC-09.approval", failed(ev))
        why = ev.facts["approvalCandidates"]["factory-aman"]
        self.assertTrue(any("releaseManifest" in x and "declaredServices" in x for x in why), why)
        # a new presentation and a new approval clear it
        w.present_packet(800)
        w.review(AMAN, "APPROVED", 900)
        ev, _ = w.evaluate(20)
        self.assertTrue(ev.ok, failed(ev))

    def test_newer_plan_makes_approval_stale(self):
        w = self._approved()
        plan = copy.deepcopy(w.atts[2].predicate)
        plan["planDigest"] = "sha256:plan2"
        w.atts.append(Att("techlead-plan", [("jira", "FRQ-5"), ("jira", "FRQ-6")], plan, 750))
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-09.approval-stale", failed(ev))
        why = ev.facts["approvalCandidates"]["factory-aman"]
        self.assertTrue(any("planDigests" in x for x in why), why)

    def test_signed_approval_for_old_packet_not_used_for_release_approval(self):
        w = self._approved()
        ev, _ = w.evaluate(20)
        w.atts.append(Att("human-approval", [("commit", R1), ("pr", "20")],
                          {"prNumber": 20, "commitId": R1, "baseRef": "refs/heads/main",
                           "packetDigest": "sha256:old", "reviewer": AMAN}, 710))
        w.atts.append(w.manifest(["api", "db"], 750))
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-09.approval-stale", failed(ev))

class TestJiraIdentities(unittest.TestCase):
    """Jira approvals are re-derived from the attested changelog; agent-created issues need the
    role's own account or the shared account with the acting-role marker."""

    def _sdlc01(self, changelog, **kw):
        w = World()
        w.atts[0] = req_approval(changelog, **kw)
        ev, _ = w.evaluate(10)
        return [r for r in ev.reqs if r.id.startswith("SDLC-01.req")][0]

    def test_human_approval_passes(self):
        r = self._sdlc01(approved_log())
        self.assertTrue(r.ok, r.detail)

    def test_rejected_approvals(self):
        cases = {
            "automation author": [jira_entry(2, 5, SHARED_J, [to_status("10071")])],
            "non-atlassian author": [jira_entry(2, 5, AMAN_J, [to_status("10071")], account_type="app")],
            "unlisted human": [jira_entry(2, 5, PO_J, [to_status("10071")])],
            "other status": [jira_entry(2, 5, AMAN_J, [to_status("10073")])],
            "edited after approval": approved_log() + [jira_entry(3, 7, PO_J, [edit("summary")])],
            "attachment after approval": approved_log() + [jira_entry(3, 7, PO_J, [edit("Attachment")])],
            "no changelog": None,
        }
        for name, log in cases.items():
            self.assertFalse(self._sdlc01(log).ok, name)

    def test_reporter_or_creator_cannot_approve(self):
        self.assertFalse(self._sdlc01(approved_log(), reporter=AMAN_J).ok)
        self.assertFalse(self._sdlc01(approved_log(), creator=AMAN_J).ok)

    def test_reapproval_after_edit_passes(self):
        log = approved_log() + [jira_entry(3, 7, PO_J, [edit()]),
                                jira_entry(4, 8, AMAN_J, [to_status("10071", frm="10070")])]
        self.assertTrue(self._sdlc01(log).ok)

    def test_non_content_edit_does_not_reopen(self):
        log = approved_log() + [jira_entry(3, 7, PO_J, [edit("labels")])]
        self.assertTrue(self._sdlc01(log).ok)

    def test_unpinned_status_fails_closed(self):
        w = World()
        d = json.loads(w.pol.raw)
        d["jira"]["approvalStatuses"]["requirementApproval"] = None
        w.pol = Policy(json.dumps(d).encode())
        ev, _ = w.evaluate(10)
        self.assertTrue(any(f.startswith("SDLC-01.req") for f in failed(ev)))

    def _plan_world(self, **story):
        w = World()
        plan = copy.deepcopy(w.atts[2].predicate)
        plan["stories"][0].update(story)
        w.atts[2] = Att("techlead-plan", [("jira", "FRQ-5"), ("jira", "FRQ-6")], plan, 30)
        ev, _ = w.evaluate(10)
        return ev

    def test_shared_identity_creator(self):
        ev = self._plan_world(creator=SHARED_J, actingRole="techlead", actingRoleComment=True)
        self.assertTrue(ev.ok, failed(ev))
        self.assertEqual(len(ev.facts["jiraSharedIdentity"]), 1)
        for bad in ({"actingRole": "pm", "actingRoleComment": True},
                    {"actingRole": "techlead", "actingRoleComment": False},
                    {"actingRole": "techlead"}):
            ev = self._plan_world(creator=SHARED_J, **bad)
            self.assertTrue(any(f.startswith("SDLC-03.plan") for f in failed(ev)), bad)
            self.assertNotIn("jiraSharedIdentity", ev.facts)

    def test_other_creator_fails(self):
        ev = self._plan_world(creator=AMAN_J)
        self.assertTrue(any(f.startswith("SDLC-03.plan") for f in failed(ev)))

    def test_story_type_from_plan(self):
        for bad in (None, "feature", "Dev"):
            ev = self._plan_world(type=bad)
            self.assertTrue(any(f.startswith("SDLC-03.plan") for f in failed(ev)), bad)
        ev = self._plan_world(type="qa")
        self.assertTrue(ev.ok, failed(ev))
        self.assertEqual(ev.facts["storyTypes"], {"FRQ-6": "qa"})


class TestFixturesExcluded(unittest.TestCase):
    """A signed `fixture: true` attestation is never evidence; it is set aside for reporting."""

    def _att(self, i, **pred):
        from soxlib.verify import Attestation
        st = {"subject": [{"name": "sox:pr:0"}], "predicate": dict({"outcome": "pass"}, **pred)}
        return Attestation("review-verdict", st, f"sha256:{i:064x}", {}, T0 + i, {})

    def test_evidence_drops_fixtures(self):
        from soxlib.evidence import Evidence
        real, fx = self._att(1), self._att(2, fixture=True)

        class V:
            policy = None

            def fetch(self, api, kind, ident, predicate=None):
                return [real, fx], []
        ev = Evidence(V(), None)
        self.assertEqual([a.digest for a in ev.get("pr", "0")], [real.digest])
        self.assertEqual([f["digest"] for f in ev.fixture_list()], [fx.digest])
        self.assertEqual(ev.fixture_list()[0]["lookup"], "pr:0")

    def test_fixture_false_is_evidence(self):
        from soxlib.evidence import Evidence
        a = self._att(1, fixture=False)

        class V:
            policy = None

            def fetch(self, api, kind, ident, predicate=None):
                return [a], []
        self.assertEqual(len(Evidence(V(), None).get("pr", "0")), 1)


class TestPolicyJira(unittest.TestCase):
    def _load(self, mutate):
        with open(os.path.join(SOX, "trust-policy.yaml")) as fh:
            d = json.load(fh)
        mutate(d["jira"])
        return Policy(json.dumps(d).encode())

    def test_repo_policy_loads(self):
        p = self._load(lambda j: None)
        self.assertIn(p.jira["sharedAutomationAccount"], p.jira["neverApprovers"])

    def test_rejects_bad_jira_blocks(self):
        from soxlib.policy import PolicyError
        bad = [lambda j: j.update(neverApprovers=[]),
               lambda j: j["humanApprovers"]["requirementApproval"].append(SHARED_J),
               lambda j: j["humanApprovers"].update(domainApproval=AMAN_J),
               lambda j: j["approvalStatuses"].update(requirementApproval="Approved")]
        for m in bad:
            with self.assertRaises(PolicyError):
                self._load(m)

def golive_policy(at=1000, rotations=None, **mut):
    """Trust policy with every App id pinned and a goLive block; rotations: {role: offset}."""
    with open(os.path.join(SOX, "trust-policy.yaml")) as fh:
        d = json.load(fh)
    for role, i in IDS.items():
        d["apps"][role]["id"] = i
    keys = {}
    for role, a in d["apps"].items():
        if role.startswith("$"):
            continue
        keys[a["slug"]] = {"appId": a["id"], "keyFingerprint": "SHA256:" + "A" * 43,
                           "rotationCompletedAt": t((rotations or {}).get(role, 0))}
    d["goLive"].update({"at": t(at), "mainSha": M0, "rulesetVersion": 3, "appKeys": keys})
    for path, value in mut.items():
        node = d
        parts = path.split("__")
        for p in parts[:-1]:
            node = node[p]
        node[parts[-1]] = value
    return Policy(json.dumps(d).encode())


class TestPairedChecks(unittest.TestCase):
    """F16, spec 2.5: an App key can post a success check but cannot sign the attestation it must
    pair with, so an unpaired success is check-without-evidence and blocks."""

    def _world(self, extra_checks=(), atts=()):
        w = World()
        runs = [check("sox/review-agent", "review", 460), check("sox/qa-agent", "qa", 510)]
        runs += list(extra_checks)
        w.extra_routes = {f"/repos/{REPO}/commits/{R1}/check-runs": {"check_runs": runs}}
        w.atts += list(atts)
        return w

    def test_baseline_is_paired(self):
        ev, _ = World().evaluate(20)
        self.assertNotIn("CC-02.check-without-evidence:sox/review-agent", failed(ev))
        self.assertNotIn("CC-02.check-without-evidence:sox/qa-agent", failed(ev))
        e = ev.facts["checks"]["sox/review-agent"][0]
        self.assertTrue(e["paired"])
        self.assertEqual((e["checkRunId"], e["externalId"]), (460, "460"))

    def test_forged_agent_success_blocks(self):
        for name, role in (("sox/review-agent", "review"), ("sox/qa-agent", "qa")):
            w = self._world([check(name, role, 470)])
            ev, _ = w.evaluate(20)
            self.assertIn(f"CC-02.check-without-evidence:{name}", failed(ev), name)
            self.assertNotIn(f"CC-02.check:{name}", failed(ev))

    def test_pairing_mismatches(self):
        c = check("sox/review-agent", "review", 470)
        bad = {
            "other run": paired_att("sox/review-agent", R1, 20, 470, run=999),
            "other check id": paired_att("sox/review-agent", R1, 20, 471, run=470),
            "other head": paired_att("sox/review-agent", R2, 20, 470),
            "not a pass": paired_att("sox/review-agent", R1, 20, 470, verdict="changes_requested"),
            "other repo": Att("review-verdict", [("commit", R1), ("pr", "20")],
                              {"prNumber": 20, "headSha": R1, "checkRunId": 470, "verdict": "pass"}, 469),
        }
        bad["other repo"].identity = {"runInvocationURI": "https://github.com/evil/fork/actions/runs/470/attempts/1"}
        for label, att in bad.items():
            ev, _ = self._world([c], [att]).evaluate(20)
            self.assertIn("CC-02.check-without-evidence:sox/review-agent", failed(ev), label)
        ev, _ = self._world([dict(c, external_id="pr-20")],
                            [paired_att("sox/review-agent", R1, 20, 470)]).evaluate(20)
        self.assertIn("CC-02.check-without-evidence:sox/review-agent", failed(ev))
        ev, _ = self._world([c], [paired_att("sox/review-agent", R1, 20, 470)]).evaluate(20)
        self.assertNotIn("CC-02.check-without-evidence:sox/review-agent", failed(ev))

    def test_run_uri_parsing(self):
        from soxlib import pairing
        a = paired_att("sox/review-agent", R1, 20, 470, run=123456789)
        self.assertEqual(pairing.run_of(a, REPO), ("123456789", 1))
        a.identity = {"runInvocationURI": run_uri(5, 3) + "/extra"}
        self.assertIsNone(pairing.run_of(a, REPO))

    def test_forged_gate_success_on_open_head_blocks(self):
        w = World()
        w.present_packet(600)
        w.review(AMAN, "APPROVED", 700)
        w.add_gate_success(R1, 750, paired=False)
        ev, _ = w.evaluate(20)
        self.assertEqual(failed(ev), ["CC-02.check-without-evidence:sox/evidence-gate", "SDLC-09.packet"])
        w2 = World()
        w2.present_packet(600)
        w2.review(AMAN, "APPROVED", 700)
        w2.add_gate_success(R1, 750)
        ev, _ = w2.evaluate(20)
        self.assertTrue(ev.ok, failed(ev))

    def test_gate_failure_runs_need_no_pair(self):
        w = World()
        w.gate_runs[R1] = [dict(check("sox/evidence-gate", "gate", 610), conclusion="failure")]
        ev, _ = w.evaluate(20)
        self.assertNotIn("CC-02.check-without-evidence:sox/evidence-gate", failed(ev))

    def test_success_gate_decision_signed_every_run_with_check_id(self):
        w = World()
        w.present_packet(600)
        w.review(AMAN, "APPROVED", 700)
        for cid in (4242, 4243):
            ev, ctx = w.evaluate(20)
            ctx.check_run_id = cid
            gd = [e for e in R.plan_open(ev, ctx) if e.name == "gate-decision"]
            self.assertEqual(len(gd), 1)
            self.assertEqual((gd[0].predicate["checkRunId"], gd[0].predicate["conclusion"],
                              gd[0].predicate["headSha"]), (cid, "success", R1))
            self.assertIn(("commit", R1), gd[0].subjects)
            w.atts.append(Att("gate-decision", gd[0].subjects, gd[0].predicate, 710, run=cid))


class TestMergeRecordChecks(unittest.TestCase):
    def _merged(self, paired=True):
        w = World()
        w.present_packet(600)
        w.review(AMAN, "APPROVED", 700)
        w.gate_runs[R1] = [dict(check("sox/evidence-gate", "gate", 650), conclusion="failure")]
        w.add_gate_success(R1, 880, paired=paired)
        w.release_merged = True
        ev, _ = w.evaluate(20)
        w.atts.append(Att("human-approval", [("commit", R1), ("pr", "20")],
                          {"prNumber": 20, "commitId": R1, "baseRef": "refs/heads/main",
                           "packetDigest": ev.facts["packetDigest"]}, 710))
        ev, ctx = w.evaluate(20, as_of=T0 + 900)
        return ev, ctx

    def test_checks_recorded_and_paired(self):
        ev, ctx = self._merged()
        self.assertTrue(ev.ok, failed(ev))
        mr = R.plan_merged(ev, ctx)[0][0].predicate
        self.assertTrue(mr["checksPaired"])
        self.assertEqual(mr["outcome"], "recorded")
        names = [(c["name"], c["checkRunId"]) for c in mr["checks"]]
        self.assertEqual(names, [("sox/evidence-gate", 880), ("sox/qa-agent", 510),
                                 ("sox/review-agent", 460)])
        for c in mr["checks"]:
            self.assertEqual(set(c), {"name", "checkRunId", "appId", "conclusion", "externalId",
                                      "pairedAttestation", "paired"})
            self.assertTrue(c["paired"])
            self.assertTrue(c["pairedAttestation"].startswith("sha256:"))
            self.assertEqual(c["externalId"], str(c["checkRunId"]))
        ras, why = R.release_approvals(ev, ctx, "sha256:mr", mr)
        self.assertEqual(why, [])

    def test_unpaired_gate_success_blocks_merge_record_and_release_approval(self):
        ev, ctx = self._merged(paired=False)
        self.assertIn("CC-02.check:sox/evidence-gate", failed(ev))
        self.assertIn("CC-02.check-without-evidence:sox/evidence-gate", failed(ev))
        mr = R.plan_merged(ev, ctx)[0][0].predicate
        self.assertFalse(mr["checksPaired"])
        self.assertEqual(mr["outcome"], "fail")
        ras, why = R.release_approvals(ev, ctx, "sha256:mr", dict(mr, treeMatch=True))
        self.assertEqual(ras, [])
        self.assertTrue(any("check-without-evidence" in x for x in why), why)


class TestUnattestedJudgingRuns(unittest.TestCase):
    """F17: a judging run that read an LLM verdict without attesting it from the same run attempt
    blocks the head, whatever happened to its check run."""
    STEP = "Review (droid exec, read-only)"

    def _job(self, name, at, step=STEP, attempt=1, step_conclusion="success"):
        steps = [{"name": "prepare", "status": "completed", "conclusion": "success", "started_at": t(at - 1)}]
        if step:
            steps.append({"name": step, "status": "completed", "conclusion": step_conclusion,
                          "started_at": None if step_conclusion == "skipped" else t(at)})
        return {"name": name, "run_attempt": attempt, "status": "completed", "conclusion": "success",
                "started_at": t(at - 2), "steps": steps}

    def _world(self, jobs, wf="sox-review-agent.yml", run=7001, created=450):
        w = World()
        w.workflow_runs[wf] = [{"id": run, "path": f".github/workflows/{wf}", "created_at": t(created),
                                "run_attempt": max(j["run_attempt"] for j in jobs), "display_title": wf}]
        w.jobs[run] = jobs
        return w

    def test_unattested_review_run_blocks(self):
        w = self._world([self._job("review (20)", 455)])
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-06.unattested-judging-run#20", failed(ev))
        self.assertEqual(ev.facts["judgingRuns"]["review#20"][0]["runId"], "7001")

    def test_attested_from_same_run_passes(self):
        w = self._world([self._job("review (20)", 455)])
        w.atts.append(paired_att("sox/review-agent", R1, 20, 9999, run=7001, at=458))
        ev, _ = w.evaluate(20)
        self.assertNotIn("SDLC-06.unattested-judging-run#20", failed(ev))

    def test_attested_by_other_attempt_does_not_clear(self):
        w = self._world([self._job("review (20)", 455, attempt=1), self._job("review (20)", 470, attempt=2)])
        w.atts.append(paired_att("sox/review-agent", R1, 20, 9999, run=7001, at=475))
        w.atts[-1].identity = {"runInvocationURI": run_uri(7001, 2)}
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-06.unattested-judging-run#20", failed(ev))

    def test_not_judging_is_ignored(self):
        cases = [self._job("review (20)", 455, step_conclusion="skipped"),   # nothing to judge
                 self._job("review (21)", 455),                              # another PR
                 self._job("review (20)", 300),                              # before this head
                 self._job("resolve", 455, step=None)]                       # not the judging job
        for job in cases:
            ev, _ = self._world([job]).evaluate(20)
            self.assertNotIn("SDLC-06.unattested-judging-run#20", failed(ev), job["name"])

    def test_qa_run_without_step(self):
        w = self._world([self._job("qa (20)", 455, step=None)], wf="sox-qa-agent.yml")
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-08.unattested-judging-run#20", failed(ev))
        w.atts.append(Att("qa-result", [("commit", R1), ("pr", "20")],
                          {"prNumber": 20, "headSha": R1, "outcome": "fail"}, 458, run=7001))
        ev, _ = w.evaluate(20)
        self.assertNotIn("SDLC-08.unattested-judging-run#20", failed(ev))
        self.assertIn("SDLC-08.qa-any-fail", failed(ev))

    def test_story_pr_is_covered(self):
        w = self._world([self._job("review (10)", 150)])
        ev, _ = w.evaluate(10)
        self.assertIn("SDLC-06.unattested-judging-run#10", failed(ev))

    def test_plain_job_name_is_tied_to_head_by_check_external_id(self):
        w = self._world([self._job("review", 455)])
        ev, _ = w.evaluate(20)
        self.assertNotIn("SDLC-06.unattested-judging-run#20", failed(ev))
        w.gate_runs.setdefault(R1, []).append(check("sox/review-agent", "review", 455, run=7001))
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-06.unattested-judging-run#20", failed(ev))
        w.atts.append(paired_att("sox/review-agent", R1, 20, 9999, run=7001, at=458))
        ev, _ = w.evaluate(20)
        self.assertNotIn("SDLC-06.unattested-judging-run#20", failed(ev))

    def test_plain_job_name_with_pr_in_run_name(self):
        w = self._world([self._job("review", 455)])
        w.workflow_runs["sox-review-agent.yml"][0]["display_title"] = "sox-review-agent pr=20"
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-06.unattested-judging-run#20", failed(ev))
        w.workflow_runs["sox-review-agent.yml"][0]["display_title"] = "sox-review-agent pr=21"
        ev, _ = w.evaluate(20)
        self.assertNotIn("SDLC-06.unattested-judging-run#20", failed(ev))

    def test_judging_after_merge_is_ignored_as_of(self):
        w = self._world([self._job("review (20)", 950)], created=940)
        w.add_gate_success(R1, 880)
        w.release_merged = True
        ev, _ = w.evaluate(20, as_of=T0 + 900)
        self.assertNotIn("SDLC-06.unattested-judging-run#20", failed(ev))

    def test_missing_workflow_file_is_no_runs_only_if_repo_readable(self):
        from soxlib.gate import Context

        class E(Exception):
            status = 404

        class Api:
            checked = []

            def paginate(self, path, key=None, limit=None):
                raise E()

            def require_repo(self, repo):
                self.checked.append(repo)
        ctx = Context(policy(), Api(), FakeEvidence([]))
        self.assertEqual(ctx.workflow_runs(".github/workflows/sox-qa-agent.yml", T0), [])
        self.assertEqual(Api.checked, [REPO])

        class NoRepo(Api):
            def require_repo(self, repo):
                raise RuntimeError("repo not readable")
        with self.assertRaises(RuntimeError):
            Context(policy(), NoRepo(), FakeEvidence([])).workflow_runs(".github/workflows/x.yml", T0)


class TestGoLiveRotation(unittest.TestCase):
    """Spec 7.6: rotation is a go-live precondition; a PR merged after go-live must not rely on a
    pre-rotation App check or push."""

    def test_loader(self):
        from soxlib.policy import PolicyError
        p = golive_policy(rotations={"review": 470})
        self.assertEqual(p.rotation_at("review"), T0 + 470)
        self.assertEqual(p.go_live_at, T0 + 1000)
        self.assertIsNone(policy().go_live_at)
        with self.assertRaises(PolicyError):
            golive_policy(at=400, rotations={"review": 470})
        for bad in ({"goLive__mainSha": None}, {"goLive__rulesetVersion": "3"},
                    {"goLive__at": "not a time"}):
            with self.assertRaises(PolicyError, msg=str(bad)):
                golive_policy(**bad)
        d = json.loads(golive_policy().raw)
        del d["goLive"]["appKeys"]["acme-sox-gate"]
        with self.assertRaises(PolicyError):
            Policy(json.dumps(d).encode())
        d = json.loads(golive_policy().raw)
        d["goLive"]["appKeys"]["acme-sox-gate"]["appId"] = 1
        with self.assertRaises(PolicyError):
            Policy(json.dumps(d).encode())
        d = json.loads(golive_policy().raw)
        d["goLive"]["appKeys"]["acme-sox-gate"]["keyFingerprint"] = "-----BEGIN RSA PRIVATE KEY-----"
        with self.assertRaises(PolicyError):
            Policy(json.dumps(d).encode())

    def _world(self, **rot):
        w = World()
        w.pol = golive_policy(rotations=rot)
        return w

    def test_after_rotation_passes(self):
        ev, _ = self._world(review=200, qa=200, bundler=300).evaluate(20)
        self.assertEqual(failed(ev), ["SDLC-09.approval"])

    def test_pre_rotation_check_fails_then_clears_on_new_run(self):
        w = self._world(review=470)
        ev, _ = w.evaluate(20)
        self.assertIn("CC-02.app-key-pre-rotation:sox/review-agent", failed(ev))
        self.assertIn("CC-02.check:sox/review-agent", failed(ev))
        self.assertEqual([e["checkRunId"] for e in ev.facts["checks"]["sox/review-agent"]
                          if e["preRotation"]], [460])
        runs = [check("sox/review-agent", "review", 460), check("sox/qa-agent", "qa", 510),
                check("sox/review-agent", "review", 520)]
        w.extra_routes = {f"/repos/{REPO}/commits/{R1}/check-runs": {"check_runs": runs}}
        w.atts.append(paired_att("sox/review-agent", R1, 20, 520))
        ev, _ = w.evaluate(20)
        self.assertNotIn("CC-02.app-key-pre-rotation:sox/review-agent", failed(ev))
        self.assertNotIn("CC-02.check:sox/review-agent", failed(ev))

    def test_pre_rotation_unpaired_success_is_an_exposure_finding(self):
        w = self._world(review=470)
        runs = [check("sox/review-agent", "review", 455), check("sox/review-agent", "review", 460),
                check("sox/qa-agent", "qa", 510), check("sox/review-agent", "review", 520)]
        w.extra_routes = {f"/repos/{REPO}/commits/{R1}/check-runs": {"check_runs": runs}}
        w.atts.append(paired_att("sox/review-agent", R1, 20, 520))
        ev, _ = w.evaluate(20)
        self.assertNotIn("CC-02.check-without-evidence:sox/review-agent", failed(ev))
        self.assertEqual([e["checkRunId"] for e in ev.facts["preRotationUnpaired"]], [455])

    def test_backdated_run_on_post_rotation_head_is_not_set_aside(self):
        w = self._world(review=300, qa=300, bundler=300)
        w.release_push_at = 320
        runs = [check("sox/review-agent", "review", 250), check("sox/review-agent", "review", 460),
                check("sox/qa-agent", "qa", 510)]
        w.extra_routes = {f"/repos/{REPO}/commits/{R1}/check-runs": {"check_runs": runs}}
        ev, _ = w.evaluate(20)
        self.assertIn("CC-02.check-without-evidence:sox/review-agent", failed(ev))
        self.assertNotIn("preRotationUnpaired", ev.facts)

    def test_pre_rotation_push_fails_until_new_head(self):
        w = self._world(bundler=320)
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-05.app-key-pre-rotation#20", failed(ev))
        w.release_head = R2
        w.release_push_at = 330
        w.add_release_evidence(R2, 800)
        ev, _ = w.evaluate(20)
        self.assertNotIn("SDLC-05.app-key-pre-rotation#20", failed(ev))

    def test_story_push_carries_into_release(self):
        w = self._world(dev=150)
        ev, _ = w.evaluate(20)
        self.assertIn("SDLC-05.story-pr#10", failed(ev))
        sp = ev.facts["storyPrs"][0]
        self.assertIn("SDLC-05.app-key-pre-rotation#10", sp["failed"])

    def test_merged_before_go_live_is_bootstrap(self):
        w = World()
        w.present_packet(600)
        w.review(AMAN, "APPROVED", 700)
        w.add_gate_success(R1, 880)
        w.release_merged = True
        w.pol = golive_policy(at=1000, rotations={"review": 470, "bundler": 320})
        ev, _ = w.evaluate(20, as_of=T0 + 900)
        self.assertFalse([f for f in failed(ev) if "app-key-pre-rotation" in f])

class TestScopeMapFile(unittest.TestCase):
    def test_repo_services_yaml_loads_and_digest_is_git_blob(self):
        import subprocess
        from soxlib.scope import ScopeError, parse_yaml
        root = os.path.dirname(SOX)
        m = ScopeMap.load(root, policy())
        blob = subprocess.run(["git", "hash-object", os.path.join(SOX, "services.yaml")],
                              capture_output=True, text=True).stdout.strip()
        if blob:
            self.assertEqual(m.digest, blob)
        self.assertEqual(m.map("services/api/app.py"), {"api"})
        self.assertEqual(m.map(".github/workflows/sox-gate.yml"), {"controls"})
        self.assertEqual(m.map("CODEOWNERS"), {"controls"})
        with self.assertRaises(ScopeError):
            parse_yaml("services:\n  - name: a\n      bad: indent\n")
        with self.assertRaises(ScopeError):
            ScopeMap({"api": {"paths": ["services/api/**"]}},
                     [{"path": "x", "services": ["nope"]}])

class TestCli(unittest.TestCase):
    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("gatecli", os.path.join(SOX, "gate.py"))
        self.cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.cli)
        self.tmp = tempfile.mkdtemp()
        self.out_file = os.path.join(self.tmp, "gh_output")
        os.environ["GITHUB_OUTPUT"] = self.out_file

    def tearDown(self):
        os.environ.pop("GITHUB_OUTPUT", None)

    def _run(self, w, make_ctx=None):
        api = w.api()
        orig = self.cli.make_ctx
        self.cli.make_ctx = make_ctx or (lambda p, a, m=None: w.ctx())
        try:
            a = types.SimpleNamespace(pr="20", out=os.path.join(self.tmp, "o"), mirror=None)
            rc = self.cli.cmd_run(a, api=api, policy=w.pol)
        finally:
            self.cli.make_ctx = orig
        return rc, api, a

    def outputs(self):
        with open(self.out_file) as fh:
            return dict(l.rstrip("\n").split("=", 1) for l in fh)

    def test_error_fails_closed(self):
        w = World()
        w._release = True

        def boom(*a, **k):
            raise RuntimeError("API down")
        rc, api, _ = self._run(w, make_ctx=boom)
        self.assertEqual(rc, 1)
        self.assertEqual(api.posted[0][1]["status"], "in_progress")
        self.assertEqual(api.patched[-1][1]["conclusion"], "failure")
        self.assertEqual(self.outputs()["emit-gate-decision"], "false")

    def test_run_then_finish(self):
        w = World()
        w._release = True
        rc, api, a = self._run(w)
        self.assertEqual(rc, 0)
        self.assertEqual(self.outputs()["emit-gate-decision"], "true")
        pred = json.load(open(os.path.join(a.out, "gate-decision.json")))
        self.assertEqual(pred["conclusion"], "failure")
        lines = open(os.path.join(a.out, "gate-decision.subjects")).read().splitlines()
        self.assertEqual(lines, [f"{subj.key(REPO, 'commit', R1)}  sox:commit:{R1}",
                                 f"{subj.key(REPO, 'pr', '20')}  sox:pr:20"])
        self.cli.cmd_finish(a, api=api, policy=w.pol)
        body = api.patched[-1][1]
        self.assertEqual(body["conclusion"], "failure")
        self.assertIn("Approval packet", body["output"]["summary"])

    def test_head_moved_before_finish(self):
        w = World()
        w._release = True
        w.present_packet(600)
        w.review(AMAN, "APPROVED", 700)
        rc, api, a = self._run(w)
        self.assertEqual(json.load(open(os.path.join(a.out, "state.json")))["conclusion"], "success")
        moved = w.api()
        moved.routes[f"/repos/{REPO}/pulls/20"]["head"]["sha"] = R2
        self.cli.cmd_finish(a, api=moved, policy=w.pol)
        self.assertEqual(moved.patched[-1][1]["conclusion"], "failure")

    def test_pr_number_validation(self):
        for bad in ("0", "-1", "1;ls", "", "12a"):
            with self.assertRaises(SystemExit):
                self.cli.pr_number(bad)


if __name__ == "__main__":
    unittest.main()
