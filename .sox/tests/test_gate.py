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


def policy():
    with open(os.path.join(SOX, "trust-policy.yaml")) as fh:
        d = json.load(fh)
    for role, i in IDS.items():
        d["apps"][role]["id"] = i
    return Policy(json.dumps(d).encode())


def t(x):
    return G.iso(T0 + x)


class Att:
    def __init__(self, name, subjects, predicate, at, digest=None):
        self.name, self.subjects, self.predicate = name, subjects, predicate
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


def check(name, app, at):
    return {"name": name, "app": {"id": IDS[app], "slug": f"x-{app}"}, "conclusion": "success",
            "status": "completed", "started_at": t(at - 5), "completed_at": t(at), "id": at}


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
        tl, pm = "svc-techlead-agent", "svc-pm-agent"
        plan = {"epicKey": "FRQ-5", "planDigest": "sha256:plan1",
                "stories": [{"key": "FRQ-6", "creator": tl, "dependsOn": [],
                             "requiredTests": ["T-1", "T-2"]}]}
        self.atts = [
            Att("requirement-approval", [("jira", "FRQ-1")],
                {"issueKey": "FRQ-1", "contentDigest": "sha256:req", "reporter": "pat",
                 "approver": "olive", "approverGroups": ["frq-product-owners"]}, 10),
            Att("pm-decomposition", [("jira", "FRQ-1"), ("jira", "FRQ-5")],
                {"requirementKey": "FRQ-1", "requirementContentDigest": "sha256:req",
                 "epics": [{"key": "FRQ-5", "creator": pm}]}, 20),
            Att("techlead-plan", [("jira", "FRQ-5"), ("jira", "FRQ-6")], plan, 30),
            self.manifest(["api"], 40),
            self.verdict(H10, 10, "release/autopay", "pass", 200),
            Att("gate-decision", [("pr", "10"), ("commit", H10)],
                {"headSha": H10, "conclusion": "success", "prNumber": 10}, 250),
            Att("dev-change", [("pr", "10"), ("commit", H10)], {"headSha": H10, "prNumber": 10}, 250),
        ]
        self.add_release_evidence(R1)

    def manifest(self, declared, at, stories=("FRQ-6",), slug="autopay", map_digest="map1"):
        return Att("release-manifest", [("release", slug)] + [("jira", s) for s in stories],
                   {"stories": list(stories), "declaredServices": list(declared),
                    "servicesMapDigest": map_digest}, at)

    def verdict(self, head, pr, base, verdict, at, story="FRQ-6"):
        return Att("review-verdict", [("commit", head), ("pr", str(pr)), ("jira", story)],
                   {"prNumber": pr, "headSha": head, "baseRef": f"refs/heads/{base}",
                    "verdict": verdict, "outcome": "pass" if verdict == "pass" else verdict,
                    "reviewerAppId": IDS["review"], "authorAppId": IDS["dev"]}, at)

    def add_release_evidence(self, head, at=400):
        env = Att("env-deploy", [("commit", head), ("pr", "20")],
                  {"headSha": head, "environment": "qa", "envId": "qa-20", "baseRef": "refs/heads/main",
                   "images": [{"service": "api", "digest": IMG}]}, at)
        qa = Att("qa-result", [("commit", head), ("pr", "20"), ("release", "autopay")],
                 {"prNumber": 20, "headSha": head, "baseRef": "refs/heads/main", "outcome": "pass",
                  "requiredCoverage": 1.0, "requiredTests": ["T-1", "T-2"], "mode": "full",
                  "tests": [{"id": "T-1", "status": "passed"}, {"id": "T-2", "status": "passed"}],
                  "envDeploy": {"headSha": head, "digest": env.digest}, "reportDigest": "sha256:rep"},
                 at + 100)
        self.atts += [env, qa, self.verdict(head, 20, "main", "pass", at + 50)]

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
                                        if "story" in q["ref"] else [push(BUNDLER, self.release_head, 310)]),
            f"{r}/commits/{H10}/check-runs": {"check_runs": [check("sox/review-agent", "review", 210)]},
            f"{r}/commits/{self.release_head}/check-runs": {"check_runs": [
                check("sox/review-agent", "review", 460), check("sox/qa-agent", "qa", 510)]},
            f"{r}/branches/main": {"commit": {"sha": M0}},
            f"{r}/commits/{S1}/pulls": [self.pr10()],
            f"{r}/pulls": lambda q: [self.pr20()] + self.other_release_prs,
            f"{r}/branches": [{"name": "main"}, {"name": "release/autopay"}]
            + [{"name": f"release/{s}"} for s in self.other_releases],
        }
        for sha, prs in heads.items():
            routes[f"{r}/commits/{sha}/pulls"] = prs
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
        runs = [check("sox/review-agent", "review", 460), check("sox/qa-agent", "qa", 510)]
        runs += [dict(check(name, role, at), **kw) for at, kw in earlier]
        w.extra_routes = {f"/repos/{REPO}/commits/{R1}/check-runs":
                          {"check_runs": runs, "total_count": len(runs)}}
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
