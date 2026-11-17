"""Reconciler (evidence spec 7) against a real temporary git repository, fake API and fake
verified evidence. Run: python3 -m unittest discover -s .sox/tests -p 'test_*.py'"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SOX = os.path.dirname(HERE)
sys.path.insert(0, SOX)

from soxlib import jcs, reconcile as RC  # noqa: E402
from soxlib.gitrepo import Mirror  # noqa: E402
from soxlib.policy import Policy  # noqa: E402
from soxlib.verify import parse_time  # noqa: E402

REPO = "factory-ryan-lauderback/sox-sdlc-sandbox"
GATE, REVIEW, ACTIONS = 5702165, 5702162, 15368
NOW = parse_time("2027-01-02T00:00:00Z")
MAX_REPORT = 900_000
TMP = tempfile.TemporaryDirectory()


def tearDownModule():
    TMP.cleanup()


def load_policy(go_live=None):
    with open(os.path.join(SOX, "trust-policy.yaml")) as fh:
        d = json.load(fh)
    if go_live:
        d["goLive"].update({"at": go_live, "mainSha": "0" * 40, "rulesetVersion": 1})
    return Policy(json.dumps(d).encode())


def git(path, *args, date=None):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@x")
    if date:
        env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    return subprocess.run(["git", "-C", path, *args], check=True, capture_output=True, text=True,
                          env=env).stdout.strip()


class Att:
    def __init__(self, name, predicate, digest, run=None):
        self.name, self.predicate, self.digest = name, predicate, digest
        self.identity = {"runInvocationURI": f"https://github.com/{REPO}/actions/runs/{run}/attempts/1"} if run else {}


class FakeEvidence:
    def __init__(self, by_commit=None):
        self.by_commit = by_commit or {}

    def get(self, kind, ident, predicate=None, before=None):
        items = self.by_commit.get(ident, []) if kind == "commit" else []
        return [a for a in items if predicate is None or a.name == predicate]


class FakeApi:
    def __init__(self, prs, checks=None):
        self.prs, self.checks = prs, checks or {}

    def paginate(self, path, key=None, limit=None):
        if "/pulls?" in path:
            return self.prs
        sha = path.split("/commits/")[1].split("/")[0]
        return self.checks.get(sha, [])


class World:
    """main: seed, merge of story branch (PR 1, Jan 1 10:00), merge of PR 2 (Jan 1 12:00)."""

    def __init__(self):
        p = self.path = tempfile.mkdtemp(dir=TMP.name)
        git(p, "init", "-q", "-b", "main")
        git(p, "commit", "-q", "--allow-empty", "-m", "seed", date="2027-01-01T09:00:00Z")
        self.seed = git(p, "rev-parse", "HEAD")
        self.merges, self.inner = [], []
        for i, at in ((1, "2027-01-01T10:00:00Z"), (2, "2027-01-01T12:00:00Z")):
            git(p, "checkout", "-q", "-b", f"b{i}")
            git(p, "commit", "-q", "--allow-empty", "-m", f"work {i}", date=at)
            self.inner.append(git(p, "rev-parse", "HEAD"))
            git(p, "checkout", "-q", "main")
            git(p, "merge", "-q", "--no-ff", "-m", f"Merge pull request #{i}", f"b{i}", date=at)
            self.merges.append(git(p, "rev-parse", "HEAD"))
        self.prs = [{"number": i + 1, "merged_at": t, "merge_commit_sha": m}
                    for i, (m, t) in enumerate(zip(self.merges, ("2027-01-01T10:00:00Z", "2027-01-01T12:00:00Z")))]
        self.checks, self.atts = {}, {}
        self.inventory = {"runId": "9", "at": "2027-01-01T23:00:00Z",
                          "apps": [{"role": {"bundler": "release_bundler", "evidenceWriter": "evidence_writer",
                                             "jiraAttestor": "jira_attestor"}.get(r, r),
                                    "appId": k["appId"], "keyFingerprint": k["keyFingerprint"]}
                                   for r, k in load_policy().data["goLive"]["appKeys"].items()
                                   if not r.startswith("$")]}
        self.explained = {}

    def rec(self, policy=None, evaluate=None, previous=None):
        return RC.Reconciler(policy or load_policy(), FakeApi(self.prs, self.checks),
                             FakeEvidence(self.atts), Mirror(self.path), NOW, previous=previous,
                             inventory=self.inventory, explained=self.explained, evaluate=evaluate)


def merge_record(sha, labels=(), ok=True):
    return Att("merge-record", {"outcome": "recorded" if ok else "fail", "treeMatch": True,
                                "checksPaired": True, "mergeCommitSha": sha, "labels": list(labels)},
               "sha256:mr-" + sha[:8])


def check(cid, sha, app=GATE, name="sox/evidence-gate", conclusion="success", run="77",
          at="2027-01-01T11:00:00Z"):
    return {"id": cid, "name": name, "app": {"id": app}, "head_sha": sha, "status": "completed",
            "conclusion": conclusion, "external_id": run, "started_at": at}


class TestPopulation(unittest.TestCase):
    def test_every_commit_on_main_is_covered_and_flagged(self):
        w = World()
        r = w.rec().report()
        text = json.dumps(r)
        for sha in [w.seed] + w.merges + w.inner:
            self.assertIn(sha, text)
        self.assertEqual(r["populations"]["P1"]["count"], 3)
        self.assertEqual(r["populations"]["P2"]["count"], 2)
        # BP-30b: every row has the required evidence or an exception
        for row in r["rows"]:
            self.assertTrue(set(r["required_steps"]) <= set(row["evidence"]) or row["exception"], row)
            self.assertIn("app-key-exposed-not-rotated", row["labels"])
        self.assertEqual({row["exception"] for row in r["rows"]}, {RC.BOOTSTRAP})
        self.assertEqual(r["openExceptions"], 0)
        self.assertLess(len(json.dumps(r)), MAX_REPORT)

    def test_after_go_live_missing_merge_record_is_an_exception(self):
        w = World()
        w.atts[w.merges[0]] = [merge_record(w.merges[0])]
        pol = load_policy(go_live="2027-01-01T11:00:00Z")
        r = w.rec(pol).report()
        rows = {row["sha"]: row for row in r["rows"]}
        self.assertEqual(rows[w.merges[0]]["exception"], RC.BOOTSTRAP)       # before go-live
        self.assertEqual(rows[w.merges[0]]["result"], "pass")
        late = rows[w.merges[1]]
        self.assertEqual(late["result"], "fail")
        self.assertTrue(late["exception"].startswith("EXC-"))
        self.assertEqual([e["kind"] for e in r["exceptions"]], ["merge-record-missing"])

    def test_after_go_live_gate_reperformance_and_labels(self):
        w = World()
        w.atts[w.merges[1]] = [merge_record(w.merges[1], ["app-key-exposed-not-rotated",
                                                          "sod-shortcut-owner-approver"])]
        pol = load_policy(go_live="2027-01-01T11:00:00Z")

        class Ev:
            def __init__(self, ok):
                self.ok, self.reqs = ok, [] if ok else [type("R", (), {"id": "SDLC-09.approval", "ok": False})()]
        r = w.rec(pol, evaluate=lambda n, at: Ev(True)).report()
        late = [row for row in r["rows"] if row["sha"] == w.merges[1]][0]
        self.assertEqual((late["result"], late["exception"]), ("pass", None))
        self.assertIn("sod-shortcut-owner-approver", late["labels"])
        self.assertEqual(late["evidence"]["merge-record"], "sha256:mr-" + w.merges[1][:8])
        self.assertIsNotNone(r["bundleMerkleRoot"])
        r = w.rec(pol, evaluate=lambda n, at: Ev(False)).report()
        self.assertEqual([e["kind"] for e in r["exceptions"]], ["gate-reperformance-fail"])

    def test_rewritten_history_is_an_exception(self):
        w = World()
        r = w.rec(previous={"digest": "sha256:p", "period_end": "2027-01-01T00:00:00Z",
                            "highWater": {"mainSha": "f" * 40}}).report()
        self.assertIn("history-rewritten", [e["kind"] for e in r["exceptions"]])


class TestAppKeys(unittest.TestCase):
    def test_match_changed_stale_missing(self):
        w = World()
        self.assertTrue(all(k["result"] == "match" for k in w.rec().app_keys()["keys"]))
        w.inventory["apps"][0]["keyFingerprint"] = "SHA256:" + "A" * 43 + "="
        rec = w.rec()
        keys = rec.app_keys()
        self.assertEqual(sum(k["result"] == "app-key-changed" for k in keys["keys"]), 1)
        self.assertEqual([e["kind"] for e in rec.exceptions], ["app-key-changed"])
        w = World()
        w.inventory["at"] = "2026-12-31T21:00:00Z"
        w.inventory["apps"].pop()
        rec = w.rec()
        rec.app_keys()
        self.assertEqual(sorted(e["kind"] for e in rec.exceptions),
                         ["app-inventory-stale", "app-key-unobserved"])
        w.inventory = None
        rec = w.rec()
        rec.app_keys()
        self.assertEqual([e["kind"] for e in rec.exceptions], ["app-inventory-missing"])


class TestCheckRuns(unittest.TestCase):
    def test_pairing_back_scan(self):
        w = World()
        h = w.inner[0]
        w.checks[h] = [check(1, h, run="77"), check(2, h, run="78"), check(3, h, run="79"),
                       check(4, h, conclusion="failure"), check(5, h, app=ACTIONS, name="unit")]
        w.atts[h] = [Att("gate-decision", {"conclusion": "success", "checkRunId": 1, "headSha": h},
                         "sha256:gd1", run="77")]
        w.explained = {"runs": [{"runId": "78", "reason": "red-team F16 impersonation test", "log": "u"}]}
        r = w.rec().check_runs()
        self.assertEqual((r["count"], r["success"], r["paired"], r["explained"]), (4, 3, 1, 1))
        self.assertEqual(r["unexplainedUnpaired"], 1)
        self.assertFalse(r["goLiveReady"])
        open_ = [u for u in r["unpaired"] if "exception" in u]
        self.assertEqual([u["checkRunId"] for u in open_], [3])
        rec = w.rec(load_policy(go_live="2027-01-01T10:30:00Z"))
        rec.check_runs()
        self.assertEqual([e["kind"] for e in rec.exceptions], ["check-without-evidence"])


class TestChain(unittest.TestCase):
    def test_index_chain(self):
        w = World()
        first = w.rec().report()
        self.assertIsNone(first["previousReport"])
        self.assertEqual(RC.check_chain([], first), [])
        e1 = RC.index_entry(first, "reports/a.json")
        self.assertEqual(e1["digest"], jcs.digest(first))
        rec = w.rec(previous=e1)
        rec.now = NOW + 86400
        second = rec.report()
        self.assertEqual(second["previousReport"], e1["digest"])
        self.assertEqual(second["period"]["from"], first["period"]["to"])
        self.assertEqual(RC.check_chain([e1], second), [])
        bad = dict(second, previousReport="sha256:other")
        self.assertTrue(RC.check_chain([e1], bad))
        gap = dict(second, period={"from": "2027-01-05T00:00:00Z", "to": second["period"]["to"]})
        self.assertTrue(RC.check_chain([e1], gap))
        self.assertTrue(RC.check_chain([e1], dict(first, previousReport=e1["digest"],
                                                  period={"from": e1["period_end"], "to": "x"})))
        self.assertTrue(RC.check_chain([], second))

    def test_merkle_root(self):
        self.assertIsNone(RC.merkle_root([]))
        a = RC.merkle_root(["sha256:a", "sha256:b", "sha256:c"])
        self.assertEqual(a, RC.merkle_root(["sha256:c", "sha256:a", "sha256:b", "sha256:a"]))
        self.assertNotEqual(a, RC.merkle_root(["sha256:a", "sha256:b"]))


if __name__ == "__main__":
    unittest.main()
