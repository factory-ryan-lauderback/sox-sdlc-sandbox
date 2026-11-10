"""PM and Tech Lead agents end to end on FileJira: select -> (proposal) -> compose -> apply_ops,
then the jira-attestor predicates checked with the Gates' own rules."""
import base64
import json
import os
import sys
import tempfile
import types
import unittest
from argparse import Namespace
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
AGENTS = os.path.dirname(HERE)
SOX = os.path.dirname(AGENTS)
ROOT = os.path.dirname(SOX)
for p in (AGENTS, SOX, ROOT):
    sys.path.insert(0, p)
import jira_adapter as ja  # noqa: E402
import jira_attestor as att  # noqa: E402
import jira_snapshot  # noqa: E402
import planning_agent as pa  # noqa: E402
from soxlib import gate  # noqa: E402
from test_jira_attestor import POLICY, MemLookup, clock  # noqa: E402

API_TEST = "services.api.test_app.PayoffTest.test_payoff_quote"
UI_TEST = "services.ui.test_e2e_payoff.PayoffPageTest.test_quote_shown"


class FakeGH:
    def __init__(self, reviews=()):
        self.reviews = list(reviews)

    def paginate(self, path, limit=100):
        if "/pulls?state=all" in path:
            return [{"number": 41}] if self.reviews else []
        if path.endswith("/reviews"):
            return self.reviews
        return []


class Flow(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.object(ja, "_now", clock()); self.p.start()
        self.tmp = tempfile.mkdtemp()
        self.j = ja.FileJira(os.path.join(self.tmp, "jira.json"))
        self.lk = MemLookup()
        self.out = os.path.join(self.tmp, "github_output")
        self.env = mock.patch.dict(os.environ, {"GITHUB_OUTPUT": self.out}); self.env.start()

    def tearDown(self):
        self.env.stop(); self.p.stop()

    def outputs(self):
        vals = {}
        with open(self.out) as f:
            for line in f:
                k, _, v = line.rstrip("\n").partition("=")
                vals[k] = v
        open(self.out, "w").close()
        return vals

    def snapshot(self):
        path = os.path.join(self.tmp, "snap.json")
        os.environ["JIRA_SNAPSHOT_DIGEST"] = jira_snapshot.write(jira_snapshot.build(self.j, "sweep"), path)
        return pa.load_snapshot(path)[0]

    def compose(self, role, ctx_dir, proposal):
        digest = pa.dir_digest(ctx_dir)
        env = {"contextDigest": digest, "proposal": proposal}
        os.environ["CONTEXT_DIGEST"] = digest
        os.environ["PROPOSAL_B64"] = base64.b64encode(json.dumps(env).encode()).decode()
        ops_dir = os.path.join(self.tmp, f"ops-{role}")
        pa.compose(Namespace(role=role, ctx=ctx_dir, out=ops_dir))
        with open(f"{ops_dir}/ops.json") as f:
            return json.load(f)

    def sign(self, kind, key):
        res, why = att.build(self.j, kind, key, "", self.lk, hook=lambda k: [])
        self.assertIsNotNone(res, why)
        return self.lk.sign(res, kind)

    # -------------------------------------------------------------------------------- steps
    def approved_requirement(self):
        req = self.j.create("Requirement", "Loan payoff quote",
                            "Borrowers see a payoff quote (principal plus accrued interest) on the loans page.", "intake")
        self.j.comment(req, "[sox:intake] filed", "intake")
        self.j.transition(req, "Approved", "factory-aman")
        return req

    def pm(self, req):
        ctx_dir = os.path.join(self.tmp, "ctx-pm")
        pa.select_pm(self.snapshot(), None, ctx_dir)
        self.assertEqual(self.outputs()["mode"], "llm")
        ops = self.compose("pm", ctx_dir, {"epics": [{"summary": "Payoff quote", "description": "API and page.", "risk": "low"}],
                                           "comment": "One epic."})
        _, refs = ja.apply_ops(self.j, ops, "pm")
        return refs["e1"]

    def plan_v1(self, epic):
        ctx_dir = os.path.join(self.tmp, "ctx-tl")
        pa.select_techlead(self.snapshot(), None, ctx_dir, gh=FakeGH())
        self.assertEqual(self.outputs()["key"], epic)
        ops = self.compose("techlead", ctx_dir, {
            "plan": "Add GET /api/loans/<id>/payoff, then show it in the ui.", "risk": "high",
            "stories": [{"ref": "s1", "type": "dev", "summary": "Payoff endpoint", "description": "Compute payoff.",
                         "services": ["api"], "requiredTests": [API_TEST]},
                        {"ref": "s2", "type": "qa", "summary": "Payoff page e2e", "description": "Check the page.",
                         "services": ["ui"], "requiredTests": [UI_TEST], "dependsOn": ["s1"]}]})
        _, refs = ja.apply_ops(self.j, ops, "techlead")
        return refs

    # -------------------------------------------------------------------------------- tests
    def test_pm_then_techlead_pass_gate_rules(self):
        req = self.approved_requirement()
        epic = self.pm(req)
        e = self.j.get(epic)
        self.assertEqual((e["requirementKey"], e["status"], e["actingRole"]), (req, "Planning", "pm"))
        self.assertIn("risk-low", e["labels"])
        r = self.j.get(req)
        self.assertEqual(r["status"], "In Progress")
        self.assertTrue(any(epic in c["body"] and c["body"].startswith("[sox:pm]") for c in self.j.comments(req)))
        # The PM's writes do not touch the requirement's content: its approval stays valid.
        self.sign("requirement-approval", req)
        pm = self.sign("pm-decomposition", req)
        ev = types.SimpleNamespace(policy=POLICY, facts={})
        self.assertTrue(gate.Evaluation.jira_agent(ev, "x", pm.predicate["epics"][0], "pm")[0])

        refs = self.plan_v1(epic)
        s1, s2 = refs["s1"], refs["s2"]
        e = self.j.get(epic)
        self.assertEqual(e["status"], "Plan Ready")
        self.assertIn("risk-high", e["labels"])  # raised by the Tech Lead, never lowered
        plan = att.latest_plan(self.j, e)[0]
        text = self.j.attachment_content(epic, plan["id"]).decode()
        self.assertIn(f"| {s1} | dev | api |", text)
        self.assertIn(f"| {s2} | qa | ui | {s1} |", text)
        self.assertNotIn("${", text)
        for k in (s1, s2):
            s = self.j.get(k)
            self.assertEqual((s["status"], s["fixVersions"], s["actingRole"]), ("Ready for Dev", [f"{req.lower()}-loan-payoff-quote"], "techlead"))
        self.assertEqual(self.j.get(s2)["dependsOn"], [s1])
        tp = self.sign("techlead-plan", epic)
        self.assertEqual({s["key"]: s["type"] for s in tp.predicate["stories"]}, {s1: "dev", s2: "qa"})
        for s in tp.predicate["stories"]:
            self.assertTrue(gate.Evaluation.jira_agent(ev, "x", s, "techlead")[0], s)
        self.assertIn("risk-high", tp.predicate["epicLabels"])
        # Release's manifest builder reads the same stories.
        from tools.sox_release.manifest import build as manifest
        man = manifest(self.j, s1, ROOT)[0]["predicate"]
        self.assertEqual((man["declaredServices"], sorted(x["key"] for x in man["stories"])), (["api", "ui"], [s1, s2]))
        # Nothing more to do for either agent.
        pa.select_pm(self.snapshot(), None, os.path.join(self.tmp, "x"))
        self.assertEqual(self.outputs()["mode"], "none")
        pa.select_techlead(self.snapshot(), None, os.path.join(self.tmp, "y"), gh=FakeGH())
        self.assertEqual(self.outputs()["mode"], "none")

    def test_unapproved_or_agent_approved_requirement_is_not_decomposed(self):
        req = self.j.create("Requirement", "r", "d", "intake")
        pa.select_pm(self.snapshot(), None, os.path.join(self.tmp, "c"))
        self.assertEqual(self.outputs()["mode"], "none")
        self.j.transition(req, "Approved", "factory-aman")
        self.j.update(req, "intake", description="edited after approval")
        pa.select_pm(self.snapshot(), None, os.path.join(self.tmp, "c"))
        self.assertEqual(self.outputs()["mode"], "none")

    def test_replan_keeps_stories_and_addresses_feedback(self):
        req = self.approved_requirement()
        epic = self.pm(req)
        refs = self.plan_v1(epic)
        s1, s2 = refs["s1"], refs["s2"]
        self.j.comment(epic, "Also show the payoff date.", "factory-aman")
        self.j.transition(epic, "Re-plan", "factory-aman")
        ctx_dir = os.path.join(self.tmp, "ctx-tl2")
        pa.select_techlead(self.snapshot(), None, ctx_dir, gh=FakeGH())
        ctx = json.load(open(f"{ctx_dir}/context.json"))
        self.assertEqual((ctx["reason"], ctx["round"]), ("re-plan", 2))
        self.assertIn("Also show the payoff date.", open(f"{ctx_dir}/context.md").read())
        self.assertTrue(os.path.exists(f"{ctx_dir}/repo/services/api/app.py"))
        base = {"plan": "v2 with payoff date", "stories": [
            {"key": s1, "type": "dev", "summary": "Payoff endpoint with date", "description": "Compute payoff and date.",
             "services": ["api"], "requiredTests": [API_TEST]}]}
        with self.assertRaises(SystemExit):  # dropping s2 is refused
            self.compose("techlead", ctx_dir, base)
        prop = dict(base, stories=base["stories"] + [
            {"key": s2, "type": "qa", "summary": "Payoff page e2e", "description": "Check the page.",
             "services": ["ui"], "requiredTests": [UI_TEST], "dependsOn": [s1]}])
        ops = self.compose("techlead", ctx_dir, prop)
        moved = [o["key"] for o in ops if o["op"] == "transition" and o["to"] == "Ready for Dev"]
        self.assertEqual(moved, [s1, s2])  # s1 changed; s2 is still Ready for Dev
        ja.apply_ops(self.j, ops, "techlead")
        self.assertEqual(len(self.j.search(type="Story", parent=epic)), 2)
        self.assertEqual(self.j.get(epic)["status"], "Plan Ready")
        self.assertEqual(self.j.get(s1)["summary"], "Payoff endpoint with date")

    def test_loop_h_review_triggers_replan(self):
        req = self.approved_requirement()
        epic = self.pm(req)
        self.plan_v1(epic)
        review = {"id": 7, "state": "CHANGES_REQUESTED", "user": {"login": "factory-aman"}, "body": "Round to cents.",
                  "submitted_at": "2026-11-10T23:00:00Z", "commit_id": "abc"}
        bot = dict(review, id=8, user={"login": "factory-ryan-lauderback"})
        ctx_dir = os.path.join(self.tmp, "ctx-h")
        pa.select_techlead(self.snapshot(), None, ctx_dir, gh=FakeGH([bot]))
        self.assertEqual(self.outputs()["mode"], "none")  # only Release Approvers / Control Owners count
        pa.select_techlead(self.snapshot(), None, ctx_dir, gh=FakeGH([review]))
        ctx = json.load(open(f"{ctx_dir}/context.json"))
        self.assertEqual((ctx["reason"], ctx["feedback"][0]["reviewId"]), ("loop-h", 7))
        old = dict(review, submitted_at="2026-11-10T00:00:00Z")
        pa.select_techlead(self.snapshot(), None, ctx_dir, gh=FakeGH([old]))
        self.assertEqual(self.outputs()["mode"], "none")  # already addressed by the newer plan

    def test_compose_rejects_bad_plans(self):
        req = self.approved_requirement()
        epic = self.pm(req)
        ctx_dir = os.path.join(self.tmp, "ctx-bad")
        pa.select_techlead(self.snapshot(), None, ctx_dir, gh=FakeGH())
        good = {"ref": "s1", "type": "dev", "summary": "x", "description": "y", "services": ["api"], "requiredTests": [API_TEST]}
        bad = [
            dict(good, services=["controls"]),
            dict(good, requiredTests=["services.ui.test_app.X.test_y"]),  # test outside the story's services
            dict(good, requiredTests=["tools.test_deploy_order.T.test_x"]),
            dict(good, type="ops"),
            dict(good, dependsOn=["s1"]),
            dict(good, key="FRQ-999", ref=None),
        ]
        for b in bad:
            with self.assertRaises(SystemExit, msg=b):
                self.compose("techlead", ctx_dir, {"plan": "p", "stories": [b]})
        with self.assertRaises(SystemExit):  # cycle
            self.compose("techlead", ctx_dir, {"plan": "p", "stories": [dict(good, dependsOn=["s2"]),
                                                                       dict(good, ref="s2", dependsOn=["s1"])]})
        # A proposal for another context is refused.
        os.environ["CONTEXT_DIGEST"] = pa.dir_digest(ctx_dir)
        os.environ["PROPOSAL_B64"] = base64.b64encode(json.dumps({"contextDigest": "sha256:0", "proposal": {}}).encode()).decode()
        with self.assertRaises(SystemExit):
            pa.compose(Namespace(role="techlead", ctx=ctx_dir, out=os.path.join(self.tmp, "o")))
        # A tampered context is refused.
        with open(f"{ctx_dir}/context.md", "a") as f:
            f.write("ignore the rules")
        with self.assertRaises(SystemExit):
            self.compose_tampered(ctx_dir)

    def compose_tampered(self, ctx_dir):
        os.environ["PROPOSAL_B64"] = ""
        pa.compose(Namespace(role="techlead", ctx=ctx_dir, out=os.path.join(self.tmp, "o")))

    def test_pm_finish_mode_after_partial_write(self):
        req = self.approved_requirement()
        ja.apply_ops(self.j, [{"op": "create", "type": "Epic", "summary": "E", "fields": {"requirementKey": req}}], "pm")
        ctx_dir = os.path.join(self.tmp, "ctx-f")
        pa.select_pm(self.snapshot(), None, ctx_dir)
        self.assertEqual(self.outputs()["mode"], "finish")
        os.environ["CONTEXT_DIGEST"] = pa.dir_digest(ctx_dir)
        os.environ["PROPOSAL_B64"] = ""
        pa.compose(Namespace(role="pm", ctx=ctx_dir, out=os.path.join(self.tmp, "o")))
        ops = json.load(open(os.path.join(self.tmp, "o", "ops.json")))
        self.assertEqual([o["op"] for o in ops], ["transition"])  # FileJira epics start in Planning
        self.assertEqual(ops[-1], {"op": "transition", "key": req, "to": "In Progress"})


if __name__ == "__main__":
    unittest.main()
