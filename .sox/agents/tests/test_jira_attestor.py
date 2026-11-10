"""sox-jira-attestor predicates, checked with the Gates' own rules (soxlib.gate)."""
import itertools
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
AGENTS = os.path.dirname(HERE)
SOX = os.path.dirname(AGENTS)
sys.path.insert(0, AGENTS)
sys.path.insert(0, SOX)
import jira_adapter as ja  # noqa: E402
import jira_attestor as att  # noqa: E402
from soxlib import gate  # noqa: E402
from soxlib.policy import Policy  # noqa: E402

POLICY = Policy.load(os.path.join(SOX, "trust-policy.yaml"))
AMAN = "712020:ae7e6a76-96e0-4d91-a2ac-857b21c164cd"
AUTOMATION = "712020:049f9e8f-c2c3-47f9-a0d0-bd0578d23457"


class FakeAtt:
    def __init__(self, kind, pred, n):
        self.predicate, self.digest, self.integrated_time = pred, f"sha256:{kind}{n:060d}", n


class MemLookup(att.Lookup):
    """Signed predicates kept in memory, keyed by subject, like the attestations store."""

    def __init__(self):
        super().__init__(fetch=lambda *a: [])
        self.store, self.n = [], itertools.count(1)

    def sign(self, res, kind):
        a = FakeAtt(kind, res["predicate"], next(self.n))
        self.store.append((kind, set(res["subjects"]), a))
        return a

    def fetch(self, kind, ident, predicate):
        return [a for k, subs, a in self.store if k == predicate and (kind, ident) in subs]


def clock():
    c = itertools.count(0)
    return lambda: "2026-11-10T10:%02d:%02dZ" % divmod(next(c), 60)


class Chain(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.object(ja, "_now", clock()); self.p.start()
        self.j = ja.FileJira(os.path.join(tempfile.mkdtemp(), "jira.json"))
        self.lk = MemLookup()

    def tearDown(self):
        self.p.stop()

    def sign(self, kind, key, release=""):
        res, why = att.build(self.j, kind, key, release, self.lk, hook=lambda k: [])
        self.assertIsNotNone(res, why)
        return self.lk.sign(res, kind)

    def requirement(self):
        key = self.j.create("Requirement", "Loan payoff quote", "Borrowers can see a payoff quote.", "intake")
        self.j.comment(key, "[sox:intake] filed", "intake")
        return key

    def test_requirement_approval_by_human_passes_gate_rule(self):
        key = self.requirement()
        self.assertEqual(att.build(self.j, "requirement-approval", key, "", self.lk)[0], None)
        self.j.transition(key, "Approved", "factory-aman")
        a = self.sign("requirement-approval", key)
        p = a.predicate
        self.assertEqual((p["approver"], p["reporter"], p["creator"], p["step"]), (AMAN, "svc-intake-agent", "svc-intake-agent", "SDLC-01"))
        self.assertEqual(p["changelog"], self.j.changelog(key))
        ok, detail = gate.jira_human_approval(POLICY, p, "requirementApproval")
        self.assertTrue(ok, detail)
        # Unchanged: nothing new to sign.
        self.assertIsNone(att.build(self.j, "requirement-approval", key, "", self.lk)[0])

    def test_edit_after_approval_reopens_it(self):
        key = self.requirement()
        self.j.transition(key, "Approved", "factory-aman")
        self.sign("requirement-approval", key)
        self.j.update(key, "intake", description="changed scope")
        self.assertIsNone(att.build(self.j, "requirement-approval", key, "", self.lk)[0])
        self.j.transition(key, "Spec Review", "intake")
        self.j.transition(key, "Approved", "factory-aman")
        a = self.sign("requirement-approval", key)
        self.assertTrue(gate.jira_human_approval(POLICY, a.predicate, "requirementApproval")[0])

    def test_non_human_approver_is_signed_but_gate_rejects(self):
        key = self.requirement()
        self.j.transition(key, "Approved", "automation-bot")  # FileJira only: an asserted non-human
        p = self.sign("requirement-approval", key).predicate
        self.assertFalse(gate.jira_human_approval(POLICY, p, "requirementApproval")[0])

    def full_chain(self):
        req = self.requirement()
        self.j.transition(req, "Approved", "factory-aman")
        ra = self.sign("requirement-approval", req)
        _, refs = ja.apply_ops(self.j, [
            {"op": "create", "ref": "e", "type": "Epic", "summary": "Payoff quote", "fields": {"requirementKey": req, "idempotencyKey": "pm:x"}},
            {"op": "transition", "key": req, "to": "In Progress"}], "pm")
        epic = refs["e"]
        pm = self.sign("pm-decomposition", req)
        _, refs = ja.apply_ops(self.j, [
            {"op": "create", "ref": "s1", "type": "Story", "summary": "api", "parent": epic,
             "fields": {"storyType": "dev", "services": ["api"], "requiredTests": ["api:test_payoff"], "idempotencyKey": "tl:1"}},
            {"op": "create", "ref": "s2", "type": "Story", "summary": "qa", "parent": epic,
             "fields": {"storyType": "qa", "services": ["ui"], "dependsOn": ["$s1"], "idempotencyKey": "tl:2"}},
            {"op": "attach", "key": epic, "filename": "plan.md", "content": "# plan v1"},
            {"op": "transition", "key": epic, "to": "Plan Ready"}], "techlead")
        tp = self.sign("techlead-plan", epic)
        return req, epic, refs, ra, pm, tp

    def test_chain_links_and_acting_roles(self):
        req, epic, refs, ra, pm, tp = self.full_chain()
        self.assertEqual(pm.predicate["upstream"], [ra.digest])
        self.assertEqual(pm.predicate["requirementContentDigest"], ra.predicate["contentDigest"])
        e = pm.predicate["epics"][0]
        self.assertEqual((e["key"], e["actingRole"], e["actingRoleComment"]), (epic, "pm", True))
        ev = types.SimpleNamespace(policy=POLICY, facts={})
        self.assertTrue(gate.Evaluation.jira_agent(ev, "x", e, "pm")[0])
        self.assertEqual(tp.predicate["upstream"], [pm.digest])
        types_ = {s["key"]: s["type"] for s in tp.predicate["stories"]}
        self.assertEqual(types_, {refs["s1"]: "dev", refs["s2"]: "qa"})
        for s in tp.predicate["stories"]:
            self.assertTrue(gate.Evaluation.jira_agent(ev, "x", s, "techlead")[0], s)
            self.assertFalse(gate.Evaluation.jira_agent(ev, "x", s, "pm")[0])
        self.assertEqual(tp.predicate["servicesTouched"], ["api", "ui"])

    def test_shared_account_needs_property_and_prefixed_comment(self):
        ev = types.SimpleNamespace(policy=POLICY, facts={})
        good = {"creator": AUTOMATION, "actingRole": "techlead", "actingRoleComment": True}
        self.assertTrue(gate.Evaluation.jira_agent(ev, "x", good, "techlead")[0])
        self.assertFalse(gate.Evaluation.jira_agent(ev, "x", {**good, "actingRoleComment": False}, "techlead")[0])
        # acting() only counts a prefixed comment written by the creator.
        k = self.j.create("Story", "s", "", "techlead")
        self.assertFalse(att.acting(self.j, self.j.get(k))["actingRoleComment"])
        self.j.comment(k, "[sox:techlead] by someone else", "pm")
        self.assertFalse(att.acting(self.j, self.j.get(k))["actingRoleComment"])
        self.j.comment(k, "[sox:techlead] mine", "techlead")
        self.assertTrue(att.acting(self.j, self.j.get(k))["actingRoleComment"])

    def test_pm_decomposition_needs_verified_requirement_approval(self):
        req = self.requirement()
        ja.apply_ops(self.j, [{"op": "create", "type": "Epic", "summary": "E", "fields": {"requirementKey": req}},
                              {"op": "transition", "key": req, "to": "In Progress"}], "pm")
        res, why = att.build(self.j, "pm-decomposition", req, "", self.lk)
        self.assertIsNone(res)
        self.assertIn("requirement-approval", why)

    def test_approach_approval_binds_current_plan(self):
        req, epic, refs, ra, pm, tp = self.full_chain()
        self.j.transition(epic, "Approach Approved", "factory-aman")
        aa = self.sign("approach-approval", epic)
        p = aa.predicate
        self.assertEqual((p["planDigest"], p["upstream"]), (tp.predicate["planDigest"], [tp.digest]))
        self.assertTrue(gate.jira_human_approval(POLICY, p, "approachApproval")[0])
        # A re-plan (new attachment) after the approval: the old approval no longer counts, and no
        # new approach-approval is due until a human approves again.
        ja.apply_ops(self.j, [{"op": "attach", "key": epic, "filename": "plan.md", "content": "# plan v2"},
                              {"op": "transition", "key": epic, "to": "Plan Ready"}], "techlead")
        tp2 = self.sign("techlead-plan", epic)
        self.assertNotEqual(tp2.predicate["planDigest"], tp.predicate["planDigest"])
        self.assertIsNone(att.build(self.j, "approach-approval", epic, "", self.lk)[0])
        p_now = dict(p, changelog=self.j.changelog(epic))
        self.assertFalse(gate.jira_human_approval(POLICY, p_now, "approachApproval")[0])

    def test_human_replan_is_recorded_once_for_the_loop_reset(self):
        req, epic, refs, ra, pm, tp = self.full_chain()
        tp.integrated_time = att._time(ja._now())
        s1 = refs["s1"]
        ja.apply_ops(self.j, [{"op": "transition", "key": s1, "to": "Blocked - Human Escalation"}], "review")
        ja.apply_ops(self.j, [{"op": "transition", "key": s1, "to": "Re-plan"}], "techlead")
        self.assertIsNone(att.build(self.j, "techlead-plan", epic, "", self.lk)[0], "an agent's Re-plan is not a reset")
        self.j.transition(s1, "Blocked - Human Escalation", "review")
        self.j.transition(s1, "Re-plan", "factory-aman")
        tp2 = self.sign("techlead-plan", epic)
        p = tp2.predicate
        self.assertEqual((p["replanApprovedBy"], p["replanApproval"]["issueKey"], p["replanApproval"]["accountId"]),
                         ("factory-aman", s1, AMAN))
        self.assertIn(p["replanApprovedBy"], POLICY.humans("techLeads"))
        tp2.integrated_time = att._time(ja._now())
        self.assertIsNone(att.build(self.j, "techlead-plan", epic, "", self.lk)[0], "recorded once")
        ja.apply_ops(self.j, [{"op": "attach", "key": epic, "filename": "plan.md", "content": "# plan v2"}], "techlead")
        self.assertNotIn("replanApprovedBy", self.sign("techlead-plan", epic).predicate)

    def test_agents_cannot_approve(self):
        req = self.requirement()
        for s in ("Approved", "Approach Approved", "ECAB Approved"):
            with self.assertRaises(ja.JiraError):
                ja.apply_ops(self.j, [{"op": "transition", "key": req, "to": s}], "techlead")

    def test_release_manifest_from_hook(self):
        hook_out = [{"subjects": [["jira", "FRQ-2"], ["release", "payoff"]],
                     "predicate": {"release": "payoff", "stories": [{"key": "FRQ-2"}], "declaredServices": ["api"],
                                   "jiraKeys": ["FRQ-2"], "servicesMapDigest": "abc"}}]
        res, _ = att.build(self.j, "release-manifest", "FRQ-2", "payoff", self.lk, hook=lambda k: hook_out)
        p = res["predicate"]
        self.assertEqual((p["step"], p["release"], p["declaredServices"], p["schema"]), ("SDLC-04", "payoff", ["api"], "sox/common/v1"))
        self.assertEqual(set(res["subjects"]), {("jira", "FRQ-2"), ("release", "payoff")})
        self.lk.sign(res, "release-manifest")
        self.assertIsNone(att.build(self.j, "release-manifest", "FRQ-2", "payoff", self.lk, hook=lambda k: hook_out)[0])
        self.assertIsNone(att.build(self.j, "release-manifest", "FRQ-2", "other", self.lk, hook=lambda k: hook_out)[0])
        bad = [{"subjects": [["commit", "x"], ["release", "payoff"]], "predicate": {}}]
        with self.assertRaises(SystemExit):
            att.build(self.j, "release-manifest", "FRQ-2", "payoff", MemLookup(), hook=lambda k: bad)

    def test_emergency_change(self):
        k = self.j.create("Story", "hotfix", "fix", "intake", labels=["hotfix"])
        self.j.transition(k, "ECAB Approved", "factory-aman")
        p = self.sign("emergency-change", k).predicate
        self.assertEqual(p["ecabApprover"], AMAN)
        self.assertTrue(gate.jira_human_approval(POLICY, p, "emergencyApproval")[0])

    def test_candidates_are_hints_only(self):
        req, epic, *_ = self.full_chain()
        kinds = {(c["kind"], c["key"]) for c in att.candidates(self.j)}
        self.assertIn(("requirement-approval", req), kinds)
        self.assertIn(("techlead-plan", epic), kinds)
        self.assertTrue(all(set(c) == {"kind", "key", "release"} for c in att.candidates(self.j)))


class CloudChangelogTest(unittest.TestCase):
    def test_real_cloud_timestamps_parse_in_gate(self):
        log = [{"id": "1", "created": "2026-11-10T12:00:00.000-0800", "author": {"accountId": "x", "accountType": "atlassian"},
                "items": [{"field": "description", "from": None, "to": None, "fromString": "a", "toString": "b"}]},
               {"id": "2", "created": "2026-11-10T12:05:00.123-0800", "author": {"accountId": AMAN, "accountType": "atlassian"},
                "items": [{"field": "status", "from": "10070", "to": "10071", "fromString": "Spec Review", "toString": "Approved"}]}]
        self.assertEqual(att.approval_entry(log, "10071")["id"], "2")
        ok, detail = gate.jira_human_approval(POLICY, {"changelog": log, "reporter": AUTOMATION, "creator": AUTOMATION},
                                              "requirementApproval")
        self.assertTrue(ok, detail)


if __name__ == "__main__":
    unittest.main()
