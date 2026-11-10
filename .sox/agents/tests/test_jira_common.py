import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import jira_adapter  # noqa: E402
from common import digest_of, jcs, pr_binding, subject_key, subject_lines  # noqa: E402


class FileJiraTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "jira.json")

    def test_lifecycle_and_changelog(self):
        j = jira_adapter.FileJira(self.path)
        req = j.create("Requirement", "Auto-pay", "Borrowers can enable auto-pay", "po-alice")
        j.transition(req, "Approved", "po-bob")
        j.save()
        j2 = jira_adapter.FileJira(self.path)
        self.assertEqual(j2.get(req)["status"], "Approved")
        log = j2.changelog(req)
        self.assertEqual(log[-1]["author"], "po-bob")
        self.assertEqual(log[-1]["items"][0], {"field": "status", "from": "Draft", "to": "Approved"})
        self.assertEqual(j2.get(req)["reporter"], "po-alice")

    def test_unknown_status_rejected(self):
        j = jira_adapter.FileJira(self.path)
        k = j.create("Story", "s", "", "svc-techlead-agent")
        with self.assertRaises(jira_adapter.JiraError):
            j.transition(k, "Approved", "x")

    def test_apply_ops_refs_and_idempotency(self):
        j = jira_adapter.FileJira(self.path)
        req = j.create("Requirement", "r", "", "po")
        ops = [
            {"op": "create", "ref": "e", "type": "Epic", "summary": "E", "parent": req, "fields": {"idempotencyKey": "pm:1:0"}},
            {"op": "create", "ref": "s1", "type": "Story", "summary": "S1", "parent": "$e", "fields": {"idempotencyKey": "tl:e:0", "storyType": "dev"}},
            {"op": "create", "ref": "s2", "type": "Story", "summary": "S2", "parent": "$e", "fields": {"idempotencyKey": "tl:e:1", "storyType": "qa"}},
            {"op": "update", "key": "$s2", "fields": {"dependsOn": ["$s1"]}},
            {"op": "attach", "key": "$e", "filename": "plan.md", "content": "# plan"},
        ]
        _, refs = jira_adapter.apply_ops(j, ops, "svc-techlead-agent")
        self.assertEqual(j.get(refs["s2"])["dependsOn"], [refs["s1"]])
        res2, refs2 = jira_adapter.apply_ops(j, ops[:3], "svc-techlead-agent")
        self.assertEqual(refs, {k: refs2[k] for k in ("e", "s1", "s2")} | {})
        self.assertTrue(all(r["existing"] for r in res2))
        epic = j.get(refs["e"])
        self.assertEqual(j.attachment_content(epic["key"], epic["attachments"][0]["id"]), b"# plan")
        self.assertEqual(epic["creator"], "svc-techlead-agent")


class CommonTest(unittest.TestCase):
    def test_subject_key_matches_spec_example(self):
        self.assertEqual(subject_key("pr", 0, "factory-ryan-lauderback/sox-sdlc-sandbox"),
                         "8f0af752b7d7d89a880a09622f93fe9fdf44a91a0b2334f596863dbd8880c871")

    def test_subject_lines_dedupe(self):
        lines = subject_lines([("pr", 1), ("pr", "1"), ("jira", "FRQ-2")]).strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[1].endswith("sox:jira:FRQ-2"))

    def test_jcs_sorted_and_no_floats(self):
        self.assertEqual(jcs({"b": 1, "a": [True, None]}), b'{"a":[true,null],"b":1}')
        with self.assertRaises(ValueError):
            jcs({"x": 1.5})
        self.assertTrue(digest_of([]).startswith("sha256:"))

    def test_pr_binding(self):
        pr = {"number": 7, "head": {"ref": "story/FRQ-12-autopay-api"}, "base": {"ref": "release/auto-pay"}}
        b = pr_binding(pr)
        self.assertEqual((b["kind"], b["story"], b["release"], b["loopKey"]), ("story", "FRQ-12", "auto-pay", ("jira", "FRQ-12")))
        rel = pr_binding({"number": 8, "head": {"ref": "release/auto-pay"}, "base": {"ref": "main"}})
        self.assertEqual((rel["kind"], rel["loopKey"]), ("release", ("release", "auto-pay")))
        # A story branch retargeted at main is never treated as a story PR (BP-32).
        moved = pr_binding({"number": 7, "head": {"ref": "story/FRQ-12-x"}, "base": {"ref": "main"}})
        self.assertEqual((moved["kind"], moved["loopKey"]), ("other-to-main", ("pr", "7")))
        odd = pr_binding({"number": 9, "head": {"ref": "story/FRQ-12;rm -rf"}, "base": {"ref": "release/x"}})
        self.assertEqual(odd["kind"], "other")


if __name__ == "__main__":
    unittest.main()
