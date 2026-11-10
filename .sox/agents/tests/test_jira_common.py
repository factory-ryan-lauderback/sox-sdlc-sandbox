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
        req = j.create("Requirement", "Auto-pay", "Borrowers can enable auto-pay", "intake")
        j.transition(req, "Approved", "factory-aman")
        j.save()
        j2 = jira_adapter.FileJira(self.path)
        self.assertEqual((j2.get(req)["status"], j2.get(req)["statusId"]), ("Approved", "10071"))
        last = j2.changelog(req)[-1]
        self.assertEqual(last["author"], {"accountId": "712020:ae7e6a76-96e0-4d91-a2ac-857b21c164cd", "accountType": "atlassian"})
        self.assertEqual((last["items"][0]["to"], last["items"][0]["toString"]), ("10071", "Approved"))
        self.assertEqual(j2.get(req)["reporter"], "svc-intake-agent")

    def test_unknown_status_and_human_only_rejected(self):
        j = jira_adapter.FileJira(self.path)
        k = j.create("Story", "s", "", "techlead")
        with self.assertRaises(jira_adapter.JiraError):
            j.transition(k, "Bogus", "factory-aman")
        for s in ("Approved", "Approach Approved", "ECAB Approved"):
            with self.assertRaises(jira_adapter.JiraError):
                j.transition(k, s, "techlead")
        j.transition(k, "Plan Ready", "techlead")

    def test_apply_ops_refs_idempotency_and_role_marks(self):
        j = jira_adapter.FileJira(self.path)
        req = j.create("Requirement", "r", "", "intake")
        ops = [
            {"op": "create", "ref": "e", "type": "Epic", "summary": "E", "parent": req, "fields": {"idempotencyKey": "pm:1:0"}},
            {"op": "create", "ref": "s1", "type": "Story", "summary": "S1", "parent": "$e", "fields": {"idempotencyKey": "tl:e:0", "storyType": "dev"}},
            {"op": "create", "ref": "s2", "type": "Story", "summary": "S2", "parent": "$e", "fields": {"idempotencyKey": "tl:e:1", "storyType": "qa"}},
            {"op": "update", "key": "$s2", "fields": {"dependsOn": ["$s1"]}},
            {"op": "attach", "key": "$e", "filename": "plan.md", "content": "# plan"},
            {"op": "comment", "key": "$e", "body": "plan attached"},
        ]
        _, refs = jira_adapter.apply_ops(j, ops, "techlead")
        self.assertEqual(j.get(refs["s2"])["dependsOn"], [refs["s1"]])
        res2, refs2 = jira_adapter.apply_ops(j, ops[:3], "techlead")
        self.assertEqual(refs, {k: refs2[k] for k in ("e", "s1", "s2")})
        self.assertTrue(all(r["existing"] for r in res2))
        epic = j.get(refs["e"])
        self.assertEqual(j.attachment_content(epic["key"], epic["attachments"][0]["id"]), b"# plan")
        self.assertEqual((epic["creator"], epic["actingRole"]), ("svc-techlead-agent", "techlead"))
        bodies = [c["body"] for c in j.comments(refs["e"])]
        self.assertTrue(all(b.startswith("[sox:techlead] ") for b in bodies), bodies)
        self.assertEqual(len(bodies), 2)  # one create mark (not repeated on the idempotent re-run) + one comment
        with self.assertRaises(jira_adapter.JiraError):
            jira_adapter.apply_ops(j, [{"op": "transition", "key": refs["e"], "to": "Approach Approved"}], "techlead")

    def test_snapshot_digest_bound(self):
        import jira_snapshot
        j = jira_adapter.FileJira(self.path)
        req = j.create("Requirement", "r", "d", "intake")
        epic = j.create("Epic", "e", "", "pm", parent=req)
        s = j.create("Story", "s", "", "techlead", parent=epic, fields={"storyType": "dev"})
        j.set_fix_version(s, "Auto Pay", "techlead")
        snap = jira_snapshot.build(j, "issues", [s])
        self.assertEqual([i["key"] for i in snap["issues"]], [epic, s])
        self.assertEqual(snap["issues"][1]["properties"]["sox.agent"], {"storyType": "dev"})
        out = os.path.join(self.dir, "snap.json")
        digest = jira_snapshot.write(snap, out)
        self.assertEqual(jira_snapshot.load_verified(out, digest)["schema"], "sox-jira-snapshot/v1")
        with self.assertRaises(SystemExit):
            jira_snapshot.load_verified(out, "sha256:" + "0" * 64)
        rel = jira_snapshot.build(j, "releases")
        self.assertIn(s, [i["key"] for i in rel["issues"]])
        self.assertEqual(rel["versions"][0]["name"], "Auto Pay")
        with self.assertRaises(SystemExit):
            jira_snapshot.build(j, "issues", ["FRQ-1 OR 1=1"])


class CloudPagingTest(unittest.TestCase):
    def cloud(self, pages):
        c = jira_adapter.CloudJira("https://x.example", "e", "t")
        calls = []

        def req(method, path, **kw):
            calls.append(path)
            return pages[len(calls) - 1]
        c._req = req
        return c, calls

    def entry(self, i):
        return {"id": str(i), "created": "t", "author": {"accountId": "a", "accountType": "atlassian", "emailAddress": "x@y"},
                "items": [{"field": "status", "from": "1", "to": "10071", "fromString": "A", "toString": "Approved"}]}

    def test_complete_changelog_over_pages(self):
        c, calls = self.cloud([{"startAt": 0, "total": 3, "isLast": False, "values": [self.entry(1), self.entry(2)]},
                               {"startAt": 2, "total": 3, "isLast": True, "values": [self.entry(3)]}])
        log = c.changelog("FRQ-1")
        self.assertEqual([h["id"] for h in log], ["1", "2", "3"])
        self.assertNotIn("emailAddress", json.dumps(log))
        self.assertIn("startAt=2", calls[1])

    def test_truncated_changelog_fails(self):
        for pages in ([{"startAt": 0, "total": 3, "isLast": True, "values": [self.entry(1)]}],
                      [{"startAt": 0, "total": 3, "isLast": False, "values": [self.entry(1)]},
                       {"startAt": 1, "total": 3, "isLast": False, "values": []}],
                      [{"startAt": 0, "total": 2, "isLast": False, "values": [self.entry(1)]},
                       {"startAt": 0, "total": 2, "isLast": True, "values": [self.entry(1)]}]):
            c, _ = self.cloud(pages)
            with self.assertRaises(jira_adapter.IncompleteRead):
                c.changelog("FRQ-1")

    def test_agent_token_check(self):
        c, _ = self.cloud([{"accountId": "712020:ae7e6a76-96e0-4d91-a2ac-857b21c164cd"}])
        with self.assertRaises(jira_adapter.JiraError):
            c.comment("FRQ-1", "x", "pm")

    def test_adf_round_trip(self):
        doc = jira_adapter.text_to_adf("line one\nline two\n\npara two")
        self.assertEqual(jira_adapter.adf_to_text(doc).strip(), "line one\nline two\n\npara two")

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
