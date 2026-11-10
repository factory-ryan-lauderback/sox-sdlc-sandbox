import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from tools.sox_release import bundler, common, envplan, envselect, envspec, evidence, kube, prod, train

ROOT = common.ROOT
H = "a" * 40
M1, M2, M3 = "1" * 40, "2" * 40, "3" * 40
D = {n: "sha256:" + c * 64 for n, c in (("db", "d"), ("api", "e"), ("ui", "f"))}
D_OLD = {n: "sha256:" + c * 64 for n, c in (("db", "1"), ("api", "2"), ("ui", "3"))}


class FakeGH:
    repo = common.REPO

    def __init__(self, routes):
        self.routes, self.writes = routes, []

    def _key(self, path):
        return path.replace("{repo}", self.repo)

    def get(self, path):
        k = self._key(path)
        for pat, val in self.routes.items():
            if k == pat or (pat.endswith("*") and k.startswith(pat[:-1])):
                return val
        raise AssertionError(f"unexpected GET {k}")

    def paginate(self, path):
        return self.get(path)

    def post(self, path, body):
        self.writes.append(("POST", self._key(path), body))
        return {"sha": "9" * 40}

    def put(self, path, body):
        self.writes.append(("PUT", self._key(path), body))
        return {"sha": "9" * 40}

    def patch(self, path, body):
        self.writes.append(("PATCH", self._key(path), body))

    def graphql(self, q, v):
        self.writes.append(("GRAPHQL", q.split("(")[0], v))


def att(pred, digest="sha256:" + "0" * 64, time="2026-11-10T10:00:00Z", subjects=()):
    return {"predicate": pred, "digest": digest, "time": time, "subjects": list(subjects)}


class Common(unittest.TestCase):
    def test_subject_key_matches_verifier(self):
        sys.path.insert(0, str(ROOT / ".sox"))
        from soxlib import subject
        self.assertEqual(common.subject_key("commit", H), subject.key(common.REPO, "commit", H))
        self.assertEqual(common.subject_key("train", "2026-11-11"), subject.key(common.REPO, "train", "2026-11-11"))

    def test_services_and_order(self):
        svc = common.services()
        touched, other = common.services_touched(["services/ui/app.py", "services/db/app.py", "README.md"], svc)
        self.assertEqual(common.ordered(svc, touched), ["db", "ui"])
        self.assertEqual(other, ["README.md"])
        self.assertEqual(common.ordered(svc, common.upstream_closure(svc, {"ui"})), ["db", "api", "ui"])

    def test_services_map_digest_is_git_blob(self):
        out = subprocess.run(["git", "hash-object", str(ROOT / ".sox/services.yaml")], capture_output=True, text=True, check=True)
        self.assertEqual(common.services_map_digest(), out.stdout.strip())

    def test_fetch_defers_to_verifier(self):
        sys.path.insert(0, str(ROOT / ".sox"))
        from soxlib.ghapi import APIError

        class V:
            def __init__(self, status):
                self.status = status

            def fetch(self, api, kind, ident, predicate):
                if self.status is None:
                    return [], []
                raise APIError(self.status, "https://api.github.com/repos/x/attestations/sha256:ab?per_page=100", "")
        saved = evidence._verifier
        try:
            evidence._verifier = (V(None), lambda token: None)
            self.assertEqual(evidence.fetch("commit:" + H, "release-approval"), [])
            for status in (404, 500):
                evidence._verifier = (V(status), lambda token: None)
                with self.assertRaises(evidence.EvidenceUnavailable):
                    evidence.fetch("commit:" + H, "release-approval")
        finally:
            evidence._verifier = saved

    def test_slug(self):
        self.assertEqual(common.slugify("Auto Pay 2026.11"), "auto-pay-2026-11")
        with self.assertRaises(common.RefusedError):
            common.slugify("!!!")


class Kube(unittest.TestCase):
    spec = {"envId": "eph-frq-1", "images": [{"service": "db", "digest": D["db"]}, {"service": "api", "digest": D["api"]}]}

    def test_objects_pinned_and_restricted(self):
        objs = kube.objects(self.spec)
        deps = [o for o in objs if o["kind"] == "Deployment"]
        self.assertEqual([d["spec"]["template"]["spec"]["containers"][0]["image"] for d in deps],
                         [f"{common.REGISTRY}/db@{D['db']}", f"{common.REGISTRY}/api@{D['api']}"])
        c = deps[0]["spec"]["template"]["spec"]["containers"][0]
        self.assertFalse(c["securityContext"]["allowPrivilegeEscalation"])

    def test_refuses_tags_and_missing_deps(self):
        with self.assertRaises(common.RefusedError):
            kube.objects({"envId": "x", "images": [{"service": "db", "digest": "latest"}]})
        with self.assertRaises(common.RefusedError):
            kube.objects({"envId": "x", "images": [{"service": "api", "digest": D["api"]}]})

    def test_compare(self):
        self.assertEqual(kube.compare(self.spec, {"db": [D["db"]], "api": [D["api"]]}), [])
        probs = kube.compare(self.spec, {"db": [D["db"], D_OLD["db"]], "api": [D["api"]], "ui": [D["ui"]]})
        self.assertEqual(len(probs), 2)


class EnvPlan(unittest.TestCase):
    def test_chain_root(self):
        plans = [{"stories": [{"key": "FRQ-3", "dependsOn": ["FRQ-2"]}, {"key": "FRQ-2", "dependsOn": ["FRQ-1"]},
                              {"key": "FRQ-1", "dependsOn": []}]}]
        self.assertEqual(envplan.chain_root("FRQ-3", plans), "FRQ-1")
        self.assertIsNone(envplan.chain_root("FRQ-9", plans))
        with self.assertRaises(common.RefusedError):
            envplan.chain_root("FRQ-1", [{"stories": [{"key": "FRQ-1", "dependsOn": ["FRQ-2"]}, {"key": "FRQ-2", "dependsOn": ["FRQ-1"]}]}])

    def _gh(self, head_ref, base_ref, files):
        return FakeGH({
            f"/repos/{common.REPO}/pulls/7": {"state": "open", "head": {"sha": H, "ref": head_ref, "repo": {"full_name": common.REPO}},
                                              "base": {"ref": base_ref, "sha": M1}},
            f"/repos/{common.REPO}/pulls/7/files": [{"filename": f} for f in files],
            f"/repos/{common.REPO}/git/commits/{H}": {"tree": {"sha": "t0"}},
            f"/repos/{common.REPO}/git/trees/t0": {"tree": [{"path": "services", "type": "tree", "sha": "t1"}]},
            f"/repos/{common.REPO}/git/trees/t1": {"tree": [{"path": n, "type": "tree", "sha": "tree-" + n} for n in ("db", "api", "ui")]},
        })

    def test_story_env_includes_upstream_services(self):
        fetch = lambda s, p: [att({"stories": [{"key": "FRQ-5", "dependsOn": ["FRQ-4"]}, {"key": "FRQ-4", "dependsOn": []}]})]
        p = envplan.plan(self._gh("story/FRQ-5-x", "release/auto-pay", ["services/api/app.py"]), 7, fetch=fetch)
        self.assertEqual((p["mode"], p["envId"]), ("story", "eph-frq-4"))
        self.assertEqual([s["service"] for s in p["services"]], ["db", "api"])

    def test_release_env_is_shared_and_complete(self):
        p = envplan.plan(self._gh("release/auto-pay", "main", ["services/api/app.py"]), 7, fetch=lambda s, p: [])
        self.assertEqual((p["mode"], p["envId"]), ("release", "qa-auto-pay"))
        self.assertEqual([s["service"] for s in p["services"]], ["db", "api", "ui"])

    def test_refuses_other_branches(self):
        with self.assertRaises(common.RefusedError):
            envplan.plan(self._gh("feature/x", "main", []), 7, fetch=lambda s, p: [])


class EnvSpec(unittest.TestCase):
    plan = {"repo": common.REPO, "prNumber": 7, "headSha": H, "baseRef": "refs/heads/release/r", "baseSha": M1,
            "release": "r", "jiraKeys": ["FRQ-1"], "mode": "story", "envId": "eph-frq-1", "chain": {},
            "services": [{"service": "db", "sourceTree": "t-db"}, {"service": "api", "sourceTree": "t-api"}]}

    def test_reuse_needs_verified_build_and_provenance(self):
        img = [{"name": f"{common.REGISTRY}/db", "digest": {"sha256": D["db"][7:]}}]
        build = att({"service": "db", "sourceTree": "t-db", "imageDigest": D["db"]}, subjects=img)
        prov = att({}, digest="sha256:" + "b" * 64, subjects=img)
        ok = lambda s, p: [build] if p == "image-build" else [prov]
        self.assertTrue(envspec.reusable("db", "t-db", D["db"], ok)[0])
        self.assertFalse(envspec.reusable("db", "other-tree", D["db"], ok)[0])
        self.assertFalse(envspec.reusable("db", "t-db", D["db"], lambda s, p: [build] if p == "image-build" else [])[0])

        def down(s, p):
            raise evidence.EvidenceUnavailable("x")
        self.assertFalse(envspec.reusable("db", "t-db", D["db"], down)[0])

    def test_assemble_and_predicate(self):
        spec = envspec.assemble(self.plan, [{"service": "db", "sourceTree": "t-db", "digest": D["db"]}],
                                [{"service": "api", "sourceTree": "t-api", "digest": D["api"]}], M2)
        self.assertEqual([i["ref"] for i in spec["images"]], [f"{common.REGISTRY}/db@{D['db']}", f"{common.REGISTRY}/api@{D['api']}"])
        rb = {"running": {"db": [D["db"]], "api": [D["api"]]}, "problems": []}
        p = envspec.predicate(spec, "sha256:" + "c" * 64, rb, 5, {}, "success", H)
        self.assertEqual((p["outcome"], p["repo"]), ("pass", common.REPO))
        self.assertRegex(p["observedAt"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(envspec.predicate(spec, "sha256:" + "c" * 64, rb, 5, {}, "success", M3)["outcome"], "fail")
        self.assertEqual(envspec.predicate(spec, "sha256:" + "c" * 64, None, 5, {}, "success", H)["outcome"], "fail")
        with self.assertRaises(ValueError):
            envspec.assemble(self.plan, [], [{"service": "api", "sourceTree": "t-api", "digest": D["api"]}], M2)


class EnvSelect(unittest.TestCase):
    def test_app_id_from_json_policy(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            json.dump({"apps": {"review": {"id": 42}, "qa": {"id": None}}}, f)
        self.assertEqual(envselect.trust_policy_app_id("review", f.name), 42)
        self.assertIsNone(envselect.trust_policy_app_id("qa", f.name))
        self.assertIsNone(envselect.trust_policy_app_id("dev", f.name))
        os.unlink(f.name)


def pr(n, head_ref, head, merge, base="main"):
    return {"number": n, "merged_at": "x", "base": {"ref": base}, "merge_commit_sha": merge,
            "head": {"ref": head_ref, "sha": head}}


CHECK_PREDS = {"sox/evidence-gate": ("gate-decision", "conclusion", "success", 3),
               "sox/review-agent": ("review-verdict", "verdict", "pass", 1),
               "sox/qa-agent": ("qa-result", "outcome", "pass", 2)}


def paired_checks(head, n, mutate=None):
    """merge-record.checks[] and the attestations each check pairs with, for PR n at head."""
    checks, atts = [], {}
    for i, (name, (pred, field, want, app)) in enumerate(sorted(CHECK_PREDS.items())):
        run_id, cr = 9000 + n * 10 + i, 500 + n * 10 + i
        dig = f"sha256:{n:02d}{i}" + "a" * 61
        checks.append({"name": name, "checkRunId": cr, "appId": app, "conclusion": "success", "externalId": str(run_id),
                       "pairedAttestation": dig, "paired": True})
        a = att({"checkRunId": cr, "headSha": head, field: want}, digest=dig)
        a["run"] = f"https://github.com/{common.REPO}/actions/runs/{run_id}/attempts/1"
        atts[pred] = [a]
    if mutate:
        mutate(checks, atts)
    return checks, atts


class Train(unittest.TestCase):
    today = dt.date(2026, 11, 11)
    POLICY = {"apps": {"review": {"id": 1}, "qa": {"id": 2}, "gate": {"id": 3}},
              "requiredChecks": {"sox/review-agent": "review", "sox/qa-agent": "qa", "sox/evidence-gate": "gate"},
              "predicates": {"review-verdict": {"checkName": "sox/review-agent"}, "qa-result": {"checkName": "sox/qa-agent"}}}

    def gh(self, prs_by_commit, files):
        routes = {f"/repos/{common.REPO}/compare/{M1}...{M3}": {
            "status": "ahead", "total_commits": 3,
            "commits": [{"sha": M2, "parents": [{"sha": M1}, {"sha": "b" * 40}]},
                        {"sha": "c" * 40, "parents": [{"sha": M1}]},
                        {"sha": M3, "parents": [{"sha": M2}, {"sha": "c" * 40}]}]}}
        for sha, p in prs_by_commit.items():
            routes[f"/repos/{common.REPO}/commits/{sha}/pulls"] = [p] if p else []
        for n, fl in files.items():
            routes[f"/repos/{common.REPO}/pulls/{n}/files"] = [{"filename": f} for f in fl]
        return FakeGH(routes)

    def fetch_factory(self, approved=True, prod_state=None, missing=(), mutate=None):
        heads = {10: "h" * 40, 11: H}
        paired = {n: paired_checks(h, n, mutate if n == 11 else None) for n, h in heads.items()}

        def fetch(subject, name):
            kind, ident = subject.split(":", 1)
            if name in missing:
                return []
            if name == "merge-record" and kind == "commit":
                n = {M2: 10, M3: 11}[ident]
                return [att({"mergeCommitSha": ident, "prNumber": n, "treeMatch": True, "jiraKeys": [f"FRQ-{n}"],
                             "checks": paired[n][0]})]
            if name in ("gate-decision", "review-verdict", "qa-result"):
                n = next((k for k, h in heads.items() if kind == "commit" and ident == h), None)
                return paired[n][1].get(name, []) if n else []
            if name == "human-approval":
                n = int(ident)
                return [att({"commitId": {10: "h" * 40, 11: H}[n], "prNumber": n, "baseRef": "refs/heads/main",
                             "sod": {"result": "pass"}, "reviewer": {"login": "factory-aman"}})]
            if name == "env-deploy":
                return [att({"outcome": "pass", "headSha": H, "prNumber": 11, "baseRef": "refs/heads/main",
                             "images": [{"service": n, "digest": D[n]} for n in ("db", "api", "ui")]})]
            if name == "release-approval" and approved:
                svc = next(n for n, d in D.items() if d == ident)
                return [att({"service": svc, "imageDigest": ident, "mergeCommitSha": M3, "environment": "production",
                             "humanApproval": "sha256:x"}, subjects=[{"name": f"{common.REGISTRY}/{svc}", "digest": {"sha256": ident[7:]}}])]
            if name == "deploy-result" and prod_state and ident == "2026-11-10":
                return [att({"outcome": "success", "environment": "production", "service": s, "imageDigest": d,
                             "trainId": "t0", "cutoffSha": M1}) for s, d in prod_state.items()]
            if name == "train-plan" and prod_state and ident == "2026-11-10":
                return [att({"mode": "train", "outcome": "planned", "order": sorted(prod_state), "trainId": "t0", "cutoffSha": M1})]
            return []
        return fetch

    def standard_gh(self):
        return self.gh({M2: pr(10, "release/a", "h" * 40, M2), M3: pr(11, "release/b", H, M3)},
                       {10: ["services/db/app.py"], 11: ["services/ui/app.py"]})

    def test_window_is_first_parent_only(self):
        self.assertEqual(train.first_parent_window(self.standard_gh(), M1, M3), [M2, M3])

    def test_order_and_only_changed(self):
        p = train.plan(self.standard_gh(), self.fetch_factory(prod_state={"db": D_OLD["db"], "api": D["api"], "ui": D_OLD["ui"]}),
                       M3, self.today, M1, policy=self.POLICY)
        self.assertEqual(p["outcome"], "planned", p["problems"])
        self.assertEqual(p["order"], ["db", "ui"])
        self.assertEqual(p["restore"], {"api": D["api"]})
        self.assertEqual([r["prNumber"] for r in p["releases"]], [10, 11])
        self.assertEqual(p["previousTrainCutoffSha"], M1)

    def test_first_train_deploys_all_in_dependency_order(self):
        p = train.plan(self.standard_gh(), self.fetch_factory(), M3, self.today, M1, policy=self.POLICY)
        self.assertEqual(p["order"], ["db", "api", "ui"])

    def test_whole_train_refuses_on_any_unapproved_merge(self):
        gh = self.gh({M2: pr(10, "release/a", "h" * 40, M2), M3: pr(11, "release/b", H, M3)}, {10: [], 11: []})
        p = train.plan(gh, self.fetch_factory(missing=("human-approval",)), M3, self.today, M1, policy=self.POLICY)
        self.assertEqual((p["outcome"], p["order"]), ("refused", []))
        gh = self.gh({M2: None, M3: pr(11, "release/b", H, M3)}, {11: []})
        self.assertEqual(train.plan(gh, self.fetch_factory(), M3, self.today, M1, policy=self.POLICY)["outcome"], "refused")

    def test_refuses_without_release_approval(self):
        p = train.plan(self.standard_gh(), self.fetch_factory(approved=False), M3, self.today, M1, policy=self.POLICY)
        self.assertEqual(p["outcome"], "refused")
        self.assertTrue(any("release-approval" in x for x in p["problems"]))

    def test_refuses_unpaired_or_mismatched_check(self):
        self.assertEqual(train.plan(self.standard_gh(), self.fetch_factory(), M3, self.today, M1, policy=self.POLICY)["outcome"], "planned")

        def drop(checks, atts):
            checks[:] = [c for c in checks if c["name"] != "sox/qa-agent"]

        def unpaired(checks, atts):
            checks[0]["paired"] = False

        def no_attestation(checks, atts):
            atts["review-verdict"] = []

        def other_run(checks, atts):
            atts["gate-decision"][0]["run"] = f"https://github.com/{common.REPO}/actions/runs/1/attempts/1"

        def other_check_run(checks, atts):
            atts["qa-result"][0]["predicate"]["checkRunId"] = 1

        def other_head(checks, atts):
            atts["review-verdict"][0]["predicate"]["headSha"] = M1

        def failed_outcome(checks, atts):
            atts["qa-result"][0]["predicate"]["outcome"] = "fail"

        def foreign_app(checks, atts):
            checks[1]["appId"] = 99

        cases = {"missing": drop, "unpaired": unpaired, "no attestation": no_attestation, "run": other_run,
                 "checkRunId": other_check_run, "head": other_head, "outcome": failed_outcome, "app": foreign_app}
        for label, mutate in cases.items():
            p = train.plan(self.standard_gh(), self.fetch_factory(mutate=mutate), M3, self.today, M1, policy=self.POLICY)
            self.assertEqual((p["outcome"], p["order"]), ("refused", []), label)
            self.assertTrue(any(x.startswith("PR #11 sox/") for x in p["problems"]), (label, p["problems"]))
        null_ids = dict(self.POLICY, apps={"review": {"id": None}, "qa": {"id": 2}, "gate": {"id": 3}})
        self.assertEqual(train.plan(self.standard_gh(), self.fetch_factory(), M3, self.today, M1, policy=null_ids)["outcome"], "refused")

    def test_story_branch_merged_into_main_refuses(self):
        gh = self.gh({M2: pr(10, "story/FRQ-1-x", "h" * 40, M2), M3: pr(11, "release/b", H, M3)}, {10: [], 11: []})
        self.assertEqual(train.plan(gh, self.fetch_factory(), M3, self.today, M1, policy=self.POLICY)["outcome"], "refused")

    def test_plan_digest_stable(self):
        a = train.plan(self.standard_gh(), self.fetch_factory(), M3, self.today, M1, policy=self.POLICY)
        b = train.plan(self.standard_gh(), self.fetch_factory(), M3, self.today, M1, policy=self.POLICY)
        self.assertEqual(train.plan_digest(a), train.plan_digest(b))


class Prod(unittest.TestCase):
    plan = {"outcome": "planned", "mode": "train", "trainId": "t1", "trainDate": "2026-11-11", "cutoffSha": M3,
            "planDigest": "sha256:p", "order": ["db", "ui"], "restore": {"api": D["api"], "db": D_OLD["db"]},
            "images": [{"service": n, "digest": D[n], "releaseApproval": "sha256:ra-" + n} for n in ("db", "api", "ui")],
            "jiraKeys": ["FRQ-11"], "releases": []}

    def test_spec(self):
        self.assertEqual(prod.prod_spec(self.plan)["images"],
                         [{"service": "db", "digest": D["db"]}, {"service": "api", "digest": D["api"]}, {"service": "ui", "digest": D["ui"]}])
        self.assertEqual(prod.restore_spec(self.plan)["images"], [{"service": "api", "digest": D["api"]}])

    def test_result_predicate(self):
        res = {"results": [{"service": "db", "imageDigest": D["db"], "outcome": "success", "startedAt": "a", "finishedAt": "b"}]}
        p = prod.result_predicate(self.plan, res, 0, 99, {"workflow": "w"}, "production")
        self.assertEqual((p["service"], p["imageDigest"], p["environment"], p["deploymentId"], p["repo"]),
                         ("db", D["db"], "production", 99, common.REPO))
        self.assertEqual(p["releaseApproval"], "sha256:ra-db")
        self.assertIn("sox:train:2026-11-11", prod.result_subjects(self.plan, res["results"][0]))
        self.assertIn("sox:jira:FRQ-11", prod.result_subjects(self.plan, res["results"][0]))


class Bundler(unittest.TestCase):
    pinned = {"sox/review-agent": 1, "sox/qa-agent": 2, "sox/evidence-gate": 3}
    man = att({"release": "auto-pay", "releaseName": "Auto Pay", "jiraVersionId": "1", "declaredServices": ["api"],
               "stories": [{"key": "FRQ-2", "services": ["api"], "dependsOn": []},
                           {"key": "FRQ-3", "services": ["api"], "dependsOn": ["FRQ-2"]}]})

    def routes(self, behind=0, ahead=1, open_story=(), merged=(), release_pr=None, checks_ok=True):
        R = common.REPO
        runs = lambda: {"check_runs": [{"app": {"id": i}, "status": "completed", "conclusion": "success" if checks_ok else "failure"}
                                       for i in (1, 2, 3)]}
        r = {f"/repos/{R}/git/matching-refs/heads/release/": [{"ref": "refs/heads/release/auto-pay", "object": {"sha": M2}}],
             f"/repos/{R}/compare/main...release/auto-pay": {"behind_by": behind, "ahead_by": ahead},
             f"/repos/{R}/pulls?state=closed&base=release/auto-pay": [
                 {"head": {"ref": f"story/{k}-x"}, "merged_at": "x"} for k in merged],
             f"/repos/{R}/pulls?state=open&base=release/auto-pay&sort=created&direction=asc": [
                 {"number": 20 + i, "title": k, "draft": False, "head": {"ref": f"story/{k}-x", "sha": H, "repo": {"full_name": R}}}
                 for i, k in enumerate(open_story)],
             f"/repos/{R}/pulls?state=open&base=main&head=factory-ryan-lauderback:release/auto-pay": [release_pr] if release_pr else [],
             f"/repos/{R}/commits/*": runs()}
        return r

    def run_(self, **kw):
        gh = FakeGH(self.routes(**kw))
        return gh, bundler.sweep_release(gh, gh, "auto-pay", self.man, self.pinned, M1)

    def test_sync_first(self):
        gh, out = self.run_(behind=2, open_story=["FRQ-2"])
        self.assertEqual(gh.writes[0][:2], ("POST", f"/repos/{common.REPO}/merges"))
        self.assertEqual(len(gh.writes), 1)

    def test_merges_story_pinned_to_head_respecting_dependencies(self):
        gh, out = self.run_(open_story=["FRQ-3", "FRQ-2"])
        self.assertEqual(gh.writes, [("PUT", f"/repos/{common.REPO}/pulls/21/merge",
                                      {"merge_method": "squash", "sha": H, "commit_title": "FRQ-2 (#21)"})])

    def test_no_merge_without_checks_or_outside_manifest(self):
        gh, _ = self.run_(open_story=["FRQ-2"], checks_ok=False)
        self.assertFalse([w for w in gh.writes if w[0] == "PUT"])
        gh, out = self.run_(open_story=["FRQ-9"])
        self.assertFalse([w for w in gh.writes if w[0] == "PUT"])
        self.assertTrue(out["problems"])

    def test_snapshot_names_candidates_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d, "jira.json")
            p.write_text(json.dumps({"schema": "sox-jira-fake/v1", "issues": {
                "FRQ-2": {"type": "Story", "fixVersions": ["Auto Pay"]},
                "FRQ-1": {"type": "Epic", "fixVersions": ["Epic Only"]},
                "FRQ-4": {"type": "Story", "fixVersions": ["!!!", 5]}}}))
            self.assertEqual(bundler.snapshot_releases(str(p)), ({"auto-pay": "Auto Pay"}, None))
            p.write_text("not json")
            self.assertEqual(bundler.snapshot_releases(str(p))[0], {})
        self.assertEqual(bundler.snapshot_releases(None), ({}, "no Jira snapshot"))
        gh = FakeGH(dict(self.routes(), **{f"/repos/{common.REPO}/git/ref/heads/main": {"object": {"sha": M1}}}))
        out = bundler.sweep(gh, gh, fetch=lambda s, p: [], policy={"apps": {}, "requiredChecks": {}})
        self.assertEqual([r["release"] for r in out["releases"]], ["auto-pay"])
        self.assertEqual(gh.writes, [])

    def test_null_app_ids_fail_closed(self):
        gh = FakeGH(self.routes(open_story=["FRQ-2"]))
        bundler.sweep_release(gh, gh, "auto-pay", self.man, {"sox/evidence-gate": None}, M1)
        self.assertFalse([w for w in gh.writes if w[0] == "PUT"])

    def test_release_pr_lifecycle(self):
        gh, _ = self.run_(merged=["FRQ-2"])
        self.assertEqual(gh.writes[0][:2], ("POST", f"/repos/{common.REPO}/pulls"))
        self.assertTrue(gh.writes[0][2]["draft"])
        rel = {"number": 30, "draft": True, "node_id": "N", "body": "", "head": {"sha": H}}
        gh, _ = self.run_(merged=["FRQ-2", "FRQ-3"], release_pr=rel)
        self.assertEqual([w[0] for w in gh.writes], ["PATCH", "GRAPHQL"])
        rel = dict(rel, draft=False, body=bundler.body("auto-pay", self.man, {"FRQ-2", "FRQ-3"}, []))
        gh, out = self.run_(merged=["FRQ-2", "FRQ-3"], release_pr=rel)
        self.assertEqual(gh.writes, [("PUT", f"/repos/{common.REPO}/pulls/30/merge",
                                      {"merge_method": "merge", "sha": H, "commit_title": "Release auto-pay (#30)"})])
        self.assertEqual([o["key"] for o in out["jiraOps"]], ["FRQ-2", "FRQ-3"])
        gh, _ = self.run_(merged=["FRQ-2", "FRQ-3"], release_pr=rel, checks_ok=False)
        self.assertEqual(gh.writes, [])


if __name__ == "__main__":
    unittest.main()
