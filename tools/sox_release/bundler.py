"""SDLC-04 Release Bundler and SDLC-10 Shipping Dock.

One idempotent sweep per run, all state re-read from GitHub, Jira and the verifier:
  1. Releases come from Jira fix versions (and existing release/* branches). A release is acted
     on only when the verifier returns a release-manifest for `release:<slug>`.
  2. Ensure branch release/<slug> exists (created from main).
  3. Sync: when main has moved, merge main into release/<slug> with the Merges API. A conflict is
     never resolved here; it is reported and the release waits.
  4. Squash-merge story PRs (story/FRQ-n-*, qa-fix/FRQ-n-*) into release/<slug> when the story is
     in the manifest, its dependencies are already merged, and the three required checks passed on
     the PR's current head from their pinned Apps. The merge is pinned to that head SHA.
  5. Open the release PR (release/<slug> -> main) as a draft, keep its body in sync with the
     manifest, and mark it ready once every manifest story is merged.
  6. Shipping dock: merge the release PR with a merge commit, pinned to its head SHA, once the
     required checks passed on that head (sox/evidence-gate covers the human approval). It then
     waits for the deploy train.
Reads use the job's GITHUB_TOKEN; writes use the Release Bundler App token (SOX_BUNDLER_TOKEN).
"""
import argparse
import json
import os
import pathlib
import sys

from tools.sox_release import evidence
from tools.sox_release.common import RELEASE_BRANCH, ROOT, STORY_BRANCH, RefusedError, slugify, write_json
from tools.sox_release.gh import GitHub, GitHubError

MARK = "<!-- sox-release-bundler -->"


def trust_policy(path=None):
    return json.loads(pathlib.Path(path or ROOT / ".sox" / "trust-policy.yaml").read_text())


def pinned_checks(policy):
    """{check name: App id} from requiredChecks + apps. A null App id stays None: fail closed."""
    apps = policy.get("apps", {})
    return {name: (apps.get(role) or {}).get("id") for name, role in policy.get("requiredChecks", {}).items()
            if not name.startswith("$")}


def checks_passed(gh, sha, pinned):
    problems = []
    for name, app_id in sorted(pinned.items()):
        if not isinstance(app_id, int):
            problems.append(f"{name}: App id not set in the trust policy")
            continue
        runs = gh.get(f"/repos/{{repo}}/commits/{sha}/check-runs?check_name={name}&filter=latest&per_page=100")["check_runs"]
        mine = [r for r in runs if (r.get("app") or {}).get("id") == app_id]
        if not mine:
            problems.append(f"{name}: no check run from App {app_id} on {sha[:12]}")
        elif not all(r["status"] == "completed" and r["conclusion"] == "success" for r in mine):
            problems.append(f"{name}: {[(r['status'], r['conclusion']) for r in mine]} on {sha[:12]}")
    return problems


def jira_releases():
    """{slug: version name} from Jira stories' fix versions. Empty when Jira is unreachable."""
    agents = ROOT / ".sox" / "agents"
    if not (agents / "jira_cli.py").exists():
        return {}, "Jira adapter not on main"
    sys.path.insert(0, str(agents))
    try:
        import jira_cli
        jira = jira_cli.load()
        names = {v for s in jira.search(type="Story") for v in (s.get("fixVersions") or [])}
    except Exception as e:  # Jira down: act only on releases that already have branches
        return {}, f"Jira unavailable: {e}"
    out = {}
    for n in sorted(names):
        try:
            out[slugify(n)] = n
        except RefusedError:
            continue
    return out, None


def release_branches(gh):
    refs = gh.paginate("/repos/{repo}/git/matching-refs/heads/release/")
    return {r["ref"][len("refs/heads/release/"):]: r["object"]["sha"] for r in refs if RELEASE_BRANCH.match(r["ref"][len("refs/heads/"):])}


def manifest_for(slug, fetch=evidence.fetch):
    items = [i for i in fetch(f"release:{slug}", "release-manifest") if i["predicate"].get("release") == slug]
    return evidence.latest(items)


def merged_story_keys(gh, branch):
    keys = set()
    for pr in gh.paginate(f"/repos/{{repo}}/pulls?state=closed&base={branch}"):
        m = STORY_BRANCH.match(pr["head"]["ref"])
        if m and pr.get("merged_at"):
            keys.add(m.group(2))
    return keys


def body(slug, man, merged, pending):
    p = man["predicate"]
    rows = "\n".join(f"| {s['key']} | {s.get('epic') or ''} | {', '.join(s.get('services') or [])} | "
                     f"{'merged' if s['key'] in merged else 'pending'} |" for s in p["stories"])
    return (f"{MARK}\nRelease `{slug}` ({p.get('releaseName', slug)}), Jira version id {p.get('jiraVersionId')}.\n\n"
            f"Release manifest attestation: `{man['digest']}`\n\nDeclared services: {', '.join(p.get('declaredServices') or [])}\n\n"
            f"| Story | Epic | Services | Status |\n|---|---|---|---|\n{rows}\n\n"
            f"Merged by the Release Bundler when the required checks pass on the head commit and the Release Approver "
            f"has approved it. Deployed by the daily train.\n"
            + ("" if not pending else f"\nWaiting for: {', '.join(sorted(pending))}\n"))


def sweep_release(reader, writer, slug, man, pinned, main_sha, dry_run=False):
    log, problems, jira_ops = [], [], []
    branch = f"release/{slug}"
    p = man["predicate"]
    stories = {s["key"]: s for s in p["stories"]}
    branches = release_branches(reader)
    if slug not in branches:
        log.append(f"create {branch} at main {main_sha[:12]}")
        if not dry_run:
            writer.post("/repos/{repo}/git/refs", {"ref": f"refs/heads/{branch}", "sha": main_sha})
        return {"release": slug, "log": log, "problems": problems, "jiraOps": jira_ops}
    cmp = reader.get(f"/repos/{{repo}}/compare/main...{branch}")
    if cmp["behind_by"] > 0:
        log.append(f"sync main {main_sha[:12]} into {branch} (behind by {cmp['behind_by']})")
        if not dry_run:
            try:
                writer.post("/repos/{repo}/merges", {"base": branch, "head": main_sha,
                                                     "commit_message": f"Sync main {main_sha[:12]} into {branch}"})
            except GitHubError as e:
                if e.status == 409:
                    problems.append(f"{branch} conflicts with main; a developer must resolve it on a story or qa-fix branch")
                    return {"release": slug, "log": log, "problems": problems, "jiraOps": jira_ops}
                raise
        return {"release": slug, "log": log, "problems": problems, "jiraOps": jira_ops}
    merged = merged_story_keys(reader, branch)
    for pr in reader.paginate(f"/repos/{{repo}}/pulls?state=open&base={branch}&sort=created&direction=asc"):
        m = STORY_BRANCH.match(pr["head"]["ref"])
        n, head = pr["number"], pr["head"]["sha"]
        if not m or pr["head"]["repo"]["full_name"] != reader.repo:
            problems.append(f"PR #{n} ({pr['head']['ref']}) is not a story or qa-fix branch of this repository")
            continue
        key = m.group(2)
        if key not in stories:
            problems.append(f"PR #{n}: {key} is not in the release manifest for {slug}")
            continue
        waiting = [d for d in stories[key].get("dependsOn") or [] if d in stories and d not in merged]
        if waiting and m.group(1) == "story":
            log.append(f"PR #{n} {key} waits for {waiting}")
            continue
        if pr.get("draft"):
            continue
        bad = checks_passed(reader, head, pinned)
        if bad:
            log.append(f"PR #{n} {key} not ready: {'; '.join(bad)}")
            continue
        log.append(f"squash-merge PR #{n} {key} at {head[:12]} into {branch}")
        if not dry_run:
            try:
                writer.put(f"/repos/{{repo}}/pulls/{n}/merge", {"merge_method": "squash", "sha": head,
                                                                 "commit_title": f"{pr['title']} (#{n})"})
            except GitHubError as e:
                problems.append(f"PR #{n} merge refused by GitHub ({e.status}): {e.body[:200]}")
                continue
        merged.add(key)
        # One story per run: the next story's checks must run against the new release head.
        return {"release": slug, "log": log, "problems": problems, "jiraOps": jira_ops}
    pending = sorted(set(stories) - merged)
    rel = [x for x in reader.paginate(f"/repos/{{repo}}/pulls?state=open&base=main&head={reader.repo.split('/')[0]}:{branch}")]
    if not rel:
        if cmp["ahead_by"] == 0:
            log.append(f"{branch} has no stories yet")
        else:
            log.append(f"open draft release PR for {branch}")
            if not dry_run:
                writer.post("/repos/{repo}/pulls", {"title": f"Release {p.get('releaseName', slug)}", "head": branch,
                                                   "base": "main", "draft": True, "body": body(slug, man, merged, pending)})
        return {"release": slug, "log": log, "problems": problems, "jiraOps": jira_ops}
    pr = rel[0]
    n, head = pr["number"], pr["head"]["sha"]
    want = body(slug, man, merged, pending)
    if (pr.get("body") or "") != want and not dry_run:
        writer.patch(f"/repos/{{repo}}/pulls/{n}", {"body": want})
    if pending:
        log.append(f"release PR #{n} waits for stories {pending}")
        return {"release": slug, "log": log, "problems": problems, "jiraOps": jira_ops}
    if pr.get("draft"):
        log.append(f"mark release PR #{n} ready for review")
        if not dry_run:
            writer.graphql("mutation($id:ID!){markPullRequestReadyForReview(input:{pullRequestId:$id}){pullRequest{number}}}",
                           {"id": pr["node_id"]})
        return {"release": slug, "log": log, "problems": problems, "jiraOps": jira_ops}
    bad = checks_passed(reader, head, pinned)
    if bad:
        log.append(f"release PR #{n} not ready to ship: {'; '.join(bad)}")
        return {"release": slug, "log": log, "problems": problems, "jiraOps": jira_ops}
    log.append(f"shipping dock: merge release PR #{n} at {head[:12]} into main")
    if not dry_run:
        try:
            res = writer.put(f"/repos/{{repo}}/pulls/{n}/merge", {"merge_method": "merge", "sha": head,
                                                                   "commit_title": f"Release {slug} (#{n})"})
        except GitHubError as e:
            problems.append(f"release PR #{n} merge refused by GitHub ({e.status}): {e.body[:200]}")
            return {"release": slug, "log": log, "problems": problems, "jiraOps": jira_ops}
        sha = res.get("sha")
        for k in sorted(stories):
            jira_ops.append({"op": "comment", "key": k,
                             "body": f"Release {slug} merged to main in {sha} (PR #{n}). Waiting for the daily deploy train."})
    return {"release": slug, "log": log, "problems": problems, "jiraOps": jira_ops}


def sweep(reader, writer, fetch=evidence.fetch, dry_run=False, policy=None):
    policy = policy or trust_policy()
    pinned = pinned_checks(policy)
    from_jira, jira_err = jira_releases()
    slugs = sorted(set(from_jira) | set(release_branches(reader)))
    main_sha = reader.get("/repos/{repo}/git/ref/heads/main")["object"]["sha"]
    out = {"mainSha": main_sha, "jira": jira_err or "ok", "releases": [], "problems": []}
    for slug in slugs:
        try:
            man = manifest_for(slug, fetch)
        except evidence.EvidenceUnavailable as e:
            out["problems"].append(f"{slug}: verifier unavailable: {e}")
            continue
        if not man:
            out["releases"].append({"release": slug, "log": ["no verified release-manifest; nothing to do"], "problems": [], "jiraOps": []})
            continue
        out["releases"].append(sweep_release(reader, writer, slug, man, pinned, main_sha, dry_run))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--out", required=True)
    ap.add_argument("--jira-ops-out", required=True)
    args = ap.parse_args(argv)
    reader = GitHub(token=os.environ.get("GITHUB_TOKEN"))
    writer = GitHub(token=os.environ.get("SOX_BUNDLER_TOKEN") or ("dry-run" if args.dry_run else None))
    if not args.dry_run and not os.environ.get("SOX_BUNDLER_TOKEN"):
        print("refused: SOX_BUNDLER_TOKEN (Release Bundler App token) is required for writes", file=sys.stderr)
        return 2
    out = sweep(reader, writer, dry_run=args.dry_run)
    out["rejectedEvidence"] = evidence.REJECTED[:50]
    write_json(args.out, out)
    ops = [op for r in out["releases"] for op in r["jiraOps"]]
    pathlib.Path(args.jira_ops_out).write_text(json.dumps(ops, indent=2) + "\n")
    for r in out["releases"]:
        for line in r["log"]:
            print(f"[{r['release']}] {line}")
        for line in r["problems"]:
            print(f"[{r['release']}] PROBLEM: {line}")
    for line in out["problems"]:
        print(f"PROBLEM: {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
