"""SDLC-11 daily deploy train (and the CC-04 emergency path) planning.

The plan is computed only from primary sources and verified evidence:
- the commit window comes from git history on main (first-parent), never from trigger input;
- every commit in the window must be the merge of a release (or emergency) PR with a verified
  merge-record and human-approval, otherwise the WHOLE train refuses, because main's tree
  contains every commit in the window;
- images come from the env-deploy of the last release head (what QA tested), and each needs a
  verified release-approval naming the cutoff merge;
- each service deploys at most once, in dependency order, and only if production does not
  already run that digest.
"""
import argparse
import datetime as dt
import json
import os
import pathlib
import sys

from tools.sox_release import evidence
from tools.sox_release.common import (HOTFIX_BRANCH, RELEASE_BRANCH, REPO, ROOT, SHA, RefusedError, digest_of, now_iso,
                                      ordered, services, services_touched, subject_key, write_json)
from tools.sox_release.gh import GitHub

LOOKBACK_DAYS = 45


def train_dates(today, days=LOOKBACK_DAYS):
    return [(today - dt.timedelta(days=i)).isoformat() for i in range(days)]


def deployed_state(fetch, today):
    """Latest successful deploy-result per service, and the cutoff of the last train whose every
    planned service deployed successfully."""
    state, plans, results = {}, [], []
    for d in train_dates(today):
        results += fetch(f"train:{d}", "deploy-result")
        plans += fetch(f"train:{d}", "train-plan")
    for r in sorted(results, key=lambda i: str(i.get("time") or "")):
        p = r["predicate"]
        if p.get("outcome") == "success" and p.get("environment") in ("production", "production-emergency"):
            state[p["service"]] = {"digest": p["imageDigest"], "trainId": p.get("trainId"), "cutoffSha": p.get("cutoffSha"),
                                   "mode": p.get("mode"), "attestation": r.get("digest")}
    ok = {}
    for r in results:
        p = r["predicate"]
        if p.get("outcome") == "success":
            ok.setdefault(p.get("trainId"), set()).add(p.get("service"))
    prev = None
    for pl in sorted(plans, key=lambda i: str(i.get("time") or "")):
        p = pl["predicate"]
        if p.get("mode") != "train" or p.get("outcome") not in ("planned", "no-change"):
            continue
        if set(p.get("order", [])) <= ok.get(p.get("trainId"), set()):
            prev = p
    return state, prev


def first_parent_window(gh, prev_sha, cutoff):
    if prev_sha == cutoff:
        return []
    cmp = gh.get(f"/repos/{{repo}}/compare/{prev_sha}...{cutoff}")
    if cmp["status"] not in ("ahead", "identical"):
        raise RefusedError(f"previous cutoff {prev_sha} is not an ancestor of {cutoff} (history rewritten?): {cmp['status']}")
    if cmp["total_commits"] > len(cmp["commits"]):
        raise RefusedError(f"window has {cmp['total_commits']} commits, more than one compare page; run the train more often")
    parents = {c["sha"]: [p["sha"] for p in c["parents"]] for c in cmp["commits"]}
    chain, sha = [], cutoff
    while sha != prev_sha:
        if sha not in parents:
            raise RefusedError(f"first-parent walk from {cutoff} left the window at {sha}")
        chain.append(sha)
        sha = parents[sha][0]
    return list(reversed(chain))


def _verified(fetch, subject, name, check):
    try:
        items = [i for i in fetch(subject, name) if check(i["predicate"])]
        if subject.startswith("image:"):
            items = [i for i in items if evidence.image_subject(i, subject[len("image:"):])]
    except evidence.EvidenceUnavailable as e:
        return None, f"verifier unavailable: {e}"
    if not items:
        return None, f"no verified {name} for {subject}"
    return evidence.latest(items), None


def release_for_commit(gh, fetch, sha, svc):
    problems = []
    prs = [p for p in gh.get(f"/repos/{{repo}}/commits/{sha}/pulls")
           if p.get("merged_at") and p["base"]["ref"] == "main" and p.get("merge_commit_sha") == sha]
    if len(prs) != 1:
        return None, [f"{sha[:12]} on main is not the merge commit of exactly one merged PR (found {len(prs)})"]
    pr = prs[0]
    n, head, head_ref = pr["number"], pr["head"]["sha"], pr["head"]["ref"]
    rm, hm = RELEASE_BRANCH.match(head_ref), HOTFIX_BRANCH.match(head_ref)
    if not (rm or hm):
        problems.append(f"PR #{n} merged into main from {head_ref}, which is neither release/* nor hotfix/*")
    mr, err = _verified(fetch, f"commit:{sha}", "merge-record",
                        lambda p: p.get("mergeCommitSha") == sha and p.get("prNumber") == n and p.get("treeMatch") is True)
    if err:
        problems.append(f"PR #{n}: {err}")
    ha, err = _verified(fetch, f"pr:{n}", "human-approval",
                        lambda p: p.get("commitId") == head and p.get("prNumber") == n and p.get("baseRef") == "refs/heads/main"
                        and (p.get("sod") or {}).get("result") == "pass")
    if err:
        problems.append(f"PR #{n}: {err}")
    ec = None
    if hm:
        ec, err = _verified(fetch, f"jira:{hm.group(1)}", "emergency-change", lambda p: bool(p.get("ecabApprover")))
        if err:
            problems.append(f"PR #{n}: {err}")
    files = [f["filename"] for f in gh.paginate(f"/repos/{{repo}}/pulls/{n}/files")]
    touched, _ = services_touched(files, svc)
    rec = {"prNumber": n, "kind": "release" if rm else "emergency", "slug": rm.group(1) if rm else head_ref,
           "mergeCommitSha": sha, "headSha": head, "touchedServices": ordered(svc, touched),
           "mergeRecord": mr and mr.get("digest"), "humanApproval": ha and ha.get("digest"),
           "humanApprover": ha and (ha["predicate"].get("reviewer") or {}).get("login"),
           "emergencyChange": ec and ec.get("digest"), "ecabApprover": ec and ec["predicate"].get("ecabApprover"),
           "jiraKeys": sorted(set((mr or {}).get("predicate", {}).get("jiraKeys") or [])
                              | set((ha or {}).get("predicate", {}).get("jiraKeys") or []) | ({hm.group(1)} if hm else set()))}
    return rec, problems


def desired_images(fetch, rel, cutoff, svc, only=None):
    problems, images = [], {}
    ed, err = _verified(fetch, f"commit:{rel['headSha']}", "env-deploy",
                        lambda p: p.get("outcome") == "pass" and p.get("headSha") == rel["headSha"]
                        and p.get("prNumber") == rel["prNumber"] and p.get("baseRef") == "refs/heads/main")
    if err:
        return {}, None, [f"PR #{rel['prNumber']}: {err} (QA environment for the release head)"]
    for img in ed["predicate"]["images"]:
        name, digest = img["service"], img["digest"]
        if only is not None and name not in only:
            continue
        ra, err = _verified(fetch, f"image:{digest}", "release-approval",
                            lambda p: p.get("service") == name and p.get("imageDigest") == digest
                            and p.get("mergeCommitSha") == cutoff
                            and p.get("environment") == "production" and bool(p.get("humanApproval")))
        if err:
            problems.append(f"{name}@{digest}: {err} naming merge {cutoff[:12]}")
            continue
        images[name] = {"service": name, "digest": digest, "releaseApproval": ra.get("digest")}
    missing = sorted(set(only if only is not None else svc) - set(images))
    if missing and not problems:
        problems.append(f"no approved image for {missing} in the env-deploy of {rel['headSha'][:12]}")
    return images, ed.get("digest"), problems


def plan(gh, fetch, cutoff, today, baseline, mode="train", emergency_pr=None, root=None):
    if not SHA.match(cutoff or ""):
        raise RefusedError("cutoff must be a commit SHA")
    svc = services(root) if root else services()
    state, prev = deployed_state(fetch, today)
    prev_sha = (prev or {}).get("cutoffSha") or baseline
    train_id = f"{today.isoformat()}-{mode}-{os.environ.get('GITHUB_RUN_ID', 'local')}"
    problems, releases, target = [], [], cutoff
    if mode == "emergency":
        pr = gh.get(f"/repos/{{repo}}/pulls/{int(emergency_pr)}")
        if not pr.get("merged_at") or pr["base"]["ref"] != "main" or not HOTFIX_BRANCH.match(pr["head"]["ref"]):
            raise RefusedError(f"PR #{emergency_pr} is not a merged hotfix/FRQ-n-* PR into main")
        target = pr["merge_commit_sha"]
        cmp = gh.get(f"/repos/{{repo}}/compare/{target}...{cutoff}")
        if cmp["status"] not in ("ahead", "identical"):
            raise RefusedError(f"emergency merge {target} is not on main")
    window = first_parent_window(gh, prev_sha, target)
    for sha in window:
        rec, errs = release_for_commit(gh, fetch, sha, svc)
        problems += errs
        if rec:
            releases.append(rec)
    if mode == "emergency":
        last = next((r for r in releases if r["mergeCommitSha"] == target), None)
        if last and last["kind"] != "emergency":
            problems.append("emergency path used for a non-hotfix PR")
        if last and last["ecabApprover"] and last["ecabApprover"] == last["humanApprover"]:
            last["sodShortcut"] = "ECAB approver is also the release approver (sandbox-only shortcut)"
        scope = set(last["touchedServices"]) if last else set()
    else:
        last = releases[-1] if releases else None
        scope = None
    images, env_deploy = {}, None
    if last and not problems:
        images, env_deploy, errs = desired_images(fetch, last, target, svc, only=scope)
        problems += errs
    desired = {n: i["digest"] for n, i in images.items()}
    to_deploy = [n for n in ordered(svc, desired) if (state.get(n) or {}).get("digest") != desired[n]]
    touched = sorted({s for r in releases for s in r["touchedServices"]})
    outcome = "refused" if problems else ("planned" if to_deploy else "no-change")
    return {
        "schema": "sox/common/v1", "repo": gh.repo, "step": "SDLC-11" if mode == "train" else "CC-04", "mode": mode,
        "jiraKeys": sorted({k for r in releases for k in r.get("jiraKeys", [])}),
        "prNumber": None, "headSha": None, "baseSha": None, "baseRef": None,
        "trainId": train_id, "trainDate": today.isoformat(), "outcome": outcome,
        "cutoffSha": target, "previousTrainCutoffSha": prev_sha, "previousTrainId": (prev or {}).get("trainId"),
        "releases": releases, "touchedServices": ordered(svc, touched),
        "order": to_deploy if outcome == "planned" else [],
        "images": [images[n] for n in ordered(svc, images)],
        "unchanged": sorted(n for n in desired if n not in to_deploy),
        "restore": {n: s["digest"] for n, s in sorted(state.items()) if n not in to_deploy},
        "envDeploy": env_deploy, "productionBefore": state, "problems": problems,
        "environment": "production" if mode == "train" else "production-emergency",
    }


def subject_lines(p, repo=None):
    repo = repo or REPO
    lines = [f"{subject_key('train', p['trainDate'], repo)}  sox:train:{p['trainDate']}",
             f"{subject_key('commit', p['cutoffSha'], repo)}  sox:commit:{p['cutoffSha']}"]
    lines += [f"{subject_key('release', r['slug'], repo)}  sox:release:{r['slug']}" for r in p["releases"] if r["kind"] == "release"]
    return "\n".join(lines) + "\n"


def plan_digest(p):
    """Digest of the decision content only, so a re-plan after the approval wait can be compared
    with the signed plan."""
    skip = ("planDigest", "observedAt", "rejectedEvidence", "trainId", "trainPlanAttestation")
    return digest_of({k: v for k, v in p.items() if k not in skip})


def go_live_sha(path=None):
    """goLive.mainSha from the trust policy on main: the first train's window starts after it."""
    path = pathlib.Path(path or ROOT / ".sox" / "trust-policy.yaml")
    try:
        sha = json.loads(path.read_text())["goLive"]["mainSha"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return sha if SHA.match(sha or "") else None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["train", "emergency"], default="train")
    ap.add_argument("--cutoff", required=True)
    ap.add_argument("--baseline", default=None, help="tests only; workflows use goLive.mainSha from the trust policy")
    ap.add_argument("--emergency-pr", default=None)
    ap.add_argument("--today", default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--subjects-out", required=True)
    args = ap.parse_args(argv)
    today = dt.date.fromisoformat(args.today) if args.today else dt.datetime.now(dt.timezone.utc).date()
    if args.mode == "emergency" and not (args.emergency_pr or "").isdigit():
        print("refused: --emergency-pr must be a PR number", file=sys.stderr)
        return 2
    baseline = args.baseline or go_live_sha()
    try:
        if not baseline:
            raise RefusedError("goLive.mainSha is not set in the trust policy; no train before go-live")
        p = plan(GitHub(), evidence.fetch, args.cutoff, today, baseline, args.mode, args.emergency_pr)
    except (RefusedError, evidence.EvidenceUnavailable) as e:
        p = {"schema": "sox/common/v1", "repo": REPO, "step": "SDLC-11" if args.mode == "train" else "CC-04",
             "mode": args.mode, "outcome": "refused", "cutoffSha": args.cutoff,
             "trainDate": today.isoformat(), "trainId": f"{today.isoformat()}-{args.mode}", "releases": [],
             "order": [], "images": [], "jiraKeys": [], "problems": [str(e)]}
    p["rejectedEvidence"] = evidence.REJECTED[:50]
    p["observedAt"] = now_iso()
    p["planDigest"] = plan_digest(p)
    write_json(args.out, p)
    with open(args.subjects_out, "w") as f:
        f.write(subject_lines(p))
    print(json.dumps({k: p[k] for k in ("trainId", "outcome", "cutoffSha", "order", "problems")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
