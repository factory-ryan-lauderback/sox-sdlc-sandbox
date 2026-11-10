"""SDLC-07 environment planning: which environment a PR gets, and which images go into it.

Runs in a job that holds no secrets beyond a read-only token, and reads the PR only through the
API (never by checking out or executing PR code).
"""
import argparse
import json
import sys

from tools.sox_release import evidence
from tools.sox_release.common import (HOTFIX_BRANCH, RELEASE_BRANCH, SHA, STORY_BRANCH, RefusedError, k8s_name, ordered,
                                      services, services_touched, upstream_closure, write_json)
from tools.sox_release.gh import GitHub


def chain_root(story_key, plans):
    """Root of the story's dependency chain in the verified Tech Lead plan (follow dependsOn up)."""
    deps = {}
    for plan in plans:
        for s in plan.get("stories", []):
            deps[s["key"]] = sorted(s.get("dependsOn") or [])
    if story_key not in deps:
        return None
    seen, key = set(), story_key
    while deps.get(key):
        if key in seen:
            raise RefusedError(f"dependency cycle at {key}")
        seen.add(key)
        key = deps[key][0]
    return key


def tree_of(gh, commit, path):
    tree = gh.get(f"/repos/{{repo}}/git/commits/{commit}")["tree"]["sha"]
    for part in path.split("/"):
        entries = gh.get(f"/repos/{{repo}}/git/trees/{tree}")["tree"]
        hit = [e for e in entries if e["path"] == part and e["type"] == "tree"]
        if not hit:
            return None
        tree = hit[0]["sha"]
    return tree


def plan(gh, pr_number, fetch=evidence.fetch, root=None):
    pr = gh.get(f"/repos/{{repo}}/pulls/{int(pr_number)}")
    if pr["state"] != "open":
        raise RefusedError(f"PR #{pr_number} is {pr['state']}")
    head, head_ref, base_ref = pr["head"]["sha"], pr["head"]["ref"], pr["base"]["ref"]
    if pr["head"]["repo"]["full_name"] != gh.repo:
        raise RefusedError("PR head is in another repository")
    if not SHA.match(head):
        raise RefusedError("bad head SHA")
    svc = services(root) if root else services()
    files = [f["filename"] for f in gh.paginate(f"/repos/{{repo}}/pulls/{int(pr_number)}/files")]
    touched, other = services_touched(files, svc)
    chain = {"root": None, "source": None}
    if base_ref == "main":
        m, hm = RELEASE_BRANCH.match(head_ref), HOTFIX_BRANCH.match(head_ref)
        if not (m or hm):
            raise RefusedError(f"a PR into main must come from release/* or hotfix/FRQ-n-*, not {head_ref}")
        slug = m.group(1) if m else k8s_name(head_ref.split("/", 1)[1])
        mode, env_id, names = ("release" if m else "emergency"), k8s_name(f"qa-{slug}"), set(svc)
        jira_keys = [hm.group(1)] if hm else []
        if m:
            try:
                mans = [i for i in fetch(f"release:{slug}", "release-manifest") if i["predicate"].get("release") == slug]
            except evidence.EvidenceUnavailable as e:
                mans, chain["error"] = [], str(e)
            jira_keys = sorted(evidence.latest(mans)["predicate"].get("jiraKeys") or []) if mans else []
    else:
        sm, rm = STORY_BRANCH.match(head_ref), RELEASE_BRANCH.match(base_ref)
        if not (sm and rm):
            raise RefusedError(f"story environments need story/FRQ-n-* or qa-fix/FRQ-n-* into release/*, got {head_ref} -> {base_ref}")
        slug, story = rm.group(1), sm.group(2)
        jira_keys = [story]
        try:
            plans = [p["predicate"] for p in fetch(f"jira:{story}", "techlead-plan")]
        except evidence.EvidenceUnavailable as e:
            plans, chain["error"] = [], str(e)
        root_key = chain_root(story, plans)
        chain = {"root": root_key or story, "source": "techlead-plan" if root_key else "story-only", **({"error": chain["error"]} if "error" in chain else {})}
        mode, env_id = "story", k8s_name(f"eph-{chain['root']}")
        names = upstream_closure(svc, touched) if touched else set(svc)
    return {
        "schema": "sox/env-plan/v1",
        "repo": gh.repo, "prNumber": int(pr_number), "headSha": head, "headRef": head_ref,
        "baseRef": "refs/heads/" + base_ref, "baseSha": pr["base"]["sha"], "release": slug,
        "jiraKeys": jira_keys, "mode": mode, "envId": env_id, "chain": chain,
        "touchedServices": ordered(svc, touched), "nonServicePaths": other,
        "services": [{"service": n, "sourceTree": tree_of(gh, head, f"services/{n}")} for n in ordered(svc, names)],
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pr", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    if not args.pr.isdigit() or int(args.pr) <= 0:
        print("refused: --pr must be a positive integer", file=sys.stderr)
        return 2
    try:
        out = plan(GitHub(), int(args.pr))
    except RefusedError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    write_json(args.out, out)
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
