"""Decide which PR (if any) an sox-env-deploy run serves. Trigger payloads are hints: everything
that matters is re-read from the API. Only a PR number ever leaves this module.
"""
import argparse
import json
import os
import pathlib
import sys

from tools.sox_release import evidence
from tools.sox_release.common import RELEASE_BRANCH, ROOT
from tools.sox_release.gh import GitHub

REVIEW_CHECK = "sox/review-agent"


def trust_policy_app_id(role, path=None):
    """apps.<role>.id from .sox/trust-policy.yaml on main (JSON syntax). None when absent or null,
    which makes every App-pinned check fail closed."""
    path = pathlib.Path(path or ROOT / ".sox" / "trust-policy.yaml")
    try:
        app_id = json.loads(path.read_text())["apps"][role]["id"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return app_id if isinstance(app_id, int) and app_id > 0 else None


def review_passed(gh, head_sha, review_app_id):
    if not review_app_id:
        return False
    runs = gh.get(f"/repos/{{repo}}/commits/{head_sha}/check-runs?check_name={REVIEW_CHECK}&filter=latest")
    return any(r["app"]["id"] == review_app_id and r["status"] == "completed" and r["conclusion"] == "success"
               for r in runs.get("check_runs", []))


def eligible(pr):
    base, head = pr["base"]["ref"], pr["head"]["ref"]
    return pr["state"] == "open" and (RELEASE_BRANCH.match(base) or base == "main")


def from_check_run(gh, event, review_app_id):
    cr_id = event.get("check_run", {}).get("id")
    if not isinstance(cr_id, int):
        return None, "no check run id"
    cr = gh.get(f"/repos/{{repo}}/check-runs/{cr_id}")
    if cr["name"] != REVIEW_CHECK:
        return None, f"ignored check {cr['name']!r}"
    if not review_app_id or cr["app"]["id"] != review_app_id:
        return None, "check run not from the Review App in the trust policy"
    if cr["conclusion"] != "success":
        return None, f"review concluded {cr['conclusion']}"
    for pr in gh.get(f"/repos/{{repo}}/commits/{cr['head_sha']}/pulls"):
        if pr["head"]["sha"] == cr["head_sha"] and eligible(pr):
            return pr["number"], "review passed on current head"
    return None, "no open PR whose current head is this check run's SHA"


def sweep(gh, review_app_id, fetch=evidence.fetch, limit=1):
    """Open PRs whose current head passed review but has no passing env-deploy. The scheduled run
    serves the first one itself, so this workflow never needs actions:write to dispatch."""
    todo = []
    for pr in gh.paginate("/repos/{repo}/pulls?state=open&sort=created&direction=asc"):
        if not eligible(pr) or not review_passed(gh, pr["head"]["sha"], review_app_id):
            continue
        try:
            done = [i for i in fetch(f"commit:{pr['head']['sha']}", "env-deploy") if i["predicate"].get("outcome") == "pass"]
        except evidence.EvidenceUnavailable:
            return []
        if not done:
            todo.append(pr["number"])
    return todo[:limit]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--event-name", required=True)
    ap.add_argument("--dispatch-pr", default="")
    args = ap.parse_args(argv)
    gh = GitHub()
    review_app_id = trust_policy_app_id("review")
    pr, why, sweep_list = None, "", []
    if args.event_name == "workflow_dispatch":
        if not args.dispatch_pr.isdigit() or int(args.dispatch_pr) <= 0:
            print("refused: pr input must be a positive integer", file=sys.stderr)
            return 2
        pr, why = int(args.dispatch_pr), "manual or sweep dispatch"
    elif args.event_name == "check_run":
        event = json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        pr, why = from_check_run(gh, event, review_app_id)
    elif args.event_name == "schedule":
        sweep_list = sweep(gh, review_app_id)
        pr = sweep_list[0] if sweep_list else None
        why = "sweep: oldest reviewed head without a passing env-deploy" if pr else "sweep: nothing to do"
    else:
        print(f"refused: unsupported trigger {args.event_name}", file=sys.stderr)
        return 2
    print(f"selected PR: {pr} ({why})")
    with open(os.environ.get("GITHUB_OUTPUT", os.devnull), "a") as f:
        f.write(f"pr={pr or ''}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
