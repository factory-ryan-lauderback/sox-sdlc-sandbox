"""Dev Agent (SDLC-05): select -> [droid exec --auto high, no App key] -> package -> push.

  dev_agent.py select  --snapshot S --out DIR [--key FRQ-n]        (read-only GITHUB_TOKEN, no secrets)
  dev_agent.py package --ctx DIR --work DIR --droid FILE --out DIR  (agent-llm job, after droid)
  dev_agent.py push    --ctx DIR --patch DIR --out DIR              (env agent-dev or agent-qa: App token)

`select` picks one work item from the jira-attestor snapshot and the GitHub API:
- build:   a story in Ready for Dev with a verified techlead-plan for the Epic's current plan.md, its
           dependsOn stories merged into release/<slug>, and release/<slug> already created by the bundler.
- rework:  an open story PR whose head has a verified changes_requested review-verdict (LOOP-R), fewer
           than the maximum rounds since the last human re-plan, and no earlier Dev attempt on that head;
           or a verified failing story-scope qa-result (LOOP-Q, counted per release).
- qafix:   an open release PR whose head has a verified failing qa-result (LOOP-Q): the QA App opens
           qa-fix/<story>-qa-<head> from that head into release/<slug>, for the story whose required
           test failed. One attempt per release head; the bundler merges it after its own review and QA.
- rebuild: a story PR older than the story's latest verified plan (the gate needs the plan to predate
           the branch's first push): a new branch, and the old PR is closed. A story the plan left unchanged
           is carried over (its PR diff re-applied, no model); a changed one is built again.
- rekick:  a burned head (a review run failed or hung without a failing verdict): an empty commit so the
           head gets a fresh review. After REKICK_LIMIT of those the story is escalated instead.
Stories in Blocked - Human Escalation or Re-plan are left alone until a human or the Tech Lead acts.

The model runs in a job with FACTORY_API_KEY and a read-only token only; it returns a patch as an
artifact. `push` holds the role's App token and never runs repository code: it checks the patch (paths
only under the story's services, no control paths, no symlinks or submodules, size), applies it with
`git apply` to the exact base commit select chose, commits as the App and pushes. A run that produces no
usable change escalates the story to a human (once per head; never a silent retry). Nothing here is
evidence: the review, QA and gate steps judge the pushed head.
"""
import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
from common import (REPO, GitHub, dump_json, is_control_path, jira_key, load_json,  # noqa: E402
                    positive_int, set_output)
import checks  # noqa: E402
import rounds  # noqa: E402
from planning_agent import dir_digest, slug  # noqa: E402

REVIEW_CHECK = "sox/review-agent"
MAX_ROUNDS = int(os.environ.get("SOX_MAX_REVIEW_ROUNDS", "10"))
MAX_QA_ROUNDS = int(os.environ.get("SOX_MAX_QA_ROUNDS", "10"))
MAX_PATCH_BYTES = 400_000
MAX_FILES = 60
MAX_PLAN_CHARS = 30_000
REKICK_LIMIT = 3
STALE_OPEN_SECONDS = 2 * 3600
STORY_TYPES = ("dev", "qa")
ESCALATED = "Blocked - Human Escalation"
HANDS_OFF = (ESCALATED, "Re-plan", "Done", "Released")
LLM_MODES = ("build", "rework", "rebuild", "qafix")
PUSH_MODES = LLM_MODES + ("carry", "rekick")
MARK = "<!-- sox-dev-agent"
STORY_BRANCH = re.compile(r"^story/(FRQ-[1-9][0-9]{0,6})-[a-z0-9][a-z0-9-]{0,60}$")
QAFIX_BRANCH = re.compile(r"^qa-fix/(FRQ-[1-9][0-9]{0,6})-[a-z0-9][a-z0-9-]{0,60}$")


def agent_branch_key(ref):
    m = STORY_BRANCH.match(ref) or QAFIX_BRANCH.match(ref)
    return m.group(1) if m else None
RELEASE_BRANCH = re.compile(r"^release/([a-z0-9][a-z0-9-]{0,60})$")
DIFF_FILE = re.compile(rb"^diff --git a/(\S+) b/(\S+)$", re.M)
BAD_MODE = re.compile(rb"^(new|old|deleted file|new file) mode (120000|160000)$", re.M)
JUNK = (":(exclude)**/__pycache__/**", ":(exclude)*.pyc")


# ------------------------------------------------------------------------------------------ helpers

def policy():
    return load_json(os.path.join(ROOT, ".sox", "trust-policy.yaml"))


def app_slug(role):
    return policy()["apps"][role]["slug"]


def release_slug(name):
    """Same rule as the bundler's slugify (tools/sox_release/common.py), so the branch names agree."""
    s = re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")[:40].strip("-")
    return s if s and RELEASE_BRANCH.match("release/" + s) else None


def typ(i):
    return i["type"]["name"]


def status(i):
    return i["status"]["name"]


def keynum(k):
    return int(k.split("-")[1])


def _time(s):
    import datetime as dt
    t = dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)).timestamp()


def plan_for(key, fetch=None):
    """Latest verified techlead-plan with an entry for the story: (attestation, entry) or (None, None)."""
    verified, _ = (fetch or rounds.fetch)("jira", key, "techlead-plan")
    best = None
    for a in verified:
        entry = next((s for s in a.predicate.get("stories", []) if s.get("key") == key), None)
        if entry and (best is None or (a.integrated_time, a.digest) > (best[0].integrated_time, best[0].digest)):
            best = (a, entry)
    return best or (None, None)


def check_paths(files, services):
    """Problems with a change set: only files under services/<svc>/ of the story's own services."""
    problems = []
    if not files:
        return ["no files changed"]
    if len(files) > MAX_FILES:
        problems.append(f"{len(files)} files changed (limit {MAX_FILES})")
    for p in files:
        if is_control_path(p):
            problems.append(f"{p}: control path")
        elif ".." in p.split("/") or p.startswith("/"):
            problems.append(f"{p}: not a plain repository path")
        elif not any(p.startswith(f"services/{s}/") for s in services):
            problems.append(f"{p}: outside the story's services {services}")
    return problems


def patch_problems(patch, files, services):
    problems = []
    if len(patch) > MAX_PATCH_BYTES:
        problems.append(f"patch is {len(patch)} bytes (limit {MAX_PATCH_BYTES})")
    if BAD_MODE.search(patch):
        problems.append("patch adds a symlink or submodule")
    named = sorted({m.decode() for pair in DIFF_FILE.findall(patch) for m in pair})
    if sorted(set(files)) != named:
        problems.append("patch file list does not match its metadata")
    return problems + check_paths(named, services)


class Repo:
    """GitHub reads select and push need. Everything is re-read here, never taken from an event."""

    def __init__(self, gh):
        self.gh = gh
        self.owner = REPO.split("/")[0]

    def branch_sha(self, branch):
        try:
            ref = self.gh.get(f"/repos/{REPO}/git/ref/heads/{branch}")
        except RuntimeError as e:
            if "HTTP 404" in str(e):
                return None
            raise
        return (ref.get("object") or {}).get("sha") if isinstance(ref, dict) else None

    def _open_prs(self):
        if not hasattr(self, "_open"):
            self._open = [pr for pr in self.gh.paginate(f"/repos/{REPO}/pulls?state=open&sort=created&direction=asc", limit=300)
                          if (pr["head"].get("repo") or {}).get("full_name") == REPO]
        return self._open

    def open_story_prs(self):
        """Open story/* and qa-fix/* PRs into release/*."""
        return [pr for pr in self._open_prs()
                if agent_branch_key(pr["head"]["ref"]) and RELEASE_BRANCH.match(pr["base"]["ref"])]

    def open_release_prs(self):
        return [pr for pr in self._open_prs() if RELEASE_BRANCH.match(pr["head"]["ref"]) and pr["base"]["ref"] == "main"]

    def merged_story_keys(self, base_branch):
        keys = set()
        for pr in self.gh.paginate(f"/repos/{REPO}/pulls?state=closed&base={base_branch}", limit=500):
            m = re.match(r"^(story|qa-fix)/(FRQ-[0-9]+)-", pr["head"]["ref"])
            if pr.get("merged_at") and m:
                keys.add(m.group(2))
        return keys

    def prs_for_head(self, branch, state="all"):
        return self.gh.paginate(f"/repos/{REPO}/pulls?state={state}&head={self.owner}:{branch}", limit=50)

    def first_push_at(self, branch):
        ref = f"refs/heads/{branch}".replace("/", "%2F")
        acts = self.gh.paginate(f"/repos/{REPO}/activity?ref={ref}&direction=asc", limit=300)
        times = [_time(a["timestamp"]) for a in acts
                 if a.get("activity_type") in ("push", "force_push", "branch_creation")]
        return min(times, default=None)

    def review_runs(self, head):
        res = self.gh.get(f"/repos/{REPO}/commits/{head}/check-runs?check_name={REVIEW_CHECK}&filter=all&per_page=100")
        return [r for r in res.get("check_runs", []) if (r.get("app") or {}).get("slug") == app_slug("review")]

    def marks(self, number, bots):
        """Dev Agent markers on the PR: heads already attempted without a change, and rekick count."""
        nochange, rekicks = set(), 0
        for c in self.gh.paginate(f"/repos/{REPO}/issues/{number}/comments", limit=300):
            if (c.get("user") or {}).get("login") not in bots:
                continue
            for kind, head in re.findall(r"<!-- sox-dev-agent (no-change|rekick) head=([0-9a-f]{40}) -->", c.get("body") or ""):
                if kind == "no-change":
                    nochange.add(head)
                else:
                    rekicks += 1
        return nochange, rekicks

    def free_branch(self, key, summary):
        base = f"story/{key}-{slug(summary, 40) or 'change'}"
        for n in range(1, 50):
            name = base if n == 1 else f"{base}-r{n}"
            if self.branch_sha(name) is None and not self.prs_for_head(name):
                return name
        raise RuntimeError(f"no free branch name for {key}")


# --------------------------------------------------------------------------------------------- select

def _plan_ok(key, issues, fetch):
    att, entry = plan_for(key, fetch)
    if att is None:
        return None, None, "no verified techlead-plan covers it"
    if entry.get("type") not in STORY_TYPES:
        return None, None, f"the plan gives type {entry.get('type')!r}, not dev or qa"
    epic = issues.get(att.predicate.get("epicKey")) or {}
    pm = epic.get("planMd")
    if not pm or f"sha256:{pm['sha256']}" != att.predicate.get("planDigest"):
        return None, None, "the Epic's current plan.md is not attested yet (waiting for sox-jira-attestor)"
    return att, entry, "ok"


def _failing_rounds(key):
    heads, _ = rounds.failing_heads(("jira", key))
    return len(heads)


def _qa_rounds(rel):
    heads, _ = rounds.failing_heads(("release", rel), predicate="qa-result")
    return len(heads)


def failed_tests(qa):
    return [t for t in qa.predicate.get("tests") or [] if t.get("status") not in ("passed", "pass")]


def qafix_branch(key, head):
    return f"qa-fix/{key}-qa-{head[:10]}"


def _qafix_item(rpr, issues, repo, story_prs, bots, hint, fetch, log):
    """A release head with a verified failing qa-result gets one qa-fix attempt, for the story that owns
    the first failing required test."""
    n, head, rel = rpr["number"], rpr["head"]["sha"], RELEASE_BRANCH.match(rpr["head"]["ref"]).group(1)
    qa = rounds.verdict_for_head(head, "refs/heads/main", predicate="qa-result")
    if qa is None or qa.predicate.get("outcome") != "fail":
        return None
    done = _qa_rounds(rel)
    if done >= MAX_QA_ROUNDS:
        log.append(f"release PR #{n}: {done} QA rounds, loop exhausted (the QA agent escalates)"); return None
    if any(p["head"]["ref"].startswith("qa-fix/") and p["base"]["ref"] == f"release/{rel}" for p in story_prs):
        log.append(f"release PR #{n}: a qa-fix PR into release/{rel} is open; waiting"); return None
    if head in repo.marks(n, bots)[0]:
        log.append(f"release PR #{n}: head {head[:12]} already attempted without a change"); return None
    failing = failed_tests(qa)
    owner = None
    for key in qa.predicate.get("jiraKeys") or []:
        _, entry = plan_for(key, fetch)
        if entry and any(t["id"] in (entry.get("requiredTests") or []) for t in failing):
            owner = key
            break
    if owner is None or (hint and owner != hint):
        if owner is None:
            log.append(f"release PR #{n}: no story's plan owns the failing tests"); return None
        return None
    issue = issues.get(owner)
    if issue is None or status(issue) in (ESCALATED, "Re-plan"):
        log.append(f"release PR #{n} {owner}: story is {status(issue) if issue else 'not in the snapshot'}"); return None
    att, entry, why = _plan_ok(owner, issues, fetch)
    if att is None:
        log.append(f"release PR #{n} {owner}: {why}"); return None
    branch = qafix_branch(owner, head)
    if repo.branch_sha(branch) is not None or repo.prs_for_head(branch):
        log.append(f"release PR #{n}: {branch} already exists (one qa-fix per release head)"); return None
    log.append(f"release PR #{n} {owner}: verified failing qa-result on {head[:12]} -> qafix (QA round {done + 1})")
    return {"key": owner, "role": "qa", "mode": "qafix", "pr": None, "releasePr": n, "baseBranch": f"release/{rel}",
            "baseSha": head, "head": head, "branch": branch, "plan": att, "entry": entry, "issue": issue,
            "qaResult": qa, "round": done + 1}


def _release_of(issue):
    names = [v["name"] for v in issue.get("fixVersions") or [] if not v.get("released")]
    return release_slug(names[0]) if len(names) == 1 else None


def scan(issues, repo, hint=None, fetch=None, now=None):
    """Pick one work item. Returns (item or None, jira ops for housekeeping, log lines)."""
    now = now or time.time()
    log, ops = [], []
    bots = {f"{app_slug(r)}[bot]" for r in STORY_TYPES}
    busy = set()
    story_prs = repo.open_story_prs()
    for pr in story_prs:
        key = agent_branch_key(pr["head"]["ref"])
        qafix_pr = pr["head"]["ref"].startswith("qa-fix/")
        busy.add(key)
        if hint and key != hint:
            continue
        n, head, branch = pr["number"], pr["head"]["sha"], pr["head"]["ref"]
        issue = issues.get(key)
        if pr["user"]["login"] not in bots:
            log.append(f"PR #{n} {key}: not opened by an agent App; left to its author"); continue
        if issue is None:
            log.append(f"PR #{n} {key}: story not in the Jira snapshot"); continue
        if status(issue) in HANDS_OFF:
            log.append(f"PR #{n} {key}: story is {status(issue)}"); continue
        att, entry, why = _plan_ok(key, issues, fetch)
        if att is None:
            log.append(f"PR #{n} {key}: {why}"); continue
        # Only the QA App may push to qa-fix/** (trust policy pushers), whatever the story type.
        base = {"key": key, "role": "qa" if qafix_pr else entry["type"], "pr": n, "oldBranch": branch,
                "baseBranch": pr["base"]["ref"], "plan": att, "entry": entry, "issue": issue}
        first = repo.first_push_at(branch)
        if first is not None and att.integrated_time > first and qafix_pr:
            log.append(f"PR #{n} {key}: qa-fix branch predates the story's latest plan; left for the rebuilt story"); continue
        if first is not None and att.integrated_time > first:
            sha = repo.branch_sha(pr["base"]["ref"])
            mode = "rebuild" if status(issue) == "Ready for Dev" else "carry"
            log.append(f"PR #{n} {key}: plan {att.digest[:19]} is newer than the branch's first push -> {mode}")
            return {**base, "mode": mode, "baseSha": sha, "branch": repo.free_branch(key, issue["summary"])}, ops, log
        verdict = rounds.verdict_for_head(head, f"refs/heads/{pr['base']['ref']}")
        runs = repo.review_runs(head)
        state = checks.head_state(runs)
        nochange, rekicks = repo.marks(n, bots)
        if head in nochange:
            log.append(f"PR #{n} {key}: head {head[:12]} already attempted without a change"); continue
        if verdict is not None and verdict.predicate.get("outcome") == "changes_requested":
            done = _failing_rounds(key)
            if done >= MAX_ROUNDS:
                log.append(f"PR #{n} {key}: {done} rounds, loop exhausted (the review agent escalates)"); continue
            log.append(f"PR #{n} {key}: verified changes_requested on {head[:12]} -> rework (round {done + 1})")
            return {**base, "mode": "rework", "baseSha": head, "head": head, "branch": branch,
                    "verdict": verdict, "round": done + 1}, ops, log
        qa = rounds.verdict_for_head(head, f"refs/heads/{pr['base']['ref']}", predicate="qa-result")
        if qa is not None and qa.predicate.get("outcome") == "fail":
            rel = RELEASE_BRANCH.match(pr["base"]["ref"]).group(1)
            done = _qa_rounds(rel)
            if done >= MAX_QA_ROUNDS:
                log.append(f"PR #{n} {key}: {done} QA rounds for release {rel}, loop exhausted (the QA agent escalates)"); continue
            log.append(f"PR #{n} {key}: verified failing qa-result on {head[:12]} -> rework (QA round {done + 1})")
            return {**base, "mode": "rework", "trigger": "qa", "baseSha": head, "head": head, "branch": branch,
                    "qaResult": qa, "round": done + 1}, ops, log
        stale = state == "open" and all(r.get("started_at") and now - _time(r["started_at"]) > STALE_OPEN_SECONDS
                                        for r in runs if r["status"] != "completed")
        if (state == "burned" and verdict is None) or stale:
            if rekicks >= REKICK_LIMIT:
                log.append(f"PR #{n} {key}: head {head[:12]} burned again after {rekicks} fresh-review commits -> escalate")
                ops += [{"op": "transition", "key": key, "to": ESCALATED},
                        {"op": "comment", "key": key, "body": f"Dev Agent: PR #{n} head {head[:12]} has a failed or hung "
                         f"{REVIEW_CHECK} run without a verdict after {rekicks} fresh-review commits. A human must "
                         "look at the review workflow, then move the story to Re-plan."}]
                continue
            log.append(f"PR #{n} {key}: head {head[:12]} is burned without a verdict -> rekick")
            return {**base, "mode": "rekick", "baseSha": head, "head": head, "branch": branch}, ops, log
        log.append(f"PR #{n} {key}: review state {state}; waiting")
    for rpr in repo.open_release_prs():
        item = _qafix_item(rpr, issues, repo, story_prs, bots, hint, fetch, log)
        if item:
            return item, ops, log
    merged_cache = {}

    def merged(base_branch):
        if base_branch not in merged_cache:
            merged_cache[base_branch] = repo.merged_story_keys(base_branch)
        return merged_cache[base_branch]

    stories = sorted((i for i in issues.values() if typ(i) == "Story"), key=lambda i: keynum(i["key"]))
    pick = None
    for s in stories:
        key, st = s["key"], status(s)
        if hint and key != hint:
            continue
        rel = _release_of(s)
        if st in ("In Progress", "In Review") and rel and key not in busy and key in merged(f"release/{rel}"):
            ops.append({"op": "transition", "key": key, "to": "Done"})
            ops.append({"op": "comment", "key": key, "body": f"Dev Agent: the story PR is merged into release/{rel}."})
            continue
        if st != "Ready for Dev" or key in busy or pick:
            continue
        att, entry, why = _plan_ok(key, issues, fetch)
        if att is None:
            log.append(f"{key}: {why}"); continue
        if rel is None:
            log.append(f"{key}: needs exactly one unreleased fix version"); continue
        sha = repo.branch_sha(f"release/{rel}")
        if sha is None:
            log.append(f"{key}: release/{rel} does not exist yet (the bundler creates it once the release-manifest is attested)"); continue
        waiting = sorted(set(entry.get("dependsOn") or []) - merged(f"release/{rel}"))
        if waiting:
            log.append(f"{key}: waits for {waiting} to merge into release/{rel}"); continue
        log.append(f"{key}: Ready for Dev, plan {att.digest[:19]} -> build on release/{rel} @ {sha[:12]}")
        pick = {"key": key, "role": entry["type"], "mode": "build", "pr": None, "baseBranch": f"release/{rel}",
                "baseSha": sha, "branch": repo.free_branch(key, s["summary"]), "plan": att, "entry": entry, "issue": s}
    return pick, ops, log


def _context(item, issues):
    issue, entry, att = item["issue"], item["entry"], item["plan"]
    epic = issues.get(att.predicate.get("epicKey")) or {}
    services = sorted(entry.get("services") or [])
    findings = []
    if item.get("verdict"):
        findings = [{k: f.get(k) for k in ("severity", "path", "line", "title", "body")}
                    for f in item["verdict"].predicate.get("findings") or []][:50]
    failing = [{"id": t.get("id"), "status": t.get("status")} for t in failed_tests(item["qaResult"])][:100] \
        if item.get("qaResult") else []
    ctx = {"key": item["key"], "role": item["role"], "mode": item["mode"], "branch": item["branch"],
           "baseBranch": item["baseBranch"], "baseSha": item["baseSha"], "pr": item.get("pr"),
           "oldBranch": item.get("oldBranch"), "head": item.get("head"), "round": item.get("round"),
           "summary": issue["summary"], "services": services,
           "requiredTests": sorted(entry.get("requiredTests") or []), "dependsOn": sorted(entry.get("dependsOn") or []),
           "epicKey": att.predicate.get("epicKey"), "planDigest": att.predicate.get("planDigest"),
           "planAttestation": att.digest, "reviewVerdict": item["verdict"].digest if item.get("verdict") else None,
           "findings": findings, "snapshotDigest": os.environ.get("JIRA_SNAPSHOT_DIGEST"),
           "trigger": item.get("trigger") or ("qa" if item["mode"] == "qafix" else None),
           "releasePr": item.get("releasePr"), "qaResult": item["qaResult"].digest if item.get("qaResult") else None,
           "failingTests": failing}
    who = "QA Agent" if item["role"] == "qa" else "Dev Agent"
    md = [f"# {who} task: {item['mode']} {item['key']}\n",
          f"Story {item['key']} ({entry['type']} story): {issue['summary']}\n",
          f"Services you may change: {', '.join(services)}. Allowed paths: "
          + ", ".join(f"`services/{s}/`" for s in services) + ".\n",
          f"Required tests (exact unittest IDs that must exist and pass): {', '.join(ctx['requiredTests'])}\n",
          f"Base: `{item['baseBranch']}` at `{item['baseSha']}`.\n",
          f"\n## Story description\n\n{issue.get('description') or ''}\n"]
    if failing:
        where = f"release PR #{item['releasePr']}" if item["mode"] == "qafix" else f"PR #{item['pr']}"
        md.append(f"\n## QA failures to fix (QA round {item.get('round')}, {where} at `{item['head']}`)\n\n"
                  "These plan-required tests did not pass against the deployed environment (status: failed, error, "
                  "skipped or missing). Fix the cause in the allowed paths; do not delete, skip or weaken a required test.\n")
        md.extend(f"\n- `{t['id']}`: {t['status']}" for t in failing)
        md.append("\n")
    if item["mode"] == "rework" and not failing:
        md.append(f"\n## Review findings to fix (round {item.get('round')}, PR #{item['pr']})\n")
        for f in findings:
            loc = f"`{f['path']}`{':' + str(f['line']) if f.get('line') else ''}" if f.get("path") else "(general)"
            md.append(f"\n- **{f.get('severity')}** {loc}: {f.get('title')}\n  {f.get('body')}\n")
    if item["mode"] == "rebuild":
        md.append(f"\n## Re-plan\n\nThe story changed in a new plan. Earlier work was on `{item.get('oldBranch')}` "
                  f"(PR #{item.get('pr')}); start again from the base and follow the current description.\n")
    if epic:
        plan = ((epic.get("planMd") or {}).get("text") or "")[:MAX_PLAN_CHARS]
        md.append(f"\n## Epic {epic['key']}: {epic.get('summary')}\n\n### Current plan.md\n\n{plan}\n")
    return ctx, "".join(md)


def select(args):
    import jira_snapshot
    snap = jira_snapshot.load_verified(args.snapshot, os.environ.get("JIRA_SNAPSHOT_DIGEST"))
    issues = {i["key"]: i for i in snap["issues"]}
    hint = jira_key(args.key) if args.key else None
    item, ops, log = scan(issues, Repo(GitHub()), hint)
    for line in log:
        print(line)
    os.makedirs(args.ops, exist_ok=True)
    dump_json(f"{args.ops}/jira-ops.json", ops)
    if item is None:
        set_output("mode", "none")
        print("dev: nothing to do")
        return
    ctx, md = _context(item, issues)
    if os.path.exists(args.out):
        shutil.rmtree(args.out)
    os.makedirs(args.out)
    dump_json(f"{args.out}/context.json", ctx)
    with open(f"{args.out}/context.md", "w") as f:
        f.write(md)
    set_output("mode", item["mode"])
    set_output("key", item["key"])
    set_output("role", item["role"])
    set_output("base_sha", item["baseSha"])
    set_output("llm", "true" if item["mode"] in LLM_MODES else "false")
    set_output("context_digest", dir_digest(args.out))
    print(f"dev: {item['mode']} {item['key']} as {item['role']} on {item['branch']}")


# -------------------------------------------------------------------------------------------- package

def _git(cwd, *args, check=True, env=None):
    p = subprocess.run(["git", "-C", cwd, *args], capture_output=True, env=env)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed ({p.returncode}): {p.stderr.decode(errors='replace')[-800:]}")
    return p.stdout


def _droid_summary(path):
    try:
        raw = load_json(path)
    except Exception:
        return {"ok": False, "summary": "", "session": None}
    text = str(raw.get("result") or "")
    m = re.search(r"\{.*\}", text, re.S)
    summary = text
    if m:
        try:
            summary = str(json.loads(m.group(0)).get("summary") or text)
        except (ValueError, AttributeError):
            pass
    return {"ok": not raw.get("is_error"), "summary": summary[:2000], "session": raw.get("session_id")}


def package(args):
    """The work tree's change against the base commit, as a patch plus metadata. The checks here are
    for a useful early answer only; push repeats every one of them before anything is written."""
    if dir_digest(args.ctx) != os.environ.get("CONTEXT_DIGEST"):
        raise SystemExit("context artifact does not match the select job's digest")
    ctx = load_json(f"{args.ctx}/context.json")
    os.makedirs(args.out, exist_ok=True)
    _git(args.work, "add", "-A", "--", ".", *JUNK)
    files = [f for f in _git(args.work, "diff", "--cached", "--no-renames", "--name-only", ctx["baseSha"]).decode().splitlines() if f]
    patch = _git(args.work, "diff", "--cached", "--no-renames", "--binary", ctx["baseSha"])
    droid = _droid_summary(args.droid)
    problems = check_paths(files, ctx["services"]) if files else []
    if files and not problems:
        problems = patch_problems(patch, files, ctx["services"])
    outcome = "empty" if not files else ("rejected" if problems else "patch")
    if outcome == "patch":
        with open(f"{args.out}/patch.diff", "wb") as f:
            f.write(patch)
    dump_json(f"{args.out}/meta.json", {"outcome": outcome, "files": sorted(files), "problems": problems[:30],
                                         "summary": droid["summary"], "droidOk": droid["ok"],
                                         "factorySessionId": droid["session"], "baseSha": ctx["baseSha"],
                                         "contextDigest": os.environ.get("CONTEXT_DIGEST")})
    set_output("outcome", outcome)
    set_output("patch_digest", dir_digest(args.out))
    print(f"package: {outcome}, {len(files)} file(s)" + (f"; problems: {problems[:5]}" if problems else ""))


# ----------------------------------------------------------------------------------------------- push

def _bot(gh, role):
    login = f"{app_slug(role)}[bot]"
    uid = gh.get(f"/users/{login.replace('[', '%5B').replace(']', '%5D')}")["id"]
    return login, f"{uid}+{login}@users.noreply.github.com"


def _git_env(token):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("APP_TOKEN", "GITHUB_TOKEN", "GH_"))}
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_COUNT": "2",
                "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
                "GIT_CONFIG_KEY_1": "core.hooksPath", "GIT_CONFIG_VALUE_1": "/dev/null"})
    return env


def commit_and_push(token, base_sha, branch, patch, message, author, allow_empty=False, remote=None):
    """Apply the patch to base_sha and push it to refs/heads/<branch>. No repository code runs: git
    hooks are off, and only `git apply`, `git commit` and `git push` touch the tree."""
    env = _git_env(token)
    d = tempfile.mkdtemp(prefix="sox-dev-")
    try:
        _git(d, "init", "-q", env=env)
        _git(d, "remote", "add", "origin", remote or f"https://github.com/{REPO}.git", env=env)
        _git(d, "fetch", "-q", "--depth=1", "origin", base_sha, env=env)
        _git(d, "checkout", "-q", "--detach", "FETCH_HEAD", env=env)
        if _git(d, "rev-parse", "HEAD", env=env).decode().strip() != base_sha:
            raise RuntimeError("fetched base is not the commit select chose")
        if patch:
            pf = os.path.join(d, ".git", "sox.patch")
            with open(pf, "wb") as f:
                f.write(patch)
            _git(d, "apply", "--index", "--whitespace=nowarn", pf, env=env)
        name, email = author
        _git(d, "-c", f"user.name={name}", "-c", f"user.email={email}", "commit", "-q",
             *(["--allow-empty"] if allow_empty else []), "-m", message, env=env)
        sha = _git(d, "rev-parse", "HEAD", env=env).decode().strip()
        _git(d, "push", "-q", "origin", f"HEAD:refs/heads/{branch}", env=env)
        return sha
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _run_url():
    if os.environ.get("GITHUB_RUN_ID"):
        return f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{REPO}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    return ""


def push(args, pusher=commit_and_push):
    role = os.environ["ROLE"]
    if role not in STORY_TYPES:
        raise SystemExit("bad role")
    os.makedirs(args.out, exist_ok=True)
    ops_path = f"{args.out}/jira-ops.json"
    dump_json(ops_path, [])
    if dir_digest(args.ctx) != os.environ.get("CONTEXT_DIGEST"):
        raise SystemExit("context artifact does not match the select job's digest")
    ctx = load_json(f"{args.ctx}/context.json")
    if ctx["role"] != role or ctx["mode"] not in PUSH_MODES:
        raise SystemExit(f"context is for {ctx['role']}/{ctx['mode']}, this job pushes as {role}")
    key, mode, n = jira_key(ctx["key"]), ctx["mode"], ctx.get("pr")
    qafix_ref = bool(QAFIX_BRANCH.match(ctx["branch"]))
    bad_branch = agent_branch_key(ctx["branch"]) != key or not RELEASE_BRANCH.match(ctx["baseBranch"])
    if mode == "qafix":
        bad_branch = bad_branch or not qafix_ref
    if qafix_ref:
        # qa-fix/** is the QA App's alone, and only qafix creates one; rework/rekick only continue it.
        bad_branch = bad_branch or role != "qa" or mode not in ("qafix", "rework", "rekick")
    if bad_branch:
        raise SystemExit("branch names in the context are not story|qa-fix/<key>-* and release/<slug> for this mode and role")
    gh, app = GitHub(), GitHub(os.environ["APP_TOKEN"])
    repo = Repo(gh)
    who = "QA Agent" if role == "qa" else "Dev Agent"
    bots = {f"{app_slug(r)}[bot]" for r in STORY_TYPES}
    ops = []

    def write_ops():
        dump_json(ops_path, ops)

    def escalate(reason):
        ops.extend([{"op": "transition", "key": key, "to": ESCALATED},
                    {"op": "comment", "key": key, "body": f"{who}: {reason} Escalated to a human: fix the story or "
                     f"plan and move it to Re-plan. {_run_url()}".strip()}])
        target = n or ctx.get("releasePr")
        if target and ctx.get("head"):
            app.request("POST", f"/repos/{REPO}/issues/{target}/comments",
                        {"body": f"{MARK} no-change head={ctx['head']} -->\n{who}: {reason}"})
        write_ops()
        print(f"push: escalated ({reason})")

    # Re-read the state select acted on; anything that moved means another run owns it now.
    if mode in ("rework", "rekick"):
        pr = gh.pr(positive_int(n, "pr"))
        if pr["state"] != "open" or pr["head"]["sha"] != ctx["head"] or pr["head"]["ref"] != ctx["branch"]:
            return print("push: the PR moved since select; nothing to do")
        if pr["user"]["login"] not in bots:
            raise SystemExit("PR is not an agent App's")
        if mode == "rework" and ctx.get("trigger") == "qa":
            v = rounds.verdict_for_head(ctx["head"], f"refs/heads/{ctx['baseBranch']}", predicate="qa-result")
            if v is None or v.predicate.get("outcome") != "fail":
                raise SystemExit("no verified failing qa-result for this head")
            if _qa_rounds(RELEASE_BRANCH.match(ctx["baseBranch"]).group(1)) >= MAX_QA_ROUNDS:
                return print("push: QA loop exhausted; the QA agent escalates")
        elif mode == "rework":
            v = rounds.verdict_for_head(ctx["head"], f"refs/heads/{ctx['baseBranch']}")
            if v is None or v.predicate.get("outcome") != "changes_requested":
                raise SystemExit("no verified changes_requested verdict for this head")
            if _failing_rounds(key) >= MAX_ROUNDS:
                return print("push: loop exhausted; the review agent escalates")
    elif mode == "qafix":
        rpr = gh.pr(positive_int(ctx.get("releasePr"), "release pr"))
        if rpr["state"] != "open" or rpr["head"]["sha"] != ctx["head"] or rpr["head"]["ref"] != ctx["baseBranch"] \
                or ctx["baseSha"] != ctx["head"]:
            return print("push: the release PR moved since select; nothing to do")
        v = rounds.verdict_for_head(ctx["head"], "refs/heads/main", predicate="qa-result")
        if v is None or v.predicate.get("outcome") != "fail":
            raise SystemExit("no verified failing qa-result for this release head")
        if _qa_rounds(RELEASE_BRANCH.match(ctx["baseBranch"]).group(1)) >= MAX_QA_ROUNDS:
            return print("push: QA loop exhausted; the QA agent escalates")
        if repo.branch_sha(ctx["branch"]) is not None:
            return print(f"push: {ctx['branch']} already exists; nothing to do")
    else:
        if repo.branch_sha(ctx["branch"]) is not None:
            return print(f"push: {ctx['branch']} already exists; nothing to do")
        if repo.branch_sha(ctx["baseBranch"]) is None:
            raise SystemExit(f"{ctx['baseBranch']} does not exist")

    patch, summary, allow_empty = b"", "", False
    if mode in LLM_MODES:
        meta = {}
        if os.environ.get("CODE_RESULT") == "success" and os.path.exists(f"{args.patch}/meta.json"):
            if dir_digest(args.patch) != os.environ.get("PATCH_DIGEST"):
                raise SystemExit("patch artifact does not match the code job's digest")
            meta = load_json(f"{args.patch}/meta.json")
        if meta.get("outcome") != "patch" or meta.get("baseSha") != ctx["baseSha"]:
            why = {"empty": "the agent produced no change", "rejected": "the agent's change broke the path rules: "
                   + "; ".join(meta.get("problems") or [])[:1500]}.get(meta.get("outcome"), "the coding job did not finish")
            return escalate(f"{why}.")
        with open(f"{args.patch}/patch.diff", "rb") as f:
            patch = f.read()
        bad = patch_problems(patch, meta["files"], ctx["services"])
        if bad:
            return escalate("the patch failed the push checks: " + "; ".join(bad)[:1500] + ".")
        summary = meta.get("summary") or ""
    elif mode == "carry":
        patch = gh.pr_diff(positive_int(n, "pr"))
        files = sorted({m.decode() for pair in DIFF_FILE.findall(patch) for m in pair})
        bad = patch_problems(patch, files, ctx["services"])
        if bad:
            return escalate(f"PR #{n} cannot be carried to the new plan: " + "; ".join(bad)[:1500] + ".")
        summary = f"Carried over from PR #{n} unchanged: the story is the same in the new plan."
    else:
        allow_empty = True
        summary = "Empty commit: the previous head's review run failed or hung without a verdict, so it needs a fresh review."

    title = f"{key}: {ctx['summary']}"[:120]
    message = (f"{title}\n\n{summary}\n\nSox-Story: {key}\nSox-Mode: {mode}\nSox-Plan: {ctx['planAttestation']}\n"
               + (f"Sox-Review-Verdict: {ctx['reviewVerdict']}\n" if ctx.get("reviewVerdict") else "")
               + (f"Sox-QA-Result: {ctx['qaResult']}\n" if ctx.get("qaResult") else "")
               + (f"Sox-Run: {_run_url()}\n" if _run_url() else ""))
    try:
        sha = pusher(os.environ["APP_TOKEN"], ctx["baseSha"], ctx["branch"], patch, message, _bot(gh, role), allow_empty)
    except RuntimeError as e:
        if "apply" in str(e) and mode in ("carry",) + LLM_MODES:
            return escalate("the change does not apply to the base commit.")
        raise
    if mode in ("rework", "rekick"):
        if mode == "rekick":
            app.request("POST", f"/repos/{REPO}/issues/{n}/comments",
                        {"body": f"{MARK} rekick head={ctx['head']} -->\n{who}: pushed {sha[:12]} so the PR gets a fresh review."})
        kind = "QA" if ctx.get("trigger") == "qa" else "review"
        ops.append({"op": "comment", "key": key, "body": f"{who} pushed {sha[:12]} to PR #{n} ({mode}"
                    + (f", {kind} round {ctx['round']}" if ctx.get("round") else "") + f"). {_run_url()}".strip()})
    else:
        body = (f"Story **{key}**: {ctx['summary']}\n\n{summary[:3000]}\n\n"
                + (f"- QA fix for release PR #{ctx['releasePr']} at `{ctx['head']}` (qa-result `{ctx['qaResult']}`, "
                   f"QA round {ctx['round']})\n" if mode == "qafix" else "")
                + f"- Plan: `{ctx['planAttestation']}` (plan.md {ctx['planDigest']})\n"
                f"- Required tests: {', '.join(ctx['requiredTests'])}\n- Opened by the {who} in {_run_url() or 'a local run'}\n")
        new = app.request("POST", f"/repos/{REPO}/pulls", {"title": title, "head": ctx["branch"],
                                                           "base": ctx["baseBranch"], "body": body})
        if n:
            app.request("POST", f"/repos/{REPO}/issues/{n}/comments",
                        {"body": f"{who}: superseded by #{new['number']}; the story's plan changed after this branch was first pushed."})
            app.request("PATCH", f"/repos/{REPO}/pulls/{n}", {"state": "closed"})
        ops.extend([{"op": "transition", "key": key, "to": "In Review"},
                    {"op": "comment", "key": key, "body": f"{who} opened PR #{new['number']} ({new['html_url']}) from "
                     f"{ctx['branch']} at {sha[:12]} ({mode})."}])
    write_ops()
    print(f"push: {mode} {key} -> {ctx['branch']} @ {sha[:12]}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("select"); s.add_argument("--snapshot", required=True); s.add_argument("--out", required=True)
    s.add_argument("--ops", required=True); s.add_argument("--key", default="")
    p = sub.add_parser("package"); p.add_argument("--ctx", required=True); p.add_argument("--work", required=True)
    p.add_argument("--droid", required=True); p.add_argument("--out", required=True)
    u = sub.add_parser("push"); u.add_argument("--ctx", required=True); u.add_argument("--patch", required=True)
    u.add_argument("--out", required=True)
    args = ap.parse_args()
    {"select": select, "package": package, "push": push}[args.cmd](args)


if __name__ == "__main__":
    main()
