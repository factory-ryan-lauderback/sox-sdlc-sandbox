"""PM Agent (SDLC-02) and Tech Lead Agent (SDLC-03): select -> [droid exec, read-only] -> parse -> compose.

  planning_agent.py select  --role pm|techlead --snapshot S --out DIR [--key FRQ-n]   (no secrets)
  planning_agent.py parse   --role R --dir DIR                                         (agent-llm job)
  planning_agent.py compose --role R --ctx DIR --out DIR                               (no secrets)

`select` reads the jira-attestor snapshot (accepted only if its bytes match the producing job's digest),
picks one work item and writes a context directory (context.json, context.md, repository files) whose
digest is a job output. The model sees only that directory, as data, and returns a JSON proposal as a
job output. `compose` checks the proposal against the context with fixed rules and turns it into a
Jira operation list; the only writer is sox-jira-write.yml with the role fixed in the workflow file.
Nothing here is evidence: the jira-attestor signs pm-decomposition and techlead-plan from its own
Jira read. A malformed proposal writes nothing and fails the run; the next sweep tries again.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import jira_adapter as ja  # noqa: E402
from common import REPO, GitHub, digest_of, dump_json, jira_key, load_json, set_output  # noqa: E402

ROLES = ("pm", "techlead")
PLANNING = ("Planning", "Re-plan")
PLANNED = ("Plan Ready", "Approach Approved", "Ready for Dev", "In Progress", "In Review")
# Blocked - Human Escalation is not here: an escalated story waits until a human moves it to Re-plan.
STORY_REWORK = ("Re-plan",)
MAX_EPICS = 5
MAX_STORIES = 15
TEST_ID = re.compile(r"^services\.(db|api|ui)\.[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*){0,3}$")
REF = re.compile(r"^s[0-9]{1,3}$")
REPO_FILES = ("README.md", ".sox/services.yaml")
CONTEXT_SKIP = ("droid.json", "droid.err")


# ------------------------------------------------------------------------------------------ helpers

def dir_digest(path):
    """Digest of every file in the context directory (relative path + sha256), droid output excluded."""
    entries = []
    for base, _, files in os.walk(path):
        for name in files:
            rel = os.path.relpath(os.path.join(base, name), path)
            if rel in CONTEXT_SKIP:
                continue
            with open(os.path.join(base, name), "rb") as f:
                entries.append([rel, hashlib.sha256(f.read()).hexdigest()])
    return digest_of(sorted(entries))


def services():
    """Service names from .sox/services.yaml on main (simple line parse; the file is control-owned)."""
    names = []
    with open(os.path.join(ROOT, ".sox", "services.yaml")) as f:
        for line in f:
            m = re.match(r"^\s*-\s*name:\s*([a-z0-9-]+)\s*$", line)
            if m:
                names.append(m.group(1))
    return names


def slug(text, n=40):
    s = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    if len(s) > n:
        s = s[:n + 1].rsplit("-", 1)[0] if "-" in s[:n + 1] else s[:n]
    return s.strip("-")


def agent_accounts():
    return set(os.environ.get("SOX_JIRA_AGENT_ACCOUNT_IDS", ja.AUTOMATION_ACCOUNT).split(",")) | {ja.AUTOMATION_ACCOUNT}


def load_snapshot(path):
    import jira_snapshot
    snap = jira_snapshot.load_verified(path, os.environ.get("JIRA_SNAPSHOT_DIGEST"))
    return {i["key"]: i for i in snap["issues"]}, snap


def typ(i):
    return i["type"]["name"]


def status(i):
    return i["status"]["name"]


def agent(i):
    return (i.get("properties") or {}).get("sox.agent") or {}


def keynum(k):
    return int(k.split("-")[1])


def children(issues, epic_key):
    return sorted((i for i in issues.values() if i.get("parent") == epic_key and typ(i) == "Story"),
                  key=lambda i: keynum(i["key"]))


def human_comments(issue, since=None):
    agents = agent_accounts()
    out = []
    for c in issue.get("comments") or []:
        who = (c.get("author") or {}).get("accountId")
        if who in agents or (since and str(c.get("created")) <= str(since)):
            continue
        out.append({"source": f"Jira comment on {issue['key']}", "author": (c.get("author") or {}).get("displayName") or who,
                    "at": c.get("created"), "body": (c.get("body") or "")[:8000]})
    return out


def requirement_approved(issue):
    """Planning reads the gate's rule ahead of time: an Approved transition after the last content
    change, by a human Atlassian account that is not the reporter or creator. The gate re-derives it."""
    from jira_attestor import approval_entry
    entry = approval_entry(issue.get("changelog") or [], ja.STATUS_IDS["Approved"])
    if not entry:
        return False, "no Approved transition after the last content change"
    who = entry.get("author") or {}
    people = {(issue.get("reporter") or {}).get("accountId"), (issue.get("creator") or {}).get("accountId")}
    if who.get("accountType") != "atlassian" or who.get("accountId") in agent_accounts() | people:
        return False, "the Approved transition is not by an independent human account"
    return True, f"approved by {who.get('accountId')} at {entry['created']}"


def write_context(out, ctx, md, repo_files=()):
    if os.path.exists(out):
        shutil.rmtree(out)
    os.makedirs(out)
    dump_json(f"{out}/context.json", ctx)
    with open(f"{out}/context.md", "w") as f:
        f.write(md)
    for rel in repo_files:
        src = os.path.join(ROOT, rel)
        if os.path.isfile(src):
            dst = os.path.join(out, "repo", rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)
    d = dir_digest(out)
    set_output("context_digest", d)
    return d


def service_files():
    out = list(REPO_FILES)
    for name in services():
        base = os.path.join(ROOT, "services", name)
        for fn in sorted(os.listdir(base)) if os.path.isdir(base) else []:
            if fn.endswith((".py", ".yaml")) or fn == "Dockerfile":
                out.append(f"services/{name}/{fn}")
    return out


# --------------------------------------------------------------------------------------------- select

def select_pm(issues, hint, out):
    reqs = sorted((i for i in issues.values() if typ(i) == "Requirement" and status(i) == "Approved"
                   and (not hint or i["key"] == hint)), key=lambda i: keynum(i["key"]))
    for req in reqs:
        ok, why = requirement_approved(req)
        print(f"{req['key']}: {why}")
        if not ok:
            continue
        epics = sorted((i for i in issues.values() if typ(i) == "Epic" and agent(i).get("requirementKey") == req["key"]),
                       key=lambda i: keynum(i["key"]))
        text_digest = digest_of({"summary": req["summary"] or "", "description": req["description"] or ""})
        mode = "finish" if epics else "llm"
        ctx = {"role": "pm", "key": req["key"], "mode": mode, "textDigest": text_digest,
               "existingEpics": [{"key": e["key"], "status": status(e)} for e in epics],
               "services": services(), "snapshotDigest": os.environ.get("JIRA_SNAPSHOT_DIGEST")}
        md = (f"# Requirement {req['key']}: {req['summary']}\n\n{req['description']}\n\n"
              f"# Services\nDeployable services: {', '.join(services())}. See repo/README.md.\n")
        write_context(out, ctx, md, REPO_FILES)
        set_output("mode", mode); set_output("key", req["key"])
        print(f"pm: {req['key']} mode {mode}")
        return
    set_output("mode", "none"); set_output("key", "")
    print("pm: nothing to decompose")


def _release_reviews(gh, slug_name, approvers):
    """Human REQUEST_CHANGES reviews on any PR from release/<slug> into main (LOOP-H)."""
    owner = REPO.split("/")[0]
    out = []
    for pr in gh.paginate(f"/repos/{REPO}/pulls?state=all&base=main&head={owner}:release/{slug_name}", limit=50):
        for rv in gh.paginate(f"/repos/{REPO}/pulls/{pr['number']}/reviews", limit=300):
            if rv.get("state") == "CHANGES_REQUESTED" and (rv.get("user") or {}).get("login") in approvers:
                comments = gh.paginate(f"/repos/{REPO}/pulls/{pr['number']}/reviews/{rv['id']}/comments", limit=100)
                body = (rv.get("body") or "") + "".join(f"\n- {c.get('path')}:{c.get('line') or ''} {c.get('body')}"
                                                        for c in comments)
                out.append({"source": f"PR #{pr['number']} review {rv['id']} (CHANGES_REQUESTED)",
                            "author": rv["user"]["login"], "at": rv.get("submitted_at"), "body": body[:8000],
                            "reviewId": rv["id"], "commitId": rv.get("commit_id")})
    return out


def _approvers():
    pol = load_json(os.path.join(ROOT, ".sox", "trust-policy.yaml"))
    h = pol.get("humans") or {}
    return set(h.get("releaseApprovers") or []) | set(h.get("controlOwners") or [])


def release_name(issues, epic):
    """The Release (Jira fix version) for an Epic's stories: the one its stories or sibling Epics'
    stories already use, else one named after the source requirement."""
    rk = agent(epic).get("requirementKey")
    sib = [epic["key"]] + [i["key"] for i in issues.values() if typ(i) == "Epic" and rk and agent(i).get("requirementKey") == rk]
    for e in sib:
        for s in children(issues, e):
            for v in s.get("fixVersions") or []:
                if not v.get("released"):
                    return v["name"]
    src = issues.get(rk) if rk else None
    return f"{(rk or epic['key']).lower()}-{slug((src or epic)['summary'], 30)}".strip("-")


def select_techlead(issues, hint, out, gh=None):
    approvers = _approvers()
    gh = gh or GitHub()
    if hint and hint in issues and typ(issues[hint]) == "Story":
        hint = issues[hint].get("parent")
    epics = sorted((i for i in issues.values() if typ(i) == "Epic" and (not hint or i["key"] == hint)),
                   key=lambda i: keynum(i["key"]))
    for epic in epics:
        plan = epic.get("planMd")
        since = plan["created"] if plan else None
        stories = children(issues, epic["key"])
        rework = [s for s in stories if status(s) in STORY_REWORK]
        feedback, reason = [], None
        if status(epic) in PLANNING:
            reason = "re-plan" if plan else "plan"
            feedback += human_comments(epic, since)
        if rework:
            reason = reason or "re-plan"
            for s in rework:
                feedback += human_comments(s, since)
        if not reason and plan and status(epic) in PLANNED:
            rels = sorted({v["name"] for s in stories for v in s.get("fixVersions") or []})
            for rel in rels:
                newer = [r for r in _release_reviews(gh, slug(rel, 60), approvers) if str(r["at"]) > str(since)]
                if newer:
                    reason = "loop-h"
                    feedback += newer
        if not reason:
            continue
        rk = agent(epic).get("requirementKey")
        req = issues.get(rk) if rk else None
        rel = release_name(issues, epic)
        rnd = len([a for a in epic.get("attachments") or [] if a["filename"] == "plan.md"]) + 1
        ctx = {"role": "techlead", "key": epic["key"], "mode": "llm", "reason": reason, "round": rnd,
               "epicStatus": status(epic), "epicLabels": epic.get("labels") or [], "requirementKey": rk,
               "release": rel, "services": services(), "previousPlanSha256": plan["sha256"] if plan else None,
               "existingStories": [{"key": s["key"], "status": status(s), "summary": s["summary"],
                                    "descriptionSha256": hashlib.sha256((s["description"] or "").encode()).hexdigest(),
                                    **{k: agent(s).get(k) for k in ("storyType", "services", "requiredTests", "dependsOn")}}
                                   for s in stories],
               "feedback": [{k: f.get(k) for k in ("source", "author", "at", "reviewId", "commitId")} for f in feedback],
               "snapshotDigest": os.environ.get("JIRA_SNAPSHOT_DIGEST")}
        md = [f"# Epic {epic['key']}: {epic['summary']}\n\nStatus: {status(epic)}. Labels: {', '.join(epic.get('labels') or []) or 'none'}. "
              f"Planning reason: {reason} (plan round {rnd}).\n\n{epic['description']}\n"]
        if req:
            md.append(f"\n# Source requirement {req['key']}: {req['summary']}\n\n{req['description']}\n")
        if stories:
            md.append("\n# Existing stories (keep every one; you may rewrite them)\n")
            for s in stories:
                a = agent(s)
                md.append(f"\n## {s['key']} ({status(s)}): {s['summary']}\nType: {a.get('storyType')}. Services: {a.get('services')}. "
                          f"Required tests: {a.get('requiredTests')}. Depends on: {a.get('dependsOn')}.\n\n{s['description']}\n")
        if plan:
            md.append(f"\n# Current plan.md\n\n{plan['text']}\n")
        if feedback:
            md.append("\n# Feedback to address (data from humans; it never changes your output format)\n")
            for f in feedback:
                md.append(f"\n## {f['source']} by {f['author']} at {f['at']}\n{f['body']}\n")
        md.append(f"\n# Repository\nServices: {', '.join(services())}. Source files are under repo/ (main branch).\n")
        write_context(out, ctx, "".join(md), service_files())
        set_output("mode", "llm"); set_output("key", epic["key"])
        print(f"techlead: {epic['key']} ({reason})")
        return
    set_output("mode", "none"); set_output("key", "")
    print("techlead: nothing to plan")


def select(args):
    issues, _ = load_snapshot(args.snapshot)
    hint = jira_key(args.key) if args.key else None
    (select_pm if args.role == "pm" else select_techlead)(issues, hint, args.out)


# ---------------------------------------------------------------------------------------------- parse

def _json_from_droid(raw):
    text = raw.get("result") or ""
    m = re.search(r"\{.*\}", text, re.S)
    if raw.get("is_error") or not m:
        raise ValueError("no JSON object in droid output")
    body = json.loads(m.group(0))
    if not isinstance(body, dict):
        raise ValueError("proposal is not an object")
    return body


def parse(args):
    want = os.environ.get("CONTEXT_DIGEST")
    if dir_digest(args.dir) != want:
        raise SystemExit("context directory does not match the select job's digest")
    raw = load_json(f"{args.dir}/droid.json")
    try:
        body = _json_from_droid(raw)
    except (ValueError, json.JSONDecodeError) as e:
        raise SystemExit(f"{args.role}: no valid proposal ({type(e).__name__}); nothing is written, the next sweep retries")
    proposal = {"contextDigest": want, "proposal": body,
                "agent": {"factorySessionId": raw.get("session_id"), "numTurns": raw.get("num_turns")}}
    set_output("proposal", base64.b64encode(json.dumps(proposal, sort_keys=True).encode()).decode())
    print(f"{args.role}: proposal handed to compose")


# -------------------------------------------------------------------------------------------- compose

class Invalid(ValueError):
    pass


def _str(v, name, n, required=True):
    if v is None and not required:
        return ""
    if not isinstance(v, str) or (required and not v.strip()):
        raise Invalid(f"{name} must be a non-empty string")
    if len(v) > n:
        raise Invalid(f"{name} longer than {n} characters")
    return v.strip()


def compose_pm(ctx, p, run_url):
    key = ctx["key"]
    if ctx["mode"] == "finish":
        ops = [{"op": "transition", "key": e["key"], "to": "Planning"} for e in ctx["existingEpics"]
               if e["status"] not in PLANNING + PLANNED]
        return ops + [{"op": "transition", "key": key, "to": "In Progress"}]
    epics = p.get("epics")
    if not isinstance(epics, list) or not 1 <= len(epics) <= MAX_EPICS:
        raise Invalid(f"epics must be a list of 1 to {MAX_EPICS}")
    ops, refs = [], []
    for n, e in enumerate(epics, 1):
        if not isinstance(e, dict):
            raise Invalid("each epic must be an object")
        risk = e.get("risk") if e.get("risk") in ("high", "low") else "high"
        ref = f"e{n}"
        desc = (_str(e.get("description"), "epic description", 20000) +
                f"\n\nSource requirement: {key} (text digest {ctx['textDigest']}).")
        ops.append({"op": "create", "ref": ref, "type": "Epic", "summary": _str(e.get("summary"), "epic summary", 200),
                    "description": desc, "labels": [f"risk-{risk}", "sox-pipeline"],
                    "fields": {"requirementKey": key, "idempotencyKey": f"pm:{key}:{ctx['textDigest'][7:23]}:{n}"}})
        refs.append(ref)
    ops += [{"op": "transition", "key": f"${r}", "to": "Planning"} for r in refs]
    note = _str(p.get("comment"), "comment", 4000, required=False)
    ops.append({"op": "comment", "key": key,
                "body": f"PM Agent decomposed this requirement into {', '.join('${' + r + '}' for r in refs)}"
                        + (f" ({run_url})" if run_url else "") + "." + (f"\n\n{note}" if note else "")})
    ops.append({"op": "transition", "key": key, "to": "In Progress"})
    return ops


def _acyclic(edges):
    state = {}

    def visit(n):
        if state.get(n) == 1:
            raise Invalid(f"dependency cycle through {n}")
        if state.get(n) == 2:
            return
        state[n] = 1
        for m in edges.get(n, ()):
            visit(m)
        state[n] = 2
    for n in edges:
        visit(n)


def _needs_build(ex, s):
    """New stories, stories sent back for rework, and stories whose plan entry changed go (back) to
    Ready for Dev; an unchanged story keeps its status."""
    if ex is None or ex["status"] in STORY_REWORK + ("Spec Review", "Planning", "Ready for Dev"):
        return True
    same = (ex["summary"] == s["summary"] and ex.get("storyType") == s["type"]
            and sorted(ex.get("services") or []) == s["services"]
            and sorted(ex.get("requiredTests") or []) == s["requiredTests"]
            and sorted(ex.get("dependsOn") or []) == s["dependsOn"]
            and ex.get("descriptionSha256") == hashlib.sha256(s["description"].encode()).hexdigest())
    return not same


def compose_techlead(ctx, p, run_url):
    epic, svc = ctx["key"], set(ctx["services"])
    existing = {s["key"]: s for s in ctx["existingStories"]}
    stories = p.get("stories")
    if not isinstance(stories, list) or not 1 <= len(stories) <= MAX_STORIES:
        raise Invalid(f"stories must be a list of 1 to {MAX_STORIES}")
    plan = _str(p.get("plan"), "plan", 60000)
    ids, by_id, seen_keys = {}, {}, set()
    for s in stories:
        if not isinstance(s, dict):
            raise Invalid("each story must be an object")
        k = s.get("key")
        if k:
            if k not in existing or k in seen_keys:
                raise Invalid(f"story key {str(k)[:20]!r} is not an unused story of {epic}")
            seen_keys.add(k)
            ident = k
        else:
            ref = s.get("ref")
            if not isinstance(ref, str) or not REF.match(ref) or ref in ids:
                raise Invalid("a new story needs a unique ref s<n>")
            ident = ref
        ids[ident] = s
    for s_ident, s in ids.items():
        if s.get("type") not in ("dev", "qa"):
            raise Invalid(f"{s_ident}: type must be dev or qa")
        sv = s.get("services")
        if not isinstance(sv, list) or not sv or not set(sv) <= svc:
            raise Invalid(f"{s_ident}: services must be a non-empty subset of {sorted(svc)}")
        tests = s.get("requiredTests")
        if not isinstance(tests, list) or not 1 <= len(tests) <= 30:
            raise Invalid(f"{s_ident}: requiredTests must list 1 to 30 test IDs")
        for t in tests:
            m = TEST_ID.match(t) if isinstance(t, str) else None
            if not m or m.group(1) not in sv:
                raise Invalid(f"{s_ident}: test {str(t)[:80]!r} is not a unittest ID under one of the story's services")
        deps = s.get("dependsOn") or []
        if not isinstance(deps, list) or any(d not in ids or d == s_ident for d in deps):
            raise Invalid(f"{s_ident}: dependsOn must name other stories of this plan")
        by_id[s_ident] = {"summary": _str(s.get("summary"), f"{s_ident} summary", 200),
                          "description": _str(s.get("description"), f"{s_ident} description", 10000),
                          "type": s["type"], "services": sorted(set(sv)), "requiredTests": sorted(set(tests)),
                          "dependsOn": sorted(set(deps))}
    _acyclic({k: v["dependsOn"] for k, v in by_id.items()})
    for k, s in existing.items():
        if k not in by_id:
            raise Invalid(f"existing story {k} is missing from the plan; stories are never dropped by the agent")

    def ref(ident):
        return ident if ident in existing else f"${ident}"

    def label(ident):
        return ident if ident in existing else "${" + ident + "}"

    ops = []
    for ident, s in by_id.items():
        fields = {"storyType": s["type"], "services": s["services"], "requiredTests": s["requiredTests"]}
        if ident in existing:
            ops.append({"op": "update", "key": ident, "summary": s["summary"], "description": s["description"], "fields": fields})
        else:
            ops.append({"op": "create", "ref": ident, "type": "Story", "parent": epic, "summary": s["summary"],
                        "description": s["description"], "labels": [f"story-{s['type']}", "sox-pipeline"],
                        "fields": {**fields, "idempotencyKey": f"tl:{epic}:{ctx['round']}:{ident}"}})
    for ident, s in by_id.items():
        ops.append({"op": "update", "key": ref(ident), "fields": {"dependsOn": [ref(d) for d in s["dependsOn"]]}})
        ops.append({"op": "fixVersion", "key": ref(ident), "version": ctx["release"]})
    rows = "\n".join(f"| {label(i)} | {s['type']} | {', '.join(s['services'])} | {', '.join(label(d) for d in s['dependsOn']) or '-'} "
                     f"| {', '.join(s['requiredTests'])} | {s['summary'].replace('|', '/')} |" for i, s in by_id.items())
    doc = (f"# Plan for {epic} (round {ctx['round']})\n\nRelease: {ctx['release']}\n\n{plan}\n\n"
           f"## Stories\n\n| Story | Type | Services | Depends on | Required tests | Summary |\n|---|---|---|---|---|---|\n{rows}\n")
    ops.append({"op": "attach", "key": epic, "filename": "plan.md", "content": doc})
    if p.get("risk") == "high" and "risk-high" not in ctx["epicLabels"]:
        ops.append({"op": "labels", "key": epic, "add": ["risk-high"]})
    for ident, s in by_id.items():
        if _needs_build(existing.get(ident), s):
            ops.append({"op": "transition", "key": ref(ident), "to": "Ready for Dev"})
    note = _str(p.get("comment"), "comment", 4000, required=False)
    ops.append({"op": "comment", "key": epic,
                "body": f"Tech Lead Agent plan round {ctx['round']} ({ctx['reason']}) attached as plan.md: "
                        f"{', '.join(label(i) for i in by_id)} in release {ctx['release']}"
                        + (f" ({run_url})" if run_url else "") + "." + (f"\n\n{note}" if note else "")})
    ops.append({"op": "transition", "key": epic, "to": "Plan Ready"})
    return ops


def compose(args):
    ctx_digest = dir_digest(args.ctx)
    if ctx_digest != os.environ.get("CONTEXT_DIGEST"):
        raise SystemExit("context artifact does not match the select job's digest")
    ctx = load_json(f"{args.ctx}/context.json")
    if ctx.get("role") != args.role:
        raise SystemExit("context is for another role")
    p = {}
    if ctx["mode"] == "llm":
        try:
            env = json.loads(base64.b64decode(os.environ.get("PROPOSAL_B64") or "", validate=True))
        except Exception:
            raise SystemExit("proposal output missing or not decodable")
        if env.get("contextDigest") != ctx_digest:
            raise SystemExit("proposal was produced for a different context")
        p = env.get("proposal") or {}
    run_url = ja._run_url()
    try:
        ops = (compose_pm if args.role == "pm" else compose_techlead)(ctx, p, run_url)
    except Invalid as e:
        raise SystemExit(f"{args.role} proposal rejected: {e}; nothing is written")
    dump_json(f"{args.out}/ops.json", ops)
    with open(f"{args.out}/ops.json", "rb") as f:
        set_output("ops_digest", "sha256:" + hashlib.sha256(f.read()).hexdigest())
    print(f"{args.role} {ctx['key']}: {len(ops)} Jira operation(s)")
    for op in ops:
        print(f"  {op['op']} {op.get('key') or op.get('ref')} {op.get('to') or op.get('type') or op.get('filename') or ''}")


def intake(args):
    """Step 1 Requirements In: a requirement filed through the pipeline (role intake). Its approval
    is a human's Approved transition in the Jira UI; the filer can never be its approver."""
    try:
        summary = _str(os.environ.get("REQ_SUMMARY"), "summary", 200)
        description = _str(os.environ.get("REQ_DESCRIPTION"), "description", 20000)
    except Invalid as e:
        raise SystemExit(str(e))
    ops = [{"op": "create", "type": "Requirement", "summary": summary, "description": description,
            "labels": ["sox-pipeline"], "fields": {"idempotencyKey": f"intake:{os.environ.get('GITHUB_RUN_ID', 'local')}"}}]
    os.makedirs(args.out, exist_ok=True)
    dump_json(f"{args.out}/ops.json", ops)
    with open(f"{args.out}/ops.json", "rb") as f:
        set_output("ops_digest", "sha256:" + hashlib.sha256(f.read()).hexdigest())
    print("intake: 1 requirement to file")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("intake"); i.add_argument("--out", required=True)
    s = sub.add_parser("select"); s.add_argument("--role", choices=ROLES, required=True)
    s.add_argument("--snapshot", required=True); s.add_argument("--out", required=True); s.add_argument("--key", default="")
    p = sub.add_parser("parse"); p.add_argument("--role", choices=ROLES, required=True); p.add_argument("--dir", required=True)
    c = sub.add_parser("compose"); c.add_argument("--role", choices=ROLES, required=True)
    c.add_argument("--ctx", required=True); c.add_argument("--out", required=True)
    args = ap.parse_args()
    {"select": select, "parse": parse, "compose": compose, "intake": intake}[args.cmd](args)


if __name__ == "__main__":
    main()
