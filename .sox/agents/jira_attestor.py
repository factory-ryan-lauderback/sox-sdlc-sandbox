"""Jira attestor (steps 1-4 and CC-04): turns Jira facts into signed predicates.

  jira_attestor.py plan  [--key FRQ-n]                      -> output `candidates` (lookup hints only)
  jira_attestor.py build --kind K --key FRQ-n [--release S] --out DIR -> predicate.json, subjects.txt

Runs only in env jira-attestor, from main. `plan` lists what may need signing; each `build` re-reads
Jira itself (never trusts the plan job), compares with the latest verified attestation, and writes
the predicate only when something changed. Every Jira identity is an accountId. Approval predicates
carry the raw, complete changelog so the gate re-derives the approver; a changelog that cannot be
shown complete fails the run (IncompleteRead) instead of signing a partial history.

Kinds and the Jira state that makes them due:
- requirement-approval: a requirement with a transition to Approved (10071) after its last content change.
- pm-decomposition: a requirement in In Progress with at least one Epic whose requirementKey points to it,
  and a verified requirement-approval for its current content digest.
- techlead-plan: an Epic in Plan Ready or later with a plan.md attachment and stories.
- approach-approval: an Epic with a transition to Approach Approved (10082) after its last content change.
- emergency-change: an issue with a transition to ECAB Approved (10089) after its last content change.
- release-manifest: an unreleased fix version with stories; the predicate comes from Release's hook.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import jira_adapter as ja  # noqa: E402
from common import REPO, digest_of, dump_json, jira_key, now_utc, set_output, sha256_hex, subject_lines  # noqa: E402

CONTENT_FIELDS = ("summary", "description", "Attachment")
APPROVALS = {"requirement-approval": "10071", "approach-approval": "10082", "emergency-change": "10089"}
PLAN_STATUSES = ("Plan Ready", "Approach Approved", "Ready for Dev", "In Progress", "In Review", "Done",
                 "Re-plan", "Awaiting Release Approval", "Awaiting Train", "Released")
DECOMPOSED_STATUSES = ("In Progress", "In Review", "Done", "Released")
STEP = {"requirement-approval": "SDLC-01", "pm-decomposition": "SDLC-02", "techlead-plan": "SDLC-03",
        "approach-approval": "SDLC-03", "release-manifest": "SDLC-04", "emergency-change": "CC-04"}
OUTCOME = {"requirement-approval": "approved", "approach-approval": "approved", "emergency-change": "approved"}
HOOK = os.path.join(ROOT, ".sox", "release", "manifest_predicate.py")
# Jira accountId -> GitHub login of the human Tech Leads (trust policy humans.techLeads). The policy
# pins Jira approvers by accountId and humans by GitHub login but has no join between the two.
TECH_LEADS = {"712020:ae7e6a76-96e0-4d91-a2ac-857b21c164cd": "factory-aman"}
MAX_CANDIDATES = 40


class Lookup:
    """Latest verified attestation per (kind, id, predicate), through the Gates verifier."""

    def __init__(self, fetch=None):
        self._fetch = fetch

    def fetch(self, kind, ident, predicate):
        if self._fetch is None:
            import rounds
            self._fetch = rounds.fetch
        verified, _ = self._fetch(kind, ident, predicate)
        return verified

    def latest(self, kind, ident, predicate, where=None):
        items = [a for a in self.fetch(kind, ident, predicate) if where is None or where(a)]
        return max(items, key=lambda a: (a.integrated_time or 0, a.digest)) if items else None


# ---------------------------------------------------------------------------------------------- facts

def is_requirement(issue):
    return issue["type"] == "Requirement" or ja.REQUIREMENT_LABEL in (issue.get("labels") or [])


def _time(s):
    import datetime as dt
    t = dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)).timestamp()


def approval_entry(changelog, status_id):
    """Latest transition to status_id after the last content change (the gate's rule, for planning
    and the informational approver field only; the gate re-derives it from the signed changelog)."""
    changes = [_time(h["created"]) for h in changelog if any(i.get("field") in CONTENT_FIELDS for i in h["items"])]
    last = max(changes, default=None)
    moves = [h for h in changelog if any(i.get("field") == "status" and str(i.get("to")) == status_id for i in h["items"])
             and (last is None or _time(h["created"]) > last)]
    return max(moves, key=lambda h: (_time(h["created"]), str(h["id"]))) if moves else None


def human_replan(j, keys, leads=None):
    """Latest transition to Re-plan by a human Tech Lead on any of the issues: (entry, login, key) or None."""
    leads = TECH_LEADS if leads is None else leads
    target, best = ja.STATUS_IDS["Re-plan"], None
    for k in keys:
        for h in j.changelog(k):
            who = (h.get("author") or {}).get("accountId")
            if who in leads and any(i.get("field") == "status" and str(i.get("to")) == target for i in h["items"]):
                if best is None or _time(h["created"]) > _time(best[0]["created"]):
                    best = (h, leads[who], k)
    return best


def attachment_digests(j, issue):
    out = []
    for a in sorted(issue.get("attachments") or [], key=lambda a: str(a["id"])):
        content = j.attachment_content(issue["key"], a["id"])
        out.append({"id": str(a["id"]), "filename": a["filename"], "sha256": hashlib.sha256(content).hexdigest()})
    return out


def content_digest(j, issue):
    return digest_of({"summary": issue["summary"] or "", "description": issue["description"] or "",
                      "attachments": [a["sha256"] for a in attachment_digests(j, issue)]})


def _id_order(ident):
    """Jira attachment ids are numeric; FileJira's are FRQ-n-a<k>. Either way the trailing number orders them."""
    import re
    m = re.search(r"(\d+)$", str(ident))
    return int(m.group(1)) if m else 0


def latest_plan(j, epic):
    plans = [a for a in epic.get("attachments") or [] if a["filename"] == "plan.md"]
    if not plans:
        return None, None
    a = max(plans, key=lambda a: (str(a.get("created") or ""), _id_order(a["id"])))
    content = j.attachment_content(epic["key"], a["id"])
    return a, "sha256:" + hashlib.sha256(content).hexdigest()


def acting(j, issue):
    """{creator, actingRole, actingRoleComment}: the comment must be by the creator and start with
    [sox:<actingRole>]."""
    creator = issue.get("creator")
    role = issue.get("actingRole")
    prefix = ja.role_prefix(role) if role else None
    has = bool(prefix) and any(((c.get("author") or {}).get("accountId") == creator)
                               and (c.get("body") or "").lstrip().startswith(prefix) for c in j.comments(issue["key"]))
    return {"creator": creator, "actingRole": role, "actingRoleComment": has}


def _people(j, key):
    reporter, creator = j.people(key)
    return (reporter or {}).get("accountId"), (creator or {}).get("accountId")


def _groups(j, account_id):
    finder = getattr(j, "groups_of", None)
    if not callable(finder) or not account_id:
        return []
    try:
        return finder(account_id)
    except ja.JiraError:
        return []


# ------------------------------------------------------------------------------------- predicate builders

def _common(kind, jira_keys, release, inputs, upstream, outcome=None):
    return {
        "schema": "sox/common/v1", "repo": REPO, "prNumber": None, "headSha": None, "baseSha": None, "baseRef": None,
        "jiraKeys": sorted(set(jira_keys), key=lambda k: int(k.split("-")[1])), "release": release, "step": STEP[kind],
        "actor": {"type": "workflow", "login": "sox-jira-attestor.yml",
                  "source": "Jira Cloud REST v3 read in env jira-attestor; Jira identities are accountIds"},
        "inputs": inputs, "inputsDigest": digest_of(inputs), "outcome": outcome or OUTCOME.get(kind, "recorded"),
        "round": None, "observedAt": now_utc(),
        "attestor": {"workflow": ".github/workflows/sox-jira-attestor.yml", "ref": os.environ.get("GITHUB_REF"),
                     "runId": int(os.environ.get("GITHUB_RUN_ID", "0")), "runAttempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")),
                     "codeSha": os.environ.get("GITHUB_SHA")},
        "upstream": upstream, "agentClaims": {},
    }


def _sha(d):
    return {"sha256": d.split(":", 1)[1]}


def build_approval(j, kind, key, lk):
    issue = j.get(key)
    log = j.changelog(key)
    entry = approval_entry(log, APPROVALS[kind])
    if entry is None:
        return None, "no approving transition after the last content change"
    reporter, creator = _people(j, key)
    cdig = content_digest(j, issue)
    approver = (entry.get("author") or {}).get("accountId")
    fields = {"issueKey": key, "issueVersion": issue.get("updated"), "contentDigest": cdig,
              "reporter": reporter, "creator": creator, "changelog": log,
              "approver": approver, "approvedAt": entry["created"], "approvalChangelogId": str(entry["id"]),
              "approverGroups": _groups(j, approver)}
    upstream, inputs = [], [{"name": "jira-changelog", "digest": _sha(digest_of(log))},
                            {"name": "jira-content", "digest": _sha(cdig)}]
    keys = [key]
    if kind == "approach-approval":
        _, plan_digest = latest_plan(j, issue)
        fields.update(epicKey=key, planDigest=plan_digest)
        tp = lk.latest("jira", key, "techlead-plan", where=lambda a: a.predicate.get("planDigest") == plan_digest)
        if tp:
            upstream.append(tp.digest)
    elif kind == "emergency-change":
        fields["ecabApprover"] = approver
    elif kind == "requirement-approval" and not is_requirement(issue):
        return None, "not a requirement"
    fields["dedupeKey"] = digest_of({k: fields.get(k) for k in ("issueKey", "contentDigest", "approvalChangelogId", "planDigest")})
    prev = lk.latest("jira", key, kind)
    if prev and prev.predicate.get("dedupeKey") == fields["dedupeKey"]:
        return None, f"unchanged since {prev.digest}"
    return {"subjects": [("jira", key)], "predicate": {**_common(kind, keys, None, inputs, upstream), **fields}}, "due"


def build_pm(j, key, lk):
    req = j.get(key)
    if not is_requirement(req):
        return None, "not a requirement"
    if req["status"] not in DECOMPOSED_STATUSES:
        return None, f"requirement is {req['status']}, decomposition not finished"
    epics = [e for e in j.search(type="Epic") if e.get("requirementKey") == key]
    if not epics:
        return None, "no epics for this requirement"
    cdig = content_digest(j, req)
    ra = lk.latest("jira", key, "requirement-approval", where=lambda a: a.predicate.get("contentDigest") == cdig)
    if ra is None:
        return None, "no verified requirement-approval for the current requirement content"
    entries = [{"key": e["key"], "createdAt": e.get("created"), "summary": e["summary"], **acting(j, e)} for e in epics]
    fields = {"requirementKey": key, "requirementContentDigest": cdig, "epics": entries}
    fields["dedupeKey"] = digest_of({"requirementContentDigest": cdig, "epics": entries})
    prev = lk.latest("jira", key, "pm-decomposition")
    if prev and prev.predicate.get("dedupeKey") == fields["dedupeKey"]:
        return None, f"unchanged since {prev.digest}"
    inputs = [{"name": "requirement-content", "digest": _sha(cdig)}]
    keys = [key] + [e["key"] for e in epics]
    pred = {**_common("pm-decomposition", keys, None, inputs, [ra.digest]), **fields}
    return {"subjects": [("jira", k) for k in keys], "predicate": pred}, "due"


def build_plan(j, key, lk):
    epic = j.get(key)
    if epic["type"] != "Epic":
        return None, "not an epic"
    if epic["status"] not in PLAN_STATUSES:
        return None, f"epic is {epic['status']}, plan not ready"
    att, plan_digest = latest_plan(j, epic)
    if not att:
        return None, "no plan.md attachment"
    stories = j.search(type="Story", parent=key)
    if not stories:
        return None, "no stories under the epic"
    entries = [{"key": s["key"], "type": s.get("storyType"), "dependsOn": sorted(s.get("dependsOn") or []),
                "requiredTests": sorted(s.get("requiredTests") or []), "services": sorted(s.get("services") or []),
                "summary": s["summary"], **acting(j, s)} for s in stories]
    services = sorted({x for s in entries for x in s["services"]})
    fields = {"epicKey": key, "requirementKey": epic.get("requirementKey"), "planDigest": plan_digest,
              "planSource": {"jiraAttachmentId": str(att["id"]), "filename": att["filename"]},
              "stories": entries, "servicesTouched": services, "epicLabels": sorted(epic.get("labels") or []),
              "epicActing": acting(j, epic)}
    fields["dedupeKey"] = digest_of({k: fields[k] for k in ("planDigest", "stories", "epicLabels")})
    prev = lk.latest("jira", key, "techlead-plan")
    # A human Tech Lead's Re-plan newer than the last plan attestation is recorded once, on the next
    # plan attestation (the gate restarts LOOP-R from it). Later plans do not repeat it.
    rp = human_replan(j, [key] + [s["key"] for s in entries])
    if rp and (prev is None or _time(rp[0]["created"]) > (prev.integrated_time or 0)):
        fields["replanApprovedBy"] = rp[1]
        fields["replanApproval"] = {"issueKey": rp[2], "changelogId": str(rp[0]["id"]), "at": rp[0]["created"],
                                    "accountId": (rp[0].get("author") or {}).get("accountId")}
    elif prev and prev.predicate.get("dedupeKey") == fields["dedupeKey"]:
        return None, f"unchanged since {prev.digest}"
    upstream = []
    if epic.get("requirementKey"):
        pm = lk.latest("jira", epic["requirementKey"], "pm-decomposition",
                       where=lambda a: any(e.get("key") == key for e in a.predicate.get("epics", [])))
        if pm:
            upstream.append(pm.digest)
    inputs = [{"name": "plan", "digest": _sha(plan_digest)}]
    keys = [key] + [s["key"] for s in entries]
    pred = {**_common("techlead-plan", keys, None, inputs, upstream), **fields}
    return {"subjects": [("jira", k) for k in keys], "predicate": pred}, "due"


def run_hook(key, env=None):
    if not os.path.exists(HOOK):
        return []
    p = subprocess.run([sys.executable, HOOK, "--jira-key", key], cwd=ROOT, capture_output=True, text=True,
                       env=env or os.environ.copy(), timeout=300)
    if p.returncode != 0:
        raise SystemExit(f"release-manifest hook failed for {key} (exit {p.returncode}): {p.stderr[-2000:]}")
    out = json.loads(p.stdout or "[]")
    if not isinstance(out, list):
        raise SystemExit("release-manifest hook must print a JSON list")
    return out


def build_manifest(key, release, lk, hook=run_hook):
    for entry in hook(key):
        subjects = [tuple(s) for s in entry["subjects"]]
        if ("release", release) not in subjects:
            continue
        step = dict(entry["predicate"])
        for k, _ in subjects:
            if k not in ("jira", "release"):
                raise SystemExit(f"hook produced an unexpected subject kind {k!r}")
        step["dedupeKey"] = digest_of({k: v for k, v in step.items() if k not in ("observedAt",)})
        prev = lk.latest("release", release, "release-manifest")
        if prev and prev.predicate.get("dedupeKey") == step["dedupeKey"]:
            return None, f"unchanged since {prev.digest}"
        keys = [i for k, i in subjects if k == "jira"]
        inputs = [{"name": "release-manifest-content", "digest": _sha(digest_of(entry["predicate"]))}]
        common = _common("release-manifest", keys, release, inputs, [])
        return {"subjects": subjects, "predicate": {**common, **step, "jiraKeys": common["jiraKeys"]}}, "due"
    return None, "hook produced nothing for this release"


def build(j, kind, key, release, lk, hook=run_hook):
    if kind in APPROVALS:
        return build_approval(j, kind, key, lk)
    if kind == "pm-decomposition":
        return build_pm(j, key, lk)
    if kind == "techlead-plan":
        return build_plan(j, key, lk)
    if kind == "release-manifest":
        return build_manifest(key, release, lk, hook)
    raise SystemExit(f"unknown kind {kind!r}")


# ----------------------------------------------------------------------------------------------- plan

def _slug(name):
    import re
    return re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")


def candidates(j, key=None):
    """Lookup hints only. Every hint is re-derived from Jira by `build`."""
    issues = [j.get(key)] if key else j.search()
    out = []
    for i in issues:
        st = i.get("statusId")
        if is_requirement(i):
            out.append({"kind": "requirement-approval", "key": i["key"], "release": ""})
            if i["status"] in DECOMPOSED_STATUSES:
                out.append({"kind": "pm-decomposition", "key": i["key"], "release": ""})
        if i["type"] == "Epic":
            if i["status"] in PLAN_STATUSES:
                out.append({"kind": "techlead-plan", "key": i["key"], "release": ""})
            out.append({"kind": "approach-approval", "key": i["key"], "release": ""})
        if st in (APPROVALS["emergency-change"],) or "hotfix" in (i.get("labels") or []):
            out.append({"kind": "emergency-change", "key": i["key"], "release": ""})
    if key:
        issue = issues[0]
        names = issue.get("fixVersions") or []
        for n in names:
            out.append({"kind": "release-manifest", "key": key, "release": _slug(n)})
    else:
        unreleased = {v["name"] for v in j.versions() if not v["released"] and not v.get("archived")}
        first = {}
        for i in issues:
            if i["type"] == "Story":
                for n in i.get("fixVersions") or []:
                    if n in unreleased and n not in first:
                        first[n] = i["key"]
        for n, k in sorted(first.items()):
            out.append({"kind": "release-manifest", "key": k, "release": _slug(n)})
    return out


def plan(args):
    j = ja.from_env()
    hint = jira_key(args.key) if args.key else None
    lk = Lookup()
    due = []
    for c in candidates(j, hint):
        res, why = build(j, c["kind"], c["key"], c["release"], lk)
        print(f"{c['kind']} {c['key']} {c['release']}: {why}")
        if res:
            due.append(c)
    if len(due) > MAX_CANDIDATES:
        print(f"::warning::{len(due)} predicates due; signing the first {MAX_CANDIDATES}, the next sweep continues")
        due = due[:MAX_CANDIDATES]
    set_output("candidates", json.dumps(due, separators=(",", ":")))


def build_cmd(args):
    j = ja.from_env()
    key = jira_key(args.key)
    release = args.release or ""
    if release and not all(c.isalnum() or c == "-" for c in release):
        raise SystemExit("bad release slug")
    res, why = build(j, args.kind, key, release, Lookup())
    os.makedirs(args.out, exist_ok=True)
    if not res:
        print(f"{args.kind} {key}: nothing to sign ({why})")
        set_output("attest", "false")
        return
    dump_json(f"{args.out}/predicate.json", res["predicate"])
    with open(f"{args.out}/subjects.txt", "w") as f:
        f.write(subject_lines(res["subjects"]))
    set_output("attest", "true")
    set_output("predicate_type", f"https://acme-lending.example/sox/{args.kind}/v1")
    print(f"{args.kind} {key}: signing (predicate sha256 {sha256_hex(json.dumps(res['predicate'], sort_keys=True))[:16]})")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan"); p.add_argument("--key", default="")
    b = sub.add_parser("build"); b.add_argument("--kind", required=True, choices=sorted(STEP))
    b.add_argument("--key", required=True); b.add_argument("--release", default=""); b.add_argument("--out", required=True)
    args = ap.parse_args()
    {"plan": plan, "build": build_cmd}[args.cmd](args)


if __name__ == "__main__":
    main()
