"""Jira read snapshot (schema sox-jira-snapshot/v1), produced only in env jira-attestor.

  jira_snapshot.py --preset issues --keys FRQ-12,FRQ-13 --out snapshot.json
  jira_snapshot.py --preset releases --out snapshot.json
  jira_snapshot.py --preset sweep --out snapshot.json

Consumers: LLM jobs read it as data only. A key-holding job that binds Jira facts checks that
sha256(snapshot.json) equals the producing job's `digest` output in the same run, or re-reads Jira.
Every issue's changelog and comments are complete (all pages); otherwise no snapshot is written.
Emails are never included: people are {accountId, accountType, displayName}.
"""
import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jira_adapter  # noqa: E402
from common import JIRA_KEY_RE, now_utc, set_output  # noqa: E402

SCHEMA = "sox-jira-snapshot/v1"
MAX_ISSUES = 300
MAX_PLAN_BYTES = 200_000
SWEEP_STATUSES = ["Approved", "Planning", "Plan Ready", "Approach Approved", "Ready for Dev", "Re-plan",
                  "Blocked - Human Escalation"]
DONE = ("Done", "Released")


def _keys_for(j, preset, keys):
    if preset == "issues":
        out = list(keys)
        for k in keys:
            p = j.get(k).get("parent")
            if p and p not in out:
                out.append(p)
        return out
    if preset == "sweep":
        # Work items plus what an agent needs to act on them: each Epic's stories and source
        # requirement, and each item's parent.
        found = j.search(statuses=SWEEP_STATUSES)
        out = [i["key"] for i in found]
        for i in found:
            extra = [i.get("parent"), i.get("requirementKey")]
            if i["type"] == "Epic":
                extra += [s["key"] for s in j.search(parent=i["key"])]
            for k in extra:
                if k and k not in out:
                    out.append(k)
        for k in list(out):
            if k not in [i["key"] for i in found]:
                n = j.get(k)
                if n["type"] == "Epic" and n.get("requirementKey") and n["requirementKey"] not in out:
                    out.append(n["requirementKey"])
        return out
    if preset == "releases":
        unreleased = {v["name"] for v in j.versions() if not v["released"] and not v.get("archived")}
        found = []
        for i in j.search():
            if any(v in unreleased for v in i.get("fixVersions") or []) or (i["type"] == "Epic" and i["status"] not in DONE):
                found.append(i["key"])
        return found
    raise SystemExit(f"unknown preset {preset!r}")


def latest_plan_md(j, issue):
    """The Epic's current plan.md (latest attachment by that name), as text, for planning agents."""
    plans = [a for a in issue.get("attachments") or [] if a["filename"] == "plan.md"]
    if not plans:
        return None
    a = max(plans, key=lambda a: (str(a.get("created") or ""), int(re.sub(r"\D", "", str(a["id"])) or 0)))
    content = j.attachment_content(issue["key"], a["id"])
    return {"attachmentId": str(a["id"]), "created": a.get("created"),
            "sha256": hashlib.sha256(content).hexdigest(), "text": content[:MAX_PLAN_BYTES].decode(errors="replace")}


def snapshot_issue(j, key, versions):
    n = j.get(key)
    reporter, creator = j.people(key)
    by_name = {v["name"]: v for v in versions}
    return {
        "key": n["key"], "id": n.get("id"), "type": {"name": n["type"]},
        "status": {"id": n.get("statusId"), "name": n["status"]},
        "summary": n["summary"], "description": n["description"], "labels": n["labels"],
        "fixVersions": [{"id": (by_name.get(v) or {}).get("id"), "name": v,
                         "released": bool((by_name.get(v) or {}).get("released"))} for v in n["fixVersions"]],
        "parent": n.get("parent"), "reporter": reporter, "creator": creator,
        "created": n.get("created"), "updated": n.get("updated"),
        "properties": {"sox.agent": {k: n.get(k) for k in jira_adapter.AGENT_FIELDS if n.get(k) is not None},
                       jira_adapter.ROLE_PROPERTY: {"role": n.get("actingRole")} if n.get("actingRole") else None},
        "attachments": n["attachments"],
        "comments": j.comments(key),
        "changelog": j.changelog(key),
        "planMd": latest_plan_md(j, n) if n["type"] == "Epic" else None,
    }


def build(j, preset, keys=()):
    for k in keys:
        if not JIRA_KEY_RE.fullmatch(k):
            raise SystemExit(f"not a Jira key: {k[:30]!r}")
    versions = j.versions()
    wanted = _keys_for(j, preset, keys)
    if len(wanted) > MAX_ISSUES:
        raise jira_adapter.IncompleteRead(f"{len(wanted)} issues exceed the snapshot limit {MAX_ISSUES}")
    wanted = sorted(set(wanted), key=lambda k: int(k.split("-")[1]))
    return {
        "schema": SCHEMA,
        "site": getattr(j, "site", "file"), "project": j.project, "takenAt": now_utc(),
        "run": {"workflow": os.environ.get("GITHUB_WORKFLOW_REF"), "runId": os.environ.get("GITHUB_RUN_ID"),
                "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"), "sha": os.environ.get("GITHUB_SHA")},
        "query": {"preset": preset, "keys": list(keys)},
        "complete": True,
        "versions": versions,
        "issues": [snapshot_issue(j, k, versions) for k in wanted],
    }


def write(snap, path):
    data = (json.dumps(snap, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return "sha256:" + hashlib.sha256(data).hexdigest()


def load_verified(path, digest):
    """For key-holding consumers: the snapshot only if its bytes match the producer's digest output."""
    with open(path, "rb") as f:
        data = f.read()
    if not digest or "sha256:" + hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit("Jira snapshot does not match the digest of the jira-attestor job that produced it")
    snap = json.loads(data)
    if snap.get("schema") != SCHEMA or snap.get("complete") is not True:
        raise SystemExit("not a complete sox-jira-snapshot/v1")
    return snap


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--preset", required=True, choices=["issues", "releases", "sweep"])
    ap.add_argument("--keys", default="")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    keys = [k.strip() for k in args.keys.split(",") if k.strip()]
    if args.preset == "issues" and not keys:
        raise SystemExit("--keys is required for preset issues")
    j = jira_adapter.from_env()
    digest = write(build(j, args.preset, keys), args.out)
    set_output("digest", digest)
    print(f"snapshot {args.preset}: {digest}")


if __name__ == "__main__":
    main()
