"""Jira command line for agent workflows and demos.

  jira_cli.py apply --ops ops.json --role pm [--out results.json] [--message M]
  jira_cli.py show FRQ-1 | changelog FRQ-1 | list [--type Epic] [--status Approved]
  jira_cli.py requirement --summary S --description D [--role intake | --as <human>]
  jira_cli.py transition FRQ-1 "Plan Ready" --role techlead     (agents; human-only statuses refused)
  jira_cli.py transition FRQ-1 Approved --as factory-aman        (FileJira demos only)

Backend (jira_adapter.from_env): SOX_JIRA_BACKEND=cloud (default) | file. Cloud credentials exist
only in env jira-attestor (JIRA_API_TOKEN, SOX_JIRA_EMAIL) or locally in ~/.factory/secrets/jira.
With the file backend and SOX_JIRA_STORE_BRANCH set, every write is a pull -> apply -> compare-and-swap
push of jira.json on that branch through the Contents API (token SOX_JIRA_STORE_TOKEN).
"""
import argparse
import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import REPO, GitHub  # noqa: E402
import jira_adapter  # noqa: E402

STORE_FILE = "jira.json"
ROLE_ACCOUNTS = jira_adapter.ROLE_ACCOUNTS


def _file_backend():
    return (os.environ.get("SOX_JIRA_BACKEND") or "cloud") == "file"


def _branch():
    return os.environ.get("SOX_JIRA_STORE_BRANCH")


def _store_gh(write=False):
    tok = os.environ.get("SOX_JIRA_STORE_TOKEN") if write else (os.environ.get("SOX_JIRA_STORE_TOKEN") or os.environ.get("GITHUB_TOKEN", ""))
    if write and not tok:
        raise SystemExit("SOX_JIRA_STORE_TOKEN is required to write the fake Jira store")
    return GitHub(tok, REPO)


def pull(local):
    """Fetch jira.json from the store branch into `local`; return its blob sha (None if absent)."""
    gh = _store_gh()
    try:
        meta = gh.get(f"/repos/{REPO}/contents/{STORE_FILE}?ref={_branch()}")
    except RuntimeError as e:
        if "HTTP 404" in str(e):
            if os.path.exists(local):
                os.unlink(local)
            return None
        raise
    content = base64.b64decode(meta["content"]) if meta.get("content") else gh.get(meta["git_url"])["content"]
    if isinstance(content, str):
        content = base64.b64decode(content)
    os.makedirs(os.path.dirname(os.path.abspath(local)), exist_ok=True)
    with open(local, "wb") as f:
        f.write(content)
    return meta["sha"]


def push(local, sha, message):
    gh = _store_gh(write=True)
    with open(local, "rb") as f:
        body = {"message": message, "branch": _branch(), "content": base64.b64encode(f.read()).decode()}
    if sha:
        body["sha"] = sha
    gh.request("PUT", f"/repos/{REPO}/contents/{STORE_FILE}", body)


def load(account=None):
    if _file_backend() and _branch():
        pull(os.environ.setdefault("SOX_JIRA_FILE", "jira-fake/jira.json"))
    return jira_adapter.from_env()


def _file_write(fn, message):
    local = os.environ.setdefault("SOX_JIRA_FILE", "jira-fake/jira.json")
    if not _branch():
        j = jira_adapter.FileJira(local)
        out = fn(j)
        j.save()
        return out
    for attempt in range(6):
        sha = pull(local)
        j = jira_adapter.FileJira(local)
        out = fn(j)
        j.save()
        try:
            push(local, sha, message)
            return out
        except RuntimeError as e:
            if ("HTTP 409" in str(e) or "HTTP 422" in str(e)) and attempt < 5:
                time.sleep(1 + attempt)
                continue
            raise
    raise RuntimeError("could not write the Jira store")


def write(ops, role, message):
    """Apply ops as agent `role`. Returns (results, refs)."""
    if not _file_backend():
        return jira_adapter.apply_ops(jira_adapter.from_env(), ops, role)
    return _file_write(lambda j: jira_adapter.apply_ops(j, ops, role), f"{message} [as {role}]")


def act(fn, actor, message):
    """One adapter call as `actor` (an Actor). Humans are only allowed on the file backend."""
    if not _file_backend():
        if actor.human:
            raise SystemExit("humans act in the Jira UI; the Cloud adapter writes only as an agent role")
        return fn(jira_adapter.from_env())
    return _file_write(fn, f"{message} [as {actor.account}]")


def _actor(args):
    if getattr(args, "human", None):
        return jira_adapter.Actor(human=args.human)
    return jira_adapter.Actor(role=args.role)


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    roles = sorted(jira_adapter.ROLES)
    a = sub.add_parser("apply"); a.add_argument("--ops", required=True); a.add_argument("--role", choices=roles, required=True)
    a.add_argument("--out"); a.add_argument("--message", default="jira ops")
    s = sub.add_parser("show"); s.add_argument("key")
    lst = sub.add_parser("list"); lst.add_argument("--type"); lst.add_argument("--status"); lst.add_argument("--parent"); lst.add_argument("--fix-version")
    r = sub.add_parser("requirement"); r.add_argument("--summary", required=True); r.add_argument("--description", default="")
    t = sub.add_parser("transition"); t.add_argument("key"); t.add_argument("status")
    for p in (r, t):
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--role", choices=roles); g.add_argument("--as", dest="human")
    c = sub.add_parser("changelog"); c.add_argument("key")
    args = ap.parse_args(argv)

    if args.cmd == "apply":
        with open(args.ops) as f:
            ops = json.load(f)
        if not ops:
            print("no operations"); return
        results, refs = write(ops, args.role, args.message)
        out = {"results": results, "refs": refs}
        if args.out:
            with open(args.out, "w") as f:
                json.dump(out, f, indent=2)
        json.dump(out, sys.stdout, indent=2); print()
    elif args.cmd == "show":
        j = load(); issue = j.get(args.key); issue["comments"] = j.comments(args.key)
        json.dump(issue, sys.stdout, indent=2); print()
    elif args.cmd == "changelog":
        json.dump(load().changelog(args.key), sys.stdout, indent=2); print()
    elif args.cmd == "list":
        for i in load().search(type=args.type, status=args.status, parent=args.parent, fix_version=args.fix_version):
            print(f"{i['key']}\t{i['type']}\t{i['status']}\t{i['summary']}")
    elif args.cmd == "requirement":
        actor = _actor(args)

        def mk(j):
            key = j.create("Requirement", args.summary, args.description, actor)
            if actor.role:
                j.comment(key, f"{jira_adapter.role_prefix(actor.role)} Requirement filed through the {actor.role} channel.", actor)
            return key
        print(act(mk, actor, "new requirement"))
    elif args.cmd == "transition":
        actor = _actor(args)
        act(lambda j: j.transition(args.key, args.status, actor), actor, f"transition {args.key}")
        print(f"{args.key} -> {args.status}")


if __name__ == "__main__":
    main()
