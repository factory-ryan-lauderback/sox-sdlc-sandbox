"""Jira command line for agent workflows and demos.

  jira_cli.py apply --ops ops.json --as svc-pm-agent [--out results.json]
  jira_cli.py show FRQ-1 | list [--type Epic] [--status Approved]
  jira_cli.py requirement --summary S --description D --as <reporter>
  jira_cli.py transition FRQ-1 Approved --as <account>

Backend selection (jira_adapter.from_env): SOX_JIRA_BACKEND=file|cloud.
With the file backend and SOX_JIRA_STORE_BRANCH set (Actions, demos), every write is a
pull -> apply -> compare-and-swap push of jira.json on that branch through the Contents API,
retried on conflict, so concurrent agents cannot overwrite each other. The token for the push is
SOX_JIRA_STORE_TOKEN (the acme-jira-attestor App installation token in Actions).
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
# Workflow role -> Jira service account. The account always comes from this table (workflow code on
# main), never from an LLM or an operation list.
ROLE_ACCOUNTS = {"pm": "svc-pm-agent", "techlead": "svc-techlead-agent", "review": "svc-review-agent",
                 "dev": "svc-dev-agent", "qa": "svc-qa-agent", "attestor": "svc-jira-attestor",
                 "bundler": "svc-release-bundler"}


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
    if os.environ.get("SOX_JIRA_BACKEND", "file") == "file" and _branch():
        pull(os.environ.setdefault("SOX_JIRA_FILE", "jira-fake/jira.json"))
    return jira_adapter.from_env(account)


def write(ops, account, message):
    """Apply ops as `account`. Returns (results, refs)."""
    if os.environ.get("SOX_JIRA_BACKEND", "file") != "file":
        return jira_adapter.apply_ops(jira_adapter.from_env(account), ops, account)
    local = os.environ.setdefault("SOX_JIRA_FILE", "jira-fake/jira.json")
    if not _branch():
        j = jira_adapter.FileJira(local)
        out = jira_adapter.apply_ops(j, ops, account)
        j.save()
        return out
    for attempt in range(6):
        sha = pull(local)
        j = jira_adapter.FileJira(local)
        out = jira_adapter.apply_ops(j, ops, account)
        j.save()
        try:
            push(local, sha, f"{message} [as {account}]")
            return out
        except RuntimeError as e:
            if ("HTTP 409" in str(e) or "HTTP 422" in str(e)) and attempt < 5:
                time.sleep(1 + attempt)
                continue
            raise
    raise RuntimeError("could not write the Jira store")


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("apply"); a.add_argument("--ops", required=True); g = a.add_mutually_exclusive_group(required=True); g.add_argument("--as", dest="account"); g.add_argument("--role", choices=sorted(ROLE_ACCOUNTS)); a.add_argument("--out"); a.add_argument("--message", default="jira ops")
    s = sub.add_parser("show"); s.add_argument("key")
    l = sub.add_parser("list"); l.add_argument("--type"); l.add_argument("--status"); l.add_argument("--parent"); l.add_argument("--fix-version")
    r = sub.add_parser("requirement"); r.add_argument("--summary", required=True); r.add_argument("--description", default=""); r.add_argument("--as", dest="account", required=True)
    t = sub.add_parser("transition"); t.add_argument("key"); t.add_argument("status"); t.add_argument("--as", dest="account", required=True)
    c = sub.add_parser("changelog"); c.add_argument("key")
    args = ap.parse_args(argv)

    if args.cmd == "apply":
        with open(args.ops) as f:
            ops = json.load(f)
        if not ops:
            print("no operations"); return
        account = args.account or ROLE_ACCOUNTS[args.role]
        results, refs = write(ops, account, args.message)
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
        results, _ = write([{"op": "create", "type": "Requirement", "summary": args.summary, "description": args.description}],
                           args.account, "new requirement")
        print(results[0]["key"])
    elif args.cmd == "transition":
        write([{"op": "transition", "key": args.key, "to": args.status}], args.account, f"transition {args.key}")
        print(f"{args.key} -> {args.status}")


if __name__ == "__main__":
    main()
