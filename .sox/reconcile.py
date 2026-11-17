#!/usr/bin/env python3
"""Reconciler (evidence spec section 7). Runs only from a checkout of main, in
.github/workflows/sox-reconcile.yml; never checks out or executes PR code.

  reconcile.py run     --out DIR   build the report as the Reconciler (read-only App token in
                                   SOX_GITHUB_TOKEN, job token in SOX_ACTIONS_TOKEN): writes
                                   DIR/report.json (the reconciliation-report predicate) and
                                   DIR/report.subjects for actions/attest
  reconcile.py publish --dir DIR   as the Evidence Writer (SOX_EVIDENCE_TOKEN): append the
                                   attested report to the evidence repository's reports/ chain
  reconcile.py dry-run [--out DIR] build the report locally and print a summary; writes nothing
                                   remote

Inputs are fixed: no dispatch inputs. Everything is read from the GitHub API, git, verified
attestations, and the latest app-inventory artifact from main.
"""
import argparse
import base64
import glob
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from soxlib import gate as G  # noqa: E402
from soxlib import jcs, reconcile as RC  # noqa: E402
from soxlib.evidence import Evidence  # noqa: E402
from soxlib.ghapi import APIError, GitHub  # noqa: E402
from soxlib.gitrepo import Mirror  # noqa: E402
from soxlib.policy import Policy  # noqa: E402
from soxlib.scope import ScopeMap  # noqa: E402
from soxlib.verify import Verifier, parse_time  # noqa: E402

POLICY = os.path.join(HERE, "trust-policy.yaml")
EXPLAINED = os.path.join(HERE, "reconcile-explained.json")
INVENTORY_WORKFLOW = ".github/workflows/app-inventory.yml"
MAX_FILE = 900_000   # the contents API serves files up to 1 MB


def evidence_repo(policy):
    store = policy.data.get("evidenceStore") or {}
    return store.get("repo") or policy.repo.split("/")[0] + "/sox-sdlc-evidence"


def reports_prefix(policy):
    return ((policy.data.get("evidenceStore") or {}).get("reportsPrefix") or "reports/").rstrip("/") + "/"


def read_json(api, repo, path):
    """(parsed JSON, blob sha) of a file in repo's default branch, or (None, None) if absent."""
    try:
        meta = api.get(f"/repos/{repo}/contents/{path}")
    except APIError as e:
        if e.status == 404:
            return None, None
        raise
    raw = base64.b64decode(meta["content"]) if meta.get("content") else \
        api.get_raw(f"/repos/{repo}/contents/{path}")
    return json.loads(raw), meta["sha"]


def latest_inventory(actions_api, policy, workdir):
    """Newest completed app-inventory run on main and its summary artifact, or None. The summary
    job runs even when an expectation fails, so failed runs still carry fingerprints."""
    runs = actions_api.get(f"/repos/{policy.repo}/actions/workflows/app-inventory.yml/runs"
                           "?branch=main&per_page=10") or {}
    # status is checked here, not in the query: the status=completed filter lags new runs.
    for run in runs.get("workflow_runs") or []:
        if run.get("path") != INVENTORY_WORKFLOW or run.get("head_branch") != "main" \
                or run.get("event") != "workflow_dispatch" or run.get("status") != "completed":
            continue
        dest = os.path.join(workdir, f"inventory-{run['id']}")
        env = dict(os.environ, GH_TOKEN=actions_api.token or "", GH_PROMPT_DISABLED="1")
        p = subprocess.run(["gh", "run", "download", str(run["id"]), "-R", policy.repo,
                            "-n", "app-inventory", "-D", dest], capture_output=True, text=True,
                           env=env, timeout=120)
        files = glob.glob(os.path.join(dest, "**", "app-inventory.json"), recursive=True)
        if p.returncode != 0 or not files:
            continue
        with open(files[0]) as f:
            inv = json.load(f)
        if str(inv.get("runId")) != str(run["id"]):
            continue
        inv["runUrl"], inv["headSha"] = run.get("html_url"), run.get("head_sha")
        return inv
    return None


def load_explained(path=EXPLAINED):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def build(policy, api, actions_api, mirror_path, workdir, inventory_file=None, now=None):
    policy.resolve_go_live(api.get)
    policy.resolve_bypass(api.get)
    mirror = Mirror.ensure(policy.repo, mirror_path)
    ctx = G.Context(policy, api, Evidence(Verifier(policy), api), mirror,
                    ScopeMap.load(os.path.dirname(HERE), policy))
    ctx.actions_api = actions_api
    index, _ = read_json(actions_api, evidence_repo(policy), reports_prefix(policy) + "index.json")
    previous = index[-1] if index else None
    if inventory_file:
        with open(inventory_file) as f:
            inventory = json.load(f)
    else:
        inventory = latest_inventory(actions_api, policy, workdir)

    def evaluate(n, merged_at):
        return G.evaluate(ctx, n, as_of=merged_at)
    rec = RC.Reconciler(policy, api, ctx.ev, mirror, now or time.time(), previous=previous,
                        inventory=inventory, explained=load_explained(), evaluate=evaluate,
                        code_sha=os.environ.get("GITHUB_SHA"))
    report = rec.report()
    report["forgeryAttempts"] = sorted({x.get("digest") or "" for x in ctx.ev.forgeries()} - {""})
    return report


def write_report(report, out, repo):
    os.makedirs(out, exist_ok=True)
    report["observedAt"] = RC.iso(time.time())
    body = json.dumps(report, indent=1, sort_keys=True)
    if len(body.encode()) > MAX_FILE:
        raise SystemExit(f"report is {len(body)} bytes; the evidence store serves files up to 1 MB")
    with open(os.path.join(out, "report.json"), "w") as f:
        f.write(body)
    from soxlib import subject as subj
    with open(os.path.join(out, "report.subjects"), "w") as f:
        f.write(f"{subj.key(repo, 'report', report['id'])}  sox:report:{report['id']}\n")


def summary(report):
    p = report["populations"]
    return {"id": report["id"], "period": report["period"], "previousReport": report["previousReport"],
            "P1": p["P1"]["count"], "P2": p["P2"]["count"], "P8": p["P8"],
            "appKeys": [(k["role"], k["result"]) for k in report["appKeys"]["keys"]],
            "openExceptions": report["openExceptions"],
            "exceptionKinds": sorted({e["kind"] for e in report["exceptions"]}),
            "knownExceptions": [k["label"] for k in report["knownExceptions"]],
            "bundleMerkleRoot": report["bundleMerkleRoot"], "digest": jcs.digest(report)}


def cmd_run(a):
    if os.environ.get("GITHUB_ACTIONS") and os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise SystemExit("reconcile runs only from refs/heads/main")
    policy = Policy.load(POLICY)
    api = GitHub()
    actions_api = GitHub(token=os.environ.get("SOX_ACTIONS_TOKEN"))
    work = os.environ.get("RUNNER_TEMP") or tempfile.mkdtemp()
    report = build(policy, api, actions_api, a.mirror or os.path.join(work, "sox-mirror.git"),
                   work, a.inventory)
    write_report(report, a.out, policy.repo)
    s = summary(report)
    print(json.dumps(s, indent=1))
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as f:
            f.write(f"report-id={report['id']}\n")
    step = os.environ.get("GITHUB_STEP_SUMMARY")
    if step:
        with open(step, "a") as f:
            f.write("## Reconciliation report\n\n```json\n" + json.dumps(s, indent=1) + "\n```\n")
    return 0


def cmd_dry_run(a):
    a.out = a.out or tempfile.mkdtemp(prefix="sox-reconcile-")
    return cmd_run(a)


def put(api, repo, path, data, message, sha=None):
    body = {"message": message, "content": base64.b64encode(data).decode()}
    if sha:
        body["sha"] = sha
    return api.put(f"/repos/{repo}/contents/{path}", body)


def cmd_publish(a):
    """Append-only write as the Evidence Writer. The dated report and bundle are create-only;
    index.json and latest.json are updated only if the index still ends where the report
    chains to (blob sha precondition, so a concurrent write fails instead of forking)."""
    policy = Policy.load(POLICY)
    api = GitHub(token=os.environ["SOX_EVIDENCE_TOKEN"])
    repo, prefix = evidence_repo(policy), reports_prefix(policy)
    with open(os.path.join(a.dir, "report.json"), "rb") as f:
        raw = f.read()
    report = json.loads(raw)
    bundle_path = a.bundle or os.path.join(a.dir, "report.bundle.json")
    with open(bundle_path, "rb") as f:
        bundle = f.read()
    index, index_sha = read_json(api, repo, prefix + "index.json")
    index = index or []
    problems = RC.check_chain(index, report)
    if problems:
        raise SystemExit("not publishing: " + "; ".join(problems))
    _, latest_sha = read_json(api, repo, prefix + "latest.json")
    t = parse_time(report["id"])
    day = time.strftime("%Y/%m/%d", time.gmtime(t))
    stem = f"{prefix}{day}/report-{report['id'].replace(':', '').replace('-', '')}"
    msg = f"reconciliation report {report['id']} (run {os.environ.get('GITHUB_RUN_ID', 'local')})"
    put(api, repo, stem + ".json", raw, msg)
    put(api, repo, stem + ".bundle.json", bundle, msg)
    entry = RC.index_entry(report, stem + ".json", "sha256:" + jcs.sha256_hex(bundle))
    put(api, repo, prefix + "index.json",
        (json.dumps(index + [entry], indent=1) + "\n").encode(), msg, index_sha)
    put(api, repo, prefix + "latest.json", raw, msg, latest_sha)
    print(json.dumps(entry, indent=1))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["run", "publish", "dry-run"])
    ap.add_argument("--out")
    ap.add_argument("--dir")
    ap.add_argument("--bundle")
    ap.add_argument("--mirror")
    ap.add_argument("--inventory", help="app-inventory.json to use instead of the latest artifact")
    a = ap.parse_args(argv)
    if a.command == "run" and not a.out:
        ap.error("run needs --out")
    if a.command == "publish" and not a.dir:
        ap.error("publish needs --dir")
    return {"run": cmd_run, "publish": cmd_publish, "dry-run": cmd_dry_run}[a.command](a)


if __name__ == "__main__":
    sys.exit(main())
