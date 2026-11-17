#!/usr/bin/env python3
"""sox/evidence-gate (evidence spec section 6). Runs only from a checkout of main, in
.github/workflows/sox-gate.yml; never checks out or executes PR code.

  gate.py evaluate --pr N [--as-of-merge]   dry run: print the evaluation, post nothing
  gate.py run      --pr N --out DIR         open PR: create the check run (in_progress), evaluate,
                                            write predicate files for the attest steps;
                                            merged PR into main: plan the merge-record
  gate.py finish   --out DIR                re-read the head, complete the check run (success or
                                            failure only); merged PR: plan release-approvals
  gate.py stamp    --out DIR                release-approval job: write predicate + subjects files
                                            from RA_PREDICATE / RA_SUBJECTS with a fresh observedAt

The PR number is the only input and is a lookup key. Everything else is read from the GitHub API
with the Gate App token (SOX_GITHUB_TOKEN), from git, and from verified attestations. Any error
completes the check run as failure.
"""
import argparse
import json
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from soxlib import gate as G  # noqa: E402
from soxlib import records as R  # noqa: E402
from soxlib.evidence import Evidence  # noqa: E402
from soxlib.ghapi import GitHub  # noqa: E402
from soxlib.gitrepo import Mirror  # noqa: E402
from soxlib.policy import Policy  # noqa: E402
from soxlib.scope import ScopeMap  # noqa: E402
from soxlib.verify import Verifier, parse_time  # noqa: E402

POLICY = os.path.join(HERE, "trust-policy.yaml")
CHECK = "sox/evidence-gate"
TEXT_MAX = 60000


class LazyMirror:
    """Clone the bare mirror only when an evaluation needs git (release PRs, merge records)."""

    def __init__(self, repo, path):
        self.repo, self.path, self._m = repo, path, None

    def __getattr__(self, name):
        if self._m is None:
            self._m = Mirror.ensure(self.repo, self.path)
        return getattr(self._m, name)


def load_services(policy, root=ROOT):
    return ScopeMap.load(root, policy)


def make_ctx(policy, api, mirror_path=None):
    v = Verifier(policy)
    ev = Evidence(v, api)
    path = mirror_path or os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "sox-mirror.git")
    ctx = G.Context(policy, api, ev, LazyMirror(policy.repo, path), load_services(policy))
    if os.environ.get("SOX_ACTIONS_TOKEN"):
        # Workflow runs and jobs (F17) are read with the job's own token (actions: read), so the
        # Gate App needs no Actions permission.
        ctx.actions_api = GitHub(token=os.environ["SOX_ACTIONS_TOKEN"])
    return ctx


def pr_number(text):
    s = str(text or "").strip()
    if not s.isdigit() or not 0 < int(s) < 10 ** 9:
        raise SystemExit(f"pr must be a positive integer, got {s!r}")
    return int(s)


def set_output(name, value):
    path = os.environ.get("GITHUB_OUTPUT")
    line = f"{name}={value}\n"
    if path:
        with open(path, "a") as f:
            f.write(line)
    else:
        sys.stderr.write("output " + line)


def report_markdown(ev, forgeries, notes=()):
    rows = ["| Requirement | Control | Result | Detail |", "|---|---|---|---|"]
    for r in ev.reqs:
        d = r.detail.replace("|", "\\|").replace("\n", " ")
        rows.append(f"| `{r.id}` | {r.control} | {'pass' if r.ok else '**FAIL**'} | {d} |")
    f = ev.facts
    out = [f"PR #{ev.pd.number} `{ev.pd.head_ref}` -> `{ev.pd.base_ref}` at `{ev.pd.head}` "
           f"(evaluated as **{ev.kind}**).", ""] + rows
    if f.get("packetReady") and f.get("packet"):
        out += ["", "### Approval packet", f"Packet digest: `{f['packetDigest']}`. Approve this "
                "exact head only after this packet has been presented; an approval submitted "
                "earlier does not count.", "", "```json",
                json.dumps(f["packet"], indent=1, sort_keys=True), "```"]
    if forgeries:
        out += ["", f"### Forgery attempts ({len(forgeries)}, ignored)"]
        for x in forgeries[:50]:
            out.append(f"- `{x.get('digest')}` {x.get('predicateType')}: {x.get('reason')}")
    out += list(notes)
    return "\n".join(out)


def complete(api, policy, check_id, conclusion, title, text):
    if conclusion not in ("success", "failure"):
        conclusion = "failure"
    summary = text[:TEXT_MAX]
    return api.patch(f"/repos/{policy.repo}/check-runs/{check_id}", {
        "status": "completed", "conclusion": conclusion, "completed_at": R.now_iso(),
        "output": {"title": title[:250], "summary": summary}})


def write_state(out, state):
    with open(os.path.join(out, "state.json"), "w") as f:
        json.dump(state, f, indent=1, sort_keys=True)


def read_state(out):
    with open(os.path.join(out, "state.json")) as f:
        return json.load(f)


def emit_outputs(emitted):
    for name in R.EMIT_NAMES:
        set_output(f"emit-{name}", "true" if name in emitted else "false")


# ---------------------------------------------------------------- commands

def cmd_evaluate(a):
    policy = Policy.load(POLICY)
    api = GitHub()
    n = pr_number(a.pr)
    ctx = make_ctx(policy, api, a.mirror)
    pd = ctx.prdata(n)
    as_of = pd.merged_at if a.as_of_merge else None
    ev = G.evaluate(ctx, n, as_of=as_of)
    print(json.dumps({"pr": n, "head": pd.head, "kind": ev.kind,
                      "conclusion": "success" if ev.ok else "failure",
                      "requirements": [r.to_json() for r in ev.reqs],
                      "packetDigest": ev.facts.get("packetDigest"),
                      "forgeries": ctx.ev.forgeries(), "apiCalls": api.calls},
                     indent=1, default=str))
    return 0


def cmd_run(a, api=None, policy=None):
    policy = policy or Policy.load(POLICY)
    api = api or GitHub()
    n = pr_number(a.pr)
    os.makedirs(a.out, exist_ok=True)
    pr = api.get(f"/repos/{policy.repo}/pulls/{n}")
    state = {"pr": n, "mode": "none", "emitted": []}
    if pr.get("state") == "open":
        head = pr["head"]["sha"]
        # Created before anything is read, so the newest check run always reflects the newest
        # read of the PR, whatever order concurrent runs finish in.
        check = api.post(f"/repos/{policy.repo}/check-runs", {
            "name": CHECK, "head_sha": head, "status": "in_progress",
            "external_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "output": {"title": "Evaluating evidence", "summary": "Gate evaluation in progress."}})
        state.update({"mode": "open", "checkId": check["id"], "head": head})
        write_state(a.out, state)
        try:
            ctx = make_ctx(policy, api, a.mirror)
            ctx.check_run_id = check["id"]
            ev = G.evaluate(ctx, n)
            emissions = R.plan_open(ev, ctx)
            for e in emissions:
                e.write(a.out, policy.repo)
            forgeries = ctx.ev.forgeries()
            state.update({"conclusion": "success" if ev.ok else "failure",
                          "passed": sum(r.ok for r in ev.reqs), "total": len(ev.reqs),
                          "summary": report_markdown(ev, forgeries),
                          "emitted": [e.name for e in emissions]})
        except Exception:
            err = traceback.format_exc()
            sys.stderr.write(err)
            complete(api, policy, check["id"], "failure", "Gate error (fail closed)",
                     "The gate could not complete its evaluation, so the check fails.\n\n```\n"
                     + err[-3000:] + "\n```")
            write_state(a.out, dict(state, mode="error"))
            emit_outputs([])
            return 1
    elif pr.get("merged_at") and pr["base"]["ref"] == "main":
        ctx = make_ctx(policy, api, a.mirror)
        pd = ctx.prdata(n)
        ev = G.evaluate(ctx, n, as_of=pd.merged_at)
        emissions, existing = R.plan_merged(ev, ctx)
        for e in emissions:
            e.write(a.out, policy.repo)
        state.update({"mode": "merged", "emitted": [e.name for e in emissions],
                      "existingMergeRecord": existing.digest if existing else None,
                      "mergeRecord": (existing.predicate if existing else emissions[0].predicate)})
        ras, why = R.release_approvals(ev, ctx, "sha256:pending", state["mergeRecord"])
        state["releaseApprovalBlockers"] = why
        state["releaseApprovalPlanned"] = len(ras)
        state["conclusion"] = "success" if ev.ok else "failure"
    write_state(a.out, state)
    emit_outputs(state["emitted"])
    print(json.dumps({k: v for k, v in state.items() if k != "summary"}, indent=1, default=str))
    return 0


def cmd_finish(a, api=None, policy=None):
    policy = policy or Policy.load(POLICY)
    api = api or GitHub()
    state = read_state(a.out)
    set_output("images", "[]")
    if state["mode"] == "open":
        try:
            pr = api.get(f"/repos/{policy.repo}/pulls/{state['pr']}")
            notes = []
            url = os.environ.get("GATE_DECISION_URL")
            if url:
                notes.append(f"\n\ngate-decision attestation: {url}")
            conclusion, title = state["conclusion"], (
                f"{state['passed']}/{state['total']} requirements pass")
            if pr.get("state") != "open" or pr["head"]["sha"] != state["head"]:
                conclusion, title = "failure", "Superseded: the PR changed during evaluation"
                notes.append(f"\n\nHead is now {pr['head']['sha']} (state {pr.get('state')}); "
                             "this result applies to no current head. A new run evaluates it.")
            complete(api, policy, state["checkId"], conclusion, title,
                     state["summary"] + "".join(notes))
            print(json.dumps({"check": state["checkId"], "conclusion": conclusion}))
            return 0
        except Exception:
            err = traceback.format_exc()
            sys.stderr.write(err)
            complete(api, policy, state["checkId"], "failure", "Gate error (fail closed)",
                     "```\n" + err[-3000:] + "\n```")
            return 1
    if state["mode"] == "merged":
        ctx = make_ctx(policy, api, a.mirror)
        n = state["pr"]
        pd = ctx.prdata(n)
        bundle = os.environ.get("MERGE_RECORD_BUNDLE")
        if state.get("existingMergeRecord"):
            mr = state["existingMergeRecord"]
        elif bundle and os.path.exists(bundle):
            mr = R.bundle_digest(bundle)
        else:
            print("no merge-record digest; release-approval deferred to the next run")
            return 0
        ev = G.evaluate(ctx, n, as_of=pd.merged_at)
        ras, why = R.release_approvals(ev, ctx, mr, state["mergeRecord"])
        for w in why:
            print("release-approval not signed: " + w)
        set_output("images", json.dumps(ras, separators=(",", ":"), sort_keys=True))
        print(json.dumps({"releaseApprovals": [x["service"] for x in ras], "blockers": why}))
    return 0


def cmd_stamp(a):
    pred = json.loads(os.environ["RA_PREDICATE"])
    subjects = os.environ["RA_SUBJECTS"]
    if pred.get("environment") != "production" or not pred.get("humanApproval"):
        raise SystemExit("release-approval predicate incomplete")
    pred["observedAt"] = R.now_iso()
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "release-approval.json"), "w") as f:
        json.dump(pred, f, indent=1, sort_keys=True)
    with open(os.path.join(a.out, "release-approval.subjects"), "w") as f:
        f.write(subjects if subjects.endswith("\n") else subjects + "\n")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["evaluate", "run", "finish", "stamp"])
    ap.add_argument("--pr")
    ap.add_argument("--out", default=os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "sox-gate"))
    ap.add_argument("--mirror")
    ap.add_argument("--as-of-merge", action="store_true")
    a = ap.parse_args(argv)
    return {"evaluate": cmd_evaluate, "run": cmd_run, "finish": cmd_finish,
            "stamp": cmd_stamp}[a.command](a)


if __name__ == "__main__":
    sys.exit(main())
