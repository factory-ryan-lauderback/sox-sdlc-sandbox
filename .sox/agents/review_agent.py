"""Review Agent (SDLC-06): resolve -> prepare -> [droid exec, read-only] -> parse -> record -> post.

The LLM job (`prepare`, `parse`) holds FACTORY_API_KEY and a read-only GITHUB_TOKEN, never an App key.
The record job holds the Review App token and re-derives everything it signs from the GitHub API;
the LLM job's artifact contributes only the verdict text, which is checked against the diff digest.
Neither job checks out or executes PR code: the diff is fetched as data.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (REPO, GitHub, digest_of, dump_json, is_control_path, load_json, now_utc,  # noqa: E402
                    positive_int, pr_binding, predicate_type, set_output, sha256_hex, subject_lines)
import checks  # noqa: E402
import rounds  # noqa: E402

CHECK_NAME = "sox/review-agent"
MAX_ROUNDS = int(os.environ.get("SOX_MAX_REVIEW_ROUNDS", "10"))
MAX_DIFF_BYTES = 400_000
SWEEP_LIMIT = 5


def resolve(args):
    gh = GitHub()
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    if event == "workflow_dispatch":
        prs = [positive_int(os.environ.get("INPUT_PR", "").strip(), "pr")]
    elif event == "schedule":
        prs = []
        for pr in gh.paginate(f"/repos/{REPO}/pulls?state=open&sort=updated&direction=desc", limit=100):
            if pr["draft"]:
                continue
            runs = gh.get(f"/repos/{REPO}/commits/{pr['head']['sha']}/check-runs?check_name={CHECK_NAME}")["check_runs"]
            if not any(r["app"]["slug"] == "acme-review-agent" and r["status"] == "completed" for r in runs):
                prs.append(pr["number"])
            if len(prs) >= SWEEP_LIMIT:
                break
    else:
        raise SystemExit(f"unsupported trigger {event}")
    set_output("prs", json.dumps(prs))


def _jira_context(binding):
    """Story/plan context and Jira keys for the PR, read from Jira (never from the PR)."""
    keys, text = [], []
    try:
        import jira_cli
        j = jira_cli.load()
    except Exception as e:  # Jira unavailable: review continues; the gate enforces the Jira chain.
        return ([binding["story"]] if binding["story"] else []), f"(Jira unavailable: {type(e).__name__})"
    stories = []
    if binding["kind"] == "story" and binding["story"]:
        stories = [binding["story"]]
    elif binding["kind"] == "release" and binding["release"]:
        stories = [s["key"] for s in j.search(type="Story", fix_version=binding["release"])]
    for key in stories:
        try:
            s = j.get(key)
        except Exception:
            text.append(f"## {key}\n(not found in Jira)\n"); keys.append(key); continue
        keys.append(key)
        text.append(f"## {key}: {s['summary']}\nType: {s.get('storyType')}  Services: {s.get('services')}\n"
                    f"Required tests: {s.get('requiredTests')}\nDepends on: {s.get('dependsOn')}\n\n{s['description']}\n")
        if s.get("parent"):
            try:
                epic = j.get(s["parent"])
                plan = [a for a in epic["attachments"] if a["filename"] == "plan.md"]
                if plan:
                    text.append(f"### Plan for {epic['key']}\n" + j.attachment_content(epic["key"], plan[-1]["id"]).decode()[:20000])
            except Exception:
                pass
    return sorted(set(keys), key=lambda k: int(k.split("-")[1])), "\n".join(text) or "(no Jira context)"


def _snapshot(gh, number):
    pr = gh.pr(number)
    diff = gh.pr_diff(number)
    files = [f["filename"] for f in gh.pr_files(number)]
    return pr, diff, files


def prepare(args):
    gh = GitHub()
    number = positive_int(args.pr, "pr")
    pr, diff, files = _snapshot(gh, number)
    binding = pr_binding(pr)
    jira_keys, jira_text = _jira_context(binding)
    head = pr["head"]["sha"]
    out = args.out
    os.makedirs(out, exist_ok=True)
    ctx = {"pr": number, "headSha": head, "baseSha": pr["base"]["sha"], "baseRef": binding["baseRef"],
           "diffDigest": "sha256:" + sha256_hex(diff), "binding": binding, "jiraKeys": jira_keys}
    existing = rounds.verdict_for_head(head, binding["baseRef"])
    prior, _ = rounds.failing_heads(tuple(binding["loopKey"]))
    mode = "llm"
    if existing:
        mode = "reuse"
    elif len(prior - {head}) >= MAX_ROUNDS:
        mode = "exhausted"
    elif len(diff) > MAX_DIFF_BYTES:
        mode = "too-large"
    ctx["mode"] = mode
    dump_json(f"{out}/context.json", ctx)
    with open(f"{out}/pr.diff", "wb") as f:
        f.write(diff)
    control = [p for p in files if is_control_path(p)]
    with open(f"{out}/context.md", "w") as f:
        f.write(f"# PR #{number}: {pr['title']}\n\nBranch: {binding['headRef']} -> {binding['baseRef']} ({binding['kind']} PR)\n"
                f"Author: {pr['user']['login']}\nHead: {head}\nFiles changed: {len(files)}\n"
                f"Control-path files: {control or 'none'}\n\n# Jira\n{jira_text}\n\n# PR description\n{(pr.get('body') or '')[:5000]}\n")
    set_output("mode", mode)


def parse(args):
    """Turn droid's JSON output into verdict.json. Anything malformed becomes an `error` verdict."""
    ctx = load_json(f"{args.dir}/context.json")
    verdict = {"verdict": "error", "summary": "", "findings": [], "agent": {}}
    if ctx["mode"] == "too-large":
        verdict.update(verdict="changes_requested", summary=f"Diff exceeds {MAX_DIFF_BYTES} bytes; split the change.",
                       findings=[{"severity": "blocking", "path": None, "line": None, "title": "Diff too large",
                                  "body": "Split the story into smaller PRs."}])
    elif ctx["mode"] == "llm":
        try:
            raw = load_json(f"{args.dir}/droid.json")
            verdict["agent"] = {"factorySessionId": raw.get("session_id"), "isError": raw.get("is_error"),
                                "numTurns": raw.get("num_turns")}
            text = raw.get("result") or ""
            m = re.search(r"\{.*\}", text, re.S)
            body = json.loads(m.group(0)) if m else None
            if raw.get("is_error") or not isinstance(body, dict):
                raise ValueError("no JSON verdict in droid output")
            v = body.get("verdict")
            findings = [f for f in body.get("findings") or [] if isinstance(f, dict)][:50]
            blocking = any(f.get("severity") == "blocking" for f in findings)
            if v not in ("pass", "changes_requested"):
                raise ValueError(f"bad verdict {v!r}")
            if blocking:
                v = "changes_requested"
            verdict.update(verdict=v, summary=str(body.get("summary") or "")[:1000], findings=[
                {"severity": f.get("severity") if f.get("severity") in ("blocking", "minor") else "minor",
                 "path": str(f.get("path"))[:300] if f.get("path") else None,
                 "line": f.get("line") if isinstance(f.get("line"), int) else None,
                 "title": str(f.get("title") or "")[:200], "body": str(f.get("body") or "")[:4000]} for f in findings])
        except Exception as e:
            verdict["summary"] = f"Review Agent produced no usable verdict ({type(e).__name__}: {str(e)[:200]})"
    dump_json(f"{args.dir}/verdict.json", verdict)
    print(f"verdict={verdict['verdict']}")


def _app_id_for_login(gh, user):
    if user.get("type") != "Bot" or not user["login"].endswith("[bot]"):
        return None
    try:
        return GitHub("").get(f"/apps/{user['login'][:-5]}")["id"]
    except RuntimeError:
        return None


def record(args):
    """Re-derive the PR state, decide what to sign, and write predicate/subjects/plan files."""
    gh = GitHub()
    ctx = load_json(f"{args.dir}/context.json")
    number = positive_int(ctx["pr"], "pr")
    pr, diff, files = _snapshot(gh, number)
    binding = pr_binding(pr)
    head = pr["head"]["sha"]
    # action: none (no check run), post (one completed run), attest (in_progress run, attest, complete),
    # heal (complete our stale in_progress run whose verdict was attested). See checks.py.
    plan = {"pr": number, "headSha": head, "action": "post", "conclusion": "failure", "attest": False}
    out = args.out
    os.makedirs(out, exist_ok=True)

    def finish(title, summary, details=""):
        plan.update(title=title, summary=summary, details=details)
        dump_json(f"{out}/plan.json", plan)
        set_output("attest", "true" if plan["attest"] else "false")
        set_output("action", plan["action"])
        print(json.dumps({k: plan[k] for k in ("action", "conclusion", "attest", "title")}))
        if plan["action"] == "none":
            print(f"::warning title=No check run::{title}: {summary}")

    if head != ctx["headSha"] or binding["baseRef"] != ctx["baseRef"]:
        plan["action"] = "none"
        return finish("Superseded", "PR head or base changed during review; a new run reviews the new state.")
    diff_digest = "sha256:" + sha256_hex(diff)
    if diff_digest != ctx["diffDigest"]:
        plan["action"] = "none"
        return finish("Superseded", "Diff changed during review.")

    reviewer_app = int(os.environ["REVIEWER_APP_ID"])
    runs = checks.app_runs(gh, head, CHECK_NAME, reviewer_app)
    state = checks.head_state(runs)
    existing = rounds.verdict_for_head(head, binding["baseRef"])
    if existing:
        p = existing.predicate
        plan["conclusion"] = "success" if p.get("outcome") == "pass" else "failure"
        cid = p.get("checkRunId")
        mine = [r for r in runs if r["id"] == cid]
        if mine and mine[0]["status"] != "completed":
            plan.update(action="heal", checkRunId=cid)
        elif any(r["status"] == "completed" and r.get("conclusion") == plan["conclusion"] for r in runs):
            plan["action"] = "none"
        return finish(f"Review: {p.get('outcome')} (round {p.get('round')}, existing verified verdict)",
                      "A verified review-verdict already exists for this head SHA and base. It is re-posted, not re-run; "
                      "a failing verdict for a head can never be replaced by a later pass.",
                      f"Attestation {existing.digest}, run {existing.identity.get('runInvocationURI')}")
    if state in ("burned", "open"):
        # No attested verdict, yet a Review App run exists on this head: it was cancelled, failed or
        # crashed during attest. The gate treats it as binding, so judging again cannot help.
        plan["action"] = "none"
        return finish("Head blocked", f"A {CHECK_NAME} run on {head[:12]} is {state} without an attested verdict. "
                      "Push a new commit; the new head gets a fresh review.")

    prior, forgeries = rounds.failing_heads(tuple(binding["loopKey"]))
    prior = prior - {head}
    plan["forgeryAttempts"] = forgeries
    if len(prior) >= MAX_ROUNDS:
        plan["escalate"] = True
        loop_key = ":".join(binding["loopKey"])
        if binding["story"]:
            ops = [{"op": "transition", "key": binding["story"], "to": "Blocked - Human Escalation"},
                   {"op": "comment", "key": binding["story"], "body": f"Review loop exhausted: {len(prior)} verified changes_requested rounds for {loop_key}. A human Tech Lead must re-plan (transition to Re-plan)."}]
            dump_json(f"{out}/jira-ops.json", ops)
        return finish("loop-exhausted", f"{len(prior)} verified changes_requested rounds for {loop_key} (max {MAX_ROUNDS}). Escalated to a human; no further automated review.")

    verdict = load_json(f"{args.dir}/verdict.json")
    if verdict["verdict"] not in ("pass", "changes_requested"):
        # Infrastructure or model failure before judging: no check run, so the head stays reviewable.
        plan["action"] = "none"
        return finish("Review error", verdict["summary"] or "Review Agent failed; the sweep retries.")

    author_app = _app_id_for_login(gh, pr["user"])
    if author_app is not None and author_app == reviewer_app:
        return finish("Segregation of duties", "The Review App authored this PR; it cannot review it.")

    jira_keys, _ = _jira_context(binding)
    findings_digest = digest_of(verdict["findings"])
    inputs = [{"name": "pr-diff", "digest": {"sha256": diff_digest.split(":", 1)[1]}}]
    plan_digest = rounds.latest_plan_digest(jira_keys)
    upstream = []
    if plan_digest:
        inputs.append({"name": "techlead-plan", "digest": {"sha256": plan_digest.split(":", 1)[1]}})
        upstream.append(plan_digest)
    round_no = len(prior) + 1
    predicate = {
        "schema": "sox/common/v1", "repo": REPO, "prNumber": number, "headSha": head,
        "baseSha": pr["base"]["sha"], "baseRef": binding["baseRef"], "jiraKeys": jira_keys,
        "release": binding["release"], "step": "SDLC-06",
        "actor": {"type": "github_app", "login": f"{os.environ.get('REVIEWER_APP_SLUG', 'acme-review-agent')}[bot]",
                  "appId": reviewer_app, "source": "installation token minted in this run"},
        "inputs": inputs, "inputsDigest": digest_of(inputs),
        "outcome": verdict["verdict"], "round": round_no, "loopKey": ":".join(binding["loopKey"]),
        "observedAt": now_utc(),
        "attestor": {"workflow": ".github/workflows/sox-review-agent.yml", "ref": os.environ.get("GITHUB_REF"),
                     "runId": int(os.environ.get("GITHUB_RUN_ID", "0")), "runAttempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")),
                     "codeSha": os.environ.get("GITHUB_SHA")},
        "upstream": upstream,
        "verdict": verdict["verdict"], "findingsDigest": findings_digest, "diffDigest": diff_digest,
        "checkRunId": None, "reviewerAppId": reviewer_app, "authorAppId": author_app,
        "authorLogin": pr["user"]["login"], "prKind": binding["kind"],
        "changedControlPaths": sorted(p for p in files if is_control_path(p)),
        "findings": verdict["findings"],
        "agentClaims": {**verdict.get("agent", {}), "summary": verdict["summary"][:1000],
                        "model": os.environ.get("SOX_REVIEW_MODEL") or "default"},
    }
    # Story PRs bind to their story key (the LOOP-R counter subject). Release PRs bind to the release
    # slug only, so a release-level verdict never counts as a round against each of its stories.
    bindings = [("commit", head), ("pr", number), tuple(binding["loopKey"])]
    with open(f"{out}/subjects.txt", "w") as f:
        f.write(subject_lines(bindings))
    dump_json(f"{out}/predicate.json", predicate)
    plan.update(action="attest", attest=True, conclusion="success" if verdict["verdict"] == "pass" else "failure", round=round_no)
    if binding["story"]:
        dump_json(f"{out}/jira-ops.json", [{"op": "comment", "key": binding["story"],
                                            "body": f"Review Agent round {round_no} on PR #{number} @ {head[:12]}: {verdict['verdict']}. {verdict['summary'][:500]}"}])
    lines = [f"- **{f['severity']}** `{f['path']}`{':' + str(f['line']) if f['line'] else ''}: {f['title']}\n  {f['body']}" for f in verdict["findings"]]
    note = f"\n\n{forgeries} attestation(s) for {':'.join(binding['loopKey'])} failed signer verification (forgery-attempt) and were not counted." if forgeries else ""
    finish(f"Review: {verdict['verdict']} (round {round_no}/{MAX_ROUNDS})", verdict["summary"] or verdict["verdict"],
           ("\n".join(lines) or "No findings.") + note)


def check_start(args):
    """Open the in_progress check run just before attest and bind its id into the predicate."""
    plan = load_json(f"{args.out}/plan.json")
    if plan["action"] != "attest":
        return
    gh = GitHub(os.environ["APP_TOKEN"])
    ext = f"run-{os.environ.get('GITHUB_RUN_ID', 'local')}-{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}-pr-{plan['pr']}"
    plan["checkRunId"] = checks.start(gh, CHECK_NAME, plan["headSha"], ext)
    dump_json(f"{args.out}/plan.json", plan)
    p = load_json(f"{args.out}/predicate.json")
    p["checkRunId"] = plan["checkRunId"]
    dump_json(f"{args.out}/predicate.json", p)


def check_finish(args):
    """Complete or post the check run. Success only if the verdict is pass AND its attestation exists."""
    plan = load_json(f"{args.out}/plan.json")
    action = plan["action"]
    if action == "none":
        print(f"no check run: {plan['title']}")
        return
    if action == "attest" and not plan.get("checkRunId"):
        print("check run was never opened; nothing to complete (no verdict became evidence)")
        return
    gh = GitHub(os.environ["APP_TOKEN"])
    conclusion = plan["conclusion"]
    details = plan.get("details", "")
    if action == "attest":
        if os.environ.get("ATTEST_OUTCOME") != "success" or not os.environ.get("ATTESTATION_URL"):
            conclusion, plan["title"] = "failure", "Attestation failed"
            details = ("The review-verdict attestation was not created, so the verdict is not evidence. This head is "
                       "blocked; push a new commit to get a fresh review.\n\n" + details)
        else:
            details = f"Attestation: {os.environ['ATTESTATION_URL']}\n\n" + details
    if conclusion not in ("success", "failure"):
        conclusion = "failure"
    checks.complete(gh, CHECK_NAME, plan["headSha"], conclusion, plan["title"], plan["summary"], details,
                    run_id=plan.get("checkRunId"), external_id=f"pr-{plan['pr']}")
    if action == "attest" and os.environ.get("ATTESTATION_URL") and conclusion == plan["conclusion"]:
        # Advisory PR comment for the author agent; the check run and attestation are the record.
        try:
            gh.request("POST", f"/repos/{REPO}/pulls/{plan['pr']}/reviews",
                       {"commit_id": plan["headSha"], "event": "COMMENT",
                        "body": f"**{plan['title']}**\n\n{plan['summary']}\n\n{details[:50000]}"})
        except RuntimeError as e:
            print(f"warning: could not post review comment: {e}")
    print(f"{CHECK_NAME} -> {conclusion} ({action})")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("resolve")
    p = sub.add_parser("prepare"); p.add_argument("--pr", required=True); p.add_argument("--out", required=True)
    q = sub.add_parser("parse"); q.add_argument("--dir", required=True)
    r = sub.add_parser("record"); r.add_argument("--dir", required=True); r.add_argument("--out", required=True)
    s = sub.add_parser("check-start"); s.add_argument("--out", required=True)
    t = sub.add_parser("check-finish"); t.add_argument("--out", required=True)
    args = ap.parse_args()
    {"resolve": resolve, "prepare": prepare, "parse": parse, "record": record, "check-start": check_start,
     "check-finish": check_finish}[args.cmd](args)


if __name__ == "__main__":
    main()
