"""Review Agent (SDLC-06): sweep | open -> [droid exec, read-only] -> parse -> record -> finish.

Binding order (gate F13, red team F17): the key-holding `open` job creates the in_progress
`sox/review-agent` check run for the head BEFORE any model runs. From then on the head is judged:
anything other than an attested pass (cancel, timeout, model error, invalid verdict, attest failure)
leaves that run failed or unfinished, and the gate blocks the head. Recovery is a new commit.

The verdict never appears in logs or in repo-readable artifacts before it is attested: `parse` hands
it to `record` as a job output only, and the check run text and PR comment are written by `finish`
after the attestation exists.

The LLM job (`parse`) holds FACTORY_API_KEY and a read-only GITHUB_TOKEN, never an App key. `open`
and `record` hold the Review App token and re-derive everything they sign from the GitHub API.
No job checks out or executes PR code: the diff is fetched as data.
"""
import argparse
import base64
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (REPO, GitHub, digest_of, dump_json, is_control_path, load_json, now_utc,  # noqa: E402
                    positive_int, pr_binding, set_output, sha256_hex, subject_lines)
import checks  # noqa: E402
import rounds  # noqa: E402

CHECK_NAME = "sox/review-agent"
WORKFLOW = "sox-review-agent.yml"
MAX_ROUNDS = int(os.environ.get("SOX_MAX_REVIEW_ROUNDS", "10"))
MAX_DIFF_BYTES = 400_000
SWEEP_LIMIT = 5
NO_VERDICT = "Review Agent produced no valid verdict"
# Check run external_id: the workflow run ID, so the gate can pair a check run with the attestation
# signed in the same run (spec v2.5, F16).
def run_id():
    return os.environ.get("GITHUB_RUN_ID", "local")


def sweep(args):
    """Schedule: dispatch one review run per open PR whose head has no completed Review App run."""
    gh = GitHub()
    sent = []
    for pr in gh.paginate(f"/repos/{REPO}/pulls?state=open&sort=updated&direction=desc", limit=100):
        if pr["draft"]:
            continue
        runs = gh.get(f"/repos/{REPO}/commits/{pr['head']['sha']}/check-runs?check_name={CHECK_NAME}&filter=all")["check_runs"]
        if any((r.get("app") or {}).get("slug") == "acme-review-agent" for r in runs):
            continue  # judged, being judged, or blocked: a new run cannot change that head
        gh.request("POST", f"/repos/{REPO}/actions/workflows/{WORKFLOW}/dispatches",
                   {"ref": "main", "inputs": {"pr": str(pr["number"])}})
        sent.append(pr["number"])
        if len(sent) >= SWEEP_LIMIT:
            break
    print(f"dispatched reviews for PRs {sent}")


def _jira_context(binding):
    """Story/plan context and Jira keys for the PR, read from Jira (never from the PR)."""
    keys, text = [], []
    try:
        import jira_cli
        j = jira_cli.load()
    except (Exception, SystemExit) as e:  # Jira unavailable: review continues; the gate enforces the Jira chain.
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


def _app_id_for_login(gh, user):
    if user.get("type") != "Bot" or not user["login"].endswith("[bot]"):
        return None
    try:
        return GitHub("").get(f"/apps/{user['login'][:-5]}")["id"]
    except RuntimeError:
        return None


def _escalation_ops(binding, n):
    if not binding["story"]:
        return []
    loop_key = ":".join(binding["loopKey"])
    return [{"op": "transition", "key": binding["story"], "to": "Blocked - Human Escalation"},
            {"op": "comment", "key": binding["story"],
             "body": f"Review loop exhausted: {n} verified changes_requested rounds for {loop_key}. "
                     "A human Tech Lead must re-plan (transition to Re-plan)."}]


def open_(args):
    """Decide whether this head gets judged; if so, open the binding check run before any model runs."""
    gh = GitHub()
    app = GitHub(os.environ["APP_TOKEN"])
    reviewer_app = int(os.environ["REVIEWER_APP_ID"])
    number = positive_int(args.pr, "pr")
    out = args.out
    os.makedirs(out, exist_ok=True)
    dump_json(f"{out}/jira-ops.json", [])
    pr, diff, files = _snapshot(gh, number)
    binding = pr_binding(pr)
    head = pr["head"]["sha"]
    diff_digest = "sha256:" + sha256_hex(diff)

    def done(msg):
        set_output("mode", "done")
        print(f"no judging: {msg}")

    def post(conclusion, title, summary, text=""):
        checks.complete(app, CHECK_NAME, head, conclusion, title, summary, text, external_id=run_id())

    if pr["state"] != "open":
        return done("PR is not open")
    runs = checks.app_runs(gh, head, CHECK_NAME, reviewer_app)
    existing = rounds.verdict_for_head(head, binding["baseRef"])
    if existing:
        p = existing.predicate
        conclusion = "success" if p.get("outcome") == "pass" else "failure"
        cid = p.get("checkRunId")
        mine = [r for r in runs if r["id"] == cid]
        title = f"Review: {p.get('outcome')} (round {p.get('round')}, existing verified verdict)"
        summary = ("A verified review-verdict already exists for this head SHA and base. It is re-posted, not re-run; "
                   "a failing verdict for a head can never be replaced by a later pass.")
        text = f"Attestation {existing.digest}, run {existing.identity.get('runInvocationURI')}"
        if mine and mine[0]["status"] != "completed":
            checks.complete(app, CHECK_NAME, head, conclusion, title, summary, text, run_id=cid)
            return done("completed the stale run of an attested verdict")
        if not any(r["status"] == "completed" and r.get("conclusion") == conclusion for r in runs):
            post(conclusion, title, summary, text)
        return done("verdict already attested for this head")
    state = checks.head_state(runs)
    if state != "none":
        return done(f"a {CHECK_NAME} run on {head[:12]} is {state}; this head is already being or has been judged")

    prior, _ = rounds.failing_heads(tuple(binding["loopKey"]))
    prior -= {head}
    if len(prior) >= MAX_ROUNDS:
        loop_key = ":".join(binding["loopKey"])
        dump_json(f"{out}/jira-ops.json", _escalation_ops(binding, len(prior)))
        post("failure", "loop-exhausted",
             f"{len(prior)} verified changes_requested rounds for {loop_key} (max {MAX_ROUNDS}). "
             "Escalated to a human; no further automated review.")
        return done("loop exhausted")
    author_app = _app_id_for_login(gh, pr["user"])
    if author_app is not None and author_app == reviewer_app:
        post("failure", "Segregation of duties", "The Review App authored this PR; it cannot review it.")
        return done("segregation of duties")

    jira_keys, jira_text = _jira_context(binding)
    cid = checks.start(app, CHECK_NAME, head, run_id())
    mode = "too-large" if len(diff) > MAX_DIFF_BYTES else "llm"
    ctx = {"pr": number, "headSha": head, "baseSha": pr["base"]["sha"], "baseRef": binding["baseRef"],
           "diffDigest": diff_digest, "binding": binding, "jiraKeys": jira_keys, "mode": mode, "checkRunId": cid,
           "authorAppId": author_app, "files": files}
    dump_json(f"{out}/context.json", ctx)
    with open(f"{out}/pr.diff", "wb") as f:
        f.write(diff)
    control = [p for p in files if is_control_path(p)]
    with open(f"{out}/context.md", "w") as f:
        f.write(f"# PR #{number}: {pr['title']}\n\nBranch: {binding['headRef']} -> {binding['baseRef']} ({binding['kind']} PR)\n"
                f"Author: {pr['user']['login']}\nHead: {head}\nFiles changed: {len(files)}\n"
                f"Control-path files: {control or 'none'}\n\n# Jira\n{jira_text}\n\n# PR description\n{(pr.get('body') or '')[:5000]}\n")
    set_output("mode", mode)
    set_output("check_run_id", str(cid))
    set_output("head", head)
    set_output("diff_digest", diff_digest)
    set_output("context_digest", "sha256:" + sha256_hex(open(f"{out}/context.json", "rb").read()))
    print(f"opened {CHECK_NAME} run {cid} on {head[:12]} (mode {mode})")


def _verdict_from_droid(raw):
    text = raw.get("result") or ""
    m = re.search(r"\{.*\}", text, re.S)
    body = json.loads(m.group(0)) if m else None
    if raw.get("is_error") or not isinstance(body, dict):
        raise ValueError("no JSON verdict in droid output")
    v = body.get("verdict")
    if v not in ("pass", "changes_requested"):
        raise ValueError(f"bad verdict {str(v)[:40]!r}")
    findings = [f for f in body.get("findings") or [] if isinstance(f, dict)][:50]
    if any(f.get("severity") == "blocking" for f in findings):
        v = "changes_requested"
    return {"verdict": v, "summary": str(body.get("summary") or "")[:1000], "findings": [
        {"severity": f.get("severity") if f.get("severity") in ("blocking", "minor") else "minor",
         "path": str(f.get("path"))[:300] if f.get("path") else None,
         "line": f.get("line") if isinstance(f.get("line"), int) else None,
         "title": str(f.get("title") or "")[:200], "body": str(f.get("body") or "")[:4000]} for f in findings]}


def no_verdict(reason):
    return {"verdict": "changes_requested", "summary": f"{NO_VERDICT}: {reason}"[:1000], "valid": False,
            "findings": [{"severity": "blocking", "path": None, "line": None, "title": NO_VERDICT,
                          "body": "An invalid, missing or unparseable review counts as changes requested. "
                                  "Push a new commit to get a fresh review."}]}


def parse(args):
    """droid's JSON output -> job output `verdict` (base64 JSON). Nothing about the verdict is printed.
    Anything malformed becomes changes_requested, never a free retry."""
    agent = {}
    try:
        raw = load_json(f"{args.dir}/droid.json")
        agent = {"factorySessionId": raw.get("session_id"), "isError": raw.get("is_error"), "numTurns": raw.get("num_turns")}
        verdict = _verdict_from_droid(raw)
        verdict["valid"] = True
    except Exception as e:
        verdict = no_verdict(f"{type(e).__name__}")
    verdict["agent"] = agent
    verdict["contextDigest"] = os.environ.get("CONTEXT_DIGEST")
    enc = base64.b64encode(json.dumps(verdict, sort_keys=True).encode()).decode()
    set_output("verdict", enc)
    print("verdict handed to the record job (not shown until attested)")


def _decode_verdict(mode, ctx_digest):
    if mode == "too-large":
        return {"verdict": "changes_requested", "valid": True, "agent": {},
                "summary": f"Diff exceeds {MAX_DIFF_BYTES} bytes; split the change.",
                "findings": [{"severity": "blocking", "path": None, "line": None, "title": "Diff too large",
                              "body": "Split the story into smaller PRs."}]}
    if os.environ.get("REVIEW_RESULT") != "success":
        return no_verdict(f"LLM job {os.environ.get('REVIEW_RESULT') or 'missing'}")
    try:
        v = json.loads(base64.b64decode(os.environ.get("VERDICT_B64") or "", validate=True))
    except Exception:
        return no_verdict("verdict output missing or not decodable")
    if not isinstance(v, dict) or v.get("verdict") not in ("pass", "changes_requested"):
        return no_verdict("verdict output malformed")
    if v.get("contextDigest") != ctx_digest:
        return no_verdict("verdict was produced for a different review context")
    if not v.get("valid"):
        v["verdict"] = "changes_requested"
    return v


def record(args):
    """Bind the verdict for the head the open job judged. Writes plan/predicate/subjects; never posts."""
    gh = GitHub()
    reviewer_app = int(os.environ["REVIEWER_APP_ID"])
    ctx = load_json(f"{args.ctx}/context.json")
    ctx_digest = "sha256:" + sha256_hex(open(f"{args.ctx}/context.json", "rb").read())
    if ctx_digest != os.environ.get("OPEN_CONTEXT_DIGEST"):
        raise SystemExit("review context artifact does not match the open job's digest")
    number, head, cid = ctx["pr"], ctx["headSha"], ctx["checkRunId"]
    out = args.out
    os.makedirs(out, exist_ok=True)
    dump_json(f"{out}/jira-ops.json", [])
    plan = {"pr": number, "headSha": head, "checkRunId": cid, "conclusion": "failure", "attest": False}

    def finish(title, summary, details=""):
        plan.update(title=title, summary=summary, details=details)
        dump_json(f"{out}/plan.json", plan)
        set_output("attest", "true" if plan["attest"] else "false")
        print(f"record: attest={plan['attest']}")

    run = gh.get(f"/repos/{REPO}/check-runs/{cid}")
    if (run.get("app") or {}).get("id") != reviewer_app or run["head_sha"] != head or run["name"] != CHECK_NAME:
        raise SystemExit("check run does not belong to this review")
    if run["status"] == "completed":
        plan["closed"] = True
        return finish("already completed", "The check run of this review is already completed; nothing to change.")

    existing = rounds.verdict_for_head(head, ctx["baseRef"])
    if existing:
        # A re-run of this workflow: the head already has its verdict. Never sign a second one.
        p = existing.predicate
        plan["conclusion"] = "success" if p.get("outcome") == "pass" else "failure"
        return finish(f"Review: {p.get('outcome')} (existing verified verdict)",
                      "A verified review-verdict already exists for this head; it is not re-judged.",
                      f"Attestation {existing.digest}")

    pr = gh.pr(number)
    if pr["head"]["sha"] != head:
        return finish("Superseded", "The PR head moved during review. This head is not reviewed further; "
                      "the new head gets its own review.")

    verdict = _decode_verdict(ctx["mode"], ctx_digest)
    binding = ctx["binding"]
    prior, forgeries = rounds.failing_heads(tuple(binding["loopKey"]))
    prior -= {head}
    round_no = len(prior) + 1
    diff_digest = ctx["diffDigest"]
    inputs = [{"name": "pr-diff", "digest": {"sha256": diff_digest.split(":", 1)[1]}}]
    plan_digest = rounds.latest_plan_digest(ctx["jiraKeys"])
    upstream = []
    if plan_digest:
        inputs.append({"name": "techlead-plan", "digest": {"sha256": plan_digest.split(":", 1)[1]}})
        upstream.append(plan_digest)
    predicate = {
        "schema": "sox/common/v1", "repo": REPO, "prNumber": number, "headSha": head,
        "baseSha": ctx["baseSha"], "baseRef": ctx["baseRef"], "jiraKeys": ctx["jiraKeys"],
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
        "verdict": verdict["verdict"], "verdictValid": bool(verdict.get("valid")),
        "findingsDigest": digest_of(verdict["findings"]), "diffDigest": diff_digest,
        "checkRunId": cid, "reviewerAppId": reviewer_app, "authorAppId": ctx.get("authorAppId"),
        "authorLogin": pr["user"]["login"], "prKind": binding["kind"],
        "changedControlPaths": sorted(p for p in ctx.get("files", []) if is_control_path(p)),
        "findings": verdict["findings"],
        "agentClaims": {**(verdict.get("agent") or {}), "summary": verdict["summary"][:1000],
                        "model": os.environ.get("SOX_REVIEW_MODEL") or "default"},
    }
    # Story PRs bind to their story key (the LOOP-R counter subject). Release PRs bind to the release
    # slug only, so a release-level verdict never counts as a round against each of its stories.
    with open(f"{out}/subjects.txt", "w") as f:
        f.write(subject_lines([("commit", head), ("pr", number), tuple(binding["loopKey"])]))
    dump_json(f"{out}/predicate.json", predicate)
    plan.update(attest=True, conclusion="success" if verdict["verdict"] == "pass" else "failure", round=round_no)
    if binding["story"]:
        dump_json(f"{out}/jira-ops.json", [{"op": "comment", "key": binding["story"],
                                            "body": f"Review Agent round {round_no} on PR #{number} @ {head[:12]}: "
                                                    f"{verdict['verdict']}. {verdict['summary'][:500]}"}])
        if verdict["verdict"] != "pass" and round_no >= MAX_ROUNDS:
            dump_json(f"{out}/jira-ops.json", load_json(f"{out}/jira-ops.json") + _escalation_ops(binding, round_no))
    lines = [f"- **{f['severity']}** `{f['path']}`{':' + str(f['line']) if f['line'] else ''}: {f['title']}\n  {f['body']}"
             for f in verdict["findings"]]
    note = (f"\n\n{forgeries} attestation(s) for {':'.join(binding['loopKey'])} failed signer verification "
            "(forgery-attempt) and were not counted.") if forgeries else ""
    finish(f"Review: {verdict['verdict']} (round {round_no}/{MAX_ROUNDS})", verdict["summary"] or verdict["verdict"],
           ("\n".join(lines) or "No findings.") + note)


def finish(args):
    """Complete the run opened by `open`. Success only if the verdict is pass AND its attestation exists.
    Runs even when earlier jobs failed or were cancelled; without a plan the run completes as failure."""
    gh = GitHub(os.environ["APP_TOKEN"])
    cid = positive_int(os.environ["CHECK_RUN_ID"], "check run id")
    plan = load_json(f"{args.out}/plan.json", default={}) or {}
    if plan.get("closed"):
        print("check run already completed")
        return
    run = gh.get(f"/repos/{REPO}/check-runs/{cid}")
    if run["status"] == "completed":
        print("check run already completed")
        return
    head = run["head_sha"]
    if not plan:
        plan = {"conclusion": "failure", "title": "Review did not complete",
                "summary": "The review run failed or was cancelled after this head was opened for judging. "
                           "This head is blocked; push a new commit to get a fresh review.", "details": ""}
    conclusion, details = plan["conclusion"], plan.get("details", "")
    if plan.get("attest"):
        if os.environ.get("ATTEST_OUTCOME") != "success" or not os.environ.get("ATTESTATION_URL"):
            conclusion, plan["title"] = "failure", "Attestation failed"
            plan["summary"] = "The review-verdict attestation was not created, so the verdict is not evidence."
            details = "This head is blocked; push a new commit to get a fresh review."
        else:
            details = f"Attestation: {os.environ['ATTESTATION_URL']}\n\n" + details
    if conclusion not in ("success", "failure"):
        conclusion = "failure"
    checks.complete(gh, CHECK_NAME, head, conclusion, plan["title"], plan["summary"], details, run_id=cid)
    if plan.get("attest") and os.environ.get("ATTESTATION_URL") and conclusion == plan["conclusion"]:
        # Advisory PR comment for the author agent; the check run and attestation are the record.
        try:
            gh.request("POST", f"/repos/{REPO}/pulls/{plan['pr']}/reviews",
                       {"commit_id": head, "event": "COMMENT",
                        "body": f"**{plan['title']}**\n\n{plan['summary']}\n\n{details[:50000]}"})
        except RuntimeError as e:
            print(f"warning: could not post review comment: {e}")
    print(f"{CHECK_NAME} -> {conclusion}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sweep")
    o = sub.add_parser("open"); o.add_argument("--pr", required=True); o.add_argument("--out", required=True)
    q = sub.add_parser("parse"); q.add_argument("--dir", required=True)
    r = sub.add_parser("record"); r.add_argument("--ctx", required=True); r.add_argument("--out", required=True)
    f = sub.add_parser("finish"); f.add_argument("--out", required=True)
    args = ap.parse_args()
    {"sweep": sweep, "open": open_, "parse": parse, "record": record, "finish": finish}[args.cmd](args)


if __name__ == "__main__":
    main()
