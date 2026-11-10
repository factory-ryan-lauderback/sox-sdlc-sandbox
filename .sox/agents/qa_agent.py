"""QA Agent (SDLC-08): select -> open -> [tests against the deployed images, no App key] -> record -> finish.

  qa_agent.py select --out DIR [--pr N]        (read-only token: one release PR with a passing env-deploy)
  qa_agent.py open   --ctx DIR                 (env agent-qa: opens sox/qa-agent before any test runs)
  qa_agent.py runtests --ids FILE --out FILE   (test job, cwd = the release head checkout)
  qa_agent.py record --ctx DIR --out DIR       (env agent-qa: re-derives everything it signs)
  qa_agent.py finish --out DIR                 (env agent-qa: completes the check run after the attestation)

Binding order (gate F13/F16, same as the Review Agent): `open` creates the in_progress `sox/qa-agent`
check run (external_id = this run's ID) before the environment comes up. Only an attested qa-result
with outcome pass completes it as success; a failed or cancelled test job, an attest failure or a head
that moved leaves it failed, and the gate blocks that head. Recovery is a new head on the release
branch (a qa-fix PR merged by the bundler), which then needs its own review, QA and approval.

The tests run in a job with no App key and no id-token: it checks out the release head and runs the
plan's required tests (unit tests and `test_e2e_*` against the environment re-created from the
verified env-deploy images). The results reach `record` only as a job output. LOOP-Q: rounds are the
distinct heads with a verified failing qa-result on pr:<n> and release:<slug>; at 10 the release is
escalated to a human and no further QA runs.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (REPO, GitHub, digest_of, dump_json, load_json, now_utc, positive_int,  # noqa: E402
                    set_output, sha256_hex, subject_lines)
import checks  # noqa: E402
import rounds  # noqa: E402
from planning_agent import dir_digest  # noqa: E402

CHECK_NAME = "sox/qa-agent"
MAX_ROUNDS = int(os.environ.get("SOX_MAX_QA_ROUNDS", "10"))
RELEASE_BRANCH = re.compile(r"^release/([a-z0-9][a-z0-9-]{0,60})$")
TEST_ID = re.compile(r"^services\.[a-z0-9_]+(\.[A-Za-z_][A-Za-z0-9_]*){1,4}$")
PASSED = "passed"
MAX_TESTS = 300


def run_id():
    return os.environ.get("GITHUB_RUN_ID", "local")


def _att_digest_ok(d):
    return isinstance(d, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", d)


# ---------------------------------------------------------------------------------- shared derivation

def release_prs(gh):
    owner = REPO.split("/")[0]
    out = []
    for pr in gh.paginate(f"/repos/{REPO}/pulls?state=open&base=main&sort=created&direction=asc", limit=100):
        m = RELEASE_BRANCH.match(pr["head"]["ref"])
        if m and (pr["head"].get("repo") or {}).get("full_name") == REPO and pr["head"]["repo"]["owner"]["login"] == owner:
            out.append(pr)
    return out


def env_for_head(pr, fetch=None):
    """The latest verified env-deploy of this PR head to qa, if it passed. The gate binds the qa-result
    to the latest one, so an older passing deploy behind a newer failing one is not usable."""
    verified, _ = (fetch or rounds.fetch)("commit", pr["head"]["sha"], "env-deploy")
    mine = [a for a in verified if a.predicate.get("headSha") == pr["head"]["sha"] and a.predicate.get("environment") == "qa"]
    if not mine:
        return None
    latest = max(mine, key=lambda a: (a.integrated_time, a.digest))
    ok = latest.predicate.get("outcome") == "pass" and latest.predicate.get("prNumber") == pr["number"]
    return latest if ok else None


def required_tests(slug, fetch=None):
    """The plan-required tests for a release: release-manifest stories -> their Epics' latest verified
    techlead-plan -> every story's requiredTests (the gate's refresh_plans rule)."""
    fetch = fetch or rounds.fetch
    mans, _ = fetch("release", slug, "release-manifest")
    mans = [a for a in mans if a.predicate.get("release") == slug]
    if not mans:
        return None, [], {}
    man = max(mans, key=lambda a: (a.integrated_time, a.digest))
    stories = sorted({(s.get("key") if isinstance(s, dict) else s) for s in man.predicate.get("stories") or []} - {None})
    epics = {}
    for key in stories:
        plans, _ = fetch("jira", key, "techlead-plan")
        plans = [a for a in plans if any(s.get("key") == key for s in a.predicate.get("stories", []))]
        if plans:
            epics.setdefault(max(plans, key=lambda a: (a.integrated_time, a.digest)).predicate.get("epicKey"), None)
    tests, plan_digests = set(), {}
    for epic in sorted(e for e in epics if e):
        plans, _ = fetch("jira", epic, "techlead-plan")
        plans = [a for a in plans if a.predicate.get("epicKey") == epic]
        if not plans:
            continue
        latest = max(plans, key=lambda a: (a.integrated_time, a.digest))
        plan_digests[epic] = latest.digest
        tests |= {t for s in latest.predicate.get("stories", []) for t in s.get("requiredTests", [])}
    return man, sorted(tests), {"stories": stories, "plans": plan_digests}


def env_spec(env):
    p = env.predicate
    return {"schema": "sox/env-spec/v1", "envId": p["envId"], "headSha": p["headSha"], "prNumber": p["prNumber"],
            "images": [{"service": i["service"], "digest": i["digest"],
                        "ref": f"ghcr.io/{REPO}/{i['service']}@{i['digest']}"} for i in p.get("images", [])]}


def failing_heads(number, slug):
    heads = set()
    for key in (("pr", str(number)), ("release", slug)):
        h, _ = rounds.failing_heads(key, predicate="qa-result")
        heads |= h
    return heads


# --------------------------------------------------------------------------------------------- select

def select(args):
    gh = GitHub()
    qa_slug = os.environ.get("QA_APP_SLUG", "acme-qa-agent")
    want = positive_int(args.pr, "pr") if args.pr else None
    for pr in release_prs(gh):
        n, head = pr["number"], pr["head"]["sha"]
        if want and n != want:
            continue
        slug = RELEASE_BRANCH.match(pr["head"]["ref"]).group(1)
        if pr.get("draft"):
            print(f"PR #{n}: draft (the bundler marks it ready once every story is merged)"); continue
        runs = gh.get(f"/repos/{REPO}/commits/{head}/check-runs?check_name={CHECK_NAME}&filter=all&per_page=100")["check_runs"]
        if any((r.get("app") or {}).get("slug") == qa_slug for r in runs) and not want:
            print(f"PR #{n}: head {head[:12]} already has a {CHECK_NAME} run"); continue
        env = env_for_head(pr)
        if env is None:
            print(f"PR #{n}: no verified passing env-deploy for {head[:12]} yet"); continue
        man, tests, chain = required_tests(slug)
        if man is None or not tests:
            print(f"PR #{n}: no verified release-manifest or no plan-required tests for {slug}"); continue
        os.makedirs(args.out, exist_ok=True)
        dump_json(f"{args.out}/env-spec.json", env_spec(env))
        dump_json(f"{args.out}/required-tests.json", tests)
        dump_json(f"{args.out}/context.json", {"pr": n, "headSha": head, "baseSha": pr["base"]["sha"], "release": slug,
                                               "envDeploy": env.digest, "manifest": man.digest, "requiredTests": tests,
                                               **chain})
        set_output("pr", str(n)); set_output("head", head)
        set_output("context_digest", dir_digest(args.out))
        print(f"qa: PR #{n} release {slug} head {head[:12]}, {len(tests)} required tests, env {env.digest[:19]}")
        return
    set_output("pr", "")
    print("qa: nothing to test")


# ----------------------------------------------------------------------------------------------- open

def _ctx(path):
    if dir_digest(path) != os.environ.get("CONTEXT_DIGEST"):
        raise SystemExit("context artifact does not match the select job's digest")
    return load_json(f"{path}/context.json")


def _escalation_ops(stories, slug, n):
    return [op for k in stories for op in (
        {"op": "comment", "key": k, "body": f"QA loop exhausted for release {slug}: {n} heads with a verified failing "
                                            "qa-result. A human must decide (re-plan or drop the release)."},)] + \
           [{"op": "transition", "key": k, "to": "Blocked - Human Escalation"} for k in stories[:1]]


def open_(args):
    gh, app = GitHub(), GitHub(os.environ["APP_TOKEN"])
    qa_app = int(os.environ["QA_APP_ID"])
    ctx = _ctx(args.ctx)
    os.makedirs(args.out, exist_ok=True)
    dump_json(f"{args.out}/jira-ops.json", [])
    n, head, slug = ctx["pr"], ctx["headSha"], ctx["release"]
    pr = gh.pr(n)

    def done(msg):
        set_output("mode", "done"); print(f"no QA: {msg}")

    def post(conclusion, title, summary, text=""):
        checks.complete(app, CHECK_NAME, head, conclusion, title, summary, text, external_id=run_id())

    if pr["state"] != "open" or pr["head"]["sha"] != head:
        return done("PR closed or head moved since select")
    runs = checks.app_runs(gh, head, CHECK_NAME, qa_app)
    existing = rounds.verdict_for_head(head, "refs/heads/main", predicate="qa-result")
    if existing:
        p = existing.predicate
        conclusion = "success" if p.get("outcome") == "pass" else "failure"
        mine = [r for r in runs if r["id"] == p.get("checkRunId")]
        title = f"QA: {p.get('outcome')} (existing verified qa-result)"
        text = f"Attestation {existing.digest}"
        if mine and mine[0]["status"] != "completed":
            checks.complete(app, CHECK_NAME, head, conclusion, title, "A verified qa-result exists for this head.", text,
                            run_id=p.get("checkRunId"))
        elif not any(r["status"] == "completed" and r.get("conclusion") == conclusion for r in runs):
            post(conclusion, title, "A verified qa-result exists for this head; it is re-posted, not re-run.", text)
        return done("qa-result already attested for this head")
    state = checks.head_state(runs)
    if state != "none":
        return done(f"a {CHECK_NAME} run on {head[:12]} is {state}")
    prior = failing_heads(n, slug) - {head}
    if len(prior) >= MAX_ROUNDS:
        dump_json(f"{args.out}/jira-ops.json", _escalation_ops(ctx.get("stories") or [], slug, len(prior)))
        post("failure", "loop-exhausted", f"{len(prior)} heads with a verified failing qa-result for release {slug} "
             f"(max {MAX_ROUNDS}). Escalated to a human; no further automated QA.")
        return done("loop exhausted")
    cid = checks.start(app, CHECK_NAME, head, run_id())
    set_output("mode", "test")
    set_output("check_run_id", str(cid))
    print(f"opened {CHECK_NAME} run {cid} on {head[:12]}")


# ------------------------------------------------------------------------------------------ runtests

def _flatten(suite):
    import unittest
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from _flatten(t)
        else:
            yield t


def runtests(args):
    """Run each required test by unittest ID in this process (cwd = release head checkout) and write
    {id: status}. A test that cannot be loaded is `missing`; a skip is not a pass."""
    import unittest
    sys.path.insert(0, os.getcwd())
    ids = load_json(args.ids)
    results = []

    class Rec(unittest.TestResult):
        def __init__(self):
            super().__init__()
            self.status = {}

        def addSuccess(self, t): self.status[t.id()] = PASSED
        def addFailure(self, t, e): self.status[t.id()] = "failed"
        def addError(self, t, e): self.status[t.id()] = "error"
        def addSkip(self, t, r): self.status[t.id()] = "skipped"
        def addExpectedFailure(self, t, e): self.status[t.id()] = "failed"
        def addUnexpectedSuccess(self, t): self.status[t.id()] = "failed"

    for tid in ids[:MAX_TESTS]:
        if not TEST_ID.match(tid):
            results.append({"id": tid, "status": "invalid-id"}); continue
        try:
            suite = unittest.defaultTestLoader.loadTestsFromName(tid)
        except Exception:
            results.append({"id": tid, "status": "missing"}); continue
        # The loader returns a placeholder _FailedTest (another ID) instead of raising for a name that
        # does not resolve, so an ID counts as present only if the suite holds exactly that test.
        if [t.id() for t in _flatten(suite)] != [tid]:
            results.append({"id": tid, "status": "missing"}); continue
        rec = Rec()
        try:
            suite.run(rec)
        except Exception:
            rec.status[tid] = "error"
        found = rec.status.get(tid)
        if found is None:
            found = "missing" if not rec.status else ("error" if rec.errors else "failed")
        results.append({"id": tid, "status": found})
    dump_json(args.out, results)
    print(f"ran {len(results)} required test(s)")


def encode_results(path):
    raw = json.dumps(load_json(path), sort_keys=True).encode()
    return base64.b64encode(gzip.compress(raw, mtime=0)).decode()


def decode_results(b64):
    return json.loads(gzip.decompress(base64.b64decode(b64, validate=True)))


# --------------------------------------------------------------------------------------------- record

def qa_test_files(gh, slug):
    """Test files changed by QA-authored work merged into the release: qa-fix PRs, and story PRs the QA App opened."""
    files = set()
    for pr in gh.paginate(f"/repos/{REPO}/pulls?state=closed&base=release/{slug}", limit=200):
        if not pr.get("merged_at"):
            continue
        if pr["head"]["ref"].startswith("qa-fix/") or (pr.get("user") or {}).get("login") == "acme-qa-agent[bot]":
            for f in gh.pr_files(pr["number"]):
                name = f["filename"]
                if re.search(r"(^|/)test_[^/]*\.py$", name):
                    files.add(name)
    return sorted(files)


def record(args):
    gh = GitHub()
    qa_app = int(os.environ["QA_APP_ID"])
    ctx = _ctx(args.ctx)
    os.makedirs(args.out, exist_ok=True)
    dump_json(f"{args.out}/jira-ops.json", [])
    n, head, slug, cid = ctx["pr"], ctx["headSha"], ctx["release"], positive_int(os.environ["CHECK_RUN_ID"], "check run")
    plan = {"pr": n, "headSha": head, "checkRunId": cid, "conclusion": "failure", "attest": False}

    def finish_plan(title, summary, details=""):
        plan.update(title=title, summary=summary, details=details)
        dump_json(f"{args.out}/plan.json", plan)
        set_output("attest", "true" if plan["attest"] else "false")
        print(f"record: attest={plan['attest']}")

    run = gh.get(f"/repos/{REPO}/check-runs/{cid}")
    if (run.get("app") or {}).get("id") != qa_app or run["head_sha"] != head or run["name"] != CHECK_NAME:
        raise SystemExit("check run does not belong to this QA run")
    if run["status"] == "completed":
        plan["closed"] = True
        return finish_plan("already completed", "The check run is already completed.")
    existing = rounds.verdict_for_head(head, "refs/heads/main", predicate="qa-result")
    if existing:
        plan["conclusion"] = "success" if existing.predicate.get("outcome") == "pass" else "failure"
        return finish_plan(f"QA: {existing.predicate.get('outcome')} (existing verified qa-result)",
                           "A verified qa-result already exists for this head; it is not re-tested.", existing.digest)
    pr = gh.pr(n)
    if pr["head"]["sha"] != head:
        return finish_plan("Superseded", "The release head moved during QA; the new head gets its own QA run.")
    # Re-derive what is signed; the context is only a lookup.
    env = env_for_head(pr)
    man, required, chain = required_tests(slug)
    if env is None or env.digest != ctx["envDeploy"] or man is None or required != ctx["requiredTests"]:
        return finish_plan("QA inputs changed", "The env-deploy, release-manifest or plan changed during QA; "
                           "this head is blocked. A new head gets a fresh QA run.")
    if os.environ.get("TEST_RESULT") != "success":
        return finish_plan("QA did not complete", f"The test job ended {os.environ.get('TEST_RESULT') or 'missing'} "
                           "after this head was opened for QA (environment or runner failure). No qa-result is signed; "
                           "the head is blocked until a new head is tested.")
    try:
        results = decode_results(os.environ.get("RESULTS_B64") or "")
        assert isinstance(results, list) and all(isinstance(r, dict) and isinstance(r.get("id"), str) for r in results)
    except Exception:
        return finish_plan("QA results unreadable", "The test job's results could not be decoded; no qa-result is signed.")
    by_id = {r["id"]: str(r.get("status")) for r in results}
    tests = [{"id": t, "status": by_id.get(t, "missing")} for t in required]
    passed = [t for t in tests if t["status"] == PASSED]
    outcome = "pass" if len(passed) == len(required) and required else "fail"
    report = {"schema": "sox/qa-report/v1", "pr": n, "headSha": head, "release": slug, "envDeploy": env.digest,
              "envId": env.predicate.get("envId"), "images": env.predicate.get("images"), "tests": tests,
              "runner": {"workflow": ".github/workflows/sox-qa-agent.yml", "runId": run_id(), "codeSha": os.environ.get("GITHUB_SHA")}}
    raw = json.dumps(report, sort_keys=True, indent=1).encode()
    with open(f"{args.out}/qa-report.json", "wb") as f:
        f.write(raw)
    report_digest = "sha256:" + sha256_hex(raw)
    prior = failing_heads(n, slug) - {head}
    round_no = len(prior) + 1
    stories = chain["stories"]
    inputs = [{"name": "env-deploy", "digest": {"sha256": env.digest.split(":", 1)[1]}},
              {"name": "qa-report", "digest": {"sha256": report_digest.split(":", 1)[1]}}]
    predicate = {
        "schema": "sox/common/v1", "repo": REPO, "prNumber": n, "headSha": head, "baseSha": pr["base"]["sha"],
        "baseRef": "refs/heads/main", "jiraKeys": stories, "release": slug, "step": "SDLC-08",
        "actor": {"type": "github_app", "login": f"{os.environ.get('QA_APP_SLUG', 'acme-qa-agent')}[bot]", "appId": qa_app,
                  "source": "installation token minted in this run"},
        "inputs": inputs, "inputsDigest": digest_of(inputs), "outcome": outcome, "round": round_no,
        "loopKey": f"release:{slug}", "observedAt": now_utc(),
        "attestor": {"workflow": ".github/workflows/sox-qa-agent.yml", "ref": os.environ.get("GITHUB_REF"),
                     "runId": int(os.environ.get("GITHUB_RUN_ID", "0")), "runAttempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")),
                     "codeSha": os.environ.get("GITHUB_SHA")},
        "upstream": [env.digest, man.digest] + sorted(chain["plans"].values()),
        "envDeploy": {"digest": env.digest, "headSha": head, "envId": env.predicate.get("envId")},
        "suites": sorted({".".join(t["id"].split(".")[:3]) for t in tests}),
        "tests": tests, "requiredTests": required,
        # Integer, not a ratio: canonical predicates carry no floats. 1 means every required test passed.
        "requiredCoverage": 1 if outcome == "pass" else 0, "requiredPassed": len(passed),
        "reportDigest": report_digest, "testFilesChangedByQa": qa_test_files(gh, slug), "mode": "full",
        "checkRunId": cid, "qaAppId": qa_app,
    }
    with open(f"{args.out}/subjects.txt", "w") as f:
        f.write(subject_lines([("commit", head), ("pr", n), ("release", slug)] + [("jira", k) for k in stories]
                              + [("report", report_digest)]))
    dump_json(f"{args.out}/predicate.json", predicate)
    plan.update(attest=True, conclusion="success" if outcome == "pass" else "failure", round=round_no)
    failed = [t for t in tests if t["status"] != PASSED]
    ops = [{"op": "comment", "key": k, "body": f"QA Agent round {round_no} on release PR #{n} @ {head[:12]}: {outcome} "
                                                f"({len(passed)}/{len(required)} required tests passed)."} for k in stories]
    if outcome == "fail" and round_no >= MAX_ROUNDS:
        ops += _escalation_ops(stories, slug, round_no)
    dump_json(f"{args.out}/jira-ops.json", ops)
    lines = [f"- `{t['id']}`: {t['status']}" for t in tests]
    finish_plan(f"QA: {outcome} (round {round_no}/{MAX_ROUNDS})",
                f"{len(passed)}/{len(required)} plan-required tests passed against env {env.predicate.get('envId')} "
                f"(env-deploy {env.digest[:19]}).", ("Failed or missing:\n" + "\n".join(
                    f"- `{t['id']}`: {t['status']}" for t in failed) + "\n\n" if failed else "") + "All required tests:\n" + "\n".join(lines))


def finish(args):
    gh = GitHub(os.environ["APP_TOKEN"])
    cid = positive_int(os.environ["CHECK_RUN_ID"], "check run id")
    plan = load_json(f"{args.out}/plan.json", default={}) or {}
    if plan.get("closed"):
        return print("check run already completed")
    run = gh.get(f"/repos/{REPO}/check-runs/{cid}")
    if run["status"] == "completed":
        return print("check run already completed")
    if not plan:
        plan = {"conclusion": "failure", "title": "QA did not complete",
                "summary": "The QA run failed or was cancelled after this head was opened. This head is blocked; "
                           "a new head on the release branch gets a fresh QA run.", "details": ""}
    conclusion, details = plan["conclusion"], plan.get("details", "")
    if plan.get("attest"):
        if os.environ.get("ATTEST_OUTCOME") != "success" or not os.environ.get("ATTESTATION_URL"):
            conclusion, plan["title"] = "failure", "Attestation failed"
            plan["summary"] = "The qa-result attestation was not created, so the result is not evidence."
        else:
            details = f"Attestation: {os.environ['ATTESTATION_URL']}\n\n" + details
    if conclusion not in ("success", "failure"):
        conclusion = "failure"
    checks.complete(gh, CHECK_NAME, run["head_sha"], conclusion, plan["title"], plan["summary"], details, run_id=cid)
    print(f"{CHECK_NAME} -> {conclusion}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("select"); s.add_argument("--out", required=True); s.add_argument("--pr", default="")
    o = sub.add_parser("open"); o.add_argument("--ctx", required=True); o.add_argument("--out", required=True)
    t = sub.add_parser("runtests"); t.add_argument("--ids", required=True); t.add_argument("--out", required=True)
    e = sub.add_parser("encode"); e.add_argument("--results", required=True)
    r = sub.add_parser("record"); r.add_argument("--ctx", required=True); r.add_argument("--out", required=True)
    f = sub.add_parser("finish"); f.add_argument("--out", required=True)
    args = ap.parse_args()
    if args.cmd == "encode":
        return set_output("results", encode_results(args.results))
    {"select": select, "open": open_, "runtests": runtests, "record": record, "finish": finish}[args.cmd](args)


if __name__ == "__main__":
    main()
