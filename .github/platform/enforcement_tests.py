#!/usr/bin/env python3
"""Platform enforcement tests (A-3, A-5, branch history) run as one GitHub App.

Usage: enforcement_tests.py <dev|bundler|qa> <out.json>
Token: SOX_APP_TOKEN (installation token of the role's App, minted in the role's
environment). The token is never printed. Output records only HTTP status codes and
API messages. Scratch refs: story/FRQ-0-platform-enforcement*, qa-fix/FRQ-0-platform-
enforcement*, release/platform-enforcement* (release/** refs cannot be deleted by design).
"""
import base64, json, os, sys, time, urllib.error, urllib.request

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
REPO = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["SOX_APP_TOKEN"]
RULE_VIOLATION = "Repository rule violations"
results = []


def call(method, path, body=None):
    req = urllib.request.Request(f"{API}/repos/{REPO}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Authorization", f"Bearer {TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else {}
        except ValueError:
            return e.code, {"message": raw[:200].decode(errors="replace")}


def msg(body):
    return str(body.get("message", ""))[:300] if isinstance(body, dict) else ""


def rec(test, expect, status, body, ok):
    results.append({"test": test, "expect": expect, "status": status, "message": msg(body), "pass": bool(ok)})
    print(("PASS " if ok else "FAIL ") + f"{test}: {status} {msg(body)[:120]}")


def rule_blocked(status, body):
    return status == 422 and RULE_VIOLATION in msg(body)


def main_sha():
    s, b = call("GET", "/git/ref/heads/main")
    if s != 200:
        sys.exit(f"cannot read main: {s} {msg(b)}")
    return b["object"]["sha"]


def ref_exists(ref):
    return call("GET", f"/git/ref/heads/{ref}")[0] == 200


def create_ref(ref, sha):
    return call("POST", "/git/refs", {"ref": f"refs/heads/{ref}", "sha": sha})


def put_file(branch, path, text, message):
    s, cur = call("GET", f"/contents/{path}?ref={branch}")
    body = {"message": message, "content": base64.b64encode(text.encode()).decode(), "branch": branch}
    if s == 200:
        body["sha"] = cur["sha"]
    return call("PUT", f"/contents/{path}", body)


def dev(base):
    br = "story/FRQ-0-platform-enforcement"
    if ref_exists(br):
        call("DELETE", f"/git/refs/heads/{br}")
    s, b = create_ref(br, base)
    rec("A-3 dev App creates story/** (bypass actor)", "201", s, b, s == 201)
    s, b = put_file(br, "services/db/PLATFORM_ENFORCEMENT.txt", f"run {os.environ.get('GITHUB_RUN_ID')}\n",
                    "PLATFORM ENFORCEMENT TEST: dev App updates a story branch")
    rec("A-3 dev App updates story/** (bypass actor)", "200/201", s, b, s in (200, 201))
    s, b = put_file(br, ".github/workflows/platform-enforcement-denied.yml", "name: x\non: workflow_dispatch\njobs: {}\n",
                    "PLATFORM ENFORCEMENT TEST: dev App writes a workflow via contents API")
    rec("A-5 dev App (no workflows permission) writes .github/workflows/** via contents API", "4xx", s, b, 400 <= s < 500)
    s, head = call("GET", f"/git/ref/heads/{br}")
    head_sha = head["object"]["sha"]
    _, c = call("GET", f"/git/commits/{head_sha}")
    _, blob = call("POST", "/git/blobs", {"content": "name: x\non: workflow_dispatch\njobs: {}\n", "encoding": "utf-8"})
    _, tree = call("POST", "/git/trees", {"base_tree": c["tree"]["sha"], "tree": [
        {"path": ".github/workflows/platform-enforcement-denied.yml", "mode": "100644", "type": "blob", "sha": blob.get("sha")}]})
    _, commit = call("POST", "/git/commits", {"message": "PLATFORM ENFORCEMENT TEST: workflow via git data API",
                                               "tree": tree.get("sha"), "parents": [head_sha]})
    s, b = call("PATCH", f"/git/refs/heads/{br}", {"sha": commit.get("sha"), "force": False})
    rec("A-5 dev App (no workflows permission) moves story/** to a commit adding a workflow (git data API)", "4xx", s, b,
        400 <= s < 500)
    s, b = put_file(br, ".github/PLATFORM_ENFORCEMENT.txt", "x\n", "PLATFORM ENFORCEMENT TEST: dev App writes .github/ non-workflow file")
    rec("A-5b dev App writes a .github/ non-workflow file (GitHub allows it; CODEOWNERS and the gate catch it)", "info", s, b, True)
    s, b = call("PATCH", f"/git/refs/heads/{br}", {"sha": base, "force": True})
    rec("History: dev App force-pushes story/** (agent-branch-history has no bypass)", "422 rule violation", s, b, rule_blocked(s, b))
    s, b = create_ref("qa-fix/FRQ-0-platform-enforcement-dev-denied", base)
    rec("A-3 dev App creates qa-fix/** (not a bypass actor)", "422 rule violation", s, b, rule_blocked(s, b))
    s, b = create_ref("release/platform-enforcement-dev-denied", base)
    rec("A-3 dev App creates release/** (not a bypass actor)", "422 rule violation", s, b, rule_blocked(s, b))
    s, b = call("DELETE", f"/git/refs/heads/{br}")
    rec("Cleanup: dev App deletes its story/** scratch branch", "204", s, b, s == 204)


def bundler(base):
    s, b = create_ref("story/FRQ-0-platform-enforcement-bundler-denied", base)
    rec("A-3 bundler App creates story/** (not a bypass actor)", "422 rule violation", s, b, rule_blocked(s, b))
    br = "release/platform-enforcement"
    if not ref_exists(br):
        s, b = create_ref(br, base)
        rec("A-3 bundler App creates release/** (bypass actor)", "201", s, b, s == 201)
    s, b = put_file(br, "PLATFORM_ENFORCEMENT.txt", f"run {os.environ.get('GITHUB_RUN_ID')}\n",
                    "PLATFORM ENFORCEMENT TEST: bundler App updates a release branch")
    rec("A-3 bundler App updates release/** (bypass actor)", "200/201", s, b, s in (200, 201))
    # The update above puts the branch ahead of main, so moving it back to main is a real non-fast-forward.
    s, b = call("PATCH", f"/git/refs/heads/{br}", {"sha": base, "force": True})
    rec("History: bundler App force-pushes release/** (agent-branch-history has no bypass)", "422 rule violation", s, b,
        rule_blocked(s, b))
    s, b = call("DELETE", f"/git/refs/heads/{br}")
    rec("Bundler App deletes release/** (release-branch-deletion has no bypass)", "422 rule violation", s, b, rule_blocked(s, b))


def qa(base):
    br = "qa-fix/FRQ-0-platform-enforcement"
    if ref_exists(br):
        call("DELETE", f"/git/refs/heads/{br}")
    s, b = create_ref(br, base)
    rec("A-3 qa App creates qa-fix/** (bypass actor)", "201", s, b, s == 201)
    s, b = create_ref("release/platform-enforcement-qa-denied", base)
    rec("A-3 qa App creates release/** (not a bypass actor)", "422 rule violation", s, b, rule_blocked(s, b))
    s, b = call("DELETE", f"/git/refs/heads/{br}")
    rec("Cleanup: qa App deletes its qa-fix/** scratch branch", "204", s, b, s == 204)


ROLES = {"dev": dev, "bundler": bundler, "qa": qa}

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ROLES:
        sys.exit(__doc__)
    role, out = sys.argv[1], sys.argv[2]
    base = main_sha()
    ROLES[role](base)
    json.dump({"role": role, "appSlug": os.environ.get("SOX_APP_SLUG"), "runId": os.environ.get("GITHUB_RUN_ID"),
               "mainSha": base, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": results},
              open(out, "w"), indent=2)
    sys.exit(0 if all(r["pass"] for r in results) else 1)
