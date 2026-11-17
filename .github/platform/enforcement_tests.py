#!/usr/bin/env python3
"""Platform enforcement tests (A-3, A-5, branch history) run as one GitHub App.

Usage: enforcement_tests.py <dev|bundler|qa> <out.json>
Token: SOX_APP_TOKEN, an installation token of the role's App minted in the role's
environment with the App's full granted permissions (not narrowed), so A-5 would fail if
the App had been granted `workflows`. The token is never printed. Output records only HTTP
status codes and API messages.

Oracles are specific: a "refused" case passes only on the expected status and message,
and only after its own setup calls succeeded; an "allowed" control with the same token
and branch shows that a refusal comes from the rule under test. Refs a "denied" case
must not create get a per-run name, so a leftover ref cannot answer for the rule, and
are deleted again if they were created. Scratch refs: story/FRQ-0-platform-enforcement,
qa-fix/FRQ-0-platform-enforcement, release/platform-enforcement (kept: release/** refs
cannot be deleted by design), and *-denied-<run> names.
"""
import base64, json, os, sys, time, urllib.error, urllib.request

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
REPO = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["SOX_APP_TOKEN"]
RUN = f"{os.environ.get('GITHUB_RUN_ID', 'local')}-{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}"
RULE_VIOLATION = "Repository rule violations"
NO_PERMISSION = "Resource not accessible by integration"
WORKFLOW_PATH = ".github/workflows/platform-enforcement-denied.yml"
WORKFLOW_TEXT = "name: x\non: workflow_dispatch\njobs: {}\n"
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


def rec(test, expect, status, body, ok, detail=""):
    results.append({"test": test, "expect": expect, "status": status, "message": msg(body), "detail": detail,
                    "pass": bool(ok)})
    print(("PASS " if ok else "FAIL ") + f"{test}: {status} {msg(body)[:120]} {detail}".rstrip())


def rule_blocked(status, body):
    return status == 422 and RULE_VIOLATION in msg(body)


def workflow_refused(status, body):
    """GitHub's refusal of a workflow file write by an App without the workflows permission."""
    m = msg(body).lower()
    return status in (403, 404) and (NO_PERMISSION.lower() in m or "workflow" in m)


def main_sha():
    s, b = call("GET", "/git/ref/heads/main")
    if s != 200:
        sys.exit(f"cannot read main: {s} {msg(b)}")
    return b["object"]["sha"]


def ref_exists(ref):
    return call("GET", f"/git/ref/heads/{ref}")[0] == 200


def ref_sha(ref):
    s, b = call("GET", f"/git/ref/heads/{ref}")
    return b["object"]["sha"] if s == 200 else None


def create_ref(ref, sha):
    return call("POST", "/git/refs", {"ref": f"refs/heads/{ref}", "sha": sha})


def put_file(branch, path, text, message):
    s, cur = call("GET", f"/contents/{path}?ref={branch}")
    body = {"message": message, "content": base64.b64encode(text.encode()).decode(), "branch": branch}
    if s == 200:
        body["sha"] = cur["sha"]
    return call("PUT", f"/contents/{path}", body)


def denied_create(test, name, base):
    """A create the rulesets must refuse. A per-run name means only the rule can refuse it."""
    ref = f"{name}-denied-{RUN}"
    s, b = create_ref(ref, base)
    ok = rule_blocked(s, b)
    detail = ""
    if s == 201:
        ds, _ = call("DELETE", f"/git/refs/heads/{ref}")
        detail = f"ref was created; cleanup DELETE {ds}"
    rec(test, "422 rule violation", s, b, ok, detail)


def a5_git_data(br):
    """Move the branch to a commit that adds a workflow, through the git data API. Every
    setup call must succeed, or be the refusal itself; a missing object never counts."""
    test = "A-5 dev App (no workflows permission) moves story/** to a commit adding a workflow (git data API)"
    head = ref_sha(br)
    s, c = call("GET", f"/git/commits/{head}")
    if s != 200:
        return rec(test, "refusal after setup", s, c, False, "setup: cannot read head commit")
    s, blob = call("POST", "/git/blobs", {"content": WORKFLOW_TEXT, "encoding": "utf-8"})
    if s != 201:
        return rec(test, "refusal after setup", s, blob, False, "setup: blob not created")
    s, tree = call("POST", "/git/trees", {"base_tree": c["tree"]["sha"], "tree": [
        {"path": WORKFLOW_PATH, "mode": "100644", "type": "blob", "sha": blob["sha"]}]})
    if s != 201:
        return rec(test, "403/404 workflow refusal", s, tree, workflow_refused(s, tree), "refused at tree creation")
    s, commit = call("POST", "/git/commits", {"message": "PLATFORM ENFORCEMENT TEST: workflow via git data API",
                                               "tree": tree["sha"], "parents": [head]})
    if s != 201:
        return rec(test, "403/404 workflow refusal", s, commit, workflow_refused(s, commit), "refused at commit creation")
    s, b = call("PATCH", f"/git/refs/heads/{br}", {"sha": commit["sha"], "force": False})
    moved = ref_sha(br) == commit["sha"]
    rec(test, "403/404/422 workflow refusal, ref unchanged", s, b,
        not moved and (workflow_refused(s, b) or (s == 422 and "workflow" in msg(b).lower())), "refused at ref update")


def dev(base):
    br = "story/FRQ-0-platform-enforcement"
    if ref_exists(br):
        call("DELETE", f"/git/refs/heads/{br}")
    s, b = create_ref(br, base)
    rec("A-3 dev App creates story/** (bypass actor)", "201", s, b, s == 201)
    s, b = put_file(br, "services/db/PLATFORM_ENFORCEMENT.txt", f"run {RUN}\n",
                    "PLATFORM ENFORCEMENT TEST: dev App updates a story branch")
    rec("A-3 dev App updates story/** (bypass actor)", "200/201", s, b, s in (200, 201))
    s, b = put_file(br, ".github/PLATFORM_ENFORCEMENT.txt", f"run {RUN}\n",
                    "PLATFORM ENFORCEMENT TEST: dev App writes .github/ non-workflow file")
    control = s in (200, 201)
    rec("A-5 control: same token and branch write a .github/ non-workflow file (GitHub allows it; CODEOWNERS and the gate catch it)",
        "200/201", s, b, control)
    s, b = put_file(br, WORKFLOW_PATH, WORKFLOW_TEXT, "PLATFORM ENFORCEMENT TEST: dev App writes a workflow via contents API")
    rec("A-5 dev App (no workflows permission) writes .github/workflows/** via contents API", "403/404 workflow refusal",
        s, b, control and workflow_refused(s, b), "" if control else "control failed, so the refusal is not attributable")
    a5_git_data(br)
    s, b = call("PATCH", f"/git/refs/heads/{br}", {"sha": base, "force": True})
    rec("History: dev App force-pushes story/** (agent-branch-history has no bypass)", "422 rule violation", s, b, rule_blocked(s, b))
    denied_create("A-3 dev App creates qa-fix/** (not a bypass actor)", "qa-fix/FRQ-0-platform-enforcement-dev", base)
    denied_create("A-3 dev App creates release/** (not a bypass actor)", "release/platform-enforcement-dev", base)
    s, b = call("DELETE", f"/git/refs/heads/{br}")
    rec("Cleanup: dev App deletes its story/** scratch branch", "204", s, b, s == 204)


def bundler(base):
    denied_create("A-3 bundler App creates story/** (not a bypass actor)", "story/FRQ-0-platform-enforcement-bundler", base)
    br = "release/platform-enforcement"
    if not ref_exists(br):
        s, b = create_ref(br, base)
        rec("A-3 bundler App creates release/** (bypass actor)", "201", s, b, s == 201)
    s, b = put_file(br, "PLATFORM_ENFORCEMENT.txt", f"run {RUN}\n", "PLATFORM ENFORCEMENT TEST: bundler App updates a release branch")
    rec("A-3 bundler App updates release/** (bypass actor)", "200/201", s, b, s in (200, 201))
    # The update above puts the branch ahead of main, so moving it back to main is a real non-fast-forward.
    before = ref_sha(br)
    s, b = call("PATCH", f"/git/refs/heads/{br}", {"sha": base, "force": True})
    rec("History: bundler App force-pushes release/** (agent-branch-history has no bypass)", "422 rule violation", s, b,
        rule_blocked(s, b) and ref_sha(br) == before)
    s, b = call("DELETE", f"/git/refs/heads/{br}")
    rec("Bundler App deletes release/** (release-branch-deletion has no bypass)", "422 rule violation", s, b,
        rule_blocked(s, b) and ref_exists(br))


def qa(base):
    br = "qa-fix/FRQ-0-platform-enforcement"
    if ref_exists(br):
        call("DELETE", f"/git/refs/heads/{br}")
    s, b = create_ref(br, base)
    rec("A-3 qa App creates qa-fix/** (bypass actor)", "201", s, b, s == 201)
    denied_create("A-3 qa App creates release/** (not a bypass actor)", "release/platform-enforcement-qa", base)
    s, b = call("DELETE", f"/git/refs/heads/{br}")
    rec("Cleanup: qa App deletes its qa-fix/** scratch branch", "204", s, b, s == 204)


ROLES = {"dev": dev, "bundler": bundler, "qa": qa}

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ROLES:
        sys.exit(__doc__)
    role, out = sys.argv[1], sys.argv[2]
    base = main_sha()
    head = os.environ.get("GITHUB_SHA")
    if head:
        rec("Tested main is the run's head commit", "equal", 200, {}, head == base, f"main {base[:12]} run {head[:12]}")
    ROLES[role](base)
    json.dump({"role": role, "appSlug": os.environ.get("SOX_APP_SLUG"), "runId": os.environ.get("GITHUB_RUN_ID"),
               "mainSha": base, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": results},
              open(out, "w"), indent=2)
    sys.exit(0 if all(r["pass"] for r in results) else 1)
