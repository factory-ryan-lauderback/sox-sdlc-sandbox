#!/usr/bin/env python3
"""Read-only platform snapshot as the Reconciler App (fixed GET list, no inputs).

Usage: reconciler_ro.py <out.json>
Token: SOX_APP_TOKEN (Reconciler installation token, minted in the `reconciler`
environment). Only GET requests are made, and the token is never printed. The output is
a public artifact, so it holds secret names but never values, and variable values only
for `*_APP_ID` (other variable values are replaced by their SHA-256).
"""
import hashlib, json, os, sys, time, urllib.error, urllib.parse, urllib.request

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
OWNER = os.environ.get("GITHUB_REPOSITORY_OWNER", "factory-ryan-lauderback")
REPOS = [f"{OWNER}/sox-sdlc-sandbox", f"{OWNER}/sox-sdlc-evidence"]
TOKEN = os.environ["SOX_APP_TOKEN"]
MAX_PAGES = 10
queries = []


def get(path):
    """GET with pagination over Link headers; returns (status, body)."""
    url, pages, items = f"{API}{path}", 0, None
    while url and pages < MAX_PAGES:
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {TOKEN}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                body = json.loads(r.read() or b"null")
                link = r.headers.get("Link", "")
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                body = json.loads(raw) if raw else None
            except ValueError:
                body = {"message": raw[:200].decode(errors="replace")}
            return e.code, body
        pages += 1
        if not isinstance(body, list):
            return 200, body
        items = (items or []) + body
        url = next((p.split(";")[0].strip(" <>") for p in link.split(",") if 'rel="next"' in p), None)
    return 200, items


def q(path, scrub=None):
    status, body = get(path)
    if status == 200 and scrub:
        body = scrub(body)
    queries.append({"path": path, "status": status, "body": body})
    return status, body


def scrub_variables(body):
    for v in (body or {}).get("variables", []):
        if not v.get("name", "").endswith("_APP_ID"):
            v["value"] = "sha256:" + hashlib.sha256(str(v.get("value", "")).encode()).hexdigest()
    return body


def scrub_secrets(body):
    # The API returns names and timestamps only; keep exactly those fields.
    if isinstance(body, dict) and "secrets" in body:
        body["secrets"] = [{k: s.get(k) for k in ("name", "created_at", "updated_at")} for s in body["secrets"]]
    return body


def repo(r):
    p = f"/repos/{r}"
    q(p)
    q(f"{p}/commits/main")
    s, rulesets = q(f"{p}/rulesets?includes_parents=true&per_page=100")
    for rs in rulesets if s == 200 else []:
        q(f"{p}/rulesets/{rs['id']}")
        q(f"{p}/rulesets/{rs['id']}/history?per_page=100")
    q(f"{p}/rulesets/rule-suites?time_period=week&per_page=100")
    q(f"{p}/rules/branches/main")
    q(f"{p}/branches/main/protection")
    q(f"{p}/collaborators?affiliation=all&per_page=100")
    q(f"{p}/invitations")
    q(f"{p}/keys")
    q(f"{p}/hooks")
    q(f"{p}/codeowners/errors")
    q(f"{p}/actions/permissions")
    q(f"{p}/actions/permissions/workflow")
    q(f"{p}/actions/permissions/selected-actions")
    q(f"{p}/actions/workflows?per_page=100")
    q(f"{p}/actions/secrets?per_page=100", scrub_secrets)
    q(f"{p}/actions/variables?per_page=30", scrub_variables)
    s, envs = q(f"{p}/environments?per_page=100")
    for e in (envs or {}).get("environments", []) if s == 200 else []:
        n = urllib.parse.quote(e["name"], safe="")
        q(f"{p}/environments/{n}/deployment-branch-policies?per_page=100")
        q(f"{p}/environments/{n}/deployment_protection_rules")
        q(f"{p}/environments/{n}/secrets?per_page=100", scrub_secrets)
        q(f"{p}/environments/{n}/variables?per_page=30", scrub_variables)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    q("/installation/repositories?per_page=100",
      lambda b: {"total_count": b.get("total_count"), "repositories": [x["full_name"] for x in b.get("repositories", [])]})
    for r in REPOS:
        repo(r)
    json.dump({"appSlug": os.environ.get("SOX_APP_SLUG"), "runId": os.environ.get("GITHUB_RUN_ID"),
               "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "queries": queries},
              open(sys.argv[1], "w"), indent=1)
    failed = [x["path"] for x in queries if x["status"] >= 400]
    print(f"{len(queries)} GETs, {len(failed)} non-2xx")
    for f in failed:
        print("non-2xx:", f)
