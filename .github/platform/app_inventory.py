#!/usr/bin/env python3
"""GitHub App inventory: key fingerprint, App permissions, installations and repositories.

Usage:
  app_inventory.py collect <role> <out.json>   (env APP_ID, APP_PRIVATE_KEY)
  app_inventory.py summarize <dir> <out.json>  (merges collect outputs, checks expectations)

collect runs inside the role's environment. The private key goes to a 0600 file in
RUNNER_TEMP only for openssl, and is removed before exit. Outputs contain no secret: the
key fingerprint is the format the App settings page shows ("SHA256:" + base64 of the
SHA-256 of the DER public key), so a human can match it and see that only one key remains.
Installation tokens are minted with metadata:read only, used to list repositories, and revoked.
"""
import base64, glob, json, os, subprocess, sys, tempfile, time, urllib.error, urllib.request

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
OWNER = os.environ.get("GITHUB_REPOSITORY_OWNER", "factory-ryan-lauderback")
SANDBOX, EVIDENCE = f"{OWNER}/sox-sdlc-sandbox", f"{OWNER}/sox-sdlc-evidence"
EXPECTED_REPOS = {
    "review": [SANDBOX], "qa": [SANDBOX], "dev": [SANDBOX], "techlead": [SANDBOX], "gate": [SANDBOX],
    "release_bundler": [SANDBOX], "jira_attestor": [SANDBOX], "evidence_writer": [EVIDENCE],
    "reconciler": sorted([SANDBOX, EVIDENCE]),
}
WRITE = ("write", "admin")


def call(method, path, token, scheme="Bearer", body=None):
    req = urllib.request.Request(f"{API}{path}", method=method, data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Authorization", f"{scheme} {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else None
        except ValueError:
            return e.code, {"message": raw[:200].decode(errors="replace")}


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def collect(role, out):
    app_id = os.environ["APP_ID"].strip()
    fd, key_path = tempfile.mkstemp(dir=os.environ.get("RUNNER_TEMP"), suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(os.environ["APP_PRIVATE_KEY"])
        der = subprocess.run(["openssl", "pkey", "-in", key_path, "-pubout", "-outform", "DER"],
                             check=True, capture_output=True).stdout
        digest = subprocess.run(["openssl", "dgst", "-sha256", "-binary"], input=der, check=True, capture_output=True).stdout
        fingerprint = "SHA256:" + base64.b64encode(digest).decode()
        now = int(time.time())
        signing_input = (b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()) + "." +
                         b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": app_id}).encode()))
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_path], input=signing_input.encode(),
                             check=True, capture_output=True).stdout
        jwt = signing_input + "." + b64url(sig)
    finally:
        os.remove(key_path)
    rec = {"role": role, "appIdVar": app_id, "keyFingerprint": fingerprint, "errors": []}
    s, app = call("GET", "/app", jwt)
    if s != 200:
        rec["errors"].append(f"GET /app: {s} {app}")
    else:
        rec.update({"appId": app["id"], "slug": app["slug"], "owner": app["owner"]["login"],
                    "appPermissions": app.get("permissions", {}), "events": app.get("events", []),
                    "installationsCount": app.get("installations_count")})
    s, insts = call("GET", "/app/installations?per_page=100", jwt)
    rec["installations"] = []
    for i in insts if s == 200 else []:
        entry = {"id": i["id"], "account": i["account"]["login"], "repositorySelection": i["repository_selection"],
                 "permissions": i.get("permissions", {}), "events": i.get("events", []), "suspendedAt": i.get("suspended_at")}
        ts, tok = call("POST", f"/app/installations/{i['id']}/access_tokens", jwt, body={"permissions": {"metadata": "read"}})
        if ts == 201:
            rs, repos = call("GET", "/installation/repositories?per_page=100", tok["token"])
            entry["repositories"] = sorted(r["full_name"] for r in (repos or {}).get("repositories", [])) if rs == 200 else None
            call("DELETE", "/installation/token", tok["token"])
        else:
            rec["errors"].append(f"installation {i['id']} token: {ts}")
        rec["installations"].append(entry)
    if s != 200:
        rec["errors"].append(f"GET /app/installations: {s}")
    json.dump(rec, open(out, "w"), indent=2)
    print(f"{role}: app {rec.get('appId')} {rec.get('slug')} key {fingerprint} installations "
          f"{[(x['id'], x.get('repositories')) for x in rec['installations']]}")


def summarize(directory, out):
    apps = [json.load(open(p)) for p in sorted(glob.glob(os.path.join(directory, "**", "*.json"), recursive=True))]
    checks = []

    def check(name, ok, detail=""):
        checks.append({"check": name, "pass": bool(ok), "detail": detail})

    for a in apps:
        role, insts = a["role"], a.get("installations", [])
        check(f"{role}: no API errors", not a["errors"], "; ".join(a["errors"]))
        check(f"{role}: App ID matches the environment variable", str(a.get("appId")) == a["appIdVar"], f"{a.get('appId')} vs {a['appIdVar']}")
        check(f"{role}: exactly one installation", len(insts) == 1, str([i["id"] for i in insts]))
        repos = sorted(r for i in insts for r in (i.get("repositories") or []))
        check(f"{role}: installed on exactly {EXPECTED_REPOS.get(role)}", repos == EXPECTED_REPOS.get(role), str(repos))
        grants = [a.get("appPermissions", {})] + [i["permissions"] for i in insts]
        writes = sorted({k for g in grants for k, v in g.items() if v in WRITE})
        if role == "reconciler":
            check("reconciler: no write or admin permission anywhere", not writes, str(writes))
        if EVIDENCE in repos and role != "evidence_writer":
            check(f"{role}: no write on the evidence repo (only evidence_writer writes)", not writes, str(writes))
        if role != "reconciler" and "workflows" in {k for g in grants for k in g}:
            check(f"{role}: no workflows permission", False, "workflows")
    roles = {a["role"] for a in apps}
    check("all 9 Apps reported", roles == set(EXPECTED_REPOS), str(sorted(set(EXPECTED_REPOS) - roles)))
    result = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "runId": os.environ.get("GITHUB_RUN_ID"),
              "apps": [{k: a.get(k) for k in ("role", "appId", "slug", "keyFingerprint", "appPermissions", "installations")} for a in apps],
              "checks": checks, "pass": all(c["pass"] for c in checks)}
    json.dump(result, open(out, "w"), indent=2)
    lines = ["| Role | App ID | Key fingerprint | Installation | Repositories |", "|---|---|---|---|---|"]
    for a in apps:
        for i in a.get("installations") or [{}]:
            lines.append(f"| {a['role']} | {a.get('appId')} | `{a['keyFingerprint']}` | {i.get('id', '-')} | {', '.join(i.get('repositories') or [])} |")
    lines += ["", "| Check | Result | Detail |", "|---|---|---|"]
    lines += [f"| {c['check']} | {'PASS' if c['pass'] else 'FAIL'} | {c['detail']} |" for c in checks]
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        open(summary, "a").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    sys.exit(0 if result["pass"] else 1)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "collect":
        collect(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "summarize":
        summarize(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
