"""Shared helpers for the SDLC agent workflows: subject keys, canonical JSON, GitHub REST.

Standard library only, so every runner behaves the same and nothing is installed from PR code.
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
REPO = os.environ.get("SOX_REPO") or os.environ.get("GITHUB_REPOSITORY", "factory-ryan-lauderback/sox-sdlc-sandbox")
PREDICATE_BASE = "https://acme-lending.example/sox/"
JIRA_KEY_RE = re.compile(r"^FRQ-[1-9][0-9]{0,6}$")
STORY_BRANCH_RE = re.compile(r"^(story|qa-fix)/(FRQ-[1-9][0-9]{0,6})(-[a-z0-9][a-z0-9-]{0,60})?$")
RELEASE_BRANCH_RE = re.compile(r"^release/([a-z0-9][a-z0-9-]{0,60})$")
CONTROL_PATHS = (".github/", ".sox/", ".factory/", "tools/", "CODEOWNERS")


def predicate_type(name):
    return f"{PREDICATE_BASE}{name}/v1"


def subject_preimage(kind, ident, repo=REPO):
    return f"sox-subject/v1\n{repo}\n{kind}\n{ident}".encode()


def subject_key(kind, ident, repo=REPO):
    return hashlib.sha256(subject_preimage(kind, ident, repo)).hexdigest()


def subject_lines(bindings, repo=REPO):
    """bindings: iterable of (kind, id). Returns sha256sum-style lines for actions/attest subject-checksums."""
    seen, out = set(), []
    for kind, ident in bindings:
        if (kind, str(ident)) in seen:
            continue
        seen.add((kind, str(ident)))
        out.append(f"{subject_key(kind, ident, repo)}  sox:{kind}:{ident}")
    return "\n".join(out) + "\n"


def jcs(value):
    """RFC 8785 canonical JSON for the value types used in predicates (no floats allowed)."""
    def check(v):
        if isinstance(v, float):
            raise ValueError("floats are not allowed in canonical predicates")
        if isinstance(v, dict):
            for k, x in v.items():
                if not isinstance(k, str):
                    raise ValueError("object keys must be strings")
                check(x)
        elif isinstance(v, list):
            for x in v:
                check(x)
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def digest_of(value):
    return "sha256:" + sha256_hex(jcs(value))


def now_utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def positive_int(raw, name="value"):
    s = str(raw).strip()
    if not re.fullmatch(r"[1-9][0-9]{0,8}", s):
        raise SystemExit(f"{name} must be a positive integer, got {s[:20]!r}")
    return int(s)


def jira_key(raw):
    s = str(raw).strip()
    if not JIRA_KEY_RE.fullmatch(s):
        raise SystemExit(f"not a Jira key: {s[:30]!r}")
    return s


def is_control_path(path):
    return any(path == p.rstrip("/") or path.startswith(p) for p in CONTROL_PATHS)


class GitHub:
    def __init__(self, token=None, repo=REPO):
        self.token = token if token is not None else os.environ.get("GITHUB_TOKEN", "")
        self.repo = repo

    def request(self, method, path, body=None, accept="application/vnd.github+json", raw=False, ok=(200, 201, 204)):
        url = path if path.startswith("http") else f"{API}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", accept)
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "acme-sox-agents")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    payload = resp.read()
                    if resp.status not in ok:
                        raise RuntimeError(f"{method} {path}: HTTP {resp.status}")
                    if raw:
                        return payload
                    return json.loads(payload) if payload else None
            except urllib.error.HTTPError as e:
                if e.code in (502, 503, 504) and attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                detail = e.read()[:500].decode(errors="replace")
                raise RuntimeError(f"{method} {path}: HTTP {e.code} {detail}") from None
            except urllib.error.URLError as e:
                if attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"{method} {path}: URLError {e.reason}") from None

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def paginate(self, path, key=None, limit=1000):
        out, page = [], 1
        sep = "&" if "?" in path else "?"
        while len(out) < limit:
            chunk = self.get(f"{path}{sep}per_page=100&page={page}")
            items = chunk[key] if key else chunk
            out.extend(items)
            if len(items) < 100:
                break
            page += 1
        return out[:limit]

    def pr(self, number):
        return self.get(f"/repos/{self.repo}/pulls/{number}")

    def pr_diff(self, number):
        return self.get(f"/repos/{self.repo}/pulls/{number}", accept="application/vnd.github.v3.diff", raw=True)

    def pr_files(self, number):
        return self.paginate(f"/repos/{self.repo}/pulls/{number}/files", limit=3000)

    def contents(self, path, ref):
        data = self.get(f"/repos/{self.repo}/contents/{path}?ref={ref}", accept="application/vnd.github.raw+json", raw=True)
        return data.decode()


def pr_binding(pr):
    """Derive the story/release binding of a PR from API data only."""
    head_ref, base_ref = pr["head"]["ref"], pr["base"]["ref"]
    m = STORY_BRANCH_RE.fullmatch(head_ref)
    story = m.group(2) if m else None
    rel = RELEASE_BRANCH_RE.fullmatch(base_ref) or RELEASE_BRANCH_RE.fullmatch(head_ref)
    release = rel.group(1) if rel else None
    if base_ref == "main":
        kind = "release" if RELEASE_BRANCH_RE.fullmatch(head_ref) else "other-to-main"
    elif story and RELEASE_BRANCH_RE.fullmatch(base_ref):
        kind = "story"
    else:
        kind = "other"
    loop_key = ("jira", story) if kind == "story" else (("release", release) if kind == "release" and release else ("pr", str(pr["number"])))
    return {"kind": kind, "story": story, "release": release, "headRef": head_ref,
            "baseRef": f"refs/heads/{base_ref}", "loopKey": loop_key}


def set_output(name, value):
    path = os.environ.get("GITHUB_OUTPUT")
    line = f"{name}={value}\n"
    if path:
        with open(path, "a") as f:
            f.write(line)
    else:
        sys.stdout.write(line)


def load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        if default is not None:
            return default
        raise


def dump_json(path, value):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")
