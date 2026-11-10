"""Shared helpers for the release bundler, ephemeral environments, and the deploy train.

Stdlib only, so the same code runs unchanged on any GitHub-hosted runner and on a laptop.
"""
import datetime as dt
import fnmatch
import hashlib
import json
import pathlib
import re
import subprocess

from tools.deploy_order import deploy_order, load_services, parse_yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
REPO = "factory-ryan-lauderback/sox-sdlc-sandbox"
REGISTRY = "ghcr.io/factory-ryan-lauderback/sox-sdlc-sandbox"
PREDICATE_BASE = "https://acme-lending.example/sox/"

STORY_BRANCH = re.compile(r"^(story|qa-fix)/(FRQ-[0-9]+)(-[a-z0-9][a-z0-9-]*)?$")
HOTFIX_BRANCH = re.compile(r"^hotfix/(FRQ-[0-9]+)(-[a-z0-9][a-z0-9-]*)?$")
RELEASE_BRANCH = re.compile(r"^release/([a-z0-9][a-z0-9-]{0,40})$")
JIRA_KEY = re.compile(r"^FRQ-[0-9]{1,7}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class RefusedError(Exception):
    """A deterministic control decision to refuse. Callers turn it into a failed job."""


def predicate_type(name):
    return PREDICATE_BASE + name + "/v1"


def jcs(obj):
    # RFC 8785 equals sorted-key compact JSON for the value types used here (no floats).
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def digest_of(obj):
    return "sha256:" + sha256_hex(jcs(obj))


def subject_key(kind, ident, repo=REPO):
    return sha256_hex("sox-subject/v1\n" + repo + "\n" + kind + "\n" + str(ident))


def subject(kind, ident, repo=REPO):
    return {"name": f"sox:{kind}:{ident}", "digest": {"sha256": subject_key(kind, ident, repo)}}


def slugify(name):
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40].strip("-")
    if not slug or not RELEASE_BRANCH.match("release/" + slug):
        raise RefusedError(f"cannot derive a release slug from {name!r}")
    return slug


def k8s_name(text):
    name = re.sub(r"[^a-z0-9-]+", "-", text.lower()).strip("-")[:63].strip("-")
    if not name:
        raise RefusedError(f"cannot derive a namespace from {text!r}")
    return name


def services(root=ROOT):
    return load_services(pathlib.Path(root))


def _glob_match(path, pattern):
    if pattern.endswith("/**"):
        return path.startswith(pattern[:-2])
    return fnmatch.fnmatchcase(path, pattern)


def services_touched(paths, svc):
    """Map changed paths to services. Paths outside every service are returned separately."""
    touched, other = set(), []
    for p in paths:
        hit = [n for n, m in svc.items() if any(_glob_match(p, g) for g in m.get("paths", []))]
        touched.update(hit)
        if not hit:
            other.append(p)
    return touched, sorted(other)


def ordered(svc, subset):
    subset = set(subset)
    unknown = subset - set(svc)
    if unknown:
        raise RefusedError(f"unknown services: {sorted(unknown)}")
    return [n for n in deploy_order(svc) if n in subset]


def upstream_closure(svc, names):
    out, stack = set(), list(names)
    while stack:
        n = stack.pop()
        if n in out:
            continue
        out.add(n)
        stack.extend(svc[n].get("depends_on", []))
    return out


def services_map_digest(root=ROOT):
    """Digest over the service index and every manifest, the inputs that define scope and order."""
    root = pathlib.Path(root)
    files = [".sox/services.yaml"] + [e["manifest"] for e in parse_yaml((root / ".sox/services.yaml").read_text())["services"]]
    return digest_of({f: sha256_hex((root / f).read_bytes()) for f in files})


def now_iso():
    # observedAt must be within the verifier's clock-skew window of the Rekor time, so callers
    # build predicates immediately before the attest step.
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def git(*args, cwd=ROOT):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def tree_sha(commit, path, cwd=ROOT):
    return git("rev-parse", f"{commit}:{path}", cwd=cwd)


def write_json(path, obj):
    pathlib.Path(path).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")
