"""Change scope (SDLC-04, BP-38): map changed paths to services with .sox/services.yaml from main.

A path maps to every service whose manifest `paths` match it, to every service a `shared` entry
lists for it, and to the pseudo-service `controls` if it is a control path in the trust policy.
A path that maps to nothing is unmapped and fails the gate; a new service's mapping must merge to
main before a PR may touch it.

`shared` entries in .sox/services.yaml:

    shared:
      - path: README.md            # or paths: [a/**, b.txt]
        services: [api, db, ui]    # or a block list
"""
import fnmatch
import hashlib
import os

CONTROLS = "controls"
INDEX = ".sox/services.yaml"


class ScopeError(ValueError):
    pass


def git_blob_sha(data):
    """The git blob id of data: what a release-manifest's servicesMapDigest records."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def norm_digest(v):
    if not isinstance(v, str):
        return None
    return v.split(":", 1)[-1].strip().lower() or None


def _scalar(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    if v.startswith("[") and v.endswith("]"):
        return [_scalar(x) for x in v[1:-1].split(",") if x.strip()]
    return v


def parse_yaml(text):
    """The YAML subset the service files use: nested mappings, block lists of scalars or
    mappings, inline lists, comments. Anything else raises, so the gate fails closed."""
    lines = []
    for n, raw in enumerate(text.splitlines(), 1):
        s = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if s.strip():
            if "\t" in s[:len(s) - len(s.lstrip())]:
                raise ScopeError(f"line {n}: tab indentation")
            lines.append((len(s) - len(s.lstrip()), s.strip(), n))
    pos = 0

    def block(indent):
        nonlocal pos
        if pos >= len(lines):
            return None
        if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
            out = []
            while pos < len(lines) and lines[pos][0] == indent and lines[pos][1].startswith("-"):
                ind, s, n = lines[pos]
                item = s[1:].strip()
                pos += 1
                if not item:
                    out.append(block(lines[pos][0]) if pos < len(lines) and lines[pos][0] > ind else None)
                elif ":" in item and not item.startswith(("[", "'", '"')):
                    # "- key: value" opens a mapping whose further keys sit at indent + 2
                    k, v = item.split(":", 1)
                    m = {k.strip(): _value(v, ind + 2)}
                    if pos < len(lines) and lines[pos][0] == ind + 2 and not lines[pos][1].startswith("-"):
                        rest = block(ind + 2)
                        if not isinstance(rest, dict):
                            raise ScopeError(f"line {n}: bad mapping")
                        m.update(rest)
                    out.append(m)
                else:
                    out.append(_scalar(item))
            return out
        out = {}
        while pos < len(lines) and lines[pos][0] == indent and not lines[pos][1].startswith("-"):
            ind, s, n = lines[pos]
            if ":" not in s:
                raise ScopeError(f"line {n}: expected key: value")
            k, v = s.split(":", 1)
            pos += 1
            out[k.strip()] = _value(v, ind)
        if pos < len(lines) and lines[pos][0] > indent:
            raise ScopeError(f"line {lines[pos][2]}: unexpected indentation")
        return out

    def _value(v, ind):
        nonlocal pos
        if v.strip():
            return _scalar(v)
        if pos < len(lines) and (lines[pos][0] > ind or
                                 (lines[pos][0] == ind and lines[pos][1].startswith("-"))):
            return block(lines[pos][0])
        return None

    data = block(lines[0][0]) if lines else {}
    if pos != len(lines):
        raise ScopeError(f"line {lines[pos][2]}: could not parse")
    return data


def _aslist(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return v
    raise ScopeError(f"expected a list of strings, got {v!r}")


def match(pattern, path):
    if pattern.endswith("/**"):
        pre = pattern[:-3].rstrip("/")
        return path == pre or path.startswith(pre + "/")
    if any(c in pattern for c in "*?["):
        return fnmatch.fnmatchcase(path, pattern)
    return path == pattern


class ScopeMap:
    def __init__(self, services, shared=(), policy=None, digest=None):
        self.services = {n: {"paths": _aslist((s or {}).get("paths"))} for n, s in services.items()}
        self.shared = [{"paths": _aslist(e.get("paths") or e.get("path")),
                        "services": _aslist(e.get("services"))} for e in shared or ()]
        self.policy = policy
        self.digest = digest
        names = set(self.services) | {CONTROLS}
        for e in self.shared:
            if not e["paths"] or not e["services"]:
                raise ScopeError(f"shared entry needs paths and services: {e}")
            unknown = sorted(set(e["services"]) - names)
            if unknown:
                raise ScopeError(f"shared entry names unknown services {unknown}")

    @classmethod
    def load(cls, root, policy):
        """From a checkout of main. Every manifest must parse and match its index name."""
        with open(os.path.join(root, INDEX), "rb") as f:
            raw = f.read()
        index = parse_yaml(raw.decode())
        services = {}
        for entry in index.get("services") or []:
            with open(os.path.join(root, entry["manifest"])) as f:
                man = parse_yaml(f.read())
            if man.get("name") != entry.get("name"):
                raise ScopeError(f"manifest name mismatch for {entry.get('name')}")
            services[entry["name"]] = man
        return cls(services, index.get("shared") or [], policy, git_blob_sha(raw))

    def map(self, path):
        out = set()
        for name, spec in self.services.items():
            if any(match(p, path) for p in spec["paths"]):
                out.add(name)
        for e in self.shared:
            if any(match(p, path) for p in e["paths"]):
                out.update(e["services"])
        if self.policy is not None and self.policy.is_control_path(path):
            out.add(CONTROLS)
        return out

    def touched(self, paths):
        touched, unmapped = set(), []
        for p in paths:
            hit = self.map(p)
            if hit:
                touched |= hit
            else:
                unmapped.append(p)
        return sorted(touched), unmapped
