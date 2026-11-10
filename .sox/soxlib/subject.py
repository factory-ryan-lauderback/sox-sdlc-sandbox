"""Derived subject keys (evidence spec 2.2). Lookup only: they carry no authenticity."""
import hashlib
import re

KINDS = ("commit", "pr", "jira", "release", "train", "report")
_ID_RULES = {
    "commit": re.compile(r"^[0-9a-f]{40}$"),
    "pr": re.compile(r"^[0-9]{1,9}$"),
    "jira": re.compile(r"^[A-Z][A-Z0-9]{1,9}-[0-9]{1,9}$"),
    "release": re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$"),
    "train": re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"),
    "report": re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}(T[0-9:]{8}Z)?$"),
}


def preimage(repo, kind, ident):
    if kind not in KINDS:
        raise ValueError(f"unknown subject kind {kind!r}")
    ident = str(ident)
    if not _ID_RULES[kind].match(ident):
        raise ValueError(f"invalid {kind} id {ident!r}")
    return f"sox-subject/v1\n{repo}\n{kind}\n{ident}".encode()


def key(repo, kind, ident):
    return hashlib.sha256(preimage(repo, kind, ident)).hexdigest()


def parse_name(name):
    """'sox:commit:<sha>' -> ('commit', '<sha>'), or None for non-SOX subjects (images etc)."""
    if not isinstance(name, str) or not name.startswith("sox:"):
        return None
    parts = name.split(":", 2)
    if len(parts) != 3 or parts[1] not in KINDS:
        return None
    return parts[1], parts[2]


def parse_ref(text):
    """'commit:<sha>' (CLI form) -> ('commit', '<sha>')."""
    kind, _, ident = text.partition(":")
    if kind not in KINDS or not ident:
        raise ValueError(f"expected <kind>:<id>, got {text!r}")
    preimage("x/y", kind, ident)
    return kind, ident
