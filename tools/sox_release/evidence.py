"""Adapter over the Gates verifier (.sox/soxlib, the library behind .sox/verify_evidence.py).

This module never verifies anything itself: it calls the verifier, keeps only attestations it
returns as verified, and normalizes them. If the verifier is missing or cannot run, callers get
EvidenceUnavailable and must refuse (fail closed). Rejected attestations (forgery attempts,
binding mismatches) are kept in REJECTED so workflows can report them.
"""
import os
import pathlib
import sys

from tools.sox_release.common import ROOT

SOX_DIR = pathlib.Path(os.environ.get("SOX_VERIFIER_DIR", ROOT / ".sox"))
REJECTED = []
_verifier = None


class EvidenceUnavailable(Exception):
    pass


def _load():
    global _verifier
    if _verifier is None:
        if not (SOX_DIR / "soxlib" / "verify.py").exists():
            raise EvidenceUnavailable(f"verifier library not found under {SOX_DIR}")
        if str(SOX_DIR) not in sys.path:
            sys.path.insert(0, str(SOX_DIR))
        try:
            from soxlib.ghapi import GitHub as SoxGitHub
            from soxlib.verify import Verifier
            _verifier = (Verifier.load(str(SOX_DIR / "trust-policy.yaml")), SoxGitHub)
        except Exception as e:  # any import or policy error means no verifier: fail closed
            raise EvidenceUnavailable(f"verifier unavailable: {e}") from None
    return _verifier


def normalize(att):
    st = att.statement
    return {
        "name": att.name,
        "predicate": att.predicate,
        "predicateType": st.get("predicateType"),
        "subjects": st.get("subject", []),
        "digest": att.digest,
        "time": att.time_iso,
        "signer": att.identity.get("buildSignerURI"),
        "trigger": att.identity.get("buildTrigger"),
        "run": att.identity.get("runInvocationURI"),
    }


def fetch(subject, predicate):
    """Verified attestations for a subject ("commit:<sha>", "pr:<n>", "jira:FRQ-n",
    "release:<slug>", "train:<date>", "image:sha256:<hex>"), oldest first."""
    verifier, SoxGitHub = _load()
    kind, _, ident = subject.partition(":")
    token = os.environ.get("SOX_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
    try:
        ok, bad = verifier.fetch(SoxGitHub(token=token), kind, ident, predicate)
    except Exception as e:
        raise EvidenceUnavailable(f"verifier fetch {subject} {predicate}: {e}") from None
    REJECTED.extend({"subject": subject, **r.to_json()} for r in bad)
    return [normalize(a) for a in ok]


def verify_bundle(raw, predicate, expect=()):
    """Verify one bundle (bytes or parsed JSON). expect: iterable of "kind:id" strings."""
    verifier, _ = _load()
    import json
    if isinstance(raw, (dict, list)):
        raw = json.dumps(raw).encode()
    from soxlib.verify import Rejection
    pairs = [tuple(e.split(":", 1)) for e in expect]
    try:
        return normalize(verifier.verify(raw, predicate=predicate, expect=pairs))
    except Rejection as r:
        REJECTED.append(r.to_json())
        raise EvidenceUnavailable(f"bundle rejected ({r.category}): {r.reason}") from None
    except Exception as e:
        raise EvidenceUnavailable(f"verifier error: {e}") from None


def image_subject(item, digest):
    hexd = digest.split(":", 1)[-1]
    return any(not str(s.get("name", "")).startswith("sox:") and (s.get("digest") or {}).get("sha256") == hexd
               for s in item.get("subjects", []))


def latest(items):
    return max(items, key=lambda i: (str(i.get("time") or ""), str(i.get("digest") or ""))) if items else None
