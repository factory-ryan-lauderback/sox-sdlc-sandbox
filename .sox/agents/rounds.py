"""Loop counters and evidence lookups, computed only from attestations that pass signer pinning.

Rounds are derived, never stored: the number of distinct head SHAs that received a verified
`changes_requested` review-verdict for a loop key (story key, release slug, or PR number).
Counting distinct heads means re-dispatching a review on the same SHA cannot inflate the count,
and reusing an existing verdict for the same head means it cannot be re-rolled to a different one.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import REPO, sha256_hex  # noqa: E402
import verify  # noqa: E402

_policy = None


def _verified(kind, ident, predicate):
    global _policy
    if _policy is None:
        _policy = verify.load_policy()[0]
    out = []
    for item in verify.verified(kind, ident, predicate, _policy):
        p = item["statement"].get("predicate") or {}
        if p.get("repo") != REPO:
            continue
        out.append(item)
    return out


def statement_digest(item):
    """Digest of an attestation = sha256 of its in-toto statement bytes (the DSSE payload)."""
    payload = item["bundle"]["dsseEnvelope"]["payload"]
    return "sha256:" + sha256_hex(base64.b64decode(payload))


def changes_requested_heads(loop_key, predicate="review-verdict", field="verdict", value="changes_requested"):
    kind, ident = loop_key
    want = f"{kind}:{ident}"
    heads = set()
    for item in _verified(kind, ident, predicate):
        p = item["statement"]["predicate"]
        if p.get("loopKey") == want and p.get(field) == value and p.get("headSha"):
            heads.add(p["headSha"])
    return heads


def verdict_for_head(loop_key, head, base_ref, predicate="review-verdict"):
    want = f"{loop_key[0]}:{loop_key[1]}"
    found = [i for i in _verified("commit", head, predicate)
             if i["statement"]["predicate"].get("headSha") == head
             and i["statement"]["predicate"].get("baseRef") == base_ref
             and i["statement"]["predicate"].get("loopKey") == want
             and not i["statement"]["predicate"].get("fixture")]
    found.sort(key=lambda i: i["statement"]["predicate"].get("observedAt", ""))
    return found[-1] if found else None


def latest_plan_digest(jira_keys):
    best = None
    for key in jira_keys:
        for item in _verified("jira", key, "techlead-plan"):
            p = item["statement"]["predicate"]
            if key in [s.get("key") for s in p.get("stories", [])]:
                if best is None or p.get("observedAt", "") > best[0]:
                    best = (p.get("observedAt", ""), statement_digest(item))
    return best[1] if best else None
