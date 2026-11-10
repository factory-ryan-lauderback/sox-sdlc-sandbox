"""Loop counters and evidence lookups for the agent workflows, delegated to the Gates verifier
(.sox/soxlib). Nothing here verifies signatures or counts on its own terms for story loops:
story rounds are `Verifier.count_rounds` (distinct head SHAs with a verified failing verdict).
"""
import os
import sys

_SOX = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _SOX)
from soxlib.ghapi import GitHub as SoxGitHub  # noqa: E402
from soxlib.verify import Verifier  # noqa: E402

FAILING = {"review-verdict": "changes_requested", "qa-result": "fail"}
_v = None
_api = None


def _ctx():
    global _v, _api
    if _v is None:
        _v = Verifier.load(os.environ.get("SOX_TRUST_POLICY", os.path.join(_SOX, "trust-policy.yaml")))
        _api = SoxGitHub(os.environ.get("SOX_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN"))
    return _v, _api


def fetch(kind, ident, predicate):
    v, api = _ctx()
    verified, rejected = v.fetch(api, kind, ident, predicate)
    return verified, rejected


def failing_heads(loop_key, predicate="review-verdict"):
    """Distinct head SHAs with a verified failing verdict for the loop key, plus forgery count."""
    kind, ident = loop_key
    v, api = _ctx()
    outcome = FAILING[predicate]
    if kind == "jira":
        _, items, rejected = v.count_rounds(api, ident, predicate, outcome=outcome)
    else:
        # Release and PR loop keys: same rule (verified only, distinct heads) over that subject.
        verified, rejected = v.fetch(api, kind, ident, predicate)
        items = [a for a in verified if a.predicate.get("outcome") == outcome]
    want = f"{kind}:{ident}"
    heads = {a.predicate.get("headSha") for a in items
             if a.predicate.get("loopKey", want) == want and a.predicate.get("headSha")}
    return heads, len(rejected)


def verdict_for_head(head, base_ref, predicate="review-verdict"):
    """Existing verified verdict for this exact head and base. A failing one always wins (no re-roll)."""
    verified, _ = fetch("commit", head, predicate)
    found = [a for a in verified if a.predicate.get("headSha") == head and a.predicate.get("baseRef") == base_ref
             and not a.predicate.get("fixture")]
    failing = [a for a in found if a.predicate.get("outcome") == FAILING[predicate]]
    pick = failing or found
    return pick[-1] if pick else None


def latest_plan_digest(jira_keys):
    best = None
    for key in jira_keys:
        verified, _ = fetch("jira", key, "techlead-plan")
        for a in verified:
            if key in [s.get("key") for s in a.predicate.get("stories", [])]:
                if best is None or a.integrated_time > best[0]:
                    best = (a.integrated_time, a.digest)
    return best[1] if best else None
