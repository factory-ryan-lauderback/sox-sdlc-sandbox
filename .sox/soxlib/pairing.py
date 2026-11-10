"""Paired check runs (evidence spec 2.5, F16) and judging-run pairing (F17).

A GitHub App key can post a check run but cannot obtain a Sigstore certificate. A `success` check
run is paired when a verified attestation from the same workflow run (certificate Run Invocation
URI, OID 1.3.6.1.4.1.57264.1.21) names the check's external_id, carries checkRunId = the check's ID
and the check's head SHA, and has the outcome that matches the conclusion."""
import re

from .verify import parse_time

PREDICATE_FOR_CHECK = {
    "sox/evidence-gate": "gate-decision",
    "sox/review-agent": "review-verdict",
    "sox/qa-agent": "qa-result",
    "sox/security-scan": "security-scan",
}


def _passes(name, p):
    if name == "gate-decision":
        return p.get("conclusion") == "success"
    if name == "review-verdict":
        return p.get("verdict") == "pass" and p.get("outcome", "pass") == "pass"
    if name == "qa-result":
        return p.get("outcome") == "pass"
    if name == "security-scan":
        return p.get("result") == "pass"
    return False


def run_of(att, repo):
    """(runId, attempt) from the certificate's Run Invocation URI, or None."""
    uri = (getattr(att, "identity", None) or {}).get("runInvocationURI") or ""
    m = re.fullmatch(r"https://github\.com/([^/]+/[^/]+)/actions/runs/([0-9]+)/attempts/([0-9]+)", uri)
    if not m or m.group(1).lower() != repo.lower():
        return None
    return m.group(2), int(m.group(3))


def pair(check, head, candidates, repo):
    """(attestation or None, reason) for one check run against verified attestations of the
    check's predicate bound to the head."""
    name = PREDICATE_FOR_CHECK.get(check.get("name"))
    ext = str(check.get("external_id") or "")
    if not name:
        return None, f"no paired predicate for {check.get('name')}"
    if not ext.isdigit():
        return None, f"external_id {ext!r} is not a workflow run id"
    seen = []
    for a in candidates:
        if a.name != name:
            continue
        run = run_of(a, repo)
        p = a.predicate
        if run is None or run[0] != ext:
            continue
        if p.get("checkRunId") != check.get("id"):
            seen.append(f"{a.digest[:19]} from run {ext} has checkRunId {p.get('checkRunId')!r}")
            continue
        if p.get("headSha") != head:
            seen.append(f"{a.digest[:19]} from run {ext} is for head {str(p.get('headSha'))[:12]}")
            continue
        if not _passes(name, p):
            seen.append(f"{a.digest[:19]} from run {ext} does not record a pass")
            continue
        return a, f"paired with {name} {a.digest} from run {ext}"
    return None, (f"no verified {name} from run {ext} with checkRunId {check.get('id')} for head "
                  f"{head[:12]}" + (f" ({'; '.join(seen)})" if seen else ""))


def started(check):
    try:
        return parse_time(check.get("started_at"))
    except (TypeError, ValueError):
        return None


def record(check, app_id, att):
    """merge-record.checks[] entry."""
    return {"name": check.get("name"), "checkRunId": check.get("id"), "appId": app_id,
            "conclusion": check.get("conclusion") if check.get("status") == "completed" else None,
            "externalId": None if check.get("external_id") is None else str(check.get("external_id")),
            "pairedAttestation": att.digest if att is not None else None, "paired": att is not None}
