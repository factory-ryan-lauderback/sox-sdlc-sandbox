"""Agent check runs under the gate's every-run-binds rule (F13).

The gate requires every `sox/review-agent` / `sox/qa-agent` check run that the pinned App created on a
head to be completed with `success`. A cancelled, failed, neutral or unfinished run blocks that head for
good, and only a new commit clears it. So the agents:

- create a check run only once a verdict exists and is about to be attested (or is already attested);
- never create one for an infrastructure failure before judging (no verdict, token or API errors);
- create a run in_progress only immediately before `actions/attest`, so the window in which a crash
  can leave an unfinished run is the attest step alone;
- complete a stale in_progress run whose verdict did get attested (heal) instead of adding another.
"""
import time

from common import REPO


def app_runs(gh, head, name, app_id):
    """All check runs named `name` on `head` created by App `app_id` (read with a read-only token)."""
    res = gh.get(f"/repos/{REPO}/commits/{head}/check-runs?check_name={name}&filter=all&per_page=100")
    if res.get("total_count", 0) > len(res.get("check_runs", [])):
        raise RuntimeError(f"more than one page of {name} check runs on {head}; refusing to judge on a partial list")
    return [r for r in res["check_runs"] if (r.get("app") or {}).get("id") == app_id]


def head_state(runs):
    """none | passed | burned | open. `open` means unfinished runs and nothing completed non-success."""
    if not runs:
        return "none"
    if any(r["status"] == "completed" and r.get("conclusion") != "success" for r in runs):
        return "burned"
    if any(r["status"] != "completed" for r in runs):
        return "open"
    return "passed"


def _retry(fn, attempts=4):
    for i in range(attempts):
        try:
            return fn()
        except RuntimeError as e:
            # 4xx other than rate limits are not transient; re-raising keeps the failure visible.
            transient = any(f"HTTP {c}" in str(e) for c in (403, 429, 500, 502, 503, 504)) or "URLError" in str(e)
            if i == attempts - 1 or not transient:
                raise
            time.sleep(3 * (i + 1))


def start(gh, name, head, external_id):
    """Create the in_progress run. A POST whose response was lost may still have created a run, and a
    second one would be an orphan that blocks the head, so every retry first looks for the first."""
    def find():
        res = gh.get(f"/repos/{REPO}/commits/{head}/check-runs?check_name={name}&filter=all&per_page=100")
        return next((r["id"] for r in res["check_runs"] if r.get("external_id") == external_id), None)

    def attempt():
        found = find()
        if found:
            return found
        return gh.request("POST", f"/repos/{REPO}/check-runs",
                          {"name": name, "head_sha": head, "status": "in_progress", "external_id": external_id})["id"]
    return _retry(attempt)


def complete(gh, name, head, conclusion, title, summary, text, run_id=None, external_id=None):
    body = {"status": "completed", "conclusion": conclusion,
            "output": {"title": title[:250], "summary": summary[:60000] or title[:250], "text": text[:60000]}}
    if run_id:
        return _retry(lambda: gh.request("PATCH", f"/repos/{REPO}/check-runs/{run_id}", body))
    if external_id:
        body["external_id"] = external_id
    return _retry(lambda: gh.request("POST", f"/repos/{REPO}/check-runs", {"name": name, "head_sha": head, **body}))
