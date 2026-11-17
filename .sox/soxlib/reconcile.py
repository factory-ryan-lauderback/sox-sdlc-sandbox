"""Reconciliation (evidence spec section 7), demo grade. Each run covers the whole population
from primary sources, not from the gate's own records:

  P1  every commit on main: the first-parent chain, each with the commits it brought in
  P2  PRs merged into main: count equals P1 merges; after go-live each is re-gated as of merge
  P5  App keys: the latest app-inventory artifact (computed inside each role's environment) is
      compared with the goLive.appKeys pins; the reconciler never holds another role's key
  P8  every check run the Gate, Review and QA Apps posted on any commit the mirror knows (all
      branches and refs/pull/*), since the Apps were created; each success must pair (spec 2.5)

Known exceptions are labels, not failures: app-key-exposed-not-rotated on every item while the
keys are not rotated, sod-shortcut-owner-approver where a merge-record carries it, and
bootstrap-pre-go-live for merges before goLive.at. Open exceptions get EXC ids. P3, P4, P6, P7,
ruleset history and rule suites are listed under notImplemented."""
import datetime as dt
import hashlib

from . import jcs, pairing
from .verify import parse_time

SCHEMA = "sox/reconciliation-report/v1"
STALE_INVENTORY_SECONDS = 26 * 3600
PAIRED_APPS = ("gate", "review", "qa")
# app-inventory role names -> trust policy role names
INVENTORY_ROLES = {"release_bundler": "bundler", "evidence_writer": "evidenceWriter",
                   "jira_attestor": "jiraAttestor"}
BOOTSTRAP = "bootstrap-pre-go-live"
REQUIRED_STEPS = ["merge-record"]
NOT_IMPLEMENTED = [
    "P3 story PRs into release/** (covered per release by the gate's story chain)",
    "P4 production deploys", "P6 credential scans", "P7 emergency-retro timing",
    "P5 rulesets, ruleset history and rule suites (owner token gets 403; unverified)",
    "P8 checkRunId-to-check-run resolution for every verified predicate",
]


def iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def merkle_root(digests):
    """RFC 6962-style root (0x00 leaf / 0x01 node prefixes) over the sorted unique digests."""
    level = [hashlib.sha256(b"\x00" + d.encode()).digest() for d in sorted(set(digests))]
    if not level:
        return None
    while len(level) > 1:
        nxt = [hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest()
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return "sha256:" + level[0].hex()


def _time(s):
    try:
        return parse_time(s)
    except (TypeError, ValueError):
        return None


class Reconciler:
    def __init__(self, policy, api, ev, mirror, now, previous=None, inventory=None,
                 explained=None, evaluate=None, code_sha=None):
        """previous: last index entry ({id, digest, period_end, highWater?}) or None.
        inventory: parsed app-inventory.json or None. explained: {"checkRuns": [...],
        "runs": [...]} naming setup or red-team runs. evaluate(pr, merged_at) -> Evaluation."""
        self.policy, self.api, self.ev, self.mirror = policy, api, ev, mirror
        self.now, self.previous, self.inventory = now, previous, inventory
        self.explained = explained or {}
        self.evaluate, self.code_sha = evaluate, code_sha
        self.repo = policy.repo
        self.exceptions = []
        self.evidence_digests = set()
        self.labels = list(policy.key_labels)

    # ---------- helpers ----------
    def in_scope(self, t):
        """After go-live. The go-live merge itself (at == goLive.at) is the last bootstrap change."""
        gl = self.policy.go_live_at
        return gl is not None and t is not None and t > gl

    def exception(self, control, item, kind, reason):
        eid = f"EXC-{iso(self.now)[:10]}-{len(self.exceptions) + 1:02d}"
        self.exceptions.append({"id": eid, "control": control, "item": item, "kind": kind,
                                "reason": reason, "labels": list(self.labels)})
        return eid

    def git(self, *args):
        return self.mirror.run(*args).stdout

    # ---------- P1 / P2 ----------
    def main_rows(self):
        head = self.git("rev-parse", "refs/heads/main").strip()
        prev_main = ((self.previous or {}).get("highWater") or {}).get("mainSha")
        if prev_main and not self.mirror.is_ancestor(prev_main, head):
            self.exception("CC-06", f"commit:{prev_main}", "history-rewritten",
                           f"previous report's main {prev_main} is not an ancestor of {head}")
        prs = {}
        for p in self.api.paginate(f"/repos/{self.repo}/pulls?state=closed&base=main&per_page=100"):
            if p.get("merged_at") and p.get("merge_commit_sha"):
                prs[p["merge_commit_sha"]] = p
        rows = []
        go_live_sha = self.policy.go_live_sha if self.policy.go_live_at is not None else None
        bootstrap = True
        for line in self.git("rev-list", "--first-parent", "--parents", "--reverse",
                             "--format=%cI", head).splitlines():
            if line.startswith("commit "):
                sha, *parents = line.split()[1:]
                continue
            rows.append(self.main_row(sha, parents, line.strip(), prs.get(sha), bootstrap))
            if sha == go_live_sha:
                bootstrap = False
        if go_live_sha and bootstrap:
            self.exception("CC-06", f"commit:{go_live_sha}", "go-live-not-on-main",
                           f"goLive.mainSha {go_live_sha} is not on main's first-parent chain")
        on_chain = {r["sha"] for r in rows}
        merged = [p for p in prs.values()]
        off = sorted(p["number"] for p in merged if p["merge_commit_sha"] not in on_chain)
        for n in off:
            p = next(x for x in merged if x["number"] == n)
            if self.in_scope(_time(p["merged_at"])):
                self.exception("SDLC-10", f"pr:{n}", "merge-not-on-main",
                               f"merge commit {p['merge_commit_sha']} is not on main's first-parent chain")
        p1 = {"count": len(rows), "query": f"git rev-list --first-parent {head}",
              "reachableCommits": len({c for r in rows for c in r["commits"]} | on_chain)}
        p2 = {"count": len(merged), "mergesOnMain": sum(1 for r in rows if r["pr"] is not None),
              "mergedNotOnFirstParent": off}
        return head, rows, p1, p2

    def main_row(self, sha, parents, committed_at, pr, bootstrap=True):
        inner = []
        if len(parents) > 1:
            inner = [c for c in self.git("rev-list", f"{parents[0]}..{sha}").split() if c != sha]
        row = {"kind": "main-commit", "sha": sha, "parents": parents, "committedAt": committed_at,
               "pr": pr["number"] if pr else None, "mergedAt": pr["merged_at"] if pr else None,
               "commits": inner, "evidence": {}, "labels": list(self.labels),
               "result": None, "exception": None}
        records = self.ev.get("commit", sha, "merge-record")
        mr = records[-1] if records else None
        if mr is not None:
            row["evidence"]["merge-record"] = mr.digest
            self.evidence_digests.add(mr.digest)
            for label in mr.predicate.get("labels") or []:
                if label not in row["labels"]:
                    row["labels"].append(label)
        if bootstrap:
            row["result"] = "pass" if mr is not None else "bootstrap"
            row["exception"] = BOOTSTRAP
            if BOOTSTRAP not in row["labels"]:
                row["labels"].append(BOOTSTRAP)
            return row
        problems = []
        if pr is None:
            problems.append(("SDLC-10", "direct-push", "no merged PR has this commit as its merge commit"))
        if mr is None:
            problems.append(("SDLC-10", "merge-record-missing", "no verified merge-record for this commit"))
        else:
            p = mr.predicate
            if p.get("outcome") != "recorded" or not p.get("treeMatch") or not p.get("checksPaired"):
                problems.append(("SDLC-10", "merge-record-fail",
                                 f"merge-record outcome {p.get('outcome')!r}, treeMatch "
                                 f"{p.get('treeMatch')!r}, checksPaired {p.get('checksPaired')!r}"))
        if pr is not None and self.evaluate is not None:
            ev = self.evaluate(pr["number"], _time(pr["merged_at"]))
            failed = [r.id for r in ev.reqs if not r.ok]
            row["gateAsOfMerge"] = {"result": "pass" if ev.ok else "fail", "failed": failed}
            if not ev.ok:
                problems.append(("SDLC-10", "gate-reperformance-fail",
                                 f"independent gate re-run as of merge fails {failed}"))
        ids = [self.exception(c, f"commit:{sha}", k, why) for c, k, why in problems]
        row["result"] = "fail" if ids else "pass"
        row["exception"] = ", ".join(ids) or None
        return row

    # ---------- P5 ----------
    def app_keys(self):
        inv = self.inventory
        out = {"source": "app-inventory artifact", "runId": None, "at": None, "keys": []}
        if not inv:
            self.exception("CC-07", "app-inventory", "app-inventory-missing",
                           "no app-inventory artifact from main was found")
            return out
        out.update({"runId": inv.get("runId"), "at": inv.get("at")})
        at = _time(inv.get("at"))
        if at is None or self.now - at > STALE_INVENTORY_SECONDS:
            self.exception("CC-07", f"app-inventory:{inv.get('runId')}", "app-inventory-stale",
                           f"latest app-inventory is from {inv.get('at')}, older than 26 h")
        got = {INVENTORY_ROLES.get(a.get("role"), a.get("role")): a for a in inv.get("apps") or []}
        pins = self.policy.data["goLive"]["appKeys"]
        for role in sorted(k for k in pins if not k.startswith("$")):
            pin, a = pins[role], got.get(role)
            entry = {"role": role, "appId": pin.get("appId"), "pinned": pin.get("keyFingerprint"),
                     "observed": (a or {}).get("keyFingerprint"), "labels": list(self.labels)}
            if a is None:
                entry["result"] = "missing"
                self.exception("CC-07", f"app:{role}", "app-key-unobserved",
                               f"app-inventory {inv.get('runId')} has no entry for {role}")
            elif a.get("keyFingerprint") != pin.get("keyFingerprint") or a.get("appId") != pin.get("appId"):
                entry["result"] = "app-key-changed"
                self.exception("CC-07", f"app:{role}", "app-key-changed",
                               f"{role}: observed app {a.get('appId')} key {a.get('keyFingerprint')}, "
                               f"pinned app {pin.get('appId')} key {pin.get('keyFingerprint')}")
            else:
                entry["result"] = "match"
            out["keys"].append(entry)
        return out

    # ---------- P8 ----------
    def _explanation(self, c):
        for e in self.explained.get("checkRuns") or []:
            if e.get("checkRunId") == c.get("id"):
                return e
        for e in self.explained.get("runs") or []:
            if str(e.get("runId")) == str(c.get("external_id")):
                return e
        return None

    def check_runs(self):
        apps = {self.policy.app_id(r): r for r in PAIRED_APPS}
        shas = sorted(set(self.git("rev-list", "--all").split()))
        runs = {}
        for sha in shas:
            for c in self.api.paginate(f"/repos/{self.repo}/commits/{sha}/check-runs?filter=all&per_page=100",
                                       key="check_runs"):
                if (c.get("app") or {}).get("id") in apps:
                    runs[c["id"]] = c
        out = {"commitsScanned": len(shas), "count": len(runs), "success": 0, "paired": 0,
               "explained": 0, "unpaired": [], "byApp": {}, "lastCheckRunId": max(runs, default=None)}
        for cid in sorted(runs):
            c = runs[cid]
            role = apps[c["app"]["id"]]
            out["byApp"][role] = out["byApp"].get(role, 0) + 1
            if c.get("status") != "completed" or c.get("conclusion") != "success":
                continue
            out["success"] += 1
            att, why = pairing.pair(c, c["head_sha"], self.ev.get("commit", c["head_sha"]), self.repo)
            if att is not None:
                out["paired"] += 1
                self.evidence_digests.add(att.digest)
                continue
            item = {"checkRunId": cid, "name": c.get("name"), "app": role,
                    "headSha": c["head_sha"], "startedAt": c.get("started_at"),
                    "externalId": c.get("external_id"), "url": c.get("html_url"), "reason": why,
                    "labels": list(self.labels)}
            ex = self._explanation(c)
            if ex is not None:
                out["explained"] += 1
                item["explainedBy"] = {k: ex.get(k) for k in ("reason", "log")}
            elif self.in_scope(_time(c.get("started_at"))):
                item["exception"] = self.exception("CC-02", f"check-run:{cid}", "check-without-evidence", why)
            else:
                item["exception"] = self.exception(
                    "CC-02", f"check-run:{cid}", "unpaired-pre-go-live",
                    "success before go-live not explained by a named setup or red-team run: " + why)
            out["unpaired"].append(item)
        out["unexplainedUnpaired"] = sum(1 for u in out["unpaired"] if "exception" in u)
        out["goLiveReady"] = out["unexplainedUnpaired"] == 0
        return out

    # ---------- report ----------
    def report(self):
        head, rows, p1, p2 = self.main_rows()
        keys = self.app_keys()
        checks = self.check_runs()
        prev = self.previous
        if prev:
            # The chain is only as good as its links: the previous report must be a verified
            # reconciliation-report whose predicate is the indexed digest.
            atts = self.ev.get("report", prev["id"], "reconciliation-report")
            if not any(jcs.digest(a.predicate) == prev["digest"] for a in atts):
                self.exception("CC-06", f"report:{prev['id']}", "previous-report-unverified",
                               f"no verified reconciliation-report for {prev['id']} has digest "
                               f"{prev['digest']} ({len(atts)} verified for that subject)")
        genesis = rows[0]["committedAt"] if rows else iso(self.now)
        rid = iso(self.now)
        labels = sorted({l for r in rows for l in r["labels"]})
        known = [{"label": l, "kind": "known-exception"} for l in labels]
        return {
            "schema": SCHEMA, "id": rid, "repo": self.repo, "step": "CC-06",
            "actor": {"type": "github_app", "login": self.policy.bot_login("reconciler"),
                      "appId": self.policy.app_id("reconciler")},
            "outcome": "exceptions" if self.exceptions else "clean",
            # The CLI sets observedAt again right before signing (verifier skew check).
            "observedAt": iso(self.now),
            "period": {"from": prev["period_end"] if prev else genesis, "to": rid},
            "previousReport": prev["digest"] if prev else None,
            "highWater": {"mainSha": head,
                          "lastPrNumber": max((r["pr"] for r in rows if r["pr"]), default=None),
                          "lastCheckRunId": checks["lastCheckRunId"]},
            "reconcilerCodeSha": self.code_sha, "policyDigest": self.policy.digest,
            "goLive": {"at": iso(self.policy.go_live_at) if self.policy.go_live_at else None,
                       "mainSha": self.policy.go_live_sha,
                       "anchorPr": self.policy.data["goLive"].get("anchorPr")},
            "populations": {"P1": p1, "P2": p2,
                            "P5": {"count": len(keys["keys"])},
                            "P8": {k: checks[k] for k in ("commitsScanned", "count", "success",
                                                         "paired", "explained", "unexplainedUnpaired")}},
            "required_steps": REQUIRED_STEPS,
            "rows": rows, "appKeys": keys, "checkRuns": checks, "configDrift": [],
            "exceptions": self.exceptions, "knownExceptions": known,
            "openExceptions": len(self.exceptions),
            "bundleMerkleRoot": merkle_root(self.evidence_digests),
            "bundleMerkleLeaves": len(self.evidence_digests),
            "notImplemented": NOT_IMPLEMENTED,
        }


def index_entry(report, path, bundle_digest=None):
    return {"id": report["id"], "digest": jcs.digest(report), "prev_digest": report["previousReport"],
            "period_start": report["period"]["from"], "period_end": report["period"]["to"],
            "path": path, "attestationBundle": bundle_digest,
            "highWater": report["highWater"], "openExceptions": report["openExceptions"]}


def check_chain(index, report):
    """Problems that stop a report from being appended to index (a list of entries)."""
    last = index[-1] if index else None
    problems = []
    if last is None:
        if report["previousReport"] is not None:
            problems.append("index is empty but the report names a previous report")
        return problems
    if report["previousReport"] != last["digest"]:
        problems.append(f"report chains to {report['previousReport']}, index ends at {last['digest']}")
    if report["period"]["from"] != last["period_end"]:
        problems.append(f"period starts {report['period']['from']}, previous ended {last['period_end']}")
    if any(e["id"] == report["id"] for e in index):
        problems.append(f"report {report['id']} is already in the index")
    return problems
