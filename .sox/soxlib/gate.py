"""sox/evidence-gate evaluation (evidence spec section 6). Deterministic, no LLM.

Inputs are only a PR number (lookup hint). Everything else is read from the GitHub API, git
data, and verified attestations. Each requirement is reported; the conclusion is `success` only
if every requirement passes, otherwise `failure`. The reconciler calls the same evaluation with
`as_of` set to the merge time.
"""
import datetime as dt
import re
import time
import urllib.parse

from . import jcs
from .verify import parse_time

STORY_RE = re.compile(r"^(story|qa-fix)/(FRQ-[0-9]{1,9})-[A-Za-z0-9._-]+$")
RELEASE_RE = re.compile(r"^release/([a-z0-9][a-z0-9._-]{0,63})$")
HOTFIX_RE = re.compile(r"^hotfix/(FRQ-[0-9]{1,9})-[A-Za-z0-9._-]+$")
NOT_PASSING = {"neutral", "skipped", "cancelled", "stale", "action_required", "timed_out",
               "startup_failure", "failure", None}
PASSED = {"passed", "pass"}
MAX_COMMITS = 250
MAX_FILES = 3000


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Req:
    __slots__ = ("id", "control", "ok", "detail", "evidence")

    def __init__(self, rid, control, ok, detail="", evidence=None):
        self.id, self.control, self.ok = rid, control, bool(ok)
        self.detail, self.evidence = detail, list(evidence or [])

    def to_json(self):
        return {"id": self.id, "control": self.control,
                "result": "pass" if self.ok else "fail", "detail": self.detail,
                "evidence": self.evidence}


class PRData:
    """Everything the gate reads about one PR, from the API only."""

    def __init__(self, ctx, number):
        api, r = ctx.api, ctx.repo
        self.number = int(number)
        self.pr = api.get(f"/repos/{r}/pulls/{self.number}")
        self.head = self.pr["head"]["sha"]
        self.base_ref = self.pr["base"]["ref"]
        self.head_ref = self.pr["head"]["ref"]
        self.head_repo = (self.pr["head"].get("repo") or {}).get("full_name")
        self.too_big = (self.pr.get("commits", 0) > MAX_COMMITS
                        or self.pr.get("changed_files", 0) > MAX_FILES)
        self.commits = api.paginate(f"/repos/{r}/pulls/{self.number}/commits", limit=MAX_COMMITS + 1)
        self.files = api.paginate(f"/repos/{r}/pulls/{self.number}/files", limit=MAX_FILES + 1)
        self.reviews = api.paginate(f"/repos/{r}/pulls/{self.number}/reviews")
        self.timeline = api.paginate(f"/repos/{r}/issues/{self.number}/timeline")
        ref = urllib.parse.quote(f"refs/heads/{self.head_ref}", safe="")
        self.activity = api.paginate(f"/repos/{r}/activity?ref={ref}&direction=asc")
        self.merged_at = parse_time(self.pr.get("merged_at")) if self.pr.get("merged_at") else None

    @property
    def paths(self):
        out = set()
        for f in self.files:
            out.add(f["filename"])
            if f.get("previous_filename"):
                out.add(f["previous_filename"])
        return sorted(out)

    def pushes(self):
        return [a for a in self.activity
                if a.get("activity_type") in ("push", "force_push", "branch_creation", "pr_merge",
                                              "merge_queue_merge")]


class Context:
    def __init__(self, policy, api, evidence, mirror=None, services=None, now=None):
        self.policy, self.api, self.ev, self.mirror = policy, api, evidence, mirror
        self.repo = policy.repo
        self.services = services or {}
        self.now = now or time.time()
        self._prs = {}
        self._story_results = {}
        self.participants = set()

    def prdata(self, n):
        if n not in self._prs:
            self._prs[n] = PRData(self, n)
        return self._prs[n]

    def services_touched(self, paths):
        touched, unmapped = set(), []
        for p in paths:
            hit = False
            for name, spec in self.services.items():
                for pat in spec.get("paths", []):
                    pre = pat[:-2] if pat.endswith("/**") else pat
                    if p == pre or p.startswith(pre.rstrip("/") + "/"):
                        touched.add(name)
                        hit = True
            if not hit:
                unmapped.append(p)
        return sorted(touched), unmapped

    def check_runs(self, sha):
        data = self.api.get(f"/repos/{self.repo}/commits/{sha}/check-runs?per_page=100&filter=all")
        return data.get("check_runs", [])


def classify(pd, policy):
    if pd.base_ref == "main":
        if RELEASE_RE.match(pd.head_ref):
            return "release"
        if HOTFIX_RE.match(pd.head_ref):
            return "emergency"
        return "invalid-main"
    if RELEASE_RE.match(pd.base_ref) and STORY_RE.match(pd.head_ref):
        return "story"
    return "invalid"


def _base_ok(a, pd):
    p = a.predicate
    return (p.get("prNumber") == pd.number and p.get("headSha") == pd.head
            and p.get("baseRef") == f"refs/heads/{pd.base_ref}")


class Evaluation:
    def __init__(self, ctx, pd, as_of=None):
        self.ctx, self.pd, self.as_of = ctx, pd, as_of
        self.policy = ctx.policy
        self.reqs = []
        self.facts = {"stories": [], "epics": {}, "upstream": {}}
        self.kind = classify(pd, ctx.policy)

    # ---------- helpers ----------
    def req(self, rid, control, ok, detail="", evidence=None):
        r = Req(rid, control, ok, detail, evidence)
        self.reqs.append(r)
        return r

    def use(self, label, att):
        if att is not None:
            self.facts["upstream"][label] = att.digest
        return att

    def get(self, kind, ident, pred, where=None):
        return self.ctx.ev.latest(kind, ident, pred, where=where, before=self.as_of)

    def all(self, kind, ident, pred):
        return self.ctx.ev.get(kind, ident, pred, before=self.as_of)

    @property
    def ok(self):
        return bool(self.reqs) and all(r.ok for r in self.reqs)

    # ---------- entry ----------
    def run(self):
        pd, pol = self.pd, self.policy
        self.req("CC-02.repo", "CC-02", pd.head_repo == pol.repo,
                 f"head repository {pd.head_repo}")
        self.req("CC-02.size", "CC-02", not pd.too_big,
                 f"{pd.pr.get('commits')} commits, {pd.pr.get('changed_files')} files "
                 f"(limits {MAX_COMMITS}/{MAX_FILES}; larger PRs fail closed)")
        if self.as_of is None:
            # One check run covers a SHA, so a head shared by two open PRs would let one PR's
            # evidence pass the other.
            shared = sorted(p["number"] for p in
                            self.ctx.api.get(f"/repos/{pol.repo}/commits/{pd.head}/pulls")
                            if p.get("state") == "open" and p.get("number") != pd.number
                            and (p.get("head") or {}).get("sha") == pd.head)
            self.req("CC-02.unique-head", "CC-02", not shared,
                     f"other open PRs with the same head: {shared}" if shared else
                     "no other open PR has this head")
        if self.kind == "invalid-main":
            self.req("F5.topology", "SDLC-10", False,
                     f"PR into main from {pd.head_ref!r}: only release/<slug> or hotfix/FRQ-n-* "
                     "may target main, and a PR based on main always needs release evidence")
            return self
        if self.kind == "invalid":
            self.req("TOPOLOGY", "SDLC-05", False,
                     f"{pd.head_ref!r} -> {pd.base_ref!r} is not story/qa-fix -> release/<slug>")
            return self
        self.check_agent_approvals()
        if self.kind == "story":
            self.eval_story()
        else:
            self.eval_release()
        return self

    # ---------- SDLC-05 pushers ----------
    def check_pushers(self, pd, branch_kind):
        pol = self.policy
        allowed = {pol.bot_login(role) for role in (pol.data.get("pushers") or {}).get(branch_kind, [])}
        pushes = pd.pushes()
        actors = sorted({(a.get("actor") or {}).get("login") for a in pushes})
        bad = [a for a in actors if a not in allowed]
        if pd.number == self.pd.number:
            self.facts["pushers"] = actors
            self.facts["firstPushAt"] = min((parse_time(a["timestamp"]) for a in pushes), default=None)
        self.req(f"SDLC-05.pushers#{pd.number}", "SDLC-05", bool(pushes) and not bad,
                 f"pushers to {pd.head_ref}: {actors or 'none recorded'}; allowed {sorted(allowed)}")
        return actors

    def check_agent_approvals(self):
        pol = self.policy
        writers = {pol.bot_login(r) for r in ("dev", "qa", "bundler")}
        bad = [r["user"]["login"] for r in self.pd.reviews
               if r.get("state") == "APPROVED" and (r.get("user") or {}).get("login") in writers]
        self.req("CC-08.agent-approve", "CC-08", not bad,
                 f"APPROVE reviews by agent Apps with contents:write: {bad}" if bad else
                 "no agent App with contents:write approved")

    # ---------- story chain (SDLC-01..04) ----------
    def story_chain(self, story, slug, first_push_at, tag=""):
        pol = self.policy
        t = f"#{story}" + tag
        plan = self.get("jira", story, "techlead-plan",
                        where=lambda a: any(s.get("key") == story for s in a.predicate.get("stories", [])))
        self.use(f"techlead-plan:{story}", plan)
        if plan is None:
            self.req(f"SDLC-03.plan{t}", "SDLC-03", False, f"missing: techlead-plan covering {story}")
            return None
        p = plan.predicate
        sentry = next(s for s in p.get("stories", []) if s.get("key") == story)
        tl = pol.data["jira"]["agentAccounts"]["techlead"]
        early = first_push_at is None or plan.integrated_time < first_push_at
        self.req(f"SDLC-03.plan{t}", "SDLC-03",
                 sentry.get("creator") == tl and early and p.get("planDigest"),
                 f"plan {p.get('planDigest')} for epic {p.get('epicKey')}, story creator "
                 f"{sentry.get('creator')}, plan at {plan.time_iso}, first push "
                 f"{iso(first_push_at) if first_push_at else 'n/a'}", [plan.digest])
        epic = p.get("epicKey")
        self.facts["epics"][epic] = {"planDigest": p.get("planDigest"), "plan": plan.digest,
                                     "requiredTests": sorted({x for s in p.get("stories", [])
                                                              for x in s.get("requiredTests", [])})}
        pm = self.get("jira", epic, "pm-decomposition",
                      where=lambda a: any(e.get("key") == epic for e in a.predicate.get("epics", [])))
        self.use(f"pm-decomposition:{epic}", pm)
        if pm is None:
            self.req(f"SDLC-02.pm{t}", "SDLC-02", False, f"missing: pm-decomposition for {epic}")
            return plan
        e = next(x for x in pm.predicate["epics"] if x.get("key") == epic)
        pmacct = pol.data["jira"]["agentAccounts"]["pm"]
        self.req(f"SDLC-02.pm{t}", "SDLC-02", e.get("creator") == pmacct,
                 f"epic {epic} creator {e.get('creator')} (expected {pmacct}), requirement "
                 f"{pm.predicate.get('requirementKey')}", [pm.digest])
        rk, rdig = pm.predicate.get("requirementKey"), pm.predicate.get("requirementContentDigest")
        ra = self.get("jira", rk, "requirement-approval",
                      where=lambda a: a.predicate.get("issueKey") == rk
                      and a.predicate.get("contentDigest") == rdig) if rk else None
        self.use(f"requirement-approval:{rk}", ra)
        if ra is None:
            self.req(f"SDLC-01.req{t}", "SDLC-01", False,
                     f"missing: requirement-approval {rk} with content digest {rdig}")
        else:
            q = ra.predicate
            agents = set(pol.data["jira"]["agentAccounts"].values())
            po = pol.data["jira"]["groups"]["productOwners"]
            ok = (q.get("approver") and q.get("approver") != q.get("reporter")
                  and q.get("approver") not in agents and po in (q.get("approverGroups") or [])
                  and ra.integrated_time <= pm.integrated_time)
            self.req(f"SDLC-01.req{t}", "SDLC-01", ok,
                     f"{rk} approved by {q.get('approver')} (reporter {q.get('reporter')}, groups "
                     f"{q.get('approverGroups')}) at {ra.time_iso}", [ra.digest])
        if "risk-high" in (p.get("epicLabels") or []):
            aa = self.get("jira", epic, "approach-approval",
                          where=lambda a: a.predicate.get("planDigest") == p.get("planDigest"))
            self.req(f"SDLC-03b.approach{t}", "SDLC-03", aa is not None and
                     aa.predicate.get("approver") in pol.humans("techLeads"),
                     "risk-high epic needs approach-approval of the current plan digest",
                     [aa.digest] if aa else [])
        if slug:
            man = self.get("release", slug, "release-manifest")
            self.use(f"release-manifest:{slug}", man)
            self.req(f"SDLC-04.manifest{t}", "SDLC-04",
                     man is not None and story in (man.predicate.get("stories") or []),
                     f"release {slug} manifest lists {story}" if man else
                     f"missing: release-manifest for {slug}", [man.digest] if man else [])
        return plan

    def review_verdict(self, pd, tag=""):
        pol = self.policy
        rid = pol.app_id("review")
        every = [a for a in self.all("commit", pd.head, "review-verdict")
                 if a.predicate.get("headSha") == pd.head]
        # Any-fail-wins per head (BP-41): an LLM verdict cannot be re-rolled by re-dispatching
        # the reviewer on the same head; only a new head can clear a failing verdict.
        fails = [a for a in every if a.predicate.get("verdict") != "pass"
                 or a.predicate.get("outcome") != "pass"]
        atts = [a for a in every if _base_ok(a, pd)]
        latest = atts[-1] if atts else None
        self.use(f"review-verdict:{pd.number}", latest)
        ok = (latest is not None and not fails and latest.predicate.get("verdict") == "pass"
              and latest.predicate.get("outcome") == "pass" and rid is not None
              and latest.predicate.get("reviewerAppId") == rid
              and latest.predicate.get("authorAppId") not in (None, rid))
        self.req(f"SDLC-06.review#{pd.number}{tag}", "SDLC-06", ok,
                 "latest verified review-verdict for head "
                 f"{pd.head[:12]}: {latest.predicate.get('verdict') if latest else 'missing'}"
                 + (f"; {len(fails)} failing verdict(s) for this head (any fail blocks the head)"
                    if fails else "")
                 + ("" if rid else " (review App id not pinned in trust policy)"),
                 [a.digest for a in ([latest] if latest else []) + fails])
        return latest

    def required_check(self, sha, name, role):
        app_id = self.policy.app_id(role)
        runs = [c for c in self.ctx.check_runs(sha) if c.get("name") == name]
        mine = [c for c in runs if (c.get("app") or {}).get("id") == app_id and app_id]
        if self.as_of is not None:
            mine = [c for c in mine if c.get("completed_at")
                    and parse_time(c["completed_at"]) <= self.as_of]
        mine.sort(key=lambda c: (c.get("started_at") or "", c.get("id")))
        latest = mine[-1] if mine else None
        others = sorted({(c.get("app") or {}).get("slug") for c in runs} - {self.policy.app(role).get("slug")})
        ok = latest is not None and latest.get("conclusion") == "success"
        self.req(f"CC-02.check:{name}", "CC-02", ok,
                 f"latest {name} from {self.policy.app(role).get('slug')}: "
                 f"{latest.get('conclusion') if latest else 'missing'}"
                 + (f"; same-named checks from other sources ignored: {others}" if others else ""))

    def loop_review(self, story):
        pol = self.policy
        mx = pol.loops.get("maxReviewRounds", 10)
        replans = [a for a in self.all("jira", story, "techlead-plan")
                   if a.predicate.get("replanApprovedBy") in pol.humans("techLeads")]
        since = replans[-1].integrated_time if replans else None
        rounds = [a for a in self.all("jira", story, "review-verdict")
                  if a.predicate.get("outcome") == "changes_requested"
                  and (since is None or a.integrated_time > since)]
        n = len({a.predicate.get("headSha") or a.digest for a in rounds})
        self.facts.setdefault("rounds", {})[story] = n
        self.req(f"LOOP-R#{story}", "LOOP-R", n < mx,
                 f"{n} heads with a verified changes_requested verdict for {story} since the "
                 "last human re-plan"
                 + (" (loop-exhausted)" if n >= mx else ""))
        return n, mx

    # ---------- story PR ----------
    def eval_story(self):
        pd = self.pd
        kind, story = STORY_RE.match(pd.head_ref).groups()
        slug = RELEASE_RE.match(pd.base_ref).group(1)
        self.facts.update({"story": story, "release": slug, "stories": [story]})
        self.check_pushers(pd, kind)
        plan = self.story_chain(story, slug, self.facts.get("firstPushAt"))
        touched, unmapped = self.ctx.services_touched(pd.paths)
        self.facts["servicesTouched"] = touched
        man = self.get("release", slug, "release-manifest")
        declared = set((man.predicate.get("declaredServices") if man else None) or [])
        self.req("SDLC-04.scope", "SDLC-04", man is not None and set(touched) <= declared,
                 f"services touched {touched}, declared {sorted(declared)}")
        if plan is not None:
            dep = next((s for s in plan.predicate.get("stories", []) if s.get("key") == story), {})
            missing = []
            merges = []
            for d in dep.get("dependsOn") or []:
                m = self.ctx.api.paginate(
                    f"/repos/{self.ctx.repo}/pulls?state=closed&base={urllib.parse.quote(pd.base_ref, safe='')}")
                hit = [x for x in m if x.get("merged_at") and STORY_RE.match(x["head"]["ref"])
                       and STORY_RE.match(x["head"]["ref"]).group(2) == d]
                if hit:
                    merges.append({"storyKey": d, "mergeSha": hit[0]["merge_commit_sha"]})
                else:
                    missing.append(d)
            self.facts["dependencyMerges"] = merges
            self.req("SDLC-05.deps", "SDLC-05", not missing,
                     f"dependencies not merged into {pd.base_ref}: {missing}" if missing
                     else f"dependencies merged: {[m['storyKey'] for m in merges]}")
        self.review_verdict(pd)
        self.required_check(pd.head, "sox/review-agent", "review")
        self.loop_review(story)

    # ---------- release / emergency PR ----------
    def eval_release(self):
        pd, pol, ctx = self.pd, self.policy, self.ctx
        emergency = self.kind == "emergency"
        if emergency:
            key = HOTFIX_RE.match(pd.head_ref).group(1)
            slug = None
            self.facts.update({"emergency": key, "stories": [key]})
            ec = self.get("jira", key, "emergency-change")
            self.use(f"emergency-change:{key}", ec)
            self.req("CC-04.ecab", "CC-04", ec is not None and
                     ec.predicate.get("ecabApprover") in pol.humans("ecab"),
                     f"emergency-change {key} approved by "
                     f"{ec.predicate.get('ecabApprover') if ec else 'missing'}")
            self.check_pushers(pd, "hotfix")
        else:
            slug = RELEASE_RE.match(pd.head_ref).group(1)
            self.facts["release"] = slug
            self.check_pushers(pd, "release")
            self.release_commits(slug)
        self.refresh_plans()
        stories = self.facts["stories"]
        man = self.get("release", slug, "release-manifest") if slug else None
        if slug:
            self.use(f"release-manifest:{slug}", man)
            listed = set((man.predicate.get("stories") if man else None) or [])
            extra = sorted(set(stories) - listed)
            touched, _ = ctx.services_touched(pd.paths)
            declared = set((man.predicate.get("declaredServices") if man else None) or [])
            self.facts["servicesTouched"] = touched
            self.req("SDLC-04.release-scope", "SDLC-04",
                     man is not None and not extra and set(touched) <= declared,
                     f"stories {stories} (not in manifest: {extra}); services {touched} vs "
                     f"declared {sorted(declared)}", [man.digest] if man else [])
        self.review_verdict(pd)
        self.required_check(pd.head, "sox/review-agent", "review")
        self.required_check(pd.head, "sox/qa-agent", "qa")
        env = self.get("commit", pd.head, "env-deploy",
                       where=lambda a: a.predicate.get("headSha") == pd.head
                       and a.predicate.get("environment") == "qa")
        self.use("env-deploy", env)
        self.req("SDLC-07.env", "SDLC-07", env is not None,
                 f"env-deploy of {pd.head[:12]} to qa: "
                 f"{env.predicate.get('envId') if env else 'missing'}", [env.digest] if env else [])
        required = sorted({t for e in self.facts["epics"].values() for t in e["requiredTests"]})
        qa = self.get("commit", pd.head, "qa-result", where=lambda a: _base_ok(a, pd))
        self.use("qa-result", qa)
        qa_fails = [a for a in self.all("commit", pd.head, "qa-result")
                    if a.predicate.get("headSha") == pd.head and a.predicate.get("outcome") != "pass"]
        if qa_fails:
            self.req("SDLC-08.qa-any-fail", "SDLC-08", False,
                     f"{len(qa_fails)} verified failing qa-result(s) for head {pd.head[:12]}; any "
                     "fail blocks the head until a new head is tested", [a.digest for a in qa_fails])
        if qa is None:
            self.req("SDLC-08.qa", "SDLC-08", False, f"missing: qa-result for {pd.head[:12]}")
        else:
            q = qa.predicate
            passed = {t.get("id") for t in q.get("tests", []) if t.get("status") in PASSED}
            missing = sorted(set(required) - passed)
            ed = q.get("envDeploy") or {}
            mode_ok = q.get("mode") == "full" or (emergency and q.get("mode") == "emergency-smoke")
            ok = (q.get("outcome") == "pass" and q.get("requiredCoverage") in (1, 1.0)
                  and not missing and set(required) <= set(q.get("requiredTests") or [])
                  and env is not None and ed.get("headSha") == pd.head
                  and ed.get("digest") == env.digest and mode_ok and q.get("reportDigest"))
            self.req("SDLC-08.qa", "SDLC-08", ok,
                     f"qa-result {q.get('outcome')}, mode {q.get('mode')}, coverage "
                     f"{q.get('requiredCoverage')}, plan-required tests not passed: {missing}, "
                     f"envDeploy {'matches' if env and ed.get('digest') == env.digest else 'does not match'}",
                     [qa.digest])
        self.loop_qa(slug)
        self.loop_human(slug)
        self.human_approval(emergency)

    def refresh_plans(self):
        """The release is judged against each epic's current plan, not the plan in force when a
        story merged: a re-plan changes the packet, the required tests, and clears LOOP-H."""
        for epic in sorted(self.facts["epics"]):
            plan = self.get("jira", epic, "techlead-plan",
                            where=lambda a, e=epic: a.predicate.get("epicKey") == e)
            if plan is None:
                continue
            self.use(f"techlead-plan:{epic}", plan)
            self.facts["epics"][epic] = {
                "planDigest": plan.predicate.get("planDigest"), "plan": plan.digest,
                "requiredTests": sorted({x for s in plan.predicate.get("stories", [])
                                         for x in s.get("requiredTests", [])})}

    def loop_human(self, slug):
        """LOOP-H. A Release Approver's or Control Owner's REQUEST_CHANGES binds the release (its
        head branch, slug and epics), not the PR: dismissing the review, dropping the event, or
        reopening a new PR from the same branch does not clear it (BP-39). Only a new plan for
        every epic, attested after the request, with a digest not used before, and a new head do."""
        pd, pol, api = self.pd, self.policy, self.ctx.api
        reviewers = set(pol.humans("releaseApprovers")) | set(pol.humans("controlOwners"))
        owner = pol.repo.split("/")[0]
        head = urllib.parse.quote(f"{owner}:{pd.head_ref}", safe="")
        prs = api.paginate(f"/repos/{pol.repo}/pulls?state=all&base=main&head={head}")
        if not any(p.get("number") == pd.number for p in prs):
            prs.append({"number": pd.number})
        crs = []
        for p in prs:
            n = p["number"]
            if n == pd.number:
                reviews, timeline = pd.reviews, pd.timeline
            else:
                reviews = api.paginate(f"/repos/{pol.repo}/pulls/{n}/reviews")
                timeline = api.paginate(f"/repos/{pol.repo}/issues/{n}/timeline")
            dismissed = {(e.get("dismissed_review") or {}).get("review_id") for e in timeline
                         if e.get("event") == "review_dismissed"
                         and str((e.get("dismissed_review") or {}).get("state", "")).lower()
                         == "changes_requested"}
            for r in reviews:
                u = r.get("user") or {}
                if u.get("login") not in reviewers or pol.human_id(u.get("login")) != u.get("id"):
                    continue
                if r.get("state") == "CHANGES_REQUESTED" or (
                        r.get("state") == "DISMISSED" and r.get("id") in dismissed):
                    crs.append({"pr": n, "reviewId": r.get("id"), "login": u.get("login"),
                                "commitId": r.get("commit_id"), "at": parse_time(r.get("submitted_at")),
                                "dismissed": r.get("state") == "DISMISSED"})
        kinds = [("release", slug)] if slug else [("pr", pd.number)]
        for kind, ident in kinds:
            for a in self.all(kind, ident, "human-changes-requested"):
                q = a.predicate
                crs.append({"pr": q.get("prNumber"), "reviewId": q.get("reviewId"),
                            "login": (q.get("reviewer") or {}).get("login"),
                            "commitId": q.get("commitId"),
                            "at": parse_time(q.get("submittedAt")) or a.integrated_time,
                            "attestation": a.digest})
        if self.as_of is not None:
            crs = [c for c in crs if c["at"] is not None and c["at"] <= self.as_of]
        self.facts["humanChangesRequested"] = [
            dict(c, at=iso(c["at"]) if c["at"] else None) for c in crs]
        if not crs:
            self.req("LOOP-H", "LOOP-H", True, "no human changes requested on this release")
            return
        last = max(c["at"] or 0 for c in crs)
        problems = []
        if pd.head in {c["commitId"] for c in crs}:
            problems.append(f"head {pd.head[:12]} received a changes-requested review; a new head "
                            "is required")
        if not self.facts["epics"]:
            problems.append("no epic plans found to re-plan")
        for epic in sorted(self.facts["epics"]):
            plans = [a for a in self.all("jira", epic, "techlead-plan")
                     if a.predicate.get("epicKey") == epic]
            used = {a.predicate.get("planDigest") for a in plans if a.integrated_time <= last}
            cur = plans[-1] if plans else None
            if cur is None or cur.integrated_time <= last or cur.predicate.get("planDigest") in used:
                problems.append(f"{epic}: no new techlead-plan (unused digest) after the last "
                                f"changes request at {iso(last)}")
        self.req("LOOP-H", "LOOP-H", not problems,
                 f"{len(crs)} human changes request(s), last {iso(last)}; "
                 + ("; ".join(problems) if problems else "re-planned and rebuilt since"),
                 sorted({c["attestation"] for c in crs if c.get("attestation")}))
    def release_commits(self, slug):
        pd, ctx = self.pd, self.ctx
        m = ctx.mirror
        if pd.merged_at and pd.pr.get("merge_commit_sha"):
            # As of merge: main is the merge commit's first parent, not today's tip.
            m.fetch_sha(pd.pr["merge_commit_sha"])
            main_sha = m.parents(pd.pr["merge_commit_sha"])[0]
        else:
            main_sha = ctx.api.get(f"/repos/{ctx.repo}/branches/main")["commit"]["sha"]
        m.fetch_sha(pd.head)
        mb = m.merge_base(main_sha, pd.head)
        self.facts["mergeBase"] = mb
        chain = m.first_parent_range(mb, pd.head)
        unexplained, story_prs = [], []
        for sha, parents in chain:
            pulls = ctx.api.get(f"/repos/{ctx.repo}/commits/{sha}/pulls")
            sp = [p for p in pulls if p.get("merge_commit_sha") == sha and p.get("merged_at")
                  and p["base"]["ref"] == pd.head_ref]
            if len(sp) == 1 and STORY_RE.match(sp[0]["head"]["ref"]):
                story_prs.append((sha, sp[0]["number"]))
                continue
            if len(parents) == 2 and m.is_ancestor(parents[1], main_sha):
                clean = m.clean_merge_tree(parents[0], parents[1])
                if clean is not None and clean == m.tree(sha):
                    continue
                unexplained.append(f"{sha[:12]} (sync from main with conflict resolution or edits)")
                continue
            unexplained.append(f"{sha[:12]} (not a story PR squash or clean sync)")
        self.req("SDLC-10.release-commits", "SDLC-10", not unexplained and bool(story_prs),
                 f"{len(story_prs)} story squash commits; unexplained: {unexplained}")
        for sha, n in story_prs:
            sub = self.story_pr(n)
            self.facts["stories"].append(sub.facts.get("story"))
            self.facts["epics"].update(sub.facts["epics"])
            self.facts.setdefault("storyPrs", []).append(
                {"pr": n, "squash": sha, "head": sub.pd.head, "story": sub.facts.get("story"),
                 "result": "pass" if sub.ok else "fail",
                 "failed": [r.id for r in sub.reqs if not r.ok]})
            gd = self.ctx.ev.latest("pr", n, "gate-decision",
                                    where=lambda a: a.predicate.get("headSha") == sub.pd.head
                                    and a.predicate.get("conclusion") == "success",
                                    before=sub.pd.merged_at)
            dc = self.ctx.ev.latest("pr", n, "dev-change",
                                    where=lambda a: a.predicate.get("headSha") == sub.pd.head,
                                    before=sub.pd.merged_at)
            merged_by = (sub.pd.pr.get("merged_by") or {}).get("login")
            self.req(f"SDLC-05.story-pr#{n}", "SDLC-05",
                     sub.ok and gd is not None and dc is not None
                     and merged_by == self.policy.bot_login("bundler"),
                     f"story PR #{n} ({sub.facts.get('story')}): re-evaluated "
                     f"{'pass' if sub.ok else 'fail ' + str([r.id for r in sub.reqs if not r.ok])}; "
                     f"gate-decision success before merge: {bool(gd)}; dev-change: {bool(dc)}; "
                     f"merged by {merged_by}", [x.digest for x in (gd, dc) if x])
            self.ctx.participants.update(sub.participants())

    def story_pr(self, n):
        if n not in self.ctx._story_results:
            pd = self.ctx.prdata(n)
            e = Evaluation(self.ctx, pd, as_of=pd.merged_at)
            self.ctx._story_results[n] = e.run()
        return self.ctx._story_results[n]

    def loop_qa(self, slug):
        mx = self.policy.loops.get("maxQaRounds", 10)
        seen = {}
        for kind, ident in (("pr", self.pd.number),) + ((("release", slug),) if slug else ()):
            for a in self.all(kind, ident, "qa-result"):
                if a.predicate.get("outcome") == "fail":
                    seen[a.predicate.get("headSha") or a.digest] = a
        n = len(seen)
        self.facts.setdefault("rounds", {})["qa"] = n
        self.req("LOOP-Q", "LOOP-Q", n < mx, f"{n} heads with a verified failing qa-result"
                 + (" (loop-exhausted)" if n >= mx else ""))

    def participants(self):
        pd = self.pd
        out = set()
        if pd.pr.get("user"):
            out.add(pd.pr["user"]["login"])
        for c in pd.commits:
            for k in ("author", "committer"):
                if c.get(k) and c[k].get("login"):
                    out.add(c[k]["login"])
        for a in pd.pushes():
            if a.get("actor"):
                out.add(a["actor"]["login"])
        return out

    def packet(self):
        f = self.facts
        up = f["upstream"]
        qa = up.get("qa-result")
        qa_att = None
        if qa:
            qa_att = next((a for a in self.all("commit", self.pd.head, "qa-result") if a.digest == qa), None)
        return {"prNumber": self.pd.number, "headSha": self.pd.head, "baseRef": "refs/heads/main",
                "planDigests": {k: v["planDigest"] for k, v in sorted(f["epics"].items())},
                "reviewVerdict": up.get(f"review-verdict:{self.pd.number}"),
                "envDeploy": up.get("env-deploy"), "qaResult": qa,
                "reportDigest": qa_att.predicate.get("reportDigest") if qa_att else None,
                "testFilesChangedByQa": sorted(qa_att.predicate.get("testFilesChangedByQa") or [])
                if qa_att else [],
                "controlChange": self.control_change(), "stories": sorted(set(f["stories"]))}

    def control_change(self):
        return any(self.policy.is_control_path(p) for p in self.pd.paths)

    def human_approval(self, emergency):
        pd, pol, ctx = self.pd, self.policy, self.ctx
        pre = [r for r in self.reqs if not r.ok]
        self.facts["packetReady"] = not pre
        packet = self.packet()
        pdig = jcs.digest(packet)
        self.facts["packet"], self.facts["packetDigest"] = packet, pdig
        if pre:
            self.req("SDLC-09.packet", "SDLC-09", False,
                     "approval packet not ready: earlier requirements fail")
            return
        shown = self.ctx.ev.get("pr", pd.number, "gate-decision", before=self.as_of)
        shown = [a for a in shown if a.predicate.get("packetDigest") == pdig
                 and a.predicate.get("headSha") == pd.head]
        presented_at = shown[0].integrated_time if shown else None
        self.facts["packetPresentedAt"] = iso(presented_at) if presented_at else None
        latest = {}
        for r in sorted(pd.reviews, key=lambda r: r.get("submitted_at") or ""):
            if r.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
                latest[(r.get("user") or {}).get("login")] = r
        approvers = set(pol.humans("releaseApprovers"))
        owners = set(pol.humans("controlOwners"))
        never = set(pol.humans("neverApprovers")) | set(pol.humans("platformAdmins"))
        participants = self.participants() | ctx.participants
        self.facts["participants"] = sorted(participants)
        base_changes = [parse_time(e.get("created_at")) for e in pd.timeline
                        if e.get("event") == "base_ref_changed" and e.get("created_at")]
        blocking = [l for l, r in latest.items() if r["state"] == "CHANGES_REQUESTED"
                    and l in approvers | owners]
        self.facts["changesRequested"] = [r for r in latest.values()
                                          if r["state"] == "CHANGES_REQUESTED"
                                          and r["user"]["login"] in approvers | owners]

        def qualifies(r, group):
            login = (r.get("user") or {}).get("login")
            sub = parse_time(r.get("submitted_at"))
            why = []
            if r.get("state") != "APPROVED":
                why.append("not approved")
            if r.get("commit_id") != pd.head:
                why.append("approved a different commit")
            if login not in group or pol.human_id(login) != (r.get("user") or {}).get("id"):
                why.append("not an authorized approver (login and user id)")
            if login in never:
                why.append("in neverApprovers")
            if login in participants:
                why.append("participated in the change")
            if presented_at is None or sub is None or sub <= presented_at:
                why.append("submitted before the approval packet for this SHA was presented")
            if any(t >= sub for t in base_changes if sub):
                why.append("base changed after the review")
            if self.as_of is not None and sub and sub > self.as_of:
                why.append("after merge")
            return why

        results = {l: qualifies(r, approvers) for l, r in latest.items()}
        good = [latest[l] for l, why in results.items() if not why]
        self.facts["approvalCandidates"] = {l: (why or ["ok"]) for l, why in results.items()}
        self.req("SDLC-09.approval", "SDLC-09", bool(good) and not blocking and pd.base_ref == "main",
                 (f"approved by {[r['user']['login'] for r in good]} on {pd.head[:12]}" if good else
                  "no qualifying approval: " + (str(self.facts["approvalCandidates"]) if latest else
                                                "awaiting Release Approver") +
                  ("" if presented_at else " (packet presented in this evaluation)"))
                 + (f"; outstanding changes requested by {blocking}" if blocking else ""))
        self.facts["approval"] = good[-1] if good else None
        if self.control_change():
            co = [r for r in good if r["user"]["login"] in owners]
            self.facts["sodShortcut"] = bool(co) and any(r["user"]["login"] in approvers for r in co)
            self.req("CC-03.control-owner", "CC-03", bool(co),
                     "control-path change approved by a Control Owner"
                     + (" (sod-shortcut: same person as Release Approver)" if self.facts["sodShortcut"] else "")
                     if co else "control-path change needs a Control Owner approval")


def evaluate(ctx, number, as_of=None):
    pd = ctx.prdata(number)
    return Evaluation(ctx, pd, as_of=as_of).run()
