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

from . import jcs, pairing
from .scope import ScopeMap, norm_digest
from .verify import parse_time

STORY_RE = re.compile(r"^(story|qa-fix)/(FRQ-[0-9]{1,9})-[A-Za-z0-9._-]+$")
RELEASE_RE = re.compile(r"^release/([a-z0-9][a-z0-9._-]{0,63})$")
JIRA_KEY_RE = re.compile(r"^[A-Z][A-Z0-9]{1,9}-[0-9]{1,9}$")
HOTFIX_RE = re.compile(r"^hotfix/(FRQ-[0-9]{1,9})-[A-Za-z0-9._-]+$")
NOT_PASSING = {"neutral", "skipped", "cancelled", "stale", "action_required", "timed_out",
               "startup_failure", "failure", None}
PASSED = {"passed", "pass"}
STORY_TYPES = ("dev", "qa")
MAX_COMMITS = 250
MAX_FILES = 3000
# A judging run can be queued (concurrency groups) for a while before its judging step starts on
# the current head; list runs created this long before the head was pushed.
JUDGING_QUEUE_MARGIN = 6 * 3600


def _judging_started(job, step):
    """Epoch at which the judging step (or the job, if step is None) started, or None if it never
    ran (queued, skipped)."""
    node = job
    if step:
        node = next((s for s in job.get("steps") or [] if s.get("name") == step), None)
        if node is None:
            return None
    if node.get("status") not in ("in_progress", "completed") or node.get("conclusion") == "skipped":
        return None
    try:
        return parse_time(node.get("started_at"))
    except (TypeError, ValueError):
        return None


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
        self.scope = services if isinstance(services, ScopeMap) else ScopeMap(services or {}, policy=policy)
        self.now = now or time.time()
        self._prs = {}
        self._story_results = {}
        self._release_slugs = None
        self.participants = set()
        # Set by evaluate(): the as-of time of the top-level PR, which decides whether the
        # chain is judged under the post-go-live rules (a story merged before go-live still
        # carries pre-rotation App actions into a release merged after it).
        self.top_as_of = None
        # The gate's own in-progress check run in this workflow run; gate-decision pairs with it.
        self.check_run_id = None
        self._wf_runs = {}
        self._jobs = {}
        # Actions API reads (workflow runs, jobs) may use a different read-only token.
        self.actions_api = api
    def prdata(self, n):
        if n not in self._prs:
            self._prs[n] = PRData(self, n)
        return self._prs[n]

    def scope_at(self, as_of):
        """Services map to judge a change with. The reconciler overrides this to use the map on
        main at the time of the merge."""
        return self.scope

    def services_touched(self, paths, as_of=None):
        return self.scope_at(as_of).touched(paths)

    def release_slugs(self):
        """Every release the repository has: release/* branches and release/* PRs into main."""
        if self._release_slugs is None:
            slugs = set()
            for b in self.api.paginate(f"/repos/{self.repo}/branches"):
                m = RELEASE_RE.match(b.get("name") or "")
                if m:
                    slugs.add(m.group(1))
            for p in self.api.paginate(f"/repos/{self.repo}/pulls?state=all&base=main"):
                m = RELEASE_RE.match((p.get("head") or {}).get("ref") or "")
                if m:
                    slugs.add(m.group(1))
            self._release_slugs = sorted(slugs)
        return self._release_slugs

    def check_runs(self, sha):
        data = self.api.get(f"/repos/{self.repo}/commits/{sha}/check-runs?per_page=100&filter=all")
        runs = data.get("check_runs", [])
        if (data.get("total_count") or 0) > len(runs):
            # Every run binds the head (F13); a partial list could hide a failing one.
            raise RuntimeError(f"{sha}: {data.get('total_count')} check runs, more than one page; "
                               "refusing a partial list")
        return runs

    def workflow_runs(self, workflow, since):
        """Runs of one workflow file created at or after `since` (epoch)."""
        k = (workflow, int(since))
        if k not in self._wf_runs:
            name = workflow.rsplit("/", 1)[-1]
            q = urllib.parse.quote(">=" + iso(max(0, since)), safe="")
            path = f"/repos/{self.repo}/actions/workflows/{name}/runs?created={q}&per_page=100"
            try:
                # The API caps filtered listings at 1000 runs; more fails closed in paginate.
                runs = self.actions_api.paginate(path, key="workflow_runs", limit=1000)
            except Exception as e:
                # A workflow file that is not on main yet has no runs (404). Only trust that 404
                # once the repository itself is readable with this token.
                if getattr(e, "status", None) != 404 or not hasattr(self.actions_api, "require_repo"):
                    raise
                self.actions_api.require_repo(self.repo)
                runs = []
            self._wf_runs[k] = [r for r in runs if (r.get("path") or workflow) == workflow]
        return self._wf_runs[k]

    def run_jobs(self, run_id):
        if run_id not in self._jobs:
            self._jobs[run_id] = self.actions_api.paginate(
                f"/repos/{self.repo}/actions/runs/{int(run_id)}/jobs?filter=all&per_page=100", key="jobs")
        return self._jobs[run_id]


def _jira_time(s):
    try:
        return parse_time(s)
    except (TypeError, ValueError):
        return None


def jira_human_approval(policy, pred, kind):
    """(ok, detail) for a human Jira approval, re-derived from the attested changelog: the latest
    transition into approvalStatuses[kind] after the last change to a content field (a later edit
    reopens the approval), by an atlassian account in humanApprovers[kind] that is not an
    automation or never-approver account, the reporter, or the creator."""
    j = policy.jira
    status = (j.get("approvalStatuses") or {}).get(kind)
    allowed = set((j.get("humanApprovers") or {}).get(kind) or [])
    if not status or not allowed:
        return False, f"jira.approvalStatuses/humanApprovers.{kind} not pinned in the trust policy"
    hist = pred.get("changelog")
    if not isinstance(hist, list):
        return False, "no Jira changelog in the attestation"
    fields = set(j.get("contentFields") or [])
    changed = [_jira_time(h.get("created")) for h in hist
               if any((i or {}).get("field") in fields for i in h.get("items") or [])]
    if any(c is None for c in changed):
        return False, "a content change in the changelog has no readable time"
    last_change = max(changed, default=None)
    moves = [h for h in hist if any((i or {}).get("field") == "status" and str((i or {}).get("to")) == str(status)
                                    for i in h.get("items") or [])]
    moves = [h for h in moves if _jira_time(h.get("created")) is not None
             and (last_change is None or _jira_time(h.get("created")) > last_change)]
    if not moves:
        return False, (f"no transition to status {status} after the last content change"
                       + (f" at {iso(last_change)}" if last_change else ""))
    h = max(moves, key=lambda h: (_jira_time(h.get("created")), str(h.get("id"))))
    author = h.get("author") or {}
    acct = author.get("accountId")
    why = []
    if author.get("accountType") != "atlassian":
        why.append(f"author accountType {author.get('accountType')!r} is not atlassian")
    if acct in set(j.get("neverApprovers") or []) or acct == j.get("sharedAutomationAccount"):
        why.append("author is an automation identity (jira.neverApprovers)")
    if acct not in allowed:
        why.append(f"author is not in jira.humanApprovers.{kind}")
    if acct in (pred.get("reporter"), pred.get("creator")):
        why.append("author is the issue's reporter or creator")
    return not why, (f"changelog entry {h.get('id')} moved to status {status} at {h.get('created')} "
                     f"by {acct}" + ("; " + "; ".join(why) if why else ""))


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
        self.gate_checks()
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
        self.pre_rotation_pushes(pd)
        return actors

    def check_agent_approvals(self):
        pol = self.policy
        writers = {pol.bot_login(r) for r in ("dev", "qa", "bundler")}
        bad = [r["user"]["login"] for r in self.pd.reviews
               if r.get("state") == "APPROVED" and (r.get("user") or {}).get("login") in writers]
        self.req("CC-08.agent-approve", "CC-08", not bad,
                 f"APPROVE reviews by agent Apps with contents:write: {bad}" if bad else
                 "no agent App with contents:write approved")

    def jira_agent(self, rid, entry, role):
        """An agent-created Jira issue: by the role's own account, or (sandbox) by the shared
        automation account with the acting role in the issue property and a comment prefix,
        which is weaker and marked jira-shared-identity."""
        j = self.policy.jira
        creator, shared = entry.get("creator"), j.get("sharedAutomationAccount")
        own = (j.get("agentAccounts") or {}).get(role)
        if creator and creator == own and creator != shared:
            return True, f"creator {creator} (agentAccounts.{role})"
        if creator and creator == shared:
            ok = entry.get("actingRole") == role and entry.get("actingRoleComment") is True
            if ok:
                self.facts.setdefault("jiraSharedIdentity", []).append(rid)
            return ok, (f"creator is the shared automation account, {j.get('actingRoleProperty')} "
                        f"{entry.get('actingRole')!r} (expected {role!r}), [sox:{role}] comment "
                        f"{'present' if entry.get('actingRoleComment') is True else 'missing'} "
                        "(jira-shared-identity)")
        return False, f"creator {creator!r} is neither agentAccounts.{role} nor the shared automation account"

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
        early = first_push_at is None or plan.integrated_time < first_push_at
        # The plan is the only source of a story's Dev/QA type, never Jira labels or issue types.
        stype = sentry.get("type")
        self.facts.setdefault("storyTypes", {})[story] = stype
        c_ok, c_detail = self.jira_agent(f"SDLC-03.plan{t}", sentry, "techlead")
        self.req(f"SDLC-03.plan{t}", "SDLC-03",
                 c_ok and early and p.get("planDigest") and stype in STORY_TYPES,
                 f"plan {p.get('planDigest')} for epic {p.get('epicKey')}, story type {stype!r} "
                 f"(dev or qa, from the plan), {c_detail}, plan at {plan.time_iso}, first push "
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
        c_ok, c_detail = self.jira_agent(f"SDLC-02.pm{t}", e, "pm")
        self.req(f"SDLC-02.pm{t}", "SDLC-02", c_ok,
                 f"epic {epic}: {c_detail}, requirement {pm.predicate.get('requirementKey')}",
                 [pm.digest])
        rk, rdig = pm.predicate.get("requirementKey"), pm.predicate.get("requirementContentDigest")
        ra = self.get("jira", rk, "requirement-approval",
                      where=lambda a: a.predicate.get("issueKey") == rk
                      and a.predicate.get("contentDigest") == rdig) if rk else None
        self.use(f"requirement-approval:{rk}", ra)
        if ra is None:
            self.req(f"SDLC-01.req{t}", "SDLC-01", False,
                     f"missing: requirement-approval {rk} with content digest {rdig}")
        else:
            a_ok, a_detail = jira_human_approval(pol, ra.predicate, "requirementApproval")
            in_order = ra.integrated_time <= pm.integrated_time
            self.req(f"SDLC-01.req{t}", "SDLC-01", a_ok and in_order,
                     f"{rk}: {a_detail}; attested {ra.time_iso}"
                     + ("" if in_order else " (after the pm-decomposition)"), [ra.digest])
        if "risk-high" in (p.get("epicLabels") or []):
            aa = self.get("jira", epic, "approach-approval",
                          where=lambda a: a.predicate.get("planDigest") == p.get("planDigest"))
            a_ok, a_detail = (jira_human_approval(pol, aa.predicate, "approachApproval") if aa else
                              (False, "missing: approach-approval of the current plan digest"))
            self.req(f"SDLC-03b.approach{t}", "SDLC-03", a_ok,
                     f"risk-high epic {epic} needs approach-approval of plan {p.get('planDigest')}: "
                     + a_detail, [aa.digest] if aa else [])
        return plan

    # ---------- SDLC-04 scope (every PR) ----------
    def check_scope(self, slug, stories):
        """unmapped-path, out-of-scope, manifest-stale, story-not-in-manifest,
        story-in-two-releases (BP-38a-f). Hotfixes (slug None) get the mapping check only."""
        pd, ctx = self.pd, self.ctx
        scope = ctx.scope_at(self.as_of)
        touched, unmapped = scope.touched(pd.paths)
        self.facts["servicesTouched"] = touched
        self.req("SDLC-04.unmapped-path", "SDLC-04", not unmapped,
                 f"paths that map to no service in .sox/services.yaml on main: {unmapped[:20]}"
                 + (f" (+{len(unmapped) - 20} more)" if len(unmapped) > 20 else "")
                 if unmapped else f"every changed path maps to a service: {touched}")
        if slug is None:
            return None
        man = self.get("release", slug, "release-manifest")
        self.use(f"release-manifest:{slug}", man)
        if man is None:
            self.req("SDLC-04.manifest", "SDLC-04", False, f"missing: release-manifest for {slug}")
            return None
        p = man.predicate
        declared = sorted(set(p.get("declaredServices") or []))
        listed = sorted(set(p.get("stories") or []))
        self.facts["manifest"] = {"digest": man.digest, "stories": listed,
                                  "declaredServices": declared}
        out = sorted(set(touched) - set(declared))
        self.req("SDLC-04.out-of-scope", "SDLC-04", not out,
                 f"services touched but not declared by release {slug}: {out}" if out else
                 f"services {touched} within declared {declared}", [man.digest])
        have, want = norm_digest(p.get("servicesMapDigest")), norm_digest(scope.digest)
        self.req("SDLC-04.manifest-stale", "SDLC-04", have is not None and have == want,
                 f"manifest servicesMapDigest {have} vs .sox/services.yaml on main {want}",
                 [man.digest])
        missing = sorted(set(stories) - set(listed))
        self.req("SDLC-04.story-not-in-manifest", "SDLC-04", not missing,
                 f"stories not in the {slug} manifest: {missing}" if missing else
                 f"stories {sorted(set(stories))} listed in the {slug} manifest", [man.digest])
        mine = set(stories) | set(listed)
        dup, seen = [], []
        for other in ctx.release_slugs():
            if other == slug:
                continue
            om = self.get("release", other, "release-manifest")
            if om is None:
                continue
            both = sorted(mine & set(om.predicate.get("stories") or []))
            if both:
                dup.append(f"{other}: {both}")
                seen.append(om.digest)
        self.req("SDLC-04.story-in-two-releases", "SDLC-04", not dup,
                 f"story keys also in another release's latest manifest: {dup}" if dup else
                 "no story key is in another release's latest manifest", seen)
        return man

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

    @property
    def carry_over(self):
        """Post-go-live rules apply: goLive.at is set and the top-level PR is open or merged at or
        after go-live (evidence spec 7.6)."""
        at = self.policy.go_live_at
        if at is None:
            return False
        top = getattr(self.ctx, "top_as_of", self.as_of)
        return top is None or top >= at

    def _split_rotation(self, runs, role):
        """(pre, post): runs started before the role's App key rotation are set aside (7.6): they
        neither pass nor bind the head; only a new evaluation after rotation does."""
        rot = self.policy.rotation_at(role) if self.carry_over else None
        # started_at is writable by whoever holds the App key, so a run can only be pre-rotation
        # if its head existed before the rotation; otherwise a backdated run would be set aside.
        if rot is None or self.head_pushed_at(self.pd) >= rot:
            return [], list(runs)
        pre = [c for c in runs if (pairing.started(c) or 0) < rot]
        return pre, [c for c in runs if c not in pre]

    def _pair_all(self, sha, name, role, runs, pre):
        """facts.checks[name] entries; returns {check id: attestation or None} for completed success."""
        pred = pairing.PREDICATE_FOR_CHECK[name]
        cands = self.all("commit", sha, pred)
        out, entries = {}, []
        for c in runs:
            att = None
            why = "not a success"
            if c.get("status") == "completed" and c.get("conclusion") == "success":
                att, why = pairing.pair(c, sha, cands, self.policy.repo)
                out[c.get("id")] = att
            e = dict(pairing.record(c, self.policy.app_id(role), att), headSha=sha,
                     preRotation=c in pre, startedAt=c.get("started_at"), detail=why)
            entries.append(e)
            if c in pre and att is None and c.get("conclusion") == "success":
                # Exposure finding (7.6 item 4), never an in-scope exception.
                self.facts.setdefault("preRotationUnpaired", []).append(e)
        self.facts.setdefault("checks", {}).setdefault(name, []).extend(entries)
        return out

    def required_check(self, sha, name, role):
        """Every run of the check by the role's App on this head binds it (F13, BP-41d): a run
        still in progress, cancelled, or failed before its verdict was attested is not cleared by
        a newer passing run, so re-dispatching the agent cannot re-roll the result. Every success
        must pair with a verified attestation from the same workflow run (F16, spec 2.5)."""
        app_id = self.policy.app_id(role)
        slug = self.policy.app(role).get("slug")
        runs = [c for c in self.ctx.check_runs(sha) if c.get("name") == name]
        mine = [c for c in runs if (c.get("app") or {}).get("id") == app_id and app_id]
        if self.as_of is not None:
            # Runs started after the merge could not have influenced it. A run without a start
            # time cannot be placed, so it counts.
            mine = [c for c in mine if not c.get("started_at")
                    or parse_time(c["started_at"]) <= self.as_of]
        mine.sort(key=lambda c: (c.get("started_at") or "", c.get("id") or 0))
        pre, post = self._split_rotation(mine, role)

        def state(c):
            done = c.get("completed_at")
            if c.get("status") != "completed" or not done:
                return f"not completed ({c.get('status')})"
            if self.as_of is not None and parse_time(done) > self.as_of:
                return "not completed at merge"
            return c.get("conclusion")
        bad = [f"run {c.get('id')}: {state(c)}" for c in post if state(c) != "success"]
        others = sorted({(c.get("app") or {}).get("slug") for c in runs} - {slug})
        ok = bool(post) and not bad
        self.req(f"CC-02.check:{name}", "CC-02", ok,
                 (f"{len(post)} {name} run(s) from {slug} on {sha[:12]}"
                  + (f"; not success (every run on the head binds it): {bad}" if bad else
                     ", all completed success" if post else ": missing"))
                 + (f"; {len(pre)} run(s) before the App key rotation set aside" if pre else "")
                 + (f"; same-named checks from other sources ignored: {others}" if others else ""))
        if pre and not post:
            self.req(f"CC-02.app-key-pre-rotation:{name}", "CC-02", False,
                     f"app-key-pre-rotation: every {name} run on {sha[:12]} predates the {slug} key "
                     "rotation; a new run after rotation is required")
        paired = self._pair_all(sha, name, role, mine, pre)
        unpaired = [cid for c in post for cid in [c.get("id")] if cid in paired and paired[cid] is None]
        if any(cid in paired for cid in (c.get("id") for c in post)):
            self.req(f"CC-02.check-without-evidence:{name}", "CC-02", not unpaired,
                     (f"check-without-evidence: {name} success run(s) {unpaired} on {sha[:12]} have no "
                      "verified attestation from the same workflow run (possible App key misuse)")
                     if unpaired else f"every {name} success on {sha[:12]} is paired",
                     [a.digest for a in paired.values() if a is not None])

    def gate_checks(self):
        """The gate's own sox/evidence-gate runs on this head. Open PR: every success must be paired
        (an App key cannot sign a gate-decision). As of merge: the last run completed before the
        merge, which the ruleset relied on, must be a paired success."""
        pd, name, role = self.pd, "sox/evidence-gate", "gate"
        app_id = self.policy.app_id(role)
        if not app_id:
            self.req(f"CC-02.check:{name}", "CC-02", False, "gate App id not pinned in the trust policy")
            return
        runs = [c for c in self.ctx.check_runs(pd.head)
                if c.get("name") == name and (c.get("app") or {}).get("id") == app_id
                and c.get("status") == "completed" and c.get("completed_at")]
        if self.as_of is not None:
            runs = [c for c in runs if parse_time(c["completed_at"]) <= self.as_of]
        runs.sort(key=lambda c: (c.get("completed_at") or "", c.get("id") or 0))
        pre, post = self._split_rotation(runs, role)
        self.facts["gateCheckRuns"] = len(runs)
        paired = self._pair_all(pd.head, name, role, runs, pre)
        unpaired = [c.get("id") for c in post if c.get("id") in paired and paired[c.get("id")] is None]
        self.req(f"CC-02.check-without-evidence:{name}", "CC-02", not unpaired,
                 (f"check-without-evidence: {name} success run(s) {unpaired} on {pd.head[:12]} have no "
                  "verified gate-decision from the same workflow run (possible Gate App key misuse)")
                 if unpaired else f"{len(post)} completed {name} run(s) on {pd.head[:12]}; every success paired")
        if self.as_of is not None:
            last = post[-1] if post else None
            ok = last is not None and paired.get(last.get("id")) is not None
            self.req(f"CC-02.check:{name}", "CC-02", ok,
                     f"last {name} run before the merge: "
                     + (f"{last.get('id')} {last.get('conclusion')}, "
                        f"{'paired' if ok else 'not a paired success'}" if last else "none")
                     + (f"; {len(pre)} run(s) before the App key rotation set aside" if pre else ""))
            if pre and not post:
                self.req(f"CC-02.app-key-pre-rotation:{name}", "CC-02", False,
                         f"app-key-pre-rotation: every {name} run before the merge predates the "
                         "gate App key rotation")

    def judging_runs(self, pd, role, rid, control):
        """F17: every run of the role's judging workflow whose judging step started on this head
        must have attested its predicate from the same run attempt; otherwise the verdict was
        readable and could be discarded and re-rolled (unattested-judging-run)."""
        cfg = self.policy.judging(role)
        if not cfg:
            self.req(rid, control, False, f"judgingWorkflows.{role} not configured in the trust policy")
            return
        since = self.head_pushed_at(pd)
        runs = self.ctx.workflow_runs(cfg["workflow"], since - JUDGING_QUEUE_MARGIN)
        job_re = re.compile(re.escape(cfg["job"]) + r" \(([0-9]+)(?:, [^)]*)?\)")
        # A dispatched single-PR run names neither the PR in its job nor (without run-name) in its
        # title; its check run on the head carries external_id = run id, which ties it to this head.
        on_head = {str(c.get("external_id")) for c in self.ctx.check_runs(pd.head)
                   if str(c.get("external_id") or "").isdigit()}
        hits, by_head = [], set()
        for run in runs:
            if self.as_of is not None and (parse_time(run.get("created_at")) or 0) > self.as_of:
                continue
            for job in self.ctx.run_jobs(run["id"]):
                m = job_re.fullmatch(job.get("name") or "")
                if m:
                    mine = int(m.group(1)) == pd.number
                elif job.get("name") == cfg["job"]:
                    t = re.search(r"\bpr[=#: ]?([0-9]+)\b", run.get("display_title") or "", re.I)
                    if t:
                        mine = int(t.group(1)) == pd.number
                    else:
                        mine = str(run["id"]) in on_head
                        by_head.add(str(run["id"]))
                else:
                    continue
                if not mine:
                    continue
                at = _judging_started(job, cfg.get("step"))
                if at is None or at < since or (self.as_of is not None and at > self.as_of):
                    continue
                hits.append((str(run["id"]), int(job.get("run_attempt") or run.get("run_attempt") or 1), at))
        attested = {pairing.run_of(a, self.policy.repo) for a in self.all("pr", pd.number, cfg["predicate"])
                    if a.predicate.get("prNumber") == pd.number}
        # Head-attributed runs may have judged another PR sharing this head; any attestation of the
        # predicate from that run attempt shows the verdict was signed.
        if by_head:
            attested |= {pairing.run_of(a, self.policy.repo) for a in self.all("commit", pd.head, cfg["predicate"])}
        missing = sorted({(r, n) for r, n, _ in hits if (r, n) not in attested})
        self.facts.setdefault("judgingRuns", {})[f"{role}#{pd.number}"] = [
            {"runId": r, "attempt": n, "judgingStartedAt": iso(t), "attested": (r, n) in attested}
            for r, n, t in sorted(set(hits))]
        self.req(rid, control, not missing,
                 (f"unattested-judging-run: {cfg['workflow']} run(s) {[f'{r}/attempt {n}' for r, n in missing]} "
                  f"judged PR #{pd.number} at head {pd.head[:12]} without attesting {cfg['predicate']} "
                  "from the same run; the head is blocked") if missing else
                 f"{len(hits)} judging run(s) of {cfg['workflow']} on head {pd.head[:12]}, all attested")

    def head_pushed_at(self, pd):
        """Earliest push that made pd.head the branch tip; PR creation time if none is recorded."""
        ts = [parse_time(a["timestamp"]) for a in pd.pushes()
              if a.get("after") == pd.head and a.get("timestamp")]
        if ts:
            return min(ts)
        return parse_time(pd.pr.get("created_at")) if pd.pr.get("created_at") else 0

    def pre_rotation_pushes(self, pd):
        """7.6 item 3: a commit first pushed under an App identity before that App's key rotation
        cannot be relied on after go-live; only a new head of commits pushed after rotation clears it."""
        if not self.carry_over:
            return
        order = [c["sha"] for c in pd.commits]
        idx = {s: i for i, s in enumerate(order)}
        first = {}
        for a in sorted(pd.pushes(), key=lambda a: a.get("timestamp") or ""):
            if a.get("after") in idx:
                for s in order[:idx[a["after"]] + 1]:
                    first.setdefault(s, (parse_time(a.get("timestamp")), (a.get("actor") or {}).get("login")))
        bad = []
        for s, (t, login) in first.items():
            role = self.policy.role_of_login(login)
            rot = self.policy.rotation_at(role) if role else None
            if rot is not None and (t is None or t < rot):
                bad.append(f"{s[:12]} by {login}")
        self.req(f"SDLC-05.app-key-pre-rotation#{pd.number}", "SDLC-05", not bad,
                 (f"app-key-pre-rotation: commits first pushed by an App before its key rotation: {bad}; "
                  "push a rebuilt head after rotation") if bad else
                 "no commit was first pushed by an App before its key rotation")
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
        self.check_scope(slug, [story])
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
        self.judging_runs(pd, "review", f"SDLC-06.unattested-judging-run#{pd.number}", "SDLC-06")
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
            e_ok, e_detail = (jira_human_approval(pol, ec.predicate, "emergencyApproval") if ec else
                              (False, f"missing: emergency-change for {key}"))
            self.req("CC-04.ecab", "CC-04", e_ok, f"emergency-change {key}: {e_detail}",
                     [ec.digest] if ec else [])
            self.check_pushers(pd, "hotfix")
        else:
            slug = RELEASE_RE.match(pd.head_ref).group(1)
            self.facts["release"] = slug
            self.check_pushers(pd, "release")
            self.release_commits(slug)
        self.refresh_plans()
        self.check_scope(slug, [] if emergency else self.facts["stories"])
        self.review_verdict(pd)
        self.required_check(pd.head, "sox/review-agent", "review")
        self.required_check(pd.head, "sox/qa-agent", "qa")
        self.judging_runs(pd, "review", f"SDLC-06.unattested-judging-run#{pd.number}", "SDLC-06")
        self.judging_runs(pd, "qa", f"SDLC-08.unattested-judging-run#{pd.number}", "SDLC-08")
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
        head branch, slug, stories and epics), not the PR: dismissing the review, dropping the event, or
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
        # The request also binds every story and Epic it covered (F14, BP-39g): re-bundling the
        # same work under a new release slug or branch does not shed it without a re-plan.
        kinds = ([("release", slug)] if slug else []) + [("pr", pd.number)]
        kinds += [("jira", k) for k in sorted(set(self.facts["stories"]) | set(self.facts["epics"]))
                  if JIRA_KEY_RE.match(str(k or ""))]
        seen_att = set()
        for kind, ident in kinds:
            for a in self.all(kind, ident, "human-changes-requested"):
                if a.digest in seen_att:
                    continue
                seen_att.add(a.digest)
                q = a.predicate
                crs.append({"pr": q.get("prNumber"), "reviewId": q.get("reviewId"),
                            "login": (q.get("reviewer") or {}).get("login"),
                            "commitId": q.get("commitId"),
                            "at": parse_time(q.get("submittedAt")) or a.integrated_time,
                            "attestation": a.digest})
        if self.as_of is not None:
            crs = [c for c in crs if c["at"] is not None and c["at"] <= self.as_of]
        # One review seen both in the reviews API and as its attestation counts once.
        merged = {}
        for c in crs:
            k = (c.get("pr"), c.get("reviewId")) if c.get("reviewId") is not None else (id(c),)
            merged[k] = dict(merged.get(k) or {}, **{x: y for x, y in c.items() if y is not None})
        crs = list(merged.values())
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
        man = f.get("manifest") or {}
        return {"prNumber": self.pd.number, "headSha": self.pd.head, "baseRef": "refs/heads/main",
                "planDigests": {k: v["planDigest"] for k, v in sorted(f["epics"].items())},
                "releaseManifest": man.get("digest"),
                "declaredServices": man.get("declaredServices", []),
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
        decisions = [a for a in self.ctx.ev.get("pr", pd.number, "gate-decision", before=self.as_of)
                     if a.predicate.get("headSha") == pd.head and a.predicate.get("packetDigest")]
        shown = [a for a in decisions if a.predicate.get("packetDigest") == pdig]
        older = [a for a in decisions if a.predicate.get("packetDigest") != pdig]

        def packet_changes(old):
            old = old or {}
            keys = sorted(k for k in set(old) | set(packet) if old.get(k) != packet.get(k))
            return keys or ["(packet body not recorded)"]
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
                prior = [a for a in older if sub is not None and a.integrated_time < sub]
                if prior:
                    why.append("approval-stale: approved packet " + str(prior[-1].predicate.get("packetDigest"))
                               + "; the current packet differs in "
                               + str(packet_changes(prior[-1].predicate.get("packet"))))
                else:
                    why.append("submitted before the approval packet for this SHA was presented")
            if any(t >= sub for t in base_changes if sub):
                why.append("base changed after the review")
            if self.as_of is not None and sub and sub > self.as_of:
                why.append("after merge")
            return why

        results = {l: qualifies(r, approvers) for l, r in latest.items()}
        good = [latest[l] for l, why in results.items() if not why]
        self.facts["approvalCandidates"] = {l: (why or ["ok"]) for l, why in results.items()}
        stale = sorted(l for l, why in results.items() if any(w.startswith("approval-stale") for w in why))
        signed_stale = [a for a in self.ctx.ev.get("commit", pd.head, "human-approval", before=self.as_of)
                        if a.predicate.get("prNumber") == pd.number
                        and a.predicate.get("packetDigest") not in (None, pdig)]
        if not good and (stale or signed_stale):
            # BP-38e: a newer release-manifest or techlead-plan than the approver saw.
            self.req("SDLC-09.approval-stale", "SDLC-09", False,
                     f"approval by {stale or [(a.predicate.get('reviewer') or {}).get('login') for a in signed_stale]} "
                     f"covers an earlier packet; current packet {pdig} must be approved anew",
                     [a.digest for a in signed_stale])
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
    ctx.top_as_of = as_of
    return Evaluation(ctx, pd, as_of=as_of).run()
