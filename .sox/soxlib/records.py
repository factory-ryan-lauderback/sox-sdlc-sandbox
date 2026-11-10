"""Predicates signed by sox-gate.yml (evidence spec section 3), built only from facts the gate read
from the GitHub API, git, and verified attestations. Nothing here comes from the trigger."""
import base64
import hashlib
import json
import os
import time

from . import jcs, subject as subj
from .gate import iso

GATE_WORKFLOW = ".github/workflows/sox-gate.yml"
OPEN_EMITS = ("gate-decision", "dev-change", "human-approval", "human-changes-requested",
              "loop-escalation")
MERGED_EMITS = ("merge-record",)
EMIT_NAMES = OPEN_EMITS + MERGED_EMITS


def image_name(repo, service):
    return f"ghcr.io/{repo}/{service}"


def now_iso():
    return iso(time.time())


def bundle_digest(path):
    """Attestation digest: sha256 over the DSSE payload (the in-toto statement bytes)."""
    with open(path) as f:
        b = json.load(f)
    b = b.get("bundle", b)
    return "sha256:" + hashlib.sha256(base64.b64decode(b["dsseEnvelope"]["payload"])).hexdigest()


def attestor():
    def num(k):
        v = os.environ.get(k, "")
        return int(v) if v.isdigit() else None
    return {"workflow": GATE_WORKFLOW, "ref": os.environ.get("GITHUB_REF"),
            "runId": num("GITHUB_RUN_ID"), "runAttempt": num("GITHUB_RUN_ATTEMPT"),
            "codeSha": os.environ.get("GITHUB_SHA")}


class Emission:
    def __init__(self, name, predicate, subjects):
        self.name, self.predicate, self.subjects = name, predicate, subjects

    def subjects_text(self, repo):
        lines = []
        for s in self.subjects:
            if s[0] == "image":
                lines.append(f"{s[2].split(':', 1)[-1]}  {s[1]}")
            else:
                lines.append(f"{subj.key(repo, s[0], s[1])}  sox:{s[0]}:{s[1]}")
        return "\n".join(lines) + "\n"

    def write(self, out_dir, repo):
        with open(os.path.join(out_dir, f"{self.name}.json"), "w") as f:
            json.dump(self.predicate, f, indent=1, sort_keys=True)
        with open(os.path.join(out_dir, f"{self.name}.subjects"), "w") as f:
            f.write(self.subjects_text(repo))


def jira_keys(ev):
    keys = set(ev.facts.get("stories", [])) | set(ev.facts.get("epics", {}))
    return sorted(k for k in keys if k and subj._ID_RULES["jira"].match(k))


def release_label(ev):
    if ev.kind == "emergency":
        return ev.pd.head_ref
    return ev.facts.get("release")


def base_subjects(ev, with_release=False):
    s = [("commit", ev.pd.head), ("pr", str(ev.pd.number))] + [("jira", k) for k in jira_keys(ev)]
    if with_release and ev.facts.get("release"):
        s.append(("release", ev.facts["release"]))
    return s


def common(ev, step, outcome, upstream=(), inputs=()):
    pd, pol = ev.pd, ev.policy
    inputs = list(inputs)
    return {
        "schema": "sox/common/v1", "repo": pol.repo, "prNumber": pd.number, "headSha": pd.head,
        "baseSha": (pd.pr.get("base") or {}).get("sha"), "baseRef": f"refs/heads/{pd.base_ref}",
        "jiraKeys": jira_keys(ev), "release": release_label(ev), "step": step,
        "actor": {"type": "github_app", "login": pol.bot_login("gate"), "appId": pol.app_id("gate"),
                  "source": "Gate App installation token minted in this run"},
        "inputs": inputs, "inputsDigest": jcs.digest(inputs), "outcome": outcome,
        "observedAt": now_iso(), "attestor": attestor(),
        "upstream": sorted({u for u in upstream if u}),
    }


def requirement_key(ev):
    return jcs.digest(sorted((r.id, r.ok) for r in ev.reqs))


# ---------- open PR ----------

def gate_decision(ev, forgeries, check_run_id=None):
    f = ev.facts
    p = common(ev, "SDLC-10" if ev.kind in ("release", "emergency") else "SDLC-05",
               "pass" if ev.ok else "fail", upstream=f["upstream"].values(),
               inputs=[{"name": "trust-policy", "digest": {"sha256": ev.policy.digest.split(":")[1]}}])
    p.update({"check": "sox/evidence-gate", "checkRunId": check_run_id,
              "conclusion": "success" if ev.ok else "failure",
              "kind": ev.kind, "requirements": [r.to_json() for r in ev.reqs],
              "requirementsDigest": requirement_key(ev),
              "policyDigest": ev.policy.digest, "packetDigest": f.get("packetDigest"),
              "packet": f.get("packet") if f.get("packetReady") else None,
              "forgeryAttempts": sorted({x.get("digest") or "" for x in forgeries} - {""})})
    return Emission("gate-decision", p, [("commit", ev.pd.head), ("pr", str(ev.pd.number))])


def commit_pushers(pd):
    order = [c["sha"] for c in pd.commits]
    idx = {s: i for i, s in enumerate(order)}
    out = {}
    for a in pd.pushes():
        after = a.get("after")
        if after in idx:
            for s in order[:idx[after] + 1]:
                out.setdefault(s, (a.get("actor") or {}).get("login"))
    return out


def dev_change(ev):
    pd = ev.pd
    pushers = commit_pushers(pd)
    commits = [{"sha": c["sha"],
                "author": (c.get("author") or {}).get("login"),
                "committer": (c.get("committer") or {}).get("login"),
                "pusher": pushers.get(c["sha"]),
                "verified": bool(((c.get("commit") or {}).get("verification") or {}).get("verified"))}
               for c in pd.commits]
    ok = all(r.ok for r in ev.reqs if r.control == "SDLC-05")
    p = common(ev, "SDLC-05", "recorded" if ok else "fail", upstream=ev.facts["upstream"].values())
    p.update({"branch": pd.head_ref, "commits": commits, "pushers": ev.facts.get("pushers", []),
              "changedPaths": pd.paths, "servicesTouched": ev.facts.get("servicesTouched", []),
              "dependencyMerges": ev.facts.get("dependencyMerges", [])})
    return Emission("dev-change", p, base_subjects(ev))


def human_approval(ev, review):
    f = ev.facts
    owners = set(ev.policy.humans("controlOwners"))
    login = review["user"]["login"]
    excluded = sorted(l for l, why in (f.get("approvalCandidates") or {}).items() if why != ["ok"])
    p = common(ev, "SDLC-09", "approved", upstream=f["upstream"].values())
    p.update({"reviewer": {"login": login, "id": review["user"]["id"]},
              "reviewId": review["id"], "commitId": review["commit_id"],
              "submittedAt": review["submitted_at"], "baseRefChangedAfterReview": False,
              "packetDigest": f["packetDigest"], "packet": f["packet"],
              "packetPresentedAt": f.get("packetPresentedAt"),
              "sod": {"participants": f.get("participants", []),
                      "excluded": sorted(set(ev.policy.humans("neverApprovers")) | set(excluded)),
                      "result": "pass"},
              "controlChange": ev.control_change()})
    if ev.control_change():
        p["controlOwnerApproval"] = {"login": login, "reviewId": review["id"],
                                     "isControlOwner": login in owners}
        p["sodShortcut"] = bool(f.get("sodShortcut"))
    return Emission("human-approval", p, base_subjects(ev, with_release=True))


def human_changes_requested(ev, review):
    p = common(ev, "LOOP-H", "changes_requested", upstream=ev.facts["upstream"].values())
    body = (review.get("body") or "").encode()
    p.update({"reviewer": {"login": review["user"]["login"], "id": review["user"]["id"]},
              "reviewId": review["id"], "commitId": review.get("commit_id"),
              "submittedAt": review.get("submitted_at"),
              "bodyDigest": "sha256:" + hashlib.sha256(body).hexdigest()})
    return Emission("human-changes-requested", p, base_subjects(ev, with_release=True))


def loop_escalation(ev, loop, key, rounds):
    p = common(ev, "LOOP-R" if loop == "review" else "LOOP-Q", "fail",
               upstream=ev.facts["upstream"].values())
    p.update({"loop": loop, "storyKey": key, "rounds": rounds,
              "maxRounds": ev.policy.loops.get("maxReviewRounds" if loop == "review" else "maxQaRounds", 10),
              "jiraTransition": "requested: Tech Lead re-plan (the gate holds no Jira credential; "
                                "the PR stays blocked until a human re-plan is attested)"})
    s = [("pr", str(ev.pd.number))] + ([("jira", key)] if key and key != "qa" else [])
    return Emission("loop-escalation", p, s)


def plan_open(ev, ctx):
    """Records to sign for an open PR. Already-signed facts are not signed again."""
    pd, out = ev.pd, []
    forgeries = ctx.ev.forgeries()
    prev = ctx.ev.latest("pr", pd.number, "gate-decision",
                         where=lambda a: a.predicate.get("headSha") == pd.head)
    # A success check run must pair with a gate-decision from its own run (spec 2.5), so a
    # success is signed every time; an unchanged failure is not signed again.
    if ev.ok or prev is None or (prev.predicate.get("requirementsDigest"),
                        prev.predicate.get("packetDigest"),
                        prev.predicate.get("conclusion")) != (
            requirement_key(ev), ev.facts.get("packetDigest"), "success" if ev.ok else "failure"):
        out.append(gate_decision(ev, forgeries, getattr(ctx, "check_run_id", None)))
    if ev.kind in ("story", "emergency"):
        if ctx.ev.latest("commit", pd.head, "dev-change",
                         where=lambda a: a.predicate.get("prNumber") == pd.number) is None:
            out.append(dev_change(ev))
    review = ev.facts.get("approval")
    if review and ctx.ev.latest("pr", pd.number, "human-approval",
                                where=lambda a: a.predicate.get("reviewId") == review["id"]) is None:
        out.append(human_approval(ev, review))
    attested = {c.get("reviewId") for c in ev.facts.get("humanChangesRequested") or []
                if c.get("attestation")}
    by_id = {r.get("id"): r for r in pd.reviews}
    for c in ev.facts.get("humanChangesRequested") or []:
        if c.get("pr") == pd.number and c.get("reviewId") in by_id and c["reviewId"] not in attested:
            out.append(human_changes_requested(ev, by_id[c["reviewId"]]))
            break
    mx = ev.policy.loops
    for key, n in sorted((ev.facts.get("rounds") or {}).items()):
        loop = "qa" if key == "qa" else "review"
        limit = mx.get("maxQaRounds" if loop == "qa" else "maxReviewRounds", 10)
        if n >= limit and ctx.ev.latest("pr", pd.number, "loop-escalation",
                                        where=lambda a, key=key, n=n: a.predicate.get("storyKey") == key
                                        and a.predicate.get("rounds") == n) is None:
            out.append(loop_escalation(ev, loop, key, n))
            break
    return out


# ---------- merged release / emergency PR ----------

def merge_checks(ev):
    """merge-record.checks[] (spec 2.5): for sox/evidence-gate the last run completed before the
    merge (the one the ruleset relied on); for agent checks every run on the merged head, since
    each binds it. Runs set aside as pre-rotation are listed separately."""
    out, pre = [], []
    keep = ("name", "checkRunId", "appId", "conclusion", "externalId", "pairedAttestation", "paired")
    for name in sorted(ev.policy.data.get("requiredChecks") or {}):
        entries = [e for e in (ev.facts.get("checks") or {}).get(name, [])
                   if e.get("headSha") == ev.pd.head]
        pre += [{k: e[k] for k in keep} for e in entries if e.get("preRotation")]
        post = [e for e in entries if not e.get("preRotation")]
        if name == "sox/evidence-gate":
            post = post[-1:]
        out += [{k: e[k] for k in keep} for e in post]
    names = set(ev.policy.data.get("requiredChecks") or {})
    paired = (bool(out) and all(e["paired"] for e in out)
              and names <= {e["name"] for e in out})
    return out, pre, paired

def merge_record(ev, mirror):
    pd = ev.pd
    merge = pd.pr["merge_commit_sha"]
    mirror.fetch_sha(merge)
    mirror.fetch_sha(pd.head)
    parents = mirror.parents(merge)
    tree, htree = mirror.tree(merge), mirror.tree(pd.head)
    match = tree == htree and len(parents) == 2 and parents[1] == pd.head
    checks, pre_checks, paired = merge_checks(ev)
    p = common(ev, "SDLC-10", "recorded" if match and ev.ok and paired else "fail",
               upstream=ev.facts["upstream"].values())
    p.update({"mergeCommitSha": merge, "parents": parents, "treeSha": tree,
              "approvedHeadSha": pd.head, "approvedHeadTreeSha": htree, "treeMatch": match,
              "mergedBy": (pd.pr.get("merged_by") or {}).get("login"),
              "mergedAt": pd.pr.get("merged_at"),
              "checks": checks, "checksPaired": paired, "preRotationChecks": pre_checks,
              "gateAsOfMerge": {"result": "pass" if ev.ok else "fail",
                                "failed": [r.id for r in ev.reqs if not r.ok],
                                "requirementsDigest": requirement_key(ev)}})
    s = [("commit", merge), ("commit", pd.head), ("pr", str(pd.number))]
    s += [("release", ev.facts["release"])] if ev.facts.get("release") else []
    s += [("jira", k) for k in jira_keys(ev)]
    return Emission("merge-record", p, s)


def plan_merged(ev, ctx):
    pd = ev.pd
    existing = ctx.ev.latest("commit", pd.pr["merge_commit_sha"], "merge-record",
                             where=lambda a: a.predicate.get("prNumber") == pd.number)
    if existing is not None:
        return [], existing
    return [merge_record(ev, ctx.mirror)], None


def release_approvals(ev, ctx, mr_digest, mr_predicate):
    """One release-approval per image of the verified env-deploy for the approved head.
    Returns (entries, reasons-not-signed)."""
    pd, pol = ev.pd, ev.policy
    why = []
    if not ev.ok:
        why.append("gate re-evaluation as of merge fails: " + str([r.id for r in ev.reqs if not r.ok]))
    if not (mr_predicate or {}).get("treeMatch"):
        why.append("merge-record treeMatch is not true")
    if not (mr_predicate or {}).get("checksPaired"):
        unpaired = [f"{c.get('name')}#{c.get('checkRunId')}" for c in (mr_predicate or {}).get("checks") or []
                    if not c.get("paired")]
        why.append("merge-record checks are not all paired with attestations from their own runs "
                   f"(check-without-evidence): {unpaired or 'no checks recorded'}")
    ha = ctx.ev.latest("commit", pd.head, "human-approval",
                       where=lambda a: a.predicate.get("prNumber") == pd.number
                       and a.predicate.get("commitId") == pd.head
                       and a.predicate.get("baseRef") == "refs/heads/main"
                       and a.predicate.get("packetDigest") == ev.facts.get("packetDigest"))
    if ha is None:
        why.append("no verified human-approval for the merged head")
    env = ctx.ev.latest("commit", pd.head, "env-deploy",
                        where=lambda a: a.predicate.get("headSha") == pd.head
                        and a.predicate.get("baseRef") == "refs/heads/main")
    images = (env.predicate.get("images") if env else None) or []
    if not images:
        why.append("no verified env-deploy with images for the merged head")
    if why:
        return [], why
    merge = pd.pr["merge_commit_sha"]
    out = []
    for img in images:
        service = img.get("service")
        digest = img.get("digest") or ""
        if not digest.startswith("sha256:"):
            digest = "sha256:" + digest
        if not service or not subj.IMAGE_RE.match(digest):
            why.append(f"env-deploy image entry unusable: {img}")
            continue
        done = ctx.ev.latest("commit", merge, "release-approval",
                             where=lambda a, s=service, d=digest: a.predicate.get("service") == s
                             and a.predicate.get("imageDigest") == d)
        if done is not None:
            continue
        name = image_name(pol.repo, service)
        pred = common(ev, "SDLC-10", "approved", upstream=[mr_digest, ha.digest, env.digest])
        pred.update({"environment": "production", "service": service, "image": name,
                     "imageDigest": digest, "mergeCommitSha": merge, "releaseHeadSha": pd.head,
                     "mergeRecord": mr_digest, "humanApproval": ha.digest,
                     "envDeploy": env.digest,
                     "provenanceAttestation": img.get("provenanceAttestation")})
        subjects = [("commit", merge), ("pr", str(pd.number))]
        subjects += ([("release", ev.facts["release"])] if ev.facts.get("release")
                     else [("jira", k) for k in jira_keys(ev)])
        subjects.append(("image", name, digest))
        e = Emission("release-approval", pred, subjects)
        out.append({"service": service, "image": name, "digest": digest,
                    "predicate": pred, "subjects": e.subjects_text(pol.repo)})
    return out, why
