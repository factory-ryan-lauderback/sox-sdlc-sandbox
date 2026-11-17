"""Load and validate the trust policy. Any structural problem is fatal: verifiers fail closed."""
import hashlib
import json
import re

from . import jcs

PREFIX = "https://acme-lending.example/sox/"
WORKFLOW_RE = re.compile(r"^\.github/workflows/sox-[a-z0-9-]+\.ya?ml$")
# pull_request_target is excluded: its job ref is the PR base, so a main-only environment key is
# unavailable for story PRs, and the certificate would carry a non-main ref.
SAFE_TRIGGERS = {"workflow_dispatch", "schedule", "repository_dispatch", "check_run",
                 "workflow_run"}
EXPOSED_NOT_ROTATED = "app-key-exposed-not-rotated"
SOD_SHORTCUT_LABEL = "sod-shortcut-owner-approver"
# Separation-of-duties rules an approval by the sodShortcut identity may skip. Nothing else is
# waivable: the approver must still be listed, pinned by id, atlassian, on the right SHA or status.
SOD_WAIVABLE = frozenset({"automation-account", "reporter", "creator", "author-pusher",
                          "platform-admin"})
BYPASS_KEYS = frozenset({"pr", "label", "approvedBy", "approvedAt", "reason"})
BYPASS_LABEL_RE = re.compile(r"bypass-exception-[1-9][0-9]*")


class PolicyError(ValueError):
    pass


def _epoch(value, where):
    import datetime as dt
    try:
        t = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise PolicyError(f"{where} must be an ISO 8601 timestamp, got {value!r}")
    if t.tzinfo is None:
        raise PolicyError(f"{where} must carry a timezone")
    return t.timestamp()


class Policy:
    # Only these files may ever sign evidence. Relays and the observer are dispatch-only by design
    # and must never become signers, even through a policy edit (F12, BP-53b).
    SIGNER_WORKFLOWS = frozenset(f".github/workflows/{n}.yml" for n in (
        "sox-jira-attestor", "sox-gate", "sox-review-agent", "sox-qa-agent", "sox-env-deploy",
        "sox-deploy-train", "sox-deploy-emergency", "sox-reconcile", "sox-reg-tests"))
    FORBIDDEN_WORKFLOW_WORDS = ("probe", "relay", "observer")
    GATE_WORKFLOW = ".github/workflows/sox-gate.yml"
    # Lists under humans that name non-approvers by design; every other list is a role list.
    NON_ROLE_LISTS = frozenset({"neverApprovers", "platformAdmins"})

    def __init__(self, raw_bytes, source="<memory>"):
        self.raw = raw_bytes
        self.source = source
        try:
            self.data = json.loads(raw_bytes)
        except ValueError as e:
            raise PolicyError(f"{source}: trust policy is not JSON: {e}")
        self.digest = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        self.jcs_digest = jcs.digest(self.data)
        self._validate()

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            return cls(f.read(), source=path)

    def _validate(self):
        d = self.data
        for k in ("repo", "repositoryId", "ownerId", "oidcIssuer", "predicates", "repositoryUri"):
            if k not in d:
                raise PolicyError(f"trust policy missing {k}")
        if not isinstance(d["repositoryId"], int) or not isinstance(d["ownerId"], int):
            raise PolicyError("repositoryId and ownerId must be integers")
        if d.get("sourceRef", "refs/heads/main") != "refs/heads/main":
            raise PolicyError("global sourceRef must be refs/heads/main")
        never = set(d.get("neverAllowedTriggers") or []) | {"pull_request", "push", "pull_request_target"}
        self.predicate_types = {}
        for name, spec in d["predicates"].items():
            if not isinstance(spec, dict):
                raise PolicyError(f"predicate {name}: not a mapping")
            if spec.get("sourceRef") != "refs/heads/main":
                raise PolicyError(f"predicate {name}: sourceRef must be refs/heads/main")
            if spec.get("repository") != d["repo"] or spec.get("repositoryId") != d["repositoryId"]:
                raise PolicyError(f"predicate {name}: repository pin differs from the policy repo")
            signers = spec.get("signers")
            if not signers:
                raise PolicyError(f"predicate {name}: no signers")
            for s in signers:
                wf = s.get("workflow", "")
                if (not WORKFLOW_RE.match(wf) or wf not in self.SIGNER_WORKFLOWS
                        or any(w in wf for w in self.FORBIDDEN_WORKFLOW_WORDS)):
                    raise PolicyError(f"predicate {name}: signer workflow {wf!r} is not one of the "
                                      "allowed signer workflows")
                trig = set(s.get("allowedTriggers") or [])
                if not trig:
                    raise PolicyError(f"predicate {name}: no allowedTriggers")
                bad = (trig & never) | (trig - SAFE_TRIGGERS)
                if bad:
                    raise PolicyError(f"predicate {name}: triggers {sorted(bad)} are never allowed")
                if wf == self.GATE_WORKFLOW and trig != {"workflow_dispatch"}:
                    raise PolicyError(f"predicate {name}: {wf} may only sign on workflow_dispatch "
                                      f"(one PR per run), not {sorted(trig)}")
            ptype = spec.get("predicateType") or f"{PREFIX}{name}/v1"
            if ptype in self.predicate_types:
                raise PolicyError(f"predicate type {ptype} listed twice")
            self.predicate_types[ptype] = name
        self._validate_sod_shortcut()
        self._validate_humans()
        self._validate_jira()
        self._validate_go_live()
        self._validate_bypass()
        self._validate_judging()

    def _validate_humans(self):
        humans = self.data.get("humans") or {}
        never = set(humans.get("neverApprovers") or [])
        lists = {f"humans.{k}": v for k, v in humans.items()
                 if isinstance(v, list) and k not in self.NON_ROLE_LISTS}
        reg = (self.data.get("regulated") or {}).get("domainApprovers") or {}
        lists.update({f"regulated.domainApprovers.{k}": v for k, v in reg.items()
                      if isinstance(v, list)})
        for where, logins in sorted(lists.items()):
            hit = sorted(never & set(logins))
            if hit:
                raise PolicyError(f"{where} contains neverApprovers login(s) {hit}")

    def _validate_sod_shortcut(self):
        s = self.data.get("sodShortcut")
        if s is None:
            return
        if not isinstance(s, dict) or s.get("label") != SOD_SHORTCUT_LABEL:
            raise PolicyError(f"sodShortcut.label must be {SOD_SHORTCUT_LABEL!r}")
        if not s.get("githubLogin") or self.human_id(s["githubLogin"]) is None:
            raise PolicyError("sodShortcut.githubLogin must be pinned in humans.ids")
        if not s.get("jiraAccountId"):
            raise PolicyError("sodShortcut.jiraAccountId is required")
        waives = s.get("waives")
        if not isinstance(waives, list) or not set(waives) <= SOD_WAIVABLE:
            raise PolicyError(f"sodShortcut.waives must be a subset of {sorted(SOD_WAIVABLE)}")

    def _validate_jira(self):
        j = self.data.get("jira") or {}
        never = set(j.get("neverApprovers") or [])
        shared = j.get("sharedAutomationAccount")
        shortcut = shared if self.sod_waives("automation-account", jira_account=shared) else None
        if shared and shared not in never and shared != shortcut:
            raise PolicyError("jira.sharedAutomationAccount must be in jira.neverApprovers "
                              "unless sodShortcut names it and waives automation-account")
        for kind, accounts in (j.get("humanApprovers") or {}).items():
            if kind.startswith("$"):
                continue
            if not isinstance(accounts, list):
                raise PolicyError(f"jira.humanApprovers.{kind} must be a list of accountIds")
            bad = sorted(set(accounts) & (never | {shared}) - {shortcut})
            if bad:
                raise PolicyError(f"jira.humanApprovers.{kind} contains automation or "
                                  f"never-approver accounts {bad}")
        for kind, status in (j.get("approvalStatuses") or {}).items():
            if not kind.startswith("$") and status is not None \
                    and not re.fullmatch(r"[0-9]{1,12}", str(status)):
                raise PolicyError(f"jira.approvalStatuses.{kind} must be a numeric status id or null")

    def _validate_go_live(self):
        """goLive (evidence spec 7.6, F16). appKeys pins each App's in-scope key by its role in
        `apps` (appId, public-key fingerprint; never key material) and must cover every App.
        appKeyExposure records the accepted, unremediated exposure: while rotated is false every
        in-scope merge-record and reconciliation item carries its label. It relaxes no check."""
        g = self.data.get("goLive") or {}
        self._go_live_at = None
        anchor = g.get("anchorPr")
        if anchor is not None:
            if not isinstance(anchor, int) or isinstance(anchor, bool) or anchor <= 0:
                raise PolicyError("goLive.anchorPr must be a PR number")
            if g.get("at") is not None or g.get("mainSha") is not None:
                raise PolicyError("goLive.anchorPr and goLive.at/mainSha are exclusive")
        if g.get("at") is not None:
            at = _epoch(g.get("at"), "goLive.at")
            if not re.fullmatch(r"[0-9a-f]{40}", str(g.get("mainSha") or "")):
                raise PolicyError("goLive.mainSha must be a 40-hex commit SHA once goLive.at is set")
            if not isinstance(g.get("rulesetVersion"), int) or isinstance(g.get("rulesetVersion"), bool):
                raise PolicyError("goLive.rulesetVersion must be an integer once goLive.at is set")
            self._go_live_at = at
        keys = g.get("appKeys")
        if not isinstance(keys, dict):
            raise PolicyError("goLive.appKeys must map every App in apps to its pinned key")
        apps = {r: a for r, a in (self.data.get("apps") or {}).items()
                if not r.startswith("$") and isinstance(a, dict)}
        extra = sorted(k for k in keys if not k.startswith("$") and k not in apps)
        if extra:
            raise PolicyError(f"goLive.appKeys names Apps not in apps: {extra}")
        for role in sorted(apps):
            e = keys.get(role)
            if not isinstance(e, dict):
                raise PolicyError(f"goLive.appKeys.{role} missing: every App needs a pinned key")
            if e.get("appId") is None or e.get("appId") != apps[role].get("id"):
                raise PolicyError(f"goLive.appKeys.{role}.appId {e.get('appId')!r} does not match "
                                  f"apps.{role}.id {apps[role].get('id')!r}")
            if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}=?", str(e.get("keyFingerprint") or "")):
                raise PolicyError(f"goLive.appKeys.{role}.keyFingerprint must be SHA256:<base64 of 32 bytes>")
        x = g.get("appKeyExposure")
        if not isinstance(x, dict) or not isinstance(x.get("rotated"), bool):
            raise PolicyError("goLive.appKeyExposure.rotated must be true or false")
        if not x["rotated"] and x.get("label") != EXPOSED_NOT_ROTATED:
            raise PolicyError(f"goLive.appKeyExposure.label must be {EXPOSED_NOT_ROTATED!r} while rotated is false")
        if not x["rotated"] and not x.get("decision"):
            raise PolicyError("goLive.appKeyExposure.decision must record who accepted the exposure and when")

    def _validate_bypass(self):
        """bypassExceptions: merges into main that the owner approved to land under a recorded
        bypass of main-protection, without gate evidence. Each entry names one PR; only that PR's
        merge commit, resolved from the Pulls API, is covered. Covered means reported in every
        reconciliation report as an exception, never counted as evidence."""
        items = self.data.get("bypassExceptions", [])
        if not isinstance(items, list):
            raise PolicyError("bypassExceptions must be a list")
        self._bypass = {}
        humans = self.data.get("humans") or {}
        ids, never = humans.get("ids") or {}, set(humans.get("neverApprovers") or [])
        anchor = (self.data.get("goLive") or {}).get("anchorPr")
        prs, labels = set(), set()
        for i, e in enumerate(items):
            where = f"bypassExceptions[{i}]"
            keys = {k for k in e if not k.startswith("$")} if isinstance(e, dict) else None
            if keys != BYPASS_KEYS:
                raise PolicyError(f"{where} must have exactly {sorted(BYPASS_KEYS)}")
            pr = e["pr"]
            if not isinstance(pr, int) or isinstance(pr, bool) or pr <= 0:
                raise PolicyError(f"{where}.pr must be a PR number")
            if pr == anchor:
                raise PolicyError(f"{where}.pr is goLive.anchorPr; the go-live merge is bootstrap")
            if not BYPASS_LABEL_RE.fullmatch(str(e["label"])):
                raise PolicyError(f"{where}.label must match {BYPASS_LABEL_RE.pattern}")
            if e["approvedBy"] not in ids or e["approvedBy"] in never:
                raise PolicyError(f"{where}.approvedBy must be a human pinned in humans.ids "
                                  "and not in neverApprovers")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(e["approvedAt"])):
                _epoch(e["approvedAt"], f"{where}.approvedAt")
            if not isinstance(e["reason"], str) or not e["reason"].strip():
                raise PolicyError(f"{where}.reason must say why")
            if pr in prs or e["label"] in labels:
                raise PolicyError(f"{where} repeats PR {pr} or label {e['label']}")
            prs.add(pr)
            labels.add(e["label"])
    def _validate_judging(self):
        for role, j in (self.data.get("judgingWorkflows") or {}).items():
            if role.startswith("$"):
                continue
            if not isinstance(j, dict) or j.get("workflow") not in self.SIGNER_WORKFLOWS \
                    or not j.get("job") or not j.get("predicate"):
                raise PolicyError(f"judgingWorkflows.{role} needs a signer workflow, job and predicate")
    # convenience accessors
    @property
    def repo(self):
        return self.data["repo"]

    def predicate(self, name):
        spec = self.data["predicates"].get(name)
        if spec is None:
            raise PolicyError(f"predicate {name} is not in the trust policy")
        return spec

    def predicate_type(self, name):
        return self.predicate(name).get("predicateType") or f"{PREFIX}{name}/v1"

    def signer_uri(self, workflow):
        return f"https://github.com/{self.repo}/{workflow}@refs/heads/main"

    def signer_workflows(self):
        out = set()
        for spec in self.data["predicates"].values():
            for s in spec["signers"]:
                out.add(s["workflow"])
        return out

    def app(self, role):
        return (self.data.get("apps") or {}).get(role) or {}

    def app_id(self, role):
        return self.app(role).get("id")

    def bot_login(self, role):
        return self.app(role).get("botLogin")

    def humans(self, group):
        return list((self.data.get("humans") or {}).get(group) or [])

    def human_id(self, login):
        return ((self.data.get("humans") or {}).get("ids") or {}).get(login)

    @property
    def sod_shortcut(self):
        return self.data.get("sodShortcut") or {}

    def sod_waives(self, rule, login=None, jira_account=None):
        """True when the sodShortcut identity (by GitHub login or Jira accountId) may skip rule."""
        s = self.sod_shortcut
        if rule not in (s.get("waives") or []):
            return False
        return bool((login and login == s.get("githubLogin"))
                    or (jira_account and jira_account == s.get("jiraAccountId")))

    @property
    def jira(self):
        return self.data.get("jira") or {}

    @property
    def control_paths(self):
        return list(self.data.get("controlPaths") or [])

    def is_control_path(self, path):
        for p in self.control_paths:
            if p.endswith("/") and path.startswith(p):
                return True
            if path == p or (p == "CODEOWNERS" and path.endswith("/CODEOWNERS")):
                return True
        return False

    @property
    def loops(self):
        return self.data.get("loops") or {"maxReviewRounds": 10, "maxQaRounds": 10}

    @property
    def go_live_sha(self):
        return (self.data.get("goLive") or {}).get("mainSha")

    def resolve_go_live(self, get):
        """With goLive.anchorPr, go-live is that PR's merge into main: mainSha is its merge commit
        and at its merged_at, read through get(path) -> JSON. Until it is merged, nothing is
        resolved and every change is bootstrap. A no-op for an explicit goLive.at."""
        g = self.data["goLive"]
        n = g.get("anchorPr")
        if self._go_live_at is not None or n is None:
            return
        pr = get(f"/repos/{self.repo}/pulls/{n}") or {}
        sha = pr.get("merge_commit_sha") or ""
        if not pr.get("merged_at") or (pr.get("base") or {}).get("ref") != "main" \
                or not re.fullmatch(r"[0-9a-f]{40}", sha):
            return
        g["mainSha"], g["at"] = sha, pr["merged_at"]
        self._go_live_at = _epoch(pr["merged_at"], f"merged_at of PR {n}")

    @property
    def bypass_exceptions(self):
        return [dict(e) for e in self.data.get("bypassExceptions") or []]

    def resolve_bypass(self, get):
        """Each bypassExceptions PR's merge commit into main, read through get(path) -> JSON.
        An entry whose PR is not (yet) merged into main covers no commit."""
        self._bypass = {}
        for e in self.bypass_exceptions:
            pr = get(f"/repos/{self.repo}/pulls/{e['pr']}") or {}
            sha = pr.get("merge_commit_sha") or ""
            if pr.get("number") != e["pr"] or not pr.get("merged_at") \
                    or (pr.get("base") or {}).get("ref") != "main" \
                    or not re.fullmatch(r"[0-9a-f]{40}", sha):
                continue
            self._bypass[sha] = dict(e, mergeCommitSha=sha, mergedAt=pr["merged_at"])

    def bypass_for(self, sha):
        """The bypassExceptions entry whose resolved merge commit is sha, or None."""
        return self._bypass.get(sha)

    def bypass_commits(self):
        """{pr: resolved merge commit} for each bypassExceptions PR merged into main."""
        return {e["pr"]: sha for sha, e in self._bypass.items()}

    @property
    def go_live_at(self):
        """Epoch of goLive.at, or None before go-live (bootstrap)."""
        return self._go_live_at

    def app_key(self, role):
        """The role's pinned in-scope key {appId, keyFingerprint}."""
        return (self.data["goLive"]["appKeys"]).get(role)

    @property
    def key_labels(self):
        """Labels every in-scope merge-record and reconciliation item carries (spec 7.6)."""
        x = self.data["goLive"]["appKeyExposure"]
        return [] if x["rotated"] else [x["label"]]

    def role_of_login(self, login):
        for role, a in (self.data.get("apps") or {}).items():
            if isinstance(a, dict) and login and a.get("botLogin") == login:
                return role
        return None

    def judging(self, role):
        return (self.data.get("judgingWorkflows") or {}).get(role)
