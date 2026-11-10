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


class PolicyError(ValueError):
    pass


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
        self._validate_humans()

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
