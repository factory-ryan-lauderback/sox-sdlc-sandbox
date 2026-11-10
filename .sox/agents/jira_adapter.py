"""Jira adapter: one small interface, two backends.

- CloudJira (default): Jira Cloud REST v3 with the single sandbox API token, which belongs to the
  automation account. Jira records that account as the author of every agent write, so the acting
  agent role is recorded twice by the workflow: the `sox.actingRole` issue property set on create, and
  a `[sox:<role>]` prefix on every agent comment. Both are workflow-asserted (production: one
  Atlassian service account per agent role). Human approvals are never made through this adapter:
  `Approved`, `Approach Approved` and `ECAB Approved` are human-only transitions in the Jira UI.
- FileJira: a JSON file, for unit tests and offline demos only. Identities in it are asserted.

Select with SOX_JIRA_BACKEND=cloud|file (default cloud). Agents never pass free-form identities:
the role comes from the workflow file on main, never from an LLM or an operation list.
"""
import base64
import copy
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

SITE = "https://factory-dev-testing.atlassian.net"
PROJECT = "FRQ"
AUTOMATION_ACCOUNT = "712020:049f9e8f-c2c3-47f9-a0d0-bd0578d23457"
# One workflow for every FRQ work type, all statuses reachable by global transitions.
STATUS_IDS = {
    "Spec Review": "10070", "Approved": "10071", "In Progress": "3", "In Review": "10072", "Done": "10073",
    "Draft": "10079", "Planning": "10080", "Plan Ready": "10081", "Approach Approved": "10082",
    "Ready for Dev": "10083", "Blocked - Human Escalation": "10084", "Re-plan": "10085",
    "Awaiting Release Approval": "10086", "Awaiting Train": "10087", "Released": "10088", "ECAB Approved": "10089",
}
STATUSES = list(STATUS_IDS)
HUMAN_ONLY = {"Approved", "Approach Approved", "ECAB Approved"}
TYPES = ("Requirement", "Epic", "Story", "Task", "Bug")
# Until the "Requirement" work type exists, a requirement is a Story carrying this label.
REQUIREMENT_LABEL = "sox-requirement"
# requirementKey: an Epic's source requirement (Jira cannot parent an Epic under a Story-level issue).
AGENT_FIELDS = ("storyType", "dependsOn", "requiredTests", "services", "idempotencyKey", "release", "requirementKey")
ROLE_PROPERTY = "sox.actingRole"
# intake: step 1, Requirements In, when a requirement is filed through the pipeline instead of the UI.
ROLES = ("intake", "pm", "techlead", "review", "dev", "qa", "attestor", "bundler")
# FileJira authors (asserted). Cloud authorship is always the token's account.
ROLE_ACCOUNTS = {r: f"svc-{r}-agent" for r in ROLES} | {"attestor": "svc-jira-attestor", "bundler": "svc-release-bundler"}
FAKE_HUMANS = {"factory-aman": "712020:ae7e6a76-96e0-4d91-a2ac-857b21c164cd"}


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def role_prefix(role):
    return f"[sox:{role}]"


class JiraError(RuntimeError):
    pass


class IncompleteRead(JiraError):
    """A paginated read could not be shown to be complete. Never sign or snapshot a partial history."""


class Actor:
    """Who is acting. Agents: role in ROLES. Humans exist only in FileJira (demo/test)."""

    def __init__(self, role=None, human=None):
        if (role is None) == (human is None):
            raise JiraError("exactly one of role or human")
        if role is not None and role not in ROLES:
            raise JiraError(f"unknown role {role!r}")
        self.role, self.human = role, human

    @property
    def account(self):
        return self.human or ROLE_ACCOUNTS[self.role]


def _as_actor(a):
    if isinstance(a, Actor):
        return a
    if a in ROLES:
        return Actor(role=a)
    # Legacy svc-* names map back to their role.
    for r, acct in ROLE_ACCOUNTS.items():
        if a == acct:
            return Actor(role=r)
    return Actor(human=a)


class JiraAdapter:
    """Normalized issue: key, type, summary, description, status, statusId, reporter, creator (account
    ids), created, updated, parent, labels, fixVersions (names), attachments[{id, filename, size,
    created}], actingRole (sox.actingRole property), plus AGENT_FIELDS."""

    def get(self, key): raise NotImplementedError
    def search(self, type=None, status=None, parent=None, fix_version=None, label=None, statuses=None): raise NotImplementedError
    def create(self, type, summary, description, actor, parent=None, fields=None, labels=None): raise NotImplementedError
    def update(self, key, actor, summary=None, description=None, fields=None): raise NotImplementedError
    def transition(self, key, to_status, actor): raise NotImplementedError
    def comment(self, key, body, actor): raise NotImplementedError
    def attach(self, key, filename, content, actor): raise NotImplementedError
    def attachment_content(self, key, attachment_id): raise NotImplementedError
    def set_fix_version(self, key, version, actor): raise NotImplementedError
    def add_labels(self, key, labels, actor): raise NotImplementedError
    def versions(self): raise NotImplementedError
    def changelog(self, key): raise NotImplementedError
    def comments(self, key): raise NotImplementedError

    def version_id(self, name):
        for v in self.versions():
            if v["name"] == name:
                return v["id"]
        return None

    def find_by_idempotency(self, idem):
        for issue in self.search():
            if issue.get("idempotencyKey") == idem:
                return issue
        return None

    def _check_transition(self, to_status, actor):
        if to_status not in STATUS_IDS:
            raise JiraError(f"unknown status {to_status!r}")
        if actor.role and to_status in HUMAN_ONLY:
            raise JiraError(f"{to_status!r} is a human-only approval; agents cannot perform it")


def _person_fake(name):
    if name is None:
        return None
    return {"accountId": FAKE_HUMANS.get(name, name), "accountType": "atlassian" if name in FAKE_HUMANS else "fake",
            "displayName": name}


class FileJira(JiraAdapter):
    def __init__(self, path, project=PROJECT):
        self.path, self.project = path, project
        if os.path.exists(path):
            with open(path) as f:
                self.db = json.load(f)
        else:
            self.db = {"schema": "sox-jira-fake/v1", "project": project, "seq": 0, "issues": {}, "versions": {}}

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.db, f, indent=1, sort_keys=True)
            f.write("\n")
        os.replace(tmp, self.path)

    def _issue(self, key):
        try:
            return self.db["issues"][key]
        except KeyError:
            raise JiraError(f"issue does not exist: {key}") from None

    def _log(self, issue, account, items):
        issue["changelog"].append({"id": str(len(issue["changelog"]) + 1), "author": account,
                                   "created": _now(), "items": items})
        issue["updated"] = _now()

    @staticmethod
    def _norm(issue):
        out = {k: copy.deepcopy(v) for k, v in issue.items() if k not in ("changelog", "comments")}
        out["statusId"] = STATUS_IDS.get(issue.get("status"))
        out["attachments"] = [{k: a.get(k) for k in ("id", "filename", "sha256", "size", "created")}
                              for a in issue.get("attachments", [])]
        out.setdefault("actingRole", None)
        for k in AGENT_FIELDS:
            out.setdefault(k, None)
        return out

    def get(self, key):
        return self._norm(self._issue(key))

    def search(self, type=None, status=None, parent=None, fix_version=None, label=None, statuses=None):
        res = []
        for key in sorted(self.db["issues"], key=lambda k: int(k.split("-")[1])):
            i = self.db["issues"][key]
            if type and i["type"] != type: continue
            if status and i["status"] != status: continue
            if statuses and i["status"] not in statuses: continue
            if parent and i.get("parent") != parent: continue
            if fix_version and fix_version not in i.get("fixVersions", []): continue
            if label and label not in i.get("labels", []): continue
            res.append(self._norm(i))
        return res

    def create(self, type, summary, description, actor, parent=None, fields=None, labels=None):
        actor = _as_actor(actor)
        if type not in TYPES:
            raise JiraError(f"unknown issue type {type}")
        if parent:
            self._issue(parent)
        self.db["seq"] += 1
        key = f"{self.project}-{self.db['seq']}"
        now = _now()
        issue = {"key": key, "type": type, "summary": summary, "description": description or "",
                 "status": "Draft" if type == "Requirement" else ("Planning" if type == "Epic" else "Spec Review"),
                 "reporter": actor.account, "creator": actor.account,
                 "created": now, "updated": now, "parent": parent, "labels": sorted(labels or []),
                 "fixVersions": [], "attachments": [], "comments": [], "changelog": [],
                 "actingRole": actor.role}
        for k, v in (fields or {}).items():
            if k not in AGENT_FIELDS:
                raise JiraError(f"unknown field {k}")
            issue[k] = v
        self.db["issues"][key] = issue
        self._log(issue, actor.account, [{"field": "created", "from": None, "to": key}])
        return key

    def update(self, key, actor, summary=None, description=None, fields=None):
        actor = _as_actor(actor)
        issue, items = self._issue(key), []
        for name, val in (("summary", summary), ("description", description)):
            if val is not None and issue[name] != val:
                items.append({"field": name, "from": issue[name], "to": val})
                issue[name] = val
        for k, v in (fields or {}).items():
            if k not in AGENT_FIELDS:
                raise JiraError(f"unknown field {k}")
            if issue.get(k) != v:
                items.append({"field": k, "from": issue.get(k), "to": v})
                issue[k] = v
        if items:
            self._log(issue, actor.account, items)

    def transition(self, key, to_status, actor):
        actor = _as_actor(actor)
        self._check_transition(to_status, actor)
        issue = self._issue(key)
        if issue["status"] != to_status:
            self._log(issue, actor.account, [{"field": "status", "from": issue["status"], "to": to_status,
                                              "fromId": STATUS_IDS.get(issue["status"]), "toId": STATUS_IDS[to_status]}])
            issue["status"] = to_status

    def comment(self, key, body, actor):
        actor = _as_actor(actor)
        issue = self._issue(key)
        cid = f"{key}-c{len(issue['comments']) + 1}"
        issue["comments"].append({"id": cid, "author": actor.account, "body": body, "created": _now()})
        issue["updated"] = _now()
        return cid

    def attach(self, key, filename, content, actor):
        actor = _as_actor(actor)
        issue = self._issue(key)
        if isinstance(content, str):
            content = content.encode()
        aid = f"{key}-a{len(issue['attachments']) + 1}"
        issue["attachments"].append({"id": aid, "filename": filename, "sha256": hashlib.sha256(content).hexdigest(),
                                     "size": len(content), "created": _now(),
                                     "content_b64": base64.b64encode(content).decode()})
        self._log(issue, actor.account, [{"field": "Attachment", "from": None, "to": aid, "toString": filename}])
        return aid

    def attachment_content(self, key, attachment_id):
        for a in self._issue(key)["attachments"]:
            if a["id"] == attachment_id:
                return base64.b64decode(a["content_b64"])
        raise JiraError(f"no attachment {attachment_id} on {key}")

    def set_fix_version(self, key, version, actor):
        actor = _as_actor(actor)
        issue = self._issue(key)
        self.db["versions"].setdefault(version, {"id": str(len(self.db["versions"]) + 1), "name": version, "released": False})
        if issue["fixVersions"] != [version]:
            self._log(issue, actor.account, [{"field": "Fix Version", "from": issue["fixVersions"], "to": [version]}])
            issue["fixVersions"] = [version]

    def add_labels(self, key, labels, actor):
        actor = _as_actor(actor)
        issue = self._issue(key)
        new = sorted(set(issue["labels"]) | set(labels))
        if new != issue["labels"]:
            self._log(issue, actor.account, [{"field": "labels", "from": " ".join(issue["labels"]), "to": " ".join(new)}])
            issue["labels"] = new

    def versions(self):
        return [{"id": v["id"], "name": v["name"], "released": v.get("released", False), "archived": False,
                 "releaseDate": None} for v in self.db.get("versions", {}).values()]

    def changelog(self, key):
        """Snapshot/attestor shape: {id, created, author{accountId, accountType}, items[{field, from, to, fromString, toString}]}."""
        out = []
        for h in self._issue(key)["changelog"]:
            p = _person_fake(h["author"])
            items = [{"field": i["field"], "from": i.get("fromId", i.get("from")), "to": i.get("toId", i.get("to")),
                      "fromString": i.get("fromString", i.get("from")), "toString": i.get("toString", i.get("to"))}
                     for i in h["items"]]
            out.append({"id": h["id"], "created": h["created"],
                        "author": {"accountId": p["accountId"], "accountType": p["accountType"]}, "items": items})
        return out

    def comments(self, key):
        return [{"id": c["id"], "created": c["created"], "author": _person_fake(c["author"]), "body": c["body"]}
                for c in self._issue(key)["comments"]]

    def people(self, key):
        i = self._issue(key)
        return _person_fake(i.get("reporter")), _person_fake(i.get("creator"))


# --- Atlassian Document Format (v3 API) -------------------------------------------------------------

def text_to_adf(text):
    paras = []
    for block in (text or "").split("\n\n"):
        content = []
        for n, line in enumerate(block.split("\n")):
            if n:
                content.append({"type": "hardBreak"})
            if line:
                content.append({"type": "text", "text": line})
        paras.append({"type": "paragraph", "content": content})
    return {"type": "doc", "version": 1, "content": paras or [{"type": "paragraph", "content": []}]}


def adf_to_text(node):
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    t = node.get("type")
    if t == "text":
        return node.get("text", "")
    if t == "hardBreak":
        return "\n"
    inner = "".join(adf_to_text(c) for c in node.get("content") or [])
    if t in ("paragraph", "heading", "codeBlock", "blockquote", "rule"):
        return inner + "\n\n"
    if t == "listItem":
        return "- " + inner.strip() + "\n"
    if t in ("bulletList", "orderedList"):
        return inner + "\n"
    return inner


def person(p):
    if not p:
        return None
    return {"accountId": p.get("accountId"), "accountType": p.get("accountType"), "displayName": p.get("displayName")}


ISSUE_FIELDS = ["summary", "description", "status", "issuetype", "labels", "fixVersions", "parent",
                "reporter", "creator", "created", "updated", "attachment"]


class CloudJira(JiraAdapter):
    def __init__(self, site, email, token, project=PROJECT, agent_accounts=None):
        self.site, self.project = site.rstrip("/"), project
        self.auth = base64.b64encode(f"{email}:{token}".encode()).decode()
        self.agent_accounts = set(agent_accounts or [AUTOMATION_ACCOUNT])
        self._me = None
        self._types = None
        self._project_id = None

    # -- transport
    def _req(self, method, path, body=None, headers=None, raw=False, data=None, ok404=False):
        url = path if path.startswith("http") else f"{self.site}{path}"
        payload = data if data is not None else (json.dumps(body).encode() if body is not None else None)
        for attempt in range(5):
            req = urllib.request.Request(url, method=method, data=payload)
            req.add_header("Authorization", f"Basic {self.auth}")
            req.add_header("Accept", "application/json" if not raw else "*/*")
            if body is not None:
                req.add_header("Content-Type", "application/json")
            for k, v in (headers or {}).items():
                req.add_header(k, v)
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    out = resp.read()
                    return out if raw else (json.loads(out) if out else None)
            except urllib.error.HTTPError as e:
                if e.code == 404 and ok404:
                    return None
                if e.code in (429, 500, 502, 503, 504) and attempt < 4 and method == "GET":
                    time.sleep(int(e.headers.get("Retry-After") or 2 ** attempt))
                    continue
                raise JiraError(f"{method} {path.split('?')[0]}: HTTP {e.code} {e.read()[:300].decode(errors='replace')}") from None
            except urllib.error.URLError as e:
                if attempt < 4 and method == "GET":
                    time.sleep(2 ** attempt)
                    continue
                raise JiraError(f"{method} {path.split('?')[0]}: {e.reason}") from None

    def _check_agent_token(self):
        """The token must belong to an agent (automation) account, never to a human approver."""
        if self._me is None:
            self._me = self._req("GET", "/rest/api/3/myself")
        if self._me.get("accountId") not in self.agent_accounts:
            raise JiraError("the Jira token does not belong to a configured agent account; refusing to write")

    def _type_names(self):
        if self._types is None:
            p = self._req("GET", f"/rest/api/3/project/{self.project}")
            self._project_id = p["id"]
            self._types = {t["name"] for t in p.get("issueTypes", [])}
        return self._types

    def _jira_type(self, type):
        if type == "Requirement" and "Requirement" not in self._type_names():
            return "Story", [REQUIREMENT_LABEL]
        return type, []

    # -- reads
    def _norm(self, raw):
        f = raw["fields"]
        labels = sorted(f.get("labels") or [])
        typ = f["issuetype"]["name"]
        if REQUIREMENT_LABEL in labels and typ == "Story":
            typ = "Requirement"
        props = raw.get("properties") or {}
        agent = props.get("sox.agent") or {}
        out = {"key": raw["key"], "id": raw.get("id"), "type": typ, "summary": f.get("summary"),
               "description": adf_to_text(f.get("description")).strip(), "status": f["status"]["name"],
               "statusId": f["status"]["id"],
               "reporter": (f.get("reporter") or {}).get("accountId"), "creator": (f.get("creator") or {}).get("accountId"),
               "created": f.get("created"), "updated": f.get("updated"),
               "parent": (f.get("parent") or {}).get("key"), "labels": labels,
               "fixVersions": [v["name"] for v in f.get("fixVersions") or []],
               "attachments": [{"id": a["id"], "filename": a["filename"], "sha256": None, "size": a.get("size"),
                                "created": a.get("created")} for a in f.get("attachment") or []],
               "actingRole": (props.get(ROLE_PROPERTY) or {}).get("role")}
        for k in AGENT_FIELDS:
            out[k] = agent.get(k)
        return out

    def raw(self, key):
        q = urllib.parse.urlencode({"fields": ",".join(ISSUE_FIELDS), "properties": f"sox.agent,{ROLE_PROPERTY}"})
        return self._req("GET", f"/rest/api/3/issue/{urllib.parse.quote(key)}?{q}")

    def get(self, key):
        return self._norm(self.raw(key))

    def jql(self, jql, limit=2000):
        """All issues for a JQL query (new /search/jql endpoint, token pagination). Raw issues."""
        out, token = [], None
        for _ in range(limit // 100 + 2):
            body = {"jql": jql, "maxResults": 100, "fields": ISSUE_FIELDS, "properties": ["sox.agent", ROLE_PROPERTY]}
            if token:
                body["nextPageToken"] = token
            res = self._req("POST", "/rest/api/3/search/jql", body)
            out.extend(res.get("issues", []))
            if res.get("isLast", not res.get("nextPageToken")):
                return out
            token = res.get("nextPageToken")
            if not token:
                raise IncompleteRead(f"search: isLast false without nextPageToken ({jql})")
        raise IncompleteRead(f"search exceeded {limit} issues ({jql})")

    def search_jql(self, type=None, status=None, parent=None, fix_version=None, label=None, statuses=None):
        clauses = [f'project = "{self.project}"']
        if type:
            jt, labels = self._jira_type(type)
            clauses.append(f'issuetype = "{jt}"')
            for lab in labels:
                clauses.append(f'labels = "{lab}"')
            if type == "Story" and "Requirement" not in self._type_names():
                clauses.append(f'(labels IS EMPTY OR labels != "{REQUIREMENT_LABEL}")')
        if status: clauses.append(f'status = "{status}"')
        if statuses: clauses.append("status in (" + ", ".join(f'"{s}"' for s in statuses) + ")")
        if parent: clauses.append(f'parent = "{parent}"')
        if fix_version: clauses.append(f'fixVersion = "{fix_version}"')
        if label: clauses.append(f'labels = "{label}"')
        for c in (type, status, parent, fix_version, label, *(statuses or [])):
            if c and '"' in str(c):
                raise JiraError("quote in a search value")
        return " AND ".join(clauses) + " ORDER BY key ASC"

    def search(self, type=None, status=None, parent=None, fix_version=None, label=None, statuses=None):
        return [self._norm(i) for i in self.jql(self.search_jql(type, status, parent, fix_version, label, statuses))]

    def _paged(self, path, key):
        """Offset-paginated list (changelog, comments) that must be provably complete."""
        out, start = [], 0
        while True:
            sep = "&" if "?" in path else "?"
            res = self._req("GET", f"{path}{sep}startAt={start}&maxResults=100")
            items = res.get(key) or []
            total = res.get("total")
            if res.get("startAt", start) != start:
                raise IncompleteRead(f"{path}: asked for startAt {start}, got {res.get('startAt')}")
            out.extend(items)
            start += len(items)
            last = res.get("isLast")
            if last is True or (last is None and total is not None and start >= total):
                break
            if not items:
                raise IncompleteRead(f"{path}: empty page at {start} before the end (total {total})")
        if total is not None and len(out) != total:
            raise IncompleteRead(f"{path}: read {len(out)} of {total}")
        ids = [x.get("id") for x in out]
        if len(set(ids)) != len(ids):
            raise IncompleteRead(f"{path}: duplicate entries across pages")
        return out

    def changelog(self, key):
        entries = self._paged(f"/rest/api/3/issue/{urllib.parse.quote(key)}/changelog", "values")
        return [{"id": h["id"], "created": h["created"],
                 "author": {"accountId": (h.get("author") or {}).get("accountId"),
                            "accountType": (h.get("author") or {}).get("accountType")},
                 "items": [{"field": i.get("field"), "from": i.get("from"), "to": i.get("to"),
                            "fromString": i.get("fromString"), "toString": i.get("toString")} for i in h.get("items", [])]}
                for h in entries]

    def comments(self, key):
        res = self._paged(f"/rest/api/3/issue/{urllib.parse.quote(key)}/comment?orderBy=created", "comments")
        return [{"id": c["id"], "created": c["created"], "author": person(c.get("author")),
                 "body": adf_to_text(c.get("body")).strip()} for c in res]

    def groups_of(self, account_id):
        res = self._req("GET", "/rest/api/3/user/groups?" + urllib.parse.urlencode({"accountId": account_id})) or []
        return sorted(g["name"] for g in res)

    def people(self, key):
        f = self.raw(key)["fields"]
        return person(f.get("reporter")), person(f.get("creator"))

    def versions(self):
        vs = self._req("GET", f"/rest/api/3/project/{self.project}/versions") or []
        return [{"id": v["id"], "name": v["name"], "released": bool(v.get("released")), "archived": bool(v.get("archived")),
                 "releaseDate": v.get("releaseDate")} for v in vs]

    def attachment_content(self, key, attachment_id):
        return self._req("GET", f"/rest/api/3/attachment/content/{urllib.parse.quote(str(attachment_id))}", raw=True)

    # -- writes (agent token only)
    def create(self, type, summary, description, actor, parent=None, fields=None, labels=None):
        actor = _as_actor(actor)
        if not actor.role:
            raise JiraError("Cloud writes are agent-only; humans act in the Jira UI")
        self._check_agent_token()
        jt, extra = self._jira_type(type)
        body = {"fields": {"project": {"key": self.project}, "issuetype": {"name": jt}, "summary": summary,
                           "description": text_to_adf(description), "labels": sorted(set((labels or []) + extra))},
                "properties": [{"key": ROLE_PROPERTY, "value": {"role": actor.role, "run": _run_url()}}]}
        if fields:
            bad = [k for k in fields if k not in AGENT_FIELDS]
            if bad:
                raise JiraError(f"unknown field {bad}")
            body["properties"].append({"key": "sox.agent", "value": fields})
        if parent:
            body["fields"]["parent"] = {"key": parent}
        return self._req("POST", "/rest/api/3/issue", body)["key"]

    def update(self, key, actor, summary=None, description=None, fields=None):
        actor = _as_actor(actor)
        self._check_agent_token()
        upd = {}
        if summary is not None: upd["summary"] = summary
        if description is not None: upd["description"] = text_to_adf(description)
        if upd:
            self._req("PUT", f"/rest/api/3/issue/{key}", {"fields": upd})
        if fields:
            bad = [k for k in fields if k not in AGENT_FIELDS]
            if bad:
                raise JiraError(f"unknown field {bad}")
            cur = (self._req("GET", f"/rest/api/3/issue/{key}/properties/sox.agent", ok404=True) or {}).get("value") or {}
            cur.update(fields)
            self._req("PUT", f"/rest/api/3/issue/{key}/properties/sox.agent", cur)

    def transition(self, key, to_status, actor):
        actor = _as_actor(actor)
        self._check_transition(to_status, actor)
        self._check_agent_token()
        cur = self.raw(key)["fields"]["status"]["name"]
        if cur == to_status:
            return
        ts = self._req("GET", f"/rest/api/3/issue/{key}/transitions")["transitions"]
        for t in ts:
            if t["to"]["id"] == STATUS_IDS[to_status]:
                return self._req("POST", f"/rest/api/3/issue/{key}/transitions", {"transition": {"id": t["id"]}})
        raise JiraError(f"no transition from {cur!r} of {key} to {to_status!r}")

    def comment(self, key, body, actor):
        actor = _as_actor(actor)
        self._check_agent_token()
        return self._req("POST", f"/rest/api/3/issue/{key}/comment", {"body": text_to_adf(body)})["id"]

    def attach(self, key, filename, content, actor):
        actor = _as_actor(actor)
        self._check_agent_token()
        if isinstance(content, str):
            content = content.encode()
        boundary = "soxboundary" + hashlib.sha256(content).hexdigest()[:24]
        safe = filename.replace('"', "")
        data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{safe}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
        res = self._req("POST", f"/rest/api/3/issue/{key}/attachments", data=data,
                        headers={"X-Atlassian-Token": "no-check", "Content-Type": f"multipart/form-data; boundary={boundary}"})
        return res[0]["id"]

    def set_fix_version(self, key, version, actor):
        actor = _as_actor(actor)
        self._check_agent_token()
        if self.version_id(version) is None:
            self._type_names()
            self._req("POST", "/rest/api/3/version", {"name": version, "projectId": int(self._project_id)})
        self._req("PUT", f"/rest/api/3/issue/{key}", {"update": {"fixVersions": [{"set": [{"name": version}]}]}})

    def add_labels(self, key, labels, actor):
        actor = _as_actor(actor)
        self._check_agent_token()
        self._req("PUT", f"/rest/api/3/issue/{key}", {"update": {"labels": [{"add": l} for l in sorted(set(labels))]}})


def _run_url():
    s, r, i = os.environ.get("GITHUB_SERVER_URL"), os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_RUN_ID")
    return f"{s}/{r}/actions/runs/{i}" if s and r and i else None


def from_env(account=None):
    backend = os.environ.get("SOX_JIRA_BACKEND") or "cloud"
    if backend == "file":
        return FileJira(os.environ.get("SOX_JIRA_FILE", "jira-fake/jira.json"))
    if backend == "cloud":
        email, token = os.environ.get("SOX_JIRA_EMAIL"), os.environ.get("JIRA_API_TOKEN")
        if not token:
            path = os.path.expanduser(os.environ.get("JIRA_CREDENTIALS_FILE", "~/.factory/secrets/jira"))
            if not os.path.exists(path):
                raise SystemExit("no Jira credentials: set JIRA_API_TOKEN and SOX_JIRA_EMAIL (env jira-attestor only)")
            with open(path) as f:
                lines = f.read().split("\n")
            email, token = email or lines[0].strip(), lines[1].strip()
        if not email:
            raise SystemExit("SOX_JIRA_EMAIL is not set")
        accounts = [a for a in os.environ.get("SOX_JIRA_AGENT_ACCOUNT_IDS", AUTOMATION_ACCOUNT).split(",") if a]
        return CloudJira(os.environ.get("SOX_JIRA_SITE", SITE), email, token, os.environ.get("SOX_JIRA_PROJECT", PROJECT), accounts)
    raise SystemExit(f"unknown SOX_JIRA_BACKEND {backend!r}")


def apply_ops(jira, ops, role):
    """Apply a list of write operations as one agent role. `$name` references resolve to keys created
    earlier in the same list. Creates are idempotent through `idempotencyKey`. Every create gets a
    `[sox:<role>]` comment and every comment carries that prefix, so the acting role is visible in
    Jira even though one account performs all agent writes. `${name}` inside comment bodies and text
    attachments is replaced by the key created as `name`. Labels can only be added (`labels` op), so an
    agent can raise an Epic to risk-high but never lower it."""
    actor = _as_actor(role)
    if not actor.role:
        raise JiraError("apply_ops is for agent roles only")
    prefix = role_prefix(actor.role)
    refs, results = {}, []

    def res(v):
        return refs.get(v[1:], v) if isinstance(v, str) and v.startswith("$") else v

    def subst(text):
        return re.sub(r"\$\{([A-Za-z0-9_]+)\}", lambda m: refs.get(m.group(1), m.group(0)), text)

    def tagged(body):
        body = subst(body)
        return body if body.startswith(prefix) else f"{prefix} {body}"

    for op in ops:
        kind = op["op"]
        if kind == "create":
            fields = dict(op.get("fields") or {})
            idem = fields.get("idempotencyKey")
            existing = jira.find_by_idempotency(idem) if idem else None
            if existing:
                key = existing["key"]
            else:
                key = jira.create(op["type"], op["summary"], op.get("description", ""), actor,
                                  parent=res(op.get("parent")), fields=fields, labels=op.get("labels"))
                run = _run_url()
                jira.comment(key, tagged(f"Created by the {actor.role} agent" + (f" in {run}" if run else "") + "."), actor)
            if op.get("ref"):
                refs[op["ref"]] = key
            results.append({"op": "create", "key": key, "existing": bool(existing)})
        elif kind == "update":
            fields = {k: ([res(x) for x in v] if k == "dependsOn" and isinstance(v, list) else v)
                      for k, v in (op.get("fields") or {}).items()}
            jira.update(res(op["key"]), actor, op.get("summary"), op.get("description"), fields)
            results.append({"op": "update", "key": res(op["key"])})
        elif kind == "transition":
            jira.transition(res(op["key"]), op["to"], actor)
            results.append({"op": "transition", "key": res(op["key"]), "to": op["to"]})
        elif kind == "comment":
            results.append({"op": "comment", "key": res(op["key"]), "id": jira.comment(res(op["key"]), tagged(op["body"]), actor)})
        elif kind == "attach":
            content = subst(op["content"]) if isinstance(op["content"], str) else op["content"]
            results.append({"op": "attach", "key": res(op["key"]),
                            "id": jira.attach(res(op["key"]), op["filename"], content, actor)})
        elif kind == "fixVersion":
            jira.set_fix_version(res(op["key"]), op["version"], actor)
            results.append({"op": "fixVersion", "key": res(op["key"]), "version": op["version"]})
        elif kind == "labels":
            jira.add_labels(res(op["key"]), list(op["add"]), actor)
            results.append({"op": "labels", "key": res(op["key"]), "add": sorted(op["add"])})
        else:
            raise JiraError(f"unknown op {kind}")
    return results, refs
