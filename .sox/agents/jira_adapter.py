"""Jira adapter: one small interface, two backends.

- FileJira: JSON file store (the fake). In Actions the file lives on branch `sox-jira-fake` and is
  synced by jira_store.py. Identities recorded here are asserted by the writing workflow, so they
  are weaker evidence than a real Jira changelog.
- CloudJira: Jira Cloud REST v2 with one API token per service account. The adapter checks that
  the token really belongs to the account it is asked to act as.

Select with SOX_JIRA_BACKEND=file|cloud (default file). Switching is configuration only.
Agents never call this with free-form identities: the account comes from the workflow, not the LLM.
"""
import base64
import copy
import json
import os
import time
import urllib.error
import urllib.request

STATUSES = {
    "Requirement": ["Draft", "Approved", "Planned"],
    "Epic": ["Planning", "Plan Ready", "Approach Approved", "In Build", "Done"],
    "Story": ["To Do", "Ready for Dev", "In Dev", "In Review", "In QA", "Done",
              "Blocked - Human Escalation", "Re-plan"],
}
AGENT_FIELDS = ("storyType", "dependsOn", "requiredTests", "services", "idempotencyKey", "release")


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class JiraError(RuntimeError):
    pass


class JiraAdapter:
    """Normalized issue: key, type, summary, description, status, reporter, creator, created,
    updated, parent, labels, fixVersions, attachments[{id, filename, sha256}], plus AGENT_FIELDS."""

    def get(self, key): raise NotImplementedError
    def search(self, type=None, status=None, parent=None, fix_version=None, label=None): raise NotImplementedError
    def create(self, type, summary, description, account, parent=None, fields=None, labels=None): raise NotImplementedError
    def update(self, key, account, summary=None, description=None, fields=None): raise NotImplementedError
    def transition(self, key, to_status, account): raise NotImplementedError
    def comment(self, key, body, account): raise NotImplementedError
    def attach(self, key, filename, content, account): raise NotImplementedError
    def attachment_content(self, key, attachment_id): raise NotImplementedError
    def set_fix_version(self, key, version, account): raise NotImplementedError
    def changelog(self, key): raise NotImplementedError
    def comments(self, key): raise NotImplementedError

    def find_by_idempotency(self, idem):
        for issue in self.search():
            if issue.get("idempotencyKey") == idem:
                return issue
        return None


class FileJira(JiraAdapter):
    def __init__(self, path, project="FRQ"):
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
        out["attachments"] = [{k: a[k] for k in ("id", "filename", "sha256")} for a in issue["attachments"]]
        for k in AGENT_FIELDS:
            out.setdefault(k, None)
        return out

    def get(self, key):
        return self._norm(self._issue(key))

    def search(self, type=None, status=None, parent=None, fix_version=None, label=None):
        res = []
        for key in sorted(self.db["issues"], key=lambda k: int(k.split("-")[1])):
            i = self.db["issues"][key]
            if type and i["type"] != type: continue
            if status and i["status"] != status: continue
            if parent and i.get("parent") != parent: continue
            if fix_version and fix_version not in i["fixVersions"]: continue
            if label and label not in i["labels"]: continue
            res.append(self._norm(i))
        return res

    def create(self, type, summary, description, account, parent=None, fields=None, labels=None):
        if type not in STATUSES:
            raise JiraError(f"unknown issue type {type}")
        if parent:
            self._issue(parent)
        self.db["seq"] += 1
        key = f"{self.project}-{self.db['seq']}"
        now = _now()
        issue = {"key": key, "type": type, "summary": summary, "description": description or "",
                 "status": STATUSES[type][0], "reporter": account, "creator": account,
                 "created": now, "updated": now, "parent": parent, "labels": sorted(labels or []),
                 "fixVersions": [], "attachments": [], "comments": [], "changelog": []}
        for k, v in (fields or {}).items():
            if k not in AGENT_FIELDS:
                raise JiraError(f"unknown field {k}")
            issue[k] = v
        self.db["issues"][key] = issue
        self._log(issue, account, [{"field": "created", "from": None, "to": key}])
        return key

    def update(self, key, account, summary=None, description=None, fields=None):
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
            self._log(issue, account, items)

    def transition(self, key, to_status, account):
        issue = self._issue(key)
        if to_status not in STATUSES[issue["type"]]:
            raise JiraError(f"{issue['type']} has no status {to_status!r}")
        if issue["status"] != to_status:
            self._log(issue, account, [{"field": "status", "from": issue["status"], "to": to_status}])
            issue["status"] = to_status

    def comment(self, key, body, account):
        issue = self._issue(key)
        cid = f"{key}-c{len(issue['comments']) + 1}"
        issue["comments"].append({"id": cid, "author": account, "body": body, "created": _now()})
        issue["updated"] = _now()
        return cid

    def attach(self, key, filename, content, account):
        import hashlib
        issue = self._issue(key)
        if isinstance(content, str):
            content = content.encode()
        aid = f"{key}-a{len(issue['attachments']) + 1}"
        issue["attachments"].append({"id": aid, "filename": filename, "sha256": hashlib.sha256(content).hexdigest(),
                                     "content_b64": base64.b64encode(content).decode()})
        self._log(issue, account, [{"field": "attachment", "from": None, "to": f"{aid}:{filename}"}])
        return aid

    def attachment_content(self, key, attachment_id):
        for a in self._issue(key)["attachments"]:
            if a["id"] == attachment_id:
                return base64.b64decode(a["content_b64"])
        raise JiraError(f"no attachment {attachment_id} on {key}")

    def set_fix_version(self, key, version, account):
        issue = self._issue(key)
        self.db["versions"].setdefault(version, {"id": str(len(self.db["versions"]) + 1), "name": version, "released": False})
        if issue["fixVersions"] != [version]:
            self._log(issue, account, [{"field": "fixVersion", "from": issue["fixVersions"], "to": [version]}])
            issue["fixVersions"] = [version]

    def changelog(self, key):
        return copy.deepcopy(self._issue(key)["changelog"])

    def comments(self, key):
        return copy.deepcopy(self._issue(key)["comments"])


class CloudJira(JiraAdapter):
    """Jira Cloud. Agent fields live in issue properties (`sox.agent`) so no custom fields are needed;
    statuses come from the FRQ workflow and must match STATUSES (configure names in SOX_JIRA_STATUS_MAP)."""

    def __init__(self, site, email, token, project="FRQ", expected_account=None):
        self.site, self.project = site.rstrip("/"), project
        self.auth = base64.b64encode(f"{email}:{token}".encode()).decode()
        self.status_map = json.loads(os.environ.get("SOX_JIRA_STATUS_MAP", "{}"))
        self._me = None
        self.expected_account = expected_account

    def _req(self, method, path, body=None, headers=None, raw=False, data=None):
        req = urllib.request.Request(f"{self.site}{path}", method=method,
                                     data=data if data is not None else (json.dumps(body).encode() if body is not None else None))
        req.add_header("Authorization", f"Basic {self.auth}")
        req.add_header("Accept", "application/json")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = resp.read()
                return payload if raw else (json.loads(payload) if payload else None)
        except urllib.error.HTTPError as e:
            raise JiraError(f"{method} {path}: HTTP {e.code} {e.read()[:300].decode(errors='replace')}") from None

    def _check_account(self, account):
        if self._me is None:
            self._me = self._req("GET", "/rest/api/2/myself")
        names = {self._me.get("accountId"), self._me.get("displayName"), self._me.get("emailAddress")}
        if account not in names:
            raise JiraError(f"token belongs to {self._me.get('displayName')!r}, not {account!r}")

    def _props(self, key):
        try:
            return self._req("GET", f"/rest/api/2/issue/{key}/properties/sox.agent")["value"]
        except JiraError:
            return {}

    def _norm(self, raw):
        f = raw["fields"]
        out = {"key": raw["key"], "type": f["issuetype"]["name"], "summary": f.get("summary"),
               "description": f.get("description") or "", "status": f["status"]["name"],
               "reporter": (f.get("reporter") or {}).get("displayName"),
               "creator": (f.get("creator") or {}).get("displayName"),
               "created": f.get("created"), "updated": f.get("updated"),
               "parent": (f.get("parent") or {}).get("key"), "labels": sorted(f.get("labels") or []),
               "fixVersions": [v["name"] for v in f.get("fixVersions") or []],
               "attachments": [{"id": a["id"], "filename": a["filename"], "sha256": None} for a in f.get("attachment") or []]}
        props = self._props(raw["key"])
        for k in AGENT_FIELDS:
            out[k] = props.get(k)
        return out

    def get(self, key):
        return self._norm(self._req("GET", f"/rest/api/2/issue/{key}"))

    def search(self, type=None, status=None, parent=None, fix_version=None, label=None):
        clauses = [f'project = "{self.project}"']
        if type: clauses.append(f'issuetype = "{type}"')
        if status: clauses.append(f'status = "{self.status_map.get(status, status)}"')
        if parent: clauses.append(f'parent = "{parent}"')
        if fix_version: clauses.append(f'fixVersion = "{fix_version}"')
        if label: clauses.append(f'labels = "{label}"')
        res = self._req("POST", "/rest/api/2/search", {"jql": " AND ".join(clauses) + " ORDER BY key ASC", "maxResults": 200})
        return [self._norm(i) for i in res["issues"]]

    def create(self, type, summary, description, account, parent=None, fields=None, labels=None):
        self._check_account(account)
        body = {"fields": {"project": {"key": self.project}, "issuetype": {"name": type}, "summary": summary,
                           "description": description or "", "labels": labels or []}}
        if parent:
            body["fields"]["parent"] = {"key": parent}
        key = self._req("POST", "/rest/api/2/issue", body)["key"]
        if fields:
            self._req("PUT", f"/rest/api/2/issue/{key}/properties/sox.agent", fields)
        return key

    def update(self, key, account, summary=None, description=None, fields=None):
        self._check_account(account)
        upd = {k: v for k, v in (("summary", summary), ("description", description)) if v is not None}
        if upd:
            self._req("PUT", f"/rest/api/2/issue/{key}", {"fields": upd})
        if fields:
            props = self._props(key)
            props.update(fields)
            self._req("PUT", f"/rest/api/2/issue/{key}/properties/sox.agent", props)

    def transition(self, key, to_status, account):
        self._check_account(account)
        target = self.status_map.get(to_status, to_status)
        ts = self._req("GET", f"/rest/api/2/issue/{key}/transitions")["transitions"]
        for t in ts:
            if t["to"]["name"] == target:
                return self._req("POST", f"/rest/api/2/issue/{key}/transitions", {"transition": {"id": t["id"]}})
        raise JiraError(f"no transition from current status of {key} to {target!r}")

    def comment(self, key, body, account):
        self._check_account(account)
        return self._req("POST", f"/rest/api/2/issue/{key}/comment", {"body": body})["id"]

    def attach(self, key, filename, content, account):
        self._check_account(account)
        if isinstance(content, str):
            content = content.encode()
        boundary = "soxboundary" + str(int(time.time()))
        data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
        res = self._req("POST", f"/rest/api/2/issue/{key}/attachments", data=data,
                        headers={"X-Atlassian-Token": "no-check", "Content-Type": f"multipart/form-data; boundary={boundary}"})
        return res[0]["id"]

    def attachment_content(self, key, attachment_id):
        return self._req("GET", f"/rest/api/2/attachment/content/{attachment_id}", raw=True)

    def set_fix_version(self, key, version, account):
        self._check_account(account)
        self._req("PUT", f"/rest/api/2/issue/{key}", {"update": {"fixVersions": [{"set": [{"name": version}]}]}})

    def changelog(self, key):
        res = self._req("GET", f"/rest/api/2/issue/{key}/changelog?maxResults=100")
        return [{"id": h["id"], "author": h["author"].get("displayName"), "created": h["created"],
                 "items": [{"field": i["field"], "from": i.get("fromString"), "to": i.get("toString")} for i in h["items"]]}
                for h in res["values"]]

    def comments(self, key):
        res = self._req("GET", f"/rest/api/2/issue/{key}/comment")
        return [{"id": c["id"], "author": c["author"].get("displayName"), "body": c["body"], "created": c["created"]}
                for c in res["comments"]]


def from_env(account=None):
    backend = os.environ.get("SOX_JIRA_BACKEND", "file")
    if backend == "file":
        return FileJira(os.environ.get("SOX_JIRA_FILE", "jira-fake/jira.json"))
    if backend == "cloud":
        token = os.environ.get("JIRA_API_TOKEN")
        if not token:
            token_file = os.path.expanduser(os.environ.get("JIRA_API_TOKEN_FILE", "~/.factory/secrets/jira"))
            with open(token_file) as f:
                token = f.read().strip()
        return CloudJira(os.environ.get("SOX_JIRA_SITE", "https://factory-dev-testing.atlassian.net"),
                         os.environ["SOX_JIRA_EMAIL"], token, os.environ.get("SOX_JIRA_PROJECT", "FRQ"), account)
    raise SystemExit(f"unknown SOX_JIRA_BACKEND {backend!r}")


def apply_ops(jira, ops, account):
    """Apply a list of write operations as one service account. `$name` references resolve to keys
    created earlier in the same list. Creates are idempotent through `idempotencyKey`."""
    refs, results = {}, []

    def res(v):
        return refs.get(v[1:], v) if isinstance(v, str) and v.startswith("$") else v

    for op in ops:
        kind = op["op"]
        if kind == "create":
            fields = dict(op.get("fields") or {})
            idem = fields.get("idempotencyKey")
            existing = jira.find_by_idempotency(idem) if idem else None
            key = existing["key"] if existing else jira.create(op["type"], op["summary"], op.get("description", ""), account,
                                                               parent=res(op.get("parent")), fields=fields, labels=op.get("labels"))
            if op.get("ref"):
                refs[op["ref"]] = key
            results.append({"op": "create", "key": key, "existing": bool(existing)})
        elif kind == "update":
            fields = {k: ([res(x) for x in v] if k == "dependsOn" and isinstance(v, list) else v)
                      for k, v in (op.get("fields") or {}).items()}
            jira.update(res(op["key"]), account, op.get("summary"), op.get("description"), fields)
            results.append({"op": "update", "key": res(op["key"])})
        elif kind == "transition":
            jira.transition(res(op["key"]), op["to"], account)
            results.append({"op": "transition", "key": res(op["key"]), "to": op["to"]})
        elif kind == "comment":
            results.append({"op": "comment", "key": res(op["key"]), "id": jira.comment(res(op["key"]), op["body"], account)})
        elif kind == "attach":
            results.append({"op": "attach", "key": res(op["key"]),
                            "id": jira.attach(res(op["key"]), op["filename"], op["content"], account)})
        elif kind == "fixVersion":
            jira.set_fix_version(res(op["key"]), op["version"], account)
            results.append({"op": "fixVersion", "key": res(op["key"]), "version": op["version"]})
        else:
            raise JiraError(f"unknown op {kind}")
    return results, refs
