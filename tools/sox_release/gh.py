"""Minimal GitHub REST client. The token comes from the environment and is never logged."""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


class GitHubError(Exception):
    def __init__(self, status, method, path, body):
        super().__init__(f"{method} {path} -> {status}: {body[:300]}")
        self.status = status
        self.body = body


class GitHub:
    def __init__(self, token=None, repo=None):
        self.token = token or os.environ.get("SOX_GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        self.repo = repo or os.environ.get("GITHUB_REPOSITORY")
        if not self.repo:
            raise ValueError("GITHUB_REPOSITORY not set")

    def request(self, method, path, body=None, accept="application/vnd.github+json", retries=3):
        url = path if path.startswith("http") else API + path.replace("{repo}", self.repo)
        data = None if body is None else json.dumps(body).encode()
        for attempt in range(retries):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Accept", accept)
            req.add_header("X-GitHub-Api-Version", "2022-11-28")
            if self.token:
                req.add_header("Authorization", "Bearer " + self.token)
            if data is not None:
                req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read()
                    link = resp.headers.get("Link", "")
                    return (json.loads(raw) if raw else None), link
            except urllib.error.HTTPError as e:
                text = e.read().decode(errors="replace")
                if e.code >= 500 and attempt + 1 < retries:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise GitHubError(e.code, method, path, text) from None

    def get(self, path):
        return self.request("GET", path)[0]

    def paginate(self, path):
        sep = "&" if "?" in path else "?"
        url, out = path + f"{sep}per_page=100", []
        while url:
            page, link = self.request("GET", url)
            out.extend(page if isinstance(page, list) else page.get("items", page.get("workflow_runs", [])))
            url = None
            for part in link.split(","):
                if 'rel="next"' in part:
                    url = part[part.index("<") + 1:part.index(">")]
        return out

    def post(self, path, body):
        return self.request("POST", path, body)[0]

    def put(self, path, body):
        return self.request("PUT", path, body)[0]

    def patch(self, path, body):
        return self.request("PATCH", path, body)[0]

    def graphql(self, query, variables):
        res = self.request("POST", "/graphql", {"query": query, "variables": variables})[0]
        if res.get("errors"):
            raise GitHubError(200, "POST", "/graphql", json.dumps(res["errors"]))
        return res["data"]
