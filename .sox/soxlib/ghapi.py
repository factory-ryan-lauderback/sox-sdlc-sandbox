"""Minimal GitHub REST client (stdlib). Every error raises; callers fail closed."""
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"


class APIError(RuntimeError):
    def __init__(self, status, url, body):
        super().__init__(f"HTTP {status} for {url}: {body[:300]}")
        self.status = status
        self.url = url
        self.body = body


class GitHub:
    def __init__(self, token=None, retries=4):
        self.token = token if token is not None else os.environ.get("SOX_GITHUB_TOKEN")
        self.retries = retries
        self.calls = 0

    def _request(self, method, url, body=None, accept="application/vnd.github+json"):
        if not url.startswith("http"):
            url = API + url
        data = json.dumps(body).encode() if body is not None else None
        last = None
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Accept", accept)
            req.add_header("X-GitHub-Api-Version", "2022-11-28")
            req.add_header("User-Agent", "sox-gates")
            if self.token:
                req.add_header("Authorization", f"Bearer {self.token}")
            if data is not None:
                req.add_header("Content-Type", "application/json")
            try:
                self.calls += 1
                with urllib.request.urlopen(req, timeout=60) as r:
                    raw = r.read()
                    return r.status, dict(r.headers), raw
            except urllib.error.HTTPError as e:
                raw = e.read().decode("utf-8", "replace")
                last = APIError(e.code, url, raw)
                retryable = e.code in (500, 502, 503, 504) or (
                    e.code in (403, 429) and ("rate limit" in raw.lower()
                                              or "secondary" in raw.lower()))
                if not retryable or attempt == self.retries:
                    raise last
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                last = APIError(0, url, str(e))
                if attempt == self.retries:
                    raise last
            time.sleep(min(2 ** attempt * 2, 30))
        raise last

    def get(self, path, accept="application/vnd.github+json"):
        _, _, raw = self._request("GET", path, accept=accept)
        return json.loads(raw) if raw else None

    def get_raw(self, path, accept="application/vnd.github.raw+json"):
        _, _, raw = self._request("GET", path, accept=accept)
        return raw

    def get_optional(self, path):
        try:
            return self.get(path)
        except APIError as e:
            if e.status == 404:
                return None
            raise

    def post(self, path, body):
        _, _, raw = self._request("POST", path, body=body)
        return json.loads(raw) if raw else None

    def patch(self, path, body):
        _, _, raw = self._request("PATCH", path, body=body)
        return json.loads(raw) if raw else None

    def put(self, path, body):
        _, _, raw = self._request("PUT", path, body=body)
        return json.loads(raw) if raw else None

    @staticmethod
    def _next(headers):
        link = headers.get("Link") or headers.get("link") or ""
        m = re.search(r'<([^>]+)>;\s*rel="next"', link)
        return m.group(1) if m else None

    def paginate(self, path, key=None, limit=100000):
        out = []
        url = path + ("&" if "?" in path else "?") + "per_page=100" if "per_page" not in path else path
        while url:
            _, headers, raw = self._request("GET", url)
            data = json.loads(raw) if raw else []
            items = data.get(key, []) if key else data
            out.extend(items)
            if len(out) >= limit:
                raise APIError(0, path, f"more than {limit} items; refusing a partial population")
            url = self._next(headers)
        return out

    def paginate_attestations(self, path):
        return self.paginate(path, key="attestations")
