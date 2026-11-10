"""Per-run evidence cache over the attestations API. Only verified attestations are returned;
every rejection is kept so gates and reports can list forgery attempts."""
import threading

from .verify import Rejection


class Evidence:
    def __init__(self, verifier, api):
        self.v = verifier
        self.api = api
        self.policy = verifier.policy
        self._cache = {}
        self._lock = threading.Lock()
        self.rejections = {}

    def get(self, kind, ident, predicate=None, before=None):
        """Verified attestations of `predicate` bound to kind:ident, oldest first.
        before: epoch cutoff (transparency-log time), for re-evaluating a change as of its merge."""
        k = (kind, str(ident))
        with self._lock:
            hit = self._cache.get(k)
        if hit is None:
            hit = self.v.fetch(self.api, kind, ident, None)
            with self._lock:
                self._cache[k] = hit
                for r in hit[1]:
                    self.rejections[r.digest or id(r)] = (k, r)
        verified = [a for a in hit[0] if predicate is None or a.name == predicate]
        if before is not None:
            verified = [a for a in verified if a.integrated_time <= before]
        return verified

    def latest(self, kind, ident, predicate, where=None, before=None):
        items = [a for a in self.get(kind, ident, predicate, before)
                 if where is None or where(a)]
        return items[-1] if items else None

    def forgeries(self):
        out = []
        for (kind, ident), r in self.rejections.values():
            j = r.to_json()
            j["lookup"] = f"{kind}:{ident}"
            out.append(j)
        return out
