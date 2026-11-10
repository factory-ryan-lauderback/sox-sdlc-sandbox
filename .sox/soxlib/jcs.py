"""RFC 8785 (JCS) canonical JSON for the value types SOX predicates use, and digests over it."""
import hashlib
import json


def canonical(value):
    def check(v):
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ValueError("non-finite number")
            if v.is_integer() and abs(v) < 2 ** 53:
                return int(v)
            return v
        if isinstance(v, dict):
            return {str(k): check(x) for k, x in v.items()}
        if isinstance(v, (list, tuple)):
            return [check(x) for x in v]
        return v
    return json.dumps(check(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()
