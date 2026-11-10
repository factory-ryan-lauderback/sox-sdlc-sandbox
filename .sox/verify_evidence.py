#!/usr/bin/env python3
"""SOX evidence verifier CLI (stdlib only; needs the `gh` CLI for signature checks).

  verify_evidence.py --bundle FILE [--predicate NAME] [--expect commit:<sha> ...]
  verify_evidence.py fetch  --subject jira:FRQ-12 [--predicate NAME] [--json]
  verify_evidence.py rounds --story FRQ-12 [--predicate review-verdict] [--outcome changes_requested]
  verify_evidence.py policy-check

Exit status: 0 verified, 1 rejected (forgery-attempt, binding mismatch, malformed), 2 verifier
unavailable or usage error (treat as failure). The trust policy defaults to .sox/trust-policy.yaml
next to this file; gates and the reconciler always run it from a checkout of refs/heads/main.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from soxlib import subject as subj  # noqa: E402
from soxlib.ghapi import GitHub, APIError  # noqa: E402
from soxlib.policy import Policy, PolicyError  # noqa: E402
from soxlib.verify import Rejection, Verifier, VerifierUnavailable  # noqa: E402

DEFAULT_POLICY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trust-policy.yaml")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", default=DEFAULT_POLICY)
    ap.add_argument("--bundle", help="verify one bundle file (raw Sigstore bundle or API record)")
    ap.add_argument("--predicate", help="require this predicate name")
    ap.add_argument("--expect", action="append", default=[], help="required subject, e.g. commit:<sha>")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("command", nargs="?", choices=["fetch", "rounds", "policy-check"])
    ap.add_argument("--subject")
    ap.add_argument("--story")
    ap.add_argument("--outcome", default="changes_requested")
    a = ap.parse_args(argv)
    try:
        v = Verifier.load(a.policy)
    except (PolicyError, OSError) as e:
        print(f"POLICY ERROR: {e}", file=sys.stderr)
        return 2
    if a.command == "policy-check":
        print(json.dumps({"policy": a.policy, "digest": v.policy.digest,
                          "predicates": sorted(v.policy.predicate_types.values()),
                          "signers": sorted(v.policy.signer_workflows())}, indent=2))
        return 0
    try:
        if a.bundle:
            expect = [subj.parse_ref(x) for x in a.expect]
            with open(a.bundle, "rb") as f:
                raw = f.read()
            try:
                att = v.verify(raw, predicate=a.predicate, expect=expect)
            except Rejection as r:
                print(json.dumps({"result": "rejected", **r.to_json()}, indent=2))
                print(f"REJECTED ({r.category}): {r.reason}", file=sys.stderr)
                return 1
            print(json.dumps({"result": "verified", **att.to_json(),
                              "subjects": [f"{k}:{i}" for k, i in att.subjects],
                              "predicateFields": att.predicate}, indent=2))
            return 0
        if a.command in ("fetch", "rounds"):
            api = GitHub()
            if a.command == "fetch":
                kind, ident = subj.parse_ref(a.subject or "")
                ok, bad = v.fetch(api, kind, ident, a.predicate)
                out = {"subject": f"{kind}:{ident}", "verified": [x.to_json() | {"predicateFields": x.predicate} for x in ok],
                       "rejected": [r.to_json() for r in bad]}
            else:
                n, items, bad = v.count_rounds(api, a.story, a.predicate or "review-verdict", a.outcome)
                out = {"story": a.story, "predicate": a.predicate or "review-verdict",
                       "outcome": a.outcome, "rounds": n, "verified": [x.to_json() for x in items],
                       "rejected": [r.to_json() for r in bad]}
            print(json.dumps(out, indent=2))
            return 0
    except (VerifierUnavailable, APIError, ValueError) as e:
        print(f"VERIFIER ERROR (fail closed): {e}", file=sys.stderr)
        return 2
    ap.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
