#!/usr/bin/env python3
"""Builder hook for sox-jira-attestor.yml (SDLC-04 release-manifest).

Usage: python3 .sox/release/manifest_predicate.py --jira-key FRQ-n   (cwd = main checkout)
Prints a JSON list of {"subjects": [[kind, id], ...], "predicate": {...}}. An empty list means
nothing to attest. Any refusal exits non-zero so the attestor run fails loudly.
"""
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".sox" / "agents"))

from tools.sox_release.common import RefusedError  # noqa: E402
from tools.sox_release.manifest import build  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jira-key", required=True)
    args = ap.parse_args()
    import jira_adapter  # .sox/agents/jira_adapter.py, owned by the agent pipeline
    try:
        out = build(jira_adapter.from_env(), args.jira_key, ROOT)
    except RefusedError as e:
        print(f"release-manifest refused: {e}", file=sys.stderr)
        return 2
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
