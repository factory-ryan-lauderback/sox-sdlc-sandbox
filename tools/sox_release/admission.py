"""Admission demonstration cases for sox-admission-demo.yml (production Kyverno policy).

Every case is a pod that must be admitted or denied. Denials must come from the Kyverno prod
policy (the message names it), not from an unrelated failure such as Pod Security.
"""
import argparse
import datetime as dt
import json
import pathlib
import subprocess
import sys

from tools.sox_release import evidence
from tools.sox_release.common import REGISTRY, ROOT, write_json
from tools.sox_release.kube import kubectl

CASES = ROOT / "deploy" / "kyverno" / "testdata" / "admission-cases.json"
POLICY = "sox-prod-require-release-approval"
NAMESPACE = "svc-prod"


def tree_digest(service):
    tree = subprocess.run(["git", "rev-parse", f"HEAD:services/{service}"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    ref = f"{REGISTRY}/{service}:tree-{tree}"
    res = subprocess.run(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest}}"],
                         capture_output=True, text=True)
    if res.returncode != 0:
        return None
    return json.loads(res.stdout).get("digest")


def collect():
    td = json.loads(CASES.read_text())
    img = td["image"]
    cases = [
        {"id": "branch-signed-release-approval", "expect": "deny",
         "why": "provenance and release-approval with correct fields, signed by a branch workflow (F4/F10)",
         "image": f"{img}@{td['branchMinted']}", "mintedBy": td.get("mintedBy")},
        {"id": "unsigned", "expect": "deny", "why": "no attestations", "image": f"{img}@{td['unsigned']}"},
        {"id": "by-tag", "expect": "deny", "why": "not pinned by digest", "image": f"{img}:branch-minted"},
        {"id": "foreign-registry", "expect": "deny", "why": "not this repository's registry namespace",
         "image": "docker.io/library/busybox@sha256:" + "0" * 64},
    ]
    notes = []
    # A main-built image with verified build provenance but no release approval.
    for service in ("db", "api", "ui"):
        d = tree_digest(service)
        if not d:
            continue
        try:
            provs = [p for p in evidence.fetch(f"image:{d}", "build-provenance") if evidence.image_subject(p, d)]
            ras = [p for p in evidence.fetch(f"image:{d}", "release-approval") if evidence.image_subject(p, d)]
        except evidence.EvidenceUnavailable as e:
            notes.append(f"verifier unavailable: {e}")
            break
        if provs and not ras:
            cases.append({"id": "main-provenance-without-release-approval", "expect": "deny",
                          "why": "built and provenance-signed by sox-env-deploy.yml on main, never release-approved",
                          "image": f"{REGISTRY}/{service}@{d}", "provenanceAttestation": evidence.latest(provs)["digest"]})
            break
    else:
        notes.append("no main-built image without a release approval found (main-provenance case not run)")
    # The image production runs now, from verified deploy-results (must be admitted).
    try:
        from tools.sox_release.train import deployed_state
        state, _ = deployed_state(evidence.fetch, dt.datetime.now(dt.timezone.utc).date())
    except evidence.EvidenceUnavailable as e:
        state = {}
        notes.append(f"verifier unavailable for deploy-results: {e}")
    for service, s in sorted(state.items()):
        cases.append({"id": f"approved-{service}", "expect": "admit",
                      "why": "running in production per a verified deploy-result (provenance + release-approval)",
                      "image": f"{REGISTRY}/{service}@{s['digest']}", "deployResult": s.get("attestation")})
        break
    else:
        notes.append("no verified production deploy yet (approved case not run)")
    return {"cases": cases, "notes": notes, "rejectedEvidence": evidence.REJECTED[:20]}


def pod(case_id, image):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": f"demo-{case_id}"[:63], "namespace": NAMESPACE},
            "spec": {"automountServiceAccountToken": False, "imagePullSecrets": [{"name": "ghcr-pull"}],
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "c", "image": image,
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}]}}


def run(cases):
    out = []
    for c in cases["cases"]:
        res = kubectl("create", "--dry-run=server", "-f", "-", input_text=json.dumps(pod(c["id"], c["image"])), check=False)
        msg = (res.stdout + res.stderr).strip()
        got = "admit" if res.returncode == 0 else "deny"
        by_policy = POLICY in msg
        ok = got == c["expect"] and (got == "admit" or by_policy)
        out.append({**c, "got": got, "deniedByProdPolicy": by_policy, "pass": ok, "message": msg[-1500:]})
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("cases"); p.add_argument("--out", required=True)
    p = sub.add_parser("run"); p.add_argument("--cases", required=True); p.add_argument("--out", required=True)
    p.add_argument("--summary", default=None)
    args = ap.parse_args(argv)
    if args.cmd == "cases":
        c = collect()
        write_json(args.out, c)
        print(json.dumps(c, indent=2))
        return 0
    cases = json.loads(pathlib.Path(args.cases).read_text())
    results = run(cases)
    write_json(args.out, {"results": results, "notes": cases.get("notes", [])})
    lines = ["| Case | Expected | Got | Denied by prod policy | Pass |", "|---|---|---|---|---|"]
    lines += [f"| {r['id']} | {r['expect']} | {r['got']} | {r['deniedByProdPolicy']} | {'yes' if r['pass'] else 'NO'} |" for r in results]
    lines += [""] + [f"- {n}" for n in cases.get("notes", [])]
    text = "\n".join(lines) + "\n"
    print(text)
    for r in results:
        print(f"--- {r['id']}: {r['message'][:600]}")
        # Annotations are public on the run page, so auditors can read results without artifacts.
        msg = " ".join(r["message"].split())[:700]
        level = "notice" if r["pass"] else "error"
        print(f"::{level} title={r['id']} expect={r['expect']} got={r['got']} byProdPolicy={r['deniedByProdPolicy']}::{r['image']} | {msg}")
    for n in cases.get("notes", []):
        print(f"::notice title=not run::{n}")
    if args.summary:
        with open(args.summary, "a") as f:
            f.write("## Production admission demo\n\n" + text)
    return 0 if results and all(r["pass"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
