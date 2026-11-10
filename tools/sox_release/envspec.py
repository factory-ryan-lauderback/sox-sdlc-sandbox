"""SDLC-07 environment spec and env-deploy predicate.

The spec is the whole definition of an environment: the controls code (main SHA that holds the
Tiltfile, deploy/ and tools/), the namespace, and one image digest per service. Anyone holding a
verified spec can re-create the identical environment with .github/actions/sox-env-up.
"""
import argparse
import json
import pathlib
import subprocess
import sys

from tools.sox_release import evidence
from tools.sox_release.common import DIGEST, REGISTRY, digest_of, now_iso, sha256_hex, subject_key, write_json

IMAGE_BUILD = "image-build"


def registry_digest(service, tag, runner=subprocess.run):
    ref = f"{REGISTRY}/{service}:{tag}"
    res = runner(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest}}"],
                 capture_output=True, text=True)
    if res.returncode != 0:
        return None
    try:
        digest = json.loads(res.stdout).get("digest")
    except json.JSONDecodeError:
        return None
    return digest if DIGEST.match(digest or "") else None


def reusable(service, source_tree, digest, fetch=evidence.fetch):
    """An image is reused only if the verifier returns an image-build attestation, signed by this
    workflow on main, that binds this digest to this service's exact source tree, and a verified
    build provenance for the digest. A tag alone proves nothing: any workflow in the repository
    can push tags to GHCR."""
    if not digest:
        return False, "no image for this source tree", None
    try:
        builds = fetch(f"image:{digest}", IMAGE_BUILD)
        provs = fetch(f"image:{digest}", "build-provenance")
    except evidence.EvidenceUnavailable as e:
        return False, f"verifier unavailable: {e}", None
    match = [i for i in builds if i["predicate"].get("service") == service
             and i["predicate"].get("sourceTree") == source_tree and i["predicate"].get("imageDigest") == digest
             and evidence.image_subject(i, digest)]
    provs = [p for p in provs if evidence.image_subject(p, digest)]
    if not match:
        return False, "no verified image-build attestation for this digest and tree", None
    if not provs:
        return False, "no verified build provenance for this digest", None
    return True, evidence.latest(match)["digest"], evidence.latest(provs)["digest"]


def check_reuse(plan, runner=subprocess.run, fetch=evidence.fetch):
    reuse, build = [], []
    for s in plan["services"]:
        digest = registry_digest(s["service"], f"tree-{s['sourceTree']}", runner)
        ok, why, prov = reusable(s["service"], s["sourceTree"], digest, fetch)
        if ok:
            reuse.append({**s, "digest": digest, "imageBuildAttestation": why, "provenanceAttestation": prov})
        else:
            build.append({**s, "reason": why})
    return {"reuse": reuse, "build": build}


def assemble(plan, reuse, built, controls_sha):
    images = {}
    for r in reuse:
        images[r["service"]] = {"service": r["service"], "digest": r["digest"], "sourceTree": r["sourceTree"], "built": False,
                                "provenanceAttestation": r.get("provenanceAttestation")}
    for b in built:
        if not DIGEST.match(b.get("digest", "")):
            raise ValueError(f"bad digest for {b.get('service')}")
        images[b["service"]] = {"service": b["service"], "digest": b["digest"], "sourceTree": b["sourceTree"], "built": True,
                                "provenanceAttestation": b.get("provenanceAttestation")}
    wanted = [s["service"] for s in plan["services"]]
    missing = [n for n in wanted if n not in images]
    if missing:
        raise ValueError(f"no image for {missing}")
    trees = {s["service"]: s["sourceTree"] for s in plan["services"]}
    for n in wanted:
        if images[n]["sourceTree"] != trees[n]:
            raise ValueError(f"{n}: image tree {images[n]['sourceTree']} != planned {trees[n]}")
    return {
        "schema": "sox/env-spec/v1",
        "repo": plan["repo"], "prNumber": plan["prNumber"], "headSha": plan["headSha"],
        "baseRef": plan["baseRef"], "baseSha": plan["baseSha"], "release": plan["release"],
        "jiraKeys": plan["jiraKeys"], "mode": plan["mode"], "envId": plan["envId"], "chain": plan["chain"],
        "controlsSha": controls_sha,
        "images": [{**images[n], "ref": f"{REGISTRY}/{n}@{images[n]['digest']}"} for n in wanted],
    }


def predicate(spec, spec_digest, readback, deployment_id, run, outcome, head_now):
    problems = list(readback.get("problems", [])) if readback else ["environment did not come up"]
    if head_now != spec["headSha"]:
        problems.append(f"PR head moved to {head_now} during deployment")
    ok = outcome == "success" and not problems
    return {
        "schema": "sox/common/v1",
        "repo": spec["repo"], "prNumber": spec["prNumber"], "headSha": spec["headSha"],
        "baseSha": spec["baseSha"], "baseRef": spec["baseRef"], "jiraKeys": spec["jiraKeys"],
        "release": spec["release"], "step": "SDLC-07",
        "actor": {"type": "workflow", "login": "github-actions", "source": "sox-env-deploy.yml on refs/heads/main"},
        "outcome": "pass" if ok else "fail",
        "environment": "qa", "envId": spec["envId"], "mode": spec["mode"], "chain": spec["chain"],
        "envSpecDigest": spec_digest, "controlsSha": spec["controlsSha"],
        "images": [{"service": i["service"], "digest": i["digest"], "sourceTree": i["sourceTree"], "built": i["built"],
                    "provenanceAttestation": i.get("provenanceAttestation")} for i in spec["images"]],
        "readBackDigests": (readback or {}).get("running", {}),
        "problems": problems,
        "deploymentId": deployment_id,
        "attestor": run,
        "inputs": [{"name": "env-spec", "digest": {"sha256": spec_digest.split(":", 1)[1]}}],
        "inputsDigest": digest_of([{"name": "env-spec", "digest": {"sha256": spec_digest.split(":", 1)[1]}}]),
        "observedAt": now_iso(),
    }


def subject_lines(spec, spec_digest, repo):
    lines = [f"{subject_key('commit', spec['headSha'], repo)}  sox:commit:{spec['headSha']}",
             f"{subject_key('pr', spec['prNumber'], repo)}  sox:pr:{spec['prNumber']}"]
    lines += [f"{subject_key('jira', k, repo)}  sox:jira:{k}" for k in spec["jiraKeys"]]
    lines += [f"{i['digest'].split(':', 1)[1]}  {REGISTRY}/{i['service']}" for i in spec["images"]]
    lines.append(f"{spec_digest.split(':', 1)[1]}  env-spec.json")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("reuse"); p.add_argument("--plan", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("assemble")
    p.add_argument("--plan", required=True); p.add_argument("--reuse", required=True)
    p.add_argument("--digests-dir", required=True); p.add_argument("--controls-sha", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("record")
    p.add_argument("--spec", required=True); p.add_argument("--readback", default="")
    p.add_argument("--deployment-id", type=int, default=None); p.add_argument("--outcome", required=True)
    p.add_argument("--head-now", required=True); p.add_argument("--run", required=True)
    p.add_argument("--predicate-out", required=True); p.add_argument("--subjects-out", required=True)
    args = ap.parse_args(argv)
    if args.cmd == "reuse":
        plan = json.loads(pathlib.Path(args.plan).read_text())
        out = check_reuse(plan)
        write_json(args.out, out)
        print(json.dumps(out, indent=2))
    elif args.cmd == "assemble":
        plan = json.loads(pathlib.Path(args.plan).read_text())
        reuse = json.loads(pathlib.Path(args.reuse).read_text())["reuse"]
        built = [json.loads(p.read_text()) for p in sorted(pathlib.Path(args.digests_dir).glob("**/digest-*.json"))]
        spec = assemble(plan, reuse, built, args.controls_sha)
        write_json(args.out, spec)
        print(json.dumps(spec, indent=2))
    elif args.cmd == "record":
        raw = pathlib.Path(args.spec).read_bytes()
        spec = json.loads(raw)
        spec_digest = "sha256:" + sha256_hex(raw)
        readback = json.loads(pathlib.Path(args.readback).read_text()) if args.readback and pathlib.Path(args.readback).exists() else None
        if readback is not None:
            from tools.sox_release.kube import compare
            readback["problems"] = compare(spec, readback.get("running", {}))
        pred = predicate(spec, spec_digest, readback, args.deployment_id, json.loads(args.run), args.outcome, args.head_now)
        write_json(args.predicate_out, pred)
        pathlib.Path(args.subjects_out).write_text(subject_lines(spec, spec_digest, spec["repo"]))
        print(json.dumps(pred, indent=2))
        return 0 if pred["outcome"] == "pass" else 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
