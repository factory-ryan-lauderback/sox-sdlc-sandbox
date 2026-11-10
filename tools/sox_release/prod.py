"""SDLC-11 / CC-04 production deploy steps for the simulated production cluster (namespace
svc-prod in kind, Kyverno prod policy).

The cluster lives only for one job, so every run first restores the digests production already
runs (from verified deploy-results), then deploys the planned services one at a time in
dependency order and stops at the first failure. Every outcome is read back from the Kubernetes
API, never taken from kubectl's or the plan's own claims.
"""
import argparse
import json
import pathlib
import sys
import time

from tools.sox_release.common import DIGEST, REGISTRY, REPO, SHA, now_iso, ordered, services, subject_key, write_json
from tools.sox_release.kube import compare, deploy_one, kubectl, objects, read_back, to_yaml_stream

NAMESPACE = "svc-prod"


def prod_spec(plan):
    """Spec with the final desired digest of every service production will run after this train."""
    svc = services()
    want = dict(plan.get("restore") or {})
    for img in plan.get("images") or []:
        if img["service"] in plan.get("order", []):
            want[img["service"]] = img["digest"]
    for n, d in want.items():
        if not DIGEST.match(d or ""):
            raise ValueError(f"{n}: bad digest {d!r}")
    return {"envId": NAMESPACE, "images": [{"service": n, "digest": want[n]} for n in ordered(svc, want)]}


def restore_spec(plan):
    svc = services()
    restore = {n: d for n, d in (plan.get("restore") or {}).items() if n not in plan.get("order", [])}
    return {"envId": NAMESPACE, "images": [{"service": n, "digest": restore[n]} for n in ordered(svc, restore)]}


def run(plan, clock=time.time):
    results, problems = [], []
    if plan.get("outcome") != "planned" or not plan.get("order"):
        return {"results": [], "problems": [f"plan outcome is {plan.get('outcome')}; nothing to deploy"], "running": {}}
    final = prod_spec(plan)
    rest = restore_spec(plan)
    if rest["images"]:
        # Already-approved digests; they pass the same admission policy as new ones.
        kubectl("apply", "-f", "-", input_text=to_yaml_stream(objects(rest)))
        for img in rest["images"]:
            r = kubectl("-n", NAMESPACE, "rollout", "status", f"deploy/{img['service']}", "--timeout=180s", check=False)
            if r.returncode != 0:
                problems.append(f"restore of {img['service']}@{img['digest']} failed: {(r.stdout + r.stderr).strip()[-300:]}")
    by_name = {i["service"]: i["digest"] for i in final["images"]}
    stopped = bool(problems)
    for name in plan["order"]:
        started = now_iso()
        if stopped:
            results.append({"service": name, "imageDigest": by_name[name], "outcome": "not-attempted",
                            "startedAt": None, "finishedAt": None, "detail": "an earlier step failed"})
            continue
        try:
            ok, detail = deploy_one(final, name)
        except Exception as e:  # admission denials surface here as kubectl errors
            ok, detail = False, str(e)[-500:]
        running = read_back(NAMESPACE).get(name, [])
        if ok and running != [by_name[name]]:
            ok, detail = False, f"rollout reported success but {name} runs {running}"
        results.append({"service": name, "imageDigest": by_name[name], "outcome": "success" if ok else "failure",
                        "startedAt": started, "finishedAt": now_iso(), "running": running, "detail": detail})
        if not ok:
            stopped = True
    running = read_back(NAMESPACE)
    deployed = {r["service"] for r in results if r["outcome"] == "success"}
    expect = {"envId": NAMESPACE, "images": [i for i in final["images"] if i["service"] in deployed or i["service"] not in plan["order"]]}
    problems += compare(expect, running) if not stopped else []
    return {"results": results, "problems": problems, "running": running}


def result_predicate(plan, res, slot, deployment_id, run_info, environment):
    r = res["results"][slot]
    return {
        "schema": "sox/common/v1", "repo": REPO, "step": plan.get("step", "SDLC-11"),
        "prNumber": None, "headSha": None, "baseSha": None, "baseRef": None,
        "jiraKeys": plan.get("jiraKeys", []), "release": None,
        "actor": {"type": "workflow", "login": "github-actions", "source": f"{run_info.get('workflow')} on refs/heads/main"},
        "mode": plan["mode"], "trainId": plan["trainId"], "trainDate": plan["trainDate"],
        "cutoffSha": plan["cutoffSha"], "planDigest": plan["planDigest"],
        "trainPlanAttestation": plan.get("trainPlanAttestation"),
        "service": r["service"], "imageDigest": r["imageDigest"], "imageRef": f"{REGISTRY}/{r['service']}@{r['imageDigest']}",
        "position": slot + 1, "order": plan["order"],
        "environment": environment, "deploymentId": deployment_id,
        "target": {"cluster": "kind (GitHub-hosted runner, simulated production)", "namespace": NAMESPACE,
                   "admission": "deploy/kyverno/prod-policy.yaml"},
        "outcome": r["outcome"], "startedAt": r["startedAt"], "finishedAt": r["finishedAt"],
        "readBack": r.get("running"), "detail": r.get("detail"),
        "releases": [{"prNumber": x["prNumber"], "slug": x["slug"], "mergeCommitSha": x["mergeCommitSha"],
                      "mergeRecord": x["mergeRecord"], "humanApproval": x["humanApproval"],
                      "emergencyChange": x.get("emergencyChange")} for x in plan.get("releases", [])],
        "releaseApproval": next((i.get("releaseApproval") for i in plan.get("images", []) if i["service"] == r["service"]), None),
        "attestor": run_info,
        "observedAt": now_iso(),
    }


def result_subjects(plan, r):
    lines = [f"{subject_key('train', plan['trainDate'])}  sox:train:{plan['trainDate']}",
             f"{subject_key('commit', plan['cutoffSha'])}  sox:commit:{plan['cutoffSha']}"]
    lines += [f"{subject_key('jira', k)}  sox:jira:{k}" for k in plan.get("jiraKeys", [])]
    lines.append(f"{r['imageDigest'].split(':', 1)[1]}  {REGISTRY}/{r['service']}")
    return "\n".join(lines) + "\n"


def deployment_id(gh, environment, sha, run_id):
    """The Deployments API record GitHub created for this job's environment, matched by run."""
    for d in gh.get(f"/repos/{{repo}}/deployments?environment={environment}&sha={sha}&per_page=30") or []:
        for s in gh.get(f"/repos/{{repo}}/deployments/{d['id']}/statuses?per_page=30") or []:
            url = (s.get("log_url") or "") + " " + (s.get("target_url") or "")
            if f"/actions/runs/{run_id}" in url:
                return d["id"]
    return None


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("deployment-id")
    p.add_argument("--environment", required=True); p.add_argument("--sha", required=True); p.add_argument("--run-id", required=True)
    p = sub.add_parser("deploy"); p.add_argument("--plan", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("result")
    p.add_argument("--plan", required=True); p.add_argument("--results", required=True)
    p.add_argument("--slot", type=int, required=True); p.add_argument("--deployment-id", type=int, default=None)
    p.add_argument("--run", required=True); p.add_argument("--environment", required=True)
    p.add_argument("--predicate-out", required=True); p.add_argument("--subjects-out", required=True)
    args = ap.parse_args(argv)
    if args.cmd == "deployment-id":
        from tools.sox_release.gh import GitHub
        dep = deployment_id(GitHub(), args.environment, args.sha, args.run_id)
        print(dep or "")
        return 0
    plan = json.loads(pathlib.Path(args.plan).read_text())
    if not SHA.match(plan.get("cutoffSha") or ""):
        print("refused: plan has no cutoff SHA", file=sys.stderr)
        return 2
    if args.cmd == "deploy":
        res = run(plan)
        write_json(args.out, res)
        print(json.dumps(res, indent=2))
        bad = res["problems"] or any(r["outcome"] != "success" for r in res["results"]) or not res["results"]
        return 1 if bad else 0
    res = json.loads(pathlib.Path(args.results).read_text())
    if args.slot >= len(res["results"]):
        return 0
    pred = result_predicate(plan, res, args.slot, args.deployment_id, json.loads(args.run), args.environment)
    write_json(args.predicate_out, pred)
    pathlib.Path(args.subjects_out).write_text(result_subjects(plan, res["results"][args.slot]))
    print(json.dumps({k: pred[k] for k in ("service", "imageDigest", "outcome", "position")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
