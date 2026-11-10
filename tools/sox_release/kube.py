"""Render, apply, and read back the Kubernetes objects for an environment spec.

One renderer feeds both Tilt (ephemeral and QA environments) and the deploy train (production),
so what is tested and what ships use the same object definitions. Images are always pinned by
digest; nothing here builds an image.
"""
import argparse
import json
import pathlib
import subprocess
import sys

from tools.sox_release.common import DIGEST, REGISTRY, RefusedError, services

NODE_PORT_BASE = 30000
LOCAL_PORT_BASE = 18000


def node_port(port):
    return NODE_PORT_BASE + int(port) - 8000


def local_port(port):
    return LOCAL_PORT_BASE + int(port) - 8000


def image_ref(service, digest):
    if not DIGEST.match(digest or ""):
        raise RefusedError(f"{service}: image must be pinned by sha256 digest, got {digest!r}")
    return f"{REGISTRY}/{service}@{digest}"


def objects(spec, root=None, image=None):
    image = image or image_ref
    svc = services(root) if root else services()
    ns = spec["envId"]
    present = {i["service"] for i in spec["images"]}
    out = []
    for img in spec["images"]:
        name = img["service"]
        m = svc[name]
        port = int(m["port"])
        env = [{"name": "PORT", "value": str(port)}]
        for dep in m.get("depends_on", []):
            if dep not in present:
                raise RefusedError(f"{name} needs {dep}, which is not in environment {ns}")
            env.append({"name": f"{dep.upper()}_URL", "value": f"http://{dep}:{int(svc[dep]['port'])}"})
        labels = {"app": name, "sox.acme-lending.example/env": ns}
        out.append({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "namespace": ns, "labels": labels},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": name}},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "imagePullSecrets": [{"name": "ghcr-pull"}],
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{
                            "name": name,
                            "image": image(name, img["digest"]),
                            "ports": [{"containerPort": port}],
                            "env": env,
                            "readinessProbe": {"httpGet": {"path": "/healthz", "port": port},
                                               "periodSeconds": 2, "failureThreshold": 30},
                            "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                          "limits": {"cpu": "200m", "memory": "128Mi"}},
                            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}},
                        }],
                    },
                },
            },
        })
        out.append({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": ns, "labels": labels},
            "spec": {"type": "NodePort", "selector": {"app": name},
                     "ports": [{"port": port, "targetPort": port, "nodePort": node_port(port)}]},
        })
    return out


def to_yaml_stream(objs):
    # JSON is valid YAML; kubectl and Tilt both accept a JSON document stream.
    return "\n---\n".join(json.dumps(o, sort_keys=True) for o in objs) + "\n"


def deps(spec, root=None):
    svc = services(root) if root else services()
    present = {i["service"] for i in spec["images"]}
    return {i["service"]: [d for d in svc[i["service"]].get("depends_on", []) if d in present] for i in spec["images"]}


def kubectl(*args, input_text=None, check=True):
    res = subprocess.run(["kubectl", *args], input=input_text, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args[:3])} failed: {res.stderr.strip()[:500]}")
    return res


def read_back(namespace):
    """Digests actually running, from the Kubernetes API (never from Tilt's or kubectl's output)."""
    pods = json.loads(kubectl("-n", namespace, "get", "pods", "-o", "json").stdout)["items"]
    running = {}
    for p in pods:
        if p["metadata"].get("deletionTimestamp") or p["status"].get("phase") != "Running":
            continue
        name = p["metadata"]["labels"].get("app")
        for cs in p["status"].get("containerStatuses", []):
            image_id = cs.get("imageID", "")
            digest = image_id.split("@", 1)[1] if "@" in image_id else None
            running.setdefault(name, set()).add(digest)
    return {k: sorted(v) for k, v in running.items()}


def compare(spec, running):
    problems = []
    want = {i["service"]: i["digest"] for i in spec["images"]}
    for name, digest in want.items():
        got = running.get(name, [])
        if got != [digest]:
            problems.append(f"{name}: expected {digest}, running {got}")
    for name in sorted(set(running) - set(want)):
        problems.append(f"{name}: running but not in the spec ({running[name]})")
    return problems


def deploy_one(spec, name, timeout="180s", root=None):
    objs = [o for o in objects(spec, root) if o["metadata"]["name"] == name]
    kubectl("apply", "-f", "-", input_text=to_yaml_stream(objs))
    res = kubectl("-n", spec["envId"], "rollout", "status", f"deploy/{name}", f"--timeout={timeout}", check=False)
    return res.returncode == 0, (res.stdout + res.stderr).strip()[-500:]


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("render", "deps", "verify"):
        p = sub.add_parser(c)
        p.add_argument("--spec", required=True)
        p.add_argument("--root", default=None)
    sub.add_parser("render-dev", help="laptop Tilt only; images are replaced by Tilt's local builds")
    args = ap.parse_args(argv)
    if args.cmd == "render-dev":
        spec = {"envId": "default", "images": [{"service": n, "digest": None} for n in services()]}
        objs = objects(spec, image=lambda name, _d: f"acme-lending/{name}")
        for o in objs:
            o["metadata"].pop("namespace", None)
            o["spec"].get("template", {}).get("spec", {}).pop("imagePullSecrets", None)
        sys.stdout.write(to_yaml_stream(objs))
        return 0
    spec = json.loads(pathlib.Path(args.spec).read_text())
    if args.cmd == "render":
        sys.stdout.write(to_yaml_stream(objects(spec, args.root)))
    elif args.cmd == "deps":
        json.dump(deps(spec, args.root), sys.stdout)
    elif args.cmd == "verify":
        running = read_back(spec["envId"])
        problems = compare(spec, running)
        json.dump({"running": running, "problems": problems}, sys.stdout, indent=2, sort_keys=True)
        print()
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
