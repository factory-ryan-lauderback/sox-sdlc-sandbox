"""Compute service deploy order from .sox/services.yaml and each service.yaml manifest.

Only a tiny YAML subset is parsed (flat keys, inline lists, and "- " lists) so the tool has no
dependencies and behaves identically on any runner.
"""
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def parse_yaml(text):
    data, key = {}, None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith("- ") and key:
            item = line.strip()[2:].strip()
            if ":" in item:
                k, v = item.split(":", 1)
                data[key].append({k.strip(): v.strip()})
            else:
                data[key].append(item)
            continue
        if line.startswith("    ") and key and data[key] and isinstance(data[key][-1], dict):
            k, v = line.strip().split(":", 1)
            data[key][-1][k.strip()] = v.strip()
            continue
        k, v = line.split(":", 1)
        key, v = k.strip(), v.strip()
        if v == "":
            data[key] = []
        elif v.startswith("[") and v.endswith("]"):
            data[key] = [x.strip() for x in v[1:-1].split(",") if x.strip()]
        else:
            data[key] = v
    return data


def load_services(root=ROOT):
    index = parse_yaml((root / ".sox/services.yaml").read_text())
    services = {}
    for entry in index["services"]:
        manifest = parse_yaml((root / entry["manifest"]).read_text())
        if manifest["name"] != entry["name"]:
            raise ValueError(f"manifest name mismatch for {entry['name']}")
        services[entry["name"]] = manifest
    return services


def deploy_order(services):
    order, state = [], {}

    def visit(name, chain):
        if state.get(name) == "done":
            return
        if state.get(name) == "visiting":
            raise ValueError("dependency cycle: " + " -> ".join(chain + [name]))
        if name not in services:
            raise ValueError(f"unknown service dependency: {name}")
        state[name] = "visiting"
        for dep in services[name].get("depends_on", []):
            visit(dep, chain + [name])
        state[name] = "done"
        order.append(name)

    for name in sorted(services):
        visit(name, [])
    return order


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    services = load_services()
    order = deploy_order(services)
    if args.json:
        json.dump({"order": order, "services": {n: {"depends_on": services[n].get("depends_on", []),
                                                    "paths": services[n].get("paths", [])}
                                                for n in order}}, sys.stdout, indent=2)
        print()
    else:
        print(" ".join(order))


if __name__ == "__main__":
    main()
