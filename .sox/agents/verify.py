"""Fetch attestations for a subject key and keep only those whose Sigstore certificate matches
the trust policy for their predicate type (evidence spec 2.4). Existence alone never counts.

Pinning uses `gh attestation verify` (signature, Rekor/TSA, signer workflow, ref, issuer,
GitHub-hosted runner) plus explicit checks of the repository and owner numeric IDs and the build
trigger, which gh does not pin by itself.
"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import REPO, predicate_type, subject_preimage  # noqa: E402

# Used only when .sox/trust-policy.yaml is absent on main. Values match the evidence spec.
DEFAULT_POLICY = {
    "repo": REPO,
    "repositoryId": "1453102476",
    "ownerId": "344896283",
    "oidcIssuer": "https://token.actions.githubusercontent.com",
    "predicates": {
        "review-verdict": {"signerWorkflow": ".github/workflows/sox-review-agent.yml",
                           "allowedTriggers": ["workflow_dispatch", "schedule"]},
        "qa-result": {"signerWorkflow": ".github/workflows/sox-qa-agent.yml",
                      "allowedTriggers": ["workflow_run", "workflow_dispatch", "schedule"]},
        "requirement-approval": {"signerWorkflow": ".github/workflows/sox-jira-attestor.yml",
                                 "allowedTriggers": ["repository_dispatch", "workflow_dispatch", "schedule"]},
        "pm-decomposition": {"signerWorkflow": ".github/workflows/sox-jira-attestor.yml",
                             "allowedTriggers": ["repository_dispatch", "workflow_dispatch", "schedule"]},
        "techlead-plan": {"signerWorkflow": ".github/workflows/sox-jira-attestor.yml",
                          "allowedTriggers": ["repository_dispatch", "workflow_dispatch", "schedule"]},
        "approach-approval": {"signerWorkflow": ".github/workflows/sox-jira-attestor.yml",
                              "allowedTriggers": ["repository_dispatch", "workflow_dispatch", "schedule"]},
        "env-deploy": {"signerWorkflow": ".github/workflows/sox-env-deploy.yml",
                       "allowedTriggers": ["workflow_dispatch", "workflow_run", "schedule", "pull_request_target"]},
        "human-changes-requested": {"signerWorkflow": ".github/workflows/sox-gate.yml",
                                    "allowedTriggers": ["pull_request_target", "workflow_dispatch", "schedule"]},
    },
}


def load_policy(path=None):
    path = path or os.environ.get("SOX_TRUST_POLICY", ".sox/trust-policy.yaml")
    text = None
    if os.path.exists(path):
        with open(path) as f:
            text = f.read()
    if text is None:
        return DEFAULT_POLICY, "built-in"
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            import yaml  # type: ignore
            doc = yaml.safe_load(text)
        except ImportError:
            doc = json.loads(subprocess.run(["yq", "-o=json", ".", path], check=True,
                                            capture_output=True, text=True).stdout)
    merged = dict(DEFAULT_POLICY)
    merged.update({k: v for k, v in doc.items() if k != "predicates"})
    preds = dict(DEFAULT_POLICY["predicates"])
    for name, entry in (doc.get("predicates") or {}).items():
        preds[name] = entry
    merged["predicates"] = preds
    for k in ("repositoryId", "ownerId"):
        merged[k] = str(merged[k])
    return merged, path


def _cert_ok(cert, policy, entry):
    want_signer = f"https://github.com/{policy['repo']}/{entry['signerWorkflow']}@refs/heads/main"
    checks = {
        "issuer": cert.get("issuer") == policy.get("oidcIssuer", DEFAULT_POLICY["oidcIssuer"]),
        "repositoryId": cert.get("sourceRepositoryIdentifier") == policy["repositoryId"],
        "ownerId": cert.get("sourceRepositoryOwnerIdentifier") == policy["ownerId"],
        "repositoryUri": cert.get("sourceRepositoryURI") == f"https://github.com/{policy['repo']}",
        "signer": cert.get("buildSignerURI") == want_signer,
        "ref": cert.get("sourceRepositoryRef") == "refs/heads/main",
        "runner": cert.get("runnerEnvironment") == "github-hosted",
        "trigger": cert.get("buildTrigger") in entry.get("allowedTriggers", [])
                   and cert.get("buildTrigger") != "pull_request",
    }
    return all(checks.values()), [k for k, v in checks.items() if not v]


def raw_count(kind, ident, name, gh_cmd="gh"):
    """Number of attestations stored for this key and predicate type, before any identity check."""
    from common import subject_key
    out = subprocess.run([gh_cmd, "api", f"/repos/{REPO}/attestations/sha256:{subject_key(kind, ident)}?per_page=100",
                          "--jq", f'[.attestations[] | select(.bundle.dsseEnvelope.payload | @base64d | fromjson | .predicateType == "{predicate_type(name)}")] | length'],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return 0 if "404" in out.stderr else None
    try:
        return int(out.stdout.strip() or 0)
    except ValueError:
        return None


def verified(kind, ident, name, policy=None, gh_cmd="gh"):
    """Return verified in-toto statements (dicts with 'statement', 'cert', 'bundle') for one key."""
    policy = policy or load_policy()[0]
    entry = policy["predicates"].get(name)
    if not entry:
        raise SystemExit(f"trust policy has no entry for predicate {name}")
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(subject_preimage(kind, ident, policy["repo"]))
        subj = f.name
    try:
        proc = subprocess.run(
            [gh_cmd, "attestation", "verify", subj, "--repo", policy["repo"],
             "--predicate-type", predicate_type(name),
             "--signer-workflow", f"{policy['repo']}/{entry['signerWorkflow']}",
             "--source-ref", "refs/heads/main",
             "--cert-oidc-issuer", policy.get("oidcIssuer", DEFAULT_POLICY["oidcIssuer"]),
             "--deny-self-hosted-runners", "--format", "json"],
            capture_output=True, text=True, timeout=180)
    finally:
        os.unlink(subj)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout)
        # No attestation at all, or none that passes the pinned identity: zero verified.
        low = msg.lower()
        # Policy rejections and "nothing stored" mean zero verified. Anything else (network, API
        # errors) raises, so a lookup failure can never silently lower a loop counter.
        if "http 404" in low or any(s in low for s in ("no attestations found", "failed to verify", "verification failed",
                                                          "no matching", "expected sourcerepositoryref", "expected ",
                                                          "does not match", "none of the")):
            return []
        raise RuntimeError(f"gh attestation verify failed: {msg[:400]}")
    results = []
    for item in json.loads(proc.stdout or "[]"):
        vr = item["verificationResult"]
        cert = vr["signature"]["certificate"]
        ok, failed = _cert_ok(cert, policy, entry)
        if not ok:
            continue
        stmt = vr["statement"]
        if stmt.get("predicateType") != predicate_type(name):
            continue
        results.append({"statement": stmt, "cert": cert, "bundle": item["attestation"].get("bundle")})
    return results


def statement_digest(bundle):
    """sha256 of the in-toto statement bytes (DSSE payload): the digest used in `upstream`."""
    import base64
    from common import sha256_hex
    return "sha256:" + sha256_hex(base64.b64decode(bundle["dsseEnvelope"]["payload"]))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="List verified attestations for a subject key")
    ap.add_argument("kind")
    ap.add_argument("id")
    ap.add_argument("predicate")
    a = ap.parse_args()
    res = verified(a.kind, a.id, a.predicate)
    json.dump([{"predicate": r["statement"]["predicate"], "trigger": r["cert"]["buildTrigger"],
                "run": r["cert"]["runInvocationURI"]} for r in res], sys.stdout, indent=2)
    print()
