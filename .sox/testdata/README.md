# Verifier test data

| File | What it is | Expected verifier result |
|---|---|---|
| `branch-minted-review-verdict.bundle.json` | Real Sigstore bundle, predicate `https://acme-lending.example/sox/review-verdict/v1`, subjects `sox:pr:0` and `sox:commit:4de627863b24da9d1588afb81d1275ab5fe72d27`. Minted by a throwaway `.github/workflows/sox-review-agent.yml` that existed only on branch `redteam-testdata/branch-mint` (trigger `push`), run https://github.com/factory-ryan-lauderback/sox-sdlc-sandbox/actions/runs/42887191220. Certificate ref: `refs/heads/redteam-testdata/branch-mint`. | REJECT (`forgery-attempt`): source ref is not `refs/heads/main` and trigger `push` is not allowed |
| `good-review-verdict.bundle.json` | Same predicate type and subjects, minted by the temporary `testdata-fixture` job of `.github/workflows/sox-review-agent.yml` on `refs/heads/main` (trigger `workflow_dispatch`, input `pr=0`, code `a71cc6b`), run https://github.com/factory-ryan-lauderback/sox-sdlc-sandbox/actions/runs/42898187375. Attestation digest `sha256:4ab791954c8ce7b16c76da45da779e5eedfa93487ae2505cc8dccb29bc45f8ac`. Predicate has `fixture: true` and constant fields; no real PR or Jira issue binds to `pr:0` / `FRQ-0`. The job was removed in commit `fa6ab4f9e85501f361dcc348c89a50d52f8c666e`, so no later run can mint another. | ACCEPT (signer, ref, trigger). Gates must still refuse it as approval evidence: `fixture: true` |

Subject key: `sha256("sox-subject/v1\n" + repo + "\n" + kind + "\n" + id)`; `sox:pr:0` = `8f0af752b7d7d89a880a09622f93fe9fdf44a91a0b2334f596863dbd8880c871`.
