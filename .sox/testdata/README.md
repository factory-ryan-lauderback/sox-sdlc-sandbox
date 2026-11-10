# Verifier test data

| File | What it is | Expected verifier result |
|---|---|---|
| `branch-minted-review-verdict.bundle.json` | Real Sigstore bundle, predicate `https://acme-lending.example/sox/review-verdict/v1`, subjects `sox:pr:0` and `sox:commit:4de627863b24da9d1588afb81d1275ab5fe72d27`. Minted by a throwaway `.github/workflows/sox-review-agent.yml` that existed only on branch `redteam-testdata/branch-mint` (trigger `push`), run https://github.com/factory-ryan-lauderback/sox-sdlc-sandbox/actions/runs/42887191220. Certificate ref: `refs/heads/redteam-testdata/branch-mint`. | REJECT (`forgery-attempt`): source ref is not `refs/heads/main` and trigger `push` is not allowed |
| `good-review-verdict.bundle.json` | Same predicate type and subjects, minted by `sox-review-agent.yml` on `refs/heads/main` (added by the agent pipeline) | ACCEPT |

Subject key: `sha256("sox-subject/v1\n" + repo + "\n" + kind + "\n" + id)`; `sox:pr:0` = `8f0af752b7d7d89a880a09622f93fe9fdf44a91a0b2334f596863dbd8880c871`.
