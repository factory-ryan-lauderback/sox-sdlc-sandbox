# Acme Lending: SOX SDLC sandbox

Fictional company. This public repository is a sandbox for an agent-driven SDLC that must pass a
SOX ITGC change-management audit. It contains no real customer data or secrets.

## Services

Three toy services. Each one ships a Dockerfile, unit tests, and a `service.yaml` manifest that
declares its upstream service dependencies.

| Service | Port | Depends on | What it does |
|---|---|---|---|
| `db`  | 8001 | none | In-memory loan store over HTTP |
| `api` | 8002 | `db` | Loan API that reads and writes through `db` |
| `ui`  | 8003 | `api` | HTML page that lists loans from `api` |

Deploy order is computed from the manifests:

```sh
python3 tools/deploy_order.py          # prints: db api ui
python3 tools/deploy_order.py --json   # machine-readable, with paths per service
```

Run all unit tests with `python3 -m unittest discover -s services -p "test_*.py" -t .`.

## Control paths

`.github/**`, `.sox/**`, `.factory/**`, `tools/**`, and `CODEOWNERS` are control paths. They are
owned by the Control Owner in `CODEOWNERS` and change only through the same reviewed process.
