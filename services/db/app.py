"""db: in-memory loan store. GET /loans, POST /loans {"id", "amount"}."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOANS = {}


def add_loan(store, loan):
    if not isinstance(loan.get("id"), str) or not loan["id"]:
        raise ValueError("id required")
    amount = loan.get("amount")
    if not isinstance(amount, (int, float)) or amount <= 0:
        raise ValueError("amount must be positive")
    store[loan["id"]] = {"id": loan["id"], "amount": amount}
    return store[loan["id"]]


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True})
        if self.path == "/loans":
            return self._send(200, sorted(LOANS.values(), key=lambda l: l["id"]))
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/loans":
            return self._send(404, {"error": "not found"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            self._send(201, add_loan(LOANS, body))
        except (ValueError, json.JSONDecodeError) as e:
            self._send(400, {"error": str(e)})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", 8001))), Handler).serve_forever()
