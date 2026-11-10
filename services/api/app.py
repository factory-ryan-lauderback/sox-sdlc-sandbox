"""api: loan API in front of db. GET /api/loans returns loans with a computed monthly payment."""
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_URL = os.environ.get("DB_URL", "http://localhost:8001")
TERM_MONTHS = 36
ANNUAL_RATE = 0.08


def monthly_payment(amount, annual_rate=ANNUAL_RATE, months=TERM_MONTHS):
    r = annual_rate / 12
    return round(amount * r / (1 - (1 + r) ** -months), 2)


def enrich(loans):
    return [dict(l, monthly_payment=monthly_payment(l["amount"])) for l in loans]


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
        if self.path == "/api/loans":
            with urllib.request.urlopen(f"{DB_URL}/loans", timeout=5) as resp:
                return self._send(200, enrich(json.load(resp)))
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", 8002))), Handler).serve_forever()
