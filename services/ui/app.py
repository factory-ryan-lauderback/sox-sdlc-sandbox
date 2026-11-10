"""ui: renders the loan list from api as HTML."""
import html
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_URL = os.environ.get("API_URL", "http://localhost:8002")


def render(loans):
    rows = "".join(
        f"<tr><td>{html.escape(str(l['id']))}</td><td>{l['amount']:.2f}</td>"
        f"<td>{l['monthly_payment']:.2f}</td></tr>"
        for l in loans)
    return ("<html><head><title>Acme Lending</title></head><body><h1>Acme Lending loans</h1>"
            "<table><tr><th>ID</th><th>Amount</th><th>Monthly</th></tr>"
            f"{rows}</table></body></html>")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            body, ctype = b'{"ok": true}', "application/json"
        else:
            with urllib.request.urlopen(f"{API_URL}/api/loans", timeout=5) as resp:
                body, ctype = render(json.load(resp)).encode(), "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", 8003))), Handler).serve_forever()
