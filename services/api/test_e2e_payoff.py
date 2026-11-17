"""HTTP-only checks for an isolated, disposable DB -> API -> UI deployment."""
import json
import os
import unittest
import urllib.error
import urllib.request
from uuid import uuid4


DB_URL = os.environ.get("DB_URL", "").rstrip("/")
API_URL = os.environ.get("API_URL", "").rstrip("/")
UI_URL = os.environ.get("UI_URL", "").rstrip("/")

# Independent acceptance values, not calculations imported from the service.
# amount, payoff_amount, monthly_payment
LOAN_CASES = (
    (10000, 10066.67, 313.36),
    (1, 1.01, 0.03),
    (2500.5, 2517.17, 78.36),
    (123.45, 124.27, 3.87),
    (1500, 1510.00, 47.00),
    (75, 75.50, 2.35),
)


@unittest.skipUnless(DB_URL and API_URL and UI_URL,
                     "DB_URL, API_URL and UI_URL are required")
class PayoffApiE2ETest(unittest.TestCase):
    def _read_json(self, request, status=200):
        with urllib.request.urlopen(request, timeout=10) as response:
            self.assertEqual(response.status, status)
            self.assertEqual(response.headers.get_content_type(), "application/json")
            return json.load(response)

    def test_existing_endpoints(self):
        for service, base_url in (("db", DB_URL), ("api", API_URL), ("ui", UI_URL)):
            with self.subTest(service=service):
                self.assertEqual(self._read_json(f"{base_url}/healthz"), {"ok": True})

        self.assertIsInstance(self._read_json(f"{DB_URL}/loans"), list)
        self.assertIsInstance(self._read_json(f"{API_URL}/api/loans"), list)
        with urllib.request.urlopen(f"{UI_URL}/", timeout=10) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers.get_content_type(), "text/html")
            self.assertIn("Acme Lending", response.read().decode("utf-8"))

        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(f"{API_URL}/not-found-{uuid4().hex}", timeout=10)
        with caught.exception as response:
            self.assertEqual(response.code, 404)
            self.assertEqual(response.headers.get_content_type(), "application/json")
            self.assertEqual(json.load(response), {"error": "not found"})

    def test_payoff_amounts_and_existing_fields(self):
        prefix = f"frq21-api-{uuid4().hex}"
        fixtures = []
        for index, (amount, payoff, monthly) in enumerate(LOAN_CASES):
            loan = {"id": f"{prefix}-{index}", "amount": amount}
            request = urllib.request.Request(
                f"{DB_URL}/loans",
                data=json.dumps(loan).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            self.assertEqual(self._read_json(request, status=201), loan)
            fixtures.append((loan, payoff, monthly))

        loans = self._read_json(f"{API_URL}/api/loans")
        self.assertIsInstance(loans, list)
        for fixture, payoff, monthly in fixtures:
            with self.subTest(loan_id=fixture["id"]):
                matches = [loan for loan in loans if loan["id"] == fixture["id"]]
                self.assertEqual(len(matches), 1)
                loan = matches[0]
                self.assertEqual(loan["id"], fixture["id"])
                self.assertEqual(loan["amount"], fixture["amount"])
                for field in ("amount", "payoff_amount", "monthly_payment"):
                    self.assertIn(type(loan[field]), (int, float))
                self.assertEqual(loan["payoff_amount"], payoff)
                self.assertEqual(loan["monthly_payment"], monthly)


if __name__ == "__main__":
    unittest.main()
