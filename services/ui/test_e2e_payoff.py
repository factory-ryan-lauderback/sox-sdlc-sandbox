"""HTTP-only table checks; synthetic loans remain in the disposable deployment."""
import html
from html.parser import HTMLParser
import json
import os
import unittest
import urllib.request
from uuid import uuid4


DB_URL = os.environ.get("DB_URL", "").rstrip("/")
API_URL = os.environ.get("API_URL", "").rstrip("/")
UI_URL = os.environ.get("UI_URL", "").rstrip("/")

# Independent expected amounts include fractional inputs and trailing-zero displays.
# amount, payoff_amount, monthly_payment
LOAN_CASES = (
    (10000, 10066.67, 313.36),
    (1, 1.01, 0.03),
    (2500.5, 2517.17, 78.36),
    (123.45, 124.27, 3.87),
    (1500, 1510.00, 47.00),
    (75, 75.50, 2.35),
)


class _TableParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows = []
        self.table_count = 0
        self._in_table = False
        self._row = None
        self._cell = None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.table_count += 1
            self._in_table = True
        elif self._in_table and tag == "tr":
            self._row = []
        elif self._row is not None and tag in ("td", "th"):
            self._cell = []

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self._cell is not None:
            self._row.append((tag, "".join(self._cell)))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            self.rows.append(self._row)
            self._row = None
        elif tag == "table":
            self._in_table = False


@unittest.skipUnless(DB_URL and API_URL and UI_URL,
                     "DB_URL, API_URL and UI_URL are required")
class PayoffUiE2ETest(unittest.TestCase):
    def _read_json(self, request, status=200):
        with urllib.request.urlopen(request, timeout=10) as response:
            self.assertEqual(response.status, status)
            self.assertEqual(response.headers.get_content_type(), "application/json")
            return json.load(response)

    def setUp(self):
        prefix = f"frq21-ui-{uuid4().hex}"
        self.fixtures = []
        for index, (amount, payoff, monthly) in enumerate(LOAN_CASES):
            loan_id = f"{prefix}-{index}"
            if index == 0:
                loan_id += '-<b data-qa="loan">O\'Brien & Co</b>'
            loan = {"id": loan_id, "amount": amount}
            request = urllib.request.Request(
                f"{DB_URL}/loans",
                data=json.dumps(loan).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            self.assertEqual(self._read_json(request, status=201), loan)
            self.fixtures.append((loan, payoff, monthly))

    def _fetch_rows(self):
        with urllib.request.urlopen(f"{UI_URL}/", timeout=10) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers.get_content_type(), "text/html")
            document = response.read().decode("utf-8")
        parser = _TableParser()
        parser.feed(document)
        parser.close()
        self.assertEqual(parser.table_count, 1)
        self.assertGreaterEqual(len(parser.rows), 1)
        self.assertEqual(
            parser.rows[0],
            [("th", "ID"), ("th", "Amount"), ("th", "Monthly"), ("th", "Payoff")],
        )
        rows = {}
        for row in parser.rows[1:]:
            self.assertEqual([tag for tag, value in row], ["td"] * 4)
            cells = [value for tag, value in row]
            self.assertNotIn(cells[0], rows, "Duplicate loan row")
            rows[cells[0]] = cells
        return document, rows

    def test_existing_columns_and_id_escaping(self):
        document, rows = self._fetch_rows()
        for fixture, payoff, monthly in self.fixtures:
            with self.subTest(loan_id=fixture["id"]):
                self.assertIn(fixture["id"], rows)
                self.assertEqual(
                    rows[fixture["id"]][:3],
                    [fixture["id"], f'{fixture["amount"]:.2f}', f"{monthly:.2f}"],
                )
        escaped_id = self.fixtures[0][0]["id"]
        self.assertIn(f"<td>{html.escape(escaped_id)}</td>", document)
        self.assertNotIn(escaped_id, document)

    def test_payoff_column_matches_api(self):
        loans = self._read_json(f"{API_URL}/api/loans")
        self.assertIsInstance(loans, list)
        document, rows = self._fetch_rows()
        for fixture, payoff, monthly in self.fixtures:
            with self.subTest(loan_id=fixture["id"]):
                matches = [loan for loan in loans if loan["id"] == fixture["id"]]
                self.assertEqual(len(matches), 1)
                loan = matches[0]
                self.assertIn(type(loan["payoff_amount"]), (int, float))
                self.assertEqual(loan["payoff_amount"], payoff)
                self.assertEqual(loan["amount"], fixture["amount"])
                self.assertEqual(loan["monthly_payment"], monthly)
                self.assertIn(fixture["id"], rows)
                self.assertEqual(
                    rows[fixture["id"]],
                    [fixture["id"], f'{fixture["amount"]:.2f}',
                     f"{monthly:.2f}", f"{payoff:.2f}"],
                )
                self.assertEqual(rows[fixture["id"]][3], f'{loan["payoff_amount"]:.2f}')


if __name__ == "__main__":
    unittest.main()
