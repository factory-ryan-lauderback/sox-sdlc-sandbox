import unittest

from services.ui.app import render


class RenderTest(unittest.TestCase):
    def test_escapes_ids(self):
        out = render([{"id": "<b>", "amount": 1.0, "monthly_payment": 0.5,
                       "payoff_amount": 1.01}])
        self.assertIn("&lt;b&gt;", out)
        self.assertNotIn("<b>", out.split("<table>")[1])

    def test_empty_table(self):
        self.assertEqual(
            render([]),
            "<html><head><title>Acme Lending</title></head><body><h1>Acme Lending loans</h1>"
            "<table><tr><th>ID</th><th>Amount</th><th>Monthly</th><th>Payoff</th></tr>"
            "</table></body></html>",
        )

    def test_payoff_column(self):
        out = render([
            {"id": "Z", "amount": 10000, "monthly_payment": 313.36,
             "payoff_amount": 10066.67},
            {"id": "A", "amount": 1, "monthly_payment": 0.03,
             "payoff_amount": 1.01},
        ])
        self.assertEqual(out.count("<th>Payoff</th>"), 1)
        self.assertIn(
            "<tr><td>Z</td><td>10000.00</td><td>313.36</td><td>10066.67</td></tr>"
            "<tr><td>A</td><td>1.00</td><td>0.03</td><td>1.01</td></tr>",
            out,
        )

    def test_payoff_two_decimals(self):
        for payoff, expected in [(0, "0.00"), (12, "12.00"), (12.5, "12.50"),
                                 (12.34, "12.34")]:
            with self.subTest(payoff=payoff):
                out = render([{"id": "L1", "amount": 10, "monthly_payment": 0.31,
                               "payoff_amount": payoff}])
                self.assertIn(f"<td>{expected}</td></tr>", out)

    def test_preserves_existing_columns(self):
        out = render([{"id": "L1", "amount": 123.4, "monthly_payment": 3.87,
                       "payoff_amount": 124.22}])
        self.assertIn(
            "<table><tr><th>ID</th><th>Amount</th><th>Monthly</th><th>Payoff</th></tr>",
            out,
        )
        self.assertIn(
            "<tr><td>L1</td><td>123.40</td><td>3.87</td><td>124.22</td></tr>",
            out,
        )

    def test_uses_supplied_payoff_amount(self):
        out = render([{"id": "L1", "amount": 10000, "monthly_payment": 313.36,
                       "payoff_amount": 42.5}])
        self.assertIn(
            "<tr><td>L1</td><td>10000.00</td><td>313.36</td><td>42.50</td></tr>",
            out,
        )
        self.assertNotIn("10066.67", out)


if __name__ == "__main__":
    unittest.main()
