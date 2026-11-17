from copy import deepcopy
import unittest

from services.api.app import enrich, monthly_payment


class PaymentTest(unittest.TestCase):
    def test_monthly_payment(self):
        self.assertEqual(monthly_payment(10000), 313.36)

    def test_enrich_adds_payment(self):
        self.assertEqual(enrich([{"id": "L1", "amount": 10000}])[0]["monthly_payment"], 313.36)

    def test_enrich_adds_payoff_amount(self):
        loans = [
            {"id": "L1", "amount": 10000},
            {"id": "L2", "amount": 1},
            {"id": "L3", "amount": 2500.5},
            {"id": "L4", "amount": 123.45},
        ]
        enriched = enrich(loans)
        self.assertEqual(
            [loan["payoff_amount"] for loan in enriched],
            [10066.67, 1.01, 2517.17, 124.27],
        )
        for loan in enriched:
            self.assertIsInstance(loan["payoff_amount"], (int, float))

    def test_enrich_empty(self):
        self.assertEqual(enrich([]), [])

    def test_enrich_preserves_fields_and_input(self):
        loans = [
            {"id": "Z", "amount": 10000, "status": "active", "metadata": {"term": 36}},
            {"id": "A", "amount": 1, "extra": None},
        ]
        original = deepcopy(loans)

        enriched = enrich(loans)

        self.assertEqual(loans, original)
        self.assertIsNot(enriched, loans)
        self.assertEqual(
            enriched,
            [
                {
                    "id": "Z",
                    "amount": 10000,
                    "status": "active",
                    "metadata": {"term": 36},
                    "monthly_payment": 313.36,
                    "payoff_amount": 10066.67,
                },
                {
                    "id": "A",
                    "amount": 1,
                    "extra": None,
                    "monthly_payment": 0.03,
                    "payoff_amount": 1.01,
                },
            ],
        )
        for loan, enriched_loan in zip(loans, enriched):
            self.assertIsNot(enriched_loan, loan)

    def test_payoff_rounding(self):
        for amount, expected in [
            (0, 0.0),
            (0.74, 0.74),
            (0.75, 0.76),
            (0.76, 0.77),
            (100.008, 100.67),
            (100.009, 100.68),
        ]:
            with self.subTest(amount=amount):
                self.assertEqual(enrich([{"amount": amount}])[0]["payoff_amount"], expected)


if __name__ == "__main__":
    unittest.main()
