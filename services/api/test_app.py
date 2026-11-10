import unittest

from services.api.app import enrich, monthly_payment


class PaymentTest(unittest.TestCase):
    def test_monthly_payment(self):
        self.assertEqual(monthly_payment(10000), 313.36)

    def test_enrich_adds_payment(self):
        self.assertEqual(enrich([{"id": "L1", "amount": 10000}])[0]["monthly_payment"], 313.36)


if __name__ == "__main__":
    unittest.main()
