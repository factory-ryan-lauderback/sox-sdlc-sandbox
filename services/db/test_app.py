import unittest

from services.db.app import add_loan


class AddLoanTest(unittest.TestCase):
    def test_adds_loan(self):
        store = {}
        self.assertEqual(add_loan(store, {"id": "L1", "amount": 1000}), {"id": "L1", "amount": 1000})
        self.assertIn("L1", store)

    def test_rejects_non_positive_amount(self):
        with self.assertRaises(ValueError):
            add_loan({}, {"id": "L2", "amount": 0})


if __name__ == "__main__":
    unittest.main()
