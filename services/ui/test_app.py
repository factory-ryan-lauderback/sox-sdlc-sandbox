import unittest

from services.ui.app import render


class RenderTest(unittest.TestCase):
    def test_escapes_ids(self):
        out = render([{"id": "<b>", "amount": 1.0, "monthly_payment": 0.5}])
        self.assertIn("&lt;b&gt;", out)
        self.assertNotIn("<b>", out.split("<table>")[1])


if __name__ == "__main__":
    unittest.main()
