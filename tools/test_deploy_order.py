import unittest

from tools.deploy_order import deploy_order, load_services


class DeployOrderTest(unittest.TestCase):
    def test_repo_order(self):
        self.assertEqual(deploy_order(load_services()), ["db", "api", "ui"])

    def test_cycle_rejected(self):
        with self.assertRaises(ValueError):
            deploy_order({"a": {"depends_on": ["b"]}, "b": {"depends_on": ["a"]}})

    def test_unknown_dependency_rejected(self):
        with self.assertRaises(ValueError):
            deploy_order({"a": {"depends_on": ["zz"]}})


if __name__ == "__main__":
    unittest.main()
