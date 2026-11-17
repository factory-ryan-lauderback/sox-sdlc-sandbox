"""F18: values sealed by an unkeyed job open only with the key-holding environment's secret, in the
same workflow run, for the same purpose."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import seal  # noqa: E402

SECRET = "-----BEGIN RSA PRIVATE KEY-----\nseal-test\n-----END RSA PRIVATE KEY-----\n"


class SealTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "100"})
        p.start()
        self.addCleanup(p.stop)

    def test_roundtrip_and_fresh_ciphertext(self):
        pub = seal.public_key(SECRET, "review-verdict")
        self.assertEqual(pub, seal.public_key(SECRET, "review-verdict"))
        a, b = seal.seal(pub, b"verdict text"), seal.seal(pub, b"verdict text")
        self.assertNotEqual(a, b)
        self.assertNotIn("verdict", a)
        self.assertEqual(seal.unseal(SECRET, "review-verdict", a), b"verdict text")
        self.assertEqual(seal.unseal(SECRET, "review-verdict", seal.seal(pub, b"")), b"")

    def test_wrong_secret_purpose_or_run_refused(self):
        c = seal.seal(seal.public_key(SECRET, "review-verdict"), b"x" * 1000)
        for secret, purpose in (("other", "review-verdict"), (SECRET, "qa-results")):
            with self.assertRaises(ValueError):
                seal.unseal(secret, purpose, c)
        with mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "101"}):
            with self.assertRaises(ValueError):
                seal.unseal(SECRET, "review-verdict", c)

    def test_tampering_refused(self):
        import base64
        c = seal.seal(seal.public_key(SECRET, "qa-results"), b"results")
        raw = bytearray(base64.b64decode(c[len(seal.PREFIX):]))
        for i in (0, 40, len(raw) - 1):
            t = bytearray(raw)
            t[i] ^= 1
            with self.assertRaises(ValueError):
                seal.unseal(SECRET, "qa-results", seal.PREFIX + base64.b64encode(bytes(t)).decode())
        for bad in ("", "plain", seal.PREFIX, seal.PREFIX + "!!", seal.PREFIX + base64.b64encode(b"short").decode()):
            with self.assertRaises(ValueError):
                seal.unseal(SECRET, "qa-results", bad)

    def test_missing_key_material_refused(self):
        for secret in ("", "  ", None):
            with self.assertRaises(ValueError):
                seal.public_key(secret, "review-verdict")
        with self.assertRaises(ValueError):
            seal.public_key(SECRET, "other-purpose")
        for pub in ("", None, "AAAA"):
            with self.assertRaises(ValueError):
                seal.seal(pub, b"x")


if __name__ == "__main__":
    unittest.main()
