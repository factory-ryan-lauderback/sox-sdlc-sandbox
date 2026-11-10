"""GitHub client tests: a subject with no attestations is "none", never a hidden failure, and a
missing or unreadable repository is never mistaken for "none"."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from soxlib.ghapi import API, APIError, GitHub  # noqa: E402

REPO = "factory-ryan-lauderback/sox-sdlc-sandbox"
KEY = "ab" * 32
ATT = f"/repos/{REPO}/attestations/sha256:{KEY}?per_page=100"


class FakeGitHub(GitHub):
    """Routes: {url-without-API-prefix: (status, body)}. Unlisted URLs answer 404."""

    def __init__(self, routes):
        super().__init__(token="t", retries=0)
        self.routes, self.seen = routes, []

    def _request(self, method, url, body=None, accept=None):
        url = url if url.startswith("http") else API + url
        self.seen.append(url)
        status, data, headers = (self.routes.get(url.replace(API, "", 1)) or (404, '{"message":"Not Found"}', {}))
        if status >= 400:
            raise APIError(status, url, data)
        return status, headers, data.encode()


class TestAttestations404(unittest.TestCase):
    def test_no_attestations_on_reachable_repo_is_empty(self):
        api = FakeGitHub({f"/repos/{REPO}": (200, '{"full_name": "%s"}' % REPO, {})})
        self.assertEqual(api.paginate_attestations(ATT), [])
        self.assertEqual(api.seen, [API + ATT, API + f"/repos/{REPO}"])
        # The repository check is made once per client.
        self.assertEqual(api.paginate_attestations(ATT), [])
        self.assertEqual(len(api.seen), 3)

    def test_found_attestations_are_returned(self):
        api = FakeGitHub({ATT: (200, '{"attestations": [{"bundle": {}}]}', {})})
        self.assertEqual(api.paginate_attestations(ATT), [{"bundle": {}}])

    def test_unreachable_repo_raises(self):
        for status in (404, 403, 401):
            api = FakeGitHub({f"/repos/{REPO}": (status, '{"message":"no"}', {})})
            with self.assertRaises(APIError) as cm:
                api.paginate_attestations(ATT)
            self.assertEqual(cm.exception.status, status)

    def test_auth_or_permission_failure_on_attestations_raises(self):
        for status in (401, 403, 500):
            api = FakeGitHub({ATT: (status, '{"message":"no"}', {}),
                              f"/repos/{REPO}": (200, '{"full_name": "%s"}' % REPO, {})})
            with self.assertRaises(APIError):
                api.paginate_attestations(ATT)

    def test_404_elsewhere_still_raises(self):
        api = FakeGitHub({f"/repos/{REPO}": (200, '{"full_name": "%s"}' % REPO, {})})
        for path in (f"/repos/{REPO}/pulls/1/commits", f"/repos/{REPO}/attestations/sha256:xyz",
                     f"/repos/{REPO}/attestations/sha256:{KEY}/extra"):
            with self.assertRaises(APIError):
                api.paginate_attestations(path)

    def test_404_on_a_later_page_raises(self):
        nxt = API + f"/repos/{REPO}/attestations/sha256:{KEY}?per_page=100&after=x"
        api = FakeGitHub({ATT: (200, '{"attestations": [{"bundle": {}}]}', {"Link": f'<{nxt}>; rel="next"'}),
                          f"/repos/{REPO}": (200, '{"full_name": "%s"}' % REPO, {})})
        with self.assertRaises(APIError):
            api.paginate_attestations(ATT)

    def test_repo_lookup_for_another_repo_raises(self):
        api = FakeGitHub({f"/repos/{REPO}": (200, '{"full_name": "someone/else"}', {})})
        with self.assertRaises(APIError):
            api.paginate_attestations(ATT)


if __name__ == "__main__":
    unittest.main()
