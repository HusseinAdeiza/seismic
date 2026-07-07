"""Tests for tee.cli.network.summit_client (stdlib unittest; no test deps).

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import unittest
from unittest import mock

from tee.cli.network import summit_client
from tee.cli.network.summit_client import SummitClient


class SummitClientTests(unittest.TestCase):
    def _resp(self, body: dict):
        r = mock.Mock()
        r.raise_for_status.return_value = None
        r.json.return_value = body
        return r

    def _patch(self, resp):
        return mock.patch.object(summit_client.requests, "post", return_value=resp)

    def test_get_public_keys_posts_jsonrpc_and_parses(self):
        result = {"node": "n", "consensus": "c"}
        resp = self._resp({"jsonrpc": "2.0", "id": 1, "result": result})
        with self._patch(resp) as post:
            keys = SummitClient("https://x/summit").get_public_keys()
        self.assertEqual((keys.node, keys.consensus), ("n", "c"))
        # POSTs a JSON-RPC envelope to the /summit base, camelCase method.
        self.assertEqual(post.call_args[0][0], "https://x/summit")
        self.assertEqual(post.call_args[1]["json"]["method"], "getPublicKeys")

    def test_send_genesis_posts_content_as_param(self):
        resp = self._resp({"jsonrpc": "2.0", "id": 1, "result": "ok"})
        with self._patch(resp) as post:
            SummitClient("https://x/summit").send_genesis("foo = 1\n")
        self.assertEqual(post.call_args[1]["json"]["method"], "sendGenesis")
        self.assertEqual(post.call_args[1]["json"]["params"], ["foo = 1\n"])

    def test_rpc_error_raises(self):
        resp = self._resp({"jsonrpc": "2.0", "id": 1, "error": {"message": "boom"}})
        with self._patch(resp):
            with self.assertRaises(RuntimeError):
                SummitClient("https://x/summit").get_public_keys()


if __name__ == "__main__":
    unittest.main()
