"""Tests for tee.launch_assertions (stdlib unittest; no test deps).

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import unittest
from unittest import mock

from tee.cli.network import launch_assertions
from tee.cli.network.launch_assertions import LaunchTarget

NODE_KEY = "ab" * 32
CONSENSUS_KEY = "cd" * 48
OTHER_NODE_KEY = "ef" * 32


def _target(name: str, fqdn: str, ip: str = "203.0.113.1") -> LaunchTarget:
    return LaunchTarget(
        name=name,
        public_ip=ip,
        fqdn=fqdn,
        node_public_key=NODE_KEY,
        consensus_public_key=CONSENSUS_KEY,
    )


class AssertCohortGenesisHashTests(unittest.TestCase):
    """The manifest pins eth_genesis_hash; every node's live reth must serve
    it as block 0, else the launch assertion refuses (stale image / wrong
    genesis on that node)."""

    HASH = "0x" + "ab" * 32
    OTHER_HASH = "0x" + "cd" * 32

    def _resp(self, body: dict):
        r = mock.Mock()
        r.raise_for_status.return_value = None
        r.json.return_value = body
        return r

    def _block_resp(self, hash_: str):
        return self._resp({"jsonrpc": "2.0", "id": 1, "result": {"hash": hash_}})

    def test_matching_cohort_passes(self):
        targets = [_target("node-1", "a.example"), _target("node-2", "b.example")]
        responses = [self._block_resp(self.HASH), self._block_resp(self.HASH)]
        with mock.patch.object(
            launch_assertions.requests, "post", side_effect=responses
        ) as post:
            launch_assertions.assert_cohort_genesis_hash(targets, self.HASH)
        # Queries block 0 on each node's reth through nginx's /rpc proxy.
        urls = [call.args[0] for call in post.call_args_list]
        self.assertEqual(urls, ["https://a.example/rpc", "https://b.example/rpc"])
        envelope = post.call_args[1]["json"]
        self.assertEqual(envelope["method"], "eth_getBlockByNumber")
        self.assertEqual(envelope["params"], ["0x0", False])

    def test_hash_comparison_is_case_insensitive(self):
        targets = [_target("node-1", "a.example")]
        with mock.patch.object(
            launch_assertions.requests, "post", return_value=self._block_resp(self.HASH)
        ):
            launch_assertions.assert_cohort_genesis_hash(targets, self.HASH.upper())

    def test_mismatching_node_exits_listing_whole_cohort(self):
        targets = [_target("node-1", "a.example"), _target("node-2", "b.example")]
        responses = [self._block_resp(self.HASH), self._block_resp(self.OTHER_HASH)]
        with mock.patch.object(
            launch_assertions.requests, "post", side_effect=responses
        ):
            with self.assertRaises(SystemExit) as ctx:
                launch_assertions.assert_cohort_genesis_hash(targets, self.HASH)
        # Full-cohort listing: the matching node too, so one bad node is
        # distinguishable from a manifest that matches nobody.
        msg = str(ctx.exception)
        self.assertIn(self.HASH, msg)
        self.assertIn("✓ node-1", msg)
        self.assertIn("✗ node-2", msg)
        self.assertIn(self.OTHER_HASH, msg)

    def test_unreachable_node_reported_without_hiding_others(self):
        # First node down past the deadline; second still queried and reported.
        targets = [_target("node-1", "a.example"), _target("node-2", "b.example")]
        responses = [OSError("boom"), self._block_resp(self.HASH)]
        with (
            mock.patch.object(
                launch_assertions.requests, "post", side_effect=responses
            ),
            mock.patch.object(
                launch_assertions,
                "fetch_status",
                side_effect=launch_assertions.requests.ConnectionError("not reachable"),
            ),
            self.assertRaises(SystemExit) as ctx,
        ):
            launch_assertions.assert_cohort_genesis_hash(targets, self.HASH, timeout=0)
        msg = str(ctx.exception)
        self.assertIn("https://a.example/rpc", msg)
        self.assertIn("✓ node-2", msg)

    def test_rpc_error_response_exits(self):
        targets = [_target("node-1", "a.example")]
        resp = self._resp({"jsonrpc": "2.0", "id": 1, "error": {"message": "boom"}})
        with (
            mock.patch.object(launch_assertions.requests, "post", return_value=resp),
            mock.patch.object(
                launch_assertions,
                "fetch_status",
                side_effect=launch_assertions.requests.ConnectionError("not reachable"),
            ),
            self.assertRaises(SystemExit) as ctx,
        ):
            launch_assertions.assert_cohort_genesis_hash(targets, self.HASH, timeout=0)
        self.assertIn("boom", str(ctx.exception))

    def test_unreachable_node_polled_until_it_answers(self):
        # This assertion doubles as the cohort barrier: reth comes up only
        # after the root_key → LUKS boot tail, so a node that doesn't answer
        # yet is retried rather than failing the launch.
        targets = [_target("node-1", "a.example")]
        responses = [OSError("still booting"), self._block_resp(self.HASH)]
        no_luks_status = mock.patch.object(
            launch_assertions,
            "fetch_status",
            side_effect=launch_assertions.requests.ConnectionError("not reachable"),
        )
        with mock.patch.object(
            launch_assertions.requests, "post", side_effect=responses
        ) as post:
            with no_luks_status:
                launch_assertions.assert_cohort_genesis_hash(
                    targets, self.HASH, timeout=30, interval=0
                )
        self.assertEqual(post.call_count, 2)

    def test_luks_progress_pauses_readiness_timeout(self):
        targets = [_target("node-1", "a.example")]
        responses = [
            OSError("still booting"),
            OSError("still booting"),
            self._block_resp(self.HASH),
        ]
        statuses = [
            {
                "state": "provisioning",
                "bytes_done": 1,
                "bytes_total": 2,
                "eta_seconds": 30,
            },
            {"state": "idle"},
        ]
        clock = [0.0]
        rendered: list[str] = []

        def sleep(_interval):
            clock[0] += 100

        with (
            mock.patch.object(
                launch_assertions.requests, "post", side_effect=responses
            ) as post,
            mock.patch.object(launch_assertions, "fetch_status", side_effect=statuses),
            mock.patch.object(
                launch_assertions.time, "monotonic", side_effect=lambda: clock[0]
            ),
            mock.patch.object(launch_assertions.time, "sleep", side_effect=sleep),
            mock.patch.object(launch_assertions, "CohortDashboard") as dashboard_cls,
        ):
            dashboard_cls.return_value.render.side_effect = (
                lambda states: rendered.extend(states.values())
            )
            launch_assertions.assert_cohort_genesis_hash(
                targets, self.HASH, timeout=10, interval=0
            )

        self.assertEqual(post.call_count, 3)
        self.assertTrue(any("encrypting disk" in state for state in rendered))
        self.assertTrue(any("readiness timeout paused" in state for state in rendered))

    def test_mismatch_fails_fast_without_waiting_for_stragglers(self):
        # A wrong answer can't heal by waiting — fail immediately even while
        # another node is still unreachable, instead of burning the timeout.
        targets = [_target("node-1", "a.example"), _target("node-2", "b.example")]
        responses = [self._block_resp(self.OTHER_HASH), OSError("still booting")]
        no_sleep = mock.patch.object(
            launch_assertions.time, "sleep", side_effect=AssertionError("must not wait")
        )
        with mock.patch.object(
            launch_assertions.requests, "post", side_effect=responses
        ):
            with no_sleep, self.assertRaises(SystemExit) as ctx:
                launch_assertions.assert_cohort_genesis_hash(targets, self.HASH)
        msg = str(ctx.exception)
        self.assertIn(self.OTHER_HASH, msg)
        self.assertIn("still booting", msg)


class AssertCohortHolderKeysTests(unittest.TestCase):
    """Each box's holder must serve exactly the keys harvested from it. A
    mismatch is retried (the holder serves this boot's RAM keys until the
    LUKS keystore is visible), so only a mismatch standing at the deadline
    fails — that is the reboot-inside-the-founding-window dead slot."""

    def _keys_resp(self, node: str, consensus: str):
        r = mock.Mock()
        r.raise_for_status.return_value = None
        r.json.return_value = {
            "node_public_key": node,
            "consensus_public_key": consensus,
        }
        return r

    def test_matching_cohort_passes_and_hits_the_holder_port(self):
        targets = [
            _target("node-1", "a.example", ip="203.0.113.1"),
            _target("node-2", "b.example", ip="203.0.113.2"),
        ]
        with mock.patch.object(
            launch_assertions.requests,
            "get",
            return_value=self._keys_resp(NODE_KEY, CONSENSUS_KEY),
        ) as get:
            launch_assertions.assert_cohort_holder_keys(targets)
        urls = [call.args[0] for call in get.call_args_list]
        self.assertEqual(
            urls,
            [
                f"http://203.0.113.1:{launch_assertions.HOLDER_PORT}/v1/keys",
                f"http://203.0.113.2:{launch_assertions.HOLDER_PORT}/v1/keys",
            ],
        )

    def test_unreachable_holder_polled_until_it_answers(self):
        targets = [_target("node-1", "a.example")]
        responses = [
            launch_assertions.requests.ConnectionError("still booting"),
            self._keys_resp(NODE_KEY, CONSENSUS_KEY),
        ]
        with mock.patch.object(
            launch_assertions.requests, "get", side_effect=responses
        ) as get:
            launch_assertions.assert_cohort_holder_keys(targets, timeout=30, interval=0)
        self.assertEqual(get.call_count, 2)

    def test_transient_mismatch_retried_until_keystore_visible(self):
        # Pre-persist the holder serves this boot's fresh RAM keys; the
        # assertion must not fail fast on that read.
        targets = [_target("node-1", "a.example")]
        responses = [
            self._keys_resp(OTHER_NODE_KEY, CONSENSUS_KEY),
            self._keys_resp(NODE_KEY, CONSENSUS_KEY),
        ]
        with mock.patch.object(
            launch_assertions.requests, "get", side_effect=responses
        ) as get:
            launch_assertions.assert_cohort_holder_keys(targets, timeout=30, interval=0)
        self.assertEqual(get.call_count, 2)

    def test_standing_mismatch_exits_with_refound_advice(self):
        targets = [_target("node-1", "a.example"), _target("node-2", "b.example")]
        responses = [
            self._keys_resp(OTHER_NODE_KEY, CONSENSUS_KEY),  # node-1: unpinned keys
            self._keys_resp(NODE_KEY, CONSENSUS_KEY),  # node-2: pinned
        ]
        with mock.patch.object(
            launch_assertions.requests, "get", side_effect=responses
        ):
            with self.assertRaises(SystemExit) as ctx:
                launch_assertions.assert_cohort_holder_keys(targets, timeout=0)
        msg = str(ctx.exception)
        self.assertIn("✗ node-1", msg)
        self.assertIn(OTHER_NODE_KEY, msg)
        self.assertIn("✓ node-2", msg)
        self.assertIn("Re-found", msg)

    def test_timeout_on_unreachable_holder_suggests_reassert(self):
        targets = [_target("node-1", "a.example")]
        with mock.patch.object(
            launch_assertions.requests,
            "get",
            side_effect=launch_assertions.requests.ConnectionError("no route"),
        ):
            with self.assertRaises(SystemExit) as ctx:
                launch_assertions.assert_cohort_holder_keys(targets, timeout=0)
        msg = str(ctx.exception)
        self.assertIn("no route", msg)
        self.assertIn("re-run", msg)

    def test_malformed_holder_response_exits_immediately(self):
        # Retrying can't fix a holder serving the wrong shape.
        targets = [_target("node-1", "a.example")]
        resp = mock.Mock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"node": NODE_KEY}
        no_sleep = mock.patch.object(
            launch_assertions.time, "sleep", side_effect=AssertionError("must not wait")
        )
        with mock.patch.object(launch_assertions.requests, "get", return_value=resp):
            with no_sleep, self.assertRaises(SystemExit) as ctx:
                launch_assertions.assert_cohort_holder_keys(targets)
        self.assertIn("node_public_key", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
