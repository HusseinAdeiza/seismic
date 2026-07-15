"""Tests for tee.genesis (stdlib unittest; no test deps).

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tee.cli.network import genesis
from tee.cli.network.summit_client import PublicKeys


class ParseArgsTests(unittest.TestCase):
    """Both `--node a b` and `--node a --node b` must yield the full cohort —
    with plain nargs="+", a repeated flag silently replaced the earlier one
    and the ceremony ran against a partial cohort."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.n1 = self._file("n1.json")
        self.n2 = self._file("n2.json")
        self.template = self._file("template.toml")
        self.manifest = self._file("manifest.json")
        self.common = [
            "--summit-template",
            str(self.template),
            "--manifest",
            str(self.manifest),
        ]

    def _file(self, name: str) -> Path:
        path = Path(self._tmp.name) / name
        path.write_text("{}")
        return path

    def test_single_flag_multiple_values(self):
        args = genesis._parse_args(["--node", str(self.n1), str(self.n2), *self.common])
        self.assertEqual(args.node, [self.n1, self.n2])

    def test_repeated_flag_accumulates(self):
        args = genesis._parse_args(
            ["--node", str(self.n1), "--node", str(self.n2), *self.common]
        )
        self.assertEqual(args.node, [self.n1, self.n2])

    def test_duplicate_descriptor_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            genesis._parse_args(
                ["--node", str(self.n1), "--node", str(self.n1), *self.common]
            )
        self.assertIn("duplicate", str(ctx.exception))

    def test_node_defaults_to_manifest_sibling_nodes_dir(self):
        # The layout `up --network` writes; sorted for a deterministic cohort.
        nodes = Path(self._tmp.name) / "nodes"
        nodes.mkdir()
        (nodes / "b.json").write_text("{}")
        (nodes / "a.json").write_text("{}")
        args = genesis._parse_args(list(self.common))
        self.assertEqual(args.node, [nodes / "a.json", nodes / "b.json"])

    def test_no_node_and_no_nodes_dir_errors(self):
        with self.assertRaises(SystemExit) as ctx:
            genesis._parse_args(list(self.common))
        self.assertIn("--node", str(ctx.exception))

    def test_summit_template_defaults_to_manifest_sibling(self):
        # The artifact-set layout `manifest assemble --out` writes.
        sibling = Path(self._tmp.name) / "summit-genesis-template.toml"
        sibling.write_text("")
        args = genesis._parse_args(
            ["--node", str(self.n1), "--manifest", str(self.manifest)]
        )
        self.assertEqual(args.summit_template, sibling)

    def test_missing_default_template_errors_with_hint(self):
        with self.assertRaises(SystemExit) as ctx:
            genesis._parse_args(
                ["--node", str(self.n1), "--manifest", str(self.manifest)]
            )
        self.assertIn("beside --manifest", str(ctx.exception))


class TemplateCommitmentTests(unittest.TestCase):
    """The ceremony must build genesis.toml only from the template the
    manifest commits to — the -g override protects the eth hash, but the
    namespace/timeouts/stake bounds flow into genesis.toml as-is."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.template = Path(self._tmp.name) / "summit-genesis-template.toml"
        self.template.write_text('namespace = "testnet-1"\n')

    def _manifest_committing_to(self, data: bytes) -> dict:
        return {
            "summit": {"genesis_template_hash": "0x" + hashlib.sha256(data).hexdigest()}
        }

    def test_committed_template_passes(self):
        genesis._verify_template_commitment(
            self.template, self._manifest_committing_to(self.template.read_bytes())
        )

    def test_uncommitted_template_exits(self):
        with self.assertRaises(SystemExit) as ctx:
            genesis._verify_template_commitment(
                self.template, self._manifest_committing_to(b"other bytes")
            )
        self.assertIn("genesis_template_hash", str(ctx.exception))


class AssertCohortGenesisHashTests(unittest.TestCase):
    """The manifest declares eth_genesis_hash; every node's live reth must
    serve it as block 0, else the ceremony refuses (stale image / wrong
    genesis on that node)."""

    HASH = "0x" + "ab" * 32
    OTHER_HASH = "0x" + "cd" * 32

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _descriptor(self, name: str, fqdn: str) -> Path:
        path = Path(self._tmp.name) / f"{name}.json"
        path.write_text(json.dumps({"public_ip": "203.0.113.1", "fqdn": fqdn}))
        return path

    def _resp(self, body: dict):
        r = mock.Mock()
        r.raise_for_status.return_value = None
        r.json.return_value = body
        return r

    def _block_resp(self, hash_: str):
        return self._resp({"jsonrpc": "2.0", "id": 1, "result": {"hash": hash_}})

    def test_matching_cohort_passes(self):
        nodes = [
            self._descriptor("node-1", "a.example"),
            self._descriptor("node-2", "b.example"),
        ]
        responses = [self._block_resp(self.HASH), self._block_resp(self.HASH)]
        with mock.patch.object(genesis.requests, "post", side_effect=responses) as post:
            genesis._assert_cohort_genesis_hash(nodes, self.HASH)
        # Queries block 0 on each node's reth through nginx's /rpc proxy.
        urls = [call.args[0] for call in post.call_args_list]
        self.assertEqual(urls, ["https://a.example/rpc", "https://b.example/rpc"])
        envelope = post.call_args[1]["json"]
        self.assertEqual(envelope["method"], "eth_getBlockByNumber")
        self.assertEqual(envelope["params"], ["0x0", False])

    def test_hash_comparison_is_case_insensitive(self):
        nodes = [self._descriptor("node-1", "a.example")]
        with mock.patch.object(
            genesis.requests, "post", return_value=self._block_resp(self.HASH)
        ):
            genesis._assert_cohort_genesis_hash(nodes, self.HASH.upper())

    def test_mismatching_node_exits_listing_whole_cohort(self):
        nodes = [
            self._descriptor("node-1", "a.example"),
            self._descriptor("node-2", "b.example"),
        ]
        responses = [self._block_resp(self.HASH), self._block_resp(self.OTHER_HASH)]
        with mock.patch.object(genesis.requests, "post", side_effect=responses):
            with self.assertRaises(SystemExit) as ctx:
                genesis._assert_cohort_genesis_hash(nodes, self.HASH)
        # Full-cohort listing: the matching node too, so one bad node is
        # distinguishable from a manifest that matches nobody.
        msg = str(ctx.exception)
        self.assertIn(self.HASH, msg)
        self.assertIn(f"✓ {nodes[0]}", msg)
        self.assertIn(f"✗ {nodes[1]}", msg)
        self.assertIn(self.OTHER_HASH, msg)

    def test_unreachable_node_reported_without_hiding_others(self):
        # First node down past the deadline; second still queried and reported.
        nodes = [
            self._descriptor("node-1", "a.example"),
            self._descriptor("node-2", "b.example"),
        ]
        responses = [OSError("boom"), self._block_resp(self.HASH)]
        with (
            mock.patch.object(genesis.requests, "post", side_effect=responses),
            mock.patch.object(
                genesis,
                "fetch_status",
                side_effect=genesis.requests.ConnectionError("not reachable"),
            ),
            self.assertRaises(SystemExit) as ctx,
        ):
            genesis._assert_cohort_genesis_hash(nodes, self.HASH, timeout=0)
        msg = str(ctx.exception)
        self.assertIn("https://a.example/rpc", msg)
        self.assertIn(f"✓ {nodes[1]}", msg)

    def test_rpc_error_response_exits(self):
        nodes = [self._descriptor("node-1", "a.example")]
        resp = self._resp({"jsonrpc": "2.0", "id": 1, "error": {"message": "boom"}})
        with (
            mock.patch.object(genesis.requests, "post", return_value=resp),
            mock.patch.object(
                genesis,
                "fetch_status",
                side_effect=genesis.requests.ConnectionError("not reachable"),
            ),
            self.assertRaises(SystemExit) as ctx,
        ):
            genesis._assert_cohort_genesis_hash(nodes, self.HASH, timeout=0)
        self.assertIn("boom", str(ctx.exception))

    def test_unreachable_node_polled_until_it_answers(self):
        # The ceremony is the cohort barrier: reth comes up only after the
        # root_key → LUKS boot tail, so a node that doesn't answer yet is
        # retried rather than failing the ceremony.
        nodes = [self._descriptor("node-1", "a.example")]
        responses = [OSError("still booting"), self._block_resp(self.HASH)]
        no_luks_status = mock.patch.object(
            genesis,
            "fetch_status",
            side_effect=genesis.requests.ConnectionError("not reachable"),
        )
        with mock.patch.object(genesis.requests, "post", side_effect=responses) as post:
            with no_luks_status:
                genesis._assert_cohort_genesis_hash(
                    nodes, self.HASH, timeout=30, interval=0
                )
        self.assertEqual(post.call_count, 2)

    def test_luks_progress_pauses_readiness_timeout(self):
        nodes = [self._descriptor("node-1", "a.example")]
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
            mock.patch.object(genesis.requests, "post", side_effect=responses) as post,
            mock.patch.object(genesis, "fetch_status", side_effect=statuses),
            mock.patch.object(genesis.time, "monotonic", side_effect=lambda: clock[0]),
            mock.patch.object(genesis.time, "sleep", side_effect=sleep),
            mock.patch.object(genesis, "CohortDashboard") as dashboard_cls,
        ):
            dashboard_cls.return_value.render.side_effect = (
                lambda states: rendered.extend(states.values())
            )
            genesis._assert_cohort_genesis_hash(
                nodes, self.HASH, timeout=10, interval=0
            )

        self.assertEqual(post.call_count, 3)
        self.assertTrue(any("encrypting disk" in state for state in rendered))
        self.assertTrue(any("readiness timeout paused" in state for state in rendered))

    def test_mismatch_fails_fast_without_waiting_for_stragglers(self):
        # A wrong answer can't heal by waiting — fail immediately even while
        # another node is still unreachable, instead of burning the timeout.
        nodes = [
            self._descriptor("node-1", "a.example"),
            self._descriptor("node-2", "b.example"),
        ]
        responses = [self._block_resp(self.OTHER_HASH), OSError("still booting")]
        no_sleep = mock.patch.object(
            genesis.time, "sleep", side_effect=AssertionError("must not wait")
        )
        with mock.patch.object(genesis.requests, "post", side_effect=responses):
            with no_sleep, self.assertRaises(SystemExit) as ctx:
                genesis._assert_cohort_genesis_hash(nodes, self.HASH)
        msg = str(ctx.exception)
        self.assertIn(self.OTHER_HASH, msg)
        self.assertIn("still booting", msg)


class GetPubkeysTests(unittest.TestCase):
    """The pubkey gather is the other half of the cohort barrier: summit
    answers getPublicKeys only after root_key → LUKS → keygen, so unreadable
    nodes are polled until ready (bounded), not failed on the first read."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _descriptor(self, name: str, fqdn: str, ip: str = "203.0.113.1") -> Path:
        path = Path(self._tmp.name) / f"{name}.json"
        path.write_text(json.dumps({"public_ip": ip, "fqdn": fqdn}))
        return path

    def test_waits_until_pubkeys_readable(self):
        node = self._descriptor("node-1", "a.example")
        client = mock.Mock()
        client.get_public_keys.side_effect = [
            OSError("502 Bad Gateway"),
            PublicKeys(node="0xnode", consensus="0xbls"),
        ]
        with mock.patch.object(genesis, "SummitClient", return_value=client):
            validators, clients = genesis._get_pubkeys([node], timeout=30, interval=0)
        self.assertEqual(client.get_public_keys.call_count, 2)
        self.assertEqual(
            validators,
            [
                {
                    "node_public_key": "0xnode",
                    "consensus_public_key": "0xbls",
                    "ip_address": f"203.0.113.1:{genesis.CONSENSUS_PORT}",
                    "withdrawal_credentials": genesis._ANVIL_ADDRESSES[0],
                }
            ],
        )
        self.assertEqual(clients, [(node, client)])

    def test_timeout_lists_only_the_stuck_nodes(self):
        ready = self._descriptor("node-1", "a.example")
        stuck = self._descriptor("node-2", "b.example")
        ready_client = mock.Mock()
        ready_client.get_public_keys.return_value = PublicKeys(
            node="0xnode", consensus="0xbls"
        )
        stuck_client = mock.Mock()
        stuck_client.get_public_keys.side_effect = OSError("boom")
        with mock.patch.object(
            genesis, "SummitClient", side_effect=[ready_client, stuck_client]
        ):
            with self.assertRaises(SystemExit) as ctx:
                genesis._get_pubkeys([ready, stuck], timeout=0)
        msg = str(ctx.exception)
        self.assertIn(str(stuck), msg)
        self.assertIn("boom", msg)
        self.assertNotIn(str(ready), msg)


if __name__ == "__main__":
    unittest.main()
