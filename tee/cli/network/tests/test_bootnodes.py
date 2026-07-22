"""Tests for tee.cli.network.bootnodes (stdlib unittest; no test deps).

Covers the pure/offline logic: bootnodes.json round-trip, enode host parsing
and the public_ip sanity warning, and collect_enodes' poll-until-ready +
timeout behavior (fetch mocked — no live network calls).

Run with:
    uv run python -m unittest discover -b
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tee.cli.network import bootnodes

ENODE_1 = "enode://" + "ab" * 64 + "@203.0.113.7:30303"
ENODE_2 = "enode://" + "cd" * 64 + "@203.0.113.8:30303"


class BootnodesRoundTripTests(unittest.TestCase):
    def test_save_then_load_round_trips(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "nodes" / bootnodes.BOOTNODES_FILENAME
            records = [
                bootnodes.Bootnode(name="node-1", enode=ENODE_1),
                bootnodes.Bootnode(name="node-2", enode=ENODE_2),
            ]
            # save creates the parent dir (mirrors the descriptor writer).
            bootnodes.save_bootnodes(path, records)
            self.assertEqual(bootnodes.load_bootnodes(path), records)

    def test_load_empty_when_no_records(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / bootnodes.BOOTNODES_FILENAME
            path.write_text("{}")
            self.assertEqual(bootnodes.load_bootnodes(path), [])


class EnodeHostTests(unittest.TestCase):
    def test_parses_host(self):
        self.assertEqual(bootnodes.enode_host(ENODE_1), "203.0.113.7")

    def test_unparseable_is_none(self):
        self.assertIsNone(bootnodes.enode_host("not-an-enode"))

    def test_warn_on_match_is_silent(self):
        with self.assertNoLogs(bootnodes.logger, level="WARNING"):
            bootnodes.warn_on_ip_mismatch(ENODE_1, "203.0.113.7", "node-1")

    def test_warn_on_mismatch_logs(self):
        with self.assertLogs(bootnodes.logger, level="WARNING") as cm:
            bootnodes.warn_on_ip_mismatch(ENODE_1, "10.0.0.9", "node-1")
        joined = "\n".join(cm.output)
        self.assertIn("203.0.113.7", joined)
        self.assertIn("10.0.0.9", joined)
        self.assertIn("extip", joined)


class NormalizeEnodeTests(unittest.TestCase):
    """tdx-init accepts only enode://<128 hex>@host:port; reth appends
    ?discport=<udp> when its devp2p TCP/UDP ports differ, which must be
    dropped before delivery."""

    def test_passthrough_when_already_canonical(self):
        self.assertEqual(bootnodes.normalize_enode(ENODE_1), ENODE_1)

    def test_strips_discport_query(self):
        got = bootnodes.normalize_enode(ENODE_1 + "?discport=0")
        self.assertEqual(got, ENODE_1)

    def test_preserves_bracketed_ipv6(self):
        v6 = "enode://" + "ab" * 64 + "@[2001:db8::1]:30303"
        self.assertEqual(bootnodes.normalize_enode(v6 + "?discport=30304"), v6)

    def test_rejects_short_node_id(self):
        with self.assertRaises(ValueError):
            bootnodes.normalize_enode("enode://abcd@1.2.3.4:30303")

    def test_rejects_non_enode_scheme(self):
        with self.assertRaises(ValueError):
            bootnodes.normalize_enode("http://1.2.3.4:30303")

    def test_rejects_missing_port(self):
        with self.assertRaises(ValueError):
            bootnodes.normalize_enode("enode://" + "ab" * 64 + "@1.2.3.4")


class CollectEnodesTests(unittest.TestCase):
    def test_returns_enodes_keyed_by_label(self):
        with mock.patch.object(
            bootnodes, "fetch_enode", side_effect=[ENODE_1, ENODE_2]
        ):
            got = bootnodes.collect_enodes(
                [("node-1", "a.example"), ("node-2", "b.example")]
            )
        self.assertEqual(got, {"node-1": ENODE_1, "node-2": ENODE_2})

    def test_normalizes_discport_from_live_node(self):
        # A node whose reth reports ?discport= must still yield a deliverable
        # (canonical) enode.
        with mock.patch.object(
            bootnodes, "fetch_enode", return_value=ENODE_1 + "?discport=0"
        ):
            got = bootnodes.collect_enodes([("node-1", "a.example")])
        self.assertEqual(got, {"node-1": ENODE_1})

    def test_malformed_enode_fails_fast(self):
        # Fetched but unparseable → hard error (retrying can't fix it), not a
        # 15-minute poll to timeout.
        with mock.patch.object(
            bootnodes, "fetch_enode", return_value="enode://tooshort@1.2.3.4:30303"
        ):
            with self.assertRaises(SystemExit):
                bootnodes.collect_enodes([("node-1", "a.example")], timeout=999)

    def test_retries_a_still_booting_node(self):
        # reth serves seismic_nodeInfo only once up; an early miss is retried.
        with mock.patch.object(
            bootnodes,
            "fetch_enode",
            side_effect=[RuntimeError("502 Bad Gateway"), ENODE_1],
        ) as fetch:
            got = bootnodes.collect_enodes(
                [("node-1", "a.example")], timeout=30, interval=0
            )
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(got, {"node-1": ENODE_1})

    def test_timeout_lists_pending_nodes(self):
        with mock.patch.object(
            bootnodes, "fetch_enode", side_effect=RuntimeError("boom")
        ):
            with self.assertRaises(SystemExit) as ctx:
                bootnodes.collect_enodes([("node-1", "a.example")], timeout=0)
        msg = str(ctx.exception)
        self.assertIn("node-1", msg)
        self.assertIn("boom", msg)


if __name__ == "__main__":
    unittest.main()
