"""Tests for tee.cohort_configure role/bootnode assignment (stdlib unittest).

Covers only the pure logic worth pinning — how the cohort is assembled from
descriptors (exactly one genesis) and how the two-stage greenfield flow
assigns bootnodes. The parallel driver + dashboard are verified by hand
against live nodes.

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tee.cli.network import cohort_configure
from tee.cli.network.cohort_configure import (
    build_cohort,
    load_founding_facts,
    splice_validator_ips,
)

# enode hosts chosen to match the descriptor public_ips below, so the
# public_ip sanity check stays quiet in these tests.
ENODE_N1 = "enode://" + "ab" * 64 + "@1.1.1.1:30303"
ENODE_N2 = "enode://" + "cd" * 64 + "@2.2.2.2:30303"


def _descriptor(name: str, public_ip: str, fqdn: str) -> Path:
    d = tempfile.mkdtemp()
    path = Path(d) / f"{name}.json"
    path.write_text(json.dumps({"public_ip": public_ip, "fqdn": fqdn}))
    return path


class BuildCohortTests(unittest.TestCase):
    def test_genesis_and_joiners(self):
        g = _descriptor("node-1", "1.1.1.1", "n1.example.com")
        j2 = _descriptor("node-2", "2.2.2.2", "n2.example.com")
        j3 = _descriptor("node-3", "3.3.3.3", "n3.example.com")

        nodes = build_cohort(g, [j2, j3])

        # Genesis first, exactly one (it mints root_key).
        self.assertEqual(len(nodes), 3)
        self.assertTrue(nodes[0].genesis)
        self.assertEqual(nodes[0].name, "node-1")
        self.assertEqual(sum(n.genesis for n in nodes), 1)

        # Bootnodes are assigned by the configure flow, not here.
        for node in nodes:
            self.assertEqual(node.bootnodes, [])
        for joiner in nodes[1:]:
            self.assertFalse(joiner.genesis)

    def test_genesis_only(self):
        g = _descriptor("node-1", "1.1.1.1", "n1.example.com")
        nodes = build_cohort(g, [])
        self.assertEqual(len(nodes), 1)
        self.assertTrue(nodes[0].genesis)

    def test_duplicate_descriptor_rejected(self):
        # Same descriptor as --genesis and --join would race conflicting POSTs
        # (genesis_node=true and =false) against one node.
        g = _descriptor("node-1", "1.1.1.1", "n1.example.com")
        with self.assertRaises(SystemExit):
            build_cohort(g, [g])

    def test_duplicate_ip_rejected(self):
        # Distinct descriptor files can still point at the same node.
        g = _descriptor("node-1", "1.1.1.1", "n1.example.com")
        j = _descriptor("node-2", "1.1.1.1", "n2.example.com")
        with self.assertRaises(SystemExit):
            build_cohort(g, [j])


class GreenfieldBootstrapTests(unittest.TestCase):
    """The two-stage greenfield flow (`_run_cohort` / enode fetch mocked — no
    live nodes): genesis alone first with empty bootnodes, then joiners
    carrying the genesis enode."""

    def _cohort(self):
        g = _descriptor("node-1", "1.1.1.1", "n1.example.com")
        j = _descriptor("node-2", "2.2.2.2", "n2.example.com")
        return build_cohort(g, [j])

    def test_two_stage_assigns_bootnodes(self):
        nodes = self._cohort()
        # Record each node's bootnodes at the moment its stage runs.
        stages: list[list[tuple[str, list[str]]]] = []

        def fake_run(subset, *a, **k):
            stages.append([(n.name, list(n.bootnodes)) for n in subset])
            return {n.name: True for n in subset}

        with (
            mock.patch.object(cohort_configure, "_run_cohort", side_effect=fake_run),
            mock.patch.object(
                cohort_configure.bootnodes_mod,
                "collect_enodes",
                return_value={"node-1": ENODE_N1},
            ),
        ):
            results = cohort_configure._bootstrap_greenfield(
                nodes, Path("m.json"), Path("g.json"), Path("s.toml"), "e@x"
            )

        self.assertEqual(results, {"node-1": True, "node-2": True})
        # Stage 1: genesis alone, no bootnodes yet.
        self.assertEqual(stages[0], [("node-1", [])])
        # Stage 2: joiner dials the genesis enode.
        self.assertEqual(stages[1], [("node-2", [ENODE_N1])])

    def test_genesis_failure_skips_joiners(self):
        nodes = self._cohort()

        def fake_run(subset, *a, **k):
            return {n.name: False for n in subset}  # genesis stage 1 fails

        with (
            mock.patch.object(cohort_configure, "_run_cohort", side_effect=fake_run),
            mock.patch.object(
                cohort_configure.bootnodes_mod, "collect_enodes"
            ) as collect,
        ):
            results = cohort_configure._bootstrap_greenfield(
                nodes, Path("m.json"), Path("g.json"), Path("s.toml"), "e@x"
            )

        collect.assert_not_called()  # never reached the enode fetch
        self.assertEqual(results, {"node-1": False})


class PersistFoundingBootnodesTests(unittest.TestCase):
    def _cohort(self):
        g = _descriptor("node-1", "1.1.1.1", "n1.example.com")
        j = _descriptor("node-2", "2.2.2.2", "n2.example.com")
        return build_cohort(g, [j])

    def test_writes_full_set_when_all_ready(self):
        nodes = self._cohort()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "nodes" / "bootnodes.json"
            with mock.patch.object(
                cohort_configure.bootnodes_mod,
                "collect_enodes",
                return_value={"node-1": ENODE_N1, "node-2": ENODE_N2},
            ):
                cohort_configure._persist_founding_bootnodes(
                    nodes, {"node-1": True, "node-2": True}, path
                )
            loaded = cohort_configure.bootnodes_mod.load_bootnodes(path)
            self.assertEqual([b.name for b in loaded], ["node-1", "node-2"])
            self.assertEqual([b.enode for b in loaded], [ENODE_N1, ENODE_N2])

    def test_skips_write_when_a_node_failed(self):
        nodes = self._cohort()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bootnodes.json"
            with mock.patch.object(
                cohort_configure.bootnodes_mod, "collect_enodes"
            ) as collect:
                cohort_configure._persist_founding_bootnodes(
                    nodes, {"node-1": True, "node-2": False}, path
                )
            collect.assert_not_called()
            self.assertFalse(path.exists())

    def test_collect_failure_degrades_to_warning(self):
        # Config delivery already succeeded; a node whose reth never advertises
        # an enode makes collect_enodes SystemExit. Persistence must degrade to
        # a warning (no write, no raise) so the caller's cohort report still
        # prints — the next configure run re-establishes the set.
        nodes = self._cohort()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "nodes" / "bootnodes.json"
            with (
                mock.patch.object(
                    cohort_configure.bootnodes_mod,
                    "collect_enodes",
                    side_effect=SystemExit("node(s) never returned an enode"),
                ),
                self.assertLogs(cohort_configure.logger, level="WARNING"),
            ):
                cohort_configure._persist_founding_bootnodes(
                    nodes, {"node-1": True, "node-2": True}, path
                )
            self.assertFalse(path.exists())


NODE_KEY_1 = "aa" * 32
NODE_KEY_2 = "bb" * 32
CONSENSUS_KEY_1 = "cc" * 48
CONSENSUS_KEY_2 = "dd" * 48

# The layout summit's emitter (`toml::to_string_pretty`) renders: scalar
# parameters first, then one [[validators]] block per entry with the fields
# in struct order.
GENESIS_TEXT = f"""\
eth_genesis_hash = "0x{"ab" * 32}"
leader_timeout_ms = 2000
namespace = "tmp-devnet-1"

[[validators]]
node_public_key = "{NODE_KEY_1}"
consensus_public_key = "{CONSENSUS_KEY_1}"
ip_address = "192.0.2.1:18551"
withdrawal_credentials = "0x{"00" * 19}01"

[[validators]]
node_public_key = "{NODE_KEY_2}"
consensus_public_key = "{CONSENSUS_KEY_2}"
ip_address = "192.0.2.2:18551"
withdrawal_credentials = "0x{"00" * 19}02"
"""


class SpliceValidatorIpsTests(unittest.TestCase):
    """The splice must rewrite the ip_address lines and not one byte more —
    the manifest's config digest pins every other field as the exact string
    summit emitted."""

    def test_replaces_only_the_ip_address_lines(self):
        spliced = splice_validator_ips(
            GENESIS_TEXT.encode(),
            {NODE_KEY_1: "198.51.100.7:18551", NODE_KEY_2: "192.0.2.2:18551"},
        )
        expected = GENESIS_TEXT.replace("192.0.2.1:18551", "198.51.100.7:18551")
        self.assertEqual(spliced.decode(), expected)

    def test_unchanged_ips_round_trip_byte_identical(self):
        spliced = splice_validator_ips(
            GENESIS_TEXT.encode(),
            {NODE_KEY_1: "192.0.2.1:18551", NODE_KEY_2: "192.0.2.2:18551"},
        )
        self.assertEqual(spliced, GENESIS_TEXT.encode())

    def test_ips_are_assigned_by_node_pubkey_not_position(self):
        spliced = splice_validator_ips(
            GENESIS_TEXT.encode(),
            {NODE_KEY_2: "198.51.100.2:18551", NODE_KEY_1: "198.51.100.1:18551"},
        ).decode()
        block_1, block_2 = spliced.split("[[validators]]")[1:]
        self.assertIn(NODE_KEY_1, block_1)
        self.assertIn("198.51.100.1:18551", block_1)
        self.assertIn(NODE_KEY_2, block_2)
        self.assertIn("198.51.100.2:18551", block_2)

    def test_pinned_set_and_founding_inputs_must_agree(self):
        # A pinned validator without a current IP (or vice versa) means the
        # cohort changed under the founding.
        with self.assertRaises(SystemExit) as ctx:
            splice_validator_ips(
                GENESIS_TEXT.encode(), {NODE_KEY_1: "198.51.100.7:18551"}
            )
        self.assertIn("re-found", str(ctx.exception))

    def test_empty_validator_set_rejected(self):
        text = 'namespace = "x"\nvalidators = []\n'
        with self.assertRaises(SystemExit) as ctx:
            splice_validator_ips(text.encode(), {})
        self.assertIn("no [[validators]]", str(ctx.exception))

    def test_layout_without_ip_address_lines_rejected(self):
        # An inline validators array parses to the same data but has no
        # ip_address *lines* to splice — refuse rather than deliver stale IPs.
        text = (
            'namespace = "x"\n'
            f'validators = [{{ node_public_key = "{NODE_KEY_1}", '
            'ip_address = "192.0.2.1:18551" }]\n'
        )
        with self.assertRaises(SystemExit) as ctx:
            splice_validator_ips(text.encode(), {NODE_KEY_1: "198.51.100.7:18551"})
        self.assertIn("refusing to splice", str(ctx.exception))


class LoadFoundingFactsTests(unittest.TestCase):
    """The splice map joins the harvest (pinned keys) with the live
    descriptors (current IPs); a harvested box whose descriptor is gone is a
    cohort change, not a defaultable value."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        (self.dir / "inputs" / "harvest").mkdir(parents=True)
        (self.dir / "nodes").mkdir()

    def _harvest_record(self, name: str, node_key: str, consensus_key: str) -> None:
        (self.dir / "inputs" / "harvest" / f"{name}.json").write_text(
            json.dumps(
                {
                    "harvest_nonce": "00" * 32,
                    "node_public_key": node_key,
                    "consensus_public_key": consensus_key,
                    "evidence": {},
                }
            )
        )

    def _node_descriptor(self, name: str, public_ip: str) -> None:
        (self.dir / "nodes" / f"{name}.json").write_text(
            json.dumps({"public_ip": public_ip, "fqdn": f"{name}.example"})
        )

    def test_joins_harvest_keys_with_descriptor_ips(self):
        self._harvest_record("node-1", NODE_KEY_1, CONSENSUS_KEY_1)
        self._harvest_record("node-2", NODE_KEY_2, CONSENSUS_KEY_2)
        self._node_descriptor("node-1", "198.51.100.1")
        self._node_descriptor("node-2", "198.51.100.2")

        ip_by_pubkey, records = load_founding_facts(self.dir)

        self.assertEqual(
            ip_by_pubkey,
            {NODE_KEY_1: "198.51.100.1:18551", NODE_KEY_2: "198.51.100.2:18551"},
        )
        self.assertEqual(sorted(records), ["node-1", "node-2"])

    def test_missing_descriptor_is_a_cohort_change(self):
        self._harvest_record("node-1", NODE_KEY_1, CONSENSUS_KEY_1)
        with self.assertRaises(SystemExit) as ctx:
            load_founding_facts(self.dir)
        self.assertIn("re-found", str(ctx.exception))

    def test_missing_harvest_names_the_prerequisite(self):
        with self.assertRaises(SystemExit) as ctx:
            load_founding_facts(self.dir)
        self.assertIn("harvest", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
