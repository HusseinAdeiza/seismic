"""Tests for tee.cohort_configure role/peer assignment (stdlib unittest).

Covers only the pure logic worth pinning — how the cohort is assembled from
descriptors (exactly one genesis, joiners pointed at genesis:7878). The
parallel driver + dashboard are verified by hand against live nodes.

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import json
import tempfile
import unittest
from pathlib import Path

from tee.cli.network.cohort_configure import build_cohort
from tee.cli.node.configure import ENCLAVE_PEER_PORT


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

        # Genesis first, exactly one, no peers (it mints root_key).
        self.assertEqual(len(nodes), 3)
        self.assertTrue(nodes[0].genesis)
        self.assertEqual(nodes[0].name, "node-1")
        self.assertEqual(nodes[0].peers, [])
        self.assertEqual(sum(n.genesis for n in nodes), 1)

        # Every joiner points only at the genesis node's enclave endpoint.
        genesis_peer = f"http://1.1.1.1:{ENCLAVE_PEER_PORT}"
        for joiner in nodes[1:]:
            self.assertFalse(joiner.genesis)
            self.assertEqual(joiner.peers, [genesis_peer])

    def test_genesis_only(self):
        g = _descriptor("node-1", "1.1.1.1", "n1.example.com")
        nodes = build_cohort(g, [])
        self.assertEqual(len(nodes), 1)
        self.assertTrue(nodes[0].genesis)
        self.assertEqual(nodes[0].peers, [])

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


if __name__ == "__main__":
    unittest.main()
