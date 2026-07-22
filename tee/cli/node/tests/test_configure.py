"""Tests for tee.configure (stdlib unittest; no test deps in this repo).

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import json
import tempfile
import tomllib
import unittest
from pathlib import Path

from tee.cli.common.manifest import render_manifest

# Reuse the canonical valid manifest from the manifest tests rather than
# duplicate the schema here; build_config validates it before merging.
from tee.cli.common.tests.test_manifest import FIXTURE_MANIFEST
from tee.cli.node.configure import (
    build_config,
    resolve_reth_genesis,
)

FQDN = "node1.example.com"
EMAIL = "ops@example.com"
EXTERNAL_IP = "203.0.113.7"
BOOTNODE = "enode://" + "ab" * 64 + "@198.51.100.1:30303"


def _write(suffix: str, data) -> Path:
    payload = data if isinstance(data, bytes) else data.encode()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(payload)
        return Path(f.name)


class BuildConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = []
        self.manifest = _write(".json", render_manifest(FIXTURE_MANIFEST))
        self._tmp.append(self.manifest)
        # chainId matches FIXTURE_MANIFEST's eth.chain_id.
        self.reth_genesis = _write(
            ".json", json.dumps({"config": {"chainId": 5124}, "alloc": {}})
        )
        self._tmp.append(self.reth_genesis)

    def tearDown(self):
        for p in self._tmp:
            p.unlink(missing_ok=True)

    def _build(
        self,
        *,
        genesis_node: bool,
        bootnodes: list[str] | None = None,
    ) -> dict:
        out = build_config(
            self.manifest,
            FQDN,
            EMAIL,
            genesis_node=genesis_node,
            reth_genesis_path=self.reth_genesis,
            external_ip=EXTERNAL_IP,
            bootnodes=bootnodes or [],
        )
        self._tmp.append(out)
        return tomllib.loads(out.read_text())

    def test_genesis_mode(self):
        # genesis: mints root_key locally, so genesis_node=true and (in the
        # greenfield case) no bootnodes — the key is present and empty.
        merged = self._build(genesis_node=True)
        # tdx-init rejects unknown fields, so the shape is exactly
        # [node] + [network] — no legacy [root_key]/[domain] sections.
        self.assertEqual(set(merged), {"node", "network"})
        self.assertTrue(merged["node"]["genesis_node"])
        self.assertEqual(merged["node"]["external_ip"], EXTERNAL_IP)
        # [node.domain] (fqdn + email) and [network] are injected in both modes.
        self.assertEqual(merged["node"]["domain"]["name"], FQDN)
        self.assertEqual(merged["node"]["domain"]["email"], EMAIL)
        self.assertTrue(merged["network"]["manifest_base64"])
        self.assertTrue(merged["network"]["reth_genesis_base64"])
        self.assertEqual(merged["network"]["bootnodes"], [])

    def test_join_mode(self):
        # join: genesis_node=false and the bootnode set (root_key fetch peers
        # are derived from it by tdx-init) survives verbatim.
        merged = self._build(genesis_node=False, bootnodes=[BOOTNODE])
        self.assertFalse(merged["node"]["genesis_node"])
        self.assertEqual(merged["node"]["external_ip"], EXTERNAL_IP)
        self.assertEqual(merged["node"]["domain"]["name"], FQDN)
        self.assertTrue(merged["network"]["manifest_base64"])
        self.assertTrue(merged["network"]["reth_genesis_base64"])
        self.assertEqual(merged["network"]["bootnodes"], [BOOTNODE])

    def test_bootnodes_populated(self):
        # A re-configure carries the whole founding set into
        # [network].bootnodes verbatim (a node's own enode included — tdx-init
        # drops it when deriving root_key peers).
        bootnodes = [BOOTNODE, "enode://" + "cd" * 64 + "@203.0.113.7:30303"]
        merged = self._build(genesis_node=False, bootnodes=bootnodes)
        self.assertEqual(merged["network"]["bootnodes"], bootnodes)

    def test_empty_external_ip_rejected(self):
        # tdx-init requires [node].external_ip and parses it as an IpAddr, so
        # an empty value is a far-end 400 — build_config fails fast client-side
        # instead of emitting external_ip = "".
        with self.assertRaises(SystemExit):
            build_config(
                self.manifest,
                FQDN,
                EMAIL,
                genesis_node=True,
                reth_genesis_path=self.reth_genesis,
                external_ip="",
                bootnodes=[],
            )

    def test_joiner_without_bootnodes_rejected(self):
        # tdx-init derives a joiner's root_key fetch peers from the bootnodes,
        # so an empty set is a far-end 400 — build_config fails fast instead.
        with self.assertRaises(SystemExit):
            self._build(genesis_node=False, bootnodes=[])

    def test_rejects_invalid_manifest(self):
        bad = _write(".json", "{not json")
        self._tmp.append(bad)
        with self.assertRaises(SystemExit):
            build_config(
                bad,
                FQDN,
                EMAIL,
                genesis_node=True,
                reth_genesis_path=self.reth_genesis,
                external_ip=EXTERNAL_IP,
                bootnodes=[],
            )

    def test_rejects_chain_id_mismatch(self):
        # A genesis file other than the one the manifest was assembled from
        # must fail the POST build, not boot a forked node.
        wrong = _write(".json", json.dumps({"config": {"chainId": 9999}}))
        self._tmp.append(wrong)
        with self.assertRaises(SystemExit):
            build_config(
                self.manifest,
                FQDN,
                EMAIL,
                genesis_node=True,
                reth_genesis_path=wrong,
                external_ip=EXTERNAL_IP,
                bootnodes=[],
            )


class ResolveRethGenesisTests(unittest.TestCase):
    def test_explicit_path(self):
        with tempfile.TemporaryDirectory() as d:
            genesis = Path(d) / "custom.json"
            genesis.write_text("{}")
            manifest = Path(d) / "network-manifest.json"
            self.assertEqual(resolve_reth_genesis(genesis, manifest), genesis)

    def test_defaults_to_manifest_sibling(self):
        # The artifact-set layout `manifest assemble --out` writes.
        with tempfile.TemporaryDirectory() as d:
            manifest = Path(d) / "network-manifest.json"
            sibling = Path(d) / "reth-genesis.json"
            sibling.write_text("{}")
            self.assertEqual(resolve_reth_genesis(None, manifest), sibling)

    def test_missing_default_errors(self):
        with tempfile.TemporaryDirectory() as d:
            manifest = Path(d) / "network-manifest.json"
            with self.assertRaises(SystemExit):
                resolve_reth_genesis(None, manifest)


if __name__ == "__main__":
    unittest.main()
