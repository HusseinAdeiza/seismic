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
    ENCLAVE_PEER_PORT,
    build_config,
    resolve_peer,
    resolve_reth_genesis,
)

FQDN = "node1.example.com"
EMAIL = "ops@example.com"


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

    def _build(self, *, genesis_node: bool, peers: list[str]) -> dict:
        out = build_config(
            self.manifest,
            FQDN,
            EMAIL,
            genesis_node=genesis_node,
            peers=peers,
            reth_genesis_path=self.reth_genesis,
        )
        self._tmp.append(out)
        return tomllib.loads(out.read_text())

    def test_genesis_mode(self):
        # genesis: mints root_key locally, so genesis_node=true and no peers.
        merged = self._build(genesis_node=True, peers=[])
        self.assertTrue(merged["root_key"]["genesis_node"])
        self.assertEqual(merged["root_key"]["peers"], [])
        # [domain] (fqdn + email) and [network] are injected in both modes.
        self.assertEqual(merged["domain"]["name"], FQDN)
        self.assertEqual(merged["domain"]["email"], EMAIL)
        self.assertTrue(merged["network"]["manifest_base64"])
        self.assertTrue(merged["network"]["reth_genesis_base64"])

    def test_join_mode(self):
        # join: genesis_node=false and the resolved peer URL(s) survive verbatim.
        peers = ["http://10.0.0.1:7878", "http://10.0.0.2:7878"]
        merged = self._build(genesis_node=False, peers=peers)
        self.assertFalse(merged["root_key"]["genesis_node"])
        self.assertEqual(merged["root_key"]["peers"], peers)
        self.assertEqual(merged["domain"]["name"], FQDN)
        self.assertTrue(merged["network"]["manifest_base64"])
        self.assertTrue(merged["network"]["reth_genesis_base64"])

    def test_rejects_invalid_manifest(self):
        bad = _write(".json", "{not json")
        self._tmp.append(bad)
        with self.assertRaises(SystemExit):
            build_config(
                bad,
                FQDN,
                EMAIL,
                genesis_node=True,
                peers=[],
                reth_genesis_path=self.reth_genesis,
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
                peers=[],
                reth_genesis_path=wrong,
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


class ResolvePeerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = []

    def tearDown(self):
        for p in self._tmp:
            p.unlink(missing_ok=True)

    def _descriptor(self, data: dict) -> Path:
        p = _write(".json", json.dumps(data))
        self._tmp.append(p)
        return p

    def test_url_passthrough(self):
        # A raw URL (what a late joiner uses) is used verbatim.
        for url in ("http://host:7878", "https://node.example.com:7878"):
            self.assertEqual(resolve_peer(url), url)

    def test_descriptor_derives_enclave_url(self):
        # A descriptor path → http://<public_ip>:ENCLAVE_PEER_PORT.
        path = self._descriptor({"public_ip": "1.2.3.4", "fqdn": FQDN})
        self.assertEqual(resolve_peer(str(path)), f"http://1.2.3.4:{ENCLAVE_PEER_PORT}")

    def test_missing_file_errors(self):
        with self.assertRaises(SystemExit):
            resolve_peer("/no/such/descriptor.json")

    def test_descriptor_without_public_ip_errors(self):
        path = self._descriptor({"fqdn": FQDN})  # no public_ip
        with self.assertRaises(ValueError):
            resolve_peer(str(path))


if __name__ == "__main__":
    unittest.main()
