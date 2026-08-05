"""Tests for tee.orchestrator (stdlib unittest; no test deps).

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tee.cli.common.manifest import render_manifest
from tee.cli.network.orchestrator import (
    DEFAULT_OUT_DIR,
    _check_vhd_matches_network,
    _resolve_out_dir,
)

POLICY = json.dumps(
    [
        {
            "measurement_id": "seismic-dev_2026-07-02.5c3b5e.vhd",
            "attestation_type": "azure-tdx",
            "measurements": {"4": {"expected": "ab" * 24}},
        }
    ]
).encode()


def _manifest_bytes(policy: bytes) -> bytes:
    return render_manifest(
        {
            "manifest_version": 1,
            "name": "t",
            "eth": {"chain_id": 5124, "genesis_hash": "0x" + "12" * 32},
            "summit": {"genesis_config_digest": "0x" + "bb" * 32, "namespace": "t"},
            "measurements": {
                "bootstrap_policy_hash": "0x" + hashlib.sha256(policy).hexdigest(),
                "contracts": {
                    "registry": "0x" + "10" * 20,
                    "authority": "0x" + "11" * 20,
                },
            },
        }
    )


class VhdNetworkCheckTests(unittest.TestCase):
    """`up --network` refuses a VHD pin the measurement policy doesn't cover."""

    URL = "https://acct.blob.core.windows.net/dev/seismic-dev_2026-07-02.5c3b5e.vhd"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.net = Path(self._tmp.name)
        (self.net / "measurement-policy.json").write_bytes(POLICY)
        (self.net / "network-manifest.json").write_bytes(_manifest_bytes(POLICY))

    def _template(self, url: str) -> dict:
        return {"config": {"seismic-tee-deploy:vhd_blob_url": url}}

    def test_matching_pin_passes(self):
        name = _check_vhd_matches_network(self._template(self.URL), self.net)
        self.assertEqual(name, "seismic-dev_2026-07-02.5c3b5e.vhd")

    def test_uncovered_pin_refused(self):
        bad = self.URL.replace("5c3b5e", "999999")
        with self.assertRaises(SystemExit) as ctx:
            _check_vhd_matches_network(self._template(bad), self.net)
        self.assertIn("refusing to provision", str(ctx.exception))

    def test_tampered_policy_refused(self):
        # Policy bytes not hashing to the manifest's commitment must refuse
        # before the measurement_id comparison is even attempted.
        (self.net / "measurement-policy.json").write_bytes(POLICY + b"\n")
        with self.assertRaises(SystemExit) as ctx:
            _check_vhd_matches_network(self._template(self.URL), self.net)
        self.assertIn("bootstrap_policy_hash", str(ctx.exception))

    def test_missing_artifact_set_refused(self):
        (self.net / "network-manifest.json").unlink()
        with self.assertRaises(SystemExit) as ctx:
            _check_vhd_matches_network(self._template(self.URL), self.net)
        self.assertIn("manifest assemble", str(ctx.exception))

    def test_config_without_vhd_url_refused(self):
        with self.assertRaises(SystemExit):
            _check_vhd_matches_network({"config": {}}, self.net)


class ResolveOutDirTests(unittest.TestCase):
    """Descriptor destination: --out-dir > <network>/nodes/ > shared default."""

    def test_explicit_out_dir_wins(self):
        self.assertEqual(_resolve_out_dir("/tmp/x", Path("net")), Path("/tmp/x"))

    def test_network_puts_descriptors_under_nodes(self):
        self.assertEqual(_resolve_out_dir(None, Path("net")), Path("net/nodes"))

    def test_default_shared_dir(self):
        self.assertEqual(_resolve_out_dir(None, None), DEFAULT_OUT_DIR)


if __name__ == "__main__":
    unittest.main()
