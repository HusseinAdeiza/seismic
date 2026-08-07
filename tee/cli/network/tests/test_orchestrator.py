"""Tests for tee.orchestrator (stdlib unittest; no test deps).

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import json
import tempfile
import unittest
from pathlib import Path

from tee.cli.common import manifest as manifest_mod
from tee.cli.network.orchestrator import (
    DEFAULT_OUT_DIR,
    _check_vhd_matches_network,
    _cohort_size,
    _resolve_out_dir,
)

VHD = "seismic-dev_2026-07-02.5c3b5e.vhd"


class VhdNetworkCheckTests(unittest.TestCase):
    """`up --network` refuses a VHD pin the measurements input doesn't cover.

    The check reads the authored inputs/measurements.json, not the
    assembled artifact set: provisioning precedes assembly (the founding
    order is up → harvest → assemble), so at `up` time the inputs are all
    a network directory holds.
    """

    URL = f"https://acct.blob.core.windows.net/dev/{VHD}"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.net = Path(self._tmp.name)
        self.inputs = self.net / manifest_mod.INPUTS_DIRNAME
        self.inputs.mkdir()
        self._write_measurements(
            {"measurement_id": VHD, "measurements": {"4": {"expected": "ab" * 24}}}
        )

    def _write_measurements(self, obj) -> None:
        path = self.inputs / manifest_mod.MEASUREMENTS_FILENAME
        path.write_text(json.dumps(obj))

    def _template(self, url: str) -> dict:
        return {"config": {"seismic-tee-deploy:vhd_blob_url": url}}

    def test_matching_stamped_wrapper_passes(self):
        name = _check_vhd_matches_network(self._template(self.URL), self.net)
        self.assertEqual(name, VHD)

    def test_matching_promoted_policy_record_passes(self):
        # The measurements input may already be a promoted policy; each
        # record then names its own image.
        self._write_measurements(
            [
                {
                    "measurement_id": VHD,
                    "attestation_type": "azure-tdx",
                    "measurements": {"4": {"expected": "ab" * 24}},
                }
            ]
        )
        name = _check_vhd_matches_network(self._template(self.URL), self.net)
        self.assertEqual(name, VHD)

    def test_uncovered_pin_refused(self):
        bad = self.URL.replace("5c3b5e", "999999")
        with self.assertRaises(SystemExit) as ctx:
            _check_vhd_matches_network(self._template(bad), self.net)
        self.assertIn("refusing to provision", str(ctx.exception))

    def test_missing_measurements_input_refused(self):
        (self.inputs / manifest_mod.MEASUREMENTS_FILENAME).unlink()
        with self.assertRaises(SystemExit) as ctx:
            _check_vhd_matches_network(self._template(self.URL), self.net)
        self.assertIn("manifest init", str(ctx.exception))

    def test_unstamped_wrapper_refused(self):
        # A wrapper without a stamped measurement_id leaves nothing to
        # compare the pin against — refused, not silently skipped.
        self._write_measurements({"measurements": {"4": {"expected": "ab" * 24}}})
        with self.assertRaises(SystemExit) as ctx:
            _check_vhd_matches_network(self._template(self.URL), self.net)
        self.assertIn("measurement_id", str(ctx.exception))

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


class CohortSizeTests(unittest.TestCase):
    """`up --count` is optional with --network: the authored withdrawal
    credentials are the founding set, so they size the cohort."""

    ADDRESS = "0x" + "c0" * 20

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.net = Path(self._tmp.name)
        self.inputs = self.net / manifest_mod.INPUTS_DIRNAME
        self.inputs.mkdir()
        self._write_credentials([self.ADDRESS] * 3)

    def _write_credentials(self, addresses) -> None:
        (self.inputs / manifest_mod.FOUNDERS_FILENAME).write_text(json.dumps(addresses))

    def test_count_derived_from_credentials(self):
        self.assertEqual(_cohort_size(None, self.net), 3)

    def test_matching_count_accepted(self):
        self.assertEqual(_cohort_size(3, self.net), 3)

    def test_contradicting_count_refused(self):
        with self.assertRaises(SystemExit) as ctx:
            _cohort_size(4, self.net)
        self.assertIn("contradicts", str(ctx.exception))

    def test_empty_credentials_refused(self):
        self._write_credentials([])
        with self.assertRaises(SystemExit) as ctx:
            _cohort_size(None, self.net)
        self.assertIn("--founders", str(ctx.exception))

    def test_missing_credentials_refused(self):
        (self.inputs / manifest_mod.FOUNDERS_FILENAME).unlink()
        with self.assertRaises(SystemExit) as ctx:
            _cohort_size(None, self.net)
        self.assertIn(manifest_mod.FOUNDERS_FILENAME, str(ctx.exception))

    def test_count_required_without_network(self):
        self.assertEqual(_cohort_size(2, None), 2)
        with self.assertRaises(SystemExit) as ctx:
            _cohort_size(None, None)
        self.assertIn("--count is required", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
