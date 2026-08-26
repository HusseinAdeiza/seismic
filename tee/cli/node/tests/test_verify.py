"""Tests for tee.cli.node.verify (stdlib unittest; no test deps in this repo).

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import argparse
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tee.cli.common.manifest import (
    MANIFEST_FILENAME,
    POLICY_FILENAME,
    GateError,
    render_manifest,
)

# Reuse the canonical valid manifest from the manifest tests rather than
# duplicate the schema here; the policy check parses it before use.
from tee.cli.common.tests.test_manifest import FIXTURE_MANIFEST
from tee.cli.node import verify
from tee.cli.node.verify import (
    prepare_policy,
    resolve_policy,
    verify_deployment,
)

FQDN = "node1.example.com"
PUBLIC_IP = "203.0.113.7"

# Stands in for a promoted policy document: only its bytes matter here, since
# the manifest commits to it by hash and the verifier is the one that parses it.
POLICY_BYTES = b'[{"measurement_id": "seismic-node.vhd"}]\n'


def _write(suffix: str, data) -> Path:
    payload = data if isinstance(data, bytes) else data.encode()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(payload)
        return Path(f.name)


def _manifest_pinning(policy_bytes: bytes) -> bytes:
    """Render a valid manifest whose bootstrap_policy_hash commits to
    `policy_bytes` — an artifact set as `assemble` writes it."""
    manifest = json.loads(json.dumps(FIXTURE_MANIFEST))
    manifest["measurements"]["bootstrap_policy_hash"] = (
        "0x" + hashlib.sha256(policy_bytes).hexdigest()
    )
    return render_manifest(manifest)


def _args(**overrides) -> argparse.Namespace:
    defaults = {
        "policy": None,
        "measurements": None,
        "verify_quote_bin": "verify-quote",
        "admission_bin": "seismic-measurement-admission",
        "attestation_type": "azure-tdx",
        "pccs_url": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class ResolvePolicyTests(unittest.TestCase):
    """Which policy a node is appraised against. The default is the network's
    own artifact, and it only counts if the manifest commits to it."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.network = Path(tmp.name)
        self.manifest = self.network / MANIFEST_FILENAME
        self.manifest.write_bytes(_manifest_pinning(POLICY_BYTES))
        self.policy = self.network / POLICY_FILENAME
        self.policy.write_bytes(POLICY_BYTES)

    def _resolve(self, **overrides) -> bytes:
        return resolve_policy(_args(manifest=self.manifest, **overrides))

    def test_defaults_to_the_policy_beside_the_manifest(self):
        self.assertEqual(self._resolve(), POLICY_BYTES)

    def test_policy_the_manifest_does_not_pin_is_rejected(self):
        self.policy.write_bytes(b'[{"measurement_id": "some-other-image.vhd"}]\n')
        with self.assertRaises(SystemExit) as ctx:
            self._resolve()
        message = str(ctx.exception)
        self.assertIn("bootstrap_policy_hash mismatch", message)
        self.assertIn(POLICY_FILENAME, message)

    def test_explicit_policy_elsewhere_is_pinned_just_the_same(self):
        elsewhere = _write(".json", POLICY_BYTES)
        self.addCleanup(elsewhere.unlink)
        self.policy.unlink()
        self.assertEqual(self._resolve(policy=elsewhere), POLICY_BYTES)

        elsewhere.write_bytes(b"[]\n")
        with self.assertRaisesRegex(SystemExit, "bootstrap_policy_hash mismatch"):
            self._resolve(policy=elsewhere)

    def test_missing_explicit_policy_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "--policy file not found"):
            self._resolve(policy=self.network / "absent.json")

    def test_missing_default_policy_names_the_alternatives(self):
        self.policy.unlink()
        with self.assertRaises(SystemExit) as ctx:
            self._resolve()
        message = str(ctx.exception)
        self.assertIn(POLICY_FILENAME, message)
        self.assertIn("--policy", message)
        self.assertIn("--measurements", message)
        # `verify` has nothing to skip: the appraisal is the whole command.
        self.assertNotIn("--no-verify", message)

    def test_configures_opt_out_is_offered_when_the_caller_has_one(self):
        self.policy.unlink()
        with self.assertRaises(SystemExit) as ctx:
            resolve_policy(_args(manifest=self.manifest), offer_no_verify=True)
        self.assertIn("--no-verify", str(ctx.exception))

    def test_measurements_promotes_instead_of_reading_the_artifact(self):
        measurements = _write(".json", b'[{"measurement_id": "my-build.vhd"}]')
        self.addCleanup(measurements.unlink)
        # An operator's own measurements need not promote to the founder's
        # policy — that is the point of the override — so nothing is
        # hash-checked against the manifest here.
        self.policy.write_bytes(b"not the manifest's policy\n")
        with mock.patch.object(
            verify.shell_outs, "promote_measurements", return_value=b"promoted"
        ) as promote:
            self.assertEqual(self._resolve(measurements=measurements), b"promoted")
        promote.assert_called_once_with(
            b'[{"measurement_id": "my-build.vhd"}]',
            "azure-tdx",
            admission_bin="seismic-measurement-admission",
        )

    def test_rejected_measurements_fail_fast(self):
        measurements = _write(".json", b"{}")
        self.addCleanup(measurements.unlink)
        with mock.patch.object(
            verify.shell_outs,
            "promote_measurements",
            side_effect=GateError("no measurement_id"),
        ):
            with self.assertRaises(SystemExit) as ctx:
                self._resolve(measurements=measurements)
        self.assertIn("no measurement_id", str(ctx.exception))

    def test_unparseable_manifest_is_rejected(self):
        self.manifest.write_bytes(b"{}")
        with self.assertRaisesRegex(SystemExit, "invalid manifest"):
            self._resolve()


class PreparePolicyTests(unittest.TestCase):
    """The tooling is resolved before any node is challenged, so a fixable
    local problem never surfaces mid-flight."""

    def test_missing_verifier_fails_fast(self):
        args = _args(
            manifest=Path("/nets/devnet/network-manifest.json"),
            verify_quote_bin="no-such-verify-quote",
        )
        with self.assertRaises(SystemExit) as ctx:
            prepare_policy(args)
        self.assertIn("PATH", str(ctx.exception))

    def test_verifier_without_the_deploy_subcommand_fails_fast(self):
        args = _args(manifest=Path("/nets/devnet/network-manifest.json"))
        with (
            mock.patch.object(verify.shutil, "which", return_value="/bin/vq"),
            mock.patch.object(
                verify.subprocess, "run", return_value=mock.Mock(returncode=2)
            ) as probe,
        ):
            with self.assertRaises(SystemExit) as ctx:
                prepare_policy(args)
        self.assertIn("no `deploy` subcommand", str(ctx.exception))
        self.assertEqual(probe.call_args.args[0], ["verify-quote", "deploy", "--help"])

    def test_resolves_the_policy_once_the_tooling_is_good(self):
        args = _args(manifest=Path("/nets/devnet/network-manifest.json"))
        with (
            mock.patch.object(verify.shutil, "which", return_value="/bin/vq"),
            mock.patch.object(
                verify.subprocess, "run", return_value=mock.Mock(returncode=0)
            ),
            mock.patch.object(
                verify, "resolve_policy", return_value=POLICY_BYTES
            ) as resolved,
        ):
            self.assertEqual(prepare_policy(args, offer_no_verify=True), POLICY_BYTES)
        resolved.assert_called_once_with(args, offer_no_verify=True)


class VerifyDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.args = _args(
            manifest=Path("/nets/devnet/network-manifest.json"),
            pccs_url="https://pccs.example",
        )

    def _verify(self, policy_bytes: bytes) -> None:
        verify_deployment(self.args, policy_bytes, fqdn=FQDN, public_ip=PUBLIC_IP)

    def test_challenges_the_node_with_the_manifest_and_policy(self):
        with mock.patch.object(
            verify.shell_outs,
            "verify_node_deployment",
            return_value={"verified": True},
        ) as verified:
            self._verify(b"policy bytes")
        verified.assert_called_once_with(
            f"http://{PUBLIC_IP}:7878",
            manifest_path=Path("/nets/devnet/network-manifest.json"),
            policy_bytes=b"policy bytes",
            verify_quote_bin="verify-quote",
            pccs_url="https://pccs.example",
        )

    def test_failure_is_a_nonzero_exit_naming_the_node(self):
        with mock.patch.object(
            verify.shell_outs,
            "verify_node_deployment",
            side_effect=GateError("measurement mismatch"),
        ):
            with self.assertRaises(SystemExit) as ctx:
                self._verify(b"policy")
        message = str(ctx.exception)
        self.assertIn(FQDN, message)
        self.assertIn("measurement mismatch", message)
        self.assertIn("Do not rely", message)


class MainTests(unittest.TestCase):
    """The standalone command: appraisal only — it never touches tdx-init."""

    def setUp(self):
        self.descriptor = _write(
            ".json", json.dumps({"public_ip": PUBLIC_IP, "fqdn": FQDN})
        )
        self.addCleanup(self.descriptor.unlink)
        self.measurements = _write(".json", b'[{"measurement_id": "img.vhd"}]')
        self.addCleanup(self.measurements.unlink)
        self.manifest = _write(".json", _manifest_pinning(POLICY_BYTES))
        self.addCleanup(self.manifest.unlink)
        self.argv = [
            "seismic-tee-node verify",
            "--node",
            str(self.descriptor),
            "--manifest",
            str(self.manifest),
        ]

    def test_challenges_the_descriptor_node(self):
        with (
            mock.patch("sys.argv", self.argv),
            mock.patch.object(verify, "prepare_policy", return_value=b"policy"),
            mock.patch.object(verify, "verify_deployment") as verified,
        ):
            verify.main()
        verified.assert_called_once_with(
            mock.ANY, b"policy", fqdn=FQDN, public_ip=PUBLIC_IP
        )

    def test_missing_measurements_file_is_rejected(self):
        argv = self.argv + [
            "--measurements",
            str(self.descriptor.parent / "absent.json"),
        ]
        with mock.patch("sys.argv", argv):
            with self.assertRaises(SystemExit):
                verify.main()

    def test_two_policy_sources_are_rejected(self):
        argv = self.argv + [
            "--policy",
            str(self.manifest),
            "--measurements",
            str(self.measurements),
        ]
        with mock.patch("sys.argv", argv), mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                verify.main()
