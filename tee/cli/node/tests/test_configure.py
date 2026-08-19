"""Tests for tee.configure (stdlib unittest; no test deps in this repo).

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import json
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from tee.cli.common.manifest import render_manifest

# Reuse the canonical valid manifest from the manifest tests rather than
# duplicate the schema here; build_config validates it before merging.
from tee.cli.common.tests.test_manifest import FIXTURE_MANIFEST
from tee.cli.node import configure
from tee.cli.node.configure import (
    build_config,
    resolve_reth_genesis,
    resolve_summit_genesis,
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
        # namespace matches FIXTURE_MANIFEST's summit.namespace.
        self.summit_genesis = _write(
            ".toml", 'namespace = "seismic-devnet-3"\nvalidators = []\n'
        )
        self._tmp.append(self.summit_genesis)

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
            summit_genesis_path=self.summit_genesis,
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
        self.assertTrue(merged["network"]["summit_genesis_base64"])
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
        self.assertTrue(merged["network"]["summit_genesis_base64"])
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
                summit_genesis_path=self.summit_genesis,
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
                summit_genesis_path=self.summit_genesis,
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
                summit_genesis_path=self.summit_genesis,
                external_ip=EXTERNAL_IP,
                bootnodes=[],
            )

    def test_rejects_summit_namespace_mismatch(self):
        # A summit genesis other than the one the manifest was assembled from
        # must fail the POST build (tdx-init would 400 on it anyway).
        wrong = _write(".toml", 'namespace = "other-net"\n')
        self._tmp.append(wrong)
        with self.assertRaises(SystemExit):
            build_config(
                self.manifest,
                FQDN,
                EMAIL,
                genesis_node=True,
                reth_genesis_path=self.reth_genesis,
                summit_genesis_path=wrong,
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
        # The artifact-set layout `assemble` writes.
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


class MainVerificationFlowTests(unittest.TestCase):
    """The ordering around deliver_config for the inline verify step, which
    runs unless `--no-verify` says otherwise: tooling and policy failures come
    before the POST, the challenge only after a confirmed-ready node, and the
    success summary only after the challenge passes."""

    def setUp(self):
        self.descriptor = _write(
            ".json", json.dumps({"public_ip": "203.0.113.7", "fqdn": FQDN})
        )
        self.addCleanup(self.descriptor.unlink)
        self.manifest = _write(".json", render_manifest(FIXTURE_MANIFEST))
        self.addCleanup(self.manifest.unlink)
        self.argv = [
            "seismic-tee-node configure",
            "--node",
            str(self.descriptor),
            "--manifest",
            str(self.manifest),
            "--bootnode",
            BOOTNODE,
        ]

    def _run_main(self, *, ready: bool):
        with (
            mock.patch("sys.argv", self.argv),
            mock.patch.object(
                configure.verify_mod, "prepare_policy", return_value=b"p"
            ),
            mock.patch.object(configure, "resolve_reth_genesis"),
            mock.patch.object(configure, "resolve_summit_genesis"),
            mock.patch.object(
                configure, "deliver_config", return_value=ready
            ) as deliver,
            mock.patch.object(configure.verify_mod, "verify_deployment") as verify,
            mock.patch.object(configure, "_print_summary") as summary,
        ):
            configure.main()
        return deliver, verify, summary

    def test_missing_verifier_aborts_before_any_delivery(self):
        with (
            mock.patch("sys.argv", self.argv + ["--verify-quote-bin", "no-such"]),
            mock.patch.object(configure, "deliver_config") as deliver,
        ):
            with self.assertRaises(SystemExit):
                configure.main()
        deliver.assert_not_called()

    def test_no_verify_delivers_without_appraising(self):
        # Delivery alone: no tooling is resolved, no node is challenged, and
        # the delivery path prints its own summary.
        with (
            mock.patch("sys.argv", self.argv + ["--no-verify"]),
            mock.patch.object(configure, "resolve_reth_genesis"),
            mock.patch.object(configure, "resolve_summit_genesis"),
            mock.patch.object(
                configure, "deliver_config", return_value=True
            ) as deliver,
            mock.patch.object(configure.verify_mod, "prepare_policy") as prepare,
            mock.patch.object(configure.verify_mod, "verify_deployment") as verify,
            mock.patch.object(configure, "_print_summary") as summary,
        ):
            configure.main()
        prepare.assert_not_called()
        verify.assert_not_called()
        self.assertIs(deliver.call_args.kwargs["print_summary"], True)
        summary.assert_not_called()

    def test_missing_policy_artifact_aborts_before_any_delivery(self):
        # The manifest here has no measurement-policy-bootstrap.json sibling,
        # so the default policy source is absent — a verified run cannot
        # happen, and delivery must not proceed as if it could.
        with (
            mock.patch("sys.argv", self.argv),
            mock.patch.object(
                configure.verify_mod.shutil, "which", return_value="/bin/vq"
            ),
            mock.patch.object(
                configure.verify_mod.subprocess,
                "run",
                return_value=mock.Mock(returncode=0),
            ),
            mock.patch.object(configure, "deliver_config") as deliver,
        ):
            with self.assertRaises(SystemExit) as ctx:
                configure.main()
        self.assertIn("--no-verify", str(ctx.exception))
        deliver.assert_not_called()

    def test_no_verify_contradicts_a_policy_source(self):
        argv = self.argv + ["--no-verify", "--policy", str(self.manifest)]
        with mock.patch("sys.argv", argv):
            with self.assertRaises(SystemExit) as ctx:
                configure.main()
        self.assertIn("--no-verify", str(ctx.exception))

    def test_verifies_once_the_node_is_confirmed_ready(self):
        deliver, verify, summary = self._run_main(ready=True)
        deliver.assert_called_once()
        verify.assert_called_once()
        self.assertEqual(verify.call_args.args[1], b"p")
        # The delivery path stays quiet; main prints the banner once
        # verification passed.
        self.assertIs(deliver.call_args.kwargs["print_summary"], False)
        summary.assert_called_once_with(FQDN, "203.0.113.7")

    def test_failed_verification_prints_no_success_banner(self):
        """A failed check must not be preceded by NODE CONFIGURED + endpoints:
        the summary reads as go-ahead, and there isn't one."""
        with (
            mock.patch("sys.argv", self.argv),
            mock.patch.object(
                configure.verify_mod, "prepare_policy", return_value=b"p"
            ),
            mock.patch.object(configure, "resolve_reth_genesis"),
            mock.patch.object(configure, "resolve_summit_genesis"),
            mock.patch.object(configure, "deliver_config", return_value=True),
            mock.patch.object(
                configure.verify_mod,
                "verify_deployment",
                side_effect=SystemExit("FAILED"),
            ),
            mock.patch.object(configure, "_print_summary") as summary,
        ):
            with self.assertRaises(SystemExit):
                configure.main()
            summary.assert_not_called()

    def test_skipped_watch_skips_verification_and_exits_nonzero(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run_main(ready=False)
        self.assertIn("not confirmed ready", str(ctx.exception))


class ResolveSummitGenesisTests(unittest.TestCase):
    def test_defaults_to_manifest_sibling(self):
        # The artifact-set layout `assemble` writes.
        with tempfile.TemporaryDirectory() as d:
            manifest = Path(d) / "network-manifest.json"
            sibling = Path(d) / "summit-genesis.toml"
            sibling.write_text("")
            self.assertEqual(resolve_summit_genesis(None, manifest), sibling)

    def test_missing_default_errors(self):
        with tempfile.TemporaryDirectory() as d:
            manifest = Path(d) / "network-manifest.json"
            with self.assertRaises(SystemExit):
                resolve_summit_genesis(None, manifest)


if __name__ == "__main__":
    unittest.main()
