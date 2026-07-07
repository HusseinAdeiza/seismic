"""Tests for tee.manifest (stdlib unittest; no test deps in this repo).

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import json
import tempfile
import tomllib
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from tee.cli.common import manifest as manifest_mod
from tee.cli.common.manifest import (
    AssembledManifest,
    GateContext,
    GateError,
    ManifestSchemaError,
    assemble,
    compute_network_id,
    init_network_dir,
    promote_measurements,
    render_manifest,
    render_network_section,
    run_validation_gates,
    validate_manifest_schema,
    validate_reth_genesis_matches,
    write_artifact_set,
)

# Mirrors https://github.com/SeismicSystems/enclave/blob/seismic/crates/network-manifest/fixtures/network-manifest-v1.json
# The network_id vector below is asserted by that crate's
# parses_v1_fixture_and_derives_network_id test; together they pin the deploy
# emitter and the node-side parser to byte-identical rendering.
FIXTURE_MANIFEST = {
    "manifest_version": 1,
    "name": "seismic-devnet-3",
    "genesis_nonce": "0x" + "aa" * 32,
    "eth": {
        "chain_id": 5124,
        "genesis_hash": (
            "0x78ab9057bb67f95a6182969c5d755ac02802c98c0d2f0d8daeb52f4bddc60be5"
        ),
    },
    "summit": {
        "genesis_template_hash": "0x" + "bb" * 32,
        "namespace": "seismic-devnet-3",
    },
    "measurements": {
        "bootstrap_policy_hash": "0x" + "cc" * 32,
        "contracts": {
            "registry": "0x1000000000000000000000000000000000000001",
            "authority": "0x1000000000000000000000000000000000000002",
        },
    },
}
# network_id of FIXTURE_MANIFEST: SHA-256 of its deterministically-rendered
# bytes, i.e. compute_network_id(render_manifest(FIXTURE_MANIFEST)). Pinned as
# a literal (not computed) so the assertion catches the emitter drifting from
# this value — it's the same vector the enclave crate's
# parses_v1_fixture_and_derives_network_id test asserts.
FIXTURE_NETWORK_ID = (
    "0xc4d4721b2e287df26022e6d27c8cf772841a872b6be08b1938cbc76d88703747"
)

# The node-side parser pins these exact bytes in the enclave repo. Fetch its
# fixture from GitHub (the `seismic` branch) rather than assuming a sibling
# checkout on disk, so the cross-repo byte-parity check runs in CI too. The
# network_id value is also pinned offline by
# test_render_matches_enclave_network_id_vector, so this only adds a live drift
# guard; it skips when GitHub is unreachable.
ENCLAVE_FIXTURE_URL = (
    "https://raw.githubusercontent.com/SeismicSystems/enclave/seismic/"
    "crates/network-manifest/fixtures/network-manifest-v1.json"
)


def _fetch_enclave_fixture() -> bytes:
    with urllib.request.urlopen(ENCLAVE_FIXTURE_URL, timeout=10) as resp:
        return resp.read()


class RenderTests(unittest.TestCase):
    def test_render_matches_enclave_network_id_vector(self):
        rendered = render_manifest(FIXTURE_MANIFEST)
        self.assertEqual(compute_network_id(rendered), FIXTURE_NETWORK_ID)

    def test_render_matches_enclave_fixture_bytes(self):
        try:
            fixture = _fetch_enclave_fixture()
        except urllib.error.HTTPError:
            # A 4xx/5xx means the fixture moved or the ref is gone — a real
            # drift signal, not flaky network, so fail loudly.
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            self.skipTest(f"enclave fixture unreachable: {e}")
        self.assertEqual(render_manifest(FIXTURE_MANIFEST), fixture)

    def test_render_is_deterministic_under_key_order(self):
        shuffled = dict(reversed(list(FIXTURE_MANIFEST.items())))
        self.assertEqual(render_manifest(shuffled), render_manifest(FIXTURE_MANIFEST))

    def test_network_id_is_over_raw_bytes(self):
        rendered = render_manifest(FIXTURE_MANIFEST)
        self.assertNotEqual(
            compute_network_id(rendered + b"\n"), compute_network_id(rendered)
        )


class SchemaTests(unittest.TestCase):
    def _mutated(self, mutate=None):
        """Render the fixture after applying `mutate` to a deep copy."""
        manifest = json.loads(json.dumps(FIXTURE_MANIFEST))
        if mutate is not None:
            mutate(manifest)
        return render_manifest(manifest)

    def test_valid_manifest_parses(self):
        parsed = validate_manifest_schema(self._mutated())
        self.assertEqual(parsed["eth"]["chain_id"], 5124)

    def test_rejects_unknown_key(self):
        bad = self._mutated(lambda m: m.update(tx_io_pk="0x02ab"))
        with self.assertRaisesRegex(ManifestSchemaError, "unknown keys.*tx_io_pk"):
            validate_manifest_schema(bad)

    def test_rejects_missing_key(self):
        bad = self._mutated(lambda m: m.pop("summit"))
        with self.assertRaisesRegex(ManifestSchemaError, "missing keys.*summit"):
            validate_manifest_schema(bad)

    def test_reports_unsupported_version_before_unknown_keys(self):
        bad = self._mutated(lambda m: m.update(manifest_version=2, some_v2_field="new"))
        with self.assertRaisesRegex(
            ManifestSchemaError, "unsupported manifest_version 2"
        ):
            validate_manifest_schema(bad)

    def test_rejects_malformed_hex(self):
        def wrong_length(m):
            m["genesis_nonce"] = "0x" + "aa" * 31

        def missing_prefix(m):
            m["eth"]["genesis_hash"] = "ab" * 32

        def non_hex(m):
            m["measurements"]["bootstrap_policy_hash"] = "0x" + "zz" * 32

        for mutate in (wrong_length, missing_prefix, non_hex):
            with self.assertRaises(ManifestSchemaError):
                validate_manifest_schema(self._mutated(mutate))

    def test_rejects_bool_chain_id(self):
        def bool_chain_id(m):
            m["eth"]["chain_id"] = True

        with self.assertRaisesRegex(ManifestSchemaError, "chain_id"):
            validate_manifest_schema(self._mutated(bool_chain_id))


class PromoteTests(unittest.TestCase):
    PCRS = {"4": {"expected": "ab" * 24}, "9": {"expected": "cd" * 24}}

    def test_promotes_make_measure_wrapper_shape(self):
        raw = json.dumps({"measurements": self.PCRS}).encode()
        policy = json.loads(promote_measurements(raw, "img.vhd"))
        self.assertEqual(
            policy,
            [
                {
                    "measurement_id": "img.vhd",
                    "attestation_type": "azure-tdx",
                    "measurements": self.PCRS,
                }
            ],
        )

    def test_promotes_bare_pcr_map(self):
        raw = json.dumps(self.PCRS).encode()
        policy = json.loads(promote_measurements(raw, "img.vhd", "dcap-tdx"))
        self.assertEqual(policy[0]["attestation_type"], "dcap-tdx")
        self.assertEqual(policy[0]["measurements"], self.PCRS)

    def test_already_promoted_policy_passes_through_verbatim(self):
        # Odd-but-valid formatting must survive untouched: the manifest
        # commits to these exact bytes.
        raw = (
            b'[{"measurement_id": "x", "attestation_type": "azure-tdx",'
            b'   "measurements": {"4": {"expected": "ab"}}}]'
        )
        self.assertEqual(promote_measurements(raw, None), raw)

    def test_normalizes_path_measurement_id_to_basename(self):
        # A path to the artifact is a common slip; the published id is the
        # bare filename (a real id never contains a separator).
        raw = json.dumps({"measurements": self.PCRS}).encode()
        policy = json.loads(promote_measurements(raw, "../images/build/img.vhd"))
        self.assertEqual(policy[0]["measurement_id"], "img.vhd")

    def test_requires_measurement_id(self):
        raw = json.dumps({"measurements": self.PCRS}).encode()
        with self.assertRaisesRegex(GateError, "measurement_id"):
            promote_measurements(raw, None)

    def test_rejects_malformed_records(self):
        raw = json.dumps([{"measurement_id": "x"}]).encode()
        with self.assertRaises(GateError):
            promote_measurements(raw, None)


class NetworkSectionTests(unittest.TestCase):
    def test_network_section_round_trips_exact_bytes(self):
        import base64
        import tomllib

        manifest_bytes = render_manifest(FIXTURE_MANIFEST)
        genesis_bytes = json.dumps({"config": {"chainId": 5124}}).encode()
        section = tomllib.loads(render_network_section(manifest_bytes, genesis_bytes))
        decoded = base64.standard_b64decode(section["network"]["manifest_base64"])
        self.assertEqual(decoded, manifest_bytes)
        decoded_genesis = base64.standard_b64decode(
            section["network"]["reth_genesis_base64"]
        )
        self.assertEqual(decoded_genesis, genesis_bytes)


class RethGenesisMatchTests(unittest.TestCase):
    """validate_reth_genesis_matches — the client-side mirror of tdx-init's
    POST-time chainId cross-check."""

    def _genesis(self, chain_id) -> bytes:
        return json.dumps({"config": {"chainId": chain_id}, "alloc": {}}).encode()

    def test_matching_chain_id_passes(self):
        validate_reth_genesis_matches(FIXTURE_MANIFEST, self._genesis(5124))

    def test_chain_id_mismatch(self):
        with self.assertRaises(GateError):
            validate_reth_genesis_matches(FIXTURE_MANIFEST, self._genesis(5125))

    def test_rejects_non_json(self):
        with self.assertRaises(GateError):
            validate_reth_genesis_matches(FIXTURE_MANIFEST, b"{not json")

    def test_rejects_missing_or_bool_chain_id(self):
        for genesis in (b"{}", b'{"config": {}}', self._genesis(True)):
            with self.assertRaises(GateError):
                validate_reth_genesis_matches(FIXTURE_MANIFEST, genesis)


class GateTests(unittest.TestCase):
    """End-to-end assembly + gates over a synthetic artifact set."""

    ETH_HASH = "0x" + "12" * 32

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.reth_genesis = root / "reth-genesis.json"
        self.reth_genesis.write_text(
            json.dumps(
                {
                    "config": {"chainId": 5124},
                    "alloc": {
                        # Mixed case on purpose: gate must compare lowercased.
                        "0x1000000000000000000000000000000000000001": {
                            "code": "0x60016001"
                        },
                        "0x1000000000000000000000000000000000000002": {
                            "code": "0x60016001"
                        },
                    },
                }
            )
        )
        # Authored templates carry no eth_genesis_hash — assemble fills it.
        self.summit_template = root / "summit-genesis-template.toml"
        self.summit_template.write_text('namespace = "testnet-1"\n')
        self.policy_bytes = promote_measurements(
            json.dumps({"measurements": {"4": {"expected": "ab" * 24}}}).encode(),
            "img.vhd",
        )
        self.out_dir = root / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def _assemble(self, **overrides) -> AssembledManifest:
        kwargs = {
            "name": "testnet-1",
            "reth_genesis": self.reth_genesis,
            "summit_template": self.summit_template,
            "policy_bytes": self.policy_bytes,
            "genesis_nonce": b"\xaa" * 32,
            "genesis_hash_fn": lambda _p: self.ETH_HASH,
        }
        kwargs.update(overrides)
        # ty can't verify a **kwargs dict-splat against typed params.
        return assemble(**kwargs)  # ty: ignore[invalid-argument-type]

    def _ctx(self, **overrides) -> GateContext:
        kwargs = {
            "reth_genesis": self.reth_genesis,
            "summit_template": self.summit_template,
            "policy_bytes": self.policy_bytes,
            "genesis_hash_fn": lambda _p: self.ETH_HASH,
        }
        kwargs.update(overrides)
        # ty can't verify a **kwargs dict-splat against typed params.
        return GateContext(**kwargs)  # ty: ignore[invalid-argument-type]

    def test_assemble_passes_gates_and_is_deterministic(self):
        first = self._assemble()
        second = self._assemble()
        self.assertEqual(first.manifest_bytes, second.manifest_bytes)
        self.assertEqual(first.network_id, second.network_id)
        self.assertEqual(first.manifest["eth"]["chain_id"], 5124)
        self.assertEqual(first.manifest["eth"]["genesis_hash"], self.ETH_HASH)
        # Vacuous policy<->storage gate must be surfaced, not silent.
        self.assertTrue(any("genesis-pinned" in w for w in first.warnings))

    def test_fresh_nonce_uniquifies_clones(self):
        a = self._assemble(genesis_nonce=None)
        b = self._assemble(genesis_nonce=None)
        self.assertNotEqual(a.network_id, b.network_id)

    def test_gate_chain_id_mismatch(self):
        manifest = self._assemble().manifest
        manifest["eth"]["chain_id"] = 9999
        with self.assertRaisesRegex(GateError, "chain_id mismatch"):
            run_validation_gates(manifest, self._ctx())

    def test_gate_eth_genesis_hash_mismatch(self):
        manifest = self._assemble().manifest
        with self.assertRaisesRegex(GateError, r"eth\.genesis_hash mismatch"):
            run_validation_gates(
                manifest, self._ctx(genesis_hash_fn=lambda _p: "0x" + "34" * 32)
            )

    def test_gate_template_hash_mismatch(self):
        manifest = self._assemble().manifest
        self.summit_template.write_text(
            f'eth_genesis_hash = "{self.ETH_HASH}"\n'
            'namespace = "testnet-1"\n# tampered\n'
        )
        with self.assertRaisesRegex(GateError, "genesis_template_hash mismatch"):
            run_validation_gates(manifest, self._ctx())

    def test_gate_template_namespace_mismatch(self):
        # The template-bytes override stands in for the filled artifact-set
        # copy, so the earlier template-hash gate passes and this one fires.
        assembled = self._assemble()
        manifest = assembled.manifest
        manifest["summit"]["namespace"] = "other"
        with self.assertRaisesRegex(GateError, "namespace"):
            run_validation_gates(
                manifest,
                self._ctx(summit_template_bytes=assembled.summit_template_bytes),
            )

    def test_gate_contract_missing_from_alloc(self):
        assembled = self._assemble()
        manifest = assembled.manifest
        contracts = manifest["measurements"]["contracts"]
        contracts["registry"] = "0x" + "99" * 20
        with self.assertRaisesRegex(GateError, "not in the reth genesis alloc"):
            run_validation_gates(
                manifest,
                self._ctx(summit_template_bytes=assembled.summit_template_bytes),
            )

    def test_gate_policy_hash_mismatch(self):
        assembled = self._assemble()
        with self.assertRaisesRegex(GateError, "bootstrap_policy_hash mismatch"):
            run_validation_gates(
                assembled.manifest,
                self._ctx(
                    policy_bytes=self.policy_bytes + b"\n",
                    summit_template_bytes=assembled.summit_template_bytes,
                ),
            )

    def test_gate_populated_operator_storage_trips_unimplemented_check(self):
        genesis = json.loads(self.reth_genesis.read_text())
        operator = genesis["alloc"]["0x1000000000000000000000000000000000000001"]
        operator["storage"] = {"0x" + "00" * 32: "0x" + "01" * 32}
        self.reth_genesis.write_text(json.dumps(genesis))
        with self.assertRaisesRegex(GateError, "consistency check"):
            self._assemble()

    def test_assemble_fills_template_hash(self):
        # eth_genesis_hash is derived from reth-genesis.json, not authored:
        # the computed hash gets prepended, and the filled copy is what the
        # manifest commits to and the set ships.
        assembled = self._assemble()
        filled_line = f'eth_genesis_hash = "{self.ETH_HASH}"\n'.encode()
        self.assertTrue(assembled.summit_template_bytes.startswith(filled_line))
        write_artifact_set(self.out_dir, assembled, self._ctx())
        written = self.out_dir / "summit-genesis-template.toml"
        self.assertEqual(written.read_bytes(), assembled.summit_template_bytes)
        # validate-style round trip: gates re-pass over the written copy.
        run_validation_gates(assembled.manifest, self._ctx(summit_template=written))

    def test_assemble_fills_empty_validators_placeholder(self):
        # summit's genesis binary requires the key to *parse* the template
        # (no serde default) though it replaces the value; entries stay out.
        assembled = self._assemble()
        template = tomllib.loads(assembled.summit_template_bytes.decode())
        self.assertEqual(template["validators"], [])
        self.assertFalse(any("[[validators]]" in w for w in assembled.warnings))

    def test_assemble_replaces_declared_genesis_hash(self):
        # A declared value (e.g. from summit's example_genesis.toml) is stale
        # copy-paste by definition: the shipped copy carries the computed
        # value instead, and never the declared one.
        stale = "0x" + "34" * 32
        self.summit_template.write_text(
            f'eth_genesis_hash = "{stale}"\nnamespace = "testnet-1"\n'
        )
        assembled = self._assemble()
        shipped = assembled.summit_template_bytes
        self.assertNotIn(stale.encode(), shipped)
        self.assertTrue(
            shipped.startswith(f'eth_genesis_hash = "{self.ETH_HASH}"\n'.encode())
        )
        # Exactly one occurrence: the declared line was removed, not shadowed.
        self.assertEqual(shipped.count(b"eth_genesis_hash"), 1)

    def test_replace_leaves_table_keys_alone(self):
        # Only the top-level key is derived; a same-named key inside a table
        # (hypothetical) must survive untouched.
        self.summit_template.write_text(
            'namespace = "testnet-1"\n[extra]\neth_genesis_hash = "0xdead"\n'
        )
        assembled = self._assemble()
        self.assertIn(
            b'[extra]\neth_genesis_hash = "0xdead"\n', assembled.summit_template_bytes
        )

    def test_warns_on_default_summit_namespace(self):
        self.summit_template.write_text('namespace = "_SUMMIT"\n')
        assembled = self._assemble()
        self.assertTrue(any("_SUMMIT" in w for w in assembled.warnings))

    def test_init_then_assemble_shares_directory(self):
        # The `manifest init` → edit → `assemble --dir` loop: authored inputs
        # and derived outputs coexist in one network directory.
        net = Path(self.tmp.name) / "networks" / "testnet-1"
        raw = Path(self.tmp.name) / "raw-measurements.json"
        raw.write_text(json.dumps({"measurements": {"4": {"expected": "ab" * 24}}}))
        init_network_dir(net, "testnet-1", self.reth_genesis, raw)
        authored = (net / "summit-template.toml").read_bytes()
        policy = promote_measurements((net / "measurements.json").read_bytes(), "i.vhd")
        assembled = self._assemble(
            reth_genesis=net / "reth-genesis.json",
            summit_template=net / "summit-template.toml",
            policy_bytes=policy,
        )
        ctx = self._ctx(
            reth_genesis=net / "reth-genesis.json",
            summit_template=net / "summit-template.toml",
            policy_bytes=policy,
        )
        write_artifact_set(net, assembled, ctx)
        # Authored input untouched; the shipped filled copy sits beside it;
        # the same-name reth genesis write is byte-identical.
        self.assertEqual((net / "summit-template.toml").read_bytes(), authored)
        self.assertTrue((net / "summit-genesis-template.toml").exists())
        self.assertEqual(
            (net / "reth-genesis.json").read_bytes(), self.reth_genesis.read_bytes()
        )

    def test_write_artifact_set_refuses_overwrite(self):
        assembled = self._assemble()
        write_artifact_set(self.out_dir, assembled, self._ctx())
        for name in (
            "network-manifest.json",
            "measurement-policy.json",
            "reth-genesis.json",
            "summit-genesis-template.toml",
        ):
            self.assertTrue((self.out_dir / name).exists(), name)
        # Round-trip: written bytes hash back to the same network_id.
        written = (self.out_dir / "network-manifest.json").read_bytes()
        self.assertEqual(compute_network_id(written), assembled.network_id)
        with self.assertRaisesRegex(GateError, "immutable"):
            write_artifact_set(self.out_dir, assembled, self._ctx())
        write_artifact_set(self.out_dir, assembled, self._ctx(), force=True)


class InitTests(unittest.TestCase):
    """`manifest init` scaffolds a network directory's authored inputs."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.reth_genesis = root / "dev.json"
        self.reth_genesis.write_text('{"config": {"chainId": 5124}}')
        self.measurements = root / "measurements.json"
        self.measurements.write_text('{"measurements": {"4": {"expected": "ab"}}}')
        self.out = root / "networks" / "testnet-1"

    def test_scaffolds_inputs_with_starter_template(self):
        written = init_network_dir(
            self.out, "testnet-1", self.reth_genesis, self.measurements
        )
        self.assertEqual(
            sorted(p.name for p in written),
            ["measurements.json", "reth-genesis.json", "summit-template.toml"],
        )
        self.assertEqual(
            (self.out / "reth-genesis.json").read_bytes(),
            self.reth_genesis.read_bytes(),
        )
        template = tomllib.loads((self.out / "summit-template.toml").read_text())
        self.assertEqual(template["namespace"], "testnet-1")
        self.assertNotIn("eth_genesis_hash", template)
        self.assertNotIn("validators", template)

    def test_copies_supplied_template_verbatim(self):
        src = Path(self.tmp.name) / "custom.toml"
        src.write_text('namespace = "custom"\n# comment\n')
        init_network_dir(
            self.out, "testnet-1", self.reth_genesis, self.measurements, src
        )
        self.assertEqual(
            (self.out / "summit-template.toml").read_bytes(), src.read_bytes()
        )

    def test_refuses_overwrite(self):
        init_network_dir(self.out, "t", self.reth_genesis, self.measurements)
        with self.assertRaisesRegex(GateError, "refusing to overwrite"):
            init_network_dir(self.out, "t", self.reth_genesis, self.measurements)

    def test_stamps_measurement_id(self):
        init_network_dir(
            self.out,
            "testnet-1",
            self.reth_genesis,
            self.measurements,
            measurement_id="img.vhd",
        )
        stamped = (self.out / "measurements.json").read_bytes()
        # assemble's promotion picks the id up from the file — no flag needed.
        policy = json.loads(promote_measurements(stamped, None))
        self.assertEqual(policy[0]["measurement_id"], "img.vhd")

    def test_rejects_measurement_id_for_promoted_policy(self):
        promoted = Path(self.tmp.name) / "policy.json"
        promoted.write_text(
            json.dumps(
                [
                    {
                        "measurement_id": "x",
                        "attestation_type": "azure-tdx",
                        "measurements": {"4": {"expected": "ab"}},
                    }
                ]
            )
        )
        with self.assertRaisesRegex(GateError, "already-promoted"):
            init_network_dir(
                self.out, "t", self.reth_genesis, promoted, measurement_id="img.vhd"
            )


class DirCliTests(unittest.TestCase):
    """assemble/validate take the network directory as their sole positional
    argument (`_parse_args`); only init handles loose files."""

    def test_assemble_dir_resolution(self):
        args = manifest_mod._parse_args(["assemble", "networks/testnet-1"])
        self.assertEqual(args.name, "testnet-1")
        self.assertEqual(
            args.reth_genesis, Path("networks/testnet-1/reth-genesis.json")
        )
        # assemble reads the *authored* input template.
        self.assertEqual(
            args.summit_template, Path("networks/testnet-1/summit-template.toml")
        )
        self.assertEqual(
            args.measurements, Path("networks/testnet-1/measurements.json")
        )
        self.assertEqual(args.out, Path("networks/testnet-1"))

    def test_assemble_requires_dir(self):
        with self.assertRaises(SystemExit):
            manifest_mod._parse_args(["assemble"])

    def test_init_dir_positional_defaults_name(self):
        args = manifest_mod._parse_args(
            [
                "init",
                "networks/testnet-1",
                "--reth-genesis",
                "g.json",
                "--measurements",
                "m.json",
            ]
        )
        self.assertEqual(args.dir, Path("networks/testnet-1"))
        self.assertEqual(args.name, "testnet-1")

    def test_validate_dir_resolution(self):
        args = manifest_mod._parse_args(["validate", "networks/t"])
        self.assertEqual(args.manifest, Path("networks/t/network-manifest.json"))
        # validate reads the *shipped* template copy, not the authored input.
        self.assertEqual(
            args.summit_template, Path("networks/t/summit-genesis-template.toml")
        )
        self.assertEqual(
            args.measurement_policy, Path("networks/t/measurement-policy.json")
        )


if __name__ == "__main__":
    unittest.main()
