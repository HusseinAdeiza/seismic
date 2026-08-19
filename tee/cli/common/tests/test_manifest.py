"""Tests for tee.manifest (stdlib unittest; no test deps in this repo).

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import hashlib
import json
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from eth_utils.crypto import keccak

from tee.cli.common import manifest as manifest_mod
from tee.cli.common.manifest import (
    DEFAULT_ADMISSION_BIN,
    SUMMIT_CONSENSUS_PORT,
    AssembledManifest,
    GateContext,
    GateError,
    ManifestSchemaError,
    assemble,
    compute_network_id,
    init_network_dir,
    inject_registry_genesis_storage,
    load_founding_set,
    load_harvest_records,
    promote_measurements,
    render_manifest,
    render_network_section,
    run_validation_gates,
    summit_set_validators,
    validate_manifest_schema,
    validate_reth_genesis_matches,
    validate_summit_genesis_matches,
    verify_harvest_records,
    verify_node_deployment,
    write_artifact_set,
)


def _content_digest(path: Path) -> str:
    """Test stand-in for `summit genesis digest`: content-derived (a byte
    hash, not summit's SSZ digest), so tamper-detection gates still fire."""
    return "0x" + hashlib.sha256(path.read_bytes()).hexdigest()


# A founding validator entry as load_founding_set builds it (harvested keys
# in summit's bare-lowercase-hex keystore spelling, authored credentials,
# descriptor IP + consensus port).
VALIDATOR = {
    "node_public_key": "ab" * 32,
    "consensus_public_key": "cd" * 48,
    "ip_address": f"203.0.113.7:{SUMMIT_CONSENSUS_PORT}",
    "withdrawal_credentials": "0x" + "f3" * 20,
}


def _fake_set_validators(template: bytes, validators: list[dict[str, str]]) -> bytes:
    """Test stand-in for `summit genesis set-validators`: replaces the
    template's placeholder set with inline-table entries, sorted by node key
    like summit's canonical emission. Line-level splice (not a re-render), so
    byte-oriented assertions about the rest of the template stay meaningful."""
    entries = ", ".join(
        "{ " + ", ".join(f"{k} = {json.dumps(v[k])}" for k in sorted(v)) + " }"
        for v in sorted(validators, key=lambda v: v["node_public_key"])
    )
    return template.replace(
        b"validators = []\n", f"validators = [{entries}]\n".encode(), 1
    )


# A raw `make measure` wrapper as seismic-images emits it: numeric keys,
# `expected` (not `expected_any`), and a zero register the schema drops.
RAW_MEASUREMENTS = {
    "measurements": {
        "4": {"expected": "ab" * 32},
        "8": {"expected": "00" * 32},
        "9": {"expected": "cd" * 32},
        "11": {"expected": "ef" * 32},
    }
}


def promoted_policy_bytes(measurement_id: str = "img.vhd") -> bytes:
    """A valid promoted policy document (the canonical one-record form the
    admission CLI emits: schema registers only, single-value expected_any)."""
    records = [
        {
            "attestation_type": "azure-tdx",
            "measurement_id": measurement_id,
            "measurements": {
                "pcr4": {"expected_any": ["ab" * 32]},
                "pcr9": {"expected_any": ["cd" * 32]},
                "pcr11": {"expected_any": ["ef" * 32]},
            },
        }
    ]
    return (json.dumps(records, indent=2) + "\n").encode()


# Mirrors https://github.com/SeismicSystems/enclave/blob/seismic/crates/network-manifest/fixtures/network-manifest-v1.json
# The network_id vector below is asserted by that crate's
# parses_v1_fixture_and_derives_network_id test; together they pin the deploy
# emitter and the node-side parser to byte-identical rendering. That crate
# pins the fixture's exact bytes, and drift_test_manifest.py
# (`make test-drift`) checks this emitter against them.
FIXTURE_MANIFEST = {
    "manifest_version": 1,
    "name": "seismic-devnet-3",
    "eth": {
        "chain_id": 5124,
        "genesis_hash": (
            "0x78ab9057bb67f95a6182969c5d755ac02802c98c0d2f0d8daeb52f4bddc60be5"
        ),
    },
    "summit": {
        "genesis_config_digest": "0x" + "bb" * 32,
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
    "0x8ef142e3f2bf15f8b201c4d8cda7848a9e846222c62b5615d4d36c7fccd98a24"
)


class RenderTests(unittest.TestCase):
    def test_render_matches_enclave_network_id_vector(self):
        rendered = render_manifest(FIXTURE_MANIFEST)
        self.assertEqual(compute_network_id(rendered), FIXTURE_NETWORK_ID)

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
            m["summit"]["genesis_config_digest"] = "0x" + "aa" * 31

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
    """The `promote` shell-out's failure surfacing. Running the real CLI —
    promotion, pass-through, compiler diagnostics — needs the binary, so it
    lives in drift_test_manifest.py (`make test-drift`)."""

    def test_missing_binary_is_a_gate_error(self):
        raw = json.dumps(RAW_MEASUREMENTS).encode()
        with self.assertRaisesRegex(GateError, "not found"):
            promote_measurements(raw, admission_bin="no-such-admission-cli")


class NetworkSectionTests(unittest.TestCase):
    SUMMIT_GENESIS = b'namespace = "seismic-devnet-3"\nvalidators = []\n'

    def test_network_section_round_trips_exact_bytes(self):
        import base64
        import tomllib

        manifest_bytes = render_manifest(FIXTURE_MANIFEST)
        genesis_bytes = json.dumps({"config": {"chainId": 5124}}).encode()
        section = tomllib.loads(
            render_network_section(
                manifest_bytes, genesis_bytes, self.SUMMIT_GENESIS, []
            )
        )
        decoded = base64.standard_b64decode(section["network"]["manifest_base64"])
        self.assertEqual(decoded, manifest_bytes)
        decoded_genesis = base64.standard_b64decode(
            section["network"]["reth_genesis_base64"]
        )
        self.assertEqual(decoded_genesis, genesis_bytes)
        decoded_summit = base64.standard_b64decode(
            section["network"]["summit_genesis_base64"]
        )
        self.assertEqual(decoded_summit, self.SUMMIT_GENESIS)

    def test_bootnodes_populated_survive_verbatim(self):
        import tomllib

        manifest_bytes = render_manifest(FIXTURE_MANIFEST)
        genesis_bytes = json.dumps({"config": {"chainId": 5124}}).encode()
        bootnodes = [
            "enode://" + "ab" * 64 + "@1.2.3.4:30303",
            "enode://" + "cd" * 64 + "@5.6.7.8:30303",
        ]
        section = tomllib.loads(
            render_network_section(
                manifest_bytes, genesis_bytes, self.SUMMIT_GENESIS, bootnodes
            )
        )
        self.assertEqual(section["network"]["bootnodes"], bootnodes)

    def test_bootnodes_empty_key_is_present(self):
        # tdx-init requires the key even when the list is empty (the
        # greenfield genesis case) — so the POSTed config states plainly
        # that the node has no static bootnodes yet.
        import tomllib

        manifest_bytes = render_manifest(FIXTURE_MANIFEST)
        genesis_bytes = json.dumps({"config": {"chainId": 5124}}).encode()
        rendered = render_network_section(
            manifest_bytes, genesis_bytes, self.SUMMIT_GENESIS, []
        )
        self.assertIn("bootnodes = []", rendered)
        section = tomllib.loads(rendered)
        self.assertEqual(section["network"]["bootnodes"], [])


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


class SummitGenesisMatchTests(unittest.TestCase):
    """validate_summit_genesis_matches — the client-side mirror of tdx-init's
    POST-time summit-genesis namespace cross-check."""

    def _genesis(self, namespace: str) -> bytes:
        return f"namespace = {json.dumps(namespace)}\nvalidators = []\n".encode()

    def test_matching_namespace_passes(self):
        validate_summit_genesis_matches(
            FIXTURE_MANIFEST, self._genesis("seismic-devnet-3")
        )

    def test_namespace_mismatch(self):
        with self.assertRaises(GateError):
            validate_summit_genesis_matches(
                FIXTURE_MANIFEST, self._genesis("seismic-devnet-4")
            )

    def test_rejects_non_toml(self):
        with self.assertRaises(GateError):
            validate_summit_genesis_matches(FIXTURE_MANIFEST, b'{"namespace": "x"}')

    def test_rejects_missing_or_non_string_namespace(self):
        for genesis in (b"validators = []\n", b"namespace = 5\n"):
            with self.assertRaises(GateError):
                validate_summit_genesis_matches(FIXTURE_MANIFEST, genesis)


class InjectTests(unittest.TestCase):
    """inject_registry_genesis_storage — the derive half of the registry
    gate (its exactness arms live in GateTests)."""

    # Letter-bearing address so upper/lower spellings are distinct strings.
    REGISTRY = "0x" + "ab" * 20
    REPORT = {"registry_genesis_storage": {"0x" + "00" * 31 + "01": "0x" + "11" * 32}}

    def test_preserves_alloc_key_spelling(self):
        # Genesis JSON may checksum-case the address; the account is found
        # case-insensitively and its original key survives the rewrite.
        cased = "0x" + self.REGISTRY[2:].upper()
        genesis = json.dumps({"alloc": {cased: {"code": "0x00"}}}).encode()
        injected = json.loads(
            inject_registry_genesis_storage(genesis, self.REGISTRY, self.REPORT)
        )
        self.assertEqual(list(injected["alloc"]), [cased])
        self.assertEqual(
            injected["alloc"][cased]["storage"],
            self.REPORT["registry_genesis_storage"],
        )

    def test_missing_registry_account(self):
        genesis = json.dumps({"alloc": {}}).encode()
        with self.assertRaisesRegex(GateError, "not in the reth genesis alloc"):
            inject_registry_genesis_storage(genesis, self.REGISTRY, self.REPORT)

    def test_duplicate_alloc_spellings(self):
        genesis = json.dumps(
            {
                "alloc": {
                    self.REGISTRY: {"code": "0x00"},
                    "0x" + self.REGISTRY[2:].upper(): {"code": "0x00"},
                }
            }
        ).encode()
        with self.assertRaisesRegex(GateError, "twice"):
            inject_registry_genesis_storage(genesis, self.REGISTRY, self.REPORT)

    def test_report_without_storage(self):
        genesis = json.dumps({"alloc": {self.REGISTRY: {"code": "0x00"}}}).encode()
        for report in ({}, {"registry_genesis_storage": {}}):
            with self.assertRaisesRegex(GateError, "registry_genesis_storage"):
                inject_registry_genesis_storage(genesis, self.REGISTRY, report)


class GateTests(unittest.TestCase):
    """End-to-end assembly + gates over a synthetic artifact set.

    The policy compiler is injected (compile_fn, mirroring genesis_hash_fn):
    the gates' contract is "registry account == report", so a synthetic
    report exercises every mismatch arm without the Rust binary. assemble
    itself writes the report's storage into its genesis copy, so the
    storage-mismatch arms are reached through the validate path — gates
    re-run over an artifact set whose on-disk genesis was tampered with.
    """

    ETH_HASH = "0x" + "12" * 32
    REGISTRY_CODE = "0x600160005500"
    REGISTRY_CODE_HASH = "0x" + keccak(bytes.fromhex("600160005500")).hex()
    # Canonical report spellings; the genesis alloc below writes the same
    # slots unpadded/mixed-case, which the gate must treat as equal.
    REPORT_STORAGE = {
        "0x" + "aa" * 32: "0x" + "11" * 32,
        "0x" + "00" * 31 + "02": "0x" + "00" * 31 + "01",
    }
    GENESIS_STORAGE = {
        "0x" + "AA" * 32: "0x" + "11" * 32,
        "0x2": "0x1",
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.reth_genesis = root / "reth-genesis.json"
        self._write_genesis()
        # Authored inputs carry no eth_genesis_hash — assemble fills it.
        self.summit_genesis = root / "summit-genesis.toml"
        self.summit_genesis.write_text('namespace = "testnet-1"\n')
        self.policy_bytes = promoted_policy_bytes()
        self.out_dir = root / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def _write_genesis(self, registry_overrides: dict[str, Any] | None = None):
        registry: dict[str, Any] = {
            "code": self.REGISTRY_CODE,
            "storage": dict(self.GENESIS_STORAGE),
        }
        registry.update(registry_overrides or {})
        # A None override removes the key (a policy-free genesis carries
        # no storage key at all).
        registry = {k: v for k, v in registry.items() if v is not None}
        self.reth_genesis.write_text(
            json.dumps(
                {
                    "config": {"chainId": 5124},
                    "alloc": {
                        # Mixed case on purpose: gate must compare lowercased.
                        "0x1000000000000000000000000000000000000001": registry,
                        "0x1000000000000000000000000000000000000002": {
                            "code": "0x60016001"
                        },
                    },
                }
            )
        )

    def _report(self, policy_bytes: bytes) -> dict[str, Any]:
        return {
            "policy_hash": manifest_mod._sha256_hex(policy_bytes),
            "registry_runtime_code_hash": self.REGISTRY_CODE_HASH,
            "registry_genesis_storage": dict(self.REPORT_STORAGE),
        }

    def _assemble(self, **overrides) -> AssembledManifest:
        kwargs = {
            "name": "testnet-1",
            "reth_genesis": self.reth_genesis,
            "summit_genesis": self.summit_genesis,
            "policy_bytes": self.policy_bytes,
            "validators": [dict(VALIDATOR)],
            "genesis_hash_fn": lambda _p: self.ETH_HASH,
            "compile_fn": self._report,
            "digest_fn": _content_digest,
            "set_validators_fn": _fake_set_validators,
        }
        kwargs.update(overrides)
        # ty can't verify a **kwargs dict-splat against typed params.
        return assemble(**kwargs)  # ty: ignore[invalid-argument-type]

    def _ctx(self, **overrides) -> GateContext:
        kwargs = {
            "reth_genesis": self.reth_genesis,
            "summit_genesis": self.summit_genesis,
            "policy_bytes": self.policy_bytes,
            "genesis_hash_fn": lambda _p: self.ETH_HASH,
            "compile_fn": self._report,
            "digest_fn": _content_digest,
        }
        kwargs.update(overrides)
        # ty can't verify a **kwargs dict-splat against typed params.
        return GateContext(**kwargs)  # ty: ignore[invalid-argument-type]

    def _validate(self, assembled: AssembledManifest) -> None:
        """The validate path: gates re-run over the on-disk genesis, with
        assemble's completed summit genesis standing in for the shipped file."""
        run_validation_gates(
            assembled.manifest,
            self._ctx(summit_genesis_bytes=assembled.summit_genesis_bytes),
        )

    def test_assemble_passes_gates_and_is_deterministic(self):
        first = self._assemble()
        second = self._assemble()
        self.assertEqual(first.manifest_bytes, second.manifest_bytes)
        self.assertEqual(first.network_id, second.network_id)
        self.assertEqual(first.manifest["eth"]["chain_id"], 5124)
        self.assertEqual(first.manifest["eth"]["genesis_hash"], self.ETH_HASH)

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

    def test_gate_config_digest_mismatch(self):
        manifest = self._assemble().manifest
        self.summit_genesis.write_text(
            f'eth_genesis_hash = "{self.ETH_HASH}"\n'
            'namespace = "testnet-1"\n# tampered\n'
        )
        with self.assertRaisesRegex(GateError, "genesis_config_digest mismatch"):
            run_validation_gates(manifest, self._ctx())

    def test_gate_genesis_namespace_mismatch(self):
        # The genesis-bytes override stands in for the completed artifact-set
        # copy, so the earlier config-digest gate passes and this one fires.
        assembled = self._assemble()
        manifest = assembled.manifest
        manifest["summit"]["namespace"] = "other"
        with self.assertRaisesRegex(GateError, "namespace"):
            run_validation_gates(
                manifest,
                self._ctx(summit_genesis_bytes=assembled.summit_genesis_bytes),
            )

    def test_gate_contract_missing_from_alloc(self):
        assembled = self._assemble()
        manifest = assembled.manifest
        contracts = manifest["measurements"]["contracts"]
        contracts["registry"] = "0x" + "99" * 20
        with self.assertRaisesRegex(GateError, "not in the reth genesis alloc"):
            run_validation_gates(
                manifest,
                self._ctx(summit_genesis_bytes=assembled.summit_genesis_bytes),
            )

    def test_gate_policy_hash_mismatch(self):
        assembled = self._assemble()
        with self.assertRaisesRegex(GateError, "bootstrap_policy_hash mismatch"):
            run_validation_gates(
                assembled.manifest,
                self._ctx(
                    policy_bytes=self.policy_bytes + b"\n",
                    summit_genesis_bytes=assembled.summit_genesis_bytes,
                ),
            )

    def test_gate_compiler_policy_hash_cross_check(self):
        def stale_report(policy_bytes: bytes) -> dict[str, Any]:
            return {**self._report(policy_bytes), "policy_hash": "0x" + "99" * 32}

        with self.assertRaisesRegex(GateError, "different document bytes"):
            self._assemble(compile_fn=stale_report)

    def test_gate_non_canonical_registry_code(self):
        self._write_genesis({"code": "0xdeadbeef"})
        with self.assertRaisesRegex(
            GateError, "not the canonical MeasurementRegistry runtime"
        ):
            self._assemble()

    def test_validate_accepts_equal_storage_under_other_spellings(self):
        # The on-disk genesis spells the report's slots unpadded/mixed-case
        # (GENESIS_STORAGE); the gate compares normalized words.
        self._validate(self._assemble())

    def test_gate_empty_registry_storage(self):
        assembled = self._assemble()
        self._write_genesis({"storage": {}})
        with self.assertRaisesRegex(GateError, "must be genesis-pinned"):
            self._validate(assembled)

    def test_gate_missing_storage_slot(self):
        assembled = self._assemble()
        self._write_genesis({"storage": {"0x" + "aa" * 32: "0x" + "11" * 32}})
        with self.assertRaisesRegex(
            GateError, r"slot 0x0{63}2 missing \(expected 0x0{63}1\)"
        ):
            self._validate(assembled)

    def test_gate_unexplained_storage_slot(self):
        assembled = self._assemble()
        storage = dict(self.GENESIS_STORAGE)
        storage["0x" + "cc" * 32] = "0x" + "01" * 32
        self._write_genesis({"storage": storage})
        with self.assertRaisesRegex(GateError, f"slot 0x{'cc' * 32} unexplained"):
            self._validate(assembled)

    def test_gate_wrong_storage_value(self):
        assembled = self._assemble()
        storage = dict(self.GENESIS_STORAGE)
        storage["0x2"] = "0x3"
        self._write_genesis({"storage": storage})
        with self.assertRaisesRegex(
            GateError, r"slot 0x0{63}2 holds 0x0{63}3, expected 0x0{63}1"
        ):
            self._validate(assembled)

    def test_gate_duplicate_slot_spellings(self):
        assembled = self._assemble()
        storage = dict(self.GENESIS_STORAGE)
        storage["0x02"] = "0x1"  # same slot as "0x2" under another spelling
        self._write_genesis({"storage": storage})
        with self.assertRaisesRegex(GateError, "same slot twice"):
            self._validate(assembled)

    def test_assemble_injects_registry_storage(self):
        # A policy-free input (no storage key, like reth's committed
        # dev.json) assembles: the report's storage lands verbatim in the
        # genesis copy the manifest commits to; code and other accounts
        # stay untouched.
        self._write_genesis({"storage": None})
        assembled = self._assemble()
        genesis = json.loads(assembled.reth_genesis_bytes)
        registry = genesis["alloc"]["0x1000000000000000000000000000000000000001"]
        self.assertEqual(registry["storage"], self.REPORT_STORAGE)
        self.assertEqual(registry["code"], self.REGISTRY_CODE)
        self.assertEqual(
            genesis["alloc"]["0x1000000000000000000000000000000000000002"],
            {"code": "0x60016001"},
        )

    def test_assemble_replaces_stale_storage_wholesale(self):
        # A policy change re-derives the whole map; stale slots don't linger.
        self._write_genesis({"storage": {"0x" + "dd" * 32: "0x" + "ee" * 32}})
        assembled = self._assemble()
        genesis = json.loads(assembled.reth_genesis_bytes)
        registry = genesis["alloc"]["0x1000000000000000000000000000000000000001"]
        self.assertEqual(registry["storage"], self.REPORT_STORAGE)

    def test_eth_genesis_hash_commits_to_injected_genesis(self):
        # Content-derived fake hasher: the manifest must commit to the hash
        # of the injected copy, not of the policy-free input. Passing gates
        # also pin the self-check to the same bytes.
        def content_hash(p: Path) -> str:
            return "0x" + hashlib.sha256(p.read_bytes()).hexdigest()

        assembled = self._assemble(genesis_hash_fn=content_hash)
        injected = "0x" + hashlib.sha256(assembled.reth_genesis_bytes).hexdigest()
        self.assertEqual(assembled.manifest["eth"]["genesis_hash"], injected)
        raw = "0x" + hashlib.sha256(self.reth_genesis.read_bytes()).hexdigest()
        self.assertNotEqual(injected, raw)

    def test_assemble_fills_eth_genesis_hash(self):
        # eth_genesis_hash is derived from reth-genesis.json, not authored:
        # the computed hash gets prepended, and the completed copy is what the
        # manifest commits to and the set ships as summit-genesis.toml.
        assembled = self._assemble()
        filled_line = f'eth_genesis_hash = "{self.ETH_HASH}"\n'.encode()
        self.assertTrue(assembled.summit_genesis_bytes.startswith(filled_line))
        write_artifact_set(self.out_dir, assembled)
        written = self.out_dir / "summit-genesis.toml"
        self.assertEqual(written.read_bytes(), assembled.summit_genesis_bytes)
        # validate-style round trip: gates re-pass over the written copy.
        run_validation_gates(assembled.manifest, self._ctx(summit_genesis=written))

    def test_assemble_ships_the_founding_validator_set(self):
        # The validator set the artifact ships is exactly the one passed in
        # (the founding cohort from load_founding_set), filled by the
        # set-validators emission.
        assembled = self._assemble()
        genesis = tomllib.loads(assembled.summit_genesis_bytes.decode())
        self.assertEqual(genesis["validators"], [VALIDATOR])

    def test_assemble_rejects_an_empty_validator_set(self):
        with self.assertRaisesRegex(GateError, "no founding validators"):
            self._assemble(validators=[])

    def test_digest_commits_to_the_emitted_genesis(self):
        # The manifest's config digest is computed over set-validators'
        # output (validator set included), not over the pre-emission
        # template.
        assembled = self._assemble()
        emitted = "0x" + hashlib.sha256(assembled.summit_genesis_bytes).hexdigest()
        self.assertEqual(assembled.manifest["summit"]["genesis_config_digest"], emitted)
        self.assertIn(
            VALIDATOR["node_public_key"].encode(), assembled.summit_genesis_bytes
        )

    def test_assemble_replaces_declared_genesis_hash(self):
        # A declared value (e.g. from summit's example_genesis.toml) is stale
        # copy-paste by definition: the shipped copy carries the computed
        # value instead, and never the declared one.
        stale = "0x" + "34" * 32
        self.summit_genesis.write_text(
            f'eth_genesis_hash = "{stale}"\nnamespace = "testnet-1"\n'
        )
        assembled = self._assemble()
        shipped = assembled.summit_genesis_bytes
        self.assertNotIn(stale.encode(), shipped)
        self.assertTrue(
            shipped.startswith(f'eth_genesis_hash = "{self.ETH_HASH}"\n'.encode())
        )
        # Exactly one occurrence: the declared line was removed, not shadowed.
        self.assertEqual(shipped.count(b"eth_genesis_hash"), 1)

    def test_replace_leaves_table_keys_alone(self):
        # Only the top-level key is derived; a same-named key inside a table
        # (hypothetical) must survive untouched.
        self.summit_genesis.write_text(
            'namespace = "testnet-1"\n[extra]\neth_genesis_hash = "0xdead"\n'
        )
        assembled = self._assemble()
        self.assertIn(
            b'[extra]\neth_genesis_hash = "0xdead"\n', assembled.summit_genesis_bytes
        )

    def test_warns_on_default_summit_namespace(self):
        self.summit_genesis.write_text('namespace = "_SUMMIT"\n')
        assembled = self._assemble()
        self.assertTrue(any("_SUMMIT" in w for w in assembled.warnings))

    def test_init_then_assemble_shares_directory(self):
        # The `init` → edit → `assemble` loop: authored inputs
        # under inputs/, the derived artifact set at the top level.
        net = Path(self.tmp.name) / "networks" / "testnet-1"
        inputs = net / "inputs"
        raw = Path(self.tmp.name) / "raw-measurements.json"
        raw.write_text(
            json.dumps(
                {
                    "measurement_id": "img.vhd",
                    "measurements": {"4": {"expected": "ab" * 24}},
                }
            )
        )
        starter = Path(self.tmp.name) / "summit-genesis-starter.toml"
        starter.write_text("leader_timeout_ms = 2000\n")
        init_network_dir(net, "testnet-1", self.reth_genesis, raw, starter)
        authored = (inputs / "summit-genesis.toml").read_bytes()
        assembled = self._assemble(
            reth_genesis=inputs / "reth-genesis.json",
            summit_genesis=inputs / "summit-genesis.toml",
        )
        write_artifact_set(net, assembled)
        # Authored inputs untouched; each artifact at the top level carries
        # assemble's derived copy.
        self.assertEqual((inputs / "summit-genesis.toml").read_bytes(), authored)
        self.assertEqual(
            (inputs / "reth-genesis.json").read_bytes(),
            self.reth_genesis.read_bytes(),
        )
        self.assertEqual(
            (net / "summit-genesis.toml").read_bytes(),
            assembled.summit_genesis_bytes,
        )
        self.assertEqual(
            (net / "reth-genesis.json").read_bytes(), assembled.reth_genesis_bytes
        )

    def test_write_artifact_set_refuses_overwrite(self):
        assembled = self._assemble()
        write_artifact_set(self.out_dir, assembled)
        for name in (
            "network-manifest.json",
            "measurement-policy-bootstrap.json",
            "reth-genesis.json",
            "summit-genesis.toml",
        ):
            self.assertTrue((self.out_dir / name).exists(), name)
        # Round-trip: written bytes hash back to the same network_id.
        written = (self.out_dir / "network-manifest.json").read_bytes()
        self.assertEqual(compute_network_id(written), assembled.network_id)
        with self.assertRaisesRegex(GateError, "immutable"):
            write_artifact_set(self.out_dir, assembled)
        write_artifact_set(self.out_dir, assembled, force=True)


class InitTests(unittest.TestCase):
    """`init` scaffolds a network directory's authored inputs."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.reth_genesis = root / "dev.json"
        self.reth_genesis.write_text('{"config": {"chainId": 5124}}')
        self.measurements = root / "measurements.json"
        self.measurements.write_text(
            '{"measurement_id": "img.vhd", "measurements": {"4": {"expected": "ab"}}}'
        )
        # A shared starter's shape: parameters plus the empty namespace slot.
        self.starter = root / "summit-genesis-starter.toml"
        self.starter.write_text(
            '# starter params\nnamespace = ""\nleader_timeout_ms = 2000\n'
        )
        self.out = root / "networks" / "testnet-1"

    def test_scaffolds_inputs_and_fills_namespace(self):
        written = init_network_dir(
            self.out, "testnet-1", self.reth_genesis, self.measurements, self.starter
        )
        inputs = self.out / "inputs"
        self.assertEqual({p.parent for p in written}, {inputs})
        self.assertEqual(
            sorted(p.name for p in written),
            [
                "founder-withdrawal-credentials.json",
                "measurements.json",
                "reth-genesis.json",
                "summit-genesis.toml",
            ],
        )
        # No --founders: an empty list to fill in, not a guessed cohort size.
        self.assertEqual(
            json.loads((inputs / "founder-withdrawal-credentials.json").read_text()), []
        )
        self.assertEqual(
            (inputs / "reth-genesis.json").read_bytes(),
            self.reth_genesis.read_bytes(),
        )
        # The starter's namespace slot is empty, so init fills the network
        # name into it; every other authored line (comments included) is
        # untouched.
        raw = (inputs / "summit-genesis.toml").read_text()
        self.assertEqual(
            raw,
            '# starter params\nnamespace = "testnet-1"\nleader_timeout_ms = 2000\n',
        )

    def test_fills_namespace_when_key_is_omitted(self):
        # A genesis with no namespace line at all gets one appended.
        self.starter.write_text("leader_timeout_ms = 2000\n")
        init_network_dir(
            self.out, "testnet-1", self.reth_genesis, self.measurements, self.starter
        )
        raw = (self.out / "inputs" / "summit-genesis.toml").read_bytes()
        self.assertTrue(raw.startswith(self.starter.read_bytes()))
        self.assertEqual(tomllib.loads(raw.decode())["namespace"], "testnet-1")

    def test_unrewritable_empty_namespace_is_a_gate_error(self):
        # An empty namespace spelled in a form the line rewrite can't find
        # (quoted key) fails loudly instead of shipping an empty namespace.
        self.starter.write_text('"namespace" = ""\nleader_timeout_ms = 2000\n')
        with self.assertRaisesRegex(GateError, "empty namespace"):
            init_network_dir(
                self.out, "t", self.reth_genesis, self.measurements, self.starter
            )

    def test_copies_supplied_genesis_verbatim(self):
        # A namespace already present is authored intent: no fill, no rewrite.
        src = Path(self.tmp.name) / "custom.toml"
        src.write_text('namespace = "custom"\n# comment\n')
        init_network_dir(
            self.out, "testnet-1", self.reth_genesis, self.measurements, src
        )
        self.assertEqual(
            (self.out / "inputs" / "summit-genesis.toml").read_bytes(),
            src.read_bytes(),
        )

    def test_refuses_overwrite_unless_forced(self):
        init_network_dir(
            self.out, "t", self.reth_genesis, self.measurements, self.starter
        )
        with self.assertRaisesRegex(GateError, "refusing to overwrite"):
            init_network_dir(
                self.out, "t", self.reth_genesis, self.measurements, self.starter
            )
        # The re-found/re-author path: --force overwrites the inputs.
        self.reth_genesis.write_text('{"config": {"chainId": 9999}}')
        init_network_dir(
            self.out,
            "t",
            self.reth_genesis,
            self.measurements,
            self.starter,
            force=True,
        )
        rewritten = (self.out / "inputs" / "reth-genesis.json").read_text()
        self.assertIn("9999", rewritten)

    def test_founders_scaffolds_placeholder_credentials(self):
        init_network_dir(
            self.out,
            "testnet-1",
            self.reth_genesis,
            self.measurements,
            self.starter,
            founders=3,
        )
        path = self.out / "inputs" / "founder-withdrawal-credentials.json"
        self.assertEqual(
            json.loads(path.read_text()),
            [f"0x{1:040x}", f"0x{2:040x}", f"0x{3:040x}"],
        )
        # Placeholders are a usable founder set, not a stub to be rewritten.
        self.assertEqual(len(manifest_mod.load_founder_credentials(path)), 3)

    def test_copies_measurements_verbatim(self):
        # The file assemble promotes is byte-identical to what `make measure`
        # emitted, stamped id included.
        init_network_dir(
            self.out, "testnet-1", self.reth_genesis, self.measurements, self.starter
        )
        self.assertEqual(
            (self.out / "inputs" / "measurements.json").read_bytes(),
            self.measurements.read_bytes(),
        )

    def test_requires_a_stamped_measurement_id(self):
        # Nothing binds a network to an image out of band, so unstamped
        # measurements are refused here rather than at promotion time —
        # after the cohort has been provisioned and harvested.
        self.measurements.write_text('{"measurements": {"4": {"expected": "ab"}}}')
        with self.assertRaisesRegex(GateError, "no measurement_id"):
            init_network_dir(
                self.out, "t", self.reth_genesis, self.measurements, self.starter
            )

    def test_accepts_a_promoted_policy(self):
        # A record list is the other valid input: each record names its image.
        promoted = Path(self.tmp.name) / "policy.json"
        promoted.write_text(
            json.dumps(
                [
                    {
                        "measurement_id": "img.vhd",
                        "attestation_type": "azure-tdx",
                        "measurements": {"4": {"expected": "ab"}},
                    }
                ]
            )
        )
        init_network_dir(self.out, "t", self.reth_genesis, promoted, self.starter)
        self.assertEqual(
            (self.out / "inputs" / "measurements.json").read_bytes(),
            promoted.read_bytes(),
        )

    def test_committed_starter_is_a_valid_input(self):
        # The starter shipped in this repo — what the docs point
        # --summit-genesis at — scaffolds cleanly and gets its namespace
        # filled. Its parity with summit's parameter set is pinned by
        # drift_test_manifest.SummitStarterDriftTests.
        committed = (
            Path(__file__).resolve().parents[4]
            / "tee/networks/summit-genesis-starter.toml"
        )
        init_network_dir(
            self.out, "testnet-1", self.reth_genesis, self.measurements, committed
        )
        summit = tomllib.loads((self.out / "inputs/summit-genesis.toml").read_text())
        self.assertEqual(summit["namespace"], "testnet-1")
        self.assertNotIn("eth_genesis_hash", summit)
        self.assertNotIn("validators", summit)

    def test_missing_input_file_is_a_gate_error(self):
        with self.assertRaisesRegex(GateError, "not found"):
            init_network_dir(
                self.out,
                "t",
                Path(self.tmp.name) / "no-such.json",
                self.measurements,
                self.starter,
            )

    def test_rejects_non_json_reth_genesis(self):
        self.reth_genesis.write_text("<html>not a genesis</html>")
        with self.assertRaisesRegex(GateError, "not valid JSON"):
            init_network_dir(
                self.out, "t", self.reth_genesis, self.measurements, self.starter
            )

    def test_rejects_non_toml_summit_genesis(self):
        self.starter.write_text("<html>not a genesis</html>")
        with self.assertRaisesRegex(GateError, "not valid TOML"):
            init_network_dir(
                self.out, "t", self.reth_genesis, self.measurements, self.starter
            )


class _FakeResponse:
    """The slice of requests.Response that read_input_source touches."""

    def __init__(self, url, content=b"", history=(), status=200):
        self.url = url
        self.content = content
        self.history = list(history)
        self.status = status

    def raise_for_status(self):
        if self.status >= 400:
            raise manifest_mod.requests.HTTPError(f"{self.status} for {self.url}")


class InitUrlInputTests(unittest.TestCase):
    """init inputs given as https:// URLs (fetches mocked; no network)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name) / "networks" / "testnet-1"
        self.bodies = {
            "https://example.test/dev.json": b'{"config": {"chainId": 5124}}',
            "https://example.test/measurements.json": (
                b'{"measurement_id": "img.vhd", "measurements": {}}'
            ),
            "https://example.test/starter.toml": b"leader_timeout_ms = 2000\n",
        }

    def _get(self, url, timeout=None):
        self.assertIsNotNone(timeout)  # never an unbounded fetch
        return _FakeResponse(url, content=self.bodies[url])

    def test_fetches_all_three_inputs(self):
        with mock.patch.object(manifest_mod.requests, "get", side_effect=self._get):
            init_network_dir(
                self.out,
                "testnet-1",
                "https://example.test/dev.json",
                "https://example.test/measurements.json",
                "https://example.test/starter.toml",
            )
        inputs = self.out / "inputs"
        self.assertEqual(
            (inputs / "reth-genesis.json").read_bytes(),
            self.bodies["https://example.test/dev.json"],
        )
        self.assertEqual(
            (inputs / "measurements.json").read_bytes(),
            self.bodies["https://example.test/measurements.json"],
        )
        summit = tomllib.loads((inputs / "summit-genesis.toml").read_text())
        self.assertEqual(summit["namespace"], "testnet-1")

    def test_rejects_http_url(self):
        with self.assertRaisesRegex(GateError, "https"):
            manifest_mod.read_input_source("http://example.test/dev.json")

    def test_http_error_is_a_gate_error(self):
        resp = _FakeResponse("https://example.test/gone.json", status=404)
        with mock.patch.object(manifest_mod.requests, "get", return_value=resp):
            with self.assertRaisesRegex(GateError, "failed to fetch"):
                manifest_mod.read_input_source("https://example.test/gone.json")

    def test_connection_error_is_a_gate_error(self):
        err = manifest_mod.requests.ConnectionError("refused")
        with mock.patch.object(manifest_mod.requests, "get", side_effect=err):
            with self.assertRaisesRegex(GateError, "failed to fetch"):
                manifest_mod.read_input_source("https://example.test/dev.json")

    def test_rejects_redirect_off_https(self):
        # requests follows an https -> http redirect; every hop must be https.
        final = _FakeResponse(
            "http://example.test/dev.json",
            content=b"{}",
            history=[_FakeResponse("https://example.test/dev.json", status=302)],
        )
        with mock.patch.object(manifest_mod.requests, "get", return_value=final):
            with self.assertRaisesRegex(GateError, "non-https"):
                manifest_mod.read_input_source("https://example.test/dev.json")

    def test_html_page_error_hints_at_raw_url(self):
        # The classic mistake: a GitHub blob page URL fetches HTML, not the
        # file. The parse gate catches it and points at the raw URL.
        url = "https://github.com/SeismicSystems/deploy/blob/main/dev.json"
        self.bodies[url] = b"<html>blob page</html>"
        with mock.patch.object(manifest_mod.requests, "get", side_effect=self._get):
            with self.assertRaisesRegex(GateError, "raw.githubusercontent.com"):
                init_network_dir(
                    self.out,
                    "t",
                    url,
                    "https://example.test/measurements.json",
                    "https://example.test/starter.toml",
                )


class FoundingSetTests(unittest.TestCase):
    """load_founding_set / load_harvest_records: pairing the harvest with
    the authored credentials and the cohort descriptors into the validator
    entries assemble pins."""

    ADDRESS = "0x" + "f3" * 20

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.net = Path(tmp.name)
        self.inputs = self.net / manifest_mod.INPUTS_DIRNAME
        self.harvest = self.inputs / manifest_mod.HARVEST_DIRNAME
        self.nodes = self.net / manifest_mod.NODES_DIRNAME
        self.harvest.mkdir(parents=True)
        self.nodes.mkdir()
        self._write_founders([self.ADDRESS])
        self._write_record("node-1")
        self._write_descriptor("node-1", "203.0.113.7")

    def _write_founders(self, obj) -> None:
        path = self.inputs / manifest_mod.FOUNDERS_FILENAME
        path.write_text(json.dumps(obj))

    def _write_record(
        self,
        name: str,
        node_key: str = "ab" * 32,
        consensus_key: str = "cd" * 48,
        **overrides,
    ) -> None:
        record: dict = {
            "harvest_nonce": "11" * 32,
            "node_public_key": node_key,
            "consensus_public_key": consensus_key,
            "evidence": {"attestation_type": "azure-tdx"},
        }
        record.update(overrides)
        record = {k: v for k, v in record.items() if v is not None}
        (self.harvest / f"{name}.json").write_text(json.dumps(record))

    def _write_descriptor(self, name: str, ip: str) -> None:
        (self.nodes / f"{name}.json").write_text(
            json.dumps({"public_ip": ip, "fqdn": f"{name}.example.com"})
        )

    def test_builds_validator_entries_sorted_by_node_name(self):
        # The authored credentials are positional: the i-th address pairs
        # with the i-th box in node-name order.
        self._write_founders([self.ADDRESS, "0x" + "aa" * 20])
        self._write_record("node-2", node_key="ef" * 32, consensus_key="ab" * 48)
        self._write_descriptor("node-2", "203.0.113.8")
        founding = load_founding_set(self.net)
        self.assertEqual(
            founding.validators,
            [
                {
                    "node_public_key": "ab" * 32,
                    "consensus_public_key": "cd" * 48,
                    "ip_address": f"203.0.113.7:{SUMMIT_CONSENSUS_PORT}",
                    "withdrawal_credentials": self.ADDRESS,
                },
                {
                    "node_public_key": "ef" * 32,
                    "consensus_public_key": "ab" * 48,
                    "ip_address": f"203.0.113.8:{SUMMIT_CONSENSUS_PORT}",
                    "withdrawal_credentials": "0x" + "aa" * 20,
                },
            ],
        )
        self.assertEqual(sorted(founding.records), ["node-1", "node-2"])

    def test_missing_harvest_burns_with_harvest_hint(self):
        for path in self.harvest.glob("*.json"):
            path.unlink()
        with self.assertRaisesRegex(GateError, "harvest"):
            load_founding_set(self.net)

    def test_harvested_box_without_credentials(self):
        self._write_record("node-2", node_key="ef" * 32, consensus_key="ab" * 48)
        self._write_descriptor("node-2", "203.0.113.8")
        with self.assertRaisesRegex(GateError, r"1 withdrawal credential\(s\)"):
            load_founding_set(self.net)

    def test_more_credentials_than_harvested_boxes(self):
        self._write_founders([self.ADDRESS, self.ADDRESS])
        with self.assertRaisesRegex(GateError, r"2 withdrawal credential\(s\)"):
            load_founding_set(self.net)

    def test_missing_descriptor_burns(self):
        (self.nodes / "node-1.json").unlink()
        with self.assertRaisesRegex(GateError, "re-found"):
            load_founding_set(self.net)

    def test_malformed_credentials_rejected(self):
        self._write_founders(["0x1234"])
        with self.assertRaisesRegex(GateError, "0x1234"):
            load_founding_set(self.net)

    def test_credentials_mapping_rejected(self):
        self._write_founders({"node-1": self.ADDRESS})
        with self.assertRaisesRegex(GateError, "expected a JSON array"):
            load_founding_set(self.net)

    def test_non_canonical_key_spelling_rejected(self):
        # Uppercase hex would digest differently under summit's v1 spelling
        # rules — rejected, never normalized.
        self._write_record("node-1", node_key="AB" * 32)
        with self.assertRaisesRegex(GateError, "node_public_key"):
            load_harvest_records(self.harvest)

    def test_record_without_evidence_rejected(self):
        self._write_record("node-1", evidence=None)
        with self.assertRaisesRegex(GateError, "evidence"):
            load_harvest_records(self.harvest)

    def test_duplicate_node_key_across_boxes_rejected(self):
        self._write_record("node-2", consensus_key="ab" * 48)
        with self.assertRaisesRegex(GateError, "node_public_key"):
            load_harvest_records(self.harvest)


class VerifyHarvestRecordsTests(unittest.TestCase):
    """The assemble-time re-verification driver (the verify-quote shell-out
    itself is exercised through the harvest tests, which mock the same
    subprocess boundary)."""

    RECORD = {
        "harvest_nonce": "11" * 32,
        "node_public_key": "ab" * 32,
        "consensus_public_key": "cd" * 48,
        "evidence": {"attestation_type": "azure-tdx"},
    }

    def test_verifies_every_record_against_the_policy_file(self):
        calls: list[tuple[str, bytes]] = []

        def verify_fn(name, record, policy_path):
            calls.append((name, policy_path.read_bytes()))
            return {"verified": True}

        records = {"node-2": dict(self.RECORD), "node-1": dict(self.RECORD)}
        verify_harvest_records(records, b"policy bytes", verify_fn=verify_fn)
        # Every record, deterministic order, against exactly the promoted
        # policy bytes.
        self.assertEqual(
            calls, [("node-1", b"policy bytes"), ("node-2", b"policy bytes")]
        )

    def test_failure_names_the_box_and_burns(self):
        def verify_fn(name, record, policy_path):
            if name == "node-2":
                raise GateError("quote verification failed")
            return {"verified": True}

        records = {"node-1": dict(self.RECORD), "node-2": dict(self.RECORD)}
        with self.assertRaisesRegex(GateError, "node-2.*\n.*not be pinned"):
            verify_harvest_records(records, b"policy", verify_fn=verify_fn)

    def test_missing_verifier_binary_is_a_gate_error(self):
        with self.assertRaisesRegex(GateError, "not found") as ctx:
            verify_harvest_records(
                {"node-1": dict(self.RECORD)},
                b"policy",
                verify_quote_bin="no-such-verify-quote",
            )
        # Tooling, not evidence: the preflight fails before the loop, so a
        # missing verifier never carries the burned-founding advice.
        self.assertNotIn("re-found", str(ctx.exception))


class VerifyNodeDeploymentTests(unittest.TestCase):
    """The `verify-quote deploy` shell-out contract. The verifier owns the
    whole relying-party flow (nonce, RPC, binding, verification); this side
    only assembles the argv and enforces the exit-0-plus-report contract."""

    ENDPOINT = "http://203.0.113.7:7878"
    REPORT = {"verified": True, "attestation_type": "azure-tdx", "pcrs": {}}

    def _verify(self, returncode=0, stdout=b"", stderr=b"", **kwargs):
        policy_at_call: list[bytes] = []

        def fake_run(cmd, **run_kwargs):
            # The policy tempfile is gone once verify_node_deployment
            # returns, so capture its bytes at call time.
            policy_at_call.append(Path(cmd[cmd.index("--policy") + 1]).read_bytes())
            return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

        with mock.patch.object(
            manifest_mod.subprocess, "run", side_effect=fake_run
        ) as run:
            report = verify_node_deployment(
                self.ENDPOINT,
                manifest_path=Path("/nets/devnet/network-manifest.json"),
                policy_bytes=b"policy bytes",
                verify_quote_bin="verify-quote",
                **kwargs,
            )
        return report, run, policy_at_call[0]

    def test_success_passes_endpoint_manifest_and_policy(self):
        report, run, policy = self._verify(stdout=json.dumps(self.REPORT).encode())
        self.assertTrue(report["verified"])
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[:2], ["verify-quote", "deploy"])
        self.assertIn(self.ENDPOINT, cmd)
        self.assertIn("/nets/devnet/network-manifest.json", cmd)
        # The verifier is challenged against exactly the promoted policy.
        self.assertEqual(policy, b"policy bytes")
        # Nothing goes over stdin: the verifier fetches the evidence itself.
        self.assertIsNone(run.call_args.kwargs["input"])

    def test_nonzero_exit_is_a_gate_error_with_stderr(self):
        with self.assertRaisesRegex(GateError, "binding mismatch"):
            self._verify(returncode=1, stderr=b"binding mismatch")

    def test_exit_zero_without_verified_report_is_a_gate_error(self):
        with self.assertRaisesRegex(GateError, "without a verified report"):
            self._verify(stdout=b'{"verified": false}')

    def test_optional_flags_forwarded(self):
        _, run, _ = self._verify(
            stdout=json.dumps(self.REPORT).encode(),
            pccs_url="https://pccs.example",
            override_azure_outdated_tcb=True,
        )
        cmd = run.call_args.args[0]
        self.assertIn("https://pccs.example", cmd)
        self.assertIn("--override-azure-outdated-tcb", cmd)

    def test_missing_verifier_binary_is_a_gate_error(self):
        with self.assertRaisesRegex(GateError, "not found"):
            verify_node_deployment(
                self.ENDPOINT,
                manifest_path=Path("/nets/devnet/network-manifest.json"),
                policy_bytes=b"policy",
                verify_quote_bin="no-such-verify-quote",
            )


class SetValidatorsTests(unittest.TestCase):
    """The `summit genesis set-validators` subprocess boundary (emission
    semantics — sorting, canonical rendering, reload-what-it-wrote — are
    pinned by summit's own tests)."""

    def test_missing_binary_is_a_gate_error(self):
        with self.assertRaisesRegex(GateError, "not found"):
            summit_set_validators(
                b"validators = []\n", [dict(VALIDATOR)], summit_bin="no-such-summit"
            )


class DirCliTests(unittest.TestCase):
    """assemble/validate take the network directory as their sole positional
    argument; only init handles loose files. Every derived path is absolute —
    the paths this CLI prints have to be clickable."""

    NET = Path("networks/testnet-1").resolve()

    def test_assemble_dir_resolution(self):
        args = manifest_mod._parse_assemble_args(["networks/testnet-1"])
        self.assertEqual(args.name, "testnet-1")
        self.assertEqual(args.admission_bin, DEFAULT_ADMISSION_BIN)
        self.assertEqual(args.verify_quote_bin, manifest_mod.DEFAULT_VERIFY_QUOTE_BIN)
        # assemble reads the authored inputs under inputs/.
        self.assertEqual(args.reth_genesis, self.NET / "inputs/reth-genesis.json")
        self.assertEqual(args.summit_genesis, self.NET / "inputs/summit-genesis.toml")
        self.assertEqual(args.measurements, self.NET / "inputs/measurements.json")
        self.assertEqual(args.out, self.NET)

    def test_assemble_requires_dir(self):
        with self.assertRaises(SystemExit):
            manifest_mod._parse_assemble_args([])

    def test_init_dir_positional_defaults_name(self):
        args = manifest_mod._parse_init_args(
            [
                "networks/testnet-1",
                "--reth-genesis",
                "g.json",
                "--measurements",
                "m.json",
                "--summit-genesis",
                "s.toml",
            ]
        )
        self.assertEqual(args.dir, self.NET)
        self.assertEqual(args.name, "testnet-1")

    def test_init_requires_summit_genesis(self):
        with self.assertRaises(SystemExit):
            manifest_mod._parse_init_args(
                [
                    "networks/testnet-1",
                    "--reth-genesis",
                    "g.json",
                    "--measurements",
                    "m.json",
                ]
            )

    def test_init_keeps_url_inputs_verbatim(self):
        # Inputs stay strings: Path() would collapse a URL's "//".
        url = "https://raw.githubusercontent.com/SeismicSystems/x/main/dev.json"
        args = manifest_mod._parse_init_args(
            [
                "networks/testnet-1",
                "--reth-genesis",
                url,
                "--measurements",
                "m.json",
                "--summit-genesis",
                "s.toml",
            ]
        )
        self.assertEqual(args.reth_genesis, url)

    def test_validate_dir_resolution(self):
        net = Path("networks/t").resolve()
        args = manifest_mod._parse_validate_args(["networks/t"])
        self.assertEqual(args.manifest, net / "network-manifest.json")
        self.assertEqual(args.admission_bin, DEFAULT_ADMISSION_BIN)
        # validate reads the *shipped* summit genesis, not the authored input.
        self.assertEqual(args.summit_genesis, net / "summit-genesis.toml")
        self.assertEqual(
            args.measurement_policy, net / "measurement-policy-bootstrap.json"
        )


if __name__ == "__main__":
    unittest.main()
