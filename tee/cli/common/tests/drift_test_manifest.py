"""Cross-repo drift guards (run via `make test-drift`).

These tests check this repo against the current state of its sibling repos,
reached either by fetching a pinned artifact over HTTP or by running a
binary built from a sibling branch. Every test needing something outside
this repo belongs here, so `make test` stays hermetic with nothing to skip
and every test runs in exactly one CI job. CI runs this module as its own
non-required job, where a failure names the exact cross-repo check.

The suite never skips — a missing prerequisite is a failure, because a
guard that quietly passes when its tooling is missing is how a committed
artifact goes stale unnoticed. It needs:

- network reach to raw.githubusercontent.com (the cross-repo tests fetch
  pinned artifacts from sibling repos);
- `seismic-tee-network` on PATH — the Rust deploy CLI from tee/cli/rust
  (`cargo install --path tee/cli/rust/network`; CI builds the workspace),
  whose `tools` group links the enclave crates at the rev the workspace
  pins: the admission compiler and the manifest renderer/parser under test
  here are that rev's;
- `seismic-reth` on PATH, for the `genesis-hash` subcommand (CI installs a
  prebuilt release with the setup-sreth action).

Run with:
    make test-drift
"""

import http.client
import json
import subprocess
import tomllib
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from eth_utils.crypto import keccak

from tee.cli.common import manifest as manifest_mod
from tee.cli.common.errors import ManifestSchemaError
from tee.cli.common.manifest import (
    MANIFEST_FILENAME,
    POLICY_FILENAME,
    RETH_GENESIS_FILENAME,
    SUMMIT_GENESIS_FILENAME,
    GateContext,
    GateError,
    compute_network_id,
    run_validation_gates,
    validate_manifest_schema,
)
from tee.cli.common.shell_outs import (
    DEFAULT_TEE_BIN,
    compile_measurement_policy,
    parse_manifest,
    promote_measurements,
    render_manifest,
    resolve_tee_bin,
)
from tee.cli.common.tests.test_manifest import (
    FIXTURE_MANIFEST,
    RAW_MEASUREMENTS,
    promoted_policy_bytes,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
NETWORKS_DIR = REPO_ROOT / "tee" / "networks"
TEE_BIN = resolve_tee_bin(DEFAULT_TEE_BIN)
MISSING_TEE_BIN = (
    f"{DEFAULT_TEE_BIN} (the Rust deploy CLI) not on PATH — this suite fails "
    "rather than skips; build it with `cargo install --path "
    "tee/cli/rust/network`"
)


def _fetch_live(url: str) -> bytes:
    """Fetch a cross-repo artifact, failing the calling test if it can't.

    An HTTP 4xx/5xx means the artifact moved or the ref is gone — a real
    drift signal, not flaky network — so it propagates directly. A
    transport-level failure (unreachable, timeout, truncated body) is
    retried once, then fails: this suite never skips.
    """
    last: Exception | None = None
    for _ in range(2):
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                return resp.read()
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, http.client.HTTPException) as e:
            last = e
    raise AssertionError(
        f"cross-repo artifact unreachable after retry: {last}"
    ) from last


def _committed_network_dirs() -> list[Path]:
    """Network directories git tracks.

    A real deployment writes its network directory here too, so enumerating
    the filesystem would validate whichever devnet the developer last
    founded. Only the committed ones are this repo's to keep passing.
    """
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", str(NETWORKS_DIR)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    return sorted(
        {
            (REPO_ROOT / path).parent
            for path in listed.split("\0")
            if path.endswith("/" + MANIFEST_FILENAME)
        }
    )


class ManifestBoundaryTests(unittest.TestCase):
    """The `render` / `parse` subprocess boundary, against the real
    manifest tool.

    Rendering and the strict schema are the enclave crate's — its fixture
    pins the canonical bytes and the network_id vector below. These cover
    the shell-out: what comes back, how a rejection surfaces, and that the
    committed example network still renders to its own bytes.
    """

    # The enclave crate's fixtures/network-manifest-v1.json vector: the
    # values of FIXTURE_MANIFEST, canonically rendered and hashed.
    FIXTURE_NETWORK_ID = (
        "0x8ef142e3f2bf15f8b201c4d8cda7848a9e846222c62b5615d4d36c7fccd98a24"
    )

    def setUp(self):
        self.assertIsNotNone(TEE_BIN, MISSING_TEE_BIN)

    def test_render_is_canonical_and_parse_accepts_it(self):
        # Hostile input formatting: reversed key order, no whitespace. The
        # tool owns the bytes; the id is the crate's pinned vector.
        shuffled = dict(reversed(list(FIXTURE_MANIFEST.items())))
        rendered = render_manifest(json.dumps(shuffled, separators=(",", ":")).encode())
        self.assertEqual(compute_network_id(rendered), self.FIXTURE_NETWORK_ID)
        self.assertEqual(render_manifest(rendered), rendered)
        self.assertEqual(validate_manifest_schema(rendered), FIXTURE_MANIFEST)

    def test_rejections_are_schema_errors_naming_the_field(self):
        bad = {**FIXTURE_MANIFEST, "tx_io_pk": "0x02ab"}
        with self.assertRaisesRegex(ManifestSchemaError, "tx_io_pk"):
            render_manifest(json.dumps(bad).encode())
        with self.assertRaisesRegex(ManifestSchemaError, "tx_io_pk"):
            parse_manifest(json.dumps(bad).encode())
        v2 = {**bad, "manifest_version": 2}
        with self.assertRaisesRegex(
            ManifestSchemaError, "unsupported manifest_version 2"
        ):
            parse_manifest(json.dumps(v2).encode())
        with self.assertRaises(ManifestSchemaError):
            parse_manifest(b"{not json")

    def test_committed_manifests_are_the_tools_rendering(self):
        # A committed network directory's manifest is exactly what the tool
        # renders from its own values: a rendering change would re-found
        # every existing network on its next assemble.
        networks = _committed_network_dirs()
        self.assertTrue(
            networks, f"no committed network directory under {NETWORKS_DIR}"
        )
        for network in networks:
            with self.subTest(network=network.name):
                committed = (network / MANIFEST_FILENAME).read_bytes()
                self.assertEqual(render_manifest(committed), committed)


class RuntimeCodeDriftTests(unittest.TestCase):
    """Cross-repo drift guard for the registry runtime-code pin.

    The admission CLI pins keccak256 of the canonical MeasurementRegistry
    deployed bytecode; the gates enforce that pin against the genesis alloc,
    so a stale pin already fails assembly loudly. This test is the early
    warning: the pin reported by the binary on PATH must match the artifact
    the reth genesis builder installs.
    """

    REGISTRY_ARTIFACT_URL = (
        "https://raw.githubusercontent.com/SeismicSystems/seismic/main/"
        "contracts/artifacts/MeasurementRegistry.json"
    )

    def test_admission_crate_pins_current_registry_runtime(self):
        self.assertIsNotNone(TEE_BIN, MISSING_TEE_BIN)
        report = compile_measurement_policy(promoted_policy_bytes())
        artifact = json.loads(_fetch_live(self.REGISTRY_ARTIFACT_URL))
        runtime = artifact["deployedBytecode"]["object"].removeprefix("0x")
        self.assertEqual(
            report["registry_runtime_code_hash"],
            "0x" + keccak(bytes.fromhex(runtime)).hex(),
        )


class PromoteBoundaryTests(unittest.TestCase):
    """The `promote` subprocess boundary, against the real CLI.

    Promotion semantics (register selection, normalization, pass-through,
    compile-validation) are pinned by the admission crate's own tests and
    fixtures; these cover the shell-out and what it surfaces. The
    missing-binary error path needs no CLI and stays in test_manifest.py.
    """

    def setUp(self):
        self.assertIsNotNone(TEE_BIN, MISSING_TEE_BIN)

    def test_promotes_make_measure_wrapper_to_schema_registers(self):
        raw = json.dumps({**RAW_MEASUREMENTS, "measurement_id": "img.vhd"}).encode()
        policy = json.loads(promote_measurements(raw))
        record = policy[0]
        # The stamped id carries into the record; the promoted record binds
        # exactly the named schema registers, single-value expected_any.
        self.assertEqual(record["measurement_id"], "img.vhd")
        self.assertEqual(record["attestation_type"], "azure-tdx")
        self.assertEqual(list(record["measurements"]), ["pcr4", "pcr9", "pcr11"])
        self.assertEqual(record["measurements"]["pcr4"], {"expected_any": ["ab" * 32]})

    def test_already_promoted_policy_passes_through_verbatim(self):
        # Odd-but-valid formatting must survive untouched: the manifest
        # commits to these exact bytes.
        raw = (
            b'[{"measurement_id": "x", "attestation_type": "azure-tdx",'
            b'   "measurements": {"4": {"expected": "'
            + b"ab" * 32
            + b'"}, "9": {"expected": "'
            + b"cd" * 32
            + b'"}, "11": {"expected": "'
            + b"ef" * 32
            + b'"}}}]'
        )
        self.assertEqual(promote_measurements(raw), raw)

    def test_promote_failure_surfaces_compiler_diagnostics(self):
        raw = json.dumps(
            {
                "measurement_id": "img.vhd",
                "measurements": {"4": {"expected": "ab" * 32}},
            }
        ).encode()
        with self.assertRaisesRegex(GateError, "pcr9"):
            promote_measurements(raw)

    def test_requires_measurement_id(self):
        # An unstamped wrapper has nothing to bind the policy to an image;
        # `init` gates on the stamp, and promotion refuses one that slipped
        # past it.
        raw = json.dumps(RAW_MEASUREMENTS).encode()
        with self.assertRaisesRegex(GateError, "measurement_id"):
            promote_measurements(raw)


class CompileBoundaryTests(unittest.TestCase):
    """The `compile` subprocess boundary: the report shape the gates consume."""

    def setUp(self):
        self.assertIsNotNone(TEE_BIN, MISSING_TEE_BIN)

    def test_compile_report_shape(self):
        policy = promoted_policy_bytes()
        report = compile_measurement_policy(policy)
        self.assertEqual(report["policy_hash"], manifest_mod._sha256_hex(policy))
        self.assertEqual(report["accepted_count"], 1)
        # 4 field slots (policy hashes, revision, count) + 1 status slot.
        self.assertEqual(len(report["registry_genesis_storage"]), 5)
        manifest_mod._check_hex(
            report["registry_runtime_code_hash"], 32, "registry_runtime_code_hash"
        )

    def test_compile_failure_is_a_gate_error(self):
        with self.assertRaisesRegex(GateError, "failed"):
            compile_measurement_policy(b"[]")


class SummitStarterDriftTests(unittest.TestCase):
    """The committed starter summit genesis tracks summit's parameter set.

    tee/networks/summit-genesis-starter.toml carries every founder-reviewable
    summit genesis parameter, explicitly — defaults included, so the founder
    reviews each one. Summit owns the schema, and its example_genesis.toml is
    a complete rendering of it, so a parameter summit adds or renames shows
    up as a key-set mismatch here. Values are not compared: each is a
    per-network choice.
    """

    SUMMIT_EXAMPLE_URL = (
        "https://raw.githubusercontent.com/SeismicSystems/summit/main/"
        "example_genesis.toml"
    )
    STARTER = NETWORKS_DIR / "summit-genesis-starter.toml"

    # Not parameters: the two fields assemble derives per network.
    DERIVED = {"eth_genesis_hash", "validators"}

    def test_starter_carries_summits_parameter_set(self):
        example = tomllib.loads(_fetch_live(self.SUMMIT_EXAMPLE_URL).decode())
        starter = tomllib.loads(self.STARTER.read_text())
        self.assertEqual(set(starter) & self.DERIVED, set())
        self.assertEqual(set(starter) | self.DERIVED, set(example))
        # The namespace slot ships empty: the visible fill-me init replaces
        # with the network name (unique per network — replay domain).
        self.assertEqual(starter["namespace"], "")


class CommittedNetworkDirTests(unittest.TestCase):
    """Committed network directories still pass their own gates.

    `tee/networks/example-devnet/` is the documented example of the
    network-directory shape — what `tee/README.md` and `tee/networks/README.md`
    point a reader at — and the hermetic suite builds its own artifacts, so
    nothing else reads it. Re-running the real gates over it keeps the
    example honest, and turns a semantic change in the admission compiler or
    in reth's genesis-header encoding into a failure here rather than a
    surprise at the next `assemble`.

    One gate does not recompute here: `summit genesis digest` needs a summit
    build, and summit publishes no release binary, so this test feeds the
    committed digest back in. Every other gate — genesis hash, chain id,
    policy hash, contract accounts, and the exact registry-account storage —
    runs against the real artifacts.
    """

    def test_committed_network_dirs_pass_their_gates(self):
        self.assertIsNotNone(TEE_BIN, MISSING_TEE_BIN)
        networks = _committed_network_dirs()
        self.assertTrue(
            networks, f"no committed network directory found under {NETWORKS_DIR}"
        )
        for network in networks:
            with self.subTest(network=network.name):
                manifest_bytes = (network / MANIFEST_FILENAME).read_bytes()
                manifest = validate_manifest_schema(manifest_bytes)
                digest = manifest["summit"]["genesis_config_digest"]
                run_validation_gates(
                    manifest,
                    GateContext(
                        reth_genesis=network / RETH_GENESIS_FILENAME,
                        summit_genesis=network / SUMMIT_GENESIS_FILENAME,
                        policy_bytes=(network / POLICY_FILENAME).read_bytes(),
                        digest_fn=lambda _path, digest=digest: digest,
                    ),
                )


if __name__ == "__main__":
    unittest.main()
