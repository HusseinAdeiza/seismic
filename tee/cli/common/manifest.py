"""NetworkManifest assembly and deploy-side validation gates.

The deploy tool is the manifest's *sole emitter*:
`network_id = SHA-256(file bytes)`, so the file must be rendered
deterministically once and then travel as opaque bytes through every hop
(deploy artifact -> `configure` merges it into the POST -> tdx-init ->
/run/seismic/conf/).
The node-side parser lives in the enclave repo's `seismic-network-manifest` crate:
https://github.com/SeismicSystems/enclave/tree/seismic/crates/network-manifest;
the schema here must stay in lockstep with it since the fixture-vector test in
tests/test_manifest.py pins both to the same bytes).

A network directory holds the authored inputs under `inputs/` and the
derived artifact set at the top level. Everything top-level is hash-pinned
by the manifest; everything under `inputs/` is provenance:

    inputs/reth-genesis.json             policy-free genesis
    inputs/summit-genesis.toml           summit parameter choices
    inputs/measurements.json             raw PCR map from `make measure`
    inputs/founder-withdrawal-credentials.json
                                         authored, one address per founder
    inputs/harvest/<node>.json           harvested founding pubkeys + quotes

    network-manifest.json         deploy-time facts; SHA-256 = network_id
    reth-genesis.json             the input genesis with the policy's
                                  compiled registry_genesis_storage
                                  injected into the registry account
                                  (the accepted admission IDs are a
                                  per-network fact); eth.genesis_hash
    summit-genesis.toml           the complete summit genesis every node
                                  boots from: the input with
                                  eth_genesis_hash filled and a validators
                                  set; summit.genesis_config_digest
    measurement-policy.json       Flashbots-compatible measurement
                                  allowlist promoted from the raw
                                  measurements; bootstrap_policy_hash

Each artifact is its input with derived fields filled in at assemble time;
the raw measurements become measurement-policy.json because promotion is a
format transformation.

Usage (one directory per network: `init` gathers the authored inputs — the
only command that takes loose files — then `assemble`/`validate` operate on
the directory):

    uv run python -m tee.cli.common.manifest init tee/networks/seismic-devnet-3 \
        --reth-genesis dev.json \
        --measurements ../seismic-images/build/measurements.json \
        --measurement-id seismic_2026-06-11.abc123.vhd
    # edit tee/networks/seismic-devnet-3/inputs/summit-genesis.toml:
    uv run python -m tee.cli.common.manifest assemble tee/networks/seismic-devnet-3
    uv run python -m tee.cli.common.manifest validate tee/networks/seismic-devnet-3
"""

import argparse
import base64
import hashlib
import json
import logging
import re
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from eth_utils import keccak

from tee.cli.common.logging_setup import setup_logging

logger = logging.getLogger(__name__)

MANIFEST_VERSION = 1

# Genesis-alloc addresses of the admission-policy contracts, named by role as
# in the manifest schema: registry = the measurement allowlist
# (MeasurementRegistry.sol), authority = its mutation authority (today
# MeasurementAuthorityDev.sol). The gates below check both exist in the
# alloc, and that the registry account holds the canonical runtime plus
# exactly the genesis storage its policy artifact compiles to.
DEFAULT_REGISTRY = "0x1000000000000000000000000000000000000001"
DEFAULT_AUTHORITY = "0x1000000000000000000000000000000000000002"

DEFAULT_ATTESTATION_TYPE = "azure-tdx"

# The shared policy-compiler CLI from the enclave repo's
# seismic-measurement-admission crate. Promotion and policy->genesis-storage
# compilation are schema knowledge (which registers form guest identity,
# which value forms are canonical, how admission IDs key registry storage),
# so deploy shells out to the one shared implementation instead of carrying
# a second one in Python.
DEFAULT_ADMISSION_BIN = "seismic-measurement-admission"

# Summit's node binary; its `genesis digest` subcommand computes
# summit.genesis_config_digest. The digest is SHA-256 over summit's
# domain-prefixed SSZ serialization of the complete genesis — summit's own
# definition of chain identity (its P2P and signing domains derive from it) —
# so deploy shells out to the one implementation instead of mirroring the
# SSZ layout in Python.
DEFAULT_SUMMIT_BIN = "summit"

# Today's hardcoded summit BLS domain separator.
# two chains sharing it can cross-replay BLS signatures.
# TODO: make it configurable
_SUMMIT_DEFAULT_NAMESPACE = "_SUMMIT"

MANIFEST_FILENAME = "network-manifest.json"
POLICY_FILENAME = "measurement-policy.json"
RETH_GENESIS_FILENAME = "reth-genesis.json"
# Both the authored input (under inputs/) and the shipped artifact (at the
# network directory top level) use this basename: same format, the
# artifact being the input with the derived fields filled in.
SUMMIT_GENESIS_FILENAME = "summit-genesis.toml"
MEASUREMENTS_FILENAME = "measurements.json"

# Authored inputs live under this subdir of a network directory: `manifest
# init` scaffolds them there, `assemble --dir` reads them there, and the
# derived artifact set is written to the top level — the shipped artifacts
# and the inputs they were derived from never collide.
INPUTS_DIRNAME = "inputs"

# Cohort descriptors (`up --network` output) live under this subdir of a
# network directory. Mutable infra state — regenerated per deploy, deleted by
# `down` — so it stays gitignored while the artifact set around it commits.
NODES_DIRNAME = "nodes"

# The founding cohort's inputs: founder-withdrawal-credentials.json is
# authored (node name -> withdrawal credentials); harvest/ holds what
# `network harvest` collected from the live cohort (pubkeys, quotes,
# verification reports) — provenance like measurements.json, but harvested
# rather than authored.
FOUNDERS_FILENAME = "founder-withdrawal-credentials.json"
HARVEST_DIRNAME = "harvest"


class ManifestSchemaError(Exception):
    """Manifest bytes don't satisfy the strict v1 schema."""


class GateError(Exception):
    """A cross-artifact validation gate failed (fail at deploy, not at boot)."""


def render_manifest(manifest: dict[str, Any]) -> bytes:
    """Deterministically render manifest bytes (the sole emitter).

    2-space indent, key-sorted, single trailing newline, UTF-8 — matching the
    enclave repo's network-manifest-v1.json fixture byte-for-byte so both
    stacks share test vectors. Never re-render an existing manifest: any byte
    change is a different network_id.
    """
    return (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def compute_network_id(manifest_bytes: bytes) -> str:
    """network_id = SHA-256 of the exact file bytes (`sha256sum` equivalent)."""
    return "0x" + hashlib.sha256(manifest_bytes).hexdigest()


def _sha256_hex(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()


def _check_hex(value: Any, nbytes: int, fieldname: str) -> None:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ManifestSchemaError(
            f"{fieldname}: expected 0x-prefixed hex string, got {value!r}"
        )
    digits = value[2:]
    if len(digits) != 2 * nbytes:
        raise ManifestSchemaError(
            f"{fieldname}: expected {nbytes}-byte hex string, got {value!r}"
        )
    try:
        bytes.fromhex(digits)
    except ValueError:
        raise ManifestSchemaError(
            f"{fieldname}: expected {nbytes}-byte hex string, got {value!r}"
        ) from None


def _check_keys(obj: dict[str, Any], expected: set[str], where: str) -> None:
    unknown = set(obj) - expected
    missing = expected - set(obj)
    if unknown:
        raise ManifestSchemaError(f"{where}: unknown keys {sorted(unknown)}")
    if missing:
        raise ManifestSchemaError(f"{where}: missing keys {sorted(missing)}")


def validate_manifest_schema(manifest_bytes: bytes) -> dict[str, Any]:
    """Strictly parse manifest bytes against the v1 schema.

    Mirrors NetworkManifestV1::from_json_bytes in
    enclave/crates/network-manifest: version probe first (so a future
    version reports "unsupported manifest_version", not "unknown key"), then
    reject unknown/missing keys and malformed hex.
    """
    try:
        obj = json.loads(manifest_bytes)
    except json.JSONDecodeError as e:
        raise ManifestSchemaError(f"not valid JSON: {e}") from None
    if not isinstance(obj, dict):
        raise ManifestSchemaError("manifest must be a JSON object")

    version = obj.get("manifest_version")
    if version != MANIFEST_VERSION:
        raise ManifestSchemaError(
            f"unsupported manifest_version {version!r}; "
            f"this validator implements v{MANIFEST_VERSION}"
        )

    _check_keys(
        obj,
        {
            "manifest_version",
            "name",
            "eth",
            "summit",
            "measurements",
        },
        "manifest",
    )
    if not isinstance(obj["name"], str):
        raise ManifestSchemaError(f"name: expected string, got {obj['name']!r}")

    eth = obj["eth"]
    if not isinstance(eth, dict):
        raise ManifestSchemaError("eth: expected object")
    _check_keys(eth, {"chain_id", "genesis_hash"}, "eth")
    # bool is an int subclass in Python; a JSON `true` must not pass as an id.
    if not isinstance(eth["chain_id"], int) or isinstance(eth["chain_id"], bool):
        raise ManifestSchemaError(
            f"eth.chain_id: expected integer, got {eth['chain_id']!r}"
        )
    _check_hex(eth["genesis_hash"], 32, "eth.genesis_hash")

    summit = obj["summit"]
    if not isinstance(summit, dict):
        raise ManifestSchemaError("summit: expected object")
    _check_keys(summit, {"genesis_config_digest", "namespace"}, "summit")
    _check_hex(summit["genesis_config_digest"], 32, "summit.genesis_config_digest")
    if not isinstance(summit["namespace"], str):
        raise ManifestSchemaError(
            f"summit.namespace: expected string, got {summit['namespace']!r}"
        )

    measurements = obj["measurements"]
    if not isinstance(measurements, dict):
        raise ManifestSchemaError("measurements: expected object")
    _check_keys(measurements, {"bootstrap_policy_hash", "contracts"}, "measurements")
    _check_hex(
        measurements["bootstrap_policy_hash"],
        32,
        "measurements.bootstrap_policy_hash",
    )
    contracts = measurements["contracts"]
    if not isinstance(contracts, dict):
        raise ManifestSchemaError("measurements.contracts: expected object")
    _check_keys(contracts, {"registry", "authority"}, "measurements.contracts")
    _check_hex(contracts["registry"], 20, "measurements.contracts.registry")
    _check_hex(contracts["authority"], 20, "measurements.contracts.authority")

    return obj


def _admission_cli(admission_bin: str, *args: str, input_bytes: bytes) -> bytes:
    """Run the shared policy-compiler CLI, feeding the document on stdin.

    Byte streams both ways: promoted policy bytes are hash-committed, so
    nothing may re-render them between the CLI and the artifact set.
    """
    cmd = [admission_bin, *args, "-"]
    try:
        result = subprocess.run(
            cmd, input=input_bytes, capture_output=True, timeout=120, check=True
        )
    except FileNotFoundError:
        raise GateError(
            f"{admission_bin!r} not found; build the policy-compiler CLI from "
            "the enclave repo (cargo build -p seismic-measurement-admission "
            "--features cli) or pass --admission-bin"
        ) from None
    except subprocess.TimeoutExpired:
        raise GateError(f"`{' '.join(cmd)}` timed out") from None
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or e.stdout or b"").decode("utf-8", "replace").strip()
        raise GateError(f"`{' '.join(cmd)}` failed: {detail}") from None
    return result.stdout


def promote_measurements(
    raw_bytes: bytes,
    measurement_id: str | None,
    attestation_type: str = DEFAULT_ATTESTATION_TYPE,
    admission_bin: str = DEFAULT_ADMISSION_BIN,
) -> bytes:
    """Promote `make measure` output into measurement-policy.json bytes.

    Shells out to the admission CLI's `promote`, which selects exactly the
    admission-schema registers from the raw measured-boot output, normalizes
    them to named `pcrN` keys binding a single-value `expected_any`, wraps
    them into one Flashbots-compatible policy record, and compiles its own
    output before returning it. If the input already *is* a record list it is
    passed through byte-verbatim (the manifest commits to the policy file by
    hash, so an already-published policy must not be re-rendered) — but still
    compiled, which is the whole promoted-policy validation: a document the
    compiler accepts is exactly a document that can seed registry genesis
    storage.
    """
    args = ["promote"]
    if measurement_id:
        args += ["--measurement-id", measurement_id]
    if attestation_type:
        args += ["--attestation-type", attestation_type]
    return _admission_cli(admission_bin, *args, input_bytes=raw_bytes)


def compile_measurement_policy(
    policy_bytes: bytes, admission_bin: str = DEFAULT_ADMISSION_BIN
) -> dict[str, Any]:
    """Compile a policy document via the admission CLI; returns its report:
    policy hash, admission IDs, the canonical registry runtime-code hash, and
    the complete registry genesis storage map."""
    report = _admission_cli(admission_bin, "compile", input_bytes=policy_bytes)
    return json.loads(report)


def inject_registry_genesis_storage(
    genesis_bytes: bytes, registry: str, report: dict[str, Any]
) -> bytes:
    """Write the compile report's registry_genesis_storage verbatim into the
    reth genesis's registry account, replacing any existing storage.

    Committed genesis files are policy-free (canonical registry runtime, empty
    storage — failing closed): the accepted admission IDs are a per-network
    fact, so `assemble` derives the storage from the network's policy
    document and writes it here. Replacement, not merge: the gate requires
    the account to hold exactly the compiled map, and wholesale replacement
    keeps re-assembly idempotent when the policy changes.
    """
    storage = report.get("registry_genesis_storage")
    if not isinstance(storage, dict) or not storage:
        raise GateError(
            "policy compile report carries no registry_genesis_storage; "
            "rebuild the admission CLI from the current enclave repo"
        )
    genesis = json.loads(genesis_bytes)
    alloc = genesis.get("alloc") if isinstance(genesis, dict) else None
    if not isinstance(alloc, dict):
        raise GateError("reth genesis has no alloc object")
    matches = [k for k in alloc if isinstance(k, str) and k.lower() == registry.lower()]
    if not matches:
        raise GateError(f"registry {registry} is not in the reth genesis alloc")
    if len(matches) > 1:
        raise GateError(
            f"reth genesis alloc lists registry {registry} twice under "
            "different hex spellings"
        )
    acct = alloc[matches[0]]
    if not isinstance(acct, dict):
        raise GateError(f"registry {registry} alloc entry is not an object")
    acct["storage"] = dict(storage)
    return (json.dumps(genesis, indent=2) + "\n").encode("utf-8")


def _hash_of_bytes(data: bytes, hash_fn: Callable[[Path], str], suffix: str) -> str:
    """Hash an artifact that exists only as bytes (assemble's derived copies):
    materialize it for the path-based shell-outs (`seismic-reth genesis-hash`,
    `summit genesis digest`)."""
    with tempfile.NamedTemporaryFile(suffix=suffix) as tf:
        tf.write(data)
        tf.flush()
        return hash_fn(Path(tf.name))


def reth_genesis_hash(reth_genesis: Path, reth_bin: str = "seismic-reth") -> str:
    """Compute eth_genesis_hash offline via `seismic-reth genesis-hash`.

    Same genesis parse path as `seismic-reth node --chain <file>`, so the
    result is exactly the genesis hash a node booted from this file computes.
    """
    cmd = [reth_bin, "genesis-hash", "--chain", str(reth_genesis)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, check=True
        )
    except FileNotFoundError:
        raise GateError(
            f"{reth_bin!r} not found; build seismic-reth (the genesis-hash "
            "subcommand) or pass --reth-bin"
        ) from None
    except subprocess.CalledProcessError as e:
        raise GateError(
            f"`{' '.join(cmd)}` failed: {e.stderr.strip() or e.stdout.strip()}"
        ) from None
    out = result.stdout.strip()
    _check_hex_or_gate(out, 32, f"`{' '.join(cmd)}` output")
    return out.lower()


def summit_config_digest(
    summit_genesis: Path, summit_bin: str = DEFAULT_SUMMIT_BIN
) -> str:
    """Compute summit.genesis_config_digest offline via `summit genesis digest`.

    The file is loaded down the same parse path a starting validator takes, so
    a successful digest doubles as a verdict that the genesis is well formed:
    anything this accepts a validator accepts.
    """
    cmd = [summit_bin, "genesis", "digest", str(summit_genesis)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, check=True
        )
    except FileNotFoundError:
        raise GateError(
            f"{summit_bin!r} not found; build summit (the `genesis digest` "
            "subcommand) or pass --summit-bin"
        ) from None
    except subprocess.CalledProcessError as e:
        raise GateError(
            f"`{' '.join(cmd)}` failed: {e.stderr.strip() or e.stdout.strip()}"
        ) from None
    out = result.stdout.strip()
    _check_hex_or_gate(out, 32, f"`{' '.join(cmd)}` output")
    return out.lower()


def _check_hex_or_gate(value: Any, nbytes: int, fieldname: str) -> None:
    try:
        _check_hex(value, nbytes, fieldname)
    except ManifestSchemaError as e:
        raise GateError(str(e)) from None


@dataclass
class GateContext:
    """Artifact set a manifest is validated against (deploy-side gates)."""

    reth_genesis: Path
    summit_genesis: Path
    policy_bytes: bytes
    reth_bin: str = "seismic-reth"
    admission_bin: str = DEFAULT_ADMISSION_BIN
    summit_bin: str = DEFAULT_SUMMIT_BIN
    # Injectable for tests; default to shelling out to seismic-reth, the
    # admission CLI, and summit respectively.
    genesis_hash_fn: Callable[[Path], str] | None = None
    compile_fn: Callable[[bytes], dict[str, Any]] | None = None
    digest_fn: Callable[[Path], str] | None = None
    # Set by `assemble` to its completed summit genesis (eth_genesis_hash and
    # a validators set injected into the authored input); gates then check
    # these bytes instead of re-reading summit_genesis from disk.
    summit_genesis_bytes: bytes | None = None
    # Set by `assemble` to its copy of the full genesis document, with the
    # compiled registry storage injected into the registry account; gates
    # then check these bytes instead of re-reading reth_genesis from disk.
    reth_genesis_bytes: bytes | None = None
    warnings: list[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        logger.warning(message)


def run_validation_gates(manifest: dict[str, Any], ctx: GateContext) -> None:
    """Deploy-time cross-artifact gates: every mismatch shows expected vs
    computed.

    Fails at deploy, not at boot. tdx-init re-runs the same checks over the
    embedded artifacts at POST time.
    """
    genesis_bytes = (
        ctx.reth_genesis_bytes
        if ctx.reth_genesis_bytes is not None
        else ctx.reth_genesis.read_bytes()
    )
    genesis = json.loads(genesis_bytes)

    # eth.chain_id == reth genesis config.chainId
    chain_id = genesis.get("config", {}).get("chainId")
    if manifest["eth"]["chain_id"] != chain_id:
        raise GateError(
            f"eth.chain_id mismatch: manifest has "
            f"{manifest['eth']['chain_id']}, reth genesis config.chainId "
            f"is {chain_id}"
        )

    # eth.genesis_hash == keccak(rlp(header(reth-genesis.json))), recomputed
    # offline by the seismic-reth genesis-hash subcommand.
    hash_fn = ctx.genesis_hash_fn or (
        lambda p: reth_genesis_hash(p, reth_bin=ctx.reth_bin)
    )
    computed = (
        _hash_of_bytes(genesis_bytes, hash_fn, suffix=".json")
        if ctx.reth_genesis_bytes is not None
        else hash_fn(ctx.reth_genesis)
    )
    if manifest["eth"]["genesis_hash"] != computed:
        raise GateError(
            f"eth.genesis_hash mismatch: manifest has "
            f"{manifest['eth']['genesis_hash']}, recomputed {computed} "
            f"from {ctx.reth_genesis}"
        )

    # summit.genesis_config_digest == `summit genesis digest` over the shipped
    # summit genesis: summit's own SSZ-domain digest (what its P2P and signing
    # domains derive from), not a byte hash of the file.
    summit_genesis_bytes = (
        ctx.summit_genesis_bytes
        if ctx.summit_genesis_bytes is not None
        else ctx.summit_genesis.read_bytes()
    )
    digest_fn = ctx.digest_fn or (
        lambda p: summit_config_digest(p, summit_bin=ctx.summit_bin)
    )
    computed_digest = (
        _hash_of_bytes(summit_genesis_bytes, digest_fn, suffix=".toml")
        if ctx.summit_genesis_bytes is not None
        else digest_fn(ctx.summit_genesis)
    )
    if manifest["summit"]["genesis_config_digest"] != computed_digest:
        raise GateError(
            f"summit.genesis_config_digest mismatch: manifest has "
            f"{manifest['summit']['genesis_config_digest']}, recomputed "
            f"{computed_digest} from {ctx.summit_genesis}"
        )

    # The genesis's embedded eth_genesis_hash and namespace must match the
    # manifest fields (the namespace is duplicated into the manifest so
    # verifiers don't need to parse TOML).
    summit_genesis = tomllib.loads(summit_genesis_bytes.decode("utf-8"))
    genesis_eth_hash = summit_genesis.get("eth_genesis_hash")
    if (
        not isinstance(genesis_eth_hash, str)
        or genesis_eth_hash.lower() != manifest["eth"]["genesis_hash"]
    ):
        raise GateError(
            f"summit genesis eth_genesis_hash is {genesis_eth_hash!r}, "
            f"manifest has {manifest['eth']['genesis_hash']}"
        )
    genesis_namespace = summit_genesis.get("namespace")
    if genesis_namespace != manifest["summit"]["namespace"]:
        raise GateError(
            f"summit genesis namespace is {genesis_namespace!r}, "
            f"manifest has {manifest['summit']['namespace']!r}"
        )
    if genesis_namespace == _SUMMIT_DEFAULT_NAMESPACE:
        ctx.warn(
            "summit namespace is the hardcoded default '_SUMMIT'; two chains "
            "running the same image can cross-replay BLS signatures"
        )

    # measurements.bootstrap_policy_hash == SHA-256(policy bytes)
    policy_hash = _sha256_hex(ctx.policy_bytes)
    if manifest["measurements"]["bootstrap_policy_hash"] != policy_hash:
        raise GateError(
            f"measurements.bootstrap_policy_hash mismatch: manifest has "
            f"{manifest['measurements']['bootstrap_policy_hash']}, computed "
            f"{policy_hash}"
        )

    # Contract addresses must exist in the genesis alloc (with code).
    alloc = {addr.lower(): acct for addr, acct in genesis.get("alloc", {}).items()}
    contracts = manifest["measurements"]["contracts"]
    for role in ("registry", "authority"):
        addr = contracts[role]
        acct = alloc.get(addr)
        if acct is None:
            raise GateError(
                f"measurements.contracts.{role} {addr} is not in the reth genesis alloc"
            )
        if not acct.get("code"):
            raise GateError(
                f"measurements.contracts.{role} {addr} has no code in the "
                "reth genesis alloc"
            )

    # Policy artifact <-> registry account consistency: compile the policy
    # with the shared admission CLI ("the compiler accepts it" is the whole
    # document validation) and require the registry genesis account to hold
    # the canonical runtime code plus exactly the compiled storage, so the
    # genesis hash commits to the reviewed policy and nothing else.
    compile_fn = ctx.compile_fn or (
        lambda b: compile_measurement_policy(b, admission_bin=ctx.admission_bin)
    )
    report = compile_fn(ctx.policy_bytes)
    if report.get("policy_hash") != policy_hash:
        raise GateError(
            f"policy compiler saw different document bytes: it reports "
            f"policy_hash {report.get('policy_hash')}, this file hashes to "
            f"{policy_hash}"
        )
    _validate_registry_account(
        alloc[contracts["registry"]], contracts["registry"], report
    )


def _norm_word(value: Any, where: str) -> str:
    """Normalize a 256-bit storage slot/word to 0x + 64 lowercase hex digits.

    Genesis JSON accepts unpadded and mixed-case hex; the compile report is
    already canonical. Comparing normalized words keeps the gate about
    values, not formatting.
    """
    if not isinstance(value, str):
        raise GateError(f"{where}: expected hex string, got {value!r}")
    try:
        word = int(value, 16)
    except ValueError:
        raise GateError(f"{where}: expected hex string, got {value!r}") from None
    if not 0 <= word < 2**256:
        raise GateError(f"{where}: {value!r} does not fit a 256-bit word")
    return f"0x{word:064x}"


def _validate_registry_account(
    acct: dict[str, Any], addr: str, report: dict[str, Any]
) -> None:
    """Exact registry-account gate: canonical runtime code and precisely the
    compiled genesis storage — every expected slot present with the expected
    word, and no unexplained slots."""
    for key in ("registry_runtime_code_hash", "registry_genesis_storage"):
        if key not in report:
            raise GateError(
                f"policy compile report carries no {key}; rebuild the "
                "admission CLI from the current enclave repo"
            )
    try:
        code = bytes.fromhex(acct["code"].removeprefix("0x"))
    except ValueError:
        raise GateError(f"registry {addr} code is not valid hex") from None
    code_hash = "0x" + keccak(code).hex()
    if code_hash != report.get("registry_runtime_code_hash"):
        raise GateError(
            f"registry {addr} code is not the canonical MeasurementRegistry "
            f"runtime: keccak256 is {code_hash}, the policy compiler pins "
            f"{report.get('registry_runtime_code_hash')} (rebuild the genesis "
            "from the current contract artifact)"
        )

    expected = {
        _norm_word(slot, "compile report storage slot"): _norm_word(
            value, f"compile report storage value at {slot}"
        )
        for slot, value in report.get("registry_genesis_storage", {}).items()
    }
    raw_storage = acct.get("storage", {})
    actual = {
        _norm_word(slot, f"registry {addr} storage slot"): _norm_word(
            value, f"registry {addr} storage value at {slot}"
        )
        for slot, value in raw_storage.items()
    }
    if len(actual) != len(raw_storage):
        raise GateError(
            f"registry {addr} genesis storage lists the same slot twice "
            "under different hex spellings"
        )
    if not actual:
        raise GateError(
            f"registry {addr} genesis storage is empty: the admission policy "
            "must be genesis-pinned. Seed the account with the compiled "
            "registry_genesis_storage (`seismic-measurement-admission "
            "compile measurement-policy.json`)"
        )
    if actual != expected:
        problems = [
            f"slot {slot} missing (expected {expected[slot]})"
            for slot in sorted(set(expected) - set(actual))
        ]
        problems += [
            f"slot {slot} unexplained (value {actual[slot]})"
            for slot in sorted(set(actual) - set(expected))
        ]
        problems += [
            f"slot {slot} holds {actual[slot]}, expected {expected[slot]}"
            for slot in sorted(set(actual) & set(expected))
            if actual[slot] != expected[slot]
        ]
        raise GateError(
            f"registry {addr} genesis storage does not match the compiled "
            f"policy artifact:\n  " + "\n  ".join(problems)
        )


@dataclass
class AssembledManifest:
    manifest_bytes: bytes
    manifest: dict[str, Any]
    policy_bytes: bytes
    # The completed summit genesis the manifest commits to (eth_genesis_hash
    # and a validators set filled into the authored input) — what
    # write_artifact_set ships as summit-genesis.toml.
    summit_genesis_bytes: bytes
    # The genesis copy the manifest commits to (compiled registry genesis
    # storage injected into the registry account) — what write_artifact_set
    # ships and eth.genesis_hash is computed from.
    reth_genesis_bytes: bytes
    network_id: str
    warnings: list[str]


def fill_eth_genesis_hash(genesis_bytes: bytes, eth_genesis_hash: str) -> bytes:
    """Set `eth_genesis_hash` in an authored summit genesis to the computed
    value.

    The hash is derived from reth-genesis.json — never authored — but summit's
    genesis-binary parser requires the field to be present in the TOML it
    reads, so the shipped copy must carry it. Any declared value is dropped
    (it can only be stale copy-paste, e.g. summit's example_genesis.toml) and
    the computed one is prepended — always valid TOML for a top-level key, and
    deterministic, so the filled copy is what `genesis_config_digest` commits
    to and the artifact set ships.
    """
    lines, in_table = [], False
    for line in genesis_bytes.splitlines(keepends=True):
        stripped = line.lstrip()
        # Top-level keys can only appear before the first table header; a
        # same-named key inside a table (none exists today) is left alone.
        if stripped.startswith(b"["):
            in_table = True
        if not in_table and re.match(rb"eth_genesis_hash\s*=", stripped):
            continue
        lines.append(line)
    stripped_bytes = b"".join(lines)
    if "eth_genesis_hash" in tomllib.loads(stripped_bytes.decode("utf-8")):
        raise GateError(
            "could not replace the authored file's declared eth_genesis_hash "
            "(unusual TOML layout); delete the line by hand — the value is "
            "derived from the reth genesis"
        )
    return f'eth_genesis_hash = "{eth_genesis_hash}"\n'.encode() + stripped_bytes


def assemble(
    name: str,
    reth_genesis: Path,
    summit_genesis: Path,
    policy_bytes: bytes,
    registry: str = DEFAULT_REGISTRY,
    authority: str = DEFAULT_AUTHORITY,
    reth_bin: str = "seismic-reth",
    admission_bin: str = DEFAULT_ADMISSION_BIN,
    summit_bin: str = DEFAULT_SUMMIT_BIN,
    genesis_hash_fn: Callable[[Path], str] | None = None,
    compile_fn: Callable[[bytes], dict[str, Any]] | None = None,
    digest_fn: Callable[[Path], str] | None = None,
) -> AssembledManifest:
    """Assemble, render, and gate-check a v1 network manifest.

    The summit genesis's `eth_genesis_hash` is derived from reth-genesis.json,
    never authored: whatever the input declares (if anything) is replaced with
    the computed value in the completed copy the artifact set ships —
    committed bytes never carry a stale hash. The manifest pins that
    completed genesis via summit's own config digest (`summit genesis
    digest`), which covers the consensus parameters and the validator set;
    an input without validators ships an empty placeholder set
    (`validators = []`).

    The registry account's genesis storage is likewise derived, not authored:
    the policy document is compiled and its registry_genesis_storage injected
    into the shipped genesis copy, so eth.genesis_hash commits to the
    reviewed policy. The gates then re-validate the injected copy against an
    independent compile of the same document.
    """
    input_genesis_bytes = reth_genesis.read_bytes()
    genesis = json.loads(input_genesis_bytes)
    chain_id = genesis.get("config", {}).get("chainId")
    if not isinstance(chain_id, int) or isinstance(chain_id, bool):
        raise GateError(f"reth genesis config.chainId is {chain_id!r}, not an int")

    authored_bytes = summit_genesis.read_bytes()
    authored = tomllib.loads(authored_bytes.decode("utf-8"))
    namespace = authored.get("namespace")
    if not isinstance(namespace, str):
        raise GateError(f"summit genesis has no namespace string (got {namespace!r})")

    compile_policy = compile_fn or (
        lambda b: compile_measurement_policy(b, admission_bin=admission_bin)
    )
    reth_genesis_bytes = inject_registry_genesis_storage(
        input_genesis_bytes, registry, compile_policy(policy_bytes)
    )

    hash_fn = genesis_hash_fn or (lambda p: reth_genesis_hash(p, reth_bin=reth_bin))
    eth_hash = _hash_of_bytes(reth_genesis_bytes, hash_fn, suffix=".json").lower()
    if "eth_genesis_hash" in authored and authored["eth_genesis_hash"] != eth_hash:
        logger.info(
            "replacing the authored eth_genesis_hash %s with the "
            "computed %s (the value is derived from the reth genesis)",
            authored["eth_genesis_hash"],
            eth_hash,
        )
    if "validators" not in authored:
        # summit requires the field to *parse* a genesis (its Genesis type has
        # no serde default); an input authored without a validator set ships
        # an empty placeholder.
        authored_bytes = b"validators = []\n" + authored_bytes
    summit_genesis_bytes = fill_eth_genesis_hash(authored_bytes, eth_hash)
    resolve_digest = digest_fn or (
        lambda p: summit_config_digest(p, summit_bin=summit_bin)
    )
    config_digest = _hash_of_bytes(
        summit_genesis_bytes, resolve_digest, suffix=".toml"
    ).lower()

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "name": name,
        "eth": {
            "chain_id": chain_id,
            "genesis_hash": eth_hash,
        },
        "summit": {
            "genesis_config_digest": config_digest,
            "namespace": namespace,
        },
        "measurements": {
            "bootstrap_policy_hash": _sha256_hex(policy_bytes),
            "contracts": {
                "registry": registry.lower(),
                "authority": authority.lower(),
            },
        },
    }

    manifest_bytes = render_manifest(manifest)
    # Self-check the emitted bytes through the same strict parse and gates a
    # consumer will apply, so a bad manifest never leaves the deploy tool.
    parsed = validate_manifest_schema(manifest_bytes)
    ctx = GateContext(
        reth_genesis=reth_genesis,
        summit_genesis=summit_genesis,
        policy_bytes=policy_bytes,
        reth_bin=reth_bin,
        admission_bin=admission_bin,
        summit_bin=summit_bin,
        genesis_hash_fn=genesis_hash_fn,
        compile_fn=compile_fn,
        digest_fn=digest_fn,
        summit_genesis_bytes=summit_genesis_bytes,
        reth_genesis_bytes=reth_genesis_bytes,
    )
    run_validation_gates(parsed, ctx)

    return AssembledManifest(
        manifest_bytes=manifest_bytes,
        manifest=parsed,
        policy_bytes=policy_bytes,
        summit_genesis_bytes=summit_genesis_bytes,
        reth_genesis_bytes=reth_genesis_bytes,
        network_id=compute_network_id(manifest_bytes),
        warnings=ctx.warnings,
    )


def write_artifact_set(
    out_dir: Path,
    assembled: AssembledManifest,
    force: bool = False,
) -> None:
    """Write the network artifact set: manifest, policy, and assemble's
    copies of the genesis artifacts the manifest commits to (registry
    storage injected into the reth genesis, the authored summit genesis
    completed with its derived fields).

    A manifest is immutable for the network's lifetime — refuse to overwrite
    an existing one unless forced.
    """
    manifest_path = out_dir / MANIFEST_FILENAME
    if manifest_path.exists() and not force:
        existing_id = compute_network_id(manifest_path.read_bytes())
        raise GateError(
            f"{manifest_path} already exists (network_id {existing_id}); "
            "a manifest is immutable — pass --force only for a new network"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(assembled.manifest_bytes)
    (out_dir / POLICY_FILENAME).write_bytes(assembled.policy_bytes)
    (out_dir / RETH_GENESIS_FILENAME).write_bytes(assembled.reth_genesis_bytes)
    (out_dir / SUMMIT_GENESIS_FILENAME).write_bytes(assembled.summit_genesis_bytes)


def starter_summit_genesis(name: str) -> str:
    """Starter authored summit genesis written by `manifest init` (values
    from summit's example_genesis.toml). Every value is a per-network choice
    for the founder to review; nothing in it is derived.
    """
    # json.dumps emits a valid TOML basic string for these simple values.
    return f"""\
# Summit network parameters. `manifest assemble` prepends the two derived
# fields above this header — eth_genesis_hash (from reth-genesis.json) and
# validators (the founding validator set — TEE-born keys gathered from the
# live cohort) — and ships the completed file as summit-genesis.toml.
# Review every value before founding a real network.
leader_timeout_ms = 2000
notarization_timeout_ms = 4000
nullify_timeout_ms = 4000
activity_timeout_views = 256
skip_timeout_views = 32
max_message_size_bytes = 10485760
namespace = {json.dumps(name)}
validator_minimum_stake = 32000000000
validator_maximum_stake = 32000000000
blocks_per_epoch = 10000
allowed_timestamp_future_ms = 10000
max_deposits_per_epoch = 3
max_withdrawals_per_epoch = 16
observers_per_validator = 5
"""


def stamp_measurement_id(raw_bytes: bytes, measurement_id: str) -> bytes:
    """Stamp the image artifact id into a make-measure measurements file.

    The id is a fact about the measurements (which image these PCRs measure),
    known when the file is copied in — so `init` records it in the file and
    `assemble` needs no --measurement-id. The measurements input is not
    hash-committed (the promoted policy derived from it is), so re-serializing
    it is safe.
    """
    raw = json.loads(raw_bytes)
    if isinstance(raw, list):
        raise GateError(
            "--measurement-id is meaningless for an already-promoted policy "
            "(each record carries its own measurement_id)"
        )
    if not isinstance(raw, dict):
        raise GateError(f"unrecognized measurements shape: {type(raw).__name__}")
    wrapper: dict[str, Any] = raw if "measurements" in raw else {"measurements": raw}
    # Accept a path to the artifact; the stamped id is the bare filename.
    wrapper["measurement_id"] = Path(measurement_id).name
    return (json.dumps(wrapper, indent=2, sort_keys=True) + "\n").encode("utf-8")


def init_network_dir(
    out_dir: Path,
    name: str,
    reth_genesis: Path,
    measurements: Path,
    summit_genesis: Path | None = None,
    measurement_id: str | None = None,
) -> list[Path]:
    """Scaffold a network directory's three authored inputs under inputs/.

    Copies the genesis and measurements in (stamping measurement_id into
    the latter when given), and writes a starter summit genesis
    (namespace = name) unless one is supplied to copy. The founder edits
    these in place, then `assemble --dir` derives the artifact set into the
    directory's top level — inputs and the committed artifacts live
    together, so the directory is the whole network (commit it for networks
    that matter).
    """
    measurements_bytes = measurements.read_bytes()
    if measurement_id is not None:
        measurements_bytes = stamp_measurement_id(measurements_bytes, measurement_id)
    contents = {
        RETH_GENESIS_FILENAME: reth_genesis.read_bytes(),
        MEASUREMENTS_FILENAME: measurements_bytes,
        SUMMIT_GENESIS_FILENAME: (
            summit_genesis.read_bytes()
            if summit_genesis is not None
            else starter_summit_genesis(name).encode()
        ),
    }
    inputs_dir = out_dir / INPUTS_DIRNAME
    existing = [n for n in contents if (inputs_dir / n).exists()]
    if existing:
        raise GateError(
            f"refusing to overwrite existing input(s) in {inputs_dir}: "
            f"{', '.join(existing)}"
        )
    inputs_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for filename, data in contents.items():
        path = inputs_dir / filename
        path.write_bytes(data)
        written.append(path)
    return written


def render_network_section(
    manifest_bytes: bytes,
    reth_genesis_bytes: bytes,
    summit_genesis_bytes: bytes,
    bootnodes: list[str],
) -> str:
    """Render the `[network]` config section tdx-init consumes.

    base64 keeps the artifacts opaque through the TOML hop (byte-exactness
    rule): tdx-init decodes and writes these exact bytes verbatim — the
    manifest to `network-manifest.json`, the reth genesis to
    `reth-genesis.json` (reth's `--chain`), the summit genesis to
    `summit-genesis.toml` (summit's `--genesis-path`).

    `bootnodes` is the enode set feeding reth's `--bootnodes` and — derived by
    tdx-init, `http://<host>:7878` with the node's own entry dropped — the
    attestation service's root-key fetch list. tdx-init requires the key, so
    it is always emitted; an empty list is valid only for the genesis node
    (nothing to dial, it mints `root_key` itself — the greenfield stage-1
    case), and 400s for a joiner.
    """
    manifest_b64 = base64.standard_b64encode(manifest_bytes).decode("ascii")
    reth_b64 = base64.standard_b64encode(reth_genesis_bytes).decode("ascii")
    summit_b64 = base64.standard_b64encode(summit_genesis_bytes).decode("ascii")
    # json.dumps emits valid TOML basic strings for enode URLs (ASCII).
    bootnodes_toml = ", ".join(json.dumps(b) for b in bootnodes)
    return (
        f'[network]\nmanifest_base64 = "{manifest_b64}"\n'
        f'reth_genesis_base64 = "{reth_b64}"\n'
        f'summit_genesis_base64 = "{summit_b64}"\n'
        f"bootnodes = [{bootnodes_toml}]\n"
    )


def validate_reth_genesis_matches(
    manifest: dict[str, Any], genesis_bytes: bytes
) -> None:
    """Client-side mirror of tdx-init's POST-time reth-genesis check: valid
    JSON whose config.chainId equals the manifest's eth.chain_id. Structural
    only — the genesis *hash* commitment (manifest eth.genesis_hash) is
    enforced by `assemble`/`validate` (via `seismic-reth genesis-hash`) and
    re-asserted against every node's reth at ceremony time.
    """
    try:
        genesis = json.loads(genesis_bytes)
    except json.JSONDecodeError as e:
        raise GateError(f"reth genesis is not valid JSON: {e}") from None
    config = genesis.get("config") if isinstance(genesis, dict) else None
    chain_id = config.get("chainId") if isinstance(config, dict) else None
    if not isinstance(chain_id, int) or isinstance(chain_id, bool):
        raise GateError(f"reth genesis config.chainId is {chain_id!r}, not an int")
    if chain_id != manifest["eth"]["chain_id"]:
        raise GateError(
            f"reth genesis config.chainId {chain_id} does not match the "
            f"manifest's eth.chain_id {manifest['eth']['chain_id']}"
        )


def validate_summit_genesis_matches(
    manifest: dict[str, Any], summit_genesis_bytes: bytes
) -> None:
    """Client-side mirror of tdx-init's POST-time summit-genesis check: valid
    TOML whose namespace equals the manifest's summit.namespace. Structural
    only — the *digest* commitment (manifest summit.genesis_config_digest) is
    enforced by `assemble`/`validate` (via `summit genesis digest`), and live
    nodes enforce agreement again by deriving their P2P and signing domains
    from that digest.
    """
    try:
        genesis = tomllib.loads(summit_genesis_bytes.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise GateError(f"summit genesis is not valid TOML: {e}") from None
    namespace = genesis.get("namespace")
    if not isinstance(namespace, str):
        raise GateError(f"summit genesis namespace is {namespace!r}, not a string")
    if namespace != manifest["summit"]["namespace"]:
        raise GateError(
            f"summit genesis namespace {namespace!r} does not match the "
            f"manifest's summit.namespace {manifest['summit']['namespace']!r}"
        )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m tee.cli.common.manifest", description=__doc__
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_reth_bin(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--reth-bin",
            default="seismic-reth",
            help="seismic-reth binary used to recompute eth_genesis_hash",
        )

    def add_admission_bin(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--admission-bin",
            default=DEFAULT_ADMISSION_BIN,
            help="policy-compiler CLI used to promote measurements and "
            "compile the policy into registry genesis storage",
        )

    def add_summit_bin(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--summit-bin",
            default=DEFAULT_SUMMIT_BIN,
            help="summit binary whose `genesis digest` subcommand computes "
            "summit.genesis_config_digest",
        )

    ini = sub.add_parser("init", help="scaffold a network directory's authored inputs")
    ini.add_argument("dir", type=Path, help="network directory to create")
    ini.add_argument(
        "--name",
        default=None,
        help="network name for the starter summit genesis's namespace; "
        "default: the directory's basename (which is also what assemble "
        "uses as the manifest name)",
    )
    ini.add_argument(
        "--reth-genesis",
        type=Path,
        required=True,
        help="reth genesis, copied in as "
        f"{INPUTS_DIRNAME}/{RETH_GENESIS_FILENAME}. Required: an external "
        "fact (chain state + contract alloc) init cannot invent",
    )
    ini.add_argument(
        "--measurements",
        type=Path,
        required=True,
        help="seismic-images make-measure output (or promoted policy), "
        f"copied in as {INPUTS_DIRNAME}/{MEASUREMENTS_FILENAME}. Required: "
        "the PCRs of a real published image, never generated",
    )
    ini.add_argument(
        "--summit-genesis",
        type=Path,
        default=None,
        help="authored summit genesis to copy in verbatim. Optional: unlike "
        "the two inputs above it holds only per-network parameter choices, "
        "so the default writes an editable starter with namespace = <name>",
    )
    ini.add_argument(
        "--measurement-id",
        default=None,
        help="image artifact filename the measurements belong to; stamped "
        f"into {INPUTS_DIRNAME}/{MEASUREMENTS_FILENAME} so assemble needs "
        "no --measurement-id",
    )

    asm = sub.add_parser(
        "assemble",
        help="derive the artifact set from a network directory's inputs",
    )
    asm.add_argument(
        "dir",
        type=Path,
        help=f"network directory from `manifest init`: reads its "
        f"{INPUTS_DIRNAME}/ ({RETH_GENESIS_FILENAME}, "
        f"{SUMMIT_GENESIS_FILENAME}, {MEASUREMENTS_FILENAME}), takes the "
        "network name from its basename, and writes the artifact set at "
        "the top level",
    )
    asm.add_argument(
        "--measurement-id",
        help="policy record id (image artifact filename); overrides the one "
        f"init stamped into {INPUTS_DIRNAME}/{MEASUREMENTS_FILENAME}",
    )
    asm.add_argument("--attestation-type", default=DEFAULT_ATTESTATION_TYPE)
    asm.add_argument(
        "--registry",
        default=DEFAULT_REGISTRY,
        help="measurement-registry contract address in the genesis alloc",
    )
    asm.add_argument(
        "--authority",
        default=DEFAULT_AUTHORITY,
        help="registry mutation-authority contract address",
    )
    asm.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing manifest (a new network identity)",
    )
    add_reth_bin(asm)
    add_admission_bin(asm)
    add_summit_bin(asm)

    val = sub.add_parser(
        "validate", help="re-run all gates over an assembled network directory"
    )
    val.add_argument(
        "dir",
        type=Path,
        help="network directory: audits the artifact set `assemble` wrote "
        "there (manifest, summit genesis, policy) against its reth genesis",
    )
    add_reth_bin(val)
    add_admission_bin(val)
    add_summit_bin(val)

    args = parser.parse_args(argv)

    if args.command == "init":
        args.name = args.name or args.dir.resolve().name
    elif args.command == "assemble":
        args.name = args.dir.resolve().name
        inputs_dir = args.dir / INPUTS_DIRNAME
        args.reth_genesis = inputs_dir / RETH_GENESIS_FILENAME
        args.summit_genesis = inputs_dir / SUMMIT_GENESIS_FILENAME
        args.measurements = inputs_dir / MEASUREMENTS_FILENAME
        args.out = args.dir
    elif args.command == "validate":
        args.manifest = args.dir / MANIFEST_FILENAME
        args.reth_genesis = args.dir / RETH_GENESIS_FILENAME
        args.summit_genesis = args.dir / SUMMIT_GENESIS_FILENAME
        args.measurement_policy = args.dir / POLICY_FILENAME
    return args


def main() -> None:
    setup_logging()
    args = _parse_args()
    try:
        if args.command == "init":
            written = init_network_dir(
                args.dir,
                args.name,
                args.reth_genesis,
                args.measurements,
                args.summit_genesis,
                args.measurement_id,
            )
            for path in written:
                logger.info("wrote %s", path)
            id_hint = (
                ""
                if args.measurement_id
                else " --measurement-id <image-artifact-filename>"
            )
            print(
                f"Scaffolded {args.dir}. Edit the inputs (at minimum review "
                f"{INPUTS_DIRNAME}/{SUMMIT_GENESIS_FILENAME}), then:\n"
                f"  seismic-tee-network manifest assemble {args.dir}{id_hint}"
            )
        elif args.command == "assemble":
            missing = [
                p
                for p in (args.reth_genesis, args.summit_genesis, args.measurements)
                if not p.exists()
            ]
            if missing:
                raise GateError(
                    "missing authored input(s): "
                    + ", ".join(str(p) for p in missing)
                    + f" — authored inputs live under {INPUTS_DIRNAME}/; "
                    "scaffold them with `manifest init`"
                )
            policy_bytes = promote_measurements(
                args.measurements.read_bytes(),
                args.measurement_id,
                args.attestation_type,
                admission_bin=args.admission_bin,
            )
            assembled = assemble(
                name=args.name,
                reth_genesis=args.reth_genesis,
                summit_genesis=args.summit_genesis,
                policy_bytes=policy_bytes,
                registry=args.registry,
                authority=args.authority,
                reth_bin=args.reth_bin,
                admission_bin=args.admission_bin,
                summit_bin=args.summit_bin,
            )
            write_artifact_set(args.out, assembled, force=args.force)
            logger.info("wrote %s", args.out / MANIFEST_FILENAME)
            logger.info("wrote %s", args.out / POLICY_FILENAME)
            logger.info("wrote %s", args.out / RETH_GENESIS_FILENAME)
            print(f"network_id: {assembled.network_id}")
        else:
            manifest_bytes = args.manifest.read_bytes()
            manifest = validate_manifest_schema(manifest_bytes)
            ctx = GateContext(
                reth_genesis=args.reth_genesis,
                summit_genesis=args.summit_genesis,
                policy_bytes=args.measurement_policy.read_bytes(),
                reth_bin=args.reth_bin,
                admission_bin=args.admission_bin,
                summit_bin=args.summit_bin,
            )
            run_validation_gates(manifest, ctx)
            print(f"network_id: {compute_network_id(manifest_bytes)}")
            logger.info("all validation gates passed")
    except (GateError, ManifestSchemaError) as e:
        logger.error("%s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
