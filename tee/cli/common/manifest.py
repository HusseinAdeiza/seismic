"""NetworkManifest assembly and deploy-side validation gates.

The deploy tool is the manifest's *sole emitter*:
`network_id = SHA-256(file bytes)`, so the file must be rendered
deterministically once and then travel as opaque bytes through every hop
(deploy artifact -> `configure` merges it into the POST -> tdx-init ->
/run/seismic/conf/).
The node-side parser lives in
enclave/crates/seismic-attestation/src/manifest.rs; the schema here must stay
in lockstep with it (the fixture-vector test in tests/test_manifest.py pins
both to the same bytes).

Two artifacts are produced:
- network-manifest.json    deploy-time facts; hashed into network_id
- measurement-policy.json  Flashbots-compatible measurement allowlist,
                           promoted from seismic-images' `make measure`
                           output and committed to by the manifest via
                           measurements.bootstrap_policy_hash

Usage (one directory per network: `init` gathers the authored inputs — the
only command that takes loose files — then `assemble`/`validate` operate on
the directory):

    uv run python -m tee.cli.common.manifest init tee/networks/seismic-devnet-3 \
        --reth-genesis dev.json \
        --measurements ../seismic-images/build/measurements.json \
        --measurement-id seismic_2026-06-11.abc123.vhd
    # edit tee/networks/seismic-devnet-3/summit-template.toml, then:
    uv run python -m tee.cli.common.manifest assemble tee/networks/seismic-devnet-3
    uv run python -m tee.cli.common.manifest validate tee/networks/seismic-devnet-3
"""

import argparse
import base64
import hashlib
import json
import logging
import re
import secrets
import subprocess
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tee.cli.common.logging_setup import setup_logging

logger = logging.getLogger(__name__)

MANIFEST_VERSION = 1

# Genesis-alloc addresses of the admission-policy contracts, named by role as
# in the manifest schema: registry = the measurement allowlist (today
# UpgradeOperator.sol), authority = its mutation authority (today
# MultisigUpgradeOperator.sol). The gates below check both exist in the alloc.
DEFAULT_REGISTRY = "0x1000000000000000000000000000000000000001"
DEFAULT_AUTHORITY = "0x1000000000000000000000000000000000000002"

DEFAULT_ATTESTATION_TYPE = "azure-tdx"

# Today's hardcoded summit BLS domain separator (Summit TODO 3 parameterizes
# it); two chains sharing it can cross-replay BLS signatures.
_SUMMIT_DEFAULT_NAMESPACE = "_SUMMIT"

MANIFEST_FILENAME = "network-manifest.json"
POLICY_FILENAME = "measurement-policy.json"
RETH_GENESIS_FILENAME = "reth-genesis.json"
SUMMIT_TEMPLATE_FILENAME = "summit-genesis-template.toml"

# Authored-input filenames inside a network directory (`manifest init`).
# Distinct from the shipped artifact-set names above so `assemble --dir`
# never overwrites an authored input. reth-genesis.json is shared
# deliberately: its artifact copy is byte-verbatim, so the same-name write
# is an identity.
INPUT_SUMMIT_TEMPLATE_FILENAME = "summit-template.toml"
INPUT_MEASUREMENTS_FILENAME = "measurements.json"

# Cohort descriptors (`up --network` output) live under this subdir of a
# network directory. Mutable infra state — regenerated per deploy, deleted by
# `down` — so it stays gitignored while the artifact set around it commits.
NODES_DIRNAME = "nodes"


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

    Mirrors NetworkManifest::from_json_bytes in
    enclave/crates/seismic-attestation: version probe first (so a future
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
            "genesis_nonce",
            "eth",
            "summit",
            "measurements",
        },
        "manifest",
    )
    if not isinstance(obj["name"], str):
        raise ManifestSchemaError(f"name: expected string, got {obj['name']!r}")
    _check_hex(obj["genesis_nonce"], 32, "genesis_nonce")

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
    _check_keys(summit, {"genesis_template_hash", "namespace"}, "summit")
    _check_hex(summit["genesis_template_hash"], 32, "summit.genesis_template_hash")
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


def promote_measurements(
    raw_bytes: bytes,
    measurement_id: str | None,
    attestation_type: str = DEFAULT_ATTESTATION_TYPE,
) -> bytes:
    """Promote `make measure` output into measurement-policy.json bytes.

    Accepts the shapes seismic-images produces (a bare PCR map, or an object
    wrapping one under "measurements") and wraps them into the
    Flashbots-compatible list-of-records format that attested-tls'
    `attestation` crate parses. If the input already *is* that list format it
    is passed through byte-verbatim — the manifest commits to the policy file
    by hash, so an already-published policy must not be re-rendered.
    """
    try:
        raw = json.loads(raw_bytes)
    except json.JSONDecodeError as e:
        raise GateError(f"measurements file is not valid JSON: {e}") from None

    if isinstance(raw, list):
        _validate_policy_records(raw)
        return raw_bytes

    if not isinstance(raw, dict):
        raise GateError(f"unrecognized measurements shape: {type(raw).__name__}")

    pcrs = raw.get("measurements", raw)
    measurement_id = measurement_id or raw.get("measurement_id")
    if measurement_id:
        # Accept a path to the artifact; the published record id is the bare
        # filename (a real id never contains a separator).
        measurement_id = Path(measurement_id).name
    attestation_type = raw.get("attestation_type", attestation_type)
    if not measurement_id:
        raise GateError(
            "measurements file carries no measurement_id; pass "
            "--measurement-id (conventionally the registered image "
            "artifact filename)"
        )
    records = [
        {
            "measurement_id": measurement_id,
            "attestation_type": attestation_type,
            "measurements": pcrs,
        }
    ]
    _validate_policy_records(records)
    return (
        json.dumps(records, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _validate_policy_records(records: list[Any]) -> None:
    if not records:
        raise GateError("measurement policy has no records")
    for i, rec in enumerate(records):
        where = f"measurement policy record {i}"
        if not isinstance(rec, dict):
            raise GateError(f"{where}: expected object")
        for key in ("measurement_id", "attestation_type"):
            if not isinstance(rec.get(key), str) or not rec[key]:
                raise GateError(f"{where}: missing or empty {key}")
        pcrs = rec.get("measurements")
        if not isinstance(pcrs, dict) or not pcrs:
            raise GateError(f"{where}: missing or empty measurements map")
        for reg, entry in pcrs.items():
            if not str(reg).isdigit():
                raise GateError(f"{where}: register key {reg!r} is not an index")
            if not isinstance(entry, dict) or not isinstance(
                entry.get("expected"), str
            ):
                raise GateError(
                    f"{where}: register {reg} must be {{'expected': '<hex>'}}"
                )


def reth_genesis_hash(reth_genesis: Path, reth_bin: str = "seismic-reth") -> str:
    """Compute eth_genesis_hash offline via `seismic-reth genesis-hash`.

    Same chain-spec parse path as `seismic-reth node --chain <file>`, so the
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


def _check_hex_or_gate(value: Any, nbytes: int, fieldname: str) -> None:
    try:
        _check_hex(value, nbytes, fieldname)
    except ManifestSchemaError as e:
        raise GateError(str(e)) from None


@dataclass
class GateContext:
    """Artifact set a manifest is validated against (deploy-side gates)."""

    reth_genesis: Path
    summit_template: Path
    policy_bytes: bytes
    reth_bin: str = "seismic-reth"
    # Injectable for tests; defaults to shelling out to seismic-reth.
    genesis_hash_fn: Callable[[Path], str] | None = None
    # Set by `assemble` to its filled template copy (eth_genesis_hash injected
    # when the authored file omits it); gates then check these bytes instead
    # of re-reading summit_template from disk.
    summit_template_bytes: bytes | None = None
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
    genesis = json.loads(ctx.reth_genesis.read_bytes())

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
    computed = hash_fn(ctx.reth_genesis)
    if manifest["eth"]["genesis_hash"] != computed:
        raise GateError(
            f"eth.genesis_hash mismatch: manifest has "
            f"{manifest['eth']['genesis_hash']}, recomputed {computed} "
            f"from {ctx.reth_genesis}"
        )

    # summit.genesis_template_hash == SHA-256(template bytes)
    template_bytes = (
        ctx.summit_template_bytes
        if ctx.summit_template_bytes is not None
        else ctx.summit_template.read_bytes()
    )
    template_hash = _sha256_hex(template_bytes)
    if manifest["summit"]["genesis_template_hash"] != template_hash:
        raise GateError(
            f"summit.genesis_template_hash mismatch: manifest has "
            f"{manifest['summit']['genesis_template_hash']}, computed "
            f"{template_hash} from {ctx.summit_template}"
        )

    # The template's embedded eth_genesis_hash and namespace must match the
    # manifest fields (the namespace is duplicated into the manifest so
    # verifiers don't need to parse TOML).
    template = tomllib.loads(template_bytes.decode("utf-8"))
    template_eth_hash = template.get("eth_genesis_hash")
    if (
        not isinstance(template_eth_hash, str)
        or template_eth_hash.lower() != manifest["eth"]["genesis_hash"]
    ):
        raise GateError(
            f"summit template eth_genesis_hash is {template_eth_hash!r}, "
            f"manifest has {manifest['eth']['genesis_hash']}"
        )
    template_namespace = template.get("namespace")
    if template_namespace != manifest["summit"]["namespace"]:
        raise GateError(
            f"summit template namespace is {template_namespace!r}, "
            f"manifest has {manifest['summit']['namespace']!r}"
        )
    if template_namespace == _SUMMIT_DEFAULT_NAMESPACE:
        ctx.warn(
            "summit namespace is the hardcoded default '_SUMMIT'; two chains "
            "running the same image can cross-replay BLS signatures "
            "(Summit TODO 3)"
        )
    # The shipped copy always carries a `validators` key (assemble fills an
    # empty placeholder for summit's parser); only *entries* are suspect.
    if template.get("validators"):
        ctx.warn(
            "summit template still contains [[validators]] entries; the "
            "boot-time fill-genesis-template flow (Summit TODOs 1-2) expects "
            "a template without them"
        )

    # measurements.bootstrap_policy_hash == SHA-256(policy bytes)
    policy_hash = _sha256_hex(ctx.policy_bytes)
    if manifest["measurements"]["bootstrap_policy_hash"] != policy_hash:
        raise GateError(
            f"measurements.bootstrap_policy_hash mismatch: manifest has "
            f"{manifest['measurements']['bootstrap_policy_hash']}, computed "
            f"{policy_hash}"
        )
    _validate_policy_records(json.loads(ctx.policy_bytes))

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

    # Policy artifact <-> registry genesis storage consistency. The initial
    # measurements are not genesis-pinned yet, so there is nothing to compare
    # against — but if storage shows up, this gate must trip until the
    # comparison is built, rather than silently passing.
    registry_storage = alloc[contracts["registry"]].get("storage", {})
    if registry_storage:
        raise GateError(
            "registry genesis storage is populated but the policy artifact "
            "<-> genesis storage consistency check is not implemented; "
            "implement it before deploying a genesis-pinned admission policy"
        )
    ctx.warn(
        "registry genesis storage is empty: the initial admission policy is "
        "not genesis-pinned yet, so the policy<->storage consistency gate "
        "is vacuous"
    )


@dataclass
class AssembledManifest:
    manifest_bytes: bytes
    manifest: dict[str, Any]
    policy_bytes: bytes
    # The template copy the manifest commits to (eth_genesis_hash filled if
    # the authored file omitted it) — what write_artifact_set ships.
    summit_template_bytes: bytes
    network_id: str
    warnings: list[str]


def fill_template_genesis_hash(template_bytes: bytes, eth_genesis_hash: str) -> bytes:
    """Set `eth_genesis_hash` in a summit template to the computed value.

    The hash is derived from reth-genesis.json — never authored — but summit's
    genesis-binary parser requires the field to be present in the TOML it
    reads, so the shipped copy must carry it. Any declared value is dropped
    (it can only be stale copy-paste, e.g. summit's example_genesis.toml) and
    the computed one is prepended — always valid TOML for a top-level key, and
    deterministic, so the filled copy is what `genesis_template_hash` commits
    to and the ceremony ships.
    """
    lines, in_table = [], False
    for line in template_bytes.splitlines(keepends=True):
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
            "could not replace the template's declared eth_genesis_hash "
            "(unusual TOML layout); delete the line by hand — the value is "
            "derived from the reth genesis"
        )
    return f'eth_genesis_hash = "{eth_genesis_hash}"\n'.encode() + stripped_bytes


def assemble(
    name: str,
    reth_genesis: Path,
    summit_template: Path,
    policy_bytes: bytes,
    registry: str = DEFAULT_REGISTRY,
    authority: str = DEFAULT_AUTHORITY,
    reth_bin: str = "seismic-reth",
    genesis_nonce: bytes | None = None,
    genesis_hash_fn: Callable[[Path], str] | None = None,
) -> AssembledManifest:
    """Assemble, render, and gate-check a v1 network manifest.

    genesis_nonce defaults to fresh OsRng bytes — the clone-deployment
    uniquifier; two networks spun from otherwise identical artifacts must not
    share a network_id. Only tests should pass an explicit nonce.

    The summit template's `eth_genesis_hash` is derived from reth-genesis.json,
    never authored: whatever the input declares (if anything) is replaced with
    the computed value in the copy that `genesis_template_hash` commits to and
    the artifact set ships — committed bytes never carry a stale hash.
    """
    genesis = json.loads(reth_genesis.read_bytes())
    chain_id = genesis.get("config", {}).get("chainId")
    if not isinstance(chain_id, int) or isinstance(chain_id, bool):
        raise GateError(f"reth genesis config.chainId is {chain_id!r}, not an int")

    template_bytes = summit_template.read_bytes()
    template = tomllib.loads(template_bytes.decode("utf-8"))
    namespace = template.get("namespace")
    if not isinstance(namespace, str):
        raise GateError(f"summit template has no namespace string (got {namespace!r})")

    hash_fn = genesis_hash_fn or (lambda p: reth_genesis_hash(p, reth_bin=reth_bin))
    eth_hash = hash_fn(reth_genesis).lower()
    if "eth_genesis_hash" in template and template["eth_genesis_hash"] != eth_hash:
        logger.info(
            "replacing the template's declared eth_genesis_hash %s with the "
            "computed %s (the value is derived from the reth genesis)",
            template["eth_genesis_hash"],
            eth_hash,
        )
    if "validators" not in template:
        # summit's genesis binary requires the field to *parse* the template
        # (its GenesisConfig has no serde default) even though it replaces the
        # value from -v; authored templates rightly omit validators, so the
        # shipped copy carries an empty placeholder set.
        template_bytes = b"validators = []\n" + template_bytes
    template_bytes = fill_template_genesis_hash(template_bytes, eth_hash)
    nonce = genesis_nonce if genesis_nonce is not None else secrets.token_bytes(32)
    if len(nonce) != 32:
        raise GateError(f"genesis_nonce must be 32 bytes, got {len(nonce)}")

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "name": name,
        "genesis_nonce": "0x" + nonce.hex(),
        "eth": {
            "chain_id": chain_id,
            "genesis_hash": eth_hash,
        },
        "summit": {
            "genesis_template_hash": _sha256_hex(template_bytes),
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
        summit_template=summit_template,
        policy_bytes=policy_bytes,
        reth_bin=reth_bin,
        genesis_hash_fn=genesis_hash_fn,
        summit_template_bytes=template_bytes,
    )
    run_validation_gates(parsed, ctx)

    return AssembledManifest(
        manifest_bytes=manifest_bytes,
        manifest=parsed,
        policy_bytes=policy_bytes,
        summit_template_bytes=template_bytes,
        network_id=compute_network_id(manifest_bytes),
        warnings=ctx.warnings,
    )


def write_artifact_set(
    out_dir: Path,
    assembled: AssembledManifest,
    ctx: GateContext,
    force: bool = False,
) -> None:
    """Write the network artifact set: manifest, policy, and verbatim copies
    of the genesis artifacts it commits to.

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
    # The reth genesis is a byte-verbatim copy of the input; the template is
    # assemble's copy (eth_genesis_hash filled if the author omitted it).
    # Every file re-verifies against the manifest's hashes with sha256sum.
    (out_dir / RETH_GENESIS_FILENAME).write_bytes(ctx.reth_genesis.read_bytes())
    (out_dir / SUMMIT_TEMPLATE_FILENAME).write_bytes(assembled.summit_template_bytes)


def starter_summit_template(name: str) -> str:
    """Starter authored summit template written by `manifest init` (values
    from summit's example_genesis.toml). Every value is a per-network choice
    for the founder to review; nothing in it is derived.
    """
    # json.dumps emits a valid TOML basic string for these simple values.
    return f"""\
# Summit network-params template — authored input for `manifest assemble`.
# Review every value before founding a real network. Two fields are filled
# elsewhere and do not belong here: eth_genesis_hash (derived from
# reth-genesis.json at assemble time) and [[validators]] (TEE-born, filled
# by the genesis ceremony).
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
    summit_template: Path | None = None,
    measurement_id: str | None = None,
) -> list[Path]:
    """Scaffold a network directory's three authored inputs.

    Copies the chain spec and measurements in (stamping measurement_id into
    the latter when given), and writes a starter summit template
    (namespace = name) unless one is supplied to copy. The founder edits
    these in place, then `assemble --dir` derives the artifact set into the
    same directory — inputs and the committed outputs live together, so the
    directory is the whole network (commit it for networks that matter).
    """
    measurements_bytes = measurements.read_bytes()
    if measurement_id is not None:
        measurements_bytes = stamp_measurement_id(measurements_bytes, measurement_id)
    contents = {
        RETH_GENESIS_FILENAME: reth_genesis.read_bytes(),
        INPUT_MEASUREMENTS_FILENAME: measurements_bytes,
        INPUT_SUMMIT_TEMPLATE_FILENAME: (
            summit_template.read_bytes()
            if summit_template is not None
            else starter_summit_template(name).encode()
        ),
    }
    existing = [n for n in contents if (out_dir / n).exists()]
    if existing:
        raise GateError(
            f"refusing to overwrite existing input(s) in {out_dir}: "
            f"{', '.join(existing)}"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for filename, data in contents.items():
        path = out_dir / filename
        path.write_bytes(data)
        written.append(path)
    return written


def render_network_section(manifest_bytes: bytes, reth_genesis_bytes: bytes) -> str:
    """Render the `[network]` config section tdx-init consumes.

    base64 keeps both artifacts opaque through the TOML hop (byte-exactness
    rule): tdx-init decodes and writes these exact bytes verbatim — the
    manifest to `network-manifest.json`, the genesis to `reth-genesis.json`
    (reth's `--chain`).
    """
    manifest_b64 = base64.standard_b64encode(manifest_bytes).decode("ascii")
    genesis_b64 = base64.standard_b64encode(reth_genesis_bytes).decode("ascii")
    return (
        f'[network]\nmanifest_base64 = "{manifest_b64}"\n'
        f'reth_genesis_base64 = "{genesis_b64}"\n'
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

    ini = sub.add_parser("init", help="scaffold a network directory's authored inputs")
    ini.add_argument("dir", type=Path, help="network directory to create")
    ini.add_argument(
        "--name",
        default=None,
        help="network name for the starter template's namespace; default: the "
        "directory's basename (which is also what assemble uses as the "
        "manifest name)",
    )
    ini.add_argument(
        "--reth-genesis",
        type=Path,
        required=True,
        help=f"chain spec, copied in as {RETH_GENESIS_FILENAME}. Required: "
        "an external fact (chain state + contract alloc) init cannot invent",
    )
    ini.add_argument(
        "--measurements",
        type=Path,
        required=True,
        help="seismic-images make-measure output (or promoted policy), "
        f"copied in as {INPUT_MEASUREMENTS_FILENAME}. Required: the PCRs of "
        "a real published image, never generated",
    )
    ini.add_argument(
        "--summit-template",
        type=Path,
        default=None,
        help="summit template to copy in verbatim. Optional: unlike the two "
        "inputs above it holds only per-network parameter choices, so the "
        "default writes an editable starter with namespace = <name>",
    )
    ini.add_argument(
        "--measurement-id",
        default=None,
        help="image artifact filename the measurements belong to; stamped "
        f"into {INPUT_MEASUREMENTS_FILENAME} so assemble needs no "
        "--measurement-id",
    )

    asm = sub.add_parser(
        "assemble",
        help="derive the artifact set from a network directory's inputs",
    )
    asm.add_argument(
        "dir",
        type=Path,
        help="network directory from `manifest init`: reads its "
        f"{RETH_GENESIS_FILENAME} / {INPUT_SUMMIT_TEMPLATE_FILENAME} / "
        f"{INPUT_MEASUREMENTS_FILENAME}, takes the network name from its "
        "basename, and writes the artifact set beside them",
    )
    asm.add_argument(
        "--measurement-id",
        help="policy record id (image artifact filename); overrides the one "
        f"init stamped into {INPUT_MEASUREMENTS_FILENAME}",
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

    val = sub.add_parser(
        "validate", help="re-run all gates over an assembled network directory"
    )
    val.add_argument(
        "dir",
        type=Path,
        help="network directory: audits the artifact set `assemble` wrote "
        "there (manifest, shipped template, policy) against its reth genesis",
    )
    add_reth_bin(val)

    args = parser.parse_args(argv)

    if args.command == "init":
        args.name = args.name or args.dir.resolve().name
    elif args.command == "assemble":
        args.name = args.dir.resolve().name
        args.reth_genesis = args.dir / RETH_GENESIS_FILENAME
        args.summit_template = args.dir / INPUT_SUMMIT_TEMPLATE_FILENAME
        args.measurements = args.dir / INPUT_MEASUREMENTS_FILENAME
        args.out = args.dir
    elif args.command == "validate":
        args.manifest = args.dir / MANIFEST_FILENAME
        args.reth_genesis = args.dir / RETH_GENESIS_FILENAME
        args.summit_template = args.dir / SUMMIT_TEMPLATE_FILENAME
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
                args.summit_template,
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
                f"{INPUT_SUMMIT_TEMPLATE_FILENAME}), then:\n"
                f"  seismic-tee-network manifest assemble {args.dir}{id_hint}"
            )
        elif args.command == "assemble":
            policy_bytes = promote_measurements(
                args.measurements.read_bytes(),
                args.measurement_id,
                args.attestation_type,
            )
            assembled = assemble(
                name=args.name,
                reth_genesis=args.reth_genesis,
                summit_template=args.summit_template,
                policy_bytes=policy_bytes,
                registry=args.registry,
                authority=args.authority,
                reth_bin=args.reth_bin,
            )
            ctx = GateContext(
                reth_genesis=args.reth_genesis,
                summit_template=args.summit_template,
                policy_bytes=policy_bytes,
                reth_bin=args.reth_bin,
            )
            write_artifact_set(args.out, assembled, ctx, force=args.force)
            logger.info("wrote %s", args.out / MANIFEST_FILENAME)
            logger.info("wrote %s", args.out / POLICY_FILENAME)
            print(f"network_id: {assembled.network_id}")
        else:
            manifest_bytes = args.manifest.read_bytes()
            manifest = validate_manifest_schema(manifest_bytes)
            ctx = GateContext(
                reth_genesis=args.reth_genesis,
                summit_template=args.summit_template,
                policy_bytes=args.measurement_policy.read_bytes(),
                reth_bin=args.reth_bin,
            )
            run_validation_gates(manifest, ctx)
            print(f"network_id: {compute_network_id(manifest_bytes)}")
            logger.info("all validation gates passed")
    except (GateError, ManifestSchemaError) as e:
        logger.error("%s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
