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
    inputs/measurements.json             raw PCR map from `make measure`,
                                         carrying the measurement_id of the
                                         image it measures
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
                                  boots from: the input completed with
                                  eth_genesis_hash and the founding
                                  validator set pinned from the harvest;
                                  summit.genesis_config_digest
    measurement-policy-bootstrap.json
                                  Flashbots-compatible measurement
                                  allowlist promoted from the raw
                                  measurements; bootstrap_policy_hash

Each artifact is its input with derived fields filled in at assemble time;
the raw measurements become the bootstrap policy because promotion is a
format transformation. `assemble` also reads the cohort descriptors under
nodes/ (runtime infra state, written by `up --network`) for each founding
validator's IP — delivered in the genesis file but excluded from its
config digest, so IPs never enter network_id.

Usage (one directory per network: `init` gathers the authored inputs — the
only command that takes loose files, each a local path or an https:// URL —
then `assemble`/`validate` operate on the directory; between `init` and
`assemble` the founding cohort is provisioned and harvested, since assemble
pins the harvested validator set):

    uv run seismic-tee-network init tee/networks/seismic-devnet-3 \
        --reth-genesis https://raw.githubusercontent.com/.../dev.json \
        --summit-genesis tee/networks/summit-genesis-starter.toml \
        --measurements ../seismic-images/build/measurements.json \
        --founders 4
    # edit tee/networks/seismic-devnet-3/inputs/summit-genesis.toml and
    # inputs/founder-withdrawal-credentials.json, then:
    #   seismic-tee-network up --network tee/networks/seismic-devnet-3 --count N
    #   seismic-tee-network harvest tee/networks/seismic-devnet-3
    uv run seismic-tee-network assemble tee/networks/seismic-devnet-3
    uv run seismic-tee-network validate tee/networks/seismic-devnet-3
"""

import argparse
import base64
import hashlib
import json
import logging
import re
import shutil
import sys
import tempfile
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
from eth_utils.crypto import keccak

from tee.cli.common.descriptor import load_descriptor, require
from tee.cli.common.errors import GateError, ManifestSchemaError
from tee.cli.common.logging_setup import setup_logging
from tee.cli.common.repo import DEFAULT_STACK_CONFIG
from tee.cli.common.shell_outs import (
    DEFAULT_ADMISSION_BIN,
    DEFAULT_ATTESTATION_TYPE,
    DEFAULT_RETH_BIN,
    DEFAULT_SUMMIT_BIN,
    DEFAULT_VERIFY_QUOTE_BIN,
    compile_measurement_policy,
    promote_measurements,
    reth_genesis_hash,
    summit_config_digest,
    summit_set_validators,
    verify_harvest_record,
    verify_quote_bin_not_found,
)

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

# Summit's consensus (BLS) port: each validator entry in the completed
# summit genesis pins "<ip>:<port>". IPs are operational data — the config
# digest excludes them — so they are delivered but never pinned.
SUMMIT_CONSENSUS_PORT = 18551

# Today's hardcoded summit BLS domain separator.
# two chains sharing it can cross-replay BLS signatures.
# TODO: make it configurable
_SUMMIT_DEFAULT_NAMESPACE = "_SUMMIT"

MANIFEST_FILENAME = "network-manifest.json"
# "bootstrap" because this file is only the *founding* allowlist (what the
# manifest's bootstrap_policy_hash pins and registry genesis storage is
# compiled from); the live policy is the registry contract's state, which
# the authority can mutate after genesis.
POLICY_FILENAME = "measurement-policy-bootstrap.json"
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
# authored (one address per founding node, paired in node-name order by
# load_founding_set — authorable before any box exists); harvest/ holds what
# `network harvest` collected from the live cohort (pubkeys, quotes,
# verification reports) — provenance like measurements.json, but harvested
# rather than authored.
FOUNDERS_FILENAME = "founder-withdrawal-credentials.json"
HARVEST_DIRNAME = "harvest"

# Beside each harvest record, the DCAP collateral that record's verification
# consumed (harvest/dcap-collateral/<node>.json). Intel's TCB Info, QE
# Identity and both CRLs carry nextUpdate on a roughly 30-day cadence, so an
# archived quote stays re-verifiable only against the bundle that was current
# when it was collected. A subdirectory, so load_harvest_records' glob over
# harvest/*.json never sees it.
COLLATERAL_DIRNAME = "dcap-collateral"


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


def _check_bare_hex(value: Any, nbytes: int, fieldname: str) -> None:
    """Bare lowercase hex — summit's keystore wire spelling, the form the
    genesis config_digest commits to. Any other spelling is rejected, never
    normalized, so nothing non-canonical is laundered into the pinned set."""
    if not isinstance(value, str) or not re.fullmatch(
        rf"[0-9a-f]{{{2 * nbytes}}}", value
    ):
        raise GateError(
            f"{fieldname}: expected {nbytes}-byte lowercase bare hex, got {value!r}"
        )


def load_founder_credentials(path: Path) -> list[str]:
    """Load the authored founder-withdrawal-credentials.json: one
    0x-prefixed address per founder, in a JSON array.

    A list rather than a node-name mapping so the founders' addresses are
    authorable before any box exists — they are a fact about the founders,
    not about the infrastructure. `load_founding_set` pairs the i-th
    address with the i-th founding validator in node-name order.
    """
    if not path.is_file():
        raise GateError(
            f"{path} not found — author it as a JSON array of the founders' "
            "withdrawal credentials (0x-prefixed addresses), one per "
            "founding node"
        )
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise GateError(f"{path}: not valid JSON: {e}") from None
    if not isinstance(data, list) or not all(isinstance(v, str) for v in data):
        raise GateError(
            f"{path}: expected a JSON array of withdrawal credentials "
            "(0x-prefixed addresses), one per founding node"
        )
    bad = sorted({addr for addr in data if not _is_address(addr)})
    if bad:
        raise GateError(
            f"{path}: withdrawal credentials must be 0x + 40 hex chars; bad "
            f"entr(ies): {', '.join(bad)}"
        )
    return data


def _is_address(value: str) -> bool:
    try:
        _check_hex(value, 20, "withdrawal credentials")
    except ManifestSchemaError:
        return False
    return True


def load_harvest_records(harvest_dir: Path) -> dict[str, dict[str, Any]]:
    """Read the harvested founding records (inputs/harvest/<node>.json).

    Validates the fields the founding set is built from — nonce, both
    pubkeys, the evidence object — and rejects a pubkey repeated across
    boxes: summit's genesis keys validator accounts by node pubkey, so a
    repeated key silently collapses the set, and a shared consensus key is
    accidental-equivocation material. The records are plain committed
    files, so everything is re-checked here even though the harvest
    validated it at collection time.
    """
    paths = sorted(harvest_dir.glob("*.json")) if harvest_dir.is_dir() else []
    if not paths:
        raise GateError(
            f"no harvest records in {harvest_dir} — assemble pins the "
            "founding validator set from them; provision the cohort "
            "(`up --network`) and run `seismic-tee-network harvest` first"
        )
    records: dict[str, dict[str, Any]] = {}
    for path in paths:
        try:
            record = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise GateError(f"{path}: not valid JSON: {e}") from None
        if not isinstance(record, dict):
            raise GateError(f"{path}: expected a JSON object")
        _check_bare_hex(record.get("harvest_nonce"), 32, f"{path}: harvest_nonce")
        _check_bare_hex(record.get("node_public_key"), 32, f"{path}: node_public_key")
        _check_bare_hex(
            record.get("consensus_public_key"), 48, f"{path}: consensus_public_key"
        )
        if not isinstance(record.get("evidence"), dict):
            raise GateError(
                f"{path}: no evidence object — without the archived quote the "
                "record cannot be re-verified, so it must not be pinned"
            )
        records[path.stem] = record
    for key_field in ("node_public_key", "consensus_public_key"):
        seen: dict[str, str] = {}
        for name in sorted(records):
            key = records[name][key_field]
            if key in seen:
                raise GateError(
                    f"{seen[key]} and {name} carry the same {key_field} "
                    f"({key}); the harvest is not the distinct founder set "
                    "being pinned — re-found and re-harvest"
                )
            seen[key] = name
    return records


@dataclass
class FoundingSet:
    """The founding cohort as assemble pins it: the summit validator
    entries (harvested keys + authored credentials + current IPs) and the
    harvest records they came from (for quote re-verification)."""

    validators: list[dict[str, str]]
    records: dict[str, dict[str, Any]]


def load_founding_set(network_dir: Path) -> FoundingSet:
    """Pair the harvested cohort with its authored withdrawal credentials
    and current IPs into summit validator entries.

    The credentials are positional: the i-th authored address goes to the
    i-th harvested box in node-name order, and the counts must match
    exactly — one address short means a box can't be pinned, one too many
    means the harvest isn't the cohort the founders authored for, and
    either way assembling would pin a set other than the intended one. The
    pairing is logged and lands visibly in the emitted genesis, since
    nothing downstream can tell a swapped pair from an intended one. IPs
    come from the cohort descriptors under nodes/ ("<ip>:<consensus
    port>"): delivered in the genesis file but excluded from its config
    digest, so the committed file is a founding-era snapshot and IP churn
    never re-founds.
    """
    inputs_dir = network_dir / INPUTS_DIRNAME
    founders = load_founder_credentials(inputs_dir / FOUNDERS_FILENAME)
    records = load_harvest_records(inputs_dir / HARVEST_DIRNAME)
    if len(founders) != len(records):
        raise GateError(
            f"{inputs_dir / FOUNDERS_FILENAME} carries {len(founders)} "
            f"withdrawal credential(s) but {len(records)} box(es) were "
            f"harvested into {inputs_dir / HARVEST_DIRNAME} "
            f"({', '.join(sorted(records))}) — author one address per "
            "founding node"
        )
    nodes_dir = network_dir / NODES_DIRNAME
    validators = []
    for name, credentials in zip(sorted(records), founders, strict=True):
        descriptor_path = nodes_dir / f"{name}.json"
        if not descriptor_path.is_file():
            raise GateError(
                f"{descriptor_path} not found — the cohort descriptors from "
                "`up --network` supply each founding validator's IP. A "
                "harvested box whose descriptor is gone means the cohort "
                "changed under the harvest: re-found rather than assembling"
            )
        try:
            ip = require(load_descriptor(descriptor_path), "public_ip", descriptor_path)
        except (json.JSONDecodeError, ValueError) as e:
            raise GateError(f"{descriptor_path}: {e}") from None
        logger.info("founding validator %s: withdrawals to %s", name, credentials)
        validators.append(
            {
                "node_public_key": records[name]["node_public_key"],
                "consensus_public_key": records[name]["consensus_public_key"],
                "ip_address": f"{ip}:{SUMMIT_CONSENSUS_PORT}",
                "withdrawal_credentials": credentials,
            }
        )
    return FoundingSet(validators=validators, records=records)


def verify_harvest_records(
    records: dict[str, dict[str, Any]],
    policy_bytes: bytes,
    collateral_dir: Path,
    verify_quote_bin: str = DEFAULT_VERIFY_QUOTE_BIN,
    verify_fn: Callable[[str, dict[str, Any], Path, Path], dict[str, Any]]
    | None = None,
) -> None:
    """Re-verify every archived founding record against the compiled policy,
    offline, at the instant its own collateral snapshot was held to.

    The harvest verified these records when it collected them, but assemble
    is the step that pins the validator set into network_id — so it hands
    each archived record back to the verifier rather than trusting an
    earlier run's verdict (the records are plain files that may have been
    copied, committed, and edited between harvest and assemble).

    Each record is checked against the snapshot archived beside it, so this
    gate behaves the same on the founding day and four hundred days later. A
    record with no snapshot fails: Intel's live collateral would answer for
    it today and stop answering in about a month, which would make assemble's
    verdict depend on when it ran.
    """
    if verify_fn is None and shutil.which(verify_quote_bin) is None:
        # Tooling, not evidence: a missing verifier fails here, before the
        # loop whose failures carry burned-founding advice.
        raise verify_quote_bin_not_found(verify_quote_bin)
    with tempfile.NamedTemporaryFile(
        prefix="measurement-policy-", suffix=".json"
    ) as policy_file:
        policy_file.write(policy_bytes)
        policy_file.flush()
        policy_path = Path(policy_file.name)
        run_verify = verify_fn or (
            lambda _name, record, path, collateral: verify_harvest_record(
                record,
                policy_path=path,
                verify_quote_bin=verify_quote_bin,
                collateral=collateral,
            )
        )
        for name in sorted(records):
            collateral_path = collateral_dir / f"{name}.json"
            if not collateral_path.is_file():
                raise GateError(
                    f"{name}: no DCAP collateral archived at "
                    f"{collateral_path} — the founding quote can only be "
                    "re-verified against the collateral its own harvest "
                    "used, so this cohort has to be re-harvested (or "
                    "re-founded) rather than assembled around"
                )
            try:
                run_verify(name, records[name], policy_path, collateral_path)
            except GateError as e:
                raise GateError(
                    f"{name}: {e}\nA founding key whose archived quote does "
                    "not verify must not be pinned — re-found (or re-harvest "
                    "an unchanged cohort) rather than assembling around it"
                ) from None
            logger.info("%s: archived founding quote verified", name)


@dataclass
class GateContext:
    """Artifact set a manifest is validated against (deploy-side gates)."""

    reth_genesis: Path
    summit_genesis: Path
    policy_bytes: bytes
    reth_bin: str = DEFAULT_RETH_BIN
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

    policy_hash = validate_policy_matches(manifest, ctx.policy_bytes)

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
            "compile measurement-policy-bootstrap.json`)"
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
    genesis parser requires the field to be present in the TOML it reads, so
    the template fed to `summit genesis set-validators` must carry it. Any
    declared value is dropped (it can only be stale copy-paste, e.g. summit's
    example_genesis.toml) and the computed one is prepended — always valid
    TOML for a top-level key; set-validators re-renders the completed file,
    which is what `genesis_config_digest` commits to and the artifact set
    ships.
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
    validators: list[dict[str, str]],
    registry: str = DEFAULT_REGISTRY,
    authority: str = DEFAULT_AUTHORITY,
    reth_bin: str = DEFAULT_RETH_BIN,
    admission_bin: str = DEFAULT_ADMISSION_BIN,
    summit_bin: str = DEFAULT_SUMMIT_BIN,
    genesis_hash_fn: Callable[[Path], str] | None = None,
    compile_fn: Callable[[bytes], dict[str, Any]] | None = None,
    digest_fn: Callable[[Path], str] | None = None,
    set_validators_fn: Callable[[bytes, list[dict[str, str]]], bytes] | None = None,
) -> AssembledManifest:
    """Assemble, render, and gate-check a v1 network manifest.

    The summit genesis's `eth_genesis_hash` is derived from reth-genesis.json,
    never authored: whatever the input declares (if anything) is replaced with
    the computed value — committed bytes never carry a stale hash. The
    `validators` set (the founding cohort's harvested keys, paired with
    authored credentials and current IPs — see load_founding_set) is filled
    in by `summit genesis set-validators`, which re-renders the whole file
    canonically; the artifact set ships summit's emission, and the manifest
    pins it via summit's own config digest (`summit genesis digest`), which
    covers the consensus parameters and the validator set but not the IPs.

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
    if not validators:
        raise GateError(
            "no founding validators — the validator set is pinned from the "
            "harvest, and a founding with an empty set is not a network"
        )
    if "validators" not in authored:
        # summit requires the field to *parse* a genesis (its Genesis type
        # has no serde default), and set-validators loads the template
        # before replacing whatever set it declares — so an input authored
        # without one gets an empty placeholder purely to make the template
        # loadable. The shipped set always comes from `validators`.
        authored_bytes = b"validators = []\n" + authored_bytes
    template_bytes = fill_eth_genesis_hash(authored_bytes, eth_hash)
    emit = set_validators_fn or (
        lambda template, vals: summit_set_validators(
            template, vals, summit_bin=summit_bin
        )
    )
    summit_genesis_bytes = emit(template_bytes, validators)
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


def _raw_url_hint(source: str | Path) -> str:
    """Suffix for parse-gate errors on fetched content: the classic mistake
    is pasting a GitHub HTML page URL, which fetches fine but isn't the file.
    """
    if str(source).startswith("https://"):
        return (
            " — for GitHub files pass the raw content URL "
            "(raw.githubusercontent.com), not the HTML page"
        )
    return ""


def read_input_source(source: str | Path) -> bytes:
    """Read one authored input from a local path or an https:// URL.

    URL inputs let `init` run without sibling checkouts: all SeismicSystems
    repos are public, so raw.githubusercontent.com URLs work anonymously,
    and since `init` copies inputs into inputs/ the fetch is one-time — the
    network directory stays self-contained. https is required on the request
    *and on every redirect hop* (a chain that starts https can still be
    downgraded mid-redirect); beyond that any host is accepted — founders
    running their own forks fetch from their own mirrors, and the founder
    reviews every input before assemble's gates run.
    """
    text = str(source)
    if text.startswith("http://"):
        raise GateError(f"insecure URL rejected (use https://): {text}")
    if text.startswith("https://"):
        try:
            resp = requests.get(text, timeout=30)
            resp.raise_for_status()
        except requests.RequestException as e:
            raise GateError(f"failed to fetch {text}: {e}") from None
        insecure = [
            hop.url
            for hop in [*resp.history, resp]
            if not str(hop.url).startswith("https://")
        ]
        if insecure:
            raise GateError(
                f"{text} redirected through non-https URL(s): {', '.join(insecure)}"
            )
        return resp.content
    path = Path(source)
    if not path.is_file():
        raise GateError(f"input file not found: {path}")
    return path.read_bytes()


def fill_summit_namespace(raw: bytes, name: str, source: str | Path) -> bytes:
    """Apply init's namespace rule to an authored summit genesis.

    `namespace` is the signature domain separator and must be unique per
    network, so a shared starter (like the committed
    summit-genesis-starter.toml) cannot choose one: it carries the visible
    fill-me slot `namespace = ""`. init fills `namespace = <network name>`
    when the authored genesis leaves it empty or omits the key — an empty
    string is never authorable intent (assemble would accept a namespace no
    one chose) — and copies a non-empty namespace untouched. The authored
    bytes are otherwise verbatim.
    """
    try:
        text = raw.decode("utf-8")
        parsed = tomllib.loads(text)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise GateError(
            f"{source} is not valid TOML: {e}{_raw_url_hint(source)}"
        ) from None
    if parsed.get("namespace"):
        return raw
    # json.dumps emits a valid TOML basic string for a simple name.
    filled = f"namespace = {json.dumps(name)}"
    if "namespace" in parsed:
        text, count = re.subn(
            r"^namespace\s*=.*$", lambda _: filled, text, count=1, flags=re.MULTILINE
        )
        if count != 1:
            raise GateError(
                f"{source} has an empty namespace that init cannot rewrite "
                "(no top-level `namespace = ...` line) — set it to the "
                "network's unique namespace"
            )
        return text.encode()
    if text and not text.endswith("\n"):
        text += "\n"
    return (
        text
        + "\n# Unique per network: namespaces summit signatures to this chain.\n"
        + filled
        + "\n"
    ).encode()


def require_measurement_id(raw_bytes: bytes, source: str | Path) -> None:
    """Gate a measurements input on carrying the id of the image it measures.

    The measurements file is the only binding between a network's PCR
    allowlist and an image: seismic-images' `make measure` stamps the
    versioned VHD filename into it, and promotion reads the id from there.
    `init` gates on the stamp so a missing one surfaces while the operator
    still holds loose files, not after the cohort has been provisioned and
    harvested. A promoted policy is a record list, each record carrying its
    own id.
    """
    try:
        raw = json.loads(raw_bytes)
    except json.JSONDecodeError as e:
        raise GateError(
            f"{source} is not valid JSON: {e}{_raw_url_hint(source)}"
        ) from None
    if isinstance(raw, dict) and "measurement_id" not in raw:
        raise GateError(
            f"{source} carries no measurement_id — re-export the measurements "
            "with seismic-images' `make measure`, which stamps the versioned "
            "image filename these PCRs measure into the file"
        )


def init_network_dir(
    out_dir: Path,
    name: str,
    reth_genesis: str | Path,
    measurements: str | Path,
    summit_genesis: str | Path,
    founders: int = 0,
    force: bool = False,
) -> list[Path]:
    """Scaffold a network directory's four authored inputs under inputs/.

    Each input is a local path or an https:// URL (read_input_source).
    Copies the three inputs in verbatim, gating each on parsing as its
    format (the measurements additionally on carrying the measurement_id of
    the image they measure) — except that a summit genesis with an empty or
    missing `namespace` gets `namespace = <name>` filled in
    (fill_summit_namespace).
    Also writes `founders` placeholder withdrawal credentials (`0x00…0<i>`
    — obviously fake, so a set that survives into a network anyone cares
    about shows on sight). The founder edits all four in place, then
    provisions and harvests the cohort (assemble pins the harvested validator
    set) before `assemble --dir` derives the artifact set into the directory's
    top level — inputs and the committed artifacts live together, so the
    directory is the whole network (commit it for networks that matter).
    """
    measurements_bytes = read_input_source(measurements)
    require_measurement_id(measurements_bytes, measurements)
    reth_genesis_bytes = read_input_source(reth_genesis)
    try:
        json.loads(reth_genesis_bytes)
    except json.JSONDecodeError as e:
        raise GateError(
            f"{reth_genesis} is not valid JSON: {e}{_raw_url_hint(reth_genesis)}"
        ) from None
    summit_genesis_bytes = fill_summit_namespace(
        read_input_source(summit_genesis), name, summit_genesis
    )
    credentials = [f"0x{i:040x}" for i in range(1, founders + 1)]
    contents = {
        RETH_GENESIS_FILENAME: reth_genesis_bytes,
        MEASUREMENTS_FILENAME: measurements_bytes,
        SUMMIT_GENESIS_FILENAME: summit_genesis_bytes,
        FOUNDERS_FILENAME: (json.dumps(credentials, indent=2) + "\n").encode(),
    }
    inputs_dir = out_dir / INPUTS_DIRNAME
    existing = [n for n in contents if (inputs_dir / n).exists()]
    if existing and not force:
        raise GateError(
            f"refusing to overwrite existing input(s) in {inputs_dir}: "
            f"{', '.join(existing)} — pass --force to re-author them "
            "(re-assembling from changed inputs is a new network identity)"
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
    re-asserted against every node's live reth by the launch assertions.
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


def validate_policy_matches(manifest: dict[str, Any], policy_bytes: bytes) -> str:
    """The policy document is the one this manifest commits to:
    measurements.bootstrap_policy_hash == SHA-256(policy bytes). Returns that
    agreed hash, which callers with more policy checks to run compare against.

    A byte hash, so it holds for the exact file — the same document the
    registry's genesis-seeded admission IDs were compiled from. Every consumer
    of a network's policy artifact runs this before use: `assemble`/`validate`
    over the artifact set, `seismic-tee-node verify` over the copy it appraises
    a node against.
    """
    policy_hash = _sha256_hex(policy_bytes)
    if manifest["measurements"]["bootstrap_policy_hash"] != policy_hash:
        raise GateError(
            f"measurements.bootstrap_policy_hash mismatch: manifest has "
            f"{manifest['measurements']['bootstrap_policy_hash']}, computed "
            f"{policy_hash}"
        )
    return policy_hash


def _add_reth_bin(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--reth-bin",
        default=DEFAULT_RETH_BIN,
        help="seismic-reth binary used to recompute eth_genesis_hash",
    )


def _add_admission_bin(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--admission-bin",
        default=DEFAULT_ADMISSION_BIN,
        help="policy-compiler CLI used to promote measurements and "
        "compile the policy into registry genesis storage",
    )


def _add_summit_bin(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--summit-bin",
        default=DEFAULT_SUMMIT_BIN,
        help="summit binary whose `genesis digest` subcommand computes "
        "summit.genesis_config_digest",
    )


def _parse_init_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="scaffold a network directory's authored inputs"
    )
    parser.add_argument("dir", type=Path, help="network directory to create")
    parser.add_argument(
        "--name",
        default=None,
        help="network name, filled in as the summit genesis's namespace when "
        "the authored genesis leaves it empty; default: the directory's "
        "basename (which is also what assemble uses as the manifest name)",
    )
    # The three inputs are strings, not Paths: each accepts a local path or
    # an https:// URL, and Path() would collapse a URL's "//".
    parser.add_argument(
        "--reth-genesis",
        required=True,
        metavar="PATH_OR_URL",
        help="reth genesis (local path or https:// URL), copied in as "
        f"{INPUTS_DIRNAME}/{RETH_GENESIS_FILENAME}. Required: an external "
        "fact (chain state + contract alloc) init cannot invent",
    )
    parser.add_argument(
        "--measurements",
        required=True,
        metavar="PATH_OR_URL",
        help="seismic-images make-measure output (or promoted policy; local "
        f"path or https:// URL), copied in as "
        f"{INPUTS_DIRNAME}/{MEASUREMENTS_FILENAME}. Required: the PCRs of a "
        "real published image, never generated",
    )
    parser.add_argument(
        "--summit-genesis",
        required=True,
        metavar="PATH_OR_URL",
        help="authored summit genesis (local path or https:// URL), copied "
        "in verbatim except that an empty namespace is filled with <name>. "
        "Required: every value in it is a per-network choice; start from "
        "tee/networks/summit-genesis-starter.toml (in this repo, also "
        "fetchable from its GitHub raw URL) and review each parameter",
    )
    parser.add_argument(
        "--founders",
        type=int,
        default=0,
        metavar="N",
        help="how many placeholder withdrawal credentials to scaffold into "
        f"{INPUTS_DIRNAME}/{FOUNDERS_FILENAME} (one per founding node, "
        "paired in node-name order at assemble time). The placeholders are "
        "all a throwaway needs; a real founding replaces them with the "
        "founders' addresses. Default: an empty list to fill in",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing authored inputs (re-authoring them and "
        "re-assembling is a new network identity)",
    )
    args = parser.parse_args(argv)
    # Absolute, so every path this CLI prints is clickable in a terminal and
    # names one directory unambiguously.
    args.dir = args.dir.resolve()
    args.name = args.name or args.dir.name
    return args


def _parse_assemble_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="derive the artifact set from a network directory's inputs"
    )
    parser.add_argument(
        "dir",
        type=Path,
        help=f"network directory from `init`: reads its "
        f"{INPUTS_DIRNAME}/ ({RETH_GENESIS_FILENAME}, "
        f"{SUMMIT_GENESIS_FILENAME}, {MEASUREMENTS_FILENAME}), takes the "
        "network name from its basename, and writes the artifact set at "
        "the top level",
    )
    parser.add_argument("--attestation-type", default=DEFAULT_ATTESTATION_TYPE)
    parser.add_argument(
        "--registry",
        default=DEFAULT_REGISTRY,
        help="measurement-registry contract address in the genesis alloc",
    )
    parser.add_argument(
        "--authority",
        default=DEFAULT_AUTHORITY,
        help="registry mutation-authority contract address",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing manifest (a new network identity)",
    )
    parser.add_argument(
        "--verify-quote-bin",
        default=DEFAULT_VERIFY_QUOTE_BIN,
        help="DCAP verifier CLI from the enclave repo (bin/verify-quote), "
        "used to re-verify the archived harvest quotes before the founding "
        "set is pinned",
    )
    _add_reth_bin(parser)
    _add_admission_bin(parser)
    _add_summit_bin(parser)
    args = parser.parse_args(argv)
    # Absolute, so every path this CLI prints is clickable in a terminal and
    # names one directory unambiguously.
    args.dir = args.dir.resolve()
    args.name = args.dir.name
    inputs_dir = args.dir / INPUTS_DIRNAME
    args.reth_genesis = inputs_dir / RETH_GENESIS_FILENAME
    args.summit_genesis = inputs_dir / SUMMIT_GENESIS_FILENAME
    args.measurements = inputs_dir / MEASUREMENTS_FILENAME
    args.out = args.dir
    return args


def _parse_validate_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="re-run all gates over an assembled network directory"
    )
    parser.add_argument(
        "dir",
        type=Path,
        help="network directory: audits the artifact set `assemble` wrote "
        "there (manifest, summit genesis, policy) against its reth genesis",
    )
    _add_reth_bin(parser)
    _add_admission_bin(parser)
    _add_summit_bin(parser)
    args = parser.parse_args(argv)
    # Absolute, so every path this CLI prints is clickable in a terminal and
    # names one directory unambiguously.
    args.dir = args.dir.resolve()
    args.manifest = args.dir / MANIFEST_FILENAME
    args.reth_genesis = args.dir / RETH_GENESIS_FILENAME
    args.summit_genesis = args.dir / SUMMIT_GENESIS_FILENAME
    args.measurement_policy = args.dir / POLICY_FILENAME
    return args


def init_main() -> None:
    setup_logging()
    args = _parse_init_args()
    try:
        written = init_network_dir(
            args.dir,
            args.name,
            args.reth_genesis,
            args.measurements,
            args.summit_genesis,
            founders=args.founders,
            force=args.force,
        )
        for path in written:
            logger.info("wrote %s", path)
        inputs_dir = args.dir / INPUTS_DIRNAME
        founders_hint = (
            "update the placeholder addresses in"
            if args.founders
            else "fill in one address per founding node in"
        )
        # No --count on `up`: the authored credentials size the cohort.
        print(
            f"Scaffolded {args.dir}. Next:\n"
            f"  1. review {inputs_dir / SUMMIT_GENESIS_FILENAME}\n"
            f"  2. {founders_hint}\n"
            f"     {inputs_dir / FOUNDERS_FILENAME}\n"
            f"  3. review the stack config the cohort boots from\n"
            f"     {DEFAULT_STACK_CONFIG}\n"
            "     (vhd_blob_url must name the image the measurements "
            "describe;\n"
            "      region, VM size, and operator_ip_cidr live there too)\n"
            f"  4. seismic-tee-network up --network {args.dir}\n"
            f"  5. seismic-tee-network harvest {args.dir}\n"
            f"  6. seismic-tee-network assemble {args.dir}"
        )
    except (GateError, ManifestSchemaError) as e:
        logger.error("%s", e)
        sys.exit(1)


def assemble_main() -> None:
    setup_logging()
    args = _parse_assemble_args()
    try:
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
                "scaffold them with `init`"
            )
        founding = load_founding_set(args.dir)
        logger.info(
            "founding set: %d validator(s) from %s",
            len(founding.validators),
            args.dir / INPUTS_DIRNAME / HARVEST_DIRNAME,
        )
        policy_bytes = promote_measurements(
            args.measurements.read_bytes(),
            args.attestation_type,
            admission_bin=args.admission_bin,
        )
        verify_harvest_records(
            founding.records,
            policy_bytes,
            args.dir / INPUTS_DIRNAME / HARVEST_DIRNAME / COLLATERAL_DIRNAME,
            verify_quote_bin=args.verify_quote_bin,
        )
        assembled = assemble(
            name=args.name,
            reth_genesis=args.reth_genesis,
            summit_genesis=args.summit_genesis,
            policy_bytes=policy_bytes,
            validators=founding.validators,
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
        logger.info("wrote %s", args.out / SUMMIT_GENESIS_FILENAME)
        print(f"network_id: {assembled.network_id}")
    except (GateError, ManifestSchemaError) as e:
        logger.error("%s", e)
        sys.exit(1)


def validate_main() -> None:
    setup_logging()
    args = _parse_validate_args()
    try:
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
