#!/usr/bin/env python3
"""Operator node configuration: configure a node to JOIN a network.

Assemble a node's tdx-init config from flags + a descriptor + the network
manifest, and POST it to a provisioned node's tdx-init HTTP receiver:

    seismic-tee-node configure --node n2.json \
        --bootnode enode://<pubkey>@<ip>:30303 --manifest m.json

The operator CLI only ever *joins* an existing network (`genesis_node =
false`): the node fetches `root_key` via `getWrappedRootKey` from a peer
tdx-init derives from `--bootnode` (`http://<host>:7878` per bootnode).
Founding a network — designating the one genesis node that mints `root_key`
locally — is owned by `seismic-tee-network configure`, not
exposed here. `build_config`/`post_config_to_tdx_init` below are the shared
primitives both CLIs call; `genesis_node=True` is only ever set by the
bootstrap side.

The node is deploy-verified once it reaches a ready state — the
`seismic-tee-node verify` step, run inline here so a node is appraised in the
same breath it is configured. See verify.py for what the check proves and
which measurement policy it appraises against. The configured summary is
printed only after it passes, so it never reads as success over a failed
verification. Delivery is once per boot (tdx-init accepts one config POST)
while the check is re-runnable, so anything that interrupts the check points
at `verify` rather than at another configure run.

Verification is the default because the artifact set already carries
everything it needs: the policy sits beside `--manifest`, pinned by it. An
operator who wants delivery alone asks for it with `--no-verify`.

There is no per-node `node.toml`: `[node]` (external_ip + genesis_node) comes
from the descriptor + role, `[node.domain]` from the descriptor fqdn +
`--email`, and `[network]` from `--manifest` + `--reth-genesis` +
`--summit-genesis` + `--bootnode`. Those network-wide artifacts stay
standalone files, merged only at POST time. The node address is *brought
by the operator* via a descriptor map file (see tee/cli/common/descriptor.py),
typically `pulumi stack output nodes --json`, with `--name` picking the node
when the file holds several. The CLI never provisions infrastructure
(Pulumi's job).

The POSTed TOML shape (`[network]`/`[node]`, split by provenance:
coordinator-produced vs this-node-only) is tdx-init's schema; it validates
server-side with `deny_unknown_fields`, so this CLI and the node image must
agree on the section names.
"""

import argparse
import json
import logging
import tempfile
import time
from pathlib import Path

import requests

from tee.cli.common import manifest as manifest_mod
from tee.cli.common import shell_outs
from tee.cli.common.descriptor import NodeDescriptor, add_node_args, load_node_arg
from tee.cli.common.logging_setup import setup_logging
from tee.cli.node import verify as verify_mod
from tee.cli.node.status import watch_luks_provisioning

logger = logging.getLogger(__name__)

TDX_INIT_PORT = 8080
# How long to wait for tdx-init's HTTP listener to come up. tdx-init
# starts after persistent-luks-setup, which can take ~20-40s on first
# boot (LUKS format + mkfs + TPM enroll).
TDX_INIT_LISTENER_TIMEOUT_SECONDS = 180
TDX_INIT_RETRY_INTERVAL_SECONDS = 5


def resolve_reth_genesis(reth_genesis: Path | None, manifest_path: Path) -> Path:
    """Resolve `--reth-genesis`, defaulting to the artifact-set convention:
    `reth-genesis.json` beside the manifest, exactly where `assemble`
    writes its byte-verbatim copy — so the file POSTed is the one the
    manifest's `eth.genesis_hash` was computed from.
    """
    path = reth_genesis or manifest_path.parent / manifest_mod.RETH_GENESIS_FILENAME
    if not path.is_file():
        hint = (
            ""
            if reth_genesis
            else " (the default is reth-genesis.json beside --manifest; pass "
            "--reth-genesis if it lives elsewhere)"
        )
        raise SystemExit(f"reth genesis not found: {path}{hint}")
    return path


def resolve_summit_genesis(summit_genesis: Path | None, manifest_path: Path) -> Path:
    """Resolve `--summit-genesis`, defaulting to the artifact-set convention:
    `summit-genesis.toml` beside the manifest, exactly where `assemble`
    writes its byte-verbatim copy — so the file POSTed is the one
    the manifest's `summit.genesis_config_digest` was computed from.
    """
    path = summit_genesis or manifest_path.parent / manifest_mod.SUMMIT_GENESIS_FILENAME
    if not path.is_file():
        hint = (
            ""
            if summit_genesis
            else " (the default is summit-genesis.toml beside --manifest; pass "
            "--summit-genesis if it lives elsewhere)"
        )
        raise SystemExit(f"summit genesis not found: {path}{hint}")
    return path


def build_config(
    manifest_path: Path,
    fqdn: str,
    email: str,
    *,
    genesis_node: bool,
    reth_genesis_path: Path,
    summit_genesis_path: Path,
    external_ip: str,
    bootnodes: list[str],
    manifest_bin: str = shell_outs.DEFAULT_MANIFEST_BIN,
) -> Path:
    """Assemble the config POSTed to tdx-init, mutating no source. The fields
    come from: the node's public IP (→ `[node].external_ip`, reth's
    `--nat extip`), the role (→ `[node].genesis_node`), the descriptor's fqdn
    (→ `[node.domain].name`, the cert domain), `--email`
    (→ `[node.domain].email`), and the network manifest + reth genesis +
    summit genesis + bootnode set (`--manifest`/`--reth-genesis`/
    `--summit-genesis`/`bootnodes` → `[network]`). Written fresh, so there is
    no operator-supplied TOML that could carry a conflicting
    `[node]`/`[network]` and fork the network.

    `external_ip` is the node's own public IP (from its descriptor); reth
    advertises it via `--nat extip` so its enode is dialable, which is what
    keeps a node's advertised enode host equal to `[network].bootnodes`
    entries. tdx-init requires `[node].external_ip` and parses it as an
    `IpAddr`, so it is always emitted and must be non-empty — an empty value
    would 400 at the far end, so we fail fast here instead.

    `bootnodes` is the single source for the cohort's peer machines: reth
    dials the enodes verbatim, and tdx-init derives the root-key fetch list
    from them (`http://<host>:7878`, the node's own entry dropped). Empty is
    valid only on the greenfield genesis node (it mints `root_key` itself);
    a joiner with no bootnode has no source for `root_key` and would 400 at
    the far end, so that too fails fast here.

    `genesis_node=True` is only ever passed by the bootstrap founding
    command; the operator `configure` always joins (False).
    """
    if not external_ip:
        # tdx-init requires [node].external_ip as an IpAddr; an empty value is
        # a far-end 400. Fail fast — every caller sources it from the
        # descriptor's required public_ip, so this should be unreachable.
        raise SystemExit("build_config: external_ip is required and must be non-empty")
    if not genesis_node and not bootnodes:
        # Mirrors tdx-init's POST-time rule: a non-genesis node derives its
        # root_key fetch peers from the bootnodes, so none means no way to
        # bootstrap — a far-end 400.
        raise SystemExit(
            "build_config: a joining node needs at least one bootnode "
            "(tdx-init derives its root_key fetch peers from them)"
        )
    manifest_bytes = manifest_path.read_bytes()
    try:
        # Never POST bytes tdx-init would 400 at the far end.
        manifest = manifest_mod.validate_manifest_schema(manifest_bytes, manifest_bin)
    except (manifest_mod.ManifestSchemaError, manifest_mod.GateError) as e:
        raise SystemExit(f"--manifest {manifest_path}: invalid manifest: {e}") from None

    reth_genesis_bytes = reth_genesis_path.read_bytes()
    try:
        manifest_mod.validate_reth_genesis_matches(manifest, reth_genesis_bytes)
    except manifest_mod.GateError as e:
        raise SystemExit(f"--reth-genesis {reth_genesis_path}: {e}") from None

    summit_genesis_bytes = summit_genesis_path.read_bytes()
    try:
        manifest_mod.validate_summit_genesis_matches(manifest, summit_genesis_bytes)
    except manifest_mod.GateError as e:
        raise SystemExit(f"--summit-genesis {summit_genesis_path}: {e}") from None

    # json.dumps emits valid TOML basic strings for these simple ASCII values.
    merged = (
        f"[node]\n"
        f"external_ip = {json.dumps(external_ip)}\n"
        f"genesis_node = {str(genesis_node).lower()}\n\n"
        f"[node.domain]\nname = {json.dumps(fqdn)}\nemail = {json.dumps(email)}\n\n"
        + manifest_mod.render_network_section(
            manifest_bytes, reth_genesis_bytes, summit_genesis_bytes, bootnodes
        )
    )
    with tempfile.NamedTemporaryFile(
        "w",
        suffix=".toml",
        prefix="seismic-node-config-",
        delete=False,
        encoding="utf-8",
    ) as f:
        f.write(merged)
        return Path(f.name)


def post_config_to_tdx_init(ip_address: str, config_path: Path) -> None:
    """Wait for tdx-init's HTTP listener to come up, then POST the
    assembled TOML config verbatim. tdx-init validates the schema
    server-side (`deny_unknown_fields`) and 4xx-rejects malformed
    payloads, so a non-2xx response is propagated as an error.
    """
    url = f"http://{ip_address}:{TDX_INIT_PORT}/"
    body = config_path.read_bytes()
    headers = {"Content-Type": "application/toml"}

    logger.info(f"Waiting for tdx-init listener at {url}...")
    deadline = time.monotonic() + TDX_INIT_LISTENER_TIMEOUT_SECONDS
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = requests.post(url, data=body, headers=headers, timeout=10)
        except requests.ConnectionError as e:
            last_error = e
            time.sleep(TDX_INIT_RETRY_INTERVAL_SECONDS)
            continue

        if response.status_code == 200:
            logger.info(f"tdx-init accepted config from {config_path}")
            return

        # Non-200: propagate immediately. 4xx = malformed TOML, 5xx =
        # tdx-init bug; neither benefits from retry.
        raise RuntimeError(
            f"tdx-init rejected config: {response.status_code} {response.text}"
        )

    raise TimeoutError(
        f"tdx-init listener at {url} never came up after "
        f"{TDX_INIT_LISTENER_TIMEOUT_SECONDS}s (last error: {last_error})"
    )


def deliver_config(
    descriptor: NodeDescriptor,
    manifest_path: Path,
    email: str,
    *,
    genesis_node: bool,
    reth_genesis_path: Path,
    summit_genesis_path: Path,
    bootnodes: list[str],
    print_summary: bool = True,
    manifest_bin: str = shell_outs.DEFAULT_MANIFEST_BIN,
) -> bool:
    """Build + POST one node's config, then watch its first-boot LUKS wipe.
    The per-node delivery path behind `seismic-tee-node configure`
    (join: genesis_node=False).

    Takes the node's public_ip/fqdn from its descriptor (fqdn is the cert
    domain and must resolve to this node, so it's required — a wrong/absent
    name fails certbot at boot). The public_ip doubles as `[node].external_ip`
    (reth's `--nat extip`), the same anti-drift reason `[node.domain]` is taken
    from the descriptor. Raises SystemExit if the node doesn't reach a ready
    state within the watch window, so a failure never reads as success.

    Returns whether the node was *confirmed* ready (attestation service
    :7878 up): False when the operator stopped watching early, so a caller
    with post-ready work (deploy verification) knows not to attempt it.
    Such a caller passes `print_summary=False` and prints the summary once
    its own check passes — the summary is the success banner, so nothing
    should print it before the last gate.
    """
    public_ip = descriptor.public_ip
    fqdn = descriptor.fqdn
    role = "genesis" if genesis_node else "join"

    # Assemble the POST config before contacting the node, so bad local input
    # (invalid manifest, missing bootnode) fails fast.
    config = build_config(
        manifest_path,
        fqdn,
        email,
        genesis_node=genesis_node,
        reth_genesis_path=reth_genesis_path,
        summit_genesis_path=summit_genesis_path,
        external_ip=public_ip,
        bootnodes=bootnodes,
    )
    logger.info(f"Built {role} config for {fqdn} -> {config}")

    logger.info(f"Configuring node {fqdn} ({public_ip}) as {role}...")
    post_config_to_tdx_init(public_ip, config)
    logger.info("config delivered to tdx-init.")

    # Watch the first-boot LUKS wipe — the long, otherwise-opaque phase.
    # Purely local observability: the POST already landed, so ctrl-C here
    # only stops watching; the node keeps provisioning in the background.
    try:
        rc = watch_luks_provisioning(public_ip)
    except KeyboardInterrupt:
        print("\nStopped watching — node still provisioning in the background.")
        if print_summary:
            _print_summary(fqdn, public_ip)
        return False

    if rc != 0:
        # The POST succeeded, but the node never reached a ready state within
        # the watch window: the attestation service's :7878 didn't come up (it only
        # starts serving once it has root_key) or the LUKS wipe errored. Don't
        # print a success summary — that's the misleading case. It may still be
        # mid-bootstrap (e.g. fetching root_key from a slow peer), so point at a
        # re-watch rather than declaring the node dead; exit non-zero either way.
        raise SystemExit(
            f"config delivered to {fqdn} ({public_ip}), but the node did not "
            "reach a ready state within the watch window (attestation service "
            ":7878 never came up, or the LUKS wipe errored). It may still be "
            "bootstrapping, or stuck — check attestation-service logs on the node, "
            "then re-watch with:\n    seismic-tee-node status --node <file> "
            "[--name <node>]"
        )

    if print_summary:
        _print_summary(fqdn, public_ip)
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="seismic-tee-node configure",
        description="Configure a provisioned Seismic TEE node to join a network.",
    )
    add_node_args(parser)
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        metavar="FILE",
        help=(
            "Network manifest JSON (from `seismic-tee-network assemble`). "
            "Merged into the POSTed config as [network].manifest_base64; shared "
            "across every node, so it lives outside the per-node flags."
        ),
    )
    parser.add_argument(
        "--reth-genesis",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "reth genesis JSON POSTed to the node as "
            "[network].reth_genesis_base64; tdx-init writes it to "
            "/run/seismic/conf/reth-genesis.json for reth's --chain. Must be "
            "the file the manifest's eth.genesis_hash was computed from. "
            "Default: reth-genesis.json beside --manifest (the artifact-set "
            "layout `assemble` produces)."
        ),
    )
    parser.add_argument(
        "--summit-genesis",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "summit genesis TOML POSTed to the node as "
            "[network].summit_genesis_base64; tdx-init writes it to "
            "/run/seismic/conf/summit-genesis.toml for summit's "
            "--genesis-path. Must be the file the manifest's "
            "summit.genesis_config_digest was computed from. Default: "
            "summit-genesis.toml beside --manifest (the artifact-set layout "
            "`assemble` produces)."
        ),
    )
    parser.add_argument(
        "--bootnode",
        action="append",
        required=True,
        metavar="ENODE",
        help=(
            "Bootnode enode URL "
            "(enode://<pubkey>@<host>:<port>) → [network].bootnodes. reth "
            "dials it on startup, and tdx-init derives the root_key fetch "
            "peer from it (http://<host>:7878). Repeatable; required — a "
            "joining node has no root_key of its own. Fetch a running node's "
            "enode from its seismic_nodeInfo RPC (the founding set a network "
            "writes to nodes/bootnodes.json)."
        ),
    )
    parser.add_argument(
        "--email",
        default="ops@seismic.systems",
        help=(
            "Contact email for the node's Let's Encrypt registration (certbot); "
            "goes into [node.domain].email of the POSTed config. Same across a "
            "cohort. Default: ops@seismic.systems."
        ),
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help=(
            "Configure the node without deploy-verifying it. By default the "
            "node is appraised once it is up — the same check as "
            "`seismic-tee-node verify`, against the policy --manifest pins — "
            "and this command exits nonzero unless it passes."
        ),
    )
    verify_mod.add_policy_source_args(parser)
    verify_mod.add_tooling_args(parser)

    args = parser.parse_args()
    args.descriptor = load_node_arg(args)
    if not args.manifest.is_file():
        raise SystemExit(f"--manifest file not found: {args.manifest}")
    verify_mod.check_policy_source_files(args)
    return args


def main() -> None:
    setup_logging()
    args = parse_args()
    descriptor: NodeDescriptor = args.descriptor

    # Resolve the verification tooling and policy before the node is touched:
    # a missing verifier, a policy the manifest doesn't commit to, or a
    # rejected measurements file must fail while the fix still costs nothing,
    # not after the config POST landed.
    policy_bytes = verify_mod.prepare_policy_optional(args, subject="this node")
    reth_genesis = resolve_reth_genesis(args.reth_genesis, args.manifest)
    summit_genesis = resolve_summit_genesis(args.summit_genesis, args.manifest)
    ready = deliver_config(
        descriptor,
        args.manifest,
        args.email,
        genesis_node=False,
        reth_genesis_path=reth_genesis,
        summit_genesis_path=summit_genesis,
        bootnodes=args.bootnode,
        # With verification requested, the summary belongs after it passes.
        print_summary=policy_bytes is None,
        manifest_bin=args.manifest_bin,
    )

    if policy_bytes is None:
        return
    if not ready:
        # The operator stopped watching before the attestation service came
        # up, so there is nothing to challenge yet. Exit nonzero — the
        # requested verification did not happen — and point at the standalone
        # command: the config this boot needs is already delivered.
        name_flag = f" --name {args.name}" if args.name else ""
        raise SystemExit(
            "deploy verification skipped: the node was not confirmed ready. "
            f"Once it is up, run:\n    seismic-tee-node verify --node "
            f"{args.node}{name_flag} --manifest {args.manifest}"
            f"{verify_mod.retry_flags(args)}"
        )
    verify_mod.verify_deployment(
        args, policy_bytes, fqdn=descriptor.fqdn, public_ip=descriptor.public_ip
    )
    _print_summary(descriptor.fqdn, descriptor.public_ip)


def _print_summary(fqdn: str, public_ip: str) -> None:
    print("\n" + "=" * 80)
    print("NODE CONFIGURED")
    print("=" * 80)
    print(f"\nNode:       {fqdn}")
    print(f"IP Address: {public_ip}")
    print("\nNginx + SSL set up automatically after initialization.")
    print("Endpoints (once the node settles):")
    print(f"  https://{fqdn}/rpc")
    print(f"  https://{fqdn}/ws")
    print(f"  https://{fqdn}/summit")
    print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    main()
