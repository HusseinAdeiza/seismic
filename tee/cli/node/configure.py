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
locally — is an internal act owned by `seismic-tee-network configure`, not
exposed here. `build_config`/`deliver_config` below are the shared primitives
both CLIs call; `genesis_node=True` is only ever set by the bootstrap side.

There is no per-node `node.toml`: `[node]` (external_ip + genesis_node) comes
from the descriptor + role, `[node.domain]` from the descriptor fqdn +
`--email`, and `[network]` from `--manifest` + `--reth-genesis` +
`--bootnode`. Those network-wide artifacts stay standalone files, merged only
at POST time. The node address is *brought by the operator* via a descriptor
file (see tee/cli/common/descriptor.py), typically
`pulumi stack output --json`. The CLI never provisions infrastructure
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
from tee.cli.common.descriptor import load_descriptor, require
from tee.cli.common.logging_setup import setup_logging
from tee.cli.node.proxy import ProxyClient
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
    `reth-genesis.json` beside the manifest, exactly where `manifest assemble
    --out` writes its byte-verbatim copy — so the file POSTed is the one the
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


def build_config(
    manifest_path: Path,
    fqdn: str,
    email: str,
    *,
    genesis_node: bool,
    reth_genesis_path: Path,
    external_ip: str,
    bootnodes: list[str],
) -> Path:
    """Assemble the config POSTed to tdx-init, mutating no source. The fields
    come from: the node's public IP (→ `[node].external_ip`, reth's
    `--nat extip`), the role (→ `[node].genesis_node`), the descriptor's fqdn
    (→ `[node.domain].name`, the cert domain), `--email`
    (→ `[node.domain].email`), and the network manifest + reth genesis +
    bootnode set (`--manifest`/`--reth-genesis`/`bootnodes` → `[network]`).
    Written fresh, so there is no operator-supplied TOML that could carry a
    conflicting `[node]`/`[network]` and fork the network.

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
        manifest = manifest_mod.validate_manifest_schema(manifest_bytes)
    except manifest_mod.ManifestSchemaError as e:
        raise SystemExit(f"--manifest {manifest_path}: invalid manifest: {e}") from None

    reth_genesis_bytes = reth_genesis_path.read_bytes()
    try:
        manifest_mod.validate_reth_genesis_matches(manifest, reth_genesis_bytes)
    except manifest_mod.GateError as e:
        raise SystemExit(f"--reth-genesis {reth_genesis_path}: {e}") from None

    # json.dumps emits valid TOML basic strings for these simple ASCII values.
    merged = (
        f"[node]\n"
        f"external_ip = {json.dumps(external_ip)}\n"
        f"genesis_node = {str(genesis_node).lower()}\n\n"
        f"[node.domain]\nname = {json.dumps(fqdn)}\nemail = {json.dumps(email)}\n\n"
        + manifest_mod.render_network_section(
            manifest_bytes, reth_genesis_bytes, bootnodes
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
    descriptor_path: Path,
    manifest_path: Path,
    email: str,
    *,
    genesis_node: bool,
    reth_genesis_path: Path,
    bootnodes: list[str],
) -> None:
    """Build + POST one node's config, then watch its first-boot LUKS wipe.
    The shared per-node delivery path behind both
    `seismic-tee-node configure` (join: genesis_node=False) and
    `seismic-tee-network configure` (genesis: genesis_node=True).

    Resolves the node's public_ip/fqdn from its descriptor (fqdn is the cert
    domain and must resolve to this node, so it's required — a wrong/absent
    name fails certbot at boot). The public_ip doubles as `[node].external_ip`
    (reth's `--nat extip`), the same anti-drift reason `[node.domain]` is taken
    from the descriptor. Raises SystemExit if the node doesn't reach a ready
    state within the watch window, so a failure never reads as success.
    """
    descriptor = load_descriptor(descriptor_path)
    public_ip = require(descriptor, "public_ip", descriptor_path)
    fqdn = require(descriptor, "fqdn", descriptor_path)
    role = "genesis" if genesis_node else "join"

    # Assemble the POST config before contacting the node, so bad local input
    # (invalid manifest, missing bootnode) fails fast.
    config = build_config(
        manifest_path,
        fqdn,
        email,
        genesis_node=genesis_node,
        reth_genesis_path=reth_genesis_path,
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
        _print_summary(fqdn, public_ip)
        return

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
            "then re-watch with:\n    seismic-tee-node status --node <descriptor>"
        )

    _print_summary(fqdn, public_ip)


def verify_attestation(public_ip: str, measurements_path: Path, home: str) -> None:
    """RETIRED reference — not currently called (see `main`).

    Verifies attestation via the legacy cvm-reverse-proxy client
    (`proxy.py`), which has no endpoint on current nodes and uses a
    different aTLS protocol than the enclave's attested-tls. Kept as a
    skeleton; verification will be reimplemented against attested-tls /
    seismic-attestation. `measurements_path` is the operator-supplied
    measurements.json.
    """
    logger.info("Verifying TDX attestation via cvm-reverse-proxy...")
    proxy = ProxyClient(public_ip, measurements_path, home)
    if not proxy.start():
        raise RuntimeError("attestation verification failed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="seismic-tee-node configure",
        description="Configure a provisioned Seismic TEE node to join a network.",
    )
    parser.add_argument(
        "--node",
        type=Path,
        required=True,
        metavar="DESCRIPTOR",
        help=(
            "Path to a node descriptor JSON (e.g. `pulumi stack output "
            "--json > node-2.json`). Provides the node's public_ip/fqdn."
        ),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        metavar="FILE",
        help=(
            "Network manifest JSON (from `seismic-tee-network manifest assemble`). "
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
            "layout `manifest assemble --out` produces)."
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
        "--measurements",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "(Currently unavailable.) Expected TDX measurements for "
            "attestation verification. The verify path is retired pending "
            "attested-tls integration, so passing this errors for now."
        ),
    )

    args = parser.parse_args()
    if not args.node.is_file():
        raise SystemExit(f"--node descriptor not found: {args.node}")
    if not args.manifest.is_file():
        raise SystemExit(f"--manifest file not found: {args.manifest}")
    return args


def main() -> None:
    setup_logging()
    args = parse_args()

    if args.measurements is not None:
        # TODO(attestation): verification is retired pending attested-tls
        # integration (see proxy.py). Refuse rather than silently skip a
        # check the operator explicitly requested.
        raise SystemExit(
            "--measurements: attestation verification is currently "
            "unavailable (cvm-reverse-proxy path retired, pending "
            "attested-tls). Re-run without --measurements to POST config only."
        )

    reth_genesis = resolve_reth_genesis(args.reth_genesis, args.manifest)
    deliver_config(
        args.node,
        args.manifest,
        args.email,
        genesis_node=False,
        reth_genesis_path=reth_genesis,
        bootnodes=args.bootnode,
    )


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
