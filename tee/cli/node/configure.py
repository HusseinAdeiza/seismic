#!/usr/bin/env python3
"""Operator node configuration: configure a node to JOIN a network.

Assemble a node's tdx-init config from flags + a descriptor + the network
manifest, and POST it to a provisioned node's tdx-init HTTP receiver:

    seismic-tee configure --node n2.json --peer n1.json --manifest m.json

The operator CLI only ever *joins* an existing network (`genesis_node =
false`): the node fetches `root_key` from a `--peer` via `getWrappedRootKey`.
Founding a network — designating the one genesis node that mints `root_key`
locally — is an internal act owned by `seismic-tee-bootstrap configure`, not
exposed here. `build_config`/`deliver_config` below are the shared primitives
both CLIs call; `genesis_node=True` is only ever set by the bootstrap side.

There is no per-node `node.toml`: `[enclave]` (genesis_node + peers) comes
from flags, `[domain]` from the descriptor fqdn + `--email`, and `[network]`
from `--manifest` + `--reth-genesis`. Those network-wide artifacts stay
standalone files, merged only at POST time. The node address is *brought by
the operator* via a descriptor file (see tee/cli/common/descriptor.py), typically
`pulumi stack output --json`. The CLI never provisions infrastructure
(Pulumi's job).

The POSTed TOML shape (`[domain]`/`[enclave]`/`[network]`) is unchanged, so
tdx-init and the `SEISMIC_ENCLAVE_*` env-var contract it emits are untouched.
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
# enclave-server's RPC port: a joiner reaches `getWrappedRootKey` here to
# fetch `root_key`. The attested ECDH/AES-GCM handshake runs at the
# application layer, so this is plain http on the raw port — not the
# nginx-fronted :443 that carries /rpc, /ws, /summit.
ENCLAVE_PEER_PORT = 7878
# How long to wait for tdx-init's HTTP listener to come up. tdx-init
# starts after persistent-luks-setup, which can take ~20-40s on first
# boot (LUKS format + mkfs + TPM enroll).
TDX_INIT_LISTENER_TIMEOUT_SECONDS = 180
TDX_INIT_RETRY_INTERVAL_SECONDS = 5


def resolve_peer(peer: str) -> str:
    """Resolve a `--peer` argument to an enclave-server URL.

    Accepts either a ready URL (`http://host:7878`, what a late joiner uses
    against a public entrypoint — post-POC, sourced from the on-chain operator
    registry) or a path to a node descriptor JSON, from which
    `http://<public_ip>:ENCLAVE_PEER_PORT` is derived (the founding-cohort
    form — reuses the peer's own descriptor, so its IP can't drift from what
    provisioning emitted, the same anti-drift reason [domain] is taken from
    the descriptor fqdn).
    """
    if peer.startswith(("http://", "https://")):
        return peer
    path = Path(peer)
    if not path.is_file():
        raise SystemExit(
            f"--peer {peer!r}: expected a URL (http://host:{ENCLAVE_PEER_PORT}) "
            "or a path to a node descriptor JSON, but found no such file"
        )
    descriptor = load_descriptor(path)
    public_ip = require(descriptor, "public_ip", path)
    return f"http://{public_ip}:{ENCLAVE_PEER_PORT}"


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
    peers: list[str],
    reth_genesis_path: Path,
) -> Path:
    """Assemble the config POSTed to tdx-init, mutating no source. The fields
    come from five inputs: the role (`genesis_node` + `peers` → `[enclave]`),
    the descriptor's fqdn (→ `[domain].name`, the cert domain), `--email`
    (→ `[domain].email`), and the network manifest + reth genesis
    (`--manifest`/`--reth-genesis` → `[network]`). Written fresh, so there is
    no operator-supplied TOML that could carry a conflicting
    `[domain]`/`[network]` and fork the network.

    `genesis_node=True` (peers empty) is only ever passed by the bootstrap
    founding command; the operator `configure` always joins (False + peers).
    """
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
    peers_toml = ", ".join(json.dumps(p) for p in peers)
    merged = (
        f"[enclave]\n"
        f"genesis_node = {str(genesis_node).lower()}\n"
        f"peers = [{peers_toml}]\n\n"
        f"[domain]\nname = {json.dumps(fqdn)}\nemail = {json.dumps(email)}\n\n"
        + manifest_mod.render_network_section(manifest_bytes, reth_genesis_bytes)
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
    peers: list[str],
    reth_genesis_path: Path,
    no_wait: bool,
) -> None:
    """Build + POST one node's config, then (unless `no_wait`) watch its
    first-boot LUKS wipe. The shared per-node delivery path behind both
    `seismic-tee configure` (join: genesis_node=False + peers) and
    `seismic-tee-bootstrap configure` (genesis: genesis_node=True + no peers).

    Resolves the node's public_ip/fqdn from its descriptor (fqdn is the cert
    domain and must resolve to this node, so it's required — a wrong/absent
    name fails certbot at boot). Raises SystemExit if the node doesn't reach a
    ready state within the watch window, so a failure never reads as success.
    """
    descriptor = load_descriptor(descriptor_path)
    public_ip = require(descriptor, "public_ip", descriptor_path)
    fqdn = require(descriptor, "fqdn", descriptor_path)
    role = "genesis" if genesis_node else "join"

    # Assemble the POST config before contacting the node, so bad local input
    # (invalid manifest, unresolvable peer) fails fast.
    config = build_config(
        manifest_path,
        fqdn,
        email,
        genesis_node=genesis_node,
        peers=peers,
        reth_genesis_path=reth_genesis_path,
    )
    logger.info(f"Built {role} config for {fqdn} -> {config}")

    logger.info(f"Configuring node {fqdn} ({public_ip}) as {role}...")
    post_config_to_tdx_init(public_ip, config)
    logger.info("config delivered to tdx-init.")

    if no_wait:
        # Caller opted out of watching (CI/headless); the POST landed, so
        # report where the node will be and leave it provisioning.
        _print_summary(fqdn, public_ip)
        return

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
        # the watch window: enclave-server's :7878 didn't come up (it only
        # starts serving once it has root_key) or the LUKS wipe errored. Don't
        # print a success summary — that's the misleading case. It may still be
        # mid-bootstrap (e.g. fetching root_key from a slow peer), so point at a
        # re-watch rather than declaring the node dead; exit non-zero either way.
        raise SystemExit(
            f"config delivered to {fqdn} ({public_ip}), but the node did not "
            "reach a ready state within the watch window (enclave-server :7878 "
            "never came up, or the LUKS wipe errored). It may still be "
            "bootstrapping, or stuck — check enclave-server logs on the node, "
            "then re-watch with:\n    seismic-tee status --node <descriptor>"
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
        prog="seismic-tee configure",
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
        "--peer",
        action="append",
        required=True,
        metavar="URL|DESCRIPTOR",
        help=(
            "Peer to fetch root_key from: a node descriptor JSON "
            f"(→ http://<public_ip>:{ENCLAVE_PEER_PORT}) or a raw "
            f"http://host:{ENCLAVE_PEER_PORT} URL. Repeatable; the enclave "
            "tries them in order. Required — a joining node has no root_key "
            "of its own."
        ),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        metavar="FILE",
        help=(
            "Network manifest JSON (from `seismic-tee-bootstrap manifest assemble`). "
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
            "reth genesis JSON (chain spec) POSTed to the node as "
            "[network].reth_genesis_base64; tdx-init writes it to "
            "/run/seismic/conf/reth-genesis.json for reth's --chain. Must be "
            "the file the manifest's eth.genesis_hash was computed from. "
            "Default: reth-genesis.json beside --manifest (the artifact-set "
            "layout `manifest assemble --out` produces)."
        ),
    )
    parser.add_argument(
        "--email",
        default="ops@seismic.systems",
        help=(
            "Contact email for the node's Let's Encrypt registration (certbot); "
            "goes into [domain].email of the POSTed config. Same across a "
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
    parser.add_argument(
        "--no-wait",
        action="store_true",
        default=False,
        help=(
            "Don't watch first-boot LUKS provisioning after POSTing. Default "
            "is to watch (ctrl-C to stop); use this for CI/headless runs where "
            "there's no TTY to interrupt and the wipe can take 1h+."
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

    peers = [resolve_peer(p) for p in args.peer]
    reth_genesis = resolve_reth_genesis(args.reth_genesis, args.manifest)
    deliver_config(
        args.node,
        args.manifest,
        args.email,
        genesis_node=False,
        peers=peers,
        reth_genesis_path=reth_genesis,
        no_wait=args.no_wait,
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
