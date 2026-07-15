"""Genesis ceremony (network creation, one-time).

Gathers every cohort node's summit pubkeys, builds one `genesis.toml`
for the whole initial validator set, and POSTs it back to each node's
summit. This is run *once*, by whoever brings a network up — a validator
joining an already-bootstrapped network never runs it (it joins via the
deposit contract + sync, and is configured with `genesis_node = false`).

`eth_genesis_hash` comes from the network manifest (`--manifest`), where
`manifest assemble` pinned it at deploy time — the ceremony needs no
`seismic-reth` binary. Before building anything, every cohort node's
reth is asserted to actually serve that hash as block 0, so a node
booted from a stale image or wrong genesis fails the ceremony loudly
instead of parking summit in SYNCING forever.

The ceremony doubles as the cohort barrier: its two probes (reth block 0,
summit `getPublicKeys`) answer only after a node finishes root_key → LUKS
open → summit keygen, and both are polled until every node responds — so
it can run straight after `configure` without hand-timing the boot tail.

Each node is located by a descriptor file (see tee/cli/common/descriptor.py),
so this never calls Pulumi.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import requests

from tee.cli.common import manifest as manifest_mod
from tee.cli.common.dashboard import CohortDashboard
from tee.cli.common.descriptor import load_descriptor, require
from tee.cli.network.summit_client import PublicKeys, SummitClient
from tee.cli.node.status import fetch_status, format_provisioning

# Summit's consensus (BLS) port. Each validator entry in the generated
# genesis.toml pins "<ip>:<CONSENSUS_PORT>".
CONSENSUS_PORT = 18551

# Cohort-readiness polling (the barrier). `configure` normally watches the
# first-boot disk wipe. If the ceremony observes one still running, it displays
# that progress and pauses the residual reth-readiness timeout.
POLL_INTERVAL_SECONDS = 5
READY_TIMEOUT_SECONDS = 15 * 60
WAIT_LOG_INTERVAL_SECONDS = 30

# anvil/sanvil dev accounts: the first 10 addresses from the well-known
# "test test test ... junk" mnemonic. Their private keys are public, so
# these are devnet-only — never use them as withdrawal_credentials on a
# real network (anyone could sweep the withdrawals).
# TODO(samlaf): take withdrawal_credentials (and other per-validator config)
# from each node's bootstrap input rather than this shared placeholder list,
# which also silently repeats once a cohort exceeds 10 nodes.
_ANVIL_ADDRESSES = [
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
    "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
    "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
    "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
    "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
    "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--node",
        type=Path,
        nargs="+",
        action="append",
        default=None,
        metavar="DESCRIPTOR",
        help=(
            "Node descriptor JSON file(s), one per cohort node in validator "
            "order — `--node n1.json n2.json` and `--node n1.json --node "
            "n2.json` both work (with plain nargs, a repeated flag silently "
            "*replaces* the earlier one and drops nodes from the ceremony). "
            "Each descriptor's fqdn/public_ip locates that node; produce them "
            "standalone, e.g. `pulumi stack output --json > node-1.json`. "
            "Default: every *.json in the nodes/ dir beside --manifest "
            "(written by `up --network`), sorted by name."
        ),
    )
    parser.add_argument(
        "--summit-template",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "Summit genesis template TOML (network-params without "
            "[[validators]]) the `genesis` binary fills validators into. Must "
            "be the copy the manifest commits to (summit.genesis_template_"
            "hash) — verified before building. Default: summit-genesis-"
            "template.toml beside --manifest (the artifact-set layout "
            "`manifest assemble --out` produces)."
        ),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        metavar="FILE",
        help=(
            "Network manifest JSON (from `manifest assemble`) — the same file "
            "every node was configured with. Its eth.genesis_hash is pinned "
            "into genesis.toml."
        ),
    )
    parser.add_argument(
        "-g",
        "--genesis-hash",
        type=str,
        default=None,
        help=(
            "Dev-only override of the manifest's eth.genesis_hash. The cohort "
            "assertion still runs against the overridden value."
        ),
    )
    args = parser.parse_args(argv)
    if not args.manifest.is_file():
        raise SystemExit(f"--manifest file not found: {args.manifest}")
    if args.node is None:
        nodes_dir = args.manifest.parent / manifest_mod.NODES_DIRNAME
        args.node = sorted(nodes_dir.glob("*.json"))
        if not args.node:
            raise SystemExit(
                f"no --node given and no descriptors in {nodes_dir} (written "
                "by `up --network`); pass --node explicitly"
            )
    else:
        # append+nargs yields one list per --node occurrence; flatten to the
        # cohort list callers expect.
        args.node = [path for group in args.node for path in group]
        dupes = sorted({str(p) for p in args.node if args.node.count(p) > 1})
        if dupes:
            raise SystemExit(f"duplicate --node descriptor(s): {', '.join(dupes)}")
    for path in args.node:
        if not path.is_file():
            raise SystemExit(f"--node descriptor not found: {path}")
    defaulted = args.summit_template is None
    if defaulted:
        args.summit_template = (
            args.manifest.parent / manifest_mod.SUMMIT_TEMPLATE_FILENAME
        )
    if not args.summit_template.is_file():
        hint = (
            " (the default is summit-genesis-template.toml beside --manifest; "
            "pass --summit-template if it lives elsewhere)"
            if defaulted
            else ""
        )
        raise SystemExit(f"--summit-template not found: {args.summit_template}{hint}")
    return args


def _get_pubkeys(
    descriptors: list[Path],
    *,
    timeout: float = READY_TIMEOUT_SECONDS,
    interval: float = POLL_INTERVAL_SECONDS,
) -> tuple[list[dict[str, str]], list[tuple[Path, SummitClient]]]:
    """Gather each cohort node's summit pubkeys from its descriptor file.

    Resolves every node's fqdn/public_ip from its descriptor (see
    tee/cli/common/descriptor.py), so the summit endpoints come from whatever
    infra tool produced the descriptor — this script never calls Pulumi.
    Returns the validator entries and the per-node summit clients (reused
    for the genesis.toml fanout).

    Each node is polled until its pubkeys are readable: getPublicKeys
    answers only once summit is up with generated keys (after root_key →
    LUKS open → keygen), so an unreadable node is normally just still
    booting. A node still unreadable at `timeout` aborts the ceremony with
    a per-node report.
    """
    node_clients: list[tuple[Path, SummitClient]] = []
    ip_addresses: dict[Path, str] = {}
    for path in descriptors:
        descriptor = load_descriptor(path)
        fqdn = require(descriptor, "fqdn", path)
        ip_addresses[path] = require(descriptor, "public_ip", path)
        node_clients.append((path, SummitClient(f"https://{fqdn}/summit")))

    pubkeys: dict[Path, PublicKeys] = {}
    last_error: dict[Path, str] = {}
    started = time.monotonic()
    deadline = started + timeout
    next_log = 0.0
    while True:
        for path, client in node_clients:
            if path in pubkeys:
                continue
            try:
                pubkeys[path] = client.get_public_keys()
                print(f"  ✓ {path.stem}: summit pubkeys readable")
            except Exception as e:
                last_error[path] = str(e)
        pending = [path for path in descriptors if path not in pubkeys]
        if not pending:
            break
        now = time.monotonic()
        if now >= deadline:
            listing = "\n".join(f"  ✗ {path}: {last_error[path]}" for path in pending)
            raise SystemExit(
                f"{len(pending)} node(s) still without readable summit pubkeys "
                f"after {int(timeout)}s (stuck before keygen?); aborting the "
                f"ceremony:\n{listing}"
            )
        if now >= next_log:
            elapsed = int(now - started)
            remaining = max(0, int(deadline - now))
            print(
                f"waiting for summit pubkeys ({elapsed}s elapsed, "
                f"{remaining}s until timeout): "
                + ", ".join(path.stem for path in pending)
            )
            next_log = now + WAIT_LOG_INTERVAL_SECONDS
        time.sleep(interval)

    validators = [
        {
            "node_public_key": pubkeys[path].node,
            "consensus_public_key": pubkeys[path].consensus,
            "ip_address": f"{ip_addresses[path]}:{CONSENSUS_PORT}",
            "withdrawal_credentials": _ANVIL_ADDRESSES[i % len(_ANVIL_ADDRESSES)],
        }
        for i, path in enumerate(descriptors)
    ]
    return validators, node_clients


def _verify_template_commitment(template_path: Path, manifest: dict) -> None:
    """Assert the template is the one the manifest commits to
    (summit.genesis_template_hash).

    The `-g` override protects only `eth_genesis_hash`; everything else in
    the template (namespace, timeouts, stake bounds) flows into genesis.toml
    as-is, so building from uncommitted bytes would start the chain on
    parameters the manifest never pinned.
    """
    computed = "0x" + hashlib.sha256(template_path.read_bytes()).hexdigest()
    committed = manifest["summit"]["genesis_template_hash"]
    if computed != committed.lower():
        raise SystemExit(
            f"--summit-template {template_path} is not the template the "
            "manifest commits to (summit.genesis_template_hash); refusing to "
            "build genesis.toml:\n"
            f"    committed: {committed}\n"
            f"    computed:  {computed}\n"
            "Use the artifact-set copy written by `manifest assemble --out` "
            "(the default when it sits beside --manifest)."
        )


def _assert_cohort_genesis_hash(
    descriptors: list[Path],
    expected: str,
    *,
    timeout: float = READY_TIMEOUT_SECONDS,
    interval: float = POLL_INTERVAL_SECONDS,
) -> None:
    """Assert every cohort node's reth serves `expected` as block 0.

    summit's genesis `eth_genesis_hash` must equal reth's real genesis hash:
    summit uses it as its initial forkchoice head, and a hash reth doesn't
    know parks reth in SYNCING forever with no error on either side (reth
    can't tell the unknown hash was meant to be its block 0). The manifest
    declares the intended hash; reading each node's live block 0 catches a
    node booted from a different image/genesis before the ceremony pins the
    validator set — and doubles as a reth-readiness probe before
    send_genesis.

    A node that doesn't answer is polled until `timeout` — reth comes up
    only after root_key → LUKS open, so early unreachability is the normal
    boot tail. Active disk provisioning is shown through the shared cohort
    dashboard and pauses this timeout. A *wrong* answer fails immediately:
    waiting can't fix a node booted from a stale image or different genesis.
    """
    urls: dict[Path, str] = {}
    public_ips: dict[Path, str] = {}
    for path in descriptors:
        descriptor = load_descriptor(path)
        fqdn = require(descriptor, "fqdn", path)
        public_ips[path] = require(descriptor, "public_ip", path)
        urls[path] = f"https://{fqdn}/rpc"  # nginx proxies /rpc -> reth :8545

    dashboard = CohortDashboard({str(path): path.stem for path in descriptors})
    states = {str(path): "waiting for reth block 0" for path in descriptors}
    observed: dict[Path, str] = {}  # block-0 hash, once a node has answered
    last_error: dict[Path, str] = {}
    started = time.monotonic()
    deadline = started + timeout
    provisioning_active = False
    while True:
        iteration_started = time.monotonic()
        for path in descriptors:
            if path in observed:
                continue
            try:
                response = requests.post(
                    urls[path],
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_getBlockByNumber",
                        "params": ["0x0", False],
                    },
                    timeout=30,
                )
                response.raise_for_status()
                data = response.json()
                if data.get("result") is None:
                    raise RuntimeError(
                        f"eth_getBlockByNumber returned {data.get('error') or data}"
                    )
                observed[path] = data["result"]["hash"]
                if observed[path].lower() == expected.lower():
                    states[str(path)] = "reth block 0 matches"
                else:
                    states[str(path)] = f"wrong reth block 0: {observed[path]}"
            except Exception as e:
                last_error[path] = f"unreachable via {urls[path]}: {e}"

        pending = [path for path in descriptors if path not in observed]
        mismatch = any(h.lower() != expected.lower() for h in observed.values())
        if mismatch or not pending:
            dashboard.render(states)
            break

        reth_probe_finished = time.monotonic()
        if provisioning_active:
            deadline += reth_probe_finished - iteration_started

        provisioning: set[Path] = set()
        details: dict[Path, str] = {}
        for path in pending:
            try:
                status = fetch_status(public_ips[path], timeout=2)
            except (requests.RequestException, RuntimeError, KeyError, ValueError):
                details[path] = "waiting for reth block 0"
                continue

            state = status.get("state")
            if state == "provisioning":
                provisioning.add(path)
                states[str(path)] = (
                    f"{format_provisioning(status)}  (readiness timeout paused)"
                )
            elif state == "error":
                details[path] = (
                    "disk provisioning error, auto-retrying: "
                    f"{status.get('error', '?')}"
                )
            elif state == "idle":
                details[path] = "disk idle; waiting for reth block 0"
            else:
                details[path] = f"disk status {state!r}; waiting for reth block 0"

        now = time.monotonic()
        if provisioning:
            paused_since = (
                reth_probe_finished if provisioning_active else iteration_started
            )
            deadline += now - paused_since
        elapsed = int(now - started)
        elapsed -= elapsed % WAIT_LOG_INTERVAL_SECONDS
        remaining = max(0, int(deadline - now))
        remaining = (
            (remaining + WAIT_LOG_INTERVAL_SECONDS - 1)
            // WAIT_LOG_INTERVAL_SECONDS
            * WAIT_LOG_INTERVAL_SECONDS
        )
        for path in pending:
            if path not in provisioning:
                states[str(path)] = (
                    f"{details[path]} ({elapsed}s elapsed, {remaining}s until timeout)"
                )
        dashboard.render(states)

        if now >= deadline:
            break
        sleep_started = time.monotonic()
        time.sleep(interval)
        if provisioning:
            deadline += time.monotonic() - sleep_started
        provisioning_active = bool(provisioning)

    if mismatch or pending:
        # Report the full cohort, not just the first bad node — a partial
        # listing is ambiguous with "stopped at the first bad node", and
        # which nodes match is exactly the diagnostic (one stale node vs. a
        # manifest that matches nobody).
        listing = "\n".join(
            f"  {'✓' if h.lower() == expected.lower() else '✗'} {path}: {h}"
            for path, h in (
                (path, observed.get(path) or last_error[path]) for path in descriptors
            )
        )
        raise SystemExit(
            "Cohort disagrees with the declared eth_genesis_hash (stale image, "
            "wrong reth genesis, or a node that never became ceremony-ready); "
            f"refusing to build genesis.toml:\n    declared: {expected}\n{listing}"
        )


def main():
    args = _parse_args()

    # `genesis` is summit's binary; expect it on PATH (build summit and symlink
    # its target/debug/genesis onto PATH, the same way summit expects `reth`).
    # Fail with a clear message instead of a subprocess FileNotFoundError.
    genesis_bin = shutil.which("genesis")
    if genesis_bin is None:
        raise SystemExit(
            "`genesis` binary not found on PATH. Build summit and put its "
            "`genesis` binary on PATH, e.g. "
            "`ln -s <summit>/target/debug/genesis ~/.cargo/bin/genesis`."
        )

    try:
        manifest = manifest_mod.validate_manifest_schema(args.manifest.read_bytes())
    except manifest_mod.ManifestSchemaError as e:
        raise SystemExit(f"--manifest {args.manifest}: invalid manifest: {e}") from None
    _verify_template_commitment(args.summit_template, manifest)
    manifest_hash = manifest["eth"]["genesis_hash"]

    genesis_hash = args.genesis_hash or manifest_hash
    if genesis_hash.lower() != manifest_hash.lower():
        print(
            f"WARNING: -g {genesis_hash} overrides the manifest's "
            f"eth.genesis_hash {manifest_hash}"
        )
    print(f"Pinning eth_genesis_hash = {genesis_hash}")
    timeout_minutes = READY_TIMEOUT_SECONDS // 60
    print(
        "Waiting for cohort readiness. `configure` normally waits for root-key "
        "bootstrap and encrypted-disk initialization; if that watch was skipped, "
        "interrupted, or followed by service recovery, readiness can still take "
        f"several minutes. Each stage has a {timeout_minutes}-minute readiness "
        "timeout; the reth stage pauses it while disk provisioning is active."
    )
    print("Readiness 1/2: verifying every node's reth block 0...")
    _assert_cohort_genesis_hash(args.node, genesis_hash)

    tmpdir = tempfile.mkdtemp()
    print("Readiness 2/2: gathering every node's Summit public keys...")
    validators, node_clients = _get_pubkeys(args.node)

    tmp_validators = f"{tmpdir}/validators.json"
    with open(tmp_validators, "w+") as f:
        print(f"Wrote validators to {tmp_validators}")
        json.dump(validators, f, indent=2)

    # Output streams to the terminal (check=True raises on failure).
    subprocess.run(
        [
            genesis_bin,
            "-o",
            tmpdir,
            "-i",
            str(args.summit_template),
            "-v",
            tmp_validators,
            "-g",
            genesis_hash,
        ],
        check=True,
    )

    # Log the built genesis's path (not its contents) before delivery, mirroring
    # how `configure` logs the merged node config it POSTs.
    genesis_path = Path(f"{tmpdir}/genesis.toml")
    print(f"Built genesis -> {genesis_path}")

    for _, client in node_clients:
        print(f"Sending genesis to {client.url}")
        client.post_genesis_filepath(genesis_path)


if __name__ == "__main__":
    main()
