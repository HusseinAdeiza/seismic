"""`seismic-tee-bootstrap configure` — found a network in one command.

Configures a whole cohort at once: the one genesis node (`--genesis`, mints
`root_key` locally) plus every joining node (`--join`, fetches `root_key` from
genesis via `getWrappedRootKey`). All nodes are POSTed and their first-boot
LUKS wipes watched **in parallel**, so an N-node bootstrap is one command
instead of N terminals. Exactly one node is genesis — assigned here, not left
to a per-node flag — so a double-genesis network split is unrepresentable.

Founding is an internal act, so this lives on the bootstrap CLI; joining an
already-live network is the operator `seismic-tee configure`. Both go through
the same `build_config` / `post_config_to_tdx_init` primitives and
`status.poll_provisioning`, so each node's POSTed config and wipe-watch are
identical — only the role (`genesis_node`/`peers`) differs.
"""

import argparse
import logging
import shutil
import sys
import threading
import time
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from tee.cli.common import manifest as manifest_mod
from tee.cli.common.descriptor import load_descriptor, require
from tee.cli.common.logging_setup import setup_logging
from tee.cli.node.configure import (
    ENCLAVE_PEER_PORT,
    TDX_INIT_PORT,
    build_config,
    post_config_to_tdx_init,
    resolve_reth_genesis,
)
from tee.cli.node.status import poll_provisioning

logger = logging.getLogger(__name__)


@dataclass
class Node:
    """One cohort member, resolved from its descriptor + assigned role."""

    name: str  # short label (the descriptor filename stem)
    public_ip: str
    fqdn: str
    genesis: bool
    peers: list[str] = field(default_factory=list)


def _load_node(descriptor_path: Path, *, genesis: bool, peers: list[str]) -> Node:
    descriptor = load_descriptor(descriptor_path)
    return Node(
        name=descriptor_path.stem,
        public_ip=require(descriptor, "public_ip", descriptor_path),
        fqdn=require(descriptor, "fqdn", descriptor_path),
        genesis=genesis,
        peers=peers,
    )


def build_cohort(genesis_path: Path, join_paths: list[Path]) -> list[Node]:
    """Resolve the cohort: exactly one genesis (peers empty — it mints), and
    every joiner pointed at the genesis node's enclave endpoint
    (`http://<genesis_ip>:7878`), so joiners fetch `root_key` from it. Role
    assignment lives here, not in a per-node flag, so there is exactly one
    genesis by construction.
    """
    genesis = _load_node(genesis_path, genesis=True, peers=[])
    genesis_peer = f"http://{genesis.public_ip}:{ENCLAVE_PEER_PORT}"
    joiners = [_load_node(p, genesis=False, peers=[genesis_peer]) for p in join_paths]
    nodes = [genesis, *joiners]

    # A descriptor passed twice (--genesis reused as --join, or a copy-pasted
    # --join) would race two conflicting POSTs against one node and silently
    # collide on the name-keyed dashboard/result dicts — refuse instead.
    for what, counts in (
        ("name", Counter(n.name for n in nodes)),
        ("public_ip", Counter(n.public_ip for n in nodes)),
    ):
        dupes = sorted(k for k, c in counts.items() if c > 1)
        if dupes:
            raise SystemExit(
                f"duplicate node {what}(s) in cohort: {', '.join(dupes)} — "
                "was the same descriptor passed more than once?"
            )
    return nodes


def _configure_node(
    node: Node,
    manifest_path: Path,
    reth_genesis_path: Path,
    email: str,
    no_wait: bool,
    states: dict[str, str],
    stop: threading.Event,
) -> bool:
    """Build + POST one node's config, then (unless `no_wait`) poll its LUKS
    wipe, writing the latest status line into `states[node.name]` for the
    dashboard. Returns whether the node reached a ready state. Never raises —
    a failure is recorded in `states` and reflected in the return, so one bad
    node doesn't abort the rest of the cohort. `stop` (set on ctrl-C) ends the
    wipe watch early so the worker joins promptly.
    """
    try:
        states[node.name] = "building config…"
        config = build_config(
            manifest_path,
            node.fqdn,
            email,
            genesis_node=node.genesis,
            peers=node.peers,
            reth_genesis_path=reth_genesis_path,
        )
        states[node.name] = f"POSTing config to tdx-init :{TDX_INIT_PORT}…"
        post_config_to_tdx_init(node.public_ip, config)
        if no_wait:
            states[node.name] = "config delivered (not waiting)"
            return True
        for update in poll_provisioning(node.public_ip, stop=stop):
            states[node.name] = update.line
            if update.done:
                return update.ok
        return False  # stopped early, or defensive against a silent generator end
    except Exception as e:  # noqa: BLE001 — surface per node, keep the cohort going
        states[node.name] = f"ERROR: {e}"
        return False


class _Dashboard:
    """Render N nodes' live status: an in-place multi-line block on a TTY,
    else one line per node printed only when it changes (readable in CI logs).
    """

    def __init__(self, nodes: list[Node]) -> None:
        self.isatty = sys.stdout.isatty()
        self.order = [n.name for n in nodes]
        self.labels = {
            n.name: n.name + (" (genesis)" if n.genesis else "") for n in nodes
        }
        self._width = max(len(label) for label in self.labels.values())
        self._painted = False
        self._last: dict[str, str] = {}

    def render(self, states: dict[str, str]) -> None:
        if self.isatty:
            cols = shutil.get_terminal_size((100, 24)).columns
            if self._painted:
                sys.stdout.write(f"\033[{len(self.order)}A")  # cursor up N lines
            for name in self.order:
                text = (
                    f"{self.labels[name].rjust(self._width)}  {states.get(name, '…')}"
                )
                if len(text) >= cols:
                    text = text[: cols - 1] + "…"
                sys.stdout.write(f"\033[2K{text}\n")  # clear line + write
            sys.stdout.flush()
            self._painted = True
        else:
            for name in self.order:
                line = states.get(name, "…")
                if self._last.get(name) != line:
                    print(f"{self.labels[name]}: {line}", flush=True)
                    self._last[name] = line


def _run_cohort(
    nodes: list[Node],
    manifest_path: Path,
    reth_genesis_path: Path,
    email: str,
    no_wait: bool,
) -> dict[str, bool]:
    """Configure every node concurrently, refreshing the dashboard until all
    workers finish. Returns {node name: ok}. Threads suit this — the work is
    blocking HTTP (POST + status polling), and N is small.
    """
    # The shared primitives log at INFO; that would corrupt the in-place
    # dashboard, and the per-node status lines convey the same progress. Quiet
    # them for the dashboard's duration (the process exits after, so no restore).
    logging.getLogger("tee").setLevel(logging.WARNING)

    states: dict[str, str] = {n.name: "queued…" for n in nodes}
    dashboard = _Dashboard(nodes)
    stop = threading.Event()
    futures: dict[str, Future[bool]] = {}
    with ThreadPoolExecutor(max_workers=len(nodes)) as pool:
        for node in nodes:
            futures[node.name] = pool.submit(
                _configure_node,
                node,
                manifest_path,
                reth_genesis_path,
                email,
                no_wait,
                states,
                stop,
            )
        try:
            # Refresh while workers block on POST/poll.
            while not all(f.done() for f in futures.values()):
                dashboard.render(states)
                time.sleep(1)
        except KeyboardInterrupt:
            # Must set `stop` before the pool's context exit joins the workers
            # — otherwise a wipe watch blocks that join for up to 1h+. With it,
            # workers exit within a poll interval (a worker still inside the
            # POST's listener wait is bounded at ~3min). The POSTs that landed
            # keep provisioning server-side either way.
            stop.set()
            print("\nStopped watching — configured nodes keep provisioning.")
            raise SystemExit(130) from None
        dashboard.render(states)  # final paint of terminal states
    return {name: f.result() for name, f in futures.items()}


def _report(nodes: list[Node], results: dict[str, bool]) -> None:
    print("\n" + "=" * 80)
    print("COHORT CONFIGURED")
    print("=" * 80)
    for node in nodes:
        ok = results.get(node.name, False)
        role = "genesis" if node.genesis else "join"
        print(f"  {'✓' if ok else '✗'} {node.name} ({role}) — https://{node.fqdn}/rpc")
    print("=" * 80 + "\n")

    genesis_failed = any(n.genesis and not results.get(n.name, False) for n in nodes)
    if genesis_failed:
        print(
            "Genesis node did not come up — joiners cannot fetch root_key until "
            "it does; they will keep retrying. Fix genesis first."
        )
    failed = [n.name for n in nodes if not results.get(n.name, False)]
    if failed:
        raise SystemExit(
            f"{len(failed)}/{len(nodes)} node(s) failed: {', '.join(failed)}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="seismic-tee-bootstrap configure",
        description="Configure a network cohort in parallel: one genesis + N joiners.",
    )
    parser.add_argument(
        "--genesis",
        type=Path,
        required=True,
        metavar="DESCRIPTOR",
        help=(
            "Descriptor for the one genesis node (mints root_key locally). "
            "Exactly one node per network is genesis; assigning it here (not a "
            "per-node flag) makes a double-genesis split impossible."
        ),
    )
    parser.add_argument(
        "--join",
        type=Path,
        action="append",
        default=[],
        metavar="DESCRIPTOR",
        help=(
            "Descriptor for a joining node (fetches root_key from genesis via "
            "getWrappedRootKey). Repeatable; omit for a genesis-only bring-up."
        ),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        metavar="FILE",
        help="Network manifest JSON (from `manifest assemble`); → [network].",
    )
    parser.add_argument(
        "--reth-genesis",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "reth genesis JSON (chain spec) POSTed to every node; → "
            "[network].reth_genesis_base64. Default: reth-genesis.json "
            "beside --manifest (the artifact-set layout)."
        ),
    )
    parser.add_argument(
        "--email",
        default="ops@seismic.systems",
        help="certbot contact email → [domain].email (default: ops@seismic.systems).",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        default=False,
        help="Don't watch first-boot LUKS provisioning after POSTing.",
    )
    args = parser.parse_args()
    for path in [args.genesis, *args.join, args.manifest]:
        if not path.is_file():
            raise SystemExit(f"file not found: {path}")
    return args


def main() -> None:
    setup_logging()
    args = parse_args()

    # Validate the shared network artifacts once, so a bad one fails fast here
    # rather than as N identical per-worker errors mid-dashboard.
    try:
        manifest = manifest_mod.validate_manifest_schema(args.manifest.read_bytes())
    except manifest_mod.ManifestSchemaError as e:
        raise SystemExit(f"--manifest {args.manifest}: invalid manifest: {e}") from None
    reth_genesis = resolve_reth_genesis(args.reth_genesis, args.manifest)
    try:
        manifest_mod.validate_reth_genesis_matches(manifest, reth_genesis.read_bytes())
    except manifest_mod.GateError as e:
        raise SystemExit(f"--reth-genesis {reth_genesis}: {e}") from None

    nodes = build_cohort(args.genesis, args.join)
    joiners = [n.name for n in nodes if not n.genesis]
    print(
        f"Configuring {len(nodes)} node(s): genesis={nodes[0].name}"
        + (f", joining={joiners}" if joiners else " (genesis-only)")
    )

    results = _run_cohort(nodes, args.manifest, reth_genesis, args.email, args.no_wait)
    _report(nodes, results)


if __name__ == "__main__":
    main()
