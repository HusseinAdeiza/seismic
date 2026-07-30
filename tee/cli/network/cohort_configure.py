"""`seismic-tee-network configure` — found a network in one command.

Configures a whole cohort at once: the one genesis node (`--genesis`, mints
`root_key` locally) plus every joining node (`--join`, fetches `root_key` from
genesis via `getWrappedRootKey`). Exactly one node is genesis — assigned here,
not left to a per-node flag — so a double-genesis network split is
unrepresentable.

Bootnode bootstrap is inherently two-stage on a greenfield cohort: a node's
reth enode isn't known until reth is up, so there is nothing to hand the
joiners as `[network].bootnodes` up front. So:

  Stage 1 — configure only the genesis node (empty `bootnodes`), then
            poll its `seismic_nodeInfo` until reth reports an enode.
  Stage 2 — configure the joiners **in parallel** (the existing executor path)
            with `bootnodes = [genesis enode]`.

Then every node's enode is collected and the founding set is persisted to
`nodes/bootnodes.json` beside the descriptors. On a later configure run (reboot
or re-provision) that file exists, so we skip the two-stage dance and hand the
full founding set to every node in one parallel pass.

Root-key bootstrap rides the same list: tdx-init derives each node's root-key
fetch peers from its POSTed bootnodes (`http://<host>:7878`, the node's own
entry dropped), so stage-2 joiners fetch `root_key` from genesis, and there is
no second peer list that could skew from the bootnode set.

Founding is an internal act, so this lives on the bootstrap CLI; joining an
already-live network is the operator `seismic-tee-node configure`. Both go through
the same `build_config` / `post_config_to_tdx_init` primitives and
`status.poll_provisioning`, so each node's POSTed config and wipe-watch are
identical — only `[node].genesis_node` and the bootnode set differ.
"""

import argparse
import logging
import threading
import time
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from tee.cli.common import manifest as manifest_mod
from tee.cli.common.dashboard import CohortDashboard
from tee.cli.common.descriptor import load_descriptor, require
from tee.cli.common.logging_setup import setup_logging
from tee.cli.network import bootnodes as bootnodes_mod
from tee.cli.node.configure import (
    TDX_INIT_PORT,
    build_config,
    post_config_to_tdx_init,
    resolve_reth_genesis,
)
from tee.cli.node.status import poll_provisioning

logger = logging.getLogger(__name__)


@dataclass
class Node:
    """One cohort member, resolved from its descriptor + assigned role.

    `bootnodes` (→ `[network].bootnodes`: reth p2p + tdx-init's derived
    root-key fetch peers) is assigned by the configure flow, not here —
    empty for the greenfield genesis node, [genesis enode] for its joiners,
    the full founding set on re-configure.
    """

    name: str  # short label (the descriptor filename stem)
    public_ip: str
    fqdn: str
    genesis: bool
    bootnodes: list[str] = field(default_factory=list)


def _load_node(descriptor_path: Path, *, genesis: bool) -> Node:
    descriptor = load_descriptor(descriptor_path)
    return Node(
        name=descriptor_path.stem,
        public_ip=require(descriptor, "public_ip", descriptor_path),
        fqdn=require(descriptor, "fqdn", descriptor_path),
        genesis=genesis,
    )


def build_cohort(genesis_path: Path, join_paths: list[Path]) -> list[Node]:
    """Resolve the cohort: exactly one genesis (mints `root_key`), everyone
    else a joiner. Role assignment lives here, not in a per-node flag, so
    there is exactly one genesis by construction. Joiners' root-key source
    needs no assignment: tdx-init derives it from the bootnodes the configure
    flow hands them (stage-2 joiners get the genesis enode, so they fetch
    `root_key` from `http://<genesis_ip>:7878`).
    """
    genesis = _load_node(genesis_path, genesis=True)
    joiners = [_load_node(p, genesis=False) for p in join_paths]
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
    states: dict[str, str],
    stop: threading.Event,
) -> bool:
    """Build + POST one node's config, then poll its LUKS wipe, writing the
    latest status line into `states[node.name]` for the dashboard. Returns
    whether the node reached a ready state. Never raises — a failure is
    recorded in `states` and reflected in the return, so one bad node doesn't
    abort the rest of the cohort. `stop` (set on ctrl-C) ends the wipe watch
    early so the worker joins promptly.
    """
    try:
        states[node.name] = "building config…"
        config = build_config(
            manifest_path,
            node.fqdn,
            email,
            genesis_node=node.genesis,
            reth_genesis_path=reth_genesis_path,
            external_ip=node.public_ip,
            bootnodes=node.bootnodes,
        )
        states[node.name] = f"POSTing config to tdx-init :{TDX_INIT_PORT}…"
        post_config_to_tdx_init(node.public_ip, config)
        for update in poll_provisioning(node.public_ip, stop=stop):
            states[node.name] = update.line
            if update.done:
                return update.ok
        return False  # stopped early, or defensive against a silent generator end
    except Exception as e:  # noqa: BLE001 — surface per node, keep the cohort going
        states[node.name] = f"ERROR: {e}"
        return False


def _run_cohort(
    nodes: list[Node],
    manifest_path: Path,
    reth_genesis_path: Path,
    email: str,
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
    dashboard = CohortDashboard(
        {n.name: n.name + (" (genesis)" if n.genesis else "") for n in nodes}
    )
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


def _bootstrap_greenfield(
    nodes: list[Node],
    manifest_path: Path,
    reth_genesis_path: Path,
    email: str,
) -> dict[str, bool]:
    """Two-stage greenfield bootstrap: genesis first (so its enode exists),
    then the joiners pointed at it. Returns {node name: ok} across both stages.

    A node's reth enode isn't knowable until reth is up, so the joiners can't
    be handed `bootnodes` until the genesis node reports one. If the genesis
    node fails stage 1, the joiners aren't configured (they'd have neither a
    root_key source nor a bootnode); the missing results read as failures in
    `_report`.
    """
    genesis, joiners = nodes[0], nodes[1:]

    print("Stage 1/2: configuring the genesis node (no bootnodes yet)...")
    genesis.bootnodes = []
    results = _run_cohort([genesis], manifest_path, reth_genesis_path, email)
    if not results.get(genesis.name):
        print("Genesis node failed in stage 1 — skipping joiner bootstrap.")
        return results

    if not joiners:
        return results

    print("Stage 2/2: fetching the genesis enode via seismic_nodeInfo...")
    genesis_enode = bootnodes_mod.collect_enodes([(genesis.name, genesis.fqdn)])[
        genesis.name
    ]
    bootnodes_mod.warn_on_ip_mismatch(genesis_enode, genesis.public_ip, genesis.name)

    print(f"Stage 2/2: configuring {len(joiners)} joining node(s) off genesis enode...")
    for joiner in joiners:
        joiner.bootnodes = [genesis_enode]
    results.update(_run_cohort(joiners, manifest_path, reth_genesis_path, email))
    return results


def _persist_founding_bootnodes(
    nodes: list[Node], results: dict[str, bool], path: Path
) -> None:
    """Collect every node's enode and write the founding set to `bootnodes.json`.

    Only writes when the whole cohort is ready — a partial founding set would
    silently drop a node from every later re-configure. If any node failed
    (its enode can't be fetched anyway), skip the write and warn; `_report`
    surfaces the failure.

    Best-effort: config delivery has already succeeded by the time this runs,
    and `bootnodes.json` is only a refresh for later runs, so a failure to
    collect the enodes (a node whose reth never advertises one, or advertises a
    malformed one — `collect_enodes` raises `SystemExit`) degrades to a warning
    rather than aborting before the caller's cohort report prints. The next
    configure run re-establishes the set.
    """
    not_ready = [n.name for n in nodes if not results.get(n.name)]
    if not_ready:
        logger.warning(
            "not writing %s — %d/%d node(s) not ready: %s",
            bootnodes_mod.BOOTNODES_FILENAME,
            len(not_ready),
            len(nodes),
            ", ".join(not_ready),
        )
        return

    print("Collecting the founding bootnode set (seismic_nodeInfo)...")
    try:
        enodes = bootnodes_mod.collect_enodes([(n.name, n.fqdn) for n in nodes])
    except SystemExit as e:
        logger.warning(
            "not writing %s — could not collect the founding enode set: %s",
            bootnodes_mod.BOOTNODES_FILENAME,
            e,
        )
        return
    for node in nodes:
        bootnodes_mod.warn_on_ip_mismatch(enodes[node.name], node.public_ip, node.name)
    records = [
        bootnodes_mod.Bootnode(name=node.name, enode=enodes[node.name])
        for node in nodes
    ]
    bootnodes_mod.save_bootnodes(path, records)
    print(f"Wrote founding bootnode set ({len(records)} node(s)) to {path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="seismic-tee-network configure",
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
            "reth genesis JSON POSTed to every node; → "
            "[network].reth_genesis_base64. Default: reth-genesis.json "
            "beside --manifest (the artifact-set layout)."
        ),
    )
    parser.add_argument(
        "--email",
        default="ops@seismic.systems",
        help=(
            "certbot contact email → [node.domain].email "
            "(default: ops@seismic.systems)."
        ),
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

    # bootnodes.json lives beside the descriptors (the genesis descriptor's
    # dir, i.e. <network>/nodes/) — the founding enode set from a prior run.
    bootnodes_path = args.genesis.parent / bootnodes_mod.BOOTNODES_FILENAME
    if bootnodes_path.exists():
        # Re-configure: hand the full founding set to every node (a node
        # listing its own enode is harmless) and configure in one parallel
        # pass — no genesis-first staging, since the enodes are already known.
        founding = bootnodes_mod.load_bootnodes(bootnodes_path)
        enodes = [b.enode for b in founding]
        print(
            f"Reusing {len(enodes)} founding bootnode(s) from {bootnodes_path}; "
            "configuring the whole cohort in one pass."
        )
        for node in nodes:
            node.bootnodes = enodes
        results = _run_cohort(nodes, args.manifest, reth_genesis, args.email)
    else:
        results = _bootstrap_greenfield(nodes, args.manifest, reth_genesis, args.email)

    # Refresh the founding set from every node's live enode (fresh each run).
    _persist_founding_bootnodes(nodes, results, bootnodes_path)
    _report(nodes, results)


if __name__ == "__main__":
    main()
