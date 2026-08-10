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

The summit genesis is delivered with current IPs spliced in: the committed
summit-genesis.toml is a founding-era snapshot whose `[[validators]].ip_address`
entries are network topology, not identity — excluded from the manifest's
config digest — so each configure run replaces them with the live IPs from
the cohort descriptors (`nodes/*.json`) without re-serializing any other
field. After the whole cohort accepts its config, the launch assertions
(see launch_assertions.py) verify each box against what the manifest pins:
reth block 0 equals `eth.genesis_hash`, and each holder serves exactly the
founding keys harvested from it. Any mismatch is a hard failure.

Founding is an internal act, so this lives on the bootstrap CLI; joining an
already-live network is the operator `seismic-tee-node configure`. Both go through
the same `build_config` / `post_config_to_tdx_init` primitives and
`status.poll_provisioning`, so each node's POSTed config and wipe-watch are
identical — only `[node].genesis_node` and the bootnode set differ.
"""

import argparse
import json
import logging
import re
import tempfile
import threading
import time
import tomllib
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from tee.cli.common import manifest as manifest_mod
from tee.cli.common.dashboard import CohortDashboard
from tee.cli.common.descriptor import load_descriptor, require
from tee.cli.common.logging_setup import setup_logging
from tee.cli.network import bootnodes as bootnodes_mod
from tee.cli.network import launch_assertions
from tee.cli.node.configure import (
    TDX_INIT_PORT,
    build_config,
    post_config_to_tdx_init,
    resolve_reth_genesis,
    resolve_summit_genesis,
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


def load_founding_facts(
    network_dir: Path,
) -> tuple[dict[str, str], dict[str, dict]]:
    """Load the founding facts the delivery needs from the network directory:
    the current-IP splice map (pinned node pubkey → "<ip>:<consensus port>",
    from `inputs/harvest/` joined with the live `nodes/` descriptors) and the
    harvest records themselves (each configured box's pinned keys, for the
    launch assertions).
    """
    try:
        records = manifest_mod.load_harvest_records(
            network_dir / manifest_mod.INPUTS_DIRNAME / manifest_mod.HARVEST_DIRNAME
        )
    except manifest_mod.GateError as e:
        raise SystemExit(f"{network_dir}: {e}") from None
    nodes_dir = network_dir / manifest_mod.NODES_DIRNAME
    ip_by_node_pubkey: dict[str, str] = {}
    for name in sorted(records):
        descriptor_path = nodes_dir / f"{name}.json"
        if not descriptor_path.is_file():
            raise SystemExit(
                f"{descriptor_path} not found — the cohort descriptors from "
                "`up --network` supply each founding validator's current IP. "
                "A harvested box whose descriptor is gone means the cohort "
                "changed under the founding: re-found rather than configuring"
            )
        try:
            ip = require(load_descriptor(descriptor_path), "public_ip", descriptor_path)
        except (json.JSONDecodeError, ValueError) as e:
            raise SystemExit(f"{descriptor_path}: {e}") from None
        ip_by_node_pubkey[records[name]["node_public_key"]] = (
            f"{ip}:{manifest_mod.SUMMIT_CONSENSUS_PORT}"
        )
    return ip_by_node_pubkey, records


# One TOML key-value line per validator entry, exactly as summit's emitter
# renders it. The splice rewrites these lines and nothing else.
_IP_ADDRESS_LINE = re.compile(r'^ip_address = "[^"]*"$', flags=re.MULTILINE)


def splice_validator_ips(
    genesis_bytes: bytes, ip_by_node_pubkey: dict[str, str]
) -> bytes:
    """Replace each `[[validators]].ip_address` with the box's current IP.

    The committed summit genesis is a founding-era snapshot: its validator
    IPs were the descriptors' at assemble time, and only the IPs are free to
    change — they are excluded from the config digest the manifest pins, and
    peers are authenticated by the pinned ed25519 keys, so a stale IP is a
    liveness problem only. Everything else in the file is identity: the
    digest hashes the key/credential fields as the exact strings summit
    emitted, so this must never re-serialize the document. The splice is
    therefore textual — the i-th `ip_address` line is rewritten for the i-th
    validator — and self-checked by re-parsing: the spliced file must parse
    identically to the input everywhere but `ip_address`.

    `ip_by_node_pubkey` ("<ip>:<consensus port>", keyed by pinned node
    pubkey) must cover the validator set exactly: a pinned validator without
    a current IP (or an IP for a key the genesis doesn't pin) means the
    cohort changed under the founding — re-found rather than delivering a
    genesis that strands a pinned peer.
    """
    text = genesis_bytes.decode("utf-8")
    parsed = tomllib.loads(text)
    raw_validators = parsed.get("validators")
    if not isinstance(raw_validators, list) or not raw_validators:
        raise SystemExit(
            "summit genesis carries no [[validators]] — not an assembled "
            "artifact (assemble refuses an empty founding set)"
        )
    validators: list[dict[str, Any]] = []
    pinned = []
    for i, entry in enumerate(raw_validators):
        validator = cast("dict[str, Any]", entry) if isinstance(entry, dict) else {}
        key = validator.get("node_public_key")
        if not isinstance(key, str):
            raise SystemExit(
                f"summit genesis validator #{i + 1} has no node_public_key string"
            )
        validators.append(validator)
        pinned.append(key)
    if sorted(pinned) != sorted(ip_by_node_pubkey):
        raise SystemExit(
            "the summit genesis's pinned validator set and the founding "
            "inputs (inputs/harvest/ + nodes/ descriptors) disagree — the "
            "cohort changed under the founding; re-found rather than "
            "delivering a genesis that strands a pinned peer:\n"
            f"    pinned node keys:    {', '.join(sorted(pinned))}\n"
            f"    harvested node keys: {', '.join(sorted(ip_by_node_pubkey))}"
        )
    matches = list(_IP_ADDRESS_LINE.finditer(text))
    if len(matches) != len(validators):
        raise SystemExit(
            f"summit genesis has {len(validators)} validator(s) but "
            f"{len(matches)} ip_address line(s) — not the layout summit's "
            "emitter renders; refusing to splice"
        )
    out = []
    last = 0
    for validator, match in zip(validators, matches, strict=True):
        out.append(text[last : match.start()])
        # json.dumps emits a valid TOML basic string for "<ip>:<port>".
        ip = ip_by_node_pubkey[validator["node_public_key"]]
        out.append(f"ip_address = {json.dumps(ip)}")
        last = match.end()
    out.append(text[last:])
    spliced = "".join(out)

    # Self-check: parse-identical to the input everywhere but ip_address.
    expected = dict(parsed)
    expected["validators"] = [
        {**validator, "ip_address": ip_by_node_pubkey[validator["node_public_key"]]}
        for validator in validators
    ]
    if tomllib.loads(spliced) != expected:
        raise SystemExit(
            "IP splice changed the summit genesis beyond ip_address — "
            "refusing to deliver it (the config digest pins every other field)"
        )
    return spliced.encode("utf-8")


def _configure_node(
    node: Node,
    manifest_path: Path,
    reth_genesis_path: Path,
    summit_genesis_path: Path,
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
            summit_genesis_path=summit_genesis_path,
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
    summit_genesis_path: Path,
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
                summit_genesis_path,
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
    summit_genesis_path: Path,
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
    results = _run_cohort(
        [genesis], manifest_path, reth_genesis_path, summit_genesis_path, email
    )
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
    results.update(
        _run_cohort(
            joiners, manifest_path, reth_genesis_path, summit_genesis_path, email
        )
    )
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
        "--summit-genesis",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "summit genesis TOML POSTed to every node; → "
            "[network].summit_genesis_base64. Default: summit-genesis.toml "
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
    summit_genesis = resolve_summit_genesis(args.summit_genesis, args.manifest)
    committed_genesis_bytes = summit_genesis.read_bytes()
    try:
        manifest_mod.validate_summit_genesis_matches(manifest, committed_genesis_bytes)
    except manifest_mod.GateError as e:
        raise SystemExit(f"--summit-genesis {summit_genesis}: {e}") from None

    # The founding inputs live beside the manifest (the network-directory
    # layout): the harvest supplies each box's pinned keys, the descriptors
    # its current IP.
    ip_by_node_pubkey, harvest_records = load_founding_facts(args.manifest.parent)
    spliced_bytes = splice_validator_ips(committed_genesis_bytes, ip_by_node_pubkey)
    if spliced_bytes != committed_genesis_bytes:
        print(
            f"Spliced current descriptor IPs into the delivered summit genesis "
            f"(the committed {summit_genesis.name} is a founding-era snapshot; "
            "validator IPs are topology, not identity)"
        )
    with tempfile.NamedTemporaryFile(
        "wb",
        suffix=".toml",
        prefix="summit-genesis-delivered-",
        delete=False,
    ) as f:
        f.write(spliced_bytes)
        summit_genesis = Path(f.name)

    nodes = build_cohort(args.genesis, args.join)
    unharvested = sorted(n.name for n in nodes if n.name not in harvest_records)
    if unharvested:
        raise SystemExit(
            f"node(s) without a founding harvest record: {', '.join(unharvested)} "
            "— this command configures a founding cohort, and every box's "
            "launch is asserted against the keys harvested from it. A joiner "
            "arriving after founding uses `seismic-tee-node configure`."
        )
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
        results = _run_cohort(
            nodes, args.manifest, reth_genesis, summit_genesis, args.email
        )
    else:
        results = _bootstrap_greenfield(
            nodes, args.manifest, reth_genesis, summit_genesis, args.email
        )

    # Refresh the founding set from every node's live enode (fresh each run).
    _persist_founding_bootnodes(nodes, results, bootnodes_path)
    _report(nodes, results)

    # Every node accepted its config — now assert the launch against what the
    # manifest pins (see launch_assertions.py for why both are load-bearing).
    targets = [
        launch_assertions.LaunchTarget(
            name=n.name,
            public_ip=n.public_ip,
            fqdn=n.fqdn,
            node_public_key=harvest_records[n.name]["node_public_key"],
            consensus_public_key=harvest_records[n.name]["consensus_public_key"],
        )
        for n in nodes
    ]
    genesis_hash = manifest["eth"]["genesis_hash"]
    print(f"Launch assertion 1/2: every node's reth serves block 0 {genesis_hash}...")
    launch_assertions.assert_cohort_genesis_hash(targets, genesis_hash)
    print("Launch assertion 2/2: every holder serves its pinned founding keys...")
    launch_assertions.assert_cohort_holder_keys(targets)
    print("Launch assertions green: the cohort that launched is the cohort pinned.")


if __name__ == "__main__":
    main()
