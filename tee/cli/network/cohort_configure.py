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

Every node is deploy-verified as soon as it reaches a ready state — the
`seismic-tee-node verify` check, run inside the same parallel executor so a
fast box is appraised while a slow one still wipes its disk (see verify.py for
what the check proves and which policy it appraises against). The founder is a
relying party the moment stage 2 hands genesis's enode to the joiners, so the
genesis gate lands before that: a genesis node that does not pass stops the
founding rather than pointing the cohort at an unappraised box. The verdict is
the node's result: a node that fails its appraisal counts as failed, its enode
never enters `nodes/bootnodes.json`, and the launch assertions never run.

The founding harvest DCAP-verifies each box too, but that quote is
pre-manifest: it proves the box was measured-correct when it minted its summit
keys. This gate is the post-manifest half — the box booted the manifest that
was delivered to it.

The summit genesis is delivered with current IPs spliced in: the committed
summit-genesis.toml is a founding-era snapshot whose `[[validators]].ip_address`
entries are network topology, not identity — excluded from the manifest's
config digest — so each configure run replaces them with the live IPs from
the cohort descriptors (`nodes/*.json`) without re-serializing any other
field. After the whole cohort accepts its config, the launch assertions
(see launch_assertions.py) verify each box against what the manifest pins:
reth block 0 equals `eth.genesis_hash`, and each holder serves exactly the
founding keys harvested from it. Any mismatch is a hard failure.

Founding is the founder's act, so this lives on the network CLI; joining an
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
from tee.cli.common import shell_outs
from tee.cli.common.dashboard import CohortDashboard
from tee.cli.common.descriptor import load_descriptor, require
from tee.cli.common.logging_setup import setup_logging
from tee.cli.network import bootnodes as bootnodes_mod
from tee.cli.network import launch_assertions
from tee.cli.node import verify as verify_mod
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


@dataclass(frozen=True)
class Appraisal:
    """The deploy-verification inputs shared by the whole cohort: the parsed
    flags `verify` reads (manifest, verifier binary, PCCS) and the measurement
    policy resolved once up front. Resolving the tooling and promoting the
    policy is per-run work, not per-node, and it must fail before any node is
    touched — config delivery is once per boot.
    """

    args: argparse.Namespace
    policy_bytes: bytes


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


# A whole cohort's wipes tend to finish together, so every challenge hits the
# PCCS at once — and a DCAP collateral fetch is the one transient way a
# challenge fails (verify.py names it as the expected retry case). Retry a few
# times before the verdict is terminal: a founding that a blip fails is
# expensive to recover (config delivery is once per boot), while a real
# measurement mismatch just fails every attempt.
APPRAISAL_ATTEMPTS = 3
APPRAISAL_RETRY_SECONDS = 15


def _appraise(
    node: Node, appraisal: Appraisal, states: dict[str, str], stop: threading.Event
) -> bool:
    """Deploy-verify one ready node, recording the verdict as its status line.

    The verdict is the node's result, not a warning beside it: an unappraised
    box must not be handed to the joiners as a bootnode, written into the
    founding `bootnodes.json`, or counted as a founded node.
    """
    attempt = 1
    while True:
        states[node.name] = "deploy-verifying…"
        try:
            verify_mod.challenge_node(
                appraisal.args, appraisal.policy_bytes, public_ip=node.public_ip
            )
        except manifest_mod.GateError as e:
            if attempt == APPRAISAL_ATTEMPTS or stop.is_set():
                states[node.name] = f"ERROR: deploy verification FAILED: {e}"
                return False
            states[node.name] = (
                f"appraisal attempt {attempt}/{APPRAISAL_ATTEMPTS} failed, "
                f"retrying in {APPRAISAL_RETRY_SECONDS}s…"
            )
            if stop.wait(APPRAISAL_RETRY_SECONDS):
                states[node.name] = "stopped before the appraisal retry"
                return False
            attempt += 1
            continue
        states[node.name] = "ready, deploy-verified ✓"
        return True


def _configure_node(
    node: Node,
    manifest_path: Path,
    reth_genesis_path: Path,
    summit_genesis_path: Path,
    email: str,
    appraisal: Appraisal | None,
    states: dict[str, str],
    stop: threading.Event,
    manifest_bin: str = shell_outs.DEFAULT_MANIFEST_BIN,
) -> bool:
    """Build + POST one node's config, poll its LUKS wipe, then deploy-verify
    it, writing the latest status line into `states[node.name]` for the
    dashboard. Returns whether the node reached a ready state and passed its
    appraisal (`appraisal=None` under --no-verify: ready is the whole bar).
    Never raises — a failure is recorded in `states` and reflected in the
    return, so one bad node doesn't abort the rest of the cohort. `stop` (set
    on ctrl-C) ends the wipe watch early so the worker joins promptly.
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
            manifest_bin=manifest_bin,
        )
        states[node.name] = f"POSTing config to tdx-init :{TDX_INIT_PORT}…"
        post_config_to_tdx_init(node.public_ip, config)
        for update in poll_provisioning(node.public_ip, stop=stop):
            states[node.name] = update.line
            if not update.done:
                continue
            if not update.ok:
                return False
            if appraisal is None:  # --no-verify: ready is the whole bar
                return True
            if stop.is_set():
                # Ctrl-C: don't start a challenge the run is about to abandon.
                # The node is configured, and `verify` appraises it later.
                states[node.name] = "stopped before the appraisal"
                return False
            return _appraise(node, appraisal, states, stop)
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
    appraisal: Appraisal | None,
    manifest_bin: str = shell_outs.DEFAULT_MANIFEST_BIN,
) -> dict[str, bool]:
    """Configure and appraise every node concurrently, refreshing the dashboard
    until all workers finish. Returns {node name: ok}. Threads suit this — the
    work is blocking HTTP (POST + status polling) and a blocking verifier
    subprocess, and N is small.
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
                appraisal,
                states,
                stop,
                manifest_bin,
            )
        try:
            # Refresh while workers block on POST/poll.
            while not all(f.done() for f in futures.values()):
                dashboard.render(states)
                time.sleep(1)
        except KeyboardInterrupt:
            # Must set `stop` before the pool's context exit joins the workers
            # — otherwise a wipe watch blocks that join for up to 1h+. With it,
            # workers exit within a poll interval; the bounded waits a worker
            # can already be inside (the POST's listener wait, a verifier
            # fetching DCAP collateral) hold the join for a few minutes at
            # most. The POSTs that landed keep provisioning server-side either
            # way.
            stop.set()
            print("\nStopped watching — configured nodes keep provisioning.")
            raise SystemExit(130) from None
        dashboard.render(states)  # final paint of terminal states
    results = {name: f.result() for name, f in futures.items()}
    # The dashboard folds and truncates a status to one terminal row, but a
    # failure's reason (often a verifier's multi-line stderr) is the one thing
    # the run must not swallow — print each failed node's full text.
    for node in nodes:
        if not results[node.name]:
            print(f"\n{node.name}: {states[node.name]}")
    return results


def _report(
    nodes: list[Node], results: dict[str, bool], args: argparse.Namespace
) -> None:
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
        # The bool result covers both halves of the bar (came up, passed its
        # appraisal); the failed node's full status was printed above.
        print(
            "The genesis node failed — joiners depend on it for root_key and "
            "as their bootnode. Fix genesis first."
        )
    failed = [n.name for n in nodes if not results.get(n.name, False)]
    if failed:
        if not args.no_verify:
            # tdx-init takes one config POST per boot, so a node that took its
            # config and then failed its appraisal is re-appraised, not
            # re-configured. Its full verifier reason was printed above.
            print(
                "A node that took its config but did not pass the appraisal is "
                "retried with `verify`, not with a second `configure` "
                "(tdx-init takes one config POST per boot):\n"
                "    seismic-tee-node verify --node <descriptor> --manifest "
                f"{args.manifest}{verify_mod.retry_flags(args)}\n"
            )
        raise SystemExit(
            f"{len(failed)}/{len(nodes)} node(s) failed: {', '.join(failed)}"
        )


def _bootstrap_greenfield(
    nodes: list[Node],
    manifest_path: Path,
    reth_genesis_path: Path,
    summit_genesis_path: Path,
    email: str,
    appraisal: Appraisal | None,
    manifest_bin: str = shell_outs.DEFAULT_MANIFEST_BIN,
) -> dict[str, bool]:
    """Two-stage greenfield bootstrap: genesis first (so its enode exists),
    then the joiners pointed at it. Returns {node name: ok} across both stages.

    A node's reth enode isn't knowable until reth is up, so the joiners can't
    be handed `bootnodes` until the genesis node reports one. Stage 1 therefore
    ends with the genesis node ready *and* appraised, which is the gate the
    stage boundary exists for: its enode is what every joiner dials and what
    `nodes/bootnodes.json` records. If genesis fails either half, the joiners
    aren't configured (they'd have neither a root_key source nor a bootnode);
    the missing results read as failures in `_report`.
    """
    genesis, joiners = nodes[0], nodes[1:]

    print("Stage 1/2: configuring the genesis node (no bootnodes yet)...")
    genesis.bootnodes = []
    results = _run_cohort(
        [genesis],
        manifest_path,
        reth_genesis_path,
        summit_genesis_path,
        email,
        appraisal,
        manifest_bin,
    )
    if not results.get(genesis.name):
        print(
            "Genesis node failed in stage 1 — skipping joiner bootstrap: its "
            "enode is what every joiner would dial."
        )
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
            joiners,
            manifest_path,
            reth_genesis_path,
            summit_genesis_path,
            email,
            appraisal,
            manifest_bin,
        )
    )
    return results


def _persist_founding_bootnodes(
    nodes: list[Node], results: dict[str, bool], path: Path
) -> None:
    """Collect every node's enode and write the founding set to `bootnodes.json`.

    Only writes when every node came up ready and appraised — a partial
    founding set would silently drop a node from every later re-configure, and
    an unappraised box must not be recorded as one the cohort dials. If any
    node failed, skip the write and warn; `_report` surfaces the failure.

    Best-effort: config delivery has already succeeded by the time this runs,
    and `bootnodes.json` is only a refresh for later runs, so a failure to
    collect the enodes (a node whose reth never advertises one, or advertises a
    malformed one — `collect_enodes` raises `SystemExit`) degrades to a warning
    rather than aborting before the caller's cohort report prints. The next
    configure run re-establishes the set.
    """
    failed = [n.name for n in nodes if not results.get(n.name)]
    if failed:
        logger.warning(
            "not writing %s — %d/%d node(s) failed: %s",
            bootnodes_mod.BOOTNODES_FILENAME,
            len(failed),
            len(nodes),
            ", ".join(failed),
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
        help="Network manifest JSON (from `assemble`); → [network].",
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
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help=(
            "Found the cohort without deploy-verifying it. By default each "
            "node is appraised once it is up — the same check as "
            "`seismic-tee-node verify`, against the policy --manifest pins — "
            "and a node that fails counts as failed."
        ),
    )
    verify_mod.add_policy_source_args(parser)
    verify_mod.add_tooling_args(parser)

    args = parser.parse_args()
    for path in [args.genesis, *args.join, args.manifest]:
        if not path.is_file():
            raise SystemExit(f"file not found: {path}")
    verify_mod.check_policy_source_files(args)
    return args


def main() -> None:
    setup_logging()
    args = parse_args()

    # Validate the shared network artifacts once, so a bad one fails fast here
    # rather than as N identical per-worker errors mid-dashboard.
    try:
        manifest = manifest_mod.validate_manifest_schema(
            args.manifest.read_bytes(), args.manifest_bin
        )
    except (manifest_mod.ManifestSchemaError, manifest_mod.GateError) as e:
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

    # Resolve the verifier and promote the policy once for the whole cohort,
    # before any node is touched: a missing verify-quote, a policy the manifest
    # doesn't commit to, or a rejected measurements file must fail while the
    # fix still costs nothing — config delivery is once per boot.
    policy_bytes = verify_mod.prepare_policy_optional(
        args, subject="this cohort's nodes"
    )
    appraisal = None if policy_bytes is None else Appraisal(args, policy_bytes)

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
        # Each node is still appraised the moment it is ready.
        founding = bootnodes_mod.load_bootnodes(bootnodes_path)
        enodes = [b.enode for b in founding]
        print(
            f"Reusing {len(enodes)} founding bootnode(s) from {bootnodes_path}; "
            "configuring the whole cohort in one pass."
        )
        for node in nodes:
            node.bootnodes = enodes
        results = _run_cohort(
            nodes,
            args.manifest,
            reth_genesis,
            summit_genesis,
            args.email,
            appraisal,
            args.manifest_bin,
        )
    else:
        results = _bootstrap_greenfield(
            nodes,
            args.manifest,
            reth_genesis,
            summit_genesis,
            args.email,
            appraisal,
            args.manifest_bin,
        )

    # Refresh the founding set from every node's live enode (fresh each run).
    _persist_founding_bootnodes(nodes, results, bootnodes_path)
    _report(nodes, results, args)

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
