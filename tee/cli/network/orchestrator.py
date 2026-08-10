"""Cohort orchestrator: bring up / tear down N TDX nodes as one command.

Drives the `seismic-tee-network up` / `down` subcommands.
`seismic-tee-network up --count N` brings up N independent Pulumi stacks
of the single-node `seismic_node` program via the Pulumi Automation API
(local-program workspace), and writes one node descriptor per node (the
same `{public_ip, fqdn, …}` shape `pulumi stack output --json` emits — see
tee/cli/common/descriptor.py).

Shared settings are inherited from an existing stack config file
(`Pulumi.dev.yaml` by default): the orchestrator reads its `config:` block
and applies it to every node stack unchanged, except the three per-node
fields (`resource_group`, `vm_name`, `dns_record_name`), which it sets to
`{prefix}-{i}` so each node gets its own resource graph. Pulumi config has
no templating — the `{i}` substitution is done here.

The stacks it creates are ordinary stacks: `pulumi up / destroy /
stack output --stack dev-bootstrap-node-3` all work directly afterward.

Scope is provisioning only, and genesis-agnostic: the genesis/join
distinction is applied later at configure time (genesis via
`seismic-tee-network configure`, join via `seismic-tee-node configure`), not
infra config. One stack per node, so
`seismic-tee-network down --stack dev-bootstrap-node-3` recycles a single
node without touching the others.

Runtime: like the `pulumi` CLI, the Automation API shells out to the
`pulumi` binary (must be on PATH). The passphrase secrets provider the
seismic_node stacks use needs `PULUMI_CONFIG_PASSPHRASE`; if it's unset,
`up`/`down` prompt for it on a TTY (like `pulumi stack init`; empty = no
passphrase) and require the env var otherwise. Importing this module needs
neither.

Design rationale (Automation API + local-program choice): see the PR
description.
"""

import argparse
import getpass
import json
import os
import re
import sys
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml
from pulumi import automation as auto

from tee.cli.common import manifest as manifest_mod
from tee.cli.common.repo import DEFAULT_STACK_CONFIG as DEFAULT_CONFIG
from tee.cli.common.repo import SEISMIC_NODE_DIR

# Per-node descriptors land here when no --network ties the cohort to a
# network directory (gitignored either way) so a cohort's outputs stay
# corralled instead of scattering into the cwd. The generated
# Pulumi.<stack>.yaml configs can't join them — Pulumi pins those to the
# project dir (SEISMIC_NODE_DIR).
DEFAULT_OUT_DIR = SEISMIC_NODE_DIR.parent / "descriptors"


def _resolve_out_dir(out_dir: str | None, network: Path | None) -> Path:
    """Descriptor destination: explicit --out-dir wins; a --network cohort's
    descriptors live under the network directory's nodes/ subdir (where the
    founding steps — harvest, assemble, configure — find them by default);
    else the shared descriptors/."""
    if out_dir:
        return Path(out_dir)
    if network is not None:
        return network / manifest_mod.NODES_DIRNAME
    return DEFAULT_OUT_DIR


# Fields the configure/genesis handoff actually reads (see descriptor.py); the
# rest of the stack outputs (vm_size, vhd_blob_url, …) are deploy-input echoes,
# noise for the descriptor.
DESCRIPTOR_KEYS = ("public_ip", "fqdn")

# The only config keys that must differ per node; all set to `{prefix}-{i}`.
# Matched by suffix so the `<project-namespace>:` prefix (a project rename)
# doesn't break this.
PER_NODE_FIELDS = ("resource_group", "vm_name", "dns_record_name")


def _node_config(template: Mapping, name: str) -> dict[str, auto.ConfigValue]:
    """The template's `config:` block, with the three per-node fields set to `name`.

    `template` is the parsed Pulumi.<stack>.yaml. Secret (`{secure: ...}`)
    values can't be re-encrypted for another stack by hand, so we reject
    them — seismic_node has none today (switch to get_all_config /
    set_all_config if that ever changes).
    """
    out: dict[str, auto.ConfigValue] = {}
    for key, value in template.get("config", {}).items():
        if isinstance(value, dict):  # {secure: <cipher>}
            raise NotImplementedError(
                f"secret config {key!r} can't be inherited across stacks; "
                f"this orchestrator only copies plaintext settings"
            )
        override = key.split(":", 1)[-1] in PER_NODE_FIELDS
        out[key] = auto.ConfigValue(value=name if override else str(value))
    return out


def _check_vhd_matches_network(template: Mapping, network_dir: Path) -> str:
    """Refuse to provision when the image pin names an artifact the network's
    measurements input doesn't cover.

    Name-level tripwire only: the basename of the config's `vhd_blob_url` is
    the image artifact filename (`seismic[-dev]_<date>.<commit>.vhd`), which
    is also the `measurement_id` seismic-images' `make measure` stamps into
    its measurements output (`init --measurement-id` overrides it;
    an already-promoted policy carries it per record). Comparing the two
    catches a stale or typo'd image pin before any cloud resource exists.
    The *authored input* is checked, not the assembled artifact set,
    because provisioning precedes assembly — the founding order is
    up → harvest → assemble, so at `up` time the inputs are all a network
    directory holds. No VHD bytes are
    inspected; the running VM is verified cryptographically at harvest and
    attestation time, never here.
    """
    vhd_url = next(
        (
            str(value)
            for key, value in template.get("config", {}).items()
            if key.split(":", 1)[-1] == "vhd_blob_url"
        ),
        None,
    )
    if vhd_url is None:
        raise SystemExit(
            "--network given but the stack config carries no vhd_blob_url to check"
        )
    measurements_path = (
        network_dir / manifest_mod.INPUTS_DIRNAME / manifest_mod.MEASUREMENTS_FILENAME
    )
    if not measurements_path.is_file():
        raise SystemExit(
            f"--network {network_dir}: missing {manifest_mod.INPUTS_DIRNAME}/"
            f"{manifest_mod.MEASUREMENTS_FILENAME} — scaffold the network "
            "directory with `init` before provisioning its cohort"
        )
    try:
        measurements = json.loads(measurements_path.read_bytes())
    except json.JSONDecodeError as e:
        raise SystemExit(f"{measurements_path}: not valid JSON: {e}") from None
    if isinstance(measurements, list):
        # An already-promoted policy: each record names its own image.
        ids = [
            record["measurement_id"]
            for record in measurements
            if isinstance(record, dict)
            and isinstance(record.get("measurement_id"), str)
        ]
    elif isinstance(measurements, dict) and isinstance(
        measurements.get("measurement_id"), str
    ):
        ids = [measurements["measurement_id"]]
    else:
        ids = []
    if not ids:
        raise SystemExit(
            f"{measurements_path} carries no measurement_id to check the "
            "image pin against — regenerate it with seismic-images' `make "
            "measure` (which stamps the field) or re-run `init "
            "--measurement-id <image-artifact-filename>` so a stale VHD "
            "pin can be caught before provisioning"
        )
    vhd_name = vhd_url.rsplit("/", 1)[-1]
    if vhd_name not in ids:
        raise SystemExit(
            f"vhd_blob_url points at {vhd_name!r} but {measurements_path} "
            f"covers only: {', '.join(ids)}. Stale image pin or wrong "
            "--network dir; refusing to provision."
        )
    return vhd_name


def _cohort_size(count: int | None, network: Path | None) -> int:
    """How many nodes to provision: the authored founder set, or --count.

    A network directory already states the cohort size — one withdrawal
    credential per founding node — and harvest and assemble both refuse a
    cohort that doesn't match it, so taking the count from the inputs is
    the only spelling that can't drift. --count stays accepted (and
    required without --network), but must agree.
    """
    if network is None:
        if count is None:
            raise SystemExit("--count is required without --network")
        return count
    path = network / manifest_mod.INPUTS_DIRNAME / manifest_mod.FOUNDERS_FILENAME
    try:
        authored = len(manifest_mod.load_founder_credentials(path))
    except manifest_mod.GateError as e:
        raise SystemExit(str(e)) from None
    if not authored:
        raise SystemExit(
            f"{path} is empty — it decides the cohort size, so author one "
            "withdrawal-credentials address per founding node (`manifest "
            "init --founders N` scaffolds placeholders)"
        )
    if count is not None and count != authored:
        raise SystemExit(
            f"--count {count} contradicts the {authored} withdrawal "
            f"credential(s) in {path}, which are the founding set: drop "
            "--count, or re-author the credentials for the cohort you want"
        )
    return authored


def _descriptor_from_outputs(outputs: Mapping[str, auto.OutputValue]) -> dict:
    # Just the handoff fields (DESCRIPTOR_KEYS), not every stack output.
    return {key: outputs[key].value for key in DESCRIPTOR_KEYS if key in outputs}


def _env_from_config(config_path: str) -> str:
    """Environment label from a Pulumi stack-config filename, for the default
    stack prefix: `Pulumi.dev.yaml` → `dev`, `Pulumi.testnet.yaml` → `testnet`.
    Falls back to the filename stem for non-`Pulumi.<env>.yaml` names.
    """
    match = re.fullmatch(r"Pulumi\.(.+)\.ya?ml", Path(config_path).name)
    return match.group(1) if match else Path(config_path).stem


def _ensure_passphrase(*, confirm: bool) -> None:
    """Make sure Pulumi's passphrase is available before touching stacks.

    The passphrase secrets provider (what the seismic_node stacks use) needs
    the passphrase to create/destroy each stack's secrets manager. If it isn't
    already in the environment, prompt for it like `pulumi stack init` does
    (empty entry → empty passphrase) and export it for the non-interactive
    Automation API to inherit. With no TTY (e.g. CI) we can't prompt, so
    require the env var instead. `confirm` re-prompts to guard against a typo
    locking you out of freshly created stacks.
    """
    # Presence, not truthiness: an empty passphrase is valid (Pulumi checks
    # set-vs-unset), so `PULUMI_CONFIG_PASSPHRASE=` already satisfies this.
    if (
        "PULUMI_CONFIG_PASSPHRASE" in os.environ
        or "PULUMI_CONFIG_PASSPHRASE_FILE" in os.environ
    ):
        return
    if not sys.stdin.isatty():
        raise SystemExit(
            "PULUMI_CONFIG_PASSPHRASE (or PULUMI_CONFIG_PASSPHRASE_FILE) must be "
            "set in a non-interactive context — Pulumi needs it for each stack's "
            "secrets manager."
        )
    prompt = "Pulumi passphrase for the cohort stacks (empty for none): "
    while True:
        passphrase = getpass.getpass(prompt)
        if not confirm or getpass.getpass("Re-enter to confirm: ") == passphrase:
            break
        print("Passphrases don't match; try again.")
    os.environ["PULUMI_CONFIG_PASSPHRASE"] = passphrase


# --------------------------------------------------------------------
# up (provision cohort)
# --------------------------------------------------------------------


def _parse_up_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision a cohort of TDX nodes (one Pulumi stack each)."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help=(
            "Number of nodes to provision. Optional with --network, which "
            "takes the count from the authored withdrawal credentials."
        ),
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        metavar="STACK_YAML",
        help=(
            "Pulumi stack config to inherit shared settings from "
            f"(default: the seismic_node {DEFAULT_CONFIG.name})."
        ),
    )
    parser.add_argument(
        "--stack-prefix",
        default=None,
        help=(
            "Names each node: its stack, resource group, VM, and DNS record "
            "are all '<prefix>-<i>'. Default: '<env>-bootstrap-node' derived "
            "from --config (e.g. Pulumi.dev.yaml → dev-bootstrap-node-1, …)."
        ),
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help=(
            "Directory for the emitted <stack>.json descriptors. Default: "
            "<network>/nodes/ when --network is given, else a gitignored "
            "descriptors/ dir next to the Pulumi project."
        ),
    )
    parser.add_argument(
        "--network",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Network directory (from `init`) this cohort is for: "
            "refuse to provision unless the config's vhd_blob_url basename "
            "matches the measurement_id in the directory's "
            "inputs/measurements.json (catches a stale image pin before any "
            "resource exists; name check only — attestation is the "
            "cryptographic gate), and write the descriptors to <DIR>/nodes/, "
            "where harvest and assemble find them by default."
        ),
    )
    args = parser.parse_args()
    # Absolute from here on, so every path this CLI prints is clickable.
    if args.network is not None:
        args.network = args.network.resolve()
    return args


def up_main() -> None:
    args = _parse_up_args()
    count = _cohort_size(args.count, args.network)
    _ensure_passphrase(confirm=True)
    with open(args.config) as f:
        template = yaml.safe_load(f)
    if args.network is not None:
        vhd_name = _check_vhd_matches_network(template, args.network)
        print(f"Image pin {vhd_name} matches the {args.network} measurements input.")
    prefix = args.stack_prefix or f"{_env_from_config(args.config)}-bootstrap-node"
    out_dir = _resolve_out_dir(args.out_dir, args.network)
    out_dir.mkdir(parents=True, exist_ok=True)
    names = [f"{prefix}-{i}" for i in range(1, count + 1)]

    # Sequential on purpose: clearer logs and gentler on Azure quota for a
    # first cut. The stacks are independent, so a future --parallel can run
    # them on a thread pool without changing anything else here.
    for i, name in enumerate(names, start=1):
        print(f"\n=== {name}: provisioning node {i}/{count} ===")

        stack = auto.create_or_select_stack(
            stack_name=name, work_dir=str(SEISMIC_NODE_DIR)
        )
        stack.set_all_config(_node_config(template, name))

        result = stack.up(on_output=print)

        descriptor = _descriptor_from_outputs(result.outputs)
        path = out_dir / f"{name}.json"
        path.write_text(json.dumps(descriptor, indent=2) + "\n")
        print(f"=== {name}: wrote descriptor {path} ===")

    genesis_desc = out_dir / f"{prefix}-1.json"
    join_flags = "".join(
        f" --join {out_dir / f'{prefix}-{i}.json'}" for i in range(2, count + 1)
    )
    if args.network is not None:
        # The network dir holds the descriptors, so harvest and assemble
        # find the cohort in <network>/nodes/ on their own.
        manifest_arg = args.network / manifest_mod.MANIFEST_FILENAME
        print(
            f"\nProvisioned {count} node(s) for {args.network}. Next:\n"
            "\n"
            "1. Harvest the founding keys (polls each box's summit-key-holder,\n"
            "   DCAP-verifies the quotes, archives them under inputs/harvest/):\n"
            f"     seismic-tee-network harvest {args.network}\n"
            "2. Assemble the artifact set (pins the harvested validator set,\n"
            f"   mints network_id), then commit {args.network}:\n"
            f"     seismic-tee-network assemble {args.network}\n"
            "3. Configure the cohort (re-run on every node reboot):\n"
            f"     seismic-tee-network configure --genesis {genesis_desc}"
            f"{join_flags} \\\n"
            f"       --manifest {manifest_arg}"
        )
        return
    net = "tee/networks/<name>"
    moved_genesis = f"{net}/nodes/{prefix}-1.json"
    moved_joins = "".join(
        f" --join {net}/nodes/{prefix}-{i}.json" for i in range(2, count + 1)
    )
    print(
        f"\nProvisioned {count} node(s). To found a network on them:\n"
        "\n"
        "1. Create the network directory (once per network):\n"
        f"     seismic-tee-network init {net} \\\n"
        "       --reth-genesis <reth-genesis.json> \\\n"
        "       --measurements <measurements.json> --measurement-id <image.vhd> \\\n"
        f"       --founders {count}\n"
        f"     # edit {net}/inputs/summit-genesis.toml and the scaffolded\n"
        f"     # {net}/inputs/founder-withdrawal-credentials.json\n"
        "2. Move the descriptors into the network directory (assemble reads\n"
        "   each founding validator's IP from them):\n"
        f"     mkdir -p {net}/nodes && mv {out_dir}/*.json {net}/nodes/\n"
        "3. Harvest the founding keys from the live cohort:\n"
        f"     seismic-tee-network harvest {net}\n"
        "4. Assemble the artifact set (seismic-reth, summit, and the\n"
        "   admission + verify-quote CLIs must be on PATH), then commit it:\n"
        f"     seismic-tee-network assemble {net}\n"
        "5. Configure the cohort (re-run on every node reboot):\n"
        f"     seismic-tee-network configure --genesis {moved_genesis}"
        f"{moved_joins} \\\n"
        f"       --manifest {net}/network-manifest.json"
    )


# --------------------------------------------------------------------
# down (tear down cohort)
# --------------------------------------------------------------------


def _parse_down_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Tear down cohort node(s). Each stack destroys independently."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--stack",
        nargs="+",
        metavar="STACK",
        help="Specific stack name(s) to destroy, e.g. --stack dev-bootstrap-node-3.",
    )
    group.add_argument(
        "--count",
        type=int,
        help="Destroy the whole cohort '<prefix>-1' … '<prefix>-<count>'.",
    )
    parser.add_argument(
        "--stack-prefix",
        default="dev-bootstrap-node",
        help=(
            "Stack name prefix used with --count (default: dev-bootstrap-node). "
            "Pass the cohort's <env>-bootstrap-node for non-dev environments."
        ),
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help=(
            "Where `up` wrote the descriptors; each torn-down stack's "
            "<stack>.json is removed from here too (default: matches `up` — "
            "<network>/nodes/ with --network, else the shared descriptors/)."
        ),
    )
    parser.add_argument(
        "--network",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Network directory the cohort was provisioned for (`up --network`); "
            "its nodes/ subdir is where the descriptors get deleted from."
        ),
    )
    args = parser.parse_args()
    if args.network is not None:
        args.network = args.network.resolve()
    return args


def _destroy_one(stack_name: str, out_dir: Path) -> None:
    """Tear down one stack completely, leaving no trace: destroy its resources,
    remove the stack (state registration AND its generated Pulumi.<stack>.yaml),
    and delete its descriptor. The per-node stacks regenerate from the template
    on the next `up`, so nothing here is worth keeping. After a successful
    destroy the stack is empty, so remove needs no --force.

    Output streams with a `[stack]` prefix: under parallel teardown the lines
    from different stacks interleave, but the prefix keeps them attributable
    (and live output beats a silent wait).
    """
    stack = auto.select_stack(stack_name=stack_name, work_dir=str(SEISMIC_NODE_DIR))
    stack.destroy(on_output=lambda line: print(f"[{stack_name}] {line}"))
    stack.workspace.remove_stack(stack_name)
    (out_dir / f"{stack_name}.json").unlink(missing_ok=True)


def down_main() -> None:
    args = _parse_down_args()
    _ensure_passphrase(confirm=False)
    targets = (
        list(args.stack)
        if args.stack
        else [f"{args.stack_prefix}-{i}" for i in range(1, args.count + 1)]
    )
    out_dir = _resolve_out_dir(args.out_dir, args.network)

    # Independent stacks (separate state + per-stack locks) → tear them down
    # concurrently. A failure on one is reported but doesn't abort the rest.
    print(f"Destroying {len(targets)} stack(s): {', '.join(targets)}")
    failures: list[str] = []
    with ThreadPoolExecutor(max_workers=min(len(targets), 8)) as pool:
        futures = {pool.submit(_destroy_one, name, out_dir): name for name in targets}
        for future in as_completed(futures):
            name = futures[future]
            try:
                future.result()
                print(f"  ✓ {name}: destroyed, stack removed, descriptor deleted")
            except Exception:  # noqa: BLE001 — report per stack, keep tearing down
                failures.append(name)
                print(f"  ✗ {name}: FAILED (see [{name}] output above)")
    if failures:
        raise SystemExit(
            f"{len(failures)} of {len(targets)} stack(s) failed: {', '.join(failures)}"
        )


if __name__ == "__main__":
    up_main()
