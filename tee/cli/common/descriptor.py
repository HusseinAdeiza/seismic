"""Node descriptors: the handoff from provisioning to configuration.

The descriptor file is the cohort's `nodes` map — exactly what the
seismic_node Pulumi program's `pulumi stack output nodes --json` prints:

    {
      "devnet-3-1": {"public_ip": "203.0.113.7", "fqdn": "n1.seismicdev.net"},
      "devnet-3-2": {"public_ip": "203.0.113.8", "fqdn": "n2.seismicdev.net"}
    }

Each entry describes one provisioned node: the public IP to reach it at
(`public_ip`) and the FQDN clients use (`fqdn`). The key is the node's
name — the name its harvest record and founding validator slot carry — so
identity lives in the file's content, never in how a file was saved. The
file is the boundary between the infrastructure layer (provisioning, owned
by Pulumi and run standalone) and both CLIs: a CLI consumes the map and
never shells out to or wraps Pulumi. Saving the stack output as-is is one
idempotent command with no per-node bookkeeping, so re-running it after any
map edit (add, remove, re-image) cannot leave the file drifted from the
stack.

A network directory keeps it at `<network>/nodes/nodes.json`, beside
`nodes/bootnodes.json`; a bring-your-own-infra operator (Terraform, manual
console, …) hand-writes a one-key map in the same shape, since only
`public_ip`/`fqdn` are read and any extra keys are ignored:

    seismic-tee-node configure --node my-node.json \
        --bootnode enode://… --manifest m.json
"""

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

# The descriptor map lives under this subdir of a network directory, beside
# the founding bootnode set. Mutable infra state — regenerated per deploy,
# gone with the stack — so it stays gitignored (tee/networks/.gitignore
# `*/nodes/`) while the artifact set around it commits.
NODES_DIRNAME = "nodes"
NODES_FILENAME = "nodes.json"


@dataclass(frozen=True)
class NodeDescriptor:
    """One provisioned node, as the `nodes` map describes it."""

    name: str
    public_ip: str
    fqdn: str


def nodes_file(network_dir: Path) -> Path:
    """Where a network directory keeps its descriptor map."""
    return network_dir / NODES_DIRNAME / NODES_FILENAME


def load_descriptors(path: Path) -> dict[str, NodeDescriptor]:
    """Load and validate a descriptor map, in sorted node-name order.

    `pulumi stack output --json` sorts keys, so a saved stack output is
    already in this order; sorting here means a hand-written map pairs with
    the authored withdrawal credentials the same way. Raises ValueError
    (naming the file and the entry) on any shape the CLIs can't act on:
    a top level that isn't an object, an entry that isn't an object, an
    empty map, or an entry whose `public_ip`/`fqdn` is absent, `null`, or
    empty — reported apart, because the fix differs (see `_require`).
    """
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(
            f"descriptor file {path} must be a JSON object mapping node name "
            f"→ {{public_ip, fqdn}} (the stack's `nodes` output); got "
            f"{type(data).__name__}"
        )
    if not data:
        raise ValueError(
            f"descriptor file {path} holds no nodes — is the stack's `nodes` map empty?"
        )
    if {"public_ip", "fqdn"} <= set(data) and all(
        not isinstance(v, dict) for v in data.values()
    ):
        # One node's `{public_ip, fqdn}` at the top level — the shape a
        # descriptor file had before it was the map. Say so rather than
        # reporting "node 'fqdn' must be an object".
        raise ValueError(
            f"descriptor file {path} is a single node's {{public_ip, fqdn}}, not "
            "the map; the descriptor file is {<name>: {public_ip, fqdn}, …} — "
            "wrap it under the node's name"
        )
    descriptors = {}
    for name in sorted(data):
        entry = data[name]
        if not isinstance(entry, dict):
            raise ValueError(
                f"descriptor file {path}: node {name!r} must be an object with "
                f"public_ip and fqdn; got {type(entry).__name__}"
            )
        descriptors[name] = NodeDescriptor(
            name=name,
            public_ip=_require(entry, "public_ip", name, path),
            fqdn=_require(entry, "fqdn", name, path),
        )
    return descriptors


def select_descriptor(
    descriptors: dict[str, NodeDescriptor], name: str | None, path: Path
) -> NodeDescriptor:
    """Pick the one node a single-node command acts on.

    With one entry in the file it is the node; with several, `name` says
    which. Raises ValueError naming the file and the choices otherwise.
    """
    if name is None:
        if len(descriptors) == 1:
            return next(iter(descriptors.values()))
        raise ValueError(
            f"descriptor file {path} holds {len(descriptors)} nodes "
            f"({', '.join(descriptors)}); pass --name to say which"
        )
    try:
        return descriptors[name]
    except KeyError:
        raise ValueError(
            f"descriptor file {path} has no node {name!r}; it holds "
            f"{', '.join(descriptors)}"
        ) from None


def add_node_args(parser: argparse.ArgumentParser) -> None:
    """`--node <file> [--name <name>]`: how a single-node command names its
    node. Shared by `seismic-tee-node configure` / `verify` / `status`."""
    parser.add_argument(
        "--node",
        type=Path,
        required=True,
        metavar="FILE",
        help=(
            "Descriptor map JSON: `pulumi stack output nodes --json`, i.e. "
            "{<name>: {public_ip, fqdn}, …} (a network directory keeps it at "
            f"{NODES_DIRNAME}/{NODES_FILENAME}). Provides the node's "
            "public_ip/fqdn. With one entry it is the node; with several, "
            "--name says which."
        ),
    )
    parser.add_argument(
        "--name",
        default=None,
        metavar="NAME",
        help="Which node in --node to act on (its key). Optional when the "
        "file holds exactly one.",
    )


def load_node_arg(args: argparse.Namespace) -> NodeDescriptor:
    """Resolve `--node`/`--name` to the one node, exiting with the reason if
    the file is absent, malformed, or doesn't single out a node."""
    if not args.node.is_file():
        raise SystemExit(f"--node descriptor file not found: {args.node}")
    try:
        return select_descriptor(load_descriptors(args.node), args.name, args.node)
    except json.JSONDecodeError as e:
        raise SystemExit(f"--node {args.node} is not valid JSON: {e}") from None
    except ValueError as e:
        raise SystemExit(str(e)) from None


def _require(entry: dict, key: str, name: str, path: Path) -> str:
    """Return entry[key], or raise naming the file, the node, and the mistake.

    An absent key, an explicit `null`, and an empty string all fail the
    same way — a descriptor that can't reach a node — but the fix differs,
    so they are reported apart: only the absent case is likely a typo and
    helped by listing the keys that *were* there, while a `null` is usually
    Pulumi reporting an output that never got set. Saying "missing" for a
    key the operator can plainly see in the file sends them looking in the
    wrong place.
    """
    if key not in entry:
        raise ValueError(
            f"descriptor file {path}: node {name!r} is missing required key "
            f"{key!r}; got keys {sorted(entry)}"
        )
    value = entry[key]
    if value is None:
        raise ValueError(
            f"descriptor file {path}: node {name!r} has {key!r} set to null "
            "(Pulumi emits null for an output that never got set)"
        )
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"descriptor file {path}: node {name!r} has an empty or non-string "
            f"{key!r}: {value!r}"
        )
    return value
