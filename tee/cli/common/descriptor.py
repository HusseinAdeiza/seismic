"""Node descriptor: the handoff from provisioning to configuration.

A *descriptor* is a small JSON file describing one provisioned node — the
public IP to reach it at (`public_ip`) and the FQDN clients use (`fqdn`).
It is the boundary between the infrastructure layer (provisioning, owned
by Pulumi and run standalone) and both CLIs: a CLI consumes a descriptor
and never shells out to or wraps Pulumi.

The seismic_node Pulumi program's `nodes` output is one `{public_ip, fqdn}`
per node, keyed by name; one file per node is split out of it (the runbook
has the loop). A bring-your-own-infra operator (Terraform, manual console,
…) can hand-write the same shape, since only `public_ip`/`fqdn` are read
and any extra keys are ignored:

    seismic-tee-node configure --node my-node.json \
        --bootnode enode://… --manifest m.json
"""

import json
from pathlib import Path


def load_descriptor(path: Path) -> dict:
    """Load a node descriptor JSON file."""
    with open(path) as f:
        return json.load(f)


def require(descriptor: dict, key: str, path: Path) -> str:
    """Return descriptor[key], or raise with the offending file + keys."""
    value = descriptor.get(key)
    if not value:
        raise ValueError(
            f"descriptor {path} is missing required key {key!r}; "
            f"got keys {sorted(descriptor)}"
        )
    return value
