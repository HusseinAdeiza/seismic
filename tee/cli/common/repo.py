"""Where this checkout keeps the things the CLIs point at.

Layout facts, not configuration: `init` points the founder at the Pulumi
program and its stack config, so they are spelled once here rather than
derived from `__file__` in each module that needs them.
"""

from pathlib import Path

# tee/cli/common/repo.py -> tee/
_TEE_DIR = Path(__file__).parents[2]

# The Pulumi program that provisions a cohort: one stack per environment,
# one node per key of its `nodes` config map. Neither CLI runs it — the
# founder does, with the plain `pulumi` CLI from this directory.
SEISMIC_NODE_DIR = _TEE_DIR / "pulumi" / "seismic_node"

# The committed single-node developer environment's stack config: the image
# pin every node boots (vhd_blob_url), the VM shape and region,
# operator_ip_cidr — the CIDR that may reach the operator-only ports — and
# the `nodes` map. The four-node dev network beside it is Pulumi.devnet.yaml.
DEFAULT_STACK_CONFIG = SEISMIC_NODE_DIR / "Pulumi.devnode.yaml"
