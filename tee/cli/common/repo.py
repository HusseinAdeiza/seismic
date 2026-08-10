"""Where this checkout keeps the things the CLIs point at.

Layout facts, not configuration. Both front-ends name them — the
orchestrator provisions from the Pulumi program, `init` points
the founder at its stack config — so they are spelled once here rather
than derived from `__file__` in each module that needs them.
"""

from pathlib import Path

# tee/cli/common/repo.py -> tee/
_TEE_DIR = Path(__file__).parents[2]

# The single-node program the orchestrator fans out over. A local-program
# workspace points at this dir, so the project name / runtime / venv all
# come from its Pulumi.yaml — identical to running `pulumi` in that dir.
SEISMIC_NODE_DIR = _TEE_DIR / "pulumi" / "seismic_node"

# Shared settings are inherited from this stack config unless --config
# overrides: the image pin every cohort boots (vhd_blob_url), the VM
# shape and region, and operator_ip_cidr — the CIDR that may reach the
# operator-only ports.
DEFAULT_STACK_CONFIG = SEISMIC_NODE_DIR / "Pulumi.dev.yaml"
