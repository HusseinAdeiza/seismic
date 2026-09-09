"""`seismic-tee-node` — operator CLI for a single Seismic TEE node.

Operator-facing: the commands a node operator runs against their own
already-provisioned node (configure, verify, status today; stake / sync
later). It is
cloud-agnostic and descriptor-based — it never wraps Pulumi (provisioning
is the seismic_node Pulumi program's job, for one node or a cohort).
Founding a network (harvest, assemble, configuring the cohort) is the
network founder's act and lives in the separate `seismic-tee-network` CLI.

Retired as an entry point: `seismic-tee-node` is the Rust binary built from
tee/cli/rust/node, which runs every command below, and pyproject.toml no
longer wires this group to that name. The modules stay because the Python
`seismic-tee-network configure` imports their primitives (`build_config`,
`post_config_to_tdx_init`, `poll_provisioning`, the appraisal); they go with
the Python founding port. Each leaf forwards its argv to that module's
argparse `main()`; see tee/cli/common/plumbing.py.
"""

import click

from tee.cli.common.plumbing import PASSTHROUGH, WorkflowOrderGroup, forward


@click.group(cls=WorkflowOrderGroup)
def app() -> None:
    """Seismic TEE node operator commands."""


@app.command(name="configure", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def configure(argv: tuple[str, ...]) -> None:
    """Configure a node to join a network: assemble + POST config to tdx-init."""
    from tee.cli.node import configure as configure_mod

    forward(configure_mod.main, "seismic-tee-node configure", argv)


@app.command(name="verify", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def verify(argv: tuple[str, ...]) -> None:
    """Deploy-verify a node's TDX attestation against the intended image."""
    from tee.cli.node import verify as verify_mod

    forward(verify_mod.main, "seismic-tee-node verify", argv)


@app.command(name="status", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def status(argv: tuple[str, ...]) -> None:
    """Watch a node's first-boot LUKS provisioning progress."""
    from tee.cli.node import status as status_mod

    forward(status_mod.main, "seismic-tee-node status", argv)


if __name__ == "__main__":
    app()
