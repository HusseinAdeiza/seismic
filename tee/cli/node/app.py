"""`seismic-tee-node` — operator CLI for a single Seismic TEE node.

Operator-facing: the commands a node operator runs against their own
already-provisioned node (configure today; stake / sync later). It is
cloud-agnostic and descriptor-based — it never wraps Pulumi. Standing up a
network (provisioning, harvest, founding) is a Seismic-internal act and
lives in the separate `seismic-tee-network` CLI.

Wired via [project.scripts] in pyproject.toml. Each leaf forwards its argv
to that module's argparse `main()`; see tee/cli/common/plumbing.py.
"""

import click

from tee.cli.common.plumbing import PASSTHROUGH, forward


@click.group()
def app() -> None:
    """Seismic TEE node operator commands."""


@app.command(name="configure", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def configure(argv: tuple[str, ...]) -> None:
    """Configure a node to join a network: assemble + POST config to tdx-init."""
    from tee.cli.node import configure as configure_mod

    forward(configure_mod.main, "seismic-tee-node configure", argv)


@app.command(name="status", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def status(argv: tuple[str, ...]) -> None:
    """Watch a node's first-boot LUKS provisioning progress."""
    from tee.cli.node import status as status_mod

    forward(status_mod.main, "seismic-tee-node status", argv)


if __name__ == "__main__":
    app()
