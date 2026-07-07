"""`seismic-tee-bootstrap` — internal CLI to found a Seismic TEE network.

Seismic-internal, NOT a tool node operators run: it provisions a cohort of
TDX nodes (`up` / `down`) and runs the one-time network-creation steps
(`manifest`, `genesis-ceremony`). This is the CLI that is *allowed* to wrap
Pulumi —
`up` / `down` drive the seismic_node Automation-API orchestrator. The
operator CLI (`seismic-tee`) deliberately is not; the boundary is the node
descriptor file (see tee/cli/common/descriptor.py), which this CLI produces
(via provisioning) and consumes (during the genesis ceremony).

Wired via [project.scripts] in pyproject.toml. Each leaf forwards its argv
to that module's argparse `main()`; see tee/cli/common/plumbing.py.
"""

import click

from tee.cli.common.plumbing import PASSTHROUGH, forward


@click.group()
def app() -> None:
    """Seismic network founding + provisioning (internal)."""


@app.command(name="up", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def up(argv: tuple[str, ...]) -> None:
    """Provision a cohort of TDX nodes (one independent Pulumi stack each)."""
    from tee.cli.network import orchestrator

    forward(orchestrator.up_main, "seismic-tee-bootstrap up", argv)


@app.command(name="down", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def down(argv: tuple[str, ...]) -> None:
    """Tear down cohort node(s); each stack destroys independently."""
    from tee.cli.network import orchestrator

    forward(orchestrator.down_main, "seismic-tee-bootstrap down", argv)


@app.command(name="configure", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def configure(argv: tuple[str, ...]) -> None:
    """Configure a cohort in parallel: one genesis + N joiners, one command."""
    from tee.cli.network import cohort_configure

    forward(cohort_configure.main, "seismic-tee-bootstrap configure", argv)


@app.command(
    name="genesis-ceremony", context_settings=PASSTHROUGH, add_help_option=False
)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def genesis_ceremony(argv: tuple[str, ...]) -> None:
    """One-shot genesis ceremony: build genesis.toml from the cohort, fan it out."""
    from tee.cli.network import genesis as genesis_mod

    forward(genesis_mod.main, "seismic-tee-bootstrap genesis-ceremony", argv)


@app.command(name="manifest", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def manifest(argv: tuple[str, ...]) -> None:
    """Scaffold (init) / assemble / validate a network artifact-set dir."""
    from tee.cli.common import manifest as manifest_mod

    forward(manifest_mod.main, "seismic-tee-bootstrap manifest", argv)


if __name__ == "__main__":
    app()
