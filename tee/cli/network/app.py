"""`seismic-tee-network` — CLI to found a Seismic TEE network.

The network-founder CLI — for whoever brings a network into existence
(one of Seismic's, a fork, a private devnet), NOT for operating a single
node of an existing network: it runs the one-time network-creation steps
(`init`, `harvest`, `assemble`, `validate`, `configure`). It never
provisions — neither CLI wraps Pulumi. The cohort comes from the
seismic_node Pulumi program (tee/pulumi/seismic_node, one stack per
environment with a `nodes` map), and this CLI starts at that map, saved
as the network's descriptor file (see tee/cli/common/descriptor.py);
harvest, assemble and configure consume it.

Wired via [project.scripts] in pyproject.toml. Each leaf forwards its argv
to that module's argparse `main()`; see tee/cli/common/plumbing.py.
Commands are declared in founding-workflow order (`--help` preserves it).
"""

import click

from tee.cli.common.plumbing import PASSTHROUGH, WorkflowOrderGroup, forward


@click.group(
    cls=WorkflowOrderGroup,
    epilog="Commands are listed in the order they should be run: "
    "init → harvest → assemble → validate → configure. Between init and "
    "harvest, provision the cohort with the seismic_node Pulumi program "
    "(tee/pulumi/seismic_node); pulumi destroy tears it down.",
)
def app() -> None:
    """Seismic network founding."""


@app.command(name="init", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def init(argv: tuple[str, ...]) -> None:
    """Scaffold a network directory's authored inputs."""
    from tee.cli.common import manifest as manifest_mod

    forward(manifest_mod.init_main, "seismic-tee-network init", argv)


@app.command(name="harvest", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def harvest(argv: tuple[str, ...]) -> None:
    """Harvest + DCAP-verify a founding cohort's summit keys into inputs/."""
    from tee.cli.network import harvest as harvest_mod

    forward(harvest_mod.main, "seismic-tee-network harvest", argv)


@app.command(name="assemble", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def assemble(argv: tuple[str, ...]) -> None:
    """Derive the artifact set from a network directory's inputs."""
    from tee.cli.common import manifest as manifest_mod

    forward(manifest_mod.assemble_main, "seismic-tee-network assemble", argv)


@app.command(name="validate", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def validate(argv: tuple[str, ...]) -> None:
    """Re-run all gates over an assembled network directory."""
    from tee.cli.common import manifest as manifest_mod

    forward(manifest_mod.validate_main, "seismic-tee-network validate", argv)


@app.command(name="configure", context_settings=PASSTHROUGH, add_help_option=False)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
def configure(argv: tuple[str, ...]) -> None:
    """Configure a cohort in parallel: one genesis + N joiners, one command."""
    from tee.cli.network import cohort_configure

    forward(cohort_configure.main, "seismic-tee-network configure", argv)


if __name__ == "__main__":
    app()
