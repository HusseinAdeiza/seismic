"""Shared plumbing for the tee click front-ends.

Both CLIs — `seismic-tee-node` (operator) and `seismic-tee-network`
(network founding) — are thin click groups that forward each
leaf's arguments verbatim to that module's own argparse `main()`, so
per-command flags and `--help` are unchanged. Subcommand imports are
deferred so loading the group doesn't pull in any one path's heavy deps.
"""

import sys

import click

# ignore_unknown_options + UNPROCESSED args let us capture the whole
# remainder (flags included) and hand it to the inner argparse parser.
PASSTHROUGH = {"ignore_unknown_options": True}


class WorkflowOrderGroup(click.Group):
    """`--help` lists commands in declaration order — the app files declare
    them in workflow order, which is the reading order an operator wants —
    instead of click's default alphabetical sort."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        return list(self.commands)


def forward(module_main, prog: str, argv: tuple[str, ...]) -> None:
    # argparse reads sys.argv directly, so make it look like the subcommand
    # was invoked on its own (argv[0] is only usage text).
    sys.argv = [prog, *argv]
    module_main()
