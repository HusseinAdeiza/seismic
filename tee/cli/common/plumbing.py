"""Shared plumbing for the tee click front-ends.

Both CLIs — `seismic-tee-node` (operator) and `seismic-tee-network`
(internal network founding) — are thin click groups that forward each
leaf's arguments verbatim to that module's own argparse `main()`, so
per-command flags and `--help` are unchanged. Subcommand imports are
deferred so loading the group doesn't pull in any one path's heavy deps.
"""

import sys

# ignore_unknown_options + UNPROCESSED args let us capture the whole
# remainder (flags included) and hand it to the inner argparse parser.
PASSTHROUGH = {"ignore_unknown_options": True}


def forward(module_main, prog: str, argv: tuple[str, ...]) -> None:
    # argparse reads sys.argv directly, so make it look like the subcommand
    # was invoked on its own (argv[0] is only usage text).
    sys.argv = [prog, *argv]
    module_main()
