"""The two ways deploy-side validation fails.

Both `manifest` (the gates) and `shell_outs` (the sibling binaries) raise
`GateError`, and `manifest` builds on `shell_outs` — so the exceptions live
below both.
"""


class ManifestSchemaError(Exception):
    """Manifest bytes don't satisfy the strict v1 schema — the manifest
    tool's verdict, relayed by `shell_outs`."""


class GateError(Exception):
    """A cross-artifact validation gate failed (fail at deploy, not at boot)."""
