"""The two ways deploy-side validation fails.

Both `manifest` (schema and gates) and `shell_outs` (the sibling binaries)
raise `GateError`, and `manifest` builds on `shell_outs` — so the exceptions
live below both.
"""


class ManifestSchemaError(Exception):
    """Manifest bytes don't satisfy the strict v1 schema."""


class GateError(Exception):
    """A cross-artifact validation gate failed (fail at deploy, not at boot)."""
