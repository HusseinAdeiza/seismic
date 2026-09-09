"""Tests for the deploy CLI's resolution in tee.cli.common.shell_outs.

The Rust deploy CLI shares its name with this package's own console script,
so finding it is the one shell-out concern with logic of its own. Everything
else in shell_outs is argv assembly, exercised where each caller's contract is
tested (test_manifest, test_harvest, test_verify) and against the real binary
in drift_test_manifest.
"""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tee.cli.common import shell_outs


class ResolveTeeBinTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory(prefix="tee-bin-")
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        # The venv's bin: where this interpreter and the Python console script
        # of the same name live. The interpreter is a symlink into a managed
        # install elsewhere, the way uv lays a venv out — so the skip has to
        # be by the directory the link sits in, not the one it points at.
        self.venv_bin = self.root / "venv" / "bin"
        self.venv_bin.mkdir(parents=True)
        managed = self._executable(self.root / "managed" / "bin" / "python3.13")
        self.python = self.venv_bin / "python"
        self.python.symlink_to(managed)
        self._executable(self.venv_bin / shell_outs.DEFAULT_TEE_BIN)
        # Where a real install of the Rust binary would be.
        self.cargo_bin = self.root / "cargo" / "bin"
        self.cargo_bin.mkdir(parents=True)

    def _executable(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def _resolve(self, *path_dirs: Path, name: str = shell_outs.DEFAULT_TEE_BIN):
        env = {"PATH": os.pathsep.join(str(d) for d in path_dirs)}
        with (
            mock.patch.object(shell_outs.sys, "executable", str(self.python)),
            mock.patch.object(shell_outs.sys, "prefix", str(self.root / "venv")),
            mock.patch.dict(shell_outs.os.environ, env, clear=False),
        ):
            return shell_outs.resolve_tee_bin(name)

    def test_skips_the_venvs_own_console_script(self):
        """`uv run` puts the venv's bin first on PATH, where the Python
        `seismic-tee-network` lives; the Rust one behind it is the answer."""
        rust = self._executable(self.cargo_bin / shell_outs.DEFAULT_TEE_BIN)
        self.assertEqual(self._resolve(self.venv_bin, self.cargo_bin), str(rust))

    def test_a_relative_path_entry_still_yields_an_absolute_path(self):
        """`PATH=<venv>/bin:.` with the binary in the cwd: a bare name back
        would send subprocess to PATH, and so to the console script."""
        rust = self._executable(self.cargo_bin / shell_outs.DEFAULT_TEE_BIN)
        cwd = os.getcwd()
        os.chdir(self.cargo_bin)
        self.addCleanup(os.chdir, cwd)
        resolved = self._resolve(self.venv_bin, Path("."))
        self.assertEqual(resolved, str(rust))
        self.assertTrue(Path(resolved).is_absolute())

    def test_none_when_only_the_console_script_is_on_path(self):
        self.assertIsNone(self._resolve(self.venv_bin))

    def test_none_when_nothing_of_that_name_is_on_path(self):
        self.assertIsNone(self._resolve(self.cargo_bin, name="no-such-tee-bin"))

    def test_a_non_executable_file_does_not_count(self):
        (self.cargo_bin / shell_outs.DEFAULT_TEE_BIN).write_text("not a program")
        self.assertIsNone(self._resolve(self.cargo_bin))

    def test_a_path_is_taken_as_given(self):
        # `--tee-bin ./target/release/seismic-tee-network`: no PATH search,
        # and the venv exclusion does not apply to an explicit location.
        explicit = self._executable(self.venv_bin / "seismic-tee-network-explicit")
        self.assertEqual(self._resolve(name=str(explicit)), str(explicit))
        self.assertIsNone(self._resolve(name=str(self.root / "absent" / "bin")))

    def test_the_shell_out_fails_closed_on_a_missing_binary(self):
        with mock.patch.dict(shell_outs.os.environ, {"PATH": str(self.venv_bin)}):
            with self.assertRaisesRegex(shell_outs.GateError, "not found on PATH"):
                shell_outs.parse_manifest(b"{}", tee_bin="no-such-tee-bin")


if __name__ == "__main__":
    unittest.main()
