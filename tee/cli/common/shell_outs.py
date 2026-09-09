"""The boundary to the sibling binaries deploy shells out to.

Every artifact deploy derives from a sibling binary is derived by *running*
that binary, never by mirroring its logic in Python: the hash a node computes
at boot is the hash the node's own code computes.

    seismic-reth genesis-hash                eth.genesis_hash
    summit genesis set-validators / digest   the completed summit genesis and
                                             summit.genesis_config_digest
    seismic-tee-network tools
      admission promote / compile            the bootstrap policy, its hash,
                                             and the registry genesis storage
                                             its admission IDs compile to
      verify harvest / deploy                DCAP verdicts on a founding
                                             harvest record and on a
                                             provisioned node
      manifest render / parse                the canonical manifest bytes
                                             and the strict schema verdict
                                             on existing ones

`seismic-tee-network` is the Rust deploy CLI, which links the enclave crates
those rules live in (seismic-network-manifest and its renderer,
seismic-measurement-admission, the verify-quote library); its `tools` group
is those libraries at the subprocess boundary, for as long as the founding is
orchestrated from here. `summit` and `seismic-reth` are foreign repos' node
binaries and stay shell-outs under any design.

Each function here owns one subcommand's contract — argv, what travels on
stdin/stdout, and what a failure means — and reports every failure as a
`GateError` naming the command that produced it (the manifest tool's schema
verdict is the one `ManifestSchemaError`). The `--*-bin` flags on the CLIs
override the `DEFAULT_*_BIN` names below.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from tee.cli.common.errors import GateError, ManifestSchemaError

DEFAULT_ATTESTATION_TYPE = "azure-tdx"

# The execution client. Its `genesis-hash` subcommand parses a genesis file
# down the same path `seismic-reth node --chain` takes, so the hash it prints
# is the one a node booted from that file computes.
DEFAULT_RETH_BIN = "seismic-reth"

# Summit's node binary. Its `genesis digest` subcommand computes
# summit.genesis_config_digest: SHA-256 over summit's domain-prefixed SSZ
# serialization of the complete genesis — summit's own definition of chain
# identity (its P2P and signing domains derive from it). Its `genesis
# set-validators` subcommand emits the completed genesis the digest is
# computed over. Both are shell-outs to the one implementation instead of
# mirroring the SSZ layout / canonical rendering in Python.
DEFAULT_SUMMIT_BIN = "summit"

# The Rust deploy CLI, whose `tools` group is the enclave libraries at the
# subprocess boundary. Three of them:
#
# `tools admission promote|compile` — the seismic-measurement-admission
# crate. Promotion and policy->genesis-storage compilation are schema
# knowledge (which registers form guest identity, which value forms are
# canonical, how admission IDs key registry storage), so deploy runs the one
# shared implementation instead of carrying a second one in Python.
#
# `tools verify harvest|deploy` — the verify-quote library: exit 0 plus one
# JSON report on stdout <=> verified. `harvest` checks one founding harvest
# record — `network harvest` runs it on the record it is about to archive,
# and `assemble` re-runs it over each archived record before the harvested
# set is pinned. `deploy` deploy-verifies a freshly provisioned node —
# `node verify`, and `node configure` once the node is up, run it.
# Verification-only; runs natively on any dev platform (verification is
# pure computation over the evidence bytes — no TEE hardware involved).
#
# `tools manifest render|parse` — the seismic-network-manifest crate every
# node parses the manifest with, plus its renderer, so the emitter and the
# parser cannot disagree. `render` is the manifest's sole emitter: a
# document with the manifest's values, in any JSON formatting, becomes the
# canonical network-manifest.json bytes (network_id = SHA-256 of them).
# `parse` is the strict v1 schema check every reader runs before trusting a
# manifest's fields.
#
# Built from tee/cli/rust (`cargo install --path tee/cli/rust/network`) and
# expected on PATH like the others. It shares its name with this package's
# own console script on purpose — the Rust CLI replaces the Python one command
# by command — so see `resolve_tee_bin` for how the two are told apart.
DEFAULT_TEE_BIN = "seismic-tee-network"

BUILD_TEE_BIN_HINT = (
    "build the Rust deploy CLI (`cargo install --path tee/cli/rust/network` "
    "from the deploy repo) and put it on PATH, or pass --tee-bin"
)


def resolve_tee_bin(tee_bin: str = DEFAULT_TEE_BIN) -> str | None:
    """Find the Rust deploy CLI, or None if it is not on PATH.

    The Python package installs a console script of the same name, and
    `uv run` puts the venv's bin directory first on PATH — so a plain
    PATH lookup for `seismic-tee-network` from inside `uv run
    seismic-tee-network harvest` finds *this* program, not the Rust binary.
    The lookup therefore skips the directories this interpreter's console
    scripts live in: the venv's bin, which is where `sys.executable` sits
    and `sys.prefix` points (the interpreter there is a symlink into a
    uv-managed install, so it is the directory that is compared, never the
    symlink's target). A name with a path separator is taken as given, like
    `subprocess` would.

    Returns the absolute path, so every shell-out here runs the binary this
    resolved rather than repeating the lookup — a bare or relative name would
    send `subprocess` back to PATH, and so back to the console script.
    """
    if os.sep in tee_bin or (os.altsep and os.altsep in tee_bin):
        return tee_bin if Path(tee_bin).is_file() else None
    own_scripts = {
        Path(sys.executable).parent.resolve(),
        (Path(sys.prefix) / "bin").resolve(),
    }
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        directory = Path(entry)
        try:
            if directory.resolve() in own_scripts:
                continue
        except OSError:
            continue
        candidate = directory / tee_bin
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.absolute())
    return None


def tee_bin_not_found(tee_bin: str) -> GateError:
    return GateError(f"{tee_bin!r} not found on PATH; {BUILD_TEE_BIN_HINT}")


def _tee_cmd(tee_bin: str, *args: str) -> list[str]:
    """argv for one `tools` subcommand of the deploy CLI, or the not-found
    error if the binary is not there (raised here so no caller reports a
    missing tool as the tool's verdict)."""
    resolved = resolve_tee_bin(tee_bin)
    if resolved is None:
        raise tee_bin_not_found(tee_bin)
    return [resolved, "tools", *args]


def _admission_cli(tee_bin: str, *args: str, input_bytes: bytes) -> bytes:
    """Run one `tools admission` subcommand, feeding the document on stdin.

    Byte streams both ways: promoted policy bytes are hash-committed, so
    nothing may re-render them between the CLI and the artifact set.
    """
    cmd = _tee_cmd(tee_bin, "admission", *args, "-")
    try:
        result = subprocess.run(
            cmd, input=input_bytes, capture_output=True, timeout=120, check=True
        )
    except subprocess.TimeoutExpired:
        raise GateError(f"`{' '.join(cmd)}` timed out") from None
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or e.stdout or b"").decode("utf-8", "replace").strip()
        raise GateError(f"`{' '.join(cmd)}` failed: {detail}") from None
    return result.stdout


def promote_measurements(
    raw_bytes: bytes,
    attestation_type: str = DEFAULT_ATTESTATION_TYPE,
    tee_bin: str = DEFAULT_TEE_BIN,
) -> bytes:
    """Promote `make measure` output into measurement-policy-bootstrap.json
    bytes.

    Shells out to `tools admission promote`, which selects exactly the
    admission-schema registers from the raw measured-boot output, normalizes
    them to named `pcrN` keys binding a single-value `expected_any`, wraps
    them into one Flashbots-compatible policy record, and compiles its own
    output before returning it. The record's `measurement_id` — which image
    these PCRs measure — comes from the measurements file itself, where
    `make measure` stamped it; nothing binds the policy to an image out of
    band. If the input already *is* a record list it is passed through
    byte-verbatim (the manifest commits to the policy file by hash, so an
    already-published policy must not be re-rendered) — but still compiled,
    which is the whole promoted-policy validation: a document the compiler
    accepts is exactly a document that can seed registry genesis storage.
    """
    args = ["promote"]
    if attestation_type:
        args += ["--attestation-type", attestation_type]
    return _admission_cli(tee_bin, *args, input_bytes=raw_bytes)


def compile_measurement_policy(
    policy_bytes: bytes, tee_bin: str = DEFAULT_TEE_BIN
) -> dict[str, Any]:
    """Compile a policy document via `tools admission compile`; returns its report:
    policy hash, admission IDs, the canonical registry runtime-code hash, and
    the complete registry genesis storage map."""
    report = _admission_cli(tee_bin, "compile", input_bytes=policy_bytes)
    return json.loads(report)


def _manifest_tool(
    tee_bin: str, subcommand: str, input_bytes: bytes, *, invalid: str
) -> bytes:
    """Run one `tools manifest` subcommand with the document on stdin.

    A nonzero exit is the tool's schema verdict on `input_bytes`
    (`ManifestSchemaError`, prefixed with `invalid`); everything else that can
    go wrong is tooling (`GateError`).
    """
    cmd = _tee_cmd(tee_bin, "manifest", subcommand, "-")
    try:
        result = subprocess.run(
            cmd, input=input_bytes, capture_output=True, timeout=120
        )
    except subprocess.TimeoutExpired:
        raise GateError(f"`{' '.join(cmd)}` timed out") from None
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ManifestSchemaError(f"{invalid}: {detail}")
    return result.stdout


def render_manifest(document: bytes, tee_bin: str = DEFAULT_TEE_BIN) -> bytes:
    """Render the canonical manifest bytes via `tools manifest render`.

    `document` carries the manifest's values as JSON in any formatting; the
    tool strictly parses it and emits the one canonical rendering. The
    returned bytes are the artifact: write them verbatim, never re-render.
    """
    rendered = _manifest_tool(
        tee_bin, "render", document, invalid="manifest values rejected"
    )
    if not rendered:
        raise GateError(f"`{tee_bin} tools manifest render` emitted nothing on stdout")
    return rendered


def parse_manifest(manifest_bytes: bytes, tee_bin: str = DEFAULT_TEE_BIN) -> None:
    """Put manifest bytes through `tools manifest parse`, the strict v1
    parser every node reads the file with. Raises on rejection."""
    _manifest_tool(
        tee_bin,
        "parse",
        manifest_bytes,
        invalid="manifest does not satisfy the v1 schema",
    )


def _check_digest(value: str, where: str) -> str:
    """A digest a sibling binary printed on stdout: 32-byte 0x-hex, lowercased."""
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        raise GateError(f"{where}: expected 32-byte hex string, got {value!r}")
    return value.lower()


def reth_genesis_hash(reth_genesis: Path, reth_bin: str = DEFAULT_RETH_BIN) -> str:
    """Compute eth_genesis_hash offline via `seismic-reth genesis-hash`."""
    cmd = [reth_bin, "genesis-hash", "--chain", str(reth_genesis)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, check=True
        )
    except FileNotFoundError:
        raise GateError(
            f"{reth_bin!r} not found; build seismic-reth (the genesis-hash "
            "subcommand) or pass --reth-bin"
        ) from None
    except subprocess.CalledProcessError as e:
        raise GateError(
            f"`{' '.join(cmd)}` failed: {e.stderr.strip() or e.stdout.strip()}"
        ) from None
    return _check_digest(result.stdout.strip(), f"`{' '.join(cmd)}` output")


def summit_config_digest(
    summit_genesis: Path, summit_bin: str = DEFAULT_SUMMIT_BIN
) -> str:
    """Compute summit.genesis_config_digest offline via `summit genesis digest`.

    The file is loaded down the same parse path a starting validator takes, so
    a successful digest doubles as a verdict that the genesis is well formed:
    anything this accepts a validator accepts.
    """
    cmd = [summit_bin, "genesis", "digest", str(summit_genesis)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, check=True
        )
    except FileNotFoundError:
        raise GateError(
            f"{summit_bin!r} not found; build summit (the `genesis digest` "
            "subcommand) or pass --summit-bin"
        ) from None
    except subprocess.CalledProcessError as e:
        raise GateError(
            f"`{' '.join(cmd)}` failed: {e.stderr.strip() or e.stdout.strip()}"
        ) from None
    return _check_digest(result.stdout.strip(), f"`{' '.join(cmd)}` output")


def _run_verify(
    tee_bin: str, *args: str, input_bytes: bytes | None = None
) -> dict[str, Any]:
    """Run one `tools verify` subcommand and enforce its contract: exit 0
    plus one JSON `{"verified": true, ...}` report on stdout <=> verified;
    anything else is a GateError.
    """
    cmd = _tee_cmd(tee_bin, "verify", *args)
    try:
        result = subprocess.run(
            cmd,
            input=input_bytes,
            capture_output=True,
            # Generous — DCAP verification fetches collateral over the
            # network (PCCS) — but a hung fetch must not stall the
            # caller forever.
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        raise GateError(f"`{' '.join(cmd)}` timed out") from None
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"quote verification failed:\n{detail}")
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        report = None
    if not isinstance(report, dict) or report.get("verified") is not True:
        raise GateError(
            f"`{' '.join(cmd[:4])}` exited 0 without a verified report: "
            f"{result.stdout!r}"
        )
    return report


def verify_harvest_record(
    record: dict[str, Any],
    *,
    policy_path: Path,
    tee_bin: str = DEFAULT_TEE_BIN,
    pccs_url: str | None = None,
    dump_collateral: Path | None = None,
    collateral: Path | None = None,
) -> dict[str, Any]:
    """DCAP-verify one founding harvest record via `tools verify harvest`.

    The verifier owns the whole check: the record's evidence must verify
    cryptographically, its report_data must bind the record's own nonce and
    pubkeys, and its measurements must satisfy the policy. The record goes
    over stdin as one document — the same one the archive keeps, so what is
    archived is what was verified.

    `dump_collateral` asks the verifier to write the DCAP collateral this
    verification consumed to that path, which it does only once the quote has
    verified. The verifier is the only component that knows which bundle it
    used, so a caller archiving founding provenance takes the file it writes
    rather than fetching a second copy that a cache refresh could make
    differ. Exit 0 without that file is a broken contract, not a pass.

    `collateral` is the other direction: the record is verified against that
    archived snapshot, at the instant the snapshot was held to, reaching no
    collateral service. Intel's TCB Info, QE Identity and both CRLs carry
    nextUpdate on a roughly 30-day cadence, so this is the only form of the
    check that still passes a month after the founding. It excludes
    `dump_collateral` — one call verifies live or replays an archive, never
    both — and leaves `pccs_url` with nothing to reach.
    """
    if collateral is not None and dump_collateral is not None:
        raise ValueError(
            "verify_harvest_record verifies live or replays an archive, not both"
        )
    args = ["harvest", "--record", "-", "--policy", str(policy_path)]
    if pccs_url:
        args += ["--pccs-url", pccs_url]
    if dump_collateral is not None:
        args += ["--dump-collateral", str(dump_collateral)]
    if collateral is not None:
        args += ["--collateral", str(collateral)]
    report = _run_verify(tee_bin, *args, input_bytes=json.dumps(record).encode("utf-8"))
    if dump_collateral is not None and not dump_collateral.is_file():
        raise GateError(
            f"`{tee_bin} tools verify harvest` reported the quote verified but "
            f"wrote no collateral to {dump_collateral}; without it the archived quote "
            "is not re-verifiable once Intel's live collateral ages past it"
        )
    return report


def verify_node_deployment(
    endpoint: str,
    *,
    manifest_path: Path,
    policy_bytes: bytes,
    tee_bin: str = DEFAULT_TEE_BIN,
    pccs_url: str | None = None,
) -> dict[str, Any]:
    """Deploy-verify one freshly provisioned node via `tools verify deploy`.

    The verifier owns the whole relying-party flow: it mints a fresh
    deployment_nonce, requests evidence from the node's attestation service
    (`getDeployVerificationEvidence` at `endpoint`), recomputes the deploy
    verification binding from the manifest's network identity and the nonce,
    and verifies the envelope against the policy. A pass proves a measured
    node holding this manifest answered this exact request.
    """
    with tempfile.NamedTemporaryFile(
        prefix="measurement-policy-", suffix=".json"
    ) as policy_file:
        policy_file.write(policy_bytes)
        policy_file.flush()
        args = [
            "deploy",
            "--endpoint",
            endpoint,
            "--manifest",
            str(manifest_path),
            "--policy",
            policy_file.name,
        ]
        if pccs_url:
            args += ["--pccs-url", pccs_url]
        return _run_verify(tee_bin, *args)


def summit_set_validators(
    template_bytes: bytes,
    validators: list[dict[str, str]],
    summit_bin: str = DEFAULT_SUMMIT_BIN,
) -> bytes:
    """Emit the completed summit genesis via `summit genesis set-validators`.

    Emission belongs to summit: the subcommand parses the template into
    summit's own Genesis type, replaces its validator set with
    `validators`, sorts them by node key (the order config_digest hashes),
    renders the whole file canonically — summit's hex spellings, no
    authored comments — and reloads what it emits, so a genesis no node
    could load fails here rather than at boot. The returned bytes are what
    the artifact set ships and the manifest's digest commits to.
    """
    with (
        tempfile.NamedTemporaryFile(suffix=".toml") as template_file,
        tempfile.NamedTemporaryFile(suffix=".json") as validators_file,
    ):
        template_file.write(template_bytes)
        template_file.flush()
        validators_file.write((json.dumps(validators, indent=2) + "\n").encode())
        validators_file.flush()
        cmd = [
            summit_bin,
            "genesis",
            "set-validators",
            "-i",
            template_file.name,
            "-v",
            validators_file.name,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=120, check=True)
        except FileNotFoundError:
            raise GateError(
                f"{summit_bin!r} not found; build summit (the `genesis "
                "set-validators` subcommand) or pass --summit-bin"
            ) from None
        except subprocess.TimeoutExpired:
            raise GateError(f"`{' '.join(cmd)}` timed out") from None
        except subprocess.CalledProcessError as e:
            detail = (e.stderr or e.stdout or b"").decode("utf-8", "replace").strip()
            raise GateError(f"`{' '.join(cmd)}` failed: {detail}") from None
    if not result.stdout:
        raise GateError(f"`{' '.join(cmd)}` emitted nothing on stdout")
    return result.stdout
