"""The boundary to the sibling binaries deploy shells out to.

Every artifact deploy derives from a sibling binary is derived by *running*
that binary, never by mirroring its logic in Python: the hash a node computes
at boot is the hash the node's own code computes.

    seismic-reth genesis-hash                eth.genesis_hash
    summit genesis set-validators / digest   the completed summit genesis and
                                             summit.genesis_config_digest
    seismic-measurement-admission
      promote / compile                      the bootstrap policy, its hash,
                                             and the registry genesis storage
                                             its admission IDs compile to
    verify-quote harvest / deploy            DCAP verdicts on a founding
                                             harvest record and on a
                                             provisioned node

Each function here owns one subcommand's contract — argv, what travels on
stdin/stdout, and what a failure means — and reports every failure as a
`GateError` naming the command that produced it. The `--*-bin` flags on the
CLIs override the `DEFAULT_*_BIN` names below.
"""

import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tee.cli.common.errors import GateError

DEFAULT_ATTESTATION_TYPE = "azure-tdx"

# The execution client. Its `genesis-hash` subcommand parses a genesis file
# down the same path `seismic-reth node --chain` takes, so the hash it prints
# is the one a node booted from that file computes.
DEFAULT_RETH_BIN = "seismic-reth"

# The shared policy-compiler CLI from the enclave repo's
# seismic-measurement-admission crate. Promotion and policy->genesis-storage
# compilation are schema knowledge (which registers form guest identity,
# which value forms are canonical, how admission IDs key registry storage),
# so deploy shells out to the one shared implementation instead of carrying
# a second one in Python.
DEFAULT_ADMISSION_BIN = "seismic-measurement-admission"

# Summit's node binary. Its `genesis digest` subcommand computes
# summit.genesis_config_digest: SHA-256 over summit's domain-prefixed SSZ
# serialization of the complete genesis — summit's own definition of chain
# identity (its P2P and signing domains derive from it). Its `genesis
# set-validators` subcommand emits the completed genesis the digest is
# computed over. Both are shell-outs to the one implementation instead of
# mirroring the SSZ layout / canonical rendering in Python.
DEFAULT_SUMMIT_BIN = "summit"

# The quote verifier from the enclave repo (bin/verify-quote): exit 0 plus
# one JSON report on stdout ⇔ verified. Its `harvest` subcommand checks one
# founding harvest record — `network harvest` runs it on the record it is
# about to archive, and `assemble` re-runs it over each archived record
# before the harvested set is pinned. Its `deploy` subcommand deploy-verifies a
# freshly provisioned node — `node verify`, and `node configure` once the
# node is up, run it. Verification-only; runs natively on any dev platform
# (verification is pure computation over the evidence bytes — no TEE
# hardware involved).
DEFAULT_VERIFY_QUOTE_BIN = "verify-quote"


def _admission_cli(admission_bin: str, *args: str, input_bytes: bytes) -> bytes:
    """Run the shared policy-compiler CLI, feeding the document on stdin.

    Byte streams both ways: promoted policy bytes are hash-committed, so
    nothing may re-render them between the CLI and the artifact set.
    """
    cmd = [admission_bin, *args, "-"]
    try:
        result = subprocess.run(
            cmd, input=input_bytes, capture_output=True, timeout=120, check=True
        )
    except FileNotFoundError:
        raise GateError(
            f"{admission_bin!r} not found; build the policy-compiler CLI from "
            "the enclave repo (cargo build -p seismic-measurement-admission "
            "--features cli) or pass --admission-bin"
        ) from None
    except subprocess.TimeoutExpired:
        raise GateError(f"`{' '.join(cmd)}` timed out") from None
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or e.stdout or b"").decode("utf-8", "replace").strip()
        raise GateError(f"`{' '.join(cmd)}` failed: {detail}") from None
    return result.stdout


def promote_measurements(
    raw_bytes: bytes,
    attestation_type: str = DEFAULT_ATTESTATION_TYPE,
    admission_bin: str = DEFAULT_ADMISSION_BIN,
) -> bytes:
    """Promote `make measure` output into measurement-policy-bootstrap.json
    bytes.

    Shells out to the admission CLI's `promote`, which selects exactly the
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
    return _admission_cli(admission_bin, *args, input_bytes=raw_bytes)


def compile_measurement_policy(
    policy_bytes: bytes, admission_bin: str = DEFAULT_ADMISSION_BIN
) -> dict[str, Any]:
    """Compile a policy document via the admission CLI; returns its report:
    policy hash, admission IDs, the canonical registry runtime-code hash, and
    the complete registry genesis storage map."""
    report = _admission_cli(admission_bin, "compile", input_bytes=policy_bytes)
    return json.loads(report)


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


def verify_quote_bin_not_found(verify_quote_bin: str) -> GateError:
    return GateError(
        f"{verify_quote_bin!r} not found; build the enclave repo's "
        "bin/verify-quote and put it on PATH, or pass --verify-quote-bin"
    )


def _run_verify_quote(
    cmd: list[str], *, input_bytes: bytes | None = None
) -> dict[str, Any]:
    """Run one verify-quote invocation and enforce its contract: exit 0 plus
    one JSON `{"verified": true, ...}` report on stdout ⇔ verified; anything
    else is a GateError.
    """
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
    except FileNotFoundError:
        raise verify_quote_bin_not_found(cmd[0]) from None
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
            f"`{cmd[0]}` exited 0 without a verified report: {result.stdout!r}"
        )
    return report


def verify_harvest_record(
    record: dict[str, Any],
    *,
    policy_path: Path,
    verify_quote_bin: str = DEFAULT_VERIFY_QUOTE_BIN,
    pccs_url: str | None = None,
    override_azure_outdated_tcb: bool = False,
) -> dict[str, Any]:
    """DCAP-verify one founding harvest record via `verify-quote harvest`.

    The verifier owns the whole check: the record's evidence must verify
    cryptographically, its report_data must bind the record's own nonce and
    pubkeys, and its measurements must satisfy the policy. The record goes
    over stdin as one document — the same one the archive keeps, so what is
    archived is what was verified.
    """
    cmd = [
        verify_quote_bin,
        "harvest",
        "--record",
        "-",
        "--policy",
        str(policy_path),
    ]
    if pccs_url:
        cmd += ["--pccs-url", pccs_url]
    if override_azure_outdated_tcb:
        cmd.append("--override-azure-outdated-tcb")
    return _run_verify_quote(cmd, input_bytes=json.dumps(record).encode("utf-8"))


def verify_node_deployment(
    endpoint: str,
    *,
    manifest_path: Path,
    policy_bytes: bytes,
    verify_quote_bin: str = DEFAULT_VERIFY_QUOTE_BIN,
    pccs_url: str | None = None,
    override_azure_outdated_tcb: bool = False,
) -> dict[str, Any]:
    """Deploy-verify one freshly provisioned node via `verify-quote deploy`.

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
        cmd = [
            verify_quote_bin,
            "deploy",
            "--endpoint",
            endpoint,
            "--manifest",
            str(manifest_path),
            "--policy",
            policy_file.name,
        ]
        if pccs_url:
            cmd += ["--pccs-url", pccs_url]
        if override_azure_outdated_tcb:
            cmd.append("--override-azure-outdated-tcb")
        return _run_verify_quote(cmd)


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
