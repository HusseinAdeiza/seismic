#!/usr/bin/env python3
"""Deploy-verify a node's TDX attestation before relying on it:

    seismic-tee-node verify --node n2.json --manifest m.json

The enclave repo's `verify-quote deploy` owns the whole relying-party flow:
it challenges the node's attestation service with a fresh nonce
(`getDeployVerificationEvidence` on :7878), recomputes the deploy
verification binding from the operator's own `--manifest` copy and that
nonce, and DCAP-verifies the returned quote against the measurement policy.
A pass proves a measured node holding this manifest answered this exact
request.

The check protects the operator's own decisions — publishing the node's
address, handing it to later nodes as a bootnode, pointing tooling at it.
Membership in the network is granted by the network's own gates (the attested
root-key handshake and its admission policy), never by this check.

Appraisal, not delivery: the node serves the evidence RPC for as long as it
runs and every run mints a fresh nonce, so this is re-runnable at any time —
after a reboot, after an image upgrade, on suspicion, or as a retry when DCAP
collateral was briefly unreachable. `configure` runs the same step inline once
the node it just configured reaches a ready state; delivery itself is once per
boot (tdx-init accepts one config POST), which is why the check has its own
command.

The policy the quote is appraised against is a network artifact: the
`measurement-policy-bootstrap.json` `assemble` wrote beside the manifest, the
document the manifest's `measurements.bootstrap_policy_hash` commits to and
the registry's genesis-seeded admission IDs were compiled from. So the node is
checked against the measurements *this* network founded on, not against
whatever measurements happen to be on the operator's disk.

`--measurements` is the override for an operator who will not take the
founder's artifact at face value: they supply the image's expected
measurements (published by seismic-images CI) and this promotes them into a
policy of their own. Either way nothing here computes a security-critical
measurement itself.
"""

import argparse
import json
import logging
import shutil
import subprocess
from pathlib import Path

from tee.cli.common import manifest as manifest_mod
from tee.cli.common import shell_outs
from tee.cli.common.descriptor import load_descriptor, require
from tee.cli.common.logging_setup import setup_logging
from tee.cli.node.status import ENCLAVE_PORT

logger = logging.getLogger(__name__)


def add_policy_source_args(parser: argparse.ArgumentParser) -> None:
    """Add the flags that choose which measurement policy a node is appraised
    against. Shared with `configure`, so an operator who tunes one command
    tunes both the same way.

    The two sources are exclusive: `--policy` (or its default, the network's
    own artifact) consumes a published policy document, `--measurements`
    promotes a raw measurements file into one. Only the latter needs the
    admission CLI, so `--admission-bin`/`--attestation-type` steer it alone.
    """
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--policy",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "Measurement policy JSON the node's quote is verified against. "
            "Must be the document the manifest's "
            "measurements.bootstrap_policy_hash commits to, which is checked "
            f"before use. Default: {manifest_mod.POLICY_FILENAME} beside "
            "--manifest (the artifact-set layout `assemble` produces)."
        ),
    )
    source.add_argument(
        "--measurements",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "Expected image measurements JSON (published by seismic-images CI "
            "for the node's image), promoted into a policy instead of using "
            "the network's published one. For an operator appraising the node "
            "against measurements they trust themselves."
        ),
    )
    parser.add_argument(
        "--admission-bin",
        default=shell_outs.DEFAULT_ADMISSION_BIN,
        help="policy-compiler CLI used to promote --measurements into a policy",
    )
    parser.add_argument(
        "--attestation-type",
        default=shell_outs.DEFAULT_ATTESTATION_TYPE,
        help="platform the policy promoted from --measurements pins",
    )


def check_policy_source_files(args: argparse.Namespace) -> None:
    """Reject an unreadable `--measurements` at parse time, like every other
    file flag. `--policy` is checked by `resolve_policy_path`, which also owns
    the default-location hint."""
    if args.measurements is not None and not args.measurements.is_file():
        raise SystemExit(f"--measurements file not found: {args.measurements}")


def add_tooling_args(parser: argparse.ArgumentParser) -> None:
    """Add the flags that steer the verifier itself. Shared with `configure`,
    so an operator who tunes one command tunes both the same way.
    """
    parser.add_argument(
        "--verify-quote-bin",
        default=shell_outs.DEFAULT_VERIFY_QUOTE_BIN,
        help="quote-verifier CLI from the enclave repo (bin/verify-quote)",
    )
    parser.add_argument(
        "--pccs-url",
        default=None,
        metavar="URL",
        help="forwarded to verify-quote: PCCS URL for DCAP collateral",
    )
    parser.add_argument(
        "--override-azure-outdated-tcb",
        action="store_true",
        help="forwarded to verify-quote: allow the Azure outdated-TCB override path",
    )


def resolve_policy_path(
    policy: Path | None, manifest_path: Path, *, offer_no_verify: bool = False
) -> Path:
    """Resolve `--policy`, defaulting to the artifact-set convention:
    `measurement-policy-bootstrap.json` beside the manifest, exactly where
    `assemble` writes it — so the policy appraising the node is the one the
    manifest's `measurements.bootstrap_policy_hash` was computed from.

    `offer_no_verify` names the caller's opt-out in the hint, for a command
    that verifies unless told not to.
    """
    path = policy or manifest_path.parent / manifest_mod.POLICY_FILENAME
    if path.is_file():
        return path
    if policy:
        raise SystemExit(f"--policy file not found: {path}")
    escapes = [
        "  --policy FILE        the network's policy document, if it lives elsewhere",
        "  --measurements FILE  promote your own measurements into a policy",
    ]
    if offer_no_verify:
        escapes.append("  --no-verify          configure without appraising the node")
    raise SystemExit(
        f"measurement policy not found: {path}\n"
        f"The default is {manifest_mod.POLICY_FILENAME} beside --manifest "
        "(the artifact set `assemble` writes). Instead:\n" + "\n".join(escapes)
    )


def resolve_policy(args: argparse.Namespace, *, offer_no_verify: bool = False) -> bytes:
    """Resolve the measurement policy the node will be appraised against.

    Default: the network's own artifact, checked against the manifest's
    `bootstrap_policy_hash` before use. A mismatch is fatal — appraising a node
    against a policy this network never committed to proves nothing about
    joining it.

    With `--measurements`, promote the operator's file instead. No hash check
    there: the whole point of that path is a policy the operator derived
    themselves, which need not be the founder's.
    """
    if args.measurements is not None:
        try:
            return shell_outs.promote_measurements(
                args.measurements.read_bytes(),
                args.attestation_type,
                admission_bin=args.admission_bin,
            )
        except manifest_mod.GateError as e:
            raise SystemExit(f"--measurements {args.measurements}: {e}") from None

    policy_path = resolve_policy_path(
        args.policy, args.manifest, offer_no_verify=offer_no_verify
    )
    policy_bytes = policy_path.read_bytes()
    try:
        manifest = manifest_mod.validate_manifest_schema(args.manifest.read_bytes())
    except manifest_mod.ManifestSchemaError as e:
        raise SystemExit(f"--manifest {args.manifest}: invalid manifest: {e}") from None
    try:
        manifest_mod.validate_policy_matches(manifest, policy_bytes)
    except manifest_mod.GateError as e:
        raise SystemExit(
            f"{policy_path} is not the policy --manifest commits to: {e}\n"
            "Both files come from the same `assemble` run — take them from one "
            "artifact set, or pass --measurements to appraise the node against "
            "measurements of your own."
        ) from None
    logger.info(f"Appraising against {policy_path} (pinned by {args.manifest})")
    return policy_bytes


def prepare_policy(args: argparse.Namespace, *, offer_no_verify: bool = False) -> bytes:
    """Resolve the verification tooling and the measurement policy, before the
    node is touched.

    Returns the policy bytes. A missing or too-old verifier binary, a policy
    the manifest doesn't commit to, or a measurements file the admission CLI
    rejects fails here — where the fix costs nothing, not after a config POST
    already landed.
    """
    if shutil.which(args.verify_quote_bin) is None:
        raise SystemExit(
            f"`{args.verify_quote_bin}` not found on PATH. Build the enclave "
            "repo's bin/verify-quote and put it on PATH, or pass "
            "--verify-quote-bin."
        )
    # On PATH isn't enough: a verifier predating the deploy-verification
    # subcommand would only fail after the challenge is due, which is exactly
    # what resolving the tooling up front exists to prevent.
    probe = subprocess.run(
        [args.verify_quote_bin, "deploy", "--help"], capture_output=True, timeout=60
    )
    if probe.returncode != 0:
        raise SystemExit(
            f"`{args.verify_quote_bin}` has no `deploy` subcommand. Rebuild "
            "bin/verify-quote from the current enclave repo."
        )
    return resolve_policy(args, offer_no_verify=offer_no_verify)


def verify_deployment(
    args: argparse.Namespace, policy_bytes: bytes, *, fqdn: str, public_ip: str
) -> None:
    """Challenge one node and print the verification report.

    Failure is a SystemExit: an operator who asked for verification must not
    see a zero exit from a node that didn't pass it.
    """
    logger.info(f"Deploy-verifying {fqdn} ({public_ip})...")
    try:
        report = shell_outs.verify_node_deployment(
            f"http://{public_ip}:{ENCLAVE_PORT}",
            manifest_path=args.manifest,
            policy_bytes=policy_bytes,
            verify_quote_bin=args.verify_quote_bin,
            pccs_url=args.pccs_url,
            override_azure_outdated_tcb=args.override_azure_outdated_tcb,
        )
    except manifest_mod.GateError as e:
        raise SystemExit(
            f"{fqdn} ({public_ip}): deploy verification FAILED:\n{e}\n"
            "Do not rely on this node — publish its address, hand it to later "
            "nodes as a bootnode — until `seismic-tee-node verify` passes "
            "against it."
        ) from None
    print(f"✓ {fqdn} deploy-verified: {json.dumps(report)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="seismic-tee-node verify",
        description=(
            "Deploy-verify a node's TDX attestation: challenge its attestation "
            "service with a fresh nonce and check the returned quote against "
            "the network manifest and the measurement policy the manifest pins."
        ),
    )
    parser.add_argument(
        "--node",
        type=Path,
        required=True,
        metavar="DESCRIPTOR",
        help=(
            "Path to a node descriptor JSON (e.g. `pulumi stack output "
            "--json > node-2.json`). Provides the node's public_ip/fqdn."
        ),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        metavar="FILE",
        help=(
            "Network manifest JSON the node is expected to have booted with "
            "(the one delivered by `configure`). Its exact bytes are the "
            "network identity the quote's binding commits to, and it pins the "
            "measurement policy the quote is checked against."
        ),
    )
    add_policy_source_args(parser)
    add_tooling_args(parser)

    args = parser.parse_args()
    if not args.node.is_file():
        raise SystemExit(f"--node descriptor not found: {args.node}")
    if not args.manifest.is_file():
        raise SystemExit(f"--manifest file not found: {args.manifest}")
    check_policy_source_files(args)
    return args


def main() -> None:
    setup_logging()
    args = parse_args()

    policy_bytes = prepare_policy(args)
    descriptor = load_descriptor(args.node)
    verify_deployment(
        args,
        policy_bytes,
        fqdn=require(descriptor, "fqdn", args.node),
        public_ip=require(descriptor, "public_ip", args.node),
    )


if __name__ == "__main__":
    main()
