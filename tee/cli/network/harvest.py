"""Founding harvest: collect and DCAP-verify each cohort box's summit keys.

A founding cohort boots identity-free: each box's `summit-key-holder`
generates its summit keypairs in RAM at boot and serves
`GET /v1/quote?nonce=…` → `{pubkeys, evidence}` on :7879 until the box
accepts its config POST. Harvest is the step between `up --network` and
`assemble`: it polls every box's holder, fetches its pubkeys plus
a TDX quote over a fresh per-box nonce (`report_data` binds the nonce and
both pubkeys, so a quote replayed from an earlier harvest can't satisfy
it), DCAP-verifies each quote against the network's intended image
measurements, and archives the verified facts under `inputs/harvest/` —
the provenance `assemble` pins the founding validator set from. Design
doc:
https://github.com/SeismicSystems/seismic/blob/main/docs/tee/network-founding.md

Verification here is load-bearing, not hygiene: consensus membership is
gated by whose pubkeys enter the genesis validator set, and founding keys
bypass the deposit contract's admission path — so the harvest is the one
moment TEE residency can be checked before the set is pinned. The check
shells out to the enclave repo's `verify-quote` (exit 0 plus one JSON
report on stdout ⇔ verified), against the policy promoted from
`inputs/measurements.json` by the same admission CLI `assemble` uses.
This check is purely preventive: future users and joiners should re-run
the same verification against the archived evidence (each record keeps
the quote plus the nonce it binds) and the published collateral, rather
than trust this run's verdict.

TODO: snapshot the DCAP collateral into inputs/harvest/dcap-collateral/
once the capture mechanism is resolved (open question from the
verify-quote PR) — until then re-verification depends on Intel's live
collateral, which ages out from under the archived quotes.

Any anomaly burns the whole harvest: a quote window already closed
(HTTP 410 — the box accepted a config POST), a failed verification, or a
cohort whose size doesn't match the authored
`inputs/founder-withdrawal-credentials.json` all abort
the run. A harvested key is trustworthy only if the same box later accepts
the real configure cleanly — never retry around a burned harvest; re-found
instead (`down` + fresh `up`).
"""

import argparse
import json
import re
import secrets
import shutil
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

from tee.cli.common import manifest as manifest_mod
from tee.cli.common.descriptor import load_descriptor, require
from tee.cli.network import bootnodes as bootnodes_mod

# summit-key-holder's HTTP port (plain HTTP: nginx and certbot exist only
# post-configure). The node NSG restricts it to `operator_ip_cidr`, so the
# harvest runs from the operator machine that provisioned the cohort.
HOLDER_PORT = 7879

# Holder-readiness polling. The holder starts at network-online — well
# before the config POST — so an unreachable box is normally just still
# booting; same cadence as the other cohort gathers (bootnodes, genesis).
POLL_INTERVAL_SECONDS = 5
HARVEST_TIMEOUT_SECONDS = 15 * 60
WAIT_LOG_INTERVAL_SECONDS = 30

# The DCAP verifier from the enclave repo (bin/verify-quote), expected on
# PATH like the admission CLI. Shared constant with `assemble`,
# which re-verifies the archived quotes before pinning the founding set.
DEFAULT_VERIFY_QUOTE_BIN = manifest_mod.DEFAULT_VERIFY_QUOTE_BIN

# Holder pubkeys are summit's keystore wire format: lowercase bare hex,
# exactly as `commonware_utils::hex` renders — the spelling summit's
# genesis config_digest commits to, so any other form is rejected here
# rather than laundered into the archive.
_NODE_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_CONSENSUS_KEY_RE = re.compile(r"^[0-9a-f]{96}$")


class QuoteWindowClosed(Exception):
    """The holder answered HTTP 410: the box already took a config POST."""


@dataclass(frozen=True)
class HarvestTarget:
    """One cohort box: descriptor stem (its name in inputs/harvest/), its
    IP, and the fresh 32-byte nonce (hex) minted for this run's quote
    request."""

    name: str
    public_ip: str
    nonce: str


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "dir",
        type=Path,
        help=(
            "Network directory (from `init`): reads the cohort "
            f"descriptors in {manifest_mod.NODES_DIRNAME}/, the authored "
            f"{manifest_mod.INPUTS_DIRNAME}/{manifest_mod.FOUNDERS_FILENAME} "
            f"and {manifest_mod.INPUTS_DIRNAME}/"
            f"{manifest_mod.MEASUREMENTS_FILENAME}, and writes the harvested "
            f"facts to {manifest_mod.INPUTS_DIRNAME}/"
            f"{manifest_mod.HARVEST_DIRNAME}/"
        ),
    )
    parser.add_argument(
        "--node",
        type=Path,
        nargs="+",
        action="append",
        default=None,
        metavar="DESCRIPTOR",
        help=(
            "Node descriptor JSON file(s), one per cohort box — `--node "
            "n1.json n2.json` and `--node n1.json --node n2.json` both work. "
            "Default: every *.json in <dir>/nodes/ (written by `up "
            "--network`) except bootnodes.json, sorted by name."
        ),
    )
    parser.add_argument(
        "--verify-quote-bin",
        default=DEFAULT_VERIFY_QUOTE_BIN,
        help="DCAP verifier CLI from the enclave repo (bin/verify-quote)",
    )
    parser.add_argument(
        "--admission-bin",
        default=manifest_mod.DEFAULT_ADMISSION_BIN,
        help="policy-compiler CLI used to promote the measurements into the "
        "policy each quote is verified against",
    )
    parser.add_argument(
        "--attestation-type", default=manifest_mod.DEFAULT_ATTESTATION_TYPE
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
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing harvest file(s) — a fresh harvest with new "
        "nonces, replacing the archived provenance",
    )
    args = parser.parse_args(argv)

    if not args.dir.is_dir():
        raise SystemExit(f"network directory not found: {args.dir}")
    # Absolute from here on, so every path this CLI prints is clickable.
    args.dir = args.dir.resolve()
    inputs_dir = args.dir / manifest_mod.INPUTS_DIRNAME
    args.measurements = inputs_dir / manifest_mod.MEASUREMENTS_FILENAME
    args.founders = inputs_dir / manifest_mod.FOUNDERS_FILENAME
    if not args.measurements.is_file():
        raise SystemExit(
            f"{args.measurements} not found — authored inputs live under "
            f"{manifest_mod.INPUTS_DIRNAME}/; scaffold them with `init`"
        )
    if not args.founders.is_file():
        raise SystemExit(
            f"{args.founders} not found — author it as a JSON array of the "
            "founders' withdrawal credentials (0x-prefixed addresses), one "
            "per founding node"
        )
    if args.node is None:
        nodes_dir = args.dir / manifest_mod.NODES_DIRNAME
        # `configure` writes bootnodes.json into this same dir; it's runtime
        # p2p state, not a node descriptor, so skip it or load_descriptor
        # would abort on the missing fqdn/public_ip.
        args.node = sorted(
            p
            for p in nodes_dir.glob("*.json")
            if p.name != bootnodes_mod.BOOTNODES_FILENAME
        )
        if not args.node:
            raise SystemExit(
                f"no --node given and no descriptors in {nodes_dir} (written "
                "by `up --network`); pass --node explicitly"
            )
    else:
        # append+nargs yields one list per --node occurrence; flatten to the
        # cohort list callers expect.
        args.node = [path for group in args.node for path in group]
        # Descriptor filename stems are the harvest's node names (the
        # inputs/harvest/ filenames, and the order the authored withdrawal
        # credentials pair against), so compare stems, not paths: two
        # spellings of one file or two files sharing a stem would otherwise
        # silently collapse into one harvested box.
        stems = [p.stem for p in args.node]
        dupes = sorted({s for s in stems if stems.count(s) > 1})
        if dupes:
            raise SystemExit(
                f"duplicate --node descriptor name(s): {', '.join(dupes)} — "
                "each cohort box needs a unique descriptor filename stem"
            )
        for path in args.node:
            if not path.is_file():
                raise SystemExit(f"--node descriptor not found: {path}")
    return args


def load_founders(path: Path, cohort: list[str]) -> list[str]:
    """Load inputs/founder-withdrawal-credentials.json and count it against
    the live cohort.

    `assemble` pairs the i-th authored address with the i-th box in
    node-name order, so a count that doesn't match the cohort would leave a
    box unpinnable or pin a set other than the one the founders authored
    for. Checked here too, before any quote is fetched, so the fix costs
    nothing.
    """
    try:
        data = manifest_mod.load_founder_credentials(path)
    except manifest_mod.GateError as e:
        raise SystemExit(str(e)) from None
    if len(data) != len(cohort):
        raise SystemExit(
            f"{path} carries {len(data)} withdrawal credential(s) but the "
            f"cohort has {len(cohort)} box(es) ({', '.join(sorted(cohort))}) "
            "— author one address per founding node"
        )
    return data


def fetch_quote(public_ip: str, nonce: str, *, timeout: int = 30) -> dict[str, Any]:
    """Fetch one box's `{pubkeys, evidence}` from its summit-key-holder.

    Raises QuoteWindowClosed on HTTP 410 (the box already accepted a config
    POST), a requests error on transport/HTTP failure (callers retry a
    still-booting box), and ValueError on a malformed response body —
    retrying can't fix a holder serving the wrong shape.
    """
    url = f"http://{public_ip}:{HOLDER_PORT}/v1/quote"
    response = requests.get(url, params={"nonce": nonce}, timeout=timeout)
    if response.status_code == 410:
        raise QuoteWindowClosed(url)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError(f"{url}: expected a JSON object, got {type(data).__name__}")
    node_key = data.get("node_public_key")
    if not isinstance(node_key, str) or not _NODE_KEY_RE.match(node_key):
        raise ValueError(
            f"{url}: node_public_key is not 64 lowercase hex chars: {node_key!r}"
        )
    consensus_key = data.get("consensus_public_key")
    if not isinstance(consensus_key, str) or not _CONSENSUS_KEY_RE.match(consensus_key):
        raise ValueError(
            f"{url}: consensus_public_key is not 96 lowercase hex chars: "
            f"{consensus_key!r}"
        )
    if not isinstance(data.get("evidence"), dict):
        raise ValueError(f"{url}: response carries no evidence object")
    return data


def collect_quotes(
    targets: list[HarvestTarget],
    *,
    timeout: float = HARVEST_TIMEOUT_SECONDS,
    interval: float = POLL_INTERVAL_SECONDS,
) -> dict[str, dict[str, Any]]:
    """Poll every target's holder until each serves its quote, or `timeout`.

    Round-robin like the other cohort gathers, so a slow box doesn't
    serialize behind the others. Transport errors and 5xx are the normal
    boot tail — retried until the deadline, then aborted with a per-box
    report. A closed quote window (410) or any other 4xx burns the harvest
    immediately: waiting can't fix a box that already took its config POST,
    or a holder that rejects well-formed requests.
    """
    quotes: dict[str, dict[str, Any]] = {}
    last_error: dict[str, str] = {}
    started = time.monotonic()
    deadline = started + timeout
    next_log = 0.0
    while True:
        for target in targets:
            if target.name in quotes:
                continue
            try:
                quotes[target.name] = fetch_quote(target.public_ip, target.nonce)
            except QuoteWindowClosed:
                raise SystemExit(
                    f"{target.name}: quote window closed (HTTP 410) — the box "
                    "already accepted a config POST, so its founding keys are "
                    "not harvestable. The harvest is burned: re-found (`down` "
                    "+ fresh `up`) rather than retrying around it."
                ) from None
            except ValueError as e:
                raise SystemExit(f"{target.name}: {e}") from None
            except requests.HTTPError as e:
                status = e.response.status_code if e.response is not None else None
                if status is not None and 400 <= status < 500:
                    raise SystemExit(
                        f"{target.name}: holder rejected the quote request "
                        f"({e}) — not a boot-tail condition; check that the "
                        "image and this CLI agree on the holder API."
                    ) from None
                last_error[target.name] = str(e)
            except requests.RequestException as e:
                last_error[target.name] = str(e)
            else:
                print(f"  ✓ {target.name}: pubkeys + quote harvested")
        pending = [t.name for t in targets if t.name not in quotes]
        if not pending:
            return quotes
        now = time.monotonic()
        if now >= deadline:
            listing = "\n".join(f"  ✗ {name}: {last_error[name]}" for name in pending)
            raise SystemExit(
                f"{len(pending)} box(es) never served a founding quote after "
                f"{int(timeout)}s (holder not up?):\n{listing}"
            )
        if now >= next_log:
            elapsed = int(now - started)
            remaining = max(0, int(deadline - now))
            print(
                f"waiting for founding quotes ({elapsed}s elapsed, "
                f"{remaining}s until timeout): " + ", ".join(pending)
            )
            next_log = now + WAIT_LOG_INTERVAL_SECONDS
        time.sleep(interval)


def assert_unique_keys(quotes: dict[str, dict[str, Any]]) -> None:
    """Abort if two boxes served the same pubkey.

    Summit's genesis keys validator accounts by node pubkey, so a repeated
    key silently collapses the set — and two boxes holding the same
    consensus key is accidental-equivocation material. Either way the
    cohort is not the N distinct founders being pinned: burn.
    """
    for field in ("node_public_key", "consensus_public_key"):
        seen: dict[str, str] = {}
        for name in sorted(quotes):
            key = quotes[name][field]
            if key in seen:
                raise SystemExit(
                    f"{seen[key]} and {name} served the same {field} ({key}); "
                    "the cohort is not the distinct founder set being pinned. "
                    "The harvest is burned: re-found."
                )
            seen[key] = name


def verify_quote(
    target: HarvestTarget,
    quote: dict[str, Any],
    policy_path: Path,
    verify_bin: str,
    *,
    pccs_url: str | None,
    override_azure_outdated_tcb: bool,
) -> dict[str, Any]:
    """DCAP-verify one harvested quote via the enclave repo's `verify-quote`
    (the shared shell-out in manifest.py — `assemble` re-runs the same check
    over the archived evidence before pinning the set). A failure burns the
    harvest: a founding key whose quote doesn't verify must never reach
    `assemble`.
    """
    try:
        return manifest_mod.verify_quote_evidence(
            quote["evidence"],
            nonce=target.nonce,
            node_pubkey=quote["node_public_key"],
            consensus_pubkey=quote["consensus_public_key"],
            policy_path=policy_path,
            verify_quote_bin=verify_bin,
            pccs_url=pccs_url,
            override_azure_outdated_tcb=override_azure_outdated_tcb,
        )
    except manifest_mod.GateError as e:
        raise SystemExit(
            f"{target.name}: {e}\nThe harvest is burned: re-found rather "
            "than retrying around it."
        ) from None


def check_overwrite(harvest_dir: Path, names: list[str], force: bool) -> None:
    """Refuse to clobber an existing harvest unless --force.

    The archive is founding provenance — the nonces it holds are what make
    the archived quotes re-verifiable — so replacing it is a deliberate
    re-harvest, not a default.
    """
    existing = sorted(name for name in names if (harvest_dir / f"{name}.json").exists())
    if existing and not force:
        raise SystemExit(
            f"refusing to overwrite existing harvest file(s) in {harvest_dir}: "
            f"{', '.join(existing)} — pass --force for a fresh harvest (new "
            "nonces; the archived provenance is replaced)"
        )


def save_harvest(harvest_dir: Path, records: dict[str, dict[str, Any]]) -> list[Path]:
    """Write one inputs/harvest/<node>.json per box (pretty JSON, trailing
    newline — the descriptor writer's format). Each record carries the
    evidence exactly as the holder served it plus the nonce it binds, so
    the archived quote stays re-verifiable, and the verification report
    (every quoted PCR) as measurement provenance."""
    harvest_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name in sorted(records):
        path = harvest_dir / f"{name}.json"
        path.write_text(json.dumps(records[name], indent=2) + "\n")
        written.append(path)
    return written


def main() -> None:
    args = _parse_args()

    # Fail on a missing verifier before touching the cohort.
    verify_bin = shutil.which(args.verify_quote_bin)
    if verify_bin is None:
        raise SystemExit(
            f"`{args.verify_quote_bin}` not found on PATH. Build the enclave "
            "repo's bin/verify-quote and put it on PATH."
        )

    targets = []
    for path in args.node:
        descriptor = load_descriptor(path)
        targets.append(
            HarvestTarget(
                name=path.stem,
                public_ip=require(descriptor, "public_ip", path),
                nonce=secrets.token_bytes(32).hex(),
            )
        )

    load_founders(args.founders, [t.name for t in targets])

    harvest_dir = args.dir / manifest_mod.INPUTS_DIRNAME / manifest_mod.HARVEST_DIRNAME
    check_overwrite(harvest_dir, [t.name for t in targets], args.force)

    try:
        policy_bytes = manifest_mod.promote_measurements(
            args.measurements.read_bytes(),
            args.attestation_type,
            admission_bin=args.admission_bin,
        )
    except manifest_mod.GateError as e:
        raise SystemExit(f"{args.measurements}: {e}") from None

    print(f"Harvesting founding keys from {len(targets)} box(es)...")
    quotes = collect_quotes(targets)
    assert_unique_keys(quotes)

    harvested_at = datetime.now(UTC).isoformat(timespec="seconds")
    records: dict[str, dict[str, Any]] = {}
    with tempfile.NamedTemporaryFile(
        prefix="measurement-policy-", suffix=".json"
    ) as policy_file:
        policy_file.write(policy_bytes)
        policy_file.flush()
        for target in targets:
            quote = quotes[target.name]
            report = verify_quote(
                target,
                quote,
                Path(policy_file.name),
                verify_bin,
                pccs_url=args.pccs_url,
                override_azure_outdated_tcb=args.override_azure_outdated_tcb,
            )
            print(f"  ✓ {target.name}: quote DCAP-verified against the policy")
            records[target.name] = {
                "harvest_nonce": target.nonce,
                "node_public_key": quote["node_public_key"],
                "consensus_public_key": quote["consensus_public_key"],
                "evidence": quote["evidence"],
                "harvested_at": harvested_at,
                "verification": report,
            }

    for path in save_harvest(harvest_dir, records):
        print(f"wrote {path}")
    print(
        f"Harvest complete: {len(records)} founding box(es) verified and "
        f"archived under {harvest_dir}"
    )


if __name__ == "__main__":
    main()
