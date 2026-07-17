#!/usr/bin/env python3
"""Watch a node's first-boot LUKS-provisioning progress.

The attestation service serves `getLuksProvisioningStatus` on :7878 (JSON-RPC)
for the duration of the first-boot disk wipe — the one long (1h+), otherwise
opaque phase. This module polls it and renders a progress bar, and is the
shared poller behind both `seismic-tee-node status` and `configure`'s default
post-POST wait.

States (see `LuksProvisioningStatus` in the enclave repo's `crates/enclave`):
  provisioning {bytes_done, bytes_total, eta_seconds?} | idle | error {error} | unknown

Watch-completion is deliberately conservative about `idle`: right after a
POST the server may be down (connection refused) or up-but-idle *before* the
wipe starts, which looks identical to idle-because-finished. So we treat
idle as "done" only after we've seen provisioning; otherwise we wait a short
grace for the wipe to begin and, if it never does, conclude there's no wipe
(already finished, or a fast-unlock restart). This watches only the wipe —
it is NOT a node-readiness gate (summit/reth/genesis come later).
"""

import argparse
import json
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import requests

from tee.cli.common.descriptor import load_descriptor, require
from tee.cli.common.logging_setup import setup_logging

ENCLAVE_PORT = 7878
POLL_INTERVAL_SECONDS = 5
# Max wait for :7878 to first respond — covers attestation-service startup
# (and, on a joiner, the root_key fetch that precedes the listener coming up).
CONNECT_TIMEOUT_SECONDS = 180
# Once reachable and idle, how long to wait for the wipe to begin before
# concluding none is in progress. The service-up→first-wipe-tick gap
# (udev settle, disk discovery, luksFormat warm-up) is seconds; a fast-unlock
# restart stays idle forever, so this bounds the wait instead of hanging.
IDLE_GRACE_SECONDS = 60
# How long a *continuous* error status must persist before we call it terminal.
# `setup-persistent-luks` runs under `Restart=on-failure` and retries transient
# failures (data disk not yet attached, vTPM not ready, keyfile not written
# yet), writing `error` to the status file on each failed attempt and flipping
# back to `provisioning` on the next. So a lone `error` reading is NOT terminal
# — only an error that sticks, with no recovering attempt within the grace, is.
# Any non-error reading resets the clock.
ERROR_GRACE_SECONDS = 120


def fetch_status(public_ip: str, *, timeout: int = 10) -> dict:
    """One getLuksProvisioningStatus call → the result dict (its `state` plus
    any state-specific fields). Raises requests.RequestException if the server
    isn't reachable (normal while the attestation service is coming up)."""
    url = f"http://{public_ip}:{ENCLAVE_PORT}"
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLuksProvisioningStatus",
        "params": [],
    }
    resp = requests.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        raise RuntimeError(f"RPC error from {url}: {data['error']}")
    return data["result"]


def _gib(n: int) -> str:
    return f"{n / 2**30:.1f}"


def _duration(seconds: int) -> str:
    seconds = int(seconds)
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def _bar(pct: float, width: int = 30) -> str:
    filled = max(0, min(width, int(pct / 100 * width)))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def format_provisioning(status: dict) -> str:
    """Render a `provisioning` status as a one-line progress string. A
    bytes_total of 0 is the 'just started, no measurement yet' marker."""
    done = status.get("bytes_done", 0)
    total = status.get("bytes_total", 0)
    if not total:
        return "encrypting disk: starting (no measurement yet)"
    pct = 100.0 * done / total
    line = f"encrypting disk {_bar(pct)} {pct:5.1f}%  {_gib(done)}/{_gib(total)} GiB"
    eta = status.get("eta_seconds")
    if eta:
        line += f"  eta {_duration(eta)}"
    return line


@dataclass
class ProvisioningUpdate:
    """One observation from `poll_provisioning`. `line` is a compact,
    render-agnostic status string; `transient` hints single-line watchers
    whether it's an in-place progress update vs a permanent line. `done` marks
    the terminal observation — `ok` = the wipe finished (or none was needed),
    not-`ok` = it errored or the node never became reachable.
    """

    phase: str  # connecting | provisioning | waiting | done | error
    line: str
    transient: bool = True
    done: bool = False
    ok: bool = False


def poll_provisioning(
    public_ip: str,
    *,
    interval: int = POLL_INTERVAL_SECONDS,
    stop: threading.Event | None = None,
):
    """Poll getLuksProvisioningStatus, yielding a `ProvisioningUpdate` per
    observation until a terminal one (`done=True`), then stop. Renders nothing:
    this is the shared state machine behind both the single-node
    `watch_luks_provisioning` and the parallel cohort dashboard. See the module
    docstring for the states and the conservative `idle` handling.

    `stop` (optional) makes the poll cancellable: setting it ends the generator
    within one interval, without a terminal update. The cohort dashboard uses
    this so ctrl-C doesn't block on 1h+ wipe watches.
    """

    def wait_interval() -> bool:
        """Sleep one poll interval; True means stop was requested."""
        if stop is None:
            time.sleep(interval)
            return False
        return stop.wait(interval)

    start = time.monotonic()
    first_reachable: float | None = None
    seen_provisioning = False
    error_since: float | None = None  # when the current run of `error` began

    while True:
        try:
            status = fetch_status(public_ip)
        except requests.RequestException:
            if time.monotonic() - start > CONNECT_TIMEOUT_SECONDS:
                yield ProvisioningUpdate(
                    "error",
                    f"attestation service :{ENCLAVE_PORT} never became reachable "
                    f"after {CONNECT_TIMEOUT_SECONDS}s — is the node up?",
                    transient=False,
                    done=True,
                    ok=False,
                )
                return
            yield ProvisioningUpdate(
                "connecting", f"waiting for attestation service :{ENCLAVE_PORT} ..."
            )
            if wait_interval():
                return
            continue

        first_reachable = first_reachable or time.monotonic()
        state = status.get("state")
        if state != "error":
            error_since = None  # any non-error reading clears the error clock

        if state == "provisioning":
            seen_provisioning = True
            yield ProvisioningUpdate("provisioning", format_provisioning(status))
        elif state == "error":
            # `error` is written per failed attempt, but setup-persistent-luks
            # runs under Restart=on-failure and retries transient failures, so a
            # lone `error` is not terminal — systemd restarts it and the file
            # flips back to `provisioning`. Only error that persists past the
            # grace (no recovery in sight) is terminal.
            error_since = error_since or time.monotonic()
            err = status.get("error", "?")
            if time.monotonic() - error_since > ERROR_GRACE_SECONDS:
                yield ProvisioningUpdate(
                    "error",
                    f"LUKS provisioning stuck in error for >{ERROR_GRACE_SECONDS}s "
                    f"(not recovering): {err}",
                    transient=False,
                    done=True,
                    ok=False,
                )
                return
            yield ProvisioningUpdate(
                "error", f"LUKS attempt failed, auto-retrying: {err}"
            )
        elif state == "idle":
            if seen_provisioning:
                yield ProvisioningUpdate(
                    "done",
                    "disk provisioning complete.",
                    transient=False,
                    done=True,
                    ok=True,
                )
                return
            if time.monotonic() - first_reachable > IDLE_GRACE_SECONDS:
                yield ProvisioningUpdate(
                    "done",
                    "no first-boot wipe in progress (already finished, or a "
                    "fast-unlock restart).",
                    transient=False,
                    done=True,
                    ok=True,
                )
                return
            yield ProvisioningUpdate("waiting", "waiting for provisioning to start ...")
        elif state == "unknown":
            yield ProvisioningUpdate(
                "waiting",
                "status pipeline returned 'unknown' — still polling",
                transient=False,
            )
        else:
            yield ProvisioningUpdate(
                "waiting",
                f"unexpected status {state!r} — still polling",
                transient=False,
            )

        if wait_interval():
            return


def watch_luks_provisioning(
    public_ip: str, *, interval: int = POLL_INTERVAL_SECONDS
) -> int:
    """Poll getLuksProvisioningStatus and render progress until the wipe
    finishes, errors, or we conclude none is in progress. Returns a process
    exit code (0 = wipe done / no wipe; 1 = wipe error or never reachable).

    Renders an in-place bar on a TTY; plain lines otherwise (so CI logs stay
    readable). Raises KeyboardInterrupt up to the caller on ctrl-C.
    """
    isatty = sys.stdout.isatty()
    seen_provisioning = False
    on_bar_line = False  # a TTY bar (no trailing newline) is currently shown

    def emit(line: str, *, transient: bool) -> None:
        nonlocal on_bar_line
        if isatty and transient:
            print(f"\r\033[K{line}", end="", flush=True)
            on_bar_line = True
        else:
            if on_bar_line:
                print()  # close the in-place bar before a permanent line
                on_bar_line = False
            print(line, flush=True)

    for update in poll_provisioning(public_ip, interval=interval):
        if update.phase == "provisioning" and not seen_provisioning:
            seen_provisioning = True
            # One-time context: the bar alone doesn't say what's happening,
            # and this phase is long enough to look like a hang.
            emit(
                "First-boot: initializing the encrypted /persistent disk "
                "— a one-time full-disk wipe (LUKS + dm-integrity) that can "
                "take 1h+ on large disks. The node must finish this before "
                "it can boot further.",
                transient=False,
            )
        emit(update.line, transient=update.transient)
        if update.done:
            return 0 if update.ok else 1

    return 1  # generator only stops after a terminal update; defensive


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Watch a node's first-boot LUKS provisioning progress."
    )
    parser.add_argument(
        "--node",
        type=Path,
        required=True,
        metavar="DESCRIPTOR",
        help="Node descriptor JSON (provides public_ip); "
        "see tee/cli/common/descriptor.py.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Print the current status as JSON and exit (no polling).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=POLL_INTERVAL_SECONDS,
        metavar="SECONDS",
        help=f"Poll interval (default {POLL_INTERVAL_SECONDS}s).",
    )
    args = parser.parse_args()
    if not args.node.is_file():
        raise SystemExit(f"--node descriptor not found: {args.node}")
    return args


def main() -> None:
    setup_logging()
    args = parse_args()
    public_ip = require(load_descriptor(args.node), "public_ip", args.node)

    if args.once:
        try:
            print(json.dumps(fetch_status(public_ip)))
        except requests.RequestException as e:
            raise SystemExit(
                f"attestation service :{ENCLAVE_PORT} not reachable: {e}"
            ) from None
        return

    try:
        raise SystemExit(watch_luks_provisioning(public_ip, interval=args.interval))
    except KeyboardInterrupt:
        print("\nStopped watching.")
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
