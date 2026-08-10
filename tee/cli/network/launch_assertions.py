"""Launch assertions: prove the cohort that launched is the cohort pinned.

Run by `seismic-tee-network configure` after every node accepts its config,
these are the founding design's must-build guard: admission alone cannot
catch a founder that rebooted inside the harvest → LUKS-open window,
because such a box regenerates fresh RAM keys, persists *those*, and
passes admission fine — launching a validator whose pinned pubkey nobody
holds (a silent dead consensus slot). Two checks, both against values the
network manifest pins, both hard failures:

1. **reth block 0** — every node's live reth must serve the manifest's
   `eth.genesis_hash` as block 0. summit uses that hash as its initial
   forkchoice head, and a hash reth doesn't know parks reth in SYNCING
   forever with no error on either side. This check doubles as the cohort
   barrier: reth answers only after the root_key → LUKS-open boot tail,
   so it is polled with the same dashboard + disk-provisioning pause the
   config watch uses. A *wrong* answer fails immediately — waiting can't
   fix a node booted from a stale image or different genesis.

2. **holder keys** — every box's summit-key-holder (`GET /v1/keys`) must
   serve exactly the pubkeys harvested from it, i.e. the keys the
   assembled genesis pins. A mismatch is retried until the deadline, not
   failed fast: the holder serves this boot's RAM keys until the LUKS
   volume is open and the keystore visible, so an early read can
   transiently show fresh unpinned keys on a healthy node. A mismatch
   that *persists* is the dead-slot case — the fix is a re-found
   (`down` + fresh `up`), never launching around it.

Each node is located by its cohort descriptor (public_ip/fqdn); the
expected keys come from the committed harvest records
(`inputs/harvest/<node>.json`), whose pairing with the pinned validator
set `manifest assemble` already enforced.
"""

import time
from dataclasses import dataclass

import requests

from tee.cli.common.dashboard import CohortDashboard
from tee.cli.node.status import fetch_status, format_provisioning

# summit-key-holder's HTTP port (plain HTTP, NSG-restricted to the
# operator CIDR) — the same endpoint the harvest quoted keys from.
HOLDER_PORT = 7879

# Cohort-readiness polling. `configure` watches the first-boot disk wipe;
# if the reth probe observes one still running, it displays that progress
# and pauses the residual readiness timeout.
POLL_INTERVAL_SECONDS = 5
READY_TIMEOUT_SECONDS = 15 * 60
WAIT_LOG_INTERVAL_SECONDS = 30


@dataclass(frozen=True)
class LaunchTarget:
    """One configured cohort box and the founding keys pinned for it."""

    name: str
    public_ip: str
    fqdn: str
    node_public_key: str
    consensus_public_key: str


def assert_cohort_genesis_hash(
    targets: list[LaunchTarget],
    expected: str,
    *,
    timeout: float = READY_TIMEOUT_SECONDS,
    interval: float = POLL_INTERVAL_SECONDS,
) -> None:
    """Assert every cohort node's reth serves `expected` as block 0.

    A node that doesn't answer is polled until `timeout` — reth comes up
    only after root_key → LUKS open, so early unreachability is the normal
    boot tail. Active disk provisioning is shown through the shared cohort
    dashboard and pauses this timeout. A *wrong* answer fails immediately:
    waiting can't fix a node booted from a stale image or different
    genesis, and which nodes match is exactly the diagnostic (one stale
    node vs. a manifest that matches nobody), so the failure lists the
    whole cohort.
    """
    # nginx proxies /rpc -> reth :8545
    urls = {t.name: f"https://{t.fqdn}/rpc" for t in targets}

    dashboard = CohortDashboard({t.name: t.name for t in targets})
    states = {t.name: "waiting for reth block 0" for t in targets}
    observed: dict[str, str] = {}  # block-0 hash, once a node has answered
    last_error: dict[str, str] = {}
    started = time.monotonic()
    deadline = started + timeout
    provisioning_active = False
    while True:
        iteration_started = time.monotonic()
        for target in targets:
            if target.name in observed:
                continue
            try:
                response = requests.post(
                    urls[target.name],
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_getBlockByNumber",
                        "params": ["0x0", False],
                    },
                    timeout=30,
                )
                response.raise_for_status()
                data = response.json()
                if data.get("result") is None:
                    raise RuntimeError(
                        f"eth_getBlockByNumber returned {data.get('error') or data}"
                    )
                observed[target.name] = data["result"]["hash"]
                if observed[target.name].lower() == expected.lower():
                    states[target.name] = "reth block 0 matches"
                else:
                    states[target.name] = f"wrong reth block 0: {observed[target.name]}"
            except Exception as e:
                last_error[target.name] = f"unreachable via {urls[target.name]}: {e}"

        pending = [t for t in targets if t.name not in observed]
        mismatch = any(h.lower() != expected.lower() for h in observed.values())
        if mismatch or not pending:
            dashboard.render(states)
            break

        reth_probe_finished = time.monotonic()
        if provisioning_active:
            deadline += reth_probe_finished - iteration_started

        provisioning: set[str] = set()
        details: dict[str, str] = {}
        for target in pending:
            try:
                status = fetch_status(target.public_ip, timeout=2)
            except (requests.RequestException, RuntimeError, KeyError, ValueError):
                details[target.name] = "waiting for reth block 0"
                continue

            state = status.get("state")
            if state == "provisioning":
                provisioning.add(target.name)
                states[target.name] = (
                    f"{format_provisioning(status)}  (readiness timeout paused)"
                )
            elif state == "error":
                details[target.name] = (
                    "disk provisioning error, auto-retrying: "
                    f"{status.get('error', '?')}"
                )
            elif state == "idle":
                details[target.name] = "disk idle; waiting for reth block 0"
            else:
                details[target.name] = (
                    f"disk status {state!r}; waiting for reth block 0"
                )

        now = time.monotonic()
        if provisioning:
            paused_since = (
                reth_probe_finished if provisioning_active else iteration_started
            )
            deadline += now - paused_since
        elapsed = int(now - started)
        elapsed -= elapsed % WAIT_LOG_INTERVAL_SECONDS
        remaining = max(0, int(deadline - now))
        remaining = (
            (remaining + WAIT_LOG_INTERVAL_SECONDS - 1)
            // WAIT_LOG_INTERVAL_SECONDS
            * WAIT_LOG_INTERVAL_SECONDS
        )
        for target in pending:
            if target.name not in provisioning:
                states[target.name] = (
                    f"{details[target.name]} "
                    f"({elapsed}s elapsed, {remaining}s until timeout)"
                )
        dashboard.render(states)

        if now >= deadline:
            break
        sleep_started = time.monotonic()
        time.sleep(interval)
        if provisioning:
            deadline += time.monotonic() - sleep_started
        provisioning_active = bool(provisioning)

    if mismatch or pending:
        listing = "\n".join(
            f"  {'✓' if h.lower() == expected.lower() else '✗'} {t.name}: {h}"
            for t, h in (
                (t, observed.get(t.name) or last_error[t.name]) for t in targets
            )
        )
        raise SystemExit(
            "Cohort disagrees with the pinned eth_genesis_hash (stale image, "
            "wrong reth genesis, or a node that never became ready); the "
            f"launch assertion failed:\n    pinned: {expected}\n{listing}"
        )


def fetch_holder_keys(public_ip: str, *, timeout: int = 30) -> tuple[str, str]:
    """Fetch one box's live summit pubkeys from its summit-key-holder.

    Raises a requests error on transport/HTTP failure (callers retry a
    still-booting box) and ValueError on a malformed response body —
    retrying can't fix a holder serving the wrong shape.
    """
    url = f"http://{public_ip}:{HOLDER_PORT}/v1/keys"
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError(f"{url}: expected a JSON object, got {type(data).__name__}")
    node_key = data.get("node_public_key")
    consensus_key = data.get("consensus_public_key")
    if not isinstance(node_key, str) or not isinstance(consensus_key, str):
        raise ValueError(
            f"{url}: response carries no node_public_key/consensus_public_key "
            f"strings: {data!r}"
        )
    return node_key, consensus_key


def _describe_served(served: tuple[str, str] | None, error: str | None) -> str:
    if served is None:
        return error or "never answered"
    node_key, consensus_key = served
    return f"serving node={node_key} consensus={consensus_key}"


def assert_cohort_holder_keys(
    targets: list[LaunchTarget],
    *,
    timeout: float = READY_TIMEOUT_SECONDS,
    interval: float = POLL_INTERVAL_SECONDS,
) -> None:
    """Assert every box's holder serves exactly its pinned founding keys.

    A mismatch is retried, not failed fast: until the LUKS volume is open
    and the keystore visible, the holder serves this boot's fresh RAM keys,
    so an early read on a healthy rebooted node can transiently disagree
    with the pin. A mismatch still standing at the deadline is the real
    failure — a box persisted keys the manifest never pinned (a reboot
    inside the founding window), and the network must not be trusted as
    launched: re-found rather than running with a dead consensus slot.
    """
    served: dict[str, tuple[str, str]] = {}  # latest answer per box
    matched: set[str] = set()
    last_error: dict[str, str] = {}
    started = time.monotonic()
    deadline = started + timeout
    next_log = 0.0
    while True:
        for target in targets:
            if target.name in matched:
                continue
            try:
                served[target.name] = fetch_holder_keys(target.public_ip)
            except ValueError as e:
                raise SystemExit(str(e)) from None
            except requests.RequestException as e:
                last_error[target.name] = str(e)
                continue
            if served[target.name] == (
                target.node_public_key,
                target.consensus_public_key,
            ):
                matched.add(target.name)
                print(f"  ✓ {target.name}: holder serves its pinned founding keys")
        pending = [t for t in targets if t.name not in matched]
        if not pending:
            return
        now = time.monotonic()
        if now >= deadline:
            break
        if now >= next_log:
            elapsed = int(now - started)
            remaining = max(0, int(deadline - now))
            print(
                f"waiting for pinned holder keys ({elapsed}s elapsed, "
                f"{remaining}s until timeout): " + ", ".join(t.name for t in pending)
            )
            next_log = now + WAIT_LOG_INTERVAL_SECONDS
        time.sleep(interval)

    listing = "\n".join(
        f"  {'✓' if t.name in matched else '✗'} {t.name}: "
        + (
            "holder serves its pinned founding keys"
            if t.name in matched
            else _describe_served(served.get(t.name), last_error.get(t.name))
        )
        for t in targets
    )
    mismatched = [t for t in targets if t.name not in matched and t.name in served]
    advice = (
        "A box still serving keys the manifest never pinned launched from a "
        "reboot inside the founding window — its pinned validator slot is "
        "dead. Re-found (`down` + fresh `up`) rather than running degraded."
        if mismatched
        else "Holders that never answered may still be booting — re-run "
        "`configure` to re-assert once the cohort settles."
    )
    raise SystemExit(
        f"{len(targets) - len(matched)} box(es) not serving their pinned "
        f"founding keys after {int(timeout)}s; the launch assertion failed:\n"
        f"{listing}\n{advice}"
    )
