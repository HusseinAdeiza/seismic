"""Founding bootnode set: fetch, persist, and reuse cohort enodes.

A freshly-configured reth node's enode (its devp2p node record) isn't known
until reth is up, so a greenfield cohort can't be handed a static bootnode
list up front — the genesis node must come up first, then its enode seeds the
joiners (the two-stage bootstrap in `cohort_configure`). This module fetches a
node's enode from its `seismic_nodeInfo` RPC and persists the founding set
beside the descriptors as `bootnodes.json`.

`bootnodes.json` is runtime infra state, exactly like the node descriptors it
sits next to (`nodes/`, gitignored): regenerated each configure run, and read
back on a later run to reconfigure the whole cohort (reboots wipe the tmpfs
conf dir) or to seed a joiner — the founding enodes, unlike live IPs, are
stable because each node's devp2p key lives on its encrypted disk.

`seismic_nodeInfo` returns `{"enode": "enode://<pubkey>@<host>:<port>"}` — the
`seismic` namespace deliberately keeps nodeInfo public (reth's `admin`
namespace is disabled on these nodes), see seismic-reth
crates/seismic/rpc/src/eth/ext.rs. nginx proxies `/rpc` → reth :8545, so we
query `https://<fqdn>/rpc` with a valid cert, exactly like the genesis
ceremony's block-0 probe (genesis.py).

reth's NodeRecord Display appends `?discport=<udp_port>` when its devp2p UDP
port differs from its TCP port; tdx-init rejects that form at POST time (the
`[network].bootnodes` grammar is strictly `enode://<128 hex>@host:port`). So every
fetched enode is normalized (`normalize_enode`) — the query dropped, bracketed
IPv6 preserved — before it is delivered or persisted.
"""

import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# tdx-init's node-id grammar: exactly 128 hex chars (upper or lower).
_ENODE_ID_RE = re.compile(r"^[0-9a-fA-F]{128}$")

# Written into a network's nodes/ dir (beside the descriptors), gitignored via
# tee/networks/.gitignore `*/nodes/`.
BOOTNODES_FILENAME = "bootnodes.json"

# Enode-readiness polling. reth serves seismic_nodeInfo only once it is up
# (root_key → LUKS open → reth start), so an early miss is the normal boot
# tail — polled until timeout, mirroring genesis.py's readiness timeouts.
POLL_INTERVAL_SECONDS = 5
ENODE_TIMEOUT_SECONDS = 15 * 60
WAIT_LOG_INTERVAL_SECONDS = 30


@dataclass(frozen=True)
class Bootnode:
    """One founding bootnode: the node's short label + its enode URL."""

    name: str
    enode: str


def fetch_enode(fqdn: str, *, timeout: int = 30) -> str:
    """Fetch a node's enode URL from its `seismic_nodeInfo` RPC.

    nginx proxies `/rpc` → reth :8545; the `seismic` namespace keeps nodeInfo
    public (admin is disabled). Raises on transport/RPC error or a response
    without an enode, so callers can retry a still-booting node.
    """
    url = f"https://{fqdn}/rpc"
    response = requests.post(
        url,
        json={"jsonrpc": "2.0", "id": 1, "method": "seismic_nodeInfo", "params": []},
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        raise RuntimeError(f"seismic_nodeInfo error from {url}: {data['error']}")
    result = data.get("result")
    enode = result.get("enode") if isinstance(result, dict) else None
    if not enode:
        raise RuntimeError(f"seismic_nodeInfo returned no enode from {url}: {data}")
    return enode


def normalize_enode(enode: str) -> str:
    """Coerce a NodeRecord enode into the strict `enode://<128 hex>@host:port`
    form tdx-init accepts, dropping any `?discport=` query reth appends when
    its devp2p TCP and UDP ports differ (seismic nodes run them equal, so this
    is normally a no-op). Bracketed IPv6 is preserved. Raises ValueError if the
    record isn't a well-formed enode — a founding node advertising a malformed
    record is a hard error, not something to deliver verbatim.
    """
    parsed = urlparse(enode)
    if parsed.scheme != "enode":
        raise ValueError(f"not an enode URL: {enode!r}")
    node_id = parsed.username or ""
    if not _ENODE_ID_RE.match(node_id):
        raise ValueError(f"enode node id is not 128 hex chars: {enode!r}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"enode has no host: {enode!r}")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError(f"enode port is not a valid u16: {enode!r}") from None
    if port is None:
        raise ValueError(f"enode has no port: {enode!r}")
    if parsed.query:
        logger.warning(
            "enode %s carries a query string (%s); dropping it — tdx-init "
            "accepts only enode://<id>@host:port. seismic nodes run matched "
            "devp2p TCP/UDP ports, so this is normally absent.",
            enode,
            parsed.query,
        )
    # urlparse strips IPv6 brackets from hostname; re-add them for the URL form.
    host_part = f"[{host}]" if ":" in host else host
    return f"enode://{node_id}@{host_part}:{port}"


def collect_enodes(
    targets: list[tuple[str, str]],
    *,
    timeout: float = ENODE_TIMEOUT_SECONDS,
    interval: float = POLL_INTERVAL_SECONDS,
) -> dict[str, str]:
    """Poll every `(label, fqdn)` target's `seismic_nodeInfo` until each
    returns an enode, or `timeout` elapses. Returns {label: normalized enode}.

    Round-robin like the genesis ceremony's readiness gathers, so a slow node
    doesn't serialize behind the others: each pass tries only the nodes not yet
    answered. A node still silent at the deadline aborts with a per-node report
    — a founding node that can't advertise its enode is a real bootstrap
    failure, not something waiting longer fixes. A transport/RPC error is
    retried; a *malformed* enode (fetched but unparseable) fails fast, since
    retrying can't fix it.
    """
    enodes: dict[str, str] = {}
    last_error: dict[str, str] = {}
    started = time.monotonic()
    deadline = started + timeout
    next_log = 0.0
    while True:
        for label, fqdn in targets:
            if label in enodes:
                continue
            try:
                raw = fetch_enode(fqdn)
            except Exception as e:  # noqa: BLE001 — transport/RPC error → retry
                last_error[label] = str(e)
                continue
            try:
                enodes[label] = normalize_enode(raw)
            except ValueError as e:
                raise SystemExit(f"{label}: {e}") from None
            print(f"  ✓ {label}: enode readable")
        pending = [label for label, _ in targets if label not in enodes]
        if not pending:
            return enodes
        now = time.monotonic()
        if now >= deadline:
            listing = "\n".join(
                f"  ✗ {label}: {last_error[label]}" for label in pending
            )
            raise SystemExit(
                f"{len(pending)} node(s) never returned an enode via "
                f"seismic_nodeInfo after {int(timeout)}s (reth not up?):\n{listing}"
            )
        if now >= next_log:
            elapsed = int(now - started)
            remaining = max(0, int(deadline - now))
            print(
                f"waiting for enodes ({elapsed}s elapsed, {remaining}s until "
                f"timeout): " + ", ".join(pending)
            )
            next_log = now + WAIT_LOG_INTERVAL_SECONDS
        time.sleep(interval)


def enode_host(enode: str) -> str | None:
    """Host part of an enode URL (`enode://<pubkey>@<host>:<port>`), or None
    if it can't be parsed. urlparse populates hostname from the `//` authority
    regardless of the `enode` scheme."""
    return urlparse(enode).hostname


def warn_on_ip_mismatch(enode: str, expected_ip: str, label: str) -> None:
    """Warn (never fail) if an enode's host isn't the node's public IP.

    With reth's `--nat extip <public_ip>` (from `[node].external_ip`) the
    advertised enode host should equal the descriptor's public_ip. A mismatch
    usually means extip wasn't applied, so reth advertised a private or
    auto-detected address peers can't dial — worth surfacing loudly, but not
    fatal to configuration, so we log and continue.
    """
    host = enode_host(enode)
    if host != expected_ip:
        logger.warning(
            "%s: enode host %s does not match descriptor public_ip %s — is "
            "reth's --nat extip set to the public IP? peers may be unable to "
            "reach this node's enode.",
            label,
            host,
            expected_ip,
        )


def save_bootnodes(path: Path, bootnodes: list[Bootnode]) -> None:
    """Persist the founding bootnode set (pretty JSON, trailing newline —
    matching the descriptor writer). Overwrites: it's a fresh snapshot each
    configure run."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"bootnodes": [{"name": b.name, "enode": b.enode} for b in bootnodes]}
    path.write_text(json.dumps(payload, indent=2) + "\n")


def load_bootnodes(path: Path) -> list[Bootnode]:
    """Load a `bootnodes.json` written by `save_bootnodes`."""
    data = json.loads(path.read_text())
    records = data.get("bootnodes", []) if isinstance(data, dict) else []
    return [Bootnode(name=r["name"], enode=r["enode"]) for r in records]
