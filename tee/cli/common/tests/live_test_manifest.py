"""Live cross-repo drift guards (network-required; run via `make test-live`).

These tests fetch pinned artifacts from sibling repos on GitHub and compare
them against what this repo renders or pins. The module name deliberately
does not match `make test`'s `test*.py` discovery pattern, so the default
suite stays hermetic (offline, deterministic); CI runs this module as its
own non-required job, where a failure names the exact cross-repo check.

The suite never skips — a missing prerequisite is a failure. It needs:

- network reach to raw.githubusercontent.com (both tests fetch pinned
  artifacts from sibling repos);
- `seismic-measurement-admission` on PATH — the enclave repo's admission
  CLI (`cargo install --features cli` from crates/measurement-admission;
  CI builds it from enclave's seismic branch).

Run with:
    make test-live
"""

import http.client
import json
import unittest
import urllib.error
import urllib.request

from eth_utils import keccak

from tee.cli.common.manifest import compile_measurement_policy, render_manifest
from tee.cli.common.tests.test_manifest import (
    ADMISSION_BIN,
    FIXTURE_MANIFEST,
    promoted_policy_bytes,
)


def _fetch_live(url: str) -> bytes:
    """Fetch a cross-repo artifact, failing the calling test if it can't.

    An HTTP 4xx/5xx means the artifact moved or the ref is gone — a real
    drift signal, not flaky network — so it propagates directly. A
    transport-level failure (unreachable, timeout, truncated body) is
    retried once, then fails: this suite never skips.
    """
    last: Exception | None = None
    for _ in range(2):
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                return resp.read()
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, http.client.HTTPException) as e:
            last = e
    raise AssertionError(
        f"cross-repo artifact unreachable after retry: {last}"
    ) from last


class ManifestFixtureParityTests(unittest.TestCase):
    """Byte-parity with the node-side manifest parser.

    The enclave repo pins the manifest fixture's exact bytes; deploy's
    emitter must render the same dict to the same bytes. Fetched from
    GitHub (the `seismic` branch) rather than assuming a sibling checkout
    on disk, so the check runs in CI too. The fixture's network_id is also
    pinned offline by test_manifest's
    test_render_matches_enclave_network_id_vector; this adds the live
    byte-level drift guard on top.
    """

    ENCLAVE_FIXTURE_URL = (
        "https://raw.githubusercontent.com/SeismicSystems/enclave/seismic/"
        "crates/network-manifest/fixtures/network-manifest-v1.json"
    )

    def test_render_matches_enclave_fixture_bytes(self):
        fixture = _fetch_live(self.ENCLAVE_FIXTURE_URL)
        self.assertEqual(render_manifest(FIXTURE_MANIFEST), fixture)


class RuntimeCodeDriftTests(unittest.TestCase):
    """Cross-repo drift guard for the registry runtime-code pin.

    The admission CLI pins keccak256 of the canonical MeasurementRegistry
    deployed bytecode; the gates enforce that pin against the genesis alloc,
    so a stale pin already fails assembly loudly. This test is the early
    warning: the pin reported by the binary on PATH must match the artifact
    the reth genesis builder installs.
    """

    REGISTRY_ARTIFACT_URL = (
        "https://raw.githubusercontent.com/SeismicSystems/seismic/main/"
        "contracts/artifacts/MeasurementRegistry.json"
    )

    def test_admission_crate_pins_current_registry_runtime(self):
        self.assertIsNotNone(
            ADMISSION_BIN,
            "seismic-measurement-admission not on PATH — the live suite fails "
            "rather than skips; build the enclave repo's admission CLI",
        )
        report = compile_measurement_policy(promoted_policy_bytes())
        artifact = json.loads(_fetch_live(self.REGISTRY_ARTIFACT_URL))
        runtime = artifact["deployedBytecode"]["object"].removeprefix("0x")
        self.assertEqual(
            report["registry_runtime_code_hash"],
            "0x" + keccak(bytes.fromhex(runtime)).hex(),
        )


if __name__ == "__main__":
    unittest.main()
