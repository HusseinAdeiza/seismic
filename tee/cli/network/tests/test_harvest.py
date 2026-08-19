"""Tests for tee.cli.network.harvest (stdlib unittest; no test deps).

Covers the offline logic: arg parsing, cohort/founder pairing, the
quote-poll loop and its burn conditions (fetch mocked — no live network
calls), the verify-quote shell-out contract (subprocess mocked), and the
inputs/harvest/ archive.

Run with:
    uv run python -m unittest discover -b
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests

from tee.cli.common import manifest as manifest_mod
from tee.cli.common import shell_outs
from tee.cli.network import bootnodes, harvest

NODE_KEY = "ab" * 32
CONSENSUS_KEY = "cd" * 48
NONCE = "11" * 32
EVIDENCE = {"attestation_type": "azure-tdx", "attestation": [1, 2, 3]}
ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


def quote_body(node_key: str = NODE_KEY, consensus_key: str = CONSENSUS_KEY) -> dict:
    return {
        "node_public_key": node_key,
        "consensus_public_key": consensus_key,
        "evidence": dict(EVIDENCE),
    }


def response(status_code: int = 200, body: dict | None = None) -> mock.Mock:
    resp = mock.Mock()
    resp.status_code = status_code
    resp.json.return_value = body if body is not None else quote_body()
    if status_code >= 400:
        error = requests.HTTPError(f"HTTP {status_code}")
        error.response = resp
        resp.raise_for_status.side_effect = error
    else:
        resp.raise_for_status.return_value = None
    return resp


def target(name: str = "node-1", ip: str = "203.0.113.7") -> harvest.HarvestTarget:
    return harvest.HarvestTarget(name=name, public_ip=ip, nonce=NONCE)


class ParseArgsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        # Resolved: _parse_args makes every derived path absolute so the
        # paths harvest prints are clickable.
        self.dir = Path(self._tmp.name).resolve()
        inputs = self.dir / manifest_mod.INPUTS_DIRNAME
        inputs.mkdir()
        (inputs / manifest_mod.MEASUREMENTS_FILENAME).write_text("{}")
        (inputs / manifest_mod.FOUNDERS_FILENAME).write_text("[]")
        self.nodes = self.dir / manifest_mod.NODES_DIRNAME
        self.nodes.mkdir()

    def test_node_defaults_to_nodes_dir_sorted_skipping_bootnodes(self):
        (self.nodes / "b.json").write_text("{}")
        (self.nodes / "a.json").write_text("{}")
        (self.nodes / bootnodes.BOOTNODES_FILENAME).write_text("{}")
        args = harvest._parse_args([str(self.dir)])
        self.assertEqual(args.node, [self.nodes / "a.json", self.nodes / "b.json"])

    def test_repeated_node_flag_accumulates(self):
        n1 = self.nodes / "n1.json"
        n2 = self.nodes / "n2.json"
        n1.write_text("{}")
        n2.write_text("{}")
        args = harvest._parse_args(
            [str(self.dir), "--node", str(n1), "--node", str(n2)]
        )
        self.assertEqual(args.node, [n1, n2])

    def test_duplicate_node_descriptor_rejected(self):
        n1 = self.nodes / "n1.json"
        n1.write_text("{}")
        with self.assertRaises(SystemExit) as ctx:
            harvest._parse_args([str(self.dir), "--node", str(n1), "--node", str(n1)])
        self.assertIn("duplicate", str(ctx.exception))

    def test_same_stem_under_different_paths_rejected(self):
        # Stems are the harvest's node names: two descriptors sharing one
        # stem would silently collapse into a single harvested box.
        other = self.dir / "elsewhere"
        other.mkdir()
        n1 = self.nodes / "n1.json"
        twin = other / "n1.json"
        n1.write_text("{}")
        twin.write_text("{}")
        with self.assertRaises(SystemExit) as ctx:
            harvest._parse_args([str(self.dir), "--node", str(n1), "--node", str(twin)])
        self.assertIn("duplicate", str(ctx.exception))
        self.assertIn("n1", str(ctx.exception))

    def test_empty_nodes_dir_errors(self):
        with self.assertRaises(SystemExit) as ctx:
            harvest._parse_args([str(self.dir)])
        self.assertIn("no --node given", str(ctx.exception))

    def test_missing_founders_errors_with_authoring_hint(self):
        inputs = self.dir / manifest_mod.INPUTS_DIRNAME
        (inputs / manifest_mod.FOUNDERS_FILENAME).unlink()
        with self.assertRaises(SystemExit) as ctx:
            harvest._parse_args([str(self.dir)])
        self.assertIn(manifest_mod.FOUNDERS_FILENAME, str(ctx.exception))
        self.assertIn("withdrawal credentials", str(ctx.exception))

    def test_missing_measurements_errors(self):
        (
            self.dir / manifest_mod.INPUTS_DIRNAME / manifest_mod.MEASUREMENTS_FILENAME
        ).unlink()
        with self.assertRaises(SystemExit) as ctx:
            harvest._parse_args([str(self.dir)])
        self.assertIn(manifest_mod.MEASUREMENTS_FILENAME, str(ctx.exception))

    def test_missing_network_dir_errors(self):
        with self.assertRaises(SystemExit) as ctx:
            harvest._parse_args([str(self.dir / "absent")])
        self.assertIn("network directory", str(ctx.exception))


class LoadFoundersTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / manifest_mod.FOUNDERS_FILENAME

    def _write(self, obj) -> None:
        self.path.write_text(json.dumps(obj))

    def test_matching_count_returns_addresses(self):
        self._write([ADDRESS, ADDRESS])
        founders = harvest.load_founders(self.path, ["node-1", "node-2"])
        self.assertEqual(founders, [ADDRESS, ADDRESS])

    def test_too_few_credentials_aborts(self):
        self._write([ADDRESS])
        with self.assertRaises(SystemExit) as ctx:
            harvest.load_founders(self.path, ["node-1", "node-2"])
        self.assertIn("1 withdrawal credential(s)", str(ctx.exception))
        self.assertIn("2 box(es)", str(ctx.exception))

    def test_too_many_credentials_aborts(self):
        self._write([ADDRESS, ADDRESS])
        with self.assertRaises(SystemExit) as ctx:
            harvest.load_founders(self.path, ["node-1"])
        self.assertIn("2 withdrawal credential(s)", str(ctx.exception))

    def test_malformed_address_aborts(self):
        self._write(["0x1234"])
        with self.assertRaises(SystemExit) as ctx:
            harvest.load_founders(self.path, ["node-1"])
        self.assertIn("0x1234", str(ctx.exception))

    def test_non_list_aborts(self):
        self._write({"node-1": ADDRESS})
        with self.assertRaises(SystemExit) as ctx:
            harvest.load_founders(self.path, ["node-1"])
        self.assertIn("expected a JSON array", str(ctx.exception))


class FetchQuoteTests(unittest.TestCase):
    def test_returns_quote_and_passes_nonce(self):
        with mock.patch.object(harvest.requests, "get") as get:
            get.return_value = response()
            data = harvest.fetch_quote("203.0.113.7", NONCE)
        self.assertEqual(data["node_public_key"], NODE_KEY)
        get.assert_called_once()
        self.assertEqual(get.call_args.kwargs["params"], {"nonce": NONCE})
        self.assertIn(f":{harvest.HOLDER_PORT}/v1/quote", get.call_args.args[0])

    def test_410_raises_quote_window_closed(self):
        with mock.patch.object(harvest.requests, "get") as get:
            get.return_value = response(status_code=410)
            with self.assertRaises(harvest.QuoteWindowClosed):
                harvest.fetch_quote("203.0.113.7", NONCE)

    def test_malformed_keys_raise_value_error(self):
        for body in (
            quote_body(node_key="0x" + NODE_KEY),  # keystore format is bare hex
            quote_body(node_key=NODE_KEY.upper()),
            quote_body(consensus_key="cd" * 32),  # wrong length
            {"node_public_key": NODE_KEY, "consensus_public_key": CONSENSUS_KEY},
        ):
            with mock.patch.object(harvest.requests, "get") as get:
                get.return_value = response(body=body)
                with self.assertRaises(ValueError):
                    harvest.fetch_quote("203.0.113.7", NONCE)


class CollectQuotesTests(unittest.TestCase):
    def test_retries_transport_errors_until_quote_readable(self):
        with mock.patch.object(
            harvest,
            "fetch_quote",
            side_effect=[requests.ConnectionError("refused"), quote_body()],
        ):
            quotes = harvest.collect_quotes([target()], timeout=5, interval=0)
        self.assertEqual(quotes["node-1"]["node_public_key"], NODE_KEY)

    def test_timeout_lists_only_stuck_boxes(self):
        answered = quote_body()

        def fetch(ip, nonce, **_):
            if ip == "203.0.113.7":
                return answered
            raise requests.ConnectionError("refused")

        targets = [target("node-1", "203.0.113.7"), target("node-2", "203.0.113.8")]
        with mock.patch.object(harvest, "fetch_quote", side_effect=fetch):
            with self.assertRaises(SystemExit) as ctx:
                harvest.collect_quotes(targets, timeout=0, interval=0)
        message = str(ctx.exception)
        self.assertIn("node-2", message)
        self.assertNotIn("✗ node-1", message)

    def test_quote_window_closed_burns_the_harvest(self):
        with mock.patch.object(
            harvest, "fetch_quote", side_effect=harvest.QuoteWindowClosed("url")
        ):
            with self.assertRaises(SystemExit) as ctx:
                harvest.collect_quotes([target()], timeout=5, interval=0)
        message = str(ctx.exception)
        self.assertIn("burned", message)
        self.assertIn("re-found", message)

    def test_client_error_fails_fast(self):
        error = requests.HTTPError("HTTP 400")
        error.response = mock.Mock(status_code=400)
        with mock.patch.object(harvest, "fetch_quote", side_effect=error):
            with self.assertRaises(SystemExit) as ctx:
                harvest.collect_quotes([target()], timeout=5, interval=0)
        self.assertIn("rejected", str(ctx.exception))

    def test_server_error_is_retried(self):
        error = requests.HTTPError("HTTP 500")
        error.response = mock.Mock(status_code=500)
        with mock.patch.object(
            harvest, "fetch_quote", side_effect=[error, quote_body()]
        ):
            quotes = harvest.collect_quotes([target()], timeout=5, interval=0)
        self.assertIn("node-1", quotes)


class AssertUniqueKeysTests(unittest.TestCase):
    def test_distinct_keys_pass(self):
        harvest.assert_unique_keys(
            {
                "node-1": quote_body(),
                "node-2": quote_body(node_key="ef" * 32, consensus_key="ab" * 48),
            }
        )

    def test_repeated_node_key_burns(self):
        with self.assertRaises(SystemExit) as ctx:
            harvest.assert_unique_keys(
                {
                    "node-1": quote_body(),
                    "node-2": quote_body(consensus_key="ab" * 48),
                }
            )
        self.assertIn("node_public_key", str(ctx.exception))


class VerifyQuoteTests(unittest.TestCase):
    REPORT = {"verified": True, "attestation_type": "azure-tdx", "pcrs": {}}

    def _run(self, returncode=0, stdout=b"", stderr=b""):
        completed = mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)
        # The shell-out lives in shell_outs.verify_quote_evidence (shared with
        # `assemble`'s re-verification); harvest wraps it with the
        # burn messaging.
        with mock.patch.object(
            shell_outs.subprocess, "run", return_value=completed
        ) as run:
            report = harvest.verify_quote(
                target(),
                quote_body(),
                Path("/tmp/policy.json"),
                "verify-quote",
                pccs_url=None,
                override_azure_outdated_tcb=False,
            )
        return report, run

    def test_success_returns_report_and_binds_nonce_and_pubkeys(self):
        report, run = self._run(stdout=json.dumps(self.REPORT).encode())
        self.assertTrue(report["verified"])
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[:2], ["verify-quote", "harvest"])
        for expected in (NONCE, NODE_KEY, CONSENSUS_KEY, "-"):
            self.assertIn(expected, cmd)
        # The evidence travels over stdin, byte-exact with the archive.
        self.assertEqual(json.loads(run.call_args.kwargs["input"]), EVIDENCE)

    def test_nonzero_exit_burns_with_stderr(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run(returncode=1, stderr=b"binding mismatch")
        message = str(ctx.exception)
        self.assertIn("burned", message)
        self.assertIn("binding mismatch", message)

    def test_unverified_report_aborts(self):
        with self.assertRaises(SystemExit):
            self._run(stdout=b'{"verified": false}')

    def test_exit_zero_with_non_json_stdout_aborts(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run(stdout=b"not json")
        self.assertIn("without a verified report", str(ctx.exception))

    def test_optional_flags_forwarded(self):
        completed = mock.Mock(
            returncode=0, stdout=json.dumps(self.REPORT).encode(), stderr=b""
        )
        with mock.patch.object(
            shell_outs.subprocess, "run", return_value=completed
        ) as run:
            harvest.verify_quote(
                target(),
                quote_body(),
                Path("/tmp/policy.json"),
                "verify-quote",
                pccs_url="https://pccs.example",
                override_azure_outdated_tcb=True,
            )
        cmd = run.call_args.args[0]
        self.assertIn("https://pccs.example", cmd)
        self.assertIn("--override-azure-outdated-tcb", cmd)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.harvest_dir = Path(self._tmp.name) / manifest_mod.HARVEST_DIRNAME

    def test_save_writes_one_pretty_json_per_box(self):
        record = {
            "harvest_nonce": NONCE,
            "node_public_key": NODE_KEY,
            "consensus_public_key": CONSENSUS_KEY,
            "evidence": EVIDENCE,
            "harvested_at": "2026-08-04T00:00:00+00:00",
            "verification": {"verified": True},
        }
        written = harvest.save_harvest(self.harvest_dir, {"node-1": record})
        self.assertEqual(written, [self.harvest_dir / "node-1.json"])
        text = written[0].read_text()
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(json.loads(text), record)

    def test_check_overwrite_refuses_existing_without_force(self):
        self.harvest_dir.mkdir(parents=True)
        (self.harvest_dir / "node-1.json").write_text("{}")
        with self.assertRaises(SystemExit) as ctx:
            harvest.check_overwrite(self.harvest_dir, ["node-1", "node-2"], False)
        message = str(ctx.exception)
        self.assertIn("node-1", message)
        self.assertIn("--force", message)

    def test_check_overwrite_allows_force_and_fresh_dirs(self):
        harvest.check_overwrite(self.harvest_dir, ["node-1"], False)
        self.harvest_dir.mkdir(parents=True)
        (self.harvest_dir / "node-1.json").write_text("{}")
        harvest.check_overwrite(self.harvest_dir, ["node-1"], True)


if __name__ == "__main__":
    unittest.main()
