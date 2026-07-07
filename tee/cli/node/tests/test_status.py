"""Tests for tee.status (stdlib unittest; no test deps in this repo).

Run with:
    uv run python -m unittest discover -s tee/tests -v
"""

import threading
import unittest
from unittest import mock

from tee.cli.node import status


class FormatTests(unittest.TestCase):
    def test_provisioning_with_eta(self):
        line = status.format_provisioning(
            {"bytes_done": 2**30, "bytes_total": 4 * 2**30, "eta_seconds": 291}
        )
        self.assertIn("25.0%", line)
        self.assertIn("1.0/4.0 GiB", line)
        self.assertIn("eta 4m51s", line)

    def test_provisioning_without_eta(self):
        line = status.format_provisioning({"bytes_done": 0, "bytes_total": 2**30})
        self.assertIn("0.0%", line)
        self.assertNotIn("eta", line)

    def test_zero_total_is_indeterminate(self):
        # bytes_total 0 is the "just started, no measurement yet" marker — must
        # not divide by zero.
        line = status.format_provisioning({"bytes_done": 0, "bytes_total": 0})
        self.assertIn("starting", line)

    def test_duration_formats(self):
        self.assertEqual(status._duration(45), "45s")
        self.assertEqual(status._duration(291), "4m51s")
        self.assertEqual(status._duration(3725), "1h02m")

    def test_bar_is_clamped(self):
        self.assertEqual(status._bar(0, width=10), "[----------]")
        self.assertEqual(status._bar(100, width=10), "[##########]")
        # Out-of-range percentages must not overflow the bar width.
        self.assertEqual(len(status._bar(150, width=10)), 12)
        self.assertEqual(len(status._bar(-5, width=10)), 12)


class FetchStatusTests(unittest.TestCase):
    def _resp(self, body: dict):
        resp = mock.Mock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = body
        return resp

    def test_extracts_result_and_builds_request(self):
        resp = self._resp({"jsonrpc": "2.0", "id": 1, "result": {"state": "idle"}})
        with mock.patch.object(status.requests, "post", return_value=resp) as post:
            result = status.fetch_status("1.2.3.4")
        self.assertEqual(result, {"state": "idle"})
        url, kwargs = post.call_args[0][0], post.call_args[1]
        self.assertEqual(url, "http://1.2.3.4:7878")
        self.assertEqual(kwargs["json"]["method"], "getLuksProvisioningStatus")

    def test_raises_on_rpc_error(self):
        resp = self._resp({"jsonrpc": "2.0", "id": 1, "error": {"message": "boom"}})
        with mock.patch.object(status.requests, "post", return_value=resp):
            with self.assertRaises(RuntimeError):
                status.fetch_status("1.2.3.4")


class PollProvisioningTests(unittest.TestCase):
    """poll_provisioning is the shared state machine behind the single-node
    watch and the cohort dashboard. These pin the part that bit us: a transient
    `error` (setup-persistent-luks failing an attempt but restarting under
    Restart=on-failure) must NOT be treated as terminal."""

    def _run(self, responses: list[dict]) -> list:
        # Feed a fixed sequence of getLuksProvisioningStatus results and collect
        # every ProvisioningUpdate. sleep is a no-op so the generator runs fast.
        with (
            mock.patch.object(status, "fetch_status", side_effect=responses),
            mock.patch.object(status.time, "sleep"),
        ):
            return list(status.poll_provisioning("1.2.3.4"))

    def test_transient_error_recovers_not_terminal(self):
        # Two failed attempts (systemd restarting), then progress, then done.
        updates = self._run(
            [
                {"state": "error", "error": "data disk not yet attached"},
                {"state": "error", "error": "data disk not yet attached"},
                {"state": "provisioning", "bytes_done": 5, "bytes_total": 10},
                {"state": "idle"},
            ]
        )
        # Only the final idle (after provisioning) is terminal — not the errors.
        self.assertTrue(all(not u.done for u in updates[:-1]))
        self.assertTrue(updates[-1].done and updates[-1].ok)
        # The transient errors were surfaced as retrying, not fatal.
        self.assertTrue(any(u.phase == "error" and not u.done for u in updates))

    def test_persistent_error_is_terminal(self):
        # Grace collapsed to zero → a stuck error is terminal (restarts exhausted).
        with mock.patch.object(status, "ERROR_GRACE_SECONDS", -1):
            updates = self._run([{"state": "error", "error": "boom"}])
        self.assertTrue(updates[-1].done)
        self.assertFalse(updates[-1].ok)
        self.assertIn("boom", updates[-1].line)

    def test_provisioning_then_idle_completes_ok(self):
        updates = self._run(
            [
                {"state": "provisioning", "bytes_done": 5, "bytes_total": 10},
                {"state": "idle"},
            ]
        )
        self.assertTrue(updates[-1].done and updates[-1].ok)

    def test_stop_event_ends_poll_without_terminal_update(self):
        # The cohort dashboard sets `stop` on ctrl-C; the generator must end
        # within one interval instead of watching a wipe to completion.
        stop = threading.Event()
        stop.set()
        with mock.patch.object(
            status,
            "fetch_status",
            return_value={"state": "provisioning", "bytes_done": 1, "bytes_total": 10},
        ):
            updates = list(status.poll_provisioning("1.2.3.4", stop=stop))
        self.assertTrue(updates)
        self.assertFalse(any(u.done for u in updates))


if __name__ == "__main__":
    unittest.main()
