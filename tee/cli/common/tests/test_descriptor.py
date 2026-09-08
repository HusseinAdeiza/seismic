"""Tests for tee.cli.common.descriptor (stdlib unittest; no test deps).

The descriptor file is the stack's `nodes` map. These pin what the loader
accepts (exactly `pulumi stack output nodes --json`, extra keys ignored),
how it names each mistake, and how a single-node command picks its node.

Run with:
    uv run python -m unittest discover -b
"""

import argparse
import json
import tempfile
import unittest
from pathlib import Path

from tee.cli.common import descriptor
from tee.cli.common.descriptor import (
    NodeDescriptor,
    load_descriptors,
    load_node_arg,
    select_descriptor,
)

N1 = {"public_ip": "203.0.113.7", "fqdn": "n1.example"}
N2 = {"public_ip": "203.0.113.8", "fqdn": "n2.example"}


class LoadDescriptorsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / descriptor.NODES_FILENAME

    def _load(self, obj) -> dict[str, NodeDescriptor]:
        self.path.write_text(json.dumps(obj))
        return load_descriptors(self.path)

    def _fails(self, obj) -> str:
        with self.assertRaises(ValueError) as ctx:
            self._load(obj)
        message = str(ctx.exception)
        # Every failure names the file: the format is hand-writable.
        self.assertIn(descriptor.NODES_FILENAME, message)
        return message

    def test_the_map_is_the_stack_output(self):
        loaded = self._load({"node-1": N1, "node-2": N2})
        self.assertEqual(
            loaded,
            {
                "node-1": NodeDescriptor("node-1", "203.0.113.7", "n1.example"),
                "node-2": NodeDescriptor("node-2", "203.0.113.8", "n2.example"),
            },
        )

    def test_sorted_by_node_name(self):
        # The order the authored withdrawal credentials pair against.
        self.assertEqual(list(self._load({"b": N2, "a": N1})), ["a", "b"])

    def test_extra_keys_are_ignored(self):
        loaded = self._load({"node-1": {**N1, "resource_group": "rg", "vm_id": "x"}})
        self.assertEqual(loaded["node-1"], NodeDescriptor("node-1", **N1))

    def test_a_one_key_map_is_the_bring_your_own_infra_shape(self):
        self.assertEqual(list(self._load({"mine": N1})), ["mine"])

    def test_top_level_must_be_the_map(self):
        # A list is not the map.
        self.assertIn("mapping node name", self._fails([N1]))

    def test_a_bare_single_node_object_is_told_to_wrap_itself(self):
        # The shape a descriptor file had before it was the map: refuse with
        # the fix, rather than guess a name or report "node 'fqdn' must be an
        # object".
        message = self._fails(N1)
        self.assertIn("wrap it under the node's name", message)
        self.assertNotIn("'fqdn' must be an object", message)

    def test_empty_map_is_refused(self):
        self.assertIn("holds no nodes", self._fails({}))

    def test_entry_must_be_an_object(self):
        message = self._fails({"node-1": "203.0.113.7"})
        self.assertIn("'node-1'", message)
        self.assertIn("must be an object", message)

    def test_absent_null_and_empty_keys_are_reported_apart(self):
        # Asserting the distinguishing phrase, not just the key name: the fix
        # differs, and "missing" for a key the operator can see in the file
        # sends them looking in the wrong place.
        cases = [
            ({"node-1": {"fqdn": "n1.example"}}, "missing required key 'public_ip'"),
            ({"node-1": {"public_ip": None, "fqdn": "n1.example"}}, "set to null"),
            (
                {"node-1": {"public_ip": "", "fqdn": "n1.example"}},
                "empty or non-string",
            ),
            ({"node-1": {"public_ip": 7, "fqdn": "n1.example"}}, "empty or non-string"),
        ]
        for obj, expected in cases:
            message = self._fails(obj)
            self.assertIn(expected, message)
            self.assertIn("'node-1'", message)

    def test_a_missing_key_lists_the_keys_the_entry_had(self):
        message = self._fails({"node-1": {"publicIp": "203.0.113.7", "fqdn": "x"}})
        self.assertIn("['fqdn', 'publicIp']", message)

    def test_a_present_but_unusable_key_is_not_called_missing(self):
        for obj in [
            {"node-1": {"public_ip": None, "fqdn": "n1.example"}},
            {"node-1": {"public_ip": "", "fqdn": "n1.example"}},
        ]:
            message = self._fails(obj)
            self.assertNotIn("missing", message)
            self.assertNotIn("got keys", message)


class SelectDescriptorTests(unittest.TestCase):
    ONE = {"node-1": NodeDescriptor("node-1", **N1)}
    TWO = {**ONE, "node-2": NodeDescriptor("node-2", **N2)}
    PATH = Path("nodes/nodes.json")

    def test_one_entry_is_the_node(self):
        self.assertEqual(select_descriptor(self.ONE, None, self.PATH).name, "node-1")

    def test_several_entries_need_a_name(self):
        with self.assertRaises(ValueError) as ctx:
            select_descriptor(self.TWO, None, self.PATH)
        self.assertIn("--name", str(ctx.exception))
        self.assertIn("node-1, node-2", str(ctx.exception))

    def test_name_picks(self):
        self.assertEqual(
            select_descriptor(self.TWO, "node-2", self.PATH).name, "node-2"
        )
        # Naming the only node is fine too.
        self.assertEqual(
            select_descriptor(self.ONE, "node-1", self.PATH).name, "node-1"
        )

    def test_unknown_name_lists_the_choices(self):
        with self.assertRaises(ValueError) as ctx:
            select_descriptor(self.TWO, "node-9", self.PATH)
        self.assertIn("'node-9'", str(ctx.exception))
        self.assertIn("node-1, node-2", str(ctx.exception))


class LoadNodeArgTests(unittest.TestCase):
    """`--node <file> [--name]` end to end: every failure is a SystemExit
    naming the file."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def _args(self, node: Path, name: str | None = None) -> argparse.Namespace:
        parser = argparse.ArgumentParser()
        descriptor.add_node_args(parser)
        argv = ["--node", str(node)] + (["--name", name] if name else [])
        return parser.parse_args(argv)

    def test_resolves_the_node(self):
        path = self.dir / "nodes.json"
        path.write_text(json.dumps({"node-1": N1, "node-2": N2}))
        self.assertEqual(load_node_arg(self._args(path, "node-2")).fqdn, "n2.example")

    def test_absent_file(self):
        with self.assertRaises(SystemExit) as ctx:
            load_node_arg(self._args(self.dir / "absent.json"))
        self.assertIn("absent.json", str(ctx.exception))

    def test_malformed_file(self):
        path = self.dir / "nodes.json"
        path.write_text("not json")
        with self.assertRaises(SystemExit) as ctx:
            load_node_arg(self._args(path))
        self.assertIn("not valid JSON", str(ctx.exception))

    def test_ambiguous_file(self):
        path = self.dir / "nodes.json"
        path.write_text(json.dumps({"node-1": N1, "node-2": N2}))
        with self.assertRaises(SystemExit) as ctx:
            load_node_arg(self._args(path))
        self.assertIn("--name", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
