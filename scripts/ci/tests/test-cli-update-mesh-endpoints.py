#!/usr/bin/env python3
"""Focused command-capture proof; never start CW, a helper, or a Journey run.

Only the constructor and mesh_up/verify_mesh/mesh_down methods execute. The
base constructor, CLI calls and process witnesses use synthetic substitutes.
The real kernel operation is bounded loopback socket allocation and close.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
PRIMARY = ROOT / "scripts/dev/test-cli-update.py"
options = types.SimpleNamespace(source=PRIMARY, primary=PRIMARY)


def load_candidate():
    # Keep actual sibling imports bound to the root's primary checked-in files.
    # Loading definitions does not call main or start any subprocess.
    module = types.ModuleType("port_capture_candidate")
    module.__file__ = str(options.primary)
    exec(compile(options.source.read_bytes(), str(options.primary), "exec"), module.__dict__)
    return module


class TrackedSocket:
    def __init__(self, events, sockets, family, kind, fail_bind=False):
        self.socket = socket.socket(family, kind)
        self.events = events
        self.sockets = sockets
        self.family = family
        self.kind = kind
        self.fail_bind = fail_bind
        self.closed = False
        sockets.append(self)
        events.append(("open", len(sockets)))

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.socket.close()
        self.closed = True
        self.events.append(("close", len(self.sockets)))

    def bind(self, address):
        self.events.append(("bind", address, sum(not s.closed for s in self.sockets)))
        if self.fail_bind:
            raise OSError("synthetic second bind refusal")
        self.socket.bind(address)

    def getsockname(self):
        return self.socket.getsockname()


class SyntheticProcess:
    """Typed metadata for command routing, never a custody/process proof."""
    def __init__(self, pid, expected):
        self.pid = pid
        self.fd = None
        self.identity = {"birth": pid + 1000, "executable": str(expected)}

    def verify(self):
        return None


class MeshPortCommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cw-mesh-endpoints-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.module = load_candidate()
        self.events, self.sockets, self.calls, self.parent_calls = [], [], [], []
        self.live = False
        self.a = (self.root / "release-a", {"sha256": "a" * 64})
        self.b = (self.root / "release-b", {"sha256": "b" * 64})
        self.selected = self.a[1]
        self.runtime = None

    def parent_init(self, journey, cw, native):
        # Bypass all ambient HOME/state reads, sentinel starts and fixture copies.
        self.parent_calls.append((cw, native))
        journey.root = self.root
        journey.workspace = self.root / "project"
        journey.cw = str(cw)
        journey.env = {"PATH": "/synthetic-only", "CW_HOST_DATA_DIR": str(self.root / "hosts"),
                       "CW_CONFIG_DIR": str(self.root / "config")}

    def factory(self, family, kind):
        return TrackedSocket(self.events, self.sockets, family, kind)

    def journey(self, mesh=True, factory=None):
        substitute = types.SimpleNamespace(socket=factory or self.factory,
                                           AF_INET=socket.AF_INET, SOCK_STREAM=socket.SOCK_STREAM)
        parent_initializer = lambda journey, cw, native: self.parent_init(journey, cw, native)
        with patch.object(self.module.host.Journey, "__init__", parent_initializer), \
                patch.object(self.module, "socket", substitute):
            result = self.module.Journey(self.a, self.b, mesh)
        result.call = self.capture_call
        result.wait_death = lambda processes: None
        result.network_original = {"synthetic": "unchanged"}
        result.network_state = lambda: {"synthetic": "unchanged"}
        self.module.Process = lambda pid: SyntheticProcess(
            pid, result.store / "versions" / self.selected["sha256"] / "cw")
        return result

    def capture_call(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        self.assertEqual(kwargs, {"data": True})
        self.assertEqual(args[:1], ("mesh",))
        if args[1] == "up":
            started = not self.live
            if started:
                path = self.root / "store" / "versions" / self.selected["sha256"] / "cw"
                def record(pid, role):
                    return {"pid": pid, "custody": {"schema_version": 1, "role": role,
                            "pid": pid, "uid": os.geteuid(), "start_ticks": pid + 1000,
                            "executable": {"path": str(path), "sha256": self.selected["sha256"]}}}
                self.runtime = record(10001, "embedded_mesh")
                self.runtime["derp"] = record(10002, "embedded_derp")
                directory = self.root / "mesh"
                directory.mkdir(exist_ok=True)
                (directory / "mesh_runtime.json").write_text(json.dumps(self.runtime))
                self.live = True
            return {"started": started}
        if args[1] == "status":
            return {"local": {"pid": self.runtime["pid"],
                              "derp": {"pid": self.runtime["derp"]["pid"]}}}
        if args[1] == "down":
            self.live = False
            (self.root / "mesh" / "mesh_runtime.json").unlink()
            return {"stopped": True}
        self.fail(f"unexpected synthetic command: {args}")

    def test_two_distinct_loopback_endpoints_allocated_together_once(self):
        journey = self.journey()
        journey.mesh_up(self.a[1])
        self.assertEqual(len(self.sockets), 2, "both endpoints must be allocated once")
        self.assertEqual([s.family for s in self.sockets], [socket.AF_INET] * 2)
        self.assertEqual([s.kind for s in self.sockets], [socket.SOCK_STREAM] * 2)
        binds = [event for event in self.events if event[0] == "bind"]
        self.assertEqual(binds, [("bind", ("127.0.0.1", 0), 2)] * 2)
        self.assertTrue(all(s.closed and s.socket.fileno() == -1 for s in self.sockets))
        args = self.calls[0][0]
        flags = dict(zip(args[2:-2:2], args[3:-2:2]))
        self.assertEqual(set(flags), {"--base-url", "--listen", "--derp-url", "--derp-listen"})
        self.assertNotEqual(flags["--listen"], flags["--derp-listen"])
        for url, address in (("--base-url", "--listen"), ("--derp-url", "--derp-listen")):
            self.assertTrue(flags[address].startswith("127.0.0.1:"))
            self.assertNotEqual(flags[address].rsplit(":", 1)[1], "0")
            self.assertEqual(flags[url], "http://" + flags[address])

    def test_initial_reuse_update_rollback_and_new_B_keep_identical_flags(self):
        journey = self.journey()
        journey.mesh_original = journey.mesh_up(self.a[1])
        journey.verify_mesh()  # Initial repeat.
        journey.verify_mesh()  # Selected B reuses original A.
        journey.verify_mesh()  # Rollback A reuses original A.
        journey.mesh_down()
        self.selected = self.b[1]
        journey.mesh_up(self.b[1])  # Explicit owned stop followed by new B.
        ups = [args for args, unused in self.calls if args[:2] == ("mesh", "up")]
        self.assertEqual(len(ups), 5)
        expected = {"--base-url", "--listen", "--derp-url", "--derp-listen"}
        self.assertTrue(expected.issubset(ups[0]), "fixed defaults collide with existing listeners")
        self.assertTrue(all(args == ups[0] for args in ups), "selection/restart changed endpoints")
        self.assertEqual(len(self.sockets), 2, "reuse and new B must not allocate endpoints again")
        self.assertTrue(all(args[-2:] == ("--output", "json") for args in ups))

    def test_non_mesh_does_not_allocate_any_socket_or_call_cli(self):
        def forbidden(*unused):
            self.fail("non-mesh path allocated a socket")
        self.journey(mesh=False, factory=forbidden)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.sockets, [])

    def test_second_bind_failure_closes_both_sockets_and_never_calls_cli(self):
        def refusing(family, kind):
            return TrackedSocket(self.events, self.sockets, family, kind,
                                 fail_bind=len(self.sockets) == 1)
        with self.assertRaisesRegex(OSError, "synthetic second bind refusal"):
            self.journey(factory=refusing)
        self.assertEqual(len(self.sockets), 2)
        self.assertTrue(all(s.closed and s.socket.fileno() == -1 for s in self.sockets))
        self.assertEqual(self.parent_calls, [], "failed allocation started base Journey setup")
        self.assertEqual(self.calls, [])



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--source", type=Path, default=PRIMARY)
    parser.add_argument("--primary", type=Path, default=PRIMARY)
    options = parser.parse_args()
    unittest.main(argv=[sys.argv[0]], verbosity=2)
