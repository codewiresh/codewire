#!/usr/bin/env python3
"""Focused host update harness fixtures; never start CW or a helper.

CLI calls and process witnesses use synthetic substitutes. Real kernel work
is bounded loopback socket allocation and disposal of owned fixture files.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import stat
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


class ReleaseStoreCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cw-update-cleanup-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.dispose_fixture)
        self.module = load_candidate()
        self.journey = self.module.Journey.__new__(self.module.Journey)
        self.journey.root = self.root
        metadata = self.root.lstat()
        self.journey.disposable_root_identity = (metadata.st_dev, metadata.st_ino)
        self.journey.store = self.root / "store"
        self.versions = self.journey.store / "versions"
        self.versions.mkdir(parents=True, mode=0o755)
        self.journey.a = (self.root / "release-a", {"sha256": "a" * 64})
        self.journey.b = (self.root / "release-b", {"sha256": "b" * 64})
        for pin in ("a" * 64, "b" * 64):
            member = self.versions / pin
            member.mkdir(mode=0o700)
            (member / "cw").write_bytes(b"owned executable fixture")
            (member / "cw").chmod(0o555)
            (member / "identity.json").write_text("{}\n")
            (member / "identity.json").chmod(0o444)
            member.chmod(0o555)
        self.journey.workspace = self.root / "project"
        self.journey.workspace.mkdir(mode=0o700)
        (self.journey.workspace / "child.pid").write_text("synthetic\n")
        self.journey.environment = "synthetic-environment"
        self.journey.mesh_started = False
        self.journey.processes = []
        self.journey.mesh_processes = []
        self.calls, self.checks, self.sentinel_events = [], [], []
        self.journey.call = lambda *args, **unused: self.calls.append(args)
        self.journey.check = self.checks.append
        self.journey.sentinel = types.SimpleNamespace(
            terminate=lambda: self.sentinel_events.append("terminate"),
            wait=lambda timeout: self.sentinel_events.append(("wait", timeout)))

    def dispose_fixture(self):
        # Only these generated fixture members belong to this test.
        for pin in ("a" * 64, "b" * 64, "c" * 64):
            member = self.versions / pin
            if member.exists() and not member.is_symlink():
                member.chmod(0o700)
        self.temporary.cleanup()

    def assert_immutable(self):
        for pin in ("a" * 64, "b" * 64):
            member = self.versions / pin
            self.assertEqual(stat.S_IMODE(member.lstat().st_mode), 0o555)
            self.assertEqual((member / "cw").read_bytes(), b"owned executable fixture")

    def test_success_removes_actual_readonly_members_after_runtime_project_check(self):
        # The inherited cleanup used to fail here on an actual0555 directory.
        self.journey.cleanup()
        self.assertFalse(self.root.exists())
        self.assertEqual(self.calls, [("env", "rm", "--local", "synthetic-environment", "--yes")])
        self.assertEqual(self.checks, ["remove-runtime/preserve-project"])
        self.assertEqual(self.sentinel_events, ["terminate", ("wait", 5)])

    def test_failed_journey_preserves_readonly_members_and_project(self):
        self.journey.cleanup(preserve=True)
        self.assert_immutable()
        self.assertTrue((self.journey.workspace / "child.pid").exists())
        self.assertEqual(self.calls, [("env", "stop", "--local", "synthetic-environment")])
        self.assertEqual(self.checks, [])

    def test_invalid_second_member_never_changes_first_or_deletes_project(self):
        (self.versions / ("b" * 64)).chmod(0o700)
        with self.assertRaisesRegex(AssertionError, "unsafe disposable directory mode"):
            self.journey.cleanup()
        self.assertEqual(stat.S_IMODE((self.versions / ("a" * 64)).stat().st_mode), 0o555)
        self.assertTrue((self.journey.workspace / "child.pid").exists())

    def test_extra_member_and_live_actor_refuse_before_permission_changes(self):
        extra = self.versions / ("c" * 64)
        extra.mkdir(mode=0o555)
        with self.assertRaisesRegex(AssertionError, "unknown release member"):
            self.journey.cleanup()
        self.assert_immutable()
        extra.rmdir()
        reader, writer = os.pipe()
        self.addCleanup(os.close, reader)
        self.addCleanup(os.close, writer)
        # A nonready synthetic custody FD exercises the live-actor refusal;
        # this is not a pidfd or a process-continuity acceptance claim.
        self.journey.processes = [types.SimpleNamespace(fd=reader)]
        with self.assertRaisesRegex(AssertionError, "owned actor cleanup is unknown"):
            self.journey.cleanup()
        self.assert_immutable()
        self.assertTrue((self.journey.workspace / "child.pid").exists())

    def test_symlinked_member_never_changes_external_directory(self):
        member = self.versions / ("b" * 64)
        member.chmod(0o700)
        shutil.rmtree(member)
        foreign = tempfile.TemporaryDirectory(prefix="cw-update-unrelated-")
        self.addCleanup(foreign.cleanup)
        target = Path(foreign.name) / "readonly"
        target.mkdir(mode=0o555)
        self.addCleanup(target.chmod, 0o700)
        member.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            self.journey.cleanup()
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((self.versions / ("a" * 64)).stat().st_mode), 0o555)
        self.assertTrue((self.journey.workspace / "child.pid").exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--source", type=Path, default=PRIMARY)
    parser.add_argument("--primary", type=Path, default=PRIMARY)
    options = parser.parse_args()
    unittest.main(argv=[sys.argv[0]], verbosity=2)
