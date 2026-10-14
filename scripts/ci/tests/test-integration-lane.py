#!/usr/bin/env python3
"""integration-lane.py: one lane per port range, and only its own services (#2755)."""

import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
LANE = ROOT / "scripts/ci/verify/integration-lane.py"


def wait_for(condition, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.1)
    return False


class LaneLockTest(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="integration-lane-"))
        self.lock = self.work / "locks/ports-62000.lock"
        self.children = []

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait()
        subprocess.run(["rm", "-rf", str(self.work)], check=True)

    def holder(self, label):
        # The lane shell the lock follows: the helper holds the lock while it lives.
        parent = subprocess.Popen(["sleep", "300"])
        self.children.append(parent)
        ready = self.work / f"lane-{len(self.children)}.ready"
        helper = subprocess.Popen(
            [sys.executable, "-B", str(LANE), "lock", "--file", str(self.lock), "--parent", str(parent.pid),
             "--label", label, "--ready", str(ready)],
            stdout=subprocess.PIPE, text=True)
        self.children.append(helper)
        return parent, helper, ready

    def test_a_second_lane_waits_for_the_first_and_names_it(self):
        first_parent, first, first_ready = self.holder("database in /worktrees/first")
        self.assertTrue(wait_for(first_ready.exists), "the first lane did not take the lock")
        second_parent, second, second_ready = self.holder("database in /worktrees/second")
        line = second.stdout.readline()
        self.assertIn(f"waiting for the integration lane lock {self.lock}, held by database in /worktrees/first", line)
        time.sleep(1)
        self.assertFalse(second_ready.exists(), "the second lane ran beside the first")
        # The first lane's shell exits: its helper releases the range.
        first_parent.kill()
        first_parent.wait()
        self.assertTrue(wait_for(second_ready.exists), "the second lane never acquired the lock")
        self.assertIn("acquired", second.stdout.readline())
        self.assertTrue(wait_for(lambda: first.poll() is not None), "the first helper outlived its lane")
        self.assertIn("database in /worktrees/second", (self.work / "locks/ports-62000.lock.holder").read_text())
        second_parent.kill()

    def test_the_lock_is_not_inherited_by_the_lanes_children(self):
        parent, helper, ready = self.holder("services-runtime in /worktrees/first")
        self.assertTrue(wait_for(ready.exists))
        # A long-lived child of the lane (a compiler-cache server, say) holds
        # no copy of the lock, so ending the lane frees the range at once.
        fds = {os.readlink(f"/proc/{helper.pid}/fd/{fd}") for fd in os.listdir(f"/proc/{helper.pid}/fd")}
        self.assertIn(str(self.lock), fds)
        probe = subprocess.run(
            [sys.executable, "-c", "import fcntl,os,sys; fd=os.open(sys.argv[1], os.O_RDWR);"
             "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)", str(self.lock)],
            capture_output=True)
        self.assertNotEqual(probe.returncode, 0, "the range was free while a lane held it")
        parent.kill()
        parent.wait()
        self.assertTrue(wait_for(lambda: helper.poll() is not None))
        probe = subprocess.run(
            [sys.executable, "-c", "import fcntl,os,sys; fd=os.open(sys.argv[1], os.O_RDWR);"
             "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)", str(self.lock)],
            capture_output=True)
        self.assertEqual(probe.returncode, 0, probe.stderr)


class OwnerTest(unittest.TestCase):
    def serve(self, token):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        environment = {key: value for key, value in os.environ.items() if key != "CODEWIRE_INTEGRATION_RUN_ID"}
        if token:
            environment["CODEWIRE_INTEGRATION_RUN_ID"] = token
        server = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
            env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=tempfile.gettempdir())
        self.addCleanup(lambda: (server.kill(), server.wait()))

        def listening():
            with socket.socket() as client:
                return client.connect_ex(("127.0.0.1", port)) == 0
        self.assertTrue(wait_for(listening))
        return port

    def owner(self, port, token):
        return subprocess.run([sys.executable, "-B", str(LANE), "owner", "--name", "orchestration",
                               "--port", str(port), "--token", token], capture_output=True, text=True)

    def test_only_this_runs_service_is_accepted(self):
        port = self.serve("a" * 32)
        self.assertEqual(self.owner(port, "a" * 32).returncode, 0)
        refused = self.owner(port, "b" * 32)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn(f"port {port} is served by", refused.stderr)
        self.assertIn("not this run's orchestration", refused.stderr)

    def test_a_service_without_any_token_is_refused(self):
        port = self.serve(None)
        self.assertNotEqual(self.owner(port, "a" * 32).returncode, 0)

    def test_nothing_listening_is_refused(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        result = self.owner(port, "a" * 32)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nothing listens", result.stderr)


if __name__ == "__main__":
    result = unittest.main(argv=[sys.argv[0], "-v"], exit=False).result
    print(f"test-integration-lane: tests={result.testsRun} failures={len(result.failures)} "
          f"errors={len(result.errors)}")
    sys.exit(0 if result.wasSuccessful() and result.testsRun > 0 else 1)
