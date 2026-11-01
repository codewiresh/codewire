#!/usr/bin/env python3
"""Observed local Mesh journey, the same on Linux and macOS (#3797).

Run with a built cw and a local runtime directory packed for it:

  scripts/dev/test-cli-local-mesh.py --cw /abs/cw --runtime /abs/runtime-dir [--image REF]

It proves, from one cw:
- `cw mesh up` serves the Mesh and its DERP relay from cw itself
  (`cw __local-mesh`, which owns `cw __local-derp`), not separate programs;
- a network created there and selected for new environments is the network a
  new local VM joins (`local:<network>`);
- `cw mesh down` stops both, and the VM reports `mesh_transport_exit`; after
  `cw mesh up`, `cw --local daemon repair` brings it back on its network;
- a killed Mesh owner takes its relay with it; `cw mesh up` refuses its stale
  record, and `cw mesh down` clears it without signalling anything.

Everything runs under a private root with its own HOME and the file credential
store, as the owner of its process family: a subreaper on Linux, a new session
on macOS (test-cli-host.py). At the end no process of the journey may remain.
The image pull needs network egress. On Linux the root follows TMPDIR, which
must hold the VM's disks: about 9 GB with the pinned workspace image, more than
a typical /tmp tmpfs has free.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cli_host = load("cli_host", "test-cli-host.py")

NAME = "mesh-proof"
NETWORK = "mesh-journey"


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def command_of(pid):
    result = subprocess.run(["/bin/ps", "-ww", "-o", "command=", "-p", str(pid)],
                            capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def alive(pid):
    if cli_host.MACOS:
        return cli_host.Darwin().live(pid)
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            state = handle.read().rsplit(b")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return state not in (b"Z", b"X")


class MeshJourney:
    def __init__(self, cw, runtime, image):
        parent = "/private/tmp" if cli_host.MACOS else None
        self.root = Path(tempfile.mkdtemp(prefix="m", dir=parent))
        self.home = self.root / "home"
        self.project = self.root / "project"
        for directory in (self.home, self.project, self.home / ".codewire"):
            directory.mkdir(mode=0o700)
        (self.project / "README").write_text("local Mesh journey\n")
        config = self.home / ".codewire/config.toml"
        config.write_text('local_credential_store = "file"\n')
        config.chmod(0o600)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("CODEWIRE_", "CW_"))}
        self.env["HOME"] = str(self.home)
        self.cw = str(Path(cw).resolve())
        self.runtime = str(Path(runtime).resolve())
        self.image = image
        mesh, derp = free_port(), free_port()
        self.up_args = ["mesh", "up", "--listen", f"127.0.0.1:{mesh}", "--base-url", f"http://127.0.0.1:{mesh}",
                        "--derp-listen", f"127.0.0.1:{derp}", "--derp-url", f"http://127.0.0.1:{derp}",
                        "--output", "json"]
        self.created = False
        self.mesh_up = False

    def call(self, *args, ok=True, timeout=120):
        result = subprocess.run([self.cw, *args], env=self.env, cwd=self.project, stdin=subprocess.DEVNULL,
                                text=True, capture_output=True, timeout=timeout)
        if ok and result.returncode != 0:
            raise AssertionError(f"cw {args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
        return result

    def json(self, *args, timeout=120):
        return json.loads(self.call(*args, timeout=timeout).stdout)

    def check(self, label):
        print(f"local-mesh: {label} PASS", flush=True)

    def until(self, probe, predicate, timeout, what):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = probe()
            if predicate(value):
                return value
            time.sleep(0.5)
        raise AssertionError(f"{what} did not happen within {timeout} s")

    def info(self):
        return self.json("--local", "info", NAME, "--output", "json")

    def start_mesh(self):
        started = self.json(*self.up_args, timeout=180)
        self.mesh_up = True
        assert started["started"] is True, started
        owner, relay = started["pid"], started["derp"]["pid"]
        # The service and its relay are this cw, not separate programs (#3794).
        for pid, role in ((owner, "__local-mesh"), (relay, "__local-derp")):
            assert (command_of(pid) or "").split()[:2] == [self.cw, role], (pid, command_of(pid))
        status = self.json("mesh", "status", "--output", "json")
        assert status["local"]["state"] == "running", status
        assert status["local"]["derp"]["state"] == "running", status
        return owner, relay

    def run(self):
        self.call("setup", "--local", "--from", self.runtime, timeout=900)
        self.check("runtime install")

        owner, relay = self.start_mesh()
        self.check("mesh up runs the Mesh and DERP from cw")

        organization = json.loads((self.home / ".codewire/mesh_owner.json").read_text())["organization_id"]
        self.call("--local", "network", "create", NETWORK, "--org", organization)
        self.call("--local", "network", "use", NETWORK, "--auto-connect")
        status = self.json("mesh", "status", "--output", "json")
        assert status["selected_network"] == NETWORK and status["auto_connect"] is True, status
        self.check("network created and selected")

        # A create that fails part way may still leave a VM; cleanup removes it.
        self.created = True
        image = ["--image", self.image] if self.image else []
        created = self.json("--local", "create", "--name", NAME, *image, "--no-docker", "--yes",
                            "--output", "json", timeout=1500)
        assert created["network"] == NETWORK, created
        info = self.info()
        assert info["state"] == "running" and info["network"] == NETWORK, info
        self.check("a new local VM joins local:" + NETWORK)

        stopped = self.json("mesh", "down", "--output", "json")
        self.mesh_up = False
        assert stopped["stopped"] is True and stopped["state"] == "stopped", stopped
        for pid in (owner, relay):
            self.until(lambda pid=pid: alive(pid), lambda live: not live, 10, f"process {pid} ending")
        info = self.until(self.info, lambda info: info["state"] == "error", 120, "the VM reporting Mesh loss")
        assert info.get("error_code") == "mesh_transport_exit" and info["network"] == NETWORK, info
        self.check("mesh down stops both; the VM reports mesh_transport_exit")

        owner, relay = self.start_mesh()
        repaired = self.json("--local", "daemon", "repair", NAME, "--output", "json", timeout=300)
        assert repaired["status"]["state"] == "ready", repaired
        info = self.info()
        assert info["state"] == "running" and info["network"] == NETWORK and "error_code" not in info, info
        self.check("mesh up and daemon repair bring the VM back on its network")

        # A crash: kill the owner this journey just started and observed.
        os.kill(owner, signal.SIGKILL)
        self.until(lambda: alive(owner), lambda live: not live, 10, "the killed owner exiting")
        self.until(lambda: alive(relay), lambda live: not live, 10, "its DERP relay ending with it")
        refused = self.call(*self.up_args, ok=False, timeout=180)
        assert refused.returncode != 0 and "cw mesh down" in refused.stderr, refused.stderr
        cleared = self.json("mesh", "down", "--output", "json")
        self.mesh_up = False
        assert cleared["stopped"] is False and cleared["state"] == "stale", cleared
        self.check("a killed owner takes its relay; its stale record is cleared without a signal")

    def reap(self):
        """End the processes this journey owns, such as the local supervisor,
        and require them gone."""
        if cli_host.MACOS:
            owned = list(cli_host.owned_family(self.root))
        else:
            owned = cli_host.linux_children(os.getpid())
        for pid in owned:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        if cli_host.MACOS:
            cli_host.reap_marked_family(self.root, timeout=30)
        else:
            cli_host.reap_owned_family(timeout=30)

    def cleanup(self):
        """Run every cleanup step even when one fails; keep the root for
        diagnosis unless all of them succeeded."""
        errors = []

        def step(action):
            try:
                action()
            except Exception as error:  # noqa: BLE001 - report after the rest ran
                errors.append(error)

        if self.created:
            step(lambda: self.call("--local", "rm", NAME, "--yes", timeout=300))
        if self.mesh_up:
            step(lambda: self.call("mesh", "down", "--output", "json"))
        step(self.reap)
        if errors:
            print(f"local-mesh: journey root retained for diagnosis: {self.root}", file=sys.stderr)
            raise errors[0]
        for path in self.root.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)
        shutil.rmtree(self.root)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cw", required=True)
    parser.add_argument("--runtime", required=True, help="a runtime directory packed for this cw")
    parser.add_argument("--image", help="the VM image (default: the pinned workspace image)")
    args = parser.parse_args()
    if cli_host.MACOS:
        cli_host.arm_owned_session()
    elif cli_host.LINUX:
        cli_host.arm_owned_family()
    else:
        parser.error("the local Mesh journey runs on Linux and macOS")
    journey = MeshJourney(args.cw, args.runtime, args.image)
    try:
        journey.run()
    finally:
        journey.cleanup()
    print("local-mesh: all checks PASS")


if __name__ == "__main__":
    main()
