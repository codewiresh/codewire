#!/usr/bin/env python3
"""Observed macOS local VM journey (Program #2064, #1905 conditions).

Run on an Apple silicon Mac against a built cw and a runtime directory from
`make macos-local-runtime` (or scripts/dev/macos-local-runtime.py --pack):

  scripts/dev/test-cli-local-vm-macos.py --cw /abs/cw --runtime /abs/runtime-dir

It proves, on this Mac's macOS version:
- the runtime installs and a local VM is created, runs commands and reaches
  HTTP through the egress broker;
- `cw run -- true` stays within its latency budget (#2549);
- losing the packet worker or the egress broker fails the environment closed:
  `error` with its exit code, a guest probe loop fails from that moment, no
  process of the environment holds an internet socket, and stop/start
  restores egress (#1905 condition 3);
- a VM that stops running (as in host sleep) resumes with its clock repaired
  and a streaming session intact;
- the VZ helper holds no internet socket and is signed as the packer requires,
  and VZ's own VM process is sandboxed;
- removing the environment ends VZ's VM process.

Everything runs under a private root with its own HOME and a throwaway
keychain, as a new session leader. cw's sockets live in a short per-user
directory, not under HOME (#2735), so this HOME is longer than the 27 bytes
the old layout allowed, and env rm must leave no VM socket directory. At the
end no process of the journey may remain, by the same owned-family check as
test-cli-host.py. Needs network egress for the image pull and the HTTP probes.
"""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import statistics
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
packer = load("macos_local_runtime", "macos-local-runtime.py")
socket_dir = load("native_socket_dir", "native_socket_dir.py")

IMAGE = "docker.io/library/alpine:3.22"
NAME = "proof"
RUN_BUDGET_SECONDS = 1.0


def probe_loop(log):
    """A guest loop that numbers each HTTP probe and records its result."""
    return ('n=0; while :; do n=$((n+1)); '
            'if wget -q -T 2 -O /dev/null http://example.com; then c=200; else c=000; fi; '
            f'printf "%s %s\\n" "$n" "$c" >> /workspace/project/{log}; sleep 1; done')


class LocalVmJourney:
    def __init__(self, cw, runtime):
        # Before #2735 a socket lived under <HOME>/.codewire/native-v1, so
        # HOME could be at most 27 bytes. The credential authority's socket is
        # still under HOME (#2745), which holds this HOME under 64 bytes.
        self.root = Path(tempfile.mkdtemp(prefix="v", dir="/private/tmp"))
        self.home = self.root / "home-longer-than-the-old-limit"
        assert 27 < len(str(self.home)) < 64, self.home
        self.state_root = self.home / ".codewire/native-v1"
        self.project = self.root / "project"
        for directory in (self.home, self.project):
            directory.mkdir(mode=0o700)
        (self.project / "README").write_text("local VM journey\n")
        self.keychain = self.root / "journey.keychain-db"
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("CODEWIRE_", "CW_"))}
        self.env.update(HOME=str(self.home), CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN=str(self.keychain))
        self.cw = str(Path(cw).resolve())
        self.runtime = str(Path(runtime).resolve())
        self.environment_id = None
        self.created = False
        self.stopped_vm = None
        self.streams = []
        # Outlives any journey; a check fails if the journey's cleanup of its
        # own processes ever reaches it.
        self.sentinel = subprocess.Popen(["sleep", "86400"], start_new_session=True)

    def call(self, *args, ok=True, timeout=120):
        result = subprocess.run([self.cw, *args], env=self.env, cwd=self.project, stdin=subprocess.DEVNULL,
                                text=True, capture_output=True, timeout=timeout)
        if ok and result.returncode != 0:
            raise AssertionError(f"cw {args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
        return result

    def guest(self, command, ok=True, timeout=120):
        return self.call("run", NAME, "--no-tty", "--", "sh", "-c", command, ok=ok, timeout=timeout)

    def info(self):
        return json.loads(self.call("env", "--local", "info", NAME, "--output", "json").stdout)

    def check(self, label):
        assert self.sentinel.poll() is None, "unrelated process was killed"
        print(f"local-vm: {label} PASS", flush=True)

    def until(self, probe, predicate, timeout, what):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = probe()
            if predicate(value):
                return value
            time.sleep(0.5)
        raise AssertionError(f"{what} did not happen within {timeout} s")

    def role_pid(self, role):
        """The live process with this role for the environment, if any."""
        listed = subprocess.run(["/bin/ps", "-axww", "-o", "pid=", "-o", "command="],
                                capture_output=True, text=True, check=True).stdout
        needle = f" {role} --environment-id {self.environment_id}"
        for line in listed.splitlines():
            pid, _, command = line.strip().partition(" ")
            if needle in " " + command:
                return int(pid)
        return None

    def environment_pids(self):
        """This journey's processes plus the environment's VZ VM process."""
        pids = set(cli_host.owned_family(self.root))
        vm = self.vz_vm_pid()
        if vm:
            pids.add(vm)
        return pids

    def vz_vm_pid(self):
        listed = subprocess.run(["/usr/bin/pgrep", "-f", "com.apple.Virtualization.VirtualMachine"],
                                capture_output=True, text=True).stdout.split()
        for pid in listed:
            files = subprocess.run(["/usr/sbin/lsof", "-nP", "-p", pid], capture_output=True, text=True).stdout
            if self.environment_id in files:
                return int(pid)
        return None

    def internet_holders(self):
        holders = {}
        for pid in self.environment_pids():
            listed = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-i", "-p", str(pid)],
                                    capture_output=True, text=True).stdout.splitlines()[1:]
            if listed:
                holders[pid] = listed
        return holders

    def probe_rows(self, log):
        """(number, result) of each probe the guest loop has recorded."""
        path = self.project / log
        rows = [line.split() for line in path.read_text().splitlines()] if path.exists() else []
        return [(int(number), code) for number, code in rows]

    def run(self):
        subprocess.run(["/usr/bin/security", "create-keychain", "-p", "journey", str(self.keychain)], check=True)
        subprocess.run(["/usr/bin/security", "set-keychain-settings", str(self.keychain)], check=True)
        self.call("setup", "--local", "--from", self.runtime, timeout=600)
        self.check("runtime install")

        # A create that fails part way may still leave a VM; cleanup removes it.
        self.created = True
        self.call("env", "--local", "create", "--name", NAME, "--image", IMAGE, "--no-docker", "--yes", timeout=900)
        info = self.info()
        self.environment_id = info["id"]
        assert info["state"] == "running", info
        assert self.guest("uname -m").stdout.strip() == "aarch64"
        self.check("create and run")

        samples = []
        for _ in range(5):
            started = time.monotonic()
            self.call("run", NAME, "--no-tty", "--", "true")
            samples.append(time.monotonic() - started)
        median = statistics.median(samples)
        print(f"local-vm: cw run -- true median {median:.3f} s ({', '.join(f'{s:.3f}' for s in samples)})")
        assert median < RUN_BUDGET_SECONDS, f"cw run -- true took {median:.2f} s"
        self.check("run latency")

        self.guest("wget -q -T 10 -O /dev/null http://example.com")
        self.check("egress")

        for role, code in (("__native-network-worker", "network_worker_exit"),
                           ("__native-egress-broker", "egress_broker_exit")):
            self.prove_fail_closed(role, code)
        self.prove_stall()
        self.prove_posture()

    def prove_fail_closed(self, role, error_code):
        log = f"probe-{error_code}.log"
        self.call("run", NAME, "--detach", "--no-tty", "--", "sh", "-c", probe_loop(log))
        self.until(lambda: self.probe_rows(log), lambda rows: any(code == "200" for _, code in rows),
                   30, "the guest probe reaching HTTP")
        pid = self.role_pid(role)
        assert pid, f"no {role} process for the environment"
        os.kill(pid, signal.SIGKILL)
        # Probes the host had seen at the kill, plus the one then in flight,
        # which may have finished either way. Guest timestamps are not used:
        # the guest clock is not the host's.
        seen = max((number for number, _ in self.probe_rows(log)), default=0) + 1
        info = self.until(self.info, lambda value: value["state"] == "error", 30,
                          f"{role} loss turning the environment to error")
        assert info.get("error_code") == error_code, info
        after = self.until(lambda: [code for number, code in self.probe_rows(log) if number > seen],
                           lambda codes: len(codes) >= 3, 30, "three guest probes after the kill")
        assert all(code == "000" for code in after), f"probes after the kill: {after}"
        holders = self.internet_holders()
        assert not holders, f"processes hold internet sockets after {role} loss: {holders}"
        self.call("env", "--local", "stop", NAME, timeout=300)
        self.call("env", "--local", "start", NAME, timeout=600)
        assert self.info()["state"] == "running"
        self.guest("wget -q -T 10 -O /dev/null http://example.com")
        self.check(f"{role} loss fails closed and stop/start restores egress")

    def prove_stall(self):
        clock = ('while :; do printf "%s\\n" "$(date +%s)" >> /workspace/project/clock.log; sleep 1; done')
        self.call("run", NAME, "--detach", "--no-tty", "--", "sh", "-c", clock)
        stream = subprocess.Popen(
            [self.cw, "run", NAME, "--no-tty", "--", "sh", "-c",
             'for i in $(seq 1 40); do echo "tick $i"; sleep 1; done; echo done'],
            env=self.env, cwd=self.project, stdin=subprocess.DEVNULL, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.streams.append(stream)
        time.sleep(5)
        vm = self.vz_vm_pid()
        assert vm, "no VZ VM process for the environment"
        self.stopped_vm = vm
        os.kill(vm, signal.SIGSTOP)
        try:
            time.sleep(20)
        finally:
            os.kill(vm, signal.SIGCONT)
            self.stopped_vm = None
        resumed = time.time()

        def skew():
            lines = (self.project / "clock.log").read_text().split()
            return abs(time.time() - int(lines[-1])) if lines else 99
        self.until(skew, lambda value: value <= 2, 10, "the guest clock catching up after the stall")
        print(f"local-vm: guest clock within 2 s of the host {time.time() - resumed:.1f} s after resume")
        output, _ = stream.communicate(timeout=120)
        assert stream.returncode == 0 and output.count("tick ") == 40 and "done" in output, output
        self.check("stalled VM resumes with clock and session intact")

    def prove_posture(self):
        helper = None
        listed = subprocess.run(["/bin/ps", "-axww", "-o", "pid=", "-o", "command="],
                                capture_output=True, text=True, check=True).stdout
        for line in listed.splitlines():
            pid, _, command = line.strip().partition(" ")
            if " vm --config " in command and self.environment_id in command:
                helper = int(pid)
        assert helper, "no VZ helper process for the environment"
        vm = self.vz_vm_pid()
        assert vm, "no VZ VM process for the environment"
        for pid in (helper, vm):
            listed = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-i", "-p", str(pid)],
                                    capture_output=True, text=True).stdout.splitlines()[1:]
            assert not listed, f"{pid} holds internet sockets: {listed}"
        binary = Path(subprocess.run(["/bin/ps", "-o", "comm=", "-p", str(helper)],
                                     capture_output=True, text=True, check=True).stdout.strip())
        assert binary.is_file(), binary
        # The running helper is a thin arm64 executable with the hardened
        # runtime and exactly the developer entitlements, as the packer checks.
        packer.check_helper(binary)
        libsystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        libsystem.sandbox_check.restype = ctypes.c_int
        libsystem.sandbox_check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        assert libsystem.sandbox_check(vm, None, 0) != 0, "VZ's VM process is not sandboxed"
        self.check("helper posture")

    def remove_environment(self):
        self.call("env", "--local", "rm", NAME, "--yes", timeout=300)
        if self.environment_id:
            self.until(self.vz_vm_pid, lambda pid: pid is None, 30, "VZ's VM process ending after env rm")
            vms = socket_dir.predicted(self.state_root / "engine") / "vms"
            left = sorted(path.name for path in vms.iterdir()) if vms.exists() else []
            assert not left, f"VM socket directories remain after env rm: {left}"
            self.check("env rm ends the VM and removes its sockets")

    def reap(self):
        for pid in cli_host.owned_family(self.root):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        cli_host.reap_marked_family(self.root, timeout=30)

    def cleanup(self):
        """Run every cleanup step even when one fails; keep the root for
        diagnosis unless all of them succeeded."""
        errors = []

        def step(action):
            try:
                action()
            except Exception as error:  # noqa: BLE001 - report after the rest ran
                errors.append(error)

        if self.stopped_vm:
            step(lambda: os.kill(self.stopped_vm, signal.SIGCONT))
        for stream in self.streams:
            step(lambda stream=stream: (stream.kill(), stream.wait(timeout=10)))
        if self.created:
            step(self.remove_environment)
        step(self.reap)
        # The socket directories outlive the state root; nothing serves them
        # once the journey's processes are gone.
        for root in (self.state_root, self.state_root / "engine"):
            step(lambda root=root: shutil.rmtree(socket_dir.predicted(root), ignore_errors=True))
        if self.keychain.exists():
            step(lambda: subprocess.run(["/usr/bin/security", "delete-keychain", str(self.keychain)], check=True))
        step(lambda: (self.sentinel.kill(), self.sentinel.wait(timeout=10)))
        if errors:
            print(f"local-vm: journey root retained for diagnosis: {self.root}", file=sys.stderr)
            raise errors[0]
        for path in self.root.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)
        shutil.rmtree(self.root)


def main():
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        raise SystemExit("test-cli-local-vm-macos.py needs an Apple silicon Mac")
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cw", required=True)
    parser.add_argument("--runtime", required=True, help="a runtime directory packed for this cw")
    args = parser.parse_args()
    cli_host.arm_owned_session()
    journey = LocalVmJourney(args.cw, args.runtime)
    try:
        journey.run()
    finally:
        journey.cleanup()
    print("local-vm: all checks PASS")


if __name__ == "__main__":
    main()
