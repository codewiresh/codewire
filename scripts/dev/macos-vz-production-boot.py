#!/usr/bin/env python3
"""Explicit production-init VZ developer fixture; not product or confinement proof.

Only the pinned Rust verifier interprets the real seed, progress, daemon and
network protocols and proves the fixed synthetic guest workloads. This parent
requires separate readiness and workload success before owned shutdown. It
owns artifact admission, private descriptor
transport, bounded child lifetimes and cleanup. It never prints child output.

The nominal 240-second budget reserves 230 seconds for active work and two
5-second owned-process shutdown polls. The active alarm interrupts blocking
I/O, but is masked during ownership-critical process creation. OS calls in
that creation window or filesystem cleanup can stall: this is not a hard
real-time overall deadline. PASS still requires owned quiescence and cleanup.
"""

from __future__ import annotations

import argparse
import array
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid


_spec = importlib.util.spec_from_file_location(
    "vz_artifact_admission", Path(__file__).with_name("macos-vz-inode-probe.py")
)
assert _spec and _spec.loader
artifact = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(artifact)

DEADLINE_SECONDS = 240
STOP_SECONDS = 5
MIN_DISK_BYTES = 256 * artifact.MIB
DISK_ALIGNMENT = artifact.MIB
CODESIGN = "/usr/bin/codesign"
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
OWNED_SIGNALS = (*SIGNALS, signal.SIGALRM)
MAX_LOG_BYTES = 64 * 1024
SUCCESS = (
    "macOS VZ production-init fixture: PASS production_init=true "
    "transient_exec=true session_lifecycle=true "
    "owned_kill=true private_cleanup=true confinement=false "
    "egress_mediation=false parity=false"
)
CONNECTED = {
    "network-connected": b"N",
    "progress-connected": b"P",
    "daemon-connected": b"D",
}
RESULTS = frozenset({"descriptors-admitted", "progress-closed", *CONNECTED})


class FixtureFailure(Exception):
    """No external text is included in public diagnostics."""


class Interrupted(BaseException):
    def __init__(self, signum: int):
        self.signum = signum


def require_host() -> None:
    if (
        platform.system() != "Darwin"
        or platform.machine() != "arm64"
        or int(platform.mac_ver()[0].split(".")[0]) < 26
    ):
        raise FixtureFailure()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def decode_result(payload: bytes) -> str:
    # Exact encoding rejects extra fields, duplicate keys, booleans as versions,
    # alternate schemas and all private-probe readiness markers.
    for result in RESULTS:
        if payload == canonical({"result": result, "schemaVersion": 2}):
            return result
    raise FixtureFailure()


class Frames:
    def __init__(self) -> None:
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[str]:
        self.buffer.extend(data)
        results = []
        while len(self.buffer) >= 4:
            size = struct.unpack(">I", self.buffer[:4])[0]
            if not 0 < size <= 256:
                raise FixtureFailure()
            if len(self.buffer) < size + 4:
                break
            results.append(decode_result(bytes(self.buffer[4 : size + 4])))
            del self.buffer[: size + 4]
        return results


def group_absent(process: subprocess.Popen) -> bool:
    # Reap the leader before checking: a zombie leader is still a group member.
    # After reap this numeric group may be unrelated. Observation is safe, but
    # a visible group must never authorize a later mutating signal.
    process.poll()
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


class Run:
    def __init__(self) -> None:
        # Reserve both bounded shutdown polls within the nominal budget. The
        # active alarm interrupts I/O; creation/cleanup syscall caveats are in
        # the module contract, not an assertion of hard real-time execution.
        self.deadline = time.monotonic() + DEADLINE_SECONDS - 2 * STOP_SECONDS
        self.phase = "admission"
        self.directory: Path | None = None
        self.children: list[subprocess.Popen] = []
        self.sockets: list[socket.socket] = []
        self.fds: list[int] = []
        self.logs: dict[subprocess.Popen, tuple[int, int]] = {}
        self.log_bytes: dict[subprocess.Popen, int] = {}
        self.cleaned = False
        self.cancelled = 0
        self.expired = False
        self.alarm_raised = False
        self.finishing = False
        self.committed = False

    def signal(self, signum: int, _frame: object) -> None:
        # Cancellation never raises asynchronously. The one-shot deadline must
        # interrupt blocking I/O (PEP 475 would otherwise retry it); latch the
        # exception before raising so repeated alarms cannot escape cleanup.
        if self.committed:
            return
        if signum == signal.SIGALRM:
            self.expired = True
            if not self.finishing and not self.alarm_raised:
                self.alarm_raised = True
                raise FixtureFailure()
        elif not self.cancelled:
            self.cancelled = signum

    def remaining(self) -> float:
        if self.cancelled:
            raise Interrupted(self.cancelled)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.expired:
            raise FixtureFailure()
        return remaining

    def open(self, path: Path, flags: int) -> int:
        descriptor = os.open(path, flags | os.O_NOFOLLOW, 0o600)
        self.fds.append(descriptor)
        return descriptor

    def pair(self) -> tuple[socket.socket, socket.socket]:
        pair = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sockets.extend(pair)
        return pair

    def close_fd(self, descriptor: int) -> None:
        os.close(descriptor)
        self.fds.remove(descriptor)

    def copy(self, source_fd: int, destination: Path, size: int) -> None:
        target_fd = self.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            copied = 0
            while copied < size:
                self.remaining()
                chunk = os.read(source_fd, min(artifact.MIB, size - copied))
                if not chunk:
                    raise FixtureFailure()
                copied += len(chunk)
                view = memoryview(chunk)
                while view:
                    count = os.write(target_fd, view)
                    if count <= 0:
                        raise FixtureFailure()
                    view = view[count:]
            if os.read(source_fd, 1) or os.fstat(source_fd).st_size != size:
                raise FixtureFailure()
            os.fsync(target_fd)
        finally:
            self.close_fd(target_fd)

    def digest(self, path: Path) -> str:
        descriptor = self.open(path, os.O_RDONLY)
        checksum = hashlib.sha256()
        try:
            while True:
                self.remaining()
                chunk = os.read(descriptor, artifact.MIB)
                if not chunk:
                    return checksum.hexdigest()
                checksum.update(chunk)
        finally:
            self.close_fd(descriptor)

    def spawn(self, argv: list[str], descriptors: tuple[int, ...] = ()) -> subprocess.Popen:
        self.remaining()
        assert self.directory is not None
        log = self.directory / f"child-{len(self.children)}.log"
        output = self.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(self.directory),
            "TMPDIR": str(self.directory),
            "LC_ALL": "C",
        }
        # The process must be recorded before a pending cancellation can run.
        # This program is single-threaded. Restore the child's mask/default
        # dispositions before exec, rather than leaking the parent's block.
        # A stalled Popen handshake in this critical window is not covered by
        # the active alarm; losing ownership would be the unsafe alternative.
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, OWNED_SIGNALS)

        def child_signals() -> None:
            for signum in OWNED_SIGNALS:
                signal.signal(signum, signal.SIG_DFL)
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

        try:
            process = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=environment, cwd=self.directory, close_fds=True,
                pass_fds=descriptors, start_new_session=True,
                preexec_fn=child_signals,
            )
            self.children.append(process)
            assert process.stdout is not None
            os.set_blocking(process.stdout.fileno(), False)
            self.logs[process] = (process.stdout.fileno(), output)
            self.log_bytes[process] = 0
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        self.remaining()
        return process

    def drain_logs(self) -> None:
        # Unlike RLIMIT_FSIZE, bounded pipes do not cap VZ's legitimate writes
        # to large mutable disk images. Before draining, kernel backpressure
        # bounds each child's output. Never write more than the fixed log cap.
        for process, (pipe, output) in list(self.logs.items()):
            self.remaining()
            try:
                chunk = os.read(pipe, MAX_LOG_BYTES + 1 - self.log_bytes[process])
            except BlockingIOError:
                continue
            if not chunk:
                assert process.stdout is not None
                process.stdout.close()
                self.close_fd(output)
                del self.logs[process]
                continue
            if self.log_bytes[process] + len(chunk) > MAX_LOG_BYTES:
                raise FixtureFailure()
            view = memoryview(chunk)
            while view:
                count = os.write(output, view)
                if count <= 0:
                    raise FixtureFailure()
                view = view[count:]
            self.log_bytes[process] += len(chunk)

    def wait(self, process: subprocess.Popen) -> None:
        while process.poll() is None or process in self.logs:
            self.drain_logs()
            time.sleep(min(0.02, self.remaining()))
        if process.returncode != 0 or not group_absent(process):
            raise FixtureFailure()

    def child_output(self, index: int) -> bytes:
        assert self.directory is not None
        path = self.directory / f"child-{index}.log"
        with path.open("rb") as stream:
            result = stream.read(64 * 1024 + 1)
        if len(result) > 64 * 1024:
            raise FixtureFailure()
        return result

    def signing(self, helper: Path) -> None:
        self.phase = "signing"
        self.wait(self.spawn([CODESIGN, "--verify", "--strict", str(helper)]))
        index = len(self.children)
        self.wait(self.spawn([CODESIGN, "-d", "--verbose=4", str(helper)]))
        if b"Signature=adhoc" not in self.child_output(index).splitlines():
            raise FixtureFailure()
        index = len(self.children)
        self.wait(self.spawn([CODESIGN, "-d", "--entitlements", ":-", str(helper)]))
        output = self.child_output(index)
        offset = output.find(b"<?xml")
        if offset < 0:
            raise FixtureFailure()
        entitlements = plistlib.loads(output[offset:])
        if (
            not isinstance(entitlements, dict)
            or set(entitlements) != {"com.apple.security.virtualization"}
            or entitlements["com.apple.security.virtualization"] is not True
        ):
            raise FixtureFailure()

    def cleanup(self) -> bool:
        # Do not erase evidence/artifacts until every owned process group has
        # disappeared. No subprocess output is read or published on this path.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for process in reversed(self.children):
                # Only this single-threaded parent reaps its retained children.
                # With default SIGCHLD, exit after this poll leaves a zombie
                # pinning the PID until our next poll. Never signal after reap,
                # even if that numeric group remains visible: ownership is lost.
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, sig)
                    except ProcessLookupError:
                        pass
            stop = time.monotonic() + STOP_SECONDS
            while any(not group_absent(p) for p in self.children) and time.monotonic() < stop:
                # After a cap failure, keep draining/discarding until stopped:
                # a child flushing output on TERM must not block on its pipe.
                self.discard_logs()
                time.sleep(0.02)
        stopped = all(group_absent(p) for p in self.children)
        for process in self.children:
            if process.stdout is not None:
                process.stdout.close()
        self.logs.clear()
        for stream in self.sockets:
            stream.close()
        for descriptor in self.fds:
            os.close(descriptor)
        self.fds.clear()
        if stopped and self.directory is not None:
            shutil.rmtree(self.directory)
            self.directory = None
        self.cleaned = stopped and self.directory is None
        return self.cleaned

    def discard_logs(self) -> None:
        for pipe, _output in self.logs.values():
            try:
                os.read(pipe, MAX_LOG_BYTES)
            except (BlockingIOError, OSError):
                pass


def prepare(run: Run, args: argparse.Namespace) -> tuple[dict, dict[str, Path]]:
    paths = {}
    sources = {}
    identities = set()
    for name in ("helper", "fixture", "kernel", "initramfs", "setup", "state", "root"):
        run.remaining()
        source = Path(getattr(args, name))
        if not source.is_absolute():
            raise FixtureFailure()
        descriptor = run.open(source, os.O_RDONLY | os.O_NONBLOCK)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode) or status.st_size <= 0
            or status.st_uid != os.geteuid() or status.st_nlink != 1
            or stat.S_IMODE(status.st_mode) & 0o7077
            or not status.st_mode & stat.S_IRUSR
        ):
            raise FixtureFailure()
        identity = (status.st_dev, status.st_ino)
        if identity in identities:
            raise FixtureFailure()
        identities.add(identity)
        if name in {"state", "root"}:
            if not MIN_DISK_BYTES <= status.st_size <= 1024**4 or status.st_size % DISK_ALIGNMENT:
                raise FixtureFailure()
        elif name == "setup":
            if not 64 * 1024 <= status.st_size <= 65 * 1024**3 or status.st_size % 4096:
                raise FixtureFailure()
        elif status.st_size > (4 if name == "initramfs" else 1) * 1024**3:
            raise FixtureFailure()
        sources[name] = (descriptor, status.st_size)
    expected = {
        name: artifact.exact_sha256(getattr(args, f"{name}_sha256"), name)
        for name in ("helper", "fixture", "kernel", "initramfs", "setup")
    }
    disk_ids = {name: artifact.exact_uuid(getattr(args, f"{name}_uuid"), name) for name in ("state", "root")}
    if disk_ids["state"] == disk_ids["root"]:
        raise FixtureFailure()
    run.directory = Path(tempfile.mkdtemp(prefix="codewire-vz-production-"))
    run.directory.chmod(0o700)
    for name, (descriptor, size) in sources.items():
        target = run.directory / name
        # Copy the already-admitted inode, never reopen the caller's pathname.
        run.copy(descriptor, target, size)
        run.close_fd(descriptor)
        paths[name] = target
        if name in expected and run.digest(target) != expected[name]:
            raise FixtureFailure()
        if name in disk_ids and artifact.ext4_uuid(target) != disk_ids[name]:
            raise FixtureFailure()
        if name in {"helper", "fixture"}:
            target.chmod(0o700)
        mode = 0o700 if name in {"helper", "fixture"} else 0o600
        status = target.stat()
        if stat.S_IMODE(status.st_mode) != mode or status.st_uid != os.geteuid() or status.st_nlink != 1:
            raise FixtureFailure()
    run.signing(paths["helper"])
    run.phase = "seed"
    vm_id = str(uuid.uuid4())
    seed = run.directory / "seed"
    setup_fd = run.open(paths["setup"], os.O_RDONLY)
    seed_fd = run.open(seed, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    run.wait(run.spawn([
        str(paths["fixture"]), "seed", "--setup-fd", str(setup_fd),
        "--output-fd", str(seed_fd), "--vm-id", vm_id, "--generation", "1",
    ], (setup_fd, seed_fd)))
    run.close_fd(seed_fd)
    run.close_fd(setup_fd)
    if seed.stat().st_size != artifact.SEED_BYTES:
        raise FixtureFailure()
    paths["seed"] = seed
    immutable = lambda name: {"size": paths[name].stat().st_size, "sha256": run.digest(paths[name])}
    config = {
        "schemaVersion": 2, "vmID": vm_id, "generation": 1,
        "cpuCount": 2, "memoryMiB": 2048, "daemonVsockPort": 7777,
        "kernel": immutable("kernel"), "initialRamdisk": immutable("initramfs"),
        "seedDisk": immutable("seed"), "setupDisk": immutable("setup"),
        "stateDisk": {"size": paths["state"].stat().st_size, "filesystemUUID": disk_ids["state"]},
        "rootDisk": {"size": paths["root"].stat().st_size, "filesystemUUID": disk_ids["root"]},
    }
    return config, paths


def boot(run: Run, config: dict, paths: dict[str, Path]) -> None:
    run.phase = "boot"
    helper_control, helper_child = run.pair()
    rust_control, rust_child = run.pair()
    channels = [run.pair() for _ in range(3)]
    seed_fd = run.open(paths["seed"], os.O_RDONLY)
    rust_fds = tuple(pair[0].fileno() for pair in channels) + (rust_child.fileno(), seed_fd)
    keys = ("network", "progress", "daemon", "control", "seed")
    command = [str(paths["fixture"]), "verify"]
    for key, descriptor in zip(keys, rust_fds):
        command.extend([f"--{key}-fd", str(descriptor)])
    verifier = run.spawn(command, rust_fds)
    rust_child.close()
    run.close_fd(seed_fd)
    helper = run.spawn([
        str(paths["helper"]), "production-init-fixture", "--control-fd", str(helper_child.fileno()),
    ], (helper_child.fileno(),))
    helper_child.close()
    file_fds = [
        run.open(paths[name], os.O_RDWR if name in {"state", "root"} else os.O_RDONLY)
        for name in ("kernel", "initramfs", "seed", "state", "root", "setup")
    ]
    request = artifact.framed(canonical(config))
    descriptors = array.array("i", file_fds + [pair[1].fileno() for pair in channels])
    helper_control.settimeout(run.remaining())
    sent = helper_control.sendmsg([request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)])
    if sent <= 0:
        raise FixtureFailure()
    helper_control.sendall(request[sent:])
    helper_control.setblocking(False)
    rust_control.setblocking(False)
    frames = Frames()
    seen: set[str] = set()
    ready = workload_complete = requested_kill = killed = closed = False
    helper_eof = rust_eof = False
    while True:
        run.drain_logs()
        active = ([helper_control] if not helper_eof else []) + ([rust_control] if not rust_eof else [])
        readable, _, _ = select.select(active, [], [], min(0.1, run.remaining()))
        for stream in readable:
            data = stream.recv(4096)
            if stream is helper_control:
                if not data:
                    if not killed or frames.buffer:
                        raise FixtureFailure()
                    helper_eof = True
                    continue
                for marker in frames.feed(data):
                    if marker in seen or killed:
                        raise FixtureFailure()
                    if marker == "descriptors-admitted":
                        if seen:
                            raise FixtureFailure()
                        for descriptor in file_fds:
                            run.close_fd(descriptor)
                        for pair in channels:
                            pair[1].close()
                        helper_control.sendall(artifact.framed(b"\x01"))
                    elif "descriptors-admitted" not in seen:
                        raise FixtureFailure()
                    elif marker in CONNECTED:
                        rust_control.sendall(CONNECTED[marker])
                    elif marker == "progress-closed" and "progress-connected" not in seen:
                        raise FixtureFailure()
                    seen.add(marker)
            else:
                if not data:
                    if not closed:
                        raise FixtureFailure()
                    rust_eof = True
                    continue
                for marker in data:
                    if marker == ord("R") and not ready and set(CONNECTED).issubset(seen):
                        ready = True
                        run.phase = "guest-workload"
                    elif marker == ord("W") and ready and not workload_complete and not requested_kill:
                        workload_complete = True
                    elif marker == ord("A") and requested_kill and not killed:
                        if helper.poll() is not None:
                            raise FixtureFailure()
                        os.kill(helper.pid, signal.SIGKILL)
                        killed = True
                        run.phase = "owned-stop"
                    elif marker == ord("C") and killed and not closed:
                        closed = True
                    else:
                        raise FixtureFailure()
        if ready and workload_complete and "progress-closed" in seen and not requested_kill:
            rust_control.sendall(b"K")
            requested_kill = True
        helper_status, rust_status = helper.poll(), verifier.poll()
        if helper_status is not None and (not killed or helper_status != -signal.SIGKILL):
            raise FixtureFailure()
        if rust_status is not None and rust_status != 0:
            raise FixtureFailure()
        if killed and closed and helper_eof and rust_eof and helper_status is not None and rust_status == 0:
            if run.logs:
                continue
            if not group_absent(helper) or not group_absent(verifier):
                raise FixtureFailure()
            # Keep all parent channel endpoints (especially progress) until
            # owned shutdown. A terminal progress EOF is not parent teardown.
            return


class PrivateParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise FixtureFailure()


def parser() -> argparse.ArgumentParser:
    result = PrivateParser(description=__doc__, allow_abbrev=False)
    for name in ("helper", "fixture", "kernel", "initramfs", "setup"):
        result.add_argument(f"--{name}", required=True)
        result.add_argument(f"--{name}-sha256", required=True)
    for name in ("state", "root"):
        result.add_argument(f"--{name}", required=True)
        result.add_argument(f"--{name}-uuid", required=True)
    return result


def finalize(run: Run, result: int, prior_umask: int) -> int:
    run.finishing = True
    # main's outer guard catches the single deadline exception even if it
    # arrives immediately before the assignment above. Subsequent alarms only
    # record failure; once here they are also blocked and the timer disarmed.
    signal.pthread_sigmask(signal.SIG_BLOCK, (signal.SIGALRM,))
    signal.setitimer(signal.ITIMER_REAL, 0)
    try:
        if not result:
            run.phase = "cleanup"
        if not run.cleaned and not run.cleanup():
            result = result or 1
    except Exception:
        run.cleaned = False
        result = result or 1
    os.umask(prior_umask)
    return result


def main(argv: list[str] | None = None) -> int:
    run = Run()
    # This is a standalone process, not an embeddable signal/timer manager.
    # Never suspend or reschedule a caller's pre-existing interval timer.
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        print("macOS VZ production-init fixture: FAIL phase=admission private_retained=false", file=sys.stderr)
        return 1
    admission_mask = signal.pthread_sigmask(signal.SIG_BLOCK, OWNED_SIGNALS)
    if set(admission_mask).intersection(OWNED_SIGNALS):
        signal.pthread_sigmask(signal.SIG_SETMASK, admission_mask)
        print("macOS VZ production-init fixture: FAIL phase=admission private_retained=false", file=sys.stderr)
        return 1
    prior_umask = os.umask(0o077)
    result = 1
    try:
        try:
            # Actively clear inherited SIG_IGN/SA_NOCLDWAIT before any spawn.
            # Merely getsignal()==SIG_DFL does not establish zombie retention.
            # There are no competing child reapers or SIGCHLD handlers here.
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            for signum in OWNED_SIGNALS:
                signal.signal(signum, run.signal)
            signal.setitimer(signal.ITIMER_REAL, run.remaining())
            signal.pthread_sigmask(signal.SIG_SETMASK, admission_mask)
            args = parser().parse_args(argv)
            require_host()
            config, paths = prepare(run, args)
            boot(run, config, paths)
            result = 0
        except Interrupted as error:
            result = 128 + error.signum
        except (Exception, KeyboardInterrupt):
            # No child bytes, paths, exception strings or argument values are
            # public output, including parser and filesystem failures.
            result = 1
        finally:
            result = finalize(run, result, prior_umask)
    except FixtureFailure:
        # Single alarm at the finalizer-entry boundary. The handler latched it
        # already, so another alarm cannot interrupt this idempotent retry.
        result = finalize(run, 1, prior_umask)
    # Commit the single receipt only after cleanup. The single pending-signal
    # snapshot below is the irrevocable decision boundary: recorded or pending
    # signals invalidate success; signals arriving after that snapshot do not.
    # These standalone handlers remain until process exit.
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, OWNED_SIGNALS)
    try:
        pending = signal.sigpending()
        for signum in OWNED_SIGNALS:
            if signum in pending:
                run.signal(signum, None)
        if run.cancelled:
            result = 128 + run.cancelled
        elif run.expired:
            result = result or 1
        run.committed = True
        if result:
            retained = "false" if run.cleaned else "true"
            print(f"macOS VZ production-init fixture: FAIL phase={run.phase} private_retained={retained}", file=sys.stderr)
        else:
            print(SUCCESS, flush=True)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    return result


if __name__ == "__main__":
    sys.exit(main())
