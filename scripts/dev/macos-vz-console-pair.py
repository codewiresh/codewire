#!/usr/bin/env python3
"""Run the isolated two-VM macOS virtio-console packet fixture.

This developer fixture proves one supported VZ stream topology carrying the
real authenticated Linux packet engine. It is not product enablement, egress
mediation proof, or macOS confinement parity. Inputs and private evidence are
retained for every run.

The active deadline covers setup and protocol work, and the cleanup deadline
covers owned IPC, signalling and waitpid decisions. Later retained-artifact
writes are outside that cleanup decision; no userspace deadline can bound an
uninterruptible kernel or filesystem stall.
"""

from __future__ import annotations

import argparse
import array
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid


_artifact_spec = importlib.util.spec_from_file_location(
    "vz_artifact_admission", Path(__file__).with_name("macos-vz-inode-probe.py")
)
assert _artifact_spec and _artifact_spec.loader
artifact = importlib.util.module_from_spec(_artifact_spec)
_artifact_spec.loader.exec_module(artifact)

FIXTURE = "macos-vz-console-pair"
SCHEMA_VERSION = 1
HELPER_SCHEMA_VERSION = 3
BINDING_SCHEMA_VERSION = 1
BINDING_BYTES = 4096
MAX_BINDING_JSON_BYTES = 2048
MAX_INPUT_BYTES = 1024 * 1024 * 1024
MAX_HELPER_BYTES = 512 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024
ACTIVE_SECONDS = 120.0
CLEANUP_SECONDS = 10.0
POLL_SECONDS = 0.05
CODESIGN = "/usr/bin/codesign"
WATCHED_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM)

ROLE_GUEST = 1
ROLE_SERVICE = 2
ROLES = (ROLE_GUEST, ROLE_SERVICE)
ROLE_NAMES = {ROLE_GUEST: "guest", ROLE_SERVICE: "service"}

STATUS_PORTS_READY = 1
STATUS_PREPARED = 2
STATUS_GUEST_ARMED = 3
STATUS_HOST_READY = 4
STATUS_WORKER_READY = 5
STATUS_PACKET_COMPLETED = 6
STATUS_EOF_OBSERVED = 7
STATUS_NO_EOF_OBSERVED = 8
STATUS_CANCELLED = 9
STATUS_CHILDREN_REAPED = 10
STATUS_FAILED = 11
STATUS_PACKET_CLOSED = 12
STATUS_EOF_ARMED = 13

CONTROL_START = 1
CONTROL_CANCEL = 2
CONTROL_CLOSE_PACKET = 3
CONTROL_OBSERVE_EOF = 4
CONTROL_POWER_OFF = 5

VM_STOPPED = 0
VM_FAILED = 1
VM_FORCE_STOPPED = 2

STATUS_MAGIC = b"CWCPST1\0"
CONTROL_MAGIC = b"CWCPCT1\0"
STATUS_DOMAIN = b"codewire-console-pair-status-v1\0"
CONTROL_DOMAIN = b"codewire-console-pair-control-v1\0"
ROLE_FRAME_BYTES = 128
RUN_NONCE_BYTES = 32

RESULT_KEYS = frozenset(
    {
        "schemaVersion",
        "fixture",
        "outcome",
        "artifacts",
        "packetCompleted",
        "eofObservation",
        "cancellationRequested",
        "guestCancelled",
        "serviceCancelled",
        "serviceChildrenReaped",
        "workerWaitStatus",
        "adapterWaitStatus",
        "guestVMTermination",
        "serviceVMTermination",
        "helperReaped",
    }
)


class FixtureFailure(Exception):
    """Public diagnostics never include the underlying value."""


class FixtureInterrupted(BaseException):
    def __init__(self, signum: int):
        self.signum = signum


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def framed(payload: bytes) -> bytes:
    if not 0 < len(payload) <= artifact.MAX_FRAME_BYTES:
        raise FixtureFailure()
    return struct.pack(">I", len(payload)) + payload


def exact_digest(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise FixtureFailure()
    return value


def private_artifact_root(value: str) -> Path:
    supplied = Path(value)
    if not supplied.is_absolute() or supplied.exists() or supplied.is_symlink():
        raise FixtureFailure()
    parent = supplied.parent.resolve(strict=True)
    if supplied.parent != parent or supplied.name in {"", ".", ".."}:
        raise FixtureFailure()
    status = parent.stat()
    if (
        not parent.is_dir()
        or status.st_uid != os.geteuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        raise FixtureFailure()
    return supplied


def require_host() -> None:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise FixtureFailure()
    version = platform.mac_ver()[0].split(".", 1)[0]
    if not version.isdigit() or int(version) < 26:
        raise FixtureFailure()


def file_identity(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_uid,
        status.st_gid,
        status.st_mode,
        status.st_nlink,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


@dataclass
class AdmittedInput:
    name: str
    path: Path
    descriptor: int
    status: os.stat_result
    expected_sha256: str

    def revalidate(self) -> None:
        if self.descriptor < 0:
            raise FixtureFailure()
        expected = file_identity(self.status)
        if file_identity(os.fstat(self.descriptor)) != expected:
            raise FixtureFailure()
        try:
            current = os.stat(self.path, follow_symlinks=False)
        except OSError as error:
            raise FixtureFailure() from error
        if file_identity(current) != expected:
            raise FixtureFailure()

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def admit_input(path_value: str, digest_value: str, name: str, *, executable: bool) -> AdmittedInput:
    path = Path(path_value)
    if not path.is_absolute() or path.is_symlink():
        raise FixtureFailure()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        status = os.fstat(descriptor)
        maximum = MAX_HELPER_BYTES if executable else MAX_INPUT_BYTES
        mode = stat.S_IMODE(status.st_mode)
        if (
            not stat.S_ISREG(status.st_mode)
            or not 0 < status.st_size <= maximum
            or status.st_uid != os.geteuid()
            or status.st_nlink != 1
            or mode & 0o7077
            or not mode & stat.S_IRUSR
            or (executable and not mode & stat.S_IXUSR)
        ):
            raise FixtureFailure()
        admitted = AdmittedInput(name, path, descriptor, status, exact_digest(digest_value))
        admitted.revalidate()
        return admitted
    except BaseException:
        os.close(descriptor)
        raise


def write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise FixtureFailure()
        view = view[written:]


def write_private(path: Path, content: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode
    )
    try:
        write_all(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def replace_private(path: Path, content: bytes) -> None:
    temporary = path.with_name(path.name + ".next")
    try:
        write_private(temporary, content)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def copy_admitted(source: AdmittedInput, destination: Path, *, executable: bool) -> str:
    source.revalidate()
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o700 if executable else 0o600,
    )
    checksum = hashlib.sha256()
    try:
        offset = 0
        while offset < source.status.st_size:
            chunk = os.pread(
                source.descriptor,
                min(artifact.MIB, source.status.st_size - offset),
                offset,
            )
            if not chunk:
                raise FixtureFailure()
            checksum.update(chunk)
            write_all(descriptor, chunk)
            offset += len(chunk)
        if os.pread(source.descriptor, 1, source.status.st_size):
            raise FixtureFailure()
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    source.revalidate()
    digest = checksum.hexdigest()
    if digest != source.expected_sha256:
        raise FixtureFailure()
    copied = os.stat(destination, follow_symlinks=False)
    if (
        not stat.S_ISREG(copied.st_mode)
        or copied.st_uid != os.geteuid()
        or copied.st_nlink != 1
        or stat.S_IMODE(copied.st_mode) != (0o700 if executable else 0o600)
        or copied.st_size != source.status.st_size
    ):
        raise FixtureFailure()
    return digest


def digest_path(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    checksum = hashlib.sha256()
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise FixtureFailure()
        offset = 0
        while offset < status.st_size:
            chunk = os.pread(descriptor, min(artifact.MIB, status.st_size - offset), offset)
            if not chunk:
                raise FixtureFailure()
            checksum.update(chunk)
            offset += len(chunk)
        if os.pread(descriptor, 1, status.st_size):
            raise FixtureFailure()
        return checksum.hexdigest()
    finally:
        os.close(descriptor)


def run_fixed(command: list[str], cwd: Path) -> bytes:
    result = subprocess.run(
        command,
        cwd=cwd,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=20,
    )
    if result.returncode != 0 or len(result.stdout) > MAX_LOG_BYTES:
        raise FixtureFailure()
    return result.stdout


def require_signed_helper(path: Path, cwd: Path) -> None:
    run_fixed([CODESIGN, "--verify", "--strict", str(path)], cwd)
    details = run_fixed([CODESIGN, "-d", "--verbose=4", str(path)], cwd)
    if b"Signature=adhoc" not in details.splitlines():
        raise FixtureFailure()
    output = run_fixed([CODESIGN, "-d", "--entitlements", ":-", str(path)], cwd)
    offset = output.find(b"<?xml")
    if offset < 0:
        raise FixtureFailure()
    try:
        entitlements = plistlib.loads(output[offset:])
    except plistlib.InvalidFileException as error:
        raise FixtureFailure() from error
    if entitlements != {"com.apple.security.virtualization": True}:
        raise FixtureFailure()


def binding_image(
    role: str,
    vm_id: str,
    generation: int,
    run_nonce: bytes,
    network_key: bytes,
    status_key: bytes,
) -> bytes:
    document = canonical(
        {
            "generation": generation,
            "networkKey": network_key.hex(),
            "role": role,
            "runNonce": run_nonce.hex(),
            "schemaVersion": BINDING_SCHEMA_VERSION,
            "statusKey": status_key.hex(),
            "vmID": vm_id,
        }
    )
    if not document or len(document) > MAX_BINDING_JSON_BYTES:
        raise FixtureFailure()
    return document + bytes(BINDING_BYTES - len(document))


def artifact_identity(path: Path) -> dict[str, object]:
    status = os.stat(path, follow_symlinks=False)
    return {"sha256": digest_path(path), "size": status.st_size}


def base_result() -> dict[str, object]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "fixture": FIXTURE,
        "outcome": "unknown",
        "artifacts": "retained",
        "packetCompleted": False,
        "eofObservation": "unknown",
        "cancellationRequested": False,
        "guestCancelled": False,
        "serviceCancelled": False,
        "serviceChildrenReaped": False,
        "workerWaitStatus": None,
        "adapterWaitStatus": None,
        "guestVMTermination": "unknown",
        "serviceVMTermination": "unknown",
        "helperReaped": False,
    }


def validate_result(result: dict[str, object]) -> None:
    if set(result) != RESULT_KEYS:
        raise FixtureFailure()
    if (
        result["schemaVersion"] != SCHEMA_VERSION
        or result["fixture"] != FIXTURE
        or result["outcome"] not in {"pass", "failed", "unknown"}
        or result["artifacts"] != "retained"
        or result["eofObservation"]
        not in {"observed", "not-observed-within-bound", "unknown"}
        or result["guestVMTermination"]
        not in {"actual", "owned-force-stop", "failure", "unknown"}
        or result["serviceVMTermination"]
        not in {"actual", "owned-force-stop", "failure", "unknown"}
    ):
        raise FixtureFailure()
    for key in (
        "packetCompleted",
        "cancellationRequested",
        "guestCancelled",
        "serviceCancelled",
        "serviceChildrenReaped",
        "helperReaped",
    ):
        if type(result[key]) is not bool:
            raise FixtureFailure()
    for key in ("workerWaitStatus", "adapterWaitStatus"):
        if result[key] is not None and type(result[key]) is not int:
            raise FixtureFailure()
    if result["outcome"] == "pass" and not result_is_pass(result):
        raise FixtureFailure()


def result_is_pass(result: dict[str, object]) -> bool:
    return (
        result["packetCompleted"] is True
        and result["eofObservation"] in {"observed", "not-observed-within-bound"}
        and result["cancellationRequested"] is True
        and result["guestCancelled"] is True
        and result["serviceCancelled"] is True
        and result["serviceChildrenReaped"] is True
        and result["workerWaitStatus"] == 9472
        and result["adapterWaitStatus"] == 0
        and result["guestVMTermination"] == "actual"
        and result["serviceVMTermination"] == "actual"
        and result["helperReaped"] is True
    )


class OwnedHelper:
    """Exclusive direct child whose PID is never signalled after reaping."""

    def __init__(self, pid: int, output_fd: int, log_fd: int):
        self.pid = pid
        self.output_fd = output_fd
        self.log_fd = log_fd
        self.log = bytearray()
        self.log_overflow = False
        self.returncode: int | None = None
        self.reaped = False
        self.uncertain = False

    def poll(self) -> int | None:
        if self.uncertain:
            raise FixtureFailure()
        if self.reaped:
            return self.returncode
        while True:
            try:
                child, status = os.waitpid(self.pid, os.WNOHANG)
            except InterruptedError:
                continue
            except (ChildProcessError, OSError) as error:
                self.uncertain = True
                raise FixtureFailure() from error
            if child == 0:
                return None
            if child != self.pid:
                self.uncertain = True
                raise FixtureFailure()
            self.returncode = os.waitstatus_to_exitcode(status)
            self.reaped = True
            return self.returncode

    def drain(self, *, strict: bool = True) -> None:
        if self.output_fd < 0:
            return
        budget = MAX_LOG_BYTES + 1
        while budget > 0:
            try:
                chunk = os.read(self.output_fd, min(8192, budget))
            except BlockingIOError:
                return
            if not chunk:
                os.close(self.output_fd)
                self.output_fd = -1
                return
            budget -= len(chunk)
            retained = min(len(chunk), MAX_LOG_BYTES - len(self.log))
            self.log.extend(chunk[:retained])
            if retained != len(chunk):
                self.log_overflow = True
            if self.log_overflow and strict:
                raise FixtureFailure()

    def terminate(self, seconds: float = CLEANUP_SECONDS) -> bool:
        stop = time.monotonic() + seconds
        for signum in (signal.SIGTERM, signal.SIGKILL):
            if self.poll() is not None:
                return True
            # With SIGCHLD normalized to default, a child exiting after poll
            # remains an unreaped zombie and pins this exact PID until poll.
            try:
                os.kill(self.pid, signum)
            except ProcessLookupError:
                pass
            except OSError as error:
                self.uncertain = True
                raise FixtureFailure() from error
            phase = min(stop, time.monotonic() + seconds / 2)
            while time.monotonic() < phase:
                self.drain(strict=False)
                if self.poll() is not None:
                    return True
                time.sleep(0.01)
        return self.poll() is not None

    def close_output(self) -> None:
        try:
            self.drain(strict=False)
        except (FixtureFailure, OSError):
            self.log_overflow = True
        if self.output_fd >= 0:
            os.close(self.output_fd)
            self.output_fd = -1

    def finish_log(self) -> None:
        self.close_output()
        overflow = self.log_overflow
        if self.log_fd >= 0:
            try:
                write_all(self.log_fd, self.log)
                os.fsync(self.log_fd)
            finally:
                os.close(self.log_fd)
                self.log_fd = -1
        if overflow:
            raise FixtureFailure()


def _exec_fixed_helper(executable: str, arguments: list[str], environment: dict[str, str]) -> None:
    os.execve(executable, arguments, environment)


def _close_quietly(descriptor: int) -> None:
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def inherited_descriptor_limit() -> int:
    # A lowered RLIMIT_NOFILE does not bound descriptors already open. Enumerate
    # the fixed kernel descriptor directory in this single-threaded parent;
    # no new descriptors are opened between this snapshot and fork.
    maximum = 3
    with os.scandir("/dev/fd") as entries:
        for count, entry in enumerate(entries, start=1):
            if count > 4096 or not entry.name.isascii() or not entry.name.isdecimal():
                raise FixtureFailure()
            descriptor = int(entry.name)
            if descriptor >= 1 << 20:
                raise FixtureFailure()
            maximum = max(maximum, descriptor)
    return maximum + 1


class ConsolePairSpec:
    """Fixed fixture semantics; native/process ownership stays shared."""

    __slots__ = ()
    fixture = FIXTURE
    schema_version = SCHEMA_VERSION

    def base_result(self) -> dict[str, object]:
        return base_result()

    def validate_result(self, result: dict[str, object]) -> None:
        validate_result(result)

    def result_is_pass(self, result: dict[str, object]) -> bool:
        return result_is_pass(result)

    def binding_image(
        self,
        role: str,
        vm_id: str,
        generation: int,
        run_nonce: bytes,
        network_key: bytes,
        status_key: bytes,
    ) -> bytes:
        return binding_image(role, vm_id, generation, run_nonce, network_key, status_key)

    def coordinator(
        self, run: Run, vm_id: uuid.UUID, generation: int, nonce: bytes,
        status_keys: dict[int, bytes],
    ) -> Coordinator:
        return Coordinator(run, vm_id, generation, nonce, status_keys)


CONSOLE_SPEC = ConsolePairSpec()


class Run:
    def __init__(self, root: Path, *, spec: ConsolePairSpec = CONSOLE_SPEC):
        self.spec = spec
        self.root = root
        self.deadline = time.monotonic() + ACTIVE_SECONDS
        self.phase = "admission"
        self.cancelled = 0
        self.expired = False
        self.helper: OwnedHelper | None = None
        self.coordinator: Coordinator | None = None
        self.control: socket.socket | None = None
        self.control_eof = False
        self.force_stop_requested = False
        self.committed = False
        self.result = spec.base_result()
        self.receipt_path = root / "receipt.json"
        self.receipt: dict[str, object] = {
            "schemaVersion": spec.schema_version,
            "fixture": spec.fixture,
            "status": "assembling",
            "artifacts": "retained",
            "result": self.result,
        }

    def signal(self, signum: int, _frame: object) -> None:
        if self.committed:
            return
        if signum == signal.SIGALRM:
            self.expired = True
            raise FixtureFailure()
        if not self.cancelled:
            self.cancelled = signum

    def remaining(self, phase_deadline: float | None = None) -> float:
        if self.cancelled:
            raise FixtureInterrupted(self.cancelled)
        remaining = self.deadline - time.monotonic()
        if phase_deadline is not None:
            remaining = min(remaining, phase_deadline - time.monotonic())
        if remaining <= 0 or self.expired:
            raise FixtureFailure()
        return remaining

    def persist(self, status: str) -> None:
        self.spec.validate_result(self.result)
        self.receipt["status"] = status
        self.receipt["phase"] = self.phase
        self.receipt["result"] = dict(self.result)
        if self.coordinator is not None:
            self.receipt["observations"] = self.coordinator.diagnostic_state()
        payload = canonical(self.receipt) + b"\n"
        if self.receipt_path.exists():
            replace_private(self.receipt_path, payload)
        else:
            write_private(self.receipt_path, payload)

    def spawn_helper(self, executable: Path, child_fd: int) -> OwnedHelper:
        self.remaining()
        if threading.active_count() != 1:
            raise FixtureFailure()
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        native_tmp = self.root / "native-tmp"
        native_tmp.mkdir(mode=0o700)
        native_tmp.chmod(0o700)
        log_fd = -1
        output_read = -1
        output_write = -1
        null_fd = -1
        child_sources: list[int] = []
        watched = (*WATCHED_SIGNALS, signal.SIGCHLD)
        previous_mask: set[signal.Signals] | None = None
        helper: OwnedHelper | None = None
        try:
            log_fd = os.open(
                self.root / "helper.log",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            # Python's portable pipe API creates non-inheritable descriptors.
            output_read, output_write = os.pipe()
            os.set_blocking(output_read, False)
            null_fd = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
            for source_fd in (null_fd, output_write, child_fd):
                child_sources.append(fcntl.fcntl(source_fd, fcntl.F_DUPFD_CLOEXEC, 64))
            arguments = [
                str(executable),
                "console-pair-fixture",
                "--control-fd",
                "3",
            ]
            environment = {
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "TMPDIR": str(native_tmp) + "/",
            }
            executable_text = str(executable)
            # Allocate all ownership/log bookkeeping before there can be a
            # child. In the masked parent branch only retain the returned PID.
            prepared_helper = OwnedHelper(0, output_read, log_fd)
            close_limit = inherited_descriptor_limit()
            self.remaining()
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, watched)
            pid = os.fork()
            if pid == 0:
                try:
                    for signum in (*watched, signal.SIGPIPE):
                        signal.signal(signum, signal.SIG_DFL)
                    signal.pthread_sigmask(signal.SIG_SETMASK, ())
                    os.setsid()
                    os.dup2(child_sources[0], 0, inheritable=True)
                    os.dup2(child_sources[1], 1, inheritable=True)
                    os.dup2(child_sources[1], 2, inheritable=True)
                    os.dup2(child_sources[2], 3, inheritable=True)
                    os.closerange(4, close_limit)
                    os.chdir(self.root)
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                    _exec_fixed_helper(executable_text, arguments, environment)
                except BaseException:
                    os._exit(70)
                os._exit(70)
            # This assignment is the ownership boundary. The parent never
            # waits for exec completion and can reap only this retained PID.
            prepared_helper.pid = pid
            helper = prepared_helper
            self.helper = helper
            output_read = -1
            log_fd = -1
        finally:
            _close_quietly(output_write)
            _close_quietly(null_fd)
            for descriptor in child_sources:
                _close_quietly(descriptor)
            if helper is None:
                _close_quietly(output_read)
                _close_quietly(log_fd)
            if previous_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        self.remaining()
        assert self.helper is not None
        return self.helper

    def wait_readable(self, deadline: float, *, allow_helper_exit: bool = False) -> None:
        if self.control is None or self.control_eof:
            raise FixtureFailure()
        while True:
            if self.helper is not None:
                self.helper.drain()
            readable, _, _ = select.select(
                [self.control], [], [], min(POLL_SECONDS, self.remaining(deadline))
            )
            if readable:
                return
            if (
                not allow_helper_exit
                and self.helper is not None
                and self.helper.poll() is not None
            ):
                raise FixtureFailure()

    def send(self, value: bytes) -> None:
        if self.control is None or self.control_eof:
            raise FixtureFailure()
        view = memoryview(value)
        while view:
            self.remaining()
            _, writable, _ = select.select([], [self.control], [], min(POLL_SECONDS, self.remaining()))
            if not writable:
                continue
            sent = self.control.send(view)
            if sent <= 0:
                raise FixtureFailure()
            view = view[sent:]

    def request_force_stop(self) -> None:
        if self.force_stop_requested:
            return
        self.force_stop_requested = True
        if (
            self.control is not None
            and not self.control_eof
            and self.helper is not None
            and not self.helper.reaped
        ):
            try:
                value = memoryview(framed(b"Q"))
                deadline = time.monotonic() + 0.25
                while value and time.monotonic() < deadline:
                    _, writable, _ = select.select([], [self.control], [], 0.02)
                    if writable:
                        sent = self.control.send(value)
                        if sent <= 0:
                            break
                        value = value[sent:]
            except OSError:
                pass

    def teardown(self, coordinator: "Coordinator | None") -> None:
        self.request_force_stop()
        stop = time.monotonic() + CLEANUP_SECONDS
        while self.helper is not None and time.monotonic() < stop:
            try:
                self.helper.drain()
                if self.control is not None and not self.control_eof:
                    readable, _, _ = select.select([self.control], [], [], 0.02)
                    if readable:
                        data = self.control.recv(4096)
                        if not data:
                            self.control_eof = True
                        elif coordinator is not None:
                            coordinator.feed(data, teardown=True)
                if self.helper.poll() is not None:
                    if self.control_eof:
                        break
            except (FixtureFailure, OSError):
                break
        if self.helper is not None and not self.helper.reaped:
            try:
                self.helper.terminate(max(0.1, stop - time.monotonic()))
            except (FixtureFailure, OSError):
                pass
        if self.helper is not None:
            self.result["helperReaped"] = self.helper.reaped
            # Do not make the owned-process cleanup bound depend on filesystem
            # log writes. The bounded bytes are persisted after this decision.
            self.helper.close_output()
        if self.control is not None:
            self.control.close()
            self.control = None


class Coordinator:
    status_magic = STATUS_MAGIC
    control_magic = CONTROL_MAGIC
    status_domain = STATUS_DOMAIN
    control_domain = CONTROL_DOMAIN
    wait_keys = ("workerWaitStatus", "adapterWaitStatus")

    def __init__(
        self,
        run: Run,
        vm_id: uuid.UUID,
        generation: int,
        nonce: bytes,
        keys: dict[int, bytes],
    ):
        self.run = run
        self.vm_id = vm_id
        self.generation = generation
        self.nonce = nonce
        self.keys = keys
        self.buffer = bytearray()
        self.started = False
        self.status_sequence = {role: 1 for role in ROLES}
        self.control_sequence = {role: 1 for role in ROLES}
        self.seen: dict[int, list[int]] = {role: [] for role in ROLES}
        self.vm_terminal: dict[int, int | None] = {role: None for role in ROLES}
        self.stage_deadline = time.monotonic() + 30
        self.sent_guest_start = False
        self.sent_service_start = False
        self.sent_eof_observe = False
        self.sent_close = False
        self.sent_cancel = False
        self.sent_poweroff: set[int] = set()

    def diagnostic_state(self) -> dict[str, object]:
        # Fixed classifications only: never serialize keys, frames, guest data
        # or exception text. Completed writes are not guest acknowledgements.
        return {
            "nativeStarted": self.started,
            "authenticatedStatuses": {
                ROLE_NAMES[role]: list(self.seen[role]) for role in ROLES
            },
            "guestStartWriteCompleted": self.sent_guest_start,
            "serviceStartWriteCompleted": self.sent_service_start,
            "observeEOFWriteCompleted": self.sent_eof_observe,
            "closePacketWriteCompleted": self.sent_close,
            "cancelWritesCompleted": self.sent_cancel,
            "powerOffWritesCompleted": [
                ROLE_NAMES[role] for role in sorted(self.sent_poweroff)
            ],
        }

    def set_stage(self, phase: str, seconds: float) -> None:
        self.run.phase = phase
        self.stage_deadline = min(self.run.deadline, time.monotonic() + seconds)

    def control_frame(self, role: int, code: int) -> bytes:
        sequence = self.control_sequence[role]
        self.control_sequence[role] += 1
        frame = bytearray(ROLE_FRAME_BYTES)
        frame[:8] = self.control_magic
        frame[8] = role
        frame[9] = code
        frame[16:32] = self.vm_id.bytes
        frame[32:40] = self.generation.to_bytes(8, "little")
        frame[40:72] = self.nonce
        frame[72:80] = sequence.to_bytes(8, "little")
        frame[96:] = hmac.new(
            self.keys[role], self.control_domain + frame[:96], hashlib.sha256
        ).digest()
        return b"C" + bytes([role]) + frame

    def send_control(self, role: int, code: int) -> None:
        self.run.send(framed(self.control_frame(role, code)))

    def decode_status(self, wrapper_role: int, frame: bytes) -> tuple[int | None, ...]:
        if wrapper_role not in ROLES or len(frame) != ROLE_FRAME_BYTES:
            raise FixtureFailure()
        if (
            frame[:8] != self.status_magic
            or frame[8] != wrapper_role
            or frame[10:16] != bytes(6)
            or frame[16:32] != self.vm_id.bytes
            or frame[32:40] != self.generation.to_bytes(8, "little")
            or frame[40:72] != self.nonce
        ):
            raise FixtureFailure()
        sequence = int.from_bytes(frame[72:80], "little")
        if sequence != self.status_sequence[wrapper_role]:
            raise FixtureFailure()
        code = frame[9]
        if code == STATUS_CHILDREN_REAPED:
            end = 80 + 4 * len(self.wait_keys)
            if wrapper_role != ROLE_SERVICE or frame[end:96] != bytes(96 - end):
                raise FixtureFailure()
            waits = tuple(
                int.from_bytes(frame[offset:offset + 4], "little", signed=True)
                for offset in range(80, end, 4)
            )
        else:
            if frame[80:96] != bytes(16):
                raise FixtureFailure()
            waits = (None,) * len(self.wait_keys)
        expected = hmac.new(
            self.keys[wrapper_role], self.status_domain + frame[:96], hashlib.sha256
        ).digest()
        if not hmac.compare_digest(frame[96:], expected):
            raise FixtureFailure()
        self.status_sequence[wrapper_role] += 1
        return wrapper_role, code, *waits

    def expected_statuses(self, role: int) -> list[int | tuple[int, ...]]:
        return {
            ROLE_GUEST: [
                STATUS_PORTS_READY,
                STATUS_GUEST_ARMED,
                STATUS_HOST_READY,
                STATUS_PACKET_COMPLETED,
                STATUS_PACKET_CLOSED,
                STATUS_CANCELLED,
            ],
            ROLE_SERVICE: [
                STATUS_PREPARED,
                STATUS_WORKER_READY,
                STATUS_EOF_ARMED,
                (STATUS_EOF_OBSERVED, STATUS_NO_EOF_OBSERVED),
                STATUS_CHILDREN_REAPED,
                STATUS_CANCELLED,
            ],
        }[role]

    def packet_ready(self) -> bool:
        return (
            STATUS_PACKET_COMPLETED in self.seen[ROLE_GUEST]
            and STATUS_HOST_READY in self.seen[ROLE_GUEST]
            and STATUS_WORKER_READY in self.seen[ROLE_SERVICE]
        )

    def initial_ready(self) -> bool:
        return (
            self.seen[ROLE_GUEST] == [STATUS_PORTS_READY]
            and self.seen[ROLE_SERVICE] == [STATUS_PREPARED]
        )

    def accepted_status(self, role: int, code: int) -> None:
        """A fixed protocol variant may record additional authenticated facts."""

    def handle_status(
        self,
        role: int,
        code: int,
        *waits: int | None,
        persist_packet: bool = True,
    ) -> None:
        if len(waits) != len(self.wait_keys):
            raise FixtureFailure()
        expected = self.expected_statuses(role)
        index = len(self.seen[role])
        if code == STATUS_FAILED or index >= len(expected):
            raise FixtureFailure()
        admitted = expected[index]
        if isinstance(admitted, tuple):
            if code not in admitted:
                raise FixtureFailure()
        elif code != admitted:
            raise FixtureFailure()
        self.accepted_status(role, code)
        self.seen[role].append(code)

        if (
            not self.run.result["packetCompleted"]
            and self.packet_ready()
        ):
            # Independent VM status pipes have no cross-role delivery order.
            # Preserve both authenticated facts before advancing to EOF.
            self.run.result["packetCompleted"] = True
            self.run.phase = "packet-completed"
            # This fsync is the durable proof boundary before the EOF subtrial.
            if persist_packet:
                self.run.persist("packet-completed")
        if code == STATUS_EOF_OBSERVED:
            self.run.result["eofObservation"] = "observed"
        elif code == STATUS_NO_EOF_OBSERVED:
            self.run.result["eofObservation"] = "not-observed-within-bound"
        elif code == STATUS_CANCELLED:
            self.run.result[f"{ROLE_NAMES[role]}Cancelled"] = True
        elif code == STATUS_CHILDREN_REAPED:
            self.run.result["serviceChildrenReaped"] = True
            for key, value in zip(self.wait_keys, waits):
                self.run.result[key] = value

    def handle_vm(self, role: int, state: int) -> None:
        if role not in ROLES or state not in {VM_STOPPED, VM_FAILED, VM_FORCE_STOPPED}:
            raise FixtureFailure()
        if self.vm_terminal[role] is not None:
            raise FixtureFailure()
        if state == VM_STOPPED:
            if code_not_seen(self.seen[role], STATUS_CANCELLED):
                raise FixtureFailure()
            if role == ROLE_SERVICE and code_not_seen(
                self.seen[role], STATUS_CHILDREN_REAPED
            ):
                raise FixtureFailure()
            if role not in self.sent_poweroff:
                raise FixtureFailure()
            value = "actual"
        elif state == VM_FORCE_STOPPED:
            if not self.run.force_stop_requested:
                raise FixtureFailure()
            value = "owned-force-stop"
        else:
            value = "failure"
        self.vm_terminal[role] = state
        self.run.result[f"{ROLE_NAMES[role]}VMTermination"] = value
        if state != VM_STOPPED:
            raise FixtureFailure()

    def poweroff_ready(self) -> bool:
        return True

    def advance(self) -> None:
        guest = self.seen[ROLE_GUEST]
        service = self.seen[ROLE_SERVICE]
        if (
            self.started
            and self.initial_ready()
            and not self.sent_guest_start
        ):
            self.send_control(ROLE_GUEST, CONTROL_START)
            self.sent_guest_start = True
            self.set_stage("guest-armed", 15)
        if self.sent_guest_start and STATUS_GUEST_ARMED in guest and not self.sent_service_start:
            self.send_control(ROLE_SERVICE, CONTROL_START)
            self.sent_service_start = True
            self.set_stage("authenticated-packet", 35)
        if (
            self.packet_ready()
            and not self.sent_eof_observe
        ):
            self.send_control(ROLE_SERVICE, CONTROL_OBSERVE_EOF)
            self.sent_eof_observe = True
            self.set_stage("eof-armed", 5)
        if STATUS_EOF_ARMED in service and not self.sent_close:
            self.send_control(ROLE_GUEST, CONTROL_CLOSE_PACKET)
            self.sent_close = True
            self.set_stage("eof-observation", 5)
        if (
            STATUS_PACKET_CLOSED in guest
            and any(code in service for code in (STATUS_EOF_OBSERVED, STATUS_NO_EOF_OBSERVED))
            and not self.sent_cancel
        ):
            self.send_control(ROLE_GUEST, CONTROL_CANCEL)
            self.send_control(ROLE_SERVICE, CONTROL_CANCEL)
            self.sent_cancel = True
            self.run.result["cancellationRequested"] = True
            self.set_stage("normal-cancellation", 10)
        if (
            self.sent_cancel
            and self.poweroff_ready()
            and STATUS_CANCELLED in guest
            and ROLE_GUEST not in self.sent_poweroff
        ):
            self.send_control(ROLE_GUEST, CONTROL_POWER_OFF)
            self.sent_poweroff.add(ROLE_GUEST)
        if (
            self.sent_cancel
            and self.poweroff_ready()
            and STATUS_CANCELLED in service
            and STATUS_CHILDREN_REAPED in service
            and ROLE_SERVICE not in self.sent_poweroff
        ):
            self.send_control(ROLE_SERVICE, CONTROL_POWER_OFF)
            self.sent_poweroff.add(ROLE_SERVICE)
            self.set_stage("vm-termination", 15)

    def handle_record(self, kind: int, role: int, payload: bytes) -> None:
        if kind == ord("R"):
            decoded = self.decode_status(role, payload)
            self.handle_status(*decoded)
        elif kind == ord("V"):
            if len(payload) != 1:
                raise FixtureFailure()
            self.handle_vm(role, payload[0])
        else:
            raise FixtureFailure()
        self.advance()

    def feed(self, data: bytes, *, awaiting_started: bool = False, teardown: bool = False) -> bool:
        self.buffer.extend(data)
        saw_started = False
        while len(self.buffer) >= 4:
            size = struct.unpack(">I", self.buffer[:4])[0]
            if not 0 < size <= artifact.MAX_FRAME_BYTES:
                raise FixtureFailure()
            if len(self.buffer) < size + 4:
                break
            outer = bytes(self.buffer[4 : size + 4])
            del self.buffer[: size + 4]
            expected_started = canonical(
                {"result": "console-pair-started", "schemaVersion": HELPER_SCHEMA_VERSION}
            )
            if awaiting_started and outer == expected_started:
                if self.started:
                    raise FixtureFailure()
                self.started = True
                saw_started = True
                self.advance()
                continue
            if len(outer) == 2 + ROLE_FRAME_BYTES and outer[0] == ord("R"):
                kind, role, payload = outer[0], outer[1], outer[2:]
            elif len(outer) == 3 and outer[0] == ord("V"):
                kind, role, payload = outer[0], outer[1], outer[2:]
            else:
                raise FixtureFailure()
            if teardown and kind == ord("V"):
                state = payload[0]
                if (
                    role not in ROLES
                    or state not in {VM_STOPPED, VM_FAILED, VM_FORCE_STOPPED}
                    or self.vm_terminal[role] is not None
                ):
                    raise FixtureFailure()
                self.vm_terminal[role] = state
                self.run.result[f"{ROLE_NAMES[role]}VMTermination"] = {
                    VM_STOPPED: "actual",
                    VM_FAILED: "failure",
                    VM_FORCE_STOPPED: "owned-force-stop",
                }[state]
                continue
            if teardown and kind == ord("R"):
                decoded = self.decode_status(role, payload)
                # Preserve authenticated in-memory facts without putting an
                # unbounded filesystem write inside the cleanup deadline.
                self.handle_status(*decoded, persist_packet=False)
                continue
            try:
                self.handle_record(kind, role, payload)
            except FixtureFailure:
                raise
        return saw_started

    def complete(self) -> bool:
        return all(self.vm_terminal[role] == VM_STOPPED for role in ROLES)


def code_not_seen(values: list[int], code: int) -> bool:
    return code not in values


def attach_and_start_coordinator(
    run: Run,
    vm_id: uuid.UUID,
    generation: int,
    nonce: bytes,
    status_keys: dict[int, bytes],
) -> Coordinator:
    coordinator = run.spec.coordinator(
        run, vm_id, generation, nonce, status_keys
    )
    # Retain the decoder before START can have any effect. An exception after
    # a successful or partial transport write must not erase cleanup evidence.
    run.coordinator = coordinator
    run.send(framed(b"\x01"))
    return coordinator


def close_request_descriptors(control: socket.socket, descriptors: list[int]) -> None:
    try:
        control.settimeout(None)
        control.setblocking(False)
    finally:
        for descriptor in descriptors:
            _close_quietly(descriptor)


def receive_admitted(run: Run, buffer: bytearray, deadline: float) -> None:
    expected = canonical(
        {"result": "console-pair-admitted", "schemaVersion": HELPER_SCHEMA_VERSION}
    )
    while True:
        if len(buffer) >= 4:
            size = struct.unpack(">I", buffer[:4])[0]
            if not 0 < size <= artifact.MAX_FRAME_BYTES:
                raise FixtureFailure()
            if len(buffer) >= size + 4:
                payload = bytes(buffer[4 : size + 4])
                del buffer[: size + 4]
                if payload != expected or buffer:
                    raise FixtureFailure()
                return
        run.wait_readable(deadline)
        assert run.control is not None
        data = run.control.recv(4096)
        if not data:
            run.control_eof = True
            raise FixtureFailure()
        buffer.extend(data)


def run_coordinator(run: Run, coordinator: Coordinator) -> None:
    coordinator.set_stage("native-start", 35)
    while not coordinator.started:
        run.wait_readable(coordinator.stage_deadline)
        assert run.control is not None
        data = run.control.recv(4096)
        if not data:
            run.control_eof = True
            raise FixtureFailure()
        coordinator.feed(data, awaiting_started=True)
    while not coordinator.complete():
        run.wait_readable(coordinator.stage_deadline)
        assert run.control is not None
        data = run.control.recv(4096)
        if not data:
            run.control_eof = True
            raise FixtureFailure()
        coordinator.feed(data)
    if coordinator.buffer:
        raise FixtureFailure()
    # Both exact VM instances reported actual stop. Require helper-owned
    # control closure and a successful direct-child reap without signalling.
    eof_deadline = min(run.deadline, time.monotonic() + 5)
    while not run.control_eof:
        run.wait_readable(eof_deadline, allow_helper_exit=True)
        assert run.control is not None
        data = run.control.recv(4096)
        if data:
            coordinator.feed(data)
        else:
            run.control_eof = True
    assert run.helper is not None
    while run.helper.poll() is None:
        run.helper.drain()
        time.sleep(min(0.01, run.remaining(eof_deadline)))
    run.helper.drain()
    run.result["helperReaped"] = True
    if coordinator.buffer or run.helper.returncode != 0:
        raise FixtureFailure()
    if not run.spec.result_is_pass(run.result):
        raise FixtureFailure()
    # Signal delivery is not an alternative to checking the absolute active
    # deadline after the final poll/drain has completed.
    run.remaining()


def prepare_and_run(arguments: argparse.Namespace, run: Run) -> Coordinator | None:
    run.persist("assembling")
    inputs: list[AdmittedInput] = []
    coordinator: Coordinator | None = None
    try:
        helper = admit_input(arguments.helper, arguments.helper_sha256, "helper", executable=True)
        inputs.append(helper)
        kernel = admit_input(arguments.kernel, arguments.kernel_sha256, "kernel", executable=False)
        inputs.append(kernel)
        initramfs = admit_input(
            arguments.initramfs, arguments.initramfs_sha256, "initramfs", executable=False
        )
        inputs.append(initramfs)
        if len({(item.status.st_dev, item.status.st_ino) for item in inputs}) != len(inputs):
            raise FixtureFailure()
        copied = {
            "helper": run.root / "helper",
            "kernel": run.root / "kernel",
            "initramfs": run.root / "initramfs",
        }
        copy_admitted(helper, copied["helper"], executable=True)
        copy_admitted(kernel, copied["kernel"], executable=False)
        copy_admitted(initramfs, copied["initramfs"], executable=False)
        for item in inputs:
            item.close()
        require_signed_helper(copied["helper"], run.root)

        vm_id = uuid.uuid4()
        generation = int.from_bytes(os.urandom(8), "little") or 1
        nonce = os.urandom(RUN_NONCE_BYTES)
        network_key = os.urandom(32)
        status_keys = {ROLE_GUEST: os.urandom(32), ROLE_SERVICE: os.urandom(32)}
        if len({nonce, network_key, *status_keys.values()}) != 4:
            raise FixtureFailure()
        binding_paths = {
            ROLE_GUEST: run.root / "guest-binding",
            ROLE_SERVICE: run.root / "service-binding",
        }
        for role in ROLES:
            image = run.spec.binding_image(
                ROLE_NAMES[role],
                str(vm_id),
                generation,
                nonce,
                network_key,
                status_keys[role],
            )
            if len(image) != BINDING_BYTES:
                raise FixtureFailure()
            write_private(binding_paths[role], image)
            binding_paths[role].chmod(0o400)

        configuration = {
            "generation": generation,
            "guestBinding": artifact_identity(binding_paths[ROLE_GUEST]),
            "initialRamdisk": artifact_identity(copied["initramfs"]),
            "kernel": artifact_identity(copied["kernel"]),
            "runNonce": nonce.hex(),
            "schemaVersion": HELPER_SCHEMA_VERSION,
            "serviceBinding": artifact_identity(binding_paths[ROLE_SERVICE]),
            "vmID": str(vm_id),
        }
        run.receipt["configuration"] = configuration
        run.phase = "prepared"
        run.persist("prepared")

        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        run.control = parent
        parent.setblocking(False)
        try:
            run.spawn_helper(copied["helper"], child.fileno())
        finally:
            child.close()
        descriptor_paths = [
            copied["kernel"],
            copied["initramfs"],
            binding_paths[ROLE_GUEST],
            binding_paths[ROLE_SERVICE],
        ]
        descriptors: list[int] = []
        try:
            for path in descriptor_paths:
                descriptors.append(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK))
            identities = [file_identity(os.fstat(descriptor)) for descriptor in descriptors]
            if len({(identity[0], identity[1]) for identity in identities}) != 4:
                raise FixtureFailure()
            request = framed(canonical(configuration))
            rights = array.array("i", descriptors)
            parent.setblocking(True)
            parent.settimeout(min(run.remaining(), 15.0))
            sent = parent.sendmsg(
                [request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]
            )
            if sent <= 0:
                raise FixtureFailure()
            parent.sendall(request[sent:])
            parent.settimeout(None)
            parent.setblocking(False)
            initial = bytearray()
            receive_admitted(run, initial, min(run.deadline, time.monotonic() + 15))
            for descriptor, path, identity in zip(descriptors, descriptor_paths, identities):
                if (
                    file_identity(os.fstat(descriptor)) != identity
                    or file_identity(os.stat(path, follow_symlinks=False)) != identity
                ):
                    raise FixtureFailure()
        finally:
            close_request_descriptors(parent, descriptors)

        coordinator = attach_and_start_coordinator(
            run, vm_id, generation, nonce, status_keys
        )
        run_coordinator(run, coordinator)
        run.result["outcome"] = "pass"
        # The final pending-signal snapshot is the irrevocable PASS boundary;
        # do not publish a successful receipt before it.
        run.phase = "proof-complete"
        return coordinator
    finally:
        for item in inputs:
            item.close()


class PrivateParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise FixtureFailure()


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = PrivateParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--helper", required=True)
    parser.add_argument("--helper-sha256", required=True)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--kernel-sha256", required=True)
    parser.add_argument("--initramfs", required=True)
    parser.add_argument("--initramfs-sha256", required=True)
    parser.add_argument("--artifact-root", required=True)
    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None, *, spec: ConsolePairSpec = CONSOLE_SPEC,
) -> int:
    arguments = argv if argv is not None else sys.argv[1:]
    run: Run | None = None
    coordinator: Coordinator | None = None
    result = spec.base_result()
    status = 1
    prior_umask = os.umask(0o077)
    prior_handlers: dict[int, object] = {}
    prior_sigchld = signal.getsignal(signal.SIGCHLD)
    prior_timer = signal.getitimer(signal.ITIMER_REAL)
    prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, WATCHED_SIGNALS)
    finishing_mask = prior_mask
    try:
        if prior_timer != (0.0, 0.0) or set(prior_mask).intersection(WATCHED_SIGNALS):
            raise FixtureFailure()
        parsed = parse_arguments(arguments)
        require_host()
        root = private_artifact_root(parsed.artifact_root)
        root.mkdir(mode=0o700)
        run = Run(root, spec=spec)
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        for signum in WATCHED_SIGNALS:
            prior_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, run.signal)
        signal.setitimer(signal.ITIMER_REAL, ACTIVE_SECONDS)
        signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)
        try:
            coordinator = prepare_and_run(parsed, run)
            result = run.result
            status = 0
        except FixtureInterrupted as error:
            status = 128 + error.signum
        except (Exception, KeyboardInterrupt):
            status = 1
    except FixtureInterrupted as error:
        status = 128 + error.signum
    except (Exception, KeyboardInterrupt):
        status = 1
    finally:
        finishing_mask = signal.pthread_sigmask(signal.SIG_BLOCK, WATCHED_SIGNALS)
        signal.setitimer(signal.ITIMER_REAL, 0)
        if run is not None:
            if status != 0:
                run.receipt["failurePhase"] = run.phase
                run.phase = "cleanup"
                run.teardown(run.coordinator)
                result = run.result
                result["outcome"] = (
                    "failed"
                    if run.cancelled == 0
                    and not run.expired
                    and all(
                        result[f"{ROLE_NAMES[role]}VMTermination"]
                        in {"actual", "owned-force-stop", "failure"}
                        for role in ROLES
                    )
                    and result["helperReaped"] is True
                    else "unknown"
                )
                try:
                    run.persist(result["outcome"])
                except (FixtureFailure, OSError):
                    result["outcome"] = "unknown"
            if run.helper is not None:
                try:
                    # Process ownership is already resolved. Filesystem writes
                    # happen after the cleanup decision because kernels cannot
                    # provide a universal real-time bound for file write/fsync.
                    run.helper.finish_log()
                except (FixtureFailure, OSError):
                    status = status or 1
                    result["outcome"] = "unknown"
            if run.control is not None:
                run.control.close()
            pending = signal.sigpending()
            for signum in WATCHED_SIGNALS:
                if signum not in pending:
                    continue
                if signum == signal.SIGALRM:
                    run.expired = True
                elif not run.cancelled:
                    run.cancelled = signum
            if run.cancelled:
                status = 128 + run.cancelled
                result["outcome"] = "unknown"
            elif run.expired:
                status = status or 1
                result["outcome"] = "unknown"
            try:
                run.persist(result["outcome"])
            except (FixtureFailure, OSError):
                status = status or 1
                result["outcome"] = "unknown"
            run.committed = True
        spec.validate_result(result)
        sys.stdout.buffer.write(canonical(result) + b"\n")
        sys.stdout.buffer.flush()
        os.umask(prior_umask)
        signal.pthread_sigmask(signal.SIG_SETMASK, finishing_mask)
        for signum, handler in prior_handlers.items():
            signal.signal(signum, handler)
        signal.signal(signal.SIGCHLD, prior_sigchld)
        signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
