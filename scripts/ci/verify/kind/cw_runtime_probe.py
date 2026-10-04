#!/usr/bin/env python3
"""Fixed, ordinary-owner CW selection/continuity witness for retained Kind.

The client compile-embeds this file in one public no-PTY session. Ready holds
the original process handles BEFORE Store generation0 bootstrap. The first CW
lookup is after bootstrap: the same persistent Bash then caches the managed
entry through B and rollback. This does not prove migration of an already
cached unmanaged image alias. The observer never reads credentials or signals
any process. Its one fixed child has kernel parent-death confinement only.

No native runner, provider guardian, sealed-memfd or platform managed-agent
claim is borrowed from the native update fixture. Kernel observations follow
that fixture's Process pattern; public incarnation/Attach ownership remains
the typed client's responsibility.
"""

import argparse
import ctypes
import hashlib
import json
import os
import re
import select
import stat
import subprocess
import sys
import time
import uuid

SCHEMA = 1
UID = GID = 1000
PREFIX = "CW_PLATFORM_RUNTIME_PROBE "
MAX_EXECUTABLE = 256 * 1024 * 1024
MAX_REQUEST = 4096
MAX_LINE = 16 * 1024
MAX_OUTPUT = 1024 * 1024
SECONDS = 900
INTERVAL = 0.02
PHASES = ("bootstrapped-a", "selected-b", "rolled-back-a")
ENTRY = "/home/codewire/.local/bin/cw"
VERSIONS = "/home/codewire/.local/share/codewire/cli/versions"
PROOF_ROOT = "/home/codewire/.local/state/codewire/cw-runtime-proof"
HOME_ROOT = "/home/codewire"
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

# Exact default PID1 command in sandbox/template/workspace.rs. A custom image
# command has a daemon-respawn loop and must not borrow this source invariant.
SUPERVISOR_COMMAND = (
    "user_shell=/bin/bash; [ -x /bin/bash ] || user_shell=/bin/sh; "
    "grep -q '^[^:]*:[^:]*:1000:' /etc/passwd || echo "
    '"codewire:x:1000:1000:codewire:/home/codewire:${user_shell}" >> /etc/passwd; '
    "grep -q '^[^:]*:[^:]*:1000:' /etc/group || echo 'codewire:x:1000:' >> /etc/group; "
    "while [ ! -x /codewire/bin/cw ]; do sleep 0.1; done; "
    "/codewire/bin/cw __hosted-daemon & daemon_pid=$!; "
    "shutdown() { kill -TERM \"$daemon_pid\" 2>/dev/null || true; "
    "wait \"$daemon_pid\" 2>/dev/null || true; }; "
    "trap 'shutdown; exit 143' TERM; trap 'shutdown; exit 130' INT; "
    'wait "$daemon_pid"; status=$?; trap - TERM INT; exit "$status"'
)
SUPERVISOR_ARGV = b"sh\0-c\0" + SUPERVISOR_COMMAND.encode("ascii") + b"\0"
DAEMON_ARGV = b"/codewire/bin/cw\0__hosted-daemon\0"
SHELL_ARGV = b"/bin/bash\0--noprofile\0--norc\0"


class Refused(Exception):
    def __init__(self, check, actor=None):
        super().__init__(check)
        self.check, self.actor = check, actor


def require(condition, check, actor=None):
    if not condition:
        raise Refused(check, actor)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-field")
        result[key] = value
    return result


def digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def package_version(value):
    return (type(value) is str and len(value) <= 128
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", value) is not None)


def identifier(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0
    except ValueError:
        return False


def decode_request(raw, index):
    require(0 < len(raw) <= MAX_REQUEST, "request-bound")
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused("request-json")))
    except (ValueError, UnicodeError):
        raise Refused("request-json") from None
    require(type(value) is dict, "request-fields")
    if value.get("op") == "close":
        require(set(value) == {"op"} and index == len(PHASES), "request-order")
        return value
    require(set(value) == {"op", "phase", "sha256", "size", "version"}, "request-fields")
    require(value["op"] == "checkpoint" and index < len(PHASES)
            and value["phase"] == PHASES[index], "request-order")
    require(digest(value["sha256"]) and type(value["size"]) is int
            and 0 < value["size"] <= MAX_EXECUTABLE
            and package_version(value["version"]), "request-identity")
    return value


def stamp(info):
    # Atime is read-driven; directory writes legitimately change directory times.
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def read_at(directory, name, limit=4096):
    fd = os.open(name, FILE_FLAGS, dir_fd=directory)
    try:
        raw = os.read(fd, limit + 1)
        require(len(raw) <= limit, "kernel-field-bound")
        return raw
    finally:
        os.close(fd)


def birth(raw):
    try:
        fields = raw.decode("ascii").rsplit(") ", 1)[1].split()
        require(len(fields) > 19 and fields[0] not in {"Z", "X", "x"}, "process-terminal")
        parent, ticks = int(fields[1]), int(fields[19])
        require(0 <= parent <= 2**31 - 1 and 0 < ticks < 2**64, "process-birth")
        return parent, ticks
    except (ValueError, UnicodeError, IndexError):
        raise Refused("process-birth") from None


def pidfd_pid(fd):
    root = os.open("/proc/self/fdinfo", DIRECTORY_FLAGS)
    try:
        raw = read_at(root, str(fd))
    finally:
        os.close(root)
    found = re.findall(rb"^Pid:\s*(-?[0-9]+)$", raw, re.MULTILINE)
    require(len(found) == 1, "pidfd-identity")
    return int(found[0])


def hash_file(fd, maximum, deadline):
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, "executable-bound")
    os.lseek(fd, 0, os.SEEK_SET)
    checksum, copied = hashlib.sha256(), 0
    while block := os.read(fd, 65536):
        require(time.monotonic() < deadline, "deadline")
        copied += len(block)
        require(copied <= maximum, "executable-bound")
        checksum.update(block)
    require(copied == before.st_size and stamp(before) == stamp(os.fstat(fd)), "executable-changed")
    return checksum.hexdigest(), before


class Process:
    """One held pidfd, proc directory and executable; never a signal API."""

    def __init__(self, pid, name, deadline, *, expected_parent=None, expected_path=None,
                 expected_digest=None, expected_size=None, expected_argv=None, parent=None):
        self.name, self.pid, self.pidfd, self.proc, self.exe = name, pid, None, None, None
        self.argv, self.parent = expected_argv, parent
        try:
            require(type(pid) is int and 0 < pid <= 2**31 - 1, "process-pid", name)
            if parent is not None:
                parent.verify()
            self.pidfd = os.pidfd_open(pid)
            require(pidfd_pid(self.pidfd) == pid, "pidfd-identity", name)
            self.proc = os.open(f"/proc/{pid}", DIRECTORY_FLAGS)
            require(os.fstat(self.proc).st_uid == os.geteuid(), "process-owner", name)
            require(not self.terminal(), "process-terminal", name)
            parent_pid, ticks = birth(read_at(self.proc, "stat"))
            require(expected_parent is None or expected_parent == parent_pid, "process-parent", name)
            if parent is not None:
                require(parent.pid == parent_pid, "process-parent", name)
            self.exe = os.open("exe", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.proc)
            checksum, info = hash_file(self.exe, MAX_EXECUTABLE, deadline)
            require(info.st_uid in {0, UID} and info.st_gid in {0, GID}
                    and info.st_nlink == 1 and not info.st_mode & 0o6022
                    and info.st_mode & 0o111, "executable-owner", name)
            path = os.readlink("exe", dir_fd=self.proc)
            require(path.startswith("/") and len(path.encode()) <= 4096
                    and not any(ord(c) < 32 or ord(c) == 127 for c in path), "executable-path", name)
            require(expected_path is None or path == expected_path, "executable-path", name)
            require(expected_digest is None or checksum == expected_digest, "executable-digest", name)
            require(expected_size is None or info.st_size == expected_size, "executable-size", name)
            self.exe_stamp = stamp(info)
            self.identity = {"pid": pid, "parent_pid": parent_pid, "start_ticks": ticks,
                             "executable": path, "device": info.st_dev, "inode": info.st_ino,
                             "size": info.st_size, "sha256": checksum, "uid": info.st_uid,
                             "gid": info.st_gid, "mode": info.st_mode, "links": info.st_nlink}
            self.verify()
            if parent is not None:
                parent.verify()
        except Refused as error:
            self.close()
            raise Refused(error.check, error.actor or name) from None
        except OSError:
            self.close()
            raise Refused("process-kernel", name) from None

    def terminal(self):
        return bool(select.select([self.pidfd], [], [], 0)[0])

    def verify(self):
        try:
            require(not self.terminal() and pidfd_pid(self.pidfd) == self.pid, "pidfd-live", self.name)
            before = birth(read_at(self.proc, "stat"))
            require(before == (self.identity["parent_pid"], self.identity["start_ticks"]),
                    "process-birth", self.name)
            require(os.fstat(self.proc).st_uid == os.geteuid(), "process-owner", self.name)
            require(os.readlink("exe", dir_fd=self.proc) == self.identity["executable"]
                    and stamp(os.stat("exe", dir_fd=self.proc)) == self.exe_stamp
                    and stamp(os.fstat(self.exe)) == self.exe_stamp, "executable-changed", self.name)
            if self.argv is not None:
                require(read_at(self.proc, "cmdline", 16 * 1024) == self.argv, "process-role", self.name)
            require(before == birth(read_at(self.proc, "stat"))
                    and not self.terminal() and pidfd_pid(self.pidfd) == self.pid,
                    "process-birth", self.name)
        except Refused as error:
            raise Refused(error.check, error.actor or self.name) from None
        except OSError:
            raise Refused("process-kernel", self.name) from None

    def close(self):
        for key in ("exe", "proc", "pidfd"):
            fd = getattr(self, key, None)
            if fd is not None:
                os.close(fd)
                setattr(self, key, None)


class Directory:
    """Fixed proof ancestry. Never chmod/adopt an existing directory."""

    def __init__(self, nonce):
        self.anchors, self.fd = [], None
        self.path = PROOF_ROOT + "/" + nonce
        try:
            fd = os.open("/", DIRECTORY_FLAGS)
            info = os.fstat(fd)
            self.anchors.append(("/", fd, directory_stamp(info)))
            require(info.st_uid == 0 and not info.st_mode & 0o022, "proof-owner")
            path = ""
            for part in self.path.strip("/").split("/"):
                path += "/" + part
                created = False
                try:
                    child = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
                except FileNotFoundError:
                    require(path.startswith(HOME_ROOT + "/.local"), "proof-parent")
                    os.mkdir(part, 0o700, dir_fd=fd)
                    child = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
                    created = True
                info = os.fstat(child)
                self.anchors.append((path, child, directory_stamp(info)))
                if path == self.path:
                    require(created, "proof-already-exists")
                require(info.st_uid in {0, UID} and info.st_gid in {0, GID}
                        and not info.st_mode & 0o022, "proof-owner")
                if created:
                    # Only this just-created held directory may shed inherited
                    # setgid. Existing ancestors are never rewritten.
                    require(info.st_uid == UID, "proof-owner")
                    os.fchmod(child, 0o700)
                    info = os.fstat(child)
                    self.anchors[-1] = (path, child, directory_stamp(info))
                if path == self.path:
                    require(info.st_uid == UID and info.st_gid == GID
                            and stat.S_IMODE(info.st_mode) == 0o700, "proof-private")
                fd = child
            self.fd = fd
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        for path, fd, expected in self.anchors:
            require(directory_stamp(os.fstat(fd)) == expected
                    and directory_stamp(os.stat(path, follow_symlinks=False)) == expected,
                    "proof-replaced")

    def write(self, name, body):
        require(re.fullmatch(r"[0-9]{3}-(ready|checkpoint|closed|refused)\.json", name), "proof-name")
        raw = canonical(body) + b"\n"
        require(len(raw) <= MAX_LINE, "output-bound")
        self.verify()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_NONBLOCK | os.O_CLOEXEC, 0o400, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == UID and before.st_gid == GID
                    and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o400, "proof-file")
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                require(count > 0, "proof-write")
                view = view[count:]
            os.fsync(fd)
            after = os.fstat(fd)
            require(after.st_size == len(raw) and stamp(after) == stamp(os.stat(name, dir_fd=self.fd,
                    follow_symlinks=False)), "proof-file")
            self.verify()
            os.fsync(self.fd)
        finally:
            os.close(fd)
        return {"path": self.path + "/" + name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}

    def close(self):
        for _, fd, _ in reversed(self.anchors):
            os.close(fd)
        self.anchors.clear()
        self.fd = None


def child_confinement(parent_pid):
    """One fixed child's kernel lifetime, not an observer signal interface."""
    library = ctypes.CDLL(None, use_errno=True)
    prctl = library.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int

    def prepare():
        if os.getppid() != parent_pid or os.geteuid() != UID or os.getegid() != GID:
            os._exit(127)
        # PR_SET_NO_NEW_PRIVS=38, PR_SET_PDEATHSIG=1; only this own child.
        if prctl(38, 1, 0, 0, 0) != 0 or prctl(1, 9, 0, 0, 0) != 0:
            os._exit(127)
        if os.getppid() != parent_pid:
            os._exit(127)
    return prepare


class Probe:
    def __init__(self, args):
        self.args, self.deadline = args, time.monotonic() + SECONDS
        self.actors, self.child, self.directory = {}, None, None
        self.samples, self.sequence, self.index, self.written = 0, 0, 0, 0
        self.phase, self.selection, self.shell_terminal = "baseline", None, False
        self.pending, self.stdout = b"", b""
        self.boot = ""
        self.input_fd = 0

    def budget(self):
        require(time.monotonic() < self.deadline, "deadline")

    def admit(self):
        require(sys.platform == "linux" and os.geteuid() == UID and os.getegid() == GID,
                "owner-required")
        require(hasattr(os, "pidfd_open"), "pidfd-unavailable")
        proc = os.open("/proc/sys/kernel/random", DIRECTORY_FLAGS)
        try:
            self.boot = read_at(proc, "boot_id", 64).decode("ascii").strip()
        finally:
            os.close(proc)
        require(identifier(self.boot), "boot-id")
        daemon_pid = os.getppid()
        supervisor = Process(1, "supervisor", self.deadline, expected_parent=0,
                             expected_argv=SUPERVISOR_ARGV)
        self.actors["supervisor"] = supervisor
        daemon = Process(daemon_pid, "daemon", self.deadline, expected_parent=1,
                         expected_path="/codewire/bin/cw", expected_digest=self.args.daemon_sha256,
                         expected_size=self.args.daemon_size, expected_argv=DAEMON_ARGV, parent=supervisor)
        self.actors["daemon"] = daemon
        session = Process(os.getpid(), "session", self.deadline, expected_parent=daemon_pid, parent=daemon)
        self.actors["session"] = session
        require(session.identity["executable"] == os.path.realpath("/usr/bin/python3"),
                "process-role", "session")
        # No caller command, environment, cwd or signal target can enter this
        # fixed child. Actual HOME/PATH remain as the ordinary launch supplied.
        self.child = subprocess.Popen(["/bin/bash", "--noprofile", "--norc"],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      preexec_fn=child_confinement(os.getpid()))
        self.actors["shell"] = Process(self.child.pid, "shell", self.deadline,
                                       expected_parent=os.getpid(), parent=session,
                                       expected_path=os.path.realpath("/bin/bash"), expected_argv=SHELL_ARGV)
        for stream in (self.child.stdin, self.child.stdout, self.child.stderr):
            os.set_blocking(stream.fileno(), False)
        os.set_blocking(self.input_fd, False)
        self.directory = Directory(self.args.nonce)
        self.settle()
        self.emit("ready")

    def verify(self):
        self.budget()
        for name, actor in self.actors.items():
            if name != "shell" or not self.shell_terminal:
                actor.verify()
        self.directory.verify()
        self.samples += 1

    def settle(self):
        self.verify()
        time.sleep(INTERVAL)
        self.verify()

    def emit(self, event):
        body = {"schema_version": SCHEMA, "event": event, "phase": self.phase,
                "nonce": self.args.nonce, "environment_id": self.args.environment_id,
                "sequence": self.sequence, "samples": self.samples, "boot_id": self.boot,
                "uid": UID, "gid": GID,
                "actors": {name: actor.identity for name, actor in self.actors.items()},
                "selection": self.selection, "shell_terminal": self.shell_terminal}
        proof = self.directory.write(f"{self.sequence:03}-{event}.json", body)
        self.output(body | {"evidence": proof})

    def output(self, body, observing=True):
        raw = (PREFIX + self.args.nonce + " ").encode("ascii") + canonical(body) + b"\n"
        require(len(raw) <= MAX_LINE and self.written + len(raw) <= MAX_OUTPUT, "output-bound")
        os.set_blocking(1, False)
        remaining = memoryview(raw)
        deadline = min(self.deadline, time.monotonic() + 3) if observing else time.monotonic() + 1
        while remaining:
            require(time.monotonic() < deadline, "output-deadline")
            if observing:
                self.verify()
            if not select.select([], [1], [], INTERVAL)[1]:
                continue
            try:
                count = os.write(1, remaining)
            except BlockingIOError:
                continue
            require(count > 0, "output-write")
            remaining = remaining[count:]
        self.written += len(raw)

    def request(self):
        while b"\n" not in self.pending:
            self.verify()
            ready, _, _ = select.select([self.input_fd, self.child.stdout.fileno(), self.child.stderr.fileno()], [], [], INTERVAL)
            if self.child.stdout.fileno() in ready:
                require(not os.read(self.child.stdout.fileno(), MAX_LINE + 1), "shell-unsolicited", "shell")
            if self.child.stderr.fileno() in ready:
                require(not os.read(self.child.stderr.fileno(), MAX_LINE + 1), "shell-stderr", "shell")
            if self.input_fd in ready:
                block = os.read(self.input_fd, MAX_REQUEST + 1)
                require(block, "input-ended")
                self.pending += block
                require(len(self.pending) <= MAX_REQUEST, "request-bound")
        raw, self.pending = self.pending.split(b"\n", 1)
        return decode_request(raw, self.index)

    def write_shell(self, data):
        remaining = memoryview(data)
        while remaining:
            self.verify()
            if not select.select([], [self.child.stdin.fileno()], [], INTERVAL)[1]:
                continue
            try:
                count = os.write(self.child.stdin.fileno(), remaining)
            except BlockingIOError:
                continue
            require(count > 0, "shell-input", "shell")
            remaining = remaining[count:]

    def shell_check(self, request):
        nonce = self.args.nonce
        data = (f"printf 'CWRP_PATH_{nonce}\\n'\ncommand -v cw\n"
                f"printf 'CWRP_VERSION_{nonce}\\n'\ncommand cw --version\n"
                f"printf 'CWRP_STATUS_{nonce}=%s\\n' \"$?\"\n"
                f"printf 'CWRP_END_{nonce}\\n'\n").encode("ascii")
        self.write_shell(data)
        raw = b""
        end = f"CWRP_END_{nonce}\n".encode("ascii")
        while not raw.endswith(end):
            self.verify()
            ready, _, _ = select.select([self.child.stdout.fileno(), self.child.stderr.fileno()], [], [], INTERVAL)
            if self.child.stderr.fileno() in ready:
                require(not os.read(self.child.stderr.fileno(), MAX_LINE + 1), "shell-stderr", "shell")
            if self.child.stdout.fileno() in ready:
                block = os.read(self.child.stdout.fileno(), MAX_LINE + 1)
                require(block, "shell-output-ended", "shell")
                raw += block
                require(len(raw) <= MAX_LINE, "shell-output-bound", "shell")
        expected = (f"CWRP_PATH_{nonce}\n{ENTRY}\nCWRP_VERSION_{nonce}\n"
                    f"cw {request['version']}\nCWRP_STATUS_{nonce}=0\nCWRP_END_{nonce}\n").encode("ascii")
        require(raw == expected, "shell-default", "shell")
        resolved = VERSIONS + "/" + request["sha256"] + "/cw"
        require(os.path.realpath(ENTRY) == resolved, "selection-path")
        fd = os.open(resolved, FILE_FLAGS)
        try:
            checksum, info = hash_file(fd, MAX_EXECUTABLE, self.deadline)
            require(checksum == request["sha256"] and info.st_size == request["size"]
                    and info.st_uid == UID and info.st_gid == GID and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o500
                    and stamp(info) == stamp(os.stat(resolved, follow_symlinks=False))
                    and os.path.realpath(ENTRY) == resolved, "selection-identity")
        finally:
            os.close(fd)
        self.selection = {"logical_path": ENTRY, "resolved_path": resolved,
                          "sha256": checksum, "size": info.st_size, "version": request["version"]}
        self.settle()

    def finish(self):
        require(not self.pending, "request-trailing")
        self.write_shell(b"exit\n")
        deadline = min(self.deadline, time.monotonic() + 3)
        while not self.actors["shell"].terminal():
            self.budget()
            for name, actor in self.actors.items():
                if name != "shell":
                    actor.verify()
            require(time.monotonic() < deadline, "shell-close", "shell")
            time.sleep(INTERVAL)
        require(self.child.wait(timeout=1) == 0, "shell-close", "shell")
        for stream in (self.child.stdout, self.child.stderr):
            require(not os.read(stream.fileno(), MAX_LINE + 1), "shell-close-output", "shell")
        # Attach has no close-stdin field. Refuse already-delivered trailing
        # bytes without requiring an unavailable half-close.
        if select.select([self.input_fd], [], [], 0)[0]:
            require(not os.read(self.input_fd, MAX_REQUEST + 1), "request-trailing")
        self.shell_terminal, self.phase = True, "closed"
        self.sequence += 1
        self.settle()
        self.emit("closed")

    def run(self):
        self.admit()
        while True:
            request = self.request()
            if request["op"] == "close":
                self.finish()
                return 0
            self.shell_check(request)
            self.phase = request["phase"]
            self.sequence += 1
            self.index += 1
            self.emit("checkpoint")

    def failed(self, error):
        actor = error.actor if isinstance(error, Refused) else None
        actor = actor if actor in {"supervisor", "daemon", "session", "shell"} else None
        check = error.check if isinstance(error, Refused) else "observer-io"
        if type(check) is not str or re.fullmatch(r"[a-z][a-z-]{0,63}", check) is None:
            check = "observer-io"
        body = {"schema_version": SCHEMA, "event": "refused", "phase": self.phase,
                "nonce": self.args.nonce, "environment_id": self.args.environment_id,
                "sequence": self.sequence, "samples": self.samples,
                "actor": actor, "check": check, "cleanup_unknown": self.child is not None,
                "evidence": None}
        # Never print exception strings, shell output, environment or argv.
        if self.directory is not None:
            try:
                saved = {key: value for key, value in body.items() if key != "evidence"}
                body["evidence"] = self.directory.write("999-refused.json", saved)
            except (Refused, OSError):
                pass
        try:
            self.output(body, observing=False)
        except (Refused, OSError):
            pass
        return 2

    def close(self):
        if self.child is not None:
            for stream in (self.child.stdin, self.child.stdout, self.child.stderr):
                stream.close()
        for actor in reversed(tuple(self.actors.values())):
            actor.close()
        if self.directory is not None:
            self.directory.close()


class SingleUse(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        supplied = vars(namespace).setdefault("_provided", set())
        if self.dest in supplied or not value:
            parser.error("duplicate or empty probe option")
        supplied.add(self.dest)
        setattr(namespace, self.dest, value)


def arguments(argv):
    parser = argparse.ArgumentParser(description="Fixed UID1000 Kind CW process witness", allow_abbrev=False)
    for key in ("environment-id", "nonce", "daemon-sha256", "daemon-size"):
        parser.add_argument("--" + key, required=True, action=SingleUse)
    args = parser.parse_args(argv)
    try:
        require(identifier(args.environment_id) and re.fullmatch(r"[0-9a-f]{32}", args.nonce), "option-identity")
        require(digest(args.daemon_sha256) and re.fullmatch(r"[1-9][0-9]{0,8}", args.daemon_size), "option-identity")
        args.daemon_size = int(args.daemon_size)
        require(args.daemon_size <= MAX_EXECUTABLE, "option-identity")
    except Refused:
        parser.error("probe identity refused")
    return args


def main(argv=None):
    args = arguments(sys.argv[1:] if argv is None else argv)
    probe = Probe(args)
    try:
        return probe.run()
    except (Refused, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        return probe.failed(error)
    finally:
        probe.close()


if __name__ == "__main__":
    raise SystemExit(main())
