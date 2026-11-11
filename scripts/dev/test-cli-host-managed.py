#!/usr/bin/env python3
"""Actual Linux host Codex/Claude conversations over a protected synthetic broker.

Requires explicitly admitted native agent payloads, a composed feature-only
broker and two source-bound cw releases. It never uses ambient agents/login.
The broker's upstream is synthetic; this is not live-provider, OS-keyring or
egress-mediation proof. Full acceptance requires every assertion below.
"""
import argparse
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid


MAX_AGENT_FILE = 512 * 1024 * 1024
MAX_AGENT_TOTAL = 1536 * 1024 * 1024
MAX_CW_FILE = 256 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_FILES = 4096
WALL = 0x40000000  # Linux __WALL: include non-SIGCHLD clone children.
PEERPIDFD = 77  # Linux SO_PEERPIDFD; unsupported kernels refuse.
SONAMES = sorted(["ld-linux-x86-64.so.2", "libc.so.6", "libdl.so.2", "libm.so.6",
                  "libpthread.so.0", "librt.so.1", "libtinfo.so.6"])
SOURCE = Path(__file__).resolve().parents[2]


def pinned_agent_versions():
    """The managed agents' versions in the workspace image this source pins."""
    spec = importlib.util.spec_from_file_location(
        "workspace_image_pin", SOURCE / "scripts/ci/images/workspace-image-pin.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    agents = module.read_pin(SOURCE, None)["agents"]
    return {name: agents[name] for name in ("codex", "claude")}


VERSIONS = pinned_agent_versions()
BROKER_INPUTS = [
    "Cargo.lock", "crates/codewire-credential-broker/Cargo.toml",
    "crates/codewire-credential-broker/src/lib.rs",
    "crates/codewire-credential-broker/src/host_agent_smoke.rs",
    "crates/codewire-credential-broker/src/bin/codewire-host-agent-smoke.rs",
    "crates/codewire-credential-broker/src/runtime.rs",
    "crates/codewire-credential-broker/src/runtime/native_managed_smoke.rs",
    "crates/codewire-credential-broker/src/openai.rs",
    "crates/codewire-credential-broker/src/anthropic.rs",
    "crates/codewire-local-credentials/src/lib.rs",
    "crates/codewire-protected-store/src/lib.rs",
]
TOKEN = re.compile(r"cwlocal(?:broker|anthropic|openai)[0-9a-f]{32}|cwhm_[0-9a-f]{64}")


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def scrub(text, limit=1200):
    return TOKEN.sub("[REDACTED]", str(text))[:limit]


def closed(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), f"invalid {label} fields")
    return value


def hexdigest(value, size=64):
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{size}}}", value) is not None


def stable(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
            metadata.st_mode, metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def directory(path, private=False):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, "directory contains a symlink or noncanonical component")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(fd)
        require(metadata.st_uid in (0, os.geteuid()) and stat.S_ISDIR(metadata.st_mode), "unowned directory")
        require(stat.S_IMODE(metadata.st_mode) == 0o700 if private else not metadata.st_mode & 0o022,
                "unsafe directory permissions")
        require(stable(path.lstat()) == stable(metadata), "directory changed while opened")
        return fd
    except BaseException:
        os.close(fd)
        raise


def admit_scratch(path):
    path = Path(path).absolute()
    descriptor = directory(path, private=True)
    try:
        require(os.fstat(descriptor).st_uid == os.geteuid(), "scratch parent must be owned by this user")
        require(not os.fstatvfs(descriptor).f_flag & os.ST_NOEXEC,
                "scratch parent filesystem does not permit executable agent payloads")
    finally:
        os.close(descriptor)
    return path


def scan_regular(path, maximum, executable=False, system=False, capture=False, sink=None):
    """Bounded held nofollow file read, including mutation/path replacement fence."""
    path = Path(path).absolute()
    parent = directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_uid in ((0,) if system else (0, os.geteuid())) and
                not before.st_mode & 0o7022 and 0 < before.st_size <= maximum,
                "unsafe regular file")
        require(not executable or before.st_mode & 0o111, "file is not executable")
        data, digest, count = bytearray(), hashlib.sha256(), 0
        deadline = time.monotonic() + 60
        while count <= before.st_size:
            require(time.monotonic() < deadline, "file admission deadline expired")
            chunk = os.read(fd, min(65536, before.st_size + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            digest.update(chunk)
            if capture:
                data.extend(chunk)
            if sink is not None:
                view = memoryview(chunk)
                while view:
                    written = os.write(sink, view)
                    require(written > 0, "file staging write stalled")
                    view = view[written:]
        require(count == before.st_size and stable(os.fstat(fd)) == stable(before) and
                stable(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == stable(before),
                "file changed while admitted")
        return digest.hexdigest(), before, bytes(data)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def regular(path, maximum, executable=False, system=False):
    _, metadata, data = scan_regular(path, maximum, executable, system, capture=True)
    return data, metadata


def json_value(raw):
    def pairs(items):
        value = {}
        for key, member in items:
            require(key not in value, "duplicate JSON field")
            value[key] = member
        return value
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, ValueError) as error:
        raise Failure("invalid JSON input") from error


def relative(value):
    require(isinstance(value, str) and len(value) <= 240 and
            re.fullmatch(r"[A-Za-z0-9._/-]+", value) and
            len(value.split("/")) <= 16 and
            all(part not in ("", ".", "..") for part in value.split("/")),
            "invalid payload relative path")
    require(not any(part.lower() in ("auth.json", "credentials.json", "login.json", ".env")
                    for part in value.split("/")), "payload includes a login/config member")
    return value


def elf_metadata(path):
    digest, metadata, _ = scan_regular(path, MAX_AGENT_FILE, executable=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(stable(os.fstat(fd)) == stable(metadata), "ELF changed before parsing")
        raw = os.read(fd, 64)
        require(raw[:6] == b"\x7fELF\x02\x01" and len(raw) == 64 and
                struct.unpack_from("<H", raw, 18)[0] == 62, "not an admitted Linux amd64 ELF")
    # readelf only parses admitted public bytes; it never executes the candidate.
        result = subprocess.run(["/usr/bin/readelf", "-l", "-d", f"/proc/self/fd/{fd}"],
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, pass_fds=(fd,),
                                capture_output=True, text=True, timeout=15)
        require(stable(os.fstat(fd)) == stable(metadata) and stable(Path(path).lstat()) == stable(metadata),
                "ELF changed while parsed")
    finally:
        os.close(fd)
    require(result.returncode == 0 and len(result.stdout) < 256 * 1024, "ELF metadata admission failed")
    interpreters = re.findall(r"Requesting program interpreter: ([^\]]+)\]", result.stdout)
    needed = re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", result.stdout)
    require(len(interpreters) <= 1 and all(x == "/lib64/ld-linux-x86-64.so.2" for x in interpreters) and
            set(needed) <= set(SONAMES), "unsupported host loader/library dependency")
    return {"interpreter": interpreters[0] if interpreters else None, "needed": sorted(needed), "sha256": digest}


def inventory(root, manifest_name):
    """All physical members count, including hidden/untracked files."""
    result, directories = set(), set()
    queue = [(Path(root), "")]
    while queue:
        parent, prefix = queue.pop()
        fd = directory(parent)
        try:
            for name in os.listdir(fd):
                value = relative(prefix + name)
                if value == manifest_name:
                    continue
                metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    directories.add(value)
                    queue.append((parent / name, value + "/"))
                else:
                    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                            "payload contains a link or special member")
                    result.add(value)
                require(len(result) + len(directories) <= MAX_FILES * 2, "payload inventory exceeded bound")
        finally:
            os.close(fd)
    implied = {str(Path(value).parent) for value in result if Path(value).parent != Path(".")}
    for name in list(implied):
        implied.update(str(p) for p in Path(name).parents if p != Path("."))
    require(directories == implied, "payload contains an uncovered or empty directory")
    return result


def admit_agents(manifest_path, expected_sha256):
    require(hexdigest(expected_sha256), "invalid expected agent manifest pin")
    path = Path(manifest_path).absolute()
    raw, _ = regular(path, MAX_MANIFEST)
    observed_sha256 = hashlib.sha256(raw).hexdigest()
    require(observed_sha256 == expected_sha256, "agent manifest differs from its admitted pin")
    manifest = closed(json_value(raw), ["schema", "platform", "source", "agents", "host_runtime", "files"], "agent manifest")
    require(manifest["schema"] == "codewire.host-agent-payloads/v1" and manifest["platform"] == "linux/amd64",
            "unsupported agent manifest")
    source = closed(manifest["source"], ["kind", "image_digest", "verification_sha256", "source_revision"], "agent source")
    require(source["kind"] == "workspace-oci" and isinstance(source["image_digest"], str) and
            source["image_digest"].startswith("sha256:") and hexdigest(source["image_digest"][7:]) and
            hexdigest(source["verification_sha256"]) and hexdigest(source["source_revision"], 40),
            "invalid agent source binding")
    runtime = closed(manifest["host_runtime"], ["kind", "loader", "sonames"], "host runtime")
    require(runtime == {"kind": "ordinary-trusted-linux-os", "loader": "/lib64/ld-linux-x86-64.so.2", "sonames": SONAMES},
            "unsupported ordinary host runtime")
    entries = closed(manifest["agents"], VERSIONS, "agents")
    for name, entry in entries.items():
        closed(entry, ["version", "entry"], "agent entry")
        require(entry["version"] == VERSIONS[name], "agent version differs from the pinned workspace image")
        relative(entry["entry"])
    files = manifest["files"]
    require(isinstance(files, list) and 2 <= len(files) <= MAX_FILES, "invalid payload member count")
    pins, total = {}, 0
    for item in files:
        closed(item, ["path", "sha256", "size", "mode"], "payload member")
        name = relative(item["path"])
        require(name not in pins and hexdigest(item["sha256"]) and type(item["size"]) is int and
                0 < item["size"] <= MAX_AGENT_FILE and type(item["mode"]) is int and
                0 < item["mode"] <= 0o777 and item["mode"] & 0o400 and not item["mode"] & 0o022,
                "invalid payload member pin")
        total += item["size"]
        require(total <= MAX_AGENT_TOTAL, "payload exceeded total byte bound")
        pins[name] = item
    require(list(pins) == sorted(pins) and {x["entry"] for x in entries.values()} <= set(pins),
            "payload entry/inventory mismatch")
    require(inventory(path.parent, path.name) == set(pins), "payload inventory is not complete")
    identities = {}
    for name, item in pins.items():
        digest, metadata, _ = scan_regular(path.parent / name, MAX_AGENT_FILE)
        require(metadata.st_size == item["size"] and stat.S_IMODE(metadata.st_mode) == item["mode"] and
                digest == item["sha256"], "payload byte/mode pin mismatch")
        identities[name] = stable(metadata)
    # Complete vendor trees also contain executable-mode data and optional
    # voice plugins. They remain byte-bound bundled resources, never mistaken
    # for the entrypoints or for ordinary OS libraries. Pin the actual CLI and
    # fixed shell/search/code-mode executables used by this journey.
    native = {entry["entry"] for entry in entries.values()}
    native.update(name for name in pins if Path(name).name in {"codex-code-mode-host", "rg", "zsh", "bwrap"})
    elfs = {name: elf_metadata(path.parent / name) for name in sorted(native)}
    return {"path": path, "manifest": manifest, "sha256": observed_sha256, "expected_sha256": expected_sha256,
            "pins": pins, "identities": identities, "elf": elfs}


def stage_agents(admitted, root):
    target = Path(root) / "payload"
    target.mkdir(mode=0o700)
    for name, pin in admitted["pins"].items():
        source = admitted["path"].parent / name
        final = target / name
        final.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(final, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            digest, metadata, _ = scan_regular(source, MAX_AGENT_FILE, sink=fd)
            require(stable(metadata) == admitted["identities"][name] and digest == pin["sha256"],
                    "payload changed before staging")
            os.fchmod(fd, 0o500 if pin["mode"] & 0o111 else 0o400)
            os.fsync(fd)
        finally:
            os.close(fd)
        require(scan_regular(final, MAX_AGENT_FILE)[0] == pin["sha256"], "staged bytes differ")
    binaries = Path(root) / "bin"
    binaries.mkdir(mode=0o700)
    for name, entry in admitted["manifest"]["agents"].items():
        executable = target / entry["entry"]
        wrapper = binaries / name
        wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(str(executable)) + ' "$@"\n')
        wrapper.chmod(0o500)
    # Seal after all leaf admission. Relative helper/resource layout is intact.
    for parent, dirs, _ in os.walk(target, topdown=False):
        Path(parent).chmod(0o500)
    return target, binaries


def system_inputs():
    paths = [Path("/usr/lib") / name for name in [*SONAMES, "libgcc_s.so.1"]]
    paths += [Path(x) for x in ("/lib64/ld-linux-x86-64.so.2", "/usr/bin/readelf", "/usr/bin/bash",
                               "/usr/bin/sh", "/usr/bin/printf", "/usr/bin/python3", "/usr/bin/sleep")]
    result = {}
    for path in paths:
        resolved = path.resolve(strict=True)
        require(str(resolved).startswith(("/usr/lib/", "/usr/bin/")), "system runtime escaped its fixed roots")
        digest, metadata, _ = scan_regular(resolved, MAX_AGENT_FILE, system=True)
        result[str(path)] = {"target": str(resolved), "sha256": digest,
                             "identity": stable(metadata)}
    return result


def verify_system(inputs):
    require(system_inputs() == inputs, "ordinary host runtime changed during the journey")


def remove_owned_tree(root, identity):
    """Delete only a fully inventoried private tree after external ECHILD proof.

    Symlink authority is limited to the managed entry itself; no link is ever
    traversed. Open directory FDs and leaf identities fence replacement. Any
    unsupported member preserves the whole tree before the first unlink.
    """
    root = Path(root)
    top = directory(root, private=True)
    entries, opened, total = [], [top], 0
    deadline = time.monotonic() + 30
    require((os.fstat(top).st_dev, os.fstat(top).st_ino) == identity, "owned scratch root was replaced")
    try:
        def walk(fd, prefix):
            nonlocal total
            for name in sorted(os.listdir(fd)):
                require(time.monotonic() < deadline and len(entries) < 65536, "cleanup inventory exceeded bound")
                relative(prefix + name)
                metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(metadata.st_uid == os.geteuid(), "cleanup member is not owned")
                if stat.S_ISDIR(metadata.st_mode):
                    require(not metadata.st_mode & 0o022, "cleanup directory is writable by another user")
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    opened.append(child)
                    require(stable(os.fstat(child)) == stable(metadata), "cleanup directory was replaced")
                    walk(child, prefix + name + "/")
                    entries.append((fd, name, metadata, child))
                elif stat.S_ISREG(metadata.st_mode):
                    require(metadata.st_nlink == 1 and not metadata.st_mode & 0o7022, "cleanup file has external aliases or unsafe mode")
                    total += metadata.st_size
                    require(total <= MAX_AGENT_TOTAL + 4 * MAX_CW_FILE, "cleanup bytes exceeded bound")
                    entries.append((fd, name, metadata, None))
                else:
                    require(stat.S_ISLNK(metadata.st_mode) and prefix + name == "entry/cw", "cleanup refuses special/unadmitted link")
                    target = (root / prefix / name).resolve(strict=True)
                    require(target.parent.parent == root / "store" / "versions" and hexdigest(target.parent.name) and
                            target.name == "cw", "managed entry escaped the owned store")
                    entries.append((fd, name, metadata, None))
        walk(top, "")
        # Revalidate the complete inventory before changing readonly directories.
        for fd, name, metadata, child in entries:
            require(stable(os.stat(name, dir_fd=fd, follow_symlinks=False)) == stable(metadata), "cleanup inventory changed")
            if child is not None:
                require(stable(os.fstat(child)) == stable(metadata), "cleanup directory changed")
        require((root.lstat().st_dev, root.lstat().st_ino) == identity, "cleanup root changed")
        for fd in opened:
            os.fchmod(fd, stat.S_IMODE(os.fstat(fd).st_mode) | 0o700)
        for fd, name, metadata, child in entries:
            current = os.stat(name, dir_fd=fd, follow_symlinks=False)
            # Own directory entry removal changes its mtime/ctime/link count.
            require((current.st_dev, current.st_ino, current.st_uid, stat.S_IFMT(current.st_mode)) ==
                    (metadata.st_dev, metadata.st_ino, metadata.st_uid, stat.S_IFMT(metadata.st_mode)),
                    "cleanup member identity changed")
            if child is not None:
                os.rmdir(name, dir_fd=fd)
            else:
                require(stable(current) == stable(metadata), "cleanup leaf changed")
                os.unlink(name, dir_fd=fd)
        require((root.lstat().st_dev, root.lstat().st_ino) == identity, "cleanup root replaced before removal")
        root.rmdir()
    finally:
        for fd in reversed(opened):
            os.close(fd)


def subreaper(enabled=None):
    library = ctypes.CDLL(None, use_errno=True)
    library.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    library.prctl.restype = ctypes.c_int
    if enabled is not None:
        require(library.prctl(36, int(enabled), 0, 0, 0) == 0, "Linux subreaper setup failed")
    value = ctypes.c_int()
    require(library.prctl(37, ctypes.addressof(value), 0, 0, 0) == 0 and value.value == 1,
            "Linux subreaper custody is unavailable")
    # A namespace/kernel without this procfs API must refuse before launch.
    # It must never substitute an unowned PPID census for kernel custody.
    children(os.getpid())


def process_stat(pid):
    values = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    require(values[0] not in ("Z", "X"), "owned process is terminal")
    return {"parent": int(values[1]), "birth": int(values[19])}


class Process:
    """An owned kernel handle, birth, image and socket evidence where applicable."""
    def __init__(self, pid, fd=None, parent=None):
        self.pid = pid
        self.fd = os.pidfd_open(pid) if fd is None else fd
        self.image_fd = None
        try:
            require(not select.select([self.fd], [], [], 0)[0], "owned process exited before admission")
            before = process_stat(pid)
            if parent is not None:
                require(before["parent"] == parent, "process is not the expected kernel child")
            require(Path(f"/proc/{pid}").stat().st_uid == os.geteuid(), "owned process UID differs")
            self.image_fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | os.O_CLOEXEC)
            metadata = os.fstat(self.image_fd)
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= MAX_AGENT_FILE,
                    "owned process image is unsupported")
            self.image = stable(metadata)
            self.path = os.readlink(f"/proc/{pid}/exe")
            require(not self.path.endswith(" (deleted)"), "owned process image was deleted")
            self.image_sha256 = scan_regular(self.path, MAX_AGENT_FILE, executable=True)[0]
            require(stable(os.fstat(self.image_fd)) == self.image, "process image changed while hashed")
            with Path(f"/proc/{pid}/cmdline").open("rb") as command:
                command_bytes = command.read(64 * 1024 + 1)
            require(len(command_bytes) <= 64 * 1024, "owned argv exceeded bound")
            self.args = command_bytes.split(b"\0")[:-1]
            require(sum(map(len, self.args)) <= 64 * 1024, "owned argv exceeded bound")
            self.birth = before["birth"]
            self.boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            require(process_stat(pid) == before, "owned birth changed during admission")
            self.verify()
        except BaseException:
            self.close()
            raise

    def dead(self):
        return bool(select.select([self.fd], [], [], 0)[0])

    def verify(self):
        require(not self.dead() and process_stat(self.pid)["birth"] == self.birth and
                Path("/proc/sys/kernel/random/boot_id").read_text().strip() == self.boot and
                stable(os.fstat(self.image_fd)) == self.image and
                stable(Path(f"/proc/{self.pid}/exe").stat()) == self.image and
                os.readlink(f"/proc/{self.pid}/exe") == self.path and
                Path(f"/proc/{self.pid}/cmdline").read_bytes().split(b"\0")[:-1] == self.args,
                "retained process changed or exited")

    def signal(self, number, direct=False):
        if self.dead():
            return
        self.verify()
        if direct:
            require(process_stat(self.pid)["parent"] == os.getpid(), "signal target is not an adopted child")
        signal.pidfd_send_signal(self.fd, number)

    def close(self):
        for name in ("image_fd", "fd"):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)


def children(pid):
    # Each process's /proc stat names its parent; a kernel without
    # CONFIG_PROC_CHILDREN (the CI's Kata guests) has no task children
    # lists. A process gone mid-scan is skipped; comm may hold ')'.
    found = set()
    for entry in os.scandir("/proc"):
        if not entry.name.isdecimal():
            continue
        try:
            raw = (Path("/proc") / entry.name / "stat").read_bytes()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if b")" in raw and int(raw[raw.rindex(b")") + 2:].split()[1]) == pid:
            found.add(int(entry.name))
    require(len(found) <= 256, "owned child inventory exceeded bound")
    return found


def descendants(pid):
    found, pending = set(), [pid]
    while pending:
        for child in children(pending.pop()):
            if child not in found:
                found.add(child)
                pending.append(child)
            require(len(found) <= 256, "owned descendant inventory exceeded bound")
    return found


def reap_family(timeout=15, salvage=False):
    """Actual all-child ECHILD, never snapshot-based family completeness."""
    subreaper()
    deadline = time.monotonic() + timeout
    handles, signalled = {}, []
    try:
        while True:
            for pid in children(os.getpid()):
                if pid not in handles:
                    try:
                        handles[pid] = Process(pid, parent=os.getpid())
                    except (FileNotFoundError, ProcessLookupError):
                        continue
                    except Failure:
                        # Terminal children are reaped below; live ambiguous
                        # ownership never reaches a signal or deletion path.
                        try:
                            status = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
                        except FileNotFoundError:
                            continue
                        require(status in ("Z", "X"), "adopted child custody is ambiguous")
            try:
                while True:
                    pid, _ = os.waitpid(-1, os.WNOHANG | WALL)
                    if pid == 0:
                        break
            except ChildProcessError:
                require(all(handle.dead() for handle in handles.values()), "ECHILD disagrees with a held child")
                return {"echild": True, "salvage": signalled}
            remaining = deadline - time.monotonic()
            require(remaining > 0, "owned family cleanup is unknown")
            if salvage:
                elapsed = timeout - remaining
                for handle in handles.values():
                    if not handle.dead():
                        number = signal.SIGKILL if elapsed > 2 else signal.SIGTERM
                        key = (handle.pid, handle.birth, number)
                        if key not in signalled:
                            handle.signal(number, direct=True)
                            signalled.append(key)
            time.sleep(min(0.05, remaining))
    finally:
        for handle in handles.values():
            handle.close()


def socket_process(path):
    before = path.lstat()
    require(stat.S_ISSOCK(before.st_mode) and before.st_uid == os.geteuid(), "host daemon socket is unowned")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(path))
        # Kernel socket-derived handle, not numeric PID followed by pidfd_open.
        handle = struct.unpack("i", connection.getsockopt(socket.SOL_SOCKET, PEERPIDFD, 4))[0]
        fcntl.fcntl(handle, fcntl.F_SETFD, fcntl.fcntl(handle, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)
        try:
            pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == os.geteuid() and stable(path.lstat()) == stable(before), "daemon socket peer changed")
            actor = Process(pid, fd=handle)
            handle = None
            return actor, (before.st_dev, before.st_ino)
        finally:
            if handle is not None:
                os.close(handle)


def load_producer(source):
    path = Path(source) / "scripts/ci/release/cw_release.py"
    regular(path, 2 * 1024 * 1024)
    spec = importlib.util.spec_from_file_location("cw_host_acceptance_release", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def admit_release(path, pin, producer):
    require(hexdigest(pin), "invalid cw pin")
    path = Path(path).absolute()
    raw, _ = regular(path / "cw-runtime.json", MAX_MANIFEST)
    identity = json_value(raw)
    binary, _ = regular(path / "cw", MAX_CW_FILE, executable=True)
    require(hashlib.sha256(binary).hexdigest() == pin == identity.get("sha256"), "cw artifact hash differs")
    # Reuse the checked-in primary binary/build-record admission. Original
    # asset source is an explicit dependency, not the new harness source.
    admitted = producer.make_identity(binary, identity["target"], identity["package_version"],
                                      identity["source_revision"], identity["source_tree_sha256"], identity["rustc"])
    require(admitted == identity, "cw compiled identity differs from its artifact")
    return {"path": path, "identity": identity}


def admit_broker(path, receipt_path, source, producer):
    raw, metadata = regular(path, MAX_CW_FILE, executable=True)
    receipt = closed(json_value(regular(receipt_path, MAX_MANIFEST)[0]),
                     ["schema", "source_revision", "source_tree_sha256", "executable_sha256", "executable_size", "toolchain",
                      "profile", "features", "inputs", "build_exit", "source_unchanged"], "broker build receipt")
    require(receipt["schema"] == "codewire.host-agent-broker-build/v1" and
            hexdigest(receipt["source_revision"], 40) and receipt["toolchain"] == "1.99.1" and
            receipt["profile"] == "ci" and receipt["features"] == ["host-agent-synthetic-smoke"] and
            type(receipt["build_exit"]) is int and receipt["build_exit"] == 0 and receipt["source_unchanged"] is True and
            receipt["executable_sha256"] == hashlib.sha256(raw).hexdigest() and
            receipt["executable_size"] == metadata.st_size, "broker build receipt differs")
    require(producer.head_revision(source) == receipt["source_revision"] and
            hexdigest(receipt["source_tree_sha256"]) and producer.source_tree_sha256(source) == receipt["source_tree_sha256"],
            "composed broker source/dependency graph differs from build")
    pins = closed(receipt["inputs"], BROKER_INPUTS, "broker source inputs")
    for name, pin in pins.items():
        require(hexdigest(pin) and hashlib.sha256(regular(Path(source) / name, 16 * 1024 * 1024)[0]).hexdigest() == pin,
                "composed broker/native grammar input changed")
    return receipt


def notification_id(message):
    raw = bytearray(hashlib.sha256(("codewire-agent-notification:v1:" + message).encode()).digest()[:16])
    raw[6] = (raw[6] & 0x0f) | 0x40
    raw[8] = (raw[8] & 0x3f) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def read_private_ready(stream, timeout=15):
    deadline, result = time.monotonic() + timeout, bytearray()
    while not result.endswith(b"\n"):
        remaining = deadline - time.monotonic()
        require(remaining > 0 and select.select([stream], [], [], remaining)[0], "private ready pipe timed out")
        chunk = os.read(stream.fileno(), 2049 - len(result))
        require(chunk and len(result) + len(chunk) <= 2048, "invalid private ready framing")
        result.extend(chunk)
    require(result.count(b"\n") == 1, "multiple private ready records")
    return bytes(result)


class Journey:
    def __init__(self, args, assets, agents, broker, system):
        subreaper(True)
        self.root = Path(tempfile.mkdtemp(prefix="cwhm-", dir=admit_scratch(args.scratch_parent)))
        self.root.chmod(0o700)
        self.root_identity = (self.root.stat().st_dev, self.root.stat().st_ino)
        self.workspace = self.root / "project"
        self.workspace.mkdir(mode=0o700)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.codex_home = self.home / ".codex"
        self.codex_home.mkdir(mode=0o700)
        self.env = {"HOME": str(self.home), "USER": "noel", "LOGNAME": "noel", "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin", "TERM": "dumb", "SHELL": "/usr/bin/bash",
                    "CW_HOST_DATA_DIR": str(self.root / "hosts"), "CW_CONFIG_DIR": str(self.root / "config"),
                    "CODEX_HOME": str(self.codex_home), "HTTP_PROXY": "http://127.0.0.1:1",
                    "HTTPS_PROXY": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1",
                    "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "CLAUDE_CODE_DISABLE_AUTO_UPDATER": "1",
                    "ANTHROPIC_API_KEY": "", "CLAUDE_CODE_OAUTH_TOKEN": "", "ANTHROPIC_MAX_RETRIES": "0"}
        self.args, self.assets, self.agent_input, self.broker_receipt, self.system = args, assets, agents, broker, system
        self.cw = str(assets[0]["path"] / "cw")
        self.store, self.entry = self.root / "store", self.root / "entry" / "cw"
        self.environment = None
        self.owned = []
        self.actors = []
        self.conversations = {}
        self.notifications = []
        self.checks, self.commands, self.observations = [], [], []
        self.agent_versions = {}
        self.capability = None
        self.broker_process = self.sentinel = None
        self.broker_actor = self.sentinel_actor = None
        self.setup_daemon_actor = None
        self.setup_proof = None
        self.daemon_binding = None
        self.cleanup_result = None
        self.cleanup_attempted = False
        self.deadline = time.monotonic() + 1500

    def popen(self, argv, **options):
        subreaper()
        return subprocess.Popen(argv, env=self.env, cwd=self.workspace, close_fds=True, **options)

    def call(self, *args, expected=0, timeout=60, data=False):
        subreaper()
        timeout = min(timeout, max(1, self.deadline - time.monotonic()))
        result = subprocess.run([self.cw, *args], env=self.env, cwd=self.workspace, close_fds=True,
                                text=True, capture_output=True, timeout=timeout)
        self.commands.append({"argv": [self.cw, *args], "exit": result.returncode})
        require(result.returncode == expected if expected is not None else True,
                f"cw operation exited {result.returncode}: {scrub(result.stderr)}; {scrub(result.stdout)}")
        require(not TOKEN.search(result.stdout + result.stderr), "provider canary or capability leaked into cw output")
        return json_value(result.stdout) if data else result

    def check(self, label):
        require(self.sentinel_actor is not None and not self.sentinel_actor.dead(), "unrelated sentinel exited")
        self.checks.append(label)
        print(f"host-managed: {label} PASS", flush=True)

    def until(self, probe, accept, timeout=90):
        end = min(self.deadline, time.monotonic() + timeout)
        while time.monotonic() < end:
            value = probe()
            if accept(value):
                return value
            time.sleep(0.2)
        raise Failure("bounded host acceptance wait expired")

    def inbox(self, session):
        return self.call("inbox", self.environment, session, "--output", "json", data=True)

    def idle(self, session):
        return self.until(lambda: self.inbox(session), lambda value: value.get("driver") and value["driver"]["phase"] == "idle")

    def message(self, message, expected="completed", *, claude_interrupt=None):
        result = self.call("wait", "--message", message, "--timeout", "3m", "--output", "json",
                           expected=None, timeout=190)
        record = json_value(result.stdout)
        if claude_interrupt is not None:
            # Claude may replay a user message only after its streaming turn
            # ends. A matched native interrupt proves this Interrupted outcome;
            # keep the original message's observed ACK value unchanged.
            require(expected == "interrupted" and claude_interrupt.get("action") == "interrupt" and
                    claude_interrupt.get("state") == "completed" and claude_interrupt.get("native_acknowledged") is True and
                    claude_interrupt.get("expected_active_message_id") == message and
                    claude_interrupt.get("target_session_id") == record.get("target_session_id") and
                    claude_interrupt.get("driver_id") == record.get("driver_id") and
                    record.get("action") == "message" and
                    self.conversations.get(record.get("target_session_id"), {}).get("agent") == "claude" and
                    self.conversations[record["target_session_id"]]["driver"] == record.get("driver_id"),
                    "Claude Interrupted outcome lacks its matched native interrupt")
        require(record["id"] == message and record["state"] == expected and
                (record.get("native_acknowledged") is True or
                 (claude_interrupt is not None and record.get("native_acknowledged") is False)),
                "message lacks the expected native outcome")
        self.observations.append({"message_id": message, "state": record["state"], "turn_id": record.get("turn_id"),
                                  "native_acknowledged": record["native_acknowledged"],
                                  "result_sha256": hashlib.sha256((record.get("result") or "").encode()).hexdigest()})
        if claude_interrupt is not None:
            self.observations[-1]["interrupt_message_id"] = claude_interrupt["id"]
        return record

    def held(self, session, message, thread):
        """Observe one exact Running/Busy turn continuously for two seconds."""
        conversation = self.conversations[session]
        since = None
        turn = None

        def accept(inbox):
            nonlocal since, turn
            matches = [m for m in inbox["messages"] if m["id"] == message]
            require(len(matches) == 1, "held message is missing or duplicated")
            record, driver = matches[0], inbox["driver"]
            require(record.get("target_session_id") == session and
                    record.get("driver_id") == conversation["driver"] and
                    driver.get("driver_id") == conversation["driver"] and
                    driver.get("native_thread_id") == thread and thread,
                    "held turn changed session, driver or conversation")
            require(record["state"] not in ("completed", "error", "interrupted", "unknown"),
                    "held turn ended before native interrupt")
            active = (driver.get("active_message_id") == message and driver.get("phase") == "busy" and
                      record["state"] == "running")
            if active and conversation["agent"] != "claude":
                current = driver.get("current_turn_id")
                active = record.get("native_acknowledged") is True and bool(current)
                if active:
                    require(isinstance(current, str) and record.get("turn_id") == current,
                            "running Codex message differs from its native turn")
                    require(turn is None or turn == current, "held Codex native turn changed")
                    # An inactivity gap resets only the dwell, never this pin.
                    turn = current
            if not active:
                since = None
                return False
            now = time.monotonic()
            since = now if since is None else since
            return now - since >= 2

        return self.until(lambda: self.inbox(session), accept)

    def interrupt_held(self, session, thread, parent=None):
        held = self.send(session, "CW_FIXTURE_HOLD " + uuid.uuid4().hex[:8] + "\nWait.")
        inbox = self.held(session, held["id"], thread)
        interrupted = self.call("interrupt", self.environment, "--session", session, "--output", "json", data=True)
        control = self.message(interrupted["id"])
        require(control.get("action") == "interrupt" and control.get("target_session_id") == session and
                control.get("driver_id") == self.conversations[session]["driver"] and
                control.get("expected_active_message_id") == held["id"] and
                control.get("expected_turn_id") == inbox["driver"].get("current_turn_id"),
                "native interrupt targeted another active turn")
        claude = self.conversations[session]["agent"] == "claude"
        original = self.message(held["id"], "interrupted", claude_interrupt=control if claude else None)
        if not claude:
            require(original.get("turn_id") == inbox["driver"]["current_turn_id"],
                    "Codex Interrupted outcome changed native turn")
        idle = self.idle(session)
        require(idle["driver"]["native_thread_id"] == thread and
                idle["driver"]["driver_id"] == self.conversations[session]["driver"],
                "native interrupt changed driver or conversation")
        if parent is not None:
            self.notification(held["id"], session, parent)
        return original

    def send(self, session, text, action="msg", turn=None, refused=False):
        argv = [action, self.environment, session, text]
        if turn is not None:
            argv += ["--turn-id", turn]
        argv += ["--output", "json"]
        if refused:
            require(self.call(*argv, expected=None).returncode != 0, "unsupported/stale control unexpectedly succeeded")
            return None
        return self.call(*argv, data=True)

    def launch(self, name, agent, parent=None, prompt=None):
        argv = ["run", "--in", self.environment, "--name", name, "--detach", "--output", "json", "--agent", agent,
                "--model", "codewire-synthetic" if agent == "codex" else "claude-sonnet-4-6"]
        if parent:
            argv += ["--parent", parent]
        if prompt:
            argv += ["--prompt", prompt]
        launched = self.call(*argv, data=True)
        session = launched["session"]["session_id"]
        require(session not in self.owned and launched["agent"] == agent, "managed launch returned another identity")
        self.owned.append(session)
        self.conversations[session] = {"driver": launched["driver_id"], "agent": agent}
        return launched

    def turn(self, session, text="Reply with a short fixture acknowledgement. Do not use tools."):
        record = self.send(session, text)
        done = self.message(record["id"])
        require("CWCODEX149" in done.get("result", "") or "CWCLAUDE" in done.get("result", ""),
                "actual agent did not complete the protected synthetic response")
        self.idle(session)
        return done

    def notification(self, source, worker, parent):
        expected = notification_id(source)
        inbox = self.until(lambda: self.inbox(parent), lambda v: any(m["id"] == expected for m in v["messages"]), 180)
        matches = [m for m in inbox["messages"] if (m.get("source") or {}).get("message_id") == source]
        require(len(matches) == 1 and matches[0]["id"] == expected and matches[0]["action"] == "notification" and
                matches[0]["source"]["session_id"] == worker, "parent notification was missing/duplicated/rebound")
        self.message(expected)
        self.idle(parent)
        self.notifications.append((source, worker, parent))

    def snapshot(self, sessions):
        result = {}
        for session in sessions:
            inbox = self.inbox(session)
            result[session] = {"driver": {key: inbox["driver"].get(key) for key in (
                "driver_id", "native_thread_id", "started_at", "phase", "current_turn_id", "active_message_id")},
                "messages": inbox["messages"]}
        return result

    def retain(self, sessions):
        daemon, self.socket_identity = socket_process(self.root / "hosts" / self.environment / "daemon.sock")
        require(b"_host-daemon" in daemon.args, "socket peer is not the owned host daemon")
        observed = (daemon.pid, daemon.birth, daemon.path, daemon.image_sha256, self.socket_identity)
        if self.daemon_binding is None:
            require(daemon.image_sha256 == self.assets[0]["identity"]["sha256"], "host daemon did not retain A")
            self.daemon_binding = observed
        else:
            require(observed == self.daemon_binding, "host daemon was replaced across cw selection")
        self.actors.append(daemon)
        drivers = {self.conversations[s]["driver"].encode(): s for s in sessions}
        found = set()
        for pid in descendants(daemon.pid):
            try:
                actor = Process(pid)
            except (Failure, FileNotFoundError, ProcessLookupError):
                continue
            matched = next((session for driver, session in drivers.items() if driver in actor.args), None)
            if matched and b"_agent-driver" in actor.args:
                require(actor.path == str(self.entry.resolve()), "driver did not pin selected immutable cw")
                require(actor.image_sha256 == next(a["identity"]["sha256"] for a in self.assets
                        if actor.path == str(self.store / "versions" / a["identity"]["sha256"] / "cw")),
                        "managed driver image differs from admitted cw")
                self.actors.append(actor)
                found.add(matched)
                provider = self.conversations[matched]["agent"]
                expected = str(self.root / "agents" / "payload" / self.agent_input["manifest"]["agents"][provider]["entry"])
                peers = []
                for child in children(pid):
                    peer = Process(child, parent=pid)
                    if peer.path == expected:
                        require(peer.image_sha256 == self.agent_input["pins"][self.agent_input["manifest"]["agents"][provider]["entry"]]["sha256"],
                                "actual provider image differs from admitted payload")
                        require((b"app-server" in peer.args) if provider == "codex" else (b"--input-format" in peer.args and b"stream-json" in peer.args),
                                "real agent used another protocol")
                        peers.append(peer)
                    else:
                        peer.close()
                require(len(peers) == 1, "managed driver lacks exactly one admitted real provider peer")
                self.actors.extend(peers)
            else:
                actor.close()
        require(found == set(sessions), "managed driver census did not find every exact launch")

    def verify_actors(self):
        for actor in self.actors:
            actor.verify()
        self.broker_actor.verify()
        self.sentinel_actor.verify()

    def selection(self, identity, generation, previous):
        status = self.call("upgrade", "status", "--json", data=True)
        require(status["consistent"] and status["pending"] is None and status["current"] == identity["sha256"] and
                status["generation"] == generation and status["previous"] == previous and
                self.entry.resolve() == self.store / "versions" / identity["sha256"] / "cw", "cw selection differs")
        return status

    def rejected_candidates(self, before, b, generation):
        # Private copies preserve both admitted A/B bytes. Refusal must happen
        # before any selector, retained actor or journal effect.
        bad = self.root / "bad-candidate"
        bad.mkdir(mode=0o700)
        raw, _ = regular(self.assets[1]["path"] / "cw", MAX_CW_FILE, executable=True)
        changed = bytearray(raw)
        changed[-1] ^= 1
        (bad / "cw").write_bytes(changed)
        (bad / "cw").chmod(0o500)
        (bad / "cw-runtime.json").write_text(json.dumps(b) + "\n")
        (bad / "cw-runtime.json").chmod(0o400)
        require(self.call("upgrade", "--from", str(bad), "--sha256", b["sha256"],
                          "--expect-generation", str(generation), "--json", expected=None).returncode != 0,
                "corrupt candidate was selected")
        (bad / "cw").chmod(0o600)
        (bad / "cw").write_bytes(raw)
        (bad / "cw").chmod(0o500)
        unsupported = dict(b, protocol_version=999)
        (bad / "cw-runtime.json").chmod(0o600)
        (bad / "cw-runtime.json").write_text(json.dumps(unsupported) + "\n")
        (bad / "cw-runtime.json").chmod(0o400)
        require(self.call("upgrade", "--from", str(bad), "--sha256", b["sha256"],
                          "--expect-generation", str(generation), "--json", expected=None).returncode != 0,
                "unsupported candidate identity was selected")
        require(self.call("upgrade", "status", "--json", data=True) == before, "refused candidate changed selection")
        self.verify_actors()

    def start_broker(self):
        root = self.root / "authority"
        root.mkdir(mode=0o700)
        self.broker_process = self.popen([str(self.args.broker), "--root", str(root), "--environment", self.environment],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.broker_actor = Process(self.broker_process.pid, parent=os.getpid())
        require(self.broker_actor.image_sha256 == self.broker_receipt["executable_sha256"], "broker image differs from admission")
        line = read_private_ready(self.broker_process.stdout)
        ready = closed(json_value(line), ["schema", "environment_id", "codex_base_url", "anthropic_base_url",
                                         "capability", "upstream", "protected_store"], "broker ready")
        require(ready["schema"] == "codewire.host-agent-smoke/v1" and ready["environment_id"] == self.environment and
                ready["upstream"] == "synthetic" and ready["protected_store"] == "process_lifetime" and
                re.fullmatch(r"cwhm_[0-9a-f]{64}", ready["capability"]), "broker ready identity differs")
        match = re.fullmatch(r"http://127\.0\.0\.1:([1-9][0-9]*)/codex/v1", ready["codex_base_url"])
        require(match and int(match[1]) <= 65535 and ready["anthropic_base_url"] ==
                f"http://127.0.0.1:{match[1]}/anthropic", "broker route is not the one owned loopback listener")
        self.capability = ready["capability"]
        self.env.update(CW_HOST_AGENT_CAPABILITY=self.capability, ANTHROPIC_AUTH_TOKEN=self.capability,
                        ANTHROPIC_BASE_URL=ready["anthropic_base_url"])
        config = '\n'.join([
            'model_provider = "codewire_host_fixture"', 'model = "codewire-synthetic"',
            '[model_providers.codewire_host_fixture]', 'name = "Codewire protected synthetic host"',
            'base_url = ' + json.dumps(ready["codex_base_url"]), 'wire_api = "responses"',
            'env_key = "CW_HOST_AGENT_CAPABILITY"', 'requires_openai_auth = false', 'supports_websockets = false',
            'request_max_retries = 0', 'stream_max_retries = 0', 'stream_idle_timeout_ms = 660000', ''])
        (self.codex_home / "config.toml").write_text(config)
        (self.codex_home / "config.toml").chmod(0o600)

    def setup_environment(self):
        # Host children inherit their daemon's launch environment. Establish
        # the broker projection during setup, before the continuity baseline
        # or any managed conversation, rather than passing it in CLI argv.
        require(self.environment is None and not self.owned and not self.conversations and
                self.daemon_binding is None and not self.actors, "host setup is not fresh")
        self.sentinel_actor.verify()
        created = self.call("create", "--local", "--type", "host", "--name", "host-managed-proof",
                            "--path", str(self.workspace), "--output", "json", data=True)
        require(isinstance(created, dict) and type(created.get("id")) is str and
                str(uuid.UUID(created["id"])) == created["id"] and created.get("state") == "running" and
                created.get("type") == "host" and created.get("placement") == "local" and
                created.get("path") == str(self.workspace), "created host identity differs")
        self.environment = created["id"]
        socket_path = self.root / "hosts" / self.environment / "daemon.sock"

        def admit_daemon(actor):
            require(b"_host-daemon" in actor.args and self.environment.encode() in actor.args and
                    actor.image_sha256 == self.assets[0]["identity"]["sha256"] and
                    actor.path == str(self.entry.resolve()), "setup host daemon identity differs")
            actor.verify()

        self.setup_daemon_actor, initial_socket = socket_process(socket_path)
        admit_daemon(self.setup_daemon_actor)
        self.start_broker()
        require(self.capability and self.env.get("CW_HOST_AGENT_CAPABILITY") == self.capability and
                self.env.get("ANTHROPIC_AUTH_TOKEN") == self.capability and
                re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]*/anthropic", self.env.get("ANTHROPIC_BASE_URL", "")),
                "host broker projection is unavailable")
        self.broker_actor.verify()
        self.setup_daemon_actor.verify()
        stopped = self.call("stop", "--local", self.environment, "--output", "json", data=True)
        require(stopped == dict(created, state="stopped"), "setup stop changed host identity or did not confirm cleanup")
        self.until(self.setup_daemon_actor.dead, bool, timeout=10)
        self.broker_actor.verify()
        self.sentinel_actor.verify()
        started = self.call("start", "--local", self.environment, "--output", "json", data=True)
        require(started == created, "setup start changed host identity")
        daemon, self.socket_identity = socket_process(socket_path)
        self.actors.append(daemon)
        admit_daemon(daemon)
        require((daemon.pid, daemon.birth) != (self.setup_daemon_actor.pid, self.setup_daemon_actor.birth),
                "setup daemon did not acquire a new birth after confirmed stop")
        self.daemon_binding = (daemon.pid, daemon.birth, daemon.path, daemon.image_sha256, self.socket_identity)
        self.setup_proof = {"environment_id": self.environment, "public_stop_confirmed": True,
                            "initial_daemon_death_observed": self.setup_daemon_actor.dead(),
                            "public_start_confirmed": True,
                            "initial_daemon": {"pid": self.setup_daemon_actor.pid,
                                               "start_ticks": self.setup_daemon_actor.birth,
                                               "executable": self.setup_daemon_actor.path,
                                               "sha256": self.setup_daemon_actor.image_sha256,
                                               "socket_identity": initial_socket},
                            "continuity_baseline": {"pid": daemon.pid, "start_ticks": daemon.birth,
                                                    "executable": daemon.path, "sha256": daemon.image_sha256,
                                                    "socket_identity": self.socket_identity}}

    def run(self):
        agent_root = self.root / "agents"
        agent_root.mkdir(mode=0o700)
        _, bins = stage_agents(self.agent_input, agent_root)
        self.env["PATH"] = str(bins) + ":" + str(self.entry.parent) + ":/usr/bin:/bin"
        for name in VERSIONS:
            subreaper()
            result = subprocess.run([str(bins / name), "--version"], env=self.env, cwd=self.workspace,
                                    capture_output=True, text=True, timeout=20)
            require(result.returncode == 0 and result.stdout.strip() ==
                    ("codex-cli " + VERSIONS[name] if name == "codex" else VERSIONS[name] + " (Claude Code)"),
                    "actual agent version differs from its admitted manifest")
            self.agent_versions[name] = {"actual_output": result.stdout.strip(), "exit": result.returncode}
        self.sentinel = self.popen(["/usr/bin/sleep", "1800"])
        self.sentinel_actor = Process(self.sentinel.pid, parent=os.getpid())
        installed = self.call("install", "--managed", "--bin-dir", str(self.entry.parent), "--store", str(self.store), "--json", data=True)
        a, b = (asset["identity"] for asset in self.assets)
        require(installed["identity"] == a, "managed install did not return compiled A identity")
        self.cw = str(self.entry)
        generation = installed["generation"]
        self.selection(a, generation, None)
        self.setup_environment()
        self.check("admitted-real-agent-versions/private-home/protected-synthetic-broker")

        lead = self.launch("lead", "codex")["session"]["session_id"]
        self.idle(lead)
        lead_thread = self.inbox(lead)["driver"]["native_thread_id"]
        first, second = self.turn(lead), self.turn(lead)
        require(lead_thread and first["turn_id"] and second["turn_id"] and first["turn_id"] != second["turn_id"] and
                self.inbox(lead)["driver"]["native_thread_id"] == lead_thread,
                "Codex did not retain one actual conversation")
        require(self.call("send", self.environment, "--session", lead, "raw", expected=None).returncode != 0, "managed peer accepted raw terminal input")
        self.check("codex/two-native-acknowledged-turns/same-thread/raw-refused")

        nonce, token = uuid.uuid4().hex[:8], "CW_TOOL_MARKER_" + uuid.uuid4().hex[:16].upper()
        marker = self.workspace / f".cwnm-{nonce}-tool-marker"
        self.message(self.send(lead, f"CW_FIXTURE_TOOL printf %s {token} > {marker.name}\nUse the offered shell tool once.")["id"])
        require(marker.read_text() == token, "actual Codex shell tool did not create its exact marker")
        self.idle(lead)
        self.check("actual-codex/offered-shell-tool-marker")

        worker_launch = self.launch("worker", "claude", lead, "Reply with a short fixture acknowledgement. Do not use tools.")
        worker = worker_launch["session"]["session_id"]
        completed = self.message(worker_launch["message"]["id"])
        self.idle(worker)
        worker_thread = self.inbox(worker)["driver"]["native_thread_id"]
        require(worker_thread and worker_launch["session"]["parent_session_id"] == lead and
                self.inbox(worker)["parent"] == {"session_id": lead, "driver_id": self.conversations[lead]["driver"]},
                "Claude did not establish its native UUID and canonical parent")
        self.notification(completed["id"], worker, lead)
        resumed_turn = self.turn(worker)
        require(self.inbox(worker)["driver"]["native_thread_id"] == worker_thread, "Claude second turn changed conversation")
        self.notification(resumed_turn["id"], worker, lead)
        self.check("claude/native-ack/same-conversation/idle-parent-wake-once")

        self.send(worker, "unsupported", action="steer", refused=True)
        for session in (lead, worker):
            capabilities = self.inbox(session)["driver"]["capabilities"]
            if session == worker and not capabilities.get("interrupt"):
                require(self.call("interrupt", self.environment, "--session", session, "--output", "json", expected=None).returncode != 0,
                        "undetected Claude interrupt was silently accepted")
                continue
            self.interrupt_held(session, lead_thread if session == lead else worker_thread,
                                parent=lead if session == worker else None)
        self.check("native-interrupt/claude-steer-and-undetected-controls-refused")

        stopped = self.call("stop", self.environment, "--session", worker, "--output", "json", data=True)[0]
        require(stopped["state"] == "Stopped" and not stopped["cleanup_unknown"], "worker public Stop was not clean")
        self.call("restart", self.environment, "--session", worker, "--output", "json", data=True)
        self.idle(worker)
        resumed = self.turn(worker)
        require(self.inbox(worker)["driver"]["native_thread_id"] == worker_thread, "Claude restart changed its conversation")
        self.notification(resumed["id"], worker, lead)
        self.check("claude/public-stop/restart/same-uuid/parent-once")

        active_launch = self.launch("active", "codex")
        active = active_launch["session"]["session_id"]
        self.idle(active)
        nonce = uuid.uuid4().hex[:8]
        hold = self.send(active, f"CW_FIXTURE_UPDATE_STEERABLE {nonce}\nWait for native steering.")
        inbox = self.until(lambda: self.inbox(active), lambda v: v["driver"]["active_message_id"] == hold["id"] and v["driver"]["current_turn_id"])
        turn, thread = inbox["driver"]["current_turn_id"], inbox["driver"]["native_thread_id"]
        self.retain([lead, worker, active])
        originals = self.snapshot([lead, worker, active])
        before = self.call("upgrade", "status", "--json", data=True)
        require(self.call("upgrade", "--from", str(self.assets[1]["path"]), "--sha256", b["sha256"],
                          "--expect-generation", str(generation + 1), "--json", expected=None).returncode != 0,
                "stale selection unexpectedly succeeded")
        require(self.call("upgrade", "status", "--json", data=True) == before, "stale selection changed state")
        self.rejected_candidates(before, b, generation)
        selected = self.call("upgrade", "--from", str(self.assets[1]["path"]), "--sha256", b["sha256"],
                             "--expect-generation", str(generation), "--json", data=True)
        require(selected["changed"], "B selection did not change")
        self.selection(b, generation + 1, a["sha256"])
        self.verify_actors()
        require(self.snapshot([lead, worker, active]) == originals, "update changed/replayed an original conversation")
        fresh = self.launch("selected-B", "codex")["session"]["session_id"]
        self.turn(fresh)
        self.retain([fresh])
        self.send(active, "wrong", action="steer", turn="wrong-turn", refused=True)
        steered = self.send(active, f"CW_FIXTURE_UPDATE_STEER {nonce}\nFinish now.", action="steer", turn=turn)
        # CLI delivery exit precedes native ACK. Waiting Completed before B
        # releases the stream would deadlock and cannot prove native steering.
        self.until(lambda: self.inbox(active), lambda v: any(m["id"] == steered["id"] and
                   m["native_acknowledged"] and m["state"] == "running" for m in v["messages"]))
        require(self.inbox(active)["driver"]["current_turn_id"] == turn, "native steering changed original turn")
        released = self.message(self.send(fresh, f"CW_FIXTURE_UPDATE_RELEASE {nonce}\nRelease once.")["id"])
        require(f"CW_UPDATE_RELEASE_ACK {nonce}" in released.get("result", ""), "separate idle B did not release the hold")
        self.message(steered["id"])
        held = self.message(hold["id"])
        require(f"CW_UPDATE_STEERED {nonce}" in held.get("result", "") and "CW_UPDATE_HOLD_EXPIRED" not in held.get("result", "") and
                held["turn_id"] == turn and self.inbox(active)["driver"]["native_thread_id"] == thread,
                "original A hold did not consume one steer on the same conversation")
        self.idle(active)
        self.verify_actors()
        self.check("A-to-B/live-real-actors/no-replay/native-ack-before-B-release/original-turn-steer")

        original = self.snapshot([lead, worker, active, fresh])
        self.call("upgrade", "rollback", "--expect-generation", str(generation + 1), "--json", data=True)
        self.selection(a, generation + 2, b["sha256"])
        self.verify_actors()
        require(self.snapshot([lead, worker, active, fresh]) == original and marker.read_text() == token,
                "rollback changed history/workspace or replayed a turn")
        for message, source, parent in self.notifications:
            matches = [m for m in self.inbox(parent)["messages"] if (m.get("source") or {}).get("message_id") == message]
            require(len(matches) == 1 and matches[0]["source"]["session_id"] == source, "notification duplicated across update")
        verify_system(self.system)
        self.check("B-to-A/retained-native-images/conversations/workspace/notifications-once")

    def cleanup(self):
        """Public outcome first; salvage never upgrades a failed product proof."""
        subreaper()
        if self.cleanup_attempted:
            require(self.cleanup_result and self.cleanup_result.get("normal"), "previous cleanup remains failed")
            return self.cleanup_result
        self.cleanup_attempted = True
        failure = None
        try:
            if self.environment:
                for session in self.owned:
                    result = self.call("stop", self.environment, "--session", session, "--output", "json", data=True)
                    require(result and all(v["state"] == "Stopped" and not v["cleanup_unknown"] for v in result),
                            "public managed stop did not prove clean driver exit")
                self.call("stop", "--local", self.environment)
            if self.broker_process:
                self.broker_process.stdin.write(b"STOP\n")
                self.broker_process.stdin.flush()
                self.broker_process.stdin.close()
                require(self.broker_process.wait(timeout=10) == 0, "normal broker shutdown failed")
            if self.setup_daemon_actor:
                require(self.setup_daemon_actor.dead(), "initial setup daemon death remains unknown")
            end = time.monotonic() + 10
            while any(not actor.dead() for actor in self.actors):
                require(time.monotonic() < end, "public shutdown left a driver/provider family")
                time.sleep(0.05)
            if self.sentinel_actor:
                self.sentinel_actor.verify()
                self.sentinel_actor.signal(signal.SIGTERM, direct=True)
                self.sentinel.wait(timeout=5)
            closure = reap_family(timeout=5)
            require(not closure["salvage"], "normal cleanup required salvage")
            self.cleanup_result = {"normal": True, **closure}
            return self.cleanup_result
        except BaseException as error:
            failure = scrub(error)
        finally:
            if failure:
                # Reap only kernel-owned children. Preserve the product failure
                # and every root regardless of successful salvage.
                try:
                    if self.broker_process and self.broker_process.stdin and not self.broker_process.stdin.closed:
                        self.broker_process.stdin.close()
                    closure = reap_family(timeout=15, salvage=True)
                except BaseException as error:
                    closure = {"echild": False, "salvage_error": scrub(error)}
                self.cleanup_failure = {"normal": False, "error": failure, **closure}
                self.cleanup_result = self.cleanup_failure
        raise Failure(f"normal cleanup failed: {failure}")

    def report(self, success, cleanup, error=None):
        return {"schema": "codewire.actual-host-managed-journey/v1", "success": success,
                "checks": self.checks, "commands": self.commands, "cleanup": cleanup, "error": scrub(error) if error else None,
                "setup": self.setup_proof,
                "root": str(self.root), "runtime_assets": [x["identity"] for x in self.assets],
                "agent_manifest_sha256": self.agent_input["sha256"], "agent_source": self.agent_input["manifest"]["source"],
                "expected_agent_manifest_sha256": self.agent_input["expected_sha256"],
                "agents": self.agent_input["manifest"]["agents"], "elf": self.agent_input["elf"],
                "observed_versions": self.agent_versions, "native_outcomes": self.observations,
                "retained_processes": [{"pid": p.pid, "start_ticks": p.birth, "boot_id": p.boot,
                                        "executable": p.path, "sha256": p.image_sha256,
                                        "identity": p.image, "argv": [scrub(a.decode(errors="replace")) for a in p.args],
                                        "exit_observed": p.dead()} for p in [*self.actors, self.broker_actor, self.sentinel_actor] if p],
                "broker_build": self.broker_receipt, "ordinary_host_runtime": self.system,
                "test_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "claims": {"actual_agents": set(self.agent_versions) == set(VERSIONS), "upstream": "synthetic", "protected_store": "process_lifetime",
                           "live_provider": False, "os_keyring": False, "egress_mediation": False}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("a", "b"):
        parser.add_argument(f"--release-{label}", type=Path, required=True)
        parser.add_argument(f"--sha256-{label}", required=True)
    parser.add_argument("--agents-manifest", type=Path, required=True)
    parser.add_argument("--agents-sha256", required=True, help="owner-admitted agents.json digest")
    parser.add_argument("--broker", type=Path, required=True)
    parser.add_argument("--broker-receipt", type=Path, required=True)
    parser.add_argument("--runtime-source", type=Path, default=SOURCE, help="explicit composed CW/broker source dependency")
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--scratch-parent", type=Path, required=True,
                        help="existing owned mode0700 directory on an executable filesystem")
    parser.add_argument("--admit-only", action="store_true", help="check sources/payloads; launches no agent/service")
    args = parser.parse_args()
    require(sys.platform.startswith("linux") and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
            "Linux kernel process custody is required")
    require(not args.proof.exists(), "proof already exists")
    args.scratch_parent = admit_scratch(args.scratch_parent)
    producer = load_producer(args.runtime_source)
    assets = [admit_release(getattr(args, f"release_{x}"), getattr(args, f"sha256_{x}"), producer) for x in ("a", "b")]
    require(assets[0]["identity"]["sha256"] != assets[1]["identity"]["sha256"], "A/B bytes must differ")
    agents = admit_agents(args.agents_manifest, args.agents_sha256)
    broker = admit_broker(args.broker, args.broker_receipt, args.runtime_source, producer)
    system = system_inputs()
    if args.admit_only:
        print(json.dumps({"admitted": True, "agent_manifest": agents["sha256"], "broker": broker["executable_sha256"],
                          "runtime_assets": [a["identity"]["sha256"] for a in assets], "actual_journey_run": False}))
        return
    journey = Journey(args, assets, agents, broker, system)
    success, cleanup, error = False, None, None
    try:
        journey.run()
        cleanup = journey.cleanup()
        success = True
    except BaseException as failure:
        error = scrub(failure)
        try:
            cleanup = journey.cleanup()
        except BaseException:
            cleanup = getattr(journey, "cleanup_failure", {"normal": False, "echild": False})
    finally:
        if success:
            try:
                remove_owned_tree(journey.root, journey.root_identity)
                cleanup["scratch_removed"] = True
            except BaseException as failure:
                success, error = False, scrub(failure)
                cleanup["scratch_removed"] = False
        report = journey.report(success, cleanup, error)
        output = json.dumps(report, indent=2) + "\n"
        require(not TOKEN.search(output), "protected material/capability entered report")
        fd = os.open(args.proof, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, output.encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        for actor in [journey.setup_daemon_actor, *journey.actors, journey.broker_actor, journey.sentinel_actor]:
            if actor:
                actor.close()
    require(success, f"host managed journey failed: {error}; evidence retained at {journey.root}")
    print(f"host-managed: {len(journey.checks)} actual checks passed; exact cleanup ECHILD; {args.proof}")


if __name__ == "__main__":
    try:
        main()
    except (Failure, OSError, subprocess.SubprocessError) as error:
        print("host-managed: " + scrub(error), file=sys.stderr)
        raise SystemExit(1)
