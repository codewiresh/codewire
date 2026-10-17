#!/usr/bin/env python3
"""Observe real cw A -> B -> A in the existing, caller-owned native Linux VM.

This extends test-cli-native-managed.py; it creates no environment, VM, image,
provider configuration or topology. A and B must be real, source-admitted static
CW transports from the shared producer. The host CW and caller's configuration
stay unchanged. Only the guest default changes, through public runtime commands.

Required inputs:
  --cw ABS --environment UUID
  --runtime-a ABS/cw-runtime.lock.json --image-a ABS/image.json --sha256-a SHA
  --runtime-b ABS/cw-runtime.lock.json --image-b ABS/image.json --sha256-b SHA
  --vm-state ABS/state.json --runner-socket ABS/runner.sock

Before creating a VM, use --admit-only with --cw and both runtime/image inputs
and --sha256-b. Only this mode may omit --sha256-a, deriving it from the bounded
A receipt before complete byte admission. It accepts no runtime or model flags
and reports asset admission, never a completed VM journey.

Use the checked-in synthetic protected brokers and the guest's actual agents.
--synthetic-peers is component evidence only and retains that inherited limit.
All inherited checks and cleanup remain mandatory. Source-only --self-test
launches no CW, process, provider, VM or socket.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import sys
import time
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[2]
# The synthetic rustc identities follow the repository pin, so a toolchain bump
# does not leave this suite asserting a retired channel.
PINNED_RUSTC_CHANNEL = re.search(r'channel\s*=\s*"([^"]+)"', (ROOT / "rust-toolchain.toml").read_text()).group(1)
MAX_JSON = 64 * 1024
MAX_EXE = 256 * 1024 * 1024
MAX_PACK = MAX_EXE + 16 * 1024 + 24
SO_PEERPIDFD = 77  # Linux asm-generic/socket.h; no numeric-PID fallback.
RUNTIME_ROOT = "/run/codewire-runtime/cw"
UPDATE_REQUIRED = (
    "update/admission/real-distinct-source-pinned-images-and-build-records",
    "update/original-active-turn/continuous-process-handles/idle-and-completed-history",
    "update/A-to-B/one-request/revision2/retained-A/default-B/same-shell",
    "update/refusals/stale-revision/image-pin/no-selector-or-session-effects",
    "update/new-B-driver/native-ack/retained-B-after-rollback",
    "update/B-to-A/one-request/revision3/retained-A-and-B/default-A/same-shell",
    "update/original-turn-completed/no-replay/exactly-once-parent/history/workspace",
    "update/VM-runner-VMM-unchanged/daemon-preserved-by-composed-inference",
)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("checked-in acceptance module is unavailable")
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


managed = module("cw_native_managed_acceptance", Path(__file__).with_name("test-cli-native-managed.py"))
# Runner sockets live in the state root's short socket directory (#2735).
socket_dir = module("cw_native_socket_dir", Path(__file__).with_name("native_socket_dir.py"))
require = managed.require
Failure = managed.Failure


def shared_tools():
    # Only repository siblings are production inputs. No external-tool fallback.
    producer = module("cw_native_update_release", ROOT / "scripts/ci/release/cw_release.py")
    image = module("cw_native_update_image", ROOT / "scripts/dev/cw-runtime-image.py")
    return producer, image


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hex_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def shell_default_witness(output, marker, version):
    fields, selected = {}, {}
    for field in ("PATH", "VERSION"):
        occurrences = list(re.finditer(r"^" + re.escape(marker + "_" + field + ":"), output, re.MULTILINE))
        value = None
        if len(occurrences) == 1:
            line = output[occurrences[0].end():occurrences[0].end() + 514].split("\n", 1)[0].removesuffix("\r")
            if 1 <= len(line) <= 512 and "\r" not in line:
                value = line
        selected[field] = value
        # Only the two public marker fields enter diagnostics, never terminal output.
        fields[field.lower()] = {"count": len(occurrences),
                                 "value": managed.scrub(value, 256) if value is not None else None}
    expected_path = RUNTIME_ROOT + "/cw"
    require(selected["PATH"] == expected_path and selected["VERSION"] == "cw " + version,
            "ordinary same-shell CW did not select the admitted default: "
            + json.dumps(fields, sort_keys=True))
    return fields


def path_arg(value):
    require(isinstance(value, str) and value.startswith("/") and len(os.fsencode(value)) <= 4096
            and not any(ord(c) < 32 or ord(c) == 127 for c in value)
            and not any(part in (".", "..") for part in value.split("/")),
            "input must be an absolute bounded path without traversal")
    return Path(value)


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def directory_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def parent_directory(path, private=False):
    # Walk every ancestor without following symlinks. Admit, never create/chmod.
    path = path_arg(str(path))
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        if private:
            info = os.fstat(directory)
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "custody input parent is not an existing owner-private directory")
        return directory
    except BaseException:
        os.close(directory)
        raise


def regular(path, bound, private=True, private_parent=False):
    path = path_arg(str(path))
    directory = parent_directory(path, private_parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=directory)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and 0 < before.st_size <= bound, "input is not a bounded single-link regular file")
            require(not private or (before.st_uid == os.geteuid() and not before.st_mode & 0o022),
                    "input is not owner controlled")
            data = source.read(bound + 1)
            require(len(data) == before.st_size and stamp(before) == stamp(os.fstat(source.fileno()))
                    and stamp(before) == stamp(os.stat(path.name, dir_fd=directory, follow_symlinks=False)),
                    "input changed during admission")
            return data, stamp(before)
    finally:
        os.close(directory)


class Asset:
    """Read-only byte admission; no extraction, executable launch or publication."""
    def __init__(self, lock, receipt, pin, producer, image, source_tree):
        require(hex_digest(pin), "invalid externally pinned cw digest")
        self.lock = path_arg(lock)
        self.receipt_path = path_arg(receipt)
        paths = (
            (self.lock, MAX_JSON),
            (self.lock.parent / "runtime.pack", MAX_PACK),
            (self.receipt_path, MAX_JSON),
            (self.receipt_path.parent / "cw.oci.tar", image.MAX_ARCHIVE),
        )
        self.files = {}
        data = []
        for path, limit in paths:
            raw, identity = regular(path, limit)
            self.files[str(path)] = {"stamp": identity, "sha256": digest(raw)}
            data.append(raw)
        lock_raw, pack, receipt_raw, archive = data
        saved_lock = producer.parse_canonical(lock_raw)
        require(isinstance(saved_lock,dict) and type(saved_lock.get("schema_version")) is int
                and saved_lock["schema_version"] == 1,
                "runtime lock schema must be the integer 1")
        self.receipt = producer.parse_json(receipt_raw)
        require(set(self.receipt) == {"schema_version", "index_sha256", "manifest_sha256",
                                     "archive_sha256", "cw_sha256", "source_revision"}
                and type(self.receipt["schema_version"]) is int and self.receipt["schema_version"] == 1
                and all(hex_digest(self.receipt[key]) for key in
                        ("index_sha256", "manifest_sha256", "archive_sha256", "cw_sha256")),
                "image receipt is not the closed pinned identity")
        self.provenance, payload = producer.decode_pack(pack)
        identity = self.provenance.get("payload")
        producer.validate_identity(identity, producer.RUNTIME_TARGET)
        self.identity = producer.make_identity(
            payload, identity["target"], identity["package_version"], identity["source_revision"],
            source_tree, identity["rustc"])
        producer.toolchain_rustc(ROOT, identity["rustc"])
        require(self.identity == identity and identity["sha256"] == pin, "CW bytes/build record/source pin changed")
        admitted, provenance_raw = image.admit(archive, self.receipt["index_sha256"])
        require(admitted == payload and producer.parse_json(provenance_raw) == self.provenance,
                "OCI and runtime pack do not carry the same complete identity")
        require(self.receipt["cw_sha256"] == pin and self.receipt["archive_sha256"] == digest(archive)
                and self.receipt["source_revision"] == identity["source_revision"]
                and self.receipt["manifest_sha256"] == self.provenance["image_manifest"]["sha256"],
                "image receipt contradicts the admitted bytes")
        require(saved_lock == {"schema_version": 1, "image_index_sha256": self.receipt["index_sha256"],
                               "pack": {"path": "runtime.pack", "size": len(pack), "sha256": digest(pack)}},
                "runtime lock does not bind the complete pack")

    def unchanged(self):
        for name, identity in self.files.items():
            require(stamp(os.stat(name, follow_symlinks=False)) == tuple(identity["stamp"]),
                    "admitted source changed before or after the runtime request")

    def proof(self):
        return {"identity": self.identity, "provenance": self.provenance, "files": self.files}


def host_identity(data, producer, source_tree):
    record = producer.build_record(data)
    require(record["target"] in ("x86_64-unknown-linux-gnu", producer.RUNTIME_TARGET),
            "host CW is not a supported native Linux x86_64 consumer")
    producer.toolchain_rustc(ROOT, record["rustc"])
    return producer.make_identity(data, record["target"], record["package_version"],
                                  record["source_revision"], source_tree, record["rustc"],
                                  targets=producer.DEVELOPMENT_TARGETS)


def pair(a, b):
    require(a.identity["sha256"] != b.identity["sha256"]
            and a.identity["package_version"] != b.identity["package_version"],
            "real A/B must have distinct executable bytes and versions")
    require(a.identity["target"] == b.identity["target"]
            and a.identity["source_tree_sha256"] == b.identity["source_tree_sha256"]
            and a.identity["rustc"] == b.identity["rustc"],
            "A/B do not share the qualified consumer source, target and toolchain")


def admit_assets(args):
    """Shared source admission; no kernel custody, runtime launch or publication."""
    producer, image = shared_tools()
    source_tree = producer.source_tree_sha256(ROOT)
    pin = args.sha256_a
    if pin is None:
        require(args.admit_only, "runtime execution requires an explicit A digest")
        receipt_raw, _ = regular(path_arg(args.image_a), MAX_JSON)
        receipt = producer.parse_json(receipt_raw)
        require(isinstance(receipt, dict) and hex_digest(receipt.get("cw_sha256")),
                "A receipt has no canonical CW digest")
        pin = receipt["cw_sha256"]
    a = Asset(args.runtime_a, args.image_a, pin, producer, image, source_tree)
    b = Asset(args.runtime_b, args.image_b, args.sha256_b, producer, image, source_tree)
    pair(a, b)
    cw = path_arg(args.cw)
    host_cw, host_stamp = regular(cw, MAX_EXE)
    require(host_stamp[2] & 0o111, "host CW is not executable")
    admitted_host = host_identity(host_cw, producer, source_tree)
    return producer, a, b, cw, host_stamp, admitted_host


class SingleUse(argparse.Action):
    """Reject repeated options and empty values before reading admission inputs."""
    def __call__(self, parser, namespace, values, option_string=None):
        provided = vars(namespace).setdefault("_provided", set())
        if self.dest in provided:
            parser.error(f"duplicate option: {option_string}")
        if self.nargs != 0 and not values:
            parser.error(f"empty value for {option_string}")
        provided.add(self.dest)
        setattr(namespace, self.dest, self.const if self.nargs == 0 else values)


def proc_stat(raw):
    fields = raw.rsplit(") ", 1)[1].split()
    require(len(fields) > 19 and fields[0] not in ("Z", "X"), "retained process exited")
    return {"parent": int(fields[1]), "birth": int(fields[19])}


def proc_read(directory, name, bound=4096):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        data = os.read(fd, bound + 1)
        require(len(data) <= bound, "kernel process field exceeded its bound")
        return data
    finally:
        os.close(fd)


def pidfd_pid(fd):
    with open(f"/proc/self/fdinfo/{fd}", "rb") as source:
        data = source.read(4097)
    require(len(data) <= 4096, "pidfd field exceeded its bound")
    matches = re.findall(rb"^Pid:\s*(-?[0-9]+)$", data, re.MULTILINE)
    require(len(matches) == 1, "kernel pidfd identity unavailable")
    return int(matches[0])


class Process:
    """Held kernel birth and executable FD. Observation only; never signals."""
    def __init__(self, pid, fd=None, expected=None):
        require(type(pid) is int and 1 < pid <= 2**31 - 1, "invalid process witness PID")
        self.pid, self.fd, self.proc, self.exe = pid, fd, None, None
        try:
            if self.fd is None:
                self.fd = os.pidfd_open(pid)
            require(pidfd_pid(self.fd) == pid, "pidfd is not bound to the requested process")
            self.proc = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            require(os.fstat(self.proc).st_uid == os.geteuid(), "process witness UID changed")
            before = proc_stat(proc_read(self.proc, "stat").decode())
            require(not select.select([self.fd], [], [], 0)[0], "process witness exited")
            self.exe = os.open("exe", os.O_RDONLY | os.O_CLOEXEC, dir_fd=self.proc)
            info = os.fstat(self.exe)
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_EXE, "unbounded executable witness")
            hasher = hashlib.sha256()
            copied = 0
            while block := os.read(self.exe, 65536):
                copied += len(block)
                require(copied <= MAX_EXE, "executable changed beyond its bound")
                hasher.update(block)
            require(copied == info.st_size and stamp(info) == stamp(os.fstat(self.exe)),
                    "executable changed during admission")
            self.exe_stamp = stamp(info)
            self.identity = {"pid": pid, "birth": before["birth"], "executable": os.readlink("exe", dir_fd=self.proc),
                             "device": info.st_dev, "inode": info.st_ino, "size": info.st_size,
                             "sha256": hasher.hexdigest()}
            if expected:
                require(expected["pid"] == pid and expected["start_time_ticks"] == before["birth"]
                        and expected["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                        and expected["executable"] == self.identity["executable"]
                        and expected["executable_sha256"] == self.identity["sha256"]
                        and expected["executable_file"]["device"] == info.st_dev
                        and expected["executable_file"]["inode"] == info.st_ino
                        and expected["executable_file"]["size"] == info.st_size
                        and expected["executable_file"]["uid"] == info.st_uid
                        and expected["executable_file"]["mode"] == info.st_mode
                        and expected["executable_file"]["links"] == info.st_nlink,
                        "VMM differs from its retained owner identity")
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        require(pidfd_pid(self.fd) == self.pid and not select.select([self.fd], [], [], 0)[0],
                "original process exited")
        before = proc_stat(proc_read(self.proc, "stat").decode())
        info = os.stat("exe", dir_fd=self.proc)
        require(before["birth"] == self.identity["birth"]
                and os.readlink("exe", dir_fd=self.proc) == self.identity["executable"]
                and stamp(info) == self.exe_stamp == stamp(os.fstat(self.exe))
                and before == proc_stat(proc_read(self.proc, "stat").decode())
                and not select.select([self.fd], [], [], 0)[0], "original process re-executed or changed")

    def close(self):
        for name in ("fd", "proc", "exe"):
            value = getattr(self, name, None)
            if value is not None:
                os.close(value)
                setattr(self, name, None)


class HostCustody:
    def __init__(self, state, runner_socket, environment, producer):
        self.processes, self.stream, self.socket_parent = [], None, None
        try:
            state = path_arg(state)
            path = path_arg(runner_socket)
            require(state.name == "state.json" and state.parent.name == environment
                    and state.parent.parent.name == "vms" and state.parent.parent.parent.name == "engine"
                    and path == socket_dir.predicted(state.parent.parent.parent.parent)
                    / "runners" / f"{environment}.sock",
                    "host custody paths do not select this environment's canonical VM and runner")
            raw, self.state_stamp = regular(state, MAX_JSON, private_parent=True)
            self.state_path = state
            value = producer.parse_json(raw)
            require(value["vm_id"] == environment and value["phase"] == "running"
                    and type(value["generation"]) is int and value["generation"] > 0,
                    "VM state does not belong to the explicit environment")
            self.generation = value["generation"]
            self.processes.append(Process(value["process"]["pid"], expected=value["process"]))
            self.socket_parent = parent_directory(path, private=True)
            self.socket_parent_stamp = directory_identity(os.fstat(self.socket_parent))
            before = os.stat(path.name, dir_fd=self.socket_parent, follow_symlinks=False)
            require(stat.S_ISSOCK(before.st_mode) and before.st_uid == os.geteuid()
                    and not before.st_mode & 0o077 and before.st_nlink == 1, "runner socket is not owner private")
            self.stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.stream.settimeout(3)
            # The held directory cannot redirect a lookup through replaced ancestors.
            self.stream.connect(f"/proc/self/fd/{self.socket_parent}/{path.name}")
            pid, uid, _ = struct.unpack("3i", self.stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == os.geteuid()
                    and stamp(os.stat(path.name, dir_fd=self.socket_parent, follow_symlinks=False)) == stamp(before),
                    "runner socket peer changed")
            fd, = struct.unpack("i", self.stream.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4))
            self.processes.append(Process(pid, fd))
            self.socket_path, self.socket_stamp = path, stamp(before)
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        require(stamp(self.state_path.lstat()) == self.state_stamp
                and stamp(self.socket_path.lstat()) == self.socket_stamp, "VM state or runner socket changed")
        directory = parent_directory(self.socket_path, private=True)
        try:
            require(directory_identity(os.fstat(directory)) == self.socket_parent_stamp
                    and directory_identity(os.fstat(self.socket_parent)) == self.socket_parent_stamp,
                    "runner socket parent was replaced")
        finally:
            os.close(directory)
        for process in self.processes:
            process.verify()

    def proof(self):
        return {"generation": self.generation, "VMM": self.processes[0].identity,
                "runner": self.processes[1].identity}

    def close(self):
        for process in self.processes:
            process.close()
        if self.stream is not None:
            self.stream.close()
            self.stream = None
        if self.socket_parent is not None:
            os.close(self.socket_parent)
            self.socket_parent = None


# This fixed workload observer owns no authority or signals. Its descriptors
# stay open across public host requests, not merely at before/after samples.
GUEST_OBSERVER = r'''import fcntl, hashlib, json, os, re, select, stat, sys, time
settings = json.loads(sys.argv[1])
nonce = settings["nonce"]
assert len(nonce) == 8 and all(c in "0123456789abcdef" for c in nonce)
boot = open("/proc/sys/kernel/random/boot_id").read().strip()
actors = {}
samples = 0
deadline = time.monotonic() + settings["seconds"]
flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
failure = {"actor":None, "check":None, "actual_size":None}
def mark(actor, check, actual_size=None):
    # Only fixed check names and bounded actor labels/sizes can enter diagnostics.
    failure.update(actor=actor if isinstance(actor,str) and re.fullmatch("[a-z][a-z0-9-]{0,63}",actor) else None,
                   check=check if re.fullmatch("[a-z][a-z0-9-]{0,63}",check) else None,
                   actual_size=actual_size if type(actual_size) is int and 0<=actual_size<2**63 else None)
def emit(stage):
    print("CWNU_" + nonce + " " + json.dumps({"stage":stage, "boot_id":boot,
          "continuous_samples":samples, "actors":{name:item["identity"] for name,item in actors.items()}},
          separators=(",",":")), flush=True)
def read_at(root, name, limit):
    fd = os.open(name, flags, dir_fd=root)
    try:
        data = os.read(fd, limit + 1)
        assert len(data) <= limit
        return data
    finally:
        os.close(fd)
def unique(pairs):
    value={}
    for key,item in pairs:
        assert key not in value
        value[key]=item
    return value
def birth(root):
    fields = read_at(root, "stat", 4096).decode().rsplit(") ",1)[1].split()
    assert len(fields) > 19 and fields[0] not in ("Z","X")
    return int(fields[19]), int(fields[1])
def pidfd_pid(fd):
    import re
    with open("/proc/self/fdinfo/%d" % fd,"rb") as source: data=source.read(4097)
    assert len(data)<=4096
    matches=re.findall(rb"^Pid:\s*(-?[0-9]+)$",data,re.MULTILINE)
    assert len(matches)==1
    return int(matches[0])
def stamp(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def verify(item):
    name = item["name"]
    fd, root, executable = item["handles"]
    mark(name,"pidfd-live")
    assert not select.select([fd], [], [], 0)[0]
    current = os.stat("exe", dir_fd=root)
    identity = item["identity"]
    mark(name,"process-birth")
    assert birth(root)[0] == identity["start_ticks"] and pidfd_pid(fd)==identity["pid"]
    mark(name,"executable-path")
    assert os.readlink("exe", dir_fd=root) == identity["executable"]
    mark(name,"executable-stamp",current.st_size)
    assert stamp(current)==item["stamp"]==stamp(os.fstat(executable))
    if identity["seals"] is not None:
        mark(name,"executable-seals",current.st_size)
        assert fcntl.fcntl(executable,fcntl.F_GET_SEALS)==identity["seals"]
    mark(name,"pidfd-live")
    assert not select.select([fd], [], [], 0)[0]
def capture(name, pid, ticks=None, checksum=None, parent=None):
    mark(name,"actor-admission")
    assert name not in actors and len(actors) < 16 and type(pid) is int and pid > 1
    # Only the provider captured against its held guardian gets the larger bound.
    limit = 512*1024*1024 if parent is not None and checksum is None else 256*1024*1024
    handles = []
    try:
        mark(name,"pidfd-open")
        fd = os.pidfd_open(pid); handles.append(fd)
        assert pidfd_pid(fd)==pid
        mark(name,"process-open")
        root = os.open("/proc/%d" % pid, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC); handles.append(root)
        assert os.fstat(root).st_uid == os.geteuid() and not select.select([fd], [], [], 0)[0]
        mark(name,"process-birth")
        before, ppid = birth(root)
        assert ticks is None or before == ticks
        if parent:
            verify(actors[parent])
            mark(name,"process-parent")
            assert ppid == actors[parent]["identity"]["pid"]
        mark(name,"executable-open")
        executable = os.open("exe", os.O_RDONLY|os.O_CLOEXEC, dir_fd=root); handles.append(executable)
        metadata = os.fstat(executable)
        mark(name,"executable-size",metadata.st_size)
        assert stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= limit
        h = hashlib.sha256()
        copied=0
        while True:
            block = os.read(executable,65536)
            if not block: break
            copied+=len(block)
            mark(name,"executable-stream-size",copied)
            assert copied<=limit
            h.update(block)
        mark(name,"executable-stream-stamp",copied)
        assert copied==metadata.st_size and stamp(metadata)==stamp(os.fstat(executable))
        seals = None
        if checksum:
            mark(name,"executable-sha256",metadata.st_size)
            assert h.hexdigest() == checksum
            mark(name,"executable-memfd",metadata.st_size)
            assert os.readlink("exe",dir_fd=root)=="/memfd:codewire-verified-runtime (deleted)"
            seals = fcntl.fcntl(executable, fcntl.F_GET_SEALS)
            mark(name,"executable-seals",metadata.st_size)
            assert seals & 15 == 15
        identity = {"pid":pid,"start_ticks":before,"executable":os.readlink("exe",dir_fd=root),
                    "device":metadata.st_dev,"inode":metadata.st_ino,"size":metadata.st_size,
                    "sha256":h.hexdigest(),"seals":seals}
        item = {"name":name,"handles":handles,"identity":identity,"stamp":stamp(metadata)}
        verify(item)
        if parent:
            verify(actors[parent])
            mark(name,"process-parent")
            assert birth(root)[1] == actors[parent]["identity"]["pid"]
        actors[name] = item
    except BaseException:
        for handle in handles: os.close(handle)
        raise
def peer(value):
    label, identity, checksum = value["label"], value["identity"], value["sha256"]
    assert identity["environment_id"] == settings["environment"] and identity["boot_id"] == boot
    import re
    assert re.fullmatch("[a-z][a-z-]{0,31}",label) and re.fullmatch("[0-9a-f]{64}",checksum)
    assert all(re.fullmatch("[0-9a-f-]{36}",identity[key]) for key in ("driver_id","instance_id"))
    capture(label+"-driver", identity["driver_pid"], identity["driver_start_ticks"], checksum)
    root = os.open("/", os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in ("home","codewire",".local","state","codewire","managed-agents-v1",
                     settings["environment"],"agents",identity["driver_id"]):
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root)
            os.close(root); root=child
            if part in ("managed-agents-v1",settings["environment"],"agents",identity["driver_id"]):
                meta=os.fstat(root)
                assert meta.st_uid == os.geteuid() and stat.S_IMODE(meta.st_mode)==0o700
        name="peer-"+identity["instance_id"]+".json"
        mark(label,"peer-receipt")
        fd=os.open(name,flags,dir_fd=root)
        try:
            before=os.fstat(fd)
            assert stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_nlink==1
            assert stat.S_IMODE(before.st_mode)==0o600 and 0 < before.st_size <= 65536
            raw=os.read(fd,65537)
            assert len(raw)==before.st_size and stamp(before)==stamp(os.fstat(fd))
            assert stamp(before)==stamp(os.stat(name,dir_fd=root,follow_symlinks=False))
            receipt=json.loads(raw,object_pairs_hook=unique)
        finally: os.close(fd)
        assert receipt["version"]==1 and receipt["identity"]==identity
        assert set(receipt)=={"version","identity","guardian_pid","guardian_start_ticks","provider_pid",
                              "cleanup_unknown","finished_at","exit_code","error"}
        assert receipt["cleanup_unknown"] is True and receipt["finished_at"] is None
        assert receipt["exit_code"] is None and receipt["error"] is None
        capture(label+"-guardian",receipt["guardian_pid"],receipt["guardian_start_ticks"],checksum)
        capture(label+"-provider",receipt["provider_pid"],parent=label+"-guardian")
        verify(actors[label+"-driver"]); verify(actors[label+"-guardian"])
    finally: os.close(root)
try:
    capture("sentinel",settings["sentinel_pid"])
    for value in settings["peers"]: peer(value)
    emit("ready")
    pending=b""
    while time.monotonic() < deadline:
        for item in actors.values(): verify(item)
        samples+=1
        if not select.select([0],[],[],0.02)[0]: continue
        block=os.read(0,4096)
        assert block, "observer input ended without its explicit close"
        pending+=block
        assert len(pending)<=65536
        while b"\n" in pending:
            raw,pending=pending.split(b"\n",1)
            request=json.loads(raw)
            assert set(request) in ({"op","stage"},{"op","stage","peer"})
            assert isinstance(request["stage"],str) and 0<len(request["stage"])<=64
            if request["op"]=="add": peer(request["peer"])
            elif request["op"]=="close":
                time.sleep(0.04)
                for item in actors.values(): verify(item)
                samples+=1
                emit(request["stage"])
                raise SystemExit(0)
            else: assert request["op"]=="observe"
            emit(request["stage"])
    raise RuntimeError("continuous observer reached its fixed deadline")
except SystemExit:
    raise
except Exception as error:
    print("CWNU_"+nonce+" "+json.dumps({"stage":"failed","error":type(error).__name__,**failure}),flush=True)
    raise SystemExit(1)
finally:
    for item in actors.values():
        for handle in item["handles"]: os.close(handle)
'''


def observer_failure(value):
    require(isinstance(value,dict) and set(value)=={"stage","error","actor","check","actual_size"}
            and value["stage"]=="failed"
            and isinstance(value["error"],str) and re.fullmatch(r"[A-Za-z]{1,64}",value["error"])
            and all(value[key] is None or isinstance(value[key],str)
                    and re.fullmatch(r"[a-z][a-z0-9-]{0,63}",value[key]) for key in ("actor","check"))
            and (value["actual_size"] is None or type(value["actual_size"]) is int
                 and 0<=value["actual_size"]<2**63), "guest observer failure diagnostics are invalid")
    return json.dumps(value,sort_keys=True,separators=(",",":"))


class Journey(managed.Journey):
    def __init__(self, cw, environment, synthetic, codex_model, claude_model, a, b, custody):
        super().__init__(cw, environment, synthetic, codex_model, claude_model, a.receipt)
        self.a, self.b, self.host = a, b, custody
        self.runtime_evidence, self.requests, self.observer_evidence = [], [], []
        self.observer = None
        self.observer_nonce = uuid.uuid4().hex[:8]
        self.marker = None
        self.workspace_identity = None
        self.initial = None
        self.host_proof = custody.proof()
        if not synthetic:
            self.fixture["runtime-update-held-turn"] = {
                "name":"runtime-update-held-turn",
                "request":"CW_FIXTURE_UPDATE_STEERABLE <8 hex>, then CW_FIXTURE_UPDATE_STEER <same nonce>; "
                          "a separate B Codex conversation sends CW_FIXTURE_UPDATE_RELEASE <same nonce>",
                "response":"keep the original stream open through A→B→A and the public steer ACK; "
                           "only the separate release ends that hold, then the original turn replies "
                           "CW_UPDATE_STEERED <same nonce>; release task replies CW_UPDATE_RELEASE_ACK; "
                           "CW_UPDATE_HOLD_EXPIRED is a failure",
                "checks":[UPDATE_REQUIRED[1],UPDATE_REQUIRED[6]],
                "status":"unobserved", "observed":None,
            }

    def runtime(self, *args, **kwargs):
        return self.data("env", "--local", "runtime", *args, "--output", "json", **kwargs)

    def runtime_info(self):
        _, result = self.runtime("info", self.environment, timeout=150)
        require(result["environment_id"] == self.environment and result["generation"] == self.host.generation
                and not result["interrupted_request_ids"], "runtime identity or retained uncertainty changed")
        return result

    def selection(self, result, revision, selected, previous, operations):
        value = result["selection"]
        require(value["schema_version"] == 1 and value["environment_id"] == self.environment
                and value["bootstrap_catalog_sha256"] == self.initial["selection"]["bootstrap_catalog_sha256"]
                and value["revision"] == revision and value["catalog"]["active_sha256"] == selected.identity["sha256"]
                and value["previous_sha256"] == (previous.identity["sha256"] if previous else None),
                "runtime selector does not match the exact round trip")
        expected = [self.a.provenance] if revision == 1 else sorted(
            [self.a.provenance, self.b.provenance], key=lambda item:item["payload"]["sha256"])
        require(value["catalog"]["schema_version"] == 1 and value["catalog"]["runtimes"] == expected
                and len(value["operations"]) == operations, "retained membership or commit count changed")
        self.host.verify()
        self.runtime_evidence.append(result)

    def mutate(self, verb, revision, target, previous, operations):
        request = str(uuid.uuid4())
        record = {"verb":verb, "request_id":request, "expected_revision":revision, "outcome":"prepared"}
        self.requests.append(record)
        args = [verb, self.environment, "--expected-revision", str(revision), "--request-id", request]
        if verb == "update":
            self.b.unchanged()
            args += ["--source", str(self.b.lock), "--image-sha256", self.b.receipt["index_sha256"],
                     "--target-sha256", self.b.identity["sha256"]]
        # Never retry a mutation under any ID after an uncertain local caller.
        print("cli-native-update: runtime-request " + json.dumps(record,sort_keys=True),
              file=sys.stderr,flush=True)
        try:
            _, result = self.runtime(*args, timeout=330)
            require(result["request_id"] == request and managed.is_uuid(result["operation_id"])
                    and result["phase"] == "completed" and not result["error_code"],
                    "runtime request did not complete with its exact durable identity")
            self.selection(result, revision+1, target, previous, operations)
            receipts = [item for item in result["selection"]["operations"] if item["operation_id"] == result["operation_id"]]
            require(len(receipts) == 1 and receipts[0] == {
                "operation_id":result["operation_id"], "generation":self.host.generation,
                "expected_revision":revision, "target_sha256":target.identity["sha256"],
                "outcome":"committed", "selection_revision":revision+1}, "runtime request lacks its exact single commit")
        except Exception:
            record["outcome"] = "unknown"
            self.ambiguous.append({"kind":"runtime-request", "request_id":request, "verb":verb})
            raise
        record.update(outcome="committed", operation_id=result["operation_id"])
        _, observed = self.runtime("observe", self.environment, "--request-id", request, timeout=150)
        require(observed == result, "same-request observation changed its acknowledged result")
        return result

    def snapshot(self):
        value = {}
        for sid in (self.lead, self.worker):
            inbox = self.inbox(sid)
            value[sid] = {"driver_id":inbox["driver_id"], "peer":inbox["peer"]["identity"],
                          "thread":inbox["driver"]["native_thread_id"],
                          "started_at":inbox["driver"]["started_at"],
                          "active_message_id":inbox["driver"]["active_message_id"],
                          "current_turn_id":inbox["driver"]["current_turn_id"],
                          "messages":inbox["messages"]}
        return value

    def unchanged_conversations(self, original):
        current = self.snapshot()
        for sid, before in original.items():
            after = current[sid]
            require(all(after[field] == before[field] for field in
                        ("driver_id","peer","thread","started_at","active_message_id","current_turn_id")),
                    "default update replaced an original conversation")
            existing = after["messages"][:len(before["messages"])]
            require(len(existing) == len(before["messages"]), "original history was truncated")
            for old, current_message in zip(before["messages"], existing):
                if old["state"] in managed.TERMINAL_MESSAGE:
                    require(current_message == old, "default update changed completed message history")
                else:
                    fields = ("id","driver_id","target_session_id","action","text","reply_to",
                              "expected_turn_id","expected_active_message_id","turn_id","state",
                              "created_at","accepted_at","started_at","finished_at","native_acknowledged")
                    require(all(current_message[field] == old[field] for field in fields),
                            "default update completed, replaced or reissued the active message")
        return current

    def peer(self, sid, label, asset):
        inbox = self.inbox(sid)
        identity = managed.peer_identity(inbox, self.environment, self.drivers[sid], sid)
        command = self.sessions()[sid]["command"]
        retained = f"{RUNTIME_ROOT}/{asset.identity['sha256']}/cw"
        require(command.count(retained) == 1 and "_agent-driver" in command,
                "managed driver did not name its admitted retained member")
        return {"label":label, "identity":identity, "sha256":asset.identity["sha256"],
                "logical_member":retained}

    def observe(self, stage, op="observe", peer=None):
        if op != "ready":
            request = {"op":op, "stage":stage}
            if peer is not None:
                request["peer"] = {key:value for key,value in peer.items() if key != "logical_member"}
            self.call("send", self.environment, self.observer, json.dumps(request, separators=(",",":")))
        prefix = "CWNU_" + self.observer_nonce + " "
        def probe():
            output = self.call("logs", self.environment, self.observer, "--tail", "50")[1]
            found = []
            for line in output.splitlines():
                if not line.startswith(prefix):
                    continue
                value = json.loads(line[len(prefix):])
                if value["stage"] == "failed":
                    require(False,"continuous guest kernel observer refused custody: "+observer_failure(value))
                if value["stage"] == stage:
                    found.append(value)
            require(len(found) <= 1, "guest observer checkpoint was emitted more than once")
            return found[0] if found else None
        result = self.until(probe, bool, 30, f"continuous kernel checkpoint {stage}")
        self.host.verify()
        self.observer_evidence.append(result)
        return result

    def shell(self, asset, stage):
        marker = "CWNU_" + self.observer_nonce + "_" + stage.upper()
        # The existing shell and its PATH/cache stay intact; command avoids functions.
        self.call("send", self.environment, self.sentinel,
                  f"printf '\\n{marker}_PATH:%s\\n' \"$(command -v cw)\"; "
                  f"printf '{marker}_VERSION:'; command cw --version; printf '{marker}_END\\n'")
        output = self.until(lambda:self.call("logs", self.environment, self.sentinel, "--tail", "50")[1],
                            lambda text:f"{marker}_END" in text and f"{marker}_VERSION:cw " in text,
                            30, f"same shell selected {stage}")
        shell_default_witness(output, marker, asset.identity["package_version"])
        self.sentinel_live()

    def workspace(self, op, *, phase=None):
        if self.marker is None:
            self.marker = (f".{self.prefix}-update-workspace", uuid.uuid4().hex)
        name, token = self.marker
        script = r'''import json, os, stat, sys
op,name,token,saved=sys.argv[1:]
assert name.startswith(".cwnm-") and name.endswith("-update-workspace") and "/" not in name
def identity(info):
    return {"device":info.st_dev,"inode":info.st_ino,"mode":info.st_mode,"uid":info.st_uid,
            "links":info.st_nlink,"size":info.st_size,"mtime_ns":info.st_mtime_ns,"ctime_ns":info.st_ctime_ns}
if op=="create":
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    assert os.write(fd,token.encode())==len(token)
    os.fsync(fd); before=os.fstat(fd); os.close(fd)
else:
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    before=os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_nlink==1
    assert stat.S_IMODE(before.st_mode)==0o600 and before.st_size==len(token)
    assert os.read(fd,128)==token.encode() and identity(before)==identity(os.fstat(fd))
    assert identity(before)==identity(os.stat(name,follow_symlinks=False))
    assert identity(before)==json.loads(saved)
    if op=="remove": os.unlink(name)
    else: assert op=="observe"
    os.close(fd)
print(json.dumps({"operation":op,"identity":identity(before)}))
'''
        code, output = self.guest("update-workspace-"+(phase or op),
                                  'exec python3 -I -B -c "$1" "$2" "$3" "$4" "$5"',
                                  script, op, name, token, json.dumps(self.workspace_identity))
        require(code == 0, "owned workspace marker operation failed")
        proof = json.loads(output)
        require(proof["operation"] == op, "owned workspace marker changed")
        if op == "create":
            self.workspace_identity = proof["identity"]
        else:
            require(proof["identity"] == self.workspace_identity, "workspace marker was replaced")
        if op == "remove":
            self.marker = None

    def refusals(self, original, selection):
        wrong_image = ("0" if self.b.receipt["index_sha256"][0] != "0" else "1") + self.b.receipt["index_sha256"][1:]
        for label, revision, image in (("stale",1,self.b.receipt["index_sha256"]), ("image",2,wrong_image)):
            request = str(uuid.uuid4())
            record = {"verb":"update", "request_id":request, "expected_revision":revision,
                      "negative":label, "outcome":"unknown"}
            self.requests.append(record)
            print("cli-native-update: runtime-request " + json.dumps(record,sort_keys=True),
                  file=sys.stderr,flush=True)
            code, stdout, stderr = self.call(
                "env", "--local", "runtime", "update", self.environment,
                "--source", str(self.b.lock), "--image-sha256", image,
                "--target-sha256", self.b.identity["sha256"], "--expected-revision", str(revision),
                "--request-id", request, "--output", "json", expect="fail", timeout=150)
            reason = ("runtime selection revision changed" if label == "stale" else
                      "pinned cw image asset admission failed")
            require(code != 0 and not stdout.strip() and reason in stderr,
                    f"{label} negative did not reach its exact public admission refusal")
            require(self.runtime_info()["selection"] == selection, f"{label} refusal changed the selector")
            self.unchanged_conversations(original)
            self.observe("refused-"+label)
            record["outcome"] = "refused-before-selection"
        self.check(UPDATE_REQUIRED[3])

    def finish_original_turn(self, child, active, turn):
        code, steer = self.deliver("steer", self.lead, "finish" if self.synthetic else
                                   f"CW_FIXTURE_UPDATE_STEER {self.observer_nonce}\n"
                                   f"Finish after the separate release and reply CW_UPDATE_STEERED {self.observer_nonce}.")
        require(code == 0 and steer and steer["expected_turn_id"] == turn, "steer lost the original turn identity")
        # A joined steer is acknowledged before it becomes terminal. Waiting
        # for completion here would wait for the release we have not sent yet.
        acknowledged = self.until(lambda:self.message(self.inbox(self.lead),steer["id"]),
                                  lambda item:item["native_acknowledged"],
                                  30,"original turn steer native ACK")
        require(acknowledged["expected_turn_id"] == turn,
                "original turn steer acknowledgement names a different turn")
        if not self.synthetic:
            # A second conversation releases only the checked-in synthetic held
            # response. No provider endpoint, fixture reset or task replay exists.
            pending = self.message(self.inbox(self.lead),active["id"])
            require(pending["state"] == "running" and acknowledged["state"] == "running",
                    "original stream or joined steer ended before the independent release")
            release = self.send(child,f"CW_FIXTURE_UPDATE_RELEASE {self.observer_nonce}")
            released = self.expect_state(self.wait_message(release["id"]), "completed")
            require(released["native_acknowledged"]
                    and f"CW_UPDATE_RELEASE_ACK {self.observer_nonce}" in (released.get("result") or ""),
                    "B release task lacks its native acknowledgement or exact fixture receipt")
        done = self.expect_state(self.wait_message(active["id"]), "completed")
        self.expect_state(self.wait_message(steer["id"]), "completed")
        expected = "STEERED" if self.synthetic else f"CW_UPDATE_STEERED {self.observer_nonce}"
        result = done.get("result") or ""
        require(done["native_acknowledged"] and (result == expected if self.synthetic else expected in result)
                and "CW_UPDATE_HOLD_EXPIRED" not in result,
                "original turn lost its native acknowledgement, expired, or lacked steer completion")
        return done

    def prove_controls(self):
        self.stage = "native-runtime-update"
        pair(self.a, self.b)
        self.a.unchanged(); self.b.unchanged()
        self.initial = self.runtime_info()
        self.selection(self.initial, 1, self.a, None, 0)
        self.check(UPDATE_REQUIRED[0])
        self.workspace("create")
        self.shell(self.a, "a-before")
        text = "HOLD" if self.synthetic else (
            f"CW_FIXTURE_UPDATE_STEERABLE {self.observer_nonce}\nWait for further input before replying.")
        held, active = self.hold(self.lead, text, codex=True)
        require(held and active["native_acknowledged"], "original native turn was not held and acknowledged")
        turn = self.inbox(self.lead)["driver"]["current_turn_id"]
        original = self.snapshot()
        sentinel_marker = "CWNU_" + self.observer_nonce + "_PID:"
        self.call("send", self.environment, self.sentinel, f"printf '\\n{sentinel_marker}%s\\n' \"$$\"")
        output = self.until(lambda:self.call("logs", self.environment, self.sentinel, "--tail", "50")[1],
                            lambda text:re.search(re.escape(sentinel_marker)+r"[0-9]+", text), 30, "original shell PID")
        pid = int(re.search(re.escape(sentinel_marker)+r"([0-9]+)", output)[1])
        peers = [self.peer(self.lead, "lead", self.a), self.peer(self.worker, "worker", self.a)]
        settings = {"nonce":self.observer_nonce, "environment":self.environment, "sentinel_pid":pid,
                    "seconds":int(self.budget(managed.OVERALL_SECONDS)),
                    "peers":[{key:value for key,value in item.items() if key != "logical_member"} for item in peers]}
        self.observer = self.launch_command("update-observer", ["python3","-I","-B","-u","-c",
                                                              GUEST_OBSERVER,json.dumps(settings)])
        before = self.observe("ready", op="ready")
        self.check(UPDATE_REQUIRED[1])
        updated = self.mutate("update", 1, self.b, self.a, 1)
        self.unchanged_conversations(original)
        self.observe("selected-b")
        self.shell(self.b, "b")
        self.workspace("observe", phase="selected-b")
        self.check(UPDATE_REQUIRED[2])
        self.refusals(original, updated["selection"])
        launched = self.launch_agent("update-b-child", "codex", parent=self.lead, model=self.codex_model,
                                     prompt="UPDATE_B" if self.synthetic else "Reply CW_UPDATE_B. Do not use tools.")
        child = launched["session"]["session_id"]
        message = launched["message"]["id"]
        self.started_driver(child)
        finished = self.expect_state(self.wait_message(message), "completed")
        require(finished["native_acknowledged"], "new B task was not acknowledged")
        require(self.inbox(child)["driver"]["native_thread_id"] not in
                (original[self.lead]["thread"],original[self.worker]["thread"]),
                "new B task reused an original native conversation")
        b_peer = self.peer(child, "b-child", self.b)
        self.observe("b-child-live", op="add", peer=b_peer)
        notification = managed.notification_id(message)
        self.until(lambda:self.inbox(self.lead),
                   lambda inbox:any(item["id"] == notification for item in inbox["messages"]),
                   30, "B child's queued parent notification")
        self.mutate("rollback", 2, self.a, self.b, 2)
        after = self.observe("rolled-back-a")
        require(after["boot_id"] == before["boot_id"]
                and all(after["actors"][name] == value for name,value in before["actors"].items()),
                "rollback replaced an original guest birth or executable")
        self.unchanged_conversations(original)
        self.shell(self.a, "a-after")
        self.workspace("observe", phase="rolled-back-a")
        self.check(UPDATE_REQUIRED[5])
        b_inbox = self.inbox(child)
        self.turn(child, "B_AFTER_ROLLBACK", "CW_B_AFTER_ROLLBACK")
        resumed_b = self.inbox(child)
        require(resumed_b["driver"]["native_thread_id"] == b_inbox["driver"]["native_thread_id"]
                and resumed_b["peer"]["identity"] == b_peer["identity"]
                and self.peer(child, "b-child", self.b) == b_peer,
                "rollback replaced the new B conversation or its retained member")
        resumed = self.inbox(self.lead)["driver"]
        require(resumed["active_message_id"] == active["id"] and resumed["current_turn_id"] == turn,
                "update/rollback replaced or completed the original active turn")
        self.finish_original_turn(child,active,turn)
        self.await_notification(message, child)
        child_history = self.inbox(child)["messages"]
        for item in child_history:
            if item["action"] in ("prompt","message") and item["id"] != message:
                self.await_notification(item["id"], child)
        lead = self.inbox(self.lead)
        require(sum(item["id"] == active["id"] for item in lead["messages"]) == 1
                and self.message(lead, active["id"])["turn_id"] == turn,
                "original issued turn was replayed")
        self.check(UPDATE_REQUIRED[4])
        self.check(UPDATE_REQUIRED[6])
        closed = self.observe("closed", op="close")
        require(closed["continuous_samples"] > before["continuous_samples"] + 2,
                "kernel observer did not span the supervision interval")
        _, waited = self.data("wait", self.environment, self.observer, "--timeout","30s","--output","json",timeout=45)
        require(waited["eof"] and waited["session"]["exit_code"] == 0, "continuous observer did not end known-clean")
        self.sentinel_live()
        self.host.verify()
        self.limitations.append("Daemon preservation is a composed source/kernel/behavior inference: immutable init starts it once; "
                                "daemon death kills the workload and powers off. Original workload pidfds and guest boot identity, "
                                "held host runner/VMM identities and authenticated operations survived the round trip; "
                                "the daemon's own PID/birth was not directly observed.")
        self.check(UPDATE_REQUIRED[7])
        self.workspace("remove")
        # Every original control assertion still runs once, after the new slice.
        super().prove_controls()

    def cleanup(self):
        # Use exactly the inherited reserve; removing our marker does not extend it.
        self.stage = "cleanup"
        self.deadline = self.started + managed.OVERALL_SECONDS - 5
        errors = []
        if self.marker:
            try:
                self.workspace("remove")
            except Exception as error:
                errors.append(managed.scrub(error, 300))
        return errors + super().cleanup()


def complete(journey, failure, cleanup_errors):
    required = (managed.SYNTHETIC_REQUIRED if journey.synthetic else managed.ACTUAL_REQUIRED) + UPDATE_REQUIRED
    reported = {entry["name"] for entry in journey.missing}
    for name in required:
        if name not in journey.checks and name not in reported:
            journey.missing.append({"name":name, "reason":"not reached" if failure else "not proven"})
    for expectation in journey.fixture.values():
        if expectation["status"] == "unobserved":
            unproven = [check for check in expectation["checks"] if check not in journey.checks]
            expectation.update(status="not proven" if unproven else "satisfied",
                               observed="dependent checks not passed" if unproven else "all dependent checks passed")
    return not failure and not cleanup_errors and not journey.missing and not journey.canary_hits and not journey.ambiguous


def contract_tests(producer=None, image=None):
    """Pure/synthetic admission and routing checks; no product/runtime effects."""
    import ast
    import tempfile
    if producer is None or image is None:
        producer, image = shared_tools()

    def byte_fixture(version="1.0.0", **changes):
        # Deliberately not an executable: header/build-record parser evidence only.
        record = {"package_version":version, "target":producer.RUNTIME_TARGET,
                  "source_revision":"d"*40, "source_tree_sha256":"c"*64,
                  "rustc":f"rustc {PINNED_RUSTC_CHANNEL} synthetic parser fixture"}
        record.update(changes)
        data = bytearray(max(4096, producer.MIN_EXECUTABLE))
        data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", data, 16, 2, 62)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 1)
        struct.pack_into("<I", data, 64, 1)
        body = producer.canonical(record)
        encoded = producer.BUILD_RECORD_MAGIC + struct.pack("<I", len(body)) + body
        data[256:256+len(encoded)] = encoded
        return bytes(data), record

    def write_fixture(root, data=None, metadata_changes=None, receipt_changes=None, pack_suffix=b"",
                      lock_changes=None):
        data, record = byte_fixture() if data is None else data
        identity = {"schema_version":2, "protocol_version":1, "record_version":1,
                    **record, "sha256":digest(data), "size":len(data)}
        identity.update(metadata_changes or {})
        layer = image.tar_bytes([(name,0o555,None) for name in image.DIRECTORIES]
                                + [(image.CW_PATH,0o555,data),
                                   (image.META_PATH,0o444,producer.canonical(identity))])
        config = producer.canonical({"os":"linux", "architecture":"amd64", "config":{},
                                     "rootfs":{"type":"layers", "diff_ids":["sha256:"+digest(layer)]}})
        manifest = producer.canonical({"schemaVersion":2, "mediaType":image.MANIFEST,
                                       "config":image.descriptor(image.CONFIG,config),
                                       "layers":[image.descriptor(image.LAYER,layer)]})
        selected = image.descriptor(image.MANIFEST,manifest)
        selected["platform"] = {"os":"linux", "architecture":"amd64"}
        index = producer.canonical({"schemaVersion":2, "manifests":[selected]})
        archive = image.tar_bytes([("oci-layout",0o444,producer.canonical({"imageLayoutVersion":"1.0.0"})),
                                   ("index.json",0o444,index)]
                                  + [("blobs/sha256/"+digest(value),0o444,value)
                                     for value in (manifest,config,layer)])
        provenance = {"schema_version":1, "image_index_sha256":digest(index),
                      "image_manifest":{"sha256":digest(manifest),"size":len(manifest)},
                      "image_config":{"sha256":digest(config),"size":len(config)},
                      "image_layer":{"sha256":digest(layer),"size":len(layer)},
                      "layer_diff_id":digest(layer), "payload":identity}
        encoded = producer.canonical(provenance)
        pack = b"CWRPACK1"+struct.pack("<QQ",len(encoded),len(data))+encoded+data+pack_suffix
        receipt = {"schema_version":1, "index_sha256":digest(index), "manifest_sha256":digest(manifest),
                   "archive_sha256":digest(archive), "cw_sha256":digest(data),
                   "source_revision":record["source_revision"]}
        receipt.update(receipt_changes or {})
        lock = {"schema_version":1, "image_index_sha256":receipt["index_sha256"],
                "pack":{"path":"runtime.pack","size":len(pack),"sha256":digest(pack)}}
        lock.update(lock_changes or {})
        for name,value in (("cw-runtime.lock.json",producer.canonical(lock)),("runtime.pack",pack),
                           ("image.json",producer.canonical(receipt)),("cw.oci.tar",archive)):
            (root/name).write_bytes(value)
            (root/name).chmod(0o400)
        return str(root/"cw-runtime.lock.json"), str(root/"image.json"), digest(data)

    def entrypoint_fixture(root):
        first = root/"a"; first.mkdir(mode=0o700)
        second = root/"b"; second.mkdir(mode=0o700)
        a = write_fixture(first)
        b = write_fixture(second, data=byte_fixture(version="1.0.1"))
        host = root/"cw"; host.write_bytes(byte_fixture()[0]); host.chmod(0o500)
        argv = [str(Path(__file__)), "--cw", str(host),
                "--runtime-a", a[0], "--image-a", a[1],
                "--runtime-b", b[0], "--image-b", b[1], "--sha256-b", b[2]]
        return argv, a, b

    def invoke_entrypoint(argv):
        import contextlib
        import io
        current = sys.modules[__name__]
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.object(sys, "stdout", output))
            stack.enter_context(mock.patch.object(sys, "stderr", errors))
            source = stack.enter_context(mock.patch.object(current, "shared_tools", return_value=(producer, image)))
            stack.enter_context(mock.patch.object(producer, "source_tree_sha256", return_value="c"*64))
            assets = stack.enter_context(mock.patch.object(current, "Asset", wraps=Asset))
            effects = {}
            for name, target, field in (("custody", current, "HostCustody"), ("journey", current, "Journey"),
                                        ("product", managed.Journey, "call"), ("socket", socket, "socket"),
                                        ("pidfd", os, "pidfd_open"), ("signals", signal, "signal"),
                                        ("self_test", current, "contract_tests")):
                effects[name] = stack.enter_context(mock.patch.object(
                    target, field, side_effect=Failure("test effect boundary: "+name)))
            effects["process"] = stack.enter_context(mock.patch("subprocess.Popen", side_effect=Failure("test process boundary")))
            try:
                code = main()
            except SystemExit as error:
                code = error.code
        return code, output.getvalue(), errors.getvalue(), effects, source, assets

    class Contracts(unittest.TestCase):
        def test_same_shell_runtime_alias_and_exact_versions_across_update(self):
            guest = (ROOT / "crates/codewire-vmm-guest-probe/src/guest.rs").read_text()
            self.assertIn('format!("PATH={CW_RUNTIME_ROOT}:{}", &path[5..])', guest)
            for stage, version in (("a-before", "1.0.0"), ("b", "1.0.1"), ("a-after", "1.0.0")):
                with self.subTest(stage=stage):
                    marker = "CWNU_fixture_" + stage.upper()
                    output = f"{marker}_PATH:{RUNTIME_ROOT}/cw\r\n{marker}_VERSION:cw {version}\r\n"
                    proof = shell_default_witness(output, marker, version)
                    self.assertEqual(proof["path"]["value"], RUNTIME_ROOT + "/cw")

        def test_same_shell_wrong_alias_version_duplicate_or_unanchored_refused(self):
            marker = "CWNU_fixture_A"
            correct = f"{marker}_PATH:{RUNTIME_ROOT}/cw\n{marker}_VERSION:cw 1.0.0\n"
            for output in (correct.replace(RUNTIME_ROOT + "/cw", "/usr/local/bin/cw"),
                           correct.replace(RUNTIME_ROOT + "/cw", "/workspace/cw"),
                           correct.replace("cw 1.0.0", "cw 0.9.0"), correct + correct,
                           "echo " + correct, correct.replace("_PATH:", "_OTHER:")):
                with self.subTest(output=output), self.assertRaises(Failure):
                    shell_default_witness(output, marker, "1.0.0")

        def test_same_shell_long_public_version_is_compared_before_diagnostic_redaction(self):
            marker, version = "CWNU_fixture_LONG", "1.0.0-" + "a" * 32
            output = f"{marker}_PATH:{RUNTIME_ROOT}/cw\n{marker}_VERSION:cw {version}\n"
            proof = shell_default_witness(output, marker, version)
            self.assertEqual(proof["path"]["value"], RUNTIME_ROOT + "/cw")

        def test_same_shell_empty_or_oversized_duplicate_refused(self):
            marker = "CWNU_fixture_DUPLICATE"
            correct = f"{marker}_PATH:{RUNTIME_ROOT}/cw\n{marker}_VERSION:cw 1.0.0\n"
            for field in ("PATH", "VERSION"):
                for value in ("", "x" * 513):
                    with self.subTest(field=field, length=len(value)), self.assertRaises(Failure):
                        shell_default_witness(correct + f"{marker}_{field}:{value}\n", marker, "1.0.0")

        def test_workspace_read_ignores_only_access_time(self):
            import contextlib
            import io
            source = ast.parse(Path(__file__).read_text())
            method = next(node for node in ast.walk(source)
                          if isinstance(node, ast.FunctionDef) and node.name == "workspace")
            script = next(node.value.value for node in ast.walk(method)
                          if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == "script" for target in node.targets))
            real_fstat, real_open = os.fstat, os.open
            cwd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                with tempfile.TemporaryDirectory() as directory:
                    os.chdir(directory)
                    name, token = ".cwnm-fixture-update-workspace", "fixture-owned-marker"
                    def invoke(operation, saved, changed=None):
                        opened, metadata_calls = [], []
                        def opened_file(*args, **kwargs):
                            fd = real_open(*args, **kwargs); opened.append(fd); return fd
                        def observed(fd):
                            actual = real_fstat(fd); metadata_calls.append(actual)
                            if changed and len(metadata_calls) == 2:
                                values = list(actual)
                                extra = {key: getattr(actual, key) for key in ("st_atime_ns", "st_mtime_ns", "st_ctime_ns")}
                                if changed == "st_atime_ns":
                                    values[7] += 1; extra[changed] += 1000000000
                                elif changed in extra:
                                    extra[changed] += 1
                                else:
                                    values[{"st_ino": 1, "st_nlink": 3, "st_uid": 4, "st_size": 6}[changed]] += 1
                                return os.stat_result(values, extra)
                            return actual
                        output = io.StringIO()
                        try:
                            with mock.patch.object(sys, "argv", ["workspace-probe", operation, name, token, json.dumps(saved)]), \
                                    mock.patch.object(os, "open", side_effect=opened_file), \
                                    mock.patch.object(os, "fstat", side_effect=observed), contextlib.redirect_stdout(output):
                                exec(compile(script, "checked-in-workspace-probe", "exec"), {})
                            return json.loads(output.getvalue())["identity"]
                        finally:
                            for fd in opened:
                                try: os.close(fd)
                                except OSError: pass
                    saved = invoke("create", None)
                    self.assertEqual(invoke("observe", saved, "st_atime_ns"), saved)
                    for field in ("st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_uid", "st_nlink"):
                        with self.subTest(field=field), self.assertRaises(AssertionError):
                            invoke("observe", saved, field)
                    self.assertEqual(invoke("remove", saved), saved)
                    self.assertFalse(Path(name).exists())
            finally:
                os.fchdir(cwd); os.close(cwd)

        def test_workspace_phases_preserve_marker_and_retained_names(self):
            import contextlib
            import io
            journey = Journey.__new__(Journey)
            journey.prefix, journey.marker = "cwnm-fixture", None
            journey.workspace_identity = None
            retained, operations = set(), []
            cwd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                with tempfile.TemporaryDirectory() as directory:
                    os.chdir(directory)
                    def guest(label, command, script, op, name, token, saved):
                        require(label not in retained, "fixture session name already retained")
                        retained.add(label)
                        output = io.StringIO()
                        with mock.patch.object(sys, "argv", ["workspace-probe", op, name, token, saved]), \
                                contextlib.redirect_stdout(output):
                            exec(compile(script, "checked-in-workspace-probe", "exec"), {})
                        operations.append(op)
                        return 0, output.getvalue()
                    journey.guest = guest
                    journey.workspace("create")
                    identity = journey.workspace_identity
                    journey.workspace("observe", phase="selected-b")
                    journey.workspace("observe", phase="rolled-back-a")
                    self.assertEqual(journey.workspace_identity, identity)
                    with self.assertRaisesRegex(Failure, "name already retained"):
                        journey.workspace("observe", phase="selected-b")
                    self.assertEqual(operations, ["create", "observe", "observe"])
                    journey.workspace("remove")
                    self.assertEqual(operations, ["create", "observe", "observe", "remove"])
                    self.assertEqual(len(retained), 4)
                    self.assertIsNone(journey.marker)
                    self.assertEqual(list(Path(directory).iterdir()), [])
            finally:
                os.fchdir(cwd); os.close(cwd)

        def test_workspace_failed_status_precedes_json_decode(self):
            journey = Journey.__new__(Journey)
            journey.prefix, journey.marker = "cwnm-fixture", (".cwnm-fixture-update-workspace", "marker")
            journey.workspace_identity = None
            journey.guest = mock.Mock(return_value=(1, ""))
            with self.assertRaisesRegex(Failure, "workspace marker operation failed"):
                journey.workspace("observe")

        def test_complete_asset_roundtrip_uses_real_shared_admission(self):
            with tempfile.TemporaryDirectory() as name:
                args = write_fixture(Path(name))
                admitted = Asset(*args, producer, image, "c"*64)
                admitted.unchanged()
                self.assertEqual(admitted.identity["source_tree_sha256"], "c"*64)
                self.assertEqual(admitted.identity["sha256"], args[2])
                self.assertEqual(len(admitted.files), 4)

        def test_lock_schema_types_refuse_at_entrypoint_before_journey_or_product_effects(self):
            import io
            current = sys.modules[__name__]
            for schema in (True, False, 1.0, "1", None):
                with self.subTest(schema=schema), tempfile.TemporaryDirectory() as name:
                    root = Path(name)
                    first = root/"a"; first.mkdir(mode=0o700)
                    second = root/"b"; second.mkdir(mode=0o700)
                    a = write_fixture(first,lock_changes={"schema_version":schema})
                    b = write_fixture(second,data=byte_fixture(version="1.0.1"))
                    host = root/"cw"; host.write_bytes(byte_fixture()[0]); host.chmod(0o500)
                    args = [str(Path(__file__)),"--cw",str(host),"--environment",
                            "00000000-0000-4000-8000-000000000001",
                            "--runtime-a",a[0],"--image-a",a[1],"--sha256-a",a[2],
                            "--runtime-b",b[0],"--image-b",b[1],"--sha256-b",b[2],
                            "--vm-state",str(root/"state.json"),"--runner-socket",str(root/"runner.sock")]
                    output = io.StringIO()
                    with mock.patch.object(sys,"argv",args), mock.patch.object(sys,"stdout",output), \
                         mock.patch.object(current,"shared_tools",return_value=(producer,image)), \
                         mock.patch.object(producer,"source_tree_sha256",return_value="c"*64), \
                         mock.patch.object(current,"HostCustody") as custody, \
                         mock.patch.object(current,"Journey",side_effect=AssertionError("journey started")) as journey, \
                         mock.patch.object(managed.Journey,"call",side_effect=AssertionError("product effect")) as call:
                        self.assertEqual(main(),1)
                    proof = json.loads(output.getvalue())
                    self.assertEqual(proof["stage"],"source-admission-before-product-effects")
                    self.assertFalse(proof["vm_journey_started"])
                    self.assertIn("runtime lock schema must be the integer 1",proof["failure"])
                    custody.assert_not_called(); journey.assert_not_called(); call.assert_not_called()

        def test_admit_only_complete_assets_and_derived_or_explicit_a_pin_without_effects(self):
            for explicit in (False, True):
                with self.subTest(explicit=explicit), tempfile.TemporaryDirectory() as name:
                    root = Path(name)
                    argv, a, b = entrypoint_fixture(root)
                    sentinel = root/"unrelated"; sentinel.write_bytes(b"preserve")
                    before = {str(path):stamp(path.stat()) for path in root.rglob("*") if path.is_file()}
                    argv += ["--admit-only"] + (["--sha256-a", a[2]] if explicit else [])
                    code, output, errors, effects, source, assets = invoke_entrypoint(argv)
                    self.assertEqual((code, errors), (0, ""))
                    proof = json.loads(output)
                    self.assertEqual(proof["status"], "admitted")
                    self.assertEqual(proof["proof"], "asset-admission-only")
                    self.assertEqual(proof["harness"], "scripts/dev/test-cli-native-update.py")
                    self.assertFalse(proof["vm_journey_started"])
                    self.assertEqual(proof["assets"]["A"]["identity"]["sha256"], a[2])
                    self.assertEqual(proof["assets"]["B"]["identity"]["sha256"], b[2])
                    self.assertEqual(proof["assets"]["host_cw"]["sha256"], a[2])
                    self.assertNotEqual(proof["assets"]["A"]["identity"]["package_version"],
                                        proof["assets"]["B"]["identity"]["package_version"])
                    self.assertEqual(len(proof["assets"]["A"]["files"]), 4)
                    self.assertEqual(len(proof["assets"]["B"]["files"]), 4)
                    source.assert_called_once(); self.assertEqual(assets.call_count, 2)
                    for effect in effects.values(): effect.assert_not_called()
                    after = {str(path):stamp(path.stat()) for path in root.rglob("*") if path.is_file()}
                    self.assertEqual(before, after)
                    self.assertEqual(sentinel.read_bytes(), b"preserve")

        def test_admit_only_bad_a_receipt_or_pin_refuses_without_effects(self):
            for case in ("json", "missing", "nonstring", "false-pin", "explicit-pin", "fifo", "symlink", "hardlink", "oversize"):
                with self.subTest(case=case), tempfile.TemporaryDirectory() as name:
                    argv, a, _ = entrypoint_fixture(Path(name))
                    argv += ["--admit-only"]
                    receipt = Path(a[1])
                    if case == "explicit-pin":
                        argv += ["--sha256-a", "e"*64]
                    elif case in ("fifo", "symlink"):
                        receipt.unlink()
                        if case == "fifo": os.mkfifo(receipt, 0o400)
                        else: receipt.symlink_to(receipt.with_name("runtime.pack"))
                    elif case == "hardlink":
                        retained = receipt.with_name("retained.json")
                        receipt.rename(retained); os.link(retained, receipt)
                    else:
                        value = producer.parse_json(receipt.read_bytes())
                        if case == "missing": del value["cw_sha256"]
                        if case == "nonstring": value["cw_sha256"] = True
                        if case == "false-pin": value["cw_sha256"] = "e"*64
                        raw = b"invalid-json" if case == "json" else producer.canonical(value)
                        if case == "oversize": raw = b" "*(MAX_JSON+1)
                        receipt.chmod(0o600); receipt.write_bytes(raw); receipt.chmod(0o400)
                    code, output, _, effects, _, _ = invoke_entrypoint(argv)
                    self.assertEqual(code, 1)
                    proof = json.loads(output)
                    self.assertEqual(proof["status"], "failed")
                    self.assertEqual(proof["stage"], "source-admission-before-product-effects")
                    self.assertFalse(proof["vm_journey_started"])
                    self.assertNotIn("assets", proof)
                    for effect in effects.values(): effect.assert_not_called()

        def test_duplicate_and_empty_options_refuse_before_source_or_runtime_effects(self):
            with tempfile.TemporaryDirectory() as name:
                argv, a, _ = entrypoint_fixture(Path(name))
                argv += ["--sha256-a", a[2], "--environment", "00000000-0000-4000-8000-000000000001",
                         "--vm-state", name+"/state.json", "--runner-socket", name+"/runner.sock",
                         "--codex-model", "fixture", "--claude-model", "fixture"]
                for flag in ("cw", "runtime-a", "runtime-b", "image-a", "image-b", "sha256-a", "sha256-b",
                             "environment", "vm-state", "runner-socket", "codex-model", "claude-model"):
                    value = argv[argv.index("--"+flag)+1]
                    with self.subTest(flag=flag):
                        code, _, errors, effects, source, assets = invoke_entrypoint(argv+["--"+flag+"="+value])
                        self.assertEqual(code, 2); self.assertIn("duplicate option", errors)
                        source.assert_not_called(); assets.assert_not_called()
                        for effect in effects.values(): effect.assert_not_called()
                for flag in ("admit-only", "self-test", "synthetic-peers"):
                    with self.subTest(flag=flag):
                        code, _, errors, effects, source, assets = invoke_entrypoint(argv+["--"+flag, "--"+flag])
                        self.assertEqual(code, 2); self.assertIn("duplicate option", errors)
                        source.assert_not_called(); assets.assert_not_called()
                        for effect in effects.values(): effect.assert_not_called()
                for flag in ("cw", "sha256-a", "codex-model"):
                    with self.subTest(empty=flag):
                        code, _, errors, effects, source, assets = invoke_entrypoint([argv[0], "--"+flag, ""])
                        self.assertEqual(code, 2); self.assertIn("empty value", errors)
                        source.assert_not_called(); assets.assert_not_called()
                        for effect in effects.values(): effect.assert_not_called()

        def test_admit_only_closed_mode_and_required_inputs_refuse_before_admission(self):
            with tempfile.TemporaryDirectory() as name:
                argv, _, _ = entrypoint_fixture(Path(name))
                argv += ["--admit-only"]
                illegal = (["--environment", "00000000-0000-4000-8000-000000000001"],
                           ["--vm-state", name+"/state.json"], ["--runner-socket", name+"/runner.sock"],
                           ["--codex-model", "fixture"], ["--claude-model", "fixture"],
                           ["--synthetic-peers"], ["--self-test"])
                incomplete = []
                for flag in ("cw", "runtime-a", "runtime-b", "image-a", "image-b", "sha256-b"):
                    selected = list(argv); index = selected.index("--"+flag); del selected[index:index+2]
                    incomplete.append(selected)
                for index, selected in enumerate([argv+extra for extra in illegal]+incomplete):
                    with self.subTest(case=index):
                        code, output, _, effects, source, assets = invoke_entrypoint(selected)
                        self.assertEqual(code, 2); self.assertEqual(output, "")
                        source.assert_not_called(); assets.assert_not_called()
                        for effect in effects.values(): effect.assert_not_called()

        def test_runtime_requires_explicit_inputs_and_repeats_admission_before_custody(self):
            with tempfile.TemporaryDirectory() as name:
                argv, a, b = entrypoint_fixture(Path(name))
                argv += ["--sha256-a", a[2], "--environment", "00000000-0000-4000-8000-000000000001",
                         "--vm-state", name+"/state.json", "--runner-socket", name+"/runner.sock"]
                for flag in ("sha256-a", "environment", "vm-state", "runner-socket"):
                    with self.subTest(missing=flag):
                        selected = list(argv); index = selected.index("--"+flag); del selected[index:index+2]
                        code, output, _, effects, source, assets = invoke_entrypoint(selected)
                        self.assertEqual(code, 2); self.assertEqual(output, "")
                        source.assert_not_called(); assets.assert_not_called()
                        for effect in effects.values(): effect.assert_not_called()
                code, output, _, effects, source, assets = invoke_entrypoint(argv)
                self.assertEqual(code, 1)
                self.assertIn("test effect boundary: custody", json.loads(output)["failure"])
                source.assert_called_once(); self.assertEqual(assets.call_count, 2)
                self.assertEqual(assets.call_args_list[0].args[:3], a)
                self.assertEqual(assets.call_args_list[1].args[:3], b)
                effects["custody"].assert_called_once_with(name+"/state.json", name+"/runner.sock",
                                                        "00000000-0000-4000-8000-000000000001", producer)
                for key, effect in effects.items():
                    if key != "custody": effect.assert_not_called()

        def test_rehashed_false_metadata_cannot_override_compiled_identity(self):
            for changes in ({"package_version":"1.0.1"}, {"source_revision":"e"*40},
                            {"source_tree_sha256":"e"*64}, {"rustc":f"rustc {PINNED_RUSTC_CHANNEL} wrong"},
                            {"target":"x86_64-unknown-linux-gnu"}, {"protocol_version":2},
                            {"record_version":2}, {"schema_version":True}, {"extra":"unknown"}):
                with self.subTest(changes=changes), tempfile.TemporaryDirectory() as name:
                    args = write_fixture(Path(name), metadata_changes=changes)
                    with self.assertRaises((Failure,ValueError,producer.ReleaseError)):
                        Asset(*args, producer, image, "c"*64)

        def test_source_compiler_image_and_pack_pins_fail_before_runtime(self):
            cases = (
                {"source":"e"*64},
                {"data":byte_fixture(rustc="rustc 1.92.0 synthetic fixture")},
                {"data":byte_fixture(source_revision=None,source_tree_sha256=None)},
                {"receipt_changes":{"index_sha256":"e"*64}},
                {"receipt_changes":{"archive_sha256":"e"*64}},
                {"receipt_changes":{"manifest_sha256":"e"*64}},
                {"receipt_changes":{"source_revision":"e"*40}},
                {"pack_suffix":b"unexpected trailing bytes"},
            )
            for index, options in enumerate(cases):
                with self.subTest(case=index), tempfile.TemporaryDirectory() as name:
                    options = dict(options)
                    source = options.pop("source", "c"*64)
                    args = write_fixture(Path(name), **options)
                    with mock.patch.object(managed.Journey, "call", side_effect=AssertionError("runtime effect")):
                        with self.assertRaises((Failure,ValueError,producer.ReleaseError)):
                            Asset(*args, producer, image, source)

        def test_duplicate_or_missing_build_record_and_wrong_cw_pin_refuse(self):
            data, record = byte_fixture()
            for changed in (data.replace(producer.BUILD_RECORD_MAGIC,b"x"*len(producer.BUILD_RECORD_MAGIC)),
                            data+producer.BUILD_RECORD_MAGIC):
                with tempfile.TemporaryDirectory() as name:
                    args = write_fixture(Path(name), data=(changed,record))
                    with self.assertRaises(producer.ReleaseError):
                        Asset(*args, producer, image, "c"*64)
            with tempfile.TemporaryDirectory() as name:
                lock, receipt, _ = write_fixture(Path(name))
                with self.assertRaises(Failure):
                    Asset(lock, receipt, "e"*64, producer, image, "c"*64)

        def test_admitted_inputs_cannot_change_before_mutation(self):
            with tempfile.TemporaryDirectory() as name:
                root = Path(name)
                args = write_fixture(root)
                admitted = Asset(*args, producer, image, "c"*64)
                (root/"runtime.pack").chmod(0o600)
                with self.assertRaises(Failure):
                    admitted.unchanged()

        def test_host_cw_needs_its_own_source_bound_record(self):
            data, _ = byte_fixture()
            self.assertEqual(host_identity(data, producer, "c"*64)["sha256"], digest(data))
            for changed, source in ((data,"e"*64), (b"not a cw executable","c"*64)):
                with self.assertRaises(producer.ReleaseError):
                    host_identity(changed,producer,source)

        def test_no_effect_negative_requires_the_specific_public_failure_class(self):
            value = object.__new__(Journey)
            value.environment = "00000000-0000-4000-8000-000000000001"
            value.requests = []; value.b = mock.Mock()
            value.b.lock = Path("/owned/lock")
            value.b.receipt = {"index_sha256":"b"*64}; value.b.identity = {"sha256":"c"*64}
            value.runtime_info = mock.Mock(return_value={"selection":{"revision":2}})
            value.unchanged_conversations = mock.Mock(); value.observe = mock.Mock(); value.check = mock.Mock()
            value.call = mock.Mock(return_value=(1,"","unrelated unavailable endpoint"))
            with self.assertRaises(Failure):
                value.refusals({}, {"revision":2})
            value.runtime_info.assert_not_called()
            value.check.assert_not_called()
            self.assertEqual(value.requests[0]["outcome"], "unknown")
            value.requests = []
            value.call = mock.Mock(side_effect=[
                (1,"",'status: Aborted, message: "runtime selection revision changed"'),
                (1,"",'status: FailedPrecondition, message: "pinned cw image asset admission failed"')])
            value.refusals({}, {"revision":2})
            self.assertEqual(value.call.call_count, 2)
            self.assertTrue(all(item["outcome"] == "refused-before-selection" for item in value.requests))

        def test_active_message_must_stay_running_and_completed_history_cannot_change(self):
            value = object.__new__(Journey)
            fields = ("id","driver_id","target_session_id","action","text","reply_to",
                      "expected_turn_id","expected_active_message_id","turn_id","state",
                      "created_at","accepted_at","started_at","finished_at","native_acknowledged")
            active = dict.fromkeys(fields, "stable")
            active.update(state="running", native_acknowledged=True, finished_at=None)
            before = {"driver_id":"driver", "peer":{}, "thread":"thread", "started_at":"birth",
                      "active_message_id":"message", "current_turn_id":"turn",
                      "messages":[{"id":"old", "state":"completed"},active]}
            value.snapshot = mock.Mock(return_value={"session":before})
            value.unchanged_conversations({"session":before})
            for field in ("active_message_id","current_turn_id","thread"):
                with self.subTest(field=field):
                    value.snapshot.return_value = {"session":dict(before, **{field:"replaced"})}
                    with self.assertRaises(Failure):
                        value.unchanged_conversations({"session":before})
            for messages in ([{"id":"old","state":"error"},active],
                             [before["messages"][0],dict(active,state="completed")]):
                value.snapshot.return_value = {"session":dict(before,messages=messages)}
                with self.assertRaises(Failure):
                    value.unchanged_conversations({"session":before})

        def test_two_conversations_keep_history_and_detect_worker_drift(self):
            value = object.__new__(Journey)
            fields = ("id","driver_id","target_session_id","action","text","reply_to",
                      "expected_turn_id","expected_active_message_id","turn_id","state",
                      "created_at","accepted_at","started_at","finished_at","native_acknowledged")
            active = dict.fromkeys(fields, "stable")
            active.update(state="running", native_acknowledged=True, finished_at=None)
            lead = {"driver_id":"lead-driver", "peer":{}, "thread":"lead-thread", "started_at":"birth",
                    "active_message_id":"message", "current_turn_id":"turn",
                    "messages":[{"id":"old", "state":"completed"}, active]}
            worker = dict(lead, driver_id="worker-driver", thread="worker-thread",
                          messages=[{"id":"worker-old", "state":"completed"}])
            original = {"lead":lead, "worker":worker}
            value.snapshot = mock.Mock(return_value=original)
            self.assertEqual(value.unchanged_conversations(original), original)
            for changed in (dict(worker, thread="replaced"),
                            dict(worker, messages=[]),
                            dict(worker, messages=[{"id":"worker-old", "state":"error"}])):
                with self.subTest(worker=changed):
                    value.snapshot.return_value = dict(original, worker=changed)
                    with self.assertRaises(Failure):
                        value.unchanged_conversations(original)

        def test_public_native_ack_precedes_separate_release_and_terminal_wait(self):
            value = object.__new__(Journey)
            value.synthetic = False; value.lead = "lead"; value.observer_nonce = "0a1b2c3d"
            value.ambiguous = []
            active = {"id":"original", "state":"running"}
            steer = {"id":"steer", "state":"running", "expected_turn_id":"turn", "native_acknowledged":True}
            events = []
            value.deliver = mock.Mock(return_value=(0,steer))
            value.inbox = mock.Mock(return_value={"messages":[active,steer]})
            def until(probe, predicate, *_):
                record = probe()
                require(predicate(record), "ACK absent")
                events.append("native-ack")
                return record
            value.until = until
            def send(session, text):
                self.assertEqual(session, "B")
                self.assertEqual(text, "CW_FIXTURE_UPDATE_RELEASE 0a1b2c3d")
                self.assertIn("native-ack", events)
                events.append("release")
                return {"id":"release"}
            value.send = send
            def wait(message):
                self.assertIn("release", events, "no terminal wait may precede release")
                events.append("wait-"+message)
                return {"id":message, "state":"completed", "native_acknowledged":True,
                        "result":("CW_UPDATE_RELEASE_ACK 0a1b2c3d" if message == "release" else
                                  "CW_UPDATE_STEERED 0a1b2c3d")}
            value.wait_message = wait
            value.finish_original_turn("B",active,"turn")
            self.assertEqual(events, ["native-ack","release","wait-release","wait-original","wait-steer"])
            for state, ack in (("completed",True),("running",False)):
                with self.subTest(state=state,ack=ack):
                    value.inbox.return_value = {"messages":[dict(active,state=state),
                                                           dict(steer,native_acknowledged=ack)]}
                    events.clear()
                    with self.assertRaises(Failure):
                        value.finish_original_turn("B",active,"turn")
                    self.assertNotIn("release", events)

        def test_expired_original_stream_cannot_pass_after_later_steer_text(self):
            value = object.__new__(Journey)
            value.synthetic = False; value.lead = "lead"; value.observer_nonce = "0a1b2c3d"
            active = {"id":"original", "state":"running"}
            steer = {"id":"steer", "state":"running", "expected_turn_id":"turn", "native_acknowledged":True}
            value.deliver = mock.Mock(return_value=(0,steer))
            value.until = mock.Mock(return_value=steer)
            value.inbox = mock.Mock(return_value={"messages":[active,steer]})
            value.send = mock.Mock(return_value={"id":"release"})
            value.wait_message = mock.Mock(side_effect=[
                {"id":"release", "state":"completed", "native_acknowledged":True,
                 "result":"CW_UPDATE_RELEASE_ACK 0a1b2c3d"},
                {"id":"original", "state":"completed", "native_acknowledged":True,
                 "result":"CW_UPDATE_HOLD_EXPIRED 0a1b2c3d\nCW_UPDATE_STEERED 0a1b2c3d"},
                dict(steer,state="completed"),
            ])
            with self.assertRaises(Failure):
                value.finish_original_turn("B",active,"turn")

        def test_all_inherited_checks_are_required(self):
            for synthetic in (False, True):
                value = mock.Mock(synthetic=synthetic, checks=list(UPDATE_REQUIRED), missing=[], fixture={},
                                  canary_hits=0, ambiguous=[])
                self.assertFalse(complete(value, None, []))
                expected = managed.SYNTHETIC_REQUIRED if synthetic else managed.ACTUAL_REQUIRED
                self.assertEqual({item["name"] for item in value.missing}, set(expected))

        def test_missing_cleanup_canary_or_uncertainty_refuses_success(self):
            for field in ("cleanup","canary","unknown"):
                value = mock.Mock(synthetic=False, checks=list(managed.ACTUAL_REQUIRED+UPDATE_REQUIRED),
                                  missing=[], fixture={}, canary_hits=int(field=="canary"),
                                  ambiguous=[{}] if field=="unknown" else [])
                self.assertFalse(complete(value, None, ["not clean"] if field=="cleanup" else []))

        def test_source_and_image_admission_is_shared_and_no_runtime_fallback(self):
            tree = ast.parse(Path(__file__).read_text())
            source = ast.get_source_segment(Path(__file__).read_text(),
                                           next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=="Asset"))
            self.assertIn("producer.make_identity(",source)
            self.assertIn("image.admit(",source)
            self.assertIn("producer.decode_pack(",source)
            self.assertIn("producer.toolchain_rustc(",source)
            self.assertNotIn("subprocess",source)

        def test_pair_refuses_same_bytes_or_version_or_consumer_source(self):
            first = {"sha256":"a"*64,"package_version":"1.0.0","target":producer.RUNTIME_TARGET,
                     "source_tree_sha256":"c"*64,"rustc":f"rustc {PINNED_RUSTC_CHANNEL} fixture"}
            second = dict(first,sha256="b"*64,package_version="1.0.1")
            pair(mock.Mock(identity=first),mock.Mock(identity=second))
            for field in ("sha256","package_version","target","source_tree_sha256","rustc"):
                bad = dict(second)
                bad[field] = first[field] if field in ("sha256","package_version") else "wrong"
                with self.subTest(field=field), self.assertRaises(Failure):
                    pair(mock.Mock(identity=first),mock.Mock(identity=bad))

        def test_fifo_links_and_bounds_refuse_without_opening_runtime(self):
            with tempfile.TemporaryDirectory() as name:
                root = Path(name)
                target=root/"target"; target.write_bytes(b"sentinel"); target.chmod(0o600)
                linked=root/"linked"; linked.symlink_to(target)
                fifo=root/"fifo"; os.mkfifo(fifo)
                for path in (linked,fifo):
                    with self.subTest(path=path.name), self.assertRaises((Failure,OSError)):
                        regular(path,64)
                with self.assertRaises(Failure):
                    regular(target,3)
                os.link(target,root/"hardlink")
                with self.assertRaises(Failure):
                    regular(target,64)
                self.assertEqual(target.read_bytes(),b"sentinel")

        def test_canonical_host_custody_paths_reach_the_process_boundary(self):
            current = sys.modules[__name__]
            class ProcessBoundary(Exception):
                pass

            environment = "00000000-0000-4000-8000-000000000001"
            with tempfile.TemporaryDirectory() as name:
                root = Path(name)
                state = root / "engine" / "vms" / environment / "state.json"
                state.parent.mkdir(parents=True, mode=0o700)
                runner = socket_dir.predicted(root) / "runners" / f"{environment}.sock"
                # Each level private, as cw creates them; an existing per-user
                # directory is left as it is.
                for level in (runner.parent.parent.parent, runner.parent.parent, runner.parent):
                    try:
                        level.mkdir(mode=0o700)
                    except FileExistsError:
                        pass
                expected = {"pid": 42}
                state.write_bytes(producer.canonical({"vm_id": environment, "phase": "running",
                                                     "generation": 1, "process": expected}))
                state.chmod(0o600)
                with mock.patch.object(current, "Process", side_effect=ProcessBoundary) as process:
                    # Actual lexical and descriptor/file admission; the kernel
                    # process boundary is injected, so this proves no VM custody.
                    with self.assertRaises(ProcessBoundary):
                        HostCustody(str(state), str(runner), environment, producer)
                    process.assert_called_once_with(42, expected=expected)
                    process.reset_mock()
                    state.parent.chmod(0o755)
                    with self.assertRaisesRegex(Failure, "custody input parent"):
                        HostCustody(str(state), str(runner), environment, producer)
                    process.assert_not_called()

        def test_unknown_request_is_not_resent(self):
            value = object.__new__(Journey)
            value.environment="00000000-0000-4000-8000-000000000001"
            value.requests=[]; value.ambiguous=[]; value.b=mock.Mock()
            value.b.lock=Path("/owned/lock"); value.b.receipt={"index_sha256":"b"*64}
            value.b.identity={"sha256":"c"*64}
            value.runtime=mock.Mock(side_effect=Failure("lost reply"))
            with self.assertRaises(Failure):
                value.mutate("update",1,value.b,mock.Mock(),1)
            self.assertEqual(value.runtime.call_count,1)
            self.assertEqual(value.requests[0]["request_id"],value.ambiguous[0]["request_id"])
            self.assertEqual(value.requests[0]["outcome"],"unknown")

        def test_guest_observer_has_continuous_handles_and_no_signal_or_exec(self):
            tree=ast.parse(GUEST_OBSERVER)
            attrs=[node.func.attr for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)]
            self.assertIn("pidfd_open",attrs)
            self.assertNotIn("kill",attrs); self.assertNotIn("killpg",attrs); self.assertNotIn("pidfd_send_signal",attrs)
            self.assertIn('os.O_NOFOLLOW',GUEST_OBSERVER)
            self.assertIn('fcntl.F_GET_SEALS',GUEST_OBSERVER)
            self.assertIn('time.sleep(0.04)',GUEST_OBSERVER)
            self.assertIn('parent=label+"-guardian"',GUEST_OBSERVER)

        def test_guest_observer_failure_diagnostics_are_closed_and_bounded(self):
            value={"stage":"failed","error":"AssertionError","actor":"claude-provider",
                   "check":"executable-size","actual_size":338860336}
            self.assertEqual(json.loads(observer_failure(value)),value)
            for changes in ({"actor":"x"*65}, {"check":"secret=value"}, {"error":"x"*65},
                            {"actual_size":True}, {"actual_size":-1}, {"actual_size":2**63},
                            {"terminal_output":"private"}, {"stage":"ready"}):
                with self.subTest(changes=changes),self.assertRaises(Failure):
                    observer_failure(dict(value,**changes))

        def test_guest_observer_marks_only_bounded_labels_and_sizes(self):
            tree=ast.parse(GUEST_OBSERVER)
            function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="mark")
            namespace={"failure":{},"re":re}
            exec(compile(ast.Module(body=[function],type_ignores=[]),"observer-mark","exec"),namespace)
            namespace["mark"]("claude-provider","executable-size",338860336)
            self.assertEqual(namespace["failure"],{"actor":"claude-provider","check":"executable-size",
                                                    "actual_size":338860336})
            namespace["mark"]("claude-provider","executable-sha256",338860336)
            self.assertEqual(namespace["failure"]["check"],"executable-sha256")
            namespace["mark"]("private=value","executable-size",2**63)
            self.assertEqual(namespace["failure"],{"actor":None,"check":"executable-size","actual_size":None})

        def test_guest_observer_refusal_reaches_journey_without_terminal_dump(self):
            value=object.__new__(Journey)
            value.observer_nonce="01234567"; value.environment="fixture"; value.observer="fixture"
            refusal={"stage":"failed","error":"AssertionError","actor":"claude-provider",
                     "check":"executable-size","actual_size":338860336}
            value.call=lambda *args:(0,"unrelated private terminal data\nCWNU_01234567 "+json.dumps(refusal))
            value.until=lambda probe,*args:probe()
            with self.assertRaises(Failure) as raised:
                value.observe("ready",op="ready")
            self.assertIn(observer_failure(refusal),str(raised.exception))
            self.assertNotIn("private terminal data",str(raised.exception))

        def test_public_mutation_precedes_inherited_controls_without_lifecycle_call(self):
            source=Path(__file__).read_text()
            tree=ast.parse(source)
            value=next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=="Journey")
            control=next(node for node in value.body if isinstance(node,ast.FunctionDef) and node.name=="prove_controls")
            text=ast.get_source_segment(source,control)
            self.assertLess(text.index('self.mutate("update"'),text.index('self.mutate("rollback"'))
            self.assertLess(text.index('self.mutate("rollback"'),text.index('super().prove_controls()'))
            self.assertNotIn('"restart"',text); self.assertNotIn('"repair"',text)
            self.assertNotIn('hash -r',text); self.assertNotIn('PATH=',text)
            self.assertEqual(text.count("super().prove_controls()"),1)

    result = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(Contracts))
    print(json.dumps({"status":"passed" if result.wasSuccessful() else "failed","proof":"source-contracts",
                      "tests_run":result.testsRun,"vm_executed":False,"provider_calls":False}))
    return result.wasSuccessful()


def main():
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter,
                                   allow_abbrev=False)
    for flag in ("cw","environment","runtime-a","runtime-b","image-a","image-b","sha256-a","sha256-b",
                 "vm-state","runner-socket","codex-model","claude-model"):
        parser.add_argument("--"+flag,action=SingleUse)
    for flag in ("synthetic-peers","self-test","admit-only"):
        parser.add_argument("--"+flag,action=SingleUse,nargs=0,const=True,default=False)
    args=parser.parse_args()
    provided=getattr(args,"_provided",set())
    if args.self_test:
        if provided != {"self_test"}:
            parser.error("--self-test accepts no admission or runtime inputs")
        return 0 if contract_tests() else 1
    if not all(getattr(args,name.replace("-","_")) for name in
               ("cw","runtime-a","runtime-b","image-a","image-b","sha256-b")):
        parser.error("both pinned A/B transports and host CW are required")
    if args.admit_only:
        if provided & {"environment","vm_state","runner_socket","codex_model","claude_model","synthetic_peers"}:
            parser.error("--admit-only accepts no environment, kernel custody, model or synthetic-peer inputs")
    else:
        if not all(getattr(args,name) for name in ("sha256_a","environment","vm_state","runner_socket")):
            parser.error("runtime execution requires an explicit A digest, environment and kernel custody inputs")
        require(sys.platform.startswith("linux") and hasattr(os,"pidfd_open"), "native update acceptance requires Linux pidfds")
        require(managed.is_uuid(args.environment), "environment must be an immutable canonical UUID")
    try:
        producer,a,b,cw,host_stamp,admitted_host=admit_assets(args)
        if args.admit_only:
            a.unchanged(); b.unchanged()
            require(stamp(cw.lstat()) == host_stamp, "host CW changed during source admission")
            print(json.dumps({"status":"admitted","proof":"asset-admission-only",
                              "harness":"scripts/dev/test-cli-native-update.py","vm_journey_started":False,
                              "assets":{"A":a.proof(),"B":b.proof(),"host_cw":admitted_host}},indent=2))
            return 0
        custody=HostCustody(args.vm_state,args.runner_socket,args.environment,producer)
    except Exception as error:
        print(json.dumps({"status":"failed", "harness":"scripts/dev/test-cli-native-update.py",
                          "stage":"source-admission-before-product-effects", "vm_journey_started":False,
                          "failure":managed.scrub(error)}, indent=2))
        return 1
    journey=Journey(str(cw),args.environment,args.synthetic_peers,args.codex_model,args.claude_model,a,b,custody)
    failure=None; cleanup_errors=[]
    signal.signal(signal.SIGTERM,managed.terminate); signal.signal(signal.SIGINT,managed.terminate)
    try:
        journey.run()
        a.unchanged(); b.unchanged(); custody.verify()
        require(stamp(cw.lstat()) == host_stamp, "host CW changed during the guest-only runtime journey")
    except Exception as error:
        failure={"stage":journey.stage,"detail":managed.scrub(error)}
    finally:
        signal.signal(signal.SIGTERM,signal.SIG_IGN); signal.signal(signal.SIGINT,signal.SIG_IGN)
        try:
            cleanup_errors=journey.cleanup()
            custody.verify()
        except Exception as error:
            cleanup_errors.append(managed.scrub(error,300))
        finally:
            custody.close()
    passed=complete(journey,failure,cleanup_errors)
    inherited_limits = [
        "guest agents cannot invoke host cw run or spawn sessions through the guest daemon; the host CLI "
        "launches lead and worker, same-VM parent adoption is the orchestration proof, and "
        "cross-environment parents are not claimed",
        "message records are observed only through cw inbox and wait; result-outbox cut-point recovery "
        "remains covered by the trusted-host journey",
        ("deterministic peers replace the guest agents; this mode does not prove protected provider delivery"
         if args.synthetic_peers else
         "the guest tool marker is required from the Codex lead only; Claude tool use is not exercised"),
        "No direct daemon birth observation or remote-member execution.",
    ]
    print(json.dumps({"status":"passed" if passed else "failed","harness":"scripts/dev/test-cli-native-update.py",
                      "mode":"synthetic-peers" if args.synthetic_peers else "protected-broker-actual-agents",
                      "environment_id":args.environment,"session_prefix":journey.prefix,"checks":journey.checks,
                      "profile_selected":journey.profile_selected,"agents":journey.agents,
                      "missing_acceptance":journey.missing,"fixture_expectations":list(journey.fixture.values()),
                      "failure":failure,"cleanup_errors":cleanup_errors,"unknown_or_ambiguous":journey.ambiguous,
                      "expected_unknown":journey.expected_unknown,"canary_shaped_values_observed":journey.canary_hits,
                      "assets":{"A":a.proof(),"B":b.proof(),"host_cw":admitted_host},
                      "runtime_requests":journey.requests,"runtime_evidence":journey.runtime_evidence,
                      "host_custody":journey.host_proof,"continuous_guest_evidence":journey.observer_evidence,
                      "owned_sessions":journey.final_sessions,"custody_evidence":journey.custody_evidence,
                      "retained_workspace_marker":journey.marker,"workspace_identity":journey.workspace_identity,
                      "limitations":journey.limitations+inherited_limits,
                      "elapsed_seconds":round(time.monotonic()-journey.started,1),
                      "deadline_seconds":managed.OVERALL_SECONDS},indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
