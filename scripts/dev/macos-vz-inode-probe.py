#!/usr/bin/env python3
"""Run the explicit Apple Silicon VZ exact-inode kill fixture.

This is a developer hardware probe, not CI and not product wiring. It never
signs its helper. The caller must supply an already-entitled helper and the
reviewed kernel/initramfs plus a synthetic ext4 data disk.
"""

from __future__ import annotations

import argparse
import array
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import uuid


MAX_FRAME_BYTES = 16 * 1024
SEED_BYTES = 4_096
MIB = 1024 * 1024
EXT4_SUPERBLOCK = 1_024
EXT4_MAGIC_OFFSET = 0x38
EXT4_UUID_OFFSET = 0x68


def exact_input(path: str, label: str) -> Path:
    value = Path(path)
    if not value.is_absolute() or value.is_symlink():
        raise ValueError(f"{label} must be an absolute non-symlink path")
    descriptor = os.open(value, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_size <= 0:
            raise ValueError(f"{label} must be a non-empty regular file")
    finally:
        os.close(descriptor)
    return value


def exact_sha256(value: str, label: str) -> str:
    if len(value) != 64 or any(byte not in "0123456789abcdef" for byte in value):
        raise ValueError(f"{label} must be exactly 64 lowercase hexadecimal characters")
    return value


def exact_uuid(value: str, label: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise ValueError(f"{label} must be a canonical non-nil UUID") from error
    if parsed.int == 0 or str(parsed) != value:
        raise ValueError(f"{label} must be a canonical non-nil UUID")
    return value


def copy_private(source: Path, destination: Path) -> None:
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        while True:
            chunk = os.read(source_fd, MIB)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise OSError("short artifact copy")
                view = view[written:]
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
        os.close(source_fd)


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        for chunk in iter(lambda: os.read(descriptor, MIB), b""):
            checksum.update(chunk)
    finally:
        os.close(descriptor)
    return checksum.hexdigest()


def ext4_uuid(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        magic = os.pread(descriptor, 2, EXT4_SUPERBLOCK + EXT4_MAGIC_OFFSET)
        raw = os.pread(descriptor, 16, EXT4_SUPERBLOCK + EXT4_UUID_OFFSET)
    finally:
        os.close(descriptor)
    if magic != b"\x53\xef" or len(raw) != 16 or not any(raw):
        raise ValueError("data disk must have an ext4 superblock and non-nil UUID")
    return str(uuid.UUID(bytes=raw))


def framed(payload: bytes) -> bytes:
    if not 0 < len(payload) <= MAX_FRAME_BYTES:
        raise ValueError("control frame is outside the fixed bound")
    return struct.pack(">I", len(payload)) + payload


def receive_frame(stream: socket.socket) -> bytes:
    header = receive_exact(stream, 4)
    size = struct.unpack(">I", header)[0]
    if not 0 < size <= MAX_FRAME_BYTES:
        raise RuntimeError("helper returned an invalid control frame")
    return receive_exact(stream, size)


def receive_exact(stream: socket.socket, count: int) -> bytes:
    output = bytearray()
    while len(output) < count:
        part = stream.recv(count - len(output))
        if not part:
            raise RuntimeError("helper control channel closed early")
        output.extend(part)
    return bytes(output)


def expect_response(stream: socket.socket, expected: str) -> None:
    payload = receive_frame(stream)
    canonical = json.dumps(
        {"result": expected, "schemaVersion": 1},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    if payload != canonical:
        raise RuntimeError("helper returned an unexpected control response")


def require_entitled_helper(helper: Path) -> None:
    result = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", str(helper)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    xml_offset = result.stdout.find(b"<?xml")
    try:
        entitlements = plistlib.loads(result.stdout[xml_offset:]) if xml_offset >= 0 else {}
    except plistlib.InvalidFileException:
        entitlements = {}
    if (
        result.returncode != 0
        or entitlements.get("com.apple.security.virtualization") is not True
    ):
        raise RuntimeError("helper lacks the required virtualization entitlement")


def replace_with_decoy(path: Path, size: int) -> None:
    decoy = path.with_name(path.name + ".decoy")
    descriptor = os.open(decoy, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.ftruncate(descriptor, size)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(decoy, path)


def run(arguments: argparse.Namespace) -> None:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("the VZ inode probe requires Apple Silicon macOS")
    major = int(platform.mac_ver()[0].split(".", 1)[0])
    if major < 26:
        raise RuntimeError("the VZ inode probe requires macOS 26 or later")

    helper = exact_input(arguments.helper, "helper")
    kernel = exact_input(arguments.kernel, "kernel")
    initramfs = exact_input(arguments.initramfs, "initramfs")
    data = exact_input(arguments.data, "data disk")
    helper_sha256 = exact_sha256(arguments.helper_sha256, "helper SHA-256")
    kernel_sha256 = exact_sha256(arguments.kernel_sha256, "kernel SHA-256")
    initramfs_sha256 = exact_sha256(arguments.initramfs_sha256, "initramfs SHA-256")
    data_uuid = exact_uuid(arguments.data_uuid, "data UUID")

    with tempfile.TemporaryDirectory(prefix="codewire-vz-inode-probe-") as temporary:
        root = Path(temporary)
        private_helper = root / "codewire-vz-runner"
        copy_private(helper, private_helper)
        private_helper.chmod(0o700)
        if digest(private_helper) != helper_sha256:
            raise ValueError("helper bytes differ from the reviewed SHA-256")
        require_entitled_helper(private_helper)
        paths = {
            "kernel": root / "kernel",
            "initialRamdisk": root / "initramfs",
            "seedDisk": root / "seed",
            "dataDisk": root / "data",
        }
        copy_private(kernel, paths["kernel"])
        copy_private(initramfs, paths["initialRamdisk"])
        paths["seedDisk"].write_bytes(os.urandom(SEED_BYTES))
        paths["seedDisk"].chmod(0o600)
        copy_private(data, paths["dataDisk"])

        if digest(paths["kernel"]) != kernel_sha256:
            raise ValueError("kernel bytes differ from the reviewed SHA-256")
        if digest(paths["initialRamdisk"]) != initramfs_sha256:
            raise ValueError("initramfs bytes differ from the reviewed SHA-256")
        if ext4_uuid(paths["dataDisk"]) != data_uuid:
            raise ValueError("data disk differs from the reviewed ext4 UUID")

        data_size = paths["dataDisk"].stat().st_size
        if not 256 * MIB <= data_size <= 1024 * 1024 * MIB or data_size % MIB:
            raise ValueError("data disk size is outside the admitted aligned range")
        configuration = {
            "cpuCount": 1,
            "daemonVsockPort": 7_777,
            "dataDisk": {"filesystemUUID": data_uuid, "size": data_size},
            "generation": 1,
            "initialRamdisk": {
                "sha256": initramfs_sha256,
                "size": paths["initialRamdisk"].stat().st_size,
            },
            "kernel": {"sha256": kernel_sha256, "size": paths["kernel"].stat().st_size},
            "memoryMiB": 512,
            "schemaVersion": 1,
            "seedDisk": {"sha256": digest(paths["seedDisk"]), "size": SEED_BYTES},
            "vmID": str(uuid.uuid4()),
        }
        payload = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()

        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        parent.settimeout(arguments.timeout)
        process = subprocess.Popen(
            [str(private_helper), "inode-probe", "--control-fd", str(child.fileno())],
            pass_fds=(child.fileno(),),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        child.close()
        descriptors = [
            os.open(paths["kernel"], os.O_RDONLY | os.O_NOFOLLOW),
            os.open(paths["initialRamdisk"], os.O_RDONLY | os.O_NOFOLLOW),
            os.open(paths["seedDisk"], os.O_RDONLY | os.O_NOFOLLOW),
            os.open(paths["dataDisk"], os.O_RDWR | os.O_NOFOLLOW),
        ]
        try:
            rights = array.array("i", descriptors)
            request = framed(payload)
            sent = parent.sendmsg([request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
            if sent < len(request):
                parent.sendall(request[sent:])
            expect_response(parent, "descriptors-admitted")

            # Only the helper's SCM_RIGHTS copies now retain the admitted
            # inodes. Every original fixture pathname is atomically replaced
            # by a zero-filled same-size decoy before the start command.
            for descriptor in descriptors:
                os.close(descriptor)
            descriptors.clear()
            for path in paths.values():
                replace_with_decoy(path, path.stat().st_size)
            parent.sendall(framed(b"\x01"))
            expect_response(parent, "guest-ready")

            os.kill(process.pid, signal.SIGKILL)
            return_code = process.wait(timeout=arguments.timeout)
            if return_code != -signal.SIGKILL:
                raise RuntimeError("helper did not terminate with the fixture SIGKILL")
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise RuntimeError("a helper-owned process survived the fixture SIGKILL")
            if parent.recv(1) != b"":
                raise RuntimeError("helper control ownership survived process death")
            print(
                "macOS VZ exact-inode probe: guest-ready then helper-kill ownership closed "
                f"helper={helper_sha256} kernel={kernel_sha256} "
                f"initramfs={initramfs_sha256} data_uuid={data_uuid}"
            )
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
            parent.close()
            if process.poll() is None:
                os.kill(process.pid, signal.SIGKILL)
                process.wait()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", required=True)
    parser.add_argument("--helper-sha256", required=True)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--kernel-sha256", required=True)
    parser.add_argument("--initramfs", required=True)
    parser.add_argument("--initramfs-sha256", required=True)
    parser.add_argument("--data", required=True)
    parser.add_argument("--data-uuid", required=True)
    parser.add_argument("--timeout", type=float, default=45.0)
    arguments = parser.parse_args()
    if not 5 <= arguments.timeout <= 120:
        parser.error("--timeout must be between 5 and 120 seconds")
    try:
        run(arguments)
    except Exception as error:
        print(f"macOS VZ exact-inode probe: ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
