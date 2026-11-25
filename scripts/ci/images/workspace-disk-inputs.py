#!/usr/bin/env python3
"""Hand the workspace disk's build inputs to the KVM runner and the built disk back (#5602).

  pack-inputs   --runtime DIR --smoke FILE --output TAR
  unpack-inputs --tar TAR --sha256 HEX --output DIR
  pack-disk     --dir DIR --output TAR
  unpack-disk   --tar TAR --sha256 HEX --output DIR

A workflow artifact keeps no file mode, so each hand-off is one tar, written
in a fixed order with fixed owners and times, so the same files give the same
bytes; its sha256 travels as a job output and the receiving job refuses any
other. The inputs are codewire-local-vmm-smoke and the pod-runtime image's
runtime: artifacts/ and artifacts.lock, with the modes cw installs them with
(directories 0700, Cloud Hypervisor and virtiofsd 0500, every other file
0400), each file checked against the lock. The disk is exactly the files
workspace-disk.sh build writes. Unpacking takes only those names, regular
files and directories, into a new directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tarfile
from pathlib import Path

EXECUTABLES = ("cloud_hypervisor", "virtiofsd")
DATA = ("kernel", "initramfs")
SMOKE = "codewire-local-vmm-smoke"
DISK_FILES = ({"config.json", "image.raw", "record.json"}, {"config.json", "image.raw", "index.json", "record.json"})
MAX_LOCK = 64 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}")


class Refused(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def lock_entries(runtime):
    """The lock's (key, file name, sha256, size, mode) for every artifact."""
    path = runtime / "artifacts.lock"
    require(path.is_file() and not path.is_symlink(), "the runtime has no artifacts.lock file")
    require(path.stat().st_size <= MAX_LOCK, "artifacts.lock is too large")
    lock = json.loads(path.read_text())
    require(isinstance(lock, dict) and set(lock) == {"schema_version", *EXECUTABLES, *DATA},
            "artifacts.lock is not exactly Cloud Hypervisor, virtiofsd, the kernel and the guest root")
    entries = []
    for key in EXECUTABLES + DATA:
        entry = lock[key]
        name = entry.get("path") if isinstance(entry, dict) else None
        require(isinstance(name, str) and name and "/" not in name and name not in (".", ".."),
                f"the lock's {key} path is not one file name")
        require(isinstance(entry.get("sha256"), str) and HEX64.fullmatch(entry["sha256"]),
                f"the lock's {key} sha256 is malformed")
        require(isinstance(entry.get("size"), int) and entry["size"] >= 0, f"the lock's {key} size is malformed")
        entries.append((key, name, entry["sha256"], entry["size"], 0o500 if key in EXECUTABLES else 0o400))
    return entries


def mode(path):
    return path.lstat().st_mode & 0o7777


def check_runtime(runtime):
    """RUNTIME holds exactly the lock's artifacts, with their bytes and modes."""
    artifacts = runtime / "artifacts"
    for directory in (runtime, artifacts):
        require(directory.is_dir() and not directory.is_symlink(), f"{directory.name} is not a directory")
        require(mode(directory) == 0o700, f"{directory.name}/ is not mode 0700")
    require(mode(runtime / "artifacts.lock") == 0o400, "artifacts.lock is not mode 0400")
    entries = lock_entries(runtime)
    require(sorted(os.listdir(artifacts)) == sorted(name for _, name, *_ in entries),
            "artifacts/ holds files the lock does not name, or misses one")
    for key, name, digest, size, wanted in entries:
        path = artifacts / name
        require(path.is_file() and not path.is_symlink(), f"the {key} artifact is not a regular file")
        require(mode(path) == wanted, f"the {key} artifact is not mode {wanted:o}")
        require(path.stat().st_size == size and sha256_file(path) == digest, f"the {key} artifact is not the locked bytes")
    return entries


def add(archive, path, name, file_mode):
    info = tarfile.TarInfo(name)
    info.mode, info.uid, info.gid, info.uname, info.gname, info.mtime = file_mode, 0, 0, "", "", 0
    if path is None:
        info.type = tarfile.DIRTYPE
        archive.addfile(info)
        return
    info.size = path.stat().st_size
    with open(path, "rb") as stream:
        archive.addfile(info, stream)


def write_tar(output, members):
    require(not os.path.lexists(output), f"{output} already exists")
    with tarfile.open(output, "x", format=tarfile.PAX_FORMAT) as archive:
        for path, name, file_mode in members:
            add(archive, path, name, file_mode)
    return sha256_file(output)


def pack_inputs(runtime, smoke, output):
    entries = check_runtime(runtime)
    require(smoke.is_file() and not smoke.is_symlink() and os.access(smoke, os.X_OK), "--smoke is not an executable file")
    members = [(smoke, SMOKE, 0o500), (None, "runtime", 0o700), (None, "runtime/artifacts", 0o700)]
    members += [(runtime / "artifacts" / name, f"runtime/artifacts/{name}", wanted) for _, name, _, _, wanted in entries]
    members.append((runtime / "artifacts.lock", "runtime/artifacts.lock", 0o400))
    return write_tar(output, members)


def unpack(tar, digest, output, allowed):
    """Extract TAR, whose sha256 must be DIGEST, into the new directory OUTPUT:
    only regular files and directories whose names ALLOWED accepts."""
    require(HEX64.fullmatch(digest or ""), "--sha256 is not 64 lowercase hex digits")
    require(sha256_file(tar) == digest, "the tar is not the one the job output names")
    require(not os.path.lexists(output), f"{output} already exists")
    output.mkdir(mode=0o700)
    with tarfile.open(tar, "r:") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        require(len(names) == len(set(names)), "the tar names a member twice")
        for member in members:
            require(member.isreg() or member.isdir(), f"{member.name} is not a regular file or directory")
            require(allowed(member.name, member.isdir()), f"{member.name} is not a member this hand-off carries")
            # A tampered hand-back must not carry a setuid, setgid or sticky bit.
            require(member.mode & ~0o777 == 0, f"{member.name} has a mode beyond 0777")
        for member in members:
            target = output / member.name
            if member.isdir():
                target.mkdir(mode=0o700)
            else:
                source = archive.extractfile(member)
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    while block := source.read(1 << 20):
                        stream.write(block)
        # Modes last, so a 0500 directory never refuses its own files.
        for member in sorted(members, key=lambda item: item.name.count("/"), reverse=True):
            os.chmod(output / member.name, member.mode)


def unpack_inputs(tar, digest, output):
    expected = {SMOKE: False, "runtime": True, "runtime/artifacts": True, "runtime/artifacts.lock": False}

    def allowed(name, is_dir):
        if name in expected:
            return expected[name] == is_dir
        return not is_dir and name.startswith("runtime/artifacts/") and name.count("/") == 2

    unpack(tar, digest, output, allowed)
    require(mode(output / SMOKE) == 0o500, f"{SMOKE} is not mode 0500")
    check_runtime(output / "runtime")


def pack_disk(directory, output):
    names = sorted(os.listdir(directory))
    require(set(names) in DISK_FILES, f"{directory} does not hold exactly a built disk's files")
    members = []
    for name in names:
        path = directory / name
        require(path.is_file() and not path.is_symlink(), f"{name} is not a regular file")
        members.append((path, name, 0o644))
    return write_tar(output, members)


def unpack_disk(tar, digest, output):
    names = set()

    def allowed(name, is_dir):
        names.add(name)
        return not is_dir and any(name in files for files in DISK_FILES)

    unpack(tar, digest, output, allowed)
    require(names in DISK_FILES, "the tar does not hold exactly a built disk's files")
    # The KVM runner's bytes reach a credentialed job here: only the modes
    # pack_disk writes are accepted.
    for name in names:
        require(mode(output / name) == 0o644, f"{name} is not mode 0644")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    steps = parser.add_subparsers(dest="step", required=True)
    step = steps.add_parser("pack-inputs")
    step.add_argument("--runtime", type=Path, required=True)
    step.add_argument("--smoke", type=Path, required=True)
    step.add_argument("--output", type=Path, required=True)
    for name in ("unpack-inputs", "unpack-disk"):
        step = steps.add_parser(name)
        step.add_argument("--tar", type=Path, required=True)
        step.add_argument("--sha256", required=True)
        step.add_argument("--output", type=Path, required=True)
    step = steps.add_parser("pack-disk")
    step.add_argument("--dir", type=Path, required=True)
    step.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.step == "pack-inputs":
            print(pack_inputs(args.runtime, args.smoke, args.output))
        elif args.step == "pack-disk":
            print(pack_disk(args.dir, args.output))
        elif args.step == "unpack-inputs":
            unpack_inputs(args.tar, args.sha256, args.output)
        else:
            unpack_disk(args.tar, args.sha256, args.output)
    except (Refused, OSError, ValueError, tarfile.TarError) as error:
        print(f"workspace-disk-inputs: ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
