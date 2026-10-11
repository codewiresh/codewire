#!/usr/bin/env python3
"""Build and probe a pinned native formatter; no installation, VM or product claim.

Run on the developer Mac with an explicitly supplied official source archive,
or probe an already-built binary selected by its explicit SHA-256. Probe-only
results do not attest its build or source provenance; compose that separately.
The new output directory is retained on success and failure for inspection.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import struct
import sys
import tarfile
import threading
import time
import uuid


VERSION = "1.47.4"
SOURCE_NAME = f"e2fsprogs-{VERSION}.tar.gz"
SOURCE_URL = f"https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v{VERSION}/{SOURCE_NAME}"
SOURCE_SHA256 = "da274408bebbfd13a5a2fc3cfc66e3ffff17c48534673aa67f88d49b99123b96"
SOURCE_LIMIT = 16 * 1024 * 1024
FEATURES = (
    "has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,flex_bg,"
    "sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum"
)
FEATURE_WORDS = (0x3C, 0x2C2, 0x46B)
CONFIG = (
    "[defaults]\n"
    "base_features = " + FEATURES + "\n"
    "blocksize = 4096\ninode_size = 256\ninode_ratio = 16384\n"
    "enable_periodic_fsck = 0\n"
    "[fs_types]\next4 = {\nfeatures = " + FEATURES + "\n}\n"
).encode()
CONFIG_SHA256 = hashlib.sha256(CONFIG).hexdigest()
CONFIGURE_ARGS = (
    "--enable-libuuid", "--enable-libblkid", "--disable-elf-shlibs",
    "--disable-bsd-shlibs", "--without-libarchive", "--disable-nls",
    "--disable-testio-debug", "--disable-uuidd", "--disable-fsck",
    "--without-udev-rules-dir", "--without-crond-dir",
    "--without-systemd-unit-dir",
)
FORBIDDEN_DEFINES = (
    "HAVE_MAGIC_H", "HAVE_ARCHIVE_H", "HAVE_LIBARCHIVE",
    "ENABLE_NLS", "CONFIG_TESTIO_DEBUG", "CONFIG_DLOPEN_LIBARCHIVE",
)
# The programs the macOS local runtime ships (macos-local-runtime.py): make
# directory and target. Build mode also builds the checker, resizer and
# debugfs beside the formatter; probe mode exercises only mke2fs.
TOOLS = (("misc", "mke2fs"), ("e2fsck", "e2fsck"), ("resize", "resize2fs"), ("debugfs", "debugfs"))
CASES = ((256, "CWROOT"), (513, "CWSTATE"))
# initialize.c removes an undersized final block group and retries. For the
# fixed 513 MiB case its 256-block tail cannot fit the inode table + overhead.
# Keep raw-file and filesystem capacity separate, never accept arbitrary loss.
FILESYSTEM_MIB = {256: 256, 513: 512}

_spec = importlib.util.spec_from_file_location(
    "macos_formatter_developer_loop", Path(__file__).with_name("macos-cli.py")
)
developer_loop = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(developer_loop)


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink, info.st_size)


def hash_fd(descriptor, size):
    checksum = hashlib.sha256()
    offset = 0
    while offset < size:
        block = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not block:
            raise ValueError("artifact truncated while hashing")
        checksum.update(block)
        offset += len(block)
    if os.pread(descriptor, 1, size):
        raise ValueError("artifact grew while hashing")
    return checksum.hexdigest()


@contextlib.contextmanager
def admitted_file(path, checksum, maximum, mode=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        initial = os.fstat(descriptor)
        if (not stat.S_ISREG(initial.st_mode) or initial.st_uid != os.getuid()
                or initial.st_nlink != 1 or not 0 < initial.st_size <= maximum
                or (mode is not None and stat.S_IMODE(initial.st_mode) != mode)):
            raise ValueError("artifact is not an admitted owned regular file")
        if hash_fd(descriptor, initial.st_size) != checksum:
            raise ValueError("artifact checksum mismatch")
        require_identity(path, descriptor, initial)
        yield descriptor, initial
        require_identity(path, descriptor, initial)
        if hash_fd(descriptor, initial.st_size) != checksum:
            raise ValueError("artifact changed during command")
    finally:
        os.close(descriptor)


def require_identity(path, descriptor, initial):
    if (file_identity(os.lstat(path)) != file_identity(initial)
            or file_identity(os.fstat(descriptor)) != file_identity(initial)):
        raise ValueError("retained file identity changed")


def private_directory(path):
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("expected an owned private directory")


def write_new(path, content, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def write_json(path, value):
    write_new(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def extract_source(archive, destination, normalized):
    """Keep the existing safe extractor; upstream also records directory entries."""
    with tarfile.open(archive) as original, tarfile.open(normalized, "x") as filtered:
        members = original.getmembers()
        if len(members) > 10000 or sum(item.size for item in members) > 128 * 1024 * 1024:
            raise ValueError("source archive exceeds build bounds")
        for member in members:
            name = developer_loop.safe_name(member.name)
            if name.parts[0] != f"e2fsprogs-{VERSION}":
                raise ValueError("unexpected source archive root")
            if member.isdir():
                continue
            if not member.isfile() and not member.issym():
                raise ValueError("unsupported upstream source entry")
            if member.isfile():
                with original.extractfile(member) as content:
                    filtered.addfile(member, content)
            else:
                filtered.addfile(member)
    developer_loop.extract(normalized, destination, links=True)


def validate_build_config(content, make_config):
    for macro in FORBIDDEN_DEFINES:
        if re.search(r"^\s*#\s*define\s+" + macro + r"\b", content, re.M):
            raise ValueError(f"unexpected optional build feature: {macro}")
    if not re.search(r"^#define CONFIG_DISABLE_LIBARCHIVE 1$", content, re.M):
        raise ValueError("libarchive was not explicitly disabled")
    for library, value in (("UUID", r"\$\(LIB\)/libuuid\.a"),
                           ("BLKID", r"\$\(LIB\)/libblkid\.a[ \t]+\$\(LIBUUID\)")):
        if not re.search(r"^LIB" + library + r"[ \t]*=[ \t]*" + value
                         + r"[ \t]*$", make_config, re.M):
            raise ValueError(f"private static {library} library was not selected")


def validate_dependencies(output):
    dependencies = []
    for line in output.splitlines()[1:]:
        match = re.fullmatch(r"\s+(/\S+) \(compatibility version [^)]+\)", line)
        if not match:
            raise ValueError("unrecognized Mach-O dependency report")
        dependencies.append(match.group(1))
    if dependencies != ["/usr/lib/libSystem.B.dylib"]:
        raise ValueError("formatter has non-libSystem dynamic dependencies")


def inspect_ext4(descriptor, size, filesystem_uuid, label):
    size_mib, remainder = divmod(size, 1024 * 1024)
    if remainder or size_mib not in FILESYSTEM_MIB:
        raise ValueError("unknown fixed image-size case")
    filesystem_size = FILESYSTEM_MIB[size_mib] * 1024 * 1024
    block = os.pread(descriptor, 1024, 1024)
    if len(block) != 1024:
        raise ValueError("truncated ext4 superblock")
    u16 = lambda offset: struct.unpack_from("<H", block, offset)[0]
    u32 = lambda offset: struct.unpack_from("<I", block, offset)[0]
    if u16(0x38) != 0xEF53 or u16(0x3A) != 1:
        raise ValueError("filesystem is not clean ext4")
    if u32(0x18) != 2 or ((u32(0x150) << 32) | u32(4)) * 4096 != filesystem_size:
        raise ValueError("filesystem size or block size mismatch")
    if tuple(u32(offset) for offset in (0x5C, 0x60, 0x64)) != FEATURE_WORDS:
        raise ValueError("filesystem feature profile mismatch")
    if block[0x68:0x78] != filesystem_uuid.bytes:
        raise ValueError("filesystem UUID mismatch")
    if block[0x78:0x88] != label.encode().ljust(16, b"\0"):
        raise ValueError("filesystem label mismatch")
    if u16(0x58) != 256 or u16(0xFE) != 64:
        raise ValueError("unexpected inode or group descriptor size")
    group = os.pread(descriptor, 64, 4096)
    if len(group) != 64:
        raise ValueError("truncated group descriptor")
    table = struct.unpack_from("<I", group, 8)[0] | (struct.unpack_from("<I", group, 40)[0] << 32)
    root_offset = table * 4096 + 256  # inode 2 in group 0
    if table < 2 or root_offset + 256 > filesystem_size:
        raise ValueError("root inode lies outside the filesystem")
    inode = os.pread(descriptor, 256, root_offset)
    if (len(inode) != 256 or struct.unpack_from("<H", inode, 0)[0] != 0o40755
            or any(struct.unpack_from("<H", inode, offset)[0] for offset in (2, 24, 120, 122))):
        raise ValueError("root inode mode or ownership mismatch")
    return {"uuid": str(filesystem_uuid), "label": label, "image_bytes": size,
            "filesystem_bytes": filesystem_size, "unused_tail_bytes": size - filesystem_size,
            "block_bytes": 4096, "feature_words": list(FEATURE_WORDS),
            "root_mode": "040755", "root_uid": 0, "root_gid": 0}


def require_active(cancel, deadline):
    if cancel.is_set():
        raise RuntimeError("formatter discriminator cancelled")
    if time.monotonic() >= deadline:
        raise TimeoutError("formatter discriminator exceeded its deadline")


def run_checked(argv, cwd, env, log, cancel, deadline, commands, seconds):
    command_deadline = min(deadline, time.monotonic() + seconds)
    item = {"argv": argv, "cwd": str(cwd), "log": "logs/" + log.name}
    commands.append(item)
    print(f"command {len(commands)}: {argv[0]}", flush=True)
    status = developer_loop.run_command(argv, cwd, env, log, cancel, command_deadline)
    item["exit_code"] = status  # Actual child exit, not the wrapper's acceptance.
    require_active(cancel, command_deadline)
    if status != 0:
        raise RuntimeError(f"command failed ({status}); see {log}")
    return log.read_text()


def accept_result(result, cancel, deadline):
    require_active(cancel, deadline)
    result["status"] = "passed"


def format_empty(bundle, binary_sha, probe_root, size_mib, label, command):
    if (size_mib, label) not in CASES:
        raise ValueError("only the fixed empty-image probe cases are allowed")
    private_directory(bundle)
    private_directory(probe_root)
    binary, config = bundle / "mke2fs", bundle / "mke2fs.conf"
    size = size_mib * 1024 * 1024
    filesystem_uuid = uuid.UUID(int=(1 << 120) + size_mib)
    with admitted_file(binary, binary_sha, 16 * 1024 * 1024, 0o500), \
            admitted_file(config, CONFIG_SHA256, len(CONFIG), 0o400):
        path = probe_root / f"{label.lower()}-{size_mib}.raw"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.ftruncate(descriptor, size)
            os.fsync(descriptor)
            initial = os.fstat(descriptor)
            require_identity(path, descriptor, initial)
            env = {"LC_ALL": "C", "PATH": str(bundle), "MKE2FS_CONFIG": str(config),
                   "BLKID_FILE": str(probe_root / "blkid.cache"),
                   "E2FSPROGS_UNDO_DIR": str(probe_root)}
            command([str(binary), "-q", "-F", "-t", "ext4", "-b", "4096",
                     "-I", "256", "-i", "16384", "-m", "0", "-U", str(filesystem_uuid),
                     "-L", label, "-O", "none," + FEATURES,
                     "-E", "lazy_itable_init=0,lazy_journal_init=0,nodiscard,root_owner=0:0,root_perms=0755",
                     str(path)], probe_root, env, 30)
            require_identity(path, descriptor, initial)
            os.fsync(descriptor)
            observed = inspect_ext4(descriptor, size, filesystem_uuid, label)
            observed["allocated_bytes"] = os.fstat(descriptor).st_blocks * 512
            if not 0 < observed["allocated_bytes"] < size // 2:
                raise ValueError("empty image allocation exceeds the probe bound")
            return observed
        finally:
            os.close(descriptor)


def copy_probe_binary(binary, checksum, destination):
    if not binary.is_absolute() or binary.parent.resolve() != binary.parent:
        raise ValueError("probe binary needs an absolute, non-symlinked parent")
    private_directory(binary.parent)
    if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("probe binary requires an explicit SHA-256")
    with admitted_file(binary, checksum, 16 * 1024 * 1024, 0o500) as (descriptor, initial):
        content = os.pread(descriptor, initial.st_size, 0)
        if len(content) != initial.st_size or hashlib.sha256(content).hexdigest() != checksum:
            raise ValueError("probe binary changed while copying")
        write_new(destination, content, 0o500)
    with admitted_file(destination, checksum, 16 * 1024 * 1024, 0o500):
        pass


def build_binary(archive, output, env, command, result):
    with admitted_file(archive, SOURCE_SHA256, SOURCE_LIMIT):
        extract_source(archive, output / "source", output / "source-normalized.tar")
    source = output / "source" / f"e2fsprogs-{VERSION}"
    compiler = command(["/usr/bin/xcrun", "--find", "clang"], output, env).strip()
    sdk = command(["/usr/bin/xcrun", "--show-sdk-path"], output, env).strip()
    env.update({"CC": compiler, "SDKROOT": sdk, "CFLAGS": "-O2 -g0"})
    result["compiler"] = command([compiler, "--version"], output, env)
    result["sdk_version"] = command(["/usr/bin/xcrun", "--show-sdk-version"], output, env).strip()
    result["macos"] = command(["/usr/bin/sw_vers"], output, env)
    command([str(source / "configure"), "--prefix=" + str(output / "bundle"),
             *CONFIGURE_ARGS], output / "build", env)
    config = output / "build" / "lib/config.h"
    make_config = output / "build" / "MCONFIG"
    validate_build_config(config.read_text(), make_config.read_text())
    result["config_h_sha256"] = developer_loop.digest(config)
    result["make_config_sha256"] = developer_loop.digest(make_config)
    command(["/usr/bin/make", "-j4", "libs"], output / "build", env)
    for directory, name in TOOLS:
        command(["/usr/bin/make", "-j4", "-C", directory, name], output / "build", env)
        binary = output / "bundle" / name
        shutil.copyfile(output / "build" / directory / name, binary)
        binary.chmod(0o500)
    for name in ("NOTICE", "lib/uuid/COPYING"):
        write_new(output / "bundle" / ("NOTICE" if name == "NOTICE" else "libuuid-COPYING"),
                  (source / name).read_bytes(), 0o400)


def run(archive, output, probe_binary=None, binary_sha=None):
    if (archive is None) == (probe_binary is None):
        raise ValueError("select exactly one source archive or probe binary")
    if (probe_binary is None) != (binary_sha is None):
        raise ValueError("binary SHA-256 is required only for probe-only mode")
    if probe_binary is not None and (not isinstance(binary_sha, str)
                                    or not re.fullmatch(r"[0-9a-f]{64}", binary_sha)):
        raise ValueError("probe binary requires an explicit SHA-256")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("this native developer discriminator requires an arm64 Mac")
    if not output.is_absolute() or output.parent.resolve() != output.parent:
        raise ValueError("output needs an absolute, non-symlinked parent")
    private_directory(output.parent)
    cancel = threading.Event()
    deadline = time.monotonic() + (120 if probe_binary else 600)
    commands = []
    output.mkdir(mode=0o700)
    for name in ("build", "bundle", "logs", "probe", "source", "tmp"):
        (output / name).mkdir(mode=0o700)
    result = {"schema_version": 1, "status": "running", "commands": commands,
              "scope": "native-empty-formatter-probe" if probe_binary else "native-empty-formatter-discriminator",
              "mode": "probe-only" if probe_binary else "build-and-probe",
              "tool_sha256": developer_loop.digest(Path(__file__)),
              "command_owner_sha256": developer_loop.digest(Path(developer_loop.__file__))}
    if probe_binary:
        result.update({"input_binary": str(probe_binary), "input_binary_sha256": binary_sha})
    else:
        result.update({"source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256, "version": VERSION})
    write_json(output / "request.json", result)
    write_new(output / "producer-source.py", Path(__file__).read_bytes(), 0o400)
    write_new(output / "command-owner-source.py", Path(developer_loop.__file__).read_bytes(), 0o400)
    old_handlers = {}
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        old_handlers[number] = signal.signal(number, lambda _number, _frame: cancel.set())

    def command(argv, cwd, env, seconds=300):
        log = output / "logs" / f"{len(commands):02d}.log"
        return run_checked(argv, cwd, env, log, cancel, deadline, commands, seconds)

    try:
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C",
               "TMPDIR": str(output / "tmp"), "ac_cv_lib_magic_magic_file": "no",
               "ac_cv_header_magic_h": "no"}
        binary = output / "bundle" / "mke2fs"
        if probe_binary:
            copy_probe_binary(probe_binary, binary_sha, binary)
            result["macos"] = command(["/usr/bin/sw_vers"], output, env)
        else:
            build_binary(archive, output, env, command, result)
        write_new(output / "bundle/mke2fs.conf", CONFIG, 0o400)
        # Probe mode keeps the supplied identity authoritative. Build mode binds
        # its output once, before any external validation, rather than blessing
        # whatever bytes happen to remain after those commands return.
        result["binary_sha256"] = binary_sha if probe_binary else developer_loop.digest(binary)
        tools = {"mke2fs": result["binary_sha256"]}
        if not probe_binary:
            tools.update({name: developer_loop.digest(output / "bundle" / name)
                          for _directory, name in TOOLS[1:]})
        result["tools"] = tools
        for name, checksum in tools.items():
            program = output / "bundle" / name
            with admitted_file(program, checksum, 16 * 1024 * 1024, 0o500):
                dependencies = command(["/usr/bin/otool", "-L", str(program)], output, env)
                validate_dependencies(dependencies)
                architecture = command(["/usr/bin/lipo", "-archs", str(program)], output, env).strip()
                if architecture != "arm64":
                    raise ValueError(f"{name} architecture mismatch")
                command(["/usr/bin/codesign", "--verify", "--strict", str(program)], output, env)
        result["dependencies"] = ["/usr/lib/libSystem.B.dylib"]
        result["configuration_sha256"] = CONFIG_SHA256
        result["images"] = [format_empty(output / "bundle", result["binary_sha256"],
                                         output / "probe", size, label, command)
                            for size, label in CASES]
        directory = os.open(output / "probe", os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        accept_result(result, cancel, deadline)
    except BaseException as error:
        result["status"] = "cleanup-unknown" if isinstance(error, developer_loop.CleanupUnknown) else "failed"
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        try:
            write_json(output / "result.json", result)
        finally:
            for number, handler in old_handlers.items():
                signal.signal(number, handler)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--source-archive", type=Path)
    source.add_argument("--probe-binary", type=Path,
                        help="already-built owned 0500 binary; no build/provenance claim")
    parser.add_argument("--binary-sha256", help="required explicit hash of --probe-binary")
    parser.add_argument("--output", required=True, type=Path,
                        help="new directory beneath an existing owned private directory")
    args = parser.parse_args()
    try:
        result = run(args.source_archive, args.output, args.probe_binary, args.binary_sha256)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"formatter discriminator failed: {error}; output retained", file=sys.stderr)
        return 1
    print(json.dumps({key: result[key] for key in ("status", "binary_sha256", "images")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
