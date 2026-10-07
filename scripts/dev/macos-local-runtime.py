#!/usr/bin/env python3
"""Install the macOS local VM runtime inputs for `cw env create --local`.

Developer tooling for an Apple Silicon Mac; it runs on the system Python 3.9.
It builds the Virtualization.framework helper in release mode, signs it ad hoc
with exactly developer-entitlements.plist, checks the supplied arm64 kernel
Image and Codewire guest root the way artifact admission does, and installs the
three files with the Darwin artifact lock that `cw` reads. Nothing is
downloaded. A different existing lock is replaced only with --replace, and a
Linux (Cloud Hypervisor) lock is never modified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import stat
import subprocess
import sys

PACKAGE = Path(__file__).resolve().parents[2] / "crates/codewire-local-vmm/macos-vz-runner"
ENTITLEMENTS = PACKAGE / "developer-entitlements.plist"
PRODUCT = "codewire-vz-runner"
SWIFT = "swift"
CODESIGN = "/usr/bin/codesign"
# The runtime looks only in Homebrew's keg-only e2fsprogs directories.
E2FSPROGS_DIRECTORIES = ("/opt/homebrew/opt/e2fsprogs/sbin", "/usr/local/opt/e2fsprogs/sbin")
E2FSPROGS_PROGRAMS = ("mkfs.ext4", "e2fsck", "resize2fs")
ROOT_ENV = "CODEWIRE_NATIVE_ARTIFACT_ROOT"
LOCK_ENV = "CODEWIRE_NATIVE_ARTIFACT_LOCK"
# Lock key, installed file name inside the artifact root, and exact mode.
ARTIFACTS = (("vz_runner", PRODUCT, 0o500), ("kernel", "kernel", 0o400),
             ("initramfs", "initramfs", 0o400))
INITRAMFS_LIMIT = 512 * 1024 * 1024
CHUNK = 1024 * 1024

# The canonical guest root written by codewire-vmm-guest-probe's newc.rs
# (canonical_guest_root_newc). The tests compare these with that source.
NEWC_MAGIC = b"070701"
DIRECTORY_MODE = 0o040755
INIT_MODE = 0o100755
SYMLINK_MODE = 0o120777
NULL_DEVICE_MODE = 0o020666
ARCHIVE_BLOCK = 512
TRAILER = b"TRAILER!!!\0"
CW_RUNTIME_PROVENANCE_ENTRY = b"codewire-cw/provenance.json"
BASIC_BUSYBOX_APPLETS = (
    "[", "awk", "basename", "cat", "chmod", "cp", "cut", "date", "dd", "dirname", "echo", "env",
    "expr", "false", "find", "grep", "head", "hostname", "id", "kill", "ln", "ls", "mkdir",
    "mktemp", "mv", "nproc", "printf", "ps", "pwd", "readlink", "rm", "rmdir", "sed",
    "sha256sum", "sh", "sleep", "sort", "stat", "stty", "sync", "tail", "tee", "test", "touch",
    "tr", "true", "tty", "uname", "wc", "which", "xargs",
)
ELF_MACHINE_AARCH64 = 183
GUEST_ROOT_HINT = ("build it on an x86_64 Linux host with scripts/ci/verify/build-local-vmm-initramfs.sh "
                   "--verify-root --target aarch64-unknown-linux-musl")


class InstallError(Exception):
    pass


def log(message: str) -> None:
    print("macos-local-runtime: " + message, flush=True)


def require_host() -> None:
    system, machine = platform.system(), platform.machine()
    if system != "Darwin" or machine != "arm64":
        raise InstallError("macOS local VMs need an Apple Silicon Mac (this host is %s %s)"
                           % (system, machine))


def require_e2fsprogs() -> None:
    for directory in E2FSPROGS_DIRECTORIES:
        if all(os.path.isfile(os.path.join(directory, program)) for program in E2FSPROGS_PROGRAMS):
            return
    raise InstallError("e2fsprogs is missing (cw needs mkfs.ext4, e2fsck and resize2fs from %s); "
                       "install it with: brew install e2fsprogs" % E2FSPROGS_DIRECTORIES[0])


def input_file(value: str, flag: str) -> Path:
    if not value:
        raise InstallError("%s is required: make macos-local-runtime KERNEL=/abs/Image "
                           "INITRAMFS=/abs/initramfs.cpio" % flag)
    path = Path(value)
    if not path.is_absolute():
        raise InstallError("%s must be an absolute path: %s" % (flag, value))
    try:
        status = os.stat(path)
    except FileNotFoundError:
        raise InstallError("%s does not exist: %s" % (flag, value)) from None
    if not stat.S_ISREG(status.st_mode) or status.st_size == 0:
        raise InstallError("%s must be a non-empty regular file: %s" % (flag, value))
    return path


def artifact_paths(environ) -> tuple:
    """The artifact root and lock exactly as cw resolves them."""

    def override(name):
        value = environ.get(name, "")
        if value and not os.path.isabs(value):
            raise InstallError("%s must be an absolute path" % name)
        return Path(value) if value else None

    root, lock = override(ROOT_ENV), override(LOCK_ENV)
    if root is None or lock is None:
        home = environ.get("HOME", "")
        if not home:
            raise InstallError("HOME is not set")
        parent = Path(home) / ".cache" / "codewire" / "local-vmm-v1"
        root = root or parent / "artifacts"
        lock = lock or parent / "artifacts.lock.json"
    if root.parent != lock.parent:
        raise InstallError("the artifact root and lock must share one parent directory (%s, %s)"
                           % (root, lock))
    for path in (root, lock):
        # cw opens these without following any symbolic link.
        existing = path
        while not os.path.lexists(existing):
            existing = existing.parent
        if os.path.normpath(str(path)) != str(path) or os.path.realpath(existing) != str(existing):
            raise InstallError("%s must be a canonical path without symbolic links (for example "
                               "/private/tmp rather than /tmp)" % path)
    return root, lock


def read_existing_lock(lock: Path):
    """None, or the decoded existing lock (unrecognized bytes decode to a string)."""
    try:
        status = os.lstat(lock)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(status.st_mode):
        raise InstallError("existing lock %s is not a regular file; it is left untouched" % lock)
    raw = lock.read_bytes()
    try:
        value = json.loads(raw)
    except ValueError:
        return raw.decode("utf-8", "replace")
    if isinstance(value, dict) and "cloud_hypervisor" in value:
        raise InstallError("%s is a Linux (Cloud Hypervisor) artifact lock and is left untouched, "
                           "even with --replace; set %s and %s to install the macOS runtime "
                           "elsewhere" % (lock, ROOT_ENV, LOCK_ENV))
    return value


def elf_header(data: bytes) -> bool:
    return (len(data) >= 20 and data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1
            and int.from_bytes(data[16:18], "little") in (2, 3)
            and int.from_bytes(data[18:20], "little") == ELF_MACHINE_AARCH64)


def static_elf(data: bytes) -> bool:
    """An aarch64 ELF without a program interpreter (PT_INTERP)."""
    if not elf_header(data) or len(data) < 64:
        return False
    offset = int.from_bytes(data[32:40], "little")
    entry_size = int.from_bytes(data[54:56], "little")
    count = int.from_bytes(data[56:58], "little")
    if count > 1024 or (count and entry_size < 56):
        return False
    for index in range(count):
        start = offset + index * entry_size
        kind = data[start:start + 4]
        if len(kind) != 4 or int.from_bytes(kind, "little") == 3:
            return False
    return True


def align4(value: int) -> int:
    return (value + 3) & ~3


def newc_entry(archive: bytes, expected: bytes):
    offset = 0
    while True:
        header = archive[offset:offset + 110]
        if len(header) != 110 or header[:6] != NEWC_MAGIC:
            return None
        try:
            file_size, name_size = int(header[54:62], 16), int(header[94:102], 16)
        except ValueError:
            return None
        name_end = offset + 110 + name_size
        data_start = align4(name_end)
        data_end = data_start + file_size
        if name_size == 0 or data_end > len(archive):
            return None
        name = archive[offset + 110:name_end]
        if name[-1:] == b"\0" and name[:-1] == expected:
            return archive[data_start:data_end]
        if name == TRAILER:
            return None
        offset = align4(data_end)


def newc_append(archive: bytearray, inode: int, mode: int, name: bytes, contents: bytes = b"",
                rdev: tuple = (0, 0)) -> None:
    archive += NEWC_MAGIC
    for value in (inode, mode, 0, 0, 1, 0, len(contents), 0, 0, rdev[0], rdev[1], len(name), 0):
        archive += b"%08x" % value
    archive += name
    archive += bytes(-len(archive) % 4)
    archive += contents
    archive += bytes(-len(archive) % 4)


def canonical_guest_root(init: bytes, busybox: bytes, runc: bytes) -> bytes:
    archive = bytearray()
    newc_append(archive, 1, DIRECTORY_MODE, b"dev\0")
    newc_append(archive, 2, NULL_DEVICE_MODE, b"dev/null\0", rdev=(1, 3))
    entries = [(DIRECTORY_MODE, "bin", b""), (DIRECTORY_MODE, "sbin", b""),
               (DIRECTORY_MODE, "run", b""), (INIT_MODE, "init", init),
               (INIT_MODE, "bin/busybox", busybox), (INIT_MODE, "sbin/runc", runc)]
    entries += [(SYMLINK_MODE, "bin/" + applet, b"busybox") for applet in BASIC_BUSYBOX_APPLETS]
    for inode, (mode, name, contents) in enumerate(entries, start=3):
        newc_append(archive, inode, mode, name.encode() + b"\0", contents)
    newc_append(archive, 0, 0, TRAILER)
    archive += bytes(-len(archive) % ARCHIVE_BLOCK)
    return bytes(archive)


def check_kernel(path: Path) -> None:
    with path.open("rb") as stream:
        header = stream.read(0x40)
    if header[0x38:0x3C] != b"ARM\x64":
        raise InstallError("%s is not an uncompressed arm64 Linux kernel Image (no ARM\\x64 "
                           "header magic); build it with scripts/ci/verify/build-linux-vmm-kernel.py "
                           "--arch arm64" % path)


def check_initramfs(path: Path) -> None:
    """Mirror artifact admission for an aarch64 guest root."""
    if os.stat(path).st_size > INITRAMFS_LIMIT:
        raise InstallError("%s exceeds the 512 MiB guest root limit" % path)
    data = path.read_bytes()
    init = newc_entry(data, b"init")
    busybox, runc = newc_entry(data, b"bin/busybox"), newc_entry(data, b"sbin/runc")
    if newc_entry(data, CW_RUNTIME_PROVENANCE_ENTRY) is not None:
        reason = "it embeds a cw runtime, which only x86_64 guest roots may carry"
    elif init is None or not elf_header(init):
        reason = "it has no arm64 /init"
    elif busybox is None or runc is None or not (static_elf(busybox) and static_elf(runc)):
        reason = "it lacks static arm64 /bin/busybox and /sbin/runc"
    elif canonical_guest_root(init, busybox, runc) != data:
        reason = "it is not the exact canonical archive"
    else:
        return
    raise InstallError("%s is not an arm64 Codewire guest root: %s; %s" % (path, reason, GUEST_ROOT_HINT))


def check_helper(path: Path) -> None:
    """A thin arm64 Mach-O executable signed with exactly the developer entitlements."""
    with path.open("rb") as stream:
        header = stream.read(16)
    words = [int.from_bytes(header[index:index + 4], "little") for index in range(0, 16, 4)]
    if len(header) != 16 or words[0] != 0xFEEDFACF or words[1] != 0x0100000C or words[3] != 2:
        raise InstallError("%s is not a thin arm64 Mach-O executable" % path)
    shown = run([CODESIGN, "-d", "--entitlements", "-", "--xml", str(path)], capture=True)
    start = shown.find(b"<?xml")
    try:
        signed = plistlib.loads(shown[start:]) if start >= 0 else None
    except Exception:
        signed = None
    if signed != plistlib.loads(ENTITLEMENTS.read_bytes()):
        raise InstallError("the signed helper does not carry exactly %s" % ENTITLEMENTS.name)


def run(argv: list, capture: bool = False) -> bytes:
    """Run a tool; a captured query also keeps its stderr chatter quiet."""
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE if capture else None,
                                stderr=subprocess.DEVNULL if capture else None, check=False)
    except FileNotFoundError:
        raise InstallError("%s is unavailable; install the Xcode Command Line Tools "
                           "(xcode-select --install)" % argv[0]) from None
    if result.returncode != 0:
        raise InstallError("command exited %d: %s" % (result.returncode, " ".join(argv)))
    return result.stdout or b""


def build_helper() -> Path:
    command = [SWIFT, "build", "-c", "release", "--package-path", str(PACKAGE)]
    log("building the VZ helper: " + " ".join(command))
    run(command)
    binary = Path(run([*command, "--show-bin-path"], capture=True).decode().strip()) / PRODUCT
    if not binary.is_file():
        raise InstallError("swift build produced no %s" % binary)
    return binary


def private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    status = os.lstat(path)
    if (not stat.S_ISDIR(status.st_mode) or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) != 0o700):
        raise InstallError("%s must be a directory you own with mode 0700 (chmod 700 %s)"
                           % (path, path))


def stage_copy(source: Path, staged: Path) -> None:
    with source.open("rb") as reader:
        descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as writer:
            for chunk in iter(lambda: reader.read(CHUNK), b""):
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())


def identity(path: Path) -> tuple:
    checksum, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            checksum.update(chunk)
            size += len(chunk)
    return checksum.hexdigest(), size


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def unlink_if_present(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def install(kernel: Path, initramfs: Path, replace: bool, environ) -> int:
    require_host()
    require_e2fsprogs()
    root, lock = artifact_paths(environ)
    existing = read_existing_lock(lock)
    check_kernel(kernel)
    check_initramfs(initramfs)
    helper = build_helper()

    private_directory(lock.parent)
    private_directory(root)
    sources = {"vz_runner": helper, "kernel": kernel, "initramfs": initramfs}
    staged = {key: root / (".%s.partial" % name) for key, name, _ in ARTIFACTS}
    lock_staged = lock.parent / (".%s.partial" % lock.name)
    try:
        new_lock = {"schema_version": 1}
        for key, name, mode in ARTIFACTS:
            unlink_if_present(staged[key])
            stage_copy(sources[key], staged[key])
            if key == "vz_runner":
                # A fixed identifier keeps the signed bytes independent of the
                # staging name, so an unchanged rebuild pins the same digest.
                run([CODESIGN, "--force", "--sign", "-", "--identifier", PRODUCT,
                     "--entitlements", str(ENTITLEMENTS), str(staged[key])])
                check_helper(staged[key])
            elif key == "kernel":
                check_kernel(staged[key])
            else:
                check_initramfs(staged[key])
            os.chmod(staged[key], mode)
            sha256, size = identity(staged[key])
            new_lock[key] = {"path": name, "size": size, "sha256": sha256, "architecture": "aarch64"}
        if existing is not None and existing != new_lock and not replace:
            raise InstallError("%s already pins different artifacts; rerun with --replace "
                               "(make macos-local-runtime ... REPLACE=1) to replace them" % lock)

        for key, name, _ in ARTIFACTS:
            os.replace(staged[key], root / name)
        sync_directory(root)
        unlink_if_present(lock_staged)
        descriptor = os.open(lock_staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as writer:
            writer.write(json.dumps(new_lock, indent=2) + "\n")
            writer.flush()
            os.fsync(writer.fileno())
        os.chmod(lock_staged, 0o400)
        os.replace(lock_staged, lock)
        sync_directory(lock.parent)
    finally:
        for path in (*staged.values(), lock_staged):
            unlink_if_present(path)

    state = "unchanged" if existing == new_lock else ("replaced" if existing is not None else "written")
    log("lock %s %s" % (lock, state))
    for key, name, _ in ARTIFACTS:
        log("%-9s %s sha256=%s size=%d" % (key, root / name, new_lock[key]["sha256"],
                                           new_lock[key]["size"]))
    return 0


def main(argv=None, environ=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--kernel", default="", help="absolute path to the arm64 Linux kernel Image")
    parser.add_argument("--initramfs", default="", help="absolute path to the arm64 guest root")
    parser.add_argument("--replace", action="store_true", help="replace a different existing macOS lock")
    args = parser.parse_args(argv)
    try:
        kernel = input_file(args.kernel, "KERNEL")
        initramfs = input_file(args.initramfs, "INITRAMFS")
        return install(kernel, initramfs, args.replace, os.environ if environ is None else environ)
    except (InstallError, OSError) as error:
        print("macos-local-runtime: ERROR: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
