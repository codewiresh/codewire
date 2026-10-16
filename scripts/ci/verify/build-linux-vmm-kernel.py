#!/usr/bin/env python3
"""Build the pinned, patched Linux VMM kernel without acquiring or installing it.

Each architecture's baseline configuration came from its qualified codewire1
build: x86_64 for Cloud Hypervisor, arm64 for Virtualization.framework. The
sole configuration change is PROC_CHILDREN, required by managed-agent custody.
Both architectures share the pinned source, DAX compatibility patch, bc and
build identity. Recorded build metadata is reconstructed; this command does not
claim to reproduce the original kernel or verify its historical signing
transaction.
"""
import argparse
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time

INPUTS = Path(__file__).resolve().with_name("linux-vmm-kernel")
STOP = None
WALL = 0x40000000
HOST_TOOLS = ("git", "gcc", "ld", "as", "ar", "nm", "objcopy", "objdump", "make", "patch")
TARGET_TOOLS = ("gcc", "ld", "as", "ar", "nm", "objcopy", "objdump")
# Build shape per architecture; pinned identities live in provenance.json.
ARCHITECTURES = {
    "x86_64": {"config": "x86_64.config", "make": ("ARCH=x86_64",), "prefix": "",
               "target": "bzImage", "image": "arch/x86/boot/bzImage", "published": "vmlinuz-"},
    "arm64": {"config": "arm64.config", "make": ("ARCH=arm64", "CROSS_COMPILE=aarch64-linux-gnu-"),
              "prefix": "aarch64-linux-gnu-", "target": "Image", "image": "arch/arm64/boot/Image",
              "published": "Image-"},
}


def require(value, message):
    if not value:
        raise ValueError(message)


def stamp(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def read_input(path, maximum, allow_empty=False, collect=False, system_tool=False):
    """Keep a bounded regular input open through its final path/FD checks."""
    path = Path(path)
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        links_admitted = metadata.st_nlink == 1 or (system_tool and metadata.st_nlink > 0)
        require(not system_tool or (metadata.st_uid == 0 and not metadata.st_mode & 0o022),
                "kernel build tool is not a trusted system executable")
        require(stamp(before) == stamp(metadata) and stat.S_ISREG(metadata.st_mode)
                and links_admitted and (allow_empty or metadata.st_size > 0)
                and metadata.st_size <= maximum, "invalid bounded input file")
        result = bytearray() if collect else hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - size))
            if not block:
                break
            size += len(block)
            require(size <= maximum, "input exceeds its admitted bound")
            if collect:
                result.extend(block)
            else:
                result.update(block)
        require(size == metadata.st_size and stamp(os.fstat(descriptor)) == stamp(metadata)
                and stamp(path.lstat()) == stamp(metadata), "input changed during its held read")
        return bytes(result) if collect else result.hexdigest()
    finally:
        os.close(descriptor)


def regular(path, maximum=1024 * 1024):
    return read_input(path, maximum, collect=True)


def digest(path, maximum=1024 * 1024, allow_empty=False):
    return read_input(path, maximum, allow_empty=allow_empty)


def tool_digest(path):
    # Distribution-managed gcc/ld aliases may share a root-owned inode.
    return read_input(path, 64 * 1024 * 1024, system_tool=True)


def admit_output(target):
    require(target.is_absolute() and target.parent.resolve(strict=True) == target.parent
            and not os.path.lexists(target), "output must be a fresh canonical path")
    parent = target.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
            and not parent.st_mode & 0o022, "output parent must be owned and not foreign-writable")


def private_directory(path):
    path.mkdir(mode=0o700)
    metadata = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700,
            "created output directory lost private ownership")


def architecture_pins(document, architecture):
    """Shared source/build pins plus exactly one architecture's config and toolchain pins."""
    shared = {key: value for key, value in document.items() if key != "architectures"}
    require(set(document["architectures"]) == set(ARCHITECTURES)
            and architecture in ARCHITECTURES, "kernel architecture pins differ")
    specific = document["architectures"][architecture]
    require(not set(shared) & set(specific), "architecture pins shadow shared kernel pins")
    return {**shared, **specific, "architecture": architecture}


def configuration(raw, pins):
    require(hashlib.sha256(raw).hexdigest() == pins["config_sha256"], "kernel config differs from its pin")
    before = raw.replace(b"CONFIG_PROC_CHILDREN=y\n", b"# CONFIG_PROC_CHILDREN is not set\n")
    require(raw.count(b"CONFIG_PROC_CHILDREN=y\n") == 1
            and hashlib.sha256(before).hexdigest() == pins["baseline_config_sha256"],
            "kernel config has more than the admitted child-listing change")
    require(b"CONFIG_PROC_FS=y\n" in raw and b"# CONFIG_CHECKPOINT_RESTORE is not set\n" in raw,
            "kernel process-listing prerequisites differ")
    # pahole only reports its version to Kconfig: no BTF is generated.
    pahole = pins["pahole_version"]
    detected = 0 if pahole is None else int(pahole.removeprefix("v").replace(".", ""))
    require(b"CONFIG_DEBUG_INFO_NONE=y\n" in raw
            and raw.count(b"CONFIG_PAHOLE_VERSION=%d\n" % detected) == 1,
            "kernel config pahole detection differs from its pinned tool")
    return before


def check_image(raw, pins):
    release = pins["release"].encode()
    if pins["architecture"] == "x86_64":
        require(release in raw[:65536], "kernel header does not contain its release")
    else:
        # arm64 Image: header magic at 0x38; the uncompressed banner names the release.
        require(raw[0x38:0x3c] == b"ARM\x64" and b"Linux version " + release + b" " in raw,
                "arm64 kernel image header or release banner differs")


def arm_custody():
    require(sys.platform == "linux" and hasattr(os, "pidfd_open")
            and hasattr(signal, "pidfd_send_signal"), "Linux pidfd custody is required")
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(36, 1, 0, 0, 0) == 0, "cannot enable build-family subreaper")
    active = ctypes.c_int()
    require(libc.prctl(37, ctypes.byref(active), 0, 0, 0) == 0 and active.value == 1,
            "build-family subreaper was not enabled")
    # children() scans /proc, so /proc must be this PID namespace's.
    require(os.readlink("/proc/self") == str(os.getpid()), "/proc does not show this process")
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT | WALL)
    except ChildProcessError:
        return
    raise ValueError("the kernel producer must begin without existing children")


def children():
    """Every process whose parent is this one. Scanning /proc works on every
    Linux kernel; the per-task children file needs CONFIG_PROC_CHILDREN,
    which a Kata guest kernel lacks."""
    me = os.getpid()
    result = set()
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            stat = Path(f"/proc/{entry.name}/stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if int(stat.rsplit(") ", 1)[1].split()[1]) == me:
            result.add(int(entry.name))
    return result


def child_stat(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    require(int(fields[1]) == os.getpid(), "build process is not an owned child")
    return fields[19]


def bind_child(pid):
    birth = child_stat(pid)
    descriptor = os.pidfd_open(pid)
    try:
        require(child_stat(pid) == birth, "build process birth changed")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def send(descriptor, sig):
    try:
        signal.pidfd_send_signal(descriptor, sig)
    except ProcessLookupError:
        pass


def abort_family(process, adopted, bound=30):
    """Error cleanup preserves the leader until the last group signal."""
    if process.returncode is None:
        # Only this owner reaps the leader. Confirm it is still a child before
        # using its reserved process-group identity, including bind failures.
        os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + bound
    while True:
        require(time.monotonic() < deadline, "build-family error cleanup remains unknown")
        for pid in children():
            if pid not in adopted:
                adopted[pid] = bind_child(pid)
            send(adopted[pid], signal.SIGKILL)
        try:
            pid, status = os.waitpid(-1, os.WNOHANG | WALL)
        except ChildProcessError:
            return
        if pid:
            if pid == process.pid:
                process.returncode = os.waitstatus_to_exitcode(status)
            if pid in adopted:
                os.close(adopted.pop(pid))
        else:
            time.sleep(0.05)


def run_owned(command, cwd, environment, log, deadline, grace=3, cleanup_bound=30):
    """Reserve the leader through group cleanup; join adopted children to ECHILD."""
    began = time.monotonic()
    adopted = {}
    timed_out = interrupted = unexpected_family = False
    with Path(log).open("xb") as output:
        process = subprocess.Popen(command, cwd=cwd, env=environment,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        leader = None
        try:
            leader = bind_child(process.pid)
            # WNOWAIT holds the group leader's PID until all numeric group signals
            # are finished. The producer alone owns the final reap.
            while not os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                if STOP is not None or time.monotonic() >= deadline:
                    interrupted = STOP is not None
                    timed_out = not interrupted
                    break
                time.sleep(0.05)
            cleanup_started = time.monotonic()
            killed = False
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            while True:
                require(time.monotonic() - cleanup_started < cleanup_bound,
                        "build-family cleanup is unknown; retained artifacts are not accepted")
                for pid in children() - {process.pid}:
                    if pid not in adopted:
                        adopted[pid] = bind_child(pid)
                        unexpected_family = unexpected_family or not (timed_out or interrupted)
                        send(adopted[pid], signal.SIGKILL if killed else signal.SIGTERM)
                for pid, descriptor in list(adopted.items()):
                    waited, _ = os.waitpid(pid, os.WNOHANG | WALL)
                    if waited:
                        os.close(descriptor)
                        del adopted[pid]
                terminal = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if not killed and (time.monotonic() - cleanup_started >= grace or (terminal and not adopted)):
                    # The unreaped leader still reserves the group identity.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    killed = True
                    for descriptor in adopted.values():
                        send(descriptor, signal.SIGKILL)
                if killed and terminal and not adopted and children() == {process.pid}:
                    break
                time.sleep(0.05)
            exit_code = process.wait()
            # No more numeric group signals after the final reap. A detached
            # orphan still in flight prevents ECHILD and therefore publication.
            try:
                os.waitpid(-1, os.WNOHANG | WALL)
            except ChildProcessError:
                pass
            else:
                raise ValueError("build-family completion did not prove ECHILD")
        finally:
            abort_family(process, adopted, cleanup_bound)
            if leader is not None:
                os.close(leader)
            for descriptor in adopted.values():
                os.close(descriptor)
    result = {"command": command, "exit": exit_code, "elapsed_seconds": round(time.monotonic() - began, 3),
              "log": str(log), "log_sha256": digest(log, 256 * 1024 * 1024, allow_empty=True), "timed_out": timed_out,
              "interrupted": interrupted, "unexpected_family": unexpected_family, "cleanup_unknown": False}
    require(exit_code == 0 and not (timed_out or interrupted or unexpected_family),
            "kernel command failed after owned-family cleanup: " + json.dumps(result))
    return result


def on_signal(sig, _frame):
    global STOP
    STOP = sig


def build(args):
    shape = ARCHITECTURES[args.arch]
    pins = architecture_pins(json.loads(regular(INPUTS / "provenance.json")), args.arch)
    config_path = INPUTS / shape["config"]
    config = regular(config_path)
    configuration(config, pins)
    patch = regular(INPUTS / "dax.patch")
    require(hashlib.sha256(patch).hexdigest() == pins["patch_sha256"], "kernel compatibility patch changed")
    source = args.source
    require(source.is_absolute() and source.resolve(strict=True) == source and source.is_dir(),
            "kernel source must be an existing canonical directory")
    bc = args.bc
    require(bc.is_absolute() and bc.resolve(strict=True) == bc, "bc must be canonical")
    bc_raw = regular(bc, 2 * 1024 * 1024)
    require(hashlib.sha256(bc_raw).hexdigest() == pins["bc_sha256"], "bc differs from its pin")
    target = args.output
    admit_output(target)
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC",
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    def query(command):
        return subprocess.check_output(command, cwd=source, env=environment, text=True, timeout=15).strip()
    def system_tool(name):
        found = shutil.which(name, path="/usr/bin:/bin")
        require(found, "kernel build tool is missing: " + name)
        return Path(found).resolve(strict=True)
    require(query(["git", "rev-parse", pins["source_commit"] + "^{tree}"]) == pins["source_tree"],
            "kernel source commit/tree does not match")
    prefix = shape["prefix"]
    require(query([prefix + "gcc", "--version"]).splitlines()[0] == pins["gcc_version"], "kernel GCC differs")
    require(query([prefix + "ld", "--version"]).splitlines()[0] == pins["ld_version"], "kernel linker differs")
    names = [*HOST_TOOLS, *(prefix + name for name in TARGET_TOOLS if prefix)]
    if pins["pahole_version"] is None:
        # The qualified x86_64 config predates the host's optional pahole
        # installation. Keep its detected version 0; BTF is disabled.
        pahole_setting = "PAHOLE="
        pahole_note = "PAHOLE=: preserve baseline CONFIG_PAHOLE_VERSION=0"
    else:
        # The qualified arm64 config detected pahole; BTF is still disabled,
        # so pahole only reports the version that Kconfig records.
        pahole = system_tool("pahole")
        require(query([str(pahole), "--version"]) == pins["pahole_version"], "kernel pahole differs")
        names.append("pahole")
        pahole_setting = "PAHOLE=" + str(pahole)
        pahole_note = pahole_setting + " " + pins["pahole_version"] + ": preserve baseline CONFIG_PAHOLE_VERSION; BTF disabled"
    admitted = {"architecture": args.arch, "source_commit": pins["source_commit"], "source_tree": pins["source_tree"],
                "config_sha256": digest(config_path), "patch_sha256": digest(INPUTS / "dax.patch"),
                "release": pins["release"], "bc_sha256": pins["bc_sha256"]}
    input_paths = [Path(__file__).resolve(), config_path, INPUTS / "dax.patch", INPUTS / "provenance.json"]
    producer_inputs = {str(p.relative_to(INPUTS.parent)): digest(p) for p in input_paths}
    tool_identities = {}
    for name in names:
        executable = system_tool(name)
        metadata = executable.stat()
        require(metadata.st_uid == 0 and stat.S_ISREG(metadata.st_mode) and not metadata.st_mode & 0o022,
                "kernel build tool is not a trusted system executable")
        tool_identities[name] = {"path": str(executable), "sha256": tool_digest(executable), "size": metadata.st_size}
    if args.admit_only:
        return {"status": "admitted", "proof": "kernel-build-inputs-only", **admitted}
    arm_custody()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, on_signal)
    private_directory(target)
    home = target / "home"; private_directory(home)
    scratch = target / "tmp"; private_directory(scratch)
    environment.update({"HOME": str(home), "TMPDIR": str(scratch)})
    deadline = time.monotonic() + args.timeout
    commands = []
    def run(argv, name, cwd=source):
        require(STOP is None and time.monotonic() < deadline, "kernel build cancelled or expired")
        result = run_owned(argv, cwd, environment, target / (name + ".log"), deadline)
        commands.append(result)
        print("[linux-vmm-kernel] " + name + " completed", flush=True)
    archive = target / "source.tar"
    run(["git", "archive", "--format=tar", "--output=" + str(archive), pins["source_commit"]], "archive")
    tree = target / "source"; private_directory(tree)
    with tarfile.open(archive) as tar:
        tar.extractall(tree, filter="data")
    # Kata applies this fs/dax.c fix to every 6.18 guest kernel. The upstream
    # report is an arm64 boot panic; both qualified codewire1 builds carried it.
    run(["patch", "--fuzz=0", "-p1", "--input=" + str(INPUTS / "dax.patch")], "patch", tree)
    require(digest(tree / "fs/dax.c") == pins["patched_dax_sha256"], "patched kernel source differs")
    (tree / ".config").write_bytes(config)
    tools = target / "tools"; private_directory(tools)
    with (tools / "bc").open("xb") as output:
        output.write(bc_raw)
    (tools / "bc").chmod(0o500)
    require(digest(tools / "bc", 2 * 1024 * 1024) == pins["bc_sha256"], "staged bc differs")
    environment.update({"PATH": str(tools) + ":/usr/bin:/bin", "KBUILD_BUILD_USER": "codewire",
                        "KBUILD_BUILD_HOST": "codewire", "KBUILD_BUILD_VERSION": "1",
                        "KBUILD_BUILD_TIMESTAMP": pins["build_timestamp"]})
    make = ["make", *shape["make"], "LOCALVERSION=-codewire2", pahole_setting]
    run([*make, "olddefconfig"], "configure", tree)
    require(regular(tree / ".config") == config, "processed kernel config drifted")
    run([*make, "-j" + str(args.jobs), shape["target"]], "compile", tree)
    require(regular(tree / ".config") == config, "compiled kernel config drifted")
    require(regular(tree / "include/config/kernel.release").decode().strip() == pins["release"], "kernel release differs")
    raw = regular(tree / shape["image"], 64 * 1024 * 1024)
    check_image(raw, pins)
    require(STOP is None and time.monotonic() < deadline, "kernel publication cancelled or expired")
    published = target / (shape["published"] + pins["release"])
    with published.open("xb") as output:
        output.write(raw)
    published.chmod(0o400)
    result = {"schema": "codewire.linux-vmm-kernel-build/v1", "status": "passed", "proof": "kernel-source-build",
              **admitted, "source_archive_sha256": digest(archive, 2 * 1024 * 1024 * 1024), "source_archive_size": archive.stat().st_size,
              "producer_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=INPUTS, text=True).strip(),
              "producer_inputs": producer_inputs, "tools": tool_identities,
              "build_settings": {"origin": "reconstructed-recorded-metadata", "baseline_reproduction": False,
                                 "user": "codewire", "host": "codewire", "version": 1, "timestamp": pins["build_timestamp"],
                                 "make": make[1:], "gcc": pins["gcc_version"], "ld": pins["ld_version"], "jobs": args.jobs,
                                 "pahole": pahole_note},
              "kernel": {"path": str(published), "sha256": digest(published, 64 * 1024 * 1024), "size": len(raw), "architecture": args.arch},
              "commands": commands, "cleanup_unknown": False, "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    require(producer_inputs == {str(p.relative_to(INPUTS.parent)): digest(p) for p in input_paths},
            "kernel producer inputs changed during the build")
    for identity in tool_identities.values():
        require(tool_digest(identity["path"]) == identity["sha256"], "kernel build tool changed")
    require(STOP is None and time.monotonic() < deadline, "kernel receipt cancelled or expired")
    result["source_unchanged"] = True
    with (target / "build.json").open("x") as output:
        json.dump(result, output, indent=2); output.write("\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=sorted(ARCHITECTURES), default="x86_64",
                        help="guest architecture: x86_64 bzImage or arm64 Image (cross-compiled)")
    parser.add_argument("--source", type=Path, required=True, help="existing pinned upstream Linux Git repository")
    parser.add_argument("--bc", type=Path, required=True, help="pinned static BusyBox executable, invoked as bc")
    parser.add_argument("--output", type=Path, required=True, help="fresh private build directory; never an installed kernel path")
    parser.add_argument("--jobs", type=int, choices=range(1, 9), default=4)
    parser.add_argument("--timeout", type=int, choices=range(1, 3601), default=3300)
    parser.add_argument("--admit-only", action="store_true", help="read-only admission; no build or output creation")
    args = parser.parse_args()
    try:
        print(json.dumps(build(args)))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("linux VMM kernel: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
