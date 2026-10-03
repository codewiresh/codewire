#!/usr/bin/env python3
"""Build the pinned, patched Linux VMM kernel without acquiring or installing it.

The baseline configuration came from the qualified codewire1 build. Its sole
configuration change is PROC_CHILDREN, required by managed-agent custody.
Recorded build metadata is reconstructed; this command does not claim to
reproduce the original kernel or verify its historical signing transaction.
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


def configuration(raw, pins):
    require(hashlib.sha256(raw).hexdigest() == pins["config_sha256"], "kernel config differs from its pin")
    before = raw.replace(b"CONFIG_PROC_CHILDREN=y\n", b"# CONFIG_PROC_CHILDREN is not set\n")
    require(raw.count(b"CONFIG_PROC_CHILDREN=y\n") == 1
            and hashlib.sha256(before).hexdigest() == pins["baseline_config_sha256"],
            "kernel config has more than the admitted child-listing change")
    require(b"CONFIG_PROC_FS=y\n" in raw and b"# CONFIG_CHECKPOINT_RESTORE is not set\n" in raw,
            "kernel process-listing prerequisites differ")
    return before


def arm_custody():
    require(sys.platform == "linux" and hasattr(os, "pidfd_open")
            and hasattr(signal, "pidfd_send_signal"), "Linux pidfd custody is required")
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(36, 1, 0, 0, 0) == 0, "cannot enable build-family subreaper")
    active = ctypes.c_int()
    require(libc.prctl(37, ctypes.byref(active), 0, 0, 0) == 0 and active.value == 1,
            "build-family subreaper was not enabled")
    Path("/proc/thread-self/children").read_text()
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT | WALL)
    except ChildProcessError:
        return
    raise ValueError("the kernel producer must begin without existing children")


def children():
    result = set()
    for task in Path("/proc/self/task").iterdir():
        try:
            result.update(int(pid) for pid in (task / "children").read_text().split())
        except FileNotFoundError:
            continue
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
    pins = json.loads(regular(INPUTS / "provenance.json"))
    config = regular(INPUTS / "x86_64.config")
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
    require(query(["git", "rev-parse", pins["source_commit"] + "^{tree}"]) == pins["source_tree"],
            "kernel source commit/tree does not match")
    require(query(["gcc", "--version"]).splitlines()[0] == pins["gcc_version"], "kernel GCC differs")
    require(query(["ld", "--version"]).splitlines()[0] == pins["ld_version"], "kernel linker differs")
    admitted = {"source_commit": pins["source_commit"], "source_tree": pins["source_tree"],
                "config_sha256": digest(INPUTS / "x86_64.config"), "patch_sha256": digest(INPUTS / "dax.patch"),
                "release": pins["release"], "bc_sha256": pins["bc_sha256"]}
    input_paths = [Path(__file__).resolve(), INPUTS / "x86_64.config", INPUTS / "dax.patch", INPUTS / "provenance.json"]
    producer_inputs = {str(p.relative_to(INPUTS.parent)): digest(p) for p in input_paths}
    tool_identities = {}
    for name in ("git", "gcc", "ld", "as", "ar", "nm", "objcopy", "objdump", "make", "patch"):
        executable = Path(shutil.which(name, path="/usr/bin:/bin")).resolve(strict=True)
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
    environment["HOME"] = str(home)
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
    # The qualified config predates the host's optional pahole installation.
    # Keep its detected version0; BTF is disabled in the pinned baseline.
    make = ["make", "ARCH=x86_64", "LOCALVERSION=-codewire2", "PAHOLE="]
    run([*make, "olddefconfig"], "configure", tree)
    require(regular(tree / ".config") == config, "processed kernel config drifted")
    run([*make, "-j" + str(args.jobs), "bzImage"], "compile", tree)
    require(regular(tree / ".config") == config, "compiled kernel config drifted")
    require(regular(tree / "include/config/kernel.release").decode().strip() == pins["release"], "kernel release differs")
    kernel = tree / "arch/x86/boot/bzImage"
    raw = regular(kernel, 64 * 1024 * 1024)
    require(pins["release"].encode() in raw[:65536], "kernel header does not contain its release")
    require(STOP is None and time.monotonic() < deadline, "kernel publication cancelled or expired")
    published = target / ("vmlinuz-" + pins["release"])
    with published.open("xb") as output:
        output.write(raw)
    published.chmod(0o400)
    result = {"schema": "codewire.linux-vmm-kernel-build/v1", "status": "passed", "proof": "kernel-source-build",
              **admitted, "source_archive_sha256": digest(archive, 2 * 1024 * 1024 * 1024), "source_archive_size": archive.stat().st_size,
              "producer_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=INPUTS, text=True).strip(),
              "producer_inputs": producer_inputs, "tools": tool_identities,
              "build_settings": {"origin": "reconstructed-recorded-metadata", "baseline_reproduction": False,
                                 "user": "codewire", "host": "codewire", "version": 1, "timestamp": pins["build_timestamp"],
                                 "gcc": pins["gcc_version"], "ld": pins["ld_version"], "jobs": args.jobs,
                                 "pahole": "PAHOLE=: preserve baseline CONFIG_PAHOLE_VERSION=0"},
              "kernel": {"path": str(published), "sha256": digest(published, 64 * 1024 * 1024), "size": len(raw), "architecture": "x86_64"},
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
