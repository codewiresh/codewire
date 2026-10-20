#!/usr/bin/env python3
"""One fixed musl compiler operation and durable full-record runtime export.

This runs only in the cw-builder RUN. The source/Git request is admitted before
Cargo; Cargo gets no Git-directory/config override. Original target/dep-info
remain available until shared admit_build completes. The incoming executable
is never executed. Failed compilation/admission cannot emit producer.json.
"""

import argparse
import errno
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[3]
previous_bytecode = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    spec = importlib.util.spec_from_file_location("cw_runtime_source_context", ROOT / "scripts/ci/images/prepare-cw-source-context.py")
    source = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(source)
    spec = importlib.util.spec_from_file_location("cw_runtime_source_owner", ROOT / "scripts/ci/verify/build-linux-vmm-kernel.py")
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
finally:
    sys.dont_write_bytecode = previous_bytecode
del previous_bytecode
release = source.release

SCHEMA = "codewire.cw.runtime-source-producer/v1"
SOURCE_ROOT = Path("/src")
GIT_ROOT = Path("/source-git")
REQUEST = Path("/run/cw-source-request.json")
TARGET_ROOT = Path("/tmp/cargo-target")
CARGO_HOME = Path("/usr/local/cargo")
WORK = Path("/out")
PROFILES = {"ci": ("--profile", "ci"), "release": ("--release",), "runtime": ("--profile", "runtime")}
# Every image producer, Kind's and the workspace verification's included,
# builds runtime, the one image profile; a cw release producer builds release.
# Every producer owns its worker and sizes its jobs to it; the chosen count is
# part of the recorded command.
MAX_JOBS = 16
GIB_PER_JOB = 3


def machine():
    """Visible CPUs and whole GiB of memory (the smaller of the host total and a cgroup limit)."""
    cpus = len(os.sched_getaffinity(0))
    limits = []
    try:
        with open("/proc/meminfo", encoding="ascii") as meminfo:
            for line in meminfo:
                if line.startswith("MemTotal:"):
                    limits.append(int(line.split()[1]) * 1024)
        with open("/sys/fs/cgroup/memory.max", encoding="ascii") as cgroup:
            value = cgroup.read().strip()
            if value.isdigit():
                limits.append(int(value))
    except (OSError, ValueError):
        pass
    return cpus, min(limits) // (1 << 30) if limits else 0


def cargo_jobs():
    """Parallel rustc jobs sized to what this build can use.

    The protected runners range from a cloud slot to a bare-metal slot, so a fixed
    count either idles the metal slot or risks running the cloud slot out of
    memory. Jobs are bounded by visible CPUs and by one job per GIB_PER_JOB of
    memory, and never exceed MAX_JOBS. The count does not change the output.

    A metal slot is a Kata VM, so this sees the VM's own CPUs and memory (16 jobs).
    A cloud slot is not: this sees the 8 vCPU / 15 GiB host, while the DinD
    container around the build is held to 13 GiB in a cgroup it cannot see. Three
    GiB per job (5 jobs) keeps a cold build inside that limit.
    CODEWIRE_CARGO_JOBS (1-32) overrides it for tests and diagnosis.
    """
    override = os.environ.get("CODEWIRE_CARGO_JOBS")
    if override is not None:
        source.require(re.fullmatch(r"[1-9][0-9]?", override) is not None and int(override) <= 32,
                       "CODEWIRE_CARGO_JOBS must be 1 to 32")
        return override
    cpus, gib = machine()
    return str(max(2, min(MAX_JOBS, cpus, gib // GIB_PER_JOB)))
FILES = {"cw", "cw.d", "compile.log", "cw.oci.tar", "image.json", "runtime.pack", "cw-runtime.lock.json", "producer.json"}
COMPILER_DEADLINE = 7200
COMPLETION_FIELDS = {"command", "exit", "elapsed_seconds", "log", "log_sha256", "timed_out", "interrupted",
                     "unexpected_family", "cleanup_unknown"}


DIAGNOSTIC_PHASES = frozenset({"arguments", "custody", "capsule", "profile", "readonly", "home",
                              "environment", "rustc", "compile", "export", "result",
                              "export-admission", "export-binary", "export-depinfo", "export-log",
                              "export-directory", "export-transports", "export-retained", "export-verify"})
DIAGNOSTIC_ERRNOS = {errno.EPERM: "permission", errno.EACCES: "permission", errno.EROFS: "readonly",
                     errno.EMFILE: "process_fd_limit", errno.ENFILE: "system_fd_limit",
                     errno.ENOENT: "not_found", errno.ENOTDIR: "not_directory", errno.ELOOP: "link",
                     errno.EINVAL: "invalid", errno.EIO: "io", errno.ENOSPC: "capacity"}
DIAGNOSTIC_PREFIX = "finalize-cw-runtime-source: producer refused "
_DIAGNOSTIC = {"phase": "arguments", "source_held_files_at_admit": None, "source_held_fds_at_admit": None}


def diagnostic_number(value):
    return value if type(value) is int and 0 <= value <= (1 << 63) - 1 else None


def failure_diagnostic(error):
    """Fixed labels/numbers only; never render an exception or its source chain.

    Source descriptor counts are a snapshot after complete capsule admission,
    not a partial/peak count or a measurement after refusal cleanup.
    """
    exception = "unknown"
    for category, label in ((OSError, "os"), (release.ReleaseError, "release"),
                            (subprocess.SubprocessError, "subprocess"), (ValueError, "value"),
                            (KeyError, "key"), (TypeError, "type")):
        if isinstance(error, category):
            exception = label
            break
    code = error.errno if isinstance(error, OSError) else None
    errno_class = ("none" if code is None else
                   DIAGNOSTIC_ERRNOS.get(code, "other") if type(code) is int else "other")
    limits = None
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        limits = {"soft": "unlimited" if type(soft) is int and soft == resource.RLIM_INFINITY
                  else diagnostic_number(soft),
                  "hard": "unlimited" if type(hard) is int and hard == resource.RLIM_INFINITY
                  else diagnostic_number(hard)}
    except (OSError, ValueError, TypeError):
        pass
    value = {"schema": "codewire.cw.runtime-source-refusal/v1",
             "phase": _DIAGNOSTIC["phase"] if _DIAGNOSTIC["phase"] in DIAGNOSTIC_PHASES else "unknown",
             "exception": exception, "errno": errno_class, "nofile": limits,
             "source_held_files_at_admit": diagnostic_number(_DIAGNOSTIC["source_held_files_at_admit"]),
             "source_held_fds_at_admit": diagnostic_number(_DIAGNOSTIC["source_held_fds_at_admit"])}
    return DIAGNOSTIC_PREFIX + json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# Original capsule inventory holds at most two walk descriptors per level,
# plus the root ancestry. Four bounded depths cover those handles and the
# simultaneous fixed export ancestries; 64 cover stdio, Git/transport pipes,
# selectors, eight export members, and ordinary compiler-family bookkeeping.
# Width adds no simultaneous walk handles. All original per-member FDs remain.
CAPSULE_NOFILE_HEADROOM = 4 * source.asset.MAX_DEPTH + 64


def prepare_descriptor_capacity(request_sha256):
    """Raise only soft NOFILE for this exact pinned, bounded capsule.

    This preflight never admits source or compilation. Full source.admit below
    independently rereads the request and every inode/hash/Git member, then
    main retains its existing readonly checks before the compiler dispatch.
    """
    source.require(release.is_hex(request_sha256, 64), "capsule request pin refused")
    request = source.HeldSourceFile(REQUEST, source.MAX_DOCUMENT)
    try:
        source.require(request.sha256 == request_sha256, "capsule request differs from its external pin")
        model = source.model(request.data)
        # Parent holds one FD per absolute directory component, without
        # deduplication, and HeldSourceFile retains one additional file FD.
        retained = len(request.parent.fds) + 1
        paths = [SOURCE_ROOT / name for name in model["files"]]
        paths.extend(GIT_ROOT / "objects" / oid[:2] / oid[2:] for oid in model["objects"])
        paths.extend(GIT_ROOT / name for name in ("HEAD", "index", "shallow"))
        for path in paths:
            retained += len(source.asset.path_arg(str(path)).parent.parts) + 1
        request.revalidate(content=True)
    finally:
        request.close()
    # Schema count/byte bounds and existing absolute-path depth bounds make
    # this selected capacity finite; do not demand worst-schema capacity.
    required = retained + CAPSULE_NOFILE_HEADROOM
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    valid = lambda value: type(value) is int and (value == resource.RLIM_INFINITY or 0 <= value <= (1 << 63) - 1)
    source.require(valid(soft) and valid(hard)
                   and (hard == resource.RLIM_INFINITY or soft != resource.RLIM_INFINITY and soft <= hard),
                   "compiler descriptor limits refused")
    source.require(hard == resource.RLIM_INFINITY or required <= hard,
                   "selected capsule exceeds the unchanged descriptor hard limit")
    if soft != resource.RLIM_INFINITY and soft < required:
        resource.setrlimit(resource.RLIMIT_NOFILE, (required, hard))
        observed_soft, observed_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        source.require(type(observed_soft) is int and type(observed_hard) is int
                       and observed_soft == required and observed_hard == hard,
                       "compiler descriptor limit readback differs")
    return required


def export_bound(name):
    source.require(name in FILES, "unknown producer export")
    return (8 * 1024 * 1024 if name == "cw.d" else 32 * 1024 * 1024 if name == "compile.log" else
            release.MAX_JSON if name in ("producer.json", "image.json", "cw-runtime.lock.json") else
            source.asset.image.MAX_ARCHIVE)


def completion(value, expected=None):
    source.require(type(value) is dict and set(value) == COMPLETION_FIELDS
                   and type(value["exit"]) is int and value["exit"] == 0
                   and all(value[key] is False for key in ("timed_out", "interrupted", "unexpected_family", "cleanup_unknown"))
                   and type(value["elapsed_seconds"]) in (int, float) and math.isfinite(value["elapsed_seconds"])
                   and 0 <= value["elapsed_seconds"] <= COMPILER_DEADLINE + 3600
                   and source.release.is_hex(value["log_sha256"], 64)
                   and type(value["command"]) is list and 0 < len(value["command"]) <= 256
                   and all(type(arg) is str and 0 < len(arg.encode("utf-8")) <= 4096
                           and not any(ord(c) < 32 or ord(c) == 127 for c in arg) for arg in value["command"]),
                   "owned command completion refused")
    source.asset.path_arg(value["log"])
    if expected is not None:
        source.require(value["command"] == expected, "command differs from the fixed producer")
    return value


def command(profile):
    source.require(profile in PROFILES, "producer profile refused")
    return ["/usr/local/cargo/bin/cargo", "zigbuild", "--locked", *PROFILES[profile],
            "-p", "codewire-cli-bin", "--bin", "cw", "--target", source.TARGET,
            "--manifest-path", "/src/Cargo.toml", "--target-dir", str(TARGET_ROOT), "--jobs", cargo_jobs()]


def cargo_environment(model, directory):
    # Only the established compiler-cache projection survives. Git overrides,
    # provider credentials, proxies, signing and publication variables do not.
    cache = {key: value for key, value in os.environ.items()
             if key in {"RUSTC_WRAPPER", "SCCACHE_DIR", "SCCACHE_SERVER_UDS", "SCCACHE_BASEDIRS",
                        "SCCACHE_DIRECT", "SCCACHE_BUCKET", "SCCACHE_ENDPOINT", "SCCACHE_REGION",
                        "SCCACHE_S3_USE_SSL", "SCCACHE_S3_KEY_PREFIX", "SCCACHE_MULTILEVEL_CHAIN",
                        "SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY", "SCCACHE_IGNORE_SERVER_IO_ERROR",
                        "AWS_SHARED_CREDENTIALS_FILE", "AWS_PROFILE", "AWS_EC2_METADATA_DISABLED"}}
    source.require(cache.get("RUSTC_WRAPPER") in (None, "/usr/local/bin/sccache"), "compiler wrapper refused")
    environment = {"PATH": "/usr/local/cargo/bin:/opt/zig:/opt/protoc/bin:/usr/bin:/bin",
                   "HOME": str(directory), "TMPDIR": str(directory), "CARGO_HOME": str(CARGO_HOME),
                   "RUSTUP_HOME": "/usr/local/rustup", "RUSTC": "/usr/local/cargo/bin/rustc",
                   "PROTOC": "/opt/protoc/bin/protoc", "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": cargo_jobs(),
                   "PYTHONDONTWRITEBYTECODE": "1",
                   "LC_ALL": "C", "TZ": "UTC", **cache,
                   **release.build_environment(model["version"], model["source"]["revision"],
                                               model["source"]["source_tree_sha256"])}
    source.require(not any(key.startswith("GIT_") for key in environment), "Git projection reached Cargo")
    return environment


def pin(raw):
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


# Cargo may retain one hardlink at deps/cw-<16 lowercase hex>. Only this
# compiled-output holder accounts for that exact alias; source/Git/export
# HeldSourceFile keeps its original single-link contract.
MAX_COMPILER_DEPS = source.MAX_FILES


class HeldCompilerOutput(source.HeldSourceFile):
    def __init__(self, path, maximum):
        self.path, self.maximum = source.asset.path_arg(str(path)), maximum
        self.parent, self.fd, self.deps, self.aliases = None, None, None, ()
        try:
            source.require(self.path.name == "cw", "compiler output name refused")
            self.parent = source.asset.Parent(self.path.parent)
            before = os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                              dir_fd=self.parent.fd)
            info = os.fstat(self.fd)
            source.require(source.asset.stamp(before) == source.asset.stamp(info)
                           and stat.S_ISREG(info.st_mode) and info.st_nlink in (1, 2)
                           and info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022
                           and 0 <= info.st_size <= maximum,
                           "compiler output is not a bounded owned regular file")
            self.metadata = source.asset.stamp(info)
            if info.st_nlink == 2:
                try:
                    self.deps = source.asset.Parent(self.path.parent / "deps")
                except FileNotFoundError:
                    raise source.Refused("compiler output has an unaccounted link") from None
                fresh = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=self.deps.fd)
                aliases = []
                try:
                    source.require(source.asset.stamp(os.fstat(fresh), source.asset.DIR_FIELDS)
                                   == source.asset.stamp(os.fstat(self.deps.fd), source.asset.DIR_FIELDS),
                                   "compiler alias directory changed")
                    with os.scandir(fresh) as entries:
                        for count, entry in enumerate(entries, 1):
                            source.asset.active()
                            source.require(count <= MAX_COMPILER_DEPS, "compiler alias inventory exceeds its bound")
                            name = entry.name
                            if not (name.startswith("cw-") and source.release.is_hex(name[3:], 16)):
                                continue
                            alias = os.stat(name, dir_fd=self.deps.fd, follow_symlinks=False)
                            if (alias.st_dev, alias.st_ino) == (info.st_dev, info.st_ino):
                                source.require(source.asset.stamp(alias) == self.metadata,
                                               "compiler alias differs from the held output")
                                aliases.append(name)
                    source.require(len(aliases) == 1, "compiler output has an unaccounted link")
                    self.aliases = tuple(aliases)
                finally:
                    os.close(fresh)
            self.data = self.read()
            self.sha256 = hashlib.sha256(self.data).hexdigest()
            self.revalidate(content=True)
        except BaseException:
            self.close()
            raise

    def revalidate(self, content=False):
        if self.deps is not None:
            self.deps.revalidate()
            for name in self.aliases:
                source.require(source.asset.stamp(os.stat(name, dir_fd=self.deps.fd, follow_symlinks=False))
                               == self.metadata, "held compiler alias changed")
        super().revalidate(content=content)
        if self.deps is not None:
            for name in self.aliases:
                source.require(source.asset.stamp(os.stat(name, dir_fd=self.deps.fd, follow_symlinks=False))
                               == self.metadata, "held compiler alias changed")
            self.deps.revalidate()

    def close(self):
        if self.deps is not None:
            self.deps.close()
            self.deps = None
        super().close()


def finalize(admitted, executable, depinfo, rustc, compile_result, work, target_root, cargo_home):
    """Admission/export leaf, also exercised with never-executed fixture bytes."""
    model = admitted.model
    completion(compile_result, command(model["profile"]))
    admitted.revalidate()
    selected = admitted.selected
    _DIAGNOSTIC["phase"] = "export-admission"
    with source.git_scope(admitted.git_dir, admitted.source):
        rustc = selected.toolchain_rustc(admitted.source, rustc)
        data, identity, count = selected.admit_build(
            admitted.source, executable, depinfo, source.TARGET, model["version"], model["source"]["revision"],
            model["source"]["source_tree_sha256"], rustc,
            (target_root, cargo_home / "registry", cargo_home / "git"))
    binary = dependencies = log = exported_binary = None
    try:
        _DIAGNOSTIC["phase"] = "export-binary"
        binary = HeldCompilerOutput(executable, selected.MAX_EXECUTABLE)
        _DIAGNOSTIC["phase"] = "export-depinfo"
        dependencies = source.HeldSourceFile(depinfo, 8 * 1024 * 1024)
        _DIAGNOSTIC["phase"] = "export-log"
        log = source.HeldSourceFile(compile_result["log"], 32 * 1024 * 1024)
        source.require(binary.data == data and count > 0 and log.sha256 == compile_result["log_sha256"],
                       "retained built input or compiler log changed")
        admitted.revalidate()
        _DIAGNOSTIC["phase"] = "export-directory"
        output = source.asset.path_arg(str(work))
        source.require(not os.path.lexists(output), "producer export already exists")
        parent = source.asset.Parent(output.parent)
        try:
            source.require(os.fstat(parent.fd).st_uid == os.geteuid(), "producer export parent refused")
            os.mkdir(output.name, 0o700, dir_fd=parent.fd)
            root_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent.fd)
            try:
                source.asset.write_new(root_fd, "cw", data, 0o500)
                source.asset.write_new(root_fd, "cw.d", dependencies.data, 0o400)
                source.asset.write_new(root_fd, "compile.log", log.data, 0o400)
            finally:
                os.close(root_fd)
            exported_binary = source.HeldSourceFile(output / "cw", selected.MAX_EXECUTABLE)
            source.require(exported_binary.data == data, "exclusive compiler copy differs from admitted bytes")
            # The unchanged shared producer invokes only its checked-in Python
            # transport tool; these synthetic/actual bytes are not executed.
            _DIAGNOSTIC["phase"] = "export-transports"
            image_dir, pack_dir, image_receipt, lock = selected.runtime_transports(
                output / "cw", identity, output / ".transports", tool=admitted.source / "scripts/dev/cw-runtime-image.py")
            transport_paths = {"cw.oci.tar": image_dir / "cw.oci.tar", "image.json": image_dir / "image.json",
                               "runtime.pack": pack_dir / "runtime.pack", "cw-runtime.lock.json": pack_dir / "cw-runtime.lock.json"}
            transport_bytes = {name: selected.read_regular(path, source.asset.image.MAX_ARCHIVE)
                               for name, path in transport_paths.items()}
            selected.check_transports(data, identity, transport_bytes["cw.oci.tar"], image_receipt,
                                      transport_bytes["runtime.pack"], transport_bytes["cw-runtime.lock.json"],
                                      tool=admitted.source / "scripts/dev/cw-runtime-image.py")
            _DIAGNOSTIC["phase"] = "export-retained"
            root_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent.fd)
            try:
                for name, raw in transport_bytes.items():
                    source.asset.write_new(root_fd, name, raw, 0o400)
                # Only this producer-created, exact private intermediate tree
                # is removed. Original target/dep-info remain outside it.
                import shutil
                shutil.rmtree(output / ".transports")
                binary.revalidate(content=True)
                exported_binary.revalidate(content=True)
                dependencies.revalidate(content=True)
                log.revalidate(content=True)
                admitted.revalidate()
                parent.revalidate()
                receipt = {"schema": SCHEMA, "status": "producer-admitted", "target": source.TARGET,
                           "profile": model["profile"], "version": model["version"], "source": model["source"],
                           "source_request_sha256": admitted.files["request"].sha256,
                           "payload": identity, "repository_input_count": count,
                           "depinfo": pin(dependencies.data), "compile": compile_result,
                           "outputs": {"cw": pin(data), "cw.d": pin(dependencies.data), "compile.log": pin(log.data),
                                       **{name: pin(raw) for name, raw in transport_bytes.items()}},
                           "image": image_receipt, "cache_qualified": False,
                           "claim": "one-target-compiler-and-runtime-bytes-not-image-or-cache-qualification"}
                raw = selected.canonical(receipt)
                source.require(len(raw) <= selected.MAX_JSON, "producer receipt exceeds its bound")
                source.asset.write_new(root_fd, "producer.json", raw, 0o400)
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
            _DIAGNOSTIC["phase"] = "export-verify"
            verify_export(output, model, admitted.files["request"].sha256)
            parent.revalidate()
            return receipt
        finally:
            parent.close()
    finally:
        for file in (binary, dependencies, log, exported_binary):
            if file is not None:
                file.close()


def verify_export(output, model, request_sha256):
    """Join actual exporter bytes to the producer and selected request."""
    _DIAGNOSTIC["phase"] = "export-verify"
    held = {}
    try:
        source.validate_inventory(output, FILES, ())
        for name in FILES:
            held[name] = source.HeldSourceFile(output / name, export_bound(name))
            source.require(stat.S_IMODE(held[name].metadata["mode"]) == (0o500 if name == "cw" else 0o400),
                           "export member mode refused")
        receipt = release.parse_canonical(held["producer.json"].data)
        source.require(type(receipt) is dict and set(receipt) == {"schema", "status", "target", "profile", "version",
                       "source", "source_request_sha256", "payload", "repository_input_count", "depinfo", "compile",
                       "outputs", "image", "cache_qualified", "claim"}
                       and receipt["schema"] == SCHEMA and receipt["status"] == "producer-admitted"
                       and receipt["target"] == source.TARGET and receipt["profile"] == model["profile"]
                       and receipt["version"] == model["version"]
                       and release.canonical(receipt["source"]) == release.canonical(model["source"])
                       and receipt["source_request_sha256"] == request_sha256 and receipt["cache_qualified"] is False
                       and receipt["claim"] == "one-target-compiler-and-runtime-bytes-not-image-or-cache-qualification"
                       and type(receipt["repository_input_count"]) is int
                       and 0 < receipt["repository_input_count"] <= source.MAX_FILES,
                       "producer receipt authority refused")
        completion(receipt["compile"], command(model["profile"]))
        data = held["cw"].data
        identity = release.make_identity(data, source.TARGET, model["version"], model["source"]["revision"],
                    model["source"]["source_tree_sha256"], receipt["payload"]["rustc"])
        source.require(release.canonical(identity) == release.canonical(receipt["payload"])
                       and set(receipt["outputs"]) == FILES - {"producer.json"}
                       and all(release.canonical(pin(held[name].data)) == release.canonical(binding)
                               for name, binding in receipt["outputs"].items())
                       and receipt["depinfo"] == pin(held["cw.d"].data)
                       and receipt["compile"]["log_sha256"] == held["compile.log"].sha256, "producer exported bytes differ")
        image_receipt = release.parse_canonical(held["image.json"].data)
        source.require(release.canonical(image_receipt) == release.canonical(receipt["image"]), "image receipt differs")
        release.check_transports(data, identity, held["cw.oci.tar"].data, image_receipt,
                                 held["runtime.pack"].data, held["cw-runtime.lock.json"].data)
        for file in held.values():
            file.revalidate(content=True)
        source.validate_inventory(output, FILES, ())
        return receipt
    finally:
        for file in held.values():
            file.close()


def main(argv=None):
    _DIAGNOSTIC.update(phase="arguments", source_held_files_at_admit=None, source_held_fds_at_admit=None)
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--request-sha256", required=True, action=source.asset.SingleUse)
    args = parser.parse_args(argv)
    def cancelled(sig, frame):
        source.asset.STOP = sig
        owner.on_signal(sig, frame)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, cancelled)
    _DIAGNOSTIC["phase"] = "custody"
    owner.arm_custody()
    _DIAGNOSTIC["phase"] = "capsule"
    prepare_descriptor_capacity(args.request_sha256)
    with source.admit(SOURCE_ROOT, GIT_ROOT, REQUEST, args.request_sha256) as admitted:
        _DIAGNOSTIC.update(source_held_files_at_admit=len(admitted.files),
                           source_held_fds_at_admit=sum((held.fd is not None) + len(held.parent.fds)
                                                       for held in admitted.files.values()))
        _DIAGNOSTIC["phase"] = "profile"
        source.require(os.environ.get("CODEWIRE_RUST_PROFILE") == admitted.model["profile"], "compiler profile projection differs")
        _DIAGNOSTIC["phase"] = "readonly"
        source.require(all(os.fstatvfs(held.fd).f_flag & os.ST_RDONLY for held in admitted.files.values()),
                       "compiler source/Git/request must be mounted readonly")
        _DIAGNOSTIC["phase"] = "home"
        home = WORK / "compiler-home"
        owner.admit_output(home)
        owner.private_directory(home)
        _DIAGNOSTIC["phase"] = "environment"
        environment = cargo_environment(admitted.model, home)
        _DIAGNOSTIC["phase"] = "rustc"
        rustc = subprocess.check_output(["/usr/local/cargo/bin/rustc", "--version"], cwd=SOURCE_ROOT,
                                       env=environment, text=True, timeout=15).strip()
        admitted.selected.toolchain_rustc(SOURCE_ROOT, rustc)
        _DIAGNOSTIC["phase"] = "compile"
        cpus, gib = machine()
        print(f"finalize-cw-runtime-source: cargo --jobs {cargo_jobs()} (cpus={cpus} memory_gib={gib})",
              file=sys.stderr)
        result = owner.run_owned(command(admitted.model["profile"]), SOURCE_ROOT, environment,
                                 home / "compile.log", time.monotonic() + COMPILER_DEADLINE)
        profile = admitted.model["profile"]
        _DIAGNOSTIC["phase"] = "export"
        receipt = finalize(admitted, TARGET_ROOT / source.TARGET / profile / "cw",
                           TARGET_ROOT / source.TARGET / profile / "cw.d", rustc, result,
                           WORK / "assets", TARGET_ROOT, CARGO_HOME)
        _DIAGNOSTIC["phase"] = "result"
        print(release.canonical({"status": "producer-admitted", "payload": receipt["payload"],
                                 "repository_input_count": receipt["repository_input_count"]}).decode(), end="")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, release.ReleaseError) as error:
        print(failure_diagnostic(error), file=sys.stderr)
        sys.exit(1)
