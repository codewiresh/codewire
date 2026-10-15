#!/usr/bin/env python3
"""A source-only, offline macOS developer build loop over SSH (not CI)."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid


REGISTRY = "index.crates.io-1949cf8c6b5b557f"
PUBLIC_GIT = {
    "https://github.com/connectrpc/connect-rust.git": "connect-rust",
    "https://github.com/noeljackson/av.git": "av",
    "https://github.com/microsoft/regorus": "regorus",
}
SMOKE = [[], ["env"], ["run"], ["list"], ["mesh"], ["network"]]
SSH_OPTIONS = ["-oBatchMode=yes", "-oForwardAgent=no", "-oConnectTimeout=10",
               "-oServerAliveInterval=10", "-oServerAliveCountMax=2"]
VZ_FIXTURES = {
    "vz-fixture": ("macos-production-init-fixture", "codewire-macos-vz-fixture"),
    "vz-workload-network": ("macos-workload-network-fixture", "codewire-macos-workload-network-fixture"),
}
SWIFT_COMPONENTS = {
    "vz-runner": ("macos-vz-runner", "swift-vz-runner", ("codewire-vz-runner",)),
    "sandbox-canary": ("macos-sandbox-canary-experiment", "swift-sandbox-canary",
                       ("sandbox-experiment-owner", "sandbox-candidate", "canary-deputy")),
}

# The command owner and archive helpers, shared with the runtime's e2fsprogs
# build; the upload carries the file beside worker.py.
COMMAND_OWNER = "macos-command-owner.py"
_spec = importlib.util.spec_from_file_location("macos_command_owner", Path(__file__).with_name(COMMAND_OWNER))
command_owner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(command_owner)
CleanupUnknown = command_owner.CleanupUnknown
digest = command_owner.digest
safe_name = command_owner.safe_name
extract = command_owner.extract
stop_group = command_owner.stop_group
run_command = command_owner.run_command


def output(argv, **kwargs):
    return subprocess.check_output(argv, **kwargs).decode().strip()


def add_bytes(archive, name, data, mode=0o644, link=None):
    safe_name(name)
    entry = tarfile.TarInfo(name)
    entry.mode = mode
    if link is not None:
        entry.type = tarfile.SYMTYPE
        entry.linkname = link
    else:
        entry.size = len(data)
    archive.addfile(entry, io.BytesIO(data) if link is None else None)


def source_archive(repo, destination):
    """Freeze tracked working-tree bytes; do not follow links or copy Git state."""
    entries = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=repo)
    manifest = []
    with tarfile.open(destination, "w:gz") as archive:
        for record in entries.split(b"\0"):
            if not record:
                continue
            metadata, raw_name = record.split(b"\t", 1)
            mode, _oid, stage = metadata.decode().split()
            name = os.fsdecode(raw_name)
            relative = safe_name(name)
            if stage != "0" or mode == "160000":
                raise ValueError(f"unmerged path or submodule: {name}")
            path = repo / name
            if any((repo / parent).is_symlink() for parent in relative.parents):
                raise ValueError(f"symlinked source parent: {name}")
            if not path.exists() and not path.is_symlink():
                continue  # Tracked working-tree deletion.
            link = os.readlink(path) if path.is_symlink() else None
            if link is not None:
                if Path(link).is_absolute() or not path.resolve().is_relative_to(repo):
                    raise ValueError(f"source symlink escapes checkout: {name}")
                data, bits = os.fsencode(link), 0o777
            else:
                if not path.is_file():
                    raise ValueError(f"unsupported source file: {name}")
                data = path.read_bytes()
                bits = 0o755 if path.stat().st_mode & 0o111 else 0o644
            add_bytes(archive, name, data, bits, link)
            manifest.append({"path": name, "mode": bits, "link": link,
                             "sha256": hashlib.sha256(data).hexdigest()})
    encoded = json.dumps(manifest, sort_keys=True).encode()
    return {"head": output(["git", "rev-parse", "HEAD"], cwd=repo),
            "source_sha256": hashlib.sha256(encoded).hexdigest(), "files": manifest}


def index_path(name):
    name = name.lower()
    if len(name) <= 2:
        return f"{len(name)}/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def seed_archive(lock_bytes, cargo_home, destination):
    """Copy only locked public archives/index entries and sanitized Git objects."""
    import tomllib  # Local driver requires Python 3.11; remote CLT Python is 3.9+.

    packages = tomllib.loads(lock_bytes.decode())["package"]
    missing, added, git_seeds = [], set(), []
    git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    git_env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_GRAFT_FILE": os.devnull})
    with tarfile.open(destination, "w:gz") as archive:
        def copy(path, name):
            if name in added:
                return
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"missing or symlinked dependency cache: {path}")
            add_bytes(archive, name, path.read_bytes())
            added.add(name)

        config = json.dumps({"dl": "https://static.crates.io/crates",
                             "api": "https://crates.io"}).encode()
        add_bytes(archive, f"registry/index/{REGISTRY}/config.json", config)
        for package in packages:
            source = package.get("source", "")
            if not source:
                continue
            if source == "registry+https://github.com/rust-lang/crates.io-index":
                name, version = package["name"], package["version"]
                index = f"registry/index/{REGISTRY}/.cache/{index_path(name)}"
                copy(cargo_home / index, index)
                relative = f"registry/cache/{REGISTRY}/{name}-{version}.crate"
                crate = cargo_home / relative
                if not crate.exists():
                    missing.append(f"{name}-{version}")
                    continue  # Other-platform packages need not be cached locally.
                if digest(crate) != package["checksum"]:
                    raise ValueError(f"Cargo.lock checksum mismatch: {relative}")
                copy(crate, relative)
            elif source.startswith("git+"):
                url, commit = source[4:].split("#", 1)
                url = url.split("?", 1)[0]
                if url not in PUBLIC_GIT or not re.fullmatch(r"[0-9a-f]{40}", commit):
                    raise ValueError(f"Git dependency not in public seed allowlist: {source}")
                if any(item["commit"] == commit for item in git_seeds):
                    continue
                candidates = list((cargo_home / "git/db").glob(PUBLIC_GIT[url] + "-*"))
                candidates = [path for path in candidates if path.is_dir() and not path.is_symlink()]
                if len(candidates) != 1:
                    raise ValueError(f"expected one cached public Git database for {url}")
                database = candidates[0]
                if (database / "objects/info/alternates").exists():
                    raise ValueError(f"Git cache uses external alternates: {database}")
                # pack-objects emits objects reachable from this commit, never config,
                # refs, hooks, credentials, checkout metadata or unrelated objects.
                pack = subprocess.check_output(
                    ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                     "-c", "advice.graftFileDeprecated=false", f"--git-dir={database}",
                     "pack-objects", "--stdout", "--revs"],
                    input=(commit + "\n").encode(), env=git_env)
                add_bytes(archive, f"packs/{database.name}.pack", pack)
                git_seeds.append({"database": database.name, "commit": commit})
            else:
                raise ValueError(f"non-public dependency source: {source}")
        add_bytes(archive, "git.json", json.dumps(git_seeds).encode())
    return missing


def sync_source(staged, source):
    """Stable paths/mtimes for unchanged files; remove stale owned source only."""
    owned_directory(source)
    for target in source.iterdir():
        incoming = staged / target.name
        same_kind = target.is_dir() == incoming.is_dir() and target.is_symlink() == incoming.is_symlink()
        if not incoming.exists() and not incoming.is_symlink() or not same_kind:
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink()
    for incoming in staged.iterdir():
        target = source / incoming.name
        if incoming.is_symlink():
            if target.is_symlink() and os.readlink(target) == os.readlink(incoming):
                continue
            target.unlink(missing_ok=True)
            target.symlink_to(os.readlink(incoming))
        elif incoming.is_dir():
            sync_source(incoming, target)
        elif not target.exists() or target.stat().st_mode != incoming.stat().st_mode or digest(target) != digest(incoming):
            shutil.copy2(incoming, target)


def owned_directory(path):
    if path.is_symlink():
        raise ValueError(f"symlink in helper-owned directory: {path}")
    path.mkdir(exist_ok=True)
    if not path.is_dir():
        raise ValueError(f"not a helper-owned directory: {path}")


@contextlib.contextmanager
def cache_lock(root):
    descriptor = os.open(root / "lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another developer build owns this worktree cache") from None
        if (root / "inflight.json").exists() or (root / "inflight.json").is_symlink():
            raise RuntimeError("prior developer command cleanup is unconfirmed; cache retained")
        yield


@contextlib.contextmanager
def isolated_runtime(root, run):
    # Resolved: Darwin's /tmp is a symlink, which private-root checks refuse.
    runtime = Path(tempfile.mkdtemp(prefix="cw-", dir="/tmp")).resolve()
    marker = root / "inflight.json"
    # This fail-closed marker exists before any child can start. An abrupt
    # worker death or failed cleanup cannot silently unlock cache reuse.
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump({"run_id": run.name, "isolated_state": str(runtime)}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    retain = False
    try:
        yield runtime
    except CleanupUnknown:
        retain = True
        raise
    finally:
        if not retain:
            shutil.rmtree(runtime, onerror=writable_retry)
            marker.unlink()


def writable_retry(function, path, _):
    # Tests may leave read-only directories (for example a managed release
    # store) inside this helper-owned tree; make the parent writable once.
    os.chmod(os.path.dirname(path), 0o700)
    function(path)


# The credential authority's crates carry macOS signer and repository paths
# (and the selected-key SSH signer feature the CLI enables on macOS).
CREDENTIAL_CRATES = ["-p", "codewire-local-credentials", "-p", "codewire-credential-broker",
                     "--features", "codewire-credential-broker/ssh-agent"]


def import_git_seeds(seeded, cargo, command):
    for item in json.loads((seeded / "git.json").read_text()):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", item["database"]) or not re.fullmatch(r"[0-9a-f]{40}", item["commit"]):
            raise ValueError("invalid public Git seed identity")
        database = cargo / "git/db" / item["database"]
        command(["git", "init", "--bare", "--template=", str(database)])
        # The pack contains only locked public source objects. Its canonical
        # pack-<hash> filename is required for Git to discover imported objects.
        pack = seeded / "packs" / (item["database"] + ".pack")
        command(["git", f"--git-dir={database}", "index-pack", str(pack)])
        (database / "objects/pack").mkdir(exist_ok=True)
        with pack.open("rb") as stream:
            stream.seek(-20, os.SEEK_END)
            pack_name = "pack-" + stream.read().hex()
        for suffix in (".pack", ".idx"):
            # The name is the pack's content hash, so an earlier seed's file
            # (read-only once indexed) already holds these bytes.
            destination = database / "objects/pack" / (pack_name + suffix)
            if not destination.exists():
                shutil.copy2(pack.with_suffix(suffix), destination)
        command(["git", f"--git-dir={database}", "update-ref",
                 "refs/commit/" + item["commit"], item["commit"]])


def worker(root, run):
    request = json.loads((run / "request.json").read_text())
    result = {**request, "status": "running", "commands": [], "artifacts": {}}
    cancel = threading.Event()
    last_ping = [time.monotonic()]

    def heartbeat():
        for line in sys.stdin:
            if line.strip() != "ping":
                break
            last_ping[0] = time.monotonic()
        cancel.set()

    def watchdog():
        while not cancel.wait(1):
            if time.monotonic() - last_ping[0] > 30:
                cancel.set()

    for target in (heartbeat, watchdog):
        threading.Thread(target=target, daemon=True).start()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda *_: cancel.set())
    deadline = time.monotonic() + request["timeout"]

    def save():
        temporary = run / "result.tmp"
        temporary.write_text(json.dumps(result, indent=2) + "\n")
        temporary.replace(run / "result.json")

    try:
        # Darwin Unix socket addresses are only 104 bytes. Isolated HOME/config
        # and TMPDIR must not inherit the long retained run-directory prefix.
        with cache_lock(root), isolated_runtime(root, run) as runtime:
            if platform.system() != "Darwin" or platform.machine() != "arm64":
                raise RuntimeError("native developer host must be Apple Silicon macOS")
            result["host"] = {"macos": output(["sw_vers", "-productVersion"]),
                              "arch": platform.machine()}
            for name in ("source", "artifacts"):
                (run / name).mkdir()
            isolated = Path(runtime)
            for name in ("home", "tmp", "cw"):
                (isolated / name).mkdir()
            result["isolated_state"] = str(isolated)
            for name in ("source", "cargo", "target"):
                owned_directory(root / name)
            extract(run / "source.tar.gz", run / "source", links=True)
            sync_source(run / "source", root / "source")
            source, cargo = root / "source", root / "cargo"
            env = {"PATH": f"{Path.home()}/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                   "HOME": str(isolated / "home"), "CARGO_HOME": str(cargo),
                   "RUSTUP_HOME": str(Path.home() / ".rustup"),
                   "CARGO_TARGET_DIR": str(root / "target"),
                   "CW_CONFIG_DIR": str(isolated / "cw"),
                   "TMPDIR": str(isolated / "tmp") + "/", "LANG": "en_US.UTF-8",
                   "CARGO_NET_OFFLINE": "true", "RUSTUP_AUTO_INSTALL": "0",
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
            # Tests run the runtime's pinned e2fsprogs and git, never Homebrew's
            # or the Xcode Command Line Tools' (crates/codewire-local-vmm darwin).
            if request.get("runtime_tools"):
                env["CW_TEST_RUNTIME_TOOLS"] = request["runtime_tools"]

            def command(argv):
                item = {"argv": argv, "log": f"command-{len(result['commands']):02d}.log"}
                result["commands"].append(item)
                save()
                print(shlex.join(argv), flush=True)
                item["exit_code"] = run_command(argv, source, env, run / item["log"], cancel, deadline)
                save()
                if item["exit_code"] != 0:
                    raise RuntimeError(f"command exited {item['exit_code']}: {shlex.join(argv)}")

            if (run / "seed.tar.gz").exists():
                seeded = run / "seed"
                seeded.mkdir()
                extract(run / "seed.tar.gz", seeded)
                shutil.copytree(seeded / "registry", cargo / "registry", dirs_exist_ok=True)
                import_git_seeds(seeded, cargo, command)

            action = request["action"]
            component = request.get("component", "cli")
            if component == "cli":
                for argv in (["rustc", "-Vv"], ["cargo", "-V"], ["protoc", "--version"],
                             ["xcrun", "--show-sdk-version"]):
                    command(argv)
                common = ["--locked", "--offline"]
                native = [*common, "--target", "aarch64-apple-darwin"]
                if action in ("build", "verify"):
                    command(["cargo", "build", *native, "-p", "codewire-cli-bin", "--bin", "cw"])
                    binary = root / "target/aarch64-apple-darwin/debug/cw"
                    for args in SMOKE:
                        command([str(binary), *args, "--help"])
                    shutil.copy2(binary, run / "artifacts/cw-aarch64-apple-darwin")
                if action in ("test", "verify"):
                    command(["python3", str(source / "crates/codewire-local-vmm/src/darwin/path/test_mount_fixture.py"), "-v"])
                    command(["cargo", "test", *native, "-p", "codewire-cli", "-p", "codewire-cli-bin"])
                    # The release verifier and Store run natively here. The
                    # artifact-graph test needs a git checkout; Linux CI runs it.
                    command(["cargo", "test", *native, "-p", "codewire-cw-release", "--",
                             "--skip", "compiled_trust_is_an_exact_producer_and_artifact_graph_input"])
                    command(["cargo", "test", *native, "-p", "codewire-local-vmm", "--lib"])
                    command(["cargo", "test", *native, *CREDENTIAL_CRATES, "--lib"])
                if action in ("clippy", "verify"):
                    command(["cargo", "clippy", *native, "-p", "codewire-cli", "-p", "codewire-cli-bin",
                             "--all-targets", "--", "-D", "warnings"])
                    # --tests lints macOS-only test code, which no Linux lint compiles.
                    command(["cargo", "clippy", *native, "-p", "codewire-local-vmm", "--lib", "--tests",
                             "--", "-D", "warnings"])
                    command(["cargo", "clippy", *native, *CREDENTIAL_CRATES, "--all-targets",
                             "--", "-D", "warnings"])
                if request["intel"]:
                    command(["cargo", "build", *common, "--target", "x86_64-apple-darwin",
                             "-p", "codewire-cli-bin", "--bin", "cw"])
                    # Link native primitives too: unused FFI can disappear from
                    # the CLI binary. Never execute this Intel test binary.
                    command(["cargo", "test", *common, "--target", "x86_64-apple-darwin",
                             "-p", "codewire-local-vmm", "--lib", "--no-run"])
                    shutil.copy2(root / "target/x86_64-apple-darwin/debug/cw",
                                 run / "artifacts/cw-x86_64-apple-darwin")
            elif component in VZ_FIXTURES:
                if request["intel"]:
                    raise RuntimeError("VZ production fixture accepts native arm64 only")
                feature, executable = VZ_FIXTURES[component]
                for argv in (["rustc", "-Vv"], ["cargo", "-V"], ["protoc", "--version"],
                             ["xcrun", "--show-sdk-version"]):
                    command(argv)
                native = ["--locked", "--offline", "--target", "aarch64-apple-darwin",
                          "-p", "codewire-local-vmm", "--features", feature]
                if action in ("build", "verify"):
                    command(["cargo", "build", *native, "--bin", executable])
                    binary = root / "target/aarch64-apple-darwin/debug" / executable
                    shutil.copy2(binary, run / "artifacts" / (executable + "-arm64"))
                if action in ("test", "verify"):
                    if component == "vz-fixture":
                        command(["cargo", "test", *native, "--lib", "network_session::tests"])
                    command(["cargo", "test", *native, "--bin", executable])
                if action in ("clippy", "verify"):
                    command(["cargo", "clippy", *native, "--lib", "--bin", executable,
                             "--", "-D", "warnings"])
            elif component in SWIFT_COMPONENTS:
                if action == "clippy" or request["intel"]:
                    raise RuntimeError("Swift components accept build, test, or verify on native arm64 only")
                package_name, scratch_name, products = SWIFT_COMPONENTS[component]
                package = source / "crates/codewire-local-vmm" / package_name
                scratch = root / "target" / scratch_name
                command(["xcrun", "swift", "--version"])
                command(["xcrun", "--show-sdk-version"])
                if component == "vz-runner":
                    command([str(package / "Tests/test_ipc_system.sh")])
                else:
                    command(["python3", str(package / "Tests/test_static_contract.py")])
                    command(["python3", str(source / "scripts/dev/test-macos-app-sandbox-canary.py"), "-v"])
                command(["xcrun", "swift-format", "lint", "--strict", "--recursive", str(package)])
                swift = ["--package-path", str(package), "--scratch-path", str(scratch),
                         "-Xswiftc", "-warnings-as-errors", "-Xcc", "-Werror"]
                if action in ("build", "verify"):
                    command(["xcrun", "swift", "build", *swift])
                    for product in products:
                        shutil.copy2(scratch / "debug" / product,
                                     run / "artifacts" / f"{product}-arm64")
                if action in ("test", "verify"):
                    swiftc = Path(output(["xcrun", "--find", "swiftc"])).resolve()
                    testing_plugin = (swiftc.parent.parent /
                                      "lib/swift/host/plugins/testing/libTestingMacros.dylib")
                    if not testing_plugin.is_file():
                        raise RuntimeError(
                            "Swift Testing macro plugin is missing from the selected toolchain")
                    command(["xcrun", "swift", "test", *swift, "-Xswiftc",
                             "-load-plugin-library", "-Xswiftc", str(testing_plugin)])
                    if component == "sandbox-canary":
                        # This assertion needs synchronous main-thread execution,
                        # outside Swift Testing's dispatch-main actor context.
                        command(["xcrun", "swift", "-warnings-as-errors",
                                 str(package / "Tests/test_run_loop.swift")])
                        lifecycle = isolated / "test-application-lifecycle"
                        command(["xcrun", "swiftc", "-warnings-as-errors", "-parse-as-library",
                                 "-swift-version", "6",
                                 str(package / "Sources/CanaryDeputy/ApplicationLifecycle.swift"),
                                 str(package / "Tests/test_application_lifecycle.swift"),
                                 "-o", str(lifecycle)])
                        command([str(lifecycle)])
            else:
                raise RuntimeError("unknown developer build component")
            for artifact in (run / "artifacts").iterdir():
                command(["file", str(artifact)])
                arch = "x86_64" if "x86_64" in artifact.name else "arm64"
                command(["lipo", str(artifact), "-verify_arch", arch])
                result["artifacts"][artifact.name] = digest(artifact)
            result["status"] = "passed"
    except Exception as error:
        result["status"], result["error"] = "failed", str(error)
        print(str(error), file=sys.stderr, flush=True)
    finally:
        save()
    return 0 if result["status"] == "passed" else 1


# The only bootstrap extraction accepts five regular files with fixed names.
BOOTSTRAP = """
import os, pathlib, sys, tarfile
os.umask(0o077)
root = pathlib.Path.home() / '.cache/codewire/macos-dev' / sys.argv[1]
run = root / 'runs' / sys.argv[2]
for path in reversed([run, *run.parents][:-1]):
    if path.is_symlink(): raise SystemExit('symlink in helper cache path')
run.mkdir(parents=True, exist_ok=False)
allowed = {'worker.py', 'macos-command-owner.py', 'source.tar.gz', 'seed.tar.gz', 'request.json'}
with tarfile.open(fileobj=sys.stdin.buffer, mode='r|') as archive:
    for entry in archive:
        if not entry.isfile() or entry.name not in allowed: raise SystemExit('unsafe upload')
        allowed.remove(entry.name)
        with archive.extractfile(entry) as src, (run / entry.name).open('xb') as dst:
            import shutil
            shutil.copyfileobj(src, dst)
print(run)
"""


def ssh(host, command, **kwargs):
    return subprocess.run(["ssh", *SSH_OPTIONS, "--", host, shlex.join(command)], **kwargs)


def recover(host, remote, destination):
    destination.mkdir(parents=True, exist_ok=True)
    # Ask Python for a bounded allowlist, never scp a tree of Cargo/test output.
    script = """
import pathlib, sys, tarfile
run = pathlib.Path(sys.argv[1])
paths = [run / 'request.json', run / 'result.json', *run.glob('command-*.log')]
paths += [run / 'artifacts' / name for name in (
    'cw-aarch64-apple-darwin', 'cw-x86_64-apple-darwin', 'codewire-vz-runner-arm64',
    'codewire-macos-vz-fixture-arm64', 'codewire-macos-workload-network-fixture-arm64',
    'sandbox-experiment-owner-arm64', 'sandbox-candidate-arm64', 'canary-deputy-arm64')]
if not (run / 'request.json').is_file(): raise SystemExit('run not found')
with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:
    for path in paths:
        if path.is_file() and not path.is_symlink(): archive.add(path, arcname=path.relative_to(run))
"""
    with tempfile.TemporaryDirectory(prefix="cw-macos-recovery-") as temporary:
        archive = Path(temporary) / "results.tar"
        with archive.open("wb") as stream:
            ssh(host, ["python3", "-c", script, remote], stdout=stream, check=True)
        unpacked = Path(temporary) / "unpacked"
        unpacked.mkdir()
        extract(archive, unpacked)
        # Repeat recovery can refresh a previously running result. Only this
        # run's fixed evidence files are overwritten, never arbitrary paths.
        shutil.copytree(unpacked, destination, dirs_exist_ok=True)


def evidence_status(evidence, run_id):
    request_path, result_path = evidence / "request.json", evidence / "result.json"
    if not request_path.is_file() or not result_path.is_file():
        raise RuntimeError("outcome unknown: request or result missing; recover again later")
    request, result = json.loads(request_path.read_text()), json.loads(result_path.read_text())
    if request.get("run_id") != run_id or any(result.get(key) != request.get(key)
            for key in ("run_id", "source_sha256", "lock_sha256", "helper_sha256", "command_owner_sha256")):
        raise RuntimeError("recovered evidence identity mismatch")
    if result.get("status") != "passed":
        return result.get("status", "unknown")
    commands = result.get("commands", [])
    if not commands or any(item.get("exit_code") != 0 for item in commands):
        raise RuntimeError("passed result lacks successful command evidence")
    expected = set()
    component = request.get("component", "cli")
    if component in SWIFT_COMPONENTS:
        if request["action"] in ("build", "verify"):
            expected.update(f"{product}-arm64" for product in SWIFT_COMPONENTS[component][2])
    elif component in VZ_FIXTURES:
        if request["action"] in ("build", "verify"):
            expected.add(VZ_FIXTURES[component][1] + "-arm64")
    elif component == "cli":
        if request["action"] in ("build", "verify"):
            expected.add("cw-aarch64-apple-darwin")
        if request["intel"]:
            expected.add("cw-x86_64-apple-darwin")
    else:
        raise RuntimeError("unknown developer build component in recovered evidence")
    if set(result.get("artifacts", {})) != expected:
        raise RuntimeError("passed result lacks expected artifacts")
    for name, checksum in result["artifacts"].items():
        artifact = evidence / "artifacts" / name
        if not artifact.is_file() or digest(artifact) != checksum:
            raise RuntimeError(f"artifact checksum mismatch: {name}")
    return "passed"


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--worker":
        return worker(Path(sys.argv[2]), Path(sys.argv[3]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="user@mac.example.invalid")
    parser.add_argument("--component", choices=["cli", *VZ_FIXTURES, *SWIFT_COMPONENTS], default="cli")
    parser.add_argument("--action", choices=["build", "test", "clippy", "verify"], default="build")
    parser.add_argument("--intel", action="store_true", help="also compile/link x86_64; never execute it")
    parser.add_argument("--seed-cargo", action="store_true", help="seed locked public source dependencies")
    parser.add_argument("--timeout", type=int, default=1800, help="remote deadline in seconds")
    parser.add_argument("--runtime-tools", metavar="DIR",
                        help="absolute directory on the Mac holding the runtime's pinned e2fsprogs "
                             "and git under their installed names, for tests")
    parser.add_argument("--recover", metavar="RUN_ID", help="recover an earlier interrupted run")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]+", args.host) or args.host.startswith("-"):
        parser.error("invalid SSH destination")
    if not 1 <= args.timeout <= 14400:
        parser.error("timeout must be between 1 and 14400 seconds")
    if args.runtime_tools is not None and not re.fullmatch(r"/[A-Za-z0-9._/-]{1,512}", args.runtime_tools):
        parser.error("--runtime-tools must be an absolute plain path on the Mac")
    if args.component in SWIFT_COMPONENTS and (args.action == "clippy" or args.intel or args.seed_cargo):
        parser.error("Swift components accept build, test, or verify without --intel/--seed-cargo")
    if args.component in VZ_FIXTURES and args.intel:
        parser.error("VZ production fixture accepts native arm64 only")
    repo = Path(output(["git", "rev-parse", "--show-toplevel"])).resolve()
    key = hashlib.sha256(str(repo).encode()).hexdigest()[:16]
    run_id = args.recover or uuid.uuid4().hex
    if not re.fullmatch(r"[a-f0-9]{32}", run_id):
        parser.error("invalid run ID")
    remote_relative = f".cache/codewire/macos-dev/{key}/runs/{run_id}"
    evidence = Path(output(["git", "rev-parse", "--git-path", "macos-dev"])) / run_id
    if args.recover:
        recover(args.host, remote_relative, evidence)
        status = evidence_status(evidence, run_id)
        print(f"{status}: {evidence.resolve()}")
        return 0 if status == "passed" else 1
    with tempfile.TemporaryDirectory(prefix="cw-macos-upload-") as temporary:
        stage = Path(temporary)
        request = source_archive(repo, stage / "source.tar.gz")
        request.update({"run_id": run_id, "component": args.component,
                        "action": args.action, "intel": args.intel,
                        "timeout": args.timeout, "host_requested": args.host,
                        "runtime_tools": args.runtime_tools})
        # Read the frozen lock bytes, not a concurrently edited working-tree file.
        with tarfile.open(stage / "source.tar.gz") as archive:
            lock_bytes = archive.extractfile("Cargo.lock").read()
        request["lock_sha256"] = hashlib.sha256(lock_bytes).hexdigest()
        if args.seed_cargo:
            cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
            request["uncached_crates"] = seed_archive(lock_bytes, cargo_home, stage / "seed.tar.gz")
            print(f"Seed: {len(request['uncached_crates'])} locked archives absent locally (offline build will fail if needed).", flush=True)
        shutil.copy2(Path(__file__), stage / "worker.py")
        shutil.copy2(Path(__file__).with_name(COMMAND_OWNER), stage / COMMAND_OWNER)
        request["helper_sha256"] = digest(stage / "worker.py")
        request["command_owner_sha256"] = digest(stage / COMMAND_OWNER)
        (stage / "request.json").write_text(json.dumps(request, indent=2) + "\n")
        upload = stage / "upload.tar"
        with tarfile.open(upload, "w") as archive:
            for name in ("worker.py", COMMAND_OWNER, "source.tar.gz", "seed.tar.gz", "request.json"):
                if (stage / name).exists():
                    archive.add(stage / name, arcname=name)
        print(f"Run {run_id}; source {request['source_sha256']}; evidence {evidence.resolve()}", flush=True)
        with upload.open("rb") as stream:
            response = ssh(args.host, ["python3", "-c", BOOTSTRAP, key, run_id],
                           stdin=stream, stdout=subprocess.PIPE, check=True)
        remote = response.stdout.decode().strip()
        # A Mac set to idle-sleep otherwise sleeps through most of a long build,
        # waking only briefly for network traffic; -i alone does not stop its
        # maintenance sleep, -s does on AC power. Both assertions end with the run.
        command = ["/usr/bin/caffeinate", "-i", "-s", "python3", remote + "/worker.py", "--worker",
                   str(Path(remote).parents[1]), remote]
        process = subprocess.Popen(["ssh", *SSH_OPTIONS, "--", args.host, shlex.join(command)],
                                   stdin=subprocess.PIPE)
        try:
            while process.poll() is None:
                process.stdin.write(b"ping\n")
                process.stdin.flush()
                time.sleep(1)
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        finally:
            with contextlib.suppress(BrokenPipeError):
                process.stdin.close()  # Remote EOF cancels the owned process group.
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
        try:
            recover(args.host, remote, evidence)
        except Exception as error:
            print(f"Outcome unknown: {error}. Recover with --recover {run_id}", file=sys.stderr)
            return 1
        status = evidence_status(evidence, run_id)
        print(f"{status}: {evidence.resolve()}")
        return 0 if process.returncode == 0 and status == "passed" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"macos-cli: {error}", file=sys.stderr)
        sys.exit(1)
