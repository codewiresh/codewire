#!/usr/bin/env python3
"""Real producer admission over synthetic source and never-executed CW bytes.

Only the compiler result and Docker API are synthetic. Source capture, held
Git admission, full executable record, dep-info, transport finalization and
the caller's finish/reopen paths are the unchanged production implementations.
These fixtures cannot qualify an actual compiler, image or cache operation.
"""

import argparse
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


driver = load("cw_fixture_driver", ROOT / "scripts/ci/images/build-cw-runtime-source.py")
source, finalizer, release = driver.source, driver.finalizer, driver.release
artifact = load("cw_fixture_artifact", ROOT / "scripts/ci/verify/workspace-image-artifact.py")
binary_fixture = load("cw_fixture_record", ROOT / "scripts/ci/tests/cw_release_fixtures.py")
EXTRA_INPUTS = (
    "docker-bake.hcl", "deployments/docker/rust-base.Dockerfile",
    "deployments/docker/daemon.Dockerfile", "scripts/ci/images/cw-image-consumer.py",
    "scripts/ci/images/cw-image-consumer.sh", "scripts/ci/images/cw-image-source.py",
    "scripts/ci/images/build-product-images.sh", "scripts/ci/tests/canary-workspace-r2-cache.sh",
)
PRODUCER_ID = "b" * 25
CLAIM = "synthetic-source-and-api; no-Cargo-Docker-or-CW-execution"


def write(path, raw, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
    path.chmod(mode)


def create_source(destination):
    """Create a genuine private Git fixture, never modify a delivery checkout."""
    destination = source.asset.path_arg(str(destination))
    source.require(not os.path.lexists(destination), "synthetic source must be fresh")
    with closing(source.asset.Parent(destination.parent)) as parent:
        source.require(os.fstat(parent.fd).st_uid == os.geteuid(), "synthetic parent is not owned")
        os.mkdir(destination.name, 0o700, dir_fd=parent.fd)
        parent.revalidate()
    for name in sorted(set(source.PREREQUISITES) | set(artifact.INPUTS) | set(EXTRA_INPUTS)):
        with closing(source.HeldSourceFile(ROOT / name, source.MAX_FILE)) as held:
            mode = 0o755 if held.metadata["mode"] & 0o111 else 0o644
            write(destination / name, held.data, mode)
            held.revalidate(content=True)
    # This selected source contains a real dependency, not a fabricated count.
    write(destination / "crates/demo/src/lib.rs", b"pub fn synthetic_cw_dependency() {}\n", 0o644)
    # The source model selects its own effective version through the real API.
    for name, raw in {
        "Cargo.toml": b'[workspace]\nmembers = ["crates/demo"]\n[workspace.package]\nversion = "0.0.0-ci"\n',
        "Cargo.lock": b"version = 4\n",
        "rust-toolchain.toml": b'[toolchain]\nchannel = "1.93.0"\n',
    }.items():
        path = destination / name
        path.unlink()
        write(path, raw, 0o644)
    # source.git clears configuration, hooks, credentials, maintenance and
    # network protocols. Only this freshly allocated private repo is mutated.
    source.git(destination, ["init", "-q"])
    source.git(destination, ["add", "-A"])
    source.git(destination, ["-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
                             "commit", "-q", "-m", "synthetic image caller fixture"])
    return {"source_sha": source.git(destination, ["rev-parse", "HEAD"]).strip().decode(),
            "source_tree": source.git(destination, ["rev-parse", "HEAD^{tree}"]).strip().decode(),
            "claim": CLAIM}


def one(arguments, name):
    values = [arguments[index + 1] for index, arg in enumerate(arguments[:-1]) if arg == name]
    source.require(len(values) == 1, "synthetic producer requires one " + name)
    return values[0]


def export_producer(arguments):
    """Emulate only the prepared producer solve; run its real export leaf."""
    source.require(arguments[:2] == ["buildx", "build"], "synthetic producer route refused")
    capsule_path = one(arguments, "--build-context")
    source.require(capsule_path.startswith("cw-source="), "producer source context differs")
    capsule = source.asset.path_arg(capsule_path.removeprefix("cw-source="))
    metadata = source.asset.path_arg(one(arguments, "--metadata-file"))
    output = one(arguments, "--output")
    source.require(output.startswith("type=local,dest="), "producer export route differs")
    exports = source.asset.path_arg(output.removeprefix("type=local,dest="))
    source.require(exports == metadata.parent / "assets" and metadata.name == "metadata.json",
                   "producer output is outside the exact task")
    with closing(source.HeldSourceFile(capsule / "request.json", source.MAX_DOCUMENT)) as request:
        model = source.model(request.data)
        cache_mode = next((arg.split("=", 1)[1] for arg in arguments
                           if arg.startswith("CODEWIRE_SCCACHE_MODE=")), None)
        fixed = driver.fixed_arguments(capsule, model, request.sha256, metadata.parent, cache_mode)
        builder = one(arguments, "--builder") if "--builder" in arguments else None
        driver.admit_solve_command(["docker", *arguments], fixed, builder)
        with source.admit(capsule / "source", capsule / "git", capsule / "request.json", request.sha256) as admitted:
            # No ELF is executed and no Cargo invocation is made. This is the
            # same explicitly synthetic compiler input as the producer tests.
            with tempfile.TemporaryDirectory(prefix="synthetic-inputs-", dir=metadata.parent) as temporary:
                scratch = Path(temporary)
                target, cargo = scratch / "target", scratch / "cargo"
                executable, depinfo, log = target / "cw", target / "cw.d", scratch / "compile.log"
                data = binary_fixture.executable(source.TARGET, version=model["version"],
                    revision=model["source"]["revision"], tree=model["source"]["source_tree_sha256"],
                    rustc=binary_fixture.RUSTC)
                write(executable, data, 0o500)
                write(depinfo, (str(executable) + ": " + str(admitted.source / "crates/demo/src/lib.rs") + "\n").encode(), 0o400)
                write(log, (CLAIM + "\n").encode(), 0o400)
                completion = {"command": finalizer.command(model["profile"]), "exit": 0, "elapsed_seconds": 0,
                    "log": str(log), "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                    "timed_out": False, "interrupted": False, "unexpected_family": False, "cleanup_unknown": False}
                finalizer.finalize(admitted, executable, depinfo, binary_fixture.RUSTC, completion,
                                   exports, target, cargo)
        finalizer.verify_export(exports, model, request.sha256)
        request.revalidate(content=True)
    reference = f"{builder}/{builder}-node/{PRODUCER_ID}" if builder else f"synthetic/synthetic-node/{PRODUCER_ID}"
    write(metadata, release.canonical({"buildx.build.ref": reference}), 0o600)
    print("#3 [cw-builder 1/1] RUN fixed synthetic compiler input\n#3 DONE 0.1s\n#3 0.1 Cache hits 4")
    if any(arg.startswith("type=s3,") for arg in arguments):
        print("#9 exporting cache to Amazon S3\n#9 DONE 0.1s")
    print(CLAIM)


def selected_asset(source_root, result_path):
    """Read the original admitted payload; normal reopen remains mandatory."""
    source_root = source.asset.path_arg(str(source_root))
    with closing(source.HeldSourceFile(Path(result_path), release.MAX_JSON)) as held:
        result = release.parse_canonical(held.data)
        current = source.git(source_root, ["rev-parse", "HEAD"]).strip().decode()
        with driver.reopen(result["receipt"]["path"], result["receipt"]["sha256"], source_root,
                           current, result["profile"], result["version"]) as retained:
            source.require(result == {key: retained.summary[key] for key in result},
                           "synthetic selected result differs from actual finish")
            data = retained.files["asset/cw"].data
            held.revalidate(content=True)
            retained.revalidate()
            return data


def retain_result(source_root, result_path, destination):
    """Bind the same actual finish bytes to a new fixture owner, without build."""
    with closing(source.HeldSourceFile(Path(result_path), release.MAX_JSON)) as held:
        selected_asset(source_root, result_path)
        held.revalidate(content=True)
        write(Path(destination), held.data, 0o400)


def docker_cat(source_root, result_path, image_id, arguments, mismatch=False):
    """Closed fake implementation of the verifier's exact installed-CW read."""
    source.require(len(arguments) == 17 and arguments[:7] ==
        ["run", "--rm", "--pull=never", "--network=none", "--read-only", "--user", "1000:1000"]
        and arguments[7] == "--name" and arguments[9] == "--cidfile"
        and arguments[11] == "--label" and arguments[13:] ==
        ["--entrypoint", "/usr/bin/cat", image_id, "/usr/local/bin/cw"], "synthetic CW copy route differs")
    source.require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "synthetic image ID refused")
    token = arguments[8].removeprefix("codewire-workspace-cw-")
    source.require(re.fullmatch(r"[0-9a-f]{32}", token) and
        arguments[8] == "codewire-workspace-cw-" + token and
        arguments[12] == "dev.codewire.workspace-cw-verification=" + token,
        "synthetic CW copy name/label differs")
    cidfile = source.asset.path_arg(arguments[10])
    source.require(cidfile.name == "cid", "synthetic CID path differs")
    write(cidfile, ("9" * 64 + "\n").encode(), 0o600)
    data = selected_asset(Path(source_root), Path(result_path))
    if mismatch:
        # Only the simulated installed leaf differs. Original producer inputs,
        # transports, record and receipts remain byte-identical and admitted.
        data = data[:-1] + bytes((data[-1] ^ 1,))
    sys.stdout.buffer.write(data)


def make_producer(source_root, output, profile="release", version="0.0.0-ci", builder="synthetic-owned"):
    """Run a real owned fake API solve, then the unchanged host finish().

    This convenience API supplies source-only fixtures to other consumers.
    The real caller shell tests instead drive their normal prepare/solve/finish
    wrapper through export_producer(), so that bridge is never bypassed.
    """
    source_root, output = Path(source_root), Path(output)
    with driver.prepare_plan(source_root, source.git(source_root, ["rev-parse", "HEAD"]).strip().decode(),
                             profile, version, output) as prepared:
        shim_dir = output.parent / (output.name + "-fake-api")
        shim_dir.mkdir(mode=0o700)
        shim = shim_dir / "docker"
        # Arguments go through the actual fixed-route admission; no retained
        # command is executed. These paths are generated fixture inputs only.
        import shlex
        write(shim, ("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -B " +
                     shlex.quote(str(Path(__file__).resolve())) + ' export -- "$@"\n').encode(), 0o700)
        arguments = driver.producer_arguments(prepared.capsule, output)
        command = [str(shim), "buildx", "build", "--builder", builder, *arguments]
        prepared.before_dispatch()
        driver.owner.arm_custody()
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(shim_dir), "TMPDIR": str(shim_dir),
                       "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C", "TZ": "UTC"}
        result = driver.owner.run_owned(command, source_root, environment, output / "build.log", time.monotonic() + 120)
        summary = driver.finish(prepared, result, builder)
        return summary


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    commands = parser.add_subparsers(dest="operation", required=True)
    create = commands.add_parser("source", allow_abbrev=False)
    create.add_argument("destination")
    produced = commands.add_parser("producer", allow_abbrev=False)
    produced.add_argument("source")
    produced.add_argument("output")
    produced.add_argument("result")
    export = commands.add_parser("export", allow_abbrev=False)
    export.add_argument("arguments", nargs=argparse.REMAINDER)
    selected = commands.add_parser("cat", allow_abbrev=False)
    selected.add_argument("source")
    selected.add_argument("result")
    reuse = commands.add_parser("retain-result", allow_abbrev=False)
    reuse.add_argument("source")
    reuse.add_argument("result")
    reuse.add_argument("destination")
    copied = commands.add_parser("docker-cat", allow_abbrev=False)
    copied.add_argument("--mismatch", action="store_true")
    copied.add_argument("source")
    copied.add_argument("result")
    copied.add_argument("image_id")
    copied.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.operation == "source":
        print(json.dumps(create_source(Path(args.destination)), sort_keys=True))
    elif args.operation == "producer":
        summary = make_producer(Path(args.source), Path(args.output))
        write(Path(args.result), release.canonical(summary), 0o400)
    elif args.operation == "export":
        export_producer(args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments)
    elif args.operation == "cat":
        sys.stdout.buffer.write(selected_asset(Path(args.source), Path(args.result)))
    elif args.operation == "retain-result":
        retain_result(Path(args.source), Path(args.result), Path(args.destination))
    else:
        arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
        docker_cat(args.source, args.result, args.image_id, arguments, args.mismatch)


if __name__ == "__main__":
    main()
