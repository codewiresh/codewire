#!/usr/bin/env python3
"""Own a fixed one-target, nonpublishing CW BuildKit producer operation.

The default route uses only the local Docker socket and a fresh empty Docker
configuration. Existing checked-in cache owners can reuse prepare_plan() and
finish() around their exact owned builder solve; they retain builder/secret/
layer-cache/history custody. Neither API accepts an arbitrary build command.
No build or cache receipt is supplied by merely preparing source.
"""

import argparse
import importlib.util
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time


ROOT = Path(__file__).resolve().parents[3]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    previous_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous_bytecode
    return module

source = load("cw_runtime_host_source", ROOT / "scripts/ci/images/prepare-cw-source-context.py")
finalizer = load("cw_runtime_host_finalizer", ROOT / "scripts/ci/images/finalize-cw-runtime-source.py")
owner = finalizer.owner
release = source.release
SCHEMA = "codewire.cw.runtime-source-build/v1"
BUILD_BOUND = finalizer.COMPILER_DEADLINE + 1200
CLAIM = "actual-one-target-producer-not-consumer-image-or-cache-qualification"
RECEIPT_FIELDS = {"schema", "status", "source", "target", "profile", "version", "payload",
                  "source_request_sha256", "repository_input_count", "depinfo", "build", "build_ref",
                  "metadata", "producer_receipt", "image", "index_sha256", "cache_qualified",
                  "image_qualified", "builder_ownership_verified", "claim"}


def fixed_arguments(path, model, request_sha256, work, mode="local"):
    source.require(mode in ("disabled", "local", "r2"), "compiler-cache mode refused")
    # All contexts/target/profile/request/output paths are constructed here;
    # the caller cannot replace them or add a different recipe/command/tag.
    return ["--platform", "linux/amd64", "--target", "cw-runtime-export", "--progress", "plain",
            "--build-arg", "CW_SOURCE_REQUEST_SHA256=" + request_sha256,
            "--build-arg", "CODEWIRE_RUST_PROFILE=" + model["profile"],
            "--build-arg", "CODEWIRE_SCCACHE_MODE=" + mode,
            "--build-context", "cw-source=" + str(path),
            "--metadata-file", str(work / "metadata.json"),
            "--output", "type=local,dest=" + str(work / "assets"),
            "--file", str(path / "source/images/cw-runtime/Dockerfile"), str(path / "source")]


def producer_arguments(capsule, work, mode="local"):
    capsule.revalidate()
    arguments = fixed_arguments(capsule.path, capsule.model, capsule.outputs["request.json"].sha256, work, mode)
    capsule.dispatch_arguments = tuple(arguments)
    return arguments


def admit_solve_command(command, fixed, builder=None):
    prefix = command[:-len(fixed)] if type(command) is list else []
    def docker_at(index):
        binary = prefix[index]
        # Existing owners explicitly select CODEWIRE_DOCKER_BIN, including
        # the checked-in fake Docker fixtures. This admits its recorded route,
        # and never executes a command read from a retained receipt.
        selected = binary == "docker" or (binary.startswith("/")
                    and Path(binary).name == "docker"
                    and str(Path(binary)) == binary
                    and ".." not in Path(binary).parts)
        return selected and any(prefix[index + 1:index + 1 + len(candidate)] == candidate for candidate in (
            ["buildx", "build"], ["--host", "unix:///run/docker.sock", "buildx", "build"]))
    source.require(type(command) is list and len(command) > len(fixed) and command[-len(fixed):] == fixed
                   and any(docker_at(index) for index in range(len(prefix))),
                   "actual solve command differs from the prepared route")
    if builder is not None:
        source.require(any(command[i:i + 2] == ["--builder", builder] for i in range(len(prefix) - 1)),
                       "actual solve command lacks the selected builder")


def metadata_reference(raw, builder=None):
    data = release.parse_json(raw, 1024 * 1024)
    reference = data.get("buildx.build.ref") if type(data) is dict else None
    source.require(type(reference) is str and re.fullmatch(
        r"[a-z0-9][a-z0-9_.-]{0,160}/[a-z0-9][a-z0-9_.-]{0,165}/[a-z0-9]{20,32}", reference),
        "actual solve metadata lacks its exact build reference")
    if builder is not None:
        source.require(type(builder) is str and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,160}", builder)
                       and reference.split("/", 1)[0] == builder, "solve belongs to another builder")
    return reference


class Prepared:
    def __init__(self, output, capsule):
        self.path, self.capsule = output, capsule
        self.parent = source.asset.Parent(output)
        try:
            self.root_stamp = source.asset.stamp(os.fstat(self.parent.fd), source.asset.DIR_FIELDS)
            producer_arguments(capsule, output)
        except BaseException:
            self.parent.close()
            raise

    def revalidate(self):
        self.capsule.revalidate()
        self.parent.revalidate()
        source.require(source.asset.stamp(os.fstat(self.parent.fd), source.asset.DIR_FIELDS) == self.root_stamp,
                       "producer task root changed")

    def before_dispatch(self):
        self.revalidate()
        source.require(all(not os.path.lexists(self.path / name) for name in
                           ("assets", "metadata.json", "build.log", "build.json")),
                       "producer outputs must be fresh before dispatch")

    def close(self):
        self.capsule.close()
        self.parent.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def prepare_plan(source_dir, revision, profile, version, output):
    source.require(release.is_hex(revision, 40) and profile in ("ci", "release", "runtime") and release.valid_version(version),
                   "producer selection refused before task allocation")
    path = source.asset.path_arg(str(output))
    source.require("," not in str(path), "producer output cannot contain an exporter separator")
    source.require(not os.path.lexists(path), "producer task output already exists")
    parent = source.asset.Parent(path.parent)
    try:
        source.require(os.fstat(parent.fd).st_uid == os.geteuid(), "producer task parent is not owned")
        os.mkdir(path.name, 0o700, dir_fd=parent.fd)
        parent.revalidate()
    finally:
        parent.close()
    capsule = source.prepare(source_dir, revision, profile, version, path / "source-context")
    try:
        return Prepared(path, capsule)
    except BaseException:
        capsule.close()
        raise


def finish(prepared, result, builder=None):
    """Join a real owned solve outcome, metadata and retained producer assets.

    The caller owns the actual result and must retain its command/log evidence.
    Merely supplying JSON is not accepted build observation or cache proof.
    The default main() obtains result directly from the checked-in process owner.
    """
    finalizer.completion(result)
    command = result["command"]
    fixed = list(prepared.capsule.dispatch_arguments)
    admit_solve_command(command, fixed, builder)
    source.require(result["log"] == str(prepared.path / "build.log"), "solve log is outside the exact prepared task")
    prepared.revalidate()
    metadata = source.HeldSourceFile(prepared.path / "metadata.json", 1024 * 1024)
    log = source.HeldSourceFile(result["log"], 256 * 1024 * 1024)
    try:
        source.require(log.sha256 == result["log_sha256"], "actual build log differs")
        reference = metadata_reference(metadata.data, builder)
        producer = finalizer.verify_export(prepared.path / "assets", prepared.capsule.model,
                                          prepared.capsule.outputs["request.json"].sha256)
        receipt_file = source.HeldSourceFile(prepared.path / "assets/producer.json", release.MAX_JSON)
        image_file = source.HeldSourceFile(prepared.path / "assets/cw.oci.tar", source.asset.image.MAX_ARCHIVE)
        try:
            prepared.revalidate()
            metadata.revalidate(content=True)
            log.revalidate(content=True)
            receipt_file.revalidate(content=True)
            image_file.revalidate(content=True)
            model = {"schema": SCHEMA, "status": "producer-admitted", "source": producer["source"],
                     "target": source.TARGET, "profile": producer["profile"], "version": producer["version"],
                     "payload": producer["payload"], "source_request_sha256": producer["source_request_sha256"],
                     "repository_input_count": producer["repository_input_count"], "depinfo": producer["depinfo"],
                     "build": result, "build_ref": reference, "metadata": metadata.evidence(),
                     "producer_receipt": receipt_file.evidence(), "image": image_file.evidence(),
                     "index_sha256": producer["image"]["index_sha256"], "cache_qualified": False,
                     "image_qualified": False, "builder_ownership_verified": False,
                     "claim": CLAIM}
            raw = release.canonical(model)
            source.require(len(raw) <= release.MAX_JSON, "host producer receipt exceeds its bound")
            source.asset.write_new(prepared.parent.fd, "build.json", raw, 0o400)
            result_file = source.HeldSourceFile(prepared.path / "build.json", release.MAX_JSON)
            try:
                prepared.revalidate()
                result_file.revalidate(content=True)
                return {"status": "producer-admitted", "receipt": result_file.evidence(),
                        "producer_receipt": model["producer_receipt"], "image": model["image"],
                        "index_sha256": model["index_sha256"], "payload": model["payload"],
                        "source": model["source"], "profile": model["profile"], "version": model["version"],
                        "build_ref": reference, "cache_qualified": False, "image_qualified": False}
            finally:
                result_file.close()
        finally:
            receipt_file.close()
            image_file.close()
    finally:
        metadata.close()
        log.close()


class ReusedBuild:
    """Hold an externally pinned original producer result across a consumer.

    This re-proves retained bytes and current source admission. It does not
    compile, rewrite the original receipt or qualify cache execution. A caller
    still owns its exact consumer command, cleanup and image/cache evidence.
    """

    def __init__(self, receipt_path, expected_sha256, source_dir, revision, profile, version):
        self.files, self.parent, self.capsule, self.original = {}, None, None, None
        self.reused = True
        source.require(release.is_hex(expected_sha256, 64) and release.is_hex(revision, 40)
                       and profile in ("ci", "release", "runtime") and release.valid_version(version),
                       "retained producer selection refused")
        try:
            path = source.asset.path_arg(str(receipt_path))
            source.require(path.name == "build.json", "retained build receipt name refused")
            self.path = path.parent
            self.parent = source.asset.Parent(self.path)
            info = os.fstat(self.parent.fd)
            source.require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                           "retained producer task is not private")
            self.root_stamp = source.asset.stamp(info, source.asset.DIR_FIELDS)
            receipt = self.hold("receipt", path, release.MAX_JSON, 0o400)
            source.require(receipt.sha256 == expected_sha256, "retained build differs from its external pin")
            self.model = model = release.parse_canonical(receipt.data)
            source.require(type(model) is dict and set(model) == RECEIPT_FIELDS
                           and model["schema"] == SCHEMA and model["status"] == "producer-admitted"
                           and model["target"] == source.TARGET and model["profile"] == profile
                           and model["version"] == version and model["claim"] == CLAIM
                           and all(model[key] is False for key in
                                   ("cache_qualified", "image_qualified", "builder_ownership_verified"))
                           and release.is_hex(model["source_request_sha256"], 64),
                           "retained build receipt authority refused")
            self.capsule = source.admit(self.path / "source-context/source", self.path / "source-context/git",
                                        self.path / "source-context/request.json", model["source_request_sha256"])
            capsule_model = self.capsule.model
            source.require(capsule_model["profile"] == profile
                           and capsule_model["version"] == version
                           and release.canonical(model["source"]) == release.canonical(capsule_model["source"]),
                           "retained compilation selection differs")
            self.original = source.CurrentSource(source_dir, capsule_model, revision)
            completion = finalizer.completion(model["build"])
            source.require(completion["log"] == str(self.path / "build.log"), "retained build log path refused")
            # Reconstruct each allowed fixed route; no retained pathname or
            # arbitrary command field controls which files are opened.
            matches = [fixed_arguments(self.path / "source-context", capsule_model,
                                       model["source_request_sha256"], self.path, mode)
                       for mode in ("disabled", "local", "r2")]
            fixed = next((candidate for candidate in matches
                          if completion["command"][-len(candidate):] == candidate), None)
            source.require(fixed is not None, "retained producer command route differs")
            admit_solve_command(completion["command"], fixed)
            metadata = self.hold("metadata", self.path / "metadata.json", 1024 * 1024)
            log = self.hold("build_log", self.path / "build.log", 256 * 1024 * 1024)
            source.require(metadata_reference(metadata.data) == model["build_ref"]
                           and log.sha256 == completion["log_sha256"]
                           and release.canonical(metadata.evidence()) == release.canonical(model["metadata"]),
                           "retained solve metadata or log differs")
            for name in sorted(finalizer.FILES):
                self.hold("asset/" + name, self.path / "assets" / name,
                          finalizer.export_bound(name), 0o500 if name == "cw" else 0o400)
            producer = finalizer.verify_export(self.path / "assets", capsule_model, model["source_request_sha256"])
            for key in ("source", "target", "profile", "version", "payload", "source_request_sha256",
                        "repository_input_count", "depinfo"):
                source.require(release.canonical(model[key]) == release.canonical(producer[key]),
                               "retained build and producer differ")
            source.require(release.canonical(self.files["asset/producer.json"].evidence()) ==
                           release.canonical(model["producer_receipt"])
                           and release.canonical(self.files["asset/cw.oci.tar"].evidence()) == release.canonical(model["image"])
                           and model["index_sha256"] == producer["image"]["index_sha256"],
                           "retained producer or archive evidence differs")
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def hold(self, name, path, maximum, mode=None):
        held = source.HeldSourceFile(path, maximum)
        self.files[name] = held
        source.require(held.metadata["uid"] == os.geteuid()
                       and (mode is None or stat.S_IMODE(held.metadata["mode"]) == mode),
                       "retained producer file ownership or mode refused")
        return held

    @property
    def summary(self):
        # Return a copy so caller annotations cannot mutate retained authority.
        model = self.model
        return release.parse_canonical(release.canonical({"status": "producer-admitted", "reused": True,
            "receipt": self.files["receipt"].evidence(), "producer_receipt": model["producer_receipt"],
            "image": model["image"], "index_sha256": model["index_sha256"], "payload": model["payload"],
            "source": model["source"], "profile": model["profile"], "version": model["version"],
            "current_source": self.original.model["source"],
            "build_ref": model["build_ref"], "cache_qualified": False, "image_qualified": False}))

    def revalidate(self):
        source.active()
        self.parent.revalidate()
        source.require(source.asset.stamp(os.fstat(self.parent.fd), source.asset.DIR_FIELDS) == self.root_stamp,
                       "retained producer task changed")
        self.capsule.revalidate()
        self.original.revalidate()
        for held in self.files.values():
            held.revalidate(content=True)
        source.validate_inventory(self.path / "assets", finalizer.FILES, ())
        self.parent.revalidate()

    def close(self):
        for held in self.files.values():
            held.close()
        for retained in (self.capsule, self.original, self.parent):
            if retained is not None:
                retained.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def reopen(build_json_path, expected_sha256, source_dir, selected_sha, profile, version):
    return ReusedBuild(build_json_path, expected_sha256, source_dir, selected_sha, profile, version)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for field in ("source-dir", "source-sha", "profile", "version", "output"):
        parser.add_argument("--" + field, required=True, action=source.asset.SingleUse)
    parser.add_argument("--sccache-mode", choices=("disabled", "local"), action=source.asset.SingleUse)
    parser.add_argument("--builder", action=source.asset.SingleUse)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args(argv)
    source.require(args.builder is None or re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,160}", args.builder), "builder name refused")
    def cancelled(sig, frame):
        source.asset.STOP = sig
        owner.on_signal(sig, frame)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, cancelled)
    with prepare_plan(args.source_dir, args.source_sha, args.profile, args.version, args.output) as prepared:
        arguments = producer_arguments(prepared.capsule, prepared.path, args.sccache_mode or "local")
        if args.prepare_only:
            print(release.canonical({"status": "source-admitted", "claim": "no-compiler-or-image-proof",
                                     "path": str(prepared.path), "source": prepared.capsule.model["source"],
                                     "arguments": arguments}).decode(), end="")
            return 0
        owner.arm_custody()
        # An empty private config prohibits ambient registry auth/proxy/helper
        # reuse. Protected cache owners use the library seam around their own
        # already-admitted Docker environment and exact builder instead.
        for name in ("home", "docker", "tmp"):
            owner.private_directory(prepared.path / name)
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(prepared.path / "home"),
                       "DOCKER_CONFIG": str(prepared.path / "docker"), "TMPDIR": str(prepared.path / "tmp"),
                       "LC_ALL": "C", "TZ": "UTC", "DOCKER_HOST": "unix:///run/docker.sock"}
        operation = ["/usr/bin/docker", "--host", "unix:///run/docker.sock", "buildx", "build"]
        if args.builder is not None:
            operation.extend(("--builder", args.builder))
        operation.extend(arguments)
        prepared.before_dispatch()
        result = owner.run_owned(operation, ROOT, environment, prepared.path / "build.log",
                                 time.monotonic() + BUILD_BOUND)
        completed = finish(prepared, result, args.builder)
        print(release.canonical(completed).decode(), end="")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, release.ReleaseError):
        print("build-cw-runtime-source: producer refused; owned output retained", file=sys.stderr)
        sys.exit(1)
