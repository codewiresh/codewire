#!/usr/bin/env python3
"""Bind an admitted CW producer to a canonical daemon/workspace build.

The cache and builder owners retain their existing policy and lifecycle. This
owner keeps the source, producer assets and private named context open across
the actual consumer solve. Incoming CW bytes are parsed, never executed here.
"""

import argparse
from contextlib import closing
import fnmatch
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import tomllib


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


producer = load("cw_consumer_producer", ROOT / "scripts/ci/images/build-cw-runtime-source.py")
asset = load("cw_consumer_asset", ROOT / "scripts/ci/images/prepare-cw-image-context.py")
image_source = load("cw_consumer_image_source", ROOT / "scripts/ci/images/cw-image-source.py")
release, owner = producer.release, producer.owner
SCHEMA = "codewire.cw.image-consumer/v1"
PRODUCTS = {"dashboard", "services", "mesh", "daemon", "derp"}
RECIPES = {"deployments/docker/daemon.Dockerfile", "images/workspace/Dockerfile"}
BOUND = 10800
GROUPS = {"default": sorted(PRODUCTS), "kind": [name + "-ci" for name in ("dashboard", "services", "mesh", "daemon")]}
BAKE_TARGETS = PRODUCTS | {name + "-ci" for name in PRODUCTS if name != "derp"}
BUILD_ARGS = {"BASE_IMAGE_REF", "DEBIAN_IMAGE", "CODEWIRE_RUST_PROFILE", "CODEWIRE_SCCACHE_MODE",
              "SCCACHE_BUCKET", "SCCACHE_ENDPOINT", "CODEWIRE_SCCACHE_PREFIX", "NODE_VERSION", "GO_VERSION",
              "CODEWIRE_ORCHESTRATION_FEATURES"}
VALUE_FLAGS = {"--file", "-f", "--builder", "--progress", "--metadata-file", "--cache-from", "--cache-to",
               "--provenance", "--sbom", "--no-cache-filter"}
BUILD_VALUE_FLAGS = {"--platform", "--build-context", "--build-arg", "--secret", "--tag", "-t", "--label", "--output", "-o"}
BOOLEAN_FLAGS = {"--pull", "--load", "--push", "--no-cache"}


class SolveFailure(Exception):
    def __init__(self, code, log):
        self.code, self.log = code, log


def run_solve(command, cwd, log, deadline):
    try:
        return owner.run_owned(command, cwd, dict(os.environ), log, deadline)
    except ValueError as error:
        prefix = "kernel command failed after owned-family cleanup: "
        if not str(error).startswith(prefix):
            raise
        result = json.loads(str(error)[len(prefix):])
        asset.require(result["command"] == command and result["log"] == str(log)
                      and type(result["exit"]) is int
                      and all(type(result[key]) is bool for key in
                              ("timed_out", "interrupted", "unexpected_family", "cleanup_unknown")),
                      "failed consumer outcome differs from its owner")
        if result["interrupted"]:
            code = 128 + (asset.STOP or signal.SIGTERM)
        elif result["timed_out"]:
            code = 124
        elif result["unexpected_family"] or result["cleanup_unknown"]:
            code = 70
        else:
            status = result["exit"]
            if 0 < status <= 255:
                code = status
            elif -signal.NSIG < status < 0:
                code = 128 - status
            else:
                code = 1
        raise SolveFailure(code, log) from None


def option(arguments, names):
    """Find exactly one spelling, including --name=value; reject omissions."""
    values = []
    for index, argument in enumerate(arguments):
        if argument in names:
            asset.require(index + 1 < len(arguments), "consumer option lacks its value")
            values.append(arguments[index + 1])
        for name in names:
            if name.startswith("--") and argument.startswith(name + "="):
                values.append(argument[len(name) + 1:])
    asset.require(len(values) <= 1, "consumer option repeats")
    return values[0] if values else None


def parse_command(arguments, operation):
    """Parse every option and operand; unknown flags never acquire an arity."""
    values, operands, seen = [], [], set()
    index = 0
    allowed = VALUE_FLAGS | (BUILD_VALUE_FLAGS if operation == "build" else {"--set"})
    while index < len(arguments):
        argument = arguments[index]
        if argument.startswith("-"):
            key, separator, value = argument.partition("=")
            if key in BOOLEAN_FLAGS:
                asset.require(not separator or value == "true", "consumer boolean override refused")
                values.append((key, None))
            else:
                asset.require(key in allowed, "consumer option is outside the checked-in route")
                if not separator:
                    index += 1
                    asset.require(index < len(arguments), "consumer option lacks its value")
                    value = arguments[index]
                asset.require(value and not value.startswith("-") and len(value.encode()) <= 4096,
                              "consumer option value refused")
                canonical = "--file" if key == "-f" else key
                if canonical in ("--file", "--builder", "--platform", "--metadata-file", "--progress"):
                    asset.require(canonical not in seen, "consumer option repeats")
                    seen.add(canonical)
                values.append((canonical, value))
        else:
            operands.append(argument)
        index += 1
    return values, operands


def platforms(value):
    selected = value.split(",")
    asset.require(len(selected) == len(set(selected)) and set(selected) <= {"linux/amd64", "linux/arm64"},
                  "consumer architecture refused")
    return selected


def client_platform():
    # This selects a client default, then explicitly passes it to Buildx. It
    # never treats the client machine as evidence about a remote builder.
    architecture = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(os.uname().machine)
    asset.require(architecture is not None, "consumer client architecture refused")
    return "linux/" + architecture


def canonical_plan(command, source_dir, cwd, profile, docker_bin="docker"):
    """Close the recipe/target/context boundary before any Docker dispatch."""
    asset.require(type(command) is list and len(command) > 3
                  and all(type(value) is str and value and "\0" not in value for value in command),
                  "consumer argv refused")
    asset.require(command[0] == docker_bin and command[1] == "buildx",
                  "consumer must invoke Docker Buildx")
    asset.require(command[2] in ("build", "bake"), "consumer operation refused")
    values, operands = parse_command(command[3:], command[2])
    filename = next((value for key, value in values if key == "--file"), None)
    asset.require(filename is not None, "canonical consumer recipe is required")
    recipe = Path(filename)
    if not recipe.is_absolute():
        recipe = cwd / recipe
    recipe = Path(os.path.abspath(recipe))
    injected, profile_overrides = [], []
    if command[2] == "build":
        asset.require(recipe in {source_dir / name for name in RECIPES}, "consumer recipe differs from selected source")
        asset.require(len(operands) == 1 and Path(os.path.abspath(cwd / operands[0])) == source_dir,
                      "consumer context differs from selected source")
        targets = ["workspace" if recipe.name == "Dockerfile" else "daemon"]
        selected = None
        for key, value in values:
            if key == "--platform":
                selected = platforms(value)
            if key == "--build-context":
                name, separator, location = value.partition("=")
                asset.require(separator and name in ("codewire-rust-base", "codewire-verified-base"),
                              "consumer named context override refused")
                asset.require((name == "codewire-rust-base" and re.fullmatch(r"docker-image://[^\s]+@sha256:[0-9a-f]{64}", location))
                              or (name == "codewire-verified-base" and targets == ["workspace"]
                                  and re.fullmatch(r"oci-layout:///[^\s]+@sha256:[0-9a-f]{64}", location)),
                              "consumer base mapping refused")
            if key == "--build-arg":
                name, separator, value = value.partition("=")
                asset.require(separator and name in BUILD_ARGS, "consumer build argument refused")
                if name == "CODEWIRE_RUST_PROFILE":
                    profile_overrides.append(value)
        asset.require(len(profile_overrides) <= 1 and all(value == profile for value in profile_overrides),
                      "consumer profile override refused")
        # The owning profile is explicit even when the Dockerfile default is
        # different; the cross-compiled ARM route receives the same profile.
        if not profile_overrides:
            injected += ["--build-arg", "CODEWIRE_RUST_PROFILE=" + profile]
        if selected is None:
            selected = [client_platform()]
            injected += ["--platform", ",".join(selected)]
        effective_platforms = {targets[0]: selected}
    else:
        asset.require(recipe == source_dir / "docker-bake.hcl", "consumer Bake graph differs from selected source")
        asset.require(operands and all(name in BAKE_TARGETS or name in GROUPS for name in operands),
                      "consumer Bake targets refused")
        selected_targets = sorted({target for name in operands for target in GROUPS.get(name, [name])})
        targets = [target for target in selected_targets if target in ("daemon", "daemon-ci")]
        base_profile = os.environ.get("CODEWIRE_RUST_PROFILE", "release")
        effective_profiles = {target: "ci" if target.endswith("-ci") else base_profile for target in selected_targets}
        effective_platforms = {target: None for target in selected_targets}
        for key, value in values:
            if key != "--set":
                continue
            selection, separator, value = value.partition("=")
            pattern, dot, field = selection.partition(".")
            asset.require(separator and dot and field, "consumer Bake override refused")
            affected = [target for target in selected_targets + ["rust-base"] if fnmatch.fnmatchcase(target, pattern)]
            asset.require(affected, "consumer Bake override selects no admitted target")
            if field == "context":
                asset.require(Path(os.path.abspath(cwd / value)) == source_dir,
                              "consumer Bake context differs from selected source")
            elif field == "platform":
                selected = platforms(value)
                for target in affected:
                    if target in effective_platforms:
                        asset.require(effective_platforms[target] in (None, selected), "contradictory consumer platforms")
                        effective_platforms[target] = selected
            elif field == "contexts.codewire-rust-base":
                asset.require(value == "target:rust-base", "consumer Rust base mapping refused")
            elif field.startswith("args."):
                name = field.removeprefix("args.")
                asset.require(name in BUILD_ARGS, "consumer Bake build argument refused")
                if name == "CODEWIRE_RUST_PROFILE":
                    asset.require(value in ("ci", "release", "runtime"), "consumer Bake profile refused")
                    for target in affected:
                        if target in effective_profiles:
                            effective_profiles[target] = value
            else:
                asset.require(field in ("tags", "tags+", "cache-from", "cache-from+", "cache-to", "cache-to+",
                                        "secrets", "secrets+", "output", "output+")
                              or (field.startswith("labels.") and len(field) > 7),
                              "consumer Bake routing override refused")
        asset.require(all(effective_profiles[target] == profile for target in targets),
                      "selected CW consumers require different profiles")
        for target in selected_targets:
            if effective_platforms[target] is None:
                effective_platforms[target] = [client_platform()]
            # Always bind the effective selection, including overrides, in the
            # actual command. The remote/default builder cannot choose it.
            injected += ["--set", target + ".platform=" + ",".join(effective_platforms[target])]
            # HCL context='.' is resolved from the invoking process, even with
            # an absolute Bake file. Bind every selected context to held bytes.
            injected += ["--set", target + ".context=" + str(source_dir)]
        injected += ["--set", "rust-base.context=" + str(source_dir)]
        for target in targets:
            injected += ["--set", target + ".args.CODEWIRE_RUST_PROFILE=" + profile]
    normalized = [item for key, value in values for item in ([key] if value is None else [key, value])]
    recipes = [recipe]
    if command[2] == "bake":
        recipes += [source_dir / ("apps/dashboard/Dockerfile" if target.removesuffix("-ci") == "dashboard"
                                else "deployments/docker/" + target.removesuffix("-ci") + ".Dockerfile")
                    for target in selected_targets]
        recipes.append(source_dir / "deployments/docker/rust-base.Dockerfile")
    return {"targets": targets, "needs_cw_asset": any("linux/amd64" in effective_platforms[target] for target in targets),
            "platforms": effective_platforms, "recipes": recipes,
            "command": command[:3] + normalized + injected + operands}


def canonical_command(command, source_dir, cwd, profile, docker_bin="docker"):
    plan = canonical_plan(command, source_dir, cwd, profile, docker_bin)
    return plan["targets"], plan["needs_cw_asset"]


def bind_context(command, targets, path):
    result = command[:3]
    if command[2] == "build":
        result.extend(("--build-context", asset.CONTEXT_NAME + "=" + str(path)))
    else:
        # Bake refuses a named context outside its working tree unless the
        # read is granted; grant exactly this held directory, nothing wider.
        result.append("--allow=fs.read=" + str(path))
        for target in sorted(set(targets)):
            result.extend(("--set", target + ".contexts." + asset.CONTEXT_NAME + "=" + str(path)))
    return result + command[3:]


def effective_version(source_dir, requested):
    if requested is not None:
        asset.require(release.valid_version(requested), "consumer version refused")
        return requested
    with closing(asset.HeldFile(source_dir / "Cargo.toml", release.MAX_JSON)) as cargo:
        data = tomllib.loads(cargo.data.decode("utf-8"))
        version = data["workspace"]["package"]["version"]
        asset.require(release.valid_version(version), "workspace version refused")
        cargo.revalidate(content=True)
        return version


def fresh_output(path):
    path = asset.path_arg(str(path))
    with closing(asset.Parent(path.parent)) as parent:
        asset.require(os.fstat(parent.fd).st_uid == os.geteuid(), "consumer output parent is not owned")
        os.mkdir(path.name, 0o700, dir_fd=parent.fd)
        parent.revalidate()
    return path


def compiler_cache(mode):
    asset.require(mode in ("disabled", "local", "r2"), "compiler cache mode refused")
    if mode != "r2":
        return []
    # The caller's existing Kind/workspace/protected cache owner validates its
    # bucket, endpoint, prefix and credential custody. Do not create another
    # cache namespace or project credential contents into this request.
    fields = ("SCCACHE_BUCKET", "SCCACHE_ENDPOINT", "CODEWIRE_SCCACHE_PREFIX")
    asset.require(all(os.environ.get(key) for key in fields), "owning compiler-cache configuration is missing")
    credentials = asset.path_arg(os.environ.get("CODEWIRE_SCCACHE_CREDENTIALS_FILE", ""))
    metadata = os.stat(credentials, follow_symlinks=False)
    asset.require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                  and metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) in (0o400, 0o600)
                  and "," not in str(credentials) and "\n" not in str(credentials), "owning cache credential placement refused")
    result = ["--secret", "id=aws_shared_credentials,src=" + str(credentials)]
    for field in fields:
        result.extend(("--build-arg", field + "=" + os.environ[field]))
    return result


def produce(args):
    output = Path(args.output)
    source_dir = asset.path_arg(args.source_dir)
    version = effective_version(source_dir, args.version)
    prefix = [args.docker_bin, "buildx", "build"]
    if args.builder:
        asset.require(re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,160}", args.builder), "producer builder refused")
        prefix.extend(("--builder", args.builder))
    cache = compiler_cache(args.sccache_mode)
    for name in ("cache_from", "cache_to"):
        for value in getattr(args, name):
            asset.require(value and "\0" not in value and "\n" not in value, "layer cache argument refused")
            cache.extend(("--" + name.replace("_", "-"), value))
    if args.no_cache:
        cache.append("--no-cache")
    with producer.prepare_plan(source_dir, args.source_sha, args.profile, version, output) as prepared:
        command = prefix + cache + producer.producer_arguments(prepared.capsule, prepared.path, args.sccache_mode)
        prepared.before_dispatch()
        try:
            result = run_solve(command, source_dir, prepared.path / "build.log", time.monotonic() + producer.BUILD_BOUND)
            prepared.revalidate()
            return producer.finish(prepared, result, args.builder)
        except SolveFailure:
            failed_solve_log(prepared.path / "build.log")
            raise
        except BaseException:
            # The producer retains its compiler log and history in its receipt.
            # Successful output here would mix those vertices into the caller's
            # separate image solve log; failures still need terminal diagnostics.
            stream_log(prepared.path / "build.log")
            raise


def stream_log(path):
    if path.exists():
        with closing(asset.HeldFile(path, 256 * 1024 * 1024)) as held:
            sys.stderr.buffer.write(held.data)
            sys.stderr.buffer.flush()


def failed_solve_log(path, *, terminal=False):
    """Diagnostics cannot replace an already-owned failed solve outcome."""
    try:
        if terminal:
            with closing(asset.HeldFile(path, 256 * 1024 * 1024)) as held:
                lines = [line for line in held.data.splitlines() if line.strip()]
                if lines and len(lines[-1]) <= 4096:
                    sys.stderr.buffer.write(lines[-1] + b"\n")
        else:
            stream_log(path)
    except (OSError, ValueError):
        # Keep intake strict: unreadable, empty or unsafe logs are not read
        # through another path and cannot qualify a receipt or a retry.
        pass


def consume(args, command):
    source_dir, cwd = asset.path_arg(args.source_dir), Path.cwd()
    version = effective_version(source_dir, args.version)
    image_dir = asset.path_arg(args.image_source_dir) if getattr(args, "image_source_dir", None) else source_dir
    plan = canonical_plan(command, image_dir, cwd, args.profile, args.docker_bin)
    with image_source.ImageSource(image_dir, plan["recipes"]) as held:
        return consume_plan(args, source_dir, cwd, version, plan, held)


def source_evidence(held, output):
    summary = held.summary
    raw = release.canonical(summary)
    with closing(asset.Parent(output)) as parent:
        asset.write_new(parent.fd, "image-source.json", raw, 0o400)
    return {key: summary[key] for key in ("source_dir", "files", "directories", "symlinks", "total_bytes")} | {
        "path": str(output / "image-source.json"), "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
        "logical_sha256": summary["sha256"]}


def consume_plan(args, source_dir, cwd, version, plan, held):
    targets, amd64, command = plan["targets"], plan["needs_cw_asset"], plan["command"]
    output = fresh_output(Path(args.output))
    if not amd64:
        # ARM cross-compiles its own CW from source. It receives no x86 CW
        # context and cannot emit this verified-startup consumer receipt.
        held.revalidate()
        try:
            result = run_solve(command, cwd, output / "build.log", time.monotonic() + BOUND)
        except SolveFailure:
            failed_solve_log(output / "build.log")
            raise
        except BaseException:
            stream_log(output / "build.log")
            raise
        else:
            stream_log(output / "build.log")
        held.revalidate()
        return {"status": "native-arm-consumer" if targets else "unrelated-product-consumer",
                "claim": "no-verified-startup-or-updater-claim", "build": result,
                "platforms": plan["platforms"], "current_image_source": source_evidence(held, output)}
    asset.require(args.producer_receipt and release.is_hex(args.producer_sha256, 64), "verified CW producer is required")
    with producer.reopen(args.producer_receipt, args.producer_sha256, source_dir, args.source_sha,
                         args.profile, version) as admitted:
        summary = admitted.summary
        request = {"schema_version": 1, "image": {key: summary["image"][key] for key in ("path", "sha256", "size")},
                   "index_sha256": summary["index_sha256"], "payload": summary["payload"],
                   "producer_receipt": {key: summary["producer_receipt"][key] for key in ("path", "sha256", "size")}}
        with closing(asset.Parent(output)) as parent:
            raw = release.canonical(request)
            asset.write_new(parent.fd, "asset-request.json", raw, 0o400)
        with asset.prepare(output / "asset-request.json", hashlib.sha256(raw).hexdigest(), output / "verified-cw") as context:
            operation = bind_context(command, targets, context.path)
            admitted.revalidate()
            context.revalidate()
            held.revalidate()
            try:
                result = run_solve(operation, cwd, output / "build.log", time.monotonic() + BOUND)
            except SolveFailure:
                failed_solve_log(output / "build.log")
                raise
            except BaseException:
                stream_log(output / "build.log")
                raise
            else:
                stream_log(output / "build.log")
            admitted.revalidate()
            context.revalidate()
            held.revalidate()
            model = {"schema": SCHEMA, "status": "consumer-built", "claim": "producer-and-context-bound; installed-image-proof-pending",
                     "source": summary["source"], "profile": args.profile, "version": version,
                     "current_source": summary["current_source"],
                     "current_image_source": source_evidence(held, output), "platforms": plan["platforms"],
                     "payload": summary["payload"], "producer": summary["receipt"], "original_build_ref": summary["build_ref"],
                     "compilation": "reused", "context": {"path": str(context.receipt_path), "sha256": context.receipt_sha256},
                     "build": result, "image_qualified": False, "cache_qualified": False}
            with closing(asset.Parent(output)) as parent:
                asset.write_new(parent.fd, "consumer.json", release.canonical(model), 0o400)
            return model


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("operation", choices=("check", "produce", "consume"))
    for field in ("source-dir", "source-sha", "profile", "output"):
        parser.add_argument("--" + field, required=True, action=asset.SingleUse)
    for field in ("version", "builder", "producer-receipt", "producer-sha256", "image-source-dir"):
        parser.add_argument("--" + field, action=asset.SingleUse)
    parser.add_argument("--docker-bin", action=asset.SingleUse)
    parser.add_argument("--sccache-mode", choices=("disabled", "local", "r2"), action=asset.SingleUse)
    parser.add_argument("--cache-from", action="append", default=[])
    parser.add_argument("--cache-to", action="append", default=[])
    parser.add_argument("--no-cache", action="store_true")
    split = argv.index("--") if "--" in argv else len(argv)
    args = parser.parse_args(argv[:split])
    args.docker_bin = args.docker_bin or "docker"
    args.sccache_mode = args.sccache_mode or "local"
    command = argv[split + 1:]
    asset.require((args.operation == "produce" and not command)
                  or (args.operation in ("check", "consume") and command), "consumer command delimiter refused")
    return args, command


def main(argv=None):
    args, command = arguments(list(sys.argv[1:] if argv is None else argv))
    asset.require(args.profile in ("ci", "release", "runtime") and release.is_hex(args.source_sha, 40), "consumer source/profile refused")
    if args.operation == "check":
        source_dir = asset.path_arg(args.source_dir)
        image_dir = asset.path_arg(args.image_source_dir) if args.image_source_dir else source_dir
        plan = canonical_plan(command, image_dir, Path.cwd(), args.profile, args.docker_bin)
        asset.require(producer.source.git(source_dir, ["rev-parse", "HEAD"]).strip().decode() == args.source_sha,
                      "selected consumer HEAD differs")
        with image_source.ImageSource(image_dir, plan["recipes"]) as held:
            held.revalidate()
            image_identity = {key: value for key, value in held.summary.items() if key != "inventory"}
        print(release.canonical({"status": "consumer-arguments-admitted", "claim": "no-build-proof",
                                 "needs_cw_asset": plan["needs_cw_asset"], "targets": plan["targets"], "platforms": plan["platforms"],
                                 "builder": option(command[3:], {"--builder"}),
                                 "current_image_source": image_identity,
                                 "version": effective_version(source_dir, args.version)}).decode(), end="")
        return 0
    owner.arm_custody()
    def cancel(sig, frame):
        asset.STOP = sig
        producer.source.asset.STOP = sig
        image_source.STOP = sig
        owner.on_signal(sig, frame)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, cancel)
    result = produce(args) if args.operation == "produce" else consume(args, command)
    print(release.canonical(result).decode(), end="")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SolveFailure as error:
        try:
            print("cw-image-consumer: solve failed; owned outputs retained", file=sys.stderr)
        except OSError:
            pass
        if error.code == 1:
            # Preserve the real terminal Buildx diagnostic for the existing
            # cache owner's one diagnosed read-failure retry predicate.
            failed_solve_log(error.log, terminal=True)
        sys.exit(error.code)
    except (OSError, ValueError, KeyError, TypeError, release.ReleaseError, asset.release.ReleaseError) as error:
        # The reason is a fixed check message or an OS error; it names which
        # check refused without printing any file contents.
        reason = "".join(c if c.isprintable() else "?" for c in f"{type(error).__name__}: {error}")[:300]
        try:
            print(f"cw-image-consumer: refused: {reason}", file=sys.stderr)
            print("cw-image-consumer: build refused; owned outputs retained", file=sys.stderr)
        except OSError:
            pass
        sys.exit(1)
