#!/usr/bin/env python3
"""Build a source-bound static cw for native guest managed conversations.

The caller supplies a fresh owned output directory and an actual Rust tools
directory. The shared identity producer (scripts/ci/release/cw_release.py)
binds the result: the source digest is taken before the build and rechecked
after it, every compiled input must be digested, and the executable's own
build record must name the explicit effective version, target, compiler and
source. This prepares local artifacts; it never publishes or changes a VM.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci/release"))
import cw_release as release  # noqa: E402

TARGET = release.RUNTIME_TARGET


def bounded_build(command, environment, output, timeout):
    """Bound the compiler process group, including its build-script children."""
    process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=output,
                               stderr=subprocess.STDOUT, start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            pass
        # The group may outlive its leader, so always stop remaining children.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rust-tools", type=Path, required=True)
    parser.add_argument("--protoc", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--version", help="effective compiled version [default: the workspace version]")
    parser.add_argument("--cargo-cache", type=Path, default=Path.home() / ".cargo",
                        help="public Cargo source cache whose registry/ and git/ are reused [default: ~/.cargo]")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.exists():
        raise RuntimeError("--output must be a fresh absolute owned directory")
    tools = args.rust_tools.resolve(strict=True)
    protoc = args.protoc.resolve(strict=True)
    version = args.version or tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    rustc = release.toolchain_rustc(ROOT, subprocess.check_output([str(tools / "rustc"), "--version"], text=True))
    revision = release.head_revision(ROOT)
    before = release.source_tree_sha256(ROOT)
    args.output.mkdir(mode=0o700, parents=True)
    target_dir = args.target_dir or args.output / "target"
    if not target_dir.is_absolute():
        raise RuntimeError("--target-dir must be absolute")
    # Only public source caches are reused. No ordinary Cargo config or login
    # files enter this task's compiler environment.
    public_cargo = args.output / "cargo-home"
    public_cargo.mkdir(mode=0o700)
    for name in ("registry", "git"):
        source = args.cargo_cache / name
        if source.is_dir():
            (public_cargo / name).symlink_to(source, target_is_directory=True)
    environment = {
        "PATH": str(tools) + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
        "CARGO_HOME": str(public_cargo), "CARGO_TARGET_DIR": str(target_dir),
        "CARGO_BUILD_JOBS": str(args.jobs), "CARGO_INCREMENTAL": "0", "LC_ALL": "C",
        "RUSTFLAGS": "-C linker=rust-lld -C target-feature=+crt-static",
        "PROTOC": str(protoc), "SOURCE_DATE_EPOCH": "0", "TZ": "UTC",
        # The build record embeds exactly these explicit inputs.
        **release.build_environment(version, revision, before),
    }
    command = [str(tools / "cargo"), "build", "--offline", "--locked", "--profile", "ci",
               "--target", TARGET, "-p", "codewire-cli-bin", "--bin", "cw"]
    log = args.output / "build.log"
    with log.open("wb") as output:
        exit_code = bounded_build(command, environment, output, 1200)
    if exit_code:
        raise RuntimeError(f"static cw build exit{exit_code}; inspect {log}")
    binary = target_dir / TARGET / "ci/cw"
    data, identity, inputs = release.admit_build(
        ROOT, binary, binary.with_name("cw.d"), TARGET, version, revision, before, rustc,
        (target_dir, public_cargo / "registry", public_cargo / "git"))
    destination = args.output / "cw"
    release.write_new(destination, data, 0o500)
    # The image producer's build input: the identity without its size, plus
    # the path of these exact bytes.
    descriptor = {key: value for key, value in identity.items() if key != "size"}
    descriptor["path"] = str(destination)
    path = args.output / "managed-agent-cw.json"
    with tempfile.NamedTemporaryFile(mode="w", dir=args.output, delete=False) as temporary:
        json.dump(descriptor, temporary, indent=2)
        temporary.write("\n")
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    temporary_path.chmod(0o600)
    temporary_path.replace(path)
    proof = {"command": command, "exit": exit_code, "package_version": version, "source_revision": revision,
             "source_tree_sha256": before, "compiled_repository_inputs": inputs, "descriptor": str(path),
             "sha256": identity["sha256"], "size": identity["size"], "static_elf": True}
    (args.output / "build-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps(proof, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, KeyError, release.ReleaseError) as error:
        print(f"build-native-managed-agent: {error}", file=sys.stderr)
        sys.exit(1)
