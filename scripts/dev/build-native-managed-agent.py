#!/usr/bin/env python3
"""Build a source-bound static cw for native guest managed conversations.

The caller supplies a fresh owned output directory and an actual Rust tools
directory. This prepares local artifacts; it never publishes or changes a VM.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-musl"


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


def source_identity():
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
         "--", "*.rs", "*.toml", "*.lock", "*.proto",
         "scripts/dev/build-native-managed-agent.py", "scripts/dev/cw-runtime-image.py"], cwd=ROOT).split(b"\0")
    digest = hashlib.sha256()
    for raw in sorted(set(name for name in names if name)):
        path = ROOT / os.fsdecode(raw)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"build input must be a regular source file: {path}")
        data = path.read_bytes()
        digest.update(raw + b"\0" + str(len(data)).encode() + b"\0" + hashlib.sha256(data).digest())
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rust-tools", type=Path, required=True)
    parser.add_argument("--protoc", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.exists():
        raise RuntimeError("--output must be a fresh absolute owned directory")
    tools = args.rust_tools.resolve(strict=True)
    protoc = args.protoc.resolve(strict=True)
    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    rustc = subprocess.check_output([str(tools / "rustc"), "--version"], text=True).strip()
    if rustc.split()[1] != channel:
        raise RuntimeError(f"actual Rust must match checked-in {channel}: {rustc}")
    before = source_identity()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    args.output.mkdir(mode=0o700, parents=True)
    target_dir = args.target_dir or args.output / "target"
    if not target_dir.is_absolute():
        raise RuntimeError("--target-dir must be absolute")
    # Only public source caches are reused. No ordinary Cargo config or login
    # files enter this task's compiler environment.
    public_cargo = args.output / "cargo-home"
    public_cargo.mkdir(mode=0o700)
    cached_cargo = Path.home() / ".cargo"
    for name in ("registry", "git"):
        source = cached_cargo / name
        if source.is_dir():
            (public_cargo / name).symlink_to(source, target_is_directory=True)
    environment = {
        "PATH": str(tools) + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
        "CARGO_HOME": str(public_cargo), "CARGO_TARGET_DIR": str(target_dir),
        "CARGO_BUILD_JOBS": "4", "CARGO_INCREMENTAL": "0", "LC_ALL": "C",
        "RUSTFLAGS": "-C linker=rust-lld -C target-feature=+crt-static",
        "PROTOC": str(protoc), "SOURCE_DATE_EPOCH": "0", "TZ": "UTC",
    }
    command = [str(tools / "cargo"), "build", "--offline", "--locked", "--profile", "ci",
               "--target", TARGET, "-p", "codewire-cli-bin", "--bin", "cw"]
    log = args.output / "build.log"
    with log.open("wb") as output:
        exit_code = bounded_build(command, environment, output, 1200)
    if exit_code:
        raise RuntimeError(f"static cw build exit{exit_code}; inspect {log}")
    binary = target_dir / TARGET / "ci/cw"
    header = subprocess.check_output(["readelf", "-h", str(binary)], text=True)
    program_headers = subprocess.check_output(["readelf", "-l", str(binary)], text=True)
    dynamic = subprocess.check_output(["readelf", "-d", str(binary)], text=True)
    if "Advanced Micro Devices X86-64" not in header or "INTERP" in program_headers or "NEEDED" in dynamic:
        raise RuntimeError("guest cw must be an actual static x86_64 ELF")
    after = source_identity()
    if before != after or revision != subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip():
        raise RuntimeError("source changed during the build; artifact binding is not emitted")
    destination = args.output / "cw"
    shutil.copyfile(binary, destination)
    destination.chmod(0o500)
    descriptor = {
        "schema_version": 1, "protocol_version": 1, "target": TARGET,
        "source_revision": revision, "source_tree_sha256": after, "rustc": rustc,
        "path": str(destination), "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
    }
    path = args.output / "managed-agent-cw.json"
    with tempfile.NamedTemporaryFile(mode="w", dir=args.output, delete=False) as temporary:
        json.dump(descriptor, temporary, indent=2)
        temporary.write("\n")
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    temporary_path.chmod(0o600)
    temporary_path.replace(path)
    proof = {"command": command, "exit": exit_code, "source_tree_sha256": after,
             "descriptor": str(path), "sha256": descriptor["sha256"], "static_elf": True}
    (args.output / "build-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps(proof, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, KeyError) as error:
        print(f"build-native-managed-agent: {error}", file=sys.stderr)
        sys.exit(1)
