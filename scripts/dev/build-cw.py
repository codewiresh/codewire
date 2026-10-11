#!/usr/bin/env python3
"""Build this checkout's cw for the host with an admitted build record.

`make cli-build` and `make cli-install` use this before `cw install --managed`.
The source revision and digest are taken from this Git checkout before
compilation and passed to Cargo explicitly with the effective version
(CODEWIRE_VERSION, default the workspace version). The shared identity
producer (scripts/ci/release/cw_release.py) then rechecks the source and
admits the executable only if its embedded build record names exactly that
version, host target, compiler and source, and every repository file Cargo
compiled is part of the source digest. A checkout without Git cannot supply
provenance and is refused; nothing is guessed.

With --release-dir, the admitted cw is written beside its canonical
cw-runtime.json, the release directory that `cw update --from DIR` and
scripts/dev/test-cli-update.py consume. `cw update --from` admits only
release targets, so build the update journey's A and B for the release target
(cross-compiled with cargo-zigbuild, as release delivery does) from the same
committed checkout with different versions, for example:

    CODEWIRE_VERSION=0.1.0-journey.a scripts/dev/build-cw.py \
        --target x86_64-unknown-linux-musl --release-dir A
    CODEWIRE_VERSION=0.1.0-journey.b scripts/dev/build-cw.py \
        --target x86_64-unknown-linux-musl --release-dir B
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci/release"))
import cw_release as release  # noqa: E402

PROFILES = {"release": (["--release"], "release"), "ci": (["--profile", "ci"], "ci"), "dev": ([], "debug")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path, help="where to place the admitted cw")
    destination.add_argument("--release-dir", type=Path,
                             help="new directory for the admitted cw and its cw-runtime.json")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="release")
    parser.add_argument("--target", help="cross-compile for this target with cargo-zigbuild (default: host)")
    args = parser.parse_args(argv)
    if "CODEWIRE_VERSION" in os.environ:
        version = os.environ["CODEWIRE_VERSION"]
    else:
        version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    rustc = subprocess.check_output([os.environ.get("RUSTC", "rustc"), "--version"], cwd=ROOT, text=True).strip()
    host = next((line.split(":", 1)[1].strip() for line in subprocess.check_output(
        [os.environ.get("RUSTC", "rustc"), "-vV"], cwd=ROOT, text=True).splitlines() if line.startswith("host:")), "")
    revision = release.head_revision(ROOT)
    tree = release.source_tree_sha256(ROOT)
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target")
    if not target_dir.is_absolute():
        target_dir = ROOT / target_dir
    cargo_home = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo")
    flags, profile_dir = PROFILES[args.profile]
    target = args.target or host
    build = ["build"] if target == host else ["zigbuild", "--target", target]
    command = [os.environ.get("CARGO", "cargo"), *build, "--locked", *flags, "-p", "codewire-cli-bin", "--bin", "cw"]
    environment = {**os.environ, "CARGO_TARGET_DIR": str(target_dir),
                   **release.build_environment(version, revision, tree)}
    subprocess.run(command, cwd=ROOT, env=environment, check=True)
    binary = target_dir / ("" if target == host else target) / profile_dir / "cw"
    data, identity, inputs = release.admit_build(
        ROOT, binary, binary.with_name("cw.d"), target, version, revision, tree, rustc,
        (target_dir, cargo_home / "registry", cargo_home / "git"), release.DEVELOPMENT_TARGETS)
    if args.release_dir is not None:
        write_release_dir(args.release_dir, data, identity)
    else:
        output = args.output.resolve()
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".cw.", delete=False) as temporary:
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary.name, 0o755)
        os.replace(temporary.name, output)
    print(f"build-cw: admitted cw {identity['package_version']} target={identity['target']} "
          f"source={identity['source_revision']} tree={identity['source_tree_sha256']} "
          f"inputs={inputs} sha256={identity['sha256']} size={identity['size']}")
    return 0


def write_release_dir(directory, data, identity):
    """Create a new release directory: the admitted cw beside its canonical identity.

    The same two files the cw image carries (see stage_release in
    scripts/ci/verify/kind/cw_runtime_assets.py). An existing path is refused,
    and a partial directory is removed rather than left looking complete.
    """
    release.require(hashlib.sha256(data).hexdigest() == identity["sha256"] and len(data) == identity["size"],
                    "admitted cw differs from its identity")
    directory = Path(directory)
    os.mkdir(directory, 0o700)
    try:
        release.write_new(directory / "cw", data, 0o500)
        release.write_new(directory / "cw-runtime.json", release.canonical(identity), 0o400)
    except BaseException:
        for name in ("cw", "cw-runtime.json"):
            (directory / name).unlink(missing_ok=True)
        directory.rmdir()
        raise


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, KeyError, subprocess.CalledProcessError, release.ReleaseError) as error:
        print(f"build-cw: {error}", file=sys.stderr)
        sys.exit(1)
