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
"""
import argparse
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
    parser.add_argument("--output", type=Path, required=True, help="where to place the admitted cw")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="release")
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
    command = [os.environ.get("CARGO", "cargo"), "build", "--locked", *flags, "-p", "codewire-cli-bin", "--bin", "cw"]
    environment = {**os.environ, "CARGO_TARGET_DIR": str(target_dir),
                   **release.build_environment(version, revision, tree)}
    subprocess.run(command, cwd=ROOT, env=environment, check=True)
    binary = target_dir / profile_dir / "cw"
    data, identity, inputs = release.admit_build(
        ROOT, binary, binary.with_name("cw.d"), host, version, revision, tree, rustc,
        (target_dir, cargo_home / "registry", cargo_home / "git"), release.DEVELOPMENT_TARGETS)
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


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, KeyError, subprocess.CalledProcessError, release.ReleaseError) as error:
        print(f"build-cw: {error}", file=sys.stderr)
        sys.exit(1)
