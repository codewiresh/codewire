#!/usr/bin/env bash
# Keep crates/codewire-workspace-hack equal to cargo-hakari's output for the
# current manifests and Cargo.lock (.config/hakari.toml), with every member's
# dependency on it. A stale hack still builds, but it unifies less and can keep
# a removed dependency in the graph.
#
# Members take the hack as a dev-dependency, never a normal or build one.
# Cargo activates dev-dependencies only for builds that compile tests,
# examples or benches, so test, all-target check and clippy builds share one
# unified feature set while the shipped binaries keep exactly their own
# dependency graph. cargo-hakari's manage-deps only writes the line under
# [dependencies], so this script places and checks the member lines itself.
#
#   check-workspace-hack.sh         fail on any difference
#   check-workspace-hack.sh --fix   regenerate the crate and the member lines
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly CARGO_HAKARI_VERSION='0.9.39'
CARGO_BIN="${CARGO_BIN:-cargo}"
# generate runs `$CARGO tree` to update Cargo.lock. Only `cargo hakari` sets
# CARGO; called directly, the tool otherwise runs ./cargo.
CARGO="${CARGO:-$(command -v "$CARGO_BIN")}"
export CARGO

mode=check
case "$*" in
  '') ;;
  --fix) mode=fix ;;
  *)
    printf 'usage: %s [--fix]\n' "$0" >&2
    exit 2
    ;;
esac

# The exact tool is installed once per Cargo home from its own published
# Cargo.lock, in a versioned directory that stays off PATH.
tools_root="${CODEWIRE_CARGO_HAKARI_ROOT:-${CARGO_HOME:-${HOME:?HOME is required}/.cargo}/codewire-tools/cargo-hakari-$CARGO_HAKARI_VERSION}"
hakari="$tools_root/bin/cargo-hakari"
if [[ "$("$hakari" hakari --version 2>/dev/null || true)" != "cargo-hakari $CARGO_HAKARI_VERSION" ]]; then
  printf '[workspace-hack] installing cargo-hakari %s\n' "$CARGO_HAKARI_VERSION"
  build_dir="$tools_root.build"
  CARGO_TARGET_DIR="$build_dir" "$CARGO_BIN" install --locked --quiet --force \
    --root "$tools_root" cargo-hakari --version "=$CARGO_HAKARI_VERSION"
  rm -rf -- "$build_dir"
  [[ "$("$hakari" hakari --version)" == "cargo-hakari $CARGO_HAKARI_VERSION" ]] || {
    printf 'cargo-hakari %s did not install at %s\n' "$CARGO_HAKARI_VERSION" "$hakari" >&2
    exit 1
  }
fi

# placement check|fix: every workspace member except the hack and the
# final-excludes has exactly `codewire-workspace-hack.workspace = true` in
# [dev-dependencies] and in no other dependency table; excluded members have
# none. fix removes every one-line declaration of the hack and adds the line
# at the end of [dev-dependencies] of each member that takes it.
placement() {
  python3 -I -B - "$ROOT" "$1" <<'PY'
import re
import sys
import tomllib
from pathlib import Path

root, mode = Path(sys.argv[1]), sys.argv[2]
config = tomllib.loads((root / ".config/hakari.toml").read_text())
hack = config["hakari-package"]
excluded = set(config.get("final-excludes", {}).get("workspace-members", []))
members = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["members"]
if any(c in member for member in members for c in "*?["):
    sys.exit("workspace-hack placement: member globs are not supported")
LINE = f"{hack}.workspace = true"
DECLARATION = re.compile(rf"^\s*{re.escape(hack)}\s*[.=]")
DEV_HEADER = re.compile(r"^\[dev-dependencies\]\s*(#.*)?$")
KINDS = ("dependencies", "dev-dependencies", "build-dependencies")


def tables(manifest):
    """Every dependency table that names the hack."""
    found = [kind for kind in KINDS if hack in manifest.get(kind, {})]
    for target, document in manifest.get("target", {}).items():
        found += [f"target.{target}.{kind}" for kind in KINDS if hack in document.get(kind, {})]
    return found


def accepted(name, manifest):
    if name in excluded:
        return not tables(manifest)
    return tables(manifest) == ["dev-dependencies"] and manifest["dev-dependencies"][hack] == {"workspace": True}


def place(name, path):
    lines = [line for line in path.read_text().splitlines() if not DECLARATION.match(line)]
    if name not in excluded:
        header = next((i for i, line in enumerate(lines) if DEV_HEADER.match(line)), None)
        if header is None:
            while lines and not lines[-1].strip():
                lines.pop()
            lines += ["", "[dev-dependencies]"]
            header = len(lines) - 1
        end = next((i for i in range(header + 1, len(lines)) if lines[i].startswith("[")), len(lines))
        while end > header + 1 and not lines[end - 1].strip():
            end -= 1
        lines.insert(end, LINE)
    path.write_text("\n".join(lines) + "\n")


problems = []
for member in members:
    path = root / member / "Cargo.toml"
    manifest = tomllib.loads(path.read_text())
    name = manifest["package"]["name"]
    if name == hack or accepted(name, manifest):
        continue
    if mode == "fix":
        place(name, path)
        manifest = tomllib.loads(path.read_text())
        if accepted(name, manifest):
            continue
    want = "no dependency on it" if name in excluded else f"exactly `{LINE}` under [dev-dependencies] only"
    problems.append(f"{member}: {hack} needs {want} (found: {', '.join(tables(manifest)) or 'none'})")
for problem in problems:
    print(f"workspace-hack placement: {problem}", file=sys.stderr)
sys.exit(1 if problems else 0)
PY
}

cd "$ROOT"
if [[ "$mode" == fix ]]; then
  "$hakari" hakari generate --quiet
  placement fix
  printf '[workspace-hack] regenerated\n'
  exit 0
fi

stale=false
"$hakari" hakari generate --diff || stale=true
placement check || stale=true
if [[ "$stale" == true ]]; then
  printf 'crates/codewire-workspace-hack is stale; run scripts/ci/verify/check-workspace-hack.sh --fix\n' >&2
  exit 1
fi
# With the hack in the build, every member alone must select the same
# third-party features as the whole workspace.
"$hakari" hakari verify
printf '[workspace-hack] OK\n'
