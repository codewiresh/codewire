#!/usr/bin/env bash
# Build the Python SDK (codewire on PyPI) as one sdist and one wheel.
#
# usage: package-sdk-python.sh OUTDIR
#
# The build runs offline from hash-pinned build tools, carries the generated
# public API (codewire/v1 and google/rpc) into both archives, and refuses an
# archive that is missing it or leaks a private generated package (admin,
# console, internal or testing). CI's Python SDK check and the PyPI release
# build the same two files this way.
set -euo pipefail

[[ $# -eq 1 ]] || {
  printf 'usage: package-sdk-python.sh OUTDIR\n' >&2
  exit 2
}
root="$(cd "$(dirname "$0")/../../.." && pwd)"
mkdir -p "$1"
outdir="$(cd "$1" && pwd)"

work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-sdk-python-build.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

python3 -m venv "$work/venv"
"$work/venv/bin/python" -m pip install --quiet --require-hashes \
  -r "$root/libs/sdk-python/requirements-pip.lock"
"$work/venv/bin/python" -m pip install --quiet --require-hashes \
  -r "$root/libs/sdk-python/requirements-build.lock"
"$work/venv/bin/python" -m build --no-isolation --outdir "$work/dist" "$root/libs/sdk-python"
sdist="$(find "$work/dist" -maxdepth 1 -type f -name '*.tar.gz' -print -quit)"
wheel="$(find "$work/dist" -maxdepth 1 -type f -name '*.whl' -print -quit)"
[[ -n "$sdist" && -n "$wheel" ]] || {
  printf '[package-sdk-python] ERROR: the build wrote no sdist and wheel\n' >&2
  exit 1
}
python3 - "$sdist" "$wheel" <<'PY'
import sys
import tarfile
import zipfile

sdist_path, wheel_path = sys.argv[1:]
forbidden = ("codewire/admin/", "codewire/console/", "codewire/internal/", "codewire/testing/")

with tarfile.open(sdist_path, "r:gz") as archive:
    sdist_names = [name.split("/", 1)[-1] for name in archive.getnames()]
if not any(name.startswith("_codewire_generated/codewire/v1/") for name in sdist_names):
    raise SystemExit("Python SDK sdist is missing generated codewire/v1")
if not any(name.startswith("_codewire_generated/google/rpc/") for name in sdist_names):
    raise SystemExit("Python SDK sdist is missing generated google/rpc")
if any(any(part in name for part in forbidden) for name in sdist_names):
    raise SystemExit("Python SDK sdist leaked a forbidden generated package")

with zipfile.ZipFile(wheel_path) as archive:
    wheel_names = archive.namelist()
if not any(name.startswith("codewire/v1/") for name in wheel_names):
    raise SystemExit("Python SDK wheel is missing generated codewire/v1")
if not any(name.startswith("google/rpc/") for name in wheel_names):
    raise SystemExit("Python SDK wheel is missing generated google/rpc")
if any(name.startswith("_codewire_generated/") for name in wheel_names):
    raise SystemExit("Python SDK wheel leaked its sdist-only generated source")
if any(any(part in name for part in forbidden) for name in wheel_names):
    raise SystemExit("Python SDK wheel leaked a forbidden generated package")
PY
cp "$sdist" "$wheel" "$outdir/"
printf '[package-sdk-python] wrote %s and %s\n' "$outdir/${sdist##*/}" "$outdir/${wheel##*/}"
