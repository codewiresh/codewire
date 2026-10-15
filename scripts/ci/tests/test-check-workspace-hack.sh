#!/usr/bin/env bash
# Fixture proof for the workspace-hack drift check: the pinned tool is
# installed exactly; a stale crate, a misplaced, missing or excluded member
# line, or a failed verification fails; and --fix leaves every member line
# under [dev-dependencies]. The check runs from a copy inside a synthetic
# workspace, so it reads only fixture manifests. A synthetic cargo-hakari
# records each call.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly SOURCE_CHECK="$ROOT/scripts/ci/verify/check-workspace-hack.sh"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/check-workspace-hack-test.XXXXXX")"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

fail() {
  printf '[test-check-workspace-hack] ERROR: %s\n' "$*" >&2
  exit 1
}

readonly HACK_LINE='codewire-workspace-hack.workspace = true'
ws="$work/ws"
readonly CHECK="$ws/scripts/ci/verify/check-workspace-hack.sh"
# A workspace in the accepted state: two members with the line under
# [dev-dependencies], one excluded member without it, and the hack crate.
new_workspace() {
  rm -rf -- "$ws"
  mkdir -p "$ws/scripts/ci/verify" "$ws/.config" "$ws/crates/a" "$ws/crates/b" "$ws/crates/excluded" \
    "$ws/crates/hack"
  cp "$SOURCE_CHECK" "$CHECK"
  cat >"$ws/Cargo.toml" <<'EOF'
[workspace]
resolver = "2"
members = [
    "crates/a",
    "crates/b",
    "crates/excluded",
    "crates/hack",
]
EOF
  cat >"$ws/.config/hakari.toml" <<'EOF'
hakari-package = "codewire-workspace-hack"
[final-excludes]
workspace-members = ["excluded"]
EOF
  cat >"$ws/crates/a/Cargo.toml" <<EOF
[package]
name = "a"

[dependencies]
serde = "1"

[dev-dependencies]
tempfile = "3"
$HACK_LINE
EOF
  cat >"$ws/crates/b/Cargo.toml" <<EOF
[package]
name = "b"

[target.'cfg(target_os = "linux")'.dependencies]
libc = "0.2"

[dev-dependencies]
$HACK_LINE
EOF
  cat >"$ws/crates/excluded/Cargo.toml" <<'EOF'
[package]
name = "excluded"

[dependencies]
serde = "1"
EOF
  printf '[package]\nname = "codewire-workspace-hack"\n' >"$ws/crates/hack/Cargo.toml"
}

calls="$work/calls"
tools="$work/tools"
# The synthetic tool fails the subcommand named in FAKE_HAKARI_FAIL. Like the
# real one, generate needs CARGO to update Cargo.lock.
fake_hakari() {
  mkdir -p "$tools/bin"
  cat >"$tools/bin/cargo-hakari" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'cargo-hakari %s\n' "$*" >>"$FAKE_CALLS"
[[ "$1" == hakari ]] || exit 64
case "$2" in
  --version) printf 'cargo-hakari %s\n' "${FAKE_HAKARI_VERSION:-0.9.39}" ;;
  generate)
    [[ "${FAKE_HAKARI_FAIL:-}" != "$2" ]]
    [[ "${3:-}" == --diff || -x "${CARGO:-}" ]] || exit 65
    ;;
  verify) [[ "${FAKE_HAKARI_FAIL:-}" != "$2" ]] ;;
  *) exit 64 ;;
esac
EOF
  chmod +x "$tools/bin/cargo-hakari"
}
cat >"$work/cargo" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'cargo %s target=%s\n' "\$*" "\$CARGO_TARGET_DIR" >>"\$FAKE_CALLS"
[[ "\$1" == install ]] || exit 64
mkdir -p "$tools/bin"
cp "$work/installed-hakari" "$tools/bin/cargo-hakari"
EOF
chmod +x "$work/cargo"

run_check() {
  : >"$calls"
  env -u CARGO FAKE_CALLS="$calls" CARGO_BIN="$work/cargo" CODEWIRE_CARGO_HAKARI_ROOT="$tools" "$@"
}

# Current: no install; the crate diff, the placement and verify are checked,
# and manage-deps (which writes [dependencies]) is never run.
fake_hakari
new_workspace
run_check "$CHECK" >"$work/out" 2>&1 || { cat "$work/out" >&2; fail 'current workspace hack failed'; }
grep -Fxq 'cargo-hakari hakari generate --diff' "$calls" || fail 'generate --diff not run'
grep -Fxq 'cargo-hakari hakari verify' "$calls" || fail 'verify not run'
! grep -q 'manage-deps' "$calls" || fail 'the check consulted manage-deps'
! grep -q '^cargo install' "$calls" || fail 'installed an already current tool'

# A stale crate or a failed verification fails, and staleness names the repair.
for part in generate verify; do
  if run_check FAKE_HAKARI_FAIL="$part" "$CHECK" >"$work/out" 2>&1; then
    fail "a failing $part passed"
  fi
done
run_check FAKE_HAKARI_FAIL=generate "$CHECK" >"$work/out" 2>&1 || true
grep -Fq 'run scripts/ci/verify/check-workspace-hack.sh --fix' "$work/out" ||
  fail 'stale crate does not name the repair'

# Each misplaced, missing or excluded line fails before verification and
# names the member and the repair.
placement_case() {
  local name="$1" member="$2" edit="$3"
  new_workspace
  python3 -I -B - "$ws/crates/$member/Cargo.toml" "$edit" <<'PY'
import sys
from pathlib import Path
path, edit = Path(sys.argv[1]), sys.argv[2]
line = "codewire-workspace-hack.workspace = true"
text = path.read_text()
if edit == "normal":
    text = text.replace(line + "\n", "").replace("[dependencies]\n", "[dependencies]\n" + line + "\n")
elif edit == "both":
    text = text.replace("[dependencies]\n", "[dependencies]\n" + line + "\n")
elif edit == "missing":
    text = text.replace(line + "\n", "")
elif edit == "excluded":
    text += "\n[dev-dependencies]\n" + line + "\n"
elif edit == "build":
    text = text.replace(line + "\n", "") + "\n[build-dependencies]\n" + line + "\n"
elif edit == "target":
    text = text.replace("libc = \"0.2\"\n", "libc = \"0.2\"\n" + line + "\n")
elif edit == "shape":
    text = text.replace(line, 'codewire-workspace-hack = { workspace = true, optional = true }')
else:
    raise SystemExit("unknown edit " + edit)
path.write_text(text)
PY
  if run_check "$CHECK" >"$work/out" 2>&1; then
    fail "placement case $name passed"
  fi
  grep -Fq "workspace-hack placement: crates/$member:" "$work/out" || {
    cat "$work/out" >&2; fail "placement case $name does not name crates/$member"
  }
  grep -Fq 'run scripts/ci/verify/check-workspace-hack.sh --fix' "$work/out" ||
    fail "placement case $name does not name the repair"
  ! grep -Fxq 'cargo-hakari hakari verify' "$calls" || fail "placement case $name reached verify"
}
placement_case normal-dependency a normal
placement_case normal-and-dev a both
placement_case missing b missing
placement_case excluded-member excluded excluded
placement_case build-dependency a build
placement_case target-dependency b target
placement_case extra-keys a shape

# --fix regenerates the crate, moves a member line under [dev-dependencies],
# adds a missing one and removes an excluded member's line.
new_workspace
cp -R "$ws" "$work/accepted"
python3 -I -B - "$ws" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
line = "codewire-workspace-hack.workspace = true"
a = root / "crates/a/Cargo.toml"
a.write_text(a.read_text().replace(line + "\n", "").replace("[dependencies]\n", "[dependencies]\n" + line + "\n"))
b = root / "crates/b/Cargo.toml"
b.write_text(b.read_text().replace(line + "\n", ""))
excluded = root / "crates/excluded/Cargo.toml"
excluded.write_text(excluded.read_text() + "\n[dev-dependencies]\n" + line + "\n")
PY
run_check "$CHECK" --fix >"$work/out" 2>&1 || { cat "$work/out" >&2; fail '--fix failed'; }
grep -Fxq 'cargo-hakari hakari generate --quiet' "$calls" || fail '--fix skipped generate'
! grep -q 'manage-deps\|diff\|verify' "$calls" || fail '--fix ran more than generate'
for member in a b; do
  cmp -s "$ws/crates/$member/Cargo.toml" "$work/accepted/crates/$member/Cargo.toml" ||
    fail "--fix did not restore crates/$member to its accepted placement"
done
grep -Fq 'codewire-workspace-hack' "$ws/crates/excluded/Cargo.toml" && fail '--fix kept the excluded line'
run_check "$CHECK" >"$work/out" 2>&1 || { cat "$work/out" >&2; fail 'the check refused the --fix result'; }
cp -R "$ws" "$work/fixed"
run_check "$CHECK" --fix >/dev/null 2>&1 || fail 'a second --fix failed'
diff -r "$work/fixed" "$ws" >/dev/null || fail '--fix is not idempotent'

# A member without [dev-dependencies] gains the table.
new_workspace
printf '[package]\nname = "b"\n\n' >"$ws/crates/b/Cargo.toml"
run_check "$CHECK" --fix >/dev/null 2>&1 || fail '--fix failed for a member without dev-dependencies'
[[ "$(<"$ws/crates/b/Cargo.toml")" == $'[package]\nname = "b"\n\n[dev-dependencies]\n'"$HACK_LINE" ]] ||
  fail "--fix left a member without dev-dependencies as: $(<"$ws/crates/b/Cargo.toml")"
if run_check "$CHECK" --diff >/dev/null 2>&1; then
  fail 'an unknown argument was accepted'
fi

# A missing or different tool installs exactly the pinned version, locked,
# into its own root, building outside every product target directory.
new_workspace
cp "$tools/bin/cargo-hakari" "$work/installed-hakari"
rm -rf -- "$tools"
run_check CARGO_TARGET_DIR="$work/product-target" "$CHECK" >/dev/null 2>&1 ||
  fail 'install path failed'
grep -Fxq "cargo install --locked --quiet --force --root $tools cargo-hakari --version =0.9.39 target=$tools.build" \
  "$calls" || fail 'install is not the exact locked pin'
[[ ! -e "$tools.build" ]] || fail 'install left its build directory'
fake_hakari
if run_check FAKE_HAKARI_VERSION=0.9.38 "$CHECK" >/dev/null 2>&1; then
  fail 'a different installed version was used'
fi
grep -q '^cargo install' "$calls" || fail 'a different version was not replaced'

printf '[test-check-workspace-hack] pinned install, drift, dev-dependency placement, --fix and verification: OK\n'
