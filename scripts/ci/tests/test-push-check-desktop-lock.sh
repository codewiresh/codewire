#!/usr/bin/env bash
# The fast push check reads the desktop's own lock whenever a workspace crate
# or the workspace changes, so a dependency change that leaves
# crates/codewire-desktop/Cargo.lock stale fails the push, not CI (#4019's
# first run). A desktop change runs the desktop's own locked check instead,
# and a change outside Rust reads nothing. Cargo is a stub that records its
# calls and fails the locked read while the fixture's lock is marked stale.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/push-check-desktop-lock.XXXXXX")"
trap 'rm -rf "$work"' EXIT

fail() {
  printf '[test-push-check-desktop-lock] ERROR: %s\n' "$*" >&2
  exit 1
}

repo="$work/repo"
mkdir -p "$repo/scripts/dev" "$repo/scripts/ci/verify" "$repo/crates/client/src" \
  "$repo/crates/codewire-desktop/src" "$repo/docs" "$work/bin"
install -m 755 "$ROOT/scripts/dev/preflight-push.sh" "$repo/scripts/dev/preflight-push.sh"
printf '#!/usr/bin/env bash\nexit 0\n' >"$repo/scripts/dev/preflight-environment.sh"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$CARGO_TARGET_DIR"\n' \
  >"$repo/scripts/ci/verify/resolve-cargo-target-dir.sh"
chmod 755 "$repo/scripts/dev/preflight-environment.sh" \
  "$repo/scripts/ci/verify/resolve-cargo-target-dir.sh"
printf '# shellcheck shell=bash\nselect_local_rust_cache() { return 0; }\n' \
  >"$repo/scripts/ci/verify/local-rust-cache.sh"
printf '[workspace]\nmembers = ["crates/client"]\nexclude = ["crates/codewire-desktop"]\n' \
  >"$repo/Cargo.toml"
printf '[package]\nname = "client"\n' >"$repo/crates/client/Cargo.toml"
: >"$repo/crates/client/src/lib.rs"
printf '[package]\nname = "codewire-desktop"\n' >"$repo/crates/codewire-desktop/Cargo.toml"
: >"$repo/crates/codewire-desktop/src/main.rs"
: >"$repo/docs/notes.md"

cat >"$work/bin/cargo" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FIXTURE_WORK/cargo-calls"
if [ "${1:-}" = metadata ] && [ -e "$FIXTURE_WORK/stale" ]; then
  echo 'error: the lock file crates/codewire-desktop/Cargo.lock needs to be updated but --locked was passed' >&2
  exit 101
fi
[ "${1:-}" = metadata ] && printf '{"packages":[]}\n'
exit 0
SH
chmod 755 "$work/bin/cargo"

# push_check PATH...: run the push check on exactly these changed paths,
# started from outside the repository like a hook from another directory.
push_check() {
  printf '%s\n' "$@" >"$work/changed"
  : >"$work/cargo-calls"
  (cd "$work" && FIXTURE_WORK="$work" CARGO_TARGET_DIR="$work/target" PATH="$work/bin:$PATH" \
    "$repo/scripts/dev/preflight-push.sh" "$work/changed" HEAD "$work/ran") >"$work/out" 2>&1
}
lock_read='metadata --locked --manifest-path crates/codewire-desktop/Cargo.toml --format-version=1 --all-features --filter-platform x86_64-unknown-linux-gnu'

push_check crates/client/src/lib.rs || { cat "$work/out" >&2; fail 'a workspace crate change failed with a fresh lock'; }
grep -qx desktop-lock "$work/ran" || fail 'a workspace crate change did not read the desktop lock'
grep -qxF "$lock_read" "$work/cargo-calls" ||
  { cat "$work/cargo-calls" >&2; fail 'the desktop lock was not read the way CI reads it'; }
if grep -Fq '{"packages"' "$work/out"; then
  fail 'the lock read printed its metadata into the push output'
fi

push_check Cargo.lock || { cat "$work/out" >&2; fail 'a workspace lock change failed with a fresh lock'; }
grep -qx desktop-lock "$work/ran" || fail 'a workspace lock change did not read the desktop lock'

touch "$work/stale"
if push_check crates/client/Cargo.toml; then
  fail 'a stale desktop lock passed the push check'
fi
grep -Fq 'push check desktop-lock FAILED' "$work/out" || fail 'the stale lock did not fail as the desktop-lock step'
grep -Fq 'needs to be updated but --locked was passed' "$work/out" ||
  fail 'the failure did not show cargo'\''s reason'
rm "$work/stale"

push_check crates/codewire-desktop/src/main.rs ||
  { cat "$work/out" >&2; fail 'a desktop change failed with a fresh lock'; }
grep -qx desktop-check "$work/ran" || fail 'a desktop change did not run the desktop check'
if grep -qx desktop-lock "$work/ran"; then
  fail 'a desktop change read the lock again beside its own locked check'
fi

push_check docs/notes.md || { cat "$work/out" >&2; fail 'a change outside Rust failed'; }
if [ -s "$work/cargo-calls" ]; then
  fail 'a change outside Rust ran cargo'
fi

printf '[test-push-check-desktop-lock] crate and lock changes read the desktop lock, a stale lock fails, desktop and non-Rust changes do not read it\n'
