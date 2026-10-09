#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/local-prepush-receipt.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf '[test-local-prepush-receipt] ERROR: %s\n' "$*" >&2
  exit 1
}

assert_reason() {
  local expected="$1"
  shift
  local output
  if output="$("$@" 2>&1)"; then
    printf '%s\n' "$output" >&2
    fail "expected receipt rejection: $expected"
  fi
  grep -Fxq "reason=$expected" <<<"$output" || {
    printf '%s\n' "$output" >&2
    fail "expected reason=$expected"
  }
}

repo="$TMP/repo"
remote="$TMP/remote.git"
git init -q -b main "$repo"
git -C "$repo" config gc.auto 0
git -C "$repo" config maintenance.auto false
git init -q --bare "$remote"
git -C "$remote" config gc.auto 0
git -C "$remote" config maintenance.auto false
git -C "$repo" config user.name 'Receipt Fixture'
git -C "$repo" config user.email receipt-fixture@codewire.invalid
mkdir -p "$repo/scripts/ci/receipts" "$repo/scripts/ci/select" "$repo/docs"
install -m 755 "$ROOT/scripts/ci/receipts/local-prepush-receipt.py" \
  "$repo/scripts/ci/receipts/local-prepush-receipt.py"
install -m 755 "$ROOT/scripts/ci/select/select-verification.sh" \
  "$repo/scripts/ci/select/select-verification.sh"
printf 'base\n' > "$repo/docs/base.md"
git -C "$repo" add -A
git -C "$repo" -c commit.gpgsign=false commit -q -m 'test: seed receipt fixture'
git -C "$repo" remote add origin "$remote"
git -C "$repo" push -q -u origin main

git -C "$repo" switch -q -c feature
printf 'feature\n' > "$repo/docs/feature.md"
git -C "$repo" add docs/feature.md
git -C "$repo" -c commit.gpgsign=false commit -q -m 'test: add receipt candidate'

helper="$repo/scripts/ci/receipts/local-prepush-receipt.py"
base="$(git -C "$repo" rev-parse origin/main)"
head="$(git -C "$repo" rev-parse HEAD)"
paths="$TMP/paths"
printf 'docs/feature.md\n' > "$paths"
selector_output="$(
  cd "$repo"
  GITHUB_EVENT_NAME=pull_request KIND_E2E_OPT_IN=true \
    scripts/ci/select/select-verification.sh "$paths"
)"
selection="$(sed -n 's/^selection=//p' <<<"$selector_output")"
mode="$(sed -n 's/^required_local_mode=//p' <<<"$selector_output")"

verify_receipt() {
  (cd "$repo" && "$helper" verify --head "$head" --remote-name origin)
}

emit_wrong_mode() {
  (
    cd "$repo"
    "$helper" emit \
      --verified-base "$base" \
      --verified-mode full \
      --verified-selection "$selection"
  )
}

emit_wrong_selection() {
  (
    cd "$repo"
    "$helper" emit \
      --verified-base "$base" \
      --verified-mode "$mode" \
      --verified-selection '|valid:v3|complete|'
  )
}

assert_reason missing verify_receipt
assert_reason verified-mode-mismatch emit_wrong_mode
assert_reason verified-selection-mismatch emit_wrong_selection

emit_output="$(
  cd "$repo"
  "$helper" emit \
    --verified-base "$base" \
    --verified-mode "$mode" \
    --verified-selection "$selection"
)"
grep -Fxq 'receipt=emitted' <<<"$emit_output" || fail 'emit did not succeed'
receipt="$(sed -n 's/^receipt_path=//p' <<<"$emit_output")"
[ -f "$receipt" ] || fail 'receipt file is missing'
[ "$(stat -c '%a' "$receipt")" = 600 ] || fail 'receipt mode is not 0600'
[ "$(stat -c '%a' "$(dirname "$receipt")")" = 700 ] || \
  fail 'receipt directory mode is not 0700'
if find "$(dirname "$receipt")" -maxdepth 1 -name ".${head}.*" -print -quit | grep -q .; then
  fail 'atomic emit left a temporary file'
fi

verify_output="$(verify_receipt)"
grep -Fxq 'receipt=accepted' <<<"$verify_output" || fail 'exact receipt was rejected'
# Re-verification models an interrupted or rejected transport retry. Validation
# must not consume or delete an otherwise valid receipt.
cd "$repo"
"$helper" verify --head "$head" --remote-name origin >/dev/null
[ -f "$receipt" ] || fail 'verification consumed the receipt'
cd - >/dev/null

backup="$TMP/receipt.json"
cp "$receipt" "$backup"

chmod 0644 "$receipt"
assert_reason receipt-permissions-unsafe \
  verify_receipt
cp "$backup" "$receipt"
chmod 0600 "$receipt"

chmod 0755 "$(dirname "$receipt")"
assert_reason receipt-directory-unsafe \
  verify_receipt
chmod 0700 "$(dirname "$receipt")"

printf '{"schema":' > "$receipt"
chmod 0600 "$receipt"
assert_reason malformed verify_receipt
cp "$backup" "$receipt"
chmod 0600 "$receipt"

python3 - "$receipt" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    document = json.load(handle)
document["expires_at"] = document["created_at"] - 1
with open(path, "w", encoding="utf-8") as handle:
    json.dump(document, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
chmod 0600 "$receipt"
assert_reason expiry-invalid verify_receipt
cp "$backup" "$receipt"
chmod 0600 "$receipt"

python3 - "$receipt" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    document = json.load(handle)
document["created_at"] -= 9 * 60 * 60
document["expires_at"] -= 9 * 60 * 60
with open(path, "w", encoding="utf-8") as handle:
    json.dump(document, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
chmod 0600 "$receipt"
assert_reason expired verify_receipt
cp "$backup" "$receipt"
chmod 0600 "$receipt"

python3 - "$receipt" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    document = json.load(handle)
document["result"] = "failure"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(document, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
chmod 0600 "$receipt"
assert_reason result-not-success verify_receipt
cp "$backup" "$receipt"
chmod 0600 "$receipt"

python3 - "$receipt" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    document = json.load(handle)
document["plan"]["selection"] = "|valid:v3|complete|"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(document, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
chmod 0600 "$receipt"
assert_reason plan-mismatch verify_receipt
cp "$backup" "$receipt"
chmod 0600 "$receipt"

printf 'dirty\n' > "$repo/untracked.txt"
assert_reason dirty-worktree verify_receipt
rm "$repo/untracked.txt"

other="$TMP/other-worktree"
git -C "$repo" worktree add -q -b other-worktree "$other" "$head"
other_helper="$other/scripts/ci/receipts/local-prepush-receipt.py"
other_path="$(cd "$other" && "$other_helper" path --head "$head" --remote-name origin)"
mkdir -p "$(dirname "$other_path")"
chmod 0700 "$(dirname "$other_path")"
cp "$backup" "$other_path"
chmod 0600 "$other_path"
verify_other_receipt() {
  (cd "$other" && "$other_helper" verify --head "$head" --remote-name origin)
}
assert_reason worktree-mismatch \
  verify_other_receipt

new_base="$(
  printf 'test: synthetic newer canonical base\n' |
    git -C "$repo" commit-tree "${base}^{tree}" -p "$base"
)"
git -C "$repo" update-ref refs/remotes/origin/main "$new_base"
assert_reason source-mismatch verify_receipt
git -C "$repo" update-ref refs/remotes/origin/main "$base"

cp "$backup" "$receipt"
chmod 0600 "$receipt"
verify_receipt >/dev/null

printf '[test-local-prepush-receipt] atomicity and invalidation cases passed\n'
