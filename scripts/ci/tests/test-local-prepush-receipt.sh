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

rewrite_receipt() {
  # Rewrite one receipt field with a Python expression over `document`.
  python3 - "$receipt" "$1" <<'PY'
import json
import sys

path, statement = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    document = json.load(handle)
exec(statement)
with open(path, "w", encoding="utf-8") as handle:
    json.dump(document, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
  chmod 0600 "$receipt"
}

restore_receipt() {
  cp "$backup" "$receipt"
  chmod 0600 "$receipt"
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
# Local qualification mirrors pull-request CI without the Kind opt-in.
selector_output="$(
  cd "$repo"
  GITHUB_EVENT_NAME=pull_request KIND_E2E_OPT_IN=false \
    scripts/ci/select/select-verification.sh "$paths"
)"
selection="$(sed -n 's/^selection=//p' <<<"$selector_output")"
mode="$(sed -n 's/^required_local_mode=//p' <<<"$selector_output")"

verify_receipt() {
  (cd "$repo" && "$helper" verify --head "$head" --remote-name origin "$@")
}

verify_merge_receipt() {
  verify_receipt --accept-scope merge
}

emit_receipt() {
  local scope="$1" ran="$2" reused="${3:-}" not_run="${4:-}"
  (
    cd "$repo"
    "$helper" emit \
      --verified-base "$base" \
      --verified-mode "$mode" \
      --verified-selection "$selection" \
      --scope "$scope" --ran "$ran" --reused "$reused" --not-run "$not_run"
  )
}

emit_wrong_mode() {
  (
    cd "$repo"
    "$helper" emit \
      --verified-base "$base" \
      --verified-mode full \
      --verified-selection "$selection" \
      --scope merge --ran policy
  )
}

emit_wrong_selection() {
  (
    cd "$repo"
    "$helper" emit \
      --verified-base "$base" \
      --verified-mode "$mode" \
      --verified-selection '|valid:v3|complete|' \
      --scope merge --ran policy
  )
}

assert_reason missing verify_receipt
assert_reason verified-mode-mismatch emit_wrong_mode
assert_reason verified-selection-mismatch emit_wrong_selection
# The record of what ran is explicit and consistent: a receipt cannot claim
# that nothing ran, list a check twice, or carry a malformed name.
assert_reason execution-invalid emit_receipt merge ''
assert_reason execution-invalid emit_receipt merge policy policy
assert_reason execution-invalid emit_receipt merge policy '' policy
assert_reason execution-invalid emit_receipt merge 'Policy Verification'

# A push-scope receipt satisfies a feature-branch push, never a direct
# canonical-main update, which needs merge qualification.
push_output="$(emit_receipt push environment,rust-fmt '' merge-qualification)"
grep -Fxq 'scope=push' <<<"$push_output" || fail 'push receipt was not emitted'
push_receipt="$(sed -n 's/^receipt_path=//p' <<<"$push_output")"
push_verify="$(verify_receipt)"
grep -Fxq 'scope=push' <<<"$push_verify" || fail 'feature push rejected a push receipt'
grep -Fxq 'ran=environment,rust-fmt' <<<"$push_verify" || fail 'push receipt lost what ran'
grep -Fxq 'not_run=merge-qualification' <<<"$push_verify" ||
  fail 'push receipt hid that merge qualification did not run'
assert_reason missing verify_merge_receipt
# The legacy shared dispatcher passes --base only for a direct main update.
legacy_main_verify() {
  (cd "$repo" && "$helper" verify --head "$head" --base "$base" --remote-name origin)
}
assert_reason missing legacy_main_verify

emit_output="$(emit_receipt merge policy rust kind)"
grep -Fxq 'receipt=emitted' <<<"$emit_output" || fail 'emit did not succeed'
grep -Fxq 'scope=merge' <<<"$emit_output" || fail 'merge receipt was not emitted'
receipt="$(sed -n 's/^receipt_path=//p' <<<"$emit_output")"
[ -f "$receipt" ] || fail 'receipt file is missing'
[ -f "$push_receipt" ] || fail 'merge receipt replaced the push evidence'
[ "$(stat -c '%a' "$receipt")" = 600 ] || fail 'receipt mode is not 0600'
[ "$(stat -c '%a' "$(dirname "$receipt")")" = 700 ] || \
  fail 'receipt directory mode is not 0700'
if find "$(dirname "$receipt")" -maxdepth 1 -name ".${head}.*" -print -quit | grep -q .; then
  fail 'atomic emit left a temporary file'
fi
grep -Fq '"schema":"codewire.local-verification-receipt/v2"' "$receipt" ||
  fail 'receipt does not declare the v2 schema'
grep -Fq '"execution":{"not_run":["kind"],"ran":["policy"],"reused":["rust"],"scope":"merge"}' \
  "$receipt" || fail 'receipt does not record its execution'

verify_output="$(verify_merge_receipt)"
grep -Fxq 'receipt=accepted' <<<"$verify_output" || fail 'exact receipt was rejected'
grep -Fxq 'ran=policy' <<<"$verify_output" || fail 'merge receipt lost what ran'
grep -Fxq 'reused=rust' <<<"$verify_output" || fail 'merge receipt lost what it reused'
grep -Fxq 'not_run=kind' <<<"$verify_output" || fail 'merge receipt hid that Kind did not run'
grep -Fxq 'scope=merge' <<<"$(legacy_main_verify)" ||
  fail 'a direct main update rejected merge qualification'
# A feature push prefers the merge evidence, and a later push check never
# replaces it.
emit_receipt push environment >/dev/null
grep -Fxq 'scope=merge' <<<"$(verify_receipt)" ||
  fail 'feature push preferred push evidence over merge evidence'
# Re-verification models an interrupted or rejected transport retry. Validation
# must not consume or delete an otherwise valid receipt.
verify_merge_receipt >/dev/null
[ -f "$receipt" ] || fail 'verification consumed the receipt'

backup="$TMP/receipt.json"
cp "$receipt" "$backup"

chmod 0644 "$receipt"
assert_reason receipt-permissions-unsafe verify_merge_receipt
restore_receipt

chmod 0755 "$(dirname "$receipt")"
assert_reason receipt-directory-unsafe verify_merge_receipt
chmod 0700 "$(dirname "$receipt")"

printf '{"schema":' > "$receipt"
chmod 0600 "$receipt"
assert_reason malformed verify_merge_receipt
restore_receipt

rewrite_receipt 'document["expires_at"] = document["created_at"] - 1'
assert_reason expiry-invalid verify_merge_receipt
restore_receipt

rewrite_receipt 'document["created_at"] -= 9 * 60 * 60; document["expires_at"] -= 9 * 60 * 60'
assert_reason expired verify_merge_receipt
restore_receipt

rewrite_receipt 'document["result"] = "failure"'
assert_reason result-not-success verify_merge_receipt
restore_receipt

rewrite_receipt 'document["plan"]["selection"] = "|valid:v3|complete|"'
assert_reason plan-mismatch verify_merge_receipt
restore_receipt

# The execution record cannot be rewritten into stronger or inconsistent
# evidence: another scope, nothing executed, unknown keys or a check that is
# both executed and not run.
rewrite_receipt 'document["execution"]["scope"] = "push"'
assert_reason scope-mismatch verify_merge_receipt
restore_receipt
for execution in \
    '{"scope":"merge","ran":[],"reused":[],"not_run":["kind"]}' \
    '{"scope":"merge","ran":["policy"],"reused":[],"not_run":[],"extra":1}' \
    '{"scope":"merge","ran":["policy"],"reused":[],"not_run":["policy"]}' \
    '{"scope":"merge","ran":"policy","reused":[],"not_run":[]}'; do
  rewrite_receipt "document['execution'] = __import__('json').loads('$execution')"
  assert_reason execution-invalid verify_merge_receipt
  restore_receipt
done

# A v1 receipt carries no execution record and is not evidence here.
rewrite_receipt 'document["schema"] = "codewire.local-verification-receipt/v1"; del document["execution"]'
assert_reason schema-mismatch verify_merge_receipt
restore_receipt

printf 'dirty\n' > "$repo/untracked.txt"
assert_reason dirty-worktree verify_merge_receipt
rm "$repo/untracked.txt"

other="$TMP/other-worktree"
git -C "$repo" worktree add -q -b other-worktree "$other" "$head"
other_helper="$other/scripts/ci/receipts/local-prepush-receipt.py"
other_path="$(cd "$other" && "$other_helper" path --scope merge --head "$head" --remote-name origin)"
mkdir -p "$(dirname "$other_path")"
chmod 0700 "$(dirname "$other_path")"
cp "$backup" "$other_path"
chmod 0600 "$other_path"
verify_other_receipt() {
  (cd "$other" && "$other_helper" verify --head "$head" --remote-name origin --accept-scope merge)
}
assert_reason worktree-mismatch \
  verify_other_receipt

new_base="$(
  printf 'test: synthetic newer canonical base\n' |
    git -C "$repo" commit-tree "${base}^{tree}" -p "$base"
)"
git -C "$repo" update-ref refs/remotes/origin/main "$new_base"
assert_reason source-mismatch verify_merge_receipt
git -C "$repo" update-ref refs/remotes/origin/main "$base"

restore_receipt
verify_merge_receipt >/dev/null

printf '[test-local-prepush-receipt] scope, execution, atomicity and invalidation cases passed\n'
