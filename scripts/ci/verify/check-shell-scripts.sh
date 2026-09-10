#!/usr/bin/env bash
# Fail on every unreviewed warning from the exact repository ShellCheck.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/ci/verify/shellcheck-baseline.sh
source "$ROOT/scripts/ci/verify/shellcheck-baseline.sh"

normalize_baseline() {
  awk '
    /^[[:space:]]*#/ || NF == 0 { next }
    NF != 4 { invalid = 1; next }
    $2 !~ /^SC[0-9]+$/ || $3 !~ /^[0-9]+$/ || $4 !~ /^[a-z0-9-]+$/ {
      invalid = 1
      next
    }
    { print $1 "\t" $2 "\t" $3 }
    END { if (invalid) exit 1 }
  ' | LC_ALL=C sort
}

group_findings() {
  jq -r '
    .comments
    | group_by([.file, .code])[]
    | "\(.[0].file)\tSC\(.[0].code)\t\(length)"
  ' | LC_ALL=C sort
}

compare_findings() {
  local expected="$1"
  local actual="$2"

  if [[ "$expected" == "$actual" ]]; then
    return 0
  fi
  diff -u \
    <(printf '%s\n' "$expected") \
    <(printf '%s\n' "$actual") >&2 || true
  return 1
}

self_test() {
  local expected actual

  expected="$(printf '%s\n' \
    '# path code count reason' \
    'fixture/a.sh SC2034 2 intentional-fixture' \
    | normalize_baseline)"
  actual="$(printf '%s\n' '{"comments":[{"file":"fixture/a.sh","code":2034},{"file":"fixture/a.sh","code":2034}]}' | group_findings)"
  compare_findings "$expected" "$actual" || {
    printf 'ShellCheck baseline self-test rejected an exact match\n' >&2
    return 1
  }
  if compare_findings "$expected" "fixture/a.sh"$'\t'"SC2034"$'\t'"3" 2>/dev/null; then
    printf 'ShellCheck baseline self-test accepted a changed count\n' >&2
    return 1
  fi
  printf 'ShellCheck warning-ratchet self-test: OK\n'
}

if [[ "${1:-}" == --self-test ]]; then
  [[ $# -eq 1 ]] || {
    printf 'usage: check-shell-scripts.sh [--self-test]\n' >&2
    exit 2
  }
  self_test
  exit 0
fi
[[ $# -eq 0 ]] || {
  printf 'usage: check-shell-scripts.sh [--self-test]\n' >&2
  exit 2
}

cd "$ROOT"
# The full tracked-script analysis takes roughly three minutes on CI workers;
# retain a bounded deadline with headroom for ordinary runner variance.
shellcheck_timeout_seconds="${SHELLCHECK_TIMEOUT_SECONDS:-300}"
if [[ ! "$shellcheck_timeout_seconds" =~ ^[0-9]+$ ]] \
    || (( 10#$shellcheck_timeout_seconds < 1 )) \
    || (( 10#$shellcheck_timeout_seconds > 900 )); then
  printf 'SHELLCHECK_TIMEOUT_SECONDS must be an integer from 1 through 900\n' >&2
  exit 2
fi
shellcheck_bin="$(scripts/ci/setup/setup-shellcheck.sh)"
mapfile -d '' shell_files < <(
  git ls-files -z -- '*.sh'
)
[[ "${#shell_files[@]}" -gt 0 ]] || {
  printf 'ShellCheck policy found no tracked shell scripts\n' >&2
  exit 1
}

printf 'ShellCheck analysis: start (scripts=%s timeout_seconds=%s)\n' \
  "${#shell_files[@]}" "$shellcheck_timeout_seconds"
shellcheck_started_at=$SECONDS
set +e
findings_json="$(timeout --foreground --signal=TERM --kill-after=5s \
  "${shellcheck_timeout_seconds}s" \
  "$shellcheck_bin" --severity=warning --format=json1 "${shell_files[@]}")"
shellcheck_status=$?
set -e
shellcheck_elapsed_seconds=$((SECONDS - shellcheck_started_at))
printf 'ShellCheck analysis: finish (status=%s elapsed_seconds=%s)\n' \
  "$shellcheck_status" "$shellcheck_elapsed_seconds"
if [[ "$shellcheck_status" -eq 124 || "$shellcheck_status" -eq 137 ]]; then
  printf 'ShellCheck timed out after %s seconds\n' \
    "$shellcheck_timeout_seconds" >&2
  exit "$shellcheck_status"
fi
if [[ "$shellcheck_status" -gt 1 ]]; then
  printf 'ShellCheck failed with status %s\n' "$shellcheck_status" >&2
  exit "$shellcheck_status"
fi

expected_findings="$(printf '%s\n' "$SHELLCHECK_BASELINE_TSV" | normalize_baseline)"
actual_findings="$(printf '%s\n' "$findings_json" | group_findings)"
compare_findings "$expected_findings" "$actual_findings" || {
  printf 'ShellCheck warning set differs from the reviewed baseline\n' >&2
  exit 1
}
printf 'ShellCheck warning ratchet: OK (%s scripts, %s reviewed groups)\n' \
  "${#shell_files[@]}" \
  "$(printf '%s\n' "$SHELLCHECK_BASELINE_TSV" \
    | awk '/^[^#[:space:]]/ { count++ } END { print count + 0 }')"
