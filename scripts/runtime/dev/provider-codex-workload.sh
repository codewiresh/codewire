#!/usr/bin/env bash
# Runs only the pinned stock Codex command and emits a fixed public result.
set -euo pipefail
[[ "$-" != *x* ]] || { printf 'CW_LIVE_CODEX_ERROR\n' >&2; exit 1; }
umask 077

readonly CODEX_BIN=/opt/codewire/agents/npm/bin/codex
readonly EXPECTED_VERSION='codex-cli 0.149.0'
readonly CAPTURE_LIMIT_BYTES=1048576
readonly EXPECTED_CODEX_HOME=/run/codewire-agent/codex
readonly SCRATCH_PARENT=/dev/shm
readonly WORKLOAD_DIR=/workspace/.cw-provider-codex
readonly OUTPUT_PARSER="$WORKLOAD_DIR/provider-codex-output.py"

provider_codex_remove_capture() {
  local scratch="${1:-}"
  [[ -n "$scratch" && "$scratch" == "$SCRATCH_PARENT"/.cw-live-codex.?????? &&
    -d "$scratch" && ! -L "$scratch" && "$(stat -c '%u:%a' "$scratch" 2>/dev/null)" == "$(id -u):700" ]] || return 1
  rm -f -- "$scratch/version.out" "$scratch/version.err" "$scratch/events.jsonl" "$scratch/codex.err" &&
    rmdir -- "$scratch"
}

provider_codex_capture_bounded() {
  local capture="$1" size
  [[ -f "$capture" && ! -L "$capture" &&
    "$(stat -c '%u:%a' "$capture")" == "$(id -u):600" ]] || return 1
  size="$(stat -c '%s' "$capture")"
  [[ "$size" =~ ^[0-9]+$ && "$size" -lt "$CAPTURE_LIMIT_BYTES" ]]
}

provider_codex_apply_limits() {
  local effective
  set +o posix || return 1
  unset POSIXLY_CORRECT
  builtin ulimit -S -c 0 || return 1
  builtin ulimit -H -c 0 || return 1
  # In normal Bash, -f is expressed in 1024-byte blocks. Verify the kernel's
  # exact effective values below as the authority instead of trusting units.
  builtin ulimit -S -f 1024 || return 1
  builtin ulimit -H -f 1024 || return 1
  effective="$(awk '
    $1 == "Max" && $2 == "core" && $3 == "file" && $4 == "size" {print "core=" $5 ":" $6 ":" $7}
    $1 == "Max" && $2 == "file" && $3 == "size" {print "file=" $4 ":" $5 ":" $6}
  ' "/proc/$BASHPID/limits")" || return 1
  [[ "$effective" == $'file=1048576:1048576:bytes\ncore=0:0:bytes' ]]
}

provider_codex_exit_cleanup() {
  local status=$?
  trap - EXIT
  provider_codex_remove_capture "$scratch" || status=1
  exit "$status"
}

provider_codex_run() (
  local capture scratch='' rc=0
  [[ "${CODEX_HOME:-}" == "$EXPECTED_CODEX_HOME" && -d "$CODEX_HOME" && ! -L "$CODEX_HOME" ]] || return 1
  [[ -d "$SCRATCH_PARENT" && ! -L "$SCRATCH_PARENT" &&
    "$(realpath -e -- "$SCRATCH_PARENT" 2>/dev/null)" == "$SCRATCH_PARENT" &&
    "$(findmnt -nro FSTYPE -T "$SCRATCH_PARENT" 2>/dev/null)" == tmpfs ]] || return 1
  [[ -x "$CODEX_BIN" && -f "$OUTPUT_PARSER" && ! -L "$OUTPUT_PARSER" ]] || return 1
  timeout --version 2>/dev/null | grep -q '^timeout (GNU coreutils) ' || return 1
  scratch="$(mktemp -d "$SCRATCH_PARENT/.cw-live-codex.XXXXXX" 2>/dev/null)" || return 1
  trap provider_codex_exit_cleanup EXIT
  [[ "$(stat -c '%u:%a' "$scratch" 2>/dev/null)" == "$(id -u):700" ]] || return 1
  trap 'exit 1' HUP INT TERM
  for capture in version.out version.err events.jsonl codex.err; do
    install -m 0600 /dev/null "$scratch/$capture" >/dev/null 2>&1 || return 1
  done

  (
    provider_codex_apply_limits || exit 1
    timeout --kill-after=5s 10s "$CODEX_BIN" --version </dev/null \
      >"$scratch/version.out" 2>"$scratch/version.err"
  ) || rc=1
  provider_codex_capture_bounded "$scratch/version.out" || rc=1
  provider_codex_capture_bounded "$scratch/version.err" || rc=1
  [[ "$rc" == 0 && ! -s "$scratch/version.err" &&
    "$(cat "$scratch/version.out")" == "$EXPECTED_VERSION" ]] || return 1

  (
    provider_codex_apply_limits || exit 1
    timeout --kill-after=5s 120s "$CODEX_BIN" exec --strict-config --ephemeral --json \
      --color never --sandbox read-only --skip-git-repo-check --cd /workspace \
      'Reply with exactly CW_LIVE_CODEX_OK. Do not use tools or inspect files.' \
      </dev/null >"$scratch/events.jsonl" 2>"$scratch/codex.err"
  ) || rc=1
  provider_codex_capture_bounded "$scratch/events.jsonl" || rc=1
  provider_codex_capture_bounded "$scratch/codex.err" || rc=1
  [[ "$rc" == 0 ]] || return 1
  /usr/bin/python3 "$OUTPUT_PARSER" "$scratch/events.jsonl" >/dev/null 2>&1 || return 1
  return 0
)

main() {
  [[ "$#" == 1 && "$1" == run ]] || { printf 'CW_LIVE_CODEX_ERROR\n' >&2; return 2; }
  if provider_codex_run >/dev/null 2>&1; then
    printf 'CW_LIVE_CODEX_OK\n'
  else
    printf 'CW_LIVE_CODEX_ERROR\n' >&2
    return 1
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
