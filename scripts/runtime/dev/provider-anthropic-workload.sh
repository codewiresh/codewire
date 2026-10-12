#!/usr/bin/env bash
# Runs only the pinned stock Claude command and emits a fixed public result.
set -euo pipefail
[[ "$-" != *x* ]] || { printf 'CW_LIVE_CLAUDE_ERROR\n' >&2; exit 1; }
umask 077

readonly CLAUDE_BIN=/opt/codewire/agents/npm/bin/claude
readonly EXPECTED_VERSION='2.1.288 (Claude Code)'
readonly EXPECTED_ANTHROPIC_BASE_URL=http://127.0.0.1:38081/_codewire/anthropic
readonly EXPECTED_ANTHROPIC_AUTH_TOKEN=codewire-managed
readonly CAPTURE_LIMIT_BYTES=1048576
readonly SCRATCH_PARENT=/dev/shm
readonly WORKLOAD_DIR=/workspace/.cw-provider-anthropic
readonly OUTPUT_PARSER="$WORKLOAD_DIR/provider-anthropic-output.py"

provider_anthropic_remove_capture() {
  local scratch="${1:-}"
  [[ -n "$scratch" && "$scratch" == "$SCRATCH_PARENT"/.cw-live-anthropic.?????? &&
    -d "$scratch" && ! -L "$scratch" && "$(stat -c '%u:%a' "$scratch" 2>/dev/null)" == "$(id -u):700" ]] || return 1
  rm -f -- "$scratch/version.out" "$scratch/version.err" "$scratch/events.jsonl" "$scratch/claude.err" &&
    rmdir -- "$scratch"
}

provider_anthropic_capture_bounded() {
  local capture="$1" size
  [[ -f "$capture" && ! -L "$capture" &&
    "$(stat -c '%u:%a' "$capture")" == "$(id -u):600" ]] || return 1
  size="$(stat -c '%s' "$capture")"
  [[ "$size" =~ ^[0-9]+$ && "$size" -lt "$CAPTURE_LIMIT_BYTES" ]]
}

provider_anthropic_apply_limits() {
  local effective
  set +o posix || return 1
  unset POSIXLY_CORRECT
  builtin ulimit -S -c 0 || return 1
  builtin ulimit -H -c 0 || return 1
  builtin ulimit -S -f 1024 || return 1
  builtin ulimit -H -f 1024 || return 1
  effective="$(awk '
    $1 == "Max" && $2 == "core" && $3 == "file" && $4 == "size" {print "core=" $5 ":" $6 ":" $7}
    $1 == "Max" && $2 == "file" && $3 == "size" {print "file=" $4 ":" $5 ":" $6}
  ' "/proc/$BASHPID/limits")" || return 1
  [[ "$effective" == $'file=1048576:1048576:bytes\ncore=0:0:bytes' ]]
}

provider_anthropic_exit_cleanup() {
  local status=$?
  trap - EXIT
  provider_anthropic_remove_capture "$scratch" || status=1
  exit "$status"
}

provider_anthropic_run() (
  local capture scratch='' rc=0
  [[ "${ANTHROPIC_BASE_URL:-}" == "$EXPECTED_ANTHROPIC_BASE_URL" &&
    "${ANTHROPIC_AUTH_TOKEN:-}" == "$EXPECTED_ANTHROPIC_AUTH_TOKEN" &&
    "${ANTHROPIC_API_KEY+x}" == x && -z "$ANTHROPIC_API_KEY" &&
    "${CLAUDE_CODE_OAUTH_TOKEN+x}" == x && -z "$CLAUDE_CODE_OAUTH_TOKEN" ]] || return 1
  [[ -d "$SCRATCH_PARENT" && ! -L "$SCRATCH_PARENT" &&
    "$(realpath -e -- "$SCRATCH_PARENT" 2>/dev/null)" == "$SCRATCH_PARENT" &&
    "$(findmnt -nro FSTYPE -T "$SCRATCH_PARENT" 2>/dev/null)" == tmpfs ]] || return 1
  [[ -x "$CLAUDE_BIN" && -f "$OUTPUT_PARSER" && ! -L "$OUTPUT_PARSER" ]] || return 1
  timeout --version 2>/dev/null | grep -q '^timeout (GNU coreutils) ' || return 1
  scratch="$(mktemp -d "$SCRATCH_PARENT/.cw-live-anthropic.XXXXXX" 2>/dev/null)" || return 1
  trap provider_anthropic_exit_cleanup EXIT
  [[ "$(stat -c '%u:%a' "$scratch" 2>/dev/null)" == "$(id -u):700" ]] || return 1
  trap 'exit 1' HUP INT TERM
  for capture in version.out version.err events.jsonl claude.err; do
    install -m 0600 /dev/null "$scratch/$capture" >/dev/null 2>&1 || return 1
  done

  (
    provider_anthropic_apply_limits || exit 1
    timeout --kill-after=5s 10s "$CLAUDE_BIN" --version </dev/null \
      >"$scratch/version.out" 2>"$scratch/version.err"
  ) || rc=1
  provider_anthropic_capture_bounded "$scratch/version.out" || rc=1
  provider_anthropic_capture_bounded "$scratch/version.err" || rc=1
  [[ "$rc" == 0 && ! -s "$scratch/version.err" ]] || return 1
  cmp -s "$scratch/version.out" <(printf '%s\n' "$EXPECTED_VERSION") || return 1

  (
    provider_anthropic_apply_limits || exit 1
    # shellcheck disable=SC2016 # The child shell validates its inherited projection.
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 CLAUDE_CODE_MAX_RETRIES=0 \
      timeout --kill-after=5s 120s /bin/sh -c '
        test "${ANTHROPIC_BASE_URL-}" = "http://127.0.0.1:38081/_codewire/anthropic" &&
        test "${ANTHROPIC_AUTH_TOKEN-}" = codewire-managed &&
        test "${ANTHROPIC_API_KEY+x}" = x && test -z "$ANTHROPIC_API_KEY" &&
        test "${CLAUDE_CODE_OAUTH_TOKEN+x}" = x && test -z "$CLAUDE_CODE_OAUTH_TOKEN" &&
        exec "$@"
      ' codewire-live-anthropic "$CLAUDE_BIN" -p --model claude-sonnet-4-6 \
        --max-turns 1 --tools '' --strict-mcp-config --mcp-config '{"mcpServers":{}}' \
        --setting-sources '' --disable-slash-commands --no-session-persistence \
        --output-format stream-json --verbose --include-partial-messages \
        'Reply with exactly CW_LIVE_CLAUDE_OK. Do not use tools or inspect files.' \
        </dev/null >"$scratch/events.jsonl" 2>"$scratch/claude.err"
  ) || rc=1
  provider_anthropic_capture_bounded "$scratch/events.jsonl" || rc=1
  provider_anthropic_capture_bounded "$scratch/claude.err" || rc=1
  [[ "$rc" == 0 && ! -s "$scratch/claude.err" ]] || return 1
  /usr/bin/python3 "$OUTPUT_PARSER" "$scratch/events.jsonl" >/dev/null 2>&1 || return 1
  return 0
)

main() {
  [[ "$#" == 1 && "$1" == run ]] || { printf 'CW_LIVE_CLAUDE_ERROR\n' >&2; return 2; }
  if provider_anthropic_run >/dev/null 2>&1; then
    printf 'CW_LIVE_CLAUDE_OK\n'
  else
    printf 'CW_LIVE_CLAUDE_ERROR\n' >&2
    return 1
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
