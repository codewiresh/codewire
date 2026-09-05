#!/usr/bin/env bash
# Run inside the built workspace image. Keep failure evidence shell-builtin-only
# so PID exhaustion cannot prevent the diagnostic from being emitted.
set -euo pipefail

cgroup_root="${CODEWIRE_CGROUP_ROOT:-/sys/fs/cgroup}"
expected_pids_max="${CODEWIRE_EXPECTED_PIDS_MAX:-2048}"
bin_root="${CODEWIRE_BIN_ROOT:-/usr/local/bin}"

emit_pid_evidence_on_failure() {
  status=$?
  trap - 0
  if [ "$status" -ne 0 ]; then
    for metric in pids.current pids.max; do
      value=unavailable
      if [ -r "$cgroup_root/$metric" ]; then
        IFS= read -r value < "$cgroup_root/$metric" || value=unavailable
      fi
      printf 'workspace image verification: %s=%s\n' "$metric" "$value" >&2
    done

    lines=0
    if [ -r "$cgroup_root/pids.events" ]; then
      while IFS= read -r line; do
        printf 'workspace image verification: pids.events=%s\n' "$line" >&2
        lines=$((lines + 1))
        [ "$lines" -ge 16 ] && break
      done < "$cgroup_root/pids.events"
    else
      printf 'workspace image verification: pids.events=unavailable\n' >&2
    fi
  fi
  exit "$status"
}
trap emit_pid_evidence_on_failure 0

actual_pids_max=
IFS= read -r actual_pids_max < "$cgroup_root/pids.max"
[ "$actual_pids_max" = "$expected_pids_max" ]

test "$(id -un)" = codewire
test "$(id -u)" = 1000
for agent in codex claude gemini kimi pi aider; do
  executable="$(command -v "$agent")"
  test -n "$executable"
  test -O "$(readlink -f "$executable")"
  "$agent" --version
done

check_version() {
  executable="$1"
  shift
  command -v "$executable" >/dev/null
  "$@"
}

# This is the user-facing developer workspace contract. Check every advertised
# tool whenever the image changes so one repaired installer cannot hide a
# broken sibling or architecture-specific omission.
check_version cw cw --version
test ! -e "$bin_root/daemon"
test ! -e "$bin_root/codewire-daemon"
check_version docker docker --version
check_version dockerd dockerd --version
check_version docker docker buildx version
check_version docker docker compose version
check_version docker-compose docker-compose --version
check_version gh gh --version
check_version git git --version
check_version go go version
check_version gopls gopls version
check_version hcloud hcloud version
check_version node node --version
check_version npm npm --version
check_version bun bun --version
dynamic_bun_runner="bun""x"
check_version "$dynamic_bun_runner" "$dynamic_bun_runner" --version
check_version pnpm pnpm --version
check_version yarn yarn --version
check_version python3 python3 --version
check_version pipx pipx --version
check_version poetry poetry --version
check_version uv uv --version
check_version cargo cargo --version
check_version rustc rustc --version
check_version psql psql --version
check_version protoc protoc --version

# Codex is installed in the interactive-user npm prefix. A dry run proves the
# real vendor update path without mutating the verification image. Claude is
# the sole package allowed to run lifecycle scripts on later user updates.
test "$(npm config get allow-scripts)" = @anthropic-ai/claude-code
npm update --global --dry-run @openai/codex
