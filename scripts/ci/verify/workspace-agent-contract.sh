#!/usr/bin/env bash
# Run inside the built workspace image. Keep failure evidence shell-builtin-only
# so PID exhaustion cannot prevent the diagnostic from being emitted.
set -euo pipefail

cgroup_root="${CODEWIRE_CGROUP_ROOT:-/sys/fs/cgroup}"
expected_pids_max="${CODEWIRE_EXPECTED_PIDS_MAX:-2048}"

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
for agent in codex claude gemini kimi pi aider; do
  executable="$(command -v "$agent")"
  test -n "$executable"
  test -O "$(readlink -f "$executable")"
  "$agent" --version
done

# Codex is installed in the interactive-user npm prefix. A dry run proves the
# real vendor update path without mutating the verification image.
npm update --global --dry-run @openai/codex
