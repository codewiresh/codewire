#!/usr/bin/env bash
# Run inside the built workspace image. Keep failure evidence shell-builtin-only
# so PID exhaustion cannot prevent the diagnostic from being emitted.
set -euo pipefail

mode=full
if [ "$#" -ne 0 ]; then
  if [ "$#" -ne 1 ] || [ "$1" != --mounted-home-agents ]; then
    printf 'usage: workspace-agent-contract.sh [--mounted-home-agents]\n' >&2
    exit 2
  fi
  mode=mounted-home-agents
fi

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

if [ "$mode" = mounted-home-agents ]; then
  test "${HOME:-}" = /home/codewire
  test -w /home/codewire
  # Require the verifier's actual fresh mount, not the image's populated home.
  # The verifier owns its creation; this contract never repairs permissions or
  # installs/copies tools into it. Named Docker volumes must use volume-nocopy.
  awk '$5 == "/home/codewire" { found = 1 } END { exit !found }' /proc/self/mountinfo
  test ! -e /home/codewire/.npm-global
  test ! -e /home/codewire/.local
  test ! -e /home/codewire/.npmrc
  case "$PATH" in
    /home/codewire/.npm-global/bin:/home/codewire/.local/bin:/opt/codewire/agents/npm/bin:/opt/codewire/agents/bin:*) ;;
    *) printf 'workspace image verification: agent PATH precedence differs\n' >&2; exit 1 ;;
  esac
fi

for agent in codex claude gemini kimi pi aider; do
  executable="$(command -v "$agent")"
  test -n "$executable"
  resolved="$(readlink -f "$executable")"
  test -O "$resolved"
  if [ "$mode" = mounted-home-agents ]; then
    case "$agent:$executable:$resolved" in
      aider:/opt/codewire/agents/bin/aider:/opt/codewire/agents/pipx/venvs/aider-chat/bin/aider) ;;
      codex:/opt/codewire/agents/npm/bin/codex:/opt/codewire/agents/npm/lib/node_modules/*) ;;
      claude:/opt/codewire/agents/npm/bin/claude:/opt/codewire/agents/npm/lib/node_modules/*) ;;
      gemini:/opt/codewire/agents/npm/bin/gemini:/opt/codewire/agents/npm/lib/node_modules/*) ;;
      kimi:/opt/codewire/agents/npm/bin/kimi:/opt/codewire/agents/npm/lib/node_modules/*) ;;
      pi:/opt/codewire/agents/npm/bin/pi:/opt/codewire/agents/npm/lib/node_modules/*) ;;
      *) printf 'workspace image verification: bundled agent resolved outside its image prefix\n' >&2; exit 1 ;;
    esac
  fi
  if [ "$agent" = codex ]; then
    version="$("$agent" --version)"
    printf '%s\n' "$version"
    test "$version" = 'codex-cli 0.149.0'
  else
    "$agent" --version
  fi
done

test "$(npm config get prefix)" = /home/codewire/.npm-global
test "$(npm config get allow-scripts)" = @anthropic-ai/claude-code
# The persistent prefix starts empty: update would silently prove nothing.
# Plan an explicit pinned user install without installing packages or running
# lifecycle scripts. This proves neither a completed install nor an upgrade.
# npm's dry-run cannot create the lib directory that a normal global install
# creates automatically. Establish that dry-run-only precondition as the same
# unprivileged user; do not seed an agent or change any runtime startup path.
mkdir -p /home/codewire/.npm-global/lib
npm install --global --dry-run --ignore-scripts --no-audit --no-fund @openai/codex@0.149.0

if [ "$mode" = mounted-home-agents ]; then
  printf 'workspace image verification: fresh-home six-agent contract passed\n'
  exit 0
fi

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
