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
ssh_fixture_root="${CODEWIRE_SSH_FIXTURE_ROOT:-/opt/codewire/fixtures/openssh}"
system_sbin_root="${CODEWIRE_SYSTEM_SBIN_ROOT:-/usr/sbin}"
system_bin_root="${CODEWIRE_SYSTEM_BIN_ROOT:-/usr/bin}"
interactive_shell="${CODEWIRE_INTERACTIVE_SHELL:-/bin/bash}"
agents_root="${CODEWIRE_AGENTS_ROOT:-/opt/codewire/agents}"
upgrade_root="${CODEWIRE_AGENT_UPGRADE_ROOT:-$agents_root/upgrade}"
desktop_root="${CODEWIRE_DESKTOP_ROOT:-/opt/codewire/desktop}"
proc_root="${CODEWIRE_PROC_ROOT:-/proc}"
x11_socket_root="${CODEWIRE_X11_SOCKET_ROOT:-/tmp/.X11-unix}"

emit_pid_evidence_on_failure() {
  status=$?
  trap - 0
  # A check that fails after the desktop started must not leave it running.
  # The wait reaps the launcher: where nothing else reaps, a killed launcher
  # stays in the process table and still answers a signal.
  if [ -n "${desktop_pid:-}" ]; then
    kill -KILL -- "-$desktop_pid" 2>/dev/null || true
    wait "$desktop_pid" 2>/dev/null || true
  fi
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
test "$(id -g)" = 1000
passwd_record="$(getent passwd codewire)"
IFS=: read -r passwd_name _passwd passwd_uid passwd_gid _gecos _home _shell <<EOF
$passwd_record
EOF
test "$passwd_name:$passwd_uid:$passwd_gid" = codewire:1000:1000

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
    /home/codewire/.npm-global/bin:/home/codewire/.local/bin:/opt/codewire/agents/upgrade:/opt/codewire/agents/npm/bin:/opt/codewire/agents/bin:*) ;;
    *) printf 'workspace image verification: agent PATH precedence differs\n' >&2; exit 1 ;;
  esac
fi

# The fixed cw launcher must have trusted ancestry in both image checks. Root
# extraction of upstream archives must not restore their build user's owners.
for component in / /usr /usr/local "$bin_root"; do
  if [ ! -d "$component" ] || [ -L "$component" ] ||
    ! metadata="$(stat --format=%u:%g:%a -- "$component" 2>/dev/null)"; then
    printf 'workspace image verification: invalid fixed launcher ancestry: %s\n' "$component" >&2
    exit 1
  fi
  case "$metadata" in
    0:0:[0-7][0145][0145]|0:0:[0-7][0-7][0145][0145]) ;;
    *) printf 'workspace image verification: untrusted fixed launcher ancestry: %s\n' "$component" >&2; exit 1 ;;
  esac
done

for agent in codex claude gemini kimi pi amp aider; do
  executable="$(command -v "$agent")"
  test -n "$executable"
  resolved="$(readlink -f "$executable")"
  if [ "$mode" = mounted-home-agents ]; then
    case "$agent:$executable:$resolved" in
      aider:/opt/codewire/agents/upgrade/aider:/opt/codewire/agents/upgrade/aider) ;;
      amp:/opt/codewire/agents/upgrade/amp:/opt/codewire/agents/upgrade/amp) ;;
      codex:/opt/codewire/agents/npm/bin/codex:/opt/codewire/agents/npm/lib/node_modules/*) ;;
      claude:/opt/codewire/agents/upgrade/claude:/opt/codewire/agents/upgrade/claude) ;;
      gemini:/opt/codewire/agents/npm/bin/gemini:/opt/codewire/agents/npm/lib/node_modules/*) ;;
      kimi:/opt/codewire/agents/upgrade/kimi:/opt/codewire/agents/upgrade/kimi) ;;
      pi:/opt/codewire/agents/upgrade/pi:/opt/codewire/agents/upgrade/pi) ;;
      *) printf 'workspace image verification: bundled agent resolved outside its image prefix\n' >&2; exit 1 ;;
    esac
  fi
  if [ "$agent" = codex ]; then
    version="$("$agent" --version)"
    printf '%s\n' "$version"
    test "$version" = 'codex-cli 0.160.0'
  else
    "$agent" --version
  fi
done

test "$(npm config get prefix)" = /home/codewire/.npm-global
# Project installs use npm's default lifecycle-script policy (#2876).
test -z "${NPM_CONFIG_ALLOW_SCRIPTS:-}"
# The persistent prefix starts empty: update would silently prove nothing.
# Plan an explicit pinned user install without installing packages or running
# lifecycle scripts. This proves neither a completed install nor an upgrade.
# npm's dry-run cannot create the lib directory that a normal global install
# creates automatically. Establish that dry-run-only precondition as the same
# unprivileged user; do not seed an agent or change any runtime startup path.
mkdir -p /home/codewire/.npm-global/lib
npm install --global --dry-run --ignore-scripts --no-audit --no-fund @openai/codex@0.160.0

# The shipped agents live outside the persistent home. A self-updater that
# wrote there would appear to succeed and then revert on the next restart, so
# the whole tree is root-owned and unwritable by the user.
invalid_agent="$(find "$agents_root" -xdev \( ! -uid 0 -o \( \( -type f -o -type d \) -perm /022 \) \) -print -quit)"
if [ -n "$invalid_agent" ]; then
  printf 'workspace image verification: shipped agents are writable\n' >&2
  exit 1
fi
# pi, Kimi Code, Amp and aider would update in place or refuse; their upgrade
# commands install into the persistent home instead. Recording stubs prove the
# routing without contacting a registry.
upgrade_stubs="$(mktemp -d)"
for tool in npm pipx; do
  printf '#!/bin/sh\nprintf "%%s %%s\\n" %s "$*"\n' "$tool" >"$upgrade_stubs/$tool"
  chmod +x "$upgrade_stubs/$tool"
done
for route in \
  'pi update self=npm install --global @earendil-works/pi-coding-agent@latest' \
  'pi update=npm install --global @earendil-works/pi-coding-agent@latest' \
  'kimi upgrade=npm install --global @moonshot-ai/kimi-code@latest' \
  'kimi update --yes=npm install --global @moonshot-ai/kimi-code@latest' \
  'amp update=npm install --global --allow-scripts=@ampcode/cli @sourcegraph/amp@latest' \
  'amp up --target-version 0.0.1=npm install --global --allow-scripts=@ampcode/cli @sourcegraph/amp@0.0.1' \
  'aider --upgrade=pipx install --force aider-chat'; do
  command_line="${route%%=*}"
  # shellcheck disable=SC2086 # Each route is a fixed, space-separated command line.
  set -- $command_line
  agent="$1"
  shift
  routed="$(PATH="$upgrade_stubs:$PATH" "$upgrade_root/$agent" "$@" </dev/null)"
  if [ "$routed" != "${route#*=}" ]; then
    printf 'workspace image verification: %s does not upgrade into the home\n' "$command_line" >&2
    exit 1
  fi
done
rm -rf "$upgrade_stubs"

# A user-prefix agent update must take effect in an already-open terminal.
# Interactive bash therefore resolves PATH on every command instead of hashing.
interactive_flags="$("$interactive_shell" -ic 'printf %s "$-"' </dev/null 2>/dev/null)"
case "$interactive_flags" in
  *h*) printf 'workspace image verification: interactive bash hashes command paths\n' >&2; exit 1 ;;
  *i*) ;;
  *) printf 'workspace image verification: interactive bash did not start\n' >&2; exit 1 ;;
esac

check_version() {
  executable="$1"
  shift
  command -v "$executable" >/dev/null
  "$@"
}

# Rust must also work with the actual empty home mount. Checking only the
# populated image home previously hid the missing interactive toolchain.
check_version cargo cargo --version
check_version rustc rustc --version
check_version rustfmt rustfmt --version
check_version cargo cargo clippy --version

if [ "$mode" = mounted-home-agents ]; then
  printf 'workspace image verification: fresh-home six-agent contract passed\n'
  exit 0
fi

# The SSH acceptance target is an inert, immutable image artifact, not a system
# service. Executing -V proves its loader closure without creating host keys or
# a listener. Per-run host keys and configuration belong only to the smoke.
test -d "$ssh_fixture_root"
test ! -L "$ssh_fixture_root"
test -f "$ssh_fixture_root/usr/sbin/sshd"
test ! -L "$ssh_fixture_root/usr/sbin/sshd"
test -x "$ssh_fixture_root/usr/sbin/sshd"
test ! -e "$system_sbin_root/sshd"
invalid_fixture="$(find "$ssh_fixture_root" -xdev \( ! -uid 0 -o \( \( -type f -o -type d \) -perm /022 \) \) -print -quit)"
test -z "$invalid_fixture"
host_keys="$(find "$ssh_fixture_root" -name 'ssh_host_*' -print -quit)"
test -z "$host_keys"
case "$(uname -m)" in
  x86_64) ssh_multiarch=x86_64-linux-gnu ;;
  aarch64) ssh_multiarch=aarch64-linux-gnu ;;
  *) printf 'workspace image verification: unsupported SSH fixture architecture\n' >&2; exit 1 ;;
esac
test -f "$ssh_fixture_root/usr/lib/$ssh_multiarch/libwrap.so.0" ||
  test -f "$ssh_fixture_root/lib/$ssh_multiarch/libwrap.so.0"
ssh_version="$(LD_LIBRARY_PATH="$ssh_fixture_root/usr/lib/$ssh_multiarch:$ssh_fixture_root/lib/$ssh_multiarch" \
  "$ssh_fixture_root/usr/sbin/sshd" -V 2>&1)"
case "$ssh_version" in
  OpenSSH_9.6*) ;;
  *) printf 'workspace image verification: unexpected SSH fixture version\n' >&2; exit 1 ;;
esac
printf 'workspace image verification: inert SSH fixture contract passed\n'

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
check_version kubectl kubectl version --client
check_version atmos atmos version
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
check_version psql psql --version
check_version protoc protoc --version
# Codex's Linux sandbox runs commands through the system bubblewrap on PATH.
check_version bwrap bwrap --version
# `cw shell` from these terminals finds their terminfo, as ssh would (#4332).
for terminal in xterm-kitty alacritty wezterm foot tmux-256color xterm-256color; do
  infocmp "$terminal" >/dev/null
done
# Claude Code fills the terminal by default, as the image sets (#4332).
test "${CLAUDE_CODE_NO_FLICKER-}" = 1

# The desktop (docs/dev/SANDBOX-DESKTOP.md) is inert in the image, starts on
# request, opens nothing but what the contract names, and leaves nothing
# behind. Sockets are per network namespace, which a Pod's containers share,
# so every endpoint the desktop adds is checked, not only its VNC port.
desktop_fail() {
  printf 'workspace image verification: desktop: %s\n' "$1" >&2
  exit 1
}
# Every endpoint in this network namespace, one "<kind> <address>" per line:
# TCP listeners, unconnected UDP sockets and named Unix sockets, abstract
# ones (a leading "@") included, as /proc/net prints them.
desktop_endpoints() {
  for table in tcp tcp6; do
    [ -r "$proc_root/net/$table" ] || continue
    while read -r _slot local_address _remote state _rest; do
      case "$state" in 0A) printf 'tcp %s\n' "$local_address" ;; esac
    done <"$proc_root/net/$table"
  done
  for table in udp udp6; do
    [ -r "$proc_root/net/$table" ] || continue
    while read -r _slot local_address _remote state _rest; do
      case "$state" in 07) printf 'udp %s\n' "$local_address" ;; esac
    done <"$proc_root/net/$table"
  done
  [ -r "$proc_root/net/unix" ] || return 0
  while read -r _number _references _protocol _flags _type _state _inode path; do
    case "$path" in ''|Path) ;; *) printf 'unix %s\n' "$path" ;; esac
  done <"$proc_root/net/unix"
}
# The endpoints that were not there before the start, read from $1.
desktop_new_endpoints() {
  desktop_endpoints | while IFS= read -r endpoint; do
    case "$1" in
      "$endpoint"|"$endpoint"$'\n'*|*$'\n'"$endpoint"|*$'\n'"$endpoint"$'\n'*) ;;
      *) printf '%s\n' "$endpoint" ;;
    esac
  done
}
# Live processes as "<pid> <name>": the server and the session by name, and,
# given the launcher's session ID, everything else still in that session. A
# zombie awaiting its reaper is not one. A name may hold spaces and
# parentheses, so the fields are read after its last ")".
desktop_processes() {
  for stat_file in "$proc_root"/[0-9]*/stat; do
    [ -r "$stat_file" ] || continue
    IFS= read -r stat_line <"$stat_file" || continue
    name="${stat_line#*(}"
    name="${name%)*}"
    read -r state _parent _group session _rest <<EOF
${stat_line##*) }
EOF
    case "$state" in Z) continue ;; esac
    case "$name" in
      Xvnc|xfce4-session) ;;
      *) if [ -z "${1:-}" ] || [ "$session" != "$1" ]; then continue; fi ;;
    esac
    printf '%s %s\n' "${stat_line%% *}" "$name"
  done
}

test -f "$desktop_root/start"
test ! -L "$desktop_root/start"
test -x "$desktop_root/start"
test -f "$desktop_root/xdg/xfce4/xfconf/xfce-perchannel-xml/xfce4-session.xml"
invalid_desktop="$(find "$desktop_root" -xdev \( ! -uid 0 -o \( \( -type f -o -type d \) -perm /022 \) \) -print -quit)"
test -z "$invalid_desktop"
for tool in Xvnc dbus-daemon startxfce4 xfce4-session xfce4-terminal xdotool scrot xrandr; do
  test -x "$system_bin_root/$tool" || desktop_fail "the image lacks $tool"
done
endpoints_before="$(desktop_endpoints)"
case $'\n'"$endpoints_before"$'\n' in
  *:170D$'\n'*|*$'\n'"unix $x11_socket_root/X1"$'\n'*) desktop_fail 'something listens before any start' ;;
esac
[ -z "$(desktop_processes)" ] || desktop_fail 'a desktop process runs before any start'

desktop_work="$(mktemp -d)"
# The launcher leads its own session, so its PID names every process it
# starts. The agent socket is a marker: the session must hand it on unchanged.
SSH_AUTH_SOCK="$desktop_work/workspace-agent" setsid "$desktop_root/start" >"$desktop_work/log" 2>&1 &
desktop_pid=$!
desktop_ready=false
for _ in $(seq 150); do
  if [ "$(DISPLAY=:1 xdotool getdisplaygeometry 2>/dev/null)" = '1600 1000' ] &&
    [ -n "$(DISPLAY=:1 xdotool search --class xfce4-panel 2>/dev/null)" ]; then
    desktop_ready=true
    break
  fi
  kill -0 "$desktop_pid" 2>/dev/null || break
  sleep 0.2
done
if [ "$desktop_ready" != true ]; then
  while IFS= read -r line; do printf 'workspace image verification: desktop log: %s\n' "$line" >&2; done <"$desktop_work/log"
  desktop_fail 'the display and its XFCE panel did not come up within 30 seconds'
fi

vnc_listens=false
while IFS= read -r endpoint; do
  case "$endpoint" in
    '') ;;
    'tcp 0100007F:170D'|'tcp 00000000000000000000000001000000:170D') vnc_listens=true ;;
    "unix $x11_socket_root/X1") ;;
    # The session bus and anything else in the launcher's private directory.
    'unix /tmp/codewire-desktop.'??????/*) ;;
    # The session manager's ICE socket, which admits only a holder of the
    # cookie in the user's ICE authority file.
    'unix /tmp/.ICE-unix/'[0-9]*|'unix @/tmp/.ICE-unix/'[0-9]*) ;;
    tcp*:170D) desktop_fail "the VNC server listens beyond loopback: ${endpoint#tcp }" ;;
    *) desktop_fail "the desktop opened an endpoint the contract does not name: $endpoint" ;;
  esac
done <<EOF
$(desktop_new_endpoints "$endpoints_before")
EOF
[ "$vnc_listens" = true ] || desktop_fail 'nothing listens on 5901 while the desktop runs'

session_shares_agent=false
while read -r pid name; do
  case "$name" in
    ssh-agent|gpg-agent) desktop_fail "the session started its own $name" ;;
    xfwm4|xfce4-panel|xfdesktop|Thunar)
      agent_socket=
      while IFS= read -r -d '' variable; do
        case "$variable" in SSH_AUTH_SOCK=*) agent_socket="${variable#SSH_AUTH_SOCK=}" ;; esac
      done <"$proc_root/$pid/environ"
      [ "$agent_socket" = "$desktop_work/workspace-agent" ] ||
        desktop_fail "$name does not use the workspace's SSH agent: SSH_AUTH_SOCK=$agent_socket"
      session_shares_agent=true ;;
  esac
done <<EOF
$(desktop_processes "$desktop_pid")
EOF
[ "$session_shares_agent" = true ] || desktop_fail 'no session process was found to check its SSH agent'

DISPLAY=:1 scrot "$desktop_work/screen.png"
test -s "$desktop_work/screen.png"
kill -TERM -- "-$desktop_pid"
desktop_gone=false
for _ in $(seq 50); do
  if [ -z "$(desktop_new_endpoints "$endpoints_before")" ] && [ -z "$(desktop_processes "$desktop_pid")" ] &&
    [ ! -e "$x11_socket_root/X1" ]; then
    desktop_gone=true
    break
  fi
  sleep 0.2
done
if [ "$desktop_gone" != true ]; then
  desktop_fail "the stop left something behind: $(desktop_new_endpoints "$endpoints_before" | tr '\n' ' ')$(desktop_processes "$desktop_pid" | tr '\n' ' ')"
fi
rm -rf "$desktop_work"
printf 'workspace image verification: desktop contract passed\n'
