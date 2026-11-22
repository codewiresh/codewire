#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly CONTRACT="$ROOT/scripts/ci/verify/workspace-agent-contract.sh"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/workspace-agent-contract-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/cgroup" "$work/ssh/usr/sbin" "$work/system-sbin" \
  "$work/agents/npm/bin" "$work/agents/upgrade"
case "$(uname -m)" in
  x86_64) multiarch=x86_64-linux-gnu ;;
  aarch64) multiarch=aarch64-linux-gnu ;;
  *) printf 'unsupported test architecture\n' >&2; exit 1 ;;
esac
mkdir -p "$work/ssh/usr/lib/$multiarch"
touch "$work/ssh/usr/lib/$multiarch/libwrap.so.0"
fixture_uid="$(id -u)"

fail() {
  printf '[test-workspace-agent-contract] ERROR: %s\n' "$*" >&2
  exit 1
}

cat >"$work/bin/id" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -un) printf 'codewire\n' ;;
  -u) printf '1000\n' ;;
  -g) printf '%s\n' "${FAKE_CODEWIRE_GID:-1000}" ;;
  *) printf 'codewire\n' ;;
esac
EOF
cat >"$work/bin/getent" <<'EOF'
#!/bin/sh
[ "$*" = 'passwd codewire' ] || exit 99
printf 'codewire:x:1000:%s:Codewire:/home/codewire:/bin/bash\n' "${FAKE_CODEWIRE_PASSWD_GID:-1000}"
EOF
cat >"$work/bin/stat" <<'EOF'
#!/bin/sh
# Model image ownership for only the four checked ancestry paths. The host's
# /usr/local need not be root-owned. Directory/link checks and real modes stay
# unchanged; every other stat delegates without translation.
if [ "$#" -eq 3 ] && [ "$1" = --format=%u:%g:%a ] && [ "$2" = -- ]; then
  case "$3" in
    /|/usr|/usr/local|"$FAKE_BIN_ROOT")
      uid=0; gid=0
      if [ "$3" = "$FAKE_BIN_ROOT" ]; then
        [ "${FAIL_BIN_STAT:-false}" = false ] || exit 42
        if [ "${MALFORMED_BIN_STAT:-false}" = true ]; then
          printf '0:0:0755:unexpected\n'
          exit 0
        fi
        uid="${FAKE_BIN_UID:-0}"; gid="${FAKE_BIN_GID:-0}"
      fi
      mode="$(/usr/bin/stat --format=%a -- "$3")" || exit "$?"
      printf '%s:%s:%s\n' "$uid" "$gid" "$mode"
      exit 0 ;;
  esac
fi
exec /usr/bin/stat "$@"
EOF
cat >"$work/bin/agent" <<'EOF'
#!/bin/sh
if [ "${FAIL_AGENT:-}" = "$(basename "$0")" ]; then
  exit 42
fi
if [ "${FAIL_AGENT:-}" = cargo-clippy ] && [ "$(basename "$0"):$*" = 'cargo:clippy --version' ]; then
  exit 42
fi
if [ "$(basename "$0")" = codex ]; then
  printf 'codex-cli %s\n' "${FAKE_CODEX_VERSION:-0.160.0}"
else
  printf '%s test-version\n' "$(basename "$0")"
fi
EOF
cat >"$work/bin/npm" <<'EOF'
#!/bin/sh
case "$*" in
  'config get prefix') printf '/home/codewire/.npm-global\n' ;;
  'install --global --dry-run --ignore-scripts --no-audit --no-fund @openai/codex@0.160.0')
    [ -f "$FAKE_PREFIX_STATE" ] || exit 254
    printf 'npm dry-run OK\n' ;;
  '--version') printf 'npm test-version\n' ;;
  *) exit 97 ;;
esac
EOF
cat >"$work/bin/mkdir" <<'EOF'
#!/bin/sh
# The host-side fake must never create a real workspace user's home directory.
[ "$*" = '-p /home/codewire/.npm-global/lib' ] || exit 99
printf 'lib-prepared\n' >"$FAKE_PREFIX_STATE"
EOF
# Not on PATH: the contract itself runs under the host's bash.
cat >"$work/interactive-bash" <<'EOF'
#!/bin/sh
[ "$#" -eq 2 ] && [ "$1" = -ic ] && [ "$2" = 'printf %s "$-"' ] || exit 99
printf '%s' "$FAKE_INTERACTIVE_FLAGS"
EOF
chmod +x "$work/bin/id" "$work/bin/getent" "$work/bin/stat" "$work/bin/agent" "$work/bin/npm" "$work/bin/mkdir" \
  "$work/interactive-bash"
cat >"$work/ssh/usr/sbin/sshd" <<'EOF'
#!/bin/sh
[ "$*" = -V ] || exit 99
case "$LD_LIBRARY_PATH" in "$FAKE_SSH_ROOT/usr/lib/"*) ;; *) exit 98 ;; esac
[ "${FAIL_SSH_LOADER:-false}" = false ] || exit 127
printf 'OpenSSH_9.6p1, synthetic loader fixture\n' >&2
EOF
cat >"$work/bin/find" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  "$FAKE_SSH_ROOT")
    [[ "${FAIL_SSH_FIND:-false}" = false ]] || exit 42
    expected_uid="${FAKE_SSH_EXPECTED_UID:-$FAKE_FIXTURE_UID}" ;;
  "$FAKE_AGENTS_ROOT") expected_uid="${FAKE_AGENTS_EXPECTED_UID:-$FAKE_FIXTURE_UID}" ;;
  "$FAKE_DESKTOP_ROOT") expected_uid="${FAKE_DESKTOP_EXPECTED_UID:-$FAKE_FIXTURE_UID}" ;;
  # The setuid search is real: the test makes the helper it looks for.
  "$FAKE_CHROMIUM_ROOT") exec /usr/bin/find "$@" ;;
  *) exit 99 ;;
esac
# Host tests cannot chown files to root. Translate only the expected uid in the
# real find predicate; permission, key-file and unexpected-owner checks remain.
args=("$@")
for ((i=0; i<${#args[@]}-1; i++)); do
  if [[ "${args[i]}" == -uid && "${args[i+1]}" == 0 ]]; then
    args[i+1]="$expected_uid"
  fi
done
exec /usr/bin/find "${args[@]}"
EOF
chmod +x "$work/bin/find" "$work/ssh/usr/sbin/sshd"
chmod -R go-w "$work/ssh"
# The shipped tree: a seeded agent plus the image's actual upgrade wrappers.
printf '#!/bin/sh\n' >"$work/agents/npm/bin/kimi"
cp "$ROOT"/images/workspace/agent-upgrade/* "$work/agents/upgrade/"
chmod -R go-w "$work/agents"
for agent in codex claude gemini kimi pi amp aider; do
  ln -s agent "$work/bin/$agent"
done
for tool in cw docker dockerd docker-compose gh fj git go gopls hcloud kubectl atmos \
  node bun bun""x pnpm yarn python3 pipx poetry uv cargo rustc rustfmt psql protoc bwrap infocmp; do
  ln -s agent "$work/bin/$tool"
done

# The desktop: a launcher that "runs" by writing the tables the contract
# reads, so no test run touches a real display or a port of this host.
mkdir -p "$work/desktop/xdg/xfce4/xfconf/xfce-perchannel-xml" "$work/proc/net" "$work/x11"
touch "$work/desktop/xdg/xfce4/xfconf/xfce-perchannel-xml/xfce4-session.xml"
cat >"$work/desktop/start" <<'EOF'
#!/bin/sh
[ "${FAKE_DESKTOP_START:-runs}" != fails ] || exit 1
IFS= read -r password || true
if [ "${#password}" -ne 8 ]; then
  # A launcher that would start anyway reports success here.
  [ "${FAKE_DESKTOP_START:-runs}" != without-a-password ] || exit 0
  exit 1
fi
[ "${FAKE_DESKTOP_PASSWORD:-quiet}" != printed ] || printf 'the password is %s\n' "$password"
[ "${FAKE_DESKTOP_START:-runs}" = silent ] || printf 'codewire-desktop: display ready\n'
runtime="$FAKE_RUNTIME_ROOT/codewire-desktop.AbCdEf"
clear() {
  case "${FAKE_DESKTOP_LINGERS:-false}" in
    false) rm -rf "$FAKE_PROC_ROOT/4242" "$FAKE_PROC_ROOT/4243" "$FAKE_PROC_ROOT/4244" "$runtime" ;;
    child) rm -rf "$FAKE_PROC_ROOT/4242" "$FAKE_PROC_ROOT/4243" "$runtime" ;;
    password-file) rm -rf "$FAKE_PROC_ROOT/4242" "$FAKE_PROC_ROOT/4243" "$FAKE_PROC_ROOT/4244" ;;
  esac
  if [ "${FAKE_DESKTOP_LINGERS:-false}" != true ]; then
    rm -rf "$FAKE_X11_ROOT/X1"
    : >"$FAKE_PROC_ROOT/net/tcp"
    : >"$FAKE_PROC_ROOT/net/udp"
    : >"$FAKE_PROC_ROOT/net/unix"
  fi
}
printf '%s\n' "$$" >"$FAKE_LAUNCHER_PID"
# The server, the window manager and one more process, all in this launcher's
# session, which setsid made this process lead.
/usr/bin/mkdir -p "$FAKE_PROC_ROOT/4242" "$FAKE_PROC_ROOT/4243" "$FAKE_PROC_ROOT/4244" "$runtime"
chmod 700 "$runtime"
: >"$runtime/vnc-password"
chmod "${FAKE_DESKTOP_PASSWORD_MODE:-600}" "$runtime/vnc-password"
printf '4242 (Xvnc) S 1 %s %s 0\n' "$$" "$$" >"$FAKE_PROC_ROOT/4242/stat"
printf 'Xvnc\0:1\0-localhost\0-SecurityTypes\0%s\0-PasswordFile\0%s\0' \
  "${FAKE_DESKTOP_SECURITY:-VncAuth}" "$runtime/vnc-password" >"$FAKE_PROC_ROOT/4242/cmdline"
printf 'HOME=/home/codewire\0' >"$FAKE_PROC_ROOT/4242/environ"
printf '4243 (xfwm4) S 1 %s %s 0\n' "$$" "$$" >"$FAKE_PROC_ROOT/4243/stat"
printf 'xfwm4\0' >"$FAKE_PROC_ROOT/4243/cmdline"
case "${FAKE_DESKTOP_AGENT_SOCKET:-inherited}" in
  inherited) printf 'HOME=/home/codewire\0SSH_AUTH_SOCK=%s\0' "$SSH_AUTH_SOCK" ;;
  replaced) printf 'SSH_AUTH_SOCK=/tmp/ssh-AbCdEf/agent.39\0' ;;
esac >"$FAKE_PROC_ROOT/4243/environ"
printf '4244 (%s) S 1 %s %s 0\n' "${FAKE_DESKTOP_HELPER:-dbus-daemon}" "$$" "$$" >"$FAKE_PROC_ROOT/4244/stat"
printf 'helper\0' >"$FAKE_PROC_ROOT/4244/cmdline"
printf 'HOME=/home/codewire\0' >"$FAKE_PROC_ROOT/4244/environ"
case "${FAKE_DESKTOP_PASSWORD:-quiet}" in
  in-arguments) printf 'helper\0--password=%s\0' "$password" >"$FAKE_PROC_ROOT/4244/cmdline" ;;
  in-environment) printf 'VNC_PASSWORD=%s\0' "$password" >"$FAKE_PROC_ROOT/4244/environ" ;;
esac
printf '   0: %s 00000000:0000 0A\n' "${FAKE_DESKTOP_LISTEN:-0100007F:170D}" >"$FAKE_PROC_ROOT/net/tcp"
{
  printf 'Num RefCount Protocol Flags Type St Inode Path\n'
  printf '0: 00000002 00000000 00010000 0001 01 9 /run/earlier.sock\n'
  printf '0: 00000002 00000000 00010000 0001 01 11 %s/X1\n' "$FAKE_X11_ROOT"
  printf '0: 00000002 00000000 00010000 0001 01 12 %s/bus\n' "$runtime"
  printf '0: 00000002 00000000 00010000 0001 01 13 /tmp/.ICE-unix/4245\n'
  printf '0: 00000002 00000000 00010000 0001 01 14 @/tmp/.ICE-unix/4245\n'
  printf '0: 00000003 00000000 00000000 0001 03 15\n'
} >"$FAKE_PROC_ROOT/net/unix"
case "${FAKE_DESKTOP_EXTRA:-none}" in
  none) ;;
  tcp) printf '   1: 0100007F:1F90 00000000:0000 0A\n' >>"$FAKE_PROC_ROOT/net/tcp" ;;
  udp) printf '   1: 00000000:14E9 00000000:0000 07\n' >"$FAKE_PROC_ROOT/net/udp" ;;
  bus-in-tmp) printf '0: 00000002 00000000 00010000 0001 01 16 /tmp/dbus-AbCdEfGhIj\n' >>"$FAKE_PROC_ROOT/net/unix" ;;
  abstract-bus) printf '0: 00000002 00000000 00010000 0001 01 16 @/tmp/dbus-AbCdEfGhIj\n' >>"$FAKE_PROC_ROOT/net/unix" ;;
esac
: >"$FAKE_X11_ROOT/X1"
# The contract stops the launcher by killing it outright, which no trap
# sees: a child clears the tables once this process is gone, as the real
# launcher's children end with it.
launcher=$$
(
  while kill -0 "$launcher" 2>/dev/null; do sleep 0.1; done
  clear
) &
while :; do sleep 0.1; done
EOF
cat >"$work/bin/xdotool" <<'EOF'
#!/bin/sh
[ "${DISPLAY:-}" = :1 ] && [ -e "$FAKE_X11_ROOT/X1" ] || exit 1
case "$*" in
  getdisplaygeometry) printf '1600 1000\n' ;;
  'search --class xfce4-panel') printf '4194305\n' ;;
  *) exit 99 ;;
esac
EOF
mkdir -p "$work/desktop/share" "$work/desktop/xdg/xfce4/panel" "$work/desktop/xdg/autostart" \
  "$work/themes/Codewire/gtk-3.0" "$work/chromium-lib" "$work/apt/sources.list.d"
touch "$work/desktop/share/wallpaper.svg" "$work/desktop/share/codewire.svg" \
  "$work/desktop/xdg/xfce4/panel/default.xml" "$work/desktop/xdg/autostart/codewire-terminal.desktop" \
  "$work/desktop/xdg/xfce4/xfconf/xfce-perchannel-xml/xsettings.xml" \
  "$work/themes/Codewire/gtk-3.0/gtk.css" "$work/chromium-lib/chromium"
readonly CHROMIUM_DEFAULTS="$ROOT/images/workspace/chromium/flags"
cp "$CHROMIUM_DEFAULTS" "$work/chromium-flags"
printf 'URIs: https://snapshot.ubuntu.com/ubuntu/\n' >"$work/apt/sources.list.d/ubuntu.sources"
# As the packaged launcher does, the fake runs the defaults file as shell
# before anything else, so the image's own refusals are what is tested.
cat >"$work/bin/chromium" <<'EOF'
#!/bin/sh
# The packaged launcher starts from no flags of the caller's; one that kept
# them would hand them to the browser with its own.
effective="$*"
case "${FAKE_CHROMIUM_LAUNCHER:-drops-inherited}" in
  drops-inherited) CHROMIUM_FLAGS='' ;;
  passes-inherited) effective="${CHROMIUM_FLAGS:-} ${CHROMIUM_USER_FLAGS:-} $*" ;;
esac
. "$FAKE_CHROMIUM_FLAGS_FILE"
case " $effective " in
  *' --version '*) printf 'Chromium test-version\n'; exit 0 ;;
esac
[ "$*" = '--headless=new --dump-dom about:blank' ] || exit 99
case "${FAKE_CHROMIUM:-starts}" in
  starts) printf '<html><head></head><body></body></html>\n' ;;
  refuses) printf 'No usable sandbox! Update your kernel.\n' >&2; exit 1 ;;
  crashes) printf 'Segmentation fault\n' >&2; exit 139 ;;
  blank) ;;
esac
EOF
chmod +x "$work/bin/chromium"
cat >"$work/bin/scrot" <<'EOF'
#!/bin/sh
[ "${DISPLAY:-}" = :1 ] && [ "$#" -eq 1 ] || exit 99
printf 'synthetic picture\n' >"$1"
EOF
chmod +x "$work/desktop/start" "$work/bin/xdotool" "$work/bin/scrot"
chmod -R go-w "$work/desktop"
for tool in Xvnc tigervncpasswd setpriv dbus-daemon startxfce4 xfce4-session xfce4-terminal xrandr; do
  ln -s agent "$work/bin/$tool"
done
# Whatever a contract run found, it leaves no launcher running behind it.
assert_no_launcher() {
  local pid
  [[ -s "$work/launcher.pid" ]] || return 0
  pid="$(<"$work/launcher.pid")"
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL -- "-$pid" 2>/dev/null || true
    fail "the contract left its desktop running: $1"
  fi
  rm -f "$work/launcher.pid"
}
mkdir -p "$work/tmp"
reset_desktop() {
  rm -rf "$work/proc/4242" "$work/proc/4243" "$work/proc/4244" "$work/x11/X1" \
    "$work/tmp/codewire-desktop.AbCdEf"
  : >"$work/proc/net/tcp"
  : >"$work/proc/net/udp"
  # One socket that was there before any desktop: it is never the desktop's.
  printf '0: 00000002 00000000 00010000 0001 01 9 /run/earlier.sock\n' >"$work/proc/net/unix"
}
reset_desktop
# Another session's process, with a name that holds a space and a
# parenthesis: never the desktop's, however the contract parses it.
/usr/bin/mkdir "$work/proc/11"
printf '11 (Web) Content) S 1 11 11 0\n' >"$work/proc/11/stat"

# A stopped desktop is gone once the fake's child has cleared it, which a
# loaded machine may take seconds to schedule. So the contract may wait up to
# 120 s, and that event ends the wait (#4763). Only a desktop that lingers on
# purpose gets a short bound, since nothing ends its wait.
run_contract() {
  env PATH="$work/bin:$PATH" \
    CODEWIRE_CGROUP_ROOT="$work/cgroup" \
    CODEWIRE_BIN_ROOT="$work/bin" \
    CODEWIRE_SSH_FIXTURE_ROOT="$work/ssh" \
    CODEWIRE_SYSTEM_SBIN_ROOT="$work/system-sbin" \
    CODEWIRE_SYSTEM_BIN_ROOT="$work/bin" \
    CODEWIRE_INTERACTIVE_SHELL="$work/interactive-bash" \
    CODEWIRE_AGENTS_ROOT="$work/agents" \
    CODEWIRE_DESKTOP_ROOT="$work/desktop" \
    CODEWIRE_PROC_ROOT="$work/proc" \
    CODEWIRE_X11_SOCKET_ROOT="$work/x11" \
    CODEWIRE_DESKTOP_RUNTIME_ROOT="$work/tmp" \
    CODEWIRE_THEMES_ROOT="$work/themes" \
    CODEWIRE_CHROMIUM_ROOT="$work/chromium-lib" \
    CODEWIRE_CHROMIUM_FLAGS_FILE="$work/chromium-flags" \
    FAKE_CHROMIUM_FLAGS_FILE="$work/chromium-flags" \
    FAKE_CHROMIUM_LAUNCHER="${FAKE_CHROMIUM_LAUNCHER:-drops-inherited}" \
    CODEWIRE_APT_ROOT="$work/apt" \
    FAKE_CHROMIUM_ROOT="$work/chromium-lib" \
    FAKE_CHROMIUM="${FAKE_CHROMIUM:-starts}" \
    CODEWIRE_DESKTOP_STOP_POLLS="${FAKE_DESKTOP_STOP_POLLS:-600}" \
    FAKE_RUNTIME_ROOT="$work/tmp" \
    FAKE_DESKTOP_SECURITY="${FAKE_DESKTOP_SECURITY:-VncAuth}" \
    FAKE_DESKTOP_PASSWORD="${FAKE_DESKTOP_PASSWORD:-quiet}" \
    FAKE_DESKTOP_PASSWORD_MODE="${FAKE_DESKTOP_PASSWORD_MODE:-600}" \
    FAKE_DESKTOP_ROOT="$work/desktop" \
    FAKE_DESKTOP_EXPECTED_UID="${FAKE_DESKTOP_EXPECTED_UID:-$fixture_uid}" \
    FAKE_PROC_ROOT="$work/proc" \
    FAKE_X11_ROOT="$work/x11" \
    FAKE_DESKTOP_START="${FAKE_DESKTOP_START:-runs}" \
    FAKE_DESKTOP_LISTEN="${FAKE_DESKTOP_LISTEN:-0100007F:170D}" \
    FAKE_DESKTOP_LINGERS="${FAKE_DESKTOP_LINGERS:-false}" \
    FAKE_LAUNCHER_PID="$work/launcher.pid" \
    FAKE_DESKTOP_EXTRA="${FAKE_DESKTOP_EXTRA:-none}" \
    FAKE_DESKTOP_HELPER="${FAKE_DESKTOP_HELPER:-dbus-daemon}" \
    FAKE_DESKTOP_AGENT_SOCKET="${FAKE_DESKTOP_AGENT_SOCKET:-inherited}" \
    FAKE_AGENTS_ROOT="$work/agents" \
    FAKE_AGENTS_EXPECTED_UID="${FAKE_AGENTS_EXPECTED_UID:-$fixture_uid}" \
    FAKE_INTERACTIVE_FLAGS="${FAKE_INTERACTIVE_FLAGS:-imBHc}" \
    CODEWIRE_EXPECTED_PIDS_MAX=2048 \
    FAKE_CODEWIRE_GID="${FAKE_CODEWIRE_GID:-1000}" \
    FAKE_CODEWIRE_PASSWD_GID="${FAKE_CODEWIRE_PASSWD_GID:-1000}" \
    FAKE_BIN_ROOT="$work/bin" \
    FAKE_BIN_UID="${FAKE_BIN_UID:-0}" \
    FAKE_BIN_GID="${FAKE_BIN_GID:-0}" \
    FAIL_BIN_STAT="${FAIL_BIN_STAT:-false}" \
    MALFORMED_BIN_STAT="${MALFORMED_BIN_STAT:-false}" \
    FAIL_AGENT="${FAIL_AGENT:-}" \
    FAKE_CODEX_VERSION="${FAKE_CODEX_VERSION:-0.160.0}" \
    FAKE_PREFIX_STATE="$work/prefix-state" \
    FAKE_FIXTURE_UID="$fixture_uid" \
    FAKE_SSH_EXPECTED_UID="${FAKE_SSH_EXPECTED_UID:-$fixture_uid}" \
    FAKE_SSH_ROOT="$work/ssh" \
    FAIL_SSH_LOADER="${FAIL_SSH_LOADER:-false}" \
    FAIL_SSH_FIND="${FAIL_SSH_FIND:-false}" \
    CLAUDE_CODE_NO_FLICKER="${FAKE_NO_FLICKER-1}" \
    bash "$CONTRACT" "$@"
}

printf '8\n' >"$work/cgroup/pids.current"
printf '2048\n' >"$work/cgroup/pids.max"
printf 'max 0\n' >"$work/cgroup/pids.events"
if ! run_contract >"$work/success.out" 2>"$work/success.err"; then
  cat "$work/success.err" >&2
  fail 'a sound image failed the contract'
fi
if [[ -s "$work/success.err" ]]; then
  cat "$work/success.err" >&2
  fail 'successful contract emitted failure evidence'
fi
grep -Fxq 'codex-cli 0.160.0' "$work/success.out" || fail 'agent checks did not run'
grep -Fxq 'npm dry-run OK' "$work/success.out" || fail 'Codex install-plan check did not run'
if FAIL_AGENT=infocmp run_contract >"$work/terminfo.out" 2>"$work/terminfo.err"; then
  fail 'an image without the terminals'"'"' terminfo passed the contract'
fi
if FAKE_NO_FLICKER='' run_contract >"$work/flicker.out" 2>"$work/flicker.err"; then
  fail 'an image without CLAUDE_CODE_NO_FLICKER=1 passed the contract'
fi
for tool in kubectl atmos; do
  grep -Fxq "$tool test-version" "$work/success.out" || fail "$tool was not checked"
  status=0
  FAIL_AGENT="$tool" run_contract >"$work/$tool-failure.out" 2>"$work/$tool-failure.err" || status=$?
  [[ "$status" -eq 42 ]] || fail "$tool failure was not preserved: $status"
done
grep -Fxq 'workspace image verification: inert SSH fixture contract passed' "$work/success.out" ||
  fail 'prepared SSH fixture was not checked'
for tool in cargo rustc rustfmt cargo-clippy; do
  if FAIL_AGENT="$tool" run_contract >"$work/rust-failure.out" 2>"$work/rust-failure.err"; then
    fail "a broken Rust command was accepted: $tool"
  fi
done

for bin_failure in wrong-uid wrong-gid group-write other-write symlink stat-error malformed; do
  rm -f "$work/prefix-state"
  (
    case "$bin_failure" in
      wrong-uid) FAKE_BIN_UID=1001 ;;
      wrong-gid) FAKE_BIN_GID=1001 ;;
      group-write) chmod g+w "$work/bin" ;;
      other-write) chmod o+w "$work/bin" ;;
      symlink) mv "$work/bin" "$work/bin.real"; ln -s bin.real "$work/bin" ;;
      stat-error) FAIL_BIN_STAT=true ;;
      malformed) MALFORMED_BIN_STAT=true ;;
    esac
    if run_contract >"$work/bin-failure.out" 2>"$work/bin-failure.err"; then
      fail "invalid fixed launcher ancestry was accepted: $bin_failure"
    fi
    [[ ! -s "$work/bin-failure.out" ]] || fail "ancestry $bin_failure reached agent checks"
    [[ ! -e "$work/prefix-state" ]] || fail "ancestry $bin_failure prepared the npm prefix"
    grep -Eq '^workspace image verification: (invalid|untrusted) fixed launcher ancestry: ' "$work/bin-failure.err" ||
      fail "ancestry $bin_failure was not reported"
  )
  if [[ -L "$work/bin" ]]; then
    rm "$work/bin"
    mv "$work/bin.real" "$work/bin"
  fi
  chmod go-w "$work/bin"
done

grep -Fxq 'workspace image verification: desktop contract passed' "$work/success.out" ||
  fail 'the desktop was not checked'
[[ ! -e "$work/proc/4242" && ! -s "$work/proc/net/tcp" ]] || fail 'the desktop check left its desktop running'
assert_no_launcher 'a passing run'
for desktop_failure in missing-launcher missing-defaults writable-launcher wrong-owner missing-tool \
  running-before listening-before display-before start-fails all-interfaces another-listener a-udp-socket \
  bus-in-tmp abstract-bus ssh-agent gpg-agent agent-replaced lingers leaves-a-child \
  starts-without-a-password server-asks-for-nothing password-file-open password-in-arguments \
  password-in-environment password-printed leaves-the-password-file never-says-ready \
  no-wallpaper no-theme chromium-setuid-helper chromium-sandbox-off chromium-any-debugging-port \
  chromium-refuses-9222 chromium-silent-refusal chromium-passes-inherited-flags debian-source-left \
  chromium-crashes chromium-renders-nothing; do
  reset_desktop
  (
    case "$desktop_failure" in
      missing-launcher) chmod -x "$work/desktop/start" ;;
      missing-defaults) rm "$work/desktop/xdg/xfce4/xfconf/xfce-perchannel-xml/xfce4-session.xml" ;;
      writable-launcher) chmod o+w "$work/desktop/start" ;;
      wrong-owner) FAKE_DESKTOP_EXPECTED_UID=$((fixture_uid + 1)) ;;
      missing-tool) rm "$work/bin/Xvnc" ;;
      running-before)
        /usr/bin/mkdir "$work/proc/7"
        printf '7 (xfce4-session) S 1 7 7 0\n' >"$work/proc/7/stat" ;;
      listening-before) printf '   0: 0100007F:170D 00000000:0000 0A\n' >"$work/proc/net/tcp" ;;
      display-before)
        printf '0: 00000002 00000000 00010000 0001 01 10 %s/X1\n' "$work/x11" >>"$work/proc/net/unix" ;;
      start-fails) FAKE_DESKTOP_START=fails ;;
      all-interfaces) FAKE_DESKTOP_LISTEN=00000000:170D ;;
      another-listener) FAKE_DESKTOP_EXTRA=tcp ;;
      a-udp-socket) FAKE_DESKTOP_EXTRA=udp ;;
      bus-in-tmp) FAKE_DESKTOP_EXTRA=bus-in-tmp ;;
      abstract-bus) FAKE_DESKTOP_EXTRA=abstract-bus ;;
      ssh-agent) FAKE_DESKTOP_HELPER=ssh-agent ;;
      gpg-agent) FAKE_DESKTOP_HELPER=gpg-agent ;;
      agent-replaced) FAKE_DESKTOP_AGENT_SOCKET=replaced ;;
      lingers) FAKE_DESKTOP_LINGERS=true FAKE_DESKTOP_STOP_POLLS=5 ;;
      leaves-a-child) FAKE_DESKTOP_LINGERS=child FAKE_DESKTOP_STOP_POLLS=5 ;;
      starts-without-a-password) FAKE_DESKTOP_START=without-a-password ;;
      server-asks-for-nothing) FAKE_DESKTOP_SECURITY=None ;;
      password-file-open) FAKE_DESKTOP_PASSWORD_MODE=644 ;;
      password-in-arguments) FAKE_DESKTOP_PASSWORD=in-arguments ;;
      password-in-environment) FAKE_DESKTOP_PASSWORD=in-environment ;;
      password-printed) FAKE_DESKTOP_PASSWORD=printed ;;
      leaves-the-password-file) FAKE_DESKTOP_LINGERS=password-file FAKE_DESKTOP_STOP_POLLS=5 ;;
      never-says-ready) FAKE_DESKTOP_START=silent ;;
      no-wallpaper) rm "$work/desktop/share/wallpaper.svg" ;;
      no-theme) rm "$work/themes/Codewire/gtk-3.0/gtk.css" ;;
      chromium-setuid-helper)
        touch "$work/chromium-lib/chrome-sandbox"
        chmod 4755 "$work/chromium-lib/chrome-sandbox" ;;
      chromium-sandbox-off) printf 'export CHROMIUM_FLAGS="--no-sandbox"\n' >>"$work/chromium-flags" ;;
      chromium-any-debugging-port) printf 'export CHROMIUM_FLAGS="--no-first-run"\n' >"$work/chromium-flags" ;;
      chromium-refuses-9222)
        printf 'case "$*" in *remote-debugging*) echo "use 9222" >&2; exit 2 ;; esac\n' >"$work/chromium-flags" ;;
      chromium-passes-inherited-flags)
        # A launcher that keeps the caller's variables, with defaults that
        # read only the arguments.
        FAKE_CHROMIUM_LAUNCHER=passes-inherited
        sed '/^codewire_only_debugging_port_9222 \$/d' "$CHROMIUM_DEFAULTS" >"$work/chromium-flags"
        ! cmp -s "$CHROMIUM_DEFAULTS" "$work/chromium-flags" || fail 'the fixture did not drop the variable checks' ;;
      chromium-silent-refusal)
        printf 'case "$*" in *remote-debugging-port=9222*) ;; *remote-debugging*) exit 2 ;; esac\n' >"$work/chromium-flags" ;;
      debian-source-left)
        printf 'URIs: https://snapshot.debian.org/archive/debian/\n' >"$work/apt/sources.list.d/chromium.sources" ;;
      chromium-crashes) FAKE_CHROMIUM=crashes ;;
      chromium-renders-nothing) FAKE_CHROMIUM=blank ;;
    esac
    if run_contract >"$work/desktop-failure.out" 2>"$work/desktop-failure.err"; then
      fail "a broken desktop layer was accepted: $desktop_failure"
    fi
    # The checks before the desktop's passed, so the failure is the desktop's.
    grep -Fxq 'bwrap test-version' "$work/desktop-failure.out" ||
      fail "desktop failure $desktop_failure came from an earlier check"
  )
  assert_no_launcher "$desktop_failure"
  chmod 0755 "$work/desktop/start"
  touch "$work/desktop/xdg/xfce4/xfconf/xfce-perchannel-xml/xfce4-session.xml" \
    "$work/desktop/share/wallpaper.svg" "$work/themes/Codewire/gtk-3.0/gtk.css"
  rm -f "$work/chromium-lib/chrome-sandbox" "$work/apt/sources.list.d/chromium.sources"
  cp "$CHROMIUM_DEFAULTS" "$work/chromium-flags"
  [[ -e "$work/bin/Xvnc" ]] || ln -s agent "$work/bin/Xvnc"
  rm -rf "$work/proc/7"
done
reset_desktop
# A launcher that keeps the caller's flag variables is still held to 9222
# by the image's defaults, which read those variables too.
if ! FAKE_CHROMIUM_LAUNCHER=passes-inherited run_contract >"$work/inherits.out" 2>"$work/inherits.err"; then
  cat "$work/inherits.err" >&2
  fail 'the defaults did not refuse a debugging port in an inherited flag variable'
fi
assert_no_launcher 'a launcher that keeps inherited flags'
# Where Chromium has no sandbox it refuses to start, and that passes.
reset_desktop
if ! FAKE_CHROMIUM=refuses run_contract >"$work/refuses.out" 2>"$work/refuses.err"; then
  cat "$work/refuses.err" >&2
  fail 'a Chromium that refused to start without a sandbox failed the contract'
fi
grep -Fxq 'workspace image verification: chromium has no sandbox here and refused to start' "$work/refuses.out" ||
  fail 'the refusal was not reported'
reset_desktop
# A zombie that still names the server is not a running desktop.
/usr/bin/mkdir "$work/proc/9"
printf '9 (Xvnc) Z 1 9 9 0\n' >"$work/proc/9/stat"
if ! run_contract >"$work/zombie.out" 2>"$work/zombie.err"; then
  cat "$work/zombie.err" >&2
  fail 'a desktop process awaiting its reaper failed the contract'
fi
rm -rf "$work/proc/9"

if FAKE_CODEWIRE_GID=1001 run_contract >"$work/process-gid.out" 2>"$work/process-gid.err"; then
  fail 'process GID drift was accepted'
fi
if FAKE_CODEWIRE_PASSWD_GID=1001 run_contract >"$work/passwd-gid.out" 2>"$work/passwd-gid.err"; then
  fail 'passwd GID drift was accepted'
fi

for ssh_failure in missing-server writable-server wrong-owner host-key system-server missing-library loader find; do
  (
    case "$ssh_failure" in
      missing-server) chmod -x "$work/ssh/usr/sbin/sshd" ;;
      writable-server) chmod o+w "$work/ssh/usr/sbin/sshd" ;;
      wrong-owner) FAKE_SSH_EXPECTED_UID=4294967294 ;;
      host-key) touch "$work/ssh/ssh_host_ed25519_key" ;;
      system-server) touch "$work/system-sbin/sshd" ;;
      missing-library) mv "$work/ssh/usr/lib/$multiarch/libwrap.so.0" "$work/libwrap.saved" ;;
      loader) FAIL_SSH_LOADER=true ;;
      find) FAIL_SSH_FIND=true ;;
    esac
    if run_contract >"$work/ssh-failure.out" 2>"$work/ssh-failure.err"; then
      fail "invalid prepared SSH fixture was accepted: $ssh_failure"
    fi
  )
  chmod 0755 "$work/ssh/usr/sbin/sshd"
  rm -f "$work/ssh/ssh_host_ed25519_key" "$work/system-sbin/sshd"
  if [[ -e "$work/libwrap.saved" ]]; then
    mv "$work/libwrap.saved" "$work/ssh/usr/lib/$multiarch/libwrap.so.0"
  fi
done

if FAKE_CODEX_VERSION=0.149.0 run_contract >"$work/stale.out" 2>"$work/stale.err"; then
  fail 'stale Codex version was accepted'
fi
for agents_failure in writable wrong-owner; do
  (
    case "$agents_failure" in
      writable) chmod g+w "$work/agents/npm/bin/kimi" ;;
      wrong-owner) FAKE_AGENTS_EXPECTED_UID=4294967294 ;;
    esac
    if run_contract >"$work/agents.out" 2>"$work/agents.err"; then
      fail "shipped agents accepted as $agents_failure"
    fi
    grep -Fxq 'workspace image verification: shipped agents are writable' "$work/agents.err" ||
      fail "shipped agents $agents_failure was not reported"
  )
  chmod g-w "$work/agents/npm/bin/kimi"
done
# A wrapper that upgrades in place, not into the home, must fail the contract.
cp "$work/agents/upgrade/kimi" "$work/kimi.saved"
sed -i 's|exec npm install --global @moonshot-ai/kimi-code@latest|exec npm --prefix /opt/codewire/agents/npm install --global @moonshot-ai/kimi-code@latest|' \
  "$work/agents/upgrade/kimi"
if run_contract >"$work/route.out" 2>"$work/route.err"; then
  fail 'an in-place agent upgrade route was accepted'
fi
grep -Fxq 'workspace image verification: kimi upgrade does not upgrade into the home' "$work/route.err" ||
  fail 'in-place agent upgrade route was not reported'
cp "$work/kimi.saved" "$work/agents/upgrade/kimi"
for shell_case in 'himBHc:interactive bash hashes command paths' 'mBc:interactive bash did not start'; do
  flags="${shell_case%%:*}"
  if FAKE_INTERACTIVE_FLAGS="$flags" run_contract >"$work/shell.out" 2>"$work/shell.err"; then
    fail "interactive shell flags $flags were accepted"
  fi
  grep -Fxq "workspace image verification: ${shell_case#*:}" "$work/shell.err" ||
    fail "interactive shell flags $flags were not reported"
done
for argument in --unknown '--mounted-home-agents extra'; do
  set +e
  # shellcheck disable=SC2086 # Deliberately exercise both one and two arguments.
  run_contract $argument >"$work/argument.out" 2>"$work/argument.err"
  status=$?
  set -e
  [[ "$status" -eq 2 ]] || fail 'invalid contract arguments were accepted'
done

printf '1\n' >"$work/cgroup/pids.max"
: >"$work/cgroup/pids.events"
for i in $(seq 1 20); do
  printf 'event_%02d %d\n' "$i" "$i" >>"$work/cgroup/pids.events"
done
set +e
run_contract >"$work/mismatch.out" 2>"$work/mismatch.err"
status=$?
set -e
[[ "$status" -eq 1 ]] || fail "pids.max mismatch returned $status instead of 1"
[[ ! -s "$work/mismatch.out" ]] || fail 'pids.max mismatch reached agent checks'
[[ "$(wc -l <"$work/mismatch.err")" -eq 18 ]] ||
  fail 'PID evidence was not bounded to two counters and 16 event lines'
if grep -Ev '^workspace image verification: (pids\.current|pids\.max|pids\.events)=' "$work/mismatch.err" | grep -q .; then
  fail 'failure output contained non-PID evidence'
fi

printf '2048\n' >"$work/cgroup/pids.max"
printf 'max 3\n' >"$work/cgroup/pids.events"
set +e
FAIL_AGENT=codex run_contract >"$work/agent-failure.out" 2>"$work/agent-failure.err"
status=$?
set -e
[[ "$status" -eq 42 ]] || fail "agent failure status was not preserved: $status"
grep -Fxq 'workspace image verification: pids.current=8' "$work/agent-failure.err" ||
  fail 'agent failure omitted pids.current'
grep -Fxq 'workspace image verification: pids.max=2048' "$work/agent-failure.err" ||
  fail 'agent failure omitted pids.max'
grep -Fxq 'workspace image verification: pids.events=max 3' "$work/agent-failure.err" ||
  fail 'agent failure omitted pids.events'

# Exercise the real image dispatcher with bash as the multicall test binary.
# Unlike a script stub, bash -c observes the argv[0] passed by exec -a.
mkdir -p "$work/rust/bin" "$work/rust/cargo/bin" "$work/rust/rustup" "$work/home"
cp "$ROOT/images/workspace/rust/rustup" "$work/rust/bin/rustup"
ln -s "$(command -v bash)" "$work/rust/cargo/bin/rustup"
for tool in cargo rustc rustdoc rustfmt cargo-clippy rustup; do
  [[ "$tool" = rustup ]] || ln -s rustup "$work/rust/bin/$tool"
  # shellcheck disable=SC2016 # The child shell observes exec -a and its environment.
  observed="$(env -u RUSTUP_HOME HOME="$work/home" CARGO_HOME="$work/home/.cargo" \
    "$work/rust/bin/$tool" -c 'printf "%s:%s:%s" "$0" "$RUSTUP_HOME" "$CARGO_HOME"')"
  [[ "$observed" = "$tool:$work/rust/rustup:$work/home/.cargo" ]] ||
    fail "Rust dispatcher lost command identity, fallback or Cargo home: $tool"
done
for home_kind in directory file dangling-symlink; do
  case "$home_kind" in
    directory) mkdir "$work/home/.rustup" ;;
    file) touch "$work/home/.rustup" ;;
    dangling-symlink) ln -s absent "$work/home/.rustup" ;;
  esac
  # shellcheck disable=SC2016 # Inspect the child process, not this test shell.
  observed="$(env -u RUSTUP_HOME HOME="$work/home" "$work/rust/bin/cargo" \
    -c 'printf "%s" "${RUSTUP_HOME-unset}"')"
  [[ "$observed" = unset ]] || fail "Rust dispatcher hid existing home state: $home_kind"
  if [[ "$home_kind" = directory ]]; then rmdir "$work/home/.rustup"; else rm "$work/home/.rustup"; fi
done
for explicit_home in "$work/explicit" ''; do
  # shellcheck disable=SC2016 # Inspect the child process, not this test shell.
  observed="$(HOME="$work/home" RUSTUP_HOME="$explicit_home" "$work/rust/bin/rustup" \
    -c 'printf "%s" "$RUSTUP_HOME"')"
  [[ "$observed" = "$explicit_home" ]] || fail 'Rust dispatcher replaced an explicit home'
done
# shellcheck disable=SC2016 # Arguments and selection must survive in the child.
observed="$(env -u RUSTUP_HOME HOME="$work/home" RUSTUP_TOOLCHAIN=nightly \
  "$work/rust/bin/cargo" -c 'printf "%s:%s:%s" "$RUSTUP_TOOLCHAIN" "$1" "$2"' -- 'two words' '+stable')"
[[ "$observed" = 'nightly:two words:+stable' ]] || fail 'Rust dispatcher changed arguments or toolchain selection'
set +e
env -u RUSTUP_HOME HOME="$work/home" "$work/rust/bin/rustc" -c 'exit 42'
status=$?
set -e
[[ "$status" -eq 42 ]] || fail 'Rust dispatcher lost the tool exit status'

echo 'workspace agent PID and Rust dispatcher contracts: OK'
