# shellcheck shell=bash
# Isolation for local VM smokes that drive real cw binaries on the host
# (#5220, #5238). Sourced, never run. A smoke that sources it gets:
#
# - its own HOME and XDG roots, and a private Secret Service (dbus-daemon and
#   gnome-keyring-daemon on a short private tmpfs XDG_RUNTIME_DIR), so no cw
#   it runs reads or writes the host's keyring, login or agent;
# - cw run with `env -i` and only the variables named here, so the caller's
#   SSH_AUTH_SOCK, GITHUB_TOKEN, ANTHROPIC_* or OPENAI_* never reach it, inside
#   a private mount namespace (bwrap) where the host's runtime directory, and
#   the passwd home's keyrings, SSH keys and Codewire state, are empty, and a
#   stat-only self-check inside it refuses to run cw if the host's bus is
#   still reachable;
# - one systemd user scope around the whole smoke. cw detaches its credential
#   service and local VM supervisor (parent 1); they stay in the scope's
#   cgroup, so stopping the scope ends them, and the scope's own process list
#   names them exactly, never a command-line match;
# - no call to the host's Secret Service, ever. A loop of short-lived D-Bus
#   reads to it crashed a host gnome-keyring-daemon (#5250, #5256); the
#   namespace makes the host keyring unreachable instead.
#
# The sourcing script defines die MESSAGE (print and exit nonzero), calls
# smoke_run_in_scope first, and runs smoke_isolation_end from an EXIT trap
# inside the scope; smoke_run_in_scope then stops the scope however the
# script ended.

# Read by the sourcing smoke as well as here.
# shellcheck disable=SC2034
SMOKE_ROOT=''
SMOKE_HOME=''
SMOKE_WORKSPACE=''
SMOKE_RUNTIME=''
SMOKE_RUNTIME_PARENT=''
SMOKE_DBUS_ADDRESS=''
SMOKE_DBUS_PID=''
SMOKE_KEYRING_PID=''
SMOKE_KEYRING_CONTROL=''
# Overridden only by the library's own tests.
SMOKE_PROC_ROOT=/proc
SMOKE_CGROUP_ROOT=/sys/fs/cgroup
SMOKE_BUSCTL=/usr/bin/busctl
SMOKE_SYSTEMD_RUN=/usr/bin/systemd-run
SMOKE_SYSTEMCTL=/usr/bin/systemctl
SMOKE_BWRAP=/usr/bin/bwrap
SMOKE_HOST_RUNTIME="/run/user/$(id -u)"
# The account's home from passwd, not $HOME: anything that resolves the home
# through getpwuid finds these paths masked too.
SMOKE_HOST_HOME="$(getent passwd "$(id -u)" | cut -d: -f6)"
SMOKE_HOST_MASKS=(.ssh .config/codewire .codewire .local/share/keyrings)
# cw puts sockets under the runtime directory (#2745) and sockaddr_un bounds a
# path at 108 bytes, so the directory's own path must stay short.
SMOKE_RUNTIME_MAX_BYTES=40

# Run "$@" inside a new systemd user scope named UNIT, unless already inside
# it. Every process the command starts, detached or not, stays in the scope.
smoke_scope_exec() {
  local unit="$1"
  shift
  [[ "$unit" =~ ^cw-local-smoke-[0-9a-z]{1,24}$ && "${1:-}" == -- ]] || die 'smoke scope: unit or -- missing'
  shift
  if [[ "${CODEWIRE_SMOKE_SCOPE:-}" == "$unit" ]]; then
    "$@"
    return
  fi
  # systemd-run expands $VAR in the command it runs unless told not to; the
  # smoke's own arguments must reach it unchanged.
  CODEWIRE_SMOKE_SCOPE="$unit" "$SMOKE_SYSTEMD_RUN" --user --scope --quiet \
    --expand-environment=no --unit="$unit" --collect -- "$@"
}

# Stop the scope: everything still in it, including detached services, ends.
smoke_scope_stop() {
  local unit="$1"
  [[ "$unit" =~ ^cw-local-smoke-[0-9a-z]{1,24}$ ]] || die 'smoke scope: bad unit'
  "$SMOKE_SYSTEMCTL" --user stop "$unit.scope" 2>/dev/null || true
}

# Run the calling script inside a smoke scope of its own; call it first, as
#   smoke_run_in_scope ID -- "$0" "$@"
# Outside a scope it runs the script again in a new scope
# cw-local-smoke-ID<pid>, stops that scope once the script ends, ending what
# cw detached into it, and exits with the script's status. Inside one, it
# returns and the script goes on.
smoke_run_in_scope() {
  local id="$1" unit status=0
  shift
  [[ "$id" =~ ^[0-9a-z]{1,12}$ && "${1:-}" == -- ]] || die 'smoke scope: id or -- missing'
  shift
  [[ -z "${CODEWIRE_SMOKE_SCOPE:-}" ]] || return 0
  unit="cw-local-smoke-$id$$"
  smoke_scope_exec "$unit" -- "$@" || status=$?
  smoke_scope_stop "$unit"
  exit "$status"
}

# The PIDs in the current scope, from its cgroup; nothing else is ever killed
# or inspected by these helpers.
smoke_scope_pids() {
  local group
  group="$(cut -d: -f3 "$SMOKE_PROC_ROOT/self/cgroup")" || return 1
  [[ "$group" == *"/${CODEWIRE_SMOKE_SCOPE:?not inside a smoke scope}.scope" ]] || return 1
  cat "$SMOKE_CGROUP_ROOT$group/cgroup.procs"
}

# The scope's credential service for this HOME: the one process whose argv is
# exactly `cw __local-credential-authority --root HOME/.codewire/credentials-v1`.
smoke_credential_service_pid() {
  local pid root="$SMOKE_HOME/.codewire/credentials-v1" found=''
  local -a argv
  while read -r pid; do
    argv=()
    mapfile -d '' -t argv 2>/dev/null <"$SMOKE_PROC_ROOT/$pid/cmdline" || continue
    [[ ${#argv[@]} -eq 4 && "${argv[1]}" == __local-credential-authority &&
       "${argv[2]}" == --root && "${argv[3]}" == "$root" ]] || continue
    [[ -z "$found" ]] || return 1
    found="$pid"
  done < <(smoke_scope_pids)
  [[ -n "$found" ]] && printf '%s\n' "$found"
}

# Fail unless the credential service serving this HOME runs BIN.
smoke_assert_credential_service_binary() {
  local bin="$1" pid
  pid="$(smoke_credential_service_pid)" || die 'no single credential service serves the smoke HOME'
  [[ "$(readlink -f "$SMOKE_PROC_ROOT/$pid/exe")" == "$(readlink -f "$bin")" ]] ||
    die "the credential service runs $(readlink -f "$SMOKE_PROC_ROOT/$pid/exe"), not $bin"
}

# Refuse a binary whose content is not HEX; a downloaded release runs only
# after it matches its published sha256.
smoke_require_sha256() {
  local bin="$1" hex="$2"
  [[ "$hex" =~ ^[0-9a-f]{64}$ && -f "$bin" && ! -L "$bin" ]] ||
    die "smoke binary or checksum is invalid: $bin"
  [[ "$(sha256sum -- "$bin" | cut -d' ' -f1)" == "$hex" ]] ||
    die "smoke binary does not match its sha256: $bin"
}

# The whole environment a smoke's cw sees.
smoke_environment() {
  printf '%s\0' \
    PATH=/usr/bin:/bin \
    LANG=C.UTF-8 \
    USER="$(id -un)" \
    HOME="$SMOKE_HOME" \
    XDG_CONFIG_HOME="$SMOKE_HOME/.config" \
    XDG_DATA_HOME="$SMOKE_HOME/.local/share" \
    XDG_STATE_HOME="$SMOKE_HOME/.local/state" \
    XDG_CACHE_HOME="$SMOKE_HOME/.cache" \
    XDG_RUNTIME_DIR="$SMOKE_RUNTIME" \
    DBUS_SESSION_BUS_ADDRESS="$SMOKE_DBUS_ADDRESS" \
    CODEWIRE_SMOKE_SCOPE="${CODEWIRE_SMOKE_SCOPE:-}"
}

# Fail if the environment cw would see names the host's home, bus or runtime,
# or carries anything a provider or agent would read.
smoke_refuse_host_leaks() {
  local entry host_runtime
  local -a environment
  host_runtime="$SMOKE_HOST_RUNTIME"
  [[ -n "$SMOKE_HOME" && -n "$SMOKE_RUNTIME" && -n "$SMOKE_DBUS_ADDRESS" ]] ||
    die 'smoke isolation has not begun'
  mapfile -d '' -t environment < <(smoke_environment)
  for entry in "${environment[@]}"; do
    case "$entry" in
      SSH_AUTH_SOCK=* | GITHUB_TOKEN=* | GH_TOKEN=* | ANTHROPIC_* | OPENAI_* | CLAUDE_* | CODEX_*)
        die "smoke environment carries ${entry%%=*}" ;;
      HOME="$HOME" | HOME="$HOME"/ | XDG_RUNTIME_DIR="$host_runtime" | \
      DBUS_SESSION_BUS_ADDRESS="unix:path=$host_runtime/bus")
        die "smoke environment points at the host: ${entry%%=*}" ;;
    esac
  done
}

# The bwrap arguments of the smoke's mount namespace: the host as it is,
# except an empty tmpfs over the host's runtime directory, with only the
# smoke's own runtime directory bound back in, and over each of the passwd
# home's masked directories that exists.
smoke_namespace_arguments() {
  local relative
  printf '%s\0' --dev-bind / / --tmpfs "$SMOKE_HOST_RUNTIME" --bind "$SMOKE_RUNTIME" "$SMOKE_RUNTIME"
  for relative in "${SMOKE_HOST_MASKS[@]}"; do
    [[ -d "$SMOKE_HOST_HOME/$relative" ]] && printf '%s\0' --tmpfs "$SMOKE_HOST_HOME/$relative"
  done
  printf '%s\0' --chdir "$SMOKE_WORKSPACE"
}

# Run inside the namespace before cw, with stat alone: the host's bus socket
# is absent, each masked directory is empty, and the bus cw is given is the
# smoke's own. Then the command runs with only the smoke's environment.
# shellcheck disable=SC2016
SMOKE_SELF_CHECK='
host_runtime="$1" runtime="$2" address="$3" home="$4"
shift 4
masks=()
while [[ "$1" != --environment ]]; do masks+=("$1"); shift; done
shift
environment=()
while [[ "$1" != -- ]]; do environment+=("$1"); shift; done
shift
fail() { echo "smoke self-check: $*" >&2; exit 125; }
[[ ! -e "$host_runtime/bus" && ! -L "$host_runtime/bus" ]] || fail "the host bus is reachable"
for relative in "${masks[@]}"; do
  [[ ! -d "$home/$relative" || -z "$(ls -A -- "$home/$relative")" ]] || fail "$relative is not masked"
done
[[ "$address" == "unix:path=$runtime/bus" && -S "$runtime/bus" ]] || fail "the bus is not the smoke'"'"'s own"
exec env -i "${environment[@]}" "$@"
'

# Run a cw binary (or any command) in the smoke's namespace with only the
# smoke's environment, from the smoke's workspace directory. Never from HOME:
# a create with no configuration file shares its directory live, and cw
# refuses to share one that holds Codewire state or a keyring, as HOME does.
smoke_cw() {
  local -a environment namespace
  mapfile -d '' -t environment < <(smoke_environment)
  mapfile -d '' -t namespace < <(smoke_namespace_arguments)
  "$SMOKE_BWRAP" "${namespace[@]}" -- /usr/bin/bash -c "$SMOKE_SELF_CHECK" smoke-self-check \
    "$SMOKE_HOST_RUNTIME" "$SMOKE_RUNTIME" "$SMOKE_DBUS_ADDRESS" "$SMOKE_HOST_HOME" \
    "${SMOKE_HOST_MASKS[@]}" --environment "${environment[@]}" -- "$@"
}

smoke_wait_ready() {
  local pid="$1" service="$2"
  for _attempt in {1..200}; do
    "$SMOKE_BUSCTL" --address="$SMOKE_DBUS_ADDRESS" --no-pager status "$service" >/dev/null 2>&1 &&
      return 0
    [[ -d "$SMOKE_PROC_ROOT/$pid" ]] || return 1
    sleep 0.05
  done
  return 1
}

# Make ROOT's HOME and a short private runtime directory, start the private
# Secret Service, and prove the namespace from inside it.
smoke_isolation_begin() {
  local root="$1" parent="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
  [[ "$root" == /* && -d "$root" && ! -L "$root" ]] || die 'smoke root must be an existing absolute directory'
  [[ "$(stat -c '%u %a' "$parent")" == "$(id -u) 700" &&
     "$(findmnt -nro FSTYPE -T "$parent")" == tmpfs ]] ||
    die 'the runtime parent must be a private tmpfs directory'
  SMOKE_ROOT="$root"
  SMOKE_HOME="$root/home"
  SMOKE_WORKSPACE="$root/workspace"
  SMOKE_KEYRING_CONTROL="$root/keyring-control"
  mkdir -m 0700 "$SMOKE_HOME" "$SMOKE_WORKSPACE" "$SMOKE_KEYRING_CONTROL" "$SMOKE_HOME/.config" \
    "$SMOKE_HOME/.local" "$SMOKE_HOME/.local/share" "$SMOKE_HOME/.local/state" "$SMOKE_HOME/.cache"
  SMOKE_RUNTIME_PARENT="$parent"
  SMOKE_RUNTIME="$(mktemp -d "$parent/.cwls-XXXXXX")"
  (( ${#SMOKE_RUNTIME} <= SMOKE_RUNTIME_MAX_BYTES )) || die 'the smoke runtime directory path is too long for its sockets'
  SMOKE_DBUS_ADDRESS="unix:path=$SMOKE_RUNTIME/bus"

  env -i PATH=/usr/bin:/bin LC_ALL=C XDG_RUNTIME_DIR="$SMOKE_RUNTIME" \
    /usr/bin/dbus-daemon --session --address="$SMOKE_DBUS_ADDRESS" --nofork --nopidfile \
    >"$root/dbus.log" 2>&1 &
  SMOKE_DBUS_PID=$!
  smoke_wait_ready "$SMOKE_DBUS_PID" org.freedesktop.DBus || die 'the private D-Bus did not start'
  printf '%s' codewire-local-smoke-keyring | env -i PATH=/usr/bin:/bin LC_ALL=C \
    XDG_RUNTIME_DIR="$SMOKE_RUNTIME" XDG_CONFIG_HOME="$SMOKE_HOME/.config" \
    XDG_DATA_HOME="$SMOKE_HOME/.local/share" DBUS_SESSION_BUS_ADDRESS="$SMOKE_DBUS_ADDRESS" \
    /usr/bin/gnome-keyring-daemon --foreground --unlock --components=secrets \
      --control-directory="$SMOKE_KEYRING_CONTROL" >"$root/keyring.log" 2>&1 &
  SMOKE_KEYRING_PID=$!
  smoke_wait_ready "$SMOKE_KEYRING_PID" org.freedesktop.secrets || die 'the private Secret Service did not start'
  smoke_refuse_host_leaks
  smoke_cw /usr/bin/true || die 'the smoke namespace failed its self-check'
}

smoke_stop_pid() {
  local pid="$1" executable="$2"
  [[ -n "$pid" && -d "$SMOKE_PROC_ROOT/$pid" ]] || return 0
  [[ "$(readlink -f "$SMOKE_PROC_ROOT/$pid/exe")" == "$(readlink -f "$executable")" ]] || return 1
  kill -TERM -- "$pid" 2>/dev/null || true
  for _attempt in {1..100}; do
    [[ -d "$SMOKE_PROC_ROOT/$pid" ]] || break
    sleep 0.05
  done
  [[ -d "$SMOKE_PROC_ROOT/$pid" ]] && kill -KILL -- "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null || true
}

# Stop the private Secret Service by recorded PID and remove the runtime
# directory.
smoke_isolation_end() {
  local failed=0
  smoke_stop_pid "$SMOKE_KEYRING_PID" /usr/bin/gnome-keyring-daemon || failed=1
  smoke_stop_pid "$SMOKE_DBUS_PID" /usr/bin/dbus-daemon || failed=1
  SMOKE_KEYRING_PID='' SMOKE_DBUS_PID=''
  if [[ -n "$SMOKE_RUNTIME" && "$SMOKE_RUNTIME" == "$SMOKE_RUNTIME_PARENT"/.cwls-* &&
        -d "$SMOKE_RUNTIME" && ! -L "$SMOKE_RUNTIME" ]]; then
    rm -rf -- "$SMOKE_RUNTIME"
  fi
  SMOKE_RUNTIME=''
  return "$failed"
}
