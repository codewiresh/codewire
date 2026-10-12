#!/usr/bin/env bash
# Shared placed-workload proof for the broker-owned SSH agent. This target is
# loopback-only and receives public keys only; provider key material remains in
# the selected credential authority.
set -euo pipefail

readonly STATE_ROOT='/workspace/.cw-ssh-smoke'
readonly LISTEN_HOST='127.0.0.1'
readonly LISTEN_PORT='22222'
readonly SERVER_CONFIG="$STATE_ROOT/sshd_config"
readonly SERVER_PID="$STATE_ROOT/sshd.pid"
readonly SERVER_IDENTITY="$STATE_ROOT/sshd.identity"
readonly SERVER_BOOT="$STATE_ROOT/sshd.boot"
readonly SERVER_LOG="$STATE_ROOT/sshd.log"
readonly SERVER_ROOT='/opt/codewire/fixtures/openssh'
readonly SERVER_BINARY="$SERVER_ROOT/usr/sbin/sshd"
readonly AUTHORIZED_KEYS="$STATE_ROOT/authorized_keys"
readonly CLIENT_ROOT="$STATE_ROOT/client"
readonly KNOWN_HOSTS="$CLIENT_ROOT/known_hosts"
TARGET_USER="$(id -un)"
readonly TARGET_USER

# The native failure path intentionally preserves the VM disks after stopping
# its processes. Flush fixture evidence before that stop so journal inspection
# cannot mistake an older directory view for the failed command's result.
trap '[[ ! -d "$STATE_ROOT" ]] || /usr/bin/sync -f "$STATE_ROOT" 2>/dev/null || true' EXIT

fail() {
  local diagnostic=''
  if [[ -d "$STATE_ROOT" && ! -L "$STATE_ROOT" ]]; then
    diagnostic="$(mktemp "$STATE_ROOT/.failure.XXXXXX" 2>/dev/null || true)"
    if [[ -n "$diagnostic" ]]; then
      chmod 0600 "$diagnostic" 2>/dev/null || true
      if printf '%s\n' "$*" >"$diagnostic" 2>/dev/null; then
        # Rename replaces a hostile failure.log symlink rather than following it.
        mv -fT -- "$diagnostic" "$STATE_ROOT/failure.log" 2>/dev/null || true
      fi
      [[ ! -e "$diagnostic" ]] || rm -f -- "$diagnostic" 2>/dev/null || true
    fi
  fi
  printf '[stock-ssh-workload] ERROR: %s\n' "$*" >&2
  exit 1
}

case "$-" in
  *x*) fail 'shell tracing must remain disabled' ;;
esac

require_no_extra_arguments() {
  [[ $# -eq 0 ]] || fail 'unexpected arguments'
}

require_installed() {
  [[ -d "$STATE_ROOT" && ! -L "$STATE_ROOT" ]] || fail 'fixture is not installed'
  [[ -f "$SERVER_CONFIG" && ! -L "$SERVER_CONFIG" ]] || fail 'server config is unavailable'
}

prepare_authorization() {
  local owner mode expected
  [[ "$(authorization_command_state)" == strict-modes-safe ]] ||
    fail 'stock authorization command path is unsafe'
  [[ -f "$STATE_ROOT/client_key.pub" && ! -L "$STATE_ROOT/client_key.pub" ]] ||
    fail 'preserved public authorization is unavailable'
  expected="restrict $(cat -- "$STATE_ROOT/client_key.pub")"
  if [[ -e "$AUTHORIZED_KEYS" || -L "$AUTHORIZED_KEYS" ]]; then
    [[ -f "$AUTHORIZED_KEYS" && ! -L "$AUTHORIZED_KEYS" ]] ||
      fail 'authorization file collided with another object'
    read -r owner mode < <(stat -Lc '%u %a' -- "$AUTHORIZED_KEYS") ||
      fail 'authorization file cannot be inspected'
    [[ "$owner" == "$(id -u)" && "$mode" == 600 &&
       "$(cat -- "$AUTHORIZED_KEYS")" == "$expected" ]] ||
      fail 'authorization file ownership, mode, or public value drifted'
  else
    (umask 077; set -o noclobber; printf '%s\n' "$expected" >"$AUTHORIZED_KEYS") ||
      fail 'could not restore public authorization'
  fi
}

process_state_start() {
  local pid="$1" process_stat
  local -a process_fields
  [[ "$pid" =~ ^[1-9][0-9]*$ && -d "/proc/$pid" ]] || return 1
  process_stat="$(cat -- "/proc/$pid/stat" 2>/dev/null)" || return 1
  read -r -a process_fields <<<"${process_stat##*) }"
  [[ "${process_fields[0]:-}" =~ ^[A-Z]$ ]] || return 1
  [[ "${process_fields[19]:-}" =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s %s\n' "${process_fields[0]}" "${process_fields[19]}"
}

server_process_start() {
  local pid="$1" arguments expected listener_prefix suffix state started
  [[ "$pid" =~ ^[1-9][0-9]*$ && -d "/proc/$pid" ]] || return 1
  arguments="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null)" || return 1
  arguments="${arguments%"${arguments##*[![:space:]]}"}"
  expected="$SERVER_BINARY -D -f $SERVER_CONFIG -E $SERVER_LOG"
  listener_prefix="sshd: $expected [listener] "
  if [[ "$arguments" != "$expected" ]]; then
    [[ "$arguments" == "$listener_prefix"* ]] || return 1
    suffix="${arguments#"$listener_prefix"}"
    [[ "$suffix" =~ ^[0-9]+\ of\ [1-9][0-9]*-[1-9][0-9]*\ startups$ ]] || return 1
  fi
  read -r state started < <(process_state_start "$pid") || return 1
  [[ "$state" != Z ]] || return 1
  printf '%s\n' "$started"
}

recorded_server_identity() {
  local pid identity_pid identity_start extra
  [[ -f "$SERVER_PID" && ! -L "$SERVER_PID" ]] || return 1
  [[ -f "$SERVER_IDENTITY" && ! -L "$SERVER_IDENTITY" ]] || return 1
  [[ -f "$SERVER_BOOT" && ! -L "$SERVER_BOOT" ]] || return 1
  pid="$(cat -- "$SERVER_PID")"
  read -r identity_pid identity_start extra <"$SERVER_IDENTITY" || return 1
  [[ "$pid" =~ ^[1-9][0-9]*$ && "$identity_pid" == "$pid" &&
     "$identity_start" =~ ^[1-9][0-9]*$ && -z "${extra:-}" ]] || return 1
  printf '%s %s\n' "$pid" "$identity_start"
}

current_server_pid() {
  local pid expected_start started
  read -r pid expected_start < <(recorded_server_identity) || return 1
  [[ "$(cat -- "$SERVER_BOOT")" == "$(cat /proc/sys/kernel/random/boot_id)" ]] || return 1
  started="$(server_process_start "$pid")" || return 1
  [[ "$started" == "$expected_start" ]] || return 1
  printf '%s\n' "$pid"
}

stop_server() {
  local pid expected_start state started attempt stopped=0
  if read -r pid expected_start < <(recorded_server_identity); then
    if [[ "$(cat -- "$SERVER_BOOT")" != "$(cat /proc/sys/kernel/random/boot_id)" ]]; then
      # A process from the recorded boot cannot survive this VM restart.
      stopped=1
    elif started="$(server_process_start "$pid")" && [[ "$started" == "$expected_start" ]]; then
      if ! kill -TERM "$pid" 2>/dev/null; then
        if read -r state started < <(process_state_start "$pid") &&
            [[ "$started" == "$expected_start" && "$state" != Z ]]; then
          fail 'owned sshd could not be stopped'
        fi
        stopped=1
      fi
      for attempt in {1..200}; do
        if ! read -r state started < <(process_state_start "$pid"); then
          stopped=1
          break
        fi
        if [[ "$started" != "$expected_start" || "$state" == Z ]]; then
          # The captured server is gone. Never signal a replacement PID, and
          # do not wait for init to reap an already-dead owned process.
          stopped=1
          break
        fi
        sleep 0.05
      done
    elif ! read -r state started < <(process_state_start "$pid") ||
        [[ "$started" != "$expected_start" || "$state" == Z ]]; then
      # Absence, PID reuse, and an exact recorded zombie all prove that there
      # is no live captured server left to signal.
      stopped=1
    else
      fail 'refusing to act on an unowned sshd pid'
    fi
    [[ "$stopped" -eq 1 ]] || fail 'owned sshd did not stop'
  elif [[ -e "$SERVER_PID" || -L "$SERVER_PID" || -e "$SERVER_IDENTITY" || -L "$SERVER_IDENTITY" ]]; then
    fail 'refusing to act on an unowned sshd pid'
  fi
  rm -f -- "$SERVER_PID" "$SERVER_IDENTITY"
}

public_host_key() {
  local public
  require_installed
  [[ -f "$STATE_ROOT/ssh_host_ed25519_key.pub" && ! -L "$STATE_ROOT/ssh_host_ed25519_key.pub" ]] ||
    fail 'public host key is unavailable'
  public="$(cat -- "$STATE_ROOT/ssh_host_ed25519_key.pub")"
  [[ "$public" =~ ^ssh-ed25519\ [A-Za-z0-9+/]+={0,2}([[:space:]][^[:space:]]+)?$ ]] ||
    fail 'public host key is malformed'
  read -r algorithm blob _comment <<<"$public"
  printf '[%s]:%s %s %s\n' "$LISTEN_HOST" "$LISTEN_PORT" "$algorithm" "$blob"
}

install_fixture() {
  local public_key_file="$1" public_key algorithm blob extra source_repo invalid_fixture
  [[ "$(id -u)" != 0 ]] || fail 'stock SSH fixture requires the normal unprivileged workspace identity'
  [[ -f "$public_key_file" && ! -L "$public_key_file" ]] || fail 'public key file must be a regular file'
  [[ ! -e "$STATE_ROOT" ]] || fail 'fixture state already exists'
  public_key="$(cat -- "$public_key_file")"
  read -r algorithm blob extra <<<"$public_key"
  [[ -z "${extra:-}" && "$algorithm" =~ ^ssh-(ed25519|rsa)$ && "$blob" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] ||
    fail 'selected public key is not one exact supported OpenSSH key'
  /usr/bin/ssh-keygen -lf "$public_key_file" -E sha256 >/dev/null || fail 'selected public key is invalid'
  [[ -d "$SERVER_ROOT" && ! -L "$SERVER_ROOT" && -f "$SERVER_BINARY" &&
     ! -L "$SERVER_BINARY" && -x "$SERVER_BINARY" ]] ||
    fail 'workspace image lacks the prepared SSH fixture; rebuild the workspace image'
  invalid_fixture="$(find "$SERVER_ROOT" -xdev \( ! -uid 0 -o \( \( -type f -o -type d \) -perm /022 \) \) -print -quit)" ||
    fail 'could not inspect the prepared SSH fixture'
  [[ -z "$invalid_fixture" ]] ||
    fail 'prepared SSH fixture is not root-owned and immutable to workspace users'
  install -d -m 0700 -- "$STATE_ROOT" "$CLIENT_ROOT" "$STATE_ROOT/remote"
  # Only per-run public authorization, synthetic host keys and mutable target
  # state are created here. The prepared server needs no network or sudo.
  printf '%s %s\n' "$algorithm" "$blob" >"$STATE_ROOT/client_key.pub"
  chmod 0600 "$STATE_ROOT/client_key.pub"
  prepare_authorization
  /usr/bin/ssh-keygen -q -t ed25519 -N '' -C codewire-stock-ssh-smoke \
    -f "$STATE_ROOT/ssh_host_ed25519_key"
  chmod 0600 "$STATE_ROOT/ssh_host_ed25519_key"

  cat >"$SERVER_CONFIG" <<EOF
AddressFamily inet
ListenAddress $LISTEN_HOST
Port $LISTEN_PORT
HostKey $STATE_ROOT/ssh_host_ed25519_key
PidFile $SERVER_PID
# The workspace PVC is intentionally group-writable through fsGroup, so an
# absolute AuthorizedKeysFile below it cannot pass OpenSSH StrictModes. The
# stock root-owned helper emits only this owned public authorization as the
# target user; no private provider material enters the workspace.
AuthorizedKeysCommand /usr/bin/cat $AUTHORIZED_KEYS
AuthorizedKeysCommandUser $TARGET_USER
AuthorizedKeysFile none
AllowUsers $TARGET_USER
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM no
StrictModes yes
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no
PermitTTY no
X11Forwarding no
PrintMotd no
PrintLastLog no
TCPKeepAlive no
ClientAliveInterval 15
ClientAliveCountMax 1
MaxAuthTries 2
MaxSessions 2
LoginGraceTime 10
LogLevel VERBOSE
Subsystem sftp internal-sftp
EOF
  chmod 0600 "$SERVER_CONFIG"

  source_repo="$STATE_ROOT/source"
  /usr/bin/git init --initial-branch=main "$source_repo" >/dev/null
  printf 'selected-agent Git-over-SSH proof\n' >"$source_repo/proof.txt"
  /usr/bin/git -C "$source_repo" add proof.txt
  /usr/bin/git -C "$source_repo" -c user.name=Synthetic \
    -c user.email=synthetic@example.invalid commit -m synthetic >/dev/null
  /usr/bin/git -C "$source_repo" rev-parse HEAD >"$STATE_ROOT/revision"
  /usr/bin/git clone --bare "$source_repo" "$STATE_ROOT/repository.git" >/dev/null
  rm -rf -- "$source_repo"
  printf 'stock-ssh-workload-installed\n'
}

start_fixture() {
  local pid pid_file started launched_start='' state attempt multiarch stopped=0
  require_installed
  prepare_authorization
  if pid="$(current_server_pid)"; then
    printf 'stock-ssh-workload-ready\n'
    return
  fi
  if [[ -f "$SERVER_BOOT" && ! -L "$SERVER_BOOT" &&
        "$(cat -- "$SERVER_BOOT")" != "$(cat /proc/sys/kernel/random/boot_id)" ]]; then
    # The fixture's workspace survives a VM restart, but its old PID cannot.
    rm -f -- "$SERVER_PID" "$SERVER_IDENTITY" "$SERVER_BOOT"
  fi
  [[ ! -e "$SERVER_PID" && ! -L "$SERVER_PID" ]] || fail 'stale or unowned sshd pid file'
  [[ ! -e "$SERVER_IDENTITY" && ! -L "$SERVER_IDENTITY" ]] || fail 'stale sshd identity file'
  [[ ! -e "$SERVER_BOOT" && ! -L "$SERVER_BOOT" ]] || fail 'stale sshd boot file'
  run_server -t -f "$SERVER_CONFIG"
  (umask 077; set -o noclobber; cat /proc/sys/kernel/random/boot_id >"$SERVER_BOOT") ||
    fail 'cannot record sshd boot identity'
  multiarch="$(server_multiarch)"
  env LD_LIBRARY_PATH="$SERVER_ROOT/usr/lib/$multiarch:$SERVER_ROOT/lib/$multiarch" \
    "$SERVER_BINARY" -D -f "$SERVER_CONFIG" -E "$SERVER_LOG" \
    </dev/null >/dev/null 2>&1 &
  pid=$!
  for attempt in {1..200}; do
    if read -r state started < <(process_state_start "$pid"); then
      if [[ -z "$launched_start" ]]; then
        launched_start="$started"
      elif [[ "$started" != "$launched_start" ]]; then
        break
      fi
      [[ "$state" != Z ]] || break
    fi
    if [[ -f "$SERVER_PID" && ! -L "$SERVER_PID" ]]; then
      pid_file="$(cat -- "$SERVER_PID")"
      if [[ "$pid_file" == "$pid" ]] && started="$(server_process_start "$pid")" &&
          [[ -n "$launched_start" && "$started" == "$launched_start" ]]; then
        (umask 077; set -o noclobber; printf '%s %s\n' "$pid" "$started" >"$SERVER_IDENTITY") ||
          fail 'cannot record sshd process identity'
        if [[ "$(current_server_pid)" == "$pid" ]]; then
          printf 'stock-ssh-workload-ready\n'
          return
        fi
        break
      fi
    fi
    sleep 0.05
  done
  if [[ -n "$launched_start" ]]; then
    if read -r state started < <(process_state_start "$pid") &&
        [[ "$started" == "$launched_start" && "$state" != Z ]]; then
      kill -TERM "$pid" 2>/dev/null || true
    fi
    for attempt in {1..200}; do
      if ! read -r state started < <(process_state_start "$pid") ||
          [[ "$started" != "$launched_start" || "$state" == Z ]]; then
        stopped=1
        break
      fi
      sleep 0.05
    done
  else
    stopped=1
  fi
  [[ "$stopped" -eq 1 ]] || fail 'failed sshd launch remained live'
  rm -f -- "$SERVER_PID" "$SERVER_IDENTITY" "$SERVER_BOOT"
  fail 'owned sshd did not become ready'
}

server_multiarch() {
  case "$(dpkg --print-architecture)" in
    amd64) printf '%s\n' x86_64-linux-gnu ;;
    arm64) printf '%s\n' aarch64-linux-gnu ;;
    *) fail 'unsupported workspace architecture' ;;
  esac
}

run_server() {
  local multiarch
  multiarch="$(server_multiarch)"
  # Libraries are scoped to the server only, never to the stock clients.
  env LD_LIBRARY_PATH="$SERVER_ROOT/usr/lib/$multiarch:$SERVER_ROOT/lib/$multiarch" \
    "$SERVER_BINARY" "$@"
}

write_known_hosts() {
  local expected="$1" actual
  actual="$(public_host_key)"
  [[ "$expected" == "$actual" ]] || fail 'supplied host trust does not match the installed target'
  printf '%s\n' "$expected" >"$KNOWN_HOSTS"
  chmod 0600 "$KNOWN_HOSTS"
}

ssh_options() {
  SSH_OPTIONS=(
    -F /dev/null
    -p "$LISTEN_PORT"
    -o BatchMode=yes
    -o PasswordAuthentication=no
    -o KbdInteractiveAuthentication=no
    -o PreferredAuthentications=publickey
    -o PubkeyAuthentication=yes
    -o IdentitiesOnly=no
    -o IdentityFile=none
    -o "IdentityAgent=$SSH_AUTH_SOCK"
    -o "UserKnownHostsFile=$KNOWN_HOSTS"
    -o GlobalKnownHostsFile=/dev/null
    -o StrictHostKeyChecking=yes
    -o CheckHostIP=no
    -o UpdateHostKeys=no
    -o ForwardAgent=no
    -o ClearAllForwardings=yes
    -o PermitLocalCommand=no
    -o ProxyCommand=none
    -o ProxyJump=none
    -o ControlMaster=no
    -o PKCS11Provider=none
    -o SecurityKeyProvider=none
    -o GSSAPIAuthentication=no
    -o HostbasedAuthentication=no
    -o NumberOfPasswordPrompts=0
    -o ConnectTimeout=5
    -o LogLevel=ERROR
  )
}

accepted_count() {
  grep -cF "Accepted publickey for $TARGET_USER " "$SERVER_LOG" 2>/dev/null || true
}

clean_client_env() {
  env -i PATH='/usr/bin:/bin' HOME="$CLIENT_ROOT" USER="$TARGET_USER" LOGNAME="$TARGET_USER" \
    LC_ALL=C SSH_AUTH_SOCK="$SSH_AUTH_SOCK" "$@"
}

bounded_client() {
  clean_client_env /usr/bin/timeout --foreground --signal=TERM --kill-after=2s 20s "$@"
}

has_diagnostic_line() {
  local expected="$1" diagnostic="$2"
  # OpenSSH emits CRLF even without a PTY. Accept only the exact message with
  # either line ending, not arbitrary whitespace or a generic connection error.
  grep -qxF -e "$expected" -e "$expected"$'\r' "$diagnostic"
}

strict_modes_component_state() {
  local owner="$1" mode="$2" target_uid="$3"
  [[ "$owner" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]+$ && "$target_uid" =~ ^[0-9]+$ ]] || return 1
  if [[ "$owner" != 0 && "$owner" != "$target_uid" ]] || (( (8#$mode & 8#022) != 0 )); then
    printf '%s\n' unsafe
  else
    printf '%s\n' safe
  fi
}

authorization_command_state() {
  local path owner mode target_uid
  target_uid=0
  path="$(readlink -f /usr/bin/cat)" || return 1
  while [[ "$path" == /* ]]; do
    read -r owner mode < <(stat -Lc '%u %a' -- "$path" 2>/dev/null) || return 1
    if [[ "$(strict_modes_component_state "$owner" "$mode" "$target_uid")" != safe ]]; then
      printf '%s\n' strict-modes-unsafe
      return
    fi
    path="${path%/*}"
    [[ -n "$path" ]] || path=/
    [[ "$path" != / ]] || {
      read -r owner mode < <(stat -Lc '%u %a' -- / 2>/dev/null) || return 1
      [[ "$(strict_modes_component_state "$owner" "$mode" "$target_uid")" == safe ]] || {
        printf '%s\n' strict-modes-unsafe
        return
      }
      break
    }
  done
  printf '%s\n' strict-modes-safe
}

authorized_keys_command_failure() {
  local log="$1" line status
  if line="$(grep -E 'AuthorizedKeysCommand.*(exited|status)[^0-9]*[0-9]+' "$log" 2>/dev/null | tail -n 1)" &&
      [[ -n "$line" ]]; then
    status="$(sed -E 's/.*(exited|status)[^0-9]*([0-9]+).*/\2/' <<<"$line")"
    [[ "$status" =~ ^[0-9]+$ ]] || status=unknown
    printf 'helper-exit %s\n' "$status"
  elif grep -Eqi 'AuthorizedKeysCommand.*(stat|ownership|mode|unsafe)' "$log" 2>/dev/null; then
    printf 'helper-path unknown\n'
  elif grep -Eqi 'AuthorizedKeysCommand.*(setresgid|setresuid|setgid|setuid|initgroups)' "$log" 2>/dev/null; then
    printf 'helper-identity unknown\n'
  elif grep -Eqi 'AuthorizedKeysCommand.*(exec|execute|subprocess|fork)' "$log" 2>/dev/null; then
    printf 'helper-exec unknown\n'
  elif grep -qF 'AuthorizedKeysCommand' "$log" 2>/dev/null; then
    printf 'helper-other unknown\n'
  else
    printf 'not-reported none\n'
  fi
}

report_authentication_failure() {
  local list_status signing_status selected_state server_state command_state identities helper_state helper_status
  local algorithm blob listed_algorithm listed_blob _comment process_uid process_gid passwd_uid passwd_gid

  if identities="$(bounded_client /usr/bin/ssh-add -L 2>/dev/null)"; then
    list_status=available
    selected_state=absent
    read -r algorithm blob _comment <"$STATE_ROOT/client_key.pub"
    while read -r listed_algorithm listed_blob _comment; do
      if [[ "$listed_algorithm" == "$algorithm" && "$listed_blob" == "$blob" ]]; then
        selected_state=present
        break
      fi
    done <<<"$identities"
  else
    list_status=unavailable-or-empty
    selected_state=unknown
  fi
  identities=''
  if bounded_client /usr/bin/ssh-add -T "$STATE_ROOT/client_key.pub" >/dev/null 2>&1; then
    signing_status=allowed
  else
    signing_status=denied-or-unavailable
  fi

  read -r helper_state helper_status < <(authorized_keys_command_failure "$SERVER_LOG")
  server_state=unknown
  if [[ "$helper_state" != not-reported ]]; then
    server_state=authorized-keys-command
  elif grep -qF "User $TARGET_USER not allowed because account is locked" "$SERVER_LOG" 2>/dev/null; then
    server_state=account-locked
  elif grep -qF "Authentication refused: bad ownership or modes" "$SERVER_LOG" 2>/dev/null; then
    server_state=strict-modes-rejected
  elif grep -qF "Failed publickey for $TARGET_USER " "$SERVER_LOG" 2>/dev/null; then
    server_state=publickey-rejected
  elif grep -qF "Connection closed by authenticating user $TARGET_USER " "$SERVER_LOG" 2>/dev/null; then
    server_state=no-accepted-offer
  fi
  command_state="$(authorization_command_state 2>/dev/null || printf '%s\n' inspection-unavailable)"
  process_uid="$(id -u 2>/dev/null || printf unknown)"
  process_gid="$(id -g 2>/dev/null || printf unknown)"
  IFS=: read -r _comment _comment passwd_uid passwd_gid _comment < <(getent passwd "$TARGET_USER" 2>/dev/null) || {
    passwd_uid=unknown
    passwd_gid=unknown
  }
  [[ "$passwd_uid" =~ ^[0-9]+$ ]] || passwd_uid=unknown
  [[ "$passwd_gid" =~ ^[0-9]+$ ]] || passwd_gid=unknown
  printf '[stock-ssh-workload] AUTH_DIAGNOSTIC agent_list=%s selected_identity=%s signing=%s authorization_command=%s helper=%s helper_status=%s process_uid=%s process_gid=%s passwd_uid=%s passwd_gid=%s server=%s\n' \
    "$list_status" "$selected_state" "$signing_status" "$command_state" "$helper_state" "$helper_status" \
    "$process_uid" "$process_gid" "$passwd_uid" "$passwd_gid" "$server_state" >&2
}

expect_host_denied() {
  local pins="$1" diagnostic="$2" before_pid after_pid stderr
  local -a denied_options
  before_pid="$(current_server_pid)" || fail 'owned sshd stopped before host-trust denial'
  denied_options=("${SSH_OPTIONS[@]}")
  local index
  for index in "${!denied_options[@]}"; do
    if [[ "${denied_options[$index]}" == "UserKnownHostsFile=$KNOWN_HOSTS" ]]; then
      denied_options[index]="UserKnownHostsFile=$pins"
    fi
  done
  stderr="$CLIENT_ROOT/host-denied-$diagnostic.stderr"
  if bounded_client /usr/bin/ssh "${denied_options[@]}" \
    "$TARGET_USER@$LISTEN_HOST" 'printf unexpected' >"$CLIENT_ROOT/host-denied.stdout" 2>"$stderr"; then
    fail 'untrusted host was admitted'
  fi
  has_diagnostic_line 'Host key verification failed.' "$stderr" || fail 'host-trust denial diagnostic drifted'
  case "$diagnostic" in
    unknown)
      grep -qF 'No ED25519 host key is known for [127.0.0.1]:22222' "$stderr" ||
        fail 'unknown-host denial was not proven'
      ;;
    changed)
      grep -qF 'REMOTE HOST IDENTIFICATION HAS CHANGED' "$stderr" ||
        fail 'changed-host denial was not proven'
      ;;
    *) fail 'invalid host-trust diagnostic selector' ;;
  esac
  after_pid="$(current_server_pid)" || fail 'owned sshd stopped during host-trust denial'
  [[ "$after_pid" == "$before_pid" ]] || fail 'owned sshd changed during host-trust denial'
}

prove_fixture() {
  local expected_host_key="$1" before after fingerprint wrapper upload download sftp_download clone command_output
  local pushed newest_accepted
  local -a scp_options sftp_options
  require_installed
  : "${SSH_AUTH_SOCK:?managed SSH agent is required}"
  [[ -S "$SSH_AUTH_SOCK" ]] || fail 'managed SSH agent socket is unavailable'
  current_server_pid >/dev/null || fail 'owned sshd is not running'
  write_known_hosts "$expected_host_key"
  ssh_options
  before="$(accepted_count)"
  [[ "$before" == 0 ]] || fail 'target has prior successful authentications'

  if ! command_output="$(bounded_client /usr/bin/ssh "${SSH_OPTIONS[@]}" \
      "$TARGET_USER@$LISTEN_HOST" 'printf stock-ssh-exec-ok')"; then
    report_authentication_failure
    fail 'stock SSH command failed'
  fi
  [[ "$command_output" == 'stock-ssh-exec-ok' ]] || fail 'stock SSH command output drifted'

  upload="$CLIENT_ROOT/upload.bin"
  download="$CLIENT_ROOT/scp-download.bin"
  sftp_download="$CLIENT_ROOT/sftp-download.bin"
  printf '\0synthetic\377file\nwith\0binary' >"$upload"
  scp_options=("${SSH_OPTIONS[@]}")
  scp_options[2]=-P
  bounded_client /usr/bin/scp "${scp_options[@]}" "$upload" \
    "$TARGET_USER@$LISTEN_HOST:$STATE_ROOT/remote/scp.bin"
  bounded_client /usr/bin/scp "${scp_options[@]}" \
    "$TARGET_USER@$LISTEN_HOST:$STATE_ROOT/remote/scp.bin" "$download"
  [[ "$(sha256sum <"$upload")" == "$(sha256sum <"$download")" ]] || fail 'SCP bytes drifted'

  sftp_options=("${SSH_OPTIONS[@]}")
  sftp_options[2]=-P
  printf 'put %s %s\nget %s %s\n' "$upload" "$STATE_ROOT/remote/sftp.bin" \
    "$STATE_ROOT/remote/sftp.bin" "$sftp_download" |
    bounded_client /usr/bin/sftp -b - "${sftp_options[@]}" "$TARGET_USER@$LISTEN_HOST" >/dev/null
  [[ "$(sha256sum <"$upload")" == "$(sha256sum <"$sftp_download")" ]] || fail 'SFTP bytes drifted'

  wrapper="$CLIENT_ROOT/ssh-wrapper"
  cat >"$wrapper" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
: "${SSH_AUTH_SOCK:?managed SSH agent is required}"
exec /usr/bin/ssh -F /dev/null -p 22222 \
  -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes -o IdentitiesOnly=no \
  -o IdentityFile=none -o "IdentityAgent=$SSH_AUTH_SOCK" \
  -o UserKnownHostsFile=/workspace/.cw-ssh-smoke/client/known_hosts \
  -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o CheckHostIP=no \
  -o UpdateHostKeys=no -o ForwardAgent=no -o ClearAllForwardings=yes \
  -o PermitLocalCommand=no -o ProxyCommand=none -o ProxyJump=none -o ControlMaster=no \
  -o PKCS11Provider=none -o SecurityKeyProvider=none -o GSSAPIAuthentication=no \
  -o HostbasedAuthentication=no -o NumberOfPasswordPrompts=0 -o ConnectTimeout=5 \
  -o LogLevel=ERROR "$@"
WRAPPER
  chmod 0700 "$wrapper"
  clone="$CLIENT_ROOT/clone"
  bounded_client env GIT_SSH="$wrapper" GIT_SSH_VARIANT=ssh \
    /usr/bin/git clone --quiet "ssh://$TARGET_USER@$LISTEN_HOST:$LISTEN_PORT$STATE_ROOT/repository.git" "$clone" \
      >/dev/null 2>"$CLIENT_ROOT/git.stderr" || fail 'Git-over-SSH clone failed'
  [[ "$(/usr/bin/git -C "$clone" rev-parse HEAD)" == "$(cat -- "$STATE_ROOT/revision")" ]] ||
    fail 'Git-over-SSH revision drifted'
  [[ "$(cat -- "$clone/proof.txt")" == 'selected-agent Git-over-SSH proof' ]] ||
    fail 'Git-over-SSH content drifted'
  # Push a new commit through the same selected signer and require the
  # target's own branch to move from the installed revision to exactly it.
  printf 'selected-agent Git-over-SSH push proof\n' >"$clone/push.txt"
  /usr/bin/git -C "$clone" add push.txt
  /usr/bin/git -C "$clone" -c user.name=Synthetic \
    -c user.email=synthetic@example.invalid commit --quiet -m 'synthetic push'
  pushed="$(/usr/bin/git -C "$clone" rev-parse HEAD)"
  [[ "$pushed" != "$(cat -- "$STATE_ROOT/revision")" ]] || fail 'Git-over-SSH push commit is not new'
  # The push is the sixth authentication, and it must be the push's own: this
  # target (the wrapper pins its host key) accepted five before it and exactly
  # one more for it, from the selected public key.
  fingerprint="$(/usr/bin/ssh-keygen -lf "$STATE_ROOT/client_key.pub" -E sha256 | awk '{print $2}')"
  [[ "$fingerprint" == SHA256:* ]] || fail 'selected public-key fingerprint is unavailable'
  [[ "$(accepted_count)" == 5 ]] || fail 'target did not accept exactly five authentications before the Git push'
  bounded_client env GIT_SSH="$wrapper" GIT_SSH_VARIANT=ssh \
    /usr/bin/git -C "$clone" push --quiet origin HEAD:refs/heads/main \
      >/dev/null 2>"$CLIENT_ROOT/git-push.stderr" || fail 'Git-over-SSH push failed'
  [[ "$(accepted_count)" == 6 ]] || fail 'Git-over-SSH push did not authenticate to the target exactly once'
  newest_accepted="$(grep -F "Accepted publickey for $TARGET_USER " "$SERVER_LOG" | tail -n 1)"
  [[ "$newest_accepted" == *"$fingerprint"* ]] ||
    fail 'Git-over-SSH push did not authenticate with the selected public key'
  [[ "$(/usr/bin/git --git-dir="$STATE_ROOT/repository.git" rev-parse refs/heads/main)" == "$pushed" ]] ||
    fail 'Git-over-SSH push did not advance the target branch'
  [[ "$(/usr/bin/git --git-dir="$STATE_ROOT/repository.git" show "$pushed:push.txt")" == \
     'selected-agent Git-over-SSH push proof' ]] || fail 'Git-over-SSH pushed content drifted'

  : >"$CLIENT_ROOT/empty-known-hosts"
  expect_host_denied "$CLIENT_ROOT/empty-known-hosts" unknown
  /usr/bin/ssh-keygen -q -t ed25519 -N '' -C wrong-host -f "$CLIENT_ROOT/wrong-host"
  read -r _algorithm wrong_blob _comment <"$CLIENT_ROOT/wrong-host.pub"
  printf '[%s]:%s ssh-ed25519 %s\n' "$LISTEN_HOST" "$LISTEN_PORT" "$wrong_blob" \
    >"$CLIENT_ROOT/wrong-known-hosts"
  expect_host_denied "$CLIENT_ROOT/wrong-known-hosts" changed

  after="$(accepted_count)"
  [[ "$after" == 6 ]] || fail "target accepted $after authentications, want 6"
  [[ "$(grep -F "Accepted publickey for $TARGET_USER " "$SERVER_LOG" | grep -cF "$fingerprint")" == 6 ]] ||
    fail 'target did not authenticate the exact selected public key six times'
  printf '%s\n' "$after" >"$STATE_ROOT/proved-accepted-count"
  printf 'stock-ssh-workload-proved\n'
}

prove_revoked() {
  local expected_host_key="$1" before after before_pid after_pid stderr
  require_installed
  : "${SSH_AUTH_SOCK:?managed SSH agent is required}"
  [[ -S "$SSH_AUTH_SOCK" ]] || fail 'managed SSH agent socket is unavailable'
  write_known_hosts "$expected_host_key"
  ssh_options
  [[ -f "$STATE_ROOT/proved-accepted-count" && ! -L "$STATE_ROOT/proved-accepted-count" ]] ||
    fail 'successful placed workload proof is missing'
  before="$(cat -- "$STATE_ROOT/proved-accepted-count")"
  before_pid="$(current_server_pid)" || fail 'owned sshd stopped before revoked attempt'
  stderr="$CLIENT_ROOT/revoked.stderr"
  if bounded_client /usr/bin/ssh "${SSH_OPTIONS[@]}" \
    "$TARGET_USER@$LISTEN_HOST" 'printf unexpected-after-revoke' \
    >"$CLIENT_ROOT/revoked.stdout" 2>"$stderr"; then
    fail 'revoked selected identity opened a fresh SSH connection'
  fi
  has_diagnostic_line "${TARGET_USER}@${LISTEN_HOST}: Permission denied (publickey)." "$stderr" ||
    fail 'revoked selected identity did not reach an exact live authentication denial'
  after_pid="$(current_server_pid)" || fail 'owned sshd stopped during revoked attempt'
  [[ "$after_pid" == "$before_pid" ]] || fail 'owned sshd changed during revoked attempt'
  after="$(accepted_count)"
  [[ "$after" == "$before" ]] || fail 'revoked attempt reached successful target authentication'
  printf 'stock-ssh-workload-revoked\n'
}

cleanup_fixture() {
  require_installed
  stop_server
  rm -rf -- "$STATE_ROOT"
  [[ ! -e "$STATE_ROOT" ]] || fail 'fixture state remained after cleanup'
  printf 'stock-ssh-workload-cleaned\n'
}

wait_for_revocation() {
  local expected_host_key="$1" attempt
  require_installed
  [[ ! -e "$STATE_ROOT/revoked-trigger" ]] || fail 'revocation trigger already exists'
  write_known_hosts "$expected_host_key"
  : "${SSH_AUTH_SOCK:?managed SSH agent is required}"
  printf 'stock-ssh-workload-awaiting-revocation\n'
  # Public test synchronization through the existing authenticated file API;
  # it does not open another listener or admit another managed workload.
  for ((attempt = 0; attempt < 1200; attempt++)); do
    if [[ -f "$STATE_ROOT/revoked-trigger" && ! -L "$STATE_ROOT/revoked-trigger" ]]; then
      [[ "$(cat -- "$STATE_ROOT/revoked-trigger")" == revoked ]] || fail 'invalid revocation trigger'
      prove_revoked "$expected_host_key"
      return
    fi
    sleep 0.1
  done
  fail 'revocation trigger deadline expired'
}

mode="${1:-}"
case "$mode" in
  install)
    [[ $# -eq 2 ]] || fail 'usage: stock-ssh-workload.sh install PUBLIC_KEY_FILE'
    install_fixture "$2"
    ;;
  startup)
    shift
    require_no_extra_arguments "$@"
    start_fixture
    ;;
  public-host-key)
    shift
    require_no_extra_arguments "$@"
    public_host_key
    ;;
  prove)
    [[ $# -eq 2 ]] || fail 'usage: stock-ssh-workload.sh prove EXACT_KNOWN_HOSTS_LINE'
    prove_fixture "$2"
    ;;
  revoked)
    [[ $# -eq 2 ]] || fail 'usage: stock-ssh-workload.sh revoked EXACT_KNOWN_HOSTS_LINE'
    prove_revoked "$2"
    ;;
  wait-revoked)
    [[ $# -eq 2 ]] || fail 'usage: stock-ssh-workload.sh wait-revoked EXACT_KNOWN_HOSTS_LINE'
    wait_for_revocation "$2"
    ;;
  cleanup)
    shift
    require_no_extra_arguments "$@"
    cleanup_fixture
    ;;
  *) fail 'expected install, startup, public-host-key, prove, revoked, wait-revoked, or cleanup' ;;
esac
