#!/usr/bin/env bash
# Separate public-only Dev acceptance target, never a product bootstrap hook.
# Mounted read-only from the nonce-owned ConfigMap; all mutable state is tmpfs.
set -euo pipefail
umask 077
readonly STATE=/state/checkout
readonly SERVER_ROOT=/opt/codewire/fixtures/openssh
readonly SERVER="$SERVER_ROOT/usr/sbin/sshd"
readonly CONTENT=initial-private-checkout-synthetic-v1

fail() { printf 'hosted-checkout-target: failed\n' >&2; exit 1; }
valid_request() {
  [[ "${SSH_ORIGINAL_COMMAND:-}" == "git-upload-pack '/repository.git'" ]]
}
[[ $- != *x* && $# == 1 && "$(id -u)" == 1000 && "$(id -un)" == codewire ]] || fail

case "$1" in
  upload)
    # OpenSSH's forced command is fixed. Never evaluate the client command.
    valid_request || fail
    [[ ! -e "$STATE/drain-request" ]] || fail
    [[ -d "$STATE/repository.git" && ! -L "$STATE/repository.git" ]] || fail
    exec /usr/bin/env -i PATH=/usr/bin:/bin HOME="$STATE" LC_ALL=C \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null \
      GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false \
      /usr/bin/timeout --signal=TERM --kill-after=2 20 \
      /usr/bin/git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
      upload-pack --strict "$STATE/repository.git"
    ;;
  ready)
    [[ -f "$STATE/ready" && ! -L "$STATE/ready" && -f "$STATE/sshd.pid" ]] || fail
    pid="$(cat "$STATE/sshd.pid")"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || fail
    kill -0 "$pid" || fail
    # Exactly three public lines. No caller-selected file can be read.
    cat "$STATE/ready"
    exit 0
    ;;
  counter)
    [[ -f "$STATE/sshd.log" && ! -L "$STATE/sshd.log" ]] || fail
    # Only the single selected key can authenticate. Do not emit raw logs.
    /usr/bin/awk '/Accepted publickey for codewire / {n++} END {printf "%d\n",n}' "$STATE/sshd.log"
    exit 0
    ;;
  drain)
    [[ -f "$STATE/ready" && ! -L "$STATE/ready" ]] || fail
    printf 'drain\n' >"$STATE/drain-request"
    printf 'hosted-checkout-target-drain-requested\n'
    exit 0
    ;;
  serve) ;;
  *) fail ;;
esac

[[ ! -e "$STATE" && ! -L "$STATE" && -x "$SERVER" && ! -L "$SERVER" ]] || fail
[[ -z "$(find "$SERVER_ROOT" -xdev \( ! -uid 0 -o \( \( -type f -o -type d \) -perm /022 \) \) -print -quit)" ]] || fail
# Kubernetes ConfigMap projection uses root-owned ..data symlinks. This fixed
# path is supplied only by the immutable, read-only fixture volume.
[[ -f /fixture/client.pub && "$(stat -Lc '%u:%a' /fixture/client.pub)" == 0:444 ]] || fail
[[ "$(wc -c </fixture/client.pub)" -le 256 ]] || fail
key="$(cat /fixture/client.pub)"
[[ "$key" =~ ^ssh-ed25519\ [A-Za-z0-9+/]+={0,2}$ ]] || fail
/usr/bin/ssh-keygen -lf /fixture/client.pub -E sha256 >/dev/null || fail
install -d -m 0700 "$STATE"
printf 'restrict %s\n' "$key" >"$STATE/authorized_keys"
/usr/bin/ssh-keygen -q -t ed25519 -N '' -C synthetic-hosted-checkout -f "$STATE/host"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null
export GIT_AUTHOR_DATE=2000-01-01T00:00:00Z GIT_COMMITTER_DATE=2000-01-01T00:00:00Z
export HOME="$STATE"
/usr/bin/git -c core.hooksPath=/dev/null init --initial-branch=main "$STATE/source" >/dev/null
printf '%s\n' "$CONTENT" >"$STATE/source/proof.txt"
/usr/bin/git -C "$STATE/source" -c core.hooksPath=/dev/null add proof.txt
/usr/bin/git -C "$STATE/source" -c core.hooksPath=/dev/null -c user.name=Synthetic \
  -c user.email=synthetic@example.invalid commit -m synthetic >/dev/null
revision="$(/usr/bin/git -C "$STATE/source" rev-parse HEAD)"
/usr/bin/git -c core.hooksPath=/dev/null clone --bare "$STATE/source" "$STATE/repository.git" >/dev/null
cat >"$STATE/sshd_config" <<'CONFIG'
AddressFamily inet
ListenAddress 0.0.0.0
Port 22222
HostKey /state/checkout/host
PidFile /state/checkout/sshd.pid
AuthorizedKeysCommand /usr/bin/cat /state/checkout/authorized_keys
AuthorizedKeysCommandUser codewire
AuthorizedKeysFile none
AllowUsers codewire
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
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no
PermitTTY no
X11Forwarding no
PrintMotd no
PrintLastLog no
TCPKeepAlive no
ClientAliveInterval 10
ClientAliveCountMax 1
MaxAuthTries 2
MaxSessions 1
MaxStartups 2
LoginGraceTime 10
LogLevel VERBOSE
ForceCommand /bin/bash --noprofile --norc /fixture/target.sh upload
CONFIG
case "$(uname -m)" in
  x86_64) multiarch=x86_64-linux-gnu ;;
  aarch64) multiarch=aarch64-linux-gnu ;;
  *) fail ;;
esac
export LD_LIBRARY_PATH="$SERVER_ROOT/usr/lib/$multiarch:$SERVER_ROOT/lib/$multiarch"
"$SERVER" -t -f "$STATE/sshd_config"
server_pid=''
stop() {
  trap - EXIT TERM INT HUP
  if [[ -n "$server_pid" ]]; then
    kill -TERM "$server_pid" 2>/dev/null || true
    for ((stopping=0; stopping<50; stopping++)); do
      kill -0 "$server_pid" 2>/dev/null || break
      sleep 0.1
    done
    # Signals remain inside this disposable container's private PID namespace.
    # PID 1's subsequent exit also terminates any remaining descendants.
    if kill -0 "$server_pid" 2>/dev/null; then kill -KILL "$server_pid" 2>/dev/null || true; fi
    wait "$server_pid" || true
  fi
}
trap stop EXIT
trap 'exit 130' TERM INT HUP
# timeout owns the daemon lifetime even if the host coordinator disappears.
/usr/bin/timeout --signal=TERM --kill-after=5 1800 \
  "$SERVER" -D -f "$STATE/sshd_config" -E "$STATE/sshd.log" &
server_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
  kill -0 "$server_pid" || fail
  [[ ! -f "$STATE/sshd.pid" ]] || break
  sleep 0.1
done
[[ -f "$STATE/sshd.pid" ]] || fail
read -r algorithm blob _comment <"$STATE/host.pub"
[[ "$algorithm" == ssh-ed25519 && "$revision" =~ ^[0-9a-f]{40}$ ]] || fail
printf '%s %s\n%s\n%s\n' "$algorithm" "$blob" "$revision" "$CONTENT" >"$STATE/.ready"
mv "$STATE/.ready" "$STATE/ready"
while kill -0 "$server_pid" 2>/dev/null; do
  if [[ -f "$STATE/drain-request" && ! -L "$STATE/drain-request" ]]; then
    stop
    # PID 1 exits normally only on this explicit request. Its private container
    # PID namespace then terminates any remaining SSH/timeout/Git descendants.
    printf 'hosted-checkout-target-drained\n'
    exit 0
  fi
  sleep 0.1
done
wait "$server_pid" || true
fail
