#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CW_BIN="${CW_BIN:-}"
WORKSPACE_IMAGE="${WORKSPACE_IMAGE:-}"
BACKEND="${BACKEND:-}"
PROJECT_DIR="${PROJECT_DIR:-$ROOT}"
LIMA_HOME="${LIMA_HOME:-$HOME/.lima}"
KEEP=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/ci/verify/smoke-local-environment.sh \
    --backend docker|lima \
    --image ghcr.io/codewiresh/workspace@sha256:... \
    --cw-bin PATH

Runs the local environment daemon/session smoke through the public cw grammar.
The smoke uses an isolated HOME, clears ambient developer credentials, creates
one disposable local environment, and removes it on exit.

Options:
  --backend BACKEND    Local backend to prove: docker or lima.
  --image IMAGE        Immutable workspace image digest.
  --cw-bin PATH        Exact cw binary under test.
  --project-dir PATH   Project directory mounted by the environment.
  --lima-home PATH     Existing Lima state root (default: $HOME/.lima).
  --keep               Keep the environment and isolated state after success.
  -h, --help           Show this help.

The smoke proves:
  - create, stop, start, daemon status, daemon repair
  - generated-client run, list, logs, durable output, and restart persistence
  - start returns only after the daemon is ready
  - daemon endpoint binds only to host loopback
  - hardened local state and daemon-token non-exposure
USAGE
}

log() {
  printf '[local-environment-smoke] %s\n' "$*" >&2
}

die() {
  printf '[local-environment-smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --backend)
      [[ "$#" -ge 2 ]] || die "--backend requires a value"
      BACKEND="$2"
      shift 2
      ;;
    --image)
      [[ "$#" -ge 2 ]] || die "--image requires a value"
      WORKSPACE_IMAGE="$2"
      shift 2
      ;;
    --cw-bin)
      [[ "$#" -ge 2 ]] || die "--cw-bin requires a value"
      CW_BIN="$2"
      shift 2
      ;;
    --project-dir)
      [[ "$#" -ge 2 ]] || die "--project-dir requires a value"
      PROJECT_DIR="$2"
      shift 2
      ;;
    --lima-home)
      [[ "$#" -ge 2 ]] || die "--lima-home requires a value"
      LIMA_HOME="$2"
      shift 2
      ;;
    --keep)
      KEEP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ "$BACKEND" == "docker" || "$BACKEND" == "lima" ]] ||
  die "--backend must be docker or lima"
[[ "$WORKSPACE_IMAGE" =~ ^ghcr\.io/codewiresh/workspace@sha256:[0-9a-f]{64}$ ]] ||
  die "--image must be an immutable ghcr.io/codewiresh/workspace digest"
[[ -n "$CW_BIN" ]] || die "--cw-bin is required"
[[ -x "$CW_BIN" ]] || die "cw binary is not executable: $CW_BIN"
[[ -d "$PROJECT_DIR" ]] || die "project directory does not exist: $PROJECT_DIR"
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"

require_cmd jq
require_cmd rg
require_cmd stat
if [[ "$BACKEND" == "docker" ]]; then
  require_cmd docker
else
  require_cmd limactl
  [[ -d "$LIMA_HOME" ]] || die "Lima state root does not exist: $LIMA_HOME"
fi

mkdir -p "$ROOT/.tmp"
SMOKE_HOME="$(mktemp -d "$ROOT/.tmp/local-environment-smoke.XXXXXX")"
chmod 0700 "$SMOKE_HOME"
TRANSCRIPT="$SMOKE_HOME/transcript"
NAME="local-session-${BACKEND}-$$"
RUNTIME_NAME="cw-$NAME"
COMMAND_INDEX=0
LAST_STDOUT=""
LAST_STDERR=""
SUCCEEDED=0

cw_isolated() {
  (
    cd "$SMOKE_HOME"
    env \
      -u ANTHROPIC_API_KEY \
      -u CLAUDE_CODE_OAUTH_TOKEN \
      -u CODEWIRE_API_KEY \
      -u CODEWIRE_BASE_URL \
      -u CODEWIRE_DEV_SMOKE_API_KEY \
      -u CODEWIRE_MESH_TOKEN \
      -u CODEWIRE_MESH_URL \
      -u CODEWIRE_SERVER_URL \
      -u GH_TOKEN \
      -u GITHUB_TOKEN \
      -u INFISICAL_TOKEN \
      -u KUBECONFIG \
      -u SSH_AUTH_SOCK \
      HOME="$SMOKE_HOME" \
      CW_CONFIG_DIR="$SMOKE_HOME/.config/cw" \
      LIMA_HOME="$LIMA_HOME" \
      "$CW_BIN" "$@"
  )
}

run_cw() {
  local stdout_file stderr_file
  COMMAND_INDEX=$((COMMAND_INDEX + 1))
  stdout_file="$SMOKE_HOME/command-$COMMAND_INDEX.stdout"
  stderr_file="$SMOKE_HOME/command-$COMMAND_INDEX.stderr"
  if ! cw_isolated "$@" >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
    tail -n 80 "$stderr_file" >&2
    die "cw command $COMMAND_INDEX failed"
  fi
  cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
  LAST_STDOUT="$stdout_file"
  LAST_STDERR="$stderr_file"
}

run_cw_expect_failure() {
  local stdout_file stderr_file
  COMMAND_INDEX=$((COMMAND_INDEX + 1))
  stdout_file="$SMOKE_HOME/command-$COMMAND_INDEX.stdout"
  stderr_file="$SMOKE_HOME/command-$COMMAND_INDEX.stderr"
  if cw_isolated "$@" >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
    die "cw command $COMMAND_INDEX unexpectedly succeeded"
  fi
  cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
  LAST_STDOUT="$stdout_file"
  LAST_STDERR="$stderr_file"
}

cleanup() {
  local status=$?
  if [[ "$KEEP" == 0 || "$SUCCEEDED" == 0 ]]; then
    cw_isolated env --local rm "$NAME" --yes >/dev/null 2>&1 || true
    if [[ "$BACKEND" == "docker" ]]; then
      docker container rm --force "$RUNTIME_NAME" >/dev/null 2>&1 || true
    else
      LIMA_HOME="$LIMA_HOME" limactl delete --force "$RUNTIME_NAME" >/dev/null 2>&1 || true
    fi
    rm -r -- "$SMOKE_HOME" >/dev/null 2>&1 || true
  else
    log "kept environment $NAME and isolated state $SMOKE_HOME"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

log "creating fresh $BACKEND environment with immutable workspace image"
run_cw env --local create \
  --backend "$BACKEND" \
  --name "$NAME" \
  --path "$PROJECT_DIR" \
  --image "$WORKSPACE_IMAGE" \
  --no-network \
  --yes

STATE_FILE="$SMOKE_HOME/.codewire/local_instances.toml"
[[ -f "$STATE_FILE" ]] || die "local instance state was not created"
[[ "$(stat -c '%a' "$SMOKE_HOME/.codewire")" == "700" ]] ||
  die "local state directory is not mode 0700"
[[ "$(stat -c '%a' "$STATE_FILE")" == "600" ]] ||
  die "local instance state is not mode 0600"
DAEMON_TOKEN="$(
  sed -n 's/^daemon_auth_token = "\(.*\)"$/\1/p' "$STATE_FILE" | head -n 1
)"
[[ "${#DAEMON_TOKEN}" -ge 43 ]] || die "managed daemon token is missing"

log "checking generated-client readiness and durable session output"
run_cw env --local daemon status "$NAME" --output json
jq -e '
  .state == "ready" and
  (.capabilities | index("sessions.v1") != null) and
  (.capabilities | index("attach.v1") != null)
' "$LAST_STDOUT" >/dev/null || die "daemon capability/readiness response is incomplete"

run_cw run --no-tty "$NAME" -- printf local-session-smoke
rg -qF 'local-session-smoke' "$LAST_STDOUT" ||
  die "durable session output was not returned"
if rg -qF 'Launched session' "$LAST_STDOUT"; then
  die "session lifecycle diagnostics polluted command stdout"
fi

run_cw list "$NAME" --output json
jq -e '
  length == 1 and
  .[0].state == "Exited" and
  .[0].command == ["printf", "local-session-smoke"] and
  .[0].output_end_offset == 19
' "$LAST_STDOUT" >/dev/null || die "durable session record drifted"
SESSION_ID="$(jq -er '.[0].session_id' "$LAST_STDOUT")"

run_cw logs "$NAME" "$SESSION_ID" --raw
rg -qF 'local-session-smoke' "$LAST_STDOUT" ||
  die "saved session output was not readable"

log "checking stop/start readiness and daemon repair"
run_cw env --local stop "$NAME"
run_cw env --local start "$NAME"
run_cw env --local daemon status "$NAME" --output json
jq -e '.state == "ready"' "$LAST_STDOUT" >/dev/null ||
  die "start returned before daemon readiness"

run_cw run --no-tty "$NAME" -- printf post-start-smoke
rg -qF 'post-start-smoke' "$LAST_STDOUT" ||
  die "session launch failed immediately after start"

run_cw env --local daemon repair "$NAME" --output json
jq -e '.status.state == "ready"' "$LAST_STDOUT" >/dev/null ||
  die "daemon repair did not restore readiness"

run_cw list "$NAME" --output json
if ! jq -e '
    length == 2 and
    all(.[]; .state == "Exited") and
    any(.[]; .command == ["printf", "local-session-smoke"]) and
    any(.[]; .command == ["printf", "post-start-smoke"])
  ' "$LAST_STDOUT" >/dev/null; then
  jq . "$LAST_STDOUT" >&2
  die "durable sessions did not survive lifecycle operations"
fi

log "checking foreground command failure propagation"
run_cw_expect_failure run --no-tty "$NAME" -- sh -lc \
  'printf local-session-failure; exit 42'
rg -qF 'local-session-failure' "$LAST_STDOUT" ||
  die "failed session output was not returned"
rg -qF 'session exited with code 42' "$LAST_STDERR" ||
  die "failed session exit status was not propagated"

run_cw list "$NAME" --output json
jq -e '
  length == 3 and
  any(.[];
    .command == ["sh", "-lc", "printf local-session-failure; exit 42"] and
    .state == "Exited" and
    .exit_code == 42
  )
' "$LAST_STDOUT" >/dev/null || die "failed durable session record drifted"

log "checking loopback-only daemon exposure"
if [[ "$BACKEND" == "docker" ]]; then
  docker inspect "$RUNTIME_NAME" |
    jq -e '
      .[0].HostConfig.PortBindings["7777/tcp"] as $bindings |
      ($bindings | length) == 1 and
      $bindings[0].HostIp == "127.0.0.1"
    ' >/dev/null || die "Docker daemon endpoint is not host-loopback-only"
else
  LIMA_CONFIG="$LIMA_HOME/$RUNTIME_NAME/lima.yaml"
  [[ -f "$LIMA_CONFIG" ]] || die "Lima instance config is missing"
  rg -q 'guestPort: 7777' "$LIMA_CONFIG" ||
    die "Lima daemon guest port is missing"
  rg -q 'guestIP: 127\.0\.0\.1' "$LIMA_CONFIG" ||
    die "Lima daemon guest endpoint is not loopback-only"
  rg -q 'hostIP: 127\.0\.0\.1' "$LIMA_CONFIG" ||
    die "Lima daemon host endpoint is not loopback-only"
  LIMA_HOME="$LIMA_HOME" limactl shell --workdir / "$RUNTIME_NAME" \
    ss -ltn |
    rg -q '127\.0\.0\.1:7777' ||
    die "Lima daemon is not listening on guest loopback"
fi

if rg -Fq "$DAEMON_TOKEN" "$TRANSCRIPT"; then
  die "managed daemon token appeared in CLI output"
fi

SUCCEEDED=1
log "PASS ($BACKEND)"
