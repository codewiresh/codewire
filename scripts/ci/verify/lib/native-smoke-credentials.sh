# shellcheck shell=bash
# The managed native smoke's credential steps (#5220), for
# smoke-native-local-environment.sh: an application secret seen through a
# PTY, and the journey step smoke-credential-claude (#5374). Sourced, never
# run: they use the smoke's state, run_cw, die, log and its other helpers.

# The Claude step's own profile: by then the shared one selects credentials
# the broker smoke revoked, and an update refuses a profile like that.
CLAUDE_PROFILE_NAME='native-claude'

run_application_secret_pty() {
  local expected="$1" personal_expected="$2" collision_expected="$3" phase="$4" pty_log attempt
  local -a SMOKE_EXTRA_ENVIRONMENT
  pty_log="$SMOKE_ROOT/app-pty-$phase.log"
  managed_cw_environment PATH="$SMOKE_ROOT/bin:/usr/bin:/bin" "${NO_EGRESS_PROXIES[@]}"
  if ! (
    {
      printf 'test -t 0 && test -t 1 && /bin/sh /workspace/fixtures/app-secrets-check.sh %s %s %s %s && printf "app-secret-pty-ok\\n" || exit 77\nexit\n' \
        "$expected" "$personal_expected" "$collision_expected" "$phase"
      # The shell's own `exit` ends the session, and `cw shell` with it.
      # Input stays open until the exact guest receipt, so nothing guesses
      # when the console hop has completed. A plain `cw shell` sends every
      # key to the session, Ctrl-B included, so a Ctrl-B d sent after the
      # receipt was only stray input, and it reached a session that had
      # already exited (#5584).
      for ((attempt = 0; attempt < 400; attempt++)); do
        if rg -q $'^app-secret-pty-ok\r?$' "$pty_log" 2>/dev/null; then
          exit 0
        fi
        sleep 0.05
      done
      exit 1
    } | smoke_cw /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 30s \
      /usr/bin/script -qefc "$CW_BIN shell" "$pty_log"
  ) >"$SMOKE_ROOT/app-pty-$phase.stdout" 2>"$SMOKE_ROOT/app-pty-$phase.stderr"; then
    tail -n 80 "$SMOKE_ROOT/app-pty-$phase.stderr" >&2
    die 'application projection PTY proof failed'
  fi
  cat "$SMOKE_ROOT/app-pty-$phase.stdout" "$SMOKE_ROOT/app-pty-$phase.stderr" >>"$TRANSCRIPT"
  rg -q $'^app-secret-pty-ok\r?$' "$pty_log" || die 'PTY did not confirm the current application projection'
}

# Journey step smoke-credential-claude (#5374, #5220): a local Claude sign-in
# connected through the public command, in use in the guest, revoked while the
# VM runs, then stopped, started and re-enrolled, and in use again. The featured
# build answers the sign-in in process; the step ends revoked, so no delivered
# login is in the guest when the checkpoint is scanned.
readonly CLAUDE_SIGN_IN_NAME='native-broker-claude'
CLAUDE_CREDENTIAL_ID=''
RESTART_START_STDERR=''

# Off a terminal the CLI prints the authorize link on stderr and reads
# `code#state` from stdin to its end: read the state from the link, paste the
# synthetic code with it.
# shellcheck disable=SC2016
readonly CLAUDE_CONNECT_DRIVER='
import signal, subprocess, sys, urllib.parse
command = sys.argv[1:]
child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
# The outer timeout ends this driver with TERM; its cw goes with it.
def stop(signum, frame):
    child.kill()
    child.wait()
    sys.exit(128 + signum)
signal.signal(signal.SIGTERM, stop)
state = None
seen = []
for raw in child.stderr:
    line = raw.decode(errors="replace").strip()
    seen.append(line)
    if line.startswith("https://claude.com/cai/oauth/authorize?"):
        state = urllib.parse.parse_qs(urllib.parse.urlsplit(line).query).get("state", [None])[0]
        break
if not state:
    child.kill()
    sys.stderr.write("no authorize link with a state\n")
    sys.exit(70)
child.stdin.write(f"synthetic-smoke#{state}\n".encode())
child.stdin.close()
try:
    stdout, stderr = child.communicate(timeout=120)
except subprocess.TimeoutExpired:
    child.kill()
    child.communicate()
    sys.stderr.write("the connect did not finish within 120 s\n")
    sys.exit(71)
sys.stdout.buffer.write(stdout)
sys.stderr.write("\n".join(seen) + "\n" + stderr.decode(errors="replace"))
sys.exit(child.returncode)
'

connect_synthetic_claude() {
  local stdout_file stderr_file
  # managed_cw_environment fills it, and smoke_cw reads it, by dynamic scope.
  # shellcheck disable=SC2034
  local -a SMOKE_EXTRA_ENVIRONMENT
  managed_cw_environment PATH="$SMOKE_ROOT/bin:/usr/bin:/bin" "${NO_EGRESS_PROXIES[@]}"
  COMMAND_INDEX=$((COMMAND_INDEX + 1))
  stdout_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stdout"
  stderr_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stderr"
  if ! smoke_cw /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 150s \
    /usr/bin/python3 -I -c "$CLAUDE_CONNECT_DRIVER" "$CW_BIN" credentials --local connect claude \
    --name "$CLAUDE_SIGN_IN_NAME" --yes --output json >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
    tail -n 40 "$stderr_file" >&2
    die 'connecting the synthetic Claude sign-in failed'
  fi
  cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
  LAST_STDOUT="$stdout_file"
  # The smoke reads the last command's stderr, as after run_cw.
  # shellcheck disable=SC2034
  LAST_STDERR="$stderr_file"
}

# One model call from the guest through the loopback Anthropic route, which
# the broker serves with the profile's Claude sign-in: its status, its
# Codewire-Refusal reason, whether the refusal's Fix line names the local
# list, and whether the synthetic reply came back.
# shellcheck disable=SC2016
readonly CLAUDE_GUEST_CALL='
const http = require("http");
const body = JSON.stringify({model: "claude-sonnet-4-6", max_tokens: 64, stream: true,
  messages: [{role: "user", content: "smoke-credential-claude"}]});
const request = http.request({host: "127.0.0.1", port: 38081, path: "/_codewire/anthropic/v1/messages",
  method: "POST", headers: {"content-type": "application/json", "anthropic-version": "2023-06-01",
  "content-length": Buffer.byteLength(body)}}, response => {
  const chunks = [];
  response.on("data", chunk => chunks.push(chunk));
  response.on("end", () => {
    const text = Buffer.concat(chunks).toString("utf8");
    process.stdout.write(JSON.stringify({status: response.statusCode,
      refusal: response.headers["codewire-refusal"] ?? null,
      answered: text.includes("CWCLAUDE21238 broker"),
      fix: text.includes("Fix: in a local VM, run `cw credentials --local list`"),
      leaked: text.includes("cwlocalclaude")}) + "\n");
  });
});
request.setTimeout(60000, () => request.destroy(new Error("timeout")));
request.on("error", () => process.exit(80));
request.end(body);
'

require_claude_call() {
  local expect="$1" phase="$2"
  run_cw run --no-tty -- node -e "$CLAUDE_GUEST_CALL"
  case "$expect" in
    answered)
      jq -e '.status == 200 and .answered and (.leaked | not)' "$LAST_STDOUT" >/dev/null ||
        die "smoke-credential-claude: the Claude sign-in did not serve the guest $phase" ;;
    refused)
      # A hosted Sandbox's refusal, with its local fix (#5593).
      jq -e '.status == 403 and .refusal == "credential_revoked" and .fix and (.answered | not)' \
        "$LAST_STDOUT" >/dev/null ||
        die "smoke-credential-claude: the revoked Claude sign-in was not refused as revoked $phase: $(head -c 300 "$LAST_STDOUT")" ;;
  esac
}

run_claude_sign_in_smoke() {
  log 'smoke-credential-claude: connecting a synthetic Claude sign-in through the public command'
  connect_synthetic_claude
  CLAUDE_CREDENTIAL_ID="$(jq -er '.[0] | select(.provider == "anthropic" and .authentication_kind == "claude_sign_in") | .id' "$LAST_STDOUT")" ||
    die 'smoke-credential-claude: connect did not report one Claude sign-in'
  run_cw credentials --local --profile "$CLAUDE_PROFILE_NAME" set anthropic "id:$CLAUDE_CREDENTIAL_ID"
  run_cw update --local "$NAME" --profile "local:user/$CLAUDE_PROFILE_NAME" --yes
  wait_for_journal_complete || die 'smoke-credential-claude: the profile update left a partial journal'
  log 'smoke-credential-claude: in use (the first call refreshes the sign-in)'
  require_claude_call answered 'in use'
  log 'smoke-credential-claude: revoked while the VM runs'
  run_cw credentials --local revoke "id:$CLAUDE_CREDENTIAL_ID" --yes
  require_claude_call refused 'while the VM runs'
  log 'smoke-credential-claude: stopped and started, still refused'
  restart_failed_environment 'Claude revocation'
  # The start says which credential its agents can't use (#5545).
  rg -qF "Claude (sign-in) '$CLAUDE_SIGN_IN_NAME' in profile $CLAUDE_PROFILE_NAME is revoked; agents in this VM can't use it." \
    "$RESTART_START_STDERR" || die 'smoke-credential-claude: the start did not say the sign-in is revoked'
  require_claude_call refused 'after a restart'
  log 'smoke-credential-claude: re-enrolled, in use again'
  connect_synthetic_claude
  [[ "$(jq -er '.[0].id' "$LAST_STDOUT")" == "$CLAUDE_CREDENTIAL_ID" ]] ||
    die 'smoke-credential-claude: re-enrolment did not keep the credential'
  require_claude_call answered 'after re-enrolment'
  # The checkpoint that follows is scanned; no delivered login stays behind.
  run_cw credentials --local revoke "id:$CLAUDE_CREDENTIAL_ID" --yes
  log 'smoke-credential-claude: PASS'
}
