#!/usr/bin/env bash
# The hosted interception gate on Dev (#4001, #6181, #6302): as a Dev test
# identity, a Sandbox holding synthetic, canary-marked Anthropic and OpenAI
# API keys makes intercepted requests end to end, and no placeholder or
# canary leaves where it should not. Counts, status codes and closed labels
# only; no value, header or body is printed.
#
# Inside the Sandbox, it checks:
#  1. the interception CA is installed and named for agents;
#  2. ANTHROPIC_AUTH_TOKEN, where a hosted launch projects an Anthropic key's
#     placeholder (sent as Authorization: Bearer), is this Sandbox's
#     placeholder, and no variable holds a canary;
#  3. the system store alone refuses api.anthropic.com's front door;
#  4. the placeholder gets the provider's own 401 and a codewire-request-id,
#     and a made-up key is refused selected_credential_only before anything
#     is sent (#5555). A hosted broker never forwards a request untouched
#     (the platform bridge builds every one with untouched forwards refused,
#     pinned by a_hosted_front_door_request_without_the_placeholder_is_
#     refused_and_never_sent), so the provider's answer to the placeholder
#     can only follow a swap;
#  5. OPENAI_API_KEY is Codewire's managed value behind the loopback route,
#     and OpenAI's 401 names the last four characters of the gate's own
#     synthetic key, the one the broker swapped in;
#  6. a canary scan as root, before deletion, finds neither canary on the
#     filesystem or in any process's environment or command line, and finds
#     its own controls;
#  7. Claude Code runs with no TLS error; its own result is reported.
# It prints GATE_WINDOW and GATE_PROBES (the two Anthropic probes' request
# ids), with which the credential service's timing lines can also be read.
#
# Run it as #6074's personal-walk identity under with-dev-personal-walk.sh,
# or as the e2e test account signed in to an isolated cw config folder on
# tmpfs (GATE_EXPECTED_EMAIL=e2e@codewire.sh). GATE_EXTRA_READ, with
# GATE_CALLER_HOME, names an optional read-only look at the live Sandbox,
# given its id, run with the caller's own access before cleanup.
#
# Every object is deleted by its exact id at the end, even when a step fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

readonly DEV_ORIGIN="https://codewire-dev.sh"
# The Dev test identities the gate may run as: #6074's personal-walk user
# (under with-dev-personal-walk.sh), or the e2e test account signed in to an
# isolated cw config folder.
readonly WALK_EMAIL="${GATE_EXPECTED_EMAIL:-${EXPECTED_PERSONAL_WALK_USER_EMAIL:-}}"
case "$WALK_EMAIL" in
  success+codewire-dev-personal-walk@simulator.amazonses.com) readonly PREFIX=personal-walk ;;
  e2e@codewire.sh) readonly PREFIX=interception-gate ;;
  *) printf '[interception-gate] FAIL: not a Dev test identity: %s\n' "${WALK_EMAIL:-unset}" >&2; exit 1 ;;
esac
readonly UUID_PATTERN='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

log() { printf '[interception-gate] %s\n' "$*" >&2; }
die() { printf '[interception-gate] FAIL: %s\n' "$*" >&2; exit 1; }

case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac
readonly SERVER="${CODEWIRE_SERVER_URL:-}"
[[ "$SERVER" == "$DEV_ORIGIN" ]] || die "Dev only (server: ${SERVER:-unset})"
[[ "${XDG_RUNTIME_DIR:-}" == /* && -d "$XDG_RUNTIME_DIR" ]] || die 'XDG_RUNTIME_DIR is unset'
[[ "${CW_CONFIG_DIR:-}" == "$XDG_RUNTIME_DIR"/* ]] ||
  die 'cw must be signed in from an isolated config folder on tmpfs (CW_CONFIG_DIR)'
[[ -x "${CW_BIN:-}" ]] || die 'CW_BIN is not an executable cw'

cw() { "$CW_BIN" --server "$SERVER" "$@"; }
json() { sed -n '/^[[{]/,$p'; }

whoami="$(cw whoami --output json | json | jq -r '.email // empty')" || true
[[ "$whoami" == "$WALK_EMAIL" ]] || die "cw is not signed in as $WALK_EMAIL"

# What the account already holds, by kind and count only; the gate touches
# nothing but its own objects.
log "account holds: credentials=$(cw credentials --cloud list --output json | json | jq -c '[.[].provider] | group_by(.) | map({(.[0]): length}) | add // {}') profiles=$(cw credentials --cloud profiles list --output json | json | jq 'length') sandboxes=$(cw --cloud ls --output json | json | jq 'length')"

RUN_ID="$(date -u +%Y%m%dt%H%M%Sz)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
readonly NAME="$PREFIX-$RUN_ID"
# The scanner needs a value's last 32 characters to be random.
random_hex() { od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }
anthropic_tail="$(random_hex)"
openai_tail="$(random_hex)"
readonly CANARY="sk-ant-api03-CWCANARY-INTERCEPTION-GATE-$RUN_ID-$anthropic_tail"
readonly SCANNER="$ROOT/scripts/ci/verify/scan-credential-canaries.py"
# The OpenAI key is synthetic too; OpenAI's refusal names its last four
# characters, which shows it, and not Codewire's managed value, was sent.
readonly OPENAI_CANARY="sk-proj-CWCANARY-INTERCEPTION-GATE-$RUN_ID-$openai_tail"
[[ -r "$SCANNER" ]] || die "the canary scanner is not readable: $SCANNER"
CREDENTIAL_ID="" OPENAI_ID="" PROFILE_ID="" SANDBOX_ID="" PROJECT="" STARTED=false

by_name() { # KIND [PROVIDER]: the id of this run's object, empty when not listed
  case "$1" in
    credential) cw credentials --cloud list --output json | json |
      jq -er --arg n "$NAME" --arg p "$2" '[.[]|select(.name==$n and .provider==$p)] | if length<2 then (.[0].id // "") else error("ambiguous") end' ;;
    profile) cw credentials --cloud profiles list --output json | json |
      jq -er --arg n "$NAME" '[.[]|select(.name==$n)] | if length<2 then (.[0].id // "") else error("ambiguous") end' ;;
    sandbox) cw --cloud ls --output json | json |
      jq -er --arg n "$NAME" '[.[]|select(.name==$n)] | if length<2 then ((.[0].id // .[0].environment_id) // "") else error("ambiguous") end' ;;
  esac
}

cleanup() {
  local status=0 attempt left kind
  [[ "$STARTED" == true ]] || return 0
  [[ -n "$SANDBOX_ID" ]] || SANDBOX_ID="$(by_name sandbox)" || true
  if [[ -n "$SANDBOX_ID" ]]; then
    cw --cloud rm "$SANDBOX_ID" --yes || { log "removing Sandbox $SANDBOX_ID failed"; status=1; }
    for attempt in $(seq 1 36); do
      [[ -z "$(by_name sandbox 2>/dev/null)" ]] && break
      [[ "$attempt" != 36 ]] || { log "Sandbox $SANDBOX_ID still listed after 3 minutes"; status=1; }
      sleep 5
    done
  fi
  [[ -n "$PROFILE_ID" ]] || PROFILE_ID="$(by_name profile)" || true
  if [[ -n "$PROFILE_ID" ]]; then
    for attempt in $(seq 1 24); do
      cw credentials --cloud --profile "id:$PROFILE_ID" delete --yes && break
      [[ "$attempt" != 24 ]] || { log "deleting profile $PROFILE_ID failed for 2 minutes"; status=1; }
      sleep 5
    done
  fi
  [[ -n "$CREDENTIAL_ID" ]] || CREDENTIAL_ID="$(by_name credential anthropic)" || true
  if [[ -n "$CREDENTIAL_ID" ]]; then
    cw credentials --cloud delete "id:$CREDENTIAL_ID" --yes || { log "deleting credential $CREDENTIAL_ID failed"; status=1; }
  fi
  [[ -n "$OPENAI_ID" ]] || OPENAI_ID="$(by_name credential openai)" || true
  if [[ -n "$OPENAI_ID" ]]; then
    cw credentials --cloud delete "id:$OPENAI_ID" --yes || { log "deleting credential $OPENAI_ID failed"; status=1; }
  fi
  for kind in sandbox profile "credential anthropic" "credential openai"; do
    # shellcheck disable=SC2086
    if ! left="$(by_name $kind)"; then log "cannot list to confirm the cleanup of: $kind"; status=1
    elif [[ -n "$left" ]]; then log "$kind $left named $NAME is still listed"; status=1; fi
  done
  [[ -z "$PROJECT" ]] || rm -rf -- "$PROJECT"
  log "cleanup sandbox=${SANDBOX_ID:-none} profile=${PROFILE_ID:-none} credential=${CREDENTIAL_ID:-none} openai=${OPENAI_ID:-none} $([[ "$status" == 0 ]] && echo deleted || echo INCOMPLETE)"
  return "$status"
}
finish() {
  local status="$1"
  trap - EXIT HUP INT TERM
  cleanup || status=$((status ? status : 1))
  [[ "$status" == 0 ]] && log "PASS run=$RUN_ID"
  exit "$status"
}
trap 'finish $?' EXIT
trap 'exit 130' HUP INT TERM

log "run $RUN_ID as $WALK_EMAIL on $SERVER; canary marker CWCANARY-INTERCEPTION-GATE-$RUN_ID"
STARTED=true

printf '%s' "$CANARY" | cw credentials --cloud add anthropic --name "$NAME"
CREDENTIAL_ID="$(by_name credential anthropic)" || true
[[ "$CREDENTIAL_ID" =~ $UUID_PATTERN ]] || die 'the added Anthropic credential is not listed by its name'
printf '%s' "$OPENAI_CANARY" | cw credentials --cloud add openai --name "$NAME"
OPENAI_ID="$(by_name credential openai)" || true
[[ "$OPENAI_ID" =~ $UUID_PATTERN ]] || die 'the added OpenAI credential is not listed by its name'
# A first profile would become the default, which can't be deleted; the
# personal-credentials walk leaves the account its empty default.
cw credentials --cloud profiles list --output json | json | jq -e 'any(.[]; .is_default == true)' >/dev/null ||
  die 'the account has no default profile yet; run personal-credentials-walk.sh once first'
cw credentials --cloud --profile "$NAME" set anthropic "id:$CREDENTIAL_ID"
PROFILE_ID="$(by_name profile)" || true
[[ "$PROFILE_ID" =~ $UUID_PATTERN ]] && cw credentials --cloud --profile "id:$PROFILE_ID" set openai "id:$OPENAI_ID"
[[ "$PROFILE_ID" =~ $UUID_PATTERN ]] || die 'the new profile is not listed by its name'

PROJECT="$(mktemp -d "$XDG_RUNTIME_DIR/interception-gate.XXXXXX")"
jq -n '{version:1, working_directory:"/workspace", agents:{tools:["claude-code"]}}' > "$PROJECT/codewire.json"
cw --cloud create --name "$NAME" --profile "id:$PROFILE_ID" --file "$PROJECT/codewire.json" --ttl 30m --yes
SANDBOX_ID="$(by_name sandbox)" || true
[[ "$SANDBOX_ID" =~ $UUID_PATTERN ]] || die 'the Sandbox is not listed by its name'
log "created credential=$CREDENTIAL_ID openai=$OPENAI_ID profile=$PROFILE_ID sandbox=$SANDBOX_ID"
# The Sandbox selects the gate's own profile and nothing else.
selected="$(cw --cloud info "$SANDBOX_ID" --output json | json | jq -r '(if type == "array" then .[0] else . end) | .source_selection.credentials.profile // "none"')"
case "$selected" in
  *"$PROFILE_ID") log "ok   the Sandbox selects profile $PROFILE_ID ($selected)" ;;
  *) die "the Sandbox selects $selected, not the gate's profile $PROFILE_ID" ;;
esac

printf 'GATE_WINDOW start=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# A session, which names the CA and carries the placeholder like an agent's.
report="$(cw run --cloud --in "$SANDBOX_ID" --name interception-gate -- sh -c '
d=/codewire/run/egress-trust; h=api.anthropic.com; v="anthropic-version: 2023-06-01"
echo "ca_certs=$(grep -c "BEGIN CERTIFICATE" $d/ca.pem 2>/dev/null || echo 0)"
echo "ca_der_sha256=$(openssl x509 -in $d/ca.pem -outform der 2>/dev/null | sha256sum | cut -d" " -f1)"
echo "node_extra_ca_named=$([ "${NODE_EXTRA_CA_CERTS-}" = $d/ca.pem ] && echo 1 || echo 0)"
k="${ANTHROPIC_AUTH_TOKEN-}"
echo "key_is_placeholder=$(printf %s "$k" | grep -c "^cwp1_")"
echo "key_is_canary=$(printf %s "${ANTHROPIC_AUTH_TOKEN-}${ANTHROPIC_API_KEY-}${CLAUDE_CODE_OAUTH_TOKEN-}${OPENAI_API_KEY-}" | grep -c CWCANARY)"
echo "base_url_set=$([ -n "${ANTHROPIC_BASE_URL-}" ] && echo 1 || echo 0)"
s=$(curl -s -o /dev/null --max-time 15 -w "%{http_code}" https://$h/v1/models 2>/dev/null)
echo "system_store_http=$s"
probe() { b=$(mktemp); hd=$(mktemp); c=$(curl -s -o $b -D $hd --max-time 30 -w "%{http_code}" --cacert $d/ca.pem -H "$1" -H "$v" https://$h/v1/models 2>/dev/null)
  t=$(jq -r ".error.type // \"none\"" $b 2>/dev/null || echo unparsed)
  r=$(tr -d "\r" < $hd | awk -F": " "tolower(\$1)==\"codewire-request-id\" {print \$2}" | tail -1)
  f=$(tr -d "\r" < $hd | awk -F": " "tolower(\$1)==\"codewire-refusal\" {print \$2}" | tail -1)
  rm -f $b $hd; echo "$2_http=$c $2_error_type=$t $2_rid=${r:-none} $2_refusal=${f:-none}"; }
# The front door serves once its leaves are installed, a few seconds after the
# bind (it drops handshakes until then): wait up to 60 s, and record how long.
t0=$(date +%s); r=000; first=""
while [ "$r" = 000 ] && [ $(( $(date +%s) - t0 )) -lt 60 ]; do
  r=$(curl -s -o /dev/null --max-time 10 -w "%{http_code}" --cacert $d/ca.pem https://$h/ 2>/dev/null); [ -n "$first" ] || first=$r; [ "$r" = 000 ] && sleep 1
done
echo "front_door_ready_after_s=$(( $(date +%s) - t0 )) front_door_first_attempt_http=$first front_door_first_http=$r"
probe "Authorization: Bearer $k" placeholder; sleep 2
probe "x-api-key: sk-ant-api03-madeup$(head -c 24 /dev/urandom | od -An -tx1 | tr -d " \n")" madeup
# OpenAI: the key stays the managed value of Codewire behind the loopback
# route, whose broker swaps in the leased key; the refusal from OpenAI names
# the last four characters of the key it got.
ok="${OPENAI_API_KEY-}"
echo "openai_key_managed=$([ "$ok" = codewire-managed ] && echo 1 || echo 0) openai_base_loopback=$(printf %s "${OPENAI_BASE_URL-}" | grep -c "/_codewire/openai/v1$")"
b=$(mktemp); c=$(curl -s -o $b --max-time 30 -w "%{http_code}" -H "Authorization: Bearer $ok" "${OPENAI_BASE_URL-}/models" 2>/dev/null)
e=$(jq -r ".error.code // \"none\"" $b 2>/dev/null || echo unparsed); m=$(jq -r ".error.message // \"\"" $b 2>/dev/null | grep -oE "\\*+[A-Za-z0-9]{4}" | tail -1 | tr -d "*"); rm -f $b
echo "openai_http=$c openai_error_code=$e openai_echo_tail=${m:-none}"
cd /workspace; o=$(mktemp); timeout 120 claude -p "Reply with exactly the single word GATEOK" >$o 2>&1
echo "claude_rc=$? claude_lines=$(wc -l < $o) claude_auth_errors=$(grep -ciE "invalid.?(x-)?api.?key|authentication|401|unauthori[sz]ed|api key|/login" $o) claude_tls_errors=$(grep -ciE "certificate|self.signed|UNABLE_TO|SSL|TLS" $o)"; rm -f $o
' </dev/null 2>&1)" || true
printf 'GATE_WINDOW end=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
value() { grep -oE "(^| )$1=[^ ]*" <<<"$report" | head -1 | cut -d= -f2; }
# A caller's read-only look at the Sandbox while it lives (#6200's warm-claim
# read), given the Sandbox id; its output goes beside the gate's own.
if [[ -n "${GATE_EXTRA_READ:-}" ]]; then
  # It reads Dev with the caller's own access, never the gate's isolated sign-in.
  [[ -x "$GATE_EXTRA_READ" && -n "${GATE_CALLER_HOME:-}" ]] &&
    env -u CW_CONFIG_DIR HOME="$GATE_CALLER_HOME" "$GATE_EXTRA_READ" "$SANDBOX_ID" 2>&1 | sed 's/^/[extra-read] /' ||
    log "the extra read failed (it needs GATE_CALLER_HOME)"
fi
grep -E '^(ca_certs|ca_der_sha256|node_extra_ca_named|key_is_|base_url_set|system_store_http|front_door_ready|placeholder_http|madeup_http|openai_|claude_rc)' <<<"$report" || true
# The two probes' ids, for swap-lines.sh.
printf 'GATE_PROBES placeholder=%s madeup=%s\n' "$(value placeholder_rid)" "$(value madeup_rid)"

fail=0
check() { if [[ "$(value "$1")" == "$2" ]]; then log "ok   $1=$2"; else log "FAIL $1=$(value "$1") (want $2)"; fail=1; fi; }
check ca_certs 1
check node_extra_ca_named 1
check key_is_placeholder 1
check key_is_canary 0
check base_url_set 0
check system_store_http 000
check placeholder_http 401
check placeholder_error_type authentication_error
check placeholder_refusal none
for probe in placeholder madeup; do
  if [[ "$(value "${probe}_rid")" =~ $UUID_PATTERN ]]; then log "ok   ${probe}_rid is a request id"
  else log "FAIL ${probe}_rid=$(value "${probe}_rid") (the front door named no request id)"; fail=1; fi
done
# Hosted, a key that is none of the Sandbox's placeholders is refused before
# anything is sent (#5555), by the credential service, never the provider.
check madeup_http 403
check madeup_refusal selected_credential_only
check openai_key_managed 1
check openai_base_loopback 1
check openai_http 401
check openai_error_code invalid_api_key
if [[ "$(value openai_echo_tail)" == "${OPENAI_CANARY: -4}" ]]; then log "ok   OpenAI refused the gate's own synthetic key (its last four characters)"
else log "FAIL OpenAI did not name the gate's synthetic key (got $(value openai_echo_tail))"; fail=1; fi
# Claude Code is reported, not required: its own wording varies. A TLS error
# is a revert trigger, so that alone fails the gate.
check claude_tls_errors 0
log "info claude_rc=$(value claude_rc) claude_lines=$(value claude_lines) claude_auth_errors=$(value claude_auth_errors)"

# Before deleting: the canary is nowhere in the Sandbox, not on its
# filesystem, nor in any process's environment or command line. The canary
# reaches the scanner on stdin only. A control made inside the Sandbox is put
# in a file, an environment and a command line, and the scan must find it in
# each, so a scan that reads nothing cannot pass.
scan="$(printf 'canary\t%s\nopenai_canary\t%s\n' "$CANARY" "$OPENAI_CANARY" | cw exec --in "$SANDBOX_ID" -- sudo -n sh -c '
set -u; [ "$(id -u)" = 0 ] || { echo "scan_error=not_root"; exit 0; }
command -v python3 >/dev/null || { echo "scan_error=no_python3"; exit 0; }
w=$(mktemp -d); echo "$1" | base64 -d > $w/scan.py
ctl="gate-control-$(od -An -N16 -tx1 /dev/urandom | tr -d " \n")"
printf "%s" "$ctl" > $w/control-file
env GATE_CONTROL="$ctl" sleep 120 & e=$!
sh -c "sleep 120" "$ctl" & c=$!
sleep 1; mkdir $w/proc
for p in /proc/[0-9]*; do n=${p#/proc/}; cat $p/environ > $w/proc/$n.environ 2>/dev/null; cat $p/cmdline > $w/proc/$n.cmdline 2>/dev/null; done
roots=$(for r in /*; do case $r in /proc|/sys|/dev) ;; *) [ -d "$r" ] && echo "$r";; esac; done)
{ cat; printf "control\t%s\n" "$ctl"; } | timeout 900 python3 $w/scan.py $roots > $w/found 2>$w/err; echo "scan_rc=$?"
kill $e $c 2>/dev/null
echo "canary_found=$(grep -cE "^(canary|openai_canary)	" $w/found)"
echo "control_in_file=$(grep -c "^control	.*control-file" $w/found)"
echo "control_in_environ=$(grep "^control	" $w/found | grep -c "\.environ	")"
echo "control_in_cmdline=$(grep "^control	" $w/found | grep -c "\.cmdline	")"
echo "scan_error_detail=$(head -1 $w/err | tr " " _ | cut -c1-160)"
rm -rf $w
' sh "$(base64 -w0 "$SCANNER")" 2>&1)" || true
grep -E '^(scan_|canary_found|control_in_)' <<<"$scan" || true
sv() { grep -oE "^$1=[^ ]*" <<<"$scan" | head -1 | cut -d= -f2; }
[[ "$(sv scan_rc)" == 0 ]] || { log "FAIL canary scan did not complete (scan_rc=$(sv scan_rc) $(sv scan_error) $(sv scan_error_detail))"; fail=1; }
[[ "$(sv canary_found)" == 0 ]] || { log "FAIL canary_found=$(sv canary_found) (want 0)"; fail=1; }
for where in file environ cmdline; do
  [[ "$(sv "control_in_$where")" -ge 1 ]] 2>/dev/null || { log "FAIL control_in_$where=$(sv "control_in_$where") (the scan must find its control)"; fail=1; }
done
[[ "$fail" == 0 ]] || die 'the Sandbox checks failed'
