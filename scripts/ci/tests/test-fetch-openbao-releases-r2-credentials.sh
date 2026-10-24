#!/usr/bin/env bash
# Synthetic proof for the release publisher's exact-path R2 credential reader.
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-releases-r2-credentials.sh"
CASES=0

fail() {
  printf '[test-fetch-openbao-releases-r2-credentials] ERROR: %s\n' "$*" >&2
  exit 1
}
pass() { CASES=$((CASES + 1)); }

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-openbao-releases-r2.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/output" "$work/runner"

b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
jwt() {
  local claims="$1"
  printf '%s.%s.%s' "$(printf '{"alg":"RS256"}' | b64url)" "$(printf '%s' "$claims" | b64url)" \
    "$(printf 'synthetic-signature' | b64url)"
}
readonly GOOD_CLAIMS='{"aud":"openbao-codewire-source-cli-releases-r2","sub":"repo:codewire-41/codewire-58:ref:refs/heads/main","repository":"codewire/codewire","actor":"noel","workflow_ref":"codewire/codewire/.gitea/workflows/cli-release.yaml@refs/heads/main","ref":"refs/heads/main","event_name":"workflow_dispatch"}'

cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"
output=''
url=''
data_file=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --data-binary) data_file="${2#@}"; shift 2 ;;
    --config|--header|--connect-timeout|--max-time) shift 2 ;;
    --silent|--show-error|--fail) shift ;;
    *) url="$1"; shift ;;
  esac
done
[[ -n "$output" && -n "$url" ]]
case "$url" in
  "https://git.example.invalid/api/actions/oidc?job=synthetic&audience=openbao-${FAKE_EXPECTED_ROLE:-codewire-source-cli-releases-r2}")
    # The audience is the expected role's: "openbao-" plus its name.
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    jq -e --arg role "${FAKE_EXPECTED_ROLE:-codewire-source-cli-releases-r2}" '.role == $role' "$data_file" >/dev/null
    printf 'login\n' >>"$FAKE_EVENTS"
    jq -n --arg token "${FAKE_OPENBAO_TOKEN:?}" '{auth:{client_token:$token}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/releases-r2)
    printf 'read\n' >>"$FAKE_EVENTS"
    jq -n --arg accessKeyId "${FAKE_ACCESS_KEY_ID:?}" --arg secretAccessKey "${FAKE_SECRET_ACCESS_KEY:?}" \
      --argjson extra "${FAKE_EXTRA_FIELDS:-{\}}" \
      '{data:{data:({accessKeyId:$accessKeyId,secretAccessKey:$secretAccessKey} + $extra)}}' >"$output"
    ;;
  *) exit 91 ;;
esac
MOCK
chmod +x "$work/bin/curl"

export PATH="$work/bin:$PATH"
export FAKE_CURL_CALLS="$work/curl-calls"
export FAKE_EVENTS="$work/events"
FAKE_FORGEJO_JWT="$(jwt "$GOOD_CLAIMS")"
export FAKE_FORGEJO_JWT
export FAKE_OPENBAO_TOKEN='synthetic-openbao-token-0123456789'
export FAKE_ACCESS_KEY_ID='SYNTHETICRELEASEKEY0123456789ABC'
export FAKE_SECRET_ACCESS_KEY='syntheticreleasesecretaccesskey1234567890abcdef'
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export GITHUB_EVENT_NAME=workflow_dispatch
export GITHUB_REF=refs/heads/main
export GITHUB_ACTOR=noel
export GITHUB_REPOSITORY=codewire/codewire
export RUNNER_TEMP="$work/runner"
# The CI job's own attempt never reaches a case: each sets the one it means.
unset GITHUB_RUN_ATTEMPT
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN BAO_TOKEN VAULT_TOKEN

fetch() {
  local output="$1"
  shift
  ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token-0123456789' "$@" "$FETCHER" "$output"
}

# The exact protected run writes one private AWS credential file.
: >"$FAKE_EVENTS"
fetch "$work/output/aws-credentials" env >"$work/success.out" 2>&1 || fail "$(cat "$work/success.out")"
[[ "$(stat -c '%a' "$work/output/aws-credentials")" == 600 ]] || fail 'credential mode is not 0600'
[[ "$(cat "$work/output/aws-credentials")" == "$(printf '[default]\naws_access_key_id = %s\naws_secret_access_key = %s' \
  "$FAKE_ACCESS_KEY_ID" "$FAKE_SECRET_ACCESS_KEY")" ]] || fail 'credential file content differs'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'OIDC or OpenBao material survived cleanup'
for secret in synthetic-request-token-0123456789 "$FAKE_FORGEJO_JWT" "$FAKE_OPENBAO_TOKEN" \
    "$FAKE_SECRET_ACCESS_KEY" "$FAKE_ACCESS_KEY_ID"; do
  if grep -qF -- "$secret" "$FAKE_CURL_CALLS" "$work/success.out"; then
    fail 'credential material reached curl arguments or output'
  fi
done
[[ "$(grep -Fc -- '--connect-timeout 10 --max-time 30' "$FAKE_CURL_CALLS")" -eq 3 ]] ||
  fail 'a request lacks the reviewed network deadline'
pass

# Wrong actor, ref, event or repository is refused before any request.
for override in GITHUB_ACTOR=mallory GITHUB_REF=refs/heads/feature GITHUB_REF=refs/tags/v0.4.2 \
    GITHUB_EVENT_NAME=push GITHUB_EVENT_NAME=pull_request GITHUB_REPOSITORY=codewire/fork; do
  calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
  name="${override//[^A-Za-z0-9]/-}"
  if fetch "$work/output/$name" env "$override" >"$work/$name.out" 2>&1; then
    fail "unapproved $override was accepted"
  fi
  [[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] || fail "$override reached a request"
  [[ ! -e "$work/output/$name" ]] || fail "$override wrote credentials"
  pass
done

# The schedule's pickup of a pushed release tag (#2892) reads through its own
# role, with its own claims: event schedule, by Forgejo's Actions user.
schedule_claims="$(jq -c '.aud = "openbao-codewire-source-cli-releases-r2-schedule" | .actor = "forgejo-actions"
  | .event_name = "schedule" | .run_attempt = "1"' <<<"$GOOD_CLAIMS")"
: >"$FAKE_EVENTS"
FAKE_FORGEJO_JWT="$(jwt "$schedule_claims")" FAKE_EXPECTED_ROLE=codewire-source-cli-releases-r2-schedule \
  fetch "$work/output/schedule-credentials" env GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions GITHUB_RUN_ATTEMPT=1 \
  >"$work/schedule.out" 2>&1 || fail "a scheduled release could not read its credential: $(cat "$work/schedule.out")"
[[ "$(tr '\n' ' ' <"$FAKE_EVENTS")" == 'login read ' ]] || fail 'the scheduled release did not log in and read once'
pass
# Neither identity borrows the other's: a dispatch by the Actions user, which
# any branch's job token can make, a schedule attributed to a person, and a
# rerun of a scheduled run are refused before any request; a scheduled run
# presenting dispatch claims is refused at the claim check.
for identity in 'GITHUB_EVENT_NAME=workflow_dispatch GITHUB_ACTOR=forgejo-actions' \
    'GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=noel GITHUB_RUN_ATTEMPT=1' \
    'GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions GITHUB_RUN_ATTEMPT=2' \
    'GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions'; do
  calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
  # shellcheck disable=SC2086 # Each identity is a few assignments.
  if fetch "$work/output/identity" env $identity >"$work/identity.out" 2>&1; then
    fail "the identity $identity was accepted"
  fi
  [[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] || fail "the identity $identity reached a request"
  pass
done
: >"$FAKE_EVENTS"
if FAKE_EXPECTED_ROLE=codewire-source-cli-releases-r2-schedule \
    fetch "$work/output/mixed" env GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions GITHUB_RUN_ATTEMPT=1 >"$work/mixed.out" 2>&1; then
  fail 'a scheduled run presenting dispatch claims was accepted'
fi
grep -Fq 'OIDC token claims are not the protected release workflow' "$work/mixed.out" ||
  fail "dispatch claims on a scheduled run were not refused by the claim check: $(cat "$work/mixed.out")"
[[ ! -s "$FAKE_EVENTS" ]] || fail 'dispatch claims on a scheduled run reached OpenBao'
pass
# Each scheduled claim is checked on its own, before OpenBao: a dispatch's
# actor or event, a rerun's later attempt, or no attempt at all.
n=0
for change in '.actor = "noel"' '.event_name = "workflow_dispatch"' '.run_attempt = "2"' 'del(.run_attempt)'; do
  n=$((n + 1))
  : >"$FAKE_EVENTS"
  if FAKE_FORGEJO_JWT="$(jwt "$(jq -c "$change" <<<"$schedule_claims")")" FAKE_EXPECTED_ROLE=codewire-source-cli-releases-r2-schedule \
      fetch "$work/output/claim-$n" env GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions GITHUB_RUN_ATTEMPT=1 \
      >"$work/claim.out" 2>&1; then
    fail "a scheduled run whose claims were changed by $change was accepted"
  fi
  grep -Fq 'OIDC token claims are not the protected release workflow' "$work/claim.out" ||
    fail "$change was not refused by the claim check: $(cat "$work/claim.out")"
  [[ ! -s "$FAKE_EVENTS" ]] || fail "$change reached OpenBao"
  pass
done

# Ambient or cached credentials are never a fallback.
for ambient in AWS_ACCESS_KEY_ID=ambient AWS_SECRET_ACCESS_KEY=ambient BAO_TOKEN=ambient; do
  calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
  if fetch "$work/output/ambient" env "$ambient" >"$work/ambient.out" 2>&1; then
    fail "ambient $ambient was accepted"
  fi
  [[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] || fail "ambient $ambient reached a request"
  pass
done

# A token whose own claims are not this exact run never reaches OpenBao.
for claim in '.actor = "mallory"' '.workflow_ref = "codewire/codewire/.gitea/workflows/ci.yaml@refs/heads/main"' \
    '.ref = "refs/heads/feature"' '.event_name = "push"' '.aud = "openbao-codewire-source-cli-github-mirror"' \
    '.sub = "repo:codewire-41/codewire-58:pull_request"' 'del(.workflow_ref)'; do
  : >"$FAKE_EVENTS"
  bad_jwt="$(jwt "$(jq -c "$claim" <<<"$GOOD_CLAIMS")")"
  if FAKE_FORGEJO_JWT="$bad_jwt" fetch "$work/output/claims" env >"$work/claims.out" 2>&1; then
    fail "mismatched claim $claim was accepted"
  fi
  grep -Fq 'OIDC token claims are not the protected release workflow' "$work/claims.out" ||
    fail "claim $claim was not refused by the claim check"
  [[ ! -s "$FAKE_EVENTS" ]] || fail "claim $claim reached OpenBao"
  [[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'refused claims left private material'
  pass
done

# The document must contain exactly the two well-formed fields.
for extra in '{"accountId":"synthetic-r2-account"}' '{"endpoint":"https://example.invalid"}'; do
  if FAKE_EXTRA_FIELDS="$extra" fetch "$work/output/extra" env >"$work/extra.out" 2>&1; then
    fail "credential document with $extra was accepted"
  fi
  [[ ! -e "$work/output/extra" ]] || fail 'an extra-field document wrote credentials'
  pass
done
if FAKE_SECRET_ACCESS_KEY='short' fetch "$work/output/short" env >"$work/short.out" 2>&1; then
  fail 'a malformed secret access key was accepted'
fi
[[ ! -e "$work/output/short" ]] || fail 'a malformed key wrote credentials'
pass
if fetch "$work/output/aws-credentials" env >"$work/existing.out" 2>&1; then
  fail 'an existing output path was overwritten'
fi
pass

printf 'test-fetch-openbao-releases-r2-credentials: PASS cases=%s\n' "$CASES"
