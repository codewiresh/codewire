#!/usr/bin/env bash
# Create or rotate the synthetic Dev invitee: an account with a password and
# no organization, API key or other authority, which the invitations journey
# (docs/journeys/invitations.md) invites, signs in as and removes. An
# organization-bound API key cannot list or accept invitations, so the journey
# needs an account that signs in like a person (orchestrator, 2026-11-13).
# Run only through Infra's scoped kube-access wrapper and a current human
# OpenBao OIDC session; no secret value is ever printed.
set -euo pipefail

readonly OPENBAO_ADDR="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"
readonly OPENBAO_PATH="apps/codewire/dev/ci-invitee"
# The mail provider's simulator accepts the invitation email without reaching a
# person or counting as a bounce; codewire-dev.sh takes no mail.
readonly INVITEE_EMAIL="success+codewire-dev-invitee@simulator.amazonses.com"
readonly INVITEE_NAME="Codewire Dev invitee"
# The idp's argon2id parameters (crates/codewire-idp/src/auth_session.rs).
readonly ARGON2_ARGS=(-id -t 3 -m 16 -p 2 -l 32 -e)

CREATE_DOCUMENT=false
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
KUBE_NAMESPACE="${KUBE_NAMESPACE:-dev}"
POSTGRES_POD="${POSTGRES_POD:-}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-codewire}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
TMPDIR_INVITEE=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/provision-dev-invitee-user.sh [--create-document] [options]

Creates or rotates the synthetic Dev invitee account: verified, enabled, with a
new generated password and no organization memberships, API keys or sessions.
The password is hashed locally (argon2id, read from stdin), the hash goes to
the database, and {password, userEmail} is CAS-published to the canonical
OpenBao document apps/codewire/dev/ci-invitee. A sign-in with the new password
proves the pair before the run passes.

Options:
  --create-document         The document does not exist yet (first run)
  --context CONTEXT         kubectl context
  --namespace NAMESPACE     Dev namespace (default: dev)
  --postgres-pod POD        Postgres pod (default: the codewire-db primary)
USAGE
}

log() { printf '[runtime-invitee-provision] %s\n' "$*" >&2; }
die() { printf '[runtime-invitee-provision] ERROR: %s\n' "$*" >&2; exit 1; }

secure_remove() {
  [[ "$#" -gt 0 ]] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -u -- "$@" 2>/dev/null && return 0
  fi
  rm -f -- "$@" 2>/dev/null
}

cleanup() {
  local status=0
  if [[ -n "$TMPDIR_INVITEE" && -d "$TMPDIR_INVITEE" ]]; then
    while IFS= read -r -d '' file; do secure_remove "$file" || status=1; done \
      < <(find "$TMPDIR_INVITEE" -type f -print0)
    while IFS= read -r -d '' dir; do rmdir "$dir" 2>/dev/null || status=1; done \
      < <(find "$TMPDIR_INVITEE" -depth -type d -print0)
    [[ ! -e "$TMPDIR_INVITEE" ]] || status=1
  fi
  TMPDIR_INVITEE=""
  return "$status"
}
trap 'cleanup || true' EXIT
trap 'exit 130' HUP INT TERM

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

while (($# > 0)); do
  case "$1" in
    --create-document) CREATE_DOCUMENT=true; shift ;;
    --context) [[ $# -ge 2 ]] || die '--context requires a value'; KUBE_CONTEXT="$2"; shift 2 ;;
    --namespace) [[ $# -ge 2 ]] || die '--namespace requires a value'; KUBE_NAMESPACE="$2"; shift 2 ;;
    --postgres-pod) [[ $# -ge 2 ]] || die '--postgres-pod requires a value'; POSTGRES_POD="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
readonly CREATE_DOCUMENT

case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac
for command in argon2 awk bao basenc curl find jq kubectl mktemp rg rm rmdir stat; do
  require_cmd "$command"
done
[[ -n "${INFRA_KUBECONFIG_DIR:-}" && -n "${KUBECONFIG:-}" ]] ||
  die 'run through the scoped Infra kube-access wrapper'
[[ "$KUBECONFIG" == "$INFRA_KUBECONFIG_DIR"/* ]] ||
  die 'KUBECONFIG is outside the scoped Infra kube-access directory'
[[ "${BAO_ADDR:-$OPENBAO_ADDR}" == "$OPENBAO_ADDR" ]] ||
  die 'BAO_ADDR must be the canonical OpenBao Tailnet endpoint'
export BAO_ADDR="$OPENBAO_ADDR"

umask 077
TMPDIR_INVITEE="$(mktemp -d "${TMPDIR:-/tmp}/codewire-invitee-provision.XXXXXX")"
chmod 0700 "$TMPDIR_INVITEE"
PASSWORD_FILE="$TMPDIR_INVITEE/password"
HASH_FILE="$TMPDIR_INVITEE/hash"
PAYLOAD="$TMPDIR_INVITEE/payload.json"
CURRENT_DOCUMENT="$TMPDIR_INVITEE/current.json"
SIGN_IN_BODY="$TMPDIR_INVITEE/sign-in.json"
COOKIE_JAR="$TMPDIR_INVITEE/cookies"
BAO_STDERR="$TMPDIR_INVITEE/bao.stderr"
DB_RESULT="$TMPDIR_INVITEE/db-result"
for file in "$PASSWORD_FILE" "$HASH_FILE" "$PAYLOAD" "$CURRENT_DOCUMENT" \
  "$SIGN_IN_BODY" "$COOKIE_JAR" "$BAO_STDERR" "$DB_RESULT"; do
  : >"$file"
  chmod 0600 "$file"
done

KUBECTL=(kubectl)
[[ -z "$KUBE_CONTEXT" ]] || KUBECTL+=(--context "$KUBE_CONTEXT")
if [[ -z "$POSTGRES_POD" ]]; then
  primaries="$("${KUBECTL[@]}" -n "$KUBE_NAMESPACE" get pods \
    -l cnpg.io/cluster=codewire-db,cnpg.io/instanceRole=primary -o name)" ||
    die 'cannot list the codewire-db primary'
  [[ "$(wc -l <<<"$primaries")" == 1 && "$primaries" == pod/codewire-db-* ]] ||
    die 'expected exactly one codewire-db primary'
  POSTGRES_POD="${primaries#pod/}"
fi
readonly POSTGRES_POD
run_psql() {
  "${KUBECTL[@]}" -n "$KUBE_NAMESPACE" exec -i "$POSTGRES_POD" \
    -c "$POSTGRES_CONTAINER" -- psql -X -qAt -v ON_ERROR_STOP=1 \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"
}

# The document's version for the CAS write: 0 when it does not exist, which
# only --create-document accepts. Permission denied and every other failure stop
# the run before anything is written.
old_version=0
: >"$BAO_STDERR"
if bao kv get -format=json "$OPENBAO_PATH" >"$CURRENT_DOCUMENT" 2>"$BAO_STDERR"; then
  [[ "$CREATE_DOCUMENT" == false ]] ||
    die "OpenBao $OPENBAO_PATH already exists; rerun without --create-document to rotate it"
  jq -e '
    (.data.metadata.version | type == "number" and . > 0) and
    (.data.data | type == "object" and keys == ["password", "userEmail"])
  ' "$CURRENT_DOCUMENT" >/dev/null || die "OpenBao $OPENBAO_PATH has an unexpected shape"
  old_version="$(jq -r '.data.metadata.version' "$CURRENT_DOCUMENT")"
elif rg -qi 'permission denied|status code: 403|code 403' "$BAO_STDERR"; then
  die "OpenBao OIDC session is stale or lacks the exact Dev path $OPENBAO_PATH"
elif rg -q '^No value found at ' "$BAO_STDERR"; then
  [[ "$CREATE_DOCUMENT" == true ]] ||
    die "OpenBao $OPENBAO_PATH does not exist; pass --create-document on the first run"
else
  die "unable to read OpenBao $OPENBAO_PATH; protected output suppressed"
fi
secure_remove "$CURRENT_DOCUMENT"

log 'generating a new password and its argon2id hash'
head -c 32 /dev/urandom | basenc --base64url | tr -d '=\n' >"$PASSWORD_FILE"
[[ "$(stat -c %s "$PASSWORD_FILE")" == 43 ]] || die 'password generation failed'
salt="$(head -c 12 /dev/urandom | basenc --base64url | tr -d '=\n')"
argon2 "$salt" "${ARGON2_ARGS[@]}" <"$PASSWORD_FILE" >"$HASH_FILE" ||
  die 'argon2 hashing failed'
awk 'NR == 1 && /^\$argon2id\$v=19\$m=65536,t=3,p=2\$[A-Za-z0-9+\/]+\$[A-Za-z0-9+\/]+$/ { ok=1; next }
  { ok=0; exit } END { exit ok == 1 ? 0 : 1 }' "$HASH_FILE" ||
  die 'argon2 did not return one well-formed PHC hash'

# One transaction: the account exists, is verified and enabled, signs in only
# with the new password, and holds nothing else. A rerun repairs any of it,
# including memberships a journey run left behind.
log 'writing the invitee account and its password hash'
{
  printf '\\set hash %s\n' "'$(awk 'NR == 1' "$HASH_FILE")'"
  cat <<'SQL'
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
BEGIN;
INSERT INTO users (id, email, email_verified, name, enabled, created_at, updated_at)
VALUES (encode(public.gen_random_bytes(16), 'hex'), :'email', true, :'name', true, NOW(), NOW())
ON CONFLICT (email) DO UPDATE SET email_verified = true, enabled = true,
  name = EXCLUDED.name, updated_at = NOW();
DELETE FROM accounts
WHERE user_id = (SELECT id FROM users WHERE email = :'email') AND provider_id = 'credential';
WITH credential AS (
  INSERT INTO accounts (id, user_id, provider_id, account_id, password, created_at, updated_at)
  SELECT encode(public.gen_random_bytes(16), 'hex'), id, 'credential', email, :'hash', NOW(), NOW()
  FROM users WHERE email = :'email'
  RETURNING user_id
), memberships AS (
  DELETE FROM org_members m USING credential WHERE m.user_id = credential.user_id RETURNING m.id
), keys AS (
  DELETE FROM api_keys k USING credential WHERE k.user_id = credential.user_id RETURNING k.id
), sessions AS (
  DELETE FROM sessions s USING credential WHERE s.user_id = credential.user_id RETURNING s.id
)
SELECT (SELECT count(*) FROM credential) || ' ' || (SELECT count(*) FROM memberships)
  || ' ' || (SELECT count(*) FROM keys);
COMMIT;
SQL
} | run_psql --set "email=$INVITEE_EMAIL" --set "name=$INVITEE_NAME" >"$DB_RESULT" ||
  die 'the database write failed; nothing was published'
read -r credentials memberships keys <"$DB_RESULT" || die 'the database returned no result'
[[ "$credentials" == 1 ]] || die 'the database did not write exactly one credential'
log "account ready; removed memberships=$memberships api_keys=$keys"

jq -n --rawfile password "$PASSWORD_FILE" --arg userEmail "$INVITEE_EMAIL" \
  '{password: $password, userEmail: $userEmail}' >"$PAYLOAD"
log 'CAS-publishing the password to canonical OpenBao'
bao kv put -cas="$old_version" "$OPENBAO_PATH" "@$PAYLOAD" >/dev/null 2>"$BAO_STDERR" ||
  die "the OpenBao CAS write failed; the account has a password nobody holds, so rerun to rotate it"
bao kv get -format=json "$OPENBAO_PATH" >"$CURRENT_DOCUMENT" 2>"$BAO_STDERR" ||
  die 'the OpenBao readback failed; rerun to rotate'
jq -e --slurpfile payload "$PAYLOAD" '.data.data == $payload[0]' "$CURRENT_DOCUMENT" >/dev/null ||
  die 'the OpenBao readback did not match; a concurrent write won, so rerun to rotate'

# The proof: Dev signs the account in with the published password. The session
# it makes is signed out at once.
log 'proving the password by signing in on Dev'
jq -n --rawfile password "$PASSWORD_FILE" --arg email "$INVITEE_EMAIL" \
  '{email: $email, password: $password}' >"$SIGN_IN_BODY"
status="$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' -c "$COOKIE_JAR" \
  -H 'Content-Type: application/json' --data "@$SIGN_IN_BODY" \
  "$CODEWIRE_SERVER_URL/api/auth/sign-in")" || die 'the sign-in probe could not reach Dev'
[[ "$status" == 200 ]] || die "the sign-in probe answered HTTP $status"
rg -q 'codewire\.session_token' "$COOKIE_JAR" || die 'the sign-in probe returned no session'
curl -sS --max-time 30 -o /dev/null -b "$COOKIE_JAR" -X POST \
  "$CODEWIRE_SERVER_URL/api/auth/sign-out" || log 'signing the probe session out failed; it expires on its own'

log "PASS canonical_store=openbao path=$OPENBAO_PATH sign_in_probe=true memberships=0 api_keys=0 secret_values_printed=false"
