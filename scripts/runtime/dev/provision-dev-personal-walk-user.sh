#!/usr/bin/env bash
# Create or rotate the synthetic Dev personal-walk identity (#6074): a
# verified account with a password and no second factor, admin flag or API
# key, which is a plain member of exactly one organization on the regular
# rate card. Walks that need account-global operations (personal credentials
# and profiles) sign in as it through with-dev-personal-walk.sh: every API key
# is bound to one organization, and personal credentials refuse API keys, so
# the walk signs in like a person, as the invitations journey's invitee does.
#
# The organization's owner is a second synthetic account with no password,
# API key, linked sign-in or session, so nobody can sign in as it. Every
# billing write (automatic top-up, credit, cards, Stripe sessions) needs an
# owner or admin, so the walk's sign-in, if it leaked, can't change billing or
# add credit, and its EUR 5 grant is a server-side ceiling. The walk account
# also may not create an organization, which would make it an owner.
#
# Dev only, synthetic only. A real provider key on this account is an
# incident: revoke it at the provider and delete it here by id.
#
# Run only through Infra's scoped kube-access wrapper and a current human
# OpenBao OIDC session; no secret value is ever printed or put on argv.
set -euo pipefail

readonly DEV_ORIGIN="https://codewire-dev.sh"
readonly OPENBAO_ADDR="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-$DEV_ORIGIN}"
readonly OPENBAO_PATH="apps/codewire/dev/ci-personal-walk"
# The mail provider's simulator accepts mail without reaching a person or
# counting as a bounce; codewire-dev.sh takes no mail.
readonly WALK_EMAIL="success+codewire-dev-personal-walk@simulator.amazonses.com"
readonly WALK_NAME="Codewire Dev personal walk"
readonly OWNER_EMAIL="success+codewire-dev-personal-walk-owner@simulator.amazonses.com"
readonly OWNER_NAME="Codewire Dev personal walk owner"
readonly WALK_ORG_NAME="Codewire Dev personal walk"
readonly WALK_ORG_SLUG="codewire-dev-personal-walk"
readonly KUBE_NAMESPACE="dev"
# The idp's argon2id parameters (crates/codewire-idp/src/auth_session.rs).
readonly ARGON2_ARGS=(-id -t 3 -m 16 -p 2 -l 32 -e)

CREATE_DOCUMENT=false
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
POSTGRES_POD="${POSTGRES_POD:-}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-codewire}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
TMPDIR_WALK=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/provision-dev-personal-walk-user.sh [--create-document] [options]

Dev only. Creates or rotates the synthetic Dev personal-walk account
success+codewire-dev-personal-walk@simulator.amazonses.com: verified, enabled,
not an admin, no second factor and no API key, and a plain member (role
member, assignment viewer only) of exactly one organization,
codewire-dev-personal-walk, on the regular rate card. It may not create an
organization (its org_create limit is 0). Every other membership of it, and
every pending invitation, linked sign-in and API key, is removed.

The organization is owned by a second synthetic account,
success+codewire-dev-personal-walk-owner@simulator.amazonses.com, verified,
enabled and not an admin, with no password, API key, linked sign-in, session
or CLI sign-in: each run removes any it has and checks there are none. The
organization has exactly these two members. Billing writes need an owner or
admin, so the walk account can't turn automatic top-up on or add credit.
An organization with this slug made by any other account stops the run; one
made by the walk account (before #6074's review) moves to the owner.

The organization's quota is two environments of the smallest shape, its
credit is topped up to exactly EUR 5 by one named grant, and automatic top-up
is off.

A new generated password is hashed locally (argon2id, read from stdin), the
hash goes to the database, and {password, userEmail} is CAS-published to the
OpenBao document apps/codewire/dev/ci-personal-walk. A rerun rotates: it proves
one sign-in with the new password, only then revokes the account's other
sessions and CLI sign-ins by their exact ids, and checks that the old
password is refused.

Synthetic only: walks give this account synthetic, canary-marked provider
credentials, never a real one. A real provider key found on it is an
incident: revoke it at the provider and delete it here by id.

Options:
  --create-document         The document does not exist yet (first run)
  --context CONTEXT         kubectl context
  --postgres-pod POD        Postgres pod (default: the codewire-db primary)
USAGE
}

log() { printf '[runtime-personal-walk-provision] %s\n' "$*" >&2; }
die() { printf '[runtime-personal-walk-provision] ERROR: %s\n' "$*" >&2; exit 1; }

secure_remove() {
  [[ "$#" -gt 0 ]] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -u -- "$@" 2>/dev/null && return 0
  fi
  rm -f -- "$@" 2>/dev/null
}

cleanup() {
  local status=0
  if [[ -n "$TMPDIR_WALK" && -d "$TMPDIR_WALK" ]]; then
    while IFS= read -r -d '' file; do secure_remove "$file" || status=1; done \
      < <(find "$TMPDIR_WALK" -type f -print0)
    while IFS= read -r -d '' dir; do rmdir "$dir" 2>/dev/null || status=1; done \
      < <(find "$TMPDIR_WALK" -depth -type d -print0)
    [[ ! -e "$TMPDIR_WALK" ]] || status=1
  fi
  TMPDIR_WALK=""
  return "$status"
}
trap 'cleanup || true' EXIT
trap 'exit 130' HUP INT TERM

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

while (($# > 0)); do
  case "$1" in
    --create-document) CREATE_DOCUMENT=true; shift ;;
    --context) [[ $# -ge 2 ]] || die '--context requires a value'; KUBE_CONTEXT="$2"; shift 2 ;;
    --postgres-pod) [[ $# -ge 2 ]] || die '--postgres-pod requires a value'; POSTGRES_POD="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
readonly CREATE_DOCUMENT

case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac
[[ "$CODEWIRE_SERVER_URL" == "$DEV_ORIGIN" ]] ||
  die "this identity exists only on Dev; refusing server $CODEWIRE_SERVER_URL"
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

# The password, its hash, the sign-in cookies and the document live only in
# the caller's own tmpfs runtime directory, never under a TMPDIR on disk.
[[ "${XDG_RUNTIME_DIR:-}" == /* && -d "$XDG_RUNTIME_DIR" && ! -L "$XDG_RUNTIME_DIR" &&
  "$(stat -c '%a:%u' "$XDG_RUNTIME_DIR")" == "700:$(id -u)" ]] ||
  die 'XDG_RUNTIME_DIR must be your own 0700 runtime directory'
case "$(stat -f -c %T "$XDG_RUNTIME_DIR")" in
  tmpfs|ramfs) ;;
  *) die 'XDG_RUNTIME_DIR is not on tmpfs; the password must never reach a disk' ;;
esac

umask 077
TMPDIR_WALK="$(mktemp -d "$XDG_RUNTIME_DIR/codewire-personal-walk-provision.XXXXXX")"
chmod 0700 "$TMPDIR_WALK"
PASSWORD_FILE="$TMPDIR_WALK/password"
HASH_FILE="$TMPDIR_WALK/hash"
PAYLOAD="$TMPDIR_WALK/payload.json"
CURRENT_DOCUMENT="$TMPDIR_WALK/current.json"
SIGN_IN_BODY="$TMPDIR_WALK/sign-in.json"
OLD_SIGN_IN_BODY="$TMPDIR_WALK/old-sign-in.json"
COOKIE_JAR="$TMPDIR_WALK/cookies"
OLD_COOKIE_JAR="$TMPDIR_WALK/old-cookies"
BAO_STDERR="$TMPDIR_WALK/bao.stderr"
DB_RESULT="$TMPDIR_WALK/db-result"
GRANT_IDS="$TMPDIR_WALK/grant-ids"
for file in "$PASSWORD_FILE" "$HASH_FILE" "$PAYLOAD" "$CURRENT_DOCUMENT" \
  "$SIGN_IN_BODY" "$OLD_SIGN_IN_BODY" "$COOKIE_JAR" "$OLD_COOKIE_JAR" \
  "$BAO_STDERR" "$DB_RESULT" "$GRANT_IDS"; do
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

# One sign-in attempt with the JSON body in $1, keeping its cookies in $2.
# Prints the HTTP status. The body file holds the password; curl reads it, so
# the password is never on argv.
sign_in() {
  curl -sS --max-time 30 -o /dev/null -w '%{http_code}' -c "$2" \
    -H 'Content-Type: application/json' --data "@$1" \
    "$CODEWIRE_SERVER_URL/api/auth/sign-in"
}

sign_out() {
  curl -sS --max-time 30 -o /dev/null -b "$1" -H "Origin: $CODEWIRE_SERVER_URL" \
    -X POST "$CODEWIRE_SERVER_URL/api/auth/sign-out"
}

# The document's version for the CAS write: 0 when it does not exist, which
# only --create-document accepts. Permission denied and every other failure stop
# the run before anything is written. On a rotation the old password is kept
# in its own 0600 file, only to show that it is refused afterwards.
old_version=0
: >"$BAO_STDERR"
if bao kv get -format=json "$OPENBAO_PATH" >"$CURRENT_DOCUMENT" 2>"$BAO_STDERR"; then
  [[ "$CREATE_DOCUMENT" == false ]] ||
    die "OpenBao $OPENBAO_PATH already exists; rerun without --create-document to rotate it"
  jq -e --arg email "$WALK_EMAIL" '
    (.data.metadata.version | type == "number" and . > 0) and
    (.data.data | type == "object" and keys == ["password", "userEmail"]) and
    (.data.data.password | type == "string" and length > 0) and
    .data.data.userEmail == $email
  ' "$CURRENT_DOCUMENT" >/dev/null || die "OpenBao $OPENBAO_PATH has an unexpected shape"
  old_version="$(jq -r '.data.metadata.version' "$CURRENT_DOCUMENT")"
  jq '{email: .data.data.userEmail, password: .data.data.password}' \
    "$CURRENT_DOCUMENT" >"$OLD_SIGN_IN_BODY"
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

# One transaction. The walk account exists, is verified and enabled, is no
# admin, has no second factor and signs in only with the new password. The
# owner account exists the same way with no way in at all: no password or
# linked sign-in, no session, CLI sign-in or API key. The owner owns, and
# created, one organization on the regular rate card, whose only other member
# is the walk account, as a plain member with the viewer assignment only, and
# which has no pending invitation. The walk account belongs to nothing else
# and may create no organization, which would make it an owner. Every billing
# write needs an owner or admin, so the organization's credit, topped up to
# exactly EUR 5 by one named grant with automatic top-up off, is a ceiling the
# walk's sign-in can't raise (#6074). Its quota is two environments of the
# smallest shape. An organization with this slug made by any other account
# stops the run; one the walk account made moves to the owner. Sessions and
# CLI sign-ins of the walk account stay until the new password is proven.
log 'writing the accounts, the password hash and the organization'
{
  printf '\\set hash %s\n' "'$(awk 'NR == 1' "$HASH_FILE")'"
  cat <<'SQL'
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
BEGIN;
INSERT INTO users (id, email, email_verified, name, enabled, is_admin, two_factor_enabled,
  created_at, updated_at)
VALUES (encode(public.gen_random_bytes(16), 'hex'), :'email', true, :'name', true, false, false,
  NOW(), NOW()),
  (encode(public.gen_random_bytes(16), 'hex'), :'owner_email', true, :'owner_name', true, false,
  false, NOW(), NOW())
ON CONFLICT (email) DO UPDATE SET email_verified = true, email_vouched_by = NULL,
  enabled = true, is_admin = false, two_factor_enabled = false,
  failed_login_attempts = 0, locked_until = NULL, name = EXCLUDED.name, updated_at = NOW();
SELECT id AS walk_user_id FROM users WHERE email = :'email' \gset
SELECT id AS owner_user_id FROM users WHERE email = :'owner_email' \gset
SELECT 'previous', COALESCE((SELECT CASE created_by WHEN :'owner_user_id' THEN 'owner'
  WHEN :'walk_user_id' THEN 'walk_user' ELSE 'other' END
  FROM organizations WHERE slug = :'org_slug'), 'none');
INSERT INTO organizations (id, name, slug, created_by, rate_card, billing_exempt,
  auto_top_up_enabled, created_at, updated_at)
VALUES (encode(public.gen_random_bytes(16), 'hex'), :'org_name', :'org_slug',
  :'owner_user_id', 'regular', false, false, NOW(), NOW())
ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name, created_by = EXCLUDED.created_by,
  rate_card = 'regular', billing_exempt = false, auto_top_up_enabled = false, updated_at = NOW()
WHERE organizations.created_by IN (EXCLUDED.created_by, :'walk_user_id')
RETURNING id AS walk_org_id \gset
WITH walk_links AS (
  DELETE FROM accounts WHERE user_id = :'walk_user_id' RETURNING provider_id
), owner_links AS (
  DELETE FROM accounts WHERE user_id = :'owner_user_id' RETURNING id
), other_memberships AS (
  DELETE FROM org_members WHERE user_id IN (:'walk_user_id', :'owner_user_id')
    AND org_id <> :'walk_org_id' RETURNING id
), other_members AS (
  DELETE FROM org_members WHERE org_id = :'walk_org_id'
    AND user_id NOT IN (:'walk_user_id', :'owner_user_id') RETURNING id
), assignments AS (
  DELETE FROM org_member_assignments USING org_members
  WHERE org_member_assignments.org_member_id = org_members.id
    AND org_members.org_id = :'walk_org_id' AND org_members.user_id = :'walk_user_id'
    AND org_member_assignments.assignment <> 'viewer'
  RETURNING org_member_assignments.id
), invitations AS (
  DELETE FROM org_invitations WHERE org_id = :'walk_org_id' AND status = 'pending' RETURNING id
), keys AS (
  DELETE FROM api_keys WHERE user_id IN (:'walk_user_id', :'owner_user_id') RETURNING id
), owner_sessions AS (
  DELETE FROM sessions WHERE user_id = :'owner_user_id' RETURNING id
), owner_refresh AS (
  DELETE FROM oidc_refresh_tokens WHERE user_id = :'owner_user_id' RETURNING id
), owner_access AS (
  DELETE FROM oidc_access_tokens WHERE user_id = :'owner_user_id' RETURNING token_hash
), owner_devices AS (
  DELETE FROM oidc_device_authorizations WHERE user_id = :'owner_user_id'
  RETURNING device_code_hash
)
SELECT 'removed', (SELECT count(*) FROM walk_links WHERE provider_id <> 'credential'),
  (SELECT count(*) FROM other_memberships), (SELECT count(*) FROM other_members),
  (SELECT count(*) FROM assignments), (SELECT count(*) FROM invitations),
  (SELECT count(*) FROM keys), (SELECT count(*) FROM owner_links),
  (SELECT count(*) FROM owner_sessions),
  (SELECT count(*) FROM owner_refresh) + (SELECT count(*) FROM owner_access)
    + (SELECT count(*) FROM owner_devices);
INSERT INTO accounts (id, user_id, provider_id, account_id, password, created_at, updated_at)
VALUES (encode(public.gen_random_bytes(16), 'hex'), :'walk_user_id', 'credential', :'email',
  :'hash', NOW(), NOW());
INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
VALUES (encode(public.gen_random_bytes(16), 'hex'), :'walk_org_id', :'owner_user_id', 'owner',
  NOW(), NOW()),
  (encode(public.gen_random_bytes(16), 'hex'), :'walk_org_id', :'walk_user_id', 'member',
  NOW(), NOW())
ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = NOW();
INSERT INTO org_member_assignments (org_member_id, assignment)
SELECT id, 'viewer' FROM org_members WHERE org_id = :'walk_org_id' AND user_id = :'walk_user_id'
ON CONFLICT (org_member_id, assignment) DO NOTHING;
INSERT INTO rate_limit_overrides (user_id, name, max_requests, updated_by, updated_at)
VALUES (:'walk_user_id', 'org_create', 0, 'provision-dev-personal-walk-user', NOW())
ON CONFLICT (user_id, name) DO UPDATE SET max_requests = 0, updated_by = EXCLUDED.updated_by,
  updated_at = NOW();
INSERT INTO environment_quotas (org_id, max_concurrent_environments, max_concurrent_sandbox,
  max_cpu_millicores, max_memory_mb)
VALUES (:'walk_org_id', 2, 2, 4000, 16384)
ON CONFLICT (org_id) DO UPDATE SET max_concurrent_environments = 2, max_concurrent_sandbox = 2,
  max_cpu_millicores = 4000, max_memory_mb = 16384;
INSERT INTO billing_credit_ledger (organization_id, entry_kind, amount_nano_eur, idempotency_key,
  reason)
SELECT :'walk_org_id', 'grant', 5000000000 - balance,
  'personal-walk-dev-top-up-' || to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYYMMDD"T"HH24MISSUS'),
  'Dev personal-walk test credit (#6074): topped up to EUR 5 by its provisioner'
FROM (SELECT COALESCE((SELECT balance_nano_eur FROM billing_credit_balances
  WHERE organization_id = :'walk_org_id'), 0) AS balance) AS current
WHERE balance < 5000000000;
SELECT 'state',
  (SELECT count(*) FROM users WHERE id = :'walk_user_id' AND enabled AND email_verified
    AND NOT COALESCE(is_admin, false) AND NOT COALESCE(two_factor_enabled, false)),
  (SELECT count(*) FROM accounts WHERE user_id = :'walk_user_id' AND provider_id = 'credential'),
  (SELECT count(*) FROM accounts WHERE user_id = :'walk_user_id'),
  (SELECT count(*) FROM org_members WHERE user_id = :'walk_user_id'),
  (SELECT count(*) FROM org_members WHERE org_id = :'walk_org_id' AND user_id = :'walk_user_id'
    AND role = 'member'),
  (SELECT count(*) FROM org_member_assignments a JOIN org_members m ON m.id = a.org_member_id
    WHERE m.user_id = :'walk_user_id' AND a.assignment <> 'viewer'),
  (SELECT count(*) FROM users WHERE id = :'owner_user_id' AND enabled AND email_verified
    AND NOT COALESCE(is_admin, false) AND NOT COALESCE(two_factor_enabled, false)),
  (SELECT count(*) FROM accounts WHERE user_id = :'owner_user_id'),
  (SELECT count(*) FROM sessions WHERE user_id = :'owner_user_id')
    + (SELECT count(*) FROM oidc_refresh_tokens WHERE user_id = :'owner_user_id')
    + (SELECT count(*) FROM oidc_access_tokens WHERE user_id = :'owner_user_id')
    + (SELECT count(*) FROM oidc_device_authorizations WHERE user_id = :'owner_user_id'),
  (SELECT count(*) FROM org_members WHERE user_id = :'owner_user_id'),
  (SELECT count(*) FROM org_members WHERE org_id = :'walk_org_id' AND user_id = :'owner_user_id'
    AND role = 'owner'),
  (SELECT count(*) FROM org_members WHERE org_id = :'walk_org_id'),
  (SELECT count(*) FROM organizations WHERE id = :'walk_org_id' AND created_by = :'owner_user_id'
    AND rate_card = 'regular' AND NOT billing_exempt AND NOT auto_top_up_enabled
    AND deletion_state = 'active' AND suspended_at IS NULL),
  (SELECT count(*) FROM api_keys WHERE user_id IN (:'walk_user_id', :'owner_user_id')),
  (SELECT count(*) FROM org_invitations WHERE org_id = :'walk_org_id' AND status = 'pending'),
  (SELECT count(*) FROM rate_limit_overrides WHERE user_id = :'walk_user_id'
    AND name = 'org_create' AND max_requests = 0),
  (SELECT count(*) FROM environment_quotas WHERE org_id = :'walk_org_id'
    AND max_concurrent_environments = 2 AND max_concurrent_sandbox = 2
    AND max_cpu_millicores = 4000 AND max_memory_mb = 16384),
  (SELECT count(*) FROM billing_credit_balances WHERE organization_id = :'walk_org_id'
    AND balance_nano_eur = 5000000000);
COMMIT;
SQL
} | run_psql --set "email=$WALK_EMAIL" --set "name=$WALK_NAME" \
  --set "owner_email=$OWNER_EMAIL" --set "owner_name=$OWNER_NAME" \
  --set "org_name=$WALK_ORG_NAME" --set "org_slug=$WALK_ORG_SLUG" >"$DB_RESULT" ||
  die "the database write failed; nothing was published (an organization $WALK_ORG_SLUG that neither account created also stops it)"
previous="$(awk -F'|' '$1 == "previous" { print $2 }' "$DB_RESULT")"
removed="$(awk -F'|' '$1 == "removed" { $1 = ""; print substr($0, 2) }' "$DB_RESULT")"
state="$(awk -F'|' '$1 == "state" { $1 = ""; print substr($0, 2) }' "$DB_RESULT")"
# An organization someone else made never reaches here: the upsert returns no
# row and psql stops. This is the second guard.
[[ "$previous" =~ ^(none|owner|walk_user)$ ]] ||
  die "the organization $WALK_ORG_SLUG was made by another account (got: ${previous:-none})"
[[ "$removed" =~ ^[0-9]+(\ [0-9]+){8}$ ]] || die 'the database returned no removal counts'
# walk: flags, password, sign-ins, memberships, member role, other assignments;
# owner: flags, sign-ins, sessions and CLI sign-ins, memberships, owner role;
# organization: members, its row, API keys, invitations, org_create, quota, credit.
readonly EXPECTED_STATE='1 1 1 1 1 0 1 0 0 1 1 2 1 0 0 1 1 1'
[[ "$state" == "$EXPECTED_STATE" ]] ||
  die "the database did not reach the expected account state (got: ${state:-none}; want: $EXPECTED_STATE)"
read -r links memberships members assignments invitations keys owner_links owner_sessions \
  owner_cli_sign_ins <<<"$removed"
case "$previous" in
  none) organization=created ;;
  owner) organization=kept ;;
  walk_user) organization=moved_from_walk_user_to_owner ;;
esac
log "accounts ready; organization $organization; removed sign_in_links=$links other_memberships=$memberships other_members=$members walk_assignments=$assignments pending_invitations=$invitations api_keys=$keys owner_sign_in_links=$owner_links owner_sessions=$owner_sessions owner_cli_sign_ins=$owner_cli_sign_ins"

jq -n --rawfile password "$PASSWORD_FILE" --arg userEmail "$WALK_EMAIL" \
  '{password: $password, userEmail: $userEmail}' >"$PAYLOAD"
log 'CAS-publishing the password to canonical OpenBao'
bao kv put -cas="$old_version" "$OPENBAO_PATH" "@$PAYLOAD" >/dev/null 2>"$BAO_STDERR" ||
  die "the OpenBao CAS write failed; the account has a password nobody holds, so rerun to rotate it"
bao kv get -format=json "$OPENBAO_PATH" >"$CURRENT_DOCUMENT" 2>"$BAO_STDERR" ||
  die 'the OpenBao readback failed; rerun to rotate'
jq -e --slurpfile payload "$PAYLOAD" '.data.data == $payload[0]' "$CURRENT_DOCUMENT" >/dev/null ||
  die 'the OpenBao readback did not match; a concurrent write won, so rerun to rotate'
secure_remove "$CURRENT_DOCUMENT" "$PAYLOAD"

# The proof: Dev signs the account in with the published password. Nothing is
# revoked before it passes. The session it makes is signed out at once, and
# revoked by id below if that sign-out did not land.
log 'proving the new password by signing in on Dev'
jq -n --rawfile password "$PASSWORD_FILE" --arg email "$WALK_EMAIL" \
  '{email: $email, password: $password}' >"$SIGN_IN_BODY"
secure_remove "$PASSWORD_FILE"
status="$(sign_in "$SIGN_IN_BODY" "$COOKIE_JAR")" || die 'the sign-in probe could not reach Dev'
secure_remove "$SIGN_IN_BODY"
[[ "$status" == 200 ]] ||
  die "the sign-in probe answered HTTP $status; no session or CLI sign-in was revoked"
rg -q 'codewire\.session_token' "$COOKIE_JAR" ||
  die 'the sign-in probe returned no session; no session or CLI sign-in was revoked'
sign_out "$COOKIE_JAR" || log 'signing the probe session out failed; it is revoked by id below'
secure_remove "$COOKIE_JAR"

# Only now: every other session and CLI sign-in (OAuth refresh and access
# tokens) of this account, listed and then revoked by exact id. An access
# token's id is its stored hash, never the token.
log 'revoking the account'"'"'s other sessions and CLI sign-ins by exact id'
{
  cat <<'SQL'
SELECT 'session ' || s.id FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email = :'email'
UNION ALL
SELECT 'refresh ' || r.id FROM oidc_refresh_tokens r JOIN users u ON u.id = r.user_id
WHERE u.email = :'email'
UNION ALL
SELECT 'access ' || a.token_hash FROM oidc_access_tokens a JOIN users u ON u.id = a.user_id
WHERE u.email = :'email';
SQL
} | run_psql --set "email=$WALK_EMAIL" >"$GRANT_IDS" || die 'listing the account'"'"'s sessions failed'
session_ids=() refresh_ids=() access_ids=()
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  [[ "$line" =~ ^(session|refresh|access)\ ([A-Za-z0-9_-]{1,128})$ ]] ||
    die 'the database listed a session or CLI sign-in id of an unexpected shape'
  case "${BASH_REMATCH[1]}" in
    session) session_ids+=("${BASH_REMATCH[2]}") ;;
    refresh) refresh_ids+=("${BASH_REMATCH[2]}") ;;
    access) access_ids+=("${BASH_REMATCH[2]}") ;;
  esac
done <"$GRANT_IDS"
pg_array() { local IFS=,; printf "'{%s}'" "$*"; }
{
  printf '\\set session_ids %s\n' "$(pg_array "${session_ids[@]}")"
  printf '\\set refresh_ids %s\n' "$(pg_array "${refresh_ids[@]}")"
  printf '\\set access_ids %s\n' "$(pg_array "${access_ids[@]}")"
  cat <<'SQL'
BEGIN;
WITH walk_user AS (
  SELECT id FROM users WHERE email = :'email'
), revoked_sessions AS (
  DELETE FROM sessions USING walk_user
  WHERE sessions.user_id = walk_user.id AND sessions.id = ANY(:'session_ids'::text[])
  RETURNING sessions.id
), revoked_refresh AS (
  DELETE FROM oidc_refresh_tokens USING walk_user
  WHERE oidc_refresh_tokens.user_id = walk_user.id
    AND oidc_refresh_tokens.id = ANY(:'refresh_ids'::text[])
  RETURNING oidc_refresh_tokens.id
), revoked_access AS (
  DELETE FROM oidc_access_tokens USING walk_user
  WHERE oidc_access_tokens.user_id = walk_user.id
    AND oidc_access_tokens.token_hash = ANY(:'access_ids'::text[])
  RETURNING oidc_access_tokens.token_hash
)
SELECT 'revoked', (SELECT count(*) FROM revoked_sessions), (SELECT count(*) FROM revoked_refresh),
  (SELECT count(*) FROM revoked_access);
COMMIT;
SELECT 'remaining',
  (SELECT count(*) FROM sessions WHERE id = ANY(:'session_ids'::text[]))
  + (SELECT count(*) FROM oidc_refresh_tokens WHERE id = ANY(:'refresh_ids'::text[]))
  + (SELECT count(*) FROM oidc_access_tokens WHERE token_hash = ANY(:'access_ids'::text[]));
SQL
} | run_psql --set "email=$WALK_EMAIL" >"$DB_RESULT" ||
  die 'revoking the other sessions and CLI sign-ins failed; rerun to rotate'
revoked="$(awk -F'|' '$1 == "revoked" { print $2, $3, $4 }' "$DB_RESULT")"
remaining="$(awk -F'|' '$1 == "remaining" { print $2 }' "$DB_RESULT")"
[[ "$revoked" =~ ^[0-9]+\ [0-9]+\ [0-9]+$ && "$remaining" == 0 ]] ||
  die 'a listed session or CLI sign-in is still present; rerun to rotate'
read -r revoked_sessions revoked_refresh revoked_access <<<"$revoked"
log "revoked sessions=$revoked_sessions cli_refresh_tokens=$revoked_refresh cli_access_tokens=$revoked_access"

# The old password, on a rotation, must now be refused.
old_password_refused=not_applicable
if [[ -s "$OLD_SIGN_IN_BODY" ]]; then
  log 'checking that the old password is refused'
  status="$(sign_in "$OLD_SIGN_IN_BODY" "$OLD_COOKIE_JAR")" ||
    die 'the old-password check could not reach Dev'
  secure_remove "$OLD_SIGN_IN_BODY"
  if [[ "$status" == 200 ]]; then
    sign_out "$OLD_COOKIE_JAR" || true
    die 'Dev still accepts the old password; rerun to rotate'
  fi
  [[ "$status" == 401 ]] || die "the old-password check answered HTTP $status, not 401"
  old_password_refused=true
fi

log "PASS canonical_store=openbao path=$OPENBAO_PATH sign_in_probe=true old_password_refused=$old_password_refused org=$WALK_ORG_SLUG rate_card=regular owner=provisioned-no-sign-in walk_role=member members=2 api_keys=0 walk_org_create=0 quota=2x4000m16384MB credit_eur=5 auto_top_up=off secret_values_printed=false"
