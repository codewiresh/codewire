#!/usr/bin/env bash
# Create one scratch Dev account for an account-lifecycle proof: an email
# sign-up with a password and no organization, API key or other authority.
# --unverified makes the account the unverified sign-up purge deletes
# (codewire#4541); --verified makes one an admin deletes from the dashboard.
# Seeding the row stands in for the browser sign-up, whose bot check an agent
# cannot pass; what the proofs test is the purge and the admin delete
# (orchestrator, 2026-11-15, codewire#4541).
# The password is generated, hashed and thrown away: nobody signs in as the
# account. Run only through Infra's scoped kube-access wrapper.
set -euo pipefail

# The mail provider's simulator accepts any email to the account without
# reaching a person or counting as a bounce; codewire-dev.sh takes no mail.
readonly EMAIL_PREFIX="success+cw-scratch-"
readonly EMAIL_DOMAIN="@simulator.amazonses.com"
# The idp's argon2id parameters (crates/codewire-idp/src/auth_session.rs).
readonly ARGON2_ARGS=(-id -t 3 -m 16 -p 2 -l 32 -e)

VERIFIED=""
LABEL=""
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
KUBE_NAMESPACE="${KUBE_NAMESPACE:-dev}"
POSTGRES_POD="${POSTGRES_POD:-}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-codewire}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
TMPDIR_SCRATCH=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/provision-dev-scratch-account.sh (--unverified | --verified) --label LABEL [options]

Creates the Dev account success+cw-scratch-LABEL@simulator.amazonses.com:
enabled, with a credential sign-in whose generated password is discarded, and
no organization memberships, API keys or sessions. It refuses an address that
already exists and prints the new account's id.

Options:
  --unverified              The address is unverified, as a sign-up that never
                            followed its verification link
  --verified                The address is verified
  --label LABEL             1-32 of a-z, 0-9 and -, naming the proof
  --context CONTEXT         kubectl context
  --namespace NAMESPACE     Dev namespace (default: dev)
  --postgres-pod POD        Postgres pod (default: the codewire-db primary)
USAGE
}

log() { printf '[runtime-scratch-account] %s\n' "$*" >&2; }
die() { printf '[runtime-scratch-account] ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  [[ -n "$TMPDIR_SCRATCH" && -d "$TMPDIR_SCRATCH" ]] || return 0
  rm -rf -- "$TMPDIR_SCRATCH"
  TMPDIR_SCRATCH=""
}
trap 'cleanup || true' EXIT
trap 'exit 130' HUP INT TERM

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

while (($# > 0)); do
  case "$1" in
    --unverified) [[ -z "$VERIFIED" ]] || die 'pass one of --unverified and --verified'; VERIFIED=false; shift ;;
    --verified) [[ -z "$VERIFIED" ]] || die 'pass one of --unverified and --verified'; VERIFIED=true; shift ;;
    --label) [[ $# -ge 2 ]] || die '--label requires a value'; LABEL="$2"; shift 2 ;;
    --context) [[ $# -ge 2 ]] || die '--context requires a value'; KUBE_CONTEXT="$2"; shift 2 ;;
    --namespace) [[ $# -ge 2 ]] || die '--namespace requires a value'; KUBE_NAMESPACE="$2"; shift 2 ;;
    --postgres-pod) [[ $# -ge 2 ]] || die '--postgres-pod requires a value'; POSTGRES_POD="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ -n "$VERIFIED" ]] || die 'pass --unverified or --verified'
[[ "$LABEL" =~ ^[a-z0-9-]{1,32}$ ]] || die '--label must be 1-32 of a-z, 0-9 and -'
readonly VERIFIED LABEL
readonly EMAIL="$EMAIL_PREFIX$LABEL$EMAIL_DOMAIN"

case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac
for command in argon2 awk basenc kubectl mktemp; do
  require_cmd "$command"
done
[[ -n "${INFRA_KUBECONFIG_DIR:-}" && -n "${KUBECONFIG:-}" ]] ||
  die 'run through the scoped Infra kube-access wrapper'
[[ "$KUBECONFIG" == "$INFRA_KUBECONFIG_DIR"/* ]] ||
  die 'KUBECONFIG is outside the scoped Infra kube-access directory'

umask 077
TMPDIR_SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/codewire-scratch-account.XXXXXX")"
HASH_FILE="$TMPDIR_SCRATCH/hash"
DB_RESULT="$TMPDIR_SCRATCH/db-result"

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

# The password never touches disk: it goes straight from urandom to argon2.
salt="$(head -c 12 /dev/urandom | basenc --base64url | tr -d '=\n')"
head -c 32 /dev/urandom | basenc --base64url | tr -d '=\n' |
  argon2 "$salt" "${ARGON2_ARGS[@]}" >"$HASH_FILE" || die 'argon2 hashing failed'
awk 'NR == 1 && /^\$argon2id\$v=19\$m=65536,t=3,p=2\$[A-Za-z0-9+\/]+\$[A-Za-z0-9+\/]+$/ { ok=1; next }
  { ok=0; exit } END { exit ok == 1 ? 0 : 1 }' "$HASH_FILE" ||
  die 'argon2 did not return one well-formed PHC hash'

# One transaction: a new account with exactly one credential sign-in. An
# address that already exists writes nothing, so a rerun never changes an
# account a proof is using.
log "creating $EMAIL (email_verified=$VERIFIED)"
{
  printf '\\set hash %s\n' "'$(awk 'NR == 1' "$HASH_FILE")'"
  cat <<'SQL'
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
BEGIN;
WITH account AS (
  INSERT INTO users (id, email, email_verified, name, enabled, created_at, updated_at)
  VALUES (encode(public.gen_random_bytes(16), 'hex'), :'email', :'verified'::boolean, :'name', true, NOW(), NOW())
  ON CONFLICT (email) DO NOTHING
  RETURNING id, email
), credential AS (
  INSERT INTO accounts (id, user_id, provider_id, account_id, password, created_at, updated_at)
  SELECT encode(public.gen_random_bytes(16), 'hex'), id, 'credential', email, :'hash', NOW(), NOW()
  FROM account
  RETURNING user_id
)
SELECT user_id FROM credential;
COMMIT;
SQL
} | "${KUBECTL[@]}" -n "$KUBE_NAMESPACE" exec -i "$POSTGRES_POD" \
  -c "$POSTGRES_CONTAINER" -- psql -X -qAt -v ON_ERROR_STOP=1 \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  --set "email=$EMAIL" --set "name=Scratch $LABEL" --set "verified=$VERIFIED" >"$DB_RESULT" ||
  die 'the database write failed'
user_id="$(awk 'NF' "$DB_RESULT")"
[[ -n "$user_id" ]] || die "$EMAIL already exists; nothing was written"
[[ "$user_id" =~ ^[0-9a-f]{32}$ ]] || die 'the database did not return one account id'

log "PASS user_id=$user_id email=$EMAIL email_verified=$VERIFIED memberships=0 api_keys=0 password_kept=false"
printf '%s\n' "$user_id"
