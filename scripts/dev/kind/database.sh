#!/usr/bin/env bash
# The retained Kind cluster's databases are disposable, like every local
# database: a deploy upgrades them, and a reset recreates them.
#
#   KIND_CLUSTER_NAME=<cluster> scripts/dev/kind/database.sh prepare
#   KIND_CLUSTER_NAME=<cluster> make kind-db-reset
#   KIND_CLUSTER_NAME=<cluster> make kind-db-restore BACKUP=<directory>
#
# prepare runs before a deploy restarts a service that migrates at startup
# (deploy-service.sh). It compares each SQLx ledger with this tree's
# migrations. When this tree carries migrations the cluster has not applied,
# it backs the databases up; the restarted service then applies them, as the
# services do everywhere. It refuses only a downgrade: the cluster applied a
# migration this tree lacks, or applied it from other bytes, and the services
# would refuse to start.
#
# reset recreates the databases: it removes the Sandbox workloads of the
# environments it forgets, starts the IdP to rerun every migration, reloads
# the fixtures the Kind gate loads, then starts the other services. restore
# returns the databases to a backup. Both back the current databases up first.
#
# Backups are pg_dump archives in
# ${XDG_CACHE_HOME:-~/.cache}/codewire/kind/<cluster>/database-backups, one
# directory each, named by UTC time; the newest KIND_DB_BACKUP_KEEP (default 5)
# are kept.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/dev/kind/profile.sh
source "$ROOT/scripts/dev/kind/profile.sh"
kind_profile_load "$ROOT" || exit $?
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
NAMESPACE=codewire-e2e
SANDBOX_NAMESPACE=dev-sandboxes
BACKUPS="${XDG_CACHE_HOME:-$HOME/.cache}/codewire/kind/${KIND_CLUSTER_NAME}/database-backups"
KEEP="${KIND_DB_BACKUP_KEEP:-5}"
# Each database and the migrations its services embed.
DATABASES=(codewire:crates/codewire-server-core/migrations codewire_mesh:crates/codewire-mesh/migrations)
# The Deployments that connect to them. The IdP starts first and applies the
# migrations; the others start after the fixtures, as in the Kind gate.
SERVICES=(codewire-idp codewire-billing codewire-mesh codewire-orchestration codewire-coordinator
  codewire-credential-service)
# What the Kind gate loads after the migrations (common.sh, credentials.sh).
FIXTURES=(tests/fixtures/billing/seed.sql tests/e2e/kind/coordinator-seed.sql tests/e2e/kind/credential-broker.sql)
# What a Sandbox leaves in its namespace, labelled with its environment.
SANDBOX_KINDS=(sandboxclaims.extensions.agents.x-k8s.io sandboxes.agents.x-k8s.io pods services
  persistentvolumeclaims secrets configmaps)

log() { printf '[kind-db] %s\n' "$*" >&2; }
die() { printf '[kind-db] error: %s\n' "$*" >&2; exit 1; }
kube() { kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$NAMESPACE" "$@"; }
psql_in() {
  local database="$1"
  shift
  kube exec deploy/postgres -- psql -U codewire -d "$database" -v ON_ERROR_STOP=1 -qtA "$@"
}

[[ "$KEEP" =~ ^[1-9][0-9]*$ ]] || die 'KIND_DB_BACKUP_KEEP must be a positive integer'
if [ "$KIND_PROFILE" = 1 ]; then
  kind_profile_lock "$ROOT" || exit $?
  kind_profile_verify_node "$ROOT" || exit $?
fi

database_exists() {
  local found
  found="$(psql_in postgres -c "SELECT 1 FROM pg_database WHERE datname = '$1'")" \
    || die "cannot read ${KIND_CLUSTER_NAME}'s databases"
  [ "$found" = 1 ]
}

# "version checksum success description" for each migration the database
# applied; nothing for a database or ledger that does not exist yet.
ledger() {
  local database="$1" table
  database_exists "$database" || return 0
  table="$(psql_in "$database" -c "SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")" \
    || die "cannot read ${database}'s migration ledger"
  [ "$table" = t ] || return 0
  psql_in "$database" -F ' ' \
    -c "SELECT version, encode(checksum, 'hex'), success, description FROM _sqlx_migrations ORDER BY version" \
    || die "cannot read ${database}'s migration ledger"
}

# The tree's migrations, as SQLx embeds them: "database:version" maps to the
# SHA-384 of the up migration, which is SQLx's checksum, and to its file name.
declare -A tree_checksum=() tree_file=()
for entry in "${DATABASES[@]}"; do
  for file in "$ROOT/${entry#*:}"/*.sql; do
    [ -f "$file" ] || continue
    name="${file##*/}"
    [[ "$name" != *.down.sql && "$name" =~ ^([0-9]+)_ ]] || continue
    key="${entry%%:*}:$((10#${BASH_REMATCH[1]}))"
    tree_checksum["$key"]="$(sha384sum "$file" | cut -c1-96)"
    tree_file["$key"]="$name"
  done
done

# Back up every database that exists, then keep only the newest KEEP backups.
backup() {
  local reason="$1" directory database rows version checksum count index
  local -a backups=()
  umask 077
  mkdir -p "$BACKUPS"
  directory="$BACKUPS/$(date -u +%Y%m%dT%H%M%SZ)-${reason}"
  [ ! -e "$directory" ] || die "${directory} already exists"
  rm -rf "$directory.partial"
  mkdir "$directory.partial"
  for entry in "${DATABASES[@]}"; do
    database="${entry%%:*}"
    database_exists "$database" || continue
    kube exec deploy/postgres -- pg_dump -U codewire -d "$database" --format=custom \
      >"$directory.partial/${database}.dump" || die "backing up ${database} failed"
    rows="$(ledger "$database")" || exit 1
    while read -r version checksum _; do
      [ -z "$version" ] || printf '%s %s %s\n' "$database" "$version" "$checksum"
    done <<<"$rows" >>"$directory.partial/ledger"
  done
  mv "$directory.partial" "$directory"
  log "backed up ${KIND_CLUSTER_NAME}'s databases to ${directory}"
  mapfile -t backups < <(find "$BACKUPS" -mindepth 1 -maxdepth 1 -type d ! -name '*.partial' -printf '%f\n' | sort)
  count="${#backups[@]}"
  for ((index = 0; index < count - KEEP; index++)); do
    rm -rf "${BACKUPS:?}/${backups[index]}"
  done
}

# The newest backup whose every migration this tree has, byte for byte.
compatible_backup() {
  local directory database version checksum
  while read -r directory; do
    [ -f "$directory/ledger" ] || continue
    while read -r database version checksum; do
      [ "${tree_checksum["${database}:${version}"]:-}" = "$checksum" ] || continue 2
    done <"$directory/ledger"
    printf '%s\n' "$directory"
    return 0
  done < <(find "$BACKUPS" -mindepth 1 -maxdepth 1 -type d ! -name '*.partial' 2>/dev/null | sort -r)
}

cmd_prepare() {
  local database rows version checksum success description key restore
  local -a pending=() problems=()
  local -A applied=()
  for entry in "${DATABASES[@]}"; do
    database="${entry%%:*}"
    database_exists "$database" || continue
    rows="$(ledger "$database")" || exit 1
    while read -r version checksum success description; do
      [ -n "$version" ] || continue
      key="${database}:${version}"
      applied["$key"]=1
      if [ -z "${tree_checksum[$key]:-}" ]; then
        problems+=("${database} has migration ${version} (${description}), which this tree lacks")
      elif [ "${tree_checksum[$key]}" != "$checksum" ]; then
        problems+=("${database} applied migration ${version} (${description}) from other bytes than this tree's ${tree_file[$key]}")
      elif [ "$success" != t ]; then
        problems+=("${database} records migration ${version} (${description}) as failed")
      fi
    done <<<"$rows"
    for key in "${!tree_file[@]}"; do
      if [ "${key%%:*}" = "$database" ] && [ -z "${applied[$key]:-}" ]; then
        pending+=("${database} ${tree_file[$key]}")
      fi
    done
  done
  if [ "${#problems[@]}" -gt 0 ]; then
    log "refusing to deploy: ${KIND_CLUSTER_NAME}'s database is ahead of this tree, whose services would not start on it:"
    for problem in "${problems[@]}"; do
      log "  ${problem}"
    done
    log 'to deploy this tree, recreate the databases at its migrations (their data is disposable):'
    log '  make kind-db-reset'
    restore="$(compatible_backup)"
    if [ -n "$restore" ]; then
      log 'or return to the newest backup this tree can run:'
      log "  make kind-db-restore BACKUP=${restore}"
    fi
    log 'or deploy a tree that has the migration, or apply its .down.sql and delete its _sqlx_migrations row'
    exit 1
  fi
  [ "${#pending[@]}" -gt 0 ] || return 0
  mapfile -t pending < <(printf '%s\n' "${pending[@]}" | sort)
  log "this deploy applies new migrations to ${KIND_CLUSTER_NAME}: ${pending[*]}"
  backup upgrade
}

# Stop every service that connects to the databases; remember their replicas.
declare -A replicas=()
stop_services() {
  local deployment selector pods
  local -a previous=()
  for deployment in "${SERVICES[@]}"; do
    replicas["$deployment"]="$(kube get "deployment/${deployment}" -o 'jsonpath={.spec.replicas}')" \
      || die "cannot read ${deployment}"
    # shellcheck disable=SC2016 # a Go template, expanded by kubectl
    selector="$(kube get "deployment/${deployment}" \
      -o go-template='{{range $k, $v := .spec.selector.matchLabels}}{{$k}}={{$v}},{{end}}')" \
      || die "cannot read ${deployment}'s selector"
    pods="$(kube get pods -l "${selector%,}" -o name)" || die "cannot list ${deployment}'s Pods"
    [ -z "$pods" ] || mapfile -t -O "${#previous[@]}" previous <<<"$pods"
  done
  log "stopping ${SERVICES[*]}"
  kube scale "${SERVICES[@]/#/deployment/}" --replicas=0 >/dev/null || die 'stopping the services failed'
  if [ "${#previous[@]}" -gt 0 ]; then
    kube wait --for=delete "${previous[@]}" --timeout=180s >/dev/null || die 'the services did not stop'
  fi
}

start_services() {
  local deployment
  for deployment in "$@"; do
    [ "${replicas[$deployment]:-0}" -gt 0 ] || continue
    kube scale "deployment/${deployment}" --replicas="${replicas[$deployment]}" >/dev/null \
      || die "starting ${deployment} failed"
  done
  for deployment in "$@"; do
    [ "${replicas[$deployment]:-0}" -gt 0 ] || continue
    kube rollout status "deployment/${deployment}" --timeout=300s >/dev/null \
      || die "${deployment} did not become ready"
  done
}

ledger_head() {
  local rows version checksum success description
  rows="$(ledger "$1")" || exit 1
  [ -n "$rows" ] || { printf 'no migration\n'; return 0; }
  read -r version checksum success description <<<"$(tail -n 1 <<<"$rows")"
  printf '%s (%s)\n' "$version" "$description"
}

cmd_reset() {
  local kind
  if database_exists codewire; then
    backup before-reset
  fi
  stop_services
  # Their environments are forgotten; their Sandboxes would keep running and
  # authenticating to the credential bridge.
  log "removing environment workloads from ${SANDBOX_NAMESPACE}"
  for kind in "${SANDBOX_KINDS[@]}"; do
    kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$SANDBOX_NAMESPACE" get "$kind" \
      -l codewire.sh/environment-id -o name >/dev/null 2>&1 || continue
    kubectl --context "kind-${KIND_CLUSTER_NAME}" -n "$SANDBOX_NAMESPACE" delete "$kind" \
      -l codewire.sh/environment-id --ignore-not-found --wait=true --timeout=180s >/dev/null \
      || die "removing ${kind} from ${SANDBOX_NAMESPACE} failed"
  done
  log 'recreating the databases'
  # The fixture creates the restricted credential login; it owns nothing else.
  psql_in postgres -c 'DROP DATABASE IF EXISTS codewire WITH (FORCE)' \
    -c 'DROP DATABASE IF EXISTS codewire_mesh WITH (FORCE)' \
    -c 'DROP ROLE IF EXISTS codewire_credential_broker' -c 'CREATE DATABASE codewire' >/dev/null \
    || die 'recreating the databases failed'
  # The IdP applies every migration at startup; Mesh recreates its database.
  [ "${replicas[codewire-idp]}" -gt 0 ] || replicas[codewire-idp]=1
  start_services codewire-idp
  log "codewire is at migration $(ledger_head codewire)"
  for fixture in "${FIXTURES[@]}"; do
    kube exec -i deploy/postgres -- psql -U codewire -d codewire -v ON_ERROR_STOP=1 -q \
      <"$ROOT/$fixture" >/dev/null || die "loading ${fixture} failed"
  done
  log "loaded ${FIXTURES[*]}"
  start_services "${SERVICES[@]:1}"
  log "${KIND_CLUSTER_NAME}'s databases are new; make kind-seed-login restores the review login"
}

cmd_restore() {
  local source="${1:-}" database
  [ -n "$source" ] || die 'usage: make kind-db-restore BACKUP=<backup directory>'
  [ -f "$source/codewire.dump" ] || die "${source} holds no codewire.dump"
  backup before-restore
  stop_services
  for entry in "${DATABASES[@]}"; do
    database="${entry%%:*}"
    psql_in postgres -c "DROP DATABASE IF EXISTS ${database} WITH (FORCE)" >/dev/null \
      || die "dropping ${database} failed"
    [ -f "$source/${database}.dump" ] || continue
    psql_in postgres -c "CREATE DATABASE ${database}" >/dev/null || die "creating ${database} failed"
    kube exec -i deploy/postgres -- pg_restore -U codewire -d "$database" --exit-on-error \
      <"$source/${database}.dump" || die "restoring ${database} failed"
  done
  log "codewire is at migration $(ledger_head codewire)"
  [ "${replicas[codewire-idp]}" -gt 0 ] || replicas[codewire-idp]=1
  start_services "${SERVICES[@]}"
  log "${KIND_CLUSTER_NAME}'s databases are back at ${source}; Sandboxes created since keep running without a record"
}

case "${1:-}" in
  prepare) cmd_prepare ;;
  reset) cmd_reset ;;
  restore) cmd_restore "${2:-}" ;;
  *) echo "usage: $0 <prepare|reset|restore BACKUP>" >&2; exit 2 ;;
esac
