#!/usr/bin/env bash
# Product CLI orchestration shared with the existing commodity smoke.

docker_store_run_guest() {
  local action="$1" id="$2"
  local script
  script="$(cat "$ROOT/scripts/runtime/dev/docker-store-guest.sh")
set -eu
docker_store_guest $(shell_quote "$action") $(shell_quote "$id") containerd"
  run_cw_session_script "$script"
}

run_docker_store_core() {
  local id="${ENV_ID//-/}"
  docker_store_run_guest core "${id:0:20}"
}

docker_store_wait_stopped() {
  cw_with_timeout "$SMOKE_TIMEOUT_SECONDS" --cloud stop "$ENV_ID"
  wait_until 'Docker journey environment stopped' "$(($(seconds_now) + SMOKE_TIMEOUT_SECONDS))" env_is_stopped
}

docker_store_start() {
  cw_with_timeout "$SMOKE_TIMEOUT_SECONDS" --cloud start "$ENV_ID"
  wait_environment
  wait_for_cw_run
}

docker_store_requested() {
  local phase
  for phase in "${SMOKE_ONLY_PHASES[@]}"; do [[ "$phase" != docker-store ]] || return 0; done
  return 1
}

# Lists contain capturing and deleting snapshots too. Never resolve an ID from
# a name without checking the entire exact-name match set and source identity.
docker_store_snapshot_observe() {
  local rows="$TMPDIR_SMOKE/docker-store-snapshots.json" match row
  cw_with_timeout 30 --cloud snapshot ls --output json >"$rows" 2>/dev/null || return 2
  jq -es 'length == 1 and (.[0] | type == "array")' "$rows" >/dev/null || return 2
  match="$(jq -c --arg name "$DOCKER_STORE_SNAPSHOT_NAME" --arg id "$DOCKER_STORE_SNAPSHOT_ID" '
    [.[] | select(.name == $name or ($id != "" and .id == $id))]
  ' "$rows")" || return 2
  [[ "$match" != '[]' ]] || return 1
  row="$(jq -er --arg name "$DOCKER_STORE_SNAPSHOT_NAME" --arg source "$DOCKER_STORE_SOURCE_ID" --arg id "$DOCKER_STORE_SNAPSHOT_ID" '
    select(length == 1) | .[0]
    | select(.name == $name and .source_environment_id == $source and .location == "platform")
    | select((.id | type == "string" and test("^[A-Za-z0-9-]+$")) and ($id == "" or .id == $id))
    | select(.state == "capturing" or .state == "ready" or .state == "failed" or .state == "deleting")
    | [.id, .state] | @tsv
  ' <<<"$match")" || return 2
  IFS=$'\t' read -r DOCKER_STORE_SNAPSHOT_ID DOCKER_STORE_SNAPSHOT_STATE <<<"$row"
}

docker_store_fork_receipt_id() {
  jq -er --arg name "$DOCKER_STORE_FORK_NAME" --arg org "$DOCKER_STORE_FORK_ORG" \
    --arg creator "$DOCKER_STORE_FORK_CREATOR" --arg source "$DOCKER_STORE_SOURCE_ID" '
    select(.name == $name and .org_id == $org and .created_by == $creator)
    | .id | select(type == "string" and test("^[A-Za-z0-9-]+$") and . != $source)
  ' "$1" 2>/dev/null
}

# Inventory supplies identity/name/placement; full info supplies org/creator.
# This can establish cleanup ownership, never the fork's snapshot lineage.
docker_store_fork_observe() {
  local rows="$TMPDIR_SMOKE/docker-store-environments.json" id
  cw_with_timeout 30 --cloud ls --all --output json >"$rows" 2>/dev/null || return 2
  jq -es 'length == 1 and (.[0] | type == "array")' "$rows" >/dev/null || return 2
  jq -e --arg name "$DOCKER_STORE_FORK_NAME" '[.[] | select(.name == $name)] | length == 0' "$rows" >/dev/null && return 1
  id="$(jq -er --arg name "$DOCKER_STORE_FORK_NAME" --arg source "$DOCKER_STORE_SOURCE_ID" '
    [.[] | select(.name == $name)] | select(length == 1) | .[0]
    | select(.placement == "platform") | .id
    | select(type == "string" and test("^[A-Za-z0-9-]+$") and . != $source)
  ' "$rows")" || return 2
  cw_with_timeout 30 --cloud info "$id" --output json >"$TMPDIR_SMOKE/docker-store-fork-info.json" 2>/dev/null || return 2
  [[ "$(docker_store_fork_receipt_id "$TMPDIR_SMOKE/docker-store-fork-info.json")" == "$id" ]] || return 2
  DOCKER_STORE_FORK_ID="$id"
}

run_docker_store_journey() {
  local source="$ENV_ID" fork snapshot rc id="${ENV_ID//-/}"
  id="${id:0:20}"
  # This journey stops the supplied workspace and forks its complete disk.
  # Require the existing disposable-environment path, never a reused workspace.
  [[ -z "$SMOKE_EXISTING_ENV_ID" && "$SMOKE_KEEP_ENV" == 0 ]] ||
    die 'docker-store lifecycle journey requires a fresh disposable environment; --existing-env and --keep are unsupported'
  DOCKER_STORE_SOURCE_ID="$source"
  docker_store_run_guest seed "$id"
  docker_store_wait_stopped
  docker_store_start
  docker_store_run_guest verify "$id"
  log 'Docker image, writable layer and named volume survived environment stop/start'
  docker_store_wait_stopped
  DOCKER_STORE_SNAPSHOT_NAME="docker-store-$id"
  # Refuse a pre-existing name before any capture request. A failed create may
  # already have made remote state, so remember the name before invoking it.
  rc=0
  docker_store_snapshot_observe || rc=$?
  [[ "$rc" == 1 ]] || die 'snapshot name is not absent or inventory is unavailable; no capture requested'
  DOCKER_STORE_SNAPSHOT_ATTEMPTED=1
  cw_with_timeout "$((SMOKE_TIMEOUT_SECONDS + 1200))" --cloud snapshot create "$source" \
    --name "$DOCKER_STORE_SNAPSHOT_NAME" --output json >"$TMPDIR_SMOKE/docker-store-snapshot.json" || {
      rc=$?; log 'snapshot create did not complete; cleanup will reconcile its exact name and source'; return "$rc";
    }
  snapshot="$(jq -er --arg source "$source" --arg name "$DOCKER_STORE_SNAPSHOT_NAME" '
    select(.name == $name and .source_environment_id == $source and .state == "ready" and .location == "platform")
    | .id | select(type == "string" and test("^[A-Za-z0-9-]+$"))
  ' "$TMPDIR_SMOKE/docker-store-snapshot.json")" || die 'snapshot receipt is not ready or does not belong to the source environment'
  DOCKER_STORE_SNAPSHOT_ID="$snapshot"
  cw_with_timeout 30 --cloud info "$source" --output json >"$TMPDIR_SMOKE/docker-store-source-info.json"
  DOCKER_STORE_FORK_ORG="$(jq -er --arg id "$source" 'select(.id == $id) | .org_id | select(type == "string" and length > 0)' "$TMPDIR_SMOKE/docker-store-source-info.json")"
  DOCKER_STORE_FORK_CREATOR="$(jq -er --arg id "$source" 'select(.id == $id) | .created_by | select(type == "string" and length > 0)' "$TMPDIR_SMOKE/docker-store-source-info.json")"
  DOCKER_STORE_FORK_NAME="docker-store-fork-$id"
  rc=0
  docker_store_fork_observe || rc=$?
  [[ "$rc" == 1 ]] || die 'fork name is not absent or inventory is unavailable; no environment requested'
  DOCKER_STORE_FORK_ATTEMPTED=1
  cw_with_timeout "$SMOKE_TIMEOUT_SECONDS" --cloud create --snapshot "$snapshot" \
    --name "$DOCKER_STORE_FORK_NAME" --no-file --no-profile --no-network --ttl "$SMOKE_TTL" --yes --output json \
    >"$TMPDIR_SMOKE/docker-store-fork.json" || {
      rc=$?; log 'fork create did not complete; cleanup will reconcile its exact name and owner'; return "$rc";
    }
  fork="$(docker_store_fork_receipt_id "$TMPDIR_SMOKE/docker-store-fork.json")" || die 'fork receipt does not identify the expected new environment and owner'
  DOCKER_STORE_FORK_ID="$fork"
  ENV_ID="$fork"
  wait_environment
  wait_for_cw_run
  docker_store_run_guest verify "$id"
  docker_store_run_guest fork-write "$id"
  ENV_ID="$source"
  docker_store_start
  docker_store_run_guest verify "$id"
  log 'Docker snapshot fork retained image/layer/volume and its writes stayed separate from source'
  docker_store_run_guest cleanup "$id"
  cleanup_docker_store_journey
}

# Reuse the existing exact-ID report route: info absence is not destruction.
docker_store_remove_environment() {
  local ENV_ID="$1" deadline rc=0
  application_environment_destroyed || rc=$?
  [[ "$rc" != 0 ]] || return 0
  jq -e --arg id "$ENV_ID" '.environment.id == $id and (.environment.state | type == "string")' \
    "$TMPDIR_SMOKE/app-cleanup-environment.json" >/dev/null 2>&1 || {
      log "Docker cleanup cannot verify environment $ENV_ID; preserved"; return 1;
    }
  cw_with_timeout "$SMOKE_TIMEOUT_SECONDS" --cloud rm --yes "$ENV_ID" >/dev/null 2>&1 || \
    log "Docker removal request failed for $ENV_ID; checking its terminal state"
  deadline=$(( $(seconds_now) + SMOKE_TIMEOUT_SECONDS ))
  while (( $(seconds_now) < deadline )); do
    if application_environment_destroyed; then return 0; fi
    sleep 2
  done
  log "Docker cleanup incomplete: environment $ENV_ID is not confirmed destroyed"
  return 1
}

cleanup_docker_store_snapshot() {
  [[ "$DOCKER_STORE_SNAPSHOT_ATTEMPTED" == 1 ]] || return 0
  local deadline rc requested=0
  deadline=$(( $(seconds_now) + SMOKE_TIMEOUT_SECONDS ))
  while (( $(seconds_now) < deadline )); do
    rc=0
    docker_store_snapshot_observe || rc=$?
    if [[ "$rc" == 1 && -n "$DOCKER_STORE_SNAPSHOT_ID" ]]; then
      DOCKER_STORE_SNAPSHOT_ID=''; DOCKER_STORE_SNAPSHOT_NAME=''; DOCKER_STORE_SNAPSHOT_ATTEMPTED=0
      return 0
    elif [[ "$rc" == 2 ]]; then
      log "Docker cleanup cannot uniquely verify snapshot $DOCKER_STORE_SNAPSHOT_NAME; preserved"
      return 1
    elif [[ "$rc" == 0 && "$DOCKER_STORE_SNAPSHOT_STATE" != capturing && "$DOCKER_STORE_SNAPSHOT_STATE" != deleting && "$requested" == 0 ]]; then
      cw_with_timeout "$SMOKE_TIMEOUT_SECONDS" --cloud snapshot rm "$DOCKER_STORE_SNAPSHOT_ID" >/dev/null 2>&1 || {
        log "Docker cleanup could not request snapshot removal: $DOCKER_STORE_SNAPSHOT_ID"; return 1;
      }
      requested=1
    fi
    sleep 2
  done
  log "Docker cleanup incomplete: snapshot $DOCKER_STORE_SNAPSHOT_NAME is not confirmed absent"
  return 1
}

cleanup_docker_store_fork() {
  [[ "$DOCKER_STORE_FORK_ATTEMPTED" == 1 ]] || return 0
  local deadline rc
  deadline=$(( $(seconds_now) + SMOKE_TIMEOUT_SECONDS ))
  while [[ -z "$DOCKER_STORE_FORK_ID" ]] && (( $(seconds_now) < deadline )); do
    rc=0
    docker_store_fork_observe || rc=$?
    if [[ "$rc" == 2 ]]; then
      log "Docker cleanup cannot uniquely verify fork $DOCKER_STORE_FORK_NAME and owner; preserved"
      return 1
    fi
    [[ "$rc" != 0 ]] || break
    sleep 2
  done
  if [[ -z "$DOCKER_STORE_FORK_ID" ]]; then
    log "Docker cleanup incomplete: fork $DOCKER_STORE_FORK_NAME could not be resolved"
    return 1
  fi
  docker_store_remove_environment "$DOCKER_STORE_FORK_ID" || return 1
  DOCKER_STORE_FORK_ID=''; DOCKER_STORE_FORK_NAME=''; DOCKER_STORE_FORK_ATTEMPTED=0
}

cleanup_docker_store_journey() {
  local rc=0
  [[ -z "$DOCKER_STORE_SOURCE_ID" ]] || ENV_ID="$DOCKER_STORE_SOURCE_ID"
  cleanup_docker_store_fork || rc=1
  cleanup_docker_store_snapshot || rc=1
  return "$rc"
}

cleanup_docker_store_source() {
  if [[ -z "$DOCKER_STORE_SOURCE_ID" ]]; then
    [[ "$DOCKER_STORE_SOURCE_ATTEMPTED" == 0 ]] || {
      log "Docker cleanup incomplete: source $DOCKER_STORE_SOURCE_NAME has no verified ID (TTL $SMOKE_TTL); preserved"
      return 1
    }
    return 0
  fi
  if docker_store_remove_environment "$DOCKER_STORE_SOURCE_ID"; then
    DOCKER_STORE_SOURCE_ID=''; DOCKER_STORE_SOURCE_ATTEMPTED=0
  else
    return 1
  fi
}
