#!/usr/bin/env bash
# Checked-in adapter for the saved named Kind profile. Profile data is never
# sourced or evaluated; the owner-validating helper emits fixed NUL fields.

kind_profile_error() {
  printf '[kind-profile] error: %s\n' "$*" >&2
}

kind_profile_load() {
  local root="$1" key value status count index
  local -a fields=()
  local -A seen=() values=()
  KIND_PROFILE=0
  [ -n "${CLUSTER:-}" ] || return 0
  if [ -n "${KIND_CLUSTER_NAME:-}" ] && [ "$KIND_CLUSTER_NAME" != "$CLUSTER" ]; then
    kind_profile_error 'CLUSTER and KIND_CLUSTER_NAME select different clusters'
    return 1
  fi
  # Keep the helper's exit status in the same pipe: process substitution alone
  # would turn a failed validation into a successful empty read.
  mapfile -d '' -t fields < <(
    status=0
    python3 "$root/scripts/dev/kind/cluster-profile.py" env \
      --cluster "$CLUSTER" --format nul || status=$?
    printf '_kind_profile_exit_status\0%s\0' "$status"
  ) || return $?
  count="${#fields[@]}"
  if [ "$count" -lt 2 ] || [ "$((count % 2))" -ne 0 ] \
      || [ "${fields[count-2]}" != _kind_profile_exit_status ]; then
    kind_profile_error 'invalid profile field stream'
    return 1
  fi
  status="${fields[count-1]}"
  if [[ ! "$status" =~ ^[0-9]+$ ]] || [ "$status" -gt 255 ]; then
    kind_profile_error 'invalid profile helper status'
    return 1
  fi
  [ "$status" -eq 0 ] || return "$status"
  for ((index=0; index<count-2; index+=2)); do
    key="${fields[index]}"
    value="${fields[index+1]}"
    case "$key" in
      KIND_PROFILE|KIND_PROFILE_PATH|KIND_PROFILE_NONCE|KIND_PROFILE_DOCKER_ID|\
      KIND_PROFILE_LOCK_FILE|KIND_BUILD_PUBLICATION_LOCK_FILE|KIND_PROFILE_STATE|\
      KIND_CLUSTER_NAME|KUBE_CONTEXT|KUBECONFIG|KIND_CONFIG|RUN_DIR|\
      KIND_PROFILE_ARTIFACT_ROOT|KIND_PROFILE_ARTIFACT_DIR|\
      KIND_PROFILE_SMOKE_DIR|KIND_PROFILE_IMAGE_MANIFEST|\
      KIND_PROFILE_SOURCE_HEAD|KIND_PROFILE_SOURCE_TREE|KIND_PROFILE_IMAGE_PREFIX|\
      KIND_PROFILE_DASHBOARD_IMAGE_ID|KIND_PROFILE_SERVICES_IMAGE_ID|\
      KIND_PROFILE_MESH_IMAGE_ID|KIND_PROFILE_DAEMON_IMAGE_ID|\
      KIND_INGRESS_HOST_PORT|KIND_COORDINATOR_DIRECT_HOST_PORT|\
      KIND_INGRESS_HTTP_HOST_PORT|KIND_INGRESS_TLS_HOST_PORT|\
      KIND_ORCHESTRATION_HOST_PORT|KIND_COORDINATOR_HOST_PORT|\
      KIND_TEMPORAL_HOST_PORT|KIND_POSTGRES_HOST_PORT|KIND_WATCH_HOST_PORT|\
      KIND_INGRESS_URL|KIND_INGRESS_TLS_URL|KIND_ORCHESTRATION_URL|\
      KIND_COORDINATOR_DIRECT_URL|KIND_TEMPORAL_ADDRESS|KIND_DATABASE_URL|\
      KIND_ORCHESTRATION_HTTP_URL|KIND_TEMPORAL_FRONTEND_URL|\
      KIND_WATCH_ADDR|KIND_PUBLIC_ORIGIN|KIND_BROWSER_API_ORIGIN) ;;
      *)
        kind_profile_error "unexpected profile field: $key"
        return 1
        ;;
    esac
    if [ -n "${seen[$key]:-}" ]; then
      kind_profile_error "duplicate profile field: $key"
      return 1
    fi
    seen[$key]=1
    values[$key]="$value"
    # Check every inherited selector/endpoint before assigning any field. Empty
    # artifact fields become populated when the coordinator seals the build.
    case "$key" in
      KIND_CLUSTER_NAME|KUBE_CONTEXT|KUBECONFIG|KIND_CONFIG|RUN_DIR|\
      KIND_INGRESS_HOST_PORT|KIND_COORDINATOR_DIRECT_HOST_PORT|\
      KIND_INGRESS_HTTP_HOST_PORT|KIND_INGRESS_TLS_HOST_PORT|\
      KIND_ORCHESTRATION_HOST_PORT|KIND_COORDINATOR_HOST_PORT|\
      KIND_TEMPORAL_HOST_PORT|KIND_POSTGRES_HOST_PORT|KIND_WATCH_HOST_PORT|\
      KIND_INGRESS_URL|KIND_INGRESS_TLS_URL|KIND_ORCHESTRATION_URL|\
      KIND_COORDINATOR_DIRECT_URL|KIND_TEMPORAL_ADDRESS|KIND_DATABASE_URL|\
      KIND_ORCHESTRATION_HTTP_URL|KIND_TEMPORAL_FRONTEND_URL|\
      KIND_WATCH_ADDR|KIND_PUBLIC_ORIGIN|KIND_BROWSER_API_ORIGIN)
        if [ -n "${!key:-}" ] && [ "${!key}" != "$value" ]; then
          kind_profile_error "$key conflicts with saved cluster profile $CLUSTER"
          return 1
        fi
        ;;
    esac
  done
  for key in KIND_PROFILE KIND_CLUSTER_NAME KUBE_CONTEXT KUBECONFIG \
      KIND_PROFILE_NONCE KIND_PROFILE_LOCK_FILE KIND_PROFILE_ARTIFACT_DIR \
      KIND_PROFILE_SMOKE_DIR KIND_INGRESS_URL KIND_DATABASE_URL \
      KIND_INGRESS_HOST_PORT KIND_INGRESS_HTTP_HOST_PORT \
      KIND_COORDINATOR_DIRECT_HOST_PORT KIND_COORDINATOR_HOST_PORT \
      KIND_ORCHESTRATION_HTTP_URL KIND_ORCHESTRATION_URL \
      KIND_TEMPORAL_FRONTEND_URL KIND_TEMPORAL_ADDRESS \
      KIND_WATCH_ADDR KIND_PUBLIC_ORIGIN KIND_BROWSER_API_ORIGIN; do
    if [ -z "${seen[$key]:-}" ]; then
      kind_profile_error "missing profile field: $key"
      return 1
    fi
  done
  if [ "${values[KIND_PROFILE]}" != 1 ] \
      || [ "${values[KIND_CLUSTER_NAME]}" != "$CLUSTER" ] \
      || [ "${values[KUBE_CONTEXT]}" != "kind-$CLUSTER" ]; then
    kind_profile_error 'profile selector binding is invalid'
    return 1
  fi
  if [ "${values[KIND_INGRESS_HOST_PORT]}" != "${values[KIND_INGRESS_HTTP_HOST_PORT]}" ] \
      || [ "${values[KIND_COORDINATOR_DIRECT_HOST_PORT]}" != "${values[KIND_COORDINATOR_HOST_PORT]}" ] \
      || [ "${values[KIND_ORCHESTRATION_HTTP_URL]}" != "${values[KIND_ORCHESTRATION_URL]}" ] \
      || [ "${values[KIND_TEMPORAL_FRONTEND_URL]}" != "${values[KIND_TEMPORAL_ADDRESS]}" ]; then
    kind_profile_error 'profile endpoint aliases conflict'
    return 1
  fi
  for ((index=0; index<count-2; index+=2)); do
    printf -v "${fields[index]}" '%s' "${fields[index+1]}"
    export "${fields[index]}"
  done
  export CLUSTER
  return 0
}

kind_profile_verify_node() {
  [ "${KIND_PROFILE:-0}" = 1 ] || return 0
  python3 "$1/scripts/dev/kind/cluster-profile.py" verify-node --cluster "$CLUSTER" >/dev/null
}

kind_profile_verify_artifacts() {
  [ "${KIND_PROFILE:-0}" = 1 ] || return 0
  python3 "$1/scripts/dev/kind/cluster-profile.py" verify-artifacts --cluster "$CLUSTER" >/dev/null
}

kind_profile_lock() {
  local root="$1" inherited="${KIND_PROFILE_LOCK_FD:-}" timeout
  [ "${KIND_PROFILE:-0}" = 1 ] || return 0
  timeout="${KIND_PROFILE_LOCK_TIMEOUT_SECONDS:-1200}"
  if [[ ! "$timeout" =~ ^[1-9][0-9]*$ ]]; then
    kind_profile_error 'KIND_PROFILE_LOCK_TIMEOUT_SECONDS must be a positive integer'
    return 1
  fi
  if [ ! -f "$KIND_PROFILE_LOCK_FILE" ] || [ -L "$KIND_PROFILE_LOCK_FILE" ]; then
    kind_profile_error 'profile operation lock is missing or not a regular file'
    return 1
  fi
  if [ "$(stat -c '%u:%a:%h' "$KIND_PROFILE_LOCK_FILE")" != "$(id -u):600:1" ]; then
    kind_profile_error 'profile operation lock is not owner-private'
    return 1
  fi
  # A retained suite inherits this open description from test-selected. Opening
  # a second description would deadlock against the parent's own flock.
  if [[ "$inherited" =~ ^[0-9]+$ ]] \
      && [ "$(readlink "/proc/$$/fd/$inherited" 2>/dev/null)" = "$KIND_PROFILE_LOCK_FILE" ] \
      && [ "$(stat -Lc '%d:%i:%u' "/proc/$$/fd/$inherited" 2>/dev/null)" \
        = "$(stat -c '%d:%i:%u' "$KIND_PROFILE_LOCK_FILE")" ]; then
    flock -w "$timeout" "$inherited" || return $?
  else
    exec {KIND_PROFILE_LOCK_FD}<>"$KIND_PROFILE_LOCK_FILE" || return $?
    if ! flock -w "$timeout" "$KIND_PROFILE_LOCK_FD"; then
      kind_profile_unlock
      kind_profile_error "timed out waiting for cluster $CLUSTER"
      return 1
    fi
  fi
  export KIND_PROFILE_LOCK_FD
  kind_profile_load "$root"
}

kind_profile_unlock() {
  [ -n "${KIND_PROFILE_LOCK_FD:-}" ] || return 0
  exec {KIND_PROFILE_LOCK_FD}>&-
  unset KIND_PROFILE_LOCK_FD
}

kind_profile_private_dir() {
  local directory="$1" profile_root current component relative
  local -a components=()
  [ "${KIND_PROFILE:-0}" = 1 ] || return 0
  profile_root="$(dirname "$KIND_PROFILE_PATH")" || return $?
  case "$directory" in
    "$profile_root"/*) relative="${directory#"$profile_root"/}" ;;
    *) kind_profile_error 'mutable dev state must remain inside its profile'; return 1 ;;
  esac
  IFS=/ read -r -a components <<<"$relative"
  current="$profile_root"
  for component in "${components[@]}"; do
    case "$component" in
      ''|.|..) kind_profile_error 'invalid mutable dev state path'; return 1 ;;
    esac
    current="$current/$component"
    if [ -L "$current" ]; then
      kind_profile_error 'mutable dev state must not follow a symlink'
      return 1
    fi
    if [ ! -e "$current" ]; then
      mkdir -m 700 "$current" || return $?
    fi
    if [ ! -d "$current" ] \
        || [ "$(stat -c '%u:%a' "$current")" != "$(id -u):700" ]; then
      kind_profile_error 'mutable dev state directory is not owner-private'
      return 1
    fi
  done
}

kind_profile_image_base() {
  local key
  case "$1" in
    codewire-dashboard) key=KIND_PROFILE_DASHBOARD_IMAGE_ID ;;
    codewire-services) key=KIND_PROFILE_SERVICES_IMAGE_ID ;;
    codewire-mesh) key=KIND_PROFILE_MESH_IMAGE_ID ;;
    codewire-daemon) key=KIND_PROFILE_DAEMON_IMAGE_ID ;;
    *) kind_profile_error 'unknown product image family'; return 1 ;;
  esac
  if [[ ! "${!key:-}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    kind_profile_error 'cluster has no sealed product base; run make kind-up first'
    return 1
  fi
  printf '%s\n' "${!key}"
}
