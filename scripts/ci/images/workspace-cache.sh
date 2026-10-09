#!/usr/bin/env bash
# Sourced by non-publishing workspace verification and the bounded R2 canary.
# This is the owner's explicitly accepted provider-key projection, not a broker.
readonly WORKSPACE_BUILDKIT_IMAGE='docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
readonly WORKSPACE_CACHE_BUCKET='example-ci-cache-untrusted'
readonly WORKSPACE_CACHE_ENDPOINT='https://00000000000000000000000000000000.r2.cloudflarestorage.com'
readonly WORKSPACE_CACHE_PREFIX='untrusted/codewire/buildkit/v1/'
readonly WORKSPACE_DAEMON_CREDENTIALS='/run/codewire-cache/aws-credentials'

workspace_cache_validate() {
  local mode source_root
  docker_bin="${CODEWIRE_DOCKER_BIN:-docker}"
  sccache_mode="${CODEWIRE_SCCACHE_MODE:-local}"
  layer_cache_mode="${CODEWIRE_BUILDKIT_CACHE_MODE:-local}"
  workspace_measurement_case="${CODEWIRE_WORKSPACE_CACHE_CASE:-}"
  case "$workspace_measurement_case:$sccache_mode:$layer_cache_mode" in
    :*|seed:r2:r2|cold:disabled:disabled|compiler:r2:disabled|warm-1:r2:r2|warm-2:r2:r2) ;;
    *) echo 'workspace measurement cache modes differ from its case' >&2; return 2 ;;
  esac
  for mode in "$sccache_mode" "$layer_cache_mode"; do
    case "$mode" in
      disabled|local|r2) ;;
      *) echo 'workspace cache mode must be disabled, local, or r2' >&2; return 2 ;;
    esac
  done
  credentials_file=''
  if [[ "$sccache_mode" == r2 || "$layer_cache_mode" == r2 ]]; then
    credentials_file="${CODEWIRE_SCCACHE_CREDENTIALS_FILE:-}"
    [[ "$credentials_file" == /* && "$credentials_file" != *','* && "$credentials_file" != *$'\n'* \
        && -f "$credentials_file" && ! -L "$credentials_file" && -r "$credentials_file" && -s "$credentials_file" \
        && "$(realpath -- "$credentials_file")" == "$credentials_file" ]] || {
      echo 'workspace cache requires a private canonical credential file' >&2; return 2;
    }
    case "$(stat -c %a -- "$credentials_file")" in
      400|600) ;;
      *) echo 'workspace cache credential must have mode 0400 or 0600' >&2; return 2 ;;
    esac
    # .dockerignore is editable input, so even .tmp is not a credential boundary.
    source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
    case "$credentials_file" in
      "$source_root"/*) echo 'workspace cache credential must remain outside the build context' >&2; return 2 ;;
    esac
    [[ "${SCCACHE_BUCKET:-}" == "$WORKSPACE_CACHE_BUCKET" \
        && "${SCCACHE_ENDPOINT:-}" == "$WORKSPACE_CACHE_ENDPOINT" \
        && "${CODEWIRE_SCCACHE_PREFIX:-}" == untrusted/codewire/v1 ]] || {
      echo 'workspace cache requires the reviewed untrusted R2 configuration' >&2; return 2;
    }
  fi
  builder='' builder_container='' builder_created=false daemon_credentials=false
  workspace_command_pid=''
  workspace_cache_fallback=false
}

workspace_cache_command() {
  workspace_cache_timed_command 3300s "$@"
}

workspace_cache_timed_command() {
  local duration="$1"
  shift
  local status=0
  # Waiting on a supervised background child lets Bash run its signal trap
  # immediately. The timeout owns the child's process group, including tee or
  # a Docker client blocked in a remote request. No caller process is signalled.
  timeout --signal=TERM --kill-after=5s "$duration" "$@" <&0 &
  workspace_command_pid=$!
  wait "$workspace_command_pid" || status=$?
  workspace_command_pid=''
  return "$status"
}

workspace_cache_create_builder() {
  local scratch_dir="$1" node
  # Use a random private directory basename, never a caller-selected builder.
  builder="codewire-workspace-${scratch_dir##*/}"
  # Buildx canonicalizes names; Docker container lookup is case-sensitive.
  builder="${builder,,}"
  [[ "$builder" =~ ^[[:alnum:]][[:alnum:]_.-]*$ ]] || return 2
  node="${builder}-node"
  local -a driver_args=(--driver-opt "image=$WORKSPACE_BUILDKIT_IMAGE")
  if [[ "$layer_cache_mode" == r2 ]]; then
    driver_args+=(
      --driver-opt "env.AWS_SHARED_CREDENTIALS_FILE=$WORKSPACE_DAEMON_CREDENTIALS"
      --driver-opt env.AWS_PROFILE=default --driver-opt env.AWS_EC2_METADATA_DISABLED=true
      --driver-opt env.AWS_MAX_ATTEMPTS=2 --driver-opt env.AWS_RETRY_MODE=standard
    )
  fi
  printf '%s\n' '[worker.oci]' '  max-parallelism = 2' >"$scratch_dir/buildkitd.toml"
  # The random private-directory name reserves this job's cleanup scope even
  # when create is interrupted after writing only part of its local state.
  builder_created=true
  workspace_cache_command "$docker_bin" buildx create --name "$builder" --node "$node" --driver docker-container \
    "${driver_args[@]}" --buildkitd-config "$scratch_dir/buildkitd.toml" >/dev/null || return
  workspace_cache_command "$docker_bin" buildx inspect "$builder" --bootstrap >/dev/null || return
  # Capture the owned daemon identity in every mode, including the cold case.
  workspace_cache_command "$docker_bin" container inspect "buildx_buildkit_$node" --format '{{.Id}}' \
      >"$scratch_dir/container-id" || return
  builder_container="$(<"$scratch_dir/container-id")"
  [[ "$builder_container" =~ ^[0-9a-f]{64}$ ]] || return 2
  workspace_cache_command "$docker_bin" container inspect "$builder_container" --format '{{.Config.Image}}' \
    >"$scratch_dir/container-image" || return
  [[ "$(<"$scratch_dir/container-image")" == "$WORKSPACE_BUILDKIT_IMAGE" ]] || {
    echo 'workspace cache builder image does not match its pin' >&2; return 2;
  }
  if [[ "$layer_cache_mode" == r2 ]]; then
    # Remote DinD has a different filesystem. Stream into this exact owned
    # container; client-side bind mounts and Buildx config files are unsafe here.
    daemon_credentials=true # Partial writes must also be cleaned on failure.
    workspace_cache_command "$docker_bin" exec --interactive "$builder_container" sh -c \
      'umask 077; mkdir -p /run/codewire-cache && cat > /run/codewire-cache/aws-credentials' \
      <"$credentials_file" || return
  fi
}

workspace_cache_cleanup_builder() {
  local status=0 phase_status=0 started
  if [[ -n "$workspace_command_pid" ]]; then
    kill -TERM "$workspace_command_pid" 2>/dev/null || true
    wait "$workspace_command_pid" 2>/dev/null || true
    workspace_command_pid=''
  fi
  if [[ "$daemon_credentials" == true ]]; then
    started=$SECONDS
    timeout --signal=TERM --kill-after=3s 10s \
      "$docker_bin" exec "$builder_container" rm -f "$WORKSPACE_DAEMON_CREDENTIALS" >/dev/null 2>&1 || phase_status=$?
    if [[ "$phase_status" != 0 ]]; then
      printf 'workspace cache cleanup: phase=credential-erasure status=%s elapsed_seconds=%s\n' \
        "$phase_status" "$((SECONDS - started))" >&2
      status=$phase_status
    fi
  fi
  if [[ "$builder_created" == true ]]; then
    # A stopped daemon can leave substantial state to remove. Keep erasure
    # prompt while allowing bounded filesystem cleanup within the runner reserve.
    local removal_output=''
    started=$SECONDS phase_status=0
    removal_output="$(timeout --signal=TERM --kill-after=3s 60s \
      "$docker_bin" buildx rm --force "$builder" 2>&1)" || phase_status=$?
    # The guarantee is that the owned daemon container is gone. A removal that
    # reports failure after that container no longer exists, such as a retry
    # or a racing removal, has achieved it; an existing container still fails.
    if [[ "$phase_status" != 0 ]] && workspace_cache_builder_container_absent; then
      printf 'workspace cache cleanup: phase=builder-removal status=%s confirmed-absent=true\n' \
        "$phase_status" >&2
      phase_status=0
    fi
    if [[ "$phase_status" != 0 ]]; then
      printf 'workspace cache cleanup: phase=builder-removal status=%s elapsed_seconds=%s\n' \
        "$phase_status" "$((SECONDS - started))" >&2
      # Buildx reports builder and container names, never credential material.
      printf '%s\n' "${removal_output:0:600}" | tr -cd '[:print:]\n' |
        sed 's/^/workspace cache cleanup: builder-removal output: /' >&2
      status=$phase_status
    fi
  fi
  if [[ "$status" == 0 ]]; then
    daemon_credentials=false builder_created=false
  fi
  # The workflow owns the original file through later Kind/host builds. Never
  # remove it here. A failed daemon cleanup prevents receipt emission.
  return "$status"
}

# True only when Docker names the exact owned BuildKit container as missing.
# An unknown container identity or any other inspect failure is not proof.
workspace_cache_builder_container_absent() {
  local inspect_output='' inspect_status=0
  [[ "$builder_container" =~ ^[0-9a-f]{64}$ ]] || return 1
  inspect_output="$(timeout --signal=TERM --kill-after=3s 15s \
    "$docker_bin" container inspect --format '{{.Id}}' "$builder_container" 2>&1)" || inspect_status=$?
  [[ "$inspect_status" != 0 && "$inspect_output" == *"No such container"* ]]
}

workspace_cache_layer_args() {
  local target="$1" source_tree="$2" architecture="$3" name common alias
  layer_args=()
  [[ "$target" =~ ^(base|workspace|cw-runtime|canary-[a-z0-9-]+)$ ]] || return 2
  [[ "$source_tree" =~ ^[0-9a-f]{40}$ && "$architecture" =~ ^(amd64|arm64)$ ]] || return 2
  if [[ "$layer_cache_mode" == disabled ]]; then
    layer_args+=(--no-cache)
  else
    [[ "$target" != workspace ]] || layer_args+=(--no-cache-filter workspace-floating-tools)
  fi
  if [[ "$layer_cache_mode" == r2 ]]; then
    common="type=s3,bucket=$WORKSPACE_CACHE_BUCKET,region=auto,endpoint_url=$WORKSPACE_CACHE_ENDPOINT,use_path_style=true,prefix=$WORKSPACE_CACHE_PREFIX"
    if [[ -n "$workspace_measurement_case" ]]; then
      [[ "$target" == base || "$target" == workspace || "$target" == cw-runtime ]] || return 2
      [[ "${CODEWIRE_WORKSPACE_CACHE_SEED_ID:-}" =~ ^run-[0-9]+/tree-[0-9a-f]{40}/seed-[0-9a-f]{64}$ \
          && "$CODEWIRE_WORKSPACE_CACHE_SEED_ID" == "run-${GITHUB_RUN_ID:?}/tree-$source_tree/"* \
          && "$builder_container" =~ ^[0-9a-f]{64}$ ]] || return 2
      name="$architecture/$target/experiments/$CODEWIRE_WORKSPACE_CACHE_SEED_ID"
      if [[ "$workspace_measurement_case" == seed ]]; then
        layer_args+=(--cache-from "$common,name=$architecture/$target/tree-$source_tree"
          --cache-from "$common,name=$architecture/$target/main")
      else
        # Immutable producer binding: sibling case exports are never imports.
        layer_args+=(--cache-from "$common,name=$name")
        name="$name/$workspace_measurement_case-$builder_container"
      fi
      layer_args+=(--cache-to "$common,name=$name,mode=max,touch_refresh=24h,upload_parallelism=4,ignore-error=false")
      return
    fi
    name="$architecture/$target/tree-$source_tree"
    layer_args+=(--cache-from "$common,name=$name")
    # Every producer here is untrusted source CI, including main. These aliases
    # are performance hints only and must never be imported by publication.
    alias=''
    case "${GITHUB_REF:-}" in
      refs/pull/*/head)
        alias="${GITHUB_REF#refs/pull/}"; alias="${alias%/head}"
        [[ "$alias" =~ ^[0-9]+$ ]] || return 2
        alias="pr-$alias" ;;
      refs/heads/main) alias=main ;;
    esac
    [[ -z "$alias" ]] || layer_args+=(--cache-from "$common,name=$architecture/$target/$alias")
    [[ "$alias" == main || "$target" == canary-* ]] || layer_args+=(--cache-from "$common,name=$architecture/$target/main")
    [[ -z "$alias" ]] || name="$name;$architecture/$target/$alias"
    if [[ -n "${GITHUB_RUN_ID:-}" ]]; then
      [[ "$GITHUB_RUN_ID" =~ ^[0-9]+$ && "${GITHUB_RUN_ATTEMPT:-0}" =~ ^[0-9]+$ ]] || return 2
      name="$name;$architecture/$target/run-$GITHUB_RUN_ID-${GITHUB_RUN_ATTEMPT:-0}"
    fi
    # S3 is experimental in this exact standalone daemon. Best-effort export
    # does not turn a successfully verified image into a cache availability gate.
    layer_args+=(--cache-to "$common,name=$name,mode=max,touch_refresh=24h,upload_parallelism=4,ignore-error=true")
  fi
}

workspace_cache_compiler_args() {
  compiler_args=(--build-arg "CODEWIRE_SCCACHE_MODE=$sccache_mode")
  if [[ "$sccache_mode" == r2 ]]; then
    compiler_args+=(--secret "id=aws_shared_credentials,src=$credentials_file"
      --build-arg "SCCACHE_BUCKET=$WORKSPACE_CACHE_BUCKET"
      --build-arg "SCCACHE_ENDPOINT=$WORKSPACE_CACHE_ENDPOINT"
      --build-arg CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/v1)
  fi
}

workspace_cache_retryable_read_failure() {
  local status="$1" log="$2" line diagnostic=''
  # Buildx uses 1 for an ordinary build error and distinct statuses for its
  # own failures, resource exhaustion and cancellation. A deadline or signal
  # must never become a successful second attempt.
  [[ "$status" == 1 ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ [^[:space:]] ]] && diagnostic="$line"
  done <"$log"
  # Only the final Buildx diagnostic identifies why the command failed. Earlier
  # progress may contain a nonfatal cache warning followed by a Cargo failure.
  # Unknown/multiline/debug forms fail closed until their rendering is proven.
  [[ "$diagnostic" =~ ^ERROR:\ (failed\ to\ build:\ )?failed\ to\ solve:\ (failed\ to\ load\ cache(\ key)?|failed\ to\ configure\ s3\ cache\ importer|failed\ to\ import\ cache):\  ]] || return 1
  [[ "$diagnostic" =~ (S3|GetObject|HeadObject|r2\.cloudflarestorage\.com) ]] || return 1
  case "${diagnostic,,}" in
    *cancel*|*deadline*|*'process '*|*frontend*|*export*) return 1 ;;
  esac
}

workspace_cache_logged_command() {
  local log="$1"
  shift
  workspace_cache_command bash -c '
    set +e
    log=$1; shift
    # GNU timeout signals the whole pipeline. Keep its Bash parent alive long
    # enough to reap the Docker client and logger after they handle the signal.
    cancelled=0
    trap "cancelled=143" TERM
    trap "cancelled=130" INT
    "$@" 2>&1 | tee "$log"
    statuses=("${PIPESTATUS[@]}")
    if [[ "$cancelled" != 0 ]]; then
      exit "$cancelled"
    fi
    if [[ "${statuses[1]}" != 0 ]]; then
      echo "workspace cache build: log capture failed" >&2
      exit 74
    fi
    exit "${statuses[0]}"
  ' workspace-build "$log" "$@"
}

workspace_cache_build() {
  local target="$1" source_tree="$2" architecture="$3" log="$4" status=0 original_mode="$layer_cache_mode"
  shift 4
  local -a producer_cache=() consumer_cache=() command=()
  local cw_work="${log%/*}/cw-image-work"
  workspace_cache_layer_args "$target" "$source_tree" "$architecture" || return
  consumer_cache=("${layer_args[@]}")
  command=("$docker_bin" buildx build --builder "$builder" --progress plain --platform "linux/$architecture" "${consumer_cache[@]}" "$@")
  if [[ "$target" == workspace ]]; then
    workspace_cache_layer_args cw-runtime "$source_tree" "$architecture" || return
    producer_cache=("${layer_args[@]}")
    (umask 077; mkdir -p -- "$cw_work") || return
    command=(bash "$ROOT/scripts/ci/images/cw-image-consumer.sh" release "$ROOT" "$cw_work" "${producer_cache[@]}" -- "${command[@]}")
  fi
  workspace_cache_logged_command "$log" "${command[@]}" || status=$?
  if [[ "$original_mode" == r2 ]] \
      && workspace_cache_retryable_read_failure "$status" "$log"; then
    echo '::warning::Remote layer read failed; retrying this build once without external cache'
    # shellcheck disable=SC2034 # Consumed by the verifier receipt after this call.
    workspace_cache_fallback=true
    # A broken remote descriptor can remain in the daemon's local metadata.
    # Force computation on retry, preserving fresh floating tools without
    # combining the mutually exclusive no-cache and no-cache-filter flags.
    command=("$docker_bin" buildx build --builder "$builder" --progress plain --platform "linux/$architecture" --no-cache "$@")
    if [[ "$target" == workspace ]]; then
      command=(bash "$ROOT/scripts/ci/images/cw-image-consumer.sh" release "$ROOT" "$cw_work" --no-cache -- "${command[@]}")
    fi
    workspace_cache_logged_command "$log.retry" "${command[@]}"
    return
  fi
  return "$status"
}
