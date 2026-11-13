#!/usr/bin/env bash
# Sourced by non-publishing workspace verification.
# This is the owner's explicitly accepted provider-key projection, not a broker.
# shellcheck source=scripts/ci/images/buildx-builder.sh
source "$(dirname "${BASH_SOURCE[0]}")/buildx-builder.sh"
readonly WORKSPACE_BUILDKIT_IMAGE='docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
# The cache selector names the trust. Canonical-main pushes read and write the
# main bucket (main); pull requests only read it (protected-read) with a read-only
# token; anything else, such as a local run, uses the disposable untrusted
# bucket. Each token covers exactly one bucket, so main never imports
# a layer or compiler object a pull request wrote.
case "${CODEWIRE_R2_CACHE_TRUST:-untrusted}" in
  main|protected-read) readonly WORKSPACE_CACHE_TRUST="$CODEWIRE_R2_CACHE_TRUST" WORKSPACE_CACHE_SCOPE=protected ;;
  *) readonly WORKSPACE_CACHE_TRUST=untrusted WORKSPACE_CACHE_SCOPE=untrusted ;;
esac
# Each scope's bucket is site configuration with no default
# (docs/dev/CI-CONFIGURATION.md); the r2 modes refuse to run without it.
if [[ "$WORKSPACE_CACHE_SCOPE" == protected ]]; then
  readonly WORKSPACE_CACHE_BUCKET_VARIABLE=CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED
else
  readonly WORKSPACE_CACHE_BUCKET_VARIABLE=CODEWIRE_CI_SCCACHE_BUCKET_UNTRUSTED
fi
readonly WORKSPACE_CACHE_BUCKET="${!WORKSPACE_CACHE_BUCKET_VARIABLE:-}"
readonly WORKSPACE_CACHE_PREFIX="$WORKSPACE_CACHE_SCOPE/codewire/buildkit/v1/"
readonly WORKSPACE_SCCACHE_PREFIX="$WORKSPACE_CACHE_SCOPE/codewire/v1"
readonly WORKSPACE_DAEMON_CREDENTIALS='/run/codewire-cache/aws-credentials'
# Verification builds the amd64 cw producer with the runtime Cargo profile,
# the one profile publication (build-push-image.sh) and every other image
# build use, so Kind's workspace runs the cw profile Dev and Production run.
# This verified cw is never published. The Python reader pins the same value
# (WORKSPACE_CW_PROFILE in workspace-image-artifact.py);
# test-workspace-image-artifact.py checks it.
readonly WORKSPACE_CW_PROFILE=runtime

workspace_cache_validate() {
  local mode source_root
  docker_bin="${CODEWIRE_DOCKER_BIN:-docker}"
  sccache_mode="${CODEWIRE_SCCACHE_MODE:-local}"
  layer_cache_mode="${CODEWIRE_BUILDKIT_CACHE_MODE:-local}"
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
    # CI names the cache endpoint in the CODEWIRE_R2_CACHE_ENDPOINT Actions variable.
    [[ -n "${CODEWIRE_R2_CACHE_ENDPOINT:-}" ]] || {
      echo 'CODEWIRE_R2_CACHE_ENDPOINT: set to the CI cache R2 endpoint URL' >&2; return 2;
    }
    [[ -n "$WORKSPACE_CACHE_BUCKET" ]] || {
      echo "$WORKSPACE_CACHE_BUCKET_VARIABLE: set to the $WORKSPACE_CACHE_SCOPE CI cache bucket (docs/dev/CI-CONFIGURATION.md)" >&2
      return 2
    }
    [[ "${SCCACHE_BUCKET:-}" == "$WORKSPACE_CACHE_BUCKET" \
        && "${SCCACHE_ENDPOINT:-}" == "$CODEWIRE_R2_CACHE_ENDPOINT" \
        && "${CODEWIRE_SCCACHE_PREFIX:-}" == "$WORKSPACE_SCCACHE_PREFIX" ]] || {
      echo "workspace cache requires the reviewed $WORKSPACE_CACHE_TRUST R2 configuration" >&2; return 2;
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
  buildx_builder_cap "$builder"
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
    # The builder, its daemon container and its state volume must be gone. The
    # shared helper accepts a failed `buildx rm` once Docker reports all three
    # missing, and names any that persist.
    phase_status=0
    buildx_builder_remove "$docker_bin" "$builder" "${builder}-node" 'workspace cache cleanup' ||
      phase_status=$?
    [[ "$phase_status" == 0 ]] || status=$phase_status
  fi
  if [[ "$status" == 0 ]]; then
    daemon_credentials=false builder_created=false
  fi
  # The workflow owns the original file through later Kind/host builds. Never
  # remove it here. A failed daemon cleanup prevents receipt emission.
  return "$status"
}

workspace_cache_layer_args() {
  local target="$1" source_tree="$2" architecture="$3" name common alias
  layer_args=()
  [[ "$target" =~ ^(base|workspace|cw-runtime|cw-arm64)$ ]] || return 2
  [[ "$source_tree" =~ ^[0-9a-f]{40}$ && "$architecture" =~ ^(amd64|arm64)$ ]] || return 2
  if [[ "$layer_cache_mode" == disabled ]]; then
    layer_args+=(--no-cache)
  else
    [[ "$target" != workspace ]] || layer_args+=(--no-cache-filter workspace-floating-tools
      --no-cache-filter workspace-floating-go --no-cache-filter workspace-agents)
  fi
  if [[ "$layer_cache_mode" == r2 ]]; then
    common="type=s3,bucket=$WORKSPACE_CACHE_BUCKET,region=auto,endpoint_url=$CODEWIRE_R2_CACHE_ENDPOINT,use_path_style=true,prefix=$WORKSPACE_CACHE_PREFIX"
    name="$architecture/$target/tree-$source_tree"
    layer_args+=(--cache-from "$common,name=$name")
    if [[ "$WORKSPACE_CACHE_TRUST" == protected-read ]]; then
      # Pull requests import main's layers and export nothing remote.
      layer_args+=(--cache-from "$common,name=$architecture/$target/main")
      return
    fi
    # Each bucket has one producer class: canonical-main pushes write the main
    # bucket, and only runs outside CI write the untrusted one. These aliases
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
    [[ "$alias" == main ]] || layer_args+=(--cache-from "$common,name=$architecture/$target/main")
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
      --build-arg "SCCACHE_ENDPOINT=$CODEWIRE_R2_CACHE_ENDPOINT"
      --build-arg "CODEWIRE_SCCACHE_PREFIX=$WORKSPACE_SCCACHE_PREFIX")
  fi
}

# CI may name an internal HTTP cache of the dated apt snapshots. BuildKit
# receives it only as an optional secret, so layer cache keys and image
# history stay identical to builds without it.
workspace_cache_apt_mirror_args() {
  apt_mirror_args=()
  if [[ -n "${CODEWIRE_APT_SNAPSHOT_MIRROR:-}" ]]; then
    apt_mirror_args=(--secret "id=codewire-apt-mirror,env=CODEWIRE_APT_SNAPSHOT_MIRROR")
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
  apt_mirror_args=()
  [[ "$target" != base && "$target" != workspace ]] || workspace_cache_apt_mirror_args
  command=("$docker_bin" buildx build --builder "$builder" --progress plain --platform "linux/$architecture" \
    "${consumer_cache[@]}" "${apt_mirror_args[@]}" "$@")
  if [[ "$target" == workspace ]]; then
    workspace_cache_layer_args cw-runtime "$source_tree" "$architecture" || return
    producer_cache=("${layer_args[@]}")
    (umask 077; mkdir -p -- "$cw_work") || return
    command=(bash "$ROOT/scripts/ci/images/cw-image-consumer.sh" "$WORKSPACE_CW_PROFILE" "$ROOT" "$cw_work" "${producer_cache[@]}" -- "${command[@]}")
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
    command=("$docker_bin" buildx build --builder "$builder" --progress plain --platform "linux/$architecture" --no-cache \
      "${apt_mirror_args[@]}" "$@")
    if [[ "$target" == workspace ]]; then
      command=(bash "$ROOT/scripts/ci/images/cw-image-consumer.sh" "$WORKSPACE_CW_PROFILE" "$ROOT" "$cw_work" --no-cache -- "${command[@]}")
    fi
    workspace_cache_logged_command "$log.retry" "${command[@]}"
    return
  fi
  return "$status"
}
