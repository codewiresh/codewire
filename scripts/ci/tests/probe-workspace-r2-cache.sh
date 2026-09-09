#!/usr/bin/env bash
# Opt-in live effects only. Never invoked by ordinary policy verification.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: probe-workspace-r2-cache.sh AWS_CREDENTIALS_FILE NEW_REPORT_DIRECTORY' >&2; exit 2; }
if [[ "${CODEWIRE_CACHE_PROBE_BOUNDED_CHILD:-}" != 1 ]]; then
  # Leave the parent job 7.5 minutes for setup/finalization. The accepted 150s
  # reserve covers a signal overlapping foreground builder/state cleanup.
  exec timeout --signal=TERM --kill-after=150s 2700s \
    env CODEWIRE_CACHE_PROBE_BOUNDED_CHILD=1 "$0" "$@"
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
source "$ROOT/scripts/ci/images/workspace-cache.sh"
probe_tool="$ROOT/scripts/ci/verify/workspace-cache-probes.py"
report_tool="$ROOT/scripts/ci/verify/workspace-cache-report.py"
[[ "${CODEWIRE_SCCACHE_MODE:-}" == r2 && "${CODEWIRE_BUILDKIT_CACHE_MODE:-}" == r2 ]] || {
  echo 'cache probes require both resolved R2 modes' >&2; exit 1;
}
unset CODEWIRE_WORKSPACE_CACHE_CASE CODEWIRE_WORKSPACE_CACHE_REPORT_DIR CODEWIRE_WORKSPACE_CACHE_SEED_ID
export CODEWIRE_SCCACHE_CREDENTIALS_FILE="$1"
workspace_cache_validate
original_credentials="$credentials_file"
report="$2"
[[ "$report" == "${RUNNER_TEMP:?}/"* && "$report" == /* && "$report" != "$ROOT/"* \
    && "$(realpath -m -- "$report")" == "$report" && ! -e "$report" && ! -L "$report" ]] || exit 2
umask 077
mkdir -m 0700 "$report"
work="$(mktemp -d "$RUNNER_TEMP/workspace-cache-probes.XXXXXX")"
runtime_container='' cancel_pid=''
cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM
  if [[ -n "$cancel_pid" ]]; then
    kill -TERM "$cancel_pid" 2>/dev/null || true
    wait "$cancel_pid" 2>/dev/null || true
  fi
  workspace_cache_cleanup_builder || cleanup_status=$?
  if [[ -n "$runtime_container" ]]; then
    timeout --signal=TERM --kill-after=3s 10s \
      "$docker_bin" rm --force "$runtime_container" >/dev/null 2>&1 || cleanup_status=$?
  fi
  rm -rf -- "$work" || cleanup_status=$?
  [[ "$status" != 0 || "$cleanup_status" == 0 ]] || status="$cleanup_status"
  if [[ "$status" == 0 ]]; then
    printf 'true\n' >"$report/work-complete" || status=$?
  fi
  [[ "$status" == 0 ]] || rm -f -- "$report/work-complete" "$report/result.json"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 "$probe_tool" prepare "$ROOT" "$report" "$WORKSPACE_BUILDKIT_IMAGE" "$original_credentials"
source_sha="$(jq -er .source_sha "$report/identity.json")"
architecture="$(jq -er .architecture "$report/identity.json")"
seed_id="$(jq -er .seed_cache_id "$report/identity.json")"
nonce="$(jq -er .nonce "$report/identity.json")"
workspace_cache_command git -C "$ROOT" archive --format=tar --output "$work/source.tar" "$source_sha"
python3 "$probe_tool" derive "$work/source.tar" "$work" "$report" "$original_credentials" "$nonce"
contexts=("$ROOT" "$work/contexts/control" "$work/contexts/cw-edit" "$work/contexts/tools"
  "$work/contexts/native" "$work/contexts/cancel")
synthetic_credentials="$work/identities/denied.aws"
common="type=s3,bucket=$WORKSPACE_CACHE_BUCKET,region=auto,endpoint_url=$WORKSPACE_CACHE_ENDPOINT,use_path_style=true,prefix=$WORKSPACE_CACHE_PREFIX"
native_name="$architecture/canary-$nonce/probes/run-${GITHUB_RUN_ID:?}/payload"

new_builder() {
  local phase="$1" key="$2" scratch
  [[ "$builder_created" == false && "$daemon_credentials" == false ]]
  python3 "$probe_tool" key "$key" "${contexts[@]}"
  credentials_file="$key"
  mkdir "$report/$phase"
  scratch="$(mktemp -d "$work/$phase.XXXXXX")"
  workspace_cache_create_builder "$scratch"
  workspace_cache_command "$docker_bin" container inspect "$builder_container" --format '{{json .Mounts}}' \
    >"$report/$phase/mounts.json"
  python3 "$probe_tool" register "$report" "$phase" "$builder" "$builder_container" \
    >"$report/$phase/volume"
}

observe_removed() {
  local phase="$1" directory="$report/$1"
  # A successful list response, not an ambiguous inspect error, proves absence.
  workspace_cache_command timeout 8s "$docker_bin" info --format '{{.ID}}' >"$directory/docker-id"
  workspace_cache_command timeout 8s "$docker_bin" container ls --all --no-trunc \
    --filter "id=$(jq -er .container "$directory/owner.json")" --format '{{.ID}}' >"$directory/remaining-containers"
  workspace_cache_command timeout 8s "$docker_bin" volume ls \
    --filter "name=$(<"$directory/volume")" --format '{{.Name}}' >"$directory/remaining-volumes"
  workspace_cache_command timeout 8s "$docker_bin" buildx ls --format '{{.Name}}' >"$directory/remaining-builders"
  python3 "$probe_tool" cleaned "$report" "$phase"
}

remove_builder() {
  workspace_cache_cleanup_builder
  observe_removed "$1"
}

native_phase() {
  local phase="$1" importer="$2" key="$3" status=0
  local -a export_args=()
  new_builder "$phase" "$key"
  [[ "$phase" != native-cold ]] || export_args=(--cache-to "$common,name=$native_name,mode=max,ignore-error=false")
  workspace_cache_logged_command "$report/$phase/build.log" \
    env AWS_SHARED_CREDENTIALS_FILE="$key" AWS_PROFILE=default AWS_EC2_METADATA_DISABLED=true \
    timeout --signal=TERM --kill-after=5s 120s "$docker_bin" buildx build --builder "$builder" --progress plain \
    --cache-from "$importer" "${export_args[@]}" \
    --output "type=local,dest=$work/$phase-output" "$work/contexts/native" || status=$?
  printf '%s\n' "$status" >"$report/$phase/status"
  if ((status >= 124)); then
    echo 'native cache probe timed out, was interrupted, or could not execute' >&2
    return "$status"
  fi
  if [[ "$status" != 0 && "$phase" != native-cold && "$phase" != native-warm ]]; then
    # This is explicit probe recovery, not the production wrapper's retry.
    rm -rf -- "$work/$phase-output"
    status=0
    workspace_cache_logged_command "$report/$phase/recovery.log" \
      timeout --signal=TERM --kill-after=5s 120s "$docker_bin" buildx build --builder "$builder" --progress plain --no-cache \
      --output "type=local,dest=$work/$phase-output" "$work/contexts/native" || status=$?
    printf '%s\n' "$status" >"$report/$phase/recovery-status"
    [[ "$status" == 0 ]]
  fi
  cmp "$work/contexts/native/payload" "$work/$phase-output/payload"
  sha256sum "$work/$phase-output/payload" | cut -d ' ' -f 1 >"$report/$phase/payload.sha256"
  remove_builder "$phase"
  case "$phase" in
    native-malformed|native-missing-blob|native-denied)
      python3 "$probe_tool" replay "$ROOT" "$report" "$phase" "$work" "$synthetic_credentials" ;;
  esac
  python3 "$probe_tool" check "$report" "$phase"
}

native_phase native-cold "$common,name=$native_name" "$original_credentials"
native_phase native-warm "$common,name=$native_name" "$original_credentials"
blob="$(jq -er .blob_digest "$report/native-cold/result.json")"
native_phase native-malformed "$common,manifests_prefix=blobs/,name=$blob" "$original_credentials"
native_phase native-missing-blob "$common,name=$native_name,blobs_prefix=blobs/probe-$nonce-missing/" "$original_credentials"
native_phase native-denied "$common,name=$native_name" "$synthetic_credentials"

for phase in cw-control cw-edit; do
  new_builder "$phase" "$original_credentials"
  workspace_cache_compiler_args
  context="$work/contexts/cw-edit"
  [[ "$phase" != cw-control ]] || context="$work/contexts/control"
  status=0
  workspace_cache_logged_command "$report/$phase/build.log" \
    "$docker_bin" buildx build --builder "$builder" --progress plain --pull \
    --cache-from "$common,name=$architecture/workspace/experiments/$seed_id" \
    --cache-to "$common,name=$architecture/workspace/experiments/$seed_id/probes/$nonce/$phase-$builder_container,mode=max,touch_refresh=24h,upload_parallelism=4,ignore-error=false" \
    "${compiler_args[@]}" --build-arg BASE_IMAGE_REF=scratch \
    --file "$work/Dockerfile" --target cw-cache-probe-result \
    --output "type=local,dest=$work/$phase-output" "$context" || status=$?
  printf '%s\n' "$status" >"$report/$phase/status"
  [[ "$status" == 0 ]]
  cp -- "$work/$phase-output/version.txt" "$work/$phase-output/cw.sha256" "$report/$phase/"
  remove_builder "$phase"
  python3 "$probe_tool" check "$report" "$phase"
done

new_builder tools "$original_credentials"
workspace_cache_compiler_args
base_layout="$work/base.oci"
workspace_cache_logged_command "$report/tools/base-build.log" \
  "$docker_bin" buildx build --builder "$builder" --progress plain --pull \
  --cache-from "$common,name=$architecture/base/experiments/$seed_id" \
  --cache-to "$common,name=$architecture/base/experiments/$seed_id/probes/$nonce/tools-$builder_container,mode=max,touch_refresh=24h,upload_parallelism=4,ignore-error=false" \
  --metadata-file "$report/tools/base-metadata.json" --output "type=oci,dest=$base_layout,tar=false" \
  --file "$work/contexts/tools/images/base/Dockerfile" "$work/contexts/tools/images/base"
base_digest="$(jq -er '.["containerimage.digest"] | select(test("^sha256:[0-9a-f]{64}$"))' "$report/tools/base-metadata.json")"
image_tag="codewire-cache-probe:$nonce"
status=0
workspace_cache_logged_command "$report/tools/build.log" \
  "$docker_bin" buildx build --builder "$builder" --progress plain --pull \
  --cache-from "$common,name=$architecture/workspace/experiments/$seed_id" \
  --cache-to "$common,name=$architecture/workspace/experiments/$seed_id/probes/$nonce/tools-$builder_container,mode=max,touch_refresh=24h,upload_parallelism=4,ignore-error=false" \
  --no-cache-filter workspace-floating-tools \
  --build-context "codewire-verified-base=oci-layout://$base_layout@$base_digest" \
  --build-arg BASE_IMAGE_REF=codewire-verified-base "${compiler_args[@]}" \
  --label dev.codewire.promotable=false --tag "$image_tag" --load \
  --file "$work/contexts/tools/images/workspace/Dockerfile" "$work/contexts/tools" || status=$?
printf '%s\n' "$status" >"$report/tools/status"
[[ "$status" == 0 ]]
# Exactly the ordinary contract topology, after credential/builder removal.
remove_builder tools
workspace_cache_command "$docker_bin" image inspect "$image_tag" --format '{{.Id}}' >"$report/tools/image-id"
image_id="$(<"$report/tools/image-id")"
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]
runtime_container="codewire-cache-probe-$nonce-full"
workspace_cache_logged_command "$report/tools/agents.log" \
  "$docker_bin" run --rm --interactive --pids-limit=2048 --name "$runtime_container" \
  --user codewire --entrypoint bash "$image_id" -eu -s <"$ROOT/scripts/ci/verify/workspace-agent-contract.sh"
runtime_container="codewire-cache-probe-$nonce-mounted-home"
workspace_cache_logged_command "$report/tools/mounted-home.log" \
  "$docker_bin" run --rm --interactive --pids-limit=2048 --name "$runtime_container" --user codewire \
  --tmpfs /home/codewire:rw,exec,uid=1000,gid=1000,mode=0700,size=256m --entrypoint bash \
  "$image_id" -eu -s -- --mounted-home-agents <"$ROOT/scripts/ci/verify/workspace-agent-contract.sh"
printf '0\n' >"$report/tools/contracts-status"
runtime_container="codewire-cache-probe-$nonce-marker"
workspace_cache_command "$docker_bin" run --rm --network none --name "$runtime_container" \
  --user codewire --entrypoint cat "$image_id" /usr/local/share/codewire-cache-probe-token >"$report/tools/tool-marker"
runtime_container="codewire-cache-probe-$nonce-versions"
workspace_cache_command "$docker_bin" run --rm --interactive --pids-limit=2048 --name "$runtime_container" \
  --user codewire --entrypoint python3 "$image_id" - versions <"$report_tool" >"$report/tools/versions.json"
runtime_container=''
python3 "$probe_tool" check "$report" tools

cancel_child() {
  child_cleanup() {
    local status=$? cleanup_status=0
    trap - EXIT INT TERM
    workspace_cache_cleanup_builder || cleanup_status=$?
    [[ "$cleanup_status" == 0 ]] || status="$cleanup_status"
    printf '%s\n' "$status" >"$report/cancel/status" || status=$?
    exit "$status"
  }
  trap child_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  new_builder cancel "$original_credentials"
  workspace_cache_logged_command "$report/cancel/build.log" \
    "$docker_bin" buildx build --builder "$builder" --progress plain --no-cache \
    --output "type=local,dest=$work/cancel-output" "$work/contexts/cancel"
  : >"$report/cancel/unexpected-success"
}
cancel_child &
cancel_pid=$!
ready=false
for ((attempt=0; attempt<180; attempt++)); do
  if [[ -f "$report/cancel/build.log" ]] && python3 "$probe_tool" ready "$report/cancel/build.log" "$nonce"; then
    ready=true
    break
  fi
  kill -0 "$cancel_pid" 2>/dev/null || break
  sleep 1
done
[[ "$ready" == true ]] || { echo 'cancel probe never executed its readiness marker' >&2; exit 1; }
kill -TERM "$cancel_pid"
status=0
wait "$cancel_pid" || status=$?
cancel_pid=''
[[ "$status" == 143 ]]
printf 'true\n' >"$report/cancel/child-reaped"
observe_removed cancel
python3 "$probe_tool" check "$report" cancel
printf 'workspace cache probes completed; host credential finisher and separate finalization remain required\n'
