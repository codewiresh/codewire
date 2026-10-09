#!/usr/bin/env bash
# Build and inspect the workspace image without publishing it. This runs in
# pull-request CI and intentionally proves the user-facing agent contract.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
docker_bin="${CODEWIRE_DOCKER_BIN:-docker}"
base_context_name="codewire-verified-base"
artifact_tool="$ROOT/scripts/ci/verify/workspace-image-artifact.py"
receipt="$ROOT/.tmp/codewire-workspace-image-verification.json"
source "$ROOT/scripts/ci/images/workspace-cache.sh"
workspace_cache_validate
report_tool="$ROOT/scripts/ci/verify/workspace-cache-report.py"
report_dir=''
retain_cw_producer="${CODEWIRE_WORKSPACE_CW_PRODUCER_RETAIN:-0}"
case "$retain_cw_producer" in
  0|1) ;;
  *) echo 'workspace CW producer retention must be 0 or 1' >&2; exit 2 ;;
esac
if [[ -n "$workspace_measurement_case" ]]; then
  # Experiments always build; an old image receipt cannot seed a measurement.
  export CODEWIRE_WORKSPACE_IMAGE_REUSE=disabled
  CODEWIRE_BUILDKIT_CACHE_REQUEST=auto python3 "$ROOT/scripts/ci/setup/select-workspace-cache-experiment.py" \
    | jq -e '.selected == true' >/dev/null
fi
case "${CODEWIRE_WORKSPACE_IMAGE_REUSE:-auto}" in
  auto|disabled) ;;
  *) echo 'workspace image reuse must be auto or disabled' >&2; exit 2 ;;
esac
export CODEWIRE_SCCACHE_MODE="$sccache_mode" CODEWIRE_BUILDKIT_CACHE_MODE="$layer_cache_mode"

for tool in "$docker_bin" python3 jq timeout bash tee stat realpath; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'workspace image verification: missing required tool: %s\n' "$tool" >&2
    exit 1
  }
done

[[ "$#" -eq 0 ]] || { echo 'workspace image verifier accepts no arguments' >&2; exit 2; }
identity="$(python3 "$artifact_tool" identity "$ROOT")"
source_id="$(jq -er '.source_sha' <<<"$identity")"
source_tree="$(jq -er '.source_tree' <<<"$identity")"
architecture="$(jq -er '.architecture' <<<"$identity")"
contract_sha="$(jq -er '.inputs["scripts/ci/verify/workspace-agent-contract.sh"]' <<<"$identity")"
workspace_tag="codewire-workspace-verify:${source_id}"
if [[ "$retain_cw_producer" == 1 && "$architecture" != amd64 ]]; then
  echo 'workspace CW producer retention requires the verified amd64 producer' >&2
  exit 2
fi
# The image-only seal contains no original compiler staging/reference. A
# retention request must qualify its own producer through the existing route.
if [[ "$retain_cw_producer" == 0 && "${CODEWIRE_WORKSPACE_IMAGE_REUSE:-auto}" == auto ]] \
    && alias="$(python3 "$artifact_tool" reuse-for-build "$ROOT" "$receipt" 2>/dev/null)"; then
  printf 'workspace image verification: reused exact verified image %s\n' "$alias"
  exit 0
fi
mkdir -p "$ROOT/.tmp"
# A fresh failed attempt must never leave an older acceptance marker behind.
[[ ! -L "$receipt" && ! -L "$ROOT/.tmp" ]] || { echo 'invalid workspace receipt destination' >&2; exit 2; }
umask 077
if [[ -n "$workspace_measurement_case" ]]; then
  report_dir="${CODEWIRE_WORKSPACE_CACHE_REPORT_DIR:?measurement report directory is required}"
  [[ "$report_dir" == "${RUNNER_TEMP:?}/"* && "$report_dir" == /* \
      && "$(realpath -m -- "$report_dir")" == "$report_dir" \
      && "$report_dir" != "$(realpath -- "$ROOT")/"* && ! -e "$report_dir" && ! -L "$report_dir" ]] || exit 2
  mkdir -m 0700 "$report_dir"
fi
work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-workspace-image-verify.XXXXXX")"
build_log_root="${report_dir:-$work}"
archive_work="$(mktemp -d "$ROOT/.tmp/.workspace-oci.XXXXXX")"
workspace_archive="$archive_work/workspace.oci.tar"
previous_receipt="$archive_work/previous-receipt.json"
base_layout="$work/base.oci"
base_metadata="$work/base-metadata.json"
workspace_metadata="$build_log_root/workspace-metadata.json"
workspace_id=''
base_digest=''
contract_container=''
sampler_pid=''
cw_copy_started=false

retained_cw_producer() {
  python3 -B - "$ROOT" "$source_id" "$build_log_root/cw-image-work/cw-producer-result.json" <<'PY'
from contextlib import closing
import importlib.util, os, pathlib, stat, sys
root, revision, pointer = pathlib.Path(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3])
spec = importlib.util.spec_from_file_location('cw_retained_workspace_producer', root / 'scripts/ci/images/cw-image-consumer.py')
consumer = importlib.util.module_from_spec(spec); spec.loader.exec_module(consumer)
producer, asset, release = consumer.producer, consumer.asset, consumer.release
fields = {'status', 'receipt', 'producer_receipt', 'image', 'index_sha256', 'payload', 'source',
          'profile', 'version', 'build_ref', 'cache_qualified', 'image_qualified'}
with closing(asset.HeldFile(pointer, release.MAX_JSON)) as held:
    asset.require(pointer.name == 'cw-producer-result.json' and pointer.parent.name == 'cw-image-work'
                  and held.metadata['uid'] == os.geteuid()
                  and stat.S_IMODE(held.metadata['mode']) == 0o400, 'retained producer pointer is not private')
    parent = os.fstat(held.parent.fd)
    asset.require(parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700,
                  'retained producer pointer directory is not private')
    value = release.parse_canonical(held.data)
    asset.require(type(value) is dict and set(value) == fields and value['status'] == 'producer-admitted',
                  'retained producer pointer is not complete')
    version = consumer.effective_version(root, os.environ.get('CODEWIRE_VERSION'))
    with producer.reopen(value['receipt']['path'], value['receipt']['sha256'], root, revision, 'release', version) as admitted:
        summary = admitted.summary
        asset.require(value == {key: summary[key] for key in fields}, 'retained producer reference changed')
        admitted.revalidate(); held.revalidate(content=True)
        print(release.canonical({'status': 'workspace-cw-producer-retained', 'result': held.evidence(),
                                'profile': summary['profile'], 'version': summary['version'],
                                'source': summary['source'], 'original_build_ref': summary['build_ref']}).decode(), end='')
PY
}

stop_sampler() {
  local sampler_status=0 wait_status=0
  if [[ -n "$sampler_pid" ]]; then
    # Report IO is fallible (including ENOSPC). It must never prevent stopping
    # the observer or the caller's subsequent provider-file/builder cleanup.
    : >"$report_dir/sampler-stop-request" || sampler_status=$?
    kill -TERM "$sampler_pid" 2>/dev/null || true
    wait "$sampler_pid" 2>/dev/null || wait_status=$?
    case "$wait_status" in
      0|143) ;;
      *) [[ "$sampler_status" != 0 ]] || sampler_status="$wait_status" ;;
    esac
    sampler_pid=''
    [[ ! -e "$report_dir/metrics-error" ]] || sampler_status=1
    if [[ "$sampler_status" != 0 ]]; then
      printf 'resource sampler failed with status %s\n' "$sampler_status" >"$report_dir/metrics-error" || true
    fi
  fi
  return "$sampler_status"
}

cleanup() {
  local status=$? cleanup_status=0 retained_result=''
  trap - EXIT INT TERM

  stop_sampler || cleanup_status=$?
  workspace_cache_cleanup_builder || cleanup_status=$?
  if [[ -n "$contract_container" ]]; then
    timeout --signal=TERM --kill-after=3s 10s \
      "$docker_bin" rm --force "$contract_container" >/dev/null 2>&1 || cleanup_status=$?
  fi
  if [[ "$cw_copy_started" == false ]]; then
    # Opt-in success keeps the entire original private staging tree. Defer its
    # deletion until the existing cleanup and atomic seal have been observed.
    [[ "$retain_cw_producer" == 1 ]] || rm -rf "$work"
  else
    printf 'workspace image verification: failed CW copy evidence retained at %s\n' "$work" >&2
  fi

  if [[ "$status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
    printf 'workspace image verification: failed to remove ephemeral builder %s\n' \
      "$builder" >&2
    status="$cleanup_status"
  fi
  if [[ "$status" -eq 0 ]]; then
    # No acceptance marker may survive a failed contract or builder cleanup.
    local -a prior_receipt=()
    [[ ! -e "$previous_receipt" ]] || prior_receipt+=("$previous_receipt")
    if [[ -n "$report_dir" ]]; then
      printf '%s\n' "$(( $(date +%s) - started_at ))" >"$report_dir/elapsed-seconds" || status=$?
    fi
  fi
  if [[ "$status" -eq 0 ]]; then
    if [[ "$retain_cw_producer" == 1 ]]; then
      retained_result="$(retained_cw_producer)" || status=$?
    fi
  fi
  if [[ "$status" -eq 0 ]]; then
    CODEWIRE_BUILDKIT_CACHE_FALLBACK="$workspace_cache_fallback" \
      python3 "$artifact_tool" seal "$ROOT" "$receipt" "$workspace_id" \
        "$base_digest" "$workspace_archive" "${prior_receipt[@]}" || status=$?
  fi
  rm -rf "$archive_work"
  if [[ "$retain_cw_producer" == 1 && "$cw_copy_started" == false ]]; then
    if [[ "$status" -eq 0 ]]; then
      printf '%s\n' "$retained_result"
    else
      rm -rf "$work"
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ -e "$receipt" ]]; then
  [[ -f "$receipt" ]] || { echo 'invalid workspace receipt destination' >&2; exit 2; }
  mv -- "$receipt" "$previous_receipt"
fi

started_at="$(date +%s)"
workspace_cache_create_builder "$work"
workspace_cache_compiler_args
if [[ -n "$report_dir" ]]; then
  if [[ "$workspace_measurement_case" == seed ]]; then
    export CODEWIRE_WORKSPACE_CACHE_SEED_ID="run-${GITHUB_RUN_ID:?}/tree-$source_tree/seed-$builder_container"
  fi
  workspace_cache_command "$docker_bin" info --format '{{.ID}}' >"$report_dir/docker-id"
  workspace_cache_command "$docker_bin" version --format '{{.Client.Version}}' >"$report_dir/docker-version"
  workspace_cache_command "$docker_bin" buildx version >"$report_dir/buildx-version"
  workspace_cache_command "$docker_bin" container inspect "${HOSTNAME:?}" --format '{{.Image}}' >"$report_dir/job-image-id"
  python3 - "$report_dir" "$identity" "$builder_container" "$WORKSPACE_BUILDKIT_IMAGE" "$HOSTNAME" "$builder" <<'PY'
import json, os, re, sys
from pathlib import Path
directory, identity, builder, pin, job_container, builder_name = sys.argv[1:]
directory = Path(directory)
value = json.loads(identity)
daemon = (directory / "docker-id").read_text().strip()
job_image = (directory / "job-image-id").read_text().strip()
if not re.fullmatch(r"[A-Za-z0-9:_-]{8,128}", daemon) or not re.fullmatch(r"sha256:[0-9a-f]{64}", job_image):
    raise SystemExit("invalid worker identity")
header = {key: value[key] for key in ("source_sha", "source_tree", "architecture")}
header.update(case=os.environ["CODEWIRE_WORKSPACE_CACHE_CASE"],
              docker_daemon_id=daemon, builder_container_id=builder, builder_name=builder_name,
              job_container_id=job_container, job_id=os.environ["GITHUB_JOB"],
              run_id=os.environ["GITHUB_RUN_ID"], run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
              seed_cache_id=os.environ["CODEWIRE_WORKSPACE_CACHE_SEED_ID"],
              pins={"buildkit_image": pin, "job_image_id": job_image,
                    "docker_client": (directory / "docker-version").read_text().strip(),
                    "buildx": (directory / "buildx-version").read_text().strip(),
                    "workspace_dockerfile_sha256": value["inputs"]["images/workspace/Dockerfile"],
                    "base_dockerfile_sha256": value["inputs"]["images/base/Dockerfile"],
                    "rust_build_wrapper_sha256": value["inputs"]["scripts/ci/images/run-rust-build.sh"]})
(directory / "identity.json").write_text(json.dumps(header, sort_keys=True) + "\n")
PY
  workspace_cache_command python3 "$report_tool" sample-once "$docker_bin" "$builder_container" "$report_dir"
  timeout --signal=TERM --kill-after=3s 3300s \
    python3 "$report_tool" sample "$docker_bin" "$builder_container" "$report_dir" &
  sampler_pid=$!
fi

# Export the exact base as a local OCI layout. The workspace build consumes the
# exported manifest by digest through a named context, so this handoff neither
# relies on a daemon-local tag nor publishes an intermediate image.
workspace_cache_build base "$source_tree" "$architecture" "$build_log_root/base-build.log" \
  --pull \
  --metadata-file "$base_metadata" \
  --output "type=oci,dest=$base_layout,tar=false" \
  --file "$ROOT/images/base/Dockerfile" \
  "$ROOT/images/base"

base_digest="$(python3 - "$base_metadata" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as metadata_file:
    metadata = json.load(metadata_file)
digest = metadata.get("containerimage.digest", "")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("workspace image verification: base build returned no valid image digest")
print(digest)
PY
)"
readonly base_digest

workspace_cache_build workspace "$source_tree" "$architecture" "$build_log_root/workspace-build.log" \
  --pull \
  --metadata-file "$workspace_metadata" \
  --build-context "$base_context_name=oci-layout://$base_layout@$base_digest" \
  --tag "$workspace_tag" \
  --label "org.opencontainers.image.revision=$source_id" \
  --label "dev.codewire.source-tree=$source_tree" \
  --label "dev.codewire.workspace-contract=$contract_sha" \
  --label dev.codewire.build.profile=workspace-verify \
  --label dev.codewire.promotable=false \
  --provenance=false --sbom=false \
  --output "type=oci,dest=$workspace_archive" \
  --load \
  "${compiler_args[@]}" \
  --build-arg "BASE_IMAGE_REF=$base_context_name" \
  --file "$ROOT/images/workspace/Dockerfile" \
  "$ROOT"
chmod 0400 "$workspace_archive"

# Loaded runtime bytes do not depend on BuildKit. Remove its provider file and
# state before any runtime inspection or potentially slow agent command.
if [[ -n "$report_dir" ]]; then
  # Plain progress can hide a cache hit behind later lazy layer extraction.
  # Capture this exact completed build's native events before deleting its state.
  workspace_cache_timed_command 60s python3 "$report_tool" capture-history "$docker_bin" "$builder" "$report_dir"
  stop_sampler
  workspace_cache_command python3 "$report_tool" sample-once "$docker_bin" "$builder_container" "$report_dir"
fi
workspace_cache_cleanup_builder
workspace_cache_command "$docker_bin" image inspect "$workspace_tag" --format '{{.Id}}' >"$work/workspace-id"
workspace_id="$(<"$work/workspace-id")"
[[ "$workspace_id" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'invalid workspace image ID' >&2; exit 1; }
if [[ "$architecture" == amd64 ]]; then
  # Keep original source provenance and prove the installed bytes after the
  # owning builder/provider file is gone. This never executes incoming CW.
  cw_copy_started=true
  python3 "$artifact_tool" verify-cw "$ROOT" "$workspace_id" \
    "$build_log_root/cw-image-work/cw-producer-result.json"
  cw_copy_started=false
fi
contract_container="$builder-full"
workspace_cache_logged_command "$build_log_root/agents.log" "$docker_bin" run --rm --interactive --pids-limit=2048 \
  --name "$contract_container" --user 1000:1000 --entrypoint bash \
  "$workspace_id" -eu -s <"$ROOT/scripts/ci/verify/workspace-agent-contract.sh"
contract_container="$builder-mounted-home"
workspace_cache_logged_command "$build_log_root/mounted-home.log" "$docker_bin" run --rm --interactive --pids-limit=2048 \
  --name "$contract_container" --user 1000:1000 \
  --tmpfs /home/codewire:rw,exec,uid=1000,gid=1000,mode=0700,size=256m --entrypoint bash \
  "$workspace_id" -eu -s -- --mounted-home-agents <"$ROOT/scripts/ci/verify/workspace-agent-contract.sh"
contract_container=''
if [[ -n "$report_dir" ]]; then
  contract_container="$builder-floating-versions"
  workspace_cache_command "$docker_bin" run --rm --interactive --pids-limit=2048 \
    --name "$contract_container" --user codewire --entrypoint python3 \
    "$workspace_id" - versions <"$report_tool" >"$report_dir/versions.json"
  contract_container=''
fi

printf 'workspace image verification: base=%s workspace=%s\n' "$base_digest" "$workspace_tag"
printf 'CODEWIRE_CI_PHASE name=workspace-image-verification seconds=%s compiler=%s layers=%s layer_fallback=%s\n' \
  "$(( $(date +%s) - started_at ))" "$sccache_mode" "$layer_cache_mode" "$workspace_cache_fallback"
