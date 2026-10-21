#!/usr/bin/env bash
# Execute owned-daemon handling with a fake remote Docker API and synthetic key.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PRIMARY_ROOT="$ROOT"
# Cases below set the CI apt snapshot cache explicitly.
unset CODEWIRE_APT_SNAPSHOT_MIRROR
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/workspace-cache-test.MixedCase.XXXXXX")"
credential_work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-workspace-cache-data.XXXXXX")"
trap 'rm -rf "$work" "$credential_work"' EXIT
mkdir "$work/bin"
export CW_IMAGE_FIXTURES="$PRIMARY_ROOT/scripts/ci/tests/cw_image_fixtures.py"
python3 -B "$CW_IMAGE_FIXTURES" source "$work/source" >"$work/source-identity.json"
ROOT="$work/source"
source_tree="$(jq -er .source_tree "$work/source-identity.json")"
umask 077
printf '%s\n' '[default]' 'aws_access_key_id = synthetic-workspace-key' \
  'aws_secret_access_key = synthetic-workspace-secret' >"$credential_work/r2.aws"
cat >"$work/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$FAKE_LOG"; printf '\n' >>"$FAKE_LOG"
case "$1 $2" in
  'buildx create')
    node=''
    while (($#)); do
      if [[ "$1" == --node ]]; then node="$2"; shift; fi
      shift
    done
    [[ -n "$node" ]]
    # Real Buildx lowercases the node; Docker resolves its exact resulting name.
    printf '%s\n' "${node,,}" >"$FAKE_NODE" ;;
  'buildx inspect') ;;
  'container inspect')
    if [[ "$4" == --format && "$5" == '{{.Id}}' ]]; then
      [[ "$3" == "buildx_buildkit_$(<"$FAKE_NODE")" ]] || exit 46
      printf '%s' "$3" | sha256sum | cut -d ' ' -f 1
    elif [[ "${FAKE_FAILURE:-}" == pin ]]; then printf 'wrong-image\n'
    else printf '%s\n' "$FAKE_PIN"; fi ;;
  'exec --interactive')
    cat >"$FAKE_FILE"
    [[ "${FAKE_FAILURE:-}" != copy ]] || exit 41 ;;
  'buildx rm') [[ "${FAKE_FAILURE:-}" != cleanup ]] || exit 42 ;;
  'buildx build')
    if [[ " $* " == *' --target cw-runtime-export '* ]]; then
      printf 'producer\n' >>"$FAKE_CW_BUILDS"
      if [[ "${FAKE_FAILURE:-}" == compile ]]; then
        echo 'ERROR cargo compilation failed' >&2; exit 44
      fi
      exec python3 -B "$CW_IMAGE_FIXTURES" export -- "$@"
    fi
    printf 'build\n' >>"$FAKE_BUILDS"
    if [[ "${FAKE_CANARY:-}" == hang ]]; then
      printf '%s\n' "$$" >"$FAKE_CANARY_PROCESS"
      sleep "${FAKE_CANARY_READY_DELAY:-0}"
      sleep 30 &
      child_pid=$!
      # Arm the handler before publishing readiness: the test signals as
      # soon as the child file appears.
      trap 'kill "$child_pid" 2>/dev/null || true; wait "$child_pid" 2>/dev/null || true; exit 143' TERM INT
      printf '%s\n' "$child_pid" >"$FAKE_CANARY_CHILD"
      wait "$child_pid"
      exit 0
    fi
    if [[ -n "${FAKE_CANARY:-}" ]]; then
      destination=''
      for arg in "$@"; do
        case "$arg" in type=local,dest=*) destination="${arg#type=local,dest=}" ;; esac
      done
      mkdir -p "$destination"
      cp "${@: -1}/payload" "$destination/payload"
      printf '#7 [1/1] COPY payload /payload\n'
      if [[ "$FAKE_CANARY" == hit && "$(wc -l <"$FAKE_BUILDS")" == 2 ]]; then
        printf '#7 CACHED\n'
      elif [[ "$FAKE_CANARY" == lazy-hit || "$FAKE_CANARY" == lazy-wrong ]]; then
        digest=7
        [[ "$FAKE_CANARY" != lazy-wrong ]] || digest=8
        if [[ "$(wc -l <"$FAKE_BUILDS")" == 2 ]]; then
          printf '#7 sha256:%064d 0B / 8.39MB 0.1s\n' "$digest"
          printf '#7 sha256:%064d 8.39MB / 8.39MB 0.2s done\n' "$digest"
        else
          printf '#7 DONE 0.1s\n'
        fi
      else printf '#7 DONE 0.1s\n'; fi
      if [[ "$FAKE_CANARY" == lazy-* && "$(wc -l <"$FAKE_BUILDS")" == 1 ]]; then
        printf '#8 exporting cache to Amazon S3\n'
        printf '#8 writing layer sha256:%064d 0.1s done\n' 7
      fi
      [[ "$FAKE_CANARY" != export-failure ]] || echo 'ignoring error exporting cache to Amazon S3'
    fi
    case "${FAKE_FAILURE:-}" in
      cache) if [[ "$(wc -l <"$FAKE_BUILDS")" == 1 ]]; then
        echo 'ERROR: failed to solve: failed to load cache key: S3 GetObject unavailable' >&2; exit 1; fi ;;
      diagnostic)
        if [[ "$(wc -l <"$FAKE_BUILDS")" == 1 ]]; then
          cat "$FAKE_BUILD_DIAGNOSTIC" >&2
          exit "$FAKE_BUILD_STATUS"
        elif [[ "${FAKE_RETRY_STATUS:-0}" != 0 ]]; then
          echo 'ERROR: failed to solve: process "cargo build" did not complete successfully: exit code: 101' >&2
          exit "$FAKE_RETRY_STATUS"
        fi ;;
      compile) echo 'ERROR cargo compilation failed' >&2; exit 44 ;;
    esac
    if [[ -z "${FAKE_CANARY:-}" ]]; then
      printf '#7 [cw-builder 1/1] COPY admitted cw /usr/local/bin/cw\n#7 DONE 0.1s\n'
    fi ;;
  *)
    [[ "$1" == exec && "$3 $4 $5" == 'rm -f /run/codewire-cache/aws-credentials' ]] || exit 99
    [[ "${FAKE_FAILURE:-}" != erase ]] || exit 45
    rm -f "$FAKE_FILE" ;;
esac
SH
chmod 0755 "$work/bin/docker"
cat >"$work/bin/tee" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 && "$1" == /* ]] || exit 99
printf '%s\n' "$1" >>"$FAKE_TEE_CALLS"
fail=false
case "${FAKE_TEE_FAILURE:-}" in
  '') ;;
  first) [[ "$1" != "$FAKE_TEE_FIRST_LOG" ]] || fail=true ;;
  retry) [[ "$1" != "$FAKE_TEE_FIRST_LOG.retry" ]] || fail=true ;;
  *) exit 99 ;;
esac
if [[ "$fail" == true ]]; then
  # Retain the real diagnostic before simulating a late logger I/O failure.
  /usr/bin/tee "$@"
  exit 1
fi
exec /usr/bin/tee "$@"
SH
chmod 0755 "$work/bin/tee"
export FAKE_LOG="$work/docker.log" FAKE_FILE="$work/daemon.aws" FAKE_BUILDS="$work/builds"
export FAKE_CW_BUILDS="$work/cw-builds"
export FAKE_NODE="$work/node-name"
export FAKE_BUILD_DIAGNOSTIC="$work/diagnostic.log"
export FAKE_TEE_BIN="$work/bin/tee" FAKE_TEE_CALLS="$work/tee-calls" FAKE_TEE_FIRST_LOG="$work/build.log"
export FAKE_PIN='docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
export CODEWIRE_SCCACHE_CREDENTIALS_FILE="$credential_work/r2.aws"
export SCCACHE_BUCKET=example-ci-cache-untrusted
export SCCACHE_ENDPOINT=https://00000000000000000000000000000000.r2.cloudflarestorage.com
export CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/v1
export PATH="$work/bin:$PATH"
# A non-executable fixture must fail, never fall through to a real Docker client.
export CODEWIRE_DOCKER_BIN="$work/bin/docker"
# The helper's Bash child resolves this function to an absolute fake executable;
# a missing/non-executable fake must not fall through to another PATH entry.
tee() { exec "$FAKE_TEE_BIN" "$@"; }
export -f tee
exercise() (
  set -euo pipefail
  # Retries in one exercise share the admitted producer. A new owner exercise
  # gets fresh producer custody and cannot qualify from an earlier receipt.
  rm -rf "$work/cw-image-work"
  rm -f "$work/exercise-success" "$work/exercise-status" "$work/fallback" "$work/build.log.retry"
  source "$ROOT/scripts/ci/images/workspace-cache.sh"
  workspace_cache_validate
  # shellcheck disable=SC2329 # Invoked by the EXIT trap.
  finish_exercise() {
    local status=$? cleanup_status=0
    trap - EXIT
    workspace_cache_cleanup_builder || cleanup_status=$?
    [[ "$status" != 0 || "$cleanup_status" == 0 ]] || status="$cleanup_status"
    printf '%s\n' "$workspace_cache_fallback" >"$work/fallback"
    printf '%s\n' "$status" >"$work/exercise-status"
    # This marker models the caller's acceptance boundary after build/cleanup.
    # It is not a workspace image or prepush receipt; those have verifier tests.
    if [[ "$status" == 0 ]]; then printf 'accepted\n' >"$work/exercise-success"; fi
    exit "$status"
  }
  trap finish_exercise EXIT
  workspace_cache_create_builder "$work"
  if [[ "$layer_cache_mode" == r2 ]]; then cmp "$credential_work/r2.aws" "$FAKE_FILE"; fi
  workspace_cache_layer_args workspace "$source_tree" amd64
  printf '%s\n' "${layer_args[@]}" >"$work/layer-args"
  workspace_cache_compiler_args
  printf '%s\n' "${compiler_args[@]}" >"$work/compiler-args"
  workspace_cache_build "${EXERCISE_TARGET:-workspace}" "$source_tree" amd64 "$work/build.log" \
    --file "$ROOT/images/workspace/Dockerfile" "$ROOT"
)
for compiler in disabled local r2; do
  for layers in disabled local r2; do
    : >"$FAKE_LOG"; : >"$FAKE_BUILDS"; : >"$FAKE_CW_BUILDS"
    CODEWIRE_SCCACHE_MODE="$compiler" CODEWIRE_BUILDKIT_CACHE_MODE="$layers" exercise >"$work/out" 2>&1 || {
      cat "$work/out" >&2; exit 1;
    }
    [[ "$(wc -l <"$FAKE_CW_BUILDS")" == 1 && "$(wc -l <"$FAKE_BUILDS")" == 1 ]]
    [[ -s "$work/cw-image-work/cw-producer-result.json" ]]
    [[ -f "$credential_work/r2.aws" && ! -e "$FAKE_FILE" ]]
    grep -Fq -- '--driver-opt image=docker.io/moby/buildkit:v0.29.0@sha256:' "$FAKE_LOG"
    grep -q '^buildx rm --force codewire-workspace-' "$FAKE_LOG"
    if [[ "$layers" == r2 ]]; then
      grep -q '^exec --interactive ' "$FAKE_LOG"
      grep -q 'prefix=untrusted/codewire/buildkit/v1/' "$work/layer-args"
      grep -q 'mode=max.*ignore-error=true' "$work/layer-args"
    else
      ! grep -q '^exec ' "$FAKE_LOG" || exit 1
      ! grep -q -- '--cache-' "$work/layer-args" || exit 1
    fi
    if [[ "$layers" == disabled ]]; then
      grep -Fxq -- '--no-cache' "$work/layer-args"
      ! grep -q -- '--no-cache-filter' "$work/layer-args" || exit 1
    else
      grep -Fxq -- workspace-floating-tools "$work/layer-args"
    fi
    if [[ "$compiler" == r2 ]]; then grep -q 'id=aws_shared_credentials,src=' "$work/compiler-args"
    else ! grep -q -- '--secret' "$work/compiler-args" || exit 1; fi
    ! grep -Eq 'synthetic-workspace-(key|secret)' "$FAKE_LOG" "$work/out" "$work/layer-args" "$work/compiler-args" "$work/buildkitd.toml" || exit 1
    ! grep -q 'codewire-apt-mirror' "$FAKE_LOG" || exit 1
  done
done
# A canonical-main selection reads and writes only the main bucket and its
# prefixes; a mixed main bucket and untrusted prefix is refused.
: >"$FAKE_LOG"; : >"$FAKE_BUILDS"; : >"$FAKE_CW_BUILDS"
CODEWIRE_R2_CACHE_TRUST=main SCCACHE_BUCKET=example-ci-cache-protected CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1 \
  CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_BUILDKIT_CACHE_MODE=r2 exercise >"$work/out" 2>&1 || {
  cat "$work/out" >&2; exit 1;
}
grep -q 'bucket=example-ci-cache-protected,.*prefix=protected/codewire/buildkit/v1/' "$work/layer-args"
grep -q -- '--cache-to' "$work/layer-args"
grep -Fxq -- 'SCCACHE_BUCKET=example-ci-cache-protected' "$work/compiler-args"
grep -Fxq -- 'CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1' "$work/compiler-args"
! grep -q untrusted "$work/layer-args" "$work/compiler-args" || exit 1
if CODEWIRE_R2_CACHE_TRUST=main SCCACHE_BUCKET=example-ci-cache-protected CODEWIRE_SCCACHE_MODE=r2 \
    CODEWIRE_BUILDKIT_CACHE_MODE=r2 exercise >"$work/out" 2>&1; then
  exit 1
fi
grep -Fq 'workspace cache requires the reviewed main R2 configuration' "$work/out"
# A pull request imports main's layers read-only and exports nothing remote,
# and never runs a cache measurement against the main bucket.
: >"$FAKE_LOG"; : >"$FAKE_BUILDS"; : >"$FAKE_CW_BUILDS"
CODEWIRE_R2_CACHE_TRUST=protected-read SCCACHE_BUCKET=example-ci-cache-protected CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1 \
  GITHUB_REF=refs/pull/2047/head CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_BUILDKIT_CACHE_MODE=r2 exercise >"$work/out" 2>&1 || {
  cat "$work/out" >&2; exit 1;
}
grep -q -- '--cache-from' "$work/layer-args"
grep -q 'bucket=example-ci-cache-protected,.*name=amd64/workspace/main$' "$work/layer-args"
! grep -q -- '--cache-to' "$work/layer-args" || exit 1
! grep -q -- '--cache-to' "$FAKE_BUILDS" "$FAKE_CW_BUILDS" || exit 1
! grep -q 'pr-2047' "$work/layer-args" || exit 1
if CODEWIRE_R2_CACHE_TRUST=protected-read SCCACHE_BUCKET=example-ci-cache-protected CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1 \
    CODEWIRE_WORKSPACE_CACHE_CASE=seed CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_BUILDKIT_CACHE_MODE=r2 \
    exercise >"$work/out" 2>&1; then
  exit 1
fi
grep -Fq 'workspace cache measurements use only the untrusted bucket' "$work/out"
# The CI apt snapshot cache reaches only base and workspace builds, as an
# optional secret named by environment, and never as an argument value.
readonly apt_mirror_secret=' --secret id=codewire-apt-mirror\,env=CODEWIRE_APT_SNAPSHOT_MIRROR '
for target in base workspace canary-probe; do
  for mirror in '' http://apt-cache.invalid:8080; do
    : >"$FAKE_LOG"; : >"$FAKE_BUILDS"
    CODEWIRE_APT_SNAPSHOT_MIRROR="$mirror" EXERCISE_TARGET="$target" \
      CODEWIRE_SCCACHE_MODE=disabled CODEWIRE_BUILDKIT_CACHE_MODE=local exercise >"$work/out"
    expected=0
    [[ -z "$mirror" || "$target" == canary-probe ]] || expected=1
    [[ "$(grep '^buildx build ' "$FAKE_LOG" | grep -cF -- "$apt_mirror_secret" || true)" == "$expected" ]] || {
      echo "apt snapshot secret for target=$target mirror=${mirror:-unset} is not $expected" >&2; exit 1;
    }
    ! grep -q 'apt-cache.invalid' "$FAKE_LOG" "$work/out" || exit 1
  done
done
# The no-cache retry after a remote layer read failure keeps the secret.
: >"$FAKE_LOG"; : >"$FAKE_BUILDS"
CODEWIRE_APT_SNAPSHOT_MIRROR=http://apt-cache.invalid:8080 \
  CODEWIRE_SCCACHE_MODE=disabled CODEWIRE_BUILDKIT_CACHE_MODE=r2 FAKE_FAILURE=cache exercise >"$work/out"
[[ "$(wc -l <"$FAKE_BUILDS")" == 2 && "$(cat "$work/fallback")" == true ]]
[[ "$(grep '^buildx build ' "$FAKE_LOG" | grep -cF -- "$apt_mirror_secret")" == 2 ]]
grep '^buildx build ' "$FAKE_LOG" | tail -n 1 | grep -qF -- "--no-cache$apt_mirror_secret--file "
# The measured warm workers import only their successful producer. Their own
# exports are distinct, so neither parallel replicate can seed the other.
measurement_args() (
  source "$ROOT/scripts/ci/images/workspace-cache.sh"
  CODEWIRE_WORKSPACE_CACHE_CASE="$1" CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_BUILDKIT_CACHE_MODE=r2
  workspace_cache_validate
  builder_container="$(printf '%064d' "$2")"
  GITHUB_RUN_ID=2047
  CODEWIRE_WORKSPACE_CACHE_SEED_ID="run-2047/tree-1111111111111111111111111111111111111111/seed-$(printf '%064d' 1)"
  workspace_cache_layer_args workspace 1111111111111111111111111111111111111111 amd64
  printf '%s\n' "${layer_args[@]}"
)
for measurement in seed warm-1 warm-2; do
  measurement_args "$measurement" 2 >"$work/$measurement.args"
  grep -q 'ignore-error=false' "$work/$measurement.args"
  grep -Fxq workspace-floating-tools "$work/$measurement.args"
done
for measurement in warm-1 warm-2; do
  awk 'previous == "--cache-from" { print } { previous = $0 }' "$work/$measurement.args" >"$work/$measurement.imports"
  [[ "$(wc -l <"$work/$measurement.imports")" == 1 ]]
  grep -q "name=amd64/workspace/experiments/run-2047/tree-1111111111111111111111111111111111111111/seed-$(printf '%064d' 1)$" \
    "$work/$measurement.imports"
  grep -q "seed-$(printf '%064d' 1)/$measurement-$(printf '%064d' 2),mode=max" "$work/$measurement.args"
done
cmp "$work/warm-1.imports" "$work/warm-2.imports"
if cmp -s "$work/warm-1.args" "$work/warm-2.args"; then echo 'warm exports overlap' >&2; exit 1; fi
for failure in mode run tree; do
  if (
    source "$ROOT/scripts/ci/images/workspace-cache.sh"
    CODEWIRE_WORKSPACE_CACHE_CASE=warm-1 CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_BUILDKIT_CACHE_MODE=r2
    [[ "$failure" != mode ]] || CODEWIRE_SCCACHE_MODE=local
    workspace_cache_validate || exit
    builder_container="$(printf '%064d' 2)" GITHUB_RUN_ID=2047
    CODEWIRE_WORKSPACE_CACHE_SEED_ID="run-2047/tree-1111111111111111111111111111111111111111/seed-$(printf '%064d' 1)"
    [[ "$failure" != run ]] || GITHUB_RUN_ID=2048
    tree=1111111111111111111111111111111111111111
    [[ "$failure" != tree ]] || tree=2222222222222222222222222222222222222222
    workspace_cache_layer_args workspace "$tree" amd64
  ) >/dev/null 2>&1; then echo "accepted invalid measurement $failure" >&2; exit 1; fi
done
for failure in copy pin erase cleanup compile; do
  : >"$FAKE_LOG"; : >"$FAKE_BUILDS"; : >"$FAKE_CW_BUILDS"
  set +e
  CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_BUILDKIT_CACHE_MODE=r2 FAKE_FAILURE="$failure" exercise >"$work/out" 2>&1
  status=$?
  set -e
  [[ "$status" != 0 ]] || { echo "accepted $failure failure" >&2; exit 1; }
  [[ -s "$credential_work/r2.aws" ]]
  [[ "$failure" != compile || ( "$(wc -l <"$FAKE_CW_BUILDS")" == 1 && ! -s "$FAKE_BUILDS" ) ]]
done
: >"$FAKE_LOG"; : >"$FAKE_BUILDS"; : >"$FAKE_CW_BUILDS"
CODEWIRE_SCCACHE_MODE=disabled CODEWIRE_BUILDKIT_CACHE_MODE=r2 FAKE_FAILURE=cache exercise >"$work/out"
[[ "$(wc -l <"$FAKE_BUILDS")" == 2 && "$(cat "$work/fallback")" == true ]]
[[ "$(wc -l <"$FAKE_CW_BUILDS")" == 1 ]]
grep '^buildx build ' "$FAKE_LOG" | tail -1 | grep -q -- '--progress plain --platform linux/amd64 --no-cache --file '

# Exercise the actual command wrapper, not only its diagnostic predicate. A
# rejected first attempt must retain its status and still erase/remove its
# owned daemon; an accepted cache read retries exactly once without imports.
diagnostic_cases=0
read_failure_case() {
  local name="$1" first_status="$2" expected_status="$3" expected_builds="$4" expected_fallback="$5"
  local diagnostic="$6" retry_status="${7:-0}" tee_failure="${8:-}" status
  : >"$FAKE_LOG"; : >"$FAKE_BUILDS"; : >"$FAKE_CW_BUILDS"; : >"$FAKE_TEE_CALLS"
  printf '%s' "$diagnostic" >"$FAKE_BUILD_DIAGNOSTIC"
  set +e
  CODEWIRE_SCCACHE_MODE=disabled CODEWIRE_BUILDKIT_CACHE_MODE=r2 FAKE_FAILURE=diagnostic \
    FAKE_BUILD_STATUS="$first_status" FAKE_RETRY_STATUS="$retry_status" FAKE_TEE_FAILURE="$tee_failure" \
    exercise >"$work/out" 2>&1
  status=$?
  set -e
  if [[ "$status" != "$expected_status" || "$(wc -l <"$FAKE_BUILDS")" != "$expected_builds" \
      || "$(<"$work/fallback")" != "$expected_fallback" || "$(<"$work/exercise-status")" != "$expected_status" ]]; then
    printf 'read failure case %s: status=%s builds=%s fallback=%s; expected %s/%s/%s\n' \
      "$name" "$status" "$(wc -l <"$FAKE_BUILDS")" "$(<"$work/fallback")" \
      "$expected_status" "$expected_builds" "$expected_fallback" >&2
    cat "$work/out" >&2
    exit 1
  fi
  [[ "$(grep -c '^buildx create ' "$FAKE_LOG")" == 1 && "$(grep -c '^buildx rm --force ' "$FAKE_LOG")" == 1 ]]
  [[ "$(grep -c 'exec .* rm -f /run/codewire-cache/aws-credentials' "$FAKE_LOG")" == 1 ]]
  [[ "$(wc -l <"$FAKE_TEE_CALLS")" == "$expected_builds" ]]
  [[ "$(wc -l <"$FAKE_CW_BUILDS")" == 1 ]]
  # The outer log also contains producer/bridge diagnostics. Preserve the
  # exact original diagnostic bytes in the actual owned consumer log.
  diagnostic_retained=false
  while IFS= read -r consumer_log; do
    if cmp -s "$FAKE_BUILD_DIAGNOSTIC" "$consumer_log"; then diagnostic_retained=true; fi
  done < <(find "$work/cw-image-work" -path '*/solve/build.log' -type f)
  [[ "$diagnostic_retained" == true ]]
  [[ -s "$credential_work/r2.aws" && ! -e "$FAKE_FILE" ]]
  if [[ -n "$tee_failure" ]]; then
    grep -Fxq 'workspace cache build: log capture failed' "$work/out"
  fi
  if [[ "$expected_status" == 0 ]]; then
    [[ -s "$work/exercise-success" ]]
  else
    [[ ! -e "$work/exercise-success" ]]
  fi
  if [[ "$expected_fallback" == true ]]; then
    [[ -f "$work/build.log.retry" ]]
    grep '^buildx build ' "$FAKE_LOG" | tail -n 1 >"$work/retry-command"
    grep -q -- '--progress plain --platform linux/amd64 --no-cache --file ' "$work/retry-command"
    ! grep -Eq -- '--cache-(from|to)|--no-cache-filter' "$work/retry-command" || exit 1
  else
    [[ ! -e "$work/build.log.retry" ]]
  fi
  diagnostic_cases=$((diagnostic_cases + 1))
}

canonical='ERROR: failed to solve: failed to load cache key: S3 GetObject unavailable'
# tee's exit 1 must not hide a Docker timeout/signal or ordinary error and
# turn a failed capture into the accepted cache-read retry status.
for status in 124 137 143 1; do
  read_failure_case "first-logger-failure-$status" "$status" 74 1 false "$canonical"$'\n' 0 first
done
read_failure_case retry-logger-failure 1 74 2 true "$canonical"$'\n' 0 retry
read_failure_case retry-logger-failure-with-docker-signal 1 74 2 true "$canonical"$'\n' 143 retry
for status in 124 137 143 43; do
  read_failure_case "status-$status" "$status" "$status" 1 false "$canonical"
done
read_failure_case earlier-warning-cargo 1 1 1 false \
  $'#7 ERROR: failed to load cache key: S3 GetObject unavailable\nerror: could not compile `cw` due to 1 previous error\n'
read_failure_case earlier-warning-buildx 1 1 1 false \
  $'#7 ERROR: failed to load cache key: S3 GetObject unavailable\nERROR: failed to solve: process "cargo build" did not complete successfully: exit code: 101\n'
read_failure_case missing-final-diagnostic 1 1 1 false \
  $'#7 ERROR: failed to load cache key: S3 GetObject unavailable\n'
read_failure_case empty-diagnostic 1 1 1 false ''
read_failure_case trailing-diagnostic 1 1 1 false \
  "$canonical"$'\nSee build details: docker-desktop://dashboard/build/example\n'
read_failure_case multiline-diagnostic 1 1 1 false \
  $'ERROR: failed to solve: failed to load cache key:\n  S3 GetObject unavailable\n'
read_failure_case unknown-final-diagnostic 1 1 1 false \
  'ERROR: failed to solve: unexpected cache failure: S3 GetObject unavailable'
read_failure_case split-cache-markers 1 1 1 false \
  $'#7 S3 GetObject unavailable\nERROR: failed to solve: failed to load cache key: descriptor unavailable\n'
read_failure_case noncanonical-prefix 1 1 1 false \
  'ERROR failed to load cache key: S3 GetObject unavailable'
read_failure_case debug-prefix 1 1 1 false \
  "time=2026-09-07T00:00:00Z level=error msg=\"$canonical\""
for diagnostic in \
  'context canceled' \
  'context cancelled' \
  'context deadline exceeded' \
  'process "cargo build" did not complete successfully' \
  'frontend gateway failed' \
  'failed to export cache'; do
  read_failure_case "excluded-$diagnostic" 1 1 1 false "$canonical: $diagnostic"
done
read_failure_case canonical-key 1 0 2 true "$canonical"
read_failure_case canonical-buildx-wrapper 1 0 2 true \
  'ERROR: failed to build: failed to solve: failed to load cache key: S3 GetObject unavailable'
read_failure_case canonical-cache-without-key 1 0 2 true \
  'ERROR: failed to solve: failed to load cache: S3 GetObject unavailable'
read_failure_case canonical-configure-importer 1 0 2 true \
  'ERROR: failed to solve: failed to configure s3 cache importer: operation error S3: HeadObject denied'
read_failure_case canonical-import-cache 1 0 2 true \
  'ERROR: failed to solve: failed to import cache: HeadObject denied'
read_failure_case canonical-r2-endpoint 1 0 2 true \
  'ERROR: failed to solve: failed to load cache key: request to https://example.r2.cloudflarestorage.com failed'
read_failure_case canonical-trailing-whitespace 1 0 2 true "$canonical"$'\n \t\n'
read_failure_case retry-fails 1 44 2 true "$canonical" 44
read_failure_case retry-fails-with-status-one 1 1 2 true "$canonical" 1

for failure in mode scope symlink permissions; do
  if (
    source "$ROOT/scripts/ci/images/workspace-cache.sh"
    CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_BUILDKIT_CACHE_MODE=r2
    case "$failure" in
      mode) CODEWIRE_BUILDKIT_CACHE_MODE=auto ;;
      scope) CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1 ;;
      symlink) ln -s "$credential_work/r2.aws" "$work/link.aws"; CODEWIRE_SCCACHE_CREDENTIALS_FILE="$work/link.aws" ;;
      permissions) chmod 0644 "$credential_work/r2.aws" ;;
    esac
    workspace_cache_validate
  ) >/dev/null 2>&1; then echo "accepted $failure configuration" >&2; exit 1; fi
done
chmod 0600 "$credential_work/r2.aws"
cp "$credential_work/r2.aws" "$ROOT/in-context.aws"
chmod 0600 "$ROOT/in-context.aws"
if (
  source "$ROOT/scripts/ci/images/workspace-cache.sh"
  CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_BUILDKIT_CACHE_MODE=r2 CODEWIRE_SCCACHE_CREDENTIALS_FILE="$ROOT/in-context.aws"
  workspace_cache_validate
) >"$work/context-rejection.out" 2>&1; then exit 1; fi
grep -q 'outside the build context' "$work/context-rejection.out"
# Run the actual bounded canary against the fake API. A generic CACHED line is
# insufficient: the COPY vertex in the second daemon must reuse remote data.
for canary in hit lazy-hit lazy-wrong miss export-failure; do
  : >"$FAKE_LOG"; : >"$FAKE_BUILDS"
  set +e
  FAKE_CANARY="$canary" "$ROOT/scripts/ci/tests/canary-workspace-r2-cache.sh" \
    "$credential_work/r2.aws" "$work/report-$canary" >"$work/canary.out" 2>&1
  status=$?
  set -e
  if [[ "$canary" == hit || "$canary" == lazy-hit ]]; then
    [[ "$status" == 0 && -s "$work/report-$canary/result.txt" ]]
    [[ "$(grep -c '^buildx create ' "$FAKE_LOG")" == 2 && "$(grep -c '^buildx rm ' "$FAKE_LOG")" == 2 ]]
  else
    [[ "$status" != 0 && ! -e "$work/report-$canary/result.txt" ]]
  fi
  [[ -s "$credential_work/r2.aws" && ! -e "$FAKE_FILE" ]]
done
export FAKE_CANARY_PROCESS="$work/canary-process" FAKE_CANARY_CHILD="$work/canary-child"
# True once the recorded process has exited. A reparented zombie cannot
# execute or access credentials; the host reaper owns its final wait.
process_gone() {
  local state
  state="$(ps -o stat= -p "$1" 2>/dev/null || true)"
  [[ -z "$state" || "$state" == Z* ]]
}
# Poll a condition for at most ten seconds; never assume a fixed delay.
eventually() {
  local attempt
  for ((attempt=0; attempt<200; attempt++)); do
    "$@" && return 0
    sleep 0.05
  done
  "$@"
}
credential_erased() { [[ ! -e "$FAKE_FILE" ]]; }
# Cancel a hanging canary, then check each cleanup guarantee separately. GNU
# timeout delivers the signal it receives twice, to the canary and then to its
# whole process group, and under load the second can arrive while the canary's
# signal trap is already running (#3079). The repeated mode keeps signalling
# the group until the canary exits, so any window in which a later TERM can
# cut cleanup short is hit.
cancel_canary() {
  local mode="$1" canary_pid status pid_file
  : >"$FAKE_LOG"; : >"$FAKE_BUILDS"; rm -f "$FAKE_CANARY_CHILD"
  rm -rf "$work/report-cancel"
  FAKE_CANARY=hang FAKE_CANARY_READY_DELAY=3 \
    "$ROOT/scripts/ci/tests/canary-workspace-r2-cache.sh" \
    "$credential_work/r2.aws" "$work/report-cancel" >"$work/canary-cancel.out" 2>&1 &
  canary_pid=$!
  if ! eventually test -s "$FAKE_CANARY_CHILD" || [[ ! -s "$FAKE_FILE" ]]; then
    kill -TERM "$canary_pid" 2>/dev/null || true
    wait "$canary_pid" 2>/dev/null || true
    echo "cache canary ($mode) did not publish cancellation readiness within ten seconds" >&2
    return 1
  fi
  kill -TERM "$canary_pid"
  if [[ "$mode" == repeated ]]; then
    # The bounded canary leads its own process group (GNU timeout's setpgid).
    while kill -TERM -- "-$canary_pid" 2>/dev/null; do :; done
  fi
  set +e
  wait "$canary_pid"
  status=$?
  set -e
  for pid_file in "$FAKE_CANARY_PROCESS" "$FAKE_CANARY_CHILD"; do
    eventually process_gone "$(<"$pid_file")" || {
      kill -TERM "$(<"$pid_file")" 2>/dev/null || true
      echo "cache canary ($mode) left a live child" >&2
      return 1
    }
  done
  eventually credential_erased || {
    echo "cache canary ($mode) cancellation left the daemon credential" >&2; return 1;
  }
  [[ "$status" != 0 ]] || { echo "cache canary ($mode) cancellation reported success" >&2; return 1; }
  [[ ! -e "$work/report-cancel/result.txt" ]] || {
    echo "cache canary ($mode) cancellation left a success report" >&2; return 1;
  }
  grep -q 'exec .* rm -f /run/codewire-cache/aws-credentials' "$FAKE_LOG"
  grep -q '^buildx rm --force codewire-workspace-' "$FAKE_LOG"
}
cancel_canary single
cancel_canary repeated
printf 'workspace cache: 9 mode pairs, 7 apt snapshot cases, %s diagnostic cases, owned daemon credentials, bounded retry and failure cleanup passed\n' \
  "$diagnostic_cases"
