#!/usr/bin/env bash
# Execute owned-daemon handling with a fake remote Docker API and synthetic key.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/workspace-cache-test.MixedCase.XXXXXX")"
credential_work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-workspace-cache-data.XXXXXX")"
trap 'rm -rf "$work" "$credential_work"' EXIT
mkdir "$work/bin"
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
    printf 'build\n' >>"$FAKE_BUILDS"
    if [[ "${FAKE_CANARY:-}" == hang ]]; then
      printf '%s\n' "$$" >"$FAKE_CANARY_PROCESS"
      sleep 30 &
      child_pid=$!
      printf '%s\n' "$child_pid" >"$FAKE_CANARY_CHILD"
      trap 'kill "$child_pid" 2>/dev/null || true; wait "$child_pid" 2>/dev/null || true; exit 143' TERM INT
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
      else printf '#7 DONE 0.1s\n'; fi
      [[ "$FAKE_CANARY" != export-failure ]] || echo 'ignoring error exporting cache to Amazon S3'
    fi
    case "${FAKE_FAILURE:-}" in
      cache) if [[ "$(wc -l <"$FAKE_BUILDS")" == 1 ]]; then
        echo 'ERROR failed to load cache key: S3 GetObject unavailable' >&2; exit 43; fi ;;
      compile) echo 'ERROR cargo compilation failed' >&2; exit 44 ;;
    esac ;;
  *)
    [[ "$1" == exec && "$3 $4 $5" == 'rm -f /run/codewire-cache/aws-credentials' ]] || exit 99
    [[ "${FAKE_FAILURE:-}" != erase ]] || exit 45
    rm -f "$FAKE_FILE" ;;
esac
SH
chmod 0755 "$work/bin/docker"
export FAKE_LOG="$work/docker.log" FAKE_FILE="$work/daemon.aws" FAKE_BUILDS="$work/builds"
export FAKE_NODE="$work/node-name"
export FAKE_PIN='docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
export CODEWIRE_SCCACHE_CREDENTIALS_FILE="$credential_work/r2.aws"
export SCCACHE_BUCKET=example-ci-cache-untrusted
export SCCACHE_ENDPOINT=https://00000000000000000000000000000000.r2.cloudflarestorage.com
export CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/v1
export PATH="$work/bin:$PATH"
# A non-executable fixture must fail, never fall through to a real Docker client.
export CODEWIRE_DOCKER_BIN="$work/bin/docker"
exercise() (
  set -euo pipefail
  source "$ROOT/scripts/ci/images/workspace-cache.sh"
  workspace_cache_validate
  trap 'workspace_cache_cleanup_builder' EXIT
  workspace_cache_create_builder "$work"
  if [[ "$layer_cache_mode" == r2 ]]; then cmp "$credential_work/r2.aws" "$FAKE_FILE"; fi
  workspace_cache_layer_args workspace 1111111111111111111111111111111111111111 amd64
  printf '%s\n' "${layer_args[@]}" >"$work/layer-args"
  workspace_cache_compiler_args
  printf '%s\n' "${compiler_args[@]}" >"$work/compiler-args"
  workspace_cache_build workspace 1111111111111111111111111111111111111111 amd64 "$work/build.log" --file synthetic .
  printf '%s\n' "$workspace_cache_fallback" >"$work/fallback"
)
for compiler in disabled local r2; do
  for layers in disabled local r2; do
    : >"$FAKE_LOG"; : >"$FAKE_BUILDS"
    CODEWIRE_SCCACHE_MODE="$compiler" CODEWIRE_BUILDKIT_CACHE_MODE="$layers" exercise >"$work/out"
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
  done
done
for failure in copy pin erase cleanup compile; do
  : >"$FAKE_LOG"; : >"$FAKE_BUILDS"
  set +e
  CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_BUILDKIT_CACHE_MODE=r2 FAKE_FAILURE="$failure" exercise >"$work/out" 2>&1
  status=$?
  set -e
  [[ "$status" != 0 ]] || { echo "accepted $failure failure" >&2; exit 1; }
  [[ -s "$credential_work/r2.aws" ]]
  [[ "$failure" != compile || "$(wc -l <"$FAKE_BUILDS")" == 1 ]]
done
: >"$FAKE_LOG"; : >"$FAKE_BUILDS"
CODEWIRE_SCCACHE_MODE=disabled CODEWIRE_BUILDKIT_CACHE_MODE=r2 FAKE_FAILURE=cache exercise >"$work/out"
[[ "$(wc -l <"$FAKE_BUILDS")" == 2 && "$(cat "$work/fallback")" == true ]]
tail -n 3 "$FAKE_LOG" | grep -q -- '--progress plain --no-cache --file synthetic'
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
cp "$credential_work/r2.aws" "$work/in-context.aws"
chmod 0600 "$work/in-context.aws"
if (
  source "$ROOT/scripts/ci/images/workspace-cache.sh"
  CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_BUILDKIT_CACHE_MODE=r2 CODEWIRE_SCCACHE_CREDENTIALS_FILE="$work/in-context.aws"
  workspace_cache_validate
) >"$work/context-rejection.out" 2>&1; then exit 1; fi
grep -q 'outside the build context' "$work/context-rejection.out"
# Run the actual bounded canary against the fake API. A generic CACHED line is
# insufficient: the COPY vertex in the second daemon must reuse remote data.
for canary in hit miss export-failure; do
  : >"$FAKE_LOG"; : >"$FAKE_BUILDS"
  set +e
  FAKE_CANARY="$canary" "$ROOT/scripts/ci/tests/canary-workspace-r2-cache.sh" \
    "$credential_work/r2.aws" "$work/report-$canary" >"$work/canary.out" 2>&1
  status=$?
  set -e
  if [[ "$canary" == hit ]]; then
    [[ "$status" == 0 && -s "$work/report-$canary/result.txt" ]]
    [[ "$(grep -c '^buildx create ' "$FAKE_LOG")" == 2 && "$(grep -c '^buildx rm ' "$FAKE_LOG")" == 2 ]]
  else
    [[ "$status" != 0 && ! -e "$work/report-$canary/result.txt" ]]
  fi
  [[ -s "$credential_work/r2.aws" && ! -e "$FAKE_FILE" ]]
done
export FAKE_CANARY_PROCESS="$work/canary-process" FAKE_CANARY_CHILD="$work/canary-child"
: >"$FAKE_LOG"; : >"$FAKE_BUILDS"
FAKE_CANARY=hang "$ROOT/scripts/ci/tests/canary-workspace-r2-cache.sh" \
  "$credential_work/r2.aws" "$work/report-cancel" >"$work/canary-cancel.out" 2>&1 &
canary_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
  [[ ! -s "$FAKE_CANARY_CHILD" ]] || break
  sleep 0.02
done
[[ -s "$FAKE_CANARY_CHILD" && -s "$FAKE_FILE" ]] || { kill -TERM "$canary_pid"; exit 1; }
kill -TERM "$canary_pid"
set +e
wait "$canary_pid"
status=$?
set -e
[[ "$status" != 0 && ! -e "$work/report-cancel/result.txt" && ! -e "$FAKE_FILE" ]]
grep -q 'exec .* rm -f /run/codewire-cache/aws-credentials' "$FAKE_LOG"
grep -q '^buildx rm --force codewire-workspace-' "$FAKE_LOG"
for pid_file in "$FAKE_CANARY_PROCESS" "$FAKE_CANARY_CHILD"; do
  child_pid="$(<"$pid_file")"
  # A reparented zombie cannot execute or access credentials; the host reaper
  # owns its final wait. No live mock Docker process or child may survive.
  state="$(ps -o stat= -p "$child_pid" || true)"
  [[ -z "$state" || "$state" == Z* ]] || { kill -TERM "$child_pid"; echo 'canary left a live child' >&2; exit 1; }
done
printf 'workspace cache: 9 mode pairs, owned daemon credentials, bounded retry and failure cleanup passed\n'
