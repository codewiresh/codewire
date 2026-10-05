#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT

fail() {
  printf '[test-build-push-runtime-images] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/build-push-runtime-images.XXXXXX")"
trap 'rm -rf "$work"' EXIT
fixture="$work/fixture"
mkdir -p "$fixture/scripts/ci/images" "$fixture/bin" "$fixture/tmp"
cp "$ROOT/scripts/ci/images/build-push-runtime-images.sh" \
  "$fixture/scripts/ci/images/build-push-runtime-images.sh"
cp "$ROOT/scripts/ci/images/nexus-publication-retry-contract.sh" \
  "$fixture/scripts/ci/images/nexus-publication-retry-contract.sh"
mkdir -p "$fixture/scripts/ci/setup"
cat >"$fixture/scripts/ci/setup/fetch-openbao-harbor-credentials.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' 'robot$codewire+publisher' >"$1"
printf '%s\n' 'synthetic-harbor-password' >"$2"
SH
chmod 0755 "$fixture/scripts/ci/setup/fetch-openbao-harbor-credentials.sh"

cat >"$fixture/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$DOCKER_LOG"
if [ "${1:-}" = login ]; then
  cat >/dev/null
  exit 0
fi
if [ "${1:-} ${2:-} ${3:-}" = 'buildx imagetools inspect' ]; then
  reference="${!#}"
  if [ -n "${FAKE_BASELINE_SHA:-}" ] && [[ "$reference" == *":$FAKE_BASELINE_SHA" ]]; then
    family="$(basename "${reference%:*}")"
    if [ "${FAKE_MISSING_BASELINE_IMAGE:-}" = "$family" ]; then
      printf 'manifest unknown\n' >&2
      exit 1
    fi
    printf '{"digest":"sha256:%s"}\n' \
      "$(printf '%s' "$reference" | sha256sum | cut -d' ' -f1)"
    exit 0
  fi
  printf 'manifest unknown\n' >&2
  exit 1
fi
if [ "${1:-} ${2:-} ${3:-}" = 'buildx imagetools create' ]; then
  exit 0
fi
if [ "${1:-} ${2:-} ${3:-}" = 'image inspect --format' ]; then
  case "${4:-}" in
    *dev.codewire.build.profile*) printf '%s\n' release ;;
    *dev.codewire.promotable*) printf '%s\n' true ;;
    *org.opencontainers.image.revision*)
      reference="${5:-}"
      family="${reference#codewire-}"
      family="${family%:e2e}"
      if [ -n "${CARRIED_FAMILIES_FILE:-}" ] && grep -qx "$family" "$CARRIED_FAMILIES_FILE"; then
        printf '%s\n' "${FAKE_BASELINE_SHA:?}"
      else
        printf '%s\n' 0123456789abcdef0123456789abcdef01234567
      fi
      ;;
    '{{.Id}}') printf '%s\n' sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
    *) exit 64 ;;
  esac
fi
SH
chmod 0755 "$fixture/bin/docker"

cat >"$fixture/bin/sleep" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$SLEEP_LOG"
SH
chmod 0755 "$fixture/bin/sleep"

cat >"$fixture/scripts/ci/images/build-push-image.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
name="$1"
if [ "${FAKE_TRANSIENT_REGISTRY_IMAGE:-}" = "$name" ]; then
  state="${FAKE_TRANSIENT_REGISTRY_STATE:?}"
  failures="${FAKE_TRANSIENT_REGISTRY_FAILURES:-1}"
  count="$(cat "$state")"
  if [ "$count" -lt "$failures" ]; then
    printf '%s\n' "$((count + 1))" >"$state"
    if [ "$count" -eq 0 ]; then
      printf 'unexpected status from HEAD request to https://registry.example.invalid/v2/codewire/%s/blobs/sha256:test: 503 Service Temporarily Unavailable\n' \
        "$name" >&2
    else
      printf 'login attempt to https://registry.example.invalid/v2/ failed with status: 503 Service Unavailable\n' >&2
    fi
    exit 1
  fi
fi
if [ "${FAKE_FATAL_IMAGE:-}" = "$name" ]; then
  printf 'non-retryable protected build failure\n' >&2
  exit 1
fi
printf '%s|%s|%s|%s|%s|%s\n' \
  "$name" "$CODEWIRE_EXTERNAL_BUILDX_BUILDER" \
  "$CODEWIRE_EXTERNAL_DOCKER_CONFIG" "$CODEWIRE_SCCACHE_MODE" \
  "$CODEWIRE_PROVENANCE_BUILDER_ID" "${CODEWIRE_BUILD_RUNTIME_SET:-0}" >>"$BUILD_LOG"
printf 'candidate_ref=registry.example.invalid/codewire/%s@sha256:%064d\n' \
  "$name" 0 >>"$GITHUB_OUTPUT"
SH
chmod 0755 "$fixture/scripts/ci/images/build-push-image.sh"

output="$work/output"
docker_log="$work/docker.log"
build_log="$work/build.log"
sleep_log="$work/sleep.log"
: >"$sleep_log"
(
  cd "$fixture"
  PATH="$fixture/bin:$PATH" \
    RUNNER_TEMP="$fixture/tmp" \
    DOCKER_LOG="$docker_log" \
    BUILD_LOG="$build_log" \
    SLEEP_LOG="$sleep_log" \
    GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
    GITHUB_RUN_ID=42 \
    GITHUB_RUN_ATTEMPT=3 \
    GITHUB_OUTPUT="$output" \
    CODEWIRE_SCCACHE_MODE=local \
    scripts/ci/images/build-push-runtime-images.sh
)

[[ "$(wc -l <"$output" | tr -d ' ')" -eq 10 ]] ||
  fail "wrapper did not emit exactly ten runtime outputs"
[[ "$(wc -l <"$build_log" | tr -d ' ')" -eq 5 ]] ||
  fail "wrapper did not verify exactly five product images"
for family in dashboard derp gateway mesh services; do
  grep -Eq "^${family}_candidate_ref=.*${family}@sha256:[0-9a-f]{64}$" "$output" ||
    fail "wrapper omitted exact $family output"
  grep -qx "${family}_built_from=0123456789abcdef0123456789abcdef01234567" "$output" ||
    fail "wrapper omitted the head built-from source for built $family"
done

transient_output="$work/transient-output"
transient_docker_log="$work/transient-docker.log"
transient_build_log="$work/transient-build.log"
transient_sleep_log="$work/transient-sleep.log"
transient_state="$work/transient-state"
printf '0\n' >"$transient_state"
: >"$transient_sleep_log"
(
  cd "$fixture"
  PATH="$fixture/bin:$PATH" \
    RUNNER_TEMP="$fixture/tmp" \
    DOCKER_LOG="$transient_docker_log" \
    BUILD_LOG="$transient_build_log" \
    SLEEP_LOG="$transient_sleep_log" \
    FAKE_TRANSIENT_REGISTRY_IMAGE=mesh \
    FAKE_TRANSIENT_REGISTRY_FAILURES=2 \
    FAKE_TRANSIENT_REGISTRY_STATE="$transient_state" \
    GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
    GITHUB_RUN_ID=43 \
    GITHUB_RUN_ATTEMPT=1 \
    GITHUB_OUTPUT="$transient_output" \
    CODEWIRE_SCCACHE_MODE=local \
    scripts/ci/images/build-push-runtime-images.sh
)
[[ "$(wc -l <"$transient_output" | tr -d ' ')" -eq 10 ]] ||
  fail "transient registry recovery did not emit the exact five-image set with built-from sources"
[[ "$(wc -l <"$transient_build_log" | tr -d ' ')" -eq 5 ]] ||
  fail "transient registry recovery rebuilt a successful image"
[[ "$(cat "$transient_state")" -eq 2 ]] ||
  fail "transient registry recovery did not observe both injected failures"
[[ "$(grep -c '^60$' "$transient_sleep_log")" -eq 2 ]] ||
  fail "transient registry recovery did not use the fixed retry delay"

fatal_state="$work/fatal-state"
printf '0\n' >"$fatal_state"
if (
  cd "$fixture"
  PATH="$fixture/bin:$PATH" \
    RUNNER_TEMP="$fixture/tmp" \
    DOCKER_LOG="$work/fatal-docker.log" \
    BUILD_LOG="$work/fatal-build.log" \
    SLEEP_LOG="$work/fatal-sleep.log" \
    FAKE_FATAL_IMAGE=mesh \
    GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
    GITHUB_RUN_ID=44 \
    GITHUB_RUN_ATTEMPT=1 \
    GITHUB_OUTPUT="$work/fatal-output" \
    CODEWIRE_SCCACHE_MODE=local \
    scripts/ci/images/build-push-runtime-images.sh
) >"$work/fatal.stdout" 2>"$work/fatal.stderr"; then
  fail "non-retryable protected build failure was accepted"
fi
[[ ! -s "$work/fatal-sleep.log" ]] ||
  fail "non-retryable protected build failure entered the registry retry loop"
grep -Fq 'non-retryable protected build failure' "$work/fatal.stdout" ||
  fail "non-retryable protected build failure was not observable"

maintenance_output="$work/maintenance-output"
maintenance_state="$work/maintenance-state"
maintenance_sleep_log="$work/maintenance-sleep.log"
printf '0\n' >"$maintenance_state"
: >"$maintenance_sleep_log"
(
  cd "$fixture"
  PATH="$fixture/bin:$PATH" \
    RUNNER_TEMP="$fixture/tmp" \
    DOCKER_LOG="$work/maintenance-docker.log" \
    BUILD_LOG="$work/maintenance-build.log" \
    SLEEP_LOG="$maintenance_sleep_log" \
    FAKE_TRANSIENT_REGISTRY_IMAGE=mesh \
    FAKE_TRANSIENT_REGISTRY_FAILURES=60 \
    FAKE_TRANSIENT_REGISTRY_STATE="$maintenance_state" \
    GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
    GITHUB_RUN_ID=46 \
    GITHUB_RUN_ATTEMPT=1 \
    GITHUB_OUTPUT="$maintenance_output" \
    CODEWIRE_SCCACHE_MODE=local \
    scripts/ci/images/build-push-runtime-images.sh
)
[[ "$(cat "$maintenance_state")" -eq 60 ]] ||
  fail "registry maintenance recovery did not reach its final admitted retry"
[[ "$(grep -c '^60$' "$maintenance_sleep_log")" -eq 60 ]] ||
  fail "registry maintenance recovery did not use sixty bounded waits"
[[ "$(wc -l <"$maintenance_output" | tr -d ' ')" -eq 10 ]] ||
  fail "registry maintenance recovery did not emit the exact five-image set with built-from sources"

exhausted_state="$work/exhausted-state"
exhausted_sleep_log="$work/exhausted-sleep.log"
printf '0\n' >"$exhausted_state"
: >"$exhausted_sleep_log"
if (
  cd "$fixture"
  PATH="$fixture/bin:$PATH" \
    RUNNER_TEMP="$fixture/tmp" \
    DOCKER_LOG="$work/exhausted-docker.log" \
    BUILD_LOG="$work/exhausted-build.log" \
    SLEEP_LOG="$exhausted_sleep_log" \
    FAKE_TRANSIENT_REGISTRY_IMAGE=mesh \
    FAKE_TRANSIENT_REGISTRY_FAILURES=61 \
    FAKE_TRANSIENT_REGISTRY_STATE="$exhausted_state" \
    GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
    GITHUB_RUN_ID=45 \
    GITHUB_RUN_ATTEMPT=1 \
    GITHUB_OUTPUT="$work/exhausted-output" \
    CODEWIRE_SCCACHE_MODE=local \
    scripts/ci/images/build-push-runtime-images.sh
) >"$work/exhausted.stdout" 2>"$work/exhausted.stderr"; then
  fail "exhausted registry outage was accepted"
fi
[[ "$(cat "$exhausted_state")" -eq 61 ]] ||
  fail "registry retry boundary did not stop after 61 failed attempts"
[[ "$(grep -c '^60$' "$exhausted_sleep_log")" -eq 60 ]] ||
  fail "registry retry boundary did not use exactly 60 bounded waits"

builder="$(cut -d'|' -f2 "$build_log" | sort -u)"
[[ "$builder" =~ ^codewire-runtime-42-3-[0-9]+$ ]] ||
  fail "product builds did not share one bounded runner-scoped builder"
[[ "$(cut -d'|' -f3 "$build_log" | sort -u | wc -l | tr -d ' ')" -eq 1 ]] ||
  fail "product builds did not share one private Docker configuration"
[[ "$(cut -d'|' -f4 "$build_log" | sort -u)" = local ]] ||
  fail "protected wrapper did not keep sccache job-local"
[[ "$(cut -d'|' -f5 "$build_log" | sort -u)" = \
  'https://git.example.invalid/infra/ci/builders/protected-delivery/v1' ]] ||
  fail "protected wrapper did not bind the stable protected builder identity"
[[ "$(awk -F'|' '$1 == "services" { print $6 }' "$build_log")" = 1 ]] ||
  fail "services did not anchor the five-target protected Bake transaction"
[[ "$(awk -F'|' '$1 != "services" { print $6 }' "$build_log" | sort -u)" = 0 ]] ||
  fail "post-build product verification attempted another runtime-set Bake"
grep -Fq "buildx create --name $builder --driver docker-container" "$docker_log" ||
  fail "wrapper did not create the shared docker-container builder"
grep -Fq 'provenance-add-gha=false' "$docker_log" ||
  fail "wrapper may leak the Forgejo event payload into public provenance"
grep -Fq 'moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5' \
  "$docker_log" || fail "wrapper did not pin BuildKit"
grep -Fq "buildx rm --force $builder" "$docker_log" ||
  fail "wrapper did not destroy its BuildKit daemon"
[[ "$(grep -Ec '^pull registry\.example\.invalid/codewire/' "$docker_log")" -eq 5 ]] ||
  fail "wrapper did not pull all five protected candidates by digest"
for family in dashboard derp gateway mesh services; do
  grep -Eq "^image tag .*codewire/${family}@sha256:[0-9a-f]{64} codewire-${family}:e2e$" \
    "$docker_log" || fail "wrapper did not materialize the exact $family candidate locally"
done

if (
  cd "$fixture"
  PATH="$fixture/bin:$PATH" \
    RUNNER_TEMP="$fixture/tmp" \
    DOCKER_LOG="$docker_log" \
    BUILD_LOG="$build_log" \
    SLEEP_LOG="$sleep_log" \
    GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
    GITHUB_OUTPUT="$work/rejected-output" \
    CODEWIRE_SCCACHE_MODE=r2 \
    scripts/ci/images/build-push-runtime-images.sh
) >"$work/rejected.stdout" 2>"$work/rejected.stderr"; then
  fail "protected runtime wrapper accepted shared R2 credentials without a prefix"
fi
grep -Fq 'Protected runtime builds may use only the protected R2 compiler-cache prefix' \
  "$work/rejected.stderr" || fail "prefix-less shared-cache rejection was not attributable"

if (
  cd "$fixture"
  PATH="$fixture/bin:$PATH" \
    RUNNER_TEMP="$fixture/tmp" \
    DOCKER_LOG="$docker_log" \
    BUILD_LOG="$build_log" \
    SLEEP_LOG="$sleep_log" \
    GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
    GITHUB_OUTPUT="$work/untrusted-output" \
    CODEWIRE_SCCACHE_MODE=r2 \
    CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/v1 \
    scripts/ci/images/build-push-runtime-images.sh
) >"$work/untrusted.stdout" 2>"$work/untrusted.stderr"; then
  fail "protected runtime wrapper accepted the untrusted R2 cache prefix"
fi
grep -Fq 'Protected runtime builds may use only the protected R2 compiler-cache prefix' \
  "$work/untrusted.stderr" || fail "untrusted-prefix rejection was not attributable"

# A protected prefix inside the untrusted bucket is writable by pull-request
# builds, so the prefix alone never admits the shared cache.
if (
  cd "$fixture"
  PATH="$fixture/bin:$PATH" \
    RUNNER_TEMP="$fixture/tmp" \
    DOCKER_LOG="$docker_log" \
    BUILD_LOG="$build_log" \
    SLEEP_LOG="$sleep_log" \
    GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
    GITHUB_OUTPUT="$work/untrusted-bucket-output" \
    CODEWIRE_SCCACHE_MODE=r2 \
    CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1 \
    SCCACHE_BUCKET=example-ci-cache-untrusted \
    SCCACHE_ENDPOINT=https://00000000000000000000000000000000.r2.cloudflarestorage.com \
    scripts/ci/images/build-push-runtime-images.sh
) >"$work/untrusted-bucket.stdout" 2>"$work/untrusted-bucket.stderr"; then
  fail "protected runtime wrapper accepted the untrusted R2 cache bucket"
fi
grep -Fq 'Protected runtime builds may use only the protected R2 compiler-cache bucket' \
  "$work/untrusted-bucket.stderr" || fail "untrusted-bucket rejection was not attributable"
[[ ! -s "$work/untrusted-bucket-output" ]] ||
  fail "untrusted-bucket rejection emitted runtime image outputs"

protected_r2_output="$work/protected-r2-output"
protected_r2_build_log="$work/protected-r2-build.log"
(
  cd "$fixture"
  PATH="$fixture/bin:$PATH" \
    RUNNER_TEMP="$fixture/tmp" \
    DOCKER_LOG="$work/protected-r2-docker.log" \
    BUILD_LOG="$protected_r2_build_log" \
    SLEEP_LOG="$work/protected-r2-sleep.log" \
    GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
    GITHUB_RUN_ID=46 \
    GITHUB_RUN_ATTEMPT=1 \
    GITHUB_OUTPUT="$protected_r2_output" \
    CODEWIRE_SCCACHE_MODE=r2 \
    CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1 \
    SCCACHE_BUCKET=example-ci-cache-protected \
    SCCACHE_ENDPOINT=https://00000000000000000000000000000000.r2.cloudflarestorage.com \
    scripts/ci/images/build-push-runtime-images.sh
)
[[ "$(wc -l <"$protected_r2_output" | tr -d ' ')" -eq 10 ]] ||
  fail "protected-prefix R2 build did not emit the exact five-image set"
[[ "$(cut -d'|' -f4 "$protected_r2_build_log" | sort -u)" = r2 ]] ||
  fail "protected-prefix R2 mode did not reach every product build"

# Selective rebuild: the trusted planner's per-family change context carries
# certified-unaffected images forward from the deployed baseline source while
# affected families rebuild from the exact head.
baseline_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
carried_digest() {
  printf '%s' "registry.example.invalid/codewire/$1:${baseline_sha}" | sha256sum | cut -d' ' -f1
}
head_sha=0123456789abcdef0123456789abcdef01234567

run_wrapper() {
  local output="$1" docker_log="$2" build_log="$3" sleep_log="$4" run_id="$5"
  shift 5
  (
    cd "$fixture"
    PATH="$fixture/bin:$PATH" \
      RUNNER_TEMP="$fixture/tmp" \
      DOCKER_LOG="$docker_log" \
      BUILD_LOG="$build_log" \
      SLEEP_LOG="$sleep_log" \
      GITHUB_SHA="$head_sha" \
      GITHUB_RUN_ID="$run_id" \
      GITHUB_RUN_ATTEMPT=1 \
      GITHUB_OUTPUT="$output" \
      CODEWIRE_SCCACHE_MODE=local \
      env "$@" \
      scripts/ci/images/build-push-runtime-images.sh
  )
}

ui_output="$work/ui-output"
ui_docker_log="$work/ui-docker.log"
ui_build_log="$work/ui-build.log"
ui_carried="$work/ui-carried"
printf '%s\n' services mesh gateway derp >"$ui_carried"
run_wrapper "$ui_output" "$ui_docker_log" "$ui_build_log" "$work/ui-sleep.log" 47 \
  FAKE_BASELINE_SHA="$baseline_sha" \
  CARRIED_FAMILIES_FILE="$ui_carried" \
  CODEWIRE_RUNTIME_CARRY_FORWARD=1 \
  CODEWIRE_DEPLOY_BASELINE_SHA="$baseline_sha" \
  CODEWIRE_IMAGE_STATE_DASHBOARD=affected \
  CODEWIRE_IMAGE_STATE_DERP=unaffected \
  CODEWIRE_IMAGE_STATE_GATEWAY=unaffected \
  CODEWIRE_IMAGE_STATE_SERVICES=unaffected \
  CODEWIRE_IMAGE_STATE_MESH=unaffected
[[ "$(wc -l <"$ui_build_log" | tr -d ' ')" -eq 1 ]] ||
  fail "UI-only change rebuilt a certified-unaffected image"
[[ "$(awk -F'|' '$1 == "dashboard" { print $6 }' "$ui_build_log")" = 0 ]] ||
  fail "UI-only change anchored the runtime-set Bake without a services build"
[[ "$(wc -l <"$ui_output" | tr -d ' ')" -eq 10 ]] ||
  fail "UI-only change did not emit the complete five-image set"
for family in services mesh gateway derp; do
  grep -qx "${family}_candidate_ref=registry.example.invalid/codewire/${family}@sha256:$(carried_digest "$family")" \
    "$ui_output" ||
    fail "UI-only change did not carry forward the exact deployed $family digest"
  grep -qx "${family}_built_from=${baseline_sha}" "$ui_output" ||
    fail "UI-only change did not record the deployed baseline source for $family"
done
grep -qx "dashboard_built_from=${head_sha}" "$ui_output" ||
  fail "UI-only change did not record the head source for the rebuilt dashboard"
[[ "$(grep -c "imagetools create --tag registry.example.invalid/codewire/.*:${head_sha} " "$ui_docker_log")" -eq 4 ]] ||
  fail "UI-only change did not pin the new source tag on each carried digest"
[[ "$(grep -c '^login ' "$ui_docker_log")" -eq 1 ]] ||
  fail "UI-only change did not authenticate once for carry-forward resolution"
[[ "$(grep -Ec '^pull registry\.example\.invalid/codewire/' "$ui_docker_log")" -eq 5 ]] ||
  fail "UI-only change did not materialize all five candidates locally"
for family in dashboard derp gateway mesh services; do
  grep -Eq "^image tag .*codewire/${family}@sha256:[0-9a-f]{64} codewire-${family}:e2e$" \
    "$ui_docker_log" ||
    fail "UI-only change did not materialize the exact $family candidate locally"
done

services_output="$work/services-output"
services_docker_log="$work/services-docker.log"
services_build_log="$work/services-build.log"
services_carried="$work/services-carried"
printf '%s\n' dashboard derp gateway mesh >"$services_carried"
run_wrapper "$services_output" "$services_docker_log" "$services_build_log" \
  "$work/services-sleep.log" 48 \
  FAKE_BASELINE_SHA="$baseline_sha" \
  CARRIED_FAMILIES_FILE="$services_carried" \
  CODEWIRE_RUNTIME_CARRY_FORWARD=1 \
  CODEWIRE_DEPLOY_BASELINE_SHA="$baseline_sha" \
  CODEWIRE_IMAGE_STATE_DASHBOARD=unaffected \
  CODEWIRE_IMAGE_STATE_DERP=unaffected \
  CODEWIRE_IMAGE_STATE_GATEWAY=unaffected \
  CODEWIRE_IMAGE_STATE_SERVICES=affected \
  CODEWIRE_IMAGE_STATE_MESH=unaffected
[[ "$(wc -l <"$services_build_log" | tr -d ' ')" -eq 1 ]] ||
  fail "services-input change rebuilt a certified-unaffected image"
[[ "$(awk -F'|' '$1 == "services" { print $6 }' "$services_build_log")" = 1 ]] ||
  fail "services-input change did not anchor the runtime-set Bake on services"
for family in dashboard derp gateway mesh; do
  grep -qx "${family}_candidate_ref=registry.example.invalid/codewire/${family}@sha256:$(carried_digest "$family")" \
    "$services_output" ||
    fail "services-input change did not carry forward the exact deployed $family digest"
  grep -qx "${family}_built_from=${baseline_sha}" "$services_output" ||
    fail "services-input change did not record the deployed baseline source for $family"
done
grep -qx "services_built_from=${head_sha}" "$services_output" ||
  fail "services-input change did not rebuild services from the exact head"

gate_off_output="$work/gate-off-output"
gate_off_docker_log="$work/gate-off-docker.log"
gate_off_build_log="$work/gate-off-build.log"
run_wrapper "$gate_off_output" "$gate_off_docker_log" "$gate_off_build_log" \
  "$work/gate-off-sleep.log" 49 \
  FAKE_BASELINE_SHA="$baseline_sha" \
  CODEWIRE_RUNTIME_CARRY_FORWARD=0 \
  CODEWIRE_DEPLOY_BASELINE_SHA="$baseline_sha" \
  CODEWIRE_IMAGE_STATE_DASHBOARD=unaffected \
  CODEWIRE_IMAGE_STATE_DERP=unaffected \
  CODEWIRE_IMAGE_STATE_GATEWAY=unaffected \
  CODEWIRE_IMAGE_STATE_SERVICES=unaffected \
  CODEWIRE_IMAGE_STATE_MESH=unaffected
[[ "$(wc -l <"$gate_off_build_log" | tr -d ' ')" -eq 5 ]] ||
  fail "disabled carry-forward skipped a source build"
if grep -Eq 'imagetools (inspect|create)|^login ' "$gate_off_docker_log"; then
  fail "disabled carry-forward consulted the deployed baseline"
fi
for family in dashboard derp gateway mesh services; do
  grep -qx "${family}_built_from=${head_sha}" "$gate_off_output" ||
    fail "disabled carry-forward did not build $family from the exact head"
done

if run_wrapper "$work/no-baseline-output" "$work/no-baseline-docker.log" \
    "$work/no-baseline-build.log" "$work/no-baseline-sleep.log" 50 \
    CODEWIRE_RUNTIME_CARRY_FORWARD=1 \
    CODEWIRE_IMAGE_STATE_DASHBOARD=unaffected \
    >"$work/no-baseline.stdout" 2>"$work/no-baseline.stderr"; then
  fail "carry-forward accepted a missing deployed baseline source"
fi
grep -Fq 'requires the exact planner-certified deployed baseline source SHA' \
  "$work/no-baseline.stderr" || fail "missing-baseline rejection was not attributable"

missing_output="$work/missing-output"
missing_docker_log="$work/missing-docker.log"
missing_build_log="$work/missing-build.log"
missing_carried="$work/missing-carried"
printf '%s\n' services gateway derp >"$missing_carried"
run_wrapper "$missing_output" "$missing_docker_log" "$missing_build_log" \
  "$work/missing-sleep.log" 51 \
  FAKE_BASELINE_SHA="$baseline_sha" \
  FAKE_MISSING_BASELINE_IMAGE=mesh \
  CARRIED_FAMILIES_FILE="$missing_carried" \
  CODEWIRE_RUNTIME_CARRY_FORWARD=1 \
  CODEWIRE_DEPLOY_BASELINE_SHA="$baseline_sha" \
  CODEWIRE_IMAGE_STATE_DASHBOARD=affected \
  CODEWIRE_IMAGE_STATE_DERP=unaffected \
  CODEWIRE_IMAGE_STATE_GATEWAY=unaffected \
  CODEWIRE_IMAGE_STATE_SERVICES=unaffected \
  CODEWIRE_IMAGE_STATE_MESH=unaffected \
  >"$work/missing.stdout" 2>"$work/missing.stderr"
grep -Fq 'Carry-forward of mesh failed closed; rebuilding it from source' \
  "$work/missing.stderr" || fail "unresolvable baseline tag did not fail closed to a source build"
[[ "$(wc -l <"$missing_build_log" | tr -d ' ')" -eq 2 ]] ||
  fail "unresolvable baseline tag did not rebuild exactly the affected and unresolvable images"
[[ "$(awk -F'|' '{ print $6 }' "$missing_build_log" | sort -u)" = 0 ]] ||
  fail "unresolvable baseline tag anchored the Bake transaction without a services build"
grep -qx "mesh_built_from=${head_sha}" "$missing_output" ||
  fail "unresolvable baseline tag did not record the rebuilt mesh source"
grep -qx "gateway_candidate_ref=registry.example.invalid/codewire/gateway@sha256:$(carried_digest gateway)" \
  "$missing_output" || fail "resolvable carried images did not survive an unresolvable sibling"

stateless_output="$work/stateless-output"
stateless_docker_log="$work/stateless-docker.log"
stateless_build_log="$work/stateless-build.log"
stateless_carried="$work/stateless-carried"
printf '%s\n' dashboard derp gateway services >"$stateless_carried"
run_wrapper "$stateless_output" "$stateless_docker_log" "$stateless_build_log" \
  "$work/stateless-sleep.log" 52 \
  FAKE_BASELINE_SHA="$baseline_sha" \
  CARRIED_FAMILIES_FILE="$stateless_carried" \
  CODEWIRE_RUNTIME_CARRY_FORWARD=1 \
  CODEWIRE_DEPLOY_BASELINE_SHA="$baseline_sha" \
  CODEWIRE_IMAGE_STATE_DASHBOARD=unaffected \
  CODEWIRE_IMAGE_STATE_DERP=unaffected \
  CODEWIRE_IMAGE_STATE_GATEWAY=unaffected \
  CODEWIRE_IMAGE_STATE_SERVICES=unaffected \
  >"$work/stateless.stdout" 2>"$work/stateless.stderr"
grep -Fq 'Runtime image mesh has no trusted planner state; building it from source' \
  "$work/stateless.stderr" || fail "missing planner state did not fail closed to a source build"
[[ "$(wc -l <"$stateless_build_log" | tr -d ' ')" -eq 1 ]] ||
  fail "missing planner state rebuilt more than the unclassified image"
grep -qx "mesh_built_from=${head_sha}" "$stateless_output" ||
  fail "missing planner state did not rebuild mesh from the exact head"

printf '[test-build-push-runtime-images] shared transient BuildKit contract passed\n'
