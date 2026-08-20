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

cat >"$fixture/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$DOCKER_LOG"
if [ "${1:-} ${2:-} ${3:-}" = 'image inspect --format' ]; then
  case "${4:-}" in
    *dev.codewire.build.profile*) printf '%s\n' release ;;
    *dev.codewire.promotable*) printf '%s\n' true ;;
    *org.opencontainers.image.revision*) printf '%s\n' 0123456789abcdef0123456789abcdef01234567 ;;
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
    printf 'unexpected status from HEAD request to https://nexus-system-cluster.example.invalid/v2/oci-promoted/codewire/%s/blobs/sha256:test: 503 Service Temporarily Unavailable\n' \
      "$name" >&2
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
printf 'candidate_ref=nexus-system-cluster.example.invalid/oci-promoted/codewire/%s@sha256:%064d\n' \
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

[[ "$(wc -l <"$output" | tr -d ' ')" -eq 5 ]] ||
  fail "wrapper did not emit exactly five runtime outputs"
[[ "$(wc -l <"$build_log" | tr -d ' ')" -eq 5 ]] ||
  fail "wrapper did not verify exactly five product images"
for family in dashboard derp gateway mesh services; do
  grep -Eq "^${family}_candidate_ref=.*${family}@sha256:[0-9a-f]{64}$" "$output" ||
    fail "wrapper omitted exact $family output"
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
[[ "$(wc -l <"$transient_output" | tr -d ' ')" -eq 5 ]] ||
  fail "transient Nexus recovery did not emit the exact five-image set"
[[ "$(wc -l <"$transient_build_log" | tr -d ' ')" -eq 5 ]] ||
  fail "transient Nexus recovery rebuilt a successful image"
[[ "$(cat "$transient_state")" -eq 2 ]] ||
  fail "transient Nexus recovery did not observe both injected failures"
[[ "$(grep -c '^60$' "$transient_sleep_log")" -eq 2 ]] ||
  fail "transient Nexus recovery did not use the fixed retry delay"

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
  fail "non-retryable protected build failure entered the Nexus retry loop"
grep -Fq 'non-retryable protected build failure' "$work/fatal.stdout" ||
  fail "non-retryable protected build failure was not observable"

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
    FAKE_TRANSIENT_REGISTRY_FAILURES=16 \
    FAKE_TRANSIENT_REGISTRY_STATE="$exhausted_state" \
    GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
    GITHUB_RUN_ID=45 \
    GITHUB_RUN_ATTEMPT=1 \
    GITHUB_OUTPUT="$work/exhausted-output" \
    CODEWIRE_SCCACHE_MODE=local \
    scripts/ci/images/build-push-runtime-images.sh
) >"$work/exhausted.stdout" 2>"$work/exhausted.stderr"; then
  fail "exhausted Nexus outage was accepted"
fi
[[ "$(cat "$exhausted_state")" -eq 16 ]] ||
  fail "Nexus retry boundary did not stop after 16 failed attempts"
[[ "$(grep -c '^60$' "$exhausted_sleep_log")" -eq 15 ]] ||
  fail "Nexus retry boundary did not use exactly 15 bounded waits"

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
[[ "$(grep -Ec '^pull nexus-system-cluster\.private\.invalid/oci-promoted/codewire/' "$docker_log")" -eq 5 ]] ||
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
  fail "protected runtime wrapper accepted shared R2 credentials"
fi
grep -Fq 'Protected runtime builds may use only job-local or disabled sccache' \
  "$work/rejected.stderr" || fail "shared-cache rejection was not attributable"

printf '[test-build-push-runtime-images] shared transient BuildKit contract passed\n'
