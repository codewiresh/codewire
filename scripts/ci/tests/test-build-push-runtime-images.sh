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

cat >"$fixture/scripts/ci/images/build-push-image.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
name="$1"
printf '%s|%s|%s|%s\n' \
  "$name" "$CODEWIRE_EXTERNAL_BUILDX_BUILDER" \
  "$CODEWIRE_EXTERNAL_DOCKER_CONFIG" "$CODEWIRE_SCCACHE_MODE" >>"$BUILD_LOG"
printf 'candidate_ref=nexus-system-cluster.example.invalid/oci-promoted/codewire/%s@sha256:%064d\n' \
  "$name" 0 >>"$GITHUB_OUTPUT"
SH
chmod 0755 "$fixture/scripts/ci/images/build-push-image.sh"

output="$work/output"
docker_log="$work/docker.log"
build_log="$work/build.log"
(
  cd "$fixture"
  PATH="$fixture/bin:$PATH" \
    RUNNER_TEMP="$fixture/tmp" \
    DOCKER_LOG="$docker_log" \
    BUILD_LOG="$build_log" \
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
  fail "wrapper did not invoke exactly five separate product builds"
for family in dashboard derp gateway mesh services; do
  grep -Eq "^${family}_candidate_ref=.*${family}@sha256:[0-9a-f]{64}$" "$output" ||
    fail "wrapper omitted exact $family output"
done

builder="$(cut -d'|' -f2 "$build_log" | sort -u)"
[[ "$builder" =~ ^codewire-runtime-42-3-[0-9]+$ ]] ||
  fail "product builds did not share one bounded runner-scoped builder"
[[ "$(cut -d'|' -f3 "$build_log" | sort -u | wc -l | tr -d ' ')" -eq 1 ]] ||
  fail "product builds did not share one private Docker configuration"
[[ "$(cut -d'|' -f4 "$build_log" | sort -u)" = local ]] ||
  fail "protected wrapper did not keep sccache job-local"
grep -Fq "buildx create --name $builder --driver docker-container" "$docker_log" ||
  fail "wrapper did not create the shared docker-container builder"
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
