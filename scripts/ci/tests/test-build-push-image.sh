#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUILDER="$ROOT/scripts/ci/images/build-push-image.sh"
readonly KIND_BUILDER="$ROOT/scripts/ci/images/build-kind-images.sh"
readonly RUST_BUILD_WRAPPER="$ROOT/scripts/ci/images/run-rust-build.sh"
readonly RUST_BASE_DOCKERFILE="$ROOT/deployments/docker/rust-base.Dockerfile"
readonly BAKE_FILE="$ROOT/docker-bake.hcl"
readonly COMPOSE_FILE="$ROOT/docker-compose.yml"
readonly SERVICES_DOCKERFILE="$ROOT/deployments/docker/services.Dockerfile"
readonly SERVICES_DOCKERIGNORE="$ROOT/deployments/docker/services.Dockerfile.dockerignore"
readonly DASHBOARD_DOCKERFILE="$ROOT/apps/dashboard/Dockerfile"
readonly MESH_DOCKERFILE="$ROOT/deployments/docker/mesh.Dockerfile"
readonly GATEWAY_DOCKERFILE="$ROOT/deployments/docker/gateway.Dockerfile"
readonly DERP_DOCKERFILE="$ROOT/deployments/docker/derp.Dockerfile"
readonly SERVICES_BINARIES=(
  codewire-idp
  codewire-orchestration
  sidecar-smoke
  codewire-billing
  codewire-coordinator
  codewire-db-migrate
  codewire-udp-relay
)

fail() {
  printf '[test-build-push-image] ERROR: %s\n' "$*" >&2
  exit 1
}

build_invocation_count() {
  grep -Ec ' buildx (bake|build) ' "$FAKE_DOCKER_CALLS" || true
}

mkdir -p "$ROOT/.tmp"

verify_services_dockerfile_contract() {
  local mount binary
  local mounts=(
    'id=codewire-services-cargo-registry,target=/usr/local/cargo/registry,sharing=locked'
    'id=codewire-services-cargo-git,target=/usr/local/cargo/git,sharing=locked'
    'id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared'
  )

  [[ "$(grep -cF -- '--mount=type=cache' "$SERVICES_DOCKERFILE")" -eq 3 ]] ||
    fail 'services image must have exactly three BuildKit cache mounts'
  for mount in "${mounts[@]}"; do
    grep -qF -- "--mount=type=cache,${mount}" "$SERVICES_DOCKERFILE" ||
      fail "services image is missing cache mount ${mount}"
  done
  grep -qF 'COPY libs/gateway-proto ./libs/gateway-proto' "$SERVICES_DOCKERFILE" ||
    fail 'services image does not receive the environment daemon protocol schema'
  grep -qF '!libs/gateway-proto/**' "$SERVICES_DOCKERIGNORE" ||
    fail 'services build context excludes the environment daemon protocol schema'
  grep -qF 'find Cargo.toml Cargo.lock crates proto libs/gateway-proto -type f -exec touch {} +' \
    "$SERVICES_DOCKERFILE" ||
    fail 'services image does not revalidate copied workspace inputs'
  # shellcheck disable=SC2016
  grep -qF 'codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE"' "$SERVICES_DOCKERFILE" ||
    fail 'services image does not build the selected locked profile'
  grep -qF 'FROM codewire-rust-base AS builder' "$SERVICES_DOCKERFILE" ||
    fail 'services does not consume the shared Rust build base'
  grep -qF 'ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818' \
    "$SERVICES_DOCKERFILE" || fail 'services runtime base changed'
  grep -qF "FROM \${DEBIAN_IMAGE}" "$SERVICES_DOCKERFILE" ||
    fail 'services runtime does not consume the reviewed Debian image'
  grep -qF 'USER 65532:65532' "$SERVICES_DOCKERFILE" ||
    fail 'services runtime user changed'

  for binary in "${SERVICES_BINARIES[@]}"; do
    [[ "$(grep -cF -- "--bin ${binary}" "$SERVICES_DOCKERFILE")" -eq 1 ]] ||
      fail "services build does not request ${binary} exactly once"
    [[ "$(grep -cF "target/\$CODEWIRE_RUST_PROFILE/${binary}" "$SERVICES_DOCKERFILE")" -eq 1 ]] ||
      fail "services build does not copy ${binary} out of Cargo target exactly once"
    [[ "$(grep -cF "/out/${binary}" "$SERVICES_DOCKERFILE")" -eq 2 ]] ||
      fail "services image does not move ${binary} through the non-cache output exactly once"
    grep -qF "COPY --from=builder /out/${binary} /${binary}" \
      "$SERVICES_DOCKERFILE" ||
      fail "services runtime image is missing ${binary}"
  done
}

verify_kind_build_cache_contract() {
  local dockerfile count
  for dockerfile in \
      "$DASHBOARD_DOCKERFILE" \
      "$SERVICES_DOCKERFILE" \
      "$MESH_DOCKERFILE" \
      "$GATEWAY_DOCKERFILE" \
      "$DERP_DOCKERFILE"; do
    grep -qF 'FROM codewire-rust-base AS ' "$dockerfile" ||
      fail "$(basename "$dockerfile") omits the shared Rust build base"
    grep -qF -- 'id=codewire-sccache-v2,target=/var/cache/sccache,sharing=shared' \
      "$dockerfile" || fail "$(basename "$dockerfile") omits the shared compiler cache"
    grep -Eq -- 'id=codewire-[a-z-]+-cargo-registry,target=/usr/local/cargo/registry,sharing=locked' \
      "$dockerfile" || fail "$(basename "$dockerfile") omits its isolated Cargo registry cache"
    if grep -Eq -- 'target=/usr/local/cargo/(registry|git),sharing=shared' "$dockerfile"; then
      fail "$(basename "$dockerfile") unsafely shares a writable Cargo download cache across parallel targets"
    fi
    grep -qF -- '--mount=type=secret,id=aws_shared_credentials' "$dockerfile" ||
      fail "$(basename "$dockerfile") omits the private R2 credential mount"
    grep -qF 'ARG CODEWIRE_SCCACHE_MODE=disabled' "$dockerfile" ||
      fail "$(basename "$dockerfile") does not fail closed to disabled remote caching"
    # shellcheck disable=SC2016
    grep -qF 'codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE"' "$dockerfile" ||
      fail "$(basename "$dockerfile") bypasses the canonical compiler-cache wrapper"
    if grep -Eq 'cargo[ -]chef|recipe\.json|target=/[^ ]*/target' "$dockerfile"; then
      fail "$(basename "$dockerfile") retains cargo-chef or a coarse target-tree cache"
    fi
  done

  [[ "$(grep -cF 'codewire-rust-base = "target:rust-base"' "$BAKE_FILE")" -eq 1 ]] ||
    fail 'Bake does not build the shared Rust base once as a linked target'
  for target in dashboard-ci services-ci mesh-ci gateway-ci; do
    grep -qF "\"$target\"" "$BAKE_FILE" || fail "Bake omits Kind target $target"
  done
  grep -qF 'default = "disabled"' "$BAKE_FILE" ||
    fail 'Bake remote compiler cache does not default disabled'
  grep -qF 'sccache-v0.17.0-x86_64-unknown-linux-musl.tar.gz' "$RUST_BASE_DOCKERFILE" ||
    fail 'shared build base omits the reviewed sccache binary'
  grep -qF 'CODEWIRE_SCCACHE_MODE:-local' "$KIND_BUILDER" ||
    fail 'Kind does not enable its job-local compiler cache'
  [[ "$(grep -cF 'buildx bake' "$KIND_BUILDER")" -eq 1 ]] ||
    fail 'Kind must issue exactly one canonical Bake build'
  grep -qF 'untrusted/codewire/' "$KIND_BUILDER" ||
    fail 'Kind does not constrain its remote cache trust-domain prefix'
  grep -qF 'protected/codewire/' "$BUILDER" ||
    fail 'published image builds do not constrain their compiler-cache prefix'
  grep -qF 'AWS_SHARED_CREDENTIALS_FILE' "$RUST_BUILD_WRAPPER" ||
    fail 'sccache does not consume its private AWS shared-credentials file'
  if grep -Eq 'AWS_IAM_CREDENTIALS_URL|aws_iam_credentials_url' \
      "$RUST_BUILD_WRAPPER" "$KIND_BUILDER" "$BUILDER" \
      "$DASHBOARD_DOCKERFILE" "$SERVICES_DOCKERFILE" \
      "$MESH_DOCKERFILE" "$GATEWAY_DOCKERFILE" "$DERP_DOCKERFILE"; then
    fail 'the unsupported credential-URL contract remains in an R2 build path'
  fi
  grep -qF 'export CARGO_INCREMENTAL=0' "$RUST_BUILD_WRAPPER" ||
    fail 'sccache wrapper does not disable incompatible incremental compilation'
  grep -qF 'export SCCACHE_DIRECT=false' "$RUST_BUILD_WRAPPER" ||
    fail 'sccache wrapper permits unsafe direct-mode reuse across isolated executors'
  grep -qF 'codewire-rust-base: service:rust-base' "$COMPOSE_FILE" ||
    fail 'Compose does not supply the dashboard shared Rust build context'
  grep -A6 '^  rust-base:$' "$COMPOSE_FILE" | grep -qF 'replicas: 0' ||
    fail 'Compose may start the build-only Rust base as a runtime service'
  grep -qF 'export SCCACHE_SERVER_UDS=' "$RUST_BUILD_WRAPPER" ||
    fail 'sccache daemon is not isolated to one BuildKit executor'
  grep -qF 'dev.codewire.promotable"    = "false"' "$BAKE_FILE" ||
    fail 'Kind images are not marked non-promotable'
  # shellcheck disable=SC2016
  count="$(grep -cF 'cargo build --locked --profile "$CODEWIRE_RUST_PROFILE"' "$GATEWAY_DOCKERFILE")"
  [[ "$count" -eq 2 ]] || fail 'gateway must preserve its two distinct profile-selected builds'
}

verify_services_dockerfile_contract
verify_kind_build_cache_contract
[[ "$#" -eq 0 ]] || fail "unknown test mode: $1"

if ! CODEWIRE_SCCACHE_MODE=disabled CODEWIRE_RUST_PROFILE=ci \
  "$RUST_BUILD_WRAPPER" true >"$ROOT/.tmp/rust-build-wrapper.out"; then
  fail 'disabled sccache mode did not execute the requested command'
fi
grep -qF 'CODEWIRE_CI_PHASE name=rust-compile-link mode=disabled' \
  "$ROOT/.tmp/rust-build-wrapper.out" ||
  fail 'Rust build wrapper omitted its structured phase result'
if CODEWIRE_SCCACHE_MODE=disabled CODEWIRE_RUST_PROFILE=debug \
  "$RUST_BUILD_WRAPPER" true >"$ROOT/.tmp/rust-build-wrapper-invalid.out" 2>&1; then
  fail 'Rust build wrapper accepted an undeclared build profile'
fi
if CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_RUST_PROFILE=ci \
  SCCACHE_BUCKET=test SCCACHE_ENDPOINT=https://test.invalid \
  CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/test \
  AWS_SHARED_CREDENTIALS_FILE=relative/credentials \
  "$RUST_BUILD_WRAPPER" true >"$ROOT/.tmp/rust-build-wrapper-relative-credentials.out" 2>&1; then
  fail 'Rust build wrapper accepted a relative shared-credentials path'
fi

work="$(mktemp -d "$ROOT/.tmp/build-push-image.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

r2_credentials_file="$work/aws-shared-credentials"
cat >"$r2_credentials_file" <<'EOF'
[default]
aws_access_key_id = untrusted-access-key
aws_secret_access_key = untrusted-secret-key
EOF
chmod 0600 "$r2_credentials_file"

registry_username='nexus-publisher-test'
registry_password='registry-test-value'
digest="sha256:$(printf 'd%.0s' {1..64})"
second_digest="sha256:$(printf 'f%.0s' {1..64})"
mismatch_digest="sha256:$(printf 'c%.0s' {1..64})"
source_sha="$(git -C "$ROOT" rev-parse HEAD)"
base_digest="sha256:$(printf 'e%.0s' {1..64})"
base_ref="nexus-system-cluster.example.invalid/oci-promoted/codewire/base@$base_digest"

cat >"$work/bin/fetch-nexus" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s' "${FAKE_REGISTRY_USERNAME:?}" >"$1"
printf '%s' "${FAKE_REGISTRY_PASSWORD:?}" >"$2"
chmod 0600 "$1" "$2"
printf '%q %q\n' "$1" "$2" >>"${FAKE_FETCH_CALLS:?}"
EOF

cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'DOCKER_CONFIG=%q ' "${DOCKER_CONFIG:-}" >>"${FAKE_DOCKER_CALLS:?}"
printf 'CODEWIRE_IMAGE_SOURCE_SHA=%q CODEWIRE_RUST_PROFILE=%q CODEWIRE_SCCACHE_MODE=%q ' \
  "${CODEWIRE_IMAGE_SOURCE_SHA:-}" "${CODEWIRE_RUST_PROFILE:-}" "${CODEWIRE_SCCACHE_MODE:-}" \
  >>"$FAKE_DOCKER_CALLS"
printf '%q ' "$@" >>"$FAKE_DOCKER_CALLS"
printf '\n' >>"$FAKE_DOCKER_CALLS"

set_manifest() {
  local reference="$1"
  local digest="$2"
  local temporary="${FAKE_MANIFESTS:?}.tmp"
  awk -F '\t' -v reference="$reference" '$1 != reference' \
    "$FAKE_MANIFESTS" >"$temporary"
  printf '%s\t%s\n' "$reference" "$digest" >>"$temporary"
  mv "$temporary" "$FAKE_MANIFESTS"
}

case "${1:-} ${2:-} ${3:-}" in
  login\ nexus-system-cluster.example.invalid\ *)
    credential="$(cat)"
    [[ "$credential" == "${FAKE_REGISTRY_PASSWORD:?}" ]]
    [[ "$*" == *" -u ${FAKE_REGISTRY_USERNAME:?} "* ]]
    if [ -n "${FAKE_LOGIN_FAILURES:-}" ]; then
      login_state="${FAKE_LOGIN_STATE:?}"
      login_count="$(cat "$login_state")"
      if [ "$login_count" -lt "$FAKE_LOGIN_FAILURES" ]; then
        printf '%s\n' "$((login_count + 1))" >"$login_state"
        echo 'Error response from daemon: Nexus login failed with status: 401 Unauthorized' >&2
        exit 1
      fi
    fi
    mkdir -p "${DOCKER_CONFIG:?}"
    printf '{}\n' >"$DOCKER_CONFIG/config.json"
    ;;
  'buildx imagetools inspect')
    shift 3
    reference=''
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --format)
          shift 2
          ;;
        *)
          reference="$1"
          shift
          ;;
      esac
    done
    [[ -n "$reference" ]]
    if [ "$reference" = "${FAKE_INSPECT_AUTH_ONCE_REF:-}" ]; then
      auth_state="${FAKE_INSPECT_AUTH_STATE:?}"
      auth_count="$(cat "$auth_state")"
      if [ "$auth_count" -eq 0 ]; then
        printf '1\n' >"$auth_state"
        echo 'ERROR: failed to authorize: unexpected status from GET /v2/token: 401 Unauthorized' >&2
        exit 1
      fi
    fi
    if [ "$reference" = "${FAKE_INSPECT_ERROR_REF:-}" ]; then
      echo 'ERROR: registry authorization failed' >&2
      exit 1
    fi
    digest="$(
      awk -F '\t' -v reference="$reference" \
        '$1 == reference { value = $2 } END { print value }' \
        "$FAKE_MANIFESTS"
    )"
    if [ -z "$digest" ]; then
      printf 'ERROR: %s: manifest unknown\n' "$reference" >&2
      exit 1
    fi
    jq -n --arg digest "$digest" '{digest: $digest}'
    ;;
  'buildx imagetools create')
    shift 3
    destination=''
    source=''
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --tag)
          destination="$2"
          shift 2
          ;;
        *)
          source="$1"
          shift
          ;;
      esac
    done
    [[ -n "$destination" && "$source" =~ @sha256:[0-9a-f]{64}$ ]]
    if [ "$destination" = "${FAKE_CREATE_AUTH_ONCE_REF:-}" ]; then
      auth_state="${FAKE_CREATE_AUTH_STATE:?}"
      auth_count="$(cat "$auth_state")"
      if [ "$auth_count" -eq 0 ]; then
        printf '1\n' >"$auth_state"
        echo 'ERROR: failed to authorize: unexpected status from GET /v2/token: 401 Unauthorized' >&2
        exit 1
      fi
    fi
    set_manifest "$destination" "${source##*@}"
    ;;
  buildx\ bake\ *)
    metadata=''
    target=''
    tag=''
    shift 2
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --metadata-file)
          metadata="$2"
          shift 2
          ;;
        --set)
          case "$2" in
            *.tags=*) tag="${2#*=}" ;;
          esac
          shift 2
          ;;
        --file|--provenance)
          shift 2
          ;;
        --push)
          shift
          ;;
        *)
          target="$1"
          shift
          ;;
      esac
    done
    [[ -n "$metadata" && -n "$target" ]]
    if [ "$target" = kind ]; then
      jq -n '{
        "dashboard-ci": {},
        "services-ci": {},
        "mesh-ci": {},
        "gateway-ci": {}
      }' >"$metadata"
      exit 0
    fi
    [[ -n "$tag" ]]
    jq -n --arg target "$target" --arg digest "${FAKE_DIGEST:?}" \
      '{($target): {"containerimage.digest": $digest}}' >"$metadata"
    set_manifest "$tag" "$FAKE_DIGEST"
    ;;
  image\ inspect\ *)
    case "$*" in
      *dev.codewire.build.profile*) printf 'ci\n' ;;
      *dev.codewire.promotable*) printf 'false\n' ;;
    esac
    ;;
  buildx\ build\ *)
    metadata=''
    tags=()
    shift 2
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --metadata-file)
          metadata="$2"
          shift 2
          ;;
        --tag)
          tags+=("$2")
          shift 2
          ;;
        --build-arg|--label|-f)
          shift 2
          ;;
        --push|--provenance=*)
          shift
          ;;
        *)
          shift
          ;;
      esac
    done
    [[ -n "$metadata" && "${#tags[@]}" -eq 1 ]]
    jq -n --arg digest "${FAKE_DIGEST:?}" \
      '{"containerimage.digest": $digest}' >"$metadata"
    for tag in "${tags[@]}"; do
      set_manifest "$tag" "$FAKE_DIGEST"
    done
    ;;
  *)
    echo "unexpected fake docker command: $*" >&2
    exit 1
    ;;
esac
EOF
cat >"$work/bin/sccache" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'AWS_SHARED_CREDENTIALS_FILE=%s AWS_PROFILE=%s AWS_EC2_METADATA_DISABLED=%s AWS_ACCESS_KEY_ID=%s command=%s\n' \
  "${AWS_SHARED_CREDENTIALS_FILE:-}" "${AWS_PROFILE:-}" \
  "${AWS_EC2_METADATA_DISABLED:-}" "${AWS_ACCESS_KEY_ID:-}" "$*" \
  >>"${FAKE_SCCACHE_CALLS:?}"
EOF
chmod +x "$work/bin/fetch-nexus" "$work/bin/docker" "$work/bin/sccache"

export PATH="$work/bin:$PATH"
export OPENBAO_NEXUS_CREDENTIAL_FETCHER="$work/bin/fetch-nexus"
export FAKE_REGISTRY_USERNAME="$registry_username"
export FAKE_REGISTRY_PASSWORD="$registry_password"
export FAKE_FETCH_CALLS="$work/fetch-calls"
export FAKE_DOCKER_CALLS="$work/docker-calls"
export FAKE_SCCACHE_CALLS="$work/sccache-calls"
export FAKE_MANIFESTS="$work/manifests"
export FAKE_DIGEST="$digest"
export GITHUB_SHA="$source_sha"
export GITHUB_REF='refs/heads/main'
export GITHUB_REF_NAME='main'
export GITHUB_OUTPUT="$work/output"
: >"$FAKE_MANIFESTS"

CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_RUST_PROFILE=ci \
  SCCACHE_BUCKET=codewire-ci \
  SCCACHE_ENDPOINT=https://account.r2.cloudflarestorage.com \
  CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/test \
  AWS_SHARED_CREDENTIALS_FILE="$r2_credentials_file" \
  AWS_ACCESS_KEY_ID=ambient-static-credential \
  "$RUST_BUILD_WRAPPER" true >"$work/rust-build-wrapper-r2.out"
grep -qF "AWS_SHARED_CREDENTIALS_FILE=$r2_credentials_file" "$FAKE_SCCACHE_CALLS" ||
  fail 'Rust build wrapper did not expose the private credential file to pinned sccache'
grep -qF 'AWS_PROFILE=default AWS_EC2_METADATA_DISABLED=true AWS_ACCESS_KEY_ID=' \
  "$FAKE_SCCACHE_CALLS" ||
  fail 'Rust build wrapper retained an ambient credential or metadata fallback'

(
  cd "$ROOT"
  "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
)

grep -qxF 'family=gateway' "$GITHUB_OUTPUT" || fail 'candidate family is absent'
grep -qxF "source_sha=$source_sha" "$GITHUB_OUTPUT" ||
  fail 'candidate source SHA is absent'
grep -qxF "candidate_ref=nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway@$digest" "$GITHUB_OUTPUT" ||
  fail 'candidate digest ref is absent'
grep -qF -- "gateway.tags=nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway:$source_sha" "$FAKE_DOCKER_CALLS" ||
  fail 'immutable source tag did not reach canonical Bake target'
grep -qF -- "CODEWIRE_IMAGE_SOURCE_SHA=$source_sha" "$FAKE_DOCKER_CALLS" ||
  fail 'exact source revision did not reach canonical Bake'
grep -qF -- 'CODEWIRE_RUST_PROFILE=release' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not force the release profile'
grep -qF -- '--provenance mode=min' "$FAKE_DOCKER_CALLS" ||
  fail 'protected product build omitted minimal BuildKit SLSA provenance'
[[ "$(build_invocation_count)" -eq 1 ]] ||
  fail 'image was not built exactly once'

printf '0\n' >"$work/login-state"
login_calls_before="$(grep -c ' login ' "$FAKE_DOCKER_CALLS" || true)"
(
  cd "$ROOT"
  FAKE_LOGIN_FAILURES=1 FAKE_LOGIN_STATE="$work/login-state" \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
) >"$work/transient-login.out" 2>&1
grep -qF 'Registry login was rejected; retrying authentication' \
  "$work/transient-login.out" || fail 'transient initial registry login was not reported'
[[ "$(grep -c ' login ' "$FAKE_DOCKER_CALLS")" -eq $((login_calls_before + 2)) ]] ||
  fail 'transient initial registry login was not retried exactly once'

: >"$GITHUB_OUTPUT"
(
  cd "$ROOT"
  FAKE_DIGEST="$second_digest" \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
)
[[ "$(build_invocation_count)" -eq 1 ]] ||
  fail 'existing source-SHA image was rebuilt'
grep -qxF "candidate_ref=nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway@$digest" "$GITHUB_OUTPUT" ||
  fail 'source-SHA rerun did not preserve the original digest'

: >"$GITHUB_OUTPUT"
(
  cd "$ROOT"
  FAKE_DIGEST="$second_digest" \
  CODEWIRE_BASE_IMAGE_REF="$base_ref" \
    "$BUILDER" workspace images/workspace/Dockerfile .
)
grep -qxF 'family=workspace' "$GITHUB_OUTPUT" ||
  fail 'workspace candidate family is absent'
grep -qF -- "--build-arg BASE_IMAGE_REF=$base_ref" "$FAKE_DOCKER_CALLS" ||
  fail 'exact base digest did not reach the workspace build'
[[ "$(build_invocation_count)" -eq 2 ]] ||
  fail 'workspace image was not built exactly once'

: >"$GITHUB_OUTPUT"
create_calls_before="$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS" || true)"
(
  cd "$ROOT"
  REQUIRE_EXISTING_SOURCE_IMAGE=1 \
  CODEWIRE_RELEASE_TAG='v0.3.999' \
  CODEWIRE_SOURCE_SHA="$source_sha" \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
)
grep -qxF "candidate_ref=nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway@$digest" "$GITHUB_OUTPUT" ||
  fail 'release alias did not preserve the source-SHA digest'
awk -F '\t' \
  -v reference='nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway:v0.3.999' \
  -v digest="$digest" \
  '$1 == reference && $2 == digest { found = 1 } END { exit !found }' \
  "$FAKE_MANIFESTS" ||
  fail 'release alias was not created from the source digest'
[[ "$(build_invocation_count)" -eq 2 ]] ||
  fail 'release alias rebuilt an existing source image'
[[ "$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS")" -eq $((create_calls_before + 1)) ]] ||
  fail 'release alias was not created exactly once'

build_calls_before="$(build_invocation_count)"
if (
  cd "$ROOT"
  REQUIRE_EXISTING_SOURCE_IMAGE=1 \
  CODEWIRE_RELEASE_TAG='v0.3.999' \
  CODEWIRE_SOURCE_SHA="$source_sha" \
    "$BUILDER" services deployments/docker/services.Dockerfile .
) >"$work/required-source-missing.out" 2>&1; then
  fail 'missing required immutable source image was accepted'
fi
grep -qF 'Required immutable source image is missing' \
  "$work/required-source-missing.out" ||
  fail 'missing required immutable source image did not fail explicitly'
[[ "$(build_invocation_count)" -eq "$build_calls_before" ]] ||
  fail 'missing required immutable source image reached a build'

: >"$GITHUB_OUTPUT"
(
  cd "$ROOT"
  CODEWIRE_RELEASE_TAG='v0.3.999' \
  CODEWIRE_SOURCE_SHA="$source_sha" \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
)
[[ "$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS")" -eq $((create_calls_before + 1)) ]] ||
  fail 'matching release alias was rewritten'

printf '0\n' >"$work/inspect-auth-state"
login_calls_before="$(grep -c ' login ' "$FAKE_DOCKER_CALLS" || true)"
create_calls_before_auth="$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS" || true)"
(
  cd "$ROOT"
  FAKE_INSPECT_AUTH_ONCE_REF='nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway:v0.3.997' \
  FAKE_INSPECT_AUTH_STATE="$work/inspect-auth-state" \
  CODEWIRE_RELEASE_TAG='v0.3.997' \
  CODEWIRE_SOURCE_SHA="$source_sha" \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
) >"$work/transient-auth.out" 2>&1
grep -qF 'Registry authentication expired while inspecting' \
  "$work/transient-auth.out" || fail 'transient registry auth was not reported'
[[ "$(grep -c ' login ' "$FAKE_DOCKER_CALLS")" -eq $((login_calls_before + 2)) ]] ||
  fail 'transient registry auth did not perform exactly one bounded re-login'
[[ "$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS")" -eq $((create_calls_before_auth + 1)) ]] ||
  fail 'transient registry auth did not resume immutable alias creation'

printf '0\n' >"$work/create-auth-state"
login_calls_before="$(grep -c ' login ' "$FAKE_DOCKER_CALLS" || true)"
create_calls_before_auth="$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS" || true)"
(
  cd "$ROOT"
  FAKE_CREATE_AUTH_ONCE_REF='nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway:v0.3.996' \
  FAKE_CREATE_AUTH_STATE="$work/create-auth-state" \
  CODEWIRE_RELEASE_TAG='v0.3.996' \
  CODEWIRE_SOURCE_SHA="$source_sha" \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
) >"$work/transient-create-auth.out" 2>&1
grep -qF 'Registry authentication expired while creating' \
  "$work/transient-create-auth.out" || fail 'transient create auth was not reported'
[[ "$(grep -c ' login ' "$FAKE_DOCKER_CALLS")" -eq $((login_calls_before + 2)) ]] ||
  fail 'transient create auth did not perform exactly one bounded re-login'
[[ "$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS")" -eq $((create_calls_before_auth + 2)) ]] ||
  fail 'transient create auth was not retried exactly once'

printf '%s\t%s\n' \
  'nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway:v0.3.998' "$mismatch_digest" \
  >>"$FAKE_MANIFESTS"
if (
  cd "$ROOT"
  CODEWIRE_RELEASE_TAG='v0.3.998' \
  CODEWIRE_SOURCE_SHA="$source_sha" \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
) >"$work/mismatched-alias.out" 2>&1; then
  fail 'mismatched immutable release alias was accepted'
fi
grep -qF 'Refusing to replace immutable image tag' "$work/mismatched-alias.out" ||
  fail 'mismatched release alias did not fail with the immutable-tag guard'
[[ "$(build_invocation_count)" -eq 2 ]] ||
  fail 'mismatched release alias triggered a build'

export FAKE_INSPECT_ERROR_REF="nexus-system-cluster.example.invalid/oci-promoted/codewire/mesh:$source_sha"
login_calls_before="$(grep -c ' login ' "$FAKE_DOCKER_CALLS" || true)"
if (
  cd "$ROOT"
  "$BUILDER" mesh deployments/docker/mesh.Dockerfile .
) >"$work/inspect-error.out" 2>&1; then
  fail 'registry inspection error was treated as a missing image'
fi
unset FAKE_INSPECT_ERROR_REF
grep -qF 'Unable to determine whether immutable image tag exists' \
  "$work/inspect-error.out" || fail 'registry inspection error was not reported'
[[ "$(build_invocation_count)" -eq 2 ]] ||
  fail 'registry inspection error reached a build'
[[ "$(grep -c ' login ' "$FAKE_DOCKER_CALLS")" -eq $((login_calls_before + 3)) ]] ||
  fail 'persistent registry auth did not stop after two bounded re-logins'

fetch_calls_before="$(wc -l <"$FAKE_FETCH_CALLS")"
if (
  cd "$ROOT"
  REQUIRE_EXISTING_SOURCE_IMAGE=yes \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
) >"$work/invalid-require-existing.out" 2>&1; then
  fail 'invalid existing-source requirement was accepted'
fi
grep -qF 'REQUIRE_EXISTING_SOURCE_IMAGE must be 0 or 1' \
  "$work/invalid-require-existing.out" ||
  fail 'invalid existing-source requirement did not fail explicitly'
[[ "$(wc -l <"$FAKE_FETCH_CALLS")" -eq "$fetch_calls_before" ]] ||
  fail 'invalid existing-source requirement reached credential retrieval'

if (
  cd "$ROOT"
  CODEWIRE_BASE_IMAGE_REF='nexus-system-cluster.example.invalid/oci-promoted/codewire/base:latest' \
    "$BUILDER" workspace images/workspace/Dockerfile .
) >"$work/moving-base.out" 2>&1; then
  fail 'moving workspace base image was accepted'
fi
[[ "$(wc -l <"$FAKE_FETCH_CALLS")" -eq "$fetch_calls_before" ]] ||
  fail 'invalid workspace base reached credential retrieval'

if (
  cd "$ROOT"
  CODEWIRE_BASE_IMAGE_REF="$base_ref" \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
) >"$work/non-workspace-base.out" 2>&1; then
  fail 'workspace base argument was accepted for another image family'
fi
[[ "$(wc -l <"$FAKE_FETCH_CALLS")" -eq "$fetch_calls_before" ]] ||
  fail 'non-workspace base argument reached credential retrieval'

if grep -qF "$registry_username" "$FAKE_FETCH_CALLS" \
  || grep -qF "$registry_password" "$FAKE_DOCKER_CALLS" \
  || grep -qF "$registry_password" "$FAKE_FETCH_CALLS"; then
  fail 'a registry credential reached command arguments or fetch logs'
fi

docker_config="$(sed -nE 's/^DOCKER_CONFIG=([^ ]+).* login.*/\1/p' \
  "$FAKE_DOCKER_CALLS" | head -1)"
[[ -n "$docker_config" && ! -e "$docker_config" ]] ||
  fail 'private Docker credential directory survived the build'

: >"$FAKE_DOCKER_CALLS"
(
  cd "$ROOT"
  CODEWIRE_DOCKER_BIN="$work/bin/docker" \
  CODEWIRE_BAKE_METADATA_FILE="$work/kind-r2-metadata.json" \
  CODEWIRE_SCCACHE_MODE=r2 \
  CODEWIRE_SCCACHE_CREDENTIALS_FILE="$r2_credentials_file" \
  SCCACHE_BUCKET=codewire-ci \
  SCCACHE_ENDPOINT=https://account.r2.cloudflarestorage.com \
  CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/test \
    "$KIND_BUILDER"
)
[[ "$(grep -oF 'secret=id=aws_shared_credentials\,src=' "$FAKE_DOCKER_CALLS" | wc -l)" -eq 4 ]] ||
  fail 'Kind did not bind the private credential file to all four Bake targets'
grep -qF "src=$r2_credentials_file" "$FAKE_DOCKER_CALLS" ||
  fail 'Kind did not pass the exact private credential file path to Bake'

: >"$FAKE_DOCKER_CALLS"
(
  cd "$ROOT"
  CODEWIRE_SCCACHE_MODE=r2 \
  CODEWIRE_SCCACHE_CREDENTIALS_FILE="$r2_credentials_file" \
  SCCACHE_BUCKET=codewire-ci \
  SCCACHE_ENDPOINT=https://account.r2.cloudflarestorage.com \
  CODEWIRE_SCCACHE_PREFIX=protected/codewire/test \
    "$BUILDER" derp deployments/docker/derp.Dockerfile .
)
grep -qF 'secret=id=aws_shared_credentials\,src=' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not bind the private credential file to Bake'
grep -qF "src=$r2_credentials_file" "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not pass the exact private credential file path to Bake'
if grep -qE 'untrusted-(access-key|secret-key)' "$FAKE_DOCKER_CALLS"; then
  fail 'R2 credential material reached Docker command arguments'
fi

kind_builds_before="$(grep -Ec ' buildx bake .* kind $' "$FAKE_DOCKER_CALLS" || true)"
(
  cd "$ROOT"
  CODEWIRE_DOCKER_BIN="$work/bin/docker" \
  CODEWIRE_BAKE_METADATA_FILE="$work/kind-metadata.json" \
    "$KIND_BUILDER"
) >"$work/kind-build.out"
[[ "$(grep -Ec ' buildx bake .* kind $' "$FAKE_DOCKER_CALLS" || true)" -eq \
  $((kind_builds_before + 1)) ]] || fail 'Kind did not issue exactly one Bake graph build'
[[ "$(grep -c ' image inspect ' "$FAKE_DOCKER_CALLS" || true)" -eq 12 ]] ||
  fail 'Kind did not verify existence and trust labels for all four loaded images'
grep -qF 'CODEWIRE_CI_PHASE name=product-image-build' "$work/kind-build.out" ||
  fail 'Kind image builder omitted its structured phase result'

echo 'build-push immutable source image tests passed'
