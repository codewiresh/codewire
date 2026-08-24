#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUILDER="$ROOT/scripts/ci/images/build-push-image.sh"
readonly RUNTIME_BUILDER="$ROOT/scripts/ci/images/build-push-runtime-images.sh"
readonly NEXUS_RETRY_CONTRACT="$ROOT/scripts/ci/images/nexus-publication-retry-contract.sh"
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
  tenant-secret-operator
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

grep -Fq 'CODEWIRE_EXTERNAL_BUILDX_BUILDER' "$BUILDER" ||
  fail 'published-image builder cannot join the job-scoped BuildKit daemon'
grep -Fq 'CODEWIRE_EXTERNAL_DOCKER_CONFIG' "$BUILDER" ||
  fail 'published-image builder cannot share private job-scoped registry auth'
grep -Fq 'buildx_builder_owned=0' "$BUILDER" ||
  fail 'published-image builder does not distinguish caller-owned BuildKit state'
for protected_builder in "$BUILDER" "$RUNTIME_BUILDER"; do
  # shellcheck disable=SC2016 # Match the literal sourced contract path.
  grep -Fq 'source "$ROOT/scripts/ci/images/nexus-publication-retry-contract.sh"' \
    "$protected_builder" || fail "$(basename "$protected_builder") bypasses the shared Nexus retry contract"
  if grep -Eq '^readonly NEXUS_BACKUP_RETRY_(ATTEMPTS|DELAY_SECONDS)=' "$protected_builder"; then
    fail "$(basename "$protected_builder") duplicates the shared Nexus retry contract"
  fi
done
grep -Fq 'NEXUS_BACKUP_RETRY_ATTEMPTS=61' "$NEXUS_RETRY_CONTRACT" ||
  fail 'shared Nexus retry contract lacks sixty bounded maintenance waits'
grep -Fq 'NEXUS_BACKUP_RETRY_DELAY_SECONDS=60' "$NEXUS_RETRY_CONTRACT" ||
  fail 'shared Nexus retry contract changed its fixed one-minute delay'
grep -Fq '503 Service (Temporarily )?Unavailable' "$BUILDER" ||
  fail 'published-image retry is not restricted to the observed Nexus outage'
# shellcheck disable=SC2016 # This assertion intentionally matches literal shell source.
grep -Fq 'docker buildx inspect "$buildx_builder"' "$BUILDER" ||
  fail 'published-image builder does not validate an external BuildKit daemon'

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
  grep -qF "'  max-parallelism = 2'" "$KIND_BUILDER" ||
    fail 'Kind image builder lacks the CPX42 memory bound'
  grep -qF 'moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5' \
    "$KIND_BUILDER" || fail 'Kind image builder does not pin BuildKit'
  [[ "$(grep -cF 'buildx bake' "$KIND_BUILDER")" -eq 1 ]] ||
    fail 'Kind must issue exactly one canonical Bake build'
  grep -qF '$target.secrets+=id=aws_shared_credentials,src=$credentials_file' \
    "$KIND_BUILDER" ||
    fail 'Kind does not append its new secret through supported Bake override syntax'
  grep -qF '$product_bake_target.secrets+=id=aws_shared_credentials,src=$credentials_file' \
    "$BUILDER" ||
    fail 'protected image builds do not append their new secret through supported Bake override syntax'
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
  grep -qF 'export SCCACHE_MULTILEVEL_CHAIN=disk,s3' "$RUST_BUILD_WRAPPER" ||
    fail 'R2 mode does not retain the job-local cache as its first level'
  grep -qF 'export SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY=ignore' "$RUST_BUILD_WRAPPER" ||
    fail 'R2 write failure can stop a correctness-valid build'
  grep -qF 'export SCCACHE_IGNORE_SERVER_IO_ERROR=1' "$RUST_BUILD_WRAPPER" ||
    fail 'R2 communication failure cannot fall back to the local compiler'
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
approved_registry_username='nexus-approved-reader-test'
approved_registry_password='approved-registry-test-value'
digest="sha256:$(printf 'd%.0s' {1..64})"
second_digest="sha256:$(printf 'f%.0s' {1..64})"
mismatch_digest="sha256:$(printf 'c%.0s' {1..64})"
source_sha="$(git -C "$ROOT" rev-parse HEAD)"
source_remote_before="$(git -C "$ROOT" remote get-url origin)"
source_worktree="$work/clean-source"
git -C "$ROOT" worktree add --detach "$source_worktree" "$source_sha" >/dev/null
cleanup() {
  git -C "$ROOT" worktree remove --force "$source_worktree" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
base_digest="sha256:$(printf 'e%.0s' {1..64})"
base_ref="nexus-system-cluster.example.invalid/oci-promoted/codewire/base@$base_digest"

cat >"$work/bin/fetch-nexus" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == --approved ]]; then
  username="${FAKE_APPROVED_REGISTRY_USERNAME:?}"
  password="${FAKE_APPROVED_REGISTRY_PASSWORD:?}"
  shift
else
  username="${FAKE_REGISTRY_USERNAME:?}"
  password="${FAKE_REGISTRY_PASSWORD:?}"
fi
printf '%s' "$username" >"$1"
printf '%s' "$password" >"$2"
chmod 0600 "$1" "$2"
printf '%q %q\n' "$1" "$2" >>"${FAKE_FETCH_CALLS:?}"
EOF

cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'DOCKER_CONFIG=%q ' "${DOCKER_CONFIG:-}" >>"${FAKE_DOCKER_CALLS:?}"
printf 'CODEWIRE_IMAGE_SOURCE_SHA=%q CODEWIRE_RUST_PROFILE=%q CODEWIRE_SCCACHE_MODE=%q GIT_REMOTE=%q ' \
  "${CODEWIRE_IMAGE_SOURCE_SHA:-}" "${CODEWIRE_RUST_PROFILE:-}" "${CODEWIRE_SCCACHE_MODE:-}" \
  "$(git -C "${CODEWIRE_SOURCE_DIR:-.}" remote get-url origin)" \
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
  login\ nexus-system-cluster.example.invalid\ *|login\ nexus.example.invalid\ *)
    registry_host="$2"
    case "$registry_host" in
      nexus-system-cluster.example.invalid)
        expected_username="${FAKE_REGISTRY_USERNAME:?}"
        expected_password="${FAKE_REGISTRY_PASSWORD:?}"
        ;;
      nexus.example.invalid)
        expected_username="${FAKE_APPROVED_REGISTRY_USERNAME:?}"
        expected_password="${FAKE_APPROVED_REGISTRY_PASSWORD:?}"
        ;;
      *) exit 1 ;;
    esac
    credential="$(cat)"
    [[ "$credential" == "$expected_password" ]]
    [[ "$*" == *" -u $expected_username "* ]]
    if [ -n "${FAKE_LOGIN_FAILURES:-}" ]; then
      login_state="${FAKE_LOGIN_STATE:?}"
      login_count="$(cat "$login_state")"
      if [ "$login_count" -lt "$FAKE_LOGIN_FAILURES" ]; then
        printf '%s\n' "$((login_count + 1))" >"$login_state"
        echo 'Error response from daemon: Nexus login failed with status: 401 Unauthorized' >&2
        exit 1
      fi
    fi
    if [ "$registry_host" = nexus-system-cluster.example.invalid ] \
        && [ -n "${FAKE_LOGIN_NEXUS_FAILURES:-}" ]; then
      login_state="${FAKE_LOGIN_NEXUS_STATE:?}"
      login_count="$(cat "$login_state")"
      if [ "$login_count" -lt "$FAKE_LOGIN_NEXUS_FAILURES" ]; then
        printf '%s\n' "$((login_count + 1))" >"$login_state"
        echo "Error response from daemon: login attempt to https://${registry_host}/v2/ failed with status: 503 Service Unavailable" >&2
        exit 1
      fi
    fi
    mkdir -p "${DOCKER_CONFIG:?}"
    printf '{}\n' >"$DOCKER_CONFIG/config.json"
    ;;
  'buildx imagetools inspect')
    shift 3
    reference=''
    format=''
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --format)
          format="$2"
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
    if [ "$format" = '{{json .Provenance.SLSA}}' ]; then
      jq -n \
        --arg builder "${FAKE_PROVENANCE_BUILDER_ID:?}" \
        --arg revision "${FAKE_SOURCE_SHA:?}" \
        --arg source 'https://git.example.invalid/codewire/codewire.git' \
        --argjson envelope "${FAKE_PROVENANCE_ENVELOPE:-false}" '
          {
            buildDefinition: {
              buildType: "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
              internalParameters: {builderPlatform: "linux/amd64"}
            },
            runDetails: {
              builder: {id: $builder},
              metadata: {buildkit_metadata: {vcs: {revision: $revision, source: $source}}}
            }
          }
          | if $envelope then {
              _type: "https://in-toto.io/Statement/v1",
              predicateType: "https://slsa.dev/provenance/v1",
              predicate: .
            }
            else .
            end
        '
      exit 0
    fi
    if [ "$format" = '{{json .SBOM.SPDX}}' ]; then
      if [ "${FAKE_SBOM_INVALID:-0}" = 1 ]; then
        jq -n '{spdxVersion: "SPDX-2.3", packages: []}'
      else
        jq -n '{
          spdxVersion: "SPDX-2.3",
          documentNamespace: "https://codewire.example/sbom/test",
          packages: [{name: "codewire-test"}]
        }'
      fi
      exit 0
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
  buildx\ create\ *)
    [[ "$*" == *' --driver docker-container '* ]]
    [[ "$*" == *' --driver-opt image=docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5 '* ]]
    [[ "$*" == *' --bootstrap'* ]]
    ;;
  buildx\ rm\ *)
    [[ "$*" == *' --force '* ]]
    ;;
  buildx\ bake\ *)
    if [ -n "${FAKE_BUILD_NEXUS_FAILURES:-}" ]; then
      build_state="${FAKE_BUILD_STATE:?}"
      build_count="$(cat "$build_state")"
      if [ "$build_count" -lt "$FAKE_BUILD_NEXUS_FAILURES" ]; then
        printf '%s\n' "$((build_count + 1))" >"$build_state"
        echo 'unexpected status from HEAD request to https://nexus-system-cluster.example.invalid/v2/oci-promoted/codewire/test/blobs/sha256:test: 503 Service Temporarily Unavailable' >&2
        exit 1
      fi
    fi
    if [ "${FAKE_BUILD_FATAL:-0}" = 1 ]; then
      echo 'non-retryable BuildKit failure' >&2
      exit 1
    fi
    metadata=''
    targets=()
    declare -A tags_by_target=()
    shift 2
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --builder)
          shift 2
          ;;
        --metadata-file)
          metadata="$2"
          shift 2
          ;;
        --set)
          case "$2" in
            *.tags=*)
              setting_target="${2%%.tags=*}"
              tags_by_target["$setting_target"]="${2#*=}"
              ;;
          esac
          shift 2
          ;;
        --file|--provenance|--progress)
          shift 2
          ;;
        --push|--pull|--load|--sbom=generator=*)
          shift
          ;;
        *)
          targets+=("$1")
          shift
          ;;
      esac
    done
    [[ -n "$metadata" && "${#targets[@]}" -gt 0 ]]
    if [ "${#targets[@]}" -eq 1 ] && [ "${targets[0]}" = kind ]; then
      jq -n '{
        "dashboard-ci": {},
        "services-ci": {},
        "mesh-ci": {},
        "gateway-ci": {}
      }' >"$metadata"
      exit 0
    fi
    if [ "${#targets[@]}" -eq 1 ] && [ "${targets[0]}" = default ]; then
      targets=(dashboard services mesh gateway derp)
    fi
    printf '{}\n' >"$metadata"
    for target in "${targets[@]}"; do
      [[ -n "${tags_by_target[$target]:-}" ]]
      jq --arg target "$target" --arg digest "${FAKE_DIGEST:?}" \
        '. + {($target): {"containerimage.digest": $digest}}' \
        "$metadata" >"$metadata.tmp"
      mv "$metadata.tmp" "$metadata"
      set_manifest "${tags_by_target[$target]}" "$FAKE_DIGEST"
    done
    ;;
  image\ inspect\ *)
    case "$*" in
      *dev.codewire.build.profile*) printf 'ci\n' ;;
      *dev.codewire.promotable*) printf 'false\n' ;;
    esac
    ;;
  buildx\ build\ *)
    if [ -n "${FAKE_BUILD_NEXUS_FAILURES:-}" ]; then
      build_state="${FAKE_BUILD_STATE:?}"
      build_count="$(cat "$build_state")"
      if [ "$build_count" -lt "$FAKE_BUILD_NEXUS_FAILURES" ]; then
        printf '%s\n' "$((build_count + 1))" >"$build_state"
        echo 'unexpected status from HEAD request to https://nexus-system-cluster.example.invalid/v2/oci-promoted/codewire/test/blobs/sha256:test: 503 Service Temporarily Unavailable' >&2
        exit 1
      fi
    fi
    if [ "${FAKE_BUILD_FATAL:-0}" = 1 ]; then
      echo 'non-retryable BuildKit failure' >&2
      exit 1
    fi
    metadata=''
    tags=()
    shift 2
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --builder)
          shift 2
          ;;
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
        --push|--provenance=*|--sbom=generator=*)
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
printf 'AWS_SHARED_CREDENTIALS_FILE=%s AWS_PROFILE=%s AWS_EC2_METADATA_DISABLED=%s AWS_ACCESS_KEY_ID=%s SCCACHE_DIR=%s MULTILEVEL=%s WRITE_POLICY=%s IGNORE_IO=%s command=%s\n' \
  "${AWS_SHARED_CREDENTIALS_FILE:-}" "${AWS_PROFILE:-}" \
  "${AWS_EC2_METADATA_DISABLED:-}" "${AWS_ACCESS_KEY_ID:-}" \
  "${SCCACHE_DIR:-}" \
  "${SCCACHE_MULTILEVEL_CHAIN:-}" "${SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY:-}" \
  "${SCCACHE_IGNORE_SERVER_IO_ERROR:-}" "$*" \
  >>"${FAKE_SCCACHE_CALLS:?}"
EOF
cat >"$work/bin/sleep" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_SLEEP_CALLS:?}"
EOF
chmod +x "$work/bin/fetch-nexus" "$work/bin/docker" "$work/bin/sccache" \
  "$work/bin/sleep"

export PATH="$work/bin:$PATH"
export OPENBAO_NEXUS_CREDENTIAL_FETCHER="$work/bin/fetch-nexus"
export FAKE_REGISTRY_USERNAME="$registry_username"
export FAKE_REGISTRY_PASSWORD="$registry_password"
export FAKE_APPROVED_REGISTRY_USERNAME="$approved_registry_username"
export FAKE_APPROVED_REGISTRY_PASSWORD="$approved_registry_password"
export FAKE_FETCH_CALLS="$work/fetch-calls"
export FAKE_DOCKER_CALLS="$work/docker-calls"
export FAKE_SCCACHE_CALLS="$work/sccache-calls"
export FAKE_SLEEP_CALLS="$work/sleep-calls"
export FAKE_MANIFESTS="$work/manifests"
export FAKE_DIGEST="$digest"
export FAKE_PROVENANCE_BUILDER_ID='https://git.example.invalid/infra/ci/builders/protected-delivery/v1'
export FAKE_SOURCE_SHA="$source_sha"
export CODEWIRE_SOURCE_DIR="$source_worktree"
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
grep -qF 'MULTILEVEL=disk,s3 WRITE_POLICY=ignore IGNORE_IO=1' "$FAKE_SCCACHE_CALLS" ||
  fail 'Rust build wrapper did not activate cold-safe multilevel R2 behavior'
grep -qF 'SCCACHE_DIR=/var/cache/sccache MULTILEVEL=disk,s3' "$FAKE_SCCACHE_CALLS" ||
  fail 'Rust build wrapper did not bind the disk cache level to its BuildKit cache mount'

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
grep -qF -- 'builder-id=https://git.example.invalid/infra/ci/builders/protected-delivery/v1' "$FAKE_DOCKER_CALLS" ||
  fail 'protected product build omitted its explicit minimal BuildKit SLSA provenance identity'
grep -qF -- 'version=v1' "$FAKE_DOCKER_CALLS" ||
  fail 'protected product build did not request the verified SLSA v1 predicate'
grep -qF -- 'buildx create --name codewire-publish-' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not create an isolated BuildKit builder'
grep -qF -- '--driver docker-container' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication retained the attestation-incompatible Docker driver'
grep -qF -- '--driver-opt provenance-add-gha=false' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication may leak the Forgejo event payload into public provenance'
grep -qF -- 'GIT_REMOTE=https://git.example.invalid/codewire/codewire.git' \
  "$FAKE_DOCKER_CALLS" || fail 'protected provenance does not build from the canonical source remote'
grep -qF -- 'Provenance.SLSA' \
  "$FAKE_DOCKER_CALLS" || fail 'protected publication did not verify its emitted SLSA predicate'
grep -qF -- '--sbom=generator=nexus.example.invalid/oci-approved/docker/buildkit-syft-scanner@sha256:13864237fb990943433f89d698590aad1de38d4a7e13d38e7b12f2488c1952e7' \
  "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not request an SBOM from the approved exact generator'
grep -qF ' login nexus-system-cluster.example.invalid ' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not use its scoped promoted-output login'
grep -qF ' login nexus.example.invalid ' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not use its scoped approved-input login'
grep -qF -- 'SBOM.SPDX' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not verify its emitted SPDX SBOM'
grep -qF -- 'image=docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5' \
  "$FAKE_DOCKER_CALLS" || fail 'protected publication does not pin its BuildKit daemon image'
grep -qF -- 'buildx rm --force codewire-publish-' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not remove its isolated BuildKit builder'
[[ "$(build_invocation_count)" -eq 1 ]] ||
  fail 'image was not built exactly once'
[[ "$(git -C "$ROOT" remote get-url origin)" == "$source_remote_before" ]] ||
  fail 'protected image publication did not restore the checkout origin remote'

if ! (
  cd "$ROOT"
  FAKE_PROVENANCE_ENVELOPE=true \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
); then
  fail 'protected image build rejected the valid SLSA v1 statement envelope'
fi
[[ "$(build_invocation_count)" -eq 1 ]] ||
  fail 'SLSA statement-envelope verification rebuilt an immutable source image'

if (
  cd "$ROOT"
  CODEWIRE_PROVENANCE_BUILDER_ID=https://attacker.invalid/builder \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
) >"$work/unrecognized-builder.out" 2>"$work/unrecognized-builder.err"; then
  fail 'protected image build accepted an unrecognized builder identity'
fi
grep -qF 'unrecognized provenance builder identity' \
  "$work/unrecognized-builder.err" ||
  fail 'unrecognized provenance builder rejection was not attributable'

if (
  cd "$ROOT"
  FAKE_PROVENANCE_BUILDER_ID=https://attacker.invalid/builder \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
) >"$work/invalid-provenance.out" 2>"$work/invalid-provenance.err"; then
  fail 'protected image build accepted provenance from a different builder'
fi
grep -qF 'Protected image provenance is invalid' \
  "$work/invalid-provenance.err" ||
  fail 'invalid emitted provenance rejection was not attributable'
[[ "$(build_invocation_count)" -eq 1 ]] ||
  fail 'provenance rejection rebuilt an immutable source image'

if (
  cd "$ROOT"
  FAKE_SBOM_INVALID=1 \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
) >"$work/invalid-sbom.out" 2>"$work/invalid-sbom.err"; then
  fail 'protected image build accepted an invalid SPDX SBOM'
fi
grep -qF 'Protected image SBOM is invalid' \
  "$work/invalid-sbom.err" ||
  fail 'invalid emitted SBOM rejection was not attributable'
[[ "$(build_invocation_count)" -eq 1 ]] ||
  fail 'SBOM rejection rebuilt an immutable source image'

printf '0\n' >"$work/login-state"
login_calls_before="$(grep -c ' login ' "$FAKE_DOCKER_CALLS" || true)"
(
  cd "$ROOT"
  FAKE_LOGIN_FAILURES=1 FAKE_LOGIN_STATE="$work/login-state" \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
) >"$work/transient-login.out" 2>&1
grep -qF 'Registry login was rejected; retrying authentication' \
  "$work/transient-login.out" || fail 'transient initial registry login was not reported'
[[ "$(grep -c ' login ' "$FAKE_DOCKER_CALLS")" -eq $((login_calls_before + 3)) ]] ||
  fail 'transient initial registry login was not retried exactly once'

printf '0\n' >"$work/login-nexus-state"
: >"$FAKE_SLEEP_CALLS"
login_calls_before="$(grep -c ' login ' "$FAKE_DOCKER_CALLS" || true)"
(
  cd "$ROOT"
  FAKE_LOGIN_NEXUS_FAILURES=2 \
  FAKE_LOGIN_NEXUS_STATE="$work/login-nexus-state" \
    "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
) >"$work/transient-nexus-login.out" 2>&1
[[ "$(cat "$work/login-nexus-state")" -eq 2 ]] ||
  fail 'transient Nexus login did not consume both simulated failures'
[[ "$(grep -c ' login ' "$FAKE_DOCKER_CALLS")" -eq $((login_calls_before + 4)) ]] ||
  fail 'transient Nexus login did not retry twice before the approved login'
[[ "$(grep -cxF '60' "$FAKE_SLEEP_CALLS")" -eq 2 ]] ||
  fail 'transient Nexus login did not use the bounded retry delay'
grep -qF 'retrying nexus-system-cluster.example.invalid (2/61)' \
  "$work/transient-nexus-login.out" ||
  fail 'transient Nexus login retry was not attributable'

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
[[ "$(grep -c ' login ' "$FAKE_DOCKER_CALLS")" -eq $((login_calls_before + 3)) ]] ||
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
[[ "$(grep -c ' login ' "$FAKE_DOCKER_CALLS")" -eq $((login_calls_before + 3)) ]] ||
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
[[ "$(grep -c ' login ' "$FAKE_DOCKER_CALLS")" -eq $((login_calls_before + 4)) ]] ||
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
  || grep -qF "$registry_password" "$FAKE_FETCH_CALLS" \
  || grep -qF "$approved_registry_username" "$FAKE_FETCH_CALLS" \
  || grep -qF "$approved_registry_password" "$FAKE_DOCKER_CALLS" \
  || grep -qF "$approved_registry_password" "$FAKE_FETCH_CALLS"; then
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
[[ "$(grep -oF 'secrets+=id=aws_shared_credentials\,src=' "$FAKE_DOCKER_CALLS" | wc -l)" -eq 4 ]] ||
  fail 'Kind did not bind and append the private credential file to all four Bake targets'
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
grep -qF 'secrets+=id=aws_shared_credentials\,src=' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not bind and append the Bake secret with supported syntax'
grep -qF "src=$r2_credentials_file" "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not pass the exact private credential file path to Bake'
if grep -qE 'untrusted-(access-key|secret-key)' "$FAKE_DOCKER_CALLS"; then
  fail 'R2 credential material reached Docker command arguments'
fi

for family in dashboard services mesh gateway derp; do
  awk -F '\t' \
    -v reference="nexus-system-cluster.example.invalid/oci-promoted/codewire/${family}:$source_sha" \
    '$1 != reference' "$FAKE_MANIFESTS" >"$FAKE_MANIFESTS.tmp"
  mv "$FAKE_MANIFESTS.tmp" "$FAKE_MANIFESTS"
done
runtime_builds_before="$(build_invocation_count)"
: >"$GITHUB_OUTPUT"
(
  cd "$ROOT"
  CODEWIRE_BUILD_RUNTIME_SET=1 \
  CODEWIRE_SCCACHE_MODE=r2 \
  CODEWIRE_SCCACHE_CREDENTIALS_FILE="$r2_credentials_file" \
  SCCACHE_BUCKET=codewire-ci \
  SCCACHE_ENDPOINT=https://account.r2.cloudflarestorage.com \
  CODEWIRE_SCCACHE_PREFIX=protected/codewire/test \
    "$BUILDER" services deployments/docker/services.Dockerfile .
)
[[ "$(build_invocation_count)" -eq $((runtime_builds_before + 1)) ]] ||
  fail 'protected runtime set did not issue exactly one additional Bake build'
grep -Eq ' buildx bake .* default $' "$FAKE_DOCKER_CALLS" ||
  fail 'protected runtime set did not execute the canonical five-target Bake group'
runtime_set_call="$(grep -E ' buildx bake .* default $' "$FAKE_DOCKER_CALLS" | tail -1)"
[[ "$(grep -oF 'secrets+=id=aws_shared_credentials\,src=' <<<"$runtime_set_call" | wc -l)" -eq 5 ]] ||
  fail 'protected runtime Bake did not bind the private cache credential to all five targets'
for family in dashboard services mesh gateway derp; do
  grep -qF -- "${family}.tags=nexus-system-cluster.example.invalid/oci-promoted/codewire/${family}:$source_sha" \
    "$FAKE_DOCKER_CALLS" || fail "protected runtime Bake omitted exact $family source tag"
  awk -F '\t' \
    -v reference="nexus-system-cluster.example.invalid/oci-promoted/codewire/${family}:$source_sha" \
    -v digest="$digest" \
    '$1 == reference && $2 == digest { found = 1 } END { exit !found }' \
    "$FAKE_MANIFESTS" || fail "protected runtime Bake omitted the $family manifest"
done
grep -qxF "candidate_ref=nexus-system-cluster.example.invalid/oci-promoted/codewire/services@$digest" \
  "$GITHUB_OUTPUT" || fail 'protected runtime Bake did not preserve the anchor candidate digest'

awk -F '\t' \
  -v reference="nexus-system-cluster.example.invalid/oci-promoted/codewire/mesh:$source_sha" \
  '$1 != reference' "$FAKE_MANIFESTS" >"$FAKE_MANIFESTS.tmp"
mv "$FAKE_MANIFESTS.tmp" "$FAKE_MANIFESTS"
partial_runtime_builds_before="$(build_invocation_count)"
if (
  cd "$ROOT"
  CODEWIRE_BUILD_RUNTIME_SET=1 \
  REQUIRE_EXISTING_SOURCE_IMAGE=1 \
    "$BUILDER" services deployments/docker/services.Dockerfile .
) >"$work/required-runtime-set-missing.out" 2>&1; then
  fail 'missing required immutable runtime-set image was accepted'
fi
grep -qF 'Required immutable runtime-set source images are missing: mesh' \
  "$work/required-runtime-set-missing.out" ||
  fail 'missing required runtime-set image did not fail explicitly'
[[ "$(build_invocation_count)" -eq "$partial_runtime_builds_before" ]] ||
  fail 'missing required runtime-set image reached a build'
(
  cd "$ROOT"
  CODEWIRE_BUILD_RUNTIME_SET=1 \
    "$BUILDER" services deployments/docker/services.Dockerfile .
)
[[ "$(build_invocation_count)" -eq $((partial_runtime_builds_before + 1)) ]] ||
  fail 'partial protected runtime retry did not issue exactly one Bake build'
partial_runtime_call="$(grep -E ' buildx bake ' "$FAKE_DOCKER_CALLS" | tail -1)"
[[ "$partial_runtime_call" == *' mesh ' ]] ||
  fail 'partial protected runtime retry did not rebuild only the missing target'
[[ "$partial_runtime_call" != *'services.tags='* ]] ||
  fail 'partial protected runtime retry attempted to overwrite an existing immutable target'

fetch_calls_before="$(wc -l <"$FAKE_FETCH_CALLS")"
if (
  cd "$ROOT"
  CODEWIRE_BUILD_RUNTIME_SET=2 \
    "$BUILDER" services deployments/docker/services.Dockerfile .
) >"$work/invalid-runtime-set.out" 2>&1; then
  fail 'invalid protected runtime-set selector was accepted'
fi
grep -qF 'CODEWIRE_BUILD_RUNTIME_SET must be 0 or 1' \
  "$work/invalid-runtime-set.out" || fail 'invalid runtime-set rejection was not attributable'
[[ "$(wc -l <"$FAKE_FETCH_CALLS")" -eq "$fetch_calls_before" ]] ||
  fail 'invalid runtime-set selector reached credential retrieval'

kind_builds_before="$(grep -Ec ' buildx bake .* kind $' "$FAKE_DOCKER_CALLS" || true)"
(
  cd "$ROOT"
  CODEWIRE_DOCKER_BIN="$work/bin/docker" \
  CODEWIRE_BAKE_METADATA_FILE="$work/kind-metadata.json" \
    "$KIND_BUILDER"
) >"$work/kind-build.out"
[[ "$(grep -Ec ' buildx bake .* kind $' "$FAKE_DOCKER_CALLS" || true)" -eq \
  $((kind_builds_before + 1)) ]] || fail 'Kind did not issue exactly one Bake graph build'
grep -Eq ' buildx create --name codewire-kind-.* --driver docker-container .* --buildkitd-config .* --bootstrap ' \
  "$FAKE_DOCKER_CALLS" || fail 'Kind did not create its bounded transient BuildKit daemon'
grep -qF -- '--driver-opt image=docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5' \
  "$FAKE_DOCKER_CALLS" || fail 'Kind did not use the pinned BuildKit daemon image'
grep -Eq ' buildx bake --builder codewire-kind-.* kind $' "$FAKE_DOCKER_CALLS" ||
  fail 'Kind Bake did not use its bounded transient builder'
grep -Eq ' buildx rm --force codewire-kind-' "$FAKE_DOCKER_CALLS" ||
  fail 'Kind did not destroy its transient BuildKit daemon'
[[ "$(grep -c ' image inspect ' "$FAKE_DOCKER_CALLS" || true)" -eq 12 ]] ||
  fail 'Kind did not verify existence and trust labels for all four loaded images'
grep -qF 'CODEWIRE_CI_PHASE name=product-image-build' "$work/kind-build.out" ||
  fail 'Kind image builder omitted its structured phase result'

base_source_tag="nexus-system-cluster.example.invalid/oci-promoted/codewire/base:$source_sha"
awk -F '\t' -v reference="$base_source_tag" \
  '$1 != reference' "$FAKE_MANIFESTS" >"$FAKE_MANIFESTS.tmp"
mv "$FAKE_MANIFESTS.tmp" "$FAKE_MANIFESTS"
printf '0\n' >"$work/build-state"
: >"$FAKE_SLEEP_CALLS"
retry_builds_before="$(build_invocation_count)"
(
  cd "$ROOT"
  FAKE_BUILD_NEXUS_FAILURES=2 \
    FAKE_BUILD_STATE="$work/build-state" \
    "$BUILDER" base images/base/Dockerfile images/base
) >"$work/nexus-retry.out" 2>&1
[[ "$(cat "$work/build-state")" -eq 2 ]] ||
  fail 'published-image build did not consume both simulated Nexus failures'
[[ "$(build_invocation_count)" -eq $((retry_builds_before + 3)) ]] ||
  fail 'published-image build did not retry twice and then succeed'
[[ "$(grep -cxF '60' "$FAKE_SLEEP_CALLS")" -eq 2 ]] ||
  fail 'published-image build did not use the bounded Nexus retry delay'
grep -qF 'retrying the exact base build (2/61)' "$work/nexus-retry.out" ||
  fail 'published-image Nexus retry was not attributable'

awk -F '\t' -v reference="$base_source_tag" \
  '$1 != reference' "$FAKE_MANIFESTS" >"$FAKE_MANIFESTS.tmp"
mv "$FAKE_MANIFESTS.tmp" "$FAKE_MANIFESTS"
: >"$FAKE_SLEEP_CALLS"
fatal_builds_before="$(build_invocation_count)"
if (
  cd "$ROOT"
  FAKE_BUILD_FATAL=1 "$BUILDER" base images/base/Dockerfile images/base
) >"$work/non-retryable-build.out" 2>&1; then
  fail 'non-Nexus BuildKit failure was retried to success'
fi
[[ "$(build_invocation_count)" -eq $((fatal_builds_before + 1)) ]] ||
  fail 'non-Nexus BuildKit failure did not stop after one attempt'
[[ ! -s "$FAKE_SLEEP_CALLS" ]] ||
  fail 'non-Nexus BuildKit failure entered the retry delay'
grep -qF 'non-retryable BuildKit failure' "$work/non-retryable-build.out" ||
  fail 'non-Nexus BuildKit failure was not preserved'

printf 'untrusted build input\n' >"$source_worktree/forbidden-untracked-input"
fetch_calls_before="$(wc -l <"$FAKE_FETCH_CALLS")"
if (
  cd "$ROOT"
  "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
) >"$work/dirty-source.out" 2>&1; then
  fail 'protected image build accepted an untracked source input'
fi
grep -qF 'Protected image build requires no untracked source files' \
  "$work/dirty-source.out" || fail 'dirty source rejection was not attributable'
[[ "$(wc -l <"$FAKE_FETCH_CALLS")" -eq "$fetch_calls_before" ]] ||
  fail 'dirty source rejection reached credential retrieval'

echo 'build-push immutable source image tests passed'
