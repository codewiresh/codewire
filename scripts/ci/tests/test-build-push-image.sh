#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUILDER="$ROOT/scripts/ci/images/build-push-image.sh"
readonly SERVICES_DOCKERFILE="$ROOT/deployments/docker/services.Dockerfile"
readonly SERVICES_DOCKERIGNORE="$ROOT/deployments/docker/services.Dockerfile.dockerignore"
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

mkdir -p "$ROOT/.tmp"

verify_services_dockerfile_contract() {
  local mount binary
  local mounts=(
    'id=codewire-services-cargo-registry,target=/usr/local/cargo/registry,sharing=locked'
    'id=codewire-services-cargo-git,target=/usr/local/cargo/git,sharing=locked'
    'id=codewire-services-release-target,target=/src/target,sharing=locked'
  )

  [[ "$(grep -cF -- '--mount=type=cache' "$SERVICES_DOCKERFILE")" -eq 3 ]] ||
    fail 'services image must have exactly three BuildKit cache mounts'
  for mount in "${mounts[@]}"; do
    grep -qF -- "--mount=type=cache,${mount}" "$SERVICES_DOCKERFILE" ||
      fail "services image is missing cache mount ${mount}"
  done
  grep -qF 'ARG CODEWIRE_CARGO_CACHE_PROBE' "$SERVICES_DOCKERFILE" ||
    fail 'services image is missing its explicit cache-probe invalidator'
  grep -qF 'COPY libs/gateway-proto ./libs/gateway-proto' "$SERVICES_DOCKERFILE" ||
    fail 'services image does not receive the environment daemon protocol schema'
  grep -qF '!libs/gateway-proto/**' "$SERVICES_DOCKERIGNORE" ||
    fail 'services build context excludes the environment daemon protocol schema'
  grep -qF 'find Cargo.toml Cargo.lock crates proto libs/gateway-proto -type f -exec touch {} +' \
    "$SERVICES_DOCKERFILE" ||
    fail 'services image does not revalidate copied workspace inputs'
  grep -qF 'cargo build "$@" --locked --release' "$SERVICES_DOCKERFILE" ||
    fail 'services image does not build the locked release graph'
  if grep -qF 'COPY --from=builder /src/target/' "$SERVICES_DOCKERFILE"; then
    fail 'services runtime stage reads from the non-persistent Cargo target mount'
  fi
  grep -qF 'ARG RUST_IMAGE=rust:1.91-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33' \
    "$SERVICES_DOCKERFILE" || fail 'services Rust builder pin changed'
  grep -qF 'ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818' \
    "$SERVICES_DOCKERFILE" || fail 'services runtime base changed'
  grep -qF "FROM \${RUST_IMAGE} AS builder" "$SERVICES_DOCKERFILE" ||
    fail 'services builder does not consume the reviewed Rust image'
  grep -qF "FROM \${DEBIAN_IMAGE}" "$SERVICES_DOCKERFILE" ||
    fail 'services runtime does not consume the reviewed Debian image'
  grep -qF 'USER 65532:65532' "$SERVICES_DOCKERFILE" ||
    fail 'services runtime user changed'

  for binary in "${SERVICES_BINARIES[@]}"; do
    [[ "$(grep -cF -- "--bin ${binary}" "$SERVICES_DOCKERFILE")" -eq 1 ]] ||
      fail "services build does not request ${binary} exactly once"
    [[ "$(grep -cF "target/release/${binary}" "$SERVICES_DOCKERFILE")" -eq 1 ]] ||
      fail "services build does not copy ${binary} out of Cargo target exactly once"
    [[ "$(grep -cF "/out/${binary}" "$SERVICES_DOCKERFILE")" -eq 2 ]] ||
      fail "services image does not move ${binary} through the non-cache output exactly once"
    grep -qF "COPY --from=builder /out/${binary} /${binary}" \
      "$SERVICES_DOCKERFILE" ||
      fail "services runtime image is missing ${binary}"
  done
}

run_services_probe_build() {
  local probe_value="$1"
  local log_file="$2"
  local image_tag="$3"
  local context="$4"
  local build_status

  printf '[test-build-push-image] building services cache probe %s\n' "$probe_value"
  set +e
  (
    cd "$context"
    docker buildx build --load --progress=plain \
      --build-arg "CODEWIRE_CARGO_CACHE_PROBE=${probe_value}" \
      -f deployments/docker/services.Dockerfile \
      -t "$image_tag" .
  ) 2>&1 | tee "$log_file" | grep --line-buffered -E \
    "codewire-services cargo cache probe|Dirty codewire-proto|Compiling codewire-proto|Fresh tokio|Finished \`release\` profile|(^|[[:space:]])(ERROR|error:)"
  build_status="${PIPESTATUS[0]}"
  set -e

  if [[ "$build_status" -ne 0 ]]; then
    tail -n 120 "$log_file" >&2
    fail "services cache probe ${probe_value} build failed"
  fi
}

run_services_cache_probe() (
  command -v docker >/dev/null 2>&1 || fail 'docker is required for services-cache'
  docker buildx version >/dev/null 2>&1 ||
    fail 'Docker Buildx is required for services-cache'

  local probe_work seed_context verify_context first_log second_log
  local first_tag second_tag seed_input verify_input binary
  probe_work="$(mktemp -d "$ROOT/.tmp/services-cache-probe.XXXXXX")"
  seed_context="$probe_work/seed-context"
  verify_context="$probe_work/verify-context"
  first_log="$probe_work/seed.log"
  second_log="$probe_work/verify.log"
  first_tag="codewire-services:cache-probe-seed-$$"
  second_tag="codewire-services:cache-probe-verify-$$"

  # shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap.
  cleanup_services_cache_probe() {
    docker image rm -f "$first_tag" "$second_tag" >/dev/null 2>&1 || true
    rm -rf "$probe_work"
  }
  trap cleanup_services_cache_probe EXIT

  mkdir -p "$seed_context" "$verify_context"
  (
    cd "$ROOT"
    git ls-files --cached -z |
      tar --null --files-from=- --create --file=-
  ) | tar --extract --file=- --directory="$seed_context"

  seed_input="$seed_context/crates/codewire-proto/build.rs"
  verify_input="$verify_context/crates/codewire-proto/build.rs"
  touch "$seed_input"
  cp -a "$seed_context/." "$verify_context/"
  printf '\n// services cache old-mtime workspace-input probe\n' >>"$verify_input"
  touch -t 200001010000 "$verify_input"
  [[ "$verify_input" -ot "$seed_input" ]] ||
    fail 'services cache probe did not create an older changed workspace input'

  run_services_probe_build "seed-$$" "$first_log" "$first_tag" "$seed_context"
  run_services_probe_build "verify-$$" "$second_log" "$second_tag" "$verify_context"

  grep -Fq 'codewire-services cargo cache probe: verify' "$second_log" ||
    fail 'second services build reused its instruction layer instead of rerunning Cargo'
  grep -Fq 'Dirty codewire-proto v' "$second_log" ||
    fail 'second services build accepted a changed old-mtime workspace crate as fresh'
  grep -Fq 'Compiling codewire-proto v' "$second_log" ||
    fail 'second services build did not rebuild the changed workspace crate'
  grep -Eq 'Fresh tokio v[0-9]' "$second_log" ||
    fail 'second services build did not prove reuse of a Cargo dependency artifact'

  for binary in "${SERVICES_BINARIES[@]}"; do
    docker run --rm --entrypoint /bin/sh "$first_tag" \
      -c "test -x /${binary}" || fail "seed image is missing ${binary}"
    docker run --rm --entrypoint /bin/sh "$second_tag" \
      -c "test -x /${binary}" || fail "verify image is missing ${binary}"
  done
  [[ "$(docker image inspect --format '{{.Config.User}}' "$first_tag")" = '65532:65532' ]] ||
    fail 'seed services image runtime user changed'
  [[ "$(docker image inspect --format '{{.Config.User}}' "$second_tag")" = '65532:65532' ]] ||
    fail 'verify services image runtime user changed'

  docker run --rm --entrypoint /bin/sh "$first_tag" \
    -c 'sha256sum /codewire-idp /codewire-orchestration /sidecar-smoke /codewire-billing /codewire-coordinator /codewire-db-migrate /codewire-udp-relay' \
    >"$probe_work/seed.sha256"
  docker run --rm --entrypoint /bin/sh "$second_tag" \
    -c 'sha256sum /codewire-idp /codewire-orchestration /sidecar-smoke /codewire-billing /codewire-coordinator /codewire-db-migrate /codewire-udp-relay' \
    >"$probe_work/verify.sha256"
  cmp -s "$probe_work/seed.sha256" "$probe_work/verify.sha256" ||
    fail 'cache-probe invalidation changed services binary bytes'

  printf '[test-build-push-image] services Cargo cache reuse and image contents passed\n'
)

verify_services_dockerfile_contract
case "${1:-}" in
  '') ;;
  services-cache)
    run_services_cache_probe
    exit 0
    ;;
  *)
    fail "unknown test mode: $1"
    ;;
esac

work="$(mktemp -d "$ROOT/.tmp/build-push-image.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

registry_token='registry-test-value'
digest="sha256:$(printf 'd%.0s' {1..64})"
second_digest="sha256:$(printf 'f%.0s' {1..64})"
mismatch_digest="sha256:$(printf 'c%.0s' {1..64})"
source_sha="$(git -C "$ROOT" rev-parse HEAD)"
base_digest="sha256:$(printf 'e%.0s' {1..64})"
base_ref="git.example.invalid/codewire/base@$base_digest"

cat >"$work/bin/fetch-secret" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == GITEA_REGISTRY_TOKEN ]]
printf '%s' "${FAKE_REGISTRY_TOKEN:?}" >"$2"
chmod 0600 "$2"
printf '%q %q\n' "$1" "$2" >>"${FAKE_FETCH_CALLS:?}"
EOF

cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'DOCKER_CONFIG=%q ' "${DOCKER_CONFIG:-}" >>"${FAKE_DOCKER_CALLS:?}"
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
  login\ git.example.invalid\ *)
    credential="$(cat)"
    [[ "$credential" == "${FAKE_REGISTRY_TOKEN:?}" ]]
    if [ -n "${FAKE_LOGIN_FAILURES:-}" ]; then
      login_state="${FAKE_LOGIN_STATE:?}"
      login_count="$(cat "$login_state")"
      if [ "$login_count" -lt "$FAKE_LOGIN_FAILURES" ]; then
        printf '%s\n' "$((login_count + 1))" >"$login_state"
        echo 'Error response from daemon: login attempt to git.example.invalid failed with status: 401 Unauthorized' >&2
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
        --push)
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
chmod +x "$work/bin/fetch-secret" "$work/bin/docker"

export PATH="$work/bin:$PATH"
export INFISICAL_SECRET_FETCHER="$work/bin/fetch-secret"
export FAKE_REGISTRY_TOKEN="$registry_token"
export FAKE_FETCH_CALLS="$work/fetch-calls"
export FAKE_DOCKER_CALLS="$work/docker-calls"
export FAKE_MANIFESTS="$work/manifests"
export FAKE_DIGEST="$digest"
export REGISTRY_HOST='git.example.invalid'
export GITHUB_SHA="$source_sha"
export GITHUB_REF='refs/heads/main'
export GITHUB_REF_NAME='main'
export GITHUB_OUTPUT="$work/output"
: >"$FAKE_MANIFESTS"

(
  cd "$ROOT"
  "$BUILDER" gateway deployments/docker/gateway.Dockerfile .
)

grep -qxF 'family=gateway' "$GITHUB_OUTPUT" || fail 'candidate family is absent'
grep -qxF "source_sha=$source_sha" "$GITHUB_OUTPUT" ||
  fail 'candidate source SHA is absent'
grep -qxF "candidate_ref=git.example.invalid/codewire/gateway@$digest" "$GITHUB_OUTPUT" ||
  fail 'candidate digest ref is absent'
grep -qF -- "--tag git.example.invalid/codewire/gateway:$source_sha" "$FAKE_DOCKER_CALLS" ||
  fail 'immutable source tag did not reach Buildx'
grep -qF -- \
  '--label org.opencontainers.image.source=https://github.com/codewiresh/codewire' \
  "$FAKE_DOCKER_CALLS" || fail 'public source label did not reach Buildx'
grep -qF -- "--label org.opencontainers.image.revision=$source_sha" \
  "$FAKE_DOCKER_CALLS" || fail 'exact revision label did not reach Buildx'
grep -qF -- '--label org.opencontainers.image.title=codewire-gateway' \
  "$FAKE_DOCKER_CALLS" || fail 'image-family title label did not reach Buildx'
[[ "$(grep -c 'buildx build' "$FAKE_DOCKER_CALLS")" -eq 1 ]] ||
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
[[ "$(grep -c 'buildx build' "$FAKE_DOCKER_CALLS")" -eq 1 ]] ||
  fail 'existing source-SHA image was rebuilt'
grep -qxF "candidate_ref=git.example.invalid/codewire/gateway@$digest" "$GITHUB_OUTPUT" ||
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
[[ "$(grep -c 'buildx build' "$FAKE_DOCKER_CALLS")" -eq 2 ]] ||
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
grep -qxF "candidate_ref=git.example.invalid/codewire/gateway@$digest" "$GITHUB_OUTPUT" ||
  fail 'release alias did not preserve the source-SHA digest'
awk -F '\t' \
  -v reference='git.example.invalid/codewire/gateway:v0.3.999' \
  -v digest="$digest" \
  '$1 == reference && $2 == digest { found = 1 } END { exit !found }' \
  "$FAKE_MANIFESTS" ||
  fail 'release alias was not created from the source digest'
[[ "$(grep -c 'buildx build' "$FAKE_DOCKER_CALLS")" -eq 2 ]] ||
  fail 'release alias rebuilt an existing source image'
[[ "$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS")" -eq $((create_calls_before + 1)) ]] ||
  fail 'release alias was not created exactly once'

build_calls_before="$(grep -c 'buildx build' "$FAKE_DOCKER_CALLS")"
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
[[ "$(grep -c 'buildx build' "$FAKE_DOCKER_CALLS")" -eq "$build_calls_before" ]] ||
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
  FAKE_INSPECT_AUTH_ONCE_REF='git.example.invalid/codewire/gateway:v0.3.997' \
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
  FAKE_CREATE_AUTH_ONCE_REF='git.example.invalid/codewire/gateway:v0.3.996' \
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
  'git.example.invalid/codewire/gateway:v0.3.998' "$mismatch_digest" \
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
[[ "$(grep -c 'buildx build' "$FAKE_DOCKER_CALLS")" -eq 2 ]] ||
  fail 'mismatched release alias triggered a build'

export FAKE_INSPECT_ERROR_REF="git.example.invalid/codewire/mesh:$source_sha"
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
[[ "$(grep -c 'buildx build' "$FAKE_DOCKER_CALLS")" -eq 2 ]] ||
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
  CODEWIRE_BASE_IMAGE_REF='git.example.invalid/codewire/base:latest' \
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

if grep -qF "$registry_token" "$FAKE_DOCKER_CALLS" \
  || grep -qF "$registry_token" "$FAKE_FETCH_CALLS"; then
  fail 'registry token reached command arguments'
fi

docker_config="$(sed -nE 's/^DOCKER_CONFIG=([^ ]+) login.*/\1/p' \
  "$FAKE_DOCKER_CALLS" | head -1)"
[[ -n "$docker_config" && ! -e "$docker_config" ]] ||
  fail 'private Docker credential directory survived the build'

echo 'build-push immutable source image tests passed'
