#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
# CI names these in Actions variables and the job context; the scripts
# require them.
export CODEWIRE_IMAGE_REGISTRY=registry.example.invalid
# The job reaches Forgejo through an internal name; provenance must still name
# the canonical public clone URL from CODEWIRE_SOURCE_URL.
export GITHUB_SERVER_URL=https://forgejo-internal.tail.example.invalid/
export CODEWIRE_FORGEJO_INTERNAL_URL=https://forgejo-internal.tail.example.invalid
export CODEWIRE_SOURCE_URL=https://git.example.invalid/codewire/codewire.git
export CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED=example-ci-cache-protected
if [[ "${PYTHONDONTWRITEBYTECODE:-}" != 1 ]]; then
  # CI's release step sets this. Without it, a local Python can write
  # __pycache__ into the CW source capsule, which the producer then refuses.
  echo '[test-build-push-image] note: run with PYTHONDONTWRITEBYTECODE=1, as CI does' >&2
fi
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
readonly DAEMON_DOCKERFILE="$ROOT/deployments/docker/daemon.Dockerfile"
readonly DERP_DOCKERFILE="$ROOT/deployments/docker/derp.Dockerfile"
readonly CW_FIXTURE="$ROOT/scripts/ci/tests/cw_image_fixtures.py"
# Cases below set the CI apt snapshot cache explicitly.
unset CODEWIRE_APT_SNAPSHOT_MIRROR
readonly SERVICES_BINARY_ARTIFACTS=(
  codewire-idp:codewire-idp
  codewire-orchestration:codewire-orchestration
  sidecar-smoke:sidecar-smoke
  codewire-billing:codewire-billing
  billing-runtime-smoke:codewire-billing-runtime-smoke
  codewire-coordinator:codewire-coordinator
  codewire-db-migrate:codewire-db-migrate
  codewire-udp-relay:codewire-udp-relay
  codewire-credential-service:codewire-credential-service
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
# shellcheck disable=SC2016 # This assertion intentionally matches literal shell source.
grep -Fq 'docker buildx inspect "$buildx_builder"' "$BUILDER" ||
  fail 'published-image builder does not validate an external BuildKit daemon'

build_invocation_count() {
  { grep -E ' buildx (bake|build) ' "$FAKE_DOCKER_CALLS" || true; } |
    { grep -vc ' CW_PRODUCER=true ' || true; }
}

cw_producer_invocation_count() {
  grep -Ec ' CW_PRODUCER=true .* buildx build ' "$FAKE_DOCKER_CALLS" || true
}

assert_cw_context() {
  python3 -B - "$FAKE_CW_CONTEXTS" "$source_sha" "$1" <<'PY'
import json
from pathlib import Path
import sys
value = json.loads(Path(sys.argv[1]).read_text().splitlines()[-1])
assert value['source_revision'] == sys.argv[2] and value['profile'] == sys.argv[3]
assert len(value['payload_sha256']) == len(value['producer_receipt_sha256']) == 64
PY
}

# assert_cw_contexts TOTAL CURRENT HISTORICAL: every original-producer context
# so far has the runtime profile and its own receipt, and TOTAL of them bind
# CURRENT source_sha and HISTORICAL historical_sha.
assert_cw_contexts() {
  python3 -B - "$FAKE_CW_CONTEXTS" "$source_sha" "${historical_sha:-}" "$@" <<'PY'
from collections import Counter
import json
from pathlib import Path
import sys
records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
total, current, historical = map(int, sys.argv[4:7])
expected = {name: count for name, count in ((sys.argv[2], current), (sys.argv[3], historical)) if count}
assert len(records) == total and Counter(record['profile'] for record in records) == {'runtime': total}
assert Counter(record['source_revision'] for record in records) == expected
assert len({record['producer_receipt_sha256'] for record in records}) == total
print(f'protected/runtime/Kind CW original-producer contexts: {total} verified')
PY
}

# A part run alone checks the contexts its own cases produced; the full run
# checks all of them together above.
assert_cw_contexts_for_part() {
  [[ "$test_part" != "$1" ]] || assert_cw_contexts "${@:2}"
}

mkdir -p "$ROOT/.tmp"

verify_services_dockerfile_contract() {
  local mount binary artifact fixture_block architecture ssh_hash crypto_hash triplet ssh_block
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
  grep -qF 'COPY libs/daemon-proto ./libs/daemon-proto' "$SERVICES_DOCKERFILE" ||
    fail 'services image does not receive the environment daemon protocol schema'
  grep -qF '!libs/daemon-proto/**' "$SERVICES_DOCKERIGNORE" ||
    fail 'services build context excludes the environment daemon protocol schema'
  grep -qF 'find Cargo.toml Cargo.lock crates proto libs/daemon-proto -type f -exec touch {} +' \
    "$SERVICES_DOCKERFILE" ||
    fail 'services image does not revalidate copied workspace inputs'
  # shellcheck disable=SC2016
  grep -qF 'codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE"' "$SERVICES_DOCKERFILE" ||
    fail 'services image does not build the selected locked profile'
  # One workspace Cargo invocation compiles every shared dependency once; the
  # historical three-invocation sequence rebuilt their common dependency graph.
  # Only the services-ci fence below (Kind's DERP relay) builds anything else.
  # shellcheck disable=SC2016
  [[ "$(sed '/^    if \[ "\$CODEWIRE_ORCHESTRATION_FEATURES" = kind-e2e \]; then/,/^    fi$/d' "$SERVICES_DOCKERFILE" |
      grep -cF 'codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE"')" -eq 1 ]] ||
    fail 'services image must compile every shipped binary in one Cargo build'
  grep -qF 'FROM codewire-rust-base AS builder' "$SERVICES_DOCKERFILE" ||
    fail 'services does not consume the shared Rust build base'
  grep -qF 'ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587' \
    "$SERVICES_DOCKERFILE" || fail 'services runtime base changed'
  grep -qF "FROM \${DEBIAN_IMAGE}" "$SERVICES_DOCKERFILE" ||
    fail 'services runtime does not consume the reviewed Debian image'
  grep -qF 'USER 65532:65532' "$SERVICES_DOCKERFILE" ||
    fail 'services runtime user changed'
  grep -qF 'ARG CODEWIRE_ORCHESTRATION_FEATURES=' "$SERVICES_DOCKERFILE" ||
    fail 'services image lacks the isolated orchestration feature input'
  grep -qF 'CODEWIRE_ORCHESTRATION_FEATURES = ""' "$ROOT/docker-bake.hcl" ||
    fail 'promotable services image can enable test-only orchestration features'
  grep -qF 'CODEWIRE_ORCHESTRATION_FEATURES = "kind-e2e"' "$ROOT/docker-bake.hcl" ||
    fail 'non-promotable Kind services image lacks its test-only feature'
  # The builder's built-in frontend runs the checksum ADD; an external
  # frontend container can miss BuildKit's 10 s start on a slow disk (#4495).
  ! grep -qiE '^#[[:space:]]*syntax[[:space:]]*=' "$SERVICES_DOCKERFILE" ||
    fail 'services Dockerfile must use the builder built-in frontend'
  # Provider logins are native OAuth: the services image ships no provider CLI.
  ! grep -qE 'registry\.npmjs\.org/@openai/codex|github\.com/cli/cli/releases' "$SERVICES_DOCKERFILE" ||
    fail 'services image must not download a provider CLI'
  ! grep -qF 'deployments/docker/licenses' "$SERVICES_DOCKERIGNORE" ||
    fail 'services build context must not include provider CLI licenses'
  # Each architecture supplies exactly its reviewed tools/crypto bytes. The
  # runtime inherits their minimal closure, never the extracted package tree.
  for architecture in amd64 arm64; do
    case "$architecture" in
      amd64)
        ssh_hash=42c250b8b9110382488c53c066a960bc564ddac2cb9e449f47b6cdbb5fc1cb60
        crypto_hash=89be24b41bff568ee6e7caf5680a3d808e80315ed92e407056ce0fa7a5bda025
        triplet=x86_64-linux-gnu
        ;;
      arm64)
        ssh_hash=72f7cb7eb432038a62cd89e0552b352a514e880fe3907e73dc50ca2ef6d088d7
        crypto_hash=a256e03cc3abd7243ac5c6ee91a9deb56478221ef0d3c2b0748551e13140c0bf
        triplet=aarch64-linux-gnu
        ;;
    esac
    ssh_block="$(sed -n "/^FROM .* AS ssh-tools-$architecture\$/,/^FROM /p" "$SERVICES_DOCKERFILE")"
    grep -Fq "ADD --checksum=sha256:$ssh_hash" <<<"$ssh_block" ||
      fail "$architecture OpenSSH checksum is absent"
    grep -Fq "ADD --checksum=sha256:$crypto_hash" <<<"$ssh_block" ||
      fail "$architecture crypto checksum is absent"
    grep -Fq "https://snapshot.debian.org/archive/debian/20260505T204143Z/pool/main/o/openssh/openssh-client_9.2p1-2%2Bdeb12u10_$architecture.deb" <<<"$ssh_block" ||
      fail "$architecture OpenSSH artifact is not the reviewed immutable snapshot"
    grep -Fq "https://snapshot.debian.org/archive/debian/20260612T023739Z/pool/main/o/openssl/libssl3_3.0.20-1%7Edeb12u2_$architecture.deb" <<<"$ssh_block" ||
      fail "$architecture crypto artifact is not the reviewed immutable snapshot"
    for binary in ssh-agent ssh-add; do
      grep -Fq "install -D /payload/usr/bin/$binary /out/usr/bin/$binary" <<<"$ssh_block" ||
        fail "$architecture omits the selected $binary executable"
    done
    grep -Fq "/out/usr/lib/$triplet/libcrypto.so.3" <<<"$ssh_block" ||
      fail "$architecture crypto closure uses the wrong runtime path"
    for binary in openssh-client libssl3; do
      grep -Fq "/out/usr/share/doc/$binary/copyright" <<<"$ssh_block" ||
        fail "$architecture omits the $binary license notice"
    done
  done
  # shellcheck disable=SC2016 # Assert the literal architecture selector.
  grep -Fxq 'FROM ssh-tools-${TARGETARCH} AS selected-ssh-tools' "$SERVICES_DOCKERFILE" ||
    fail 'services image does not select one architecture-specific SSH artifact'
  grep -Fxq 'COPY --from=selected-ssh-tools /out/ /' "$SERVICES_DOCKERFILE" ||
    fail 'services image omits the minimal selected SSH closure'
  grep -Fxq 'COPY --chmod=755 crates/codewire-credential-broker/src/ssh_agent/askpass.sh /usr/local/libexec/codewire/ssh-askpass' "$SERVICES_DOCKERFILE" ||
    fail 'services image omits the exact checked-in public askpass helper'
  grep -Fxq 'FROM ssh-runtime' "$SERVICES_DOCKERFILE" ||
    fail 'final services image does not inherit the qualified SSH runtime stage'
  # shellcheck disable=SC2016 # Match the Dockerfile's literal shell variable.
  fixture_block="$(sed -n '/^    if \[ "\$CODEWIRE_ORCHESTRATION_FEATURES" = kind-e2e \]; then/,/^    fi$/p' "$SERVICES_DOCKERFILE")"
  # The kind-e2e feature, which only the non-promotable services-ci target
  # sets, fences the only test-artifact build. It compiles in the image's one
  # runtime profile and reads that profile's target directory. A promotable
  # image receives an empty directory, never a runtime test switch.
  # shellcheck disable=SC2016
  grep -qF 'codewire-rust-build cargo test --locked --profile "$CODEWIRE_RUST_PROFILE"' <<<"$fixture_block" ||
    fail 'credential fixture compilation escaped its test-only branch or the selected profile'
  # shellcheck disable=SC2016
  grep -qF '"executable":"\(/src/target/'\''"$CODEWIRE_RUST_PROFILE"'\''/deps/codewire_credential_service-' <<<"$fixture_block" ||
    fail 'credential fixture is not read from the selected profile target directory'
  ! grep -qE -- '--profile ci|target/ci/|= ci( |$)' <<<"$fixture_block" ||
    fail 'credential fixture still selects the ci profile'
  [[ "$(grep -cF 'cargo test --locked' "$SERVICES_DOCKERFILE")" -eq 1 ]] ||
    fail 'services image contains an unexpected test-artifact build'
  grep -qF 'runtime::kind::serve_kind_credential_fixture: test' <<<"$fixture_block" ||
    fail 'services image does not validate the exact ignored fixture entrypoint'
  grep -qF 'COPY --from=builder /out/kind-fixtures/ /codewire-kind-fixtures/' "$SERVICES_DOCKERFILE" ||
    fail 'services-ci fixture has no explicit image artifact path'
  # The synthetic provider's stock Git comes only from the pinned toolchain,
  # inside the same feature fence. Never add it to production, copy
  # client network helpers or replace the final base's runtime libraries.
  # shellcheck disable=SC2016
  grep -qF 'test "$(git --version)" = '\''git version 2.39.5'\''' <<<"$fixture_block" ||
    fail 'Kind Git fixture no longer checks the pinned toolchain Git version'
  for binary in \
    'install -D /usr/bin/git /out/kind-git-runtime/usr/bin/git' \
    'install -D /usr/lib/git-core/git-http-backend /out/kind-git-runtime/usr/lib/git-core/git-http-backend' \
    'ln -s ../../bin/git /out/kind-git-runtime/usr/lib/git-core/git' \
    'ln -s git /out/kind-git-runtime/usr/lib/git-core/git-upload-pack' \
    'ln -s git /out/kind-git-runtime/usr/lib/git-core/git-pack-objects' \
    'install -Dm644 /usr/share/doc/git/copyright /out/kind-git-runtime/usr/share/doc/git/copyright'; do
    grep -qF "$binary" <<<"$fixture_block" || fail "Kind Git payload escaped CI fence: $binary"
  done
  [[ "$(grep -c '/out/kind-git-runtime/' "$SERVICES_DOCKERFILE")" -eq 7 ]] ||
    fail 'unexpected Kind Git payload copy or runtime dependency'
  grep -Fxq 'COPY --from=builder /out/kind-git-runtime/ /' "$SERVICES_DOCKERFILE" ||
    fail 'Kind Git fixture lacks the explicit CI-only runtime artifact path'
  grep -qF "grep -qx 'runtime::kind::git::tests::stock_git_smart_http_round_trip: test'" "$SERVICES_DOCKERFILE" ||
    fail 'final runtime Git proof can silently select zero tests'
  grep -qF 'runtime::kind::git::tests::stock_git_smart_http_round_trip --test-threads=1' "$SERVICES_DOCKERFILE" ||
    fail 'final runtime does not execute the real stock Git transfer proof'
  grep -qF 'test ! -e /usr/bin/git && test ! -e /usr/lib/git-core/git-http-backend' "$SERVICES_DOCKERFILE" ||
    fail 'release runtime does not prove Git fixture payload absence'
  # Kind's DERP relay (tests/e2e/kind/tailnet.yaml) is built in its own Cargo
  # invocation inside the same feature fence, so the shipped binaries' feature
  # set never includes it and a promotable image carries no relay.
  # shellcheck disable=SC2016
  grep -qF 'codewire-rust-build cargo build --locked --profile "$CODEWIRE_RUST_PROFILE" \' <<<"$fixture_block" &&
    grep -qF -- '-p codewire-derp --bin codewire-derp && \' <<<"$fixture_block" ||
    fail 'Kind DERP relay build escaped the services-ci fence'
  [[ "$(grep -cF -- '-p codewire-derp' "$SERVICES_DOCKERFILE")" -eq 1 ]] ||
    fail 'services image builds codewire-derp outside the Kind fence'
  [[ "$(grep -c '/out/kind-derp' "$SERVICES_DOCKERFILE")" -eq 3 ]] ||
    fail 'unexpected Kind DERP relay payload copy'
  grep -Fxq 'COPY --from=builder /out/kind-derp/ /' "$SERVICES_DOCKERFILE" ||
    fail 'Kind DERP relay lacks its explicit CI-only runtime artifact path'
  grep -qF 'test ! -e /codewire-derp; \' "$SERVICES_DOCKERFILE" ||
    fail 'release runtime does not prove Kind DERP relay absence'
  grep -qF 'test -x /codewire-derp; \' "$SERVICES_DOCKERFILE" ||
    fail 'services-ci runtime does not prove the Kind DERP relay is present'

  for binary_artifact in "${SERVICES_BINARY_ARTIFACTS[@]}"; do
    binary="${binary_artifact%%:*}"
    artifact="${binary_artifact#*:}"
    [[ "$(grep -cF -- "--bin ${binary}" "$SERVICES_DOCKERFILE")" -eq 1 ]] ||
      fail "services build does not request ${binary} exactly once"
    [[ "$(grep -cF "target/\$CODEWIRE_RUST_PROFILE/${binary}" "$SERVICES_DOCKERFILE")" -eq 1 ]] ||
      fail "services build does not copy ${binary} out of Cargo target exactly once"
    [[ "$(grep -Ec "/out/${artifact}([[:space:]]|$)" "$SERVICES_DOCKERFILE")" -eq 2 ]] ||
      fail "services image does not move ${artifact} through the non-cache output exactly once"
    grep -qF "COPY --from=builder /out/${artifact} /${artifact}" \
      "$SERVICES_DOCKERFILE" ||
      fail "services runtime image is missing ${artifact}"
  done
}

verify_kind_build_cache_contract() {
  local dockerfile count
  for dockerfile in \
      "$DASHBOARD_DOCKERFILE" \
      "$SERVICES_DOCKERFILE" \
      "$MESH_DOCKERFILE" \
      "$DAEMON_DOCKERFILE" \
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
  for target in dashboard-ci services-ci mesh-ci daemon-ci; do
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
  # shellcheck disable=SC2016 # Match the build script's literal Bake override.
  grep -qF '$target.secrets+=id=aws_shared_credentials,src=$credentials_file' \
    "$KIND_BUILDER" ||
    fail 'Kind does not append its new secret through supported Bake override syntax'
  # shellcheck disable=SC2016 # Match the build script's literal Bake override.
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
      "$MESH_DOCKERFILE" "$DAEMON_DOCKERFILE" "$DERP_DOCKERFILE"; then
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
  # Kind images differ from promotable ones only in promotability (and
  # services-ci's kind-e2e features): every target builds the one runtime
  # profile, which the shared product target fixes and no Kind target or
  # caller's environment overrides (#2892).
  local kind_target kind_block
  for kind_target in dashboard-ci services-ci mesh-ci daemon-ci; do
    kind_block="$(sed -n "/^target \"$kind_target\" {/,/^}/p" "$BAKE_FILE")"
    grep -Eq '"dev\.codewire\.promotable"[[:space:]]*=[[:space:]]*"false"' <<<"$kind_block" ||
      fail "Kind image $kind_target is not marked non-promotable"
    ! grep -Eq 'CODEWIRE_RUST_PROFILE|dev\.codewire\.build\.profile' <<<"$kind_block" ||
      fail "Kind image $kind_target overrides the runtime profile"
  done
  kind_block="$(sed -n '/^target "_rust-product" {/,/^}/p' "$BAKE_FILE")"
  grep -Eq '"dev\.codewire\.build\.profile"[[:space:]]*=[[:space:]]*"runtime"' <<<"$kind_block" &&
    grep -Eq 'CODEWIRE_RUST_PROFILE[[:space:]]*=[[:space:]]*"runtime"' <<<"$kind_block" ||
    fail 'the shared product target does not fix the runtime profile'
  ! grep -q '^variable "CODEWIRE_RUST_PROFILE"' "$BAKE_FILE" ||
    fail 'a caller environment can select the image profile through a Bake variable'
  # shellcheck disable=SC2016
  count="$(grep -cF 'cargo build --locked --profile "$CODEWIRE_RUST_PROFILE"' "$DAEMON_DOCKERFILE")"
  [[ "$count" -eq 1 ]] || fail 'the support image must build only cw, profile-selected'
  grep -qF -- '-p codewire-cli-bin --bin cw' "$DAEMON_DOCKERFILE" ||
    fail 'daemon support image does not build the self-contained cw binary'
  if grep -Eq -- '--bin codewire-daemon|/usr/local/bin/(daemon|codewire-daemon)' \
      "$DAEMON_DOCKERFILE"; then
    fail 'daemon support image retained a standalone daemon binary or alias'
  fi
}

verify_services_dockerfile_contract
verify_kind_build_cache_contract
# The cases fall into four parts that share only the fixture built below, so
# the release family runs them side by side. With no argument every part runs,
# in order.
readonly TEST_PARTS=(publish kind builds support)
[[ "$#" -le 1 ]] || fail "unknown test mode: $*"
test_part="${1:-all}"
[[ " all ${TEST_PARTS[*]} " == *" $test_part "* ]] || fail "unknown test part: $test_part"
runs_part() {
  [[ "$test_part" == all || "$test_part" == "$1" ]]
}
# The release family runs every part; a part it omits would never run in CI.
for listed_part in "${TEST_PARTS[@]}"; do
  grep -qxF "  scripts/ci/tests/test-build-push-image.sh $listed_part" \
    "$ROOT/scripts/ci/verify/run-product-verification.sh" ||
    fail "the release family does not run the $listed_part part"
done

work="$(mktemp -d "$ROOT/.tmp/build-push-image.XXXXXX")"
mkdir -p "$work/bin"
cleanup() {
  local status=$?
  if [[ "$status" -eq 0 ]]; then
    rm -rf "$work"
  else
    printf '[test-build-push-image] retained failed fixture at %s\n' "$work" >&2
  fi
}
trap cleanup EXIT

if ! CODEWIRE_SCCACHE_MODE=disabled CODEWIRE_RUST_PROFILE=ci \
  "$RUST_BUILD_WRAPPER" true >"$work/rust-build-wrapper.out"; then
  fail 'disabled sccache mode did not execute the requested command'
fi
grep -qF 'CODEWIRE_CI_PHASE name=rust-compile-link mode=disabled' \
  "$work/rust-build-wrapper.out" ||
  fail 'Rust build wrapper omitted its structured phase result'
if CODEWIRE_SCCACHE_MODE=disabled CODEWIRE_RUST_PROFILE=debug \
  "$RUST_BUILD_WRAPPER" true >"$work/rust-build-wrapper-invalid.out" 2>&1; then
  fail 'Rust build wrapper accepted an undeclared build profile'
fi
if CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_RUST_PROFILE=ci \
  SCCACHE_BUCKET=test SCCACHE_ENDPOINT=https://test.invalid \
  CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/test \
  AWS_SHARED_CREDENTIALS_FILE=relative/credentials \
  "$RUST_BUILD_WRAPPER" true >"$work/rust-build-wrapper-relative-credentials.out" 2>&1; then
  fail 'Rust build wrapper accepted a relative shared-credentials path'
fi

r2_credentials_file="$work/aws-shared-credentials"
cat >"$r2_credentials_file" <<'EOF'
[default]
aws_access_key_id = untrusted-access-key
aws_secret_access_key = untrusted-secret-key
EOF
chmod 0600 "$r2_credentials_file"

registry_username='harbor-publisher-test'
registry_password='registry-test-value'
digest="sha256:$(printf 'd%.0s' {1..64})"
second_digest="sha256:$(printf 'f%.0s' {1..64})"
mismatch_digest="sha256:$(printf 'c%.0s' {1..64})"
source_fixture="$work/source"
python3 -B - "$CW_FIXTURE" "$ROOT" "$source_fixture" <<'PY'
from contextlib import closing
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location('push_image_fixture', sys.argv[1])
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
root, destination = Path(sys.argv[2]), Path(sys.argv[3])
fixture.create_source(destination)
# Exact additional production callers/recipes used below. This remains a
# private synthetic source, with no linked checkout or delivery-repo mutation.
for name in (
    'apps/dashboard/Dockerfile', 'deployments/docker/services.Dockerfile',
    'deployments/docker/services.Dockerfile.dockerignore',
    'deployments/docker/mesh.Dockerfile', 'deployments/docker/derp.Dockerfile',
    'docker-compose.yml', 'images/confidential-probe/Dockerfile',
    'scripts/ci/images/build-kind-images.sh',
    'scripts/ci/images/build-push-image.sh', 'scripts/ci/images/build-push-runtime-images.sh',
    'scripts/ci/images/image-bundle.py',
    'scripts/ci/images/compute-image-tags.sh',
):
    with closing(fixture.source.HeldSourceFile(root / name, fixture.source.MAX_FILE)) as held:
        fixture.write(destination / name, held.data, 0o755 if held.metadata['mode'] & 0o111 else 0o644)
        held.revalidate(content=True)
fixture.source.git(destination, ['add', '-A'])
fixture.source.git(destination, ['-c', 'user.name=Synthetic', '-c',
    'user.email=synthetic@example.invalid', 'commit', '-q', '-m', 'synthetic image callers'])
fixture.source.git(destination, ['remote', 'add', 'origin', 'https://fixture.invalid/codewire.git'])
PY
source_sha="$(git -C "$source_fixture" rev-parse HEAD)"
source_remote_before="$(git -C "$source_fixture" remote get-url origin)"
base_digest="sha256:$(printf 'e%.0s' {1..64})"
base_ref="registry.example.invalid/codewire/base@$base_digest"

# Harbor supplies the only registry identity: the publisher robot both pushes
# codewire/ images and pulls the digest-pinned oci-approved/ inputs.
cat >"$work/bin/fetch-harbor" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 2 ]]; then
  echo 'Harbor publisher credential takes exactly two output paths' >&2
  exit 98
fi
printf '%s' "${FAKE_REGISTRY_USERNAME:?}" >"$1"
printf '%s' "${FAKE_REGISTRY_PASSWORD:?}" >"$2"
chmod 0600 "$1" "$2"
printf '%q %q\n' "$1" "$2" >>"${FAKE_FETCH_CALLS:?}"
EOF

cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'DOCKER_CONFIG=%q ' "${DOCKER_CONFIG:-}" >>"${FAKE_DOCKER_CALLS:?}"
cw_producer=false
for argument in "$@"; do
  if [[ "$argument" == cw-source=* ]]; then cw_producer=true; fi
done
printf 'CW_PRODUCER=%s ' "$cw_producer" >>"$FAKE_DOCKER_CALLS"
printf 'CODEWIRE_IMAGE_SOURCE_SHA=%q CODEWIRE_RUST_PROFILE=%q CODEWIRE_SCCACHE_MODE=%q GIT_REMOTE=%q ' \
  "${CODEWIRE_IMAGE_SOURCE_SHA:-}" "${CODEWIRE_RUST_PROFILE:-}" "${CODEWIRE_SCCACHE_MODE:-}" \
  "$(git -C "${CODEWIRE_SOURCE_DIR:-.}" remote get-url origin)" \
  >>"$FAKE_DOCKER_CALLS"
printf 'CODEWIRE_APT_SNAPSHOT_MIRROR=%q ' "${CODEWIRE_APT_SNAPSHOT_MIRROR:-}" >>"$FAKE_DOCKER_CALLS"
printf 'CODEWIRE_CARGO_BUILD_JOBS=%q ' "${CODEWIRE_CARGO_BUILD_JOBS:-}" >>"$FAKE_DOCKER_CALLS"
printf '%q ' "$@" >>"$FAKE_DOCKER_CALLS"
printf '\n' >>"$FAKE_DOCKER_CALLS"

if [[ "$cw_producer" == true ]]; then
  if [[ "${FAKE_KIND_PRODUCER_FAILURE:-0}" = 1 ]]; then
    echo 'synthetic Kind CW producer failure' >&2
    exit 67
  fi
  exec python3 -B "${FAKE_CW_FIXTURE:?}" export -- "$@"
fi

# Reopen the real original producer and compare its payload with every actual
# verified context handed to the image solve. No incoming CW is executed.
for argument in "$@"; do
  case "$argument" in
    codewire-verified-cw=*|*.contexts.codewire-verified-cw=*)
      python3 -B - "$FAKE_CW_FIXTURE" "$CODEWIRE_SOURCE_DIR" \
        "${argument#*=}" "$FAKE_CW_CONTEXTS" <<'PY'
from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location('push_context_fixture', sys.argv[1])
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
source, context = Path(sys.argv[2]), Path(sys.argv[3])
result = context.parents[2] / 'cw-producer-result.json'
expected = fixture.selected_asset(source, result)
with closing(fixture.source.HeldSourceFile(context / 'cw', fixture.release.MAX_EXECUTABLE)) as held:
    assert held.data == expected
    held.revalidate(content=True)
with closing(fixture.source.HeldSourceFile(result, fixture.release.MAX_JSON)) as held:
    summary = fixture.release.parse_canonical(held.data)
    held.revalidate(content=True)
with Path(sys.argv[4]).open('a') as output:
    output.write(json.dumps({'context': str(context), 'profile': summary['profile'],
        'source_revision': summary['source']['revision'], 'payload_sha256': hashlib.sha256(expected).hexdigest(),
        'producer_receipt_sha256': summary['receipt']['sha256']}, sort_keys=True) + '\n')
PY
      ;;
  esac
done

set_manifest() {
  local reference="$1"
  local digest="$2"
  local platforms="${3:-}"
  local temporary="${FAKE_MANIFESTS:?}.tmp"
  awk -F '\t' -v reference="$reference" '$1 != reference' \
    "$FAKE_MANIFESTS" >"$temporary"
  printf '%s\t%s\t%s\n' "$reference" "$digest" "$platforms" >>"$temporary"
  mv "$temporary" "$FAKE_MANIFESTS"
}

case "${1:-} ${2:-} ${3:-}" in
  login\ registry.example.invalid\ *)
    credential="$(cat)"
    [[ "$credential" == "${FAKE_REGISTRY_PASSWORD:?}" ]]
    [[ "$*" == *" -u ${FAKE_REGISTRY_USERNAME:?} "* ]]
    if [ -n "${FAKE_LOGIN_FAILURES:-}" ]; then
      login_state="${FAKE_LOGIN_STATE:?}"
      login_count="$(cat "$login_state")"
      if [ "$login_count" -lt "$FAKE_LOGIN_FAILURES" ]; then
        printf '%s\n' "$((login_count + 1))" >"$login_state"
        echo 'Error response from daemon: login failed with status: 401 Unauthorized' >&2
        exit 1
      fi
    fi
    if [ "${FAKE_LOGIN_UNAVAILABLE:-0}" = 1 ]; then
      echo "Error response from daemon: login attempt to https://registry.example.invalid/v2/ failed with status: 503 Service Unavailable" >&2
      exit 1
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
    # Like Buildx, a multi-platform index exposes one attestation per
    # platform as a map keyed by platform, and its single-attestation view is
    # null. A single-platform image exposes one attestation stub instead.
    index_platforms=''
    if [[ "$reference" == *@sha256:* ]]; then
      index_platforms="$(awk -F '\t' -v repository="${reference%@*}:" -v digest="${reference##*@}" \
        'index($1, repository) == 1 && $2 == digest && $3 != "" { print $3; exit }' "$FAKE_MANIFESTS")"
    fi
    attested_platforms="${FAKE_ATTESTED_PLATFORMS:-$index_platforms}"
    if [[ -n "$index_platforms" && ( "$format" == '{{json .Provenance.SLSA}}' || "$format" == '{{json .SBOM.SPDX}}' ) ]]; then
      printf 'null\n'
      exit 0
    fi
    if [ "$format" = '{{json .Provenance.SLSA}}' ] || [ "$format" = '{{json .Provenance}}' ]; then
      predicate="$(jq -cn \
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
        ')"
      if [[ "$format" == '{{json .Provenance}}' && -z "$index_platforms" ]]; then
        jq -n --argjson predicate "$predicate" '{SLSA: $predicate}'
      elif [ "$format" = '{{json .Provenance}}' ]; then
        jq -n --arg platforms "$attested_platforms" --argjson predicate "$predicate" \
          '$platforms | split(",") | map({key: ., value: {SLSA: $predicate}}) | from_entries'
      else
        printf '%s\n' "$predicate"
      fi
      exit 0
    fi
    if [ "$format" = '{{json .SBOM.SPDX}}' ] || [ "$format" = '{{json .SBOM}}' ]; then
      valid_sbom='{"spdxVersion":"SPDX-2.3","documentNamespace":"https://codewire.example/sbom/test","packages":[{"name":"codewire-test"}]}'
      invalid_sbom='{"spdxVersion":"SPDX-2.3","packages":[]}'
      if [[ "$format" == '{{json .SBOM}}' && -z "$index_platforms" ]]; then
        jq -n --argjson valid "$valid_sbom" '{SPDX: $valid, AdditionalSPDXs: []}'
      elif [ "$format" = '{{json .SBOM}}' ]; then
        jq -n --arg platforms "$attested_platforms" \
          --arg invalid_platform "${FAKE_SBOM_INVALID_PLATFORM:-}" \
          --argjson all_invalid "$([ "${FAKE_SBOM_INVALID:-0}" = 1 ] && echo true || echo false)" \
          --argjson valid "$valid_sbom" --argjson invalid "$invalid_sbom" '
            $platforms | split(",")
            | map({key: ., value: {
                SPDX: (if $all_invalid or . == $invalid_platform then $invalid else $valid end),
                AdditionalSPDXs: []
              }})
            | from_entries'
      elif [ "${FAKE_SBOM_INVALID:-0}" = 1 ]; then
        printf '%s\n' "$invalid_sbom"
      else
        printf '%s\n' "$valid_sbom"
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
    sources=()
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --tag)
          destination="$2"
          shift 2
          ;;
        *)
          source="$1"
          sources+=("$1")
          shift
          ;;
      esac
    done
    [[ -n "$destination" && "$source" =~ @sha256:[0-9a-f]{64}$ ]]
    if [ "${#sources[@]}" -gt 1 ]; then
      # A join: one index over every source image's platform.
      for joined in "${sources[@]}"; do
        grep -qF "$(printf '%s\t' "$joined")" "$FAKE_MANIFESTS" || {
          printf 'ERROR: %s: manifest unknown\n' "$joined" >&2
          exit 1
        }
      done
      set_manifest "$destination" "${FAKE_JOIN_DIGEST:?}" "${FAKE_JOIN_PLATFORMS:-linux/amd64,linux/arm64}"
      exit 0
    fi
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
    if [[ "$*" == *' --driver remote '* ]]; then
      # The trusted BuildKit builder: mutual TLS to its pinned endpoint only.
      [[ "$*" == *' --driver-opt cacert='*'/ca.crt,cert='*'/client.crt,key='*'/client.key,servername=ams3-1-trusted-builder-large-0.forgejo-ci-builder.svc.cluster.local tcp://ams3-1-trusted-builder-large-0.forgejo-ci-builder.svc.cluster.local:1234' ]]
      exit 0
    fi
    [[ "$*" == *' --driver docker-container '* ]]
    [[ "$*" == *' --driver-opt image=docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5 '* ]]
    [[ "$*" == *' --bootstrap'* ]]
    if [[ -n "${FAKE_KIND_WORK_FILE:-}" ]]; then
      arguments=("$@")
      buildkit_config=''
      for ((index = 0; index + 1 < ${#arguments[@]}; index++)); do
        if [[ "${arguments[index]}" == --buildkitd-config ]]; then
          buildkit_config="${arguments[index + 1]}"
        fi
      done
      [[ "$buildkit_config" == */buildkitd.toml ]]
      printf '%s\n' "${buildkit_config%/buildkitd.toml}" >"$FAKE_KIND_WORK_FILE"
    fi
    if [[ -n "${FAKE_PERSISTENT_BUILDERS:-}" && "$4" == codewire-kind-images-* ]]; then
      : >"$FAKE_PERSISTENT_BUILDERS/$4"
    fi
    ;;
  buildx\ inspect\ --bootstrap|buildx\ inspect\ codewire-kind-images-*)
    # A persistent local image builder exists once created and is reused.
    [[ -n "${FAKE_PERSISTENT_BUILDERS:-}" && -e "$FAKE_PERSISTENT_BUILDERS/${*: -1}" ]] || {
      echo "ERROR: no builder \"${*: -1}\" found" >&2
      exit 1
    }
    ;;
  buildx\ rm\ *)
    [[ "$*" == *' --force '* ]]
    if [[ "${FAKE_KIND_BUILDER_REMOVE_FAILURE:-0}" != 0 && "${4:-}" == codewire-kind-* ]]; then
      echo 'ERROR: failed to remove one or more builders' >&2
      exit 73
    fi
    ;;
  buildx\ inspect\ codewire-publish-*)
    # The trusted BuildKit builder a direct protected build may attach.
    [ "${FAKE_TRUSTED_DOWN:-0}" = 0 ] || { echo 'connection refused' >&2; exit 1; }
    printf 'Name: %s\nDriver: remote\nStatus: running\nPlatforms: linux/amd64\n' "${4:-}"
    exit 0
    ;;
  buildx\ inspect\ codewire-kind-*|container\ inspect\ --format|volume\ inspect\ --format)
    [[ "$1" == buildx || "${*: -1}" == buildx_buildkit_codewire-kind-* ]] || {
      echo "unexpected fake docker command: $*" >&2
      exit 1
    }
    # A failed removal is checked object by object. "gone": the client failed
    # although Docker already removed everything; "1": every object persists.
    if [[ "${FAKE_KIND_BUILDER_REMOVE_FAILURE:-0}" == 1 ]]; then
      printf 'present\n'
    else
      case "$1" in
        buildx) echo "ERROR: no builder \"$3\" found" >&2 ;;
        container) echo "Error response from daemon: No such container: ${*: -1}" >&2 ;;
        volume) echo "Error response from daemon: get ${*: -1}: no such volume" >&2 ;;
      esac
      exit 1
    fi
    ;;
  rm\ --force\ buildx_buildkit_codewire-kind-*|volume\ rm\ buildx_buildkit_codewire-kind-*)
    [[ "${FAKE_KIND_BUILDER_REMOVE_FAILURE:-0}" != 1 ]] || exit 74
    ;;
  buildx\ bake\ *)
    if [ "${FAKE_BUILD_FATAL:-0}" = 1 ]; then
      echo 'unexpected status from HEAD request to https://registry.example.invalid/v2/codewire/test/blobs/sha256:test: 503 Service Unavailable' >&2
      exit 1
    fi
    printf '#1 synthetic image Bake solve; no Docker/CW execution\n'
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
        --file|--provenance|--progress|--sbom)
          shift 2
          ;;
        --push|--pull|--load|--sbom=generator=*)
          shift
          ;;
        --allow=fs.read=*)
          # The consumer grants Bake exactly its held verified-cw context.
          [[ "$1" == --allow=fs.read=/*/solve/verified-cw ]]
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
        "daemon-ci": {}
      }' >"$metadata"
      exit 0
    fi
    if [ "${#targets[@]}" -eq 1 ] && [ "${targets[0]}" = default ]; then
      targets=(dashboard services mesh daemon derp)
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
      *dev.codewire.build.profile*)
        # A Kind image from the retired ci profile is the invalid case.
        if [[ "${FAKE_KIND_IMAGE_INVALID:-0}" = 1 ]]; then printf 'ci\n'; else printf 'runtime\n'; fi
        ;;
      *dev.codewire.promotable*) printf 'false\n' ;;
    esac
    ;;
  buildx\ build\ *)
    if [ "${FAKE_BUILD_NETWORK_FAILURES:-0}" -gt 0 ]; then
      network_attempt=1
      if [ -f "${FAKE_BUILD_NETWORK_STATE:?}" ]; then
        network_attempt="$(($(cat "$FAKE_BUILD_NETWORK_STATE") + 1))"
      fi
      printf '%s\n' "$network_attempt" >"$FAKE_BUILD_NETWORK_STATE"
      if [ "$network_attempt" -le "$FAKE_BUILD_NETWORK_FAILURES" ]; then
        echo 'ERROR: failed to solve: failed to load cache key: Get "https://github.com/virtee/snpguest/releases/download/v0.10.0/snpguest": net/http: TLS handshake timeout' >&2
        exit 1
      fi
    fi
    if [ "${FAKE_BUILD_FATAL:-0}" = 1 ]; then
      echo 'unexpected status from HEAD request to https://registry.example.invalid/v2/codewire/test/blobs/sha256:test: 503 Service Unavailable' >&2
      exit 1
    fi
    printf '#1 synthetic image build solve; no Docker/CW execution\n'
    metadata=''
    tags=()
    by_digest=''
    build_platforms=''
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
        --platform)
          # A single explicit platform still yields a single-platform image.
          if [[ "$2" == *,* ]]; then build_platforms="$2"; fi
          shift 2
          ;;
        --output)
          # A per-platform build pushes by digest under its repository only.
          if [[ "$2" == type=image,name=*,push-by-digest=true,name-canonical=true,push=true ]]; then
            by_digest="${2#type=image,name=}"
            by_digest="${by_digest%%,*}"
          fi
          shift 2
          ;;
        --build-arg|--label|-f|--file|--build-context|--no-cache-filter|--provenance|--sbom|--progress)
          shift 2
          ;;
        --push|--pull|--load|--no-cache|--provenance=*|--sbom=generator=*)
          shift
          ;;
        *)
          shift
          ;;
      esac
    done
    [[ -n "$metadata" ]]
    [[ ( "${#tags[@]}" -eq 1 && -z "$by_digest" ) || ( "${#tags[@]}" -eq 0 && -n "$by_digest" ) ]]
    jq -n --arg digest "${FAKE_DIGEST:?}" \
      '{"containerimage.digest": $digest}' >"$metadata"
    for tag in "${tags[@]}"; do
      set_manifest "$tag" "$FAKE_DIGEST" "$build_platforms"
    done
    [ -z "$by_digest" ] || set_manifest "$by_digest@$FAKE_DIGEST" "$FAKE_DIGEST"
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
chmod +x "$work/bin/fetch-harbor" "$work/bin/docker" "$work/bin/sccache"

export PATH="$work/bin:$PATH"
export OPENBAO_HARBOR_CREDENTIAL_FETCHER="$work/bin/fetch-harbor"
export FAKE_REGISTRY_USERNAME="$registry_username"
export FAKE_REGISTRY_PASSWORD="$registry_password"
export FAKE_FETCH_CALLS="$work/fetch-calls"
export FAKE_DOCKER_CALLS="$work/docker-calls"
export FAKE_SCCACHE_CALLS="$work/sccache-calls"
export FAKE_MANIFESTS="$work/manifests"
export FAKE_DIGEST="$digest"
export FAKE_PROVENANCE_BUILDER_ID='https://codewire.sh/ci/builders/protected-delivery/v1'
export FAKE_CW_FIXTURE="$CW_FIXTURE"
export FAKE_CW_CONTEXTS="$work/cw-contexts.jsonl"
export FAKE_SOURCE_SHA="$source_sha"
export CODEWIRE_SOURCE_DIR="$source_fixture"
export GITHUB_SHA="$source_sha"
export GITHUB_REF='refs/heads/main'
export GITHUB_REF_NAME='main'
export GITHUB_OUTPUT="$work/output"
cd "$source_fixture"
: >"$FAKE_MANIFESTS"

if runs_part publish; then
CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_RUST_PROFILE=ci \
  SCCACHE_BUCKET=example-ci-cache-protected \
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
  cd "$source_fixture"
  "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
)

grep -qxF 'family=daemon' "$GITHUB_OUTPUT" || fail 'candidate family is absent'
grep -qxF "source_sha=$source_sha" "$GITHUB_OUTPUT" ||
  fail 'candidate source SHA is absent'
grep -qxF "candidate_ref=registry.example.invalid/codewire/daemon@$digest" "$GITHUB_OUTPUT" ||
  fail 'candidate digest ref is absent'
grep -qF -- "daemon.tags=registry.example.invalid/codewire/daemon:$source_sha" "$FAKE_DOCKER_CALLS" ||
  fail 'immutable source tag did not reach canonical Bake target'
grep -qF -- "CODEWIRE_IMAGE_SOURCE_SHA=$source_sha" "$FAKE_DOCKER_CALLS" ||
  fail 'exact source revision did not reach canonical Bake'
grep -qF -- 'CODEWIRE_RUST_PROFILE=runtime' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not force the runtime profile'
grep -qF -- 'builder-id=https://codewire.sh/ci/builders/protected-delivery/v1' "$FAKE_DOCKER_CALLS" ||
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
! grep -qF 'tail.example.invalid' "$FAKE_DOCKER_CALLS" ||
  fail 'the job'"'"'s internal Forgejo URL reached the image build or its provenance'
grep -qF -- 'Provenance.SLSA' \
  "$FAKE_DOCKER_CALLS" || fail 'protected publication did not verify its emitted SLSA predicate'
{ grep -qF -- '--sbom=generator=registry.example.invalid/oci-approved/docker/buildkit-syft-scanner@sha256:ae4f3b554449e7e25548e7d8ccc029d17357348e30c6e3df01b92bc93654d6a9' \
  "$FAKE_DOCKER_CALLS" ||
  grep -qF -- '--sbom generator=registry.example.invalid/oci-approved/docker/buildkit-syft-scanner@sha256:ae4f3b554449e7e25548e7d8ccc029d17357348e30c6e3df01b92bc93654d6a9' \
    "$FAKE_DOCKER_CALLS"; } ||
  fail 'protected publication did not request an SBOM from the approved exact generator'
grep -qF ' login registry.example.invalid ' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not use its scoped promoted-output login'
# Publication targets Harbor only: every login and every pushed or applied tag
# names registry.example.invalid.
if grep -F ' login ' "$FAKE_DOCKER_CALLS" | grep -vF ' login registry.example.invalid ' >/dev/null; then
  fail 'protected publication logged in to a registry other than Harbor'
fi
if grep -Eo '(--tag|-t)[ =][^ ]+|\.tags=[^ ]+' "$FAKE_DOCKER_CALLS" |
    grep -Ev '^((--tag|-t)[ =]|\.tags=)registry\.example\.invalid/codewire/' >/dev/null; then
  fail 'protected publication pushed or tagged an image outside Harbor'
fi
grep -Eq '(--tag|-t)[ =]registry\.example\.invalid/codewire/|\.tags=registry\.example\.invalid/codewire/' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not tag its image in Harbor'
grep -qF -- 'SBOM.SPDX' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not verify its emitted SPDX SBOM'
grep -qF -- 'image=docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5' \
  "$FAKE_DOCKER_CALLS" || fail 'protected publication does not pin its BuildKit daemon image'
grep -qF -- 'buildx rm --force codewire-publish-' "$FAKE_DOCKER_CALLS" ||
  fail 'protected publication did not remove its isolated BuildKit builder'
[[ "$(build_invocation_count)" -eq 1 ]] ||
  fail 'image was not built exactly once'
[[ "$(cw_producer_invocation_count)" -eq 1 ]] ||
  fail 'daemon did not use exactly one original CW producer'
assert_cw_context runtime
[[ "$(git -C "$source_fixture" remote get-url origin)" == "$source_remote_before" ]] ||
  fail 'protected image publication did not restore the checkout origin remote'

if ! (
  cd "$source_fixture"
  FAKE_PROVENANCE_ENVELOPE=true \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
); then
  fail 'protected image build rejected the valid SLSA v1 statement envelope'
fi
[[ "$(build_invocation_count)" -eq 1 ]] ||
  fail 'SLSA statement-envelope verification rebuilt an immutable source image'

if (
  cd "$source_fixture"
  CODEWIRE_PROVENANCE_BUILDER_ID=https://attacker.invalid/builder \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
) >"$work/unrecognized-builder.out" 2>"$work/unrecognized-builder.err"; then
  fail 'protected image build accepted an unrecognized builder identity'
fi
grep -qF 'unrecognized provenance builder identity' \
  "$work/unrecognized-builder.err" ||
  fail 'unrecognized provenance builder rejection was not attributable'

if (
  cd "$source_fixture"
  FAKE_PROVENANCE_BUILDER_ID=https://attacker.invalid/builder \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
) >"$work/invalid-provenance.out" 2>"$work/invalid-provenance.err"; then
  fail 'protected image build accepted provenance from a different builder'
fi
grep -qF 'Protected image provenance is invalid' \
  "$work/invalid-provenance.err" ||
  fail 'invalid emitted provenance rejection was not attributable'
[[ "$(build_invocation_count)" -eq 1 ]] ||
  fail 'provenance rejection rebuilt an immutable source image'

if (
  cd "$source_fixture"
  FAKE_SBOM_INVALID=1 \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
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
  cd "$source_fixture"
  FAKE_LOGIN_FAILURES=1 FAKE_LOGIN_STATE="$work/login-state" \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
) >"$work/transient-login.out" 2>&1
grep -qF 'Registry login was rejected; retrying authentication' \
  "$work/transient-login.out" || fail 'transient initial registry login was not reported'
[[ "$(grep -c ' login ' "$FAKE_DOCKER_CALLS")" -eq $((login_calls_before + 2)) ]] ||
  fail 'transient initial registry login was not retried exactly once'

# Only a rejected credential is retried; an unavailable registry fails the
# login at once.
login_calls_before="$(grep -c ' login ' "$FAKE_DOCKER_CALLS" || true)"
if (
  cd "$source_fixture"
  FAKE_LOGIN_UNAVAILABLE=1 \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
) >"$work/unavailable-login.out" 2>&1; then
  fail 'unavailable registry login was accepted'
fi
[[ "$(grep -c ' login ' "$FAKE_DOCKER_CALLS")" -eq $((login_calls_before + 1)) ]] ||
  fail 'unavailable registry login was retried'
grep -qF 'Unable to authenticate to registry registry.example.invalid' \
  "$work/unavailable-login.out" ||
  fail 'unavailable registry login was not attributable'

: >"$GITHUB_OUTPUT"
(
  cd "$source_fixture"
  FAKE_DIGEST="$second_digest" \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
)
[[ "$(build_invocation_count)" -eq 1 ]] ||
  fail 'existing source-SHA image was rebuilt'
[[ "$(cw_producer_invocation_count)" -eq 1 ]] ||
  fail 'source-SHA reuse needlessly rebuilt CW'
grep -qxF "candidate_ref=registry.example.invalid/codewire/daemon@$digest" "$GITHUB_OUTPUT" ||
  fail 'source-SHA rerun did not preserve the original digest'

: >"$GITHUB_OUTPUT"
(
  cd "$source_fixture"
  FAKE_DIGEST="$second_digest" \
  CODEWIRE_BASE_IMAGE_REF="$base_ref" \
  CODEWIRE_CARGO_BUILD_JOBS=14 CODEWIRE_CARGO_JOBS=7 \
    "$BUILDER" workspace images/workspace/Dockerfile .
)
grep -qxF 'family=workspace' "$GITHUB_OUTPUT" ||
  fail 'workspace candidate family is absent'
# On the trusted builder the workspace solve bounds Cargo's jobs to the
# builder's memory, and the CW producer receives the job count this job also
# uses to verify its receipt, never one sized from another machine.
[[ "$(grep -E ' CW_PRODUCER=false .* buildx build ' "$FAKE_DOCKER_CALLS" | grep -c -- '--build-arg CARGO_BUILD_JOBS=14')" -eq 1 ]] ||
  fail 'the workspace build did not bound Cargo jobs'
producer_call="$(grep -E ' CW_PRODUCER=true .* buildx build ' "$FAKE_DOCKER_CALLS")"
[[ "$(grep -c -- '--build-arg CODEWIRE_CARGO_JOBS=7' <<<"$producer_call")" -eq 1 ]] ||
  fail 'the CW producer did not receive the pinned Cargo job count'
if grep -qF -- '--build-arg CARGO_BUILD_JOBS=' <<<"$producer_call"; then
  fail 'the CW producer received the workspace Cargo job count'
fi
grep -qF -- "--build-arg BASE_IMAGE_REF=$base_ref" "$FAKE_DOCKER_CALLS" ||
  fail 'exact base digest did not reach the workspace build'
[[ "$(build_invocation_count)" -eq 2 ]] ||
  fail 'workspace image was not built exactly once'
[[ "$(cw_producer_invocation_count)" -eq 2 ]] ||
  fail 'workspace did not use exactly one additional original CW producer'
assert_cw_context runtime
grep -qF -- '--no-cache-filter workspace-floating-tools' "$FAKE_DOCKER_CALLS" ||
  fail 'published workspace could reuse floating developer tools'
grep -qF -- '--no-cache-filter workspace-agents' "$FAKE_DOCKER_CALLS" ||
  fail 'published workspace could reuse an earlier install of the shipped agents'

if (
  cd "$source_fixture"
  CODEWIRE_BASE_IMAGE_REF="$base_ref" CODEWIRE_CARGO_BUILD_JOBS=many \
    "$BUILDER" workspace images/workspace/Dockerfile . >"$work/cargo-jobs.out" 2>&1
); then
  fail 'an invalid Cargo job count was accepted'
fi
grep -qF 'CODEWIRE_CARGO_BUILD_JOBS must be a whole number of jobs' "$work/cargo-jobs.out" ||
  fail 'the Cargo job count refusal was not attributable'

: >"$GITHUB_OUTPUT"
create_calls_before="$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS" || true)"
(
  cd "$source_fixture"
  REQUIRE_EXISTING_SOURCE_IMAGE=1 \
  CODEWIRE_RELEASE_TAG='v0.3.999' \
  CODEWIRE_SOURCE_SHA="$source_sha" \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
)
grep -qxF "candidate_ref=registry.example.invalid/codewire/daemon@$digest" "$GITHUB_OUTPUT" ||
  fail 'release alias did not preserve the source-SHA digest'
awk -F '\t' \
  -v reference='registry.example.invalid/codewire/daemon:v0.3.999' \
  -v digest="$digest" \
  '$1 == reference && $2 == digest { found = 1 } END { exit !found }' \
  "$FAKE_MANIFESTS" ||
  fail 'release alias was not created from the source digest'
[[ "$(build_invocation_count)" -eq 2 ]] ||
  fail 'release alias rebuilt an existing source image'
[[ "$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS")" -eq $((create_calls_before + 1)) ]] ||
  fail 'release alias was not created exactly once'

# Provenance names only the configured canonical source: without it, or with
# the internal Forgejo URL, the build stops before it touches Docker.
build_calls_before="$(build_invocation_count)"
for bad_source in '' 'https://forgejo-internal.tail.example.invalid/codewire/codewire.git' \
    'http://git.example.invalid/codewire/codewire.git'; do
  if (
    cd "$source_fixture"
    CODEWIRE_SOURCE_URL="$bad_source" \
      "$BUILDER" services deployments/docker/services.Dockerfile .
  ) >"$work/source-url-refused.out" 2>&1; then
    fail "an image build accepted CODEWIRE_SOURCE_URL='$bad_source'"
  fi
  grep -qF 'CODEWIRE_SOURCE_URL' "$work/source-url-refused.out" ||
    fail "a refused CODEWIRE_SOURCE_URL='$bad_source' did not name the variable"
done
[[ "$(build_invocation_count)" -eq "$build_calls_before" ]] ||
  fail 'a refused provenance source reached a build'

build_calls_before="$(build_invocation_count)"
if (
  cd "$source_fixture"
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
  cd "$source_fixture"
  CODEWIRE_RELEASE_TAG='v0.3.999' \
  CODEWIRE_SOURCE_SHA="$source_sha" \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
)
[[ "$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS")" -eq $((create_calls_before + 1)) ]] ||
  fail 'matching release alias was rewritten'

printf '0\n' >"$work/inspect-auth-state"
login_calls_before="$(grep -c ' login ' "$FAKE_DOCKER_CALLS" || true)"
create_calls_before_auth="$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS" || true)"
(
  cd "$source_fixture"
  FAKE_INSPECT_AUTH_ONCE_REF='registry.example.invalid/codewire/daemon:v0.3.997' \
  FAKE_INSPECT_AUTH_STATE="$work/inspect-auth-state" \
  CODEWIRE_RELEASE_TAG='v0.3.997' \
  CODEWIRE_SOURCE_SHA="$source_sha" \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
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
  cd "$source_fixture"
  FAKE_CREATE_AUTH_ONCE_REF='registry.example.invalid/codewire/daemon:v0.3.996' \
  FAKE_CREATE_AUTH_STATE="$work/create-auth-state" \
  CODEWIRE_RELEASE_TAG='v0.3.996' \
  CODEWIRE_SOURCE_SHA="$source_sha" \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
) >"$work/transient-create-auth.out" 2>&1
grep -qF 'Registry authentication expired while creating' \
  "$work/transient-create-auth.out" || fail 'transient create auth was not reported'
[[ "$(grep -c ' login ' "$FAKE_DOCKER_CALLS")" -eq $((login_calls_before + 2)) ]] ||
  fail 'transient create auth did not perform exactly one bounded re-login'
[[ "$(grep -c 'buildx imagetools create' "$FAKE_DOCKER_CALLS")" -eq $((create_calls_before_auth + 2)) ]] ||
  fail 'transient create auth was not retried exactly once'

printf '%s\t%s\n' \
  'registry.example.invalid/codewire/daemon:v0.3.998' "$mismatch_digest" \
  >>"$FAKE_MANIFESTS"
if (
  cd "$source_fixture"
  CODEWIRE_RELEASE_TAG='v0.3.998' \
  CODEWIRE_SOURCE_SHA="$source_sha" \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
) >"$work/mismatched-alias.out" 2>&1; then
  fail 'mismatched immutable release alias was accepted'
fi
grep -qF 'Refusing to replace immutable image tag' "$work/mismatched-alias.out" ||
  fail 'mismatched release alias did not fail with the immutable-tag guard'
[[ "$(build_invocation_count)" -eq 2 ]] ||
  fail 'mismatched release alias triggered a build'

export FAKE_INSPECT_ERROR_REF="registry.example.invalid/codewire/mesh:$source_sha"
login_calls_before="$(grep -c ' login ' "$FAKE_DOCKER_CALLS" || true)"
if (
  cd "$source_fixture"
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
  cd "$source_fixture"
  REQUIRE_EXISTING_SOURCE_IMAGE=yes \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
) >"$work/invalid-require-existing.out" 2>&1; then
  fail 'invalid existing-source requirement was accepted'
fi
grep -qF 'REQUIRE_EXISTING_SOURCE_IMAGE must be 0 or 1' \
  "$work/invalid-require-existing.out" ||
  fail 'invalid existing-source requirement did not fail explicitly'
[[ "$(wc -l <"$FAKE_FETCH_CALLS")" -eq "$fetch_calls_before" ]] ||
  fail 'invalid existing-source requirement reached credential retrieval'

if (
  cd "$source_fixture"
  CODEWIRE_BASE_IMAGE_REF='registry.example.invalid/codewire/base:latest' \
    "$BUILDER" workspace images/workspace/Dockerfile .
) >"$work/moving-base.out" 2>&1; then
  fail 'moving workspace base image was accepted'
fi
[[ "$(wc -l <"$FAKE_FETCH_CALLS")" -eq "$fetch_calls_before" ]] ||
  fail 'invalid workspace base reached credential retrieval'

if (
  cd "$source_fixture"
  CODEWIRE_BASE_IMAGE_REF="$base_ref" \
    "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
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
  cd "$source_fixture"
  CODEWIRE_DOCKER_BIN="$work/bin/docker" \
  CODEWIRE_BAKE_METADATA_FILE="$work/kind-r2-metadata.json" \
  CODEWIRE_SCCACHE_MODE=r2 \
  CODEWIRE_SCCACHE_CREDENTIALS_FILE="$r2_credentials_file" \
  SCCACHE_BUCKET=example-ci-cache-protected \
  SCCACHE_ENDPOINT=https://account.r2.cloudflarestorage.com \
  CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/test \
    "$source_fixture/scripts/ci/images/build-kind-images.sh"
)
[[ "$(grep -oF 'secrets+=id=aws_shared_credentials\,src=' "$FAKE_DOCKER_CALLS" | wc -l)" -eq 4 ]] ||
  fail 'Kind did not bind and append the private credential file to all four Bake targets'
grep -qF "src=$r2_credentials_file" "$FAKE_DOCKER_CALLS" ||
  fail 'Kind did not pass the exact private credential file path to Bake'
[[ "$(cw_producer_invocation_count)" -eq 1 ]] ||
  fail 'Kind R2 caller did not use one runtime-profile original CW producer'
assert_cw_context runtime

: >"$FAKE_DOCKER_CALLS"
(
  cd "$source_fixture"
  CODEWIRE_SCCACHE_MODE=r2 \
  CODEWIRE_SCCACHE_CREDENTIALS_FILE="$r2_credentials_file" \
  SCCACHE_BUCKET=example-ci-cache-protected \
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

for family in dashboard services mesh daemon derp; do
  awk -F '\t' \
    -v reference="registry.example.invalid/codewire/${family}:$source_sha" \
    '$1 != reference' "$FAKE_MANIFESTS" >"$FAKE_MANIFESTS.tmp"
  mv "$FAKE_MANIFESTS.tmp" "$FAKE_MANIFESTS"
done
runtime_builds_before="$(build_invocation_count)"
: >"$GITHUB_OUTPUT"
(
  cd "$source_fixture"
  CODEWIRE_BUILD_RUNTIME_SET=1 \
  CODEWIRE_SCCACHE_MODE=r2 \
  CODEWIRE_SCCACHE_CREDENTIALS_FILE="$r2_credentials_file" \
  SCCACHE_BUCKET=example-ci-cache-protected \
  SCCACHE_ENDPOINT=https://account.r2.cloudflarestorage.com \
  CODEWIRE_SCCACHE_PREFIX=protected/codewire/test \
    "$BUILDER" services deployments/docker/services.Dockerfile .
)
[[ "$(build_invocation_count)" -eq $((runtime_builds_before + 1)) ]] ||
  fail 'protected runtime set did not issue exactly one additional Bake build'
# The daemon and its static CW producer build in their own protected job, so
# the service runtime set never runs the producer or touches the daemon tag.
[[ "$(cw_producer_invocation_count)" -eq 0 ]] ||
  fail 'protected service runtime set ran the CW producer'
grep -Eq ' buildx bake .* dashboard services mesh derp ?$' "$FAKE_DOCKER_CALLS" ||
  fail 'protected runtime set did not execute exactly the four service targets'
runtime_set_call="$(grep -E ' buildx bake .* dashboard services mesh derp ?$' "$FAKE_DOCKER_CALLS" | tail -1)"
[[ "$(grep -oF 'secrets+=id=aws_shared_credentials\,src=' <<<"$runtime_set_call" | wc -l)" -eq 4 ]] ||
  fail 'protected runtime Bake did not bind the private cache credential to all four service targets'
[[ "$runtime_set_call" != *'daemon.'* && "$runtime_set_call" != *' default'* ]] ||
  fail 'protected service runtime set built or tagged the daemon'
awk -F '\t' \
  -v reference="registry.example.invalid/codewire/daemon:$source_sha" \
  '$1 == reference { found = 1 } END { exit found }' \
  "$FAKE_MANIFESTS" || fail 'protected service runtime set published a daemon source tag'
for family in dashboard services mesh derp; do
  grep -qF -- "${family}.tags=registry.example.invalid/codewire/${family}:$source_sha" \
    "$FAKE_DOCKER_CALLS" || fail "protected runtime Bake omitted exact $family source tag"
  awk -F '\t' \
    -v reference="registry.example.invalid/codewire/${family}:$source_sha" \
    -v digest="$digest" \
    '$1 == reference && $2 == digest { found = 1 } END { exit !found }' \
    "$FAKE_MANIFESTS" || fail "protected runtime Bake omitted the $family manifest"
done
grep -qxF "candidate_ref=registry.example.invalid/codewire/services@$digest" \
  "$GITHUB_OUTPUT" || fail 'protected runtime Bake did not preserve the anchor candidate digest'

awk -F '\t' \
  -v reference="registry.example.invalid/codewire/mesh:$source_sha" \
  '$1 != reference' "$FAKE_MANIFESTS" >"$FAKE_MANIFESTS.tmp"
mv "$FAKE_MANIFESTS.tmp" "$FAKE_MANIFESTS"
partial_runtime_builds_before="$(build_invocation_count)"
if (
  cd "$source_fixture"
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
  cd "$source_fixture"
  CODEWIRE_BUILD_RUNTIME_SET=1 \
    "$BUILDER" services deployments/docker/services.Dockerfile .
)
[[ "$(build_invocation_count)" -eq $((partial_runtime_builds_before + 1)) ]] ||
  fail 'partial protected runtime retry did not issue exactly one Bake build'
[[ "$(cw_producer_invocation_count)" -eq 0 ]] ||
  fail 'a mesh-only retry needlessly rebuilt CW'
partial_runtime_call="$(grep -E ' buildx bake ' "$FAKE_DOCKER_CALLS" | tail -1)"
[[ "$partial_runtime_call" == *' mesh ' ]] ||
  fail 'partial protected runtime retry did not rebuild only the missing target'
[[ "$partial_runtime_call" != *'services.tags='* ]] ||
  fail 'partial protected runtime retry attempted to overwrite an existing immutable target'

fetch_calls_before="$(wc -l <"$FAKE_FETCH_CALLS")"
if (
  cd "$source_fixture"
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
mkdir -m 0700 "$work/kind-default"
(
  cd "$source_fixture"
  unset CODEWIRE_KIND_RETAIN_CW_ASSETS
  RUNNER_TEMP="$work/kind-default" \
  FAKE_KIND_WORK_FILE="$work/kind-default-work" \
  CODEWIRE_DOCKER_BIN="$work/bin/docker" \
  CODEWIRE_BAKE_METADATA_FILE="$work/kind-metadata.json" \
    "$source_fixture/scripts/ci/images/build-kind-images.sh"
) >"$work/kind-build.out"
[[ "$(grep -Ec ' buildx bake .* kind $' "$FAKE_DOCKER_CALLS" || true)" -eq \
  $((kind_builds_before + 1)) ]] || fail 'Kind did not issue exactly one Bake graph build'
grep -Eq ' buildx create --name codewire-kind-.* --driver docker-container .* --buildkitd-config .* --bootstrap ' \
  "$FAKE_DOCKER_CALLS" || fail 'Kind did not create its bounded transient BuildKit daemon'
grep -qF -- '--driver-opt image=docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5' \
  "$FAKE_DOCKER_CALLS" || fail 'Kind did not use the pinned BuildKit daemon image'
grep -Eq ' buildx bake .*--builder codewire-kind-.* kind $' "$FAKE_DOCKER_CALLS" ||
  fail 'Kind Bake did not use its bounded transient builder'
grep -Eq ' buildx rm --force codewire-kind-' "$FAKE_DOCKER_CALLS" ||
  fail 'Kind did not destroy its transient BuildKit daemon'
[[ "$(grep -c ' image inspect ' "$FAKE_DOCKER_CALLS" || true)" -eq 12 ]] ||
  fail 'Kind did not verify existence and trust labels for all four loaded images'
grep -qF 'CODEWIRE_CI_PHASE name=product-image-build' "$work/kind-build.out" ||
  fail 'Kind image builder omitted its structured phase result'
[[ "$(cw_producer_invocation_count)" -eq 1 ]] ||
  fail 'local Kind caller did not use one additional runtime-profile original CW producer'
assert_cw_context runtime
kind_default_work="$(cat "$work/kind-default-work")"
[[ "$kind_default_work" == "$work/kind-default/"codewire-kind-images.* \
    && ! -e "$kind_default_work" && ! -L "$kind_default_work" ]] ||
  fail 'default Kind cleanup retained or retargeted the original work'
if grep -qF 'CODEWIRE_KIND_CW_' "$work/kind-build.out"; then
  fail 'default Kind cleanup emitted an opt-in asset locator'
fi

assert_cw_contexts_for_part publish 4 4 0
fi

if runs_part kind; then
# Every case invokes the unchanged consumer/producer with its real admission
# leaves. Only existing synthetic Docker effects vary. A locator cannot turn
# failed produce/solve/image checks or EXIT cleanup into qualification.
kind_retention_case() {
  local name="$1" mode="$2" failure="$3" expected="$4" case_dir status owned_work build_status cleanup_status
  case_dir="$work/kind-retention-$name"
  mkdir -m 0700 "$case_dir" "$case_dir/temp"
  : >"$case_dir/docker-calls"
  set +e
  (
    set -e
    unset CODEWIRE_KIND_RETAIN_CW_ASSETS FAKE_KIND_PRODUCER_FAILURE \
      FAKE_KIND_IMAGE_INVALID FAKE_KIND_BUILDER_REMOVE_FAILURE FAKE_BUILD_FATAL
    if [[ "$mode" != unset ]]; then export CODEWIRE_KIND_RETAIN_CW_ASSETS="$mode"; fi
    case "$failure" in
      producer) export FAKE_KIND_PRODUCER_FAILURE=1 ;;
      solve) export FAKE_BUILD_FATAL=1 ;;
      image) export FAKE_KIND_IMAGE_INVALID=1 ;;
      cleanup) export FAKE_KIND_BUILDER_REMOVE_FAILURE=1 ;;
      cleanup-gone) export FAKE_KIND_BUILDER_REMOVE_FAILURE=gone ;;
      none) ;;
      *) exit 99 ;;
    esac
    RUNNER_TEMP="$case_dir/temp" \
    CODEWIRE_DOCKER_BIN="$work/bin/docker" \
    CODEWIRE_BAKE_METADATA_FILE="$case_dir/metadata.json" \
    FAKE_DOCKER_CALLS="$case_dir/docker-calls" \
    FAKE_CW_CONTEXTS="$case_dir/cw-contexts.jsonl" \
    FAKE_KIND_WORK_FILE="$case_dir/original-work" \
      "$source_fixture/scripts/ci/images/build-kind-images.sh"
  ) >"$case_dir/output" 2>&1
  status=$?
  set -e
  if [[ "$expected" == nonzero ]]; then
    [[ "$status" -ne 0 ]] || fail "retained Kind $name accepted its failed effect"
  else
    [[ "$status" -eq "$expected" ]] || fail "Kind $name exited $status, expected $expected"
  fi
  if [[ "$name" == invalid ]]; then
    [[ ! -s "$case_dir/docker-calls" && ! -e "$case_dir/original-work" \
        && ! -e "$case_dir/metadata.json" ]] || fail 'invalid retention selector reached effects'
    grep -qF 'CODEWIRE_KIND_RETAIN_CW_ASSETS must be 0 or 1' "$case_dir/output" ||
      fail 'invalid retention selector has no attributable refusal'
    [[ -z "$(find "$case_dir/temp" -mindepth 1 -print -quit)" ]] ||
      fail 'invalid retention selector created original work'
    return
  fi
  owned_work="$(cat "$case_dir/original-work")"
  [[ "$owned_work" == "$case_dir/temp/"codewire-kind-images.* ]] ||
    fail "Kind $name work escaped its private parent"
  # One removal, and after a failed one exactly one retry round when objects persist.
  removals=1
  [[ "$failure" != cleanup ]] || removals=2
  [[ "$(grep -Ec ' buildx rm --force codewire-kind-' "$case_dir/docker-calls" || true)" -eq "$removals" ]] ||
    fail "Kind $name did not attempt exactly its transient builder removals"
  if [[ "$mode" == 1 ]]; then
    [[ -d "$owned_work" && ! -L "$owned_work" && -f "$owned_work/buildkitd.toml" ]] ||
      fail "retained Kind $name lost its original work"
    build_status="$status" cleanup_status=0
    if [[ "$failure" == cleanup ]]; then build_status=0; cleanup_status=73; fi
    grep -Fxq "CODEWIRE_KIND_CW_ASSETS work=$owned_work build_status=$build_status cleanup_status=$cleanup_status" \
      "$case_dir/output" || fail "Kind $name omitted exact terminal retention evidence"
  else
    [[ ! -e "$owned_work" && ! -L "$owned_work" ]] || fail "Kind $name retained work without opt-in"
    if grep -qF 'CODEWIRE_KIND_CW_' "$case_dir/output"; then
      fail "Kind $name emitted a retention locator without opt-in"
    fi
  fi
  if [[ "$status" -eq 0 || "$failure" == cleanup ]]; then
    if [[ "$mode" == 1 ]]; then
      python3 -B - "$CW_FIXTURE" "$source_fixture" "$owned_work" "$case_dir/output" \
        "$case_dir/cw-contexts.jsonl" <<'PY'
from contextlib import closing
import hashlib, importlib.util, json, re, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('kind_retention_fixture', sys.argv[1])
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
source, work, output, contexts = map(Path, sys.argv[2:])
locators = re.findall(r'^CODEWIRE_KIND_CW_PRODUCER path=(\S+) sha256=([0-9a-f]{64})$', output.read_text(), re.M)
assert len(locators) == 1
result_path = work / 'cw-producer-result.json'
with closing(fixture.source.HeldSourceFile(result_path, fixture.release.MAX_JSON)) as held:
    result = fixture.release.parse_canonical(held.data)
    assert locators[0] == (result['receipt']['path'], result['receipt']['sha256'])
    reference = Path(locators[0][0])
    assert reference.is_relative_to(work) and reference.name == 'build.json'
    assert hashlib.sha256(reference.read_bytes()).hexdigest() == locators[0][1]
    payload = fixture.selected_asset(source, result_path)
    context_rows = [json.loads(line) for line in contexts.read_text().splitlines()]
    assert len(context_rows) == 1 and context_rows[0]['profile'] == 'runtime'
    assert context_rows[0]['payload_sha256'] == hashlib.sha256(payload).hexdigest()
    assert context_rows[0]['producer_receipt_sha256'] == result['receipt']['sha256']
    consumers = list(work.glob('.cw-consumer-parent.*/solve/consumer.json'))
    assert len(consumers) == 1
    consumer = fixture.release.parse_canonical(consumers[0].read_bytes())
    assert consumer['status'] == 'consumer-built' and consumer['producer'] == result['receipt']
    assert consumer['image_qualified'] is False and consumer['cache_qualified'] is False
    held.revalidate(content=True)
PY
    fi
  else
    if grep -qF 'CODEWIRE_KIND_CW_PRODUCER' "$case_dir/output"; then
      fail "Kind $name emitted its successful-solve locator after a failed effect"
    fi
    case "$failure" in
      producer)
        [[ ! -e "$owned_work/cw-producer-result.json" ]] || fail 'failed producer published admitted selection'
        grep -qF 'synthetic Kind CW producer failure' "$case_dir/output" || fail 'producer failure lost its diagnostic'
        ;;
      solve|image)
        [[ -f "$owned_work/cw-producer-result.json" ]] || fail 'failed image stage lost its original producer'
        if [[ "$failure" == solve ]]; then
          [[ -z "$(find "$owned_work" -name consumer.json -print -quit)" ]] ||
            fail 'failed image solve published successful consumer evidence'
          grep -qF '503 Service Unavailable' "$case_dir/output" || fail 'solve failure lost its diagnostic'
        else
          grep -qF 'Kind image is not marked with the runtime profile' "$case_dir/output" || fail 'image-label failure lost its diagnostic'
        fi
        ;;
    esac
  fi
  if [[ "$failure" == cleanup ]]; then
    grep -qF 'failed to remove transient builder' "$case_dir/output" || fail 'cleanup failure was hidden'
    grep -Eq '^Kind image build cleanup: phase=builder-removal status=73 elapsed_seconds=[0-9]+ persists: builder codewire-kind-[^,]+, container buildx_buildkit_codewire-kind-[^,]+-node, volume buildx_buildkit_codewire-kind-[^,]+-node_state$' \
      "$case_dir/output" || fail 'persisting builder objects were not named'
  fi
  if [[ "$failure" == cleanup-gone ]]; then
    # #2990: Buildx's client gave up while Docker finished deleting the state
    # volume. Docker reporting every builder object missing is the cleanup.
    grep -Eq '^Kind image build cleanup: phase=builder-removal status=73 confirmed-absent=true elapsed_seconds=[0-9]+$' \
      "$case_dir/output" || fail 'confirmed-absent builder removal was not reported'
    ! grep -qF 'failed to remove transient builder' "$case_dir/output" ||
      fail 'a builder Docker reports gone failed the Kind image build'
  fi
}

kind_retention_case explicit-zero 0 none 0
kind_retention_case retained-success 1 none 0
kind_retention_case producer-failure 1 producer nonzero
kind_retention_case solve-failure 1 solve nonzero
kind_retention_case image-check-failure 1 image nonzero
kind_retention_case invalid 2 none 2
kind_retention_case retained-cleanup-failure 1 cleanup 73
kind_retention_case default-cleanup-failure unset cleanup 73
kind_retention_case default-cleanup-gone unset cleanup-gone 0

# #2965: a local Kind build keeps one persistent image builder. The first run
# creates it, a later run reuses it, and neither removes it; an unknown builder
# selection is refused before any effect.
persistent_case() {
  local case_dir="$work/kind-persistent-$1"
  mkdir -m 0700 "$case_dir"
  mkdir -m 0700 "$case_dir/temp"
  : >"$case_dir/docker-calls"
  (
    unset CODEWIRE_KIND_RETAIN_CW_ASSETS FAKE_KIND_PRODUCER_FAILURE FAKE_KIND_IMAGE_INVALID \
      FAKE_KIND_BUILDER_REMOVE_FAILURE FAKE_BUILD_FATAL
    RUNNER_TEMP="$case_dir/temp" CODEWIRE_DOCKER_BIN="$work/bin/docker" \
    CODEWIRE_KIND_IMAGE_BUILDER="$2" FAKE_PERSISTENT_BUILDERS="$work/persistent-builders" \
    CODEWIRE_BAKE_METADATA_FILE="$case_dir/metadata.json" FAKE_DOCKER_CALLS="$case_dir/docker-calls" \
    FAKE_CW_CONTEXTS="$case_dir/cw-contexts.jsonl" FAKE_KIND_WORK_FILE="$case_dir/original-work" \
      "$source_fixture/scripts/ci/images/build-kind-images.sh"
  ) >"$case_dir/output" 2>&1
}
mkdir -m 0700 "$work/persistent-builders"
for name in first second; do
  persistent_case "$name" persistent ||
    { cat "$work/kind-persistent-$name/output" >&2; fail "the $name persistent Kind build failed"; }
  ! grep -Eq ' buildx rm ' "$work/kind-persistent-$name/docker-calls" ||
    fail "the $name persistent Kind build removed its builder"
done
[[ "$(grep -Ec ' buildx create .*--name codewire-kind-images-' "$work/kind-persistent-first/docker-calls" || true)" -eq 1 ]] ||
  fail 'the first persistent Kind build did not create its builder once'
! grep -Eq ' buildx create ' "$work/kind-persistent-second/docker-calls" ||
  fail 'the second persistent Kind build created another builder'
grep -Fq 'reusing the persistent builder codewire-kind-images-' "$work/kind-persistent-second/output" ||
  fail 'the second persistent Kind build did not say it reused its builder'
if persistent_case invalid sometimes; then fail 'an unknown Kind builder selection was accepted'; fi
grep -Fq 'CODEWIRE_KIND_IMAGE_BUILDER must be transient or persistent' "$work/kind-persistent-invalid/output" ||
  fail 'an unknown Kind builder selection has no attributable refusal'
[[ ! -s "$work/kind-persistent-invalid/docker-calls" ]] || fail 'an unknown Kind builder selection reached Docker'

fi

if runs_part builds; then
base_source_tag="registry.example.invalid/codewire/base:$source_sha"
awk -F '\t' -v reference="$base_source_tag" \
  '$1 != reference' "$FAKE_MANIFESTS" >"$FAKE_MANIFESTS.tmp"
mv "$FAKE_MANIFESTS.tmp" "$FAKE_MANIFESTS"
fatal_builds_before="$(build_invocation_count)"
if (
  cd "$source_fixture"
  FAKE_BUILD_FATAL=1 "$BUILDER" base images/base/Dockerfile images/base
) >"$work/failed-build.out" 2>&1; then
  fail 'failed protected publication was accepted'
fi
[[ "$(build_invocation_count)" -eq $((fatal_builds_before + 1)) ]] ||
  fail 'failed protected publication was retried'
grep -qF '503 Service Unavailable' "$work/failed-build.out" ||
  fail 'failed protected publication was not preserved'

# A build that fails on a transient network error (#2691) is retried, with
# its error and a fixed marker in the log, and recovers within three attempts.
rm -f "$work/build-network-state"
network_builds_before="$(build_invocation_count)"
if ! (
  cd "$source_fixture"
  FAKE_BUILD_NETWORK_FAILURES=2 FAKE_BUILD_NETWORK_STATE="$work/build-network-state" \
    CODEWIRE_BUILD_NETWORK_RETRY_DELAY_SECONDS=0 \
    "$BUILDER" base images/base/Dockerfile images/base
) >"$work/network-build.out" 2>&1; then
  sed -n '1,80p' "$work/network-build.out" >&2
  fail 'a transient network failure was not retried to success'
fi
[[ "$(build_invocation_count)" -eq $((network_builds_before + 3)) ]] ||
  fail 'a transient network failure did not use exactly three build attempts'
[[ "$(grep -Fc '[build-network] transient network failure image=base status=1; retrying in 0s' "$work/network-build.out")" == 2 ]] ||
  fail 'network build retries were not reported with their fixed marker'
[[ "$(grep -Fc 'net/http: TLS handshake timeout' "$work/network-build.out")" == 2 ]] ||
  fail 'network build retries hid the failed fetch'

# Removing the published tag makes the next case build again.
awk -F '\t' -v reference="$base_source_tag" \
  '$1 != reference' "$FAKE_MANIFESTS" >"$FAKE_MANIFESTS.tmp"
mv "$FAKE_MANIFESTS.tmp" "$FAKE_MANIFESTS"
rm -f "$work/build-network-state"
network_builds_before="$(build_invocation_count)"
if (
  cd "$source_fixture"
  FAKE_BUILD_NETWORK_FAILURES=3 FAKE_BUILD_NETWORK_STATE="$work/build-network-state" \
    CODEWIRE_BUILD_NETWORK_RETRY_DELAY_SECONDS=0 \
    "$BUILDER" base images/base/Dockerfile images/base
) >"$work/network-exhausted.out" 2>&1; then
  fail 'an exhausted network retry was accepted'
fi
[[ "$(build_invocation_count)" -eq $((network_builds_before + 3)) ]] ||
  fail 'network build retries exceeded three attempts'
grep -qF '[build-network] class=transient-exhausted image=base status=1 attempts=3' \
  "$work/network-exhausted.out" || fail 'exhausted network build retries lack their fixed marker'

# Workspace publication retains the protected compiler-cache API, but no
# untrusted external layer cache may reach any publisher, even on source reuse.
fetch_calls_before="$(wc -l <"$FAKE_FETCH_CALLS")"
for mode in r2 auto invalid; do
  if CODEWIRE_BUILDKIT_CACHE_MODE="$mode" "$BUILDER" workspace images/workspace/Dockerfile . >"$work/layer-rejection.out" 2>&1; then
    fail "publisher accepted external layer mode $mode"
  fi
done
[[ "$(wc -l <"$FAKE_FETCH_CALLS")" == "$fetch_calls_before" ]] || fail 'layer mode rejection reached protected credentials'
if CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_SCCACHE_CREDENTIALS_FILE="$r2_credentials_file" \
    SCCACHE_BUCKET=example-ci-cache SCCACHE_ENDPOINT=https://account.r2.cloudflarestorage.com \
    CODEWIRE_SCCACHE_PREFIX=untrusted/codewire/v1 \
    "$BUILDER" workspace images/workspace/Dockerfile . >"$work/compiler-rejection.out" 2>&1; then
  fail 'published workspace accepted an untrusted compiler prefix'
fi
# Every published image writes only the one protected CI cache (infra#1544):
# any other bucket is refused, whatever its prefix.
for image in 'workspace images/workspace/Dockerfile' 'services deployments/docker/services.Dockerfile'; do
  # shellcheck disable=SC2086 # Each fixture is a deliberate argument vector.
  if CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_SCCACHE_CREDENTIALS_FILE="$r2_credentials_file" \
      SCCACHE_BUCKET=example-ci-cache-protected-workspace SCCACHE_ENDPOINT=https://account.r2.cloudflarestorage.com \
      CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1 \
      "$BUILDER" $image . >"$work/lane-rejection.out" 2>&1; then
    fail "published image ${image%% *} accepted a bucket other than the protected cache"
  fi
  grep -Fq 'Published images may use only the protected sccache bucket' "$work/lane-rejection.out" ||
    fail "published image ${image%% *} rejection was not attributable"
done
# The protected bucket is site configuration with no default: unset, an r2
# build stops and names the variable.
if CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED='' CODEWIRE_SCCACHE_MODE=r2 \
    CODEWIRE_SCCACHE_CREDENTIALS_FILE="$r2_credentials_file" \
    SCCACHE_BUCKET=example-ci-cache-protected SCCACHE_ENDPOINT=https://account.r2.cloudflarestorage.com \
    CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1 \
    "$BUILDER" workspace images/workspace/Dockerfile . >"$work/no-bucket.out" 2>&1; then
  fail 'a published image built without the protected bucket variable'
fi
grep -Fq 'CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED' "$work/no-bucket.out" ||
  fail 'the missing protected bucket variable was not named'

# Exercise old release sources and explicit cold mode through the real argument
# construction. Only the synthetic registry manifests are removed between runs.
workspace_source_tag="registry.example.invalid/codewire/workspace:$source_sha"
printf 'FROM scratch\n' >"$work/legacy-workspace.Dockerfile"
for variant in legacy disabled protected; do
  awk -F '\t' -v reference="$workspace_source_tag" '$1 != reference' "$FAKE_MANIFESTS" >"$FAKE_MANIFESTS.tmp"
  mv "$FAKE_MANIFESTS.tmp" "$FAKE_MANIFESTS"
  : >"$FAKE_DOCKER_CALLS"
  case "$variant" in
    legacy)
      CODEWIRE_BASE_IMAGE_REF="$base_ref" "$BUILDER" workspace "$work/legacy-workspace.Dockerfile" . ;;
    disabled)
      CODEWIRE_BUILDKIT_CACHE_MODE=disabled CODEWIRE_BASE_IMAGE_REF="$base_ref" \
        "$BUILDER" workspace images/workspace/Dockerfile . ;;
    protected)
      CODEWIRE_SCCACHE_MODE=r2 CODEWIRE_SCCACHE_CREDENTIALS_FILE="$r2_credentials_file" \
        SCCACHE_BUCKET=example-ci-cache-protected SCCACHE_ENDPOINT=https://account.r2.cloudflarestorage.com \
        CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1 CODEWIRE_BASE_IMAGE_REF="$base_ref" \
        "$BUILDER" workspace images/workspace/Dockerfile . ;;
  esac
  [[ "$(build_invocation_count)" == 1 ]] || fail "$variant workspace was not built exactly once"
  if [[ "$variant" == legacy ]]; then
    [[ "$(cw_producer_invocation_count)" -eq 0 ]] || fail 'legacy noncanonical recipe claimed verified CW'
  else
    [[ "$(cw_producer_invocation_count)" -eq 1 ]] || fail "$variant workspace did not use one original CW producer"
    assert_cw_context runtime
  fi
  if [[ "$variant" == protected ]]; then
    grep -qF -- '--no-cache-filter workspace-floating-tools' "$FAKE_DOCKER_CALLS" || fail 'protected compiler cache omitted freshness'
    grep -qF -- '--build-arg CODEWIRE_SCCACHE_MODE=r2' "$FAKE_DOCKER_CALLS" || fail 'protected workspace compiler API was lost'
    grep -qF -- 'CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1' "$FAKE_DOCKER_CALLS" || fail 'protected compiler prefix was lost'
  else
    grep -qF -- '--no-cache ' "$FAKE_DOCKER_CALLS" || fail "$variant workspace lacks cold-layer bypass"
    if grep -qF -- '--no-cache-filter' "$FAKE_DOCKER_CALLS"; then fail 'publisher combined exclusive no-cache flags'; fi
  fi
  if grep -qE -- '--cache-(from|to)|untrusted-(access-key|secret-key)' "$FAKE_DOCKER_CALLS"; then fail 'publisher exported candidate cache or credential material'; fi
  if grep -qF 'codewire-apt-mirror' "$FAKE_DOCKER_CALLS"; then fail "$variant workspace received an unset apt snapshot secret"; fi
done

# The CI apt snapshot cache reaches only base and workspace builds, as an
# optional secret whose value the Buildx client reads from its environment.
apt_mirror='http://apt-cache.invalid:8080'
apt_mirror_secret=' --secret id=codewire-apt-mirror\,env=CODEWIRE_APT_SNAPSHOT_MIRROR '
probe_source_tag="registry.example.invalid/codewire/confidential-probe:$source_sha"
for variant in base-mirror workspace-mirror base-empty-mirror probe-mirror; do
  for reference in "$base_source_tag" "$workspace_source_tag" "$probe_source_tag"; do
    awk -F '\t' -v reference="$reference" '$1 != reference' "$FAKE_MANIFESTS" >"$FAKE_MANIFESTS.tmp"
    mv "$FAKE_MANIFESTS.tmp" "$FAKE_MANIFESTS"
  done
  : >"$FAKE_DOCKER_CALLS"
  case "$variant" in
    base-mirror)
      CODEWIRE_APT_SNAPSHOT_MIRROR="$apt_mirror" "$BUILDER" base images/base/Dockerfile images/base ;;
    workspace-mirror)
      CODEWIRE_APT_SNAPSHOT_MIRROR="$apt_mirror" CODEWIRE_BASE_IMAGE_REF="$base_ref" \
        "$BUILDER" workspace images/workspace/Dockerfile . ;;
    base-empty-mirror)
      CODEWIRE_APT_SNAPSHOT_MIRROR='' "$BUILDER" base images/base/Dockerfile images/base ;;
    probe-mirror)
      CODEWIRE_APT_SNAPSHOT_MIRROR="$apt_mirror" \
        "$BUILDER" confidential-probe images/confidential-probe/Dockerfile images/confidential-probe ;;
  esac >"$work/$variant.out" 2>&1
  [[ "$(build_invocation_count)" == 1 ]] || fail "$variant was not built exactly once"
  build_call="$(grep -E ' buildx (bake|build) ' "$FAKE_DOCKER_CALLS")"
  # Only a Dockerfile that declares the registry argument receives it.
  if [[ "$variant" == probe-mirror ]]; then
    grep -qF -- '--build-arg CODEWIRE_IMAGE_REGISTRY=registry.example.invalid ' <<<"$build_call" ||
      fail 'the probe build did not receive its registry host'
  elif grep -qF 'CODEWIRE_IMAGE_REGISTRY=' <<<"$build_call"; then
    fail "$variant received a registry build argument its Dockerfile does not declare"
  fi
  case "$variant" in
    base-mirror|workspace-mirror)
      [[ "$(grep -oF -- "$apt_mirror_secret" <<<"$build_call" | wc -l)" == 1 ]] ||
        fail "$variant did not receive exactly one apt snapshot secret"
      grep -qF "CODEWIRE_APT_SNAPSHOT_MIRROR=$apt_mirror " <<<"$build_call" ||
        fail "$variant Buildx client cannot read the apt snapshot secret source"
      # The value appears only as the client's inherited environment.
      [[ "$(grep -oF 'apt-cache.invalid' "$FAKE_DOCKER_CALLS" | wc -l)" == \
        "$(grep -c 'CODEWIRE_APT_SNAPSHOT_MIRROR=http://apt-cache.invalid:8080 ' "$FAKE_DOCKER_CALLS")" ]] ||
        fail "$variant passed the apt snapshot cache host as an argument"
      ;;
    *)
      if grep -qF 'codewire-apt-mirror' "$FAKE_DOCKER_CALLS"; then
        fail "$variant received the apt snapshot secret"
      fi
      ;;
  esac
done

# A direct protected build that asks for the trusted BuildKit builder attaches
# it over mutual TLS and starts no BuildKit container of its own; without the
# builder it fails before building, and only the owner's recovery builds here.
cat >"$work/trusted-fetcher" <<'SH'
#!/usr/bin/env bash
[ "${FAKE_TRUSTED_CLIENT:-valid}" = valid ] || exit 1
for file in ca.crt client.crt client.key; do printf 'synthetic\n' >"$1/$file"; done
SH
chmod 0755 "$work/trusted-fetcher"
for variant in trusted trusted-down trusted-refused in-job ambiguous; do
  awk -F '\t' -v reference="$probe_source_tag" '$1 != reference' "$FAKE_MANIFESTS" >"$FAKE_MANIFESTS.tmp"
  mv "$FAKE_MANIFESTS.tmp" "$FAKE_MANIFESTS"
  : >"$FAKE_DOCKER_CALLS"
  case "$variant" in
    trusted) case_env=() ;;
    trusted-down) case_env=(FAKE_TRUSTED_DOWN=1) ;;
    trusted-refused) case_env=(FAKE_TRUSTED_CLIENT=refused) ;;
    in-job) case_env=(CODEWIRE_IN_JOB_BUILD=1) ;;
    ambiguous) case_env=(CODEWIRE_IN_JOB_BUILD=yes) ;;
  esac
  status=0
  env "${case_env[@]}" CODEWIRE_TRUSTED_BUILDKIT=1 TRUSTED_BUILDKIT_CLIENT_FETCHER="$work/trusted-fetcher" \
    "$BUILDER" confidential-probe images/confidential-probe/Dockerfile images/confidential-probe \
    >"$work/$variant.out" 2>&1 || status=$?
  case "$variant" in
    trusted|in-job)
      [[ "$status" == 0 && "$(build_invocation_count)" == 1 ]] || fail "$variant probe build failed"
      ;;
    *)
      [[ "$status" != 0 && "$(build_invocation_count)" == 0 ]] || fail "$variant probe build was not refused"
      ;;
  esac
  case "$variant" in
    trusted)
      grep -qE ' buildx create --name codewire-publish-[^ ]+ --driver remote --platform linux/amd64 ' "$FAKE_DOCKER_CALLS" ||
        fail 'the probe did not attach the trusted BuildKit builder'
      if grep -qF -- '--driver docker-container' "$FAKE_DOCKER_CALLS"; then
        fail 'the probe started its own BuildKit container'
      fi
      grep -qE ' buildx rm --force codewire-publish-' "$FAKE_DOCKER_CALLS" ||
        fail 'the probe did not forget the trusted builder'
      ;;
    trusted-down|trusted-refused)
      grep -qF 'do not fall back to building in the job' "$work/$variant.out" ||
        fail "$variant refusal was not attributable"
      if grep -qF -- '--driver docker-container' "$FAKE_DOCKER_CALLS"; then
        fail "$variant fell back to building in the job"
      fi
      ;;
    in-job)
      grep -qF -- '--driver docker-container' "$FAKE_DOCKER_CALLS" ||
        fail 'the owner recovery did not build on the job builder'
      if grep -qF -- '--driver remote' "$FAKE_DOCKER_CALLS"; then
        fail 'the owner recovery still attached the trusted builder'
      fi
      ;;
  esac
done
if CODEWIRE_TRUSTED_BUILDKIT=yes "$BUILDER" confidential-probe images/confidential-probe/Dockerfile \
    images/confidential-probe >"$work/trusted-ambiguous.out" 2>&1; then
  fail 'an ambiguous trusted builder switch was accepted'
fi

assert_cw_contexts_for_part builds 3 3 0
fi

if runs_part support; then
# The support pair publishes one index for amd64 and arm64. Every platform in
# that index, and no other, must carry its own valid provenance and SBOM.
remove_source_manifest() {
  awk -F '\t' -v reference="$1" '$1 != reference' "$FAKE_MANIFESTS" >"$FAKE_MANIFESTS.tmp"
  mv "$FAKE_MANIFESTS.tmp" "$FAKE_MANIFESTS"
}
readonly support_platforms_call='--platform linux/amd64\,linux/arm64 '
# shellcheck disable=SC2016 # Match the escaped literal template in the call log.
readonly multi_provenance_call='\{\{json\ .Provenance\}\}'
# shellcheck disable=SC2016
readonly multi_sbom_call='\{\{json\ .SBOM\}\}'
for family in base workspace; do
  case "$family" in
    base) family_args=(images/base/Dockerfile images/base) ;;
    workspace) family_args=(images/workspace/Dockerfile .) ;;
  esac
  family_env=()
  [[ "$family" != workspace ]] || family_env=("CODEWIRE_BASE_IMAGE_REF=$base_ref")
  remove_source_manifest "registry.example.invalid/codewire/$family:$source_sha"
  : >"$FAKE_DOCKER_CALLS"
  (
    cd "$source_fixture"
    env "${family_env[@]}" "$BUILDER" "$family" "${family_args[@]}"
  ) >"$work/support-$family.out" 2>&1 || fail "$family support image did not publish both architectures"
  [[ "$(build_invocation_count)" -eq 1 ]] || fail "$family support image was not built exactly once"
  grep -qF -- "$support_platforms_call" "$FAKE_DOCKER_CALLS" ||
    fail "$family support image was not built for amd64 and arm64"
  grep -qF -- "$multi_provenance_call" "$FAKE_DOCKER_CALLS" ||
    fail "$family support index did not verify per-platform provenance"
  grep -qF -- "$multi_sbom_call" "$FAKE_DOCKER_CALLS" ||
    fail "$family support index did not verify per-platform SBOMs"
  if grep -qF -- 'Provenance.SLSA' "$FAKE_DOCKER_CALLS" || grep -qF -- 'SBOM.SPDX' "$FAKE_DOCKER_CALLS"; then
    fail "$family support index accepted a single-platform attestation view"
  fi
done
# The amd64 leg still consumes the verified static CW; arm64 compiles natively.
[[ "$(cw_producer_invocation_count)" -eq 1 ]] ||
  fail 'multi-platform workspace did not bind the one original amd64 CW producer'
assert_cw_context runtime

base_source_tag="registry.example.invalid/codewire/base:$source_sha"
for attestation_case in missing-arm64 extra-platform invalid-arm64-sbom; do
  remove_source_manifest "$base_source_tag"
  case "$attestation_case" in
    missing-arm64) case_env=('FAKE_ATTESTED_PLATFORMS=linux/amd64') expected='Protected image provenance is invalid' ;;
    extra-platform) case_env=('FAKE_ATTESTED_PLATFORMS=linux/amd64,linux/arm64,linux/riscv64') expected='Protected image provenance is invalid' ;;
    invalid-arm64-sbom) case_env=('FAKE_SBOM_INVALID_PLATFORM=linux/arm64') expected='Protected image SBOM is invalid' ;;
  esac
  if (
    cd "$source_fixture"
    env "${case_env[@]}" "$BUILDER" base images/base/Dockerfile images/base
  ) >"$work/support-$attestation_case.out" 2>&1; then
    fail "support index accepted $attestation_case attestations"
  fi
  grep -qF "$expected" "$work/support-$attestation_case.out" ||
    fail "support index $attestation_case rejection was not attributable"
done

# A main commit whose support inputs did not change gets the pair built for an
# earlier commit as an alias (#3504), so its indexes' provenance names that
# commit. A release reuses such an index only when it names the building
# commit (CODEWIRE_PROVENANCE_REVISION, proved by release-support-pair-state.sh);
# without it the index is refused, as deploy-prod run 24911 refused v0.4.3's.
remove_source_manifest "$base_source_tag"
(
  cd "$source_fixture"
  "$BUILDER" base images/base/Dockerfile images/base
) >"$work/alias-base.out" 2>&1 || fail 'the base index for the alias cases did not publish'
alias_origin_sha=3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
alias_reuse() {
  : >"$GITHUB_OUTPUT"
  (
    cd "$source_fixture"
    env FAKE_SOURCE_SHA="$alias_origin_sha" REQUIRE_EXISTING_SOURCE_IMAGE=1 \
      CODEWIRE_RELEASE_TAG='v0.3.998' CODEWIRE_SOURCE_SHA="$source_sha" "$@" \
      "$BUILDER" base images/base/Dockerfile images/base
  ) >"$work/alias-reuse.out" 2>&1
}
build_calls_before="$(build_invocation_count)"
if alias_reuse; then
  fail 'a reused support index whose provenance names another commit was accepted unnamed'
fi
grep -qF 'Protected image provenance is invalid' "$work/alias-reuse.out" ||
  fail "the unnamed aliased provenance was not refused attributably: $(cat "$work/alias-reuse.out")"
alias_reuse CODEWIRE_PROVENANCE_REVISION="$alias_origin_sha" ||
  fail "a reused support index aliased from its named building commit was refused: $(cat "$work/alias-reuse.out")"
grep -qF "Reusing immutable source image $base_source_tag@" "$work/alias-reuse.out" ||
  fail 'the aliased support index was not reused as it is'
grep -qxF "source_sha=$source_sha" "$GITHUB_OUTPUT" ||
  fail 'the aliased support index was not reported under the release source'
grep -qF "registry.example.invalid/codewire/base:v0.3.998" "$FAKE_MANIFESTS" ||
  fail 'the aliased support index did not get its release tag'
# The named commit is exact: an index built from any other commit is refused.
if alias_reuse CODEWIRE_PROVENANCE_REVISION="$(printf '%040d' 9)"; then
  fail 'a reused support index was accepted against a commit its provenance does not name'
fi
grep -qF 'Protected image provenance is invalid' "$work/alias-reuse.out" ||
  fail 'a wrongly named building commit was not refused attributably'
[[ "$(build_invocation_count)" -eq "$build_calls_before" ]] ||
  fail 'reusing an aliased support index built an image'
# Only an existing support index may name another commit: never a build, a
# runtime image, or a malformed commit.
for refused in 'support-build' 'runtime' 'malformed'; do
  case "$refused" in
    support-build) refused_args=(base images/base/Dockerfile images/base) refused_env=(REQUIRE_EXISTING_SOURCE_IMAGE=0 "CODEWIRE_PROVENANCE_REVISION=$alias_origin_sha") expected='never a build' ;;
    runtime) refused_args=(daemon deployments/docker/daemon.Dockerfile .) refused_env=(REQUIRE_EXISTING_SOURCE_IMAGE=1 "CODEWIRE_PROVENANCE_REVISION=$alias_origin_sha") expected='Only a reused support image' ;;
    malformed) refused_args=(base images/base/Dockerfile images/base) refused_env=(REQUIRE_EXISTING_SOURCE_IMAGE=1 CODEWIRE_PROVENANCE_REVISION=3a3a) expected='must be a full lowercase commit ID' ;;
  esac
  if (
    cd "$source_fixture"
    env "${refused_env[@]}" CODEWIRE_SOURCE_SHA="$source_sha" "$BUILDER" "${refused_args[@]}"
  ) >"$work/alias-refused.out" 2>&1; then
    fail "another commit's provenance was accepted for a $refused"
  fi
  grep -qF "$expected" "$work/alias-refused.out" ||
    fail "the $refused refusal was not attributable: $(cat "$work/alias-refused.out")"
done
[[ "$(build_invocation_count)" -eq "$build_calls_before" ]] ||
  fail 'a refused provenance commit reached a build'

# A historical release recipe compiled its arm64 cw under emulation and cannot
# build arm64. Its recovered pair keeps the single native platform it shipped with.
historical_source="$work/historical-source"
git clone -q "$source_fixture" "$historical_source"
sed -i 's/^FROM cw-cross-compiler AS cw-builder-arm64$/FROM cw-toolchain AS cw-builder-arm64/' \
  "$historical_source/images/workspace/Dockerfile"
grep -qxF 'FROM cw-toolchain AS cw-builder-arm64' "$historical_source/images/workspace/Dockerfile" ||
  fail 'historical recipe fixture still cross-compiles its arm64 cw'
if grep -qF 'cw-cross-compiler AS cw-builder-arm64' "$historical_source/images/workspace/Dockerfile"; then
  fail 'historical recipe fixture still cross-compiles its arm64 cw'
fi
git -C "$historical_source" -c core.hooksPath=/dev/null -c commit.gpgsign=false \
  -c user.name=Synthetic -c user.email=synthetic@example.invalid \
  commit -q -am 'synthetic historical workspace recipe'
historical_sha="$(git -C "$historical_source" rev-parse HEAD)"
for family in base workspace; do
  case "$family" in
    base) family_args=(images/base/Dockerfile images/base) ;;
    workspace) family_args=(images/workspace/Dockerfile .) ;;
  esac
  family_env=()
  [[ "$family" != workspace ]] || family_env=("CODEWIRE_BASE_IMAGE_REF=$base_ref")
  : >"$FAKE_DOCKER_CALLS"
  (
    cd "$historical_source"
    # A distinct digest keeps this image apart from the multi-platform index.
    env "${family_env[@]}" CODEWIRE_SOURCE_DIR="$historical_source" GITHUB_SHA="$historical_sha" \
      FAKE_SOURCE_SHA="$historical_sha" FAKE_DIGEST="$mismatch_digest" \
      "$BUILDER" "$family" "${family_args[@]}"
  ) >"$work/historical-$family.out" 2>&1 || fail "historical $family recipe could not be recovered"
  [[ "$(build_invocation_count)" -eq 1 ]] || fail "historical $family recipe was not built exactly once"
  if grep -qF -- 'linux/arm64' "$FAKE_DOCKER_CALLS"; then
    fail "historical $family recipe was built for arm64"
  fi
  grep -qF -- 'Provenance.SLSA' "$FAKE_DOCKER_CALLS" ||
    fail "historical $family image did not verify its single-platform provenance"
done

# Runtime images are unchanged: one native platform, one attestation view.
: >"$FAKE_DOCKER_CALLS"
remove_source_manifest "registry.example.invalid/codewire/daemon:$source_sha"
(
  cd "$source_fixture"
  "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
) >"$work/runtime-platform.out" 2>&1 || fail 'runtime image did not publish'
if grep -qF -- 'linux/arm64' "$FAKE_DOCKER_CALLS"; then
  fail 'runtime image joined the multi-platform support contract'
fi
grep -qF -- 'Provenance.SLSA' "$FAKE_DOCKER_CALLS" ||
  fail 'runtime image changed its single-platform provenance verification'

printf 'untrusted build input\n' >"$source_fixture/forbidden-untracked-input"
fetch_calls_before="$(wc -l <"$FAKE_FETCH_CALLS")"
if (
  cd "$source_fixture"
  "$BUILDER" daemon deployments/docker/daemon.Dockerfile .
) >"$work/dirty-source.out" 2>&1; then
  fail 'protected image build accepted an untracked source input'
fi
grep -qF 'Protected image build requires no untracked source files' \
  "$work/dirty-source.out" || fail 'dirty source rejection was not attributable'
[[ "$(wc -l <"$FAKE_FETCH_CALLS")" -eq "$fetch_calls_before" ]] ||
  fail 'dirty source rejection reached credential retrieval'

# The service runtime set binds no CW: the daemon builds alone on its own
# protected worker, with the runtime profile; the workspace and both Kind
# daemon builds bind cw with the same runtime profile. The apt snapshot cache
# case adds one workspace build.
[[ "$test_part" != all ]] || assert_cw_contexts 10 9 1

# support-images.yaml builds each platform of the pair in its own job and
# joins them. A per-platform build pushes one platform by digest, untagged,
# and verifies it as the single-platform image it is; only the amd64
# workspace binds the admitted CW producer.
platform_digest_for() {
  case "$1:$2" in
    base:linux/amd64) printf 'sha256:%s\n' "$(printf '1%.0s' {1..64})" ;;
    base:linux/arm64) printf 'sha256:%s\n' "$(printf '2%.0s' {1..64})" ;;
    workspace:linux/amd64) printf 'sha256:%s\n' "$(printf '3%.0s' {1..64})" ;;
    workspace:linux/arm64) printf 'sha256:%s\n' "$(printf '4%.0s' {1..64})" ;;
  esac
}
rm -f -- "$source_fixture/forbidden-untracked-input"
contexts_before="$(wc -l <"$FAKE_CW_CONTEXTS")"
for family in base workspace; do
  case "$family" in
    base) family_args=(images/base/Dockerfile images/base) ;;
    workspace) family_args=(images/workspace/Dockerfile .) ;;
  esac
  for platform in linux/amd64 linux/arm64; do
    family_env=()
    [[ "$family" != workspace ]] ||
      family_env=("CODEWIRE_BASE_IMAGE_REF=registry.example.invalid/codewire/base@$(platform_digest_for base "$platform")")
    platform_digest="$(platform_digest_for "$family" "$platform")"
    : >"$FAKE_DOCKER_CALLS"
    : >"$work/platform-output"
    (
      cd "$source_fixture"
      env "${family_env[@]}" CODEWIRE_IMAGE_PLATFORM="$platform" FAKE_DIGEST="$platform_digest" \
        GITHUB_OUTPUT="$work/platform-output" "$BUILDER" "$family" "${family_args[@]}"
    ) >"$work/platform-$family.out" 2>&1 || { cat "$work/platform-$family.out" >&2; fail "$platform $family image did not build"; }
    [[ "$(build_invocation_count)" -eq 1 ]] || fail "$platform $family image was not built exactly once"
    build_call="$(grep -E ' buildx build ' "$FAKE_DOCKER_CALLS" | grep -v ' CW_PRODUCER=true ')"
    [[ "$build_call" == *"--platform ${platform//\//\\/} "* || "$build_call" == *"--platform $platform "* ]] ||
      fail "$platform $family image was not built for exactly its platform"
    [[ "$build_call" == *"type=image\\,name=registry.example.invalid/codewire/$family\\,push-by-digest=true\\,name-canonical=true\\,push=true"* ]] ||
      fail "$platform $family image was not pushed by digest"
    if [[ "$build_call" == *' --tag '* || "$build_call" == *' --push '* ]]; then
      fail "$platform $family image was tagged"
    fi
    if grep -qF 'buildx imagetools create' "$FAKE_DOCKER_CALLS"; then
      fail "$platform $family image created a tag"
    fi
    grep -qF -- 'Provenance.SLSA' "$FAKE_DOCKER_CALLS" && grep -qF -- 'SBOM.SPDX' "$FAKE_DOCKER_CALLS" ||
      fail "$platform $family image was not verified as a single-platform image"
    [[ "$(cat "$work/platform-output")" == "platform_digest=$platform_digest" ]] ||
      fail "$platform $family image did not report exactly its digest"
    case "$family:$platform" in
      workspace:linux/amd64) expected_producers=1 ;;
      *) expected_producers=0 ;;
    esac
    [[ "$(cw_producer_invocation_count)" -eq "$expected_producers" ]] ||
      fail "$platform $family image bound the CW producer $(cw_producer_invocation_count) times"
  done
done
[[ "$(wc -l <"$FAKE_CW_CONTEXTS")" -eq $((contexts_before + 1)) ]] ||
  fail 'per-platform builds did not bind exactly one CW producer context'

# The join creates the source-SHA index from the two platform images, then
# verifies, tags and reports it exactly as one multi-platform build.
join_digest="sha256:$(printf '5%.0s' {1..64})"
for family in base workspace; do
  case "$family" in
    base) family_args=(images/base/Dockerfile images/base) ;;
    workspace) family_args=(images/workspace/Dockerfile .) ;;
  esac
  remove_source_manifest "registry.example.invalid/codewire/$family:$source_sha"
  : >"$FAKE_DOCKER_CALLS"
  : >"$work/join-output"
  (
    cd "$source_fixture"
    env CODEWIRE_IMAGE_JOIN="$(platform_digest_for "$family" linux/amd64) $(platform_digest_for "$family" linux/arm64)" \
      FAKE_JOIN_DIGEST="$join_digest" GITHUB_OUTPUT="$work/join-output" "$BUILDER" "$family" "${family_args[@]}"
  ) >"$work/join-$family.out" 2>&1 || { cat "$work/join-$family.out" >&2; fail "$family support index was not joined"; }
  [[ "$(build_invocation_count)" -eq 0 && "$(cw_producer_invocation_count)" -eq 0 ]] ||
    fail "$family join rebuilt an image"
  grep -qF "buildx imagetools create --tag registry.example.invalid/codewire/$family:$source_sha registry.example.invalid/codewire/$family@$(platform_digest_for "$family" linux/amd64) registry.example.invalid/codewire/$family@$(platform_digest_for "$family" linux/arm64)" \
    "$FAKE_DOCKER_CALLS" || fail "$family join did not create the source-SHA index from both platform images"
  grep -qF -- "$multi_provenance_call" "$FAKE_DOCKER_CALLS" && grep -qF -- "$multi_sbom_call" "$FAKE_DOCKER_CALLS" ||
    fail "$family join did not verify per-platform provenance and SBOMs"
  grep -qxF "candidate_ref=registry.example.invalid/codewire/$family@$join_digest" "$work/join-output" ||
    fail "$family join did not report the joined index as its candidate"
done
for join_case in missing-arm64 invalid-arm64-sbom; do
  remove_source_manifest "registry.example.invalid/codewire/base:$source_sha"
  case "$join_case" in
    missing-arm64) case_env=('FAKE_JOIN_PLATFORMS=linux/amd64') expected='Protected image provenance is invalid' ;;
    invalid-arm64-sbom) case_env=('FAKE_SBOM_INVALID_PLATFORM=linux/arm64') expected='Protected image SBOM is invalid' ;;
  esac
  if (
    cd "$source_fixture"
    env "${case_env[@]}" CODEWIRE_IMAGE_JOIN="$(platform_digest_for base linux/amd64) $(platform_digest_for base linux/arm64)" \
      FAKE_JOIN_DIGEST="$join_digest" GITHUB_OUTPUT="$work/join-output" "$BUILDER" base images/base/Dockerfile images/base
  ) >"$work/join-$join_case.out" 2>&1; then
    fail "support join accepted $join_case"
  fi
  grep -qF "$expected" "$work/join-$join_case.out" || fail "support join $join_case rejection was not attributable"
done
# refuse MESSAGE ENV... -- ARGS...: the helper refuses before any credential read.
refuse() {
  local message="$1" fetches_before
  shift
  local -a refusal_env=()
  while [ "$1" != -- ]; do refusal_env+=("$1"); shift; done
  shift
  fetches_before="$(wc -l <"$FAKE_FETCH_CALLS")"
  if (cd "$source_fixture" && env "${refusal_env[@]}" "$BUILDER" "$@") >"$work/refusal.out" 2>&1; then
    fail "build helper accepted: ${refusal_env[*]}"
  fi
  grep -qF "$message" "$work/refusal.out" || { cat "$work/refusal.out" >&2; fail "refusal was not attributable: ${refusal_env[*]}"; }
  [[ "$(wc -l <"$FAKE_FETCH_CALLS")" -eq "$fetches_before" ]] || fail "refusal reached credential retrieval: ${refusal_env[*]}"
}
amd64_base="$(platform_digest_for base linux/amd64)"
refuse 'apply only to a multi-platform support image' CODEWIRE_IMAGE_PLATFORM=linux/amd64 -- \
  daemon deployments/docker/daemon.Dockerfile .
refuse 'unsupported platform' CODEWIRE_IMAGE_PLATFORM=linux/riscv64 -- base images/base/Dockerfile images/base
refuse 'two distinct exact platform digests' "CODEWIRE_IMAGE_JOIN=$amd64_base" -- base images/base/Dockerfile images/base
refuse 'two distinct exact platform digests' "CODEWIRE_IMAGE_JOIN=$amd64_base $amd64_base" -- \
  base images/base/Dockerfile images/base
refuse 'either built for one platform or joined' CODEWIRE_IMAGE_PLATFORM=linux/amd64 \
  "CODEWIRE_IMAGE_JOIN=$amd64_base $join_digest" -- base images/base/Dockerfile images/base

assert_cw_contexts_for_part support 4 3 1
fi

echo 'build-push immutable source image tests passed'
