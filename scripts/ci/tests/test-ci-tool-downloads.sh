#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly VERIFIER="$ROOT/scripts/ci/verify/run-product-verification.sh"
readonly WORKFLOW="$ROOT/.gitea/workflows/ci.yaml"
readonly CHROMIUM_INSTALLER="$ROOT/scripts/ci/install-pinned-playwright-chromium.sh"
readonly RUST_BASE_DOCKERFILE="$ROOT/deployments/docker/rust-base.Dockerfile"
readonly PROTOC_URL='https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip'
readonly PROTOC_CHECKSUM='sha256:6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7'

fail() {
  printf 'CI tool download contract: %s\n' "$*" >&2
  exit 1
}

bash -n "$VERIFIER" "$CHROMIUM_INSTALLER"

grep -Fq 'download_ci_tool() {' "$VERIFIER" ||
  fail 'shared pinned-tool downloader is absent'
grep -Fq -- '--retry 5 --retry-all-errors --retry-delay 2 --connect-timeout 20' \
  "$VERIFIER" || fail 'bounded transport retry is absent'
grep -Fq 'download_ci_tool \' "$VERIFIER" ||
  fail 'pinned Kustomize installer bypasses the shared downloader'

checksum='grep "kustomize_${version}_linux_amd64.tar.gz" checksums.txt | sha256sum -c -'
grep -Fq "$checksum" "$VERIFIER" ||
  fail "checksum verification is absent: $checksum"

grep -Fq "installed_version=\"\$(helm version --template '{{.Version}}')\"" "$VERIFIER" ||
  fail 'sealed Helm version assertion is absent'
if grep -Fq 'https://get.helm.sh/' "$VERIFIER"; then
  fail 'Helm must come from the immutable runner image, not job-time network'
fi

if grep -Fq 'playwright install-deps' "$WORKFLOW"; then
  fail 'browser native dependencies must come from the immutable runner image'
fi
grep -Fq 'ldd "$chromium"' "$CHROMIUM_INSTALLER" ||
  fail 'pinned Chromium does not fail closed on missing runner-image libraries'

for dockerfile in \
  deployments/docker/services.Dockerfile \
  deployments/docker/mesh.Dockerfile \
  deployments/docker/daemon.Dockerfile \
  deployments/docker/derp.Dockerfile; do
  if grep -Eq '\b(apt-get|apt)\b' "$ROOT/$dockerfile"; then
    fail "$dockerfile must not install operating-system packages at build time"
  fi
  grep -Fq 'FROM codewire-rust-base AS ' "$ROOT/$dockerfile" ||
    fail "$dockerfile does not consume the shared reviewed build-tool image"
done

grep -Fq "ADD --checksum=$PROTOC_CHECKSUM" "$RUST_BASE_DOCKERFILE" ||
  fail 'shared Rust build base does not checksum-pin protoc'
grep -Fq "$PROTOC_URL" "$RUST_BASE_DOCKERFILE" ||
  fail 'shared Rust build base does not use the reviewed protoc origin'

# Every host job compiling the shared bridge needs debug_redact support, not
# only the release and guest-probe jobs. Image builds already pin this compiler.
for job in database services-control services-runtime kind-smokes; do
  block="$(awk -v job="$job" '
    $0 == "  " job ":" { selected=1; next }
    selected && /^  [a-z][a-z-]*:$/ { exit }
    selected { print }
  ' "$WORKFLOW")"
  grep -Fq 'name: Install pinned protoc for Rust compilation' <<<"$block" ||
    fail "$job does not prepare the shared bridge compiler"
  grep -Fq "$PROTOC_URL" <<<"$block" || fail "$job uses a different protoc source"
  grep -Fq "${PROTOC_CHECKSUM#sha256:}  /tmp/protoc.zip" <<<"$block" ||
    fail "$job does not verify the protoc archive"
  grep -Fq '"$HOME/.proto-tools/protoc/bin" >> "$GITHUB_PATH"' <<<"$block" ||
    fail "$job does not select the pinned protoc for host Cargo builds"
done
edge_kind_block="$(awk '
  $0 == "  edge-kind:" { selected=1; next }
  selected && /^  [a-z][a-z-]*:$/ { exit }
  selected { print }
' "$WORKFLOW")"
if grep -Fq 'name: Install pinned protoc for Rust compilation' <<<"$edge_kind_block"; then
  fail 'Kind consumer still installs the compiler used only by the smoke producer'
fi
grep -Fq 'ADD --checksum=sha256:67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006' \
  "$RUST_BASE_DOCKERFILE" || fail 'shared Rust build base does not checksum-pin sccache'

printf 'CI tool download contract: OK\n'
