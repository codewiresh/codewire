#!/usr/bin/env bash
# The cargo-nextest pin (infra#1632) is one version, one URL and one SHA-256,
# in install-cargo-nextest.sh and rust-base.Dockerfile alike, and the measure
# workflow installs it through the script.
# shellcheck disable=SC2016 # The checks match literal shell and workflow text.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly SCRIPT="$ROOT/scripts/ci/setup/install-cargo-nextest.sh"
readonly DOCKERFILE="$ROOT/deployments/docker/rust-base.Dockerfile"
readonly WORKFLOW="$ROOT/.gitea/workflows/test-archive-measure.yaml"

fail() {
  echo "test-install-cargo-nextest: $*" >&2
  exit 1
}

value() {
  sed -nE "s/^readonly $1='([^']*)'$/\\1/p" "$SCRIPT"
}
version="$(value NEXTEST_VERSION)"
digest="$(value NEXTEST_SHA256)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "the script pins no exact version: ${version:-none}"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail 'the script pins no SHA-256'
url="https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-${version}/cargo-nextest-${version}-x86_64-unknown-linux-musl.tar.gz"
grep -Fq 'readonly NEXTEST_URL="https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-${NEXTEST_VERSION}/cargo-nextest-${NEXTEST_VERSION}-x86_64-unknown-linux-musl.tar.gz"' "$SCRIPT" ||
  fail 'the script fetches another URL'
grep -Fq '"$ROOT/scripts/ci/release/fetch-pinned.sh" "$NEXTEST_URL" "$NEXTEST_SHA256"' "$SCRIPT" ||
  fail 'the script does not fetch through fetch-pinned.sh with its digest'

# A kept tarball is used only when it matches the pin; a stale one is fetched
# again. A stub fetch-pinned.sh stands in for the network.
cache_case="$(mktemp -d "${TMPDIR:-/tmp}/test-install-cargo-nextest.XXXXXX")"
trap 'rm -rf -- "$cache_case"' EXIT
mkdir -p "$cache_case/root/scripts/ci/setup" "$cache_case/root/scripts/ci/release" "$cache_case/pkg"
cp "$SCRIPT" "$cache_case/root/scripts/ci/setup/install-cargo-nextest.sh"
printf '#!/bin/sh\necho "cargo-nextest %s (fake)"\n' "$version" > "$cache_case/pkg/cargo-nextest"
chmod +x "$cache_case/pkg/cargo-nextest"
tar -czf "$cache_case/good.tar.gz" -C "$cache_case/pkg" cargo-nextest
good="$(sha256sum "$cache_case/good.tar.gz" | cut -d' ' -f1)"
sed -i "s/^readonly NEXTEST_SHA256='[0-9a-f]*'$/readonly NEXTEST_SHA256='$good'/" \
  "$cache_case/root/scripts/ci/setup/install-cargo-nextest.sh"
cat > "$cache_case/root/scripts/ci/release/fetch-pinned.sh" <<FETCH
#!/bin/sh
echo fetched >> "$cache_case/fetches"
cp "$cache_case/good.tar.gz" "\$3"
FETCH
chmod +x "$cache_case/root/scripts/ci/release/fetch-pinned.sh"
cache_install() {
  CODEWIRE_TOOL_CACHE="$cache_case/tools" RUNNER_TEMP="$cache_case" \
    "$cache_case/root/scripts/ci/setup/install-cargo-nextest.sh" "$cache_case/bin" > "$cache_case/out" 2>&1 ||
    fail "the cached install failed: $(cat "$cache_case/out")"
}
cache_install
cache_install
[ "$(wc -l < "$cache_case/fetches")" -eq 1 ] || fail 'a kept tarball was fetched again'
grep -q 'kept .* tarball matches its SHA-256' "$cache_case/out" || fail 'the kept tarball was not used'
printf 'tampered' > "$cache_case/tools/$good.tar.gz"
cache_install
[ "$(wc -l < "$cache_case/fetches")" -eq 2 ] || fail 'a tampered kept tarball was used'
[ "$(sha256sum "$cache_case/tools/$good.tar.gz" | cut -d' ' -f1)" = "$good" ] || fail 'the tampered tarball was kept'

# rust-base carries exactly the same pin and checks the installed version.
grep -Fxq "ADD --checksum=sha256:$digest \\" "$DOCKERFILE" || fail 'rust-base pins another digest'
grep -Fxq "  $url \\" "$DOCKERFILE" || fail 'rust-base fetches another URL'
grep -Fq "grep -q '^cargo-nextest ${version//./\\.} '" "$DOCKERFILE" || fail 'rust-base does not check the installed version'

grep -Fxq '        run: scripts/ci/setup/install-cargo-nextest.sh "$RUNNER_TEMP/nextest"' "$WORKFLOW" ||
  fail 'the measure workflow does not install the pin'
grep -Fq '      CARGO_TARGET_DIR: ${{ github.workspace }}/target/test-archive' "$WORKFLOW" ||
  fail 'the measure workflow shares a CI target directory'
if grep -Eq 'enable-openid-connect|secrets\.|vars\.CODEWIRE_CI_RUNNER_(TRUSTED|MACOS)' "$WORKFLOW"; then
  fail 'the measure workflow reaches a credential or a trusted runner'
fi

# The script refuses usage errors before fetching anything.
if "$SCRIPT" >/dev/null 2>&1; then
  fail 'the script ran without a directory'
fi
echo "test-install-cargo-nextest: cargo-nextest $version pinned once, in the script and rust-base"
