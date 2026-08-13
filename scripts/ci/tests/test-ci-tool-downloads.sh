#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly VERIFIER="$ROOT/scripts/ci/verify/run-product-verification.sh"

fail() {
  printf 'CI tool download contract: %s\n' "$*" >&2
  exit 1
}

bash -n "$VERIFIER"

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

printf 'CI tool download contract: OK\n'
