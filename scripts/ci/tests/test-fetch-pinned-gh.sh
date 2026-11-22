#!/usr/bin/env bash
# fetch-pinned-gh.sh reads the amd64 gh_sha from the workspace image's
# Dockerfile whatever else shares its line: a checksum after it once broke
# the parse (#5927). A malformed value, or one only another arm has, is
# refused.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCH="$ROOT/scripts/ci/setup/fetch-pinned-gh.sh"
readonly AMD64=a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112
readonly ARM64=73ea440ecad9c9e284429997ee6f93577bc6f7bc6fba357ef62c53ad8fb641a5
readonly FJ=ea559da5449b6dd7e0dd9f7ea51c906b575696f782edd606b52adcf773602742

fail() {
  printf 'fetch-pinned-gh contract: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

# A Dockerfile with ARMS as its case arms.
dockerfile() {
  # The Dockerfile's own $TARGETARCH, written unexpanded.
  # shellcheck disable=SC2016
  printf 'ARG GH_VERSION=2.97.0\nRUN set -eux; \\\n    case "$TARGETARCH" in \\\n%s\n    esac\n' "$1" >"$work/Dockerfile"
}

expect_pin() {
  local label="$1" got
  got="$("$FETCH" --pin "$work/Dockerfile")" || fail "$label: refused"
  [ "$got" = "2.97.0 $AMD64" ] || fail "$label: read '$got'"
}

expect_refused() {
  local label="$1" output
  if output="$("$FETCH" --pin "$work/Dockerfile" 2>&1)"; then
    fail "$label: accepted '$output'"
  fi
  [[ "$output" == *"no amd64 gh_sha"* ]] || fail "$label: refused with '$output'"
}

# Another checksum after gh_sha on its line's arm, as since fj was pinned.
dockerfile "      amd64) \\
        gh_arch=amd64; fj_arch=x86_64; \\
        gh_sha=$AMD64; \\
        fj_sha=$FJ ;; \\
      arm64) \\
        gh_arch=arm64; fj_arch=aarch64; \\
        gh_sha=$ARM64; \\
        fj_sha=$FJ ;; \\"
expect_pin 'gh_sha followed by another checksum'

# gh_sha last in its arm.
dockerfile "      amd64) \\
        gh_arch=amd64; \\
        gh_sha=$AMD64 ;; \\
      arm64) \\
        gh_arch=arm64; \\
        gh_sha=$ARM64 ;; \\"
expect_pin 'gh_sha last in its arm'

# The arm64 arm first: only the amd64 arm's value is read.
dockerfile "      arm64) \\
        gh_sha=$ARM64 ;; \\
      amd64) \\
        gh_sha=$AMD64 ;; \\"
expect_pin 'arm64 arm first'

for malformed in "${AMD64:1}" "${AMD64}0" "${AMD64^^}" "${AMD64:1}g"; do
  dockerfile "      amd64) \\
        gh_sha=$malformed; \\
        fj_sha=$FJ ;; \\
      arm64) \\
        gh_sha=$ARM64 ;; \\"
  expect_refused "malformed amd64 gh_sha '$malformed'"
done

# An amd64 arm with no gh_sha never borrows the next arm's.
dockerfile "      amd64) \\
        gh_arch=amd64 ;; \\
      arm64) \\
        gh_sha=$ARM64 ;; \\"
expect_refused 'gh_sha only in the arm64 arm'

# The workspace image's own Dockerfile.
got="$("$FETCH" --pin "$ROOT/images/base/Dockerfile")" || fail 'images/base/Dockerfile: refused'
[[ "$got" =~ ^[0-9]+\.[0-9]+\.[0-9]+\ [0-9a-f]{64}$ ]] || fail "images/base/Dockerfile: read '$got'"

printf 'fetch-pinned-gh contract: ok\n'
