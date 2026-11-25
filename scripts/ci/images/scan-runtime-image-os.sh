#!/usr/bin/env bash
# Scan one published runtime image's OS packages, report only (#5402, step 1).
#
#   scan-runtime-image-os.sh NAME REGISTRY/REPOSITORY@sha256:<64 hex>
#
# It runs the job image's own supplychain, the scanner the supply-chain scan
# runs, at the version that scan pins, so no workflow names the scanner's
# repository. A fixable High or Critical finding fails the step; the caller's
# continue-on-error keeps that from delaying or failing delivery. Grype must
# reach its update server and refuses a database older than 5 days. The SBOM
# goes to RUNNER_TEMP/os-scan-NAME.spdx.json. Registry access is the caller's
# DOCKER_CONFIG (image-scan-login.sh).
set -euo pipefail

readonly EXPECTED_SUPPLYCHAIN=47a53e3035dbbd040f3249bd2ac858617a7c8fd7

fail() {
  printf '[scan-runtime-image-os] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 2 ]] || {
  echo 'usage: scan-runtime-image-os.sh NAME REGISTRY/REPOSITORY@sha256:<64 hex>' >&2
  exit 2
}
name="$1" image="$2"
[[ "$name" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || fail "the image name is not a short lowercase name"
[[ "$image" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]] ||
  fail "the image is not one exact registry digest reference"
[[ "$(supplychain version)" == "supplychain $EXPECTED_SUPPLYCHAIN" ]] ||
  fail "the job image's supplychain is not $EXPECTED_SUPPLYCHAIN"

export GRYPE_DB_REQUIRE_UPDATE_CHECK=true GRYPE_DB_AUTO_UPDATE=true GRYPE_DB_MAX_ALLOWED_BUILT_AGE=120h
supplychain image -only-fixed -fail-on high -sbom "${RUNNER_TEMP:?}/os-scan-$name.spdx.json" "$image"
