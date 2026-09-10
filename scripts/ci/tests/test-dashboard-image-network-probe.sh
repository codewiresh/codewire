#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly VERIFIER="$ROOT/scripts/ci/verify/dashboard-image.sh"

fail() {
  printf 'dashboard image network probe contract: %s\n' "$*" >&2
  exit 1
}

bash -n "$VERIFIER"

grep -Fq -- '--env CODEWIRE_CREDENTIAL_ORIGIN=http://127.0.0.1:8086' "$VERIFIER" ||
  fail 'standalone image smoke omits its isolated required credential origin'

grep -Fq 'docker container inspect "$self_container"' "$VERIFIER" ||
  fail 'verifier cannot detect that its Docker client is attached to DinD'
grep -Fq -- '--network "container:$smoke_container"' "$VERIFIER" ||
  fail 'DinD probe does not share only the dashboard network namespace'
grep -Fq 'docker image inspect "$probe_image"' "$VERIFIER" ||
  fail 'DinD probe can use an image that is not already present'
grep -Fq -- '--read-only --cap-drop ALL --security-opt no-new-privileges:true' "$VERIFIER" ||
  fail 'DinD probe omits the disposable container security boundary'
grep -Fq '"$probe_image" "$@"' "$VERIFIER" ||
  fail 'DinD probe does not reuse the exact current job image'

if grep -Eq '(curlimages/curl|docker\.io/.+curl|ghcr\.io/.+curl)' "$VERIFIER"; then
  fail 'verifier introduces a mutable or separately pulled curl image'
fi
if grep -Eq -- '--network[= ]+(host|bridge)' "$VERIFIER"; then
  fail 'verifier widens the DinD probe to a shared network mode'
fi

printf 'dashboard image network probe contract: OK\n'
