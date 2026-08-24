#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly PUBLISH_IMAGE="$ROOT/scripts/ci/images/publish-image-to-ghcr.sh"

fail() {
  printf '[test-publish-image-to-ghcr] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/publish-image-to-ghcr.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

expected_digest="sha256:$(printf 'a%.0s' {1..64})"
other_digest="sha256:$(printf 'b%.0s' {1..64})"
base_digest="sha256:$(printf 'd%.0s' {1..64})"
workspace_digest="sha256:$(printf 'e%.0s' {1..64})"
source_sha="$(printf 'c%.0s' {1..40})"
source_ref="nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway@$expected_digest"
target_repository='ghcr.io/codewiresh/gateway'
base_source_ref="nexus-system-cluster.example.invalid/oci-promoted/codewire/base@$base_digest"
workspace_source_ref="nexus-system-cluster.example.invalid/oci-promoted/codewire/workspace@$workspace_digest"
base_repository='ghcr.io/codewiresh/base'
workspace_repository='ghcr.io/codewiresh/workspace'
nexus_username='nexus-publisher-test'
nexus_password='nexus-wrapper-test-password'
ghcr_token='ghcr-wrapper-test-token'

cat >"$work/bin/fetch-nexus" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${FAKE_NEXUS_FETCH_FAIL:-0}" != 1 ] || exit 1
printf '%s' "${FAKE_NEXUS_USERNAME:?}" >"$1"
printf '%s' "${FAKE_NEXUS_PASSWORD:?}" >"$2"
chmod 0600 "$1" "$2"
printf '%s\t%s\n' "$1" "$2" >>"${FAKE_NEXUS_FETCH_CALLS:?}"
EOF

cat >"$work/bin/fetch-ghcr" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${FAKE_GHCR_FETCH_FAIL:-0}" != 1 ] || exit 1
printf '%s' "${FAKE_GHCR_USERNAME:?}" >"$1"
printf '%s' "${FAKE_GHCR_TOKEN:?}" >"$2"
chmod 0600 "$1" "$2"
printf '%s\t%s\n' "$1" "$2" >>"${FAKE_GHCR_FETCH_CALLS:?}"
EOF

cat >"$work/bin/copy-image" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${FAKE_COPY_FAIL:-0}" != 1 ] || exit 1
[[ "${GHCR_PUBLISH_USERNAME:?}" == codewire-package-publisher ]]
[[ "$(<"${NEXUS_REGISTRY_USERNAME_FILE:?}")" == "${FAKE_NEXUS_USERNAME:?}" ]]
[[ "$(<"${NEXUS_REGISTRY_PASSWORD_FILE:?}")" == "${FAKE_NEXUS_PASSWORD:?}" ]]
[[ "$(<"${GHCR_PUBLISH_TOKEN_FILE:?}")" == "${FAKE_GHCR_TOKEN:?}" ]]
[[ "$(stat -c '%a' "$NEXUS_REGISTRY_USERNAME_FILE")" == 600 ]]
[[ "$(stat -c '%a' "$NEXUS_REGISTRY_PASSWORD_FILE")" == 600 ]]
[[ "$(stat -c '%a' "$GHCR_PUBLISH_TOKEN_FILE")" == 600 ]]
printf '%s\n' "$*" >>"${FAKE_COPY_CALLS:?}"
call=1
if [ -n "${FAKE_COPY_COUNTER:-}" ]; then
  if [ -s "$FAKE_COPY_COUNTER" ]; then
    call="$(( $(<"$FAKE_COPY_COUNTER") + 1 ))"
  fi
  printf '%s\n' "$call" >"$FAKE_COPY_COUNTER"
fi
[ "${FAKE_COPY_FAIL_AT:-}" != "$call" ] || exit 1
EOF

cat >"$work/bin/skopeo-runner" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${SKOPEO_AUTH_VOLUME:-}" ]]
printf '%s\n' "$*" >>"${FAKE_SKOPEO_CALLS:?}"
[ "${FAKE_ANON_FAIL:-0}" != 1 ] || exit 1
case "$1" in
  --check)
    [[ "$#" -eq 1 ]]
    if [ "${FAKE_RUNTIME_UNAVAILABLE:-0}" = 1 ]; then
      echo '[skopeo-runtime] class=runtime-unavailable detail=approved-image-missing' >&2
      exit 1
    fi
    echo 'SKOPEO_RUNTIME_READY'
    ;;
  list-tags)
    [[ "$#" -eq 3 && "$2" == --no-creds && "$3" == docker://* ]]
    repository="${3#docker://}"
    [ "${FAKE_PREFLIGHT_FAIL_REPOSITORY:-}" != "$repository" ] || exit 1
    printf '{"Repository":"%s","Tags":["existing"]}\n' "$repository"
    ;;
  inspect)
    [[ "$*" == *'inspect --no-creds --format {{.Digest}} docker://'* ]]
    public_ref="${!#}"
    public_ref="${public_ref#docker://}"
    [ "${FAKE_ANON_FAIL_REF:-}" != "$public_ref" ] || exit 1
    case "$public_ref" in
      ghcr.io/codewiresh/base@*|ghcr.io/codewiresh/base:latest)
        printf '%s\n' "${FAKE_BASE_DIGEST:?}"
        ;;
      ghcr.io/codewiresh/workspace@*|ghcr.io/codewiresh/workspace:latest)
        printf '%s\n' "${FAKE_WORKSPACE_DIGEST:?}"
        ;;
      *) printf '%s\n' "${FAKE_ANON_DIGEST:?}" ;;
    esac
    ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$work/bin/fetch-nexus" "$work/bin/fetch-ghcr" "$work/bin/copy-image" "$work/bin/skopeo-runner"

export OPENBAO_NEXUS_CREDENTIAL_FETCHER="$work/bin/fetch-nexus"
export OPENBAO_GHCR_CREDENTIAL_FETCHER="$work/bin/fetch-ghcr"
export GHCR_COPY_HELPER="$work/bin/copy-image"
export SKOPEO_RUNNER="$work/bin/skopeo-runner"
export FAKE_NEXUS_USERNAME="$nexus_username"
export FAKE_NEXUS_PASSWORD="$nexus_password"
export FAKE_GHCR_USERNAME='codewire-package-publisher'
export FAKE_GHCR_TOKEN="$ghcr_token"
export FAKE_NEXUS_FETCH_CALLS="$work/nexus-fetch-calls"
export FAKE_GHCR_FETCH_CALLS="$work/ghcr-fetch-calls"
export FAKE_COPY_CALLS="$work/copy-calls"
export FAKE_COPY_COUNTER="$work/copy-counter"
export FAKE_SKOPEO_CALLS="$work/skopeo-calls"
export FAKE_ANON_DIGEST="$expected_digest"
export FAKE_BASE_DIGEST="$base_digest"
export FAKE_WORKSPACE_DIGEST="$workspace_digest"
export GITHUB_OUTPUT="$work/output"

"$PUBLISH_IMAGE" "$source_ref" "$target_repository" "$source_sha"

grep -qxF -- '--check' "$FAKE_SKOPEO_CALLS" ||
  fail 'pinned Skopeo runtime was not checked before publication'
[[ "$(wc -l <"$FAKE_NEXUS_FETCH_CALLS")" -eq 1 ]] ||
  fail 'paired Nexus credential was not fetched exactly once'
[[ "$(wc -l <"$FAKE_GHCR_FETCH_CALLS")" -eq 1 ]] ||
  fail 'paired GHCR credential was not fetched exactly once'
grep -qxF "$source_ref $target_repository $source_sha" "$FAKE_COPY_CALLS" ||
  fail 'exact copy arguments changed'
grep -qxF "inspect --no-creds --format {{.Digest}} docker://$target_repository@$expected_digest" \
  "$FAKE_SKOPEO_CALLS" || fail 'anonymous digest verification is absent'
grep -qxF "ghcr_public_ref=$target_repository@$expected_digest" "$GITHUB_OUTPUT" ||
  fail 'public digest output is absent'

probe_source_ref="nexus-system-cluster.example.invalid/oci-promoted/codewire/confidential-probe@$expected_digest"
probe_repository='ghcr.io/codewiresh/confidential-probe'
"$PUBLISH_IMAGE" "$probe_source_ref" "$probe_repository" "$source_sha"
grep -qxF "$probe_source_ref $probe_repository $source_sha" "$FAKE_COPY_CALLS" ||
  fail 'confidential-probe publication family is absent'
grep -qxF "ghcr_public_ref=$probe_repository@$expected_digest" "$GITHUB_OUTPUT" ||
  fail 'confidential-probe public digest output is absent'
while IFS=$'\t' read -r username_file token_file; do
  [ ! -e "$username_file" ] || fail 'private GHCR username file survived publication'
  [ ! -e "$token_file" ] || fail 'private credential file survived publication'
done <"$FAKE_GHCR_FETCH_CALLS"
while IFS=$'\t' read -r username_file password_file; do
  [ ! -e "$username_file" ] || fail 'private Nexus username file survived publication'
  [ ! -e "$password_file" ] || fail 'private Nexus password file survived publication'
done <"$FAKE_NEXUS_FETCH_CALLS"
if grep -qF "$nexus_username" "$FAKE_GHCR_FETCH_CALLS" "$FAKE_COPY_CALLS" \
  || grep -qF "$nexus_password" "$FAKE_GHCR_FETCH_CALLS" "$FAKE_COPY_CALLS" \
  || grep -qF "$ghcr_token" "$FAKE_GHCR_FETCH_CALLS" "$FAKE_COPY_CALLS"; then
  fail 'a registry token reached command arguments'
fi

runtime_bundle="$work/runtime-bundle.json"
python3 "$ROOT/scripts/ci/images/image-bundle.py" create \
  --source-sha "$source_sha" \
  --output "$runtime_bundle" \
  --candidate dashboard "$source_sha" "nexus-system-cluster.example.invalid/oci-promoted/codewire/dashboard@$expected_digest" \
  --candidate derp "$source_sha" "nexus-system-cluster.example.invalid/oci-promoted/codewire/derp@$expected_digest" \
  --candidate gateway "$source_sha" "nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway@$expected_digest" \
  --candidate services "$source_sha" "nexus-system-cluster.example.invalid/oci-promoted/codewire/services@$expected_digest" \
  --candidate mesh "$source_sha" "nexus-system-cluster.example.invalid/oci-promoted/codewire/mesh@$expected_digest"
: >"$FAKE_NEXUS_FETCH_CALLS"
: >"$FAKE_GHCR_FETCH_CALLS"
: >"$FAKE_COPY_CALLS"
: >"$FAKE_COPY_COUNTER"
: >"$FAKE_SKOPEO_CALLS"
: >"$GITHUB_OUTPUT"
"$PUBLISH_IMAGE" --runtime-bundle "$runtime_bundle"
[[ "$(wc -l <"$FAKE_NEXUS_FETCH_CALLS")" -eq 1 ]] ||
  fail 'runtime bundle fetched the paired Nexus credential more than once'
[[ "$(wc -l <"$FAKE_GHCR_FETCH_CALLS")" -eq 1 ]] ||
  fail 'runtime bundle fetched the paired GHCR credential more than once'
mapfile -t runtime_copy_calls <"$FAKE_COPY_CALLS"
[[ "${#runtime_copy_calls[@]}" -eq 5 ]] ||
  fail 'runtime bundle did not perform exactly five immutable copy operations'
for index in "${!runtime_copy_calls[@]}"; do
  family=(dashboard derp gateway services mesh)
  expected_source="nexus-system-cluster.example.invalid/oci-promoted/codewire/${family[$index]}@$expected_digest"
  expected_target="ghcr.io/codewiresh/${family[$index]}"
  [[ "${runtime_copy_calls[$index]}" == "$expected_source $expected_target $source_sha" ]] ||
    fail "runtime bundle copy order or source identity changed at ${family[$index]}"
  grep -qxF "${family[$index]}_ghcr_public_ref=$expected_target@$expected_digest" \
    "$GITHUB_OUTPUT" || fail "runtime bundle omitted ${family[$index]} output"
done

: >"$FAKE_NEXUS_FETCH_CALLS"
: >"$FAKE_GHCR_FETCH_CALLS"
: >"$FAKE_COPY_CALLS"
: >"$FAKE_COPY_COUNTER"
: >"$FAKE_SKOPEO_CALLS"
if FAKE_COPY_FAIL_AT=5 "$PUBLISH_IMAGE" --runtime-bundle "$runtime_bundle" \
    >"$work/runtime-copy-failure.out" 2>&1; then
  fail 'partial runtime bundle copy was accepted'
fi
[[ "$(wc -l <"$FAKE_COPY_CALLS")" -eq 5 ]] ||
  fail 'runtime bundle did not stop at the selected fifth-copy failure'
while IFS=$'\t' read -r username_file token_file; do
  [[ ! -e "$username_file" && ! -e "$token_file" ]] ||
    fail 'runtime bundle failure retained a private GHCR credential file'
done <"$FAKE_GHCR_FETCH_CALLS"
while IFS=$'\t' read -r username_file password_file; do
  [[ ! -e "$username_file" && ! -e "$password_file" ]] ||
    fail 'runtime bundle failure retained a private Nexus credential file'
done <"$FAKE_NEXUS_FETCH_CALLS"

bad_runtime_bundle="$work/bad-runtime-bundle.json"
cp "$runtime_bundle" "$bad_runtime_bundle"
jq '.images |= .[0:4]' "$runtime_bundle" >"$bad_runtime_bundle"
runtime_fetches_before="$(wc -l <"$FAKE_GHCR_FETCH_CALLS")"
if "$PUBLISH_IMAGE" --runtime-bundle "$bad_runtime_bundle" \
    >"$work/bad-runtime-bundle.out" 2>&1; then
  fail 'incomplete runtime bundle was accepted'
fi
[[ "$(wc -l <"$FAKE_GHCR_FETCH_CALLS")" -eq "$runtime_fetches_before" ]] ||
  fail 'invalid runtime bundle reached credential retrieval'

if FAKE_ANON_DIGEST="$other_digest" "$PUBLISH_IMAGE" "$source_ref" \
    "$target_repository" "$source_sha" >"$work/mismatch.out" 2>&1; then
  fail 'anonymous digest mismatch was accepted'
fi

skopeo_calls_before="$(wc -l <"$FAKE_SKOPEO_CALLS")"
if FAKE_COPY_FAIL=1 "$PUBLISH_IMAGE" "$source_ref" "$target_repository" \
    "$source_sha" >"$work/copy-failure.out" 2>&1; then
  fail 'copy failure was accepted'
fi
[[ "$(wc -l <"$FAKE_SKOPEO_CALLS")" -eq $((skopeo_calls_before + 1)) ]] ||
  fail 'copy failure did more than the required runtime preflight'

copy_calls_before="$(wc -l <"$FAKE_COPY_CALLS")"
if FAKE_GHCR_FETCH_FAIL=1 "$PUBLISH_IMAGE" "$source_ref" \
    "$target_repository" "$source_sha" >"$work/fetch-failure.out" 2>&1; then
  fail 'credential fetch failure was accepted'
fi
[[ "$(wc -l <"$FAKE_COPY_CALLS")" -eq "$copy_calls_before" ]] ||
  fail 'credential fetch failure reached the copy helper'

fetch_calls_before="$(wc -l <"$FAKE_GHCR_FETCH_CALLS")"
if "$PUBLISH_IMAGE" 'nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway:latest' \
    "$target_repository" "$source_sha" >"$work/moving-source.out" 2>&1; then
  fail 'moving source reference was accepted'
fi
[[ "$(wc -l <"$FAKE_GHCR_FETCH_CALLS")" -eq "$fetch_calls_before" ]] ||
  fail 'invalid source reference reached credential retrieval'

if "$PUBLISH_IMAGE" "$source_ref" 'ghcr.io/codewiresh/services' \
    "$source_sha" >"$work/family-mismatch.out" 2>&1; then
  fail 'source and destination family mismatch was accepted'
fi
[[ "$(wc -l <"$FAKE_GHCR_FETCH_CALLS")" -eq "$fetch_calls_before" ]] ||
  fail 'family mismatch reached credential retrieval'

: >"$FAKE_GHCR_FETCH_CALLS"
: >"$FAKE_COPY_CALLS"
: >"$FAKE_COPY_COUNTER"
: >"$FAKE_SKOPEO_CALLS"
: >"$GITHUB_OUTPUT"
"$PUBLISH_IMAGE" --support-pair "$base_source_ref" "$workspace_source_ref" \
  "$source_sha"

mapfile -t pair_copy_calls <"$FAKE_COPY_CALLS"
[[ "${#pair_copy_calls[@]}" -eq 4 ]] ||
  fail 'support pair does not perform exactly four ordered copy operations'
[[ "${pair_copy_calls[0]}" == "$base_source_ref $base_repository $source_sha" ]] ||
  fail 'support base immutable tag is not staged first'
[[ "${pair_copy_calls[1]}" == "$workspace_source_ref $workspace_repository $source_sha" ]] ||
  fail 'support workspace immutable tag is not staged second'
[[ "${pair_copy_calls[2]}" == "$base_source_ref $base_repository latest" ]] ||
  fail 'support base latest alias moved before both immutable tags verified'
[[ "${pair_copy_calls[3]}" == "$workspace_source_ref $workspace_repository latest" ]] ||
  fail 'support workspace latest alias ordering changed'
mapfile -t pair_skopeo_calls <"$FAKE_SKOPEO_CALLS"
[[ "${pair_skopeo_calls[0]}" == '--check' ]] ||
  fail 'support publisher omitted the Skopeo runtime preflight'
[[ "${pair_skopeo_calls[1]}" == "list-tags --no-creds docker://$base_repository" ]] ||
  fail 'support base public preflight is not first'
[[ "${pair_skopeo_calls[2]}" == "list-tags --no-creds docker://$workspace_repository" ]] ||
  fail 'support workspace public preflight is not before credential retrieval'
grep -qxF "base_ghcr_public_ref=$base_repository@$base_digest" "$GITHUB_OUTPUT" ||
  fail 'support base immutable receipt is absent'
grep -qxF "workspace_ghcr_public_ref=$workspace_repository@$workspace_digest" \
  "$GITHUB_OUTPUT" || fail 'support workspace immutable receipt is absent'

for unavailable_repository in "$base_repository" "$workspace_repository"; do
  : >"$FAKE_GHCR_FETCH_CALLS"
  : >"$FAKE_COPY_CALLS"
  : >"$FAKE_COPY_COUNTER"
  : >"$FAKE_SKOPEO_CALLS"
  if FAKE_PREFLIGHT_FAIL_REPOSITORY="$unavailable_repository" \
      "$PUBLISH_IMAGE" --support-pair "$base_source_ref" \
        "$workspace_source_ref" "$source_sha" \
        >"$work/preflight-failure.out" 2>&1; then
    fail "unreadable support package was accepted: $unavailable_repository"
  fi
  [[ ! -s "$FAKE_GHCR_FETCH_CALLS" ]] ||
    fail "unreadable support package reached credential retrieval: $unavailable_repository"
  [[ ! -s "$FAKE_COPY_CALLS" ]] ||
    fail "unreadable support package caused GHCR mutation: $unavailable_repository"
done

: >"$FAKE_GHCR_FETCH_CALLS"
: >"$FAKE_COPY_CALLS"
: >"$FAKE_COPY_COUNTER"
: >"$FAKE_SKOPEO_CALLS"
if FAKE_ANON_FAIL_REF="$workspace_repository@$workspace_digest" \
    "$PUBLISH_IMAGE" --support-pair "$base_source_ref" \
      "$workspace_source_ref" "$source_sha" \
      >"$work/workspace-verify-failure.out" 2>&1; then
  fail 'unverified workspace immutable tag was accepted'
fi
mapfile -t failed_pair_copy_calls <"$FAKE_COPY_CALLS"
[[ "${#failed_pair_copy_calls[@]}" -eq 2 ]] ||
  fail 'compatibility aliases were attempted before both immutable tags verified'
if grep -qE ' latest$' "$FAKE_COPY_CALLS"; then
  fail 'an unverified immutable pair reached compatibility alias mutation'
fi

: >"$FAKE_NEXUS_FETCH_CALLS"
: >"$FAKE_GHCR_FETCH_CALLS"
: >"$FAKE_COPY_CALLS"
: >"$FAKE_SKOPEO_CALLS"
if FAKE_RUNTIME_UNAVAILABLE=1 "$PUBLISH_IMAGE" "$source_ref" \
    "$target_repository" "$source_sha" >"$work/runtime-unavailable.out" 2>&1; then
  fail 'missing approved Skopeo runtime was accepted'
fi
grep -Fq 'Pinned Skopeo runtime is unavailable' "$work/runtime-unavailable.out" ||
  fail 'missing Skopeo runtime was not classified before registry activity'
[[ ! -s "$FAKE_NEXUS_FETCH_CALLS" && ! -s "$FAKE_GHCR_FETCH_CALLS" ]] ||
  fail 'missing Skopeo runtime reached credential retrieval'
[[ ! -s "$FAKE_COPY_CALLS" ]] ||
  fail 'missing Skopeo runtime reached image mutation'

echo 'publish-image-to-ghcr tests passed'
