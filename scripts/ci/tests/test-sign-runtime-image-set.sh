#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly SIGNER="$ROOT/scripts/ci/images/sign-runtime-image-set.sh"
readonly COSIGN_IMAGE='registry.example.invalid/oci-approved/sigstore/cosign/cosign@sha256:6ca1127dc1e9ff19f3f2bfa214936813a86fbbf52919652eda49d393c888ad3c'

fail() {
  printf '[test-sign-runtime-image-set] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/sign-runtime-image-set.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/tmp"
docker_log="$work/docker.log"
cosign_log="$work/cosign.log"
curl_log="$work/curl.log"
signature_state="$work/signatures"
: >"$docker_log"
: >"$cosign_log"
: >"$curl_log"
: >"$signature_state"

cat >"$work/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
output=''
args=("$@")
for ((index = 0; index < ${#args[@]}; index += 1)); do
  if [[ "${args[$index]}" == --output ]]; then
    output="${args[$((index + 1))]}"
  fi
done
[[ -n "$output" ]]
url="${args[$((${#args[@]} - 1))]}"
printf '%s\n' "$url" >>"${CURL_LOG:?}"
case "$url" in
  *'/id_token?'*) printf '%s\n' '{"value":"synthetic-forgejo-jwt"}' >"$output" ;;
  */v1/auth/forgejo-jwt/login)
    printf '%s\n' '{"auth":{"client_token":"synthetic-openbao-token"}}' >"$output"
    ;;
  */v1/platform/data/ci/codewire/ghcr-publisher)
    printf '%s\n' '{"data":{"data":{"username":"ghcr-user","token":"synthetic-ghcr-token"}}}' >"$output"
    ;;
  */v1/platform/data/ci/codewire/harbor-publisher)
    printf '%s\n' '{"data":{"data":{"username":"robot$codewire+publisher","password":"synthetic-harbor-password"}}}' >"$output"
    ;;
  *) printf 'unexpected curl URL: %s\n' "$url" >&2; exit 1 ;;
esac
SH
chmod 0755 "$work/bin/curl"

cat >"$work/fake-cosign" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${COSIGN_LOG:?}"
printf '\n' >>"$COSIGN_LOG"
command="${1:-}"
reference="${!#:-}"
case "$command" in
  version)
    printf '%s\n' 'cosign synthetic'
    ;;
  sign)
    [[ "${BAO_ADDR:-}" == https://openbao.example.invalid ]]
    [[ "${BAO_TOKEN:-}" == synthetic-openbao-token ]]
    [[ -f "${DOCKER_CONFIG:?}/config.json" ]]
    [[ " $* " == *' --key openbao://codewire-runtime '* ]]
    signing_config=''
    args=("$@")
    for ((index = 0; index < ${#args[@]}; index += 1)); do
      if [[ "${args[$index]}" == --signing-config ]]; then
        signing_config="${args[$((index + 1))]}"
      fi
    done
    [[ -f "$signing_config" && ! -L "$signing_config" ]]
    jq -e '
      .mediaType == "application/vnd.dev.sigstore.signingconfig.v0.2+json"
      and .rekorTlogConfig == {}
      and .tsaConfig == {}
    ' "$signing_config" >/dev/null
    [[ " $* " != *' --tlog-upload'* ]]
    [[ " $* " == *' --new-bundle-format=true '* ]]
    [[ " $* " != *' --registry-referrers-mode'* ]]
    if [[ -n "${FAKE_SIGN_BARRIER:-}" ]]; then
      # Every family must be signing at once: a serial signer never fills
      # the barrier and fails here.
      printf '%s\n' "$reference" | sha256sum | cut -d' ' -f1 >"$FAKE_SIGN_BARRIER/$BASHPID"
      for _ in $(seq 1 100); do
        [[ "$(find "$FAKE_SIGN_BARRIER" -type f | wc -l)" -lt 5 ]] || break
        sleep 0.1
      done
      [[ "$(find "$FAKE_SIGN_BARRIER" -type f | wc -l)" -ge 5 ]]
    fi
    grep -Fxq "$reference" "$SIGNATURE_STATE" || printf '%s\n' "$reference" >>"$SIGNATURE_STATE"
    ;;
  verify)
    [[ -z "${BAO_ADDR:-}" && -z "${BAO_TOKEN:-}" ]]
    [[ -f "${DOCKER_CONFIG:?}/config.json" ]]
    public_key=''
    args=("$@")
    for ((index = 0; index < ${#args[@]}; index += 1)); do
      if [[ "${args[$index]}" == --key ]]; then
        public_key="${args[$((index + 1))]}"
      fi
    done
    [[ -f "$public_key" && ! -L "$public_key" ]]
    [[ " $* " == *' --insecure-ignore-tlog '* ]]
    [[ " $* " == *' --new-bundle-format=true '* ]]
    grep -Fxq "$reference" "$SIGNATURE_STATE"
    ;;
  *) exit 64 ;;
esac
SH
chmod 0755 "$work/fake-cosign"

cat >"$work/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${DOCKER_LOG:?}"
printf '\n' >>"$DOCKER_LOG"

case "${1:-} ${2:-} ${3:-}" in
  login\ *)
    credential="$(cat)"
    [[ "$credential" == synthetic-ghcr-token || "$credential" == synthetic-harbor-password ]]
    mkdir -p "${DOCKER_CONFIG:?}"
    printf '%s\n' '{}' >"$DOCKER_CONFIG/config.json"
    ;;
  'image inspect --format')
    [[ "${FAKE_COSIGN_MISSING:-0}" != 1 ]] || exit 1
    [[ "${5:-}" == *sigstore/cosign/cosign@sha256:* ]]
    printf '%s\n' sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    ;;
  create\ *)
    [[ " $* " == *' --pull=never '* ]]
    [[ "${3:-}" == */sigstore/cosign/cosign@sha256:* ]]
    [[ "${!#}" == version ]]
    printf '%s\n' cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    ;;
  cp\ *)
    [[ "${2:-}" == cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:/ko-app/cosign ]]
    [[ -n "${3:-}" ]]
    cp "${FAKE_COSIGN_BINARY:?}" "$3"
    ;;
  rm\ *)
    [[ "${2:-}" == -f ]]
    [[ "${3:-}" == cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc ]]
    ;;
  'buildx imagetools inspect')
    format=''
    reference=''
    shift 3
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --format) format="$2"; shift 2 ;;
        *) reference="$1"; shift ;;
      esac
    done
    [[ -n "$format" && -n "$reference" ]]
    if [[ "$format" == '{{json .Provenance.SLSA}}' ]]; then
      builder='https://codewire.sh/ci/builders/protected-delivery/v1'
      [[ "$reference" != "${FAKE_BAD_PROVENANCE_REF:-}" ]] || builder='https://attacker.invalid/builder'
      revision="${GITHUB_SHA:?}"
      if [[ -n "${FAKE_CARRIED_REF:-}" && "$reference" == "$FAKE_CARRIED_REF" ]]; then
        revision="${FAKE_CARRIED_REVISION:?}"
      fi
      jq -n --arg builder "$builder" --arg revision "$revision" '{
        buildDefinition: {
          buildType: "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
          internalParameters: {builderPlatform: "linux/amd64"}
        },
        runDetails: {
          builder: {id: $builder},
          metadata: {buildkit_metadata: {vcs: {
            revision: $revision,
            source: "https://git.example.invalid/codewire/codewire.git"
          }}}
        }
      }'
    elif [[ "$format" == '{{json .SBOM.SPDX}}' ]]; then
      if [[ "$reference" == "${FAKE_BAD_SBOM_REF:-}" ]]; then
        jq -n '{spdxVersion: "SPDX-2.3", packages: []}'
      else
        jq -n '{
          spdxVersion: "SPDX-2.3",
          documentNamespace: "https://codewire.example/sbom/runtime",
          packages: [{name: "codewire-runtime"}]
        }'
      fi
    else
      exit 64
    fi
    ;;
  *) printf 'unexpected docker command: %s\n' "$*" >&2; exit 1 ;;
esac
SH
chmod 0755 "$work/bin/docker"

source_sha=0123456789abcdef0123456789abcdef01234567
digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
bundle="$work/bundle.json"
public_key="$work/codewire-runtime-signing.pub"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$work/signing.key" >/dev/null 2>&1
openssl pkey -in "$work/signing.key" -pubout -out "$public_key" >/dev/null 2>&1
python3 "$ROOT/scripts/ci/images/image-bundle.py" create \
  --source-sha "$source_sha" \
  --output "$bundle" \
  --candidate dashboard "$source_sha" "registry.example.invalid/codewire/dashboard@$digest" \
  --candidate derp "$source_sha" "registry.example.invalid/codewire/derp@$digest" \
  --candidate daemon "$source_sha" "registry.example.invalid/codewire/daemon@$digest" \
  --candidate services "$source_sha" "registry.example.invalid/codewire/services@$digest" \
  --candidate mesh "$source_sha" "registry.example.invalid/codewire/mesh@$digest"

export DOCKER_LOG="$docker_log"
export COSIGN_LOG="$cosign_log"
export CURL_LOG="$curl_log"
export FAKE_COSIGN_BINARY="$work/fake-cosign"
export SIGNATURE_STATE="$signature_state"
export GITHUB_SHA="$source_sha"
export GITHUB_REF=refs/heads/main
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/runs/1/id_token?token=opaque'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'

run_signer() {
  PATH="$work/bin:$PATH" RUNNER_TEMP="$work/tmp" \
    "$SIGNER" "$bundle" "$public_key"
}

mkdir "$work/sign-barrier"
if ! FAKE_SIGN_BARRIER="$work/sign-barrier" run_signer >"$work/first.out" 2>"$work/first.err"; then
  sed -n '1,80p' "$work/first.err" >&2
  sed -n '1,80p' "$docker_log" >&2
  sed -n '1,80p' "$cosign_log" >&2
  fail 'valid protected runtime signing fixture failed'
fi
[[ "$(wc -l <"$signature_state" | tr -d ' ')" -eq 5 ]] ||
  fail 'signer did not create exactly five Harbor signatures'
[[ "$(sort -u "$signature_state" | wc -l | tr -d ' ')" -eq 5 ]] ||
  fail 'signer signed a registry reference more than once'
[[ "$(grep -c '^sign ' "$cosign_log")" -eq 5 ]] ||
  fail 'signer did not invoke Cosign exactly once per registry reference'
[[ "$(grep -c '/id_token?' "$curl_log")" -eq 6 ]] ||
  fail 'signer did not mint one initial and one per-signature Forgejo identity'
[[ "$(grep -c '/v1/auth/forgejo-jwt/login$' "$curl_log")" -eq 6 ]] ||
  fail 'signer reused one short-lived OpenBao token across registry signatures'
[[ "$(grep -c '/v1/platform/data/ci/codewire/harbor-publisher$' "$curl_log")" -eq 1 ]] ||
  fail 'signer fetched Harbor credentials more than once'
if grep -q '/v1/platform/data/ci/codewire/ghcr-publisher$' "$curl_log"; then
  fail 'delivery signing depended on the GHCR mirror credential'
fi
[[ "$(grep -c '^registry.example.invalid/codewire/' "$signature_state")" -eq 5 ]] ||
  fail 'delivery signing did not sign all five Harbor references'
if grep -q '^ghcr.io/' "$signature_state"; then
  fail 'delivery signing signed a GHCR mirror reference'
fi
[[ "$(grep -c "create .*--pull=never .*${COSIGN_IMAGE} version" "$docker_log")" -eq 1 ]] ||
  fail 'signer did not extract the exact preloaded Cosign image without pulling'
grep -Fq 'cp cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:/ko-app/cosign ' \
  "$docker_log" || fail 'signer did not extract the canonical Cosign binary path'
if grep -q '^run ' "$docker_log"; then
  fail 'signer retained a cross-DinD bind-mount execution path'
fi
[[ "$(grep -c "buildx imagetools inspect .*Provenance.SLSA" "$docker_log")" -eq 5 ]] ||
  fail 'signer did not verify provenance for every Harbor reference'
[[ "$(grep -c "buildx imagetools inspect .*SBOM.SPDX" "$docker_log")" -eq 5 ]] ||
  fail 'signer did not verify SBOMs for every Harbor reference'
grep -Fq 'Verified and signed the exact five-image runtime set in Harbor' \
  "$work/first.out" || fail 'signer omitted its complete-set result'
if rg -n 'synthetic-(request|forgejo|openbao|ghcr-token|harbor-password)' \
  "$work/first.out" "$work/first.err" "$docker_log" "$cosign_log"; then
  fail 'signer exposed short-lived identity or registry credential material'
fi

sign_calls_before="$(grep -c '^sign ' "$cosign_log")"
oidc_calls_before="$(grep -c '/id_token?' "$curl_log")"
login_calls_before="$(grep -c '/v1/auth/forgejo-jwt/login$' "$curl_log")"
run_signer >"$work/second.out" 2>"$work/second.err"
[[ "$(grep -c '^sign ' "$cosign_log")" -eq "$sign_calls_before" ]] ||
  fail 'idempotent signer duplicated an accepted signature'
[[ "$(grep -c '/id_token?' "$curl_log")" -eq $((oidc_calls_before + 1)) ]] ||
  fail 'idempotent signer minted identities for already accepted signatures'
[[ "$(grep -c '/v1/auth/forgejo-jwt/login$' "$curl_log")" -eq $((login_calls_before + 1)) ]] ||
  fail 'idempotent signer refreshed OpenBao for already accepted signatures'
[[ "$(grep -Fc 'Runtime signature already accepted:' "$work/second.out")" -eq 5 ]] ||
  fail 'idempotent signer did not report all accepted signatures'

if GITHUB_REF=refs/pull/1/head run_signer >"$work/pr.out" 2>"$work/pr.err"; then
  fail 'signer accepted a pull-request ref'
fi
grep -Fq 'restricted to canonical main' "$work/pr.err" ||
  fail 'non-main signing rejection was not attributable'

bad_ref="registry.example.invalid/codewire/dashboard@$digest"
if FAKE_BAD_PROVENANCE_REF="$bad_ref" run_signer \
  >"$work/provenance.out" 2>"$work/provenance.err"; then
  fail 'signer accepted invalid protected provenance'
fi
grep -Fq 'Runtime provenance is invalid for dashboard' "$work/provenance.err" ||
  fail 'invalid provenance rejection was not attributable'
grep -Fxq 'Runtime signing failed for: dashboard' "$work/provenance.err" ||
  fail 'a failed family did not fail the whole set by name'

bad_sbom_ref="registry.example.invalid/codewire/dashboard@$digest"
if FAKE_BAD_SBOM_REF="$bad_sbom_ref" run_signer \
  >"$work/sbom.out" 2>"$work/sbom.err"; then
  fail 'signer accepted an invalid protected SBOM'
fi
grep -Fq 'Runtime SBOM is invalid for dashboard' "$work/sbom.err" ||
  fail 'invalid SBOM rejection was not attributable'

if FAKE_COSIGN_MISSING=1 run_signer \
  >"$work/missing.out" 2>"$work/missing.err"; then
  fail 'signer pulled or accepted an unapproved Cosign runtime'
fi
grep -Fq 'Approved Cosign image was not preloaded' "$work/missing.err" ||
  fail 'missing approved Cosign rejection was not attributable'

# The GHCR mirror is signed separately and needs only the GHCR credential.
: >"$curl_log"
if ! PATH="$work/bin:$PATH" RUNNER_TEMP="$work/tmp" \
    "$SIGNER" --ghcr-mirror "$bundle" "$public_key" >"$work/mirror.out" 2>"$work/mirror.err"; then
  sed -n '1,40p' "$work/mirror.err" >&2
  fail 'GHCR mirror signing fixture failed'
fi
[[ "$(grep -c '^ghcr.io/codewiresh/' "$signature_state")" -eq 5 ]] ||
  fail 'GHCR mirror signing did not sign all five mirror references'
[[ "$(grep -c '/v1/platform/data/ci/codewire/ghcr-publisher$' "$curl_log")" -eq 1 ]] ||
  fail 'GHCR mirror signing did not fetch the GHCR credential once'
if grep -q '/v1/platform/data/ci/codewire/harbor-publisher$' "$curl_log"; then
  fail 'GHCR mirror signing fetched delivery registry credentials'
fi
grep -Fq 'runtime set in the GHCR mirror' "$work/mirror.out" ||
  fail 'GHCR mirror signing omitted its result'

# A carried-forward image keeps the provenance of the protected build that
# produced its bits. Signing binds the workflow source while accepting the
# planner-certified deployed baseline as that family's built-from revision.
baseline_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
carried_digest=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
carried_ref="registry.example.invalid/codewire/mesh@$carried_digest"
carried_bundle="$work/carried-bundle.json"
python3 "$ROOT/scripts/ci/images/image-bundle.py" create \
  --source-sha "$source_sha" \
  --output "$carried_bundle" \
  --candidate dashboard "$source_sha" "registry.example.invalid/codewire/dashboard@$digest" \
  --candidate derp "$source_sha" "registry.example.invalid/codewire/derp@$digest" \
  --candidate daemon "$source_sha" "registry.example.invalid/codewire/daemon@$digest" \
  --candidate services "$source_sha" "registry.example.invalid/codewire/services@$digest" \
  --candidate mesh "$source_sha" "$carried_ref"

: >"$signature_state"
: >"$cosign_log"
: >"$curl_log"
if ! PATH="$work/bin:$PATH" RUNNER_TEMP="$work/tmp" \
    CODEWIRE_DEPLOY_BASELINE_SHA="$baseline_sha" \
    CODEWIRE_BUILT_FROM_MESH="$baseline_sha" \
    FAKE_CARRIED_REF="$carried_ref" FAKE_CARRIED_REVISION="$baseline_sha" \
    "$SIGNER" "$carried_bundle" "$public_key" >"$work/carried.out" 2>"$work/carried.err"; then
  sed -n '1,40p' "$work/carried.err" >&2
  fail 'carried-forward runtime signing fixture failed'
fi
[[ "$(wc -l <"$signature_state" | tr -d ' ')" -eq 5 ]] ||
  fail 'carried-forward signing did not sign all five Harbor references'
carried_sign_line="$(grep '^sign ' "$cosign_log" | grep -F "$carried_ref" | head -1)"
grep -Fq "dev.codewire.source-sha=$source_sha" <<<"$carried_sign_line" ||
  fail 'carried-forward signature did not bind the workflow source'
grep -Fq "dev.codewire.built-from-sha=$baseline_sha" <<<"$carried_sign_line" ||
  fail 'carried-forward signature did not record the deployed baseline provenance'
dashboard_sign_line="$(grep '^sign ' "$cosign_log" | grep -F 'codewire/dashboard@' | head -1)"
grep -Fq "dev.codewire.built-from-sha=$source_sha" <<<"$dashboard_sign_line" ||
  fail 'freshly built image signature did not record the head built-from source'
carried_verify_line="$(grep '^verify ' "$cosign_log" | grep -F "$carried_ref" | head -1)"
grep -Fq "dev.codewire.built-from-sha=$baseline_sha" <<<"$carried_verify_line" ||
  fail 'carried-forward verification did not bind the deployed baseline annotation'

if PATH="$work/bin:$PATH" RUNNER_TEMP="$work/tmp" \
    CODEWIRE_BUILT_FROM_MESH="$baseline_sha" \
    FAKE_CARRIED_REF="$carried_ref" FAKE_CARRIED_REVISION="$baseline_sha" \
    "$SIGNER" "$carried_bundle" "$public_key" >"$work/unbounded.out" 2>"$work/unbounded.err"; then
  fail 'signer accepted a built-from source without the certified baseline'
fi
grep -Fq 'neither the workflow source nor the certified deployed baseline' \
  "$work/unbounded.err" || fail 'unbounded built-from rejection was not attributable'

if PATH="$work/bin:$PATH" RUNNER_TEMP="$work/tmp" \
    CODEWIRE_DEPLOY_BASELINE_SHA="$baseline_sha" \
    CODEWIRE_BUILT_FROM_MESH="$baseline_sha" \
    FAKE_CARRIED_REF="$carried_ref" FAKE_CARRIED_REVISION="$source_sha" \
    "$SIGNER" "$carried_bundle" "$public_key" >"$work/rebadged.out" 2>"$work/rebadged.err"; then
  fail 'signer accepted carried provenance from the wrong revision'
fi
grep -Fq 'Runtime provenance is invalid for mesh' "$work/rebadged.err" ||
  fail 'wrong-revision carried provenance rejection was not attributable'

printf '[test-sign-runtime-image-set] closed protected signing contract passed\n'
