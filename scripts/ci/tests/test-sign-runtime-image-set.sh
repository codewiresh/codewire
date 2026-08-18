#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly SIGNER="$ROOT/scripts/ci/images/sign-runtime-image-set.sh"
readonly COSIGN_IMAGE='nexus-system-cluster.example.invalid/oci-approved/sigstore/cosign/cosign@sha256:6ca1127dc1e9ff19f3f2bfa214936813a86fbbf52919652eda49d393c888ad3c'

fail() {
  printf '[test-sign-runtime-image-set] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/sign-runtime-image-set.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/tmp"
docker_log="$work/docker.log"
signature_state="$work/signatures"
: >"$docker_log"
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
case "$url" in
  *'/id_token?'*) printf '%s\n' '{"value":"synthetic-forgejo-jwt"}' >"$output" ;;
  */v1/auth/forgejo-jwt/login)
    printf '%s\n' '{"auth":{"client_token":"synthetic-openbao-token"}}' >"$output"
    ;;
  */v1/platform/data/nexus/oci-promoter)
    printf '%s\n' '{"data":{"data":{"username":"nexus-user","password":"synthetic-nexus-password"}}}' >"$output"
    ;;
  */v1/platform/data/ci/codewire/ghcr-publisher)
    printf '%s\n' '{"data":{"data":{"username":"ghcr-user","token":"synthetic-ghcr-token"}}}' >"$output"
    ;;
  *) printf 'unexpected curl URL: %s\n' "$url" >&2; exit 1 ;;
esac
SH
chmod 0755 "$work/bin/curl"

cat >"$work/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${DOCKER_LOG:?}"
printf '\n' >>"$DOCKER_LOG"

case "${1:-} ${2:-} ${3:-}" in
  login\ *)
    credential="$(cat)"
    [[ "$credential" == synthetic-nexus-password || "$credential" == synthetic-ghcr-token ]]
    ;;
  'image inspect --format')
    [[ "${FAKE_COSIGN_MISSING:-0}" != 1 ]] || exit 1
    [[ "${5:-}" == *sigstore/cosign/cosign@sha256:* ]]
    printf '%s\n' sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
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
      builder='https://git.example.invalid/infra/ci/builders/protected-delivery/v1'
      [[ "$reference" != "${FAKE_BAD_PROVENANCE_REF:-}" ]] || builder='https://attacker.invalid/builder'
      jq -n --arg builder "$builder" --arg revision "${GITHUB_SHA:?}" '{
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
  run\ *)
    args=("$@")
    [[ " $* " == *' --pull=never '* ]]
    [[ " $* " == *' --cap-drop=ALL '* ]]
    [[ " $* " == *' --security-opt=no-new-privileges '* ]]
    [[ " $* " == *' --pids-limit=256 '* ]]
    [[ " $* " == *' --network=bridge '* ]]
    image_index=-1
    for ((index = 0; index < ${#args[@]}; index += 1)); do
      if [[ "${args[$index]}" == *sigstore/cosign/cosign@sha256:* ]]; then
        image_index="$index"
        break
      fi
    done
    [[ "$image_index" -ge 0 ]]
    command="${args[$((image_index + 1))]}"
    reference="${args[$((${#args[@]} - 1))]}"
    case "$command" in
      sign)
        [[ "${BAO_ADDR:-}" == https://openbao.example.invalid ]]
        [[ "${BAO_TOKEN:-}" == synthetic-openbao-token ]]
        [[ " $* " == *' --key openbao://codewire-runtime '* ]]
        [[ " $* " == *' --signing-config /trust/signing-config.json '* ]]
        [[ " $* " == *' --use-signing-config=true '* ]]
        [[ " $* " == *' --new-bundle-format=false '* ]]
        [[ " $* " == *' --registry-referrers-mode=legacy '* ]]
        grep -Fxq "$reference" "$SIGNATURE_STATE" || printf '%s\n' "$reference" >>"$SIGNATURE_STATE"
        ;;
      verify)
        [[ -z "${BAO_TOKEN:-}" ]]
        [[ " $* " == *' --key /trust/codewire-runtime-signing.pub '* ]]
        [[ " $* " == *' --insecure-ignore-tlog '* ]]
        grep -Fxq "$reference" "$SIGNATURE_STATE"
        ;;
      *) exit 64 ;;
    esac
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
  --candidate dashboard "$source_sha" "nexus-system-cluster.example.invalid/oci-promoted/codewire/dashboard@$digest" \
  --candidate derp "$source_sha" "nexus-system-cluster.example.invalid/oci-promoted/codewire/derp@$digest" \
  --candidate gateway "$source_sha" "nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway@$digest" \
  --candidate services "$source_sha" "nexus-system-cluster.example.invalid/oci-promoted/codewire/services@$digest" \
  --candidate mesh "$source_sha" "nexus-system-cluster.example.invalid/oci-promoted/codewire/mesh@$digest"

export DOCKER_LOG="$docker_log"
export SIGNATURE_STATE="$signature_state"
export GITHUB_SHA="$source_sha"
export GITHUB_REF=refs/heads/main
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/runs/1/id_token?token=opaque'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'

run_signer() {
  PATH="$work/bin:$PATH" RUNNER_TEMP="$work/tmp" \
    "$SIGNER" "$bundle" "$public_key"
}

if ! run_signer >"$work/first.out" 2>"$work/first.err"; then
  sed -n '1,80p' "$work/first.err" >&2
  fail 'valid protected runtime signing fixture failed'
fi
[[ "$(wc -l <"$signature_state" | tr -d ' ')" -eq 10 ]] ||
  fail 'signer did not create exactly ten registry-specific signatures'
[[ "$(sort -u "$signature_state" | wc -l | tr -d ' ')" -eq 10 ]] ||
  fail 'signer signed a registry reference more than once'
[[ "$(grep -c "run .*${COSIGN_IMAGE} sign " "$docker_log")" -eq 10 ]] ||
  fail 'signer did not invoke Cosign exactly once per registry reference'
[[ "$(grep -c "buildx imagetools inspect .*Provenance.SLSA" "$docker_log")" -eq 10 ]] ||
  fail 'signer did not verify provenance in both registries'
[[ "$(grep -c "buildx imagetools inspect .*SBOM.SPDX" "$docker_log")" -eq 10 ]] ||
  fail 'signer did not verify SBOMs in both registries'
grep -Fq 'Verified and signed the exact five-image runtime set in Nexus and GHCR' \
  "$work/first.out" || fail 'signer omitted its complete-set result'
if rg -n 'synthetic-(request|forgejo|openbao|nexus-password|ghcr-token)' \
  "$work/first.out" "$work/first.err" "$docker_log"; then
  fail 'signer exposed short-lived identity or registry credential material'
fi

sign_calls_before="$(grep -c "run .*${COSIGN_IMAGE} sign " "$docker_log")"
run_signer >"$work/second.out" 2>"$work/second.err"
[[ "$(grep -c "run .*${COSIGN_IMAGE} sign " "$docker_log")" -eq "$sign_calls_before" ]] ||
  fail 'idempotent signer duplicated an accepted signature'
[[ "$(grep -Fc 'Runtime signature already accepted:' "$work/second.out")" -eq 10 ]] ||
  fail 'idempotent signer did not report all accepted signatures'

if GITHUB_REF=refs/pull/1/head run_signer >"$work/pr.out" 2>"$work/pr.err"; then
  fail 'signer accepted a pull-request ref'
fi
grep -Fq 'restricted to canonical main' "$work/pr.err" ||
  fail 'non-main signing rejection was not attributable'

bad_ref="nexus-system-cluster.example.invalid/oci-promoted/codewire/dashboard@$digest"
if FAKE_BAD_PROVENANCE_REF="$bad_ref" run_signer \
  >"$work/provenance.out" 2>"$work/provenance.err"; then
  fail 'signer accepted invalid protected provenance'
fi
grep -Fq 'Runtime provenance is invalid for dashboard' "$work/provenance.err" ||
  fail 'invalid provenance rejection was not attributable'

bad_sbom_ref="ghcr.io/codewiresh/dashboard@$digest"
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

printf '[test-sign-runtime-image-set] closed protected signing contract passed\n'
