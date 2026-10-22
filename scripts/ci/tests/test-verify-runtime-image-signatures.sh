#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
# CI names these in Actions variables and the job context; the scripts
# require them.
export CODEWIRE_IMAGE_REGISTRY=registry.example.invalid
readonly VERIFIER="$ROOT/scripts/ci/images/verify-runtime-image-signatures.sh"

fail() {
  printf '[test-verify-runtime-image-signatures] ERROR: %s\n' "$*" >&2
  exit 1
}

bash -n "$VERIFIER"
[[ -x "$VERIFIER" ]] || fail "verifier is not executable"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/verify-runtime-image-signatures.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/tmp"
signatures="$work/signatures"
docker_log="$work/docker.log"
cosign_log="$work/cosign.log"
fetch_log="$work/fetch.log"
: >"$signatures"
: >"$docker_log"
: >"$cosign_log"
: >"$fetch_log"

cat >"$work/fetcher" <<'FETCH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FETCH_LOG:?}"
[[ "${1:-}" == --pull ]]
printf '%s\n' 'robot$codewire+pull' >"$2"
printf '%s\n' 'synthetic-pull-password' >"$3"
FETCH
chmod 0755 "$work/fetcher"

# A signature record is "REFERENCE FAMILY SOURCE_SHA VERIFIED", where VERIFIED
# is the dev.codewire.verified annotation, or "none" for a set signed before
# Deploy Dev waited for main CI (#2892). Cosign matches the requested
# annotations as a subset of the signed ones.
cat >"$work/fake-cosign" <<'COSIGN'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${COSIGN_LOG:?}"
printf '\n' >>"$COSIGN_LOG"
[[ "${1:-}" == verify ]] || exit 64
[[ -z "${BAO_ADDR:-}" && -z "${BAO_TOKEN:-}" ]]
[[ -f "${DOCKER_CONFIG:?}/config.json" ]]
[[ " $* " == *' --insecure-ignore-tlog '* && " $* " == *' --new-bundle-format=true '* ]]
family='' source='' verified=''
args=("$@")
for ((index = 0; index < ${#args[@]}; index += 1)); do
  case "${args[$index]}" in
    --annotations)
      value="${args[$((index + 1))]}"
      case "$value" in
        dev.codewire.image-family=*) family="${value#*=}" ;;
        dev.codewire.source-sha=*) source="${value#*=}" ;;
        dev.codewire.verified=*) verified="${value#*=}" ;;
      esac
      ;;
  esac
done
while read -r signed_ref signed_family signed_source signed_verified; do
  [[ "$signed_ref" == "${!#}" && "$signed_family" == "$family" && "$signed_source" == "$source" ]] ||
    continue
  [[ -z "$verified" || "$signed_verified" == "$verified" ]] || continue
  exit 0
done <"$SIGNATURES"
echo 'no matching signatures' >&2
exit 10
COSIGN
chmod 0755 "$work/fake-cosign"

cat >"$work/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${DOCKER_LOG:?}"
printf '\n' >>"$DOCKER_LOG"
case "${1:-} ${2:-}" in
  'login registry.example.invalid')
    [[ "$(cat)" == synthetic-pull-password ]]
    mkdir -p "${DOCKER_CONFIG:?}"
    printf '{}\n' >"$DOCKER_CONFIG/config.json"
    ;;
  'image inspect')
    [[ "${FAKE_COSIGN_MISSING:-0}" != 1 ]] || exit 1
    printf 'sha256:%064d\n' 0
    ;;
  create\ *)
    [[ " $* " == *' --pull=never '* && "${!#}" == version ]]
    printf '%s\n' cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    ;;
  cp\ *) cp "${FAKE_COSIGN_BINARY:?}" "$3" ;;
  rm\ *) ;;
  *) printf 'unexpected docker command: %s\n' "$*" >&2; exit 1 ;;
esac
DOCKER
chmod 0755 "$work/bin/docker"

source_sha=0123456789abcdef0123456789abcdef01234567
other_sha=fedcba9876543210fedcba9876543210fedcba98
digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
public_key="$work/codewire-runtime-signing.pub"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/signing.key" >/dev/null 2>&1
openssl pkey -in "$work/signing.key" -pubout -out "$public_key" >/dev/null 2>&1
bundle="$work/bundle.json"
python3 "$ROOT/scripts/ci/images/image-bundle.py" create \
  --environment prod --source-sha "$source_sha" --output "$bundle" \
  --candidate dashboard "$source_sha" "registry.example.invalid/codewire/dashboard@$digest" \
  --candidate derp "$source_sha" "registry.example.invalid/codewire/derp@$digest" \
  --candidate daemon "$source_sha" "registry.example.invalid/codewire/daemon@$digest" \
  --candidate services "$source_sha" "registry.example.invalid/codewire/services@$digest" \
  --candidate mesh "$source_sha" "registry.example.invalid/codewire/mesh@$digest"

sign() {
  printf 'registry.example.invalid/codewire/%s@%s %s %s %s\n' "$1" "$digest" "$1" "$2" "${3:-main-ci}" >>"$signatures"
}
run_verifier() {
  PATH="$work/bin:$PATH" RUNNER_TEMP="$work/tmp" \
    DOCKER_LOG="$docker_log" COSIGN_LOG="$cosign_log" FETCH_LOG="$fetch_log" \
    SIGNATURES="$signatures" FAKE_COSIGN_BINARY="$work/fake-cosign" \
    OPENBAO_HARBOR_CREDENTIAL_FETCHER="$work/fetcher" \
    "$VERIFIER" "$bundle" "$public_key"
}

for family in dashboard derp daemon services mesh; do
  sign "$family" "$source_sha"
done
run_verifier >"$work/signed.out" 2>"$work/signed.err" || {
  cat "$work/signed.err" >&2
  fail "a completely signed set was refused"
}
[[ "$(grep -c '^Runtime signature accepted: ' "$work/signed.out")" -eq 5 ]] ||
  fail "the verifier did not accept exactly five signatures"
grep -Fq "carries the main-CI-verified delivery signature for source $source_sha" "$work/signed.out" ||
  fail "the verifier omitted its complete-set result"
[[ "$(grep -c '^verify .*--annotations dev.codewire.verified=main-ci ' "$cosign_log")" -eq 5 ]] ||
  fail "the verifier does not require main CI's verdict on every image"
[[ "$(cat "$fetch_log")" == --pull* ]] ||
  fail "the verifier did not use the read-only pull identity"
if grep -q '^sign ' "$cosign_log"; then
  fail "the verifier signed instead of only verifying"
fi
if grep -rq 'synthetic-pull-password' "$work/signed.out" "$work/signed.err" "$docker_log" "$cosign_log"; then
  fail "the verifier exposed the registry credential"
fi

# A delivery that pushed and stopped before signing leaves unsigned images.
grep -v ' services ' "$signatures" >"$signatures.tmp" && mv "$signatures.tmp" "$signatures"
if run_verifier >"$work/unsigned.out" 2>"$work/unsigned.err"; then
  fail "an unsigned image was accepted"
fi
grep -Fxq 'Refusing to reuse unsigned runtime images: services' "$work/unsigned.err" ||
  fail "an unsigned image was not refused by name"

# A signature for another source never admits this one.
sign services "$other_sha"
if run_verifier >"$work/other.out" 2>"$work/other.err"; then
  fail "a signature for another source was accepted"
fi
grep -Fq 'Refusing to reuse unsigned runtime images: services' "$work/other.err" ||
  fail "a signature for another source was not refused by name"
sign services "$source_sha"
run_verifier >/dev/null 2>&1 || fail "a re-signed set was refused"

# A set signed before Deploy Dev waited for main CI's verdict lacks
# dev.codewire.verified=main-ci, so it can never be released.
: >"$signatures"
for family in dashboard derp daemon services mesh; do
  sign "$family" "$source_sha" none
done
if run_verifier >"$work/legacy.out" 2>"$work/legacy.err"; then
  fail "a set signed before main CI verdicts was accepted"
fi
grep -Fxq 'Refusing to reuse unsigned runtime images: dashboard derp daemon services mesh' "$work/legacy.err" ||
  fail "a set without main CI's verdict was not refused by name"
grep -Fq 'has no valid main-CI-verified delivery signature' "$work/legacy.err" ||
  fail "the refusal does not say the verdict is missing"
: >"$signatures"
for family in dashboard derp daemon services mesh; do
  sign "$family" "$source_sha"
done
run_verifier >/dev/null 2>&1 || fail "a main-CI-verified set was refused"

if FAKE_COSIGN_MISSING=1 run_verifier >"$work/no-cosign.out" 2>"$work/no-cosign.err"; then
  fail "the verifier pulled or accepted an unapproved Cosign runtime"
fi
grep -Fq 'Approved Cosign image was not preloaded' "$work/no-cosign.err" ||
  fail "missing approved Cosign rejection was not attributable"
if PATH="$work/bin:$PATH" "$VERIFIER" "$bundle" >/dev/null 2>&1; then
  fail "the verifier accepted a missing public key argument"
fi

printf '[test-verify-runtime-image-signatures] Production signature reuse contract passed\n'
