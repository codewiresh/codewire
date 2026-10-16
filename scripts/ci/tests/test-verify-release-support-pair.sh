#!/usr/bin/env bash
# verify-release-support-pair.sh against a recording curl: a release commit is
# accepted only when both source-SHA indexes exist and each serves exactly
# linux/amd64 and linux/arm64. No network is used.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly CHECK="$ROOT/scripts/ci/release/verify-release-support-pair.sh"

fail() {
  printf '[test-verify-release-support-pair] ERROR: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/bin"
cat >"$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
output='' url='' write_out=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --write-out) write_out="$2"; shift 2 ;;
    --header|--connect-timeout|--max-time|--proto) shift 2 ;;
    --silent|--show-error|--fail) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "$url" >>"$FAKE_CURL_CALLS"
case "$url" in
  https://ghcr.io/token\?scope=repository:codewiresh/*:pull)
    [[ "${FAKE_TOKEN:-ok}" == ok ]] || exit 22
    printf '{"token":"synthetic"}' >"$output" ;;
  https://ghcr.io/v2/codewiresh/*/manifests/*)
    image="${url#https://ghcr.io/v2/codewiresh/}"; image="${image%%/*}"
    state="$(printf '%s\n' "$FAKE_STATES" | sed -n "s/^$image=//p")"
    case "$state" in
      pair) platforms='{"os":"linux","architecture":"amd64"} {"os":"linux","architecture":"arm64"}' ;;
      amd64) platforms='{"os":"linux","architecture":"amd64"}' ;;
      missing) printf '{}' >"$output"; printf '404'; exit 0 ;;
      error) printf '{}' >"$output"; printf '500'; exit 0 ;;
    esac
    jq -n --argjson attestation '{"os":"unknown","architecture":"unknown"}' \
      "[$(sed 's/} {/},{/g' <<<"$platforms")] | {manifests: (map({platform: .}) + [{platform: \$attestation}])}" >"$output"
    printf '%s' "${write_out:+200}" ;;
  *) exit 6 ;;
esac
EOF
chmod +x "$work/bin/curl"
commit="$(printf '%040d' 3)"

check_case() {
  : >"$work/calls"
  if env PATH="$work/bin:$PATH" FAKE_CURL_CALLS="$work/calls" FAKE_STATES="$1" "${@:2}" \
      "$CHECK" "$commit" >"$work/out" 2>&1; then
    echo ok
  else
    echo failed
  fi
}

[[ "$(check_case $'base=pair\nworkspace=pair')" == ok ]] || { cat "$work/out" >&2; fail 'a published two-platform pair was refused'; }
grep -qxF "https://ghcr.io/v2/codewiresh/workspace/manifests/$commit" "$work/calls" ||
  fail 'the exact source-SHA workspace index was not read'
for refused in $'base=missing\nworkspace=pair|is not published' \
    $'base=pair\nworkspace=missing|is not published' \
    $'base=pair\nworkspace=amd64|not exactly linux/amd64 and linux/arm64' \
    $'base=error\nworkspace=pair|returned HTTP 500'; do
  [[ "$(check_case "${refused%%|*}")" == failed ]] || fail "accepted: ${refused%%|*}"
  grep -qF "${refused#*|}" "$work/out" || { cat "$work/out" >&2; fail "refusal not attributable: ${refused%%|*}"; }
done
[[ "$(check_case $'base=pair\nworkspace=pair' FAKE_TOKEN=fail)" == failed ]] ||
  fail 'a missing pull token was accepted'
if env PATH="$work/bin:$PATH" FAKE_CURL_CALLS="$work/calls" FAKE_STATES='' "$CHECK" main >/dev/null 2>&1; then
  fail 'a non-SHA release commit was accepted'
fi

echo 'test-verify-release-support-pair: PASS cases=7'
