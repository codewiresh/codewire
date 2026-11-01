#!/usr/bin/env bash
# Offline contract for the Dev memory-fill proof (#3718) and the commodity overhead
# it measures: the Pod fills every container past its limit, and the tool touches
# only its own objects.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROOF="$ROOT/scripts/runtime/dev/prove-dev-runtime-memory-fill.sh"
PROFILES="$ROOT/deployments/k8s/runtime-profiles/base"

fail() { printf 'test-runtime-memory-fill-proof: %s\n' "$*" >&2; exit 1; }

bash -n "$PROOF"
"$PROOF" --help | grep -F 'Dev proof that a Kata commodity Pod survives' >/dev/null || fail "help is missing"

# The measured margin of each commodity memory tier (#3718): up to 16 GiB, 1 GiB is
# killed and 1.5 GiB survives; 32 GiB held at 4 GiB with peaks at the margin, so 5 GiB.
for tier in commodity=1536Mi commodity-32g=5Gi; do
  memory="$(yq -er '.overhead.podFixed.memory' "$PROFILES/runtime-class-${tier%%=*}.yaml")"
  [[ "$memory" == "${tier#*=}" ]] || fail "${tier%%=*} overhead changed to $memory; re-measure with the fill proof"
done

# Every mutating call names the tool's own objects, or its applied JSON.
# shellcheck disable=SC2016
if grep -nE 'k( -n "\$NAMESPACE")? (delete|annotate)' "$PROOF" | grep -vF 'TEST_NAME' >/dev/null; then
  fail "the proof deletes or annotates something other than its own objects"
fi
grep -F 'readonly TEST_NAME=cw-fill-test' "$PROOF" >/dev/null || fail "the test object name changed"

# The sourced proof reads these.
# shellcheck disable=SC1090,SC2034
source "$PROOF"
# shellcheck disable=SC2034
MAIN_GIB=4
# shellcheck disable=SC2034
SECOND_GIB=2

pod="$(pod_json)"
[[ "$(jq -r '.spec.runtimeClassName' <<<"$pod")" == commodity ]] || fail "default runtime class is not commodity"
[[ "$(jq -c '[.spec.containers[].resources.limits.memory]' <<<"$pod")" == '["4Gi","2Gi"]' ]] ||
  fail "the Pod does not have the requested shape"
# Writing twice each limit keeps every container's page cache at its limit.
[[ "$(jq -c '[.spec.containers[].env[] | select(.name == "COUNT") | .value]' <<<"$pod")" == '["8","4"]' ]] ||
  fail "a container does not write twice its limit"
[[ "$(jq -r '.spec.containers[0].command[2]' <<<"$pod")" == *'dd if=/dev/urandom'* ]] ||
  fail "the fill does not write incompressible data"

volume="$(volume_json)"
[[ "$(jq -r '.spec.resources.requests.storage' <<<"$volume")" == 22Gi ]] ||
  fail "the volume does not hold everything the fill writes"

# shellcheck disable=SC2034
OVERHEAD=512Mi
class="$(runtime_class_json '{"handler":"kata-clh","overhead":{"podFixed":{"cpu":"250m","memory":"1Gi"}},"scheduling":{"nodeSelector":{"a":"b"}}}')"
[[ "$(jq -c '.overhead.podFixed' <<<"$class")" == '{"cpu":"250m","memory":"512Mi"}' ]] ||
  fail "the throwaway RuntimeClass does not carry the tested overhead"
[[ "$(jq -r '.handler + "/" + .metadata.name' <<<"$class")" == kata-clh/cw-fill-test ]] ||
  fail "the throwaway RuntimeClass does not copy commodity's handler"
[[ "$(jq -c '.scheduling' <<<"$class")" == '{"nodeSelector":{"a":"b"}}' ]] ||
  fail "the throwaway RuntimeClass does not copy commodity's scheduling"

for bad in '--overhead 5' '--tries 0' '--main-gib 0' '--nope'; do
  # shellcheck disable=SC2086
  if ( parse_args $bad ) 2>/dev/null; then fail "accepted $bad"; fi
done
