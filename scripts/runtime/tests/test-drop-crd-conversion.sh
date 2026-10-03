#!/usr/bin/env bash
# Contract tests for the one-time agent-sandbox CRD conversion migration: it
# needs an explicit context, refuses before any change unless every CRD stores
# only v1beta1 and still points at the old webhook, guards its JSON patch with
# test operations and is a server-side dry run unless --apply is given.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/runtime/agent-sandbox/drop-crd-conversion.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { printf 'drop-crd-conversion tests: %s\n' "$*" >&2; exit 1; }

# A fake kubectl that serves CRD JSON from $FAKE_STATE and records every call.
mkdir -p "$TMP/bin"
cat >"$TMP/bin/kubectl" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_CALLS"
[[ "$1" == --context && "$2" == synthetic ]] || { echo "unexpected context: $*" >&2; exit 9; }
shift 2
case "$1 $2" in
  "get crd")
    stored='["v1beta1"]'
    [[ "$FAKE_STATE" != stored-v1alpha1 || "$3" != sandboxclaims.extensions.agents.x-k8s.io ]] ||
      stored='["v1alpha1","v1beta1"]'
    case "$FAKE_STATE" in
      webhook|stored-v1alpha1)
        conversion='{"strategy":"Webhook","webhook":{"clientConfig":{"caBundle":"c3ludGhldGlj","service":{"name":"agent-sandbox-webhook-service","namespace":"agent-sandbox-system","path":"/convert","port":443}},"conversionReviewVersions":["v1"]}}' ;;
      foreign)
        conversion='{"strategy":"Webhook","webhook":{"clientConfig":{"service":{"name":"other","namespace":"elsewhere"}}}}' ;;
      dropped) conversion='{"strategy":"None"}' ;;
    esac
    printf '{"metadata":{"name":"%s"},"spec":{"conversion":%s},"status":{"storedVersions":%s}}\n' \
      "$3" "$conversion" "$stored"
    ;;
  "patch crd") echo "customresourcedefinition/$3 patched" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 9 ;;
esac
FAKE
chmod +x "$TMP/bin/kubectl"
export PATH="$TMP/bin:$PATH" FAKE_CALLS="$TMP/calls"

run() { # state args... -> output; leaves calls in $FAKE_CALLS
  : >"$FAKE_CALLS"
  FAKE_STATE="$1" "$SCRIPT" "${@:2}" 2>&1
}

refuses() { # expected state args...
  local expected="$1" output
  shift
  if output="$(run "$@")"; then fail "accepted: $*"; fi
  [[ "$output" == *"$expected"* ]] || fail "unexpected refusal for $*: $output"
  ! grep -q '^--context synthetic patch' "$FAKE_CALLS" || fail "patched despite refusing: $*"
}

bash -n "$SCRIPT"
"$SCRIPT" --help | grep -q 'drop-crd-conversion.sh --context NAME' || fail '--help does not show usage'

refuses '--context is required' webhook
refuses 'unknown option' webhook --context synthetic --force
refuses 'finish the v1alpha1 storage migration first' stored-v1alpha1 --context synthetic --apply
refuses 'unexpected conversion' foreign --context synthetic --apply

# Dry run by default: four guarded patches, all server-side dry runs.
run webhook --context synthetic >/dev/null
[[ "$(grep -c ' patch crd ' "$FAKE_CALLS")" -eq 4 ]] || fail 'dry run did not plan four patches'
[[ "$(grep ' patch crd ' "$FAKE_CALLS" | grep -c -- '--dry-run=server')" -eq 4 ]] ||
  fail 'dry run patched without --dry-run=server'
patch="$(grep -m1 ' patch crd ' "$FAKE_CALLS")"
for op in '"op":"test","path":"/spec/conversion/strategy","value":"Webhook"' \
  '"op":"test","path":"/spec/conversion/webhook/clientConfig/service/name","value":"agent-sandbox-webhook-service"' \
  '"op":"replace","path":"/spec/conversion","value":{"strategy":"None"}'; do
  [[ "$patch" == *"$op"* ]] || fail "patch lacks $op: $patch"
done

# Already-dropped conversion is left alone, with or without --apply.
run dropped --context synthetic --apply >/dev/null
! grep -q ' patch crd ' "$FAKE_CALLS" || fail 'patched an already-dropped conversion'

echo 'drop-crd-conversion contract: OK'
