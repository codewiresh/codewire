#!/usr/bin/env bash
# Contract tests for the Dev workspace-binding proof (Program #2238 B2): it
# runs only against Dev with the smoke key, refuses unsafe options before any
# network or build step, and is read-only toward Kubernetes except one
# opted-in, UID-bound Pod delete.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROOF="$ROOT/scripts/runtime/dev/prove-dev-workspace-binding.sh"

fail() { printf 'workspace binding proof tests: %s\n' "$*" >&2; exit 1; }

refuses() {
  local expected="$1"
  shift
  local output
  if output="$(env -u CODEWIRE_DEV_SMOKE_API_KEY "$@" 2>&1)"; then
    fail "accepted: $*"
  fi
  [[ "$output" == *"$expected"* ]] || fail "unexpected refusal for $*: $output"
}

bash -n "$PROOF"
"$PROOF" --help | grep -q 'prove-dev-workspace-binding.sh' || fail '--help does not describe the proof'

refuses 'only against Dev' env CODEWIRE_SERVER_URL=https://codewire.sh CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF"
refuses 'CODEWIRE_DEV_SMOKE_API_KEY is required' "$PROOF"
refuses 'unknown journey' env CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF" --journeys create,nonsense
refuses 'pod-replace requires --allow-pod-delete' env CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF" --journeys pod-replace
refuses 'legacy-upgrade requires --legacy-env' env CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF" --journeys legacy-upgrade
refuses '--creates must be 1-99' env CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF" --creates 0
refuses 'invariants requires --sql-cmd' env CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF" --journeys invariants
refuses 'shell tracing is enabled' env CODEWIRE_DEV_SMOKE_API_KEY=x bash -x "$PROOF"

# Kubernetes access is read-only through kubectl_ro, except the one opted-in
# delete in the pod-replace journey.
mapfile -t direct < <(grep -n 'kubectl --context' "$PROOF")
[[ "${#direct[@]}" -eq 2 ]] || fail "unexpected direct kubectl calls: ${direct[*]}"
grep -qF "kubectl --context \"\$KUBE_CONTEXT\" \"\$@\"" "$PROOF" || fail 'kubectl_ro is not the read path'
grep -qF "kubectl --context \"\$KUBE_CONTEXT\" delete pod" "$PROOF" || fail 'the opted-in delete moved'
grep -A3 '^kubectl_ro()' "$PROOF" | grep -q 'get) ;;' || fail 'kubectl_ro allows more than get'
# Design §10 and L1: destroyed environments keep no live binding, and the
# fleet check compares each live binding's Pod UID with the live Pod.
grep -q "e.state = 'destroyed'" "$PROOF" || fail 'no destroyed-environment binding check'
grep -q 'released_at IS NULL' "$PROOF" || fail 'no live-binding filter'
grep -q 'live-pod-uid-differs' "$PROOF" || fail 'no live Pod UID comparison (L1)'
# A codewire.yaml where the proof runs must not change the requested shape.
grep -qF 'cw create --no-file --image' "$PROOF" || fail 'the proof create reads a codewire.yaml'
grep -q "e.state = 'running' AND e.desired_state = 'started'" "$PROOF" ||
  fail 'the running-environment check does not exclude destroyed environments'
for journey in create destroy-stopped replay; do
  grep -q "check \"${journey}[^\"]*: no live binding once destroyed\" sql_released_after_destroy" "$PROOF" ||
    fail "$journey does not check the release after destroy"
done
# The SQL runner only ever receives statements on stdin; no write keyword.
if grep -nE '\b(INSERT|UPDATE|DELETE|TRUNCATE|ALTER|DROP)\b' "$PROOF" | grep -v '^[0-9]*:#'; then
  fail 'the proof contains a SQL write statement'
fi
# Tokens and credentials are never echoed: only status codes and modes.
# shellcheck disable=SC2016
if grep -nE 'echo[^\n]*\$(own|stolen|token)\b' "$PROOF"; then fail 'a token may be printed'; fi

printf 'workspace binding proof tests: OK\n'
