#!/usr/bin/env bash
# Contract tests for the Dev warm-pool proof (Program #2238 C5): it runs only
# against Dev with the smoke key, refuses unsafe options before any network or
# build step, is read-only toward Kubernetes and never writes through SQL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROOF="$ROOT/scripts/runtime/dev/prove-dev-warm-pools.sh"

fail() { printf 'warm pool proof tests: %s\n' "$*" >&2; exit 1; }

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
"$PROOF" --help | grep -q 'prove-dev-warm-pools.sh' || fail '--help does not describe the proof'
"$PROOF" --help | grep -q 'at least 20 warm hits' || fail '--help does not state the acceptance hit count'

refuses 'only against Dev' env CODEWIRE_SERVER_URL=https://codewire.sh CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF"
refuses 'CODEWIRE_DEV_SMOKE_API_KEY is required' "$PROOF"
refuses 'unknown journey' env CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF" --journeys hits,nonsense
refuses '--hits must be 1-99' env CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF" --hits 0
refuses '--min-hits must be 0-3' env CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF" --hits 3 --min-hits 4
refuses 'stats requires --sql-cmd' env CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF" --journeys stats
refuses 'OFF_SHAPE_CPU must differ' env CODEWIRE_DEV_SMOKE_API_KEY=x OFF_SHAPE_CPU=1000 "$PROOF"
refuses 'shell tracing is enabled' env CODEWIRE_DEV_SMOKE_API_KEY=x bash -x "$PROOF"

# Kubernetes access is read-only: kubectl_ro is the only kubectl call, and it
# allows get alone.
mapfile -t direct < <(grep -n 'kubectl --context' "$PROOF")
[[ "${#direct[@]}" -eq 1 ]] || fail "unexpected direct kubectl calls: ${direct[*]}"
grep -qF "kubectl --context \"\$KUBE_CONTEXT\" \"\$@\"" "$PROOF" || fail 'kubectl_ro is not the read path'
grep -A3 '^kubectl_ro()' "$PROOF" | grep -q 'get) ;;' || fail 'kubectl_ro allows more than get'
if grep -nE '^[^#]*\bkubectl[[:space:]]+(apply|create|delete|patch|edit|scale|label|annotate|cordon|drain|replace|set)\b' "$PROOF"; then
  fail 'the proof contains a mutating kubectl call'
fi
# A hit is a Claim naming the shared pool and an adopted warm member; the
# off-shape create goes through its own shadow pool.
grep -qF 'POOL_PREFIX="cw-pool-"' "$PROOF" || fail 'no shared-pool prefix'
grep -qF '"$launch" == warm' "$PROOF" || fail 'hits are not classified by the warm launch type'
grep -qF 'SHADOW_PREFIX="shadow-pool-"' "$PROOF" || fail 'no shadow-pool check for the off-shape create'
grep -qF 'observedGeneration == .metadata.generation' "$PROOF" || fail 'no capable-controller preflight'
# Billing opens at bind, and destroyed environments keep no live binding.
grep -qF 'w.bound_at <= s.started_at' "$PROOF" || fail 'no billing-at-bind check'
grep -q "e.state = 'destroyed'" "$PROOF" || fail 'no destroyed-environment binding check'
grep -q 'check "hit \$n: no live binding once destroyed" sql_released_after_destroy' "$PROOF" ||
  fail 'hits do not check the release after destroy'
# C6 (#2434): every warm hit checks that the warm-member bridge selects
# exactly the bound Pod, and skips with a message, never a pass, while the
# fork's sandbox-uid label is absent; destroy removes the bridge.
grep -qF 'SANDBOX_UID_LABEL="agents.x-k8s.io/sandbox-uid"' "$PROOF" || fail 'no sandbox-uid bridge label'
grep -qF 'check_bridge "$n" "$id"' "$PROOF" || fail 'hits do not check the warm-member bridge'
grep -qF 'the warm-member bridge selects exactly the bound Pod' "$PROOF" || fail 'no exact-selection bridge check'
grep -qF 'skip "hit $n: warm-member bridge not checked' "$PROOF" || fail 'no labelled skip without the fork label'
grep -q 'check "hit \$n: no warm-member bridge once destroyed" bridge_absent' "$PROOF" ||
  fail 'hits do not check the bridge is removed on destroy'
# The SQL runner only ever receives statements on stdin; no write keyword.
if grep -nE '\b(INSERT|UPDATE|DELETE|TRUNCATE|ALTER|DROP|GRANT|COPY)\b' "$PROOF" | grep -v '^[0-9]*:#'; then
  fail 'the proof contains a SQL write statement'
fi
# Tokens and credentials are never echoed.
# shellcheck disable=SC2016
if grep -nE 'echo[^\n]*\$(own|stolen|token|CODEWIRE_API_KEY|CODEWIRE_DEV_SMOKE_API_KEY)\b' "$PROOF"; then
  fail 'a token may be printed'
fi
printf 'warm pool proof tests: OK\n'
