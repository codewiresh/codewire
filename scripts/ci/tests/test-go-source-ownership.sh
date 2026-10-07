#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

retired_paths=(
  apps/api
  autoagent
  libs/daemon-proto/buf.gen.yaml
  libs/daemon-proto/gen
  libs/daemon-proto/go.mod
  libs/daemon-proto/go.sum
  libs/gatewayauth
  tests/contract/billing
  tests/contract/connectcore
  tests/contract/coordinator
  tests/contract/file
  tests/contract/orchestration
)

for path in "${retired_paths[@]}"; do
  if [ -e "$ROOT/$path" ]; then
    echo "retired former-Go implementation path remains: $path" >&2
    exit 1
  fi
done

expected_modules="$(cat <<'EOF'
libs/gen-go/go.mod
libs/sdk-go/go.mod
libs/tailnet/go.mod
tests/contract/go.mod
EOF
)"
actual_modules="$(
  cd "$ROOT"
  find . -name go.mod -not -path './.git/*' -printf '%P\n' | LC_ALL=C sort
)"
if [ "$actual_modules" != "$expected_modules" ]; then
  echo 'Go module ownership differs from the accepted four-module boundary' >&2
  diff -u <(printf '%s\n' "$expected_modules") <(printf '%s\n' "$actual_modules") >&2 || true
  exit 1
fi

expected_workspace="$(sed 's#/go.mod$##' <<<"$expected_modules")"
actual_workspace="$(
  awk '
    /^use \($/ { in_use = 1; next }
    in_use && /^\)$/ { exit }
    in_use { sub(/^[[:space:]]*\.\//, ""); print }
  ' "$ROOT/go.work" | LC_ALL=C sort
)"
if [ "$actual_workspace" != "$expected_workspace" ]; then
  echo 'go.work does not contain exactly the accepted in-repository modules' >&2
  diff -u <(printf '%s\n' "$expected_workspace") <(printf '%s\n' "$actual_workspace") >&2 || true
  exit 1
fi
if grep -Eq '(^|[[:space:]])\.\./' "$ROOT/go.work"; then
  echo 'go.work must not depend on a sibling checkout' >&2
  exit 1
fi

expected_contract_source='tests/contract/derp/derp_test.go'
actual_contract_source="$(
  cd "$ROOT"
  find tests/contract -type f -name '*.go' -print | LC_ALL=C sort
)"
if [ "$actual_contract_source" != "$expected_contract_source" ]; then
  echo 'tests/contract must contain only the retained Go/Tailscale DERP client' >&2
  diff -u <(printf '%s\n' "$expected_contract_source") \
    <(printf '%s\n' "$actual_contract_source") >&2 || true
  exit 1
fi

if rg -n 'prepare_go_workspace|github\.com/noeljackson/agent-sandbox|AGENT_SANDBOX' \
    "$ROOT/scripts/ci/verify/run-product-verification.sh"; then
  echo 'automatic verification still depends on the former external Go workspace' >&2
  exit 1
fi

grep -qF '../../libs/daemon-proto/proto' \
  "$ROOT/crates/codewire-daemon-proto/build.rs"
python3 "$ROOT/scripts/checks/repo_checks.py" go-source-classification

echo 'Go source ownership: OK'
