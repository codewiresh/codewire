#!/usr/bin/env bash
# Build the host binaries consumed by the Kind smoke suites and record the
# no-run test artifact selected by the billing fixture.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT

if [[ $# -ne 1 || -z "$1" ]]; then
  printf 'usage: %s BILLING_TEST_ARTIFACT_JSONL\n' "$0" >&2
  exit 2
fi

billing_artifact_jsonl="$1"
started_at="$(date +%s)"
(
  cd "$ROOT"
  "$ROOT/scripts/ci/verify/run-host-rust-build.sh" bash -ceu '
    cargo build --profile ci -p codewire-orchestration --bin crd-smoke --bin environment-setup-smoke --bin exec-smoke --bin exec-stream-smoke --bin file-service-smoke --bin prepare-stream-smoke --bin log-stream-smoke --bin temporal-smoke --bin temporal-fencing-smoke --bin reconciler-ttl-smoke --bin sidecar-smoke --features kind-e2e
    cargo build --profile ci -p codewire-client --example platform-run-smoke --example environment-session-smoke
    cargo build --profile ci -p codewire-client --example coordinator-ingress-smoke --features kind-e2e
    cargo build --locked --profile ci -p codewire-cli-bin --bin cw
    cargo test --locked --profile ci -p codewire-billing --test wire_contract --no-run --message-format=json configured_billing_wire_contract >"$1"
  ' -- "$billing_artifact_jsonl"
)
printf 'CODEWIRE_CI_PHASE name=kind-smoke-binary-build seconds=%s\n' \
  "$(( $(date +%s) - started_at ))"
