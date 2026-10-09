#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUILDER="$ROOT/scripts/ci/images/build-kind-smokes.sh"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/build-kind-smokes-test.XXXXXX")"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

fail() {
  printf '[test-build-kind-smokes] ERROR: %s\n' "$*" >&2
  exit 1
}

fixture_root="$work/repository"
mkdir -p "$fixture_root/scripts/ci/images" "$fixture_root/scripts/ci/verify" \
  "$work/bin" "$work/output"
cp "$BUILDER" "$fixture_root/scripts/ci/images/build-kind-smokes.sh"

cat >"$fixture_root/scripts/ci/verify/run-host-rust-build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$PWD" >>"$FAKE_WRAPPER_CWD"
[[ "$#" -eq 5 && "$1" == bash && "$2" == -ceu && "$4" == -- \
  && "$5" == "$EXPECTED_BILLING_ARTIFACT" ]] || {
  printf 'unexpected host Rust wrapper invocation\n' >&2
  exit 98
}
exec "$@"
EOF
chmod +x "$fixture_root/scripts/ci/verify/run-host-rust-build.sh"

cat >"$work/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "$FAKE_CARGO_COUNT" ]]; then
  read -r count <"$FAKE_CARGO_COUNT"
fi
count=$((count + 1))
printf '%s\n' "$count" >"$FAKE_CARGO_COUNT"
printf 'cargo' >>"$FAKE_CARGO_CALLS"
printf ' <%s>' "$@" >>"$FAKE_CARGO_CALLS"
printf '\n' >>"$FAKE_CARGO_CALLS"
if [[ "$count" -eq "${FAIL_CARGO_CALL:-0}" ]]; then
  exit "${FAIL_CARGO_STATUS:-1}"
fi
if [[ "${1:-}" == test && "$*" == *'codewire-billing'* ]]; then
  printf '{"reason":"compiler-artifact","target":{"name":"wire_contract"}}\n'
fi
EOF
chmod +x "$work/bin/cargo"

run_builder() {
  env \
    PATH="$work/bin:$PATH" \
    FAKE_CARGO_CALLS="$work/cargo.calls" \
    FAKE_CARGO_COUNT="$work/cargo.count" \
    FAKE_WRAPPER_CWD="$work/wrapper.cwd" \
    EXPECTED_BILLING_ARTIFACT="$work/output/billing contract.jsonl" \
    FAIL_CARGO_CALL="${1:-0}" \
    FAIL_CARGO_STATUS="${2:-1}" \
    "$fixture_root/scripts/ci/images/build-kind-smokes.sh" \
      "$work/output/billing contract.jsonl"
}

cat >"$work/expected.calls" <<'EOF'
cargo <build> <--profile> <ci> <-p> <codewire-orchestration> <--bin> <crd-smoke> <--bin> <environment-setup-smoke> <--bin> <exec-smoke> <--bin> <exec-stream-smoke> <--bin> <file-service-smoke> <--bin> <prepare-stream-smoke> <--bin> <log-stream-smoke> <--bin> <temporal-smoke> <--bin> <temporal-fencing-smoke> <--bin> <reconciler-ttl-smoke> <--bin> <sidecar-smoke> <--features> <kind-e2e>
cargo <build> <--profile> <ci> <-p> <codewire-client> <--example> <platform-run-smoke> <--example> <environment-session-smoke> <--example> <environment-cw-runtime-smoke>
cargo <build> <--profile> <ci> <-p> <codewire-client> <--example> <coordinator-ingress-smoke> <--features> <kind-e2e>
cargo <build> <--locked> <--profile> <ci> <-p> <codewire-cli-bin> <--bin> <cw>
cargo <test> <--locked> <--profile> <ci> <-p> <codewire-billing> <--test> <wire_contract> <--no-run> <--message-format=json> <configured_billing_wire_contract>
EOF

: >"$work/cargo.calls"
: >"$work/wrapper.cwd"
rm -f "$work/cargo.count"
success_output="$(run_builder)"
cmp -s "$work/expected.calls" "$work/cargo.calls" || {
  diff -u "$work/expected.calls" "$work/cargo.calls" >&2 || true
  fail 'Cargo command sequence or arguments drifted'
}
printf '%s\n' "$fixture_root" | cmp -s - "$work/wrapper.cwd" ||
  fail 'host Rust wrapper did not run from the repository root'
grep -Fxq '{"reason":"compiler-artifact","target":{"name":"wire_contract"}}' \
  "$work/output/billing contract.jsonl" ||
  fail 'billing Cargo JSON artifact did not reach its explicit output path'
[[ "$success_output" =~ ^CODEWIRE_CI_PHASE\ name=kind-smoke-binary-build\ seconds=[0-9]+$ ]] ||
  fail 'successful build did not retain the Kind smoke phase timing'

: >"$work/cargo.calls"
: >"$work/wrapper.cwd"
rm -f "$work/cargo.count" "$work/output/billing contract.jsonl"
set +e
failure_output="$(run_builder 3 37 2>&1)"
failure_status=$?
set -e
[[ "$failure_status" -eq 37 ]] ||
  fail "Cargo failure status was not preserved: $failure_status"
[[ "$(wc -l <"$work/cargo.calls")" -eq 3 ]] ||
  fail 'build continued after the failed Cargo command'
if [[ "$failure_output" == *'CODEWIRE_CI_PHASE name=kind-smoke-binary-build'* ]]; then
  fail 'failed build emitted a successful phase timing'
fi
[[ ! -e "$work/output/billing contract.jsonl" ]] ||
  fail 'failed pre-test build reached the billing Cargo JSON artifact command'

set +e
"$fixture_root/scripts/ci/images/build-kind-smokes.sh" >"$work/usage.out" 2>&1
usage_status=$?
set -e
[[ "$usage_status" -eq 2 ]] || fail 'missing artifact path did not fail with usage status'
grep -Fq 'usage: ' "$work/usage.out" && grep -Fq ' BILLING_TEST_ARTIFACT_JSONL' "$work/usage.out" ||
  fail 'missing artifact path did not explain the required input'

# The retired orchestration libtest artifact is no longer an input.
set +e
"$fixture_root/scripts/ci/images/build-kind-smokes.sh" \
  "$work/output/credential bootstrap.jsonl" "$work/output/billing contract.jsonl" \
  >"$work/usage-two.out" 2>&1
usage_two_status=$?
set -e
[[ "$usage_two_status" -eq 2 ]] || fail 'a retired second artifact path was accepted'

bash -n "$BUILDER" "$0"
printf '[test-build-kind-smokes] command sequence, artifact path, timing, and failure propagation passed\n'
