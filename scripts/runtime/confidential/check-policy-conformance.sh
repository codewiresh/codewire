#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/kata-containers" >&2
  exit 2
fi

codewire_root=$(git rev-parse --show-toplevel)
kata_root=$1
codewire_fixture="$codewire_root/crates/codewire-orchestration/tests/fixtures/confidential-storage-policy-v1.json"
kata_fixture="$kata_root/src/tools/genpolicy/tests/policy/testdata/confidential-storage-contract-v1.json"

if [[ ! -f "$kata_root/Cargo.toml" || ! -f "$kata_fixture" ]]; then
  echo "error: argument is not a Kata tree with the confidential-storage conformance fixture" >&2
  exit 2
fi

cmp "$codewire_fixture" "$kata_fixture"

cargo test \
  --locked \
  --manifest-path "$codewire_root/Cargo.toml" \
  -p codewire-orchestration \
  confidential_policy_matches_shared_kata_contract_corpus

cargo test \
  --locked \
  --manifest-path "$kata_root/Cargo.toml" \
  -p genpolicy \
  confidential_policy_compiler_matches_shared_contract_fixture

cargo test \
  --locked \
  --manifest-path "$kata_root/Cargo.toml" \
  -p genpolicy \
  --test policy \
  test_confidential_storage_policy_exact_contract

echo "confidential-storage policy conformance: OK"
