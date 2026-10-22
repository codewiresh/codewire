#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/source-approval.yml"
readonly GITLEAKS_CONFIG="$ROOT/.gitleaks.toml"

FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/codewire-source-approval.XXXXXX")"
trap 'rm -rf "$FIXTURE"' EXIT

fail() {
  printf '[test-source-approval-workflow] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$WORKFLOW" ]] || fail 'source-approval workflow is missing'
grep -Fq 'runs-on: ci-lite' "$WORKFLOW" ||
  fail 'the supply-chain scan does not use the credential-free validation profile'
grep -Fq 'EXPECTED_SUPPLYCHAIN: cf1984547d9af47807e4f27766baa2cc7f84579d' \
  "$WORKFLOW" || fail 'sealed Supplychain revision changed without review'
grep -Fq 'Candidate files are scanned as data only' "$WORKFLOW" ||
  fail 'candidate-as-data boundary is undocumented'
if grep -Fq -- '--osv-offline' "$WORKFLOW"; then
  fail 'workflow requests an incomplete ecosystem-specific offline database'
fi

for input in \
  '.supplychain/source-policy.json' \
  '.gitleaks.toml' \
  '.supplychain/bun-baseline.json'; do
  [[ -f "$ROOT/$input" && ! -L "$ROOT/$input" ]] ||
    fail "canonical source-approval input is not a regular file: $input"
  git -C "$ROOT" ls-files --error-unmatch "$input" >/dev/null ||
    fail "canonical source-approval input is not tracked: $input"
  grep -Fq "\$GITHUB_WORKSPACE/.source-approval-base/$input" "$WORKFLOW" ||
    fail "protected base does not own $input"
done
# shellcheck disable=SC2016 # Match the workflow's literal shell expression.
grep -Fq '[[ -f "$source" && ! -L "$source" ]]' "$WORKFLOW" ||
  fail 'trusted policy inputs do not reject symlinks and missing files'
# shellcheck disable=SC2016 # Match the workflow's literal argument.
grep -Fq -- '--source-policy="$source_policy"' "$WORKFLOW" ||
  fail 'source policy is not passed explicitly'
# shellcheck disable=SC2016 # Match the workflow's literal argument.
grep -Fq -- '--gitleaks-config="$gitleaks_config"' "$WORKFLOW" ||
  fail 'reviewed Gitleaks policy is not passed explicitly'
# shellcheck disable=SC2016 # Match the workflow's literal argument.
grep -Fq -- '--baseline="$bun_baseline"' "$WORKFLOW" ||
  fail 'reviewed Bun baseline is not passed explicitly'
readonly INSTALL_COMMAND=install
if grep -Eq "npm (ci|${INSTALL_COMMAND})|bun ${INSTALL_COMMAND}|cargo (build|run|test)|docker (build|run)" \
    "$WORKFLOW"; then
  fail 'the supply-chain scan executes a candidate build or dependency installer'
fi

command -v gitleaks >/dev/null || fail 'gitleaks is required for source-approval policy fixtures'
command -v jq >/dev/null || fail 'jq is required for source-approval policy fixtures'

old_config="$FIXTURE/old-gitleaks.toml"
# These two exceptions are deliberately the terminal policy blocks. Adding a
# later allowlist requires updating this old-policy boundary explicitly.
awk '
  /^\[\[allowlists\]\]$/ { pending = $0; next }
  /description = "Explicit disposable stock OpenSSH fixtures for bounded SSH import; never account keys"/ { exit }
  { if (pending != "") { print pending; pending = "" }; print }
' "$GITLEAKS_CONFIG" >"$old_config"
grep -Fq 'Codewire Kind support manifest embeds a disposable EC private-key fixture' "$old_config" ||
  fail 'old-policy fixture lost the protected-base allowlists'
if grep -Fq 'Explicit disposable stock OpenSSH fixtures' "$old_config"; then
  fail 'old-policy fixture retained the new SSH exception'
fi

positive="$FIXTURE/positive"
negative="$FIXTURE/negative"
mkdir -p "$positive/crates/codewire-protected-store/src/ssh_material/fixtures" \
  "$negative/crates/codewire-protected-store/src/ssh_material/fixtures"
private_key_label='PRIVATE KEY'
openssh_key_label="OPENSSH $private_key_label"
openssh_begin="-----BEGIN $openssh_key_label-----"
openssh_end="-----END $openssh_key_label-----"
armor="$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
  "$openssh_begin" \
  U1lOVEhFVElDLUZJWFRVUkUtTk9ULUEtS0VZ \
  LVNZTlRIRVRJQy1GSVhUVVJFLU5PVC1BLUtF \
  WVNZTlRIRVRJQy1GSVhUVVJFLU5PVC1BLUtF \
  WVNZTlRIRVRJQy1GSVhUVVJFLU5PVC1BLUtF \
  WVNZTlRIRVRJQy1GSVhUVVJFLU5PVC1BLUtF \
  WVNZTlRIRVRJQy1GSVhUVVJFLU5PVC1BLUtF \
  "$openssh_end")"
armor+=$'\n'
positive_names=(
  ed25519-aes128-ctr.openssh
  ed25519-aes192-ctr.openssh
  ed25519-aes256-ctr.openssh
  rsa-1024.openssh
  rsa-2048.openssh
  rsa-2048-encrypted.openssh
  rsa-3072.openssh
  rsa-3072-encrypted.openssh
  rsa-4096.openssh
  rsa-4096-encrypted.openssh
  rsa-8192.openssh
  rsa-8192-encrypted.openssh
  ecdsa.openssh
)
for name in "${positive_names[@]}"; do
  printf '%s' "$armor" >"$positive/crates/codewire-protected-store/src/ssh_material/fixtures/$name"
done
printf '    assert!(actual.starts_with(b"%s\\n"));\n' "$openssh_begin" \
  >"$positive/crates/codewire-protected-store/src/ssh_material/tests.rs"
printf '    assert!(actual.ends_with(b"\\n%s\\n"));\n' "$openssh_end" \
  >>"$positive/crates/codewire-protected-store/src/ssh_material/tests.rs"
printf '%s\n' \
  "    assert!(!actual.contains(&b'\\r'));" \
  >>"$positive/crates/codewire-protected-store/src/ssh_material/tests.rs"

run_scan() {
  local config="$1" tree="$2" report="$3" expected_status="$4" status
  set +e
  gitleaks dir --no-banner --redact --exit-code 23 --config "$config" \
    --report-format json --report-path "$report" "$tree" \
    >"$report.log" 2>&1
  status=$?
  set -e
  [ "$status" -eq "$expected_status" ] || {
    sed -n '1,80p' "$report.log" >&2
    fail "gitleaks status $status, want $expected_status for $(basename "$report")"
  }
}

run_scan "$old_config" "$positive" "$FIXTURE/old-positive.json" 23
jq -e '
  (unique_by(.Fingerprint)) as $findings
  | ($findings | length) == 14
    and ($findings | all(.[]; .RuleID == "private-key"))
' "$FIXTURE/old-positive.json" >/dev/null || {
  fail 'old protected-base policy did not report exactly 14 private-key findings'
}

run_scan "$GITLEAKS_CONFIG" "$positive" "$FIXTURE/new-positive.json" 0
jq -e 'length == 0' "$FIXTURE/new-positive.json" >/dev/null ||
  fail 'new policy did not allow exactly the reviewed synthetic fixtures'

printf '%s' "$armor" \
  >"$negative/crates/codewire-protected-store/src/ssh_material/fixtures/unrelated.openssh"
printf '%s' "$armor" \
  >"$negative/crates/codewire-protected-store/src/ssh_material/fixtures/rsa-2048-copy.openssh"
printf '    assert!(actual.starts_with(b"%s\\nchanged"));\n' "$openssh_begin" \
  >"$negative/crates/codewire-protected-store/src/ssh_material/tests.rs"
printf '    assert!(actual.ends_with(b"\\n%s\\n"));\n' "$openssh_end" \
  >>"$negative/crates/codewire-protected-store/src/ssh_material/tests.rs"
printf '%s\n' "    assert!(!actual.contains(&b'\\r'));" \
  >>"$negative/crates/codewire-protected-store/src/ssh_material/tests.rs"
non_openssh_label="RSA $private_key_label"
printf '%s\n' "-----BEGIN $non_openssh_label-----" \
  U1lOVEhFVElDLUZJWFRVUkUtTk9ULUEtS0VZ \
  LVNZTlRIRVRJQy1GSVhUVVJFLU5PVC1BLUtF \
  WVNZTlRIRVRJQy1GSVhUVVJFLU5PVC1BLUtF \
  WVNZTlRIRVRJQy1GSVhUVVJFLU5PVC1BLUtF \
  WVNZTlRIRVRJQy1GSVhUVVJFLU5PVC1BLUtF \
  WVNZTlRIRVRJQy1GSVhUVVJFLU5PVC1BLUtF \
  "-----END $non_openssh_label-----" \
  >"$negative/crates/codewire-protected-store/src/ssh_material/fixtures/ecdsa.openssh"
printf -v generic_value '%s' a B 3 d E 5 f G 7 h J 9 k L 2 m N 4 p Q 6 r S 8
printf 'api_key = "%s"\n' "$generic_value" \
  >"$negative/crates/codewire-protected-store/src/ssh_material/fixtures/rsa-2048.openssh"

run_scan "$GITLEAKS_CONFIG" "$negative" "$FIXTURE/new-negative.json" 23
jq -e '
  (unique_by(.Fingerprint)) as $findings
  | ($findings | length) == 5
    and ([$findings[] | select(.RuleID == "private-key")] | length == 4)
    and ([$findings[] | select(.RuleID == "generic-api-key")] | length == 1)
' "$FIXTURE/new-negative.json" >/dev/null || {
  jq -r 'group_by(.RuleID)[] | "\(.[0].RuleID): \(length)"' \
    "$FIXTURE/new-negative.json" >&2
  jq -r 'unique_by(.Fingerprint) | group_by(.RuleID)[] | "unique \(.[0].RuleID): \(length)"' \
    "$FIXTURE/new-negative.json" >&2
  fail 'scoped policy hid an unrelated path, near miss, altered armor, key format, or other rule'
}

printf '[test-source-approval-workflow] PASS\n'
