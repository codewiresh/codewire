#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
# shellcheck source=scripts/ci/tests/fixtures/ci-runners.sh
source "$ROOT/scripts/ci/tests/fixtures/ci-runners.sh"
readonly WORKFLOW="$ROOT/.gitea/workflows/source-approval.yml"
readonly GITLEAKS_CONFIG="$ROOT/.gitleaks.toml"

FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/codewire-source-approval.XXXXXX")"
trap 'rm -rf "$FIXTURE"' EXIT

fail() {
  printf '[test-source-approval-workflow] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$WORKFLOW" ]] || fail 'source-approval workflow is missing'
grep -Fq "runs-on: ${RUNS_ON_UNTRUSTED_LIGHT}" "$WORKFLOW" ||
  fail 'the supply-chain scan does not use the credential-free validation profile'
grep -Fq 'EXPECTED_SUPPLYCHAIN: cf1984547d9af47807e4f27766baa2cc7f84579d' \
  "$WORKFLOW" || fail 'sealed Supplychain revision changed without review'
grep -Fq 'Candidate files are scanned as data only' "$WORKFLOW" ||
  fail 'candidate-as-data boundary is undocumented'
if grep -Fq -- '--osv-offline' "$WORKFLOW"; then
  fail 'workflow requests an incomplete ecosystem-specific offline database'
fi

# infra#1630: the scan takes the IOC and OSM data from the mounted
# advisory bundle, verified against its manifest and at most 24 hours old,
# and keeps OSV live.
grep -Fq 'ADVISORIES: /opt/supplychain/advisories' "$WORKFLOW" ||
  fail 'the scan does not verify the mounted advisory bundle'
grep -Fq 'MAX_AGE_SECONDS: "86400"' "$WORKFLOW" ||
  fail 'the advisory bundle has no 24-hour fail-closed age'
# shellcheck disable=SC2016 # Match the workflow expression literally.
grep -Fq 'SUPPLYCHAIN_DATA_DIR: ${{ steps.advisories.outputs.data_dir }}' "$WORKFLOW" ||
  fail 'the scan does not read the verified IOC and OSM data'
if grep -Fq 'OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY' "$WORKFLOW"; then
  fail 'Codewire keeps OSV live; the scan must not read the bundle databases'
fi
verifier="$FIXTURE/advisory-verifier.py"
awk '/^          python3 -I - "\$ADVISORIES"/ { capture = 1; next }
     capture && /^          PY$/ { exit }
     capture { sub(/^          /, ""); print }' "$WORKFLOW" >"$verifier"
python3 -I - "$verifier" "$FIXTURE/advisories" <<'PY' ||
import datetime, hashlib, json, subprocess, sys
from pathlib import Path

verifier, root = Path(sys.argv[1]).read_text(), Path(sys.argv[2])


def bundle(age):
    for path in sorted(root.rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    files = {f"osv-scanner/{name}/all.zip": name.encode() for name in ("crates.io", "Go", "npm", "PyPI")}
    files.update({"data/iocs/manifest.json": b"{}", "data/osm-cache.json": b'{"entries": [1]}'})
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    built = datetime.datetime.now(datetime.timezone.utc) - age
    (root / "manifest.json").write_text(json.dumps({"schema": 1, "built_at": built.isoformat(), "files": [
        {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in files.items()]}))


def verify():
    data = root.parent / "data"
    data.mkdir(exist_ok=True)
    return subprocess.run([sys.executable, "-I", "-", str(root), "86400", str(data)], input=verifier,
                          capture_output=True, text=True, timeout=300), data


bundle(datetime.timedelta(minutes=5))
result, data = verify()
assert result.returncode == 0, result.stderr
assert "advisory bundle receipt" in result.stdout and (data / "osm-cache.json").is_file()
bundle(datetime.timedelta(hours=25))
assert verify()[0].returncode == 65, "a stale bundle passed"
bundle(datetime.timedelta(minutes=5))
(root / "data/osm-cache.json").write_bytes(b"tampered")
assert verify()[0].returncode == 65, "an altered bundle passed"
PY
  fail 'the advisory bundle check does not pass a fresh bundle and refuse a stale or altered one'

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

# #3991: the scan refuses any scanner configuration in the scanned tree, so a
# candidate cannot carry its own osv-scanner or zizmor ignores. The guard runs
# as written in the workflow, against one tree per case.
guard="$FIXTURE/scanner-config-guard.sh"
sed -n '/# BEGIN scanner-configuration guard/,/# END scanner-configuration guard/p' "$WORKFLOW" |
  sed 's/^          //' >"$guard"
[[ "$(grep -c . "$guard")" -gt 5 ]] || fail 'scanner-configuration guard is missing from the scan step'
guard_exit() { # TREE
  (cd "$1" && bash -euo pipefail "$guard" >/dev/null 2>&1) && echo 0 || echo "$?"
}
scanner_tree() { # NAME, then files to create beneath it
  local tree="$FIXTURE/scanner-$1" path
  shift
  mkdir -p "$tree/.git" "$tree/src"
  printf 'fn main() {}\n' >"$tree/src/main.rs"
  for path in "$@"; do
    mkdir -p "$(dirname "$tree/$path")"
    printf '[[IgnoredVulns]]\nid = "RUSTSEC-2021-0003"\n' >"$tree/$path"
  done
  printf '%s' "$tree"
}
[[ "$(guard_exit "$(scanner_tree clean)")" == 0 ]] ||
  fail 'the scanner-configuration guard refused a clean tree'
[[ "$(guard_exit "$(scanner_tree git-internal .git/osv-scanner.toml)")" == 0 ]] ||
  fail 'the scanner-configuration guard looked inside .git'
for case in osv-scanner.toml crates/nested/osv-scanner.toml .github/zizmor.yml zizmor.yaml .zizmor.yml; do
  name="$(printf '%s' "$case" | tr '/.' '--')"
  [[ "$(guard_exit "$(scanner_tree "$name" "$case")")" == 65 ]] ||
    fail "the scanner-configuration guard admitted $case"
done
linked="$(scanner_tree linked)"
ln -s src/main.rs "$linked/osv-scanner.toml"
[[ "$(guard_exit "$linked")" == 65 ]] ||
  fail 'the scanner-configuration guard admitted a symbolic link'

printf '[test-source-approval-workflow] PASS\n'
