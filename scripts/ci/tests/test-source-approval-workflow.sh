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
grep -Fq 'EXPECTED_SUPPLYCHAIN: 83fffe1ee4a44bb7ef2b5bdc8d6269775e6534a4' \
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
[[ "$(guard_exit "$(scanner_tree deep a/b/c/d/e/osv-scanner.toml)")" == 65 ]] ||
  fail 'the scanner-configuration guard admitted a deeply nested osv-scanner.toml'

# Gitleaks honours an in-file allow marker, so the guard also refuses any file
# that carries one, in any case and at any depth (#3991). The marker is put
# together here, so that neither this file nor the workflow carries it.
marker="gitleaks"":allow"
upper_marker="GITLEAKS"":ALLOW"
if grep -r -i -l -a -e 'gitleaks[:]allow' "$WORKFLOW" "${BASH_SOURCE[0]}" >/dev/null; then
  fail 'the workflow or this test carries the allow marker and would refuse itself'
fi
guard_output() { # TREE
  (cd "$1" && { bash -euo pipefail "$guard" >/dev/null; } 2>&1) || true
}
marked_tree() { # NAME MARKER PATH
  local tree
  tree="$(scanner_tree "$1")"
  mkdir -p "$(dirname "$tree/$3")"
  printf 'token = "not-a-secret"  # %s\n' "$2" >"$tree/$3"
  printf '%s' "$tree"
}
for case in "lower:$marker:config.py" "upper:$upper_marker:config.py" "nested:$marker:a/b/c/settings.env"; do
  IFS=: read -r name first second path <<<"$case"
  tree="$(marked_tree "marker-$name" "$first:$second" "$path")"
  [[ "$(guard_exit "$tree")" == 65 ]] || fail "the guard admitted an allow marker ($name)"
  grep -Fq "./$path" <<<"$(guard_output "$tree")" ||
    fail "the guard did not name the file that carries the allow marker ($name)"
done
git_internal="$(scanner_tree marker-git-internal)"
printf '# %s\n' "$marker" >"$git_internal/.git/description"
[[ "$(guard_exit "$git_internal")" == 0 ]] ||
  fail 'the allow-marker guard looked inside .git'
unreadable="$(scanner_tree marker-unreadable)"
printf 'data\n' >"$unreadable/src/locked.txt"
chmod 000 "$unreadable/src/locked.txt"
if [[ -r "$unreadable/src/locked.txt" ]]; then
  : # Running as root, where every file is readable.
else
  [[ "$(guard_exit "$unreadable")" != 0 ]] ||
    fail 'the allow-marker guard passed a tree it could not read'
fi
chmod 600 "$unreadable/src/locked.txt"

# #3991, the scanners themselves. The guard is the first layer. These cases run
# the sealed scanner with the guard out of the way, on a tree a candidate
# could send:
#   - osv-scanner.toml files, at the root and nested, that ignore a real
#     advisory (RUSTSEC-2021-0003, smallvec 1.6.0). The sealed revision must
#     still report it for both lock files, because it gives osv-scanner an
#     empty configuration of its own.
#   - a token beside an allow marker. The sealed revision does not report
#     it, which is why the guard above exists; that control flips when the
#     scanner stops honouring the marker.
# Everything is offline: the advisory database is one record written here.
expected_supplychain="$(sed -n 's/^ *EXPECTED_SUPPLYCHAIN: \([0-9a-f]\{40\}\)$/\1/p' "$WORKFLOW")"
[[ "$expected_supplychain" =~ ^[0-9a-f]{40}$ ]] || fail 'the workflow names no sealed Supplychain revision'
sealed() { # supplychain arguments, run as the sealed revision
  EXPECTED_SUPPLYCHAIN="$expected_supplychain" supplychain "$@"
}
if [[ "$(sealed version 2>/dev/null || true)" != "supplychain $expected_supplychain" ]]; then
  # The CI runner image seals every pinned revision and selects one by
  # EXPECTED_SUPPLYCHAIN. A workstation usually has some other build.
  [[ -z "${CI:-}${GITHUB_ACTIONS:-}" ]] ||
    fail "the sealed Supplychain revision $expected_supplychain is not in this runner image"
  printf '[test-source-approval-workflow] note: supplychain %s is not installed here; the sealed-scanner cases were skipped\n' \
    "${expected_supplychain:0:12}"
  printf '[test-source-approval-workflow] PASS\n'
  exit 0
fi
command -v osv-scanner >/dev/null || fail 'osv-scanner is required for the sealed-scanner cases'

database="$FIXTURE/advisory-database"
mkdir -p "$database/osv-scanner/crates.io" "$FIXTURE/supplychain-data"
python3 -I - "$database/osv-scanner/crates.io/all.zip" <<'PY'
import json, sys, zipfile

record = {
    "schema_version": "1.4.0",
    "id": "RUSTSEC-2021-0003",
    "modified": "2023-06-13T13:10:24Z",
    "published": "2021-01-08T12:00:00Z",
    "summary": "Buffer overflow in SmallVec::insert_many",
    "affected": [{
        "package": {"ecosystem": "crates.io", "name": "smallvec"},
        "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0.6.3"}, {"fixed": "0.6.14"},
            {"introduced": "1.0.0"}, {"fixed": "1.6.1"},
        ]}],
    }],
}
with zipfile.ZipFile(sys.argv[1], "w") as archive:
    archive.writestr("RUSTSEC-2021-0003.json", json.dumps(record))
PY
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$database"
export SUPPLYCHAIN_DATA_DIR="$FIXTURE/supplychain-data"

candidate_repository() { # NAME: an empty Git repository for a candidate tree
  local tree="$FIXTURE/candidate-$1"
  mkdir -p "$tree"
  git -C "$tree" init -q
  printf '%s' "$tree"
}
track() { # TREE
  git -C "$1" add -A
  git -C "$1" -c user.name=fixture -c user.email=fixture@example.invalid \
    -c commit.gpgsign=false commit -q -m 'candidate'
}

suppressing="$(candidate_repository suppressing)"
for directory in "$suppressing" "$suppressing/crates/nested"; do
  mkdir -p "$directory"
  cat >"$directory/Cargo.lock" <<'LOCK'
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "fixture"
version = "0.1.0"
dependencies = [
 "smallvec",
]

[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1a55ca5f3b68e41c979bf8c46a6f1da892ca4db8f94023ce0bd32407573b1ac0"
LOCK
  printf '[[IgnoredVulns]]\nid = "RUSTSEC-2021-0003"\nreason = "a candidate hiding a finding"\n' \
    >"$directory/osv-scanner.toml"
done
track "$suppressing"

# The first layer refuses this tree and names both files.
[[ "$(guard_exit "$suppressing")" == 65 ]] ||
  fail 'the guard admitted a tree whose osv-scanner.toml files ignore an advisory'
refused="$(guard_output "$suppressing")"
for named in ./osv-scanner.toml ./crates/nested/osv-scanner.toml; do
  grep -Fxq "$named" <<<"$refused" || fail "the guard did not name $named"
done

# Control: the files do hide the advisory from a scanner that reads them.
honoured="$(cd "$suppressing" && osv-scanner scan source --offline --offline-vulnerabilities \
  --no-resolve --recursive --format json . 2>/dev/null || true)"
[[ "$(jq -r '[.results[]?.packages[]?.vulnerabilities[]?.id] | length' <<<"$honoured")" == 0 ]] ||
  fail 'the fixture osv-scanner.toml files do not hide the advisory, so this case proves nothing'

# The second layer: the sealed scanner reports it for both lock files.
report="$FIXTURE/suppressing-report.json"
status=0
(cd "$suppressing" && sealed --no-update --osv-offline --json ci --policy=strict . >"$report" 2>"$FIXTURE/suppressing.log") ||
  status=$?
[[ "$status" != 0 ]] || fail 'the sealed scan passed a tree with a known advisory'
found="$(jq -r --arg root "$suppressing/" \
  '[.findings.osv[]? | select(.ids | index("RUSTSEC-2021-0003")) | .source_path | ltrimstr($root)] | sort | join(" ")' \
  "$report")"
[[ "$found" == 'Cargo.lock crates/nested/Cargo.lock' ]] || {
  cat "$FIXTURE/suppressing.log" >&2
  fail "the sealed scan reported the ignored advisory for '$found', not for both lock files"
}

# The allow marker: a token Gitleaks reports, and the same token beside the
# marker. The token is derived here; it is no credential and is never stored.
token="ghp_$(printf 'codewire source-approval fixture' | sha256sum | cut -c1-36)"
secrets_exit() { # TREE
  (cd "$1" && sealed secrets . >/dev/null 2>&1) && echo 0 || echo "$?"
}
plain="$(candidate_repository plain-token)"
printf 'token = "%s"\n' "$token" >"$plain/config.py"
track "$plain"
[[ "$(secrets_exit "$plain")" != 0 ]] ||
  fail 'the sealed secrets scan does not report the fixture token, so the marker case proves nothing'
[[ "$(guard_exit "$plain")" == 0 ]] || fail 'the guard refused a tree without an allow marker'
marked="$(candidate_repository marked-token)"
printf 'token = "%s"  # %s\n' "$token" "$marker" >"$marked/config.py"
track "$marked"
[[ "$(guard_exit "$marked")" == 65 ]] || fail 'the guard admitted a token beside an allow marker'
# Not yet closed in the scanner: beside the marker, the token is not reported.
# When the sealed revision stops honouring the marker, this exit becomes
# nonzero; change the expectation then, and keep the guard.
[[ "$(secrets_exit "$marked")" == 0 ]] ||
  fail 'the sealed secrets scan now reports a token beside the allow marker: update this control (#3991)'

printf '[test-source-approval-workflow] PASS\n'
