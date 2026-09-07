#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/cargo-target-runner-failures.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  echo "test-cargo-target-runner-failures: $*" >&2
  exit 1
}

fixture_root="$TMP/root"
mkdir -p "$fixture_root/scripts/ci/verify"

for runner in \
  scripts/ci/verify/run-product-verification.sh \
  scripts/ci/verify/run-integration-verification.sh \
  scripts/ci/verify/rust-stack-rehearsal.sh; do
  cp "$ROOT/$runner" "$fixture_root/$runner"
done

cat >"$fixture_root/scripts/ci/verify/resolve-cargo-target-dir.sh" <<'SH'
#!/usr/bin/env bash
printf 'fixture resolver failure\n' >&2
exit 42
SH
chmod 0755 "$fixture_root/scripts/ci/verify/resolve-cargo-target-dir.sh"

assert_resolver_failure() {
  local runner="$1" output status

  set +e
  output="$(bash "$fixture_root/$runner" 2>&1)"
  status=$?
  set -e

  [[ "$status" == 42 ]] ||
    fail "$runner: expected resolver status 42, got $status"
  [[ "$output" == *'fixture resolver failure'* ]] ||
    fail "$runner: resolver diagnostic was not preserved"
}

assert_resolver_failure scripts/ci/verify/run-product-verification.sh
assert_resolver_failure scripts/ci/verify/run-integration-verification.sh
assert_resolver_failure scripts/ci/verify/rust-stack-rehearsal.sh

# The user-facing Cargo install alias must retain the existing installer and
# its failure boundary. This private tree has no ambient .env or real build.
dogfood_fixture="$TMP/dogfood"
dogfood_log="$TMP/dogfood-install.log"
mkdir -p "$dogfood_fixture/apps/cli"
cp "$ROOT/Makefile" "$dogfood_fixture/Makefile"
cat >"$dogfood_fixture/apps/cli/Makefile" <<'EOF'
.PHONY: install-user
install-user:
	@printf 'install-user\n' >> "$(DOGFOOD_TEST_LOG)"
	@test "$(DOGFOOD_TEST_FAIL)" != 1
EOF
run_dogfood_make() {
  env -i PATH="$PATH" DOGFOOD_TEST_LOG="$dogfood_log" DOGFOOD_TEST_FAIL="$1" \
    make --no-print-directory -C "$dogfood_fixture" \
      AGENT_SANDBOX_SHA=synthetic BUF=/synthetic/buf GO_BIN=/synthetic/go/bin \
      "$2"
}
run_dogfood_make 0 help >"$TMP/dogfood-help"
grep -qF 'make dogfood' "$TMP/dogfood-help" || fail 'dogfood is absent from make help'
[[ ! -e "$dogfood_log" ]] || fail 'make help invoked the installer'
touch "$dogfood_fixture/dogfood"
run_dogfood_make 0 dogfood >"$TMP/dogfood-success"
[[ "$(cat "$dogfood_log")" == install-user ]] ||
  fail 'dogfood must delegate exactly once to the existing user installer'
: >"$dogfood_log"
if run_dogfood_make 1 dogfood >"$TMP/dogfood-failure" 2>&1; then
  fail 'dogfood hid a failed user install'
fi
[[ "$(cat "$dogfood_log")" == install-user ]] ||
  fail 'dogfood retried or skipped the failed user installer'
printf 'CLI user-install alias delegation: green\n'

integration_runner="$ROOT/scripts/ci/verify/run-integration-verification.sh"
grep -Fq 'CARGO_CI_TARGET_DIR="${CODEWIRE_CARGO_CI_TARGET_DIR:-$CARGO_TARGET_DIR}"' \
  "$integration_runner" \
  || fail 'integration runner does not support an isolated CI-profile target directory'
grep -Fq 'CARGO_TARGET_DIR="$CARGO_CI_TARGET_DIR" cargo "$@"' \
  "$integration_runner" \
  || fail 'integration runner does not route CI-profile commands through its isolated target directory'
if rg -n '^\s*(?:[A-Z_]+="[^" ]*"\s+)?cargo (?:build|test|check|run).*--profile ci' \
    "$integration_runner" >/dev/null; then
  fail 'a CI-profile integration command bypasses the isolated Cargo target directory'
fi

printf 'Cargo target runner resolver failures: green\n'

# Trace the real product entrypoint with synthetic packages and tool commands.
# No Cargo subprocess can escape to a real build or an ambient credential.
python3 - "$ROOT" "$TMP" <<'PY'
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

source_root, temporary = map(Path, sys.argv[1:])
fixture = temporary / 'rust-composition'
runner = fixture / 'scripts/ci/verify/run-product-verification.sh'
runner.parent.mkdir(parents=True)
production = (source_root / 'scripts/ci/verify/run-product-verification.sh').read_text()
runner.write_text(production)
binary = fixture / 'bin'
binary.mkdir()
trace = fixture / 'trace.jsonl'
packages = ['codewire-alpha', 'codewire-beta', 'codewire-desktop',
            'codewire-local-vmm', 'codewire-vmm-guest-probe',
            'codewire-protected-store']
for package in packages:
    manifest = fixture / 'crates' / package / 'Cargo.toml'
    manifest.parent.mkdir(parents=True)
    manifest.write_text(f'[package]\nname = "{package}"\nversion = "0.0.0"\n')

tool = binary / 'cargo'
tool.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
record = dict(tool=Path(sys.argv[0]).name, args=sys.argv[1:],
              target=os.environ.get('CARGO_TARGET_DIR'),
              flags=os.environ.get('RUSTFLAGS'))
with open(os.environ['COMPOSITION_TRACE'], 'a') as output:
    output.write(json.dumps(record) + '\\n')
if record['tool'] == 'cargo' and sys.argv[1] == os.environ.get('COMPOSITION_FAIL'):
    sys.exit(43)
''')
tool.chmod(0o755)
for helper in ('scripts/ci/tests/test-openbao-only-secret-authority.sh',
               'scripts/ci/tests/test-admin-proto-boundary.sh',
               'scripts/ci/verify/build-local-vmm-initramfs.sh',
               'scripts/ci/release/package-codewire-desktop.sh'):
    destination = fixture / helper
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(tool, destination)
resolver = runner.parent / 'resolve-cargo-target-dir.sh'
resolver.write_text('#!/usr/bin/env bash\nprintf "%s/target\\n" "$1"\n')
resolver.chmod(0o755)
environment = dict(PATH=f'{binary}:{os.environ["PATH"]}',
                   HOME=str(fixture), COMPOSITION_TRACE=str(trace),
                   RUST_COMPOSE_FORMAT='true', RUST_COMPOSE_FORMAT_DONE='true')
cases = 0

def run(tokens, family='rust-transport', fail=None, status=None):
    global cases
    cases += 1
    trace.write_text('')
    env = dict(environment, VERIFICATION_SELECTION='|valid:v3|' + '|'.join(tokens) + '|complete|')
    if fail:
        env['COMPOSITION_FAIL'] = fail
    result = subprocess.run(['bash', str(runner), family], env=env,
                            text=True, capture_output=True)
    records = [json.loads(line) for line in trace.read_text().splitlines()]
    assert result.returncode == (status if status is not None else 43 if fail else 0), (tokens, result.stderr)
    return records, result.stdout

def generic(records):
    return [r['args'] for r in records if r['tool'] == 'cargo'
            and r['args'][0] in ('build', 'clippy', 'test')
            and '--features' not in r['args'] and '--manifest-path' not in r['args']]

def expected(*arguments):
    return [['build', '--locked', *arguments],
            ['clippy', *arguments, '--all-targets', '--', '-D', 'warnings'],
            ['test', *arguments, '--all-targets']]

both = ['rust', 'transport', 'rust_pkg_codewire_alpha', 'transport_pkg_codewire_beta']
records, _ = run([], status=1)
assert not records
for tokens, selected_package in (([both[0], both[2]], 'codewire-alpha'),
                                 ([both[1], both[3]], 'codewire-beta')):
    records, _ = run(tokens)
    assert generic(records) == expected('-p', selected_package)
    assert sum(r['args'] == ['fmt', '--all', '--check'] for r in records) == 1
records, _ = run(both)
assert generic(records) == expected('-p', 'codewire-alpha') + expected('-p', 'codewire-beta')
assert sum(r['args'] == ['fmt', '--all', '--check'] for r in records) == 1

records, _ = run(['rust', 'transport', 'rust_workspace'] +
                 ['transport_pkg_' + p.replace('-', '_') for p in packages])
assert generic(records) == expected('--workspace') + expected(
    *[a for p in sorted(packages) for a in ('-p', p)])
assert any(r['args'] == ['--production-features'] for r in records)
assert any('--features' in r['args'] and 'platform' in r['args'] for r in records)

special = ['rust', 'transport', 'rust_pkg_codewire_alpha', 'transport_pkg_codewire_local_vmm',
           'transport_pkg_codewire_vmm_guest_probe', 'rust_pkg_codewire_desktop']
records, _ = run(special)
assert generic(records) == expected('-p', 'codewire-alpha') + expected('-p', 'codewire-local-vmm', '-p', 'codewire-vmm-guest-probe')
assert sum(r['tool'] == 'package-codewire-desktop.sh' for r in records) == 1
assert sum(r['tool'] == 'build-local-vmm-initramfs.sh' for r in records) == 1
assert sum('--target' in r['args'] and 'aarch64-apple-darwin' in r['args'] for r in records) == 1

for command in ('fmt', 'build', 'clippy', 'test'):
    records, _ = run(both, fail=command)
    assert records[-1]['args'][0] == command

# The standalone families retain their original local entrypoint behavior.
for family, token in [('rust', 'rust_pkg_codewire_alpha'),
                      ('transport', 'transport_pkg_codewire_alpha')]:
    records, output = run([family, token], family=family)
    assert generic(records) == expected('-p', 'codewire-alpha')
    assert records[0]['args'] == ['fmt', '--all', '--check']

print(f'Rust/transport composition trace: {cases} cases passed')
PY
