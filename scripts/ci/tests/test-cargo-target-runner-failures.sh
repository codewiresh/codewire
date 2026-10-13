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
import re
import shlex
import shutil
import subprocess
import sys

source_root, temporary = map(Path, sys.argv[1:])
fixture = temporary / 'rust-composition'
runner = fixture / 'scripts/ci/verify/run-product-verification.sh'
runner.parent.mkdir(parents=True)
production = (source_root / 'scripts/ci/verify/run-product-verification.sh').read_text()
runner.write_text(production)
runner.chmod(0o755)
shutil.copy(source_root / 'scripts/ci/verify/local-rust-cache.sh',
            runner.parent / 'local-rust-cache.sh')
binary = fixture / 'bin'
binary.mkdir()
trace = temporary / 'rust-composition-trace.jsonl'
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
record = dict(tool=os.environ.get('COMPOSITION_TOOL_NAME', Path(sys.argv[0]).name), args=sys.argv[1:],
              target=os.environ.get('CARGO_TARGET_DIR'),
              flags=os.environ.get('RUSTFLAGS'))
with open(os.environ['COMPOSITION_TRACE'], 'a') as output:
    output.write(json.dumps(record) + '\\n')
if record['tool'] == 'zig':
    print('0.15.2')
    sys.exit(0)
if record['tool'] == 'cargo-zigbuild' and sys.argv[1:] == ['--version']:
    print('cargo-zigbuild 0.23.0')
    sys.exit(0)
if record['tool'] == 'cargo-zigbuild':
    assert os.environ['CARGO_ZIGBUILD_PYTHON_PATH'] == '/usr/bin/false'
    assert os.environ['CARGO_ZIGBUILD_ZIG_PATH'] == str(Path(sys.argv[0]).with_name('zig'))
    os.environ['COMPOSITION_DARWIN_COMPILER'] = 'pinned-zig'
    os.execv(str(Path(sys.argv[0]).with_name('cargo')), ['cargo', *sys.argv[1:]])
if record['tool'] == 'cargo' and sys.argv[1] in ('check', 'clippy') and 'aarch64-apple-darwin' in sys.argv:
    if os.environ.get('COMPOSITION_DARWIN_COMPILER') != 'pinned-zig':
        print('fixture bare Cargo lacks the Darwin C compiler', file=sys.stderr)
        sys.exit(47)
if record['tool'] == 'cargo' and sys.argv[1] == os.environ.get('COMPOSITION_FAIL'):
    sys.exit(43)
if record['tool'] == os.environ.get('COMPOSITION_FAIL_TOOL'):
    sys.exit(44)
if record['tool'] == 'cargo' and sys.argv[1] == 'test' and os.environ.get('COMPOSITION_FAIL_FEATURE') in sys.argv:
    sys.exit(45)
if record['tool'] == 'cargo' and sys.argv[1:] == json.loads(os.environ.get('COMPOSITION_FAIL_ARGS', 'null')):
    sys.exit(46)
''')
tool.chmod(0o755)
for name in ('zig', 'cargo-zigbuild'):
    shutil.copy(tool, binary / name)
shutil.copy(source_root / 'scripts/ci/verify/check-darwin-cross.sh',
            runner.parent / 'check-darwin-cross.sh')
for helper in ('scripts/ci/tests/test-openbao-only-secret-authority.sh',
               'scripts/ci/tests/test-admin-proto-boundary.sh',
               'scripts/ci/tests/test-cli-host-managed.py',
               'scripts/ci/tests/test-cli-update-mesh-endpoints.py',
               'scripts/ci/tests/test-build-cw-release-dir.py',
               'scripts/dev/test-cw-runtime-image.py',
               'scripts/dev/test-cli-native-managed.py',
               'scripts/dev/test-cli-native-update.py',
               'scripts/ci/tests/test-native-managed-update-entrypoint.py',
               'crates/codewire-local-vmm/macos-vz-runner/Tests/test_ipc_system.sh',
               'crates/codewire-local-vmm/macos-vz-runner/Tests/test_static_contract.py',
               'crates/codewire-local-vmm/macos-vz-runner/Tests/test_console_pair_static_contract.py',
               'scripts/ci/verify/build-local-vmm-initramfs.sh',
               'scripts/ci/release/package-codewire-desktop.sh'):
    destination = fixture / helper
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(tool, destination)
resolver = runner.parent / 'resolve-cargo-target-dir.sh'
resolver.write_text('#!/usr/bin/env bash\nprintf "%s/target\\n" "$1"\n')
resolver.chmod(0o755)
# The trace covers composition, not the workstation compiler cache: never
# start a real sccache server from a fixture.
environment = dict(PATH=f'{binary}:{os.environ["PATH"]}',
                   HOME=str(fixture), COMPOSITION_TRACE=str(trace),
                   CODEWIRE_LOCAL_RUST_CACHE='off',
                   RUST_COMPOSE_FORMAT='true', RUST_COMPOSE_FORMAT_DONE='true')
cases = 0

def run(tokens, family='rust-transport', fail=None, status=None, fail_tool=None, fail_feature=None, fail_args=None, shard=None):
    global cases
    cases += 1
    trace.write_text('')
    env = dict(environment, VERIFICATION_SELECTION='|valid:v3|' + '|'.join(tokens) + '|complete|')
    if fail:
        env['COMPOSITION_FAIL'] = fail
    if fail_tool:
        env['COMPOSITION_FAIL_TOOL'] = fail_tool
    if fail_feature:
        env['COMPOSITION_FAIL_FEATURE'] = fail_feature
    if fail_args:
        env['COMPOSITION_FAIL_ARGS'] = json.dumps(fail_args)
    if shard:
        env['RUST_TRANSPORT_SHARD'] = shard
    result = subprocess.run(['bash', str(runner), family], env=env,
                            text=True, capture_output=True)
    records = [json.loads(line) for line in trace.read_text().splitlines()]
    assert result.returncode == (status if status is not None else 43 if fail else 0), (tokens, result.stderr)
    return records, result.stdout

def generic(records):
    # Privileged kernel fixtures run with --ignored only where the host can
    # grant a mount namespace; they are not part of a package graph. The
    # Darwin cross-check's clippy is asserted on its own below.
    return [r['args'] for r in records if r['tool'] == 'cargo'
            and r['args'][0] in ('build', 'clippy', 'test')
            and '--features' not in r['args'] and '--manifest-path' not in r['args']
            and '--ignored' not in r['args'] and 'aarch64-apple-darwin' not in r['args']]

def expected(*arguments):
    # Workspace clippy runs once in the fast compile job, not per package graph,
    # and the locked test build compiles the graph; no separate debug build.
    return [['test', '--locked', *arguments, '--all-targets']]

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
for helper in ('test-cli-host-managed.py', 'test-cli-update-mesh-endpoints.py',
               'test-build-cw-release-dir.py'):
    assert sum(r['tool'] == helper for r in records) == 1
    run(['rust', 'rust_workspace'], fail_tool=helper, status=44)

special = ['rust', 'transport', 'rust_pkg_codewire_alpha', 'transport_pkg_codewire_local_vmm',
           'transport_pkg_codewire_vmm_guest_probe', 'rust_pkg_codewire_desktop']
records, _ = run(special)
assert generic(records) == expected('-p', 'codewire-alpha') + expected('-p', 'codewire-local-vmm', '-p', 'codewire-vmm-guest-probe')
# The three CI shards together run exactly the single-job composition, and
# formatting still runs once per shard that verifies package graphs.
def comparable(trace_records):
    return sorted(json.dumps(r, sort_keys=True) for r in trace_records)
sharded = []
for shard in ('packages', 'features', 'local-vmm'):
    shard_records, _ = run(special, shard=shard)
    sharded += shard_records
assert comparable(sharded) == comparable(records), 'Rust/transport shards diverged from the single job'
_, invalid_shard_output = run(special, shard='everything', status=2)
assert sum(r['tool'] == 'package-codewire-desktop.sh' for r in records) == 1
assert sum(r['tool'] == 'build-local-vmm-initramfs.sh' for r in records) == 1
assert sum(r['tool'] == 'test_ipc_system.sh' for r in records) == 1
assert sum(r['tool'] == 'test_static_contract.py' for r in records) == 1
assert sum(r['tool'] == 'test_console_pair_static_contract.py' for r in records) == 1
product_feature = 'macos-product-network-fixture'
product_test = ['test', '--locked', '-p', 'codewire-local-vmm', '--features',
                product_feature, '--lib', 'macos_console_pair_fixture']
assert sum(r['tool'] == 'cargo' and r['args'] == product_test for r in records) == 1
assert sum(r['tool'] == 'cargo' and r['args'][0] == 'clippy' and
           product_feature in r['args'] and 'codewire-macos-product-network-fixture' in r['args']
           for r in records) == 1
darwin_check = ['clippy', '--locked', '-p', 'codewire-local-vmm',
                '-p', 'codewire-vmm-guest-probe', '--target', 'aarch64-apple-darwin',
                '--', '-D', 'warnings']
assert sum(r['tool'] == 'cargo' and r['args'] == darwin_check for r in records) == 1
assert sum(r['tool'] == 'cargo-zigbuild' and r['args'] == darwin_check for r in records) == 1
assert all(r['args'] == darwin_check for r in records if 'aarch64-apple-darwin' in r['args'])

# Old fail/new pass uses the actual runner with only its old bare check restored.
# The synthetic Cargo rejects missing cross-compilation setup, not the package
# or target. The new runner must still make exactly the same Cargo check once.
new_check = '    scripts/ci/verify/check-darwin-cross.sh\n'
assert production.count(new_check) == 1
old_check = '    cargo ' + ' '.join(darwin_check) + '\n'
runner.write_text(production.replace(new_check, old_check))
old_records, _ = run(special, status=47)
assert old_records[-1]['tool'] == 'cargo' and old_records[-1]['args'] == darwin_check
runner.write_text(production)

workload_feature = 'macos-workload-network-fixture'
workload_test = ['test', '--locked', '-p', 'codewire-local-vmm', '--features',
                 workload_feature, '--bin', 'codewire-macos-workload-network-fixture']
workload_clippy = ['clippy', '--locked', '-p', 'codewire-local-vmm', '--features',
                   workload_feature, '--bin', 'codewire-macos-workload-network-fixture',
                   '--', '-D', 'warnings']
client_test = ['test', '--locked', '-p', 'codewire-vmm-guest-probe', '--features',
               workload_feature, '--lib', 'macos_workload_network_fixture::']
client_clippy = ['clippy', '--locked', '-p', 'codewire-vmm-guest-probe', '--features',
                 workload_feature, '--lib', '--bin', 'codewire-vmm-guest-probe',
                 '--', '-D', 'warnings']
transcript_test = ['test', '--locked', '-p', 'codewire-local-vmm', '--features',
                   product_feature + ',' + workload_feature, '--lib',
                   'macos_console_pair_fixture::product_network::tests::'
                   'actual_workload_client_and_service_endpoint_share_exact_transcript',
                   '--', '--exact']
old_production_test = ['test', '--locked', '-p', 'codewire-local-vmm', '--features',
                       'macos-production-init-fixture', '--bin', 'codewire-macos-vz-fixture']
old_console_test = ['test', '--locked', '-p', 'codewire-local-vmm', '--features',
                    'macos-console-pair-fixture', '--lib', 'macos_console_pair_fixture']
old_production_clippy = ['clippy', '--locked', '-p', 'codewire-local-vmm', '--features',
                         'macos-production-init-fixture', '--bin', 'codewire-macos-vz-fixture',
                         '--', '-D', 'warnings']
old_console_clippy = ['clippy', '--locked', '-p', 'codewire-local-vmm', '--features',
                      'macos-console-pair-fixture', '--lib', '--bin',
                      'codewire-macos-console-pair-fixture', '--', '-D', 'warnings']
for command in (workload_test, workload_clippy, client_test, client_clippy,
                transcript_test, old_production_test, old_console_test,
                old_production_clippy, old_console_clippy):
    assert sum(r['tool'] == 'cargo' and r['args'] == command for r in records) == 1, command

# Every new command must fail the actual shared entrypoint, not merely a
# duplicated list in the fixture. A later command may not hide its failure.
for command in (darwin_check, workload_test, workload_clippy, client_test, client_clippy, transcript_test):
    records, _ = run(special, fail_args=command, status=46)
    assert records[-1]['args'] == command

records, _ = run(special, fail_tool='test_console_pair_static_contract.py', status=44)
assert records[-1]['tool'] == 'test_console_pair_static_contract.py'

records, _ = run(special, fail_feature=product_feature, status=45)
assert records[-1]['args'] == product_test

for command in ('fmt', 'test'):
    records, _ = run(both, fail=command)
    assert records[-1]['args'][0] == command

# The standalone families retain their original local entrypoint behavior.
for family, token in [('rust', 'rust_pkg_codewire_alpha'),
                      ('transport', 'transport_pkg_codewire_alpha')]:
    records, output = run([family, token], family=family)
    assert generic(records) == expected('-p', 'codewire-alpha')
    assert records[0]['args'] == ['fmt', '--all', '--check']

print(f'Rust/transport composition trace: {cases} cases passed')

# Exercise the actual local receipt owner through the actual shared core too.
# Only terminal checks are synthetic; selection, preflight and receipt logic
# are copied byte-for-byte. This isolated repository has no external remote or secrets.
# Policy core is two parts; together they hold every shared policy helper.
policy_body = '\n'.join(production.split(part + '() {', 1)[1].split('\n}\n', 1)[0]
                        for part in ('run_policy_core_one', 'run_policy_core_two'))
policy_helpers = re.findall(r'^  (?:python3 (?:(?:-I|-B) )*)?((?:scripts|crates)/[\w/.-]+)', policy_body, re.M)
image_guards = ('test-cw-image-context.py', 'test-cw-runtime-source.py',
                'test-cw-image-source.py', 'test-cw-image-consumer.py')
assert set(image_guards) <= {Path(helper).name for helper in policy_helpers}
assert 'scripts/dev/test-macos-vz-workload-network.py' in policy_helpers
assert 'scripts/ci/tests/test-darwin-cross-check.sh' in policy_helpers
canary_guard = 'crates/codewire-local-vmm/macos-sandbox-canary-experiment/Tests/test_static_contract.py'
assert canary_guard in policy_helpers, 'composition fixture omitted the actual crate-local policy guard'
# Merge lanes run beside policy, so every selected family's terminal helper is
# synthetic too (this selection's security family audits the JS supply chain).
for helper in [*policy_helpers, 'scripts/ci/verify/check-shell-scripts.sh',
               'scripts/ci/verify/compile-all-targets.sh',
               'scripts/checks/security/audit-js-supply-chain.sh']:
    destination = fixture / helper
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.suffix == '.sh':
        destination.write_text('#!/usr/bin/env bash\nCOMPOSITION_TOOL_NAME=' +
                               shlex.quote(destination.name) + ' exec python3 ' +
                               shlex.quote(str(tool)) + ' "$@"\n')
        destination.chmod(0o755)
    else:
        shutil.copy(tool, destination)
for helper in ('scripts/dev/preflight.sh', 'scripts/ci/select/select-verification.sh',
               'scripts/ci/receipts/local-prepush-receipt.py'):
    destination = fixture / helper
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(source_root / helper, destination)
# The environment precheck is a terminal check here; its own fixture lives in
# test-pre-push-worktree.sh. Merge state lives in ignored .tmp/, as in the repo.
environment_check = fixture / 'scripts/dev/preflight-environment.sh'
environment_check.write_text('#!/usr/bin/env bash\nexit 0\n')
environment_check.chmod(0o755)
# The merge pass key reads the toolchain identity; never reach a real rustup.
rustc = binary / 'rustc'
rustc.write_text('#!/usr/bin/env bash\nprintf "rustc 0.0.0 (composition fixture)\\n"\n')
rustc.chmod(0o755)
(fixture / '.gitignore').write_text('.tmp/\n')
git_env = dict(environment, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')

def git(*args):
    return subprocess.run(['git', '-C', str(fixture), *args], env=git_env,
                          check=True, capture_output=True, text=True).stdout.strip()

git('init', '-q', '-b', 'main')
# The finite fixture environment must still join Git's automatic maintenance.
git('config', 'maintenance.autoDetach', 'false')
git('config', 'gc.autoDetach', 'false')
git('config', 'user.name', 'Composition Fixture')
git('config', 'user.email', 'composition@codewire.invalid')
git('remote', 'add', 'origin', str(fixture))
git('add', '.')
git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'synthetic base')
git('update-ref', 'refs/remotes/origin/main', 'HEAD')
parent = fixture / 'scripts/dev/macos-vz-workload-network.py'
parent.write_text('# exact new developer path; never executed by this fixture\n')
git('add', '.')
git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'synthetic selected workload parent')
receipt_owner = fixture / 'scripts/ci/receipts/local-prepush-receipt.py'
preflight = fixture / 'scripts/dev/preflight.sh'
receipt_cases = [dict(COMPOSITION_FAIL_TOOL=name) for name in
                 (Path(canary_guard).name, 'test-macos-vz-workload-network.py',
                  'test-darwin-cross-check.sh', *image_guards)]
receipt_cases += [dict(COMPOSITION_FAIL_ARGS=json.dumps(command)) for command in
                 (darwin_check, workload_test, workload_clippy, client_test, client_clippy, transcript_test)]
for injected in receipt_cases:
    trace.write_text('')
    # An injected failure lives in the environment, outside the exact-tree
    # pass key, so each case starts without earlier passes.
    shutil.rmtree(fixture / '.tmp', ignore_errors=True)
    result = subprocess.run([str(preflight), '--for-merge', '--emit-receipt'], cwd=fixture,
                            env=dict(git_env, **injected), capture_output=True, text=True)
    assert result.returncode != 0, result.stdout
    assert 'preflight merge mode: default' in result.stdout, result.stdout
    assert 'receipt=emitted' not in result.stdout and 'receipt_path=' not in result.stdout
    assert 'preflight: OK' not in result.stdout
    assert "FAILED" in result.stderr, result.stderr
    records = [json.loads(line) for line in trace.read_text().splitlines()]
    assert records, (result.stdout, result.stderr)
    # Lanes run concurrently, so the failing command need not be the last
    # traced one; it must have run and stopped qualification.
    if 'COMPOSITION_FAIL_TOOL' in injected:
        assert any(r['tool'] == injected['COMPOSITION_FAIL_TOOL'] for r in records), (records, result.stderr[-3000:])
    else:
        assert any(r['args'] == json.loads(injected['COMPOSITION_FAIL_ARGS']) for r in records), (records, result.stderr[-3000:])
    missing = subprocess.run([str(receipt_owner), 'verify', '--accept-scope', 'merge'], cwd=fixture,
                             env=git_env, capture_output=True, text=True)
    assert missing.returncode != 0 and 'missing' in missing.stdout, missing.stdout
    assert not list((fixture / '.git/codewire-receipts').rglob('*.json'))
print(f'Actual selected policy/workload failures without a receipt: {len(receipt_cases)} cases passed')

# The opt-in root packager flag cannot select archive-only/default verification.
# Exercise real argument dispatch with a Cargo sentinel, then the actual shared
# build_one function with both flags and all four target/independent-tree pairs.
# This proves flag propagation and build failure, not binary reproducibility.
builder = source_root / 'scripts/ci/verify/build-local-vmm-initramfs.sh'
builder_source = builder.read_text()
builder_fixture = temporary / 'initramfs-flag'
builder_bin = builder_fixture / 'bin'
builder_bin.mkdir(parents=True)
builder_trace = builder_fixture / 'cargo.jsonl'
sentinel = builder_bin / 'cargo'
sentinel.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ['BUILDER_TRACE'], 'a') as output:
    output.write(json.dumps(dict(args=sys.argv[1:], target=os.environ.get('CARGO_TARGET_DIR'))) + '\\n')
sys.exit(47)
''')
sentinel.chmod(0o755)
builder_env = dict(PATH=f'{builder_bin}:{os.environ["PATH"]}', HOME=str(builder_fixture),
                   CARGO_HOME=str(builder_fixture), BUILDER_TRACE=str(builder_trace))
for arguments in (
    ['--workload-network-fixture'],
    ['--verify', '--workload-network-fixture'],
    ['--probe', '/synthetic/probe', '--output', '/synthetic/output', '--workload-network-fixture'],
    ['--verify-root', '--workload-network-fixture'],
    ['--verify-root', '--workload-network-fixture', '--workload-network-fixture'],
):
    result = subprocess.run(['bash', str(builder), *arguments], env=builder_env,
                            text=True, capture_output=True)
    assert result.returncode == 2, (arguments, result.stderr)
    assert not builder_trace.exists()
    assert 'reproducibility OK' not in result.stdout

function_runner = builder_fixture / 'scripts/ci/verify/build-function-fixture.sh'
function_runner.parent.mkdir(parents=True)
function_runner.write_text(builder_source.split("VERIFY_WORK=''", 1)[0] + '''
workload_network_fixture="$1"
RUST_TOOLS_DIR="$2"
build_one "$3" "$4"
''')
build_cases = 0
for enabled in (0, 1):
    for tree in ('target-a', 'target-b'):
        for target in ('aarch64-unknown-linux-musl', 'x86_64-unknown-linux-musl'):
            builder_trace.write_text('')
            destination = builder_fixture / tree
            result = subprocess.run(['bash', str(function_runner), str(enabled), str(builder_bin),
                                     str(destination), target], env=builder_env,
                                    text=True, capture_output=True)
            assert result.returncode == 47, result.stderr
            records = [json.loads(line) for line in builder_trace.read_text().splitlines()]
            expected_build = ['build', '--locked', '--release', '--target', target,
                              '-p', 'codewire-vmm-guest-probe', '--bin', 'codewire-vmm-guest-probe']
            if enabled:
                expected_build += ['--features', workload_feature]
            assert records == [dict(args=expected_build, target=str(destination))], records
            assert 'reproducibility OK' not in result.stdout
            build_cases += 1
print(f'Initramfs flag boundary: 5 rejected modes; {build_cases} feature/failure traces passed')
PY
