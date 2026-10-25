#!/usr/bin/env bash
# Synthetic commands exercise the real cross-check wrapper, never a real build.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
python3 - "$ROOT" <<'PY'
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

source = Path(sys.argv[1])
check = source / 'scripts/ci/verify/check-darwin-cross.sh'
# Clippy with warnings as errors: Linux clippy never compiles macOS-only code.
expected_check = ['clippy', '--locked', '-p', 'codewire-local-vmm',
                  '-p', 'codewire-vmm-guest-probe', '--target', 'aarch64-apple-darwin',
                  '--', '-D', 'warnings']
# The macOS cw links Apple frameworks, so Linux only compile-checks it, after
# the CLI library's macOS-only unit tests.
expected_cli_tests = ['clippy', '--locked', '-p', 'codewire-cli', '--lib', '--tests',
                      '--target', 'aarch64-apple-darwin', '--', '-D', 'warnings']
expected_cli = ['clippy', '--locked', '-p', 'codewire-cli-bin', '--bin', 'cw',
                '--target', 'aarch64-apple-darwin', '--target', 'x86_64-apple-darwin',
                '--', '-D', 'warnings']
with tempfile.TemporaryDirectory(prefix='codewire-darwin-cross-') as temporary:
    root = Path(temporary)
    binary = root / 'bin'
    binary.mkdir()
    trace = root / 'trace.jsonl'
    tool_source = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
tool = Path(sys.argv[0]).name
arguments = sys.argv[1:]
with open(os.environ['DARWIN_FIXTURE_TRACE'], 'a') as output:
    output.write(json.dumps(dict(tool=tool, args=arguments)) + '\\n')
if tool == 'uname':
    print(os.environ.get('DARWIN_FIXTURE_HOST', 'Linux'))
elif tool == 'zig':
    print(os.environ.get('DARWIN_FIXTURE_ZIG', '0.15.2'))
    sys.exit(int(os.environ.get('DARWIN_FIXTURE_ZIG_STATUS', '0')))
elif tool == 'cargo-zigbuild' and arguments == ['--version']:
    print(os.environ.get('DARWIN_FIXTURE_ZIGBUILD', 'cargo-zigbuild 0.23.0'))
    sys.exit(int(os.environ.get('DARWIN_FIXTURE_ZIGBUILD_STATUS', '0')))
elif tool == 'cargo-zigbuild':
    assert os.environ['CARGO_ZIGBUILD_PYTHON_PATH'] == '/usr/bin/false'
    assert os.environ['CARGO_ZIGBUILD_ZIG_PATH'] == str(Path(sys.argv[0]).with_name('zig'))
    # Model only the selected compiler route; the real compilation is separate.
    os.environ['DARWIN_FIXTURE_PINNED_COMPILER'] = '1'
    os.execv(str(Path(sys.argv[0]).with_name('cargo')), ['cargo', *arguments])
elif tool == 'cargo':
    if os.environ.get('DARWIN_FIXTURE_PINNED_COMPILER') != '1':
        print('fixture bare Cargo lacks the Darwin C compiler', file=sys.stderr)
        sys.exit(47)
    sys.exit(int(os.environ.get('DARWIN_FIXTURE_CHECK_STATUS', '0')))
else:
    raise AssertionError(tool)
'''
    for name in ('uname', 'zig', 'cargo-zigbuild', 'cargo'):
        tool = binary / name
        tool.write_text(tool_source)
        tool.chmod(0o755)
    environment = dict(PATH=f'{binary}:{os.environ["PATH"]}', HOME=str(root),
                       DARWIN_FIXTURE_TRACE=str(trace))
    cases = 0

    def run(extra=None, status=0, arguments=()):
        global cases
        cases += 1
        trace.write_text('')
        result = subprocess.run(['bash', str(check), *arguments],
                                env=dict(environment, **(extra or {})),
                                capture_output=True, text=True, timeout=10)
        records = [json.loads(line) for line in trace.read_text().splitlines()]
        assert result.returncode == status, (extra, result.returncode, result.stderr)
        if status == 1:
            assert '[darwin-cross] ERROR:' in result.stderr, result.stderr
            assert not any(r['tool'] == 'cargo' or
                           (r['tool'] == 'cargo-zigbuild' and r['args'] != ['--version'])
                           for r in records), records
        return records, result

    # Preserve the old check's exact argv. With no Darwin C compiler, the old
    # bare invocation fails; the wrapper supplies the compiler route, not a skip.
    bare = subprocess.run([str(binary / 'cargo'), *expected_check], env=environment,
                          capture_output=True, text=True, timeout=10)
    assert bare.returncode == 47 and 'lacks the Darwin C compiler' in bare.stderr
    for extra in ({}, dict(ZIG_VERSION='0.15.2', CARGO_ZIGBUILD_VERSION='0.23.0')):
        records, _ = run(extra)
        assert records == [dict(tool='uname', args=['-s']),
                           dict(tool='zig', args=['version']),
                           dict(tool='cargo-zigbuild', args=['--version']),
                           dict(tool='cargo-zigbuild', args=expected_check),
                           dict(tool='cargo', args=expected_check)], records
    records, _ = run(dict(DARWIN_FIXTURE_CHECK_STATUS='46'), status=46)
    assert records[-1] == dict(tool='cargo', args=expected_check)
    records, result = run(arguments=['--cli'])
    assert records == [dict(tool='uname', args=['-s']),
                       dict(tool='zig', args=['version']),
                       dict(tool='cargo-zigbuild', args=['--version']),
                       dict(tool='cargo-zigbuild', args=expected_cli_tests),
                       dict(tool='cargo', args=expected_cli_tests),
                       dict(tool='cargo-zigbuild', args=expected_cli),
                       dict(tool='cargo', args=expected_cli)], records
    assert 'macOS cw for aarch64 and x86_64' in result.stdout, result.stdout
    # A failing test check stops before the cw check and is the exit status.
    records, _ = run(dict(DARWIN_FIXTURE_CHECK_STATUS='46'), status=46, arguments=['--cli'])
    assert records[-1] == dict(tool='cargo', args=expected_cli_tests), records
    run(arguments=['--features', 'synthetic'], status=1)
    run(arguments=['--cli', '--features', 'synthetic'], status=1)
    run(dict(DARWIN_FIXTURE_HOST='Darwin'), status=1, arguments=['--cli'])
    run(dict(DARWIN_FIXTURE_HOST='Darwin'), status=1)
    for override in ('ZIG_VERSION', 'CARGO_ZIGBUILD_VERSION', 'DARWIN_FIXTURE_ZIG',
                     'DARWIN_FIXTURE_ZIGBUILD'):
        for value in ('', '0.0.0'):
            run({override: value}, status=1)
    for override in ('DARWIN_FIXTURE_ZIG_STATUS', 'DARWIN_FIXTURE_ZIGBUILD_STATUS'):
        run({override: '42'}, status=1)

    # Both cc-rs spellings and empty overrides must fail before Cargo starts.
    overrides = ['CC', 'CXX', 'AR', 'RANLIB', 'LD', 'TARGET_CC', 'TARGET_CXX',
                 'TARGET_AR', 'TARGET_RANLIB', 'TARGET_LD',
                 'CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER',
                 'CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER', 'SDKROOT', 'ZIG_COMMAND',
                 'CARGO_ZIGBUILD_ZIG_PATH', 'CARGO_ZIGBUILD_PYTHON_PATH',
                 'CARGO_ZIGBUILD_ZIG_VERSION', 'CARGO_ZIGBUILD_RUSTC_VERSION', 'CARGO']
    overrides += ['CARGO_BIN_EXE_cargo-zigbuild', 'LIBSQLITE3_SYS_USE_PKG_CONFIG',
                  'LIBSQLITE3_FLAGS', 'CFLAGS', 'CXXFLAGS', 'TARGET_CFLAGS', 'TARGET_CXXFLAGS']
    overrides += [f'{tool}_{target}' for tool in ('CFLAGS', 'CXXFLAGS')
                  for target in ('aarch64-apple-darwin', 'aarch64_apple_darwin',
                                 'x86_64-apple-darwin', 'x86_64_apple_darwin')]
    overrides += [f'{tool}_{target}' for tool in ('CC', 'CXX', 'AR', 'RANLIB', 'LD')
                  for target in ('aarch64-apple-darwin', 'aarch64_apple_darwin',
                                 'x86_64-apple-darwin', 'x86_64_apple_darwin')]
    for override in overrides:
        for value in ('', '/synthetic/override'):
            _, result = run({override: value}, status=1)
            assert f'unset inherited {override}' in result.stderr

    # Missing tools are modeled with a private PATH: no ambient installation
    # can turn a missing-tool fixture into a real compiler invocation.
    essentials = root / 'essentials'
    essentials.mkdir()
    for name in ('bash', 'dirname', 'printenv', 'python3'):
        (essentials / name).symlink_to(shutil.which(name))
    saved_path = environment['PATH']
    environment['PATH'] = f'{binary}:{essentials}'
    for name in ('zig', 'cargo-zigbuild'):
        tool = binary / name
        parked = root / name
        tool.rename(parked)
        run(status=1)
        parked.rename(tool)
    environment['PATH'] = saved_path

    # These fixture pins must move atomically with the existing workflow pins.
    # The release Linux builds take theirs from local-runtime-sources.json
    # (build-cw-linux.sh, #3119), so their workflows carry none.
    for workflow in ('.gitea/workflows/ci.yaml',):
        content = (source / workflow).read_text()
        assert content.count('  ZIG_VERSION: 0.15.2\n') == 1, workflow
        assert content.count('  CARGO_ZIGBUILD_VERSION: 0.23.0\n') == 1, workflow
    for workflow in ('.gitea/workflows/cli-release.yaml', '.gitea/workflows/cw-release-dry-run.yaml'):
        assert 'ZIG_VERSION' not in (source / workflow).read_text(), workflow
    ci = (source / '.gitea/workflows/ci.yaml').read_text()
    transport = ci.split('\n  rust-transport:\n', 1)[1].split('\n  database:\n', 1)[0]
    assert 'CARGO_HOME: ${{ github.workspace }}/target/ci-rust-cargo-home' in transport
    setup = transport.split('      - name: Set up pinned Darwin C cross-check tools\n', 1)[1].split('      - name:', 1)[0]
    assert "tested_tree_receipt != 'accepted'" in setup
    assert "contains(needs.verification-selection.outputs.selection, '|transport_pkg_codewire_local_vmm|')" in setup
    install = 'cargo install --locked cargo-zigbuild --version "$CARGO_ZIGBUILD_VERSION"'
    export = 'echo "$CARGO_HOME/bin" >> "$GITHUB_PATH"'
    assert install in setup and export in setup and setup.index(install) < setup.index(export)
    assert '"${ZIG_X86_64_LINUX_SHA256}  zig.tar.xz" | sha256sum -c -' in setup
    # Compile every Rust target runs the --cli check when the cw package
    # changes (#3119 A13), with the installed cargo-zigbuild on PATH from the
    # job's own Cargo home.
    assert '\n  cw-release-assets:\n' not in ci
    compile_job = ci.split('\n  rust-compile:\n', 1)[1].split('\n  rust-packages:\n', 1)[0]
    # A main push compiles in the job's own Cargo home; every other run on the
    # build runner, in its warm one (infra#1632).
    assert "format('{0}/target/ci-rust-cargo-home', github.workspace) || '/ci-cache/pr/cargo-home'" in compile_job
    cw_selected = "needs.verification-selection.outputs.cw_package_selected == 'true'"
    setup = compile_job.split('      - name: Set up pinned Darwin C cross-check tools\n', 1)[1].split('      - name:', 1)[0]
    assert "tested_tree_receipt != 'accepted'" in setup and cw_selected in setup
    assert install in setup and export in setup and setup.index(install) < setup.index(export)
    assert '"${ZIG_X86_64_LINUX_SHA256}  zig.tar.xz" | sha256sum -c -' in setup
    check = compile_job.split('      - name: Compile the macOS cw for both Mac targets\n', 1)[1].split('      - name:', 1)[0]
    assert "tested_tree_receipt != 'accepted'" in check and cw_selected in check
    assert 'run: scripts/ci/verify/check-darwin-cross.sh --cli' in check
    assert compile_job.index('Set up pinned Darwin C cross-check tools') < compile_job.index('Compile the macOS cw for both Mac targets')
    print(f'Darwin cross-check wrapper: {cases} cases passed; old bare check rejected')
PY
