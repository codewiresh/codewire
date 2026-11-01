#!/usr/bin/env python3
"""Synthetic argv/refusal proof for the checked-in native journey entrypoint.

No VM, actual CW executable, broker, credential store or asset is used here.
The real parser rejects invalid profiles; isolated real shell functions exercise
the selected argv, admission failures and receipt checks with synthetic peers.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'scripts/ci/verify/smoke-native-local-environment.sh'
A = 'a' * 64
B = 'b' * 64
UUID = '00000000-0000-4000-8000-000000000001'


def function(name):
    match = re.search(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}\n',
                      SOURCE.read_text(), re.MULTILINE | re.DOTALL)
    if not match:
        raise AssertionError(f'missing checked-in function {name}')
    return match[0]


class Contracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='native-update-entrypoint-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.capture = self.root / 'argv'
        self.response = self.root / 'response'
        self.calls = self.root / 'calls'

    def shell(self, name, update=True, code=0, response=None):
        if response is None:
            response = {'status': 'passed', 'mode': 'protected-broker-actual-agents',
                        'harness': 'scripts/dev/test-cli-native-update.py' if update else
                                   'scripts/dev/test-cli-native-managed.py',
                        'missing_acceptance': [], 'cleanup_errors': []}
        self.response.write_text(json.dumps(response))
        values = {
            'SOURCE_ROOT': '/source with spaces', 'SMOKE_ROOT': str(self.root),
            'SMOKE_HOME': str(self.root / 'synthetic-home'), 'STATE_ROOT': '/private/state',
            'SOCKET_DIR': '/tmp/cw-1000/0123456789abcdef',
            'PLATFORM_CONFIG': '/private/config', 'CREDENTIAL_ROOT': '/private/synthetic-credentials',
            'KEYRING_RUNTIME': '/private/synthetic-runtime',
            'KEYRING_DBUS_ADDRESS': 'unix:path=/private/synthetic-bus',
            'ARTIFACT_ROOT': '/selected/artifacts', 'ARTIFACT_LOCK': '/selected/artifacts.lock.json',
            'ORIGINAL_ARTIFACT_LOCK': '/original/artifacts.lock.json',
            'MANAGED_AGENT_CW_IMAGE_RECEIPT': '/A image/image.json',
            'MANAGED_AGENT_UPDATE_A_LOCK': '/original/cw-runtime.lock.json',
            'MANAGED_AGENT_UPDATE_A_SHA256': A,
            'MANAGED_AGENT_UPDATE_RUNTIME_LOCK': '/B pack/cw-runtime.lock.json',
            'MANAGED_AGENT_UPDATE_IMAGE_RECEIPT': '/B image/image.json',
            'MANAGED_AGENT_UPDATE_SHA256': B, 'CW_BIN': '/private/cw',
            'ENVIRONMENT_ID': UUID, 'MANAGED_AGENT_UPDATE': str(int(update)),
            'COMMAND_INDEX': '0', 'TRANSCRIPT': str(self.root / 'transcript'),
            'CAPTURE': str(self.capture), 'RESPONSE': str(self.response),
            'CALLS': str(self.calls), 'FIXTURE_EXIT': str(code),
        }
        script = 'set -euo pipefail\n' + '\n'.join(
            key + '=' + shlex.quote(value) for key, value in values.items()) + '\n'
        script += r'''
die() { printf '%s\n' "$*" >&2; exit 13; }
log() { :; }
require_absolute_canonical_file() { :; }
env() {
  printf '%s\0' "$@" >"$CAPTURE"
  printf 'invoke\n' >>"$CALLS"
  cat "$RESPONSE"
  return "$FIXTURE_EXIT"
}
'''
        script += function(name) + name + '\n'
        script += 'printf "after-function\\n"\n'
        if name == 'admit_native_managed_update_assets':
            script += 'printf "%s\\n" "$MANAGED_AGENT_UPDATE_A_SHA256"\n'
        result = subprocess.run(['bash', '-c', script], text=True, capture_output=True,
                                env={'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME']}, timeout=300)
        args = self.capture.read_bytes().rstrip(b'\0').decode().split('\0') if self.capture.exists() else []
        return result, args

    def test_synthetic_github_login_matches_the_synthetic_broker(self):
        smoke = re.search(r"^readonly SYNTHETIC_GITHUB_LOGIN='([^']+)'$", SOURCE.read_text(), re.MULTILINE)
        broker = re.search(
            r'\("GET", "https://api\.github\.com/user"\) => \{\s*serde_json::json!\(\{"id": 1, "login": "([^"]+)"\}\)',
            (ROOT / 'crates/codewire-credential-broker/src/runtime.rs').read_text())
        self.assertIsNotNone(smoke, 'smoke lacks its synthetic GitHub login')
        self.assertIsNotNone(broker, 'synthetic broker lacks its GitHub /user login')
        self.assertEqual(smoke[1], broker[1])

    def test_default_invokes_original_journey_once(self):
        result, args = self.shell('run_native_managed_agent_smoke', update=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls.read_text(), 'invoke\n')
        self.assertEqual(args[args.index('python3') + 1],
                         '/source with spaces/scripts/dev/test-cli-native-managed.py')
        self.assertEqual(args[args.index('--cw-image-receipt') + 1], '/A image/image.json')
        self.assertNotIn('--runtime-b', args)
        self.assertIn('1220s', args)

    def test_update_invokes_exact_selected_uuid_once(self):
        result, args = self.shell('run_native_managed_agent_smoke')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls.read_text(), 'invoke\n')
        self.assertEqual(args[args.index('python3') + 1],
                         '/source with spaces/scripts/dev/test-cli-native-update.py')
        expected = {'--environment': UUID, '--runtime-a': '/original/cw-runtime.lock.json',
                    '--image-a': '/A image/image.json', '--sha256-a': A,
                    '--runtime-b': '/B pack/cw-runtime.lock.json', '--image-b': '/B image/image.json',
                    '--sha256-b': B, '--vm-state': '/private/state/engine/vms/' + UUID + '/state.json',
                    '--runner-socket': '/tmp/cw-1000/0123456789abcdef/runners/' + UUID + '.sock'}
        for key, value in expected.items():
            self.assertEqual(args.count(key), 1)
            self.assertEqual(args[args.index(key) + 1], value)
        self.assertIn('1220s', args)
        self.assertIn('CODEWIRE_API_KEY=synthetic-platform-key-must-not-be-used', args)

    def test_failed_journey_propagates(self):
        result, _ = self.shell('run_native_managed_agent_smoke', code=7)
        self.assertEqual(result.returncode, 13)
        self.assertNotIn('after-function', result.stdout)

    def test_wrong_harness_cannot_satisfy_update_receipt(self):
        response = {'status': 'passed', 'harness': 'scripts/dev/test-cli-native-managed.py',
                    'mode': 'protected-broker-actual-agents', 'missing_acceptance': [], 'cleanup_errors': []}
        result, _ = self.shell('run_native_managed_agent_smoke', response=response)
        self.assertEqual(result.returncode, 13)
        self.assertNotIn('after-function', result.stdout)

    def admission(self):
        return {'status': 'admitted', 'proof': 'asset-admission-only',
                'harness': 'scripts/dev/test-cli-native-update.py', 'vm_journey_started': False,
                'assets': {'A': {'identity': {'sha256': A}}, 'B': {'identity': {'sha256': B}}}}

    def test_admission_derives_original_lock_without_runtime_args(self):
        result, args = self.shell('admit_native_managed_update_assets', response=self.admission())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls.read_text(), 'invoke\n')
        self.assertIn('--admit-only', args)
        self.assertEqual(args[args.index('--runtime-a') + 1], '/original/cw-runtime.lock.json')
        self.assertNotIn('--environment', args)
        self.assertNotIn('--vm-state', args)
        self.assertNotIn('--runner-socket', args)
        self.assertTrue(result.stdout.endswith(A + '\n'))

    def test_failed_or_drifted_admission_stops_before_effect_continuation(self):
        values = [(7, self.admission())]
        for key, value in [('status', 'passed'), ('proof', 'product'),
                           ('harness', 'scripts/dev/test-cli-native-managed.py'), ('vm_journey_started', True)]:
            changed = self.admission(); changed[key] = value; values.append((0, changed))
        changed = self.admission(); changed['assets']['B']['identity']['sha256'] = A; values.append((0, changed))
        changed = self.admission(); changed['assets']['A']['identity']['sha256'] = 'invalid'; values.append((0, changed))
        for code, response in values:
            with self.subTest(code=code, response=response):
                result, _ = self.shell('admit_native_managed_update_assets', code=code, response=response)
                self.assertEqual(result.returncode, 13)
                self.assertNotIn('after-function', result.stdout)

    def test_invalid_broker_renewal_profiles_refuse_before_effect_tools(self):
        base = []
        for flag in ['cw-bin', 'data-plane-smoke-bin',
                     'credential-bridge-smoke-bin', 'state-probe-bin', 'artifact-root', 'artifact-lock']:
            base.extend(['--' + flag, '/unused/' + flag])
        renewal = ['--broker-renewal-observation']
        profiles = [renewal, renewal + renewal + ['--managed-credential-broker'],
                    renewal + ['--managed-credential-broker', '--managed-agent-sessions'],
                    renewal + ['--managed-credential-broker', '--managed-agent-cw-image-receipt', '/unused/A/image.json'],
                    renewal + ['--managed-credential-broker', '--managed-agent-update-cw-sha256', B]]
        spy = self.root / 'bin'; spy.mkdir()
        effects = self.root / 'effects'
        for name in ('mktemp', 'secret-tool', 'dbus-daemon', 'gnome-keyring-daemon'):
            path = spy / name
            path.write_text('#!/bin/sh\nprintf "effect\\n" >>"$EFFECTS"\nexit 99\n')
            path.chmod(0o700)
        for args in profiles:
            with self.subTest(args=args):
                result = subprocess.run(['bash', str(SOURCE), *base, *args], text=True, capture_output=True,
                    env={'PATH': str(spy) + ':/usr/bin:/bin', 'HOME': os.environ['HOME'],
                         'EFFECTS': str(effects), 'TMPDIR': str(self.root)}, timeout=300)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(effects.exists(), 'invalid profile reached an effect tool')

    def test_invalid_update_profiles_refuse_before_effect_tools(self):
        base = []
        for flag in ['cw-bin', 'data-plane-smoke-bin',
                     'credential-bridge-smoke-bin', 'state-probe-bin', 'artifact-root', 'artifact-lock']:
            base.extend(['--' + flag, '/unused/' + flag])
        modes = ['--managed-credential-broker', '--managed-agent-sessions',
                 '--managed-agent-cw-image-receipt', '/unused/A/image.json']
        group = ['--managed-agent-update-runtime-lock', '/unused/B/cw-runtime.lock.json',
                 '--managed-agent-update-cw-image-receipt', '/unused/B/image.json',
                 '--managed-agent-update-cw-sha256', B]
        profiles = [modes + group[:2], modes + group[2:4], modes + group[4:],
                    group, modes[1:] + group, modes[:1] + group,
                    ['--managed-agent-cw-image-receipt', '']]
        for position in (0, 2, 4):
            profiles.append(modes + group + group[position:position + 2])
            profiles.append(modes + [group[position], ''] + group)
            missing = group.copy(); missing[position + 1] = ''; profiles.append(modes + missing)
        for pin in ['B' * 64, 'b' * 63, 'b' * 65, 'g' * 64]:
            profiles.append(modes + group[:-1] + [pin])
        spy = self.root / 'bin'; spy.mkdir()
        effects = self.root / 'effects'
        for name in ('mktemp', 'secret-tool', 'dbus-daemon', 'gnome-keyring-daemon'):
            path = spy / name
            path.write_text('#!/bin/sh\nprintf "effect\\n" >>"$EFFECTS"\nexit 99\n')
            path.chmod(0o700)
        for args in profiles:
            with self.subTest(args=args):
                result = subprocess.run(['bash', str(SOURCE), *base, *args], text=True, capture_output=True,
                    env={'PATH': str(spy) + ':/usr/bin:/bin', 'HOME': os.environ['HOME'],
                         'EFFECTS': str(effects), 'TMPDIR': str(self.root)}, timeout=300)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(effects.exists(), 'invalid profile reached an effect tool')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=SOURCE)
    args, remaining = parser.parse_known_args()
    SOURCE = args.source.resolve(strict=True)
    unittest.main(argv=[__file__, *remaining])
