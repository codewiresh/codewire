#!/usr/bin/env python3
"""Credential-free execution of the real isolated stock-gh workload boundary."""

from pathlib import Path
import contextlib
import os
import re
import socket
import subprocess
import signal
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "dev/provider-github-workload.py").read_text()
PUBLIC_ERROR = re.compile(
    rb"\ACW_LIVE_GITHUB_ERROR:(?:preflight|binary|socket|account-hint|tmpfs|version|request|response)\n\Z"
)


def process_report(pid):
    """The state, signal masks and wait channel of a process and its children,
    for a failure that would otherwise say only that it outlived its bound."""
    lines = []
    for each in [pid, *sorted(int(child) for child in
                              (Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
                               if Path(f"/proc/{pid}").exists() else []))]:
        try:
            status = Path(f"/proc/{each}/status").read_text()
            wchan = Path(f"/proc/{each}/wchan").read_text()
            command = Path(f"/proc/{each}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        except OSError as error:
            lines.append(f"{each}: {error}")
            continue
        fields = dict(line.split(":\t", 1) for line in status.splitlines() if ":\t" in line)
        lines.append(f"{each} {command.strip()}: " + ", ".join(
            f"{key}={fields.get(key, '?').strip()}" for key in
            ("State", "PPid", "SigPnd", "ShdPnd", "SigBlk", "SigIgn", "SigCgt")) + f", wchan={wchan}")
    return "\n".join(lines)


class WorkloadTests(unittest.TestCase):
    def setUp(self):
        self.root_owner = tempfile.TemporaryDirectory(prefix="cw-gh-test-", dir="/var/tmp")
        self.scratch_owner = tempfile.TemporaryDirectory(prefix="cw-gh-scratch-", dir="/dev/shm")
        self.root = Path(self.root_owner.name)
        self.scratch = Path(self.scratch_owner.name)
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(self.root / "credential.sock"))
        self.login = self.root / "expected-login"
        self.login.write_text("fixture-owner")
        self.login.chmod(0o400)
        self.fake = self.root / "gh"
        self.fake.write_text("""#!/usr/bin/env bash
set -euo pipefail
root="$(dirname "$0")"
[[ "$HOME" == "$GH_CONFIG_DIR" && "$HOME" == "$XDG_CONFIG_HOME" &&
  "$HOME" == "$XDG_CACHE_HOME" && "$HOME" == "$TMPDIR" &&
  "$GH_HOST" == github.com && "$GH_TOKEN" == codewire-managed ]]
[[ "$(cat "$GH_CONFIG_DIR/config.yml")" == "$(printf 'version: "1"\\nhttp_unix_socket: %s' "$root/credential.sock")" ]]
for key in GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN GH_DEBUG HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY BASH_ENV; do
  [[ -z "${!key+x}" ]]
done
kind="$(cat "$root/kind")"
if [[ "$*" == --version ]]; then
  [[ "$kind" != wrong-version ]] || { printf 'private-hostile-version\\n'; exit 0; }
  printf 'gh version 2.97.0 (2026-07-20)\\nhttps://github.com/cli/cli/releases/tag/v2.97.0\\n'
  exit 0
fi
[[ "$*" == 'api --method GET user --hostname github.com' ]]
printf '%s\\n' "$$" >"$root/pid"
case "$kind" in
  timeout) sleep 30 ;;
  oversize) head -c 1048576 /dev/zero ;;
  stderr) printf 'PRIVATE_CANARY\\n' >&2 ;;
  failure) printf 'PRIVATE_CANARY\\n'; exit 1 ;;
  malformed) printf '{PRIVATE_CANARY' ;;
  duplicate) printf '{"login":"fixture-owner","login":"PRIVATE_CANARY","id":1,"type":"User"}' ;;
  wrong-login) printf '{"login":"PRIVATE_CANARY","id":1,"type":"User"}' ;;
  wrong-id) printf '{"login":"fixture-owner","id":true,"type":"User"}' ;;
  wrong-type) printf '{"login":"fixture-owner","id":1,"type":"Organization"}' ;;
  *) printf '{"login":"fixture-owner","id":1,"type":"User"}' ;;
esac
""")
        self.fake.chmod(0o755)
        # Only fixture paths and ownership stand-ins change: routing, command,
        # limits, parsing, cleanup and the real entrypoint remain executable.
        transformed = SOURCE.replace('Path("/usr/local/bin/gh")', repr(self.fake).replace("PosixPath", "Path"))
        transformed = transformed.replace('Path("/workspace/.cw-provider-github/expected-login")',
                                          repr(self.login).replace("PosixPath", "Path"))
        transformed = transformed.replace('Path("/run/codewire-host/credential.sock")',
                                          repr(self.root / "credential.sock").replace("PosixPath", "Path"))
        transformed = transformed.replace('Path("/dev/shm")',
                                          repr(self.scratch).replace("PosixPath", "Path"))
        transformed = transformed.replace("info.st_uid != 0", "info.st_uid != os.getuid()")
        transformed = transformed.replace('scratch, "account", 110)', 'scratch, "account", 1)')
        self.wrapper = self.root / "workload.py"
        self.wrapper.write_text(transformed)

    def tearDown(self):
        self.sock.close()
        self.root_owner.cleanup()
        self.scratch_owner.cleanup()

    def execute(self, kind="success", args=()):
        (self.root / "kind").write_text(kind)
        completed = subprocess.run(
            ["/usr/bin/python3", str(self.wrapper), *args], capture_output=True,
            timeout=300, env={"PATH": "/usr/bin:/bin", "GH_TOKEN": "PRIVATE_CANARY",
                             "GITHUB_TOKEN": "PRIVATE_CANARY", "GH_CONFIG_DIR": "/ambient",
                             "HTTPS_PROXY": "PRIVATE_CANARY", "BASH_ENV": "/ambient"},
        )
        self.assertEqual(list(self.scratch.iterdir()), [], "capture cleanup omitted")
        self.assertNotIn(b"PRIVATE_CANARY", completed.stdout + completed.stderr)
        return completed.returncode, completed.stdout, completed.stderr

    def assert_public_failure(self, result):
        self.assertEqual(result[:2], (1, b""))
        self.assertRegex(result[2], PUBLIC_ERROR)

    def test_exact_stock_routing_isolation_and_account(self):
        self.assertEqual(self.execute(), (0, b"CW_LIVE_GITHUB_OK\n", b""))

    def test_hostile_output_and_identity_rejections(self):
        for kind in ("wrong-version", "stderr", "failure", "malformed", "duplicate",
                     "wrong-login", "wrong-id", "wrong-type", "oversize"):
            with self.subTest(kind=kind):
                self.assert_public_failure(self.execute(kind))

    def test_timeout_drains_stock_process_and_removes_capture(self):
        self.assert_public_failure(self.execute("timeout"))
        pid = int((self.root / "pid").read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_malformed_hint_socket_and_binary_fail_closed(self):
        for kind in ("hint", "socket", "binary"):
            with self.subTest(kind=kind):
                if kind == "hint":
                    self.login.chmod(0o600)
                    self.login.write_text("PRIVATE_CANARY\n")
                    self.login.chmod(0o400)
                elif kind == "socket":
                    self.login.chmod(0o600)
                    self.login.write_text("fixture-owner")
                    self.login.chmod(0o400)
                    (self.root / "credential.sock").unlink()
                    (self.root / "credential.sock").write_text("PRIVATE_CANARY")
                else:
                    self.fake.chmod(0o777)
                self.assert_public_failure(self.execute())

    def test_unsupported_arguments_never_emit_success(self):
        self.assert_public_failure(self.execute(args=("unsupported",)))

    def test_signal_drains_and_removes_private_capture(self):
        # The wrapper keeps its real 110 s account timeout here, so the signal
        # is the only thing that can end it. With the fixture's 1 s timeout a
        # loaded host let that timeout end the wrapper first, and the signal
        # then met Python's default handler at exit (rc -15).
        wrapper = self.root / "workload-signal.py"
        source = self.wrapper.read_text()
        self.assertEqual(source.count('scratch, "account", 1)'), 1)
        wrapper.write_text(source.replace('scratch, "account", 1)', 'scratch, "account", 110)'))
        (self.root / "kind").write_text("timeout")
        child = subprocess.Popen(["/usr/bin/python3", str(wrapper)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            # gh creates the file before it writes its pid, so wait for the line.
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                with contextlib.suppress(FileNotFoundError):
                    if (self.root / "pid").read_text().endswith("\n"):
                        break
                time.sleep(0.01)
            pid = int((self.root / "pid").read_text())
            # A wrapper can be reaped while gh is left as an orphan/zombie
            # under a container PID 1. Require direct ownership before cancel.
            status = Path(f"/proc/{pid}/status").read_text()
            parent = re.search(r"^PPid:\s+(\d+)$", status, re.MULTILINE)
            self.assertIsNotNone(parent)
            self.assertEqual(int(parent.group(1)), child.pid)
            child.send_signal(signal.SIGTERM)
            try:
                stdout, stderr = child.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                # Run 45210 saw this once, with no cause yet: name the state.
                self.fail("the wrapper outlived SIGTERM by 60 s:\n" + process_report(child.pid))
            self.assertEqual((child.returncode, stdout, stderr), (1, b"", b"CW_LIVE_GITHUB_ERROR:request\n"))
            self.assertEqual(list(self.scratch.iterdir()), [])
            with self.assertRaises(ProcessLookupError):
                os.kill(int((self.root / "pid").read_text()), 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    def test_capture_cleanup_failure_cannot_emit_success(self):
        # Exercise the real main fence with an exception from its cleanup owner,
        # not a mocked success receipt or a source-text assertion.
        script = (
            "import importlib.util; from unittest.mock import patch; "
            "s=importlib.util.spec_from_file_location('w', " + repr(str(self.wrapper)) + "); "
            "w=importlib.util.module_from_spec(s); s.loader.exec_module(w); "
            "p=patch.object(w.tempfile.TemporaryDirectory, 'cleanup', "
            "side_effect=OSError('PRIVATE_CANARY')); p.start(); "
            "raise SystemExit(w.main(['workload']))"
        )
        (self.root / "kind").write_text("success")
        completed = subprocess.run(["/usr/bin/python3", "-c", script],
                                   capture_output=True, timeout=300)
        self.assert_public_failure((completed.returncode, completed.stdout, completed.stderr))


if __name__ == "__main__":
    unittest.main()
