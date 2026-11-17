#!/usr/bin/env python3
"""The local VM smoke isolation library (#5220), without KVM, a keyring or a
scope: a fake /proc and cgroup tree stand in for the scope's processes."""

import hashlib
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
LIBRARY = ROOT / "scripts/ci/verify/lib/local-smoke-isolation.sh"
UNIT = "cw-local-smoke-test1"
# Fake tools must be executable, and /tmp may be mounted noexec.
SCRATCH = ROOT / ".tmp"


def scratch_directory(test, prefix):
    SCRATCH.mkdir(exist_ok=True)
    scratch = tempfile.TemporaryDirectory(prefix=prefix, dir=SCRATCH)
    test.addCleanup(scratch.cleanup)
    return Path(scratch.name)


def bash(script, env=None, cwd=None):
    """Run SCRIPT after sourcing the library, with die defined as a smoke does."""
    prelude = 'set -euo pipefail\ndie() { echo "die: $*" >&2; exit 3; }\nsource "$1"\n'
    return subprocess.run(["bash", "-c", prelude + script, "test", str(LIBRARY)],
                          capture_output=True, text=True, env=env, cwd=cwd, timeout=60)


class Isolation(unittest.TestCase):
    def setUp(self):
        self.root = scratch_directory(self, "smoke-isolation-")
        self.home = self.root / "home"
        self.home.mkdir()

    def isolated(self, body, **variables):
        assignments = "".join(f'{name}="{value}"\n' for name, value in {
            "SMOKE_HOME": self.home, "SMOKE_RUNTIME": "/run/user/0/.cwls-abc123",
            "SMOKE_DBUS_ADDRESS": "unix:path=/run/user/0/.cwls-abc123/bus", **variables}.items())
        return bash(assignments + body, env={**os.environ, "CODEWIRE_SMOKE_SCOPE": UNIT})

    def test_an_environment_that_points_at_the_host_is_refused(self):
        uid = os.getuid()
        for variables in ({"SMOKE_HOME": os.environ["HOME"]},
                          {"SMOKE_RUNTIME": f"/run/user/{uid}"},
                          {"SMOKE_DBUS_ADDRESS": f"unix:path=/run/user/{uid}/bus"},
                          {"SMOKE_HOME": ""}):
            with self.subTest(variables=variables):
                result = self.isolated("smoke_refuse_host_leaks", **variables)
                self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(self.isolated("smoke_refuse_host_leaks").returncode, 0)

    def test_a_binary_runs_only_with_its_published_sha256(self):
        binary = self.root / "cw"
        binary.write_bytes(b"#!/bin/sh\n")
        binary.chmod(0o755)
        good = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.assertEqual(bash(f"smoke_require_sha256 {binary} {good}").returncode, 0)
        link = self.root / "cw-link"
        link.symlink_to(binary)
        for path, digest in ((binary, "0" * 64), (binary, good.upper()), (link, good),
                             (self.root / "absent", good)):
            with self.subTest(path=path, digest=digest):
                self.assertEqual(bash(f"smoke_require_sha256 {path} {digest}").returncode, 3)

    def fake_scope(self, processes):
        """A /proc and cgroup tree whose scope holds PROCESSES {pid: (argv, exe)}."""
        proc, cgroup = self.root / "proc", self.root / "cgroup"
        group = f"/user.slice/user-1000.slice/user@1000.service/app.slice/{UNIT}.scope"
        (proc / "self").mkdir(parents=True)
        (proc / "self/cgroup").write_text(f"0::{group}\n")
        (cgroup / group.lstrip("/")).mkdir(parents=True)
        (cgroup / group.lstrip("/") / "cgroup.procs").write_text(
            "".join(f"{pid}\n" for pid in processes))
        for pid, (argv, exe) in processes.items():
            (proc / str(pid)).mkdir()
            (proc / str(pid) / "cmdline").write_bytes(b"".join(a.encode() + b"\0" for a in argv))
            (proc / str(pid) / "exe").symlink_to(exe)
        return f'SMOKE_PROC_ROOT="{proc}"\nSMOKE_CGROUP_ROOT="{cgroup}"\n'

    def test_the_credential_service_is_the_scopes_one_authority_for_this_home(self):
        cw_new, cw_old = self.root / "cw-new", self.root / "cw-old"
        for binary in (cw_new, cw_old):
            binary.write_bytes(b"")
        root = f"{self.home}/.codewire/credentials-v1"
        authority = ["cw", "__local-credential-authority", "--root", root]
        roots = self.fake_scope({
            11: (["cw", "__local-vm-supervisor", "--root", root], cw_new),
            12: (["cw", "__local-credential-authority", "--root", "/elsewhere"], cw_new),
            13: (authority, cw_new),
        })
        result = self.isolated(roots + "smoke_credential_service_pid")
        self.assertEqual((result.returncode, result.stdout), (0, "13\n"), result.stderr)
        self.assertEqual(self.isolated(
            roots + f"smoke_assert_credential_service_binary {cw_new}").returncode, 0)
        refused = self.isolated(roots + f"smoke_assert_credential_service_binary {cw_old}")
        self.assertEqual(refused.returncode, 3)
        self.assertIn("not " + str(cw_old), refused.stderr)

    def test_no_service_or_two_services_is_not_an_answer(self):
        root = f"{self.home}/.codewire/credentials-v1"
        authority = ["cw", "__local-credential-authority", "--root", root]
        for processes in ({}, {21: (authority, "/usr/bin/true"), 22: (authority, "/usr/bin/true")}):
            with self.subTest(processes=processes):
                self.root_reset()
                result = self.isolated(self.fake_scope(processes) + "smoke_credential_service_pid")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def root_reset(self):
        for name in ("proc", "cgroup"):
            path = self.root / name
            if path.exists():
                subprocess.run(["rm", "-rf", "--", str(path)], check=True)

    def test_scope_pids_belong_only_to_the_named_scope(self):
        roots = self.fake_scope({31: (["sleep"], "/usr/bin/sleep")})
        self.assertEqual(self.isolated(roots + "smoke_scope_pids").stdout, "31\n")
        other = bash(roots + "smoke_scope_pids",
                     env={**os.environ, "CODEWIRE_SMOKE_SCOPE": "cw-local-smoke-other"})
        self.assertNotEqual(other.returncode, 0)

    def test_scope_exec_runs_in_place_inside_its_scope_and_refuses_a_bad_unit(self):
        inside = self.isolated(f"smoke_scope_exec {UNIT} -- echo ran")
        self.assertEqual((inside.returncode, inside.stdout), (0, "ran\n"), inside.stderr)
        for unit in ("other-unit", "cw-local-smoke-UPPER", f"{UNIT} extra"):
            with self.subTest(unit=unit):
                self.assertEqual(self.isolated(f'smoke_scope_exec "{unit}" -- echo ran').returncode, 3)
        self.assertEqual(self.isolated(f"smoke_scope_exec {UNIT} echo ran").returncode, 3)


FAKE_BWRAP = r"""#!/bin/sh
# Records its arguments, masks nothing, applies --chdir as bwrap does, and
# runs what follows --.
: >"$LOG"
for arg in "$@"; do printf '%s\n' "$arg" >>"$LOG"; done
while [ "$1" != -- ]; do
  if [ "$1" = --chdir ]; then cd "$2" || exit 1; fi
  shift
done
shift
exec "$@"
"""


class Namespace(unittest.TestCase):
    """smoke_cw runs every command through the namespace and its self-check;
    a fake bwrap that masks nothing shows the self-check refusing (#5250)."""

    def setUp(self):
        self.root = scratch_directory(self, "smoke-namespace-")
        self.host_runtime = self.root / "host-run"
        self.host_home = self.root / "host-home"
        self.home = self.root / "home"
        self.workspace = self.root / "workspace"
        for directory in (self.host_runtime, self.host_home / ".ssh", self.host_home / ".codewire",
                          self.home, self.workspace):
            directory.mkdir(parents=True)
        # A socket needs a short path: the repository's may be long.
        sockets = tempfile.TemporaryDirectory(prefix="smk-")
        self.addCleanup(sockets.cleanup)
        self.runtime = Path(sockets.name)
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(self.runtime / "bus"))
        self.addCleanup(listener.close)
        self.bwrap = self.root / "bwrap"
        self.bwrap.write_text(FAKE_BWRAP)
        self.bwrap.chmod(0o755)
        self.log = self.root / "bwrap-args"

    def cw(self, command, env=None, address=None):
        assignments = (f'SMOKE_BWRAP="{self.bwrap}"\nSMOKE_HOST_RUNTIME="{self.host_runtime}"\n'
                       f'SMOKE_HOST_HOME="{self.host_home}"\nSMOKE_HOME="{self.home}"\n'
                       f'SMOKE_WORKSPACE="{self.workspace}"\nSMOKE_RUNTIME="{self.runtime}"\n'
                       f'SMOKE_DBUS_ADDRESS="{address or f"unix:path={self.runtime}/bus"}"\n')
        return bash(assignments + "smoke_cw " + command,
                    env={**os.environ, "LOG": str(self.log), **(env or {})})

    def test_the_namespace_masks_the_host_runtime_and_every_existing_home_store(self):
        result = self.cw("/usr/bin/true")
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.log.read_text().splitlines()
        def follows(flag, *values):
            return any(arguments[i:i + 1 + len(values)] == [flag, *values]
                       for i in range(len(arguments)))
        self.assertTrue(follows("--tmpfs", str(self.host_runtime)))
        self.assertTrue(follows("--bind", str(self.runtime), str(self.runtime)))
        self.assertTrue(follows("--tmpfs", str(self.host_home / ".ssh")))
        self.assertTrue(follows("--tmpfs", str(self.host_home / ".codewire")))
        self.assertFalse(follows("--tmpfs", str(self.host_home / ".config/codewire")),
                         "only directories that exist are masked")
        self.assertTrue(follows("--chdir", str(self.workspace)))
        self.assertLess(arguments.index("--tmpfs"), arguments.index("--bind"),
                        "the runtime is bound back in after the host's is masked")

    def test_cw_sees_only_the_smokes_environment_from_its_workspace(self):
        leaked = {"SSH_AUTH_SOCK": "/tmp/agent", "GITHUB_TOKEN": "ghp_synthetic",
                  "ANTHROPIC_API_KEY": "synthetic", "OPENAI_API_KEY": "synthetic",
                  "CODEX_HOME": "/tmp/codex", "SHELL_ONLY": "x"}
        result = self.cw("/usr/bin/env", env=leaked)
        self.assertEqual(result.returncode, 0, result.stderr)
        seen = dict(line.split("=", 1) for line in result.stdout.splitlines())
        for name in (*leaked, "LOG"):
            self.assertNotIn(name, seen)
        self.assertEqual(seen["HOME"], str(self.home))
        self.assertEqual(seen["XDG_RUNTIME_DIR"], str(self.runtime))
        self.assertEqual(seen["DBUS_SESSION_BUS_ADDRESS"], f"unix:path={self.runtime}/bus")
        self.assertEqual(seen["PATH"], "/usr/bin:/bin")
        self.assertEqual(self.cw("/bin/pwd").stdout, f"{self.workspace}\n")

    def test_the_self_check_refuses_a_namespace_that_leaves_the_host_reachable(self):
        (self.host_runtime / "bus").write_text("")
        result = self.cw("/usr/bin/echo ran")
        self.assertEqual((result.returncode, result.stdout), (125, ""))
        self.assertIn("the host bus is reachable", result.stderr)
        (self.host_runtime / "bus").unlink()
        (self.host_home / ".ssh" / "id_ed25519").write_text("synthetic")
        result = self.cw("/usr/bin/echo ran")
        self.assertEqual((result.returncode, result.stdout), (125, ""))
        self.assertIn(".ssh is not masked", result.stderr)
        (self.host_home / ".ssh" / "id_ed25519").unlink()
        result = self.cw("/usr/bin/echo ran", address=f"unix:path={self.host_runtime}/bus")
        self.assertEqual((result.returncode, result.stdout), (125, ""))
        self.assertIn("not the smoke's own", result.stderr)

    def test_the_library_never_calls_the_host_secret_service(self):
        source = LIBRARY.read_text()
        for call in ("org.freedesktop.Secret.Service", "SearchItems", "get-property",
                     "NameHasOwner", "secret-tool"):
            self.assertNotIn(call, source)


class RunInScope(unittest.TestCase):
    def setUp(self):
        self.root = scratch_directory(self, "smoke-run-in-scope-")
        self.log = self.root / "calls"
        for name, body in (("systemd-run", 'echo "run $*" >>"$LOG"\n'
                                           'while [ "$1" != -- ]; do shift; done; shift\nexec "$@"\n'),
                           ("systemctl", 'echo "systemctl $*" >>"$LOG"\n')):
            tool = self.root / name
            tool.write_text("#!/bin/sh\n" + body)
            tool.chmod(0o755)

    def run_script(self, status, scope=None):
        script = (f'SMOKE_SYSTEMD_RUN="{self.root}/systemd-run"\n'
                  f'SMOKE_SYSTEMCTL="{self.root}/systemctl"\n'
                  f'if [ -z "${{CODEWIRE_SMOKE_SCOPE:-}}" ]; then\n'
                  f'  smoke_run_in_scope case1 -- bash -c "echo inside \\$CODEWIRE_SMOKE_SCOPE; exit {status}"\n'
                  f'fi\necho went-on\n')
        env = {**os.environ, "LOG": str(self.log)}
        env.pop("CODEWIRE_SMOKE_SCOPE", None)
        if scope:
            env["CODEWIRE_SMOKE_SCOPE"] = scope
        return bash(script, env=env)

    def test_outside_a_scope_the_script_runs_inside_one_and_the_scope_is_stopped(self):
        for status in (0, 7):
            with self.subTest(status=status):
                self.log.unlink(missing_ok=True)
                result = self.run_script(status)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertRegex(result.stdout, r"^inside cw-local-smoke-case1[0-9]+\n$")
                unit = result.stdout.split()[1]
                calls = self.log.read_text().splitlines()
                self.assertIn(f"--expand-environment=no --unit={unit}", calls[0])
                self.assertEqual(calls[1], f"systemctl --user stop {unit}.scope")

    def test_inside_a_scope_the_script_goes_on(self):
        result = self.run_script(0, scope="cw-local-smoke-case1123")
        self.assertEqual((result.returncode, result.stdout), (0, "went-on\n"), result.stderr)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
