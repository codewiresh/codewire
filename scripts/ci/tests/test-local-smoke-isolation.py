#!/usr/bin/env python3
"""The local VM smoke isolation library (#5220), without KVM, a keyring or a
scope: a fake /proc and cgroup tree stand in for the scope's processes."""

import hashlib
import os
from pathlib import Path
import shlex
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


# Fakes for the privileged namespace: each records its arguments in LOG (a
# path written into it, since the namespace shells start with no environment)
# and hands on what follows its options, so the real setup and self-check
# run, with no mount made and no privilege taken.
# Records only the options before --, then runs what follows.
OPTIONS = ('options=""\nwhile [ "$1" != -- ]; do options="$options $1"; shift; done\nshift\n'
           'echo "TOOL$options" >>"LOG"\nexec "$@"\n')
FAKE_TOOLS = {
    "sudo": 'echo "sudo $1" >>"LOG"\n[ "$1" = -n ] && shift\nexec "$@"\n',
    "unshare": OPTIONS.replace("TOOL", "unshare"),
    "mount": 'echo "mount $*" >>"LOG"\n',
    "setpriv": OPTIONS.replace("TOOL", "setpriv"),
}


class Namespace(unittest.TestCase):
    """smoke_cw runs every command through the mount namespace and its
    self-check; fakes that mask nothing show the self-check refusing."""

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
        # The capabilities the self-check reads: a fake setpriv drops none, and
        # CI may run these tests as root.
        self.proc = self.root / "proc"
        (self.proc / "self").mkdir(parents=True)
        self.status(0)
        self.log = self.root / "calls"
        for name, body in FAKE_TOOLS.items():
            tool = self.root / name
            tool.write_text("#!/bin/sh\n" + body.replace('"LOG"', f'"{self.log}"'))
            tool.chmod(0o755)

    def status(self, capabilities):
        (self.proc / "self" / "status").write_text(
            f"Uid:\t{os.getuid()}\nCapEff:\t{capabilities:016x}\n")

    def variables(self, address=None):
        return (f'SMOKE_SUDO="{self.root}/sudo"\nSMOKE_UNSHARE="{self.root}/unshare"\n'
                f'SMOKE_PROC_ROOT="{self.proc}"\n'
                f'SMOKE_MOUNT="{self.root}/mount"\nSMOKE_SETPRIV="{self.root}/setpriv"\n'
                f'SMOKE_HOST_RUNTIME="{self.host_runtime}"\nSMOKE_HOST_HOME="{self.host_home}"\n'
                f'SMOKE_HOME="{self.home}"\nSMOKE_WORKSPACE="{self.workspace}"\n'
                f'SMOKE_RUNTIME="{self.runtime}"\n'
                f'SMOKE_DBUS_ADDRESS="{address or f"unix:path={self.runtime}/bus"}"\n')

    def cw(self, command, env=None, address=None):
        self.log.unlink(missing_ok=True)
        return bash(self.variables(address) + "smoke_cw " + command,
                    env={**os.environ, "LOG": str(self.log), **(env or {})})

    def test_root_only_masks_binds_and_drops_to_the_user_with_no_capabilities(self):
        result = self.cw("/usr/bin/true")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.log.read_text().splitlines()
        uid, gid = os.getuid(), os.getgid()
        self.assertEqual(calls[:2], ["sudo -n", "unshare --mount --propagation private"])
        self.assertEqual(calls[2:-1], [
            f"mount --bind {self.runtime} /mnt",
            f"mount -t tmpfs -o mode=0700,uid={uid},gid={gid} tmpfs {self.host_runtime}",
            f"mount --move /mnt {self.runtime}",
            f"mount -t tmpfs -o mode=0700,uid={uid},gid={gid} tmpfs {self.host_home}/.ssh",
            f"mount -t tmpfs -o mode=0700,uid={uid},gid={gid} tmpfs {self.host_home}/.codewire",
        ], "only directories that exist are masked, after the runtime is moved back in")
        self.assertEqual(calls[-1],
            f"setpriv --reuid={uid} --regid={gid} --init-groups --inh-caps=-all --bounding-set=-all")

    def test_the_namespace_shells_read_no_startup_file(self):
        source = LIBRARY.read_text()
        self.assertEqual(source.count("/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash --norc --noprofile -c"), 2)

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

    def extra(self, *entries):
        return (f'SMOKE_ROOT="{self.root}"\n'
                f"SMOKE_EXTRA_ENVIRONMENT=({' '.join(shlex.quote(e) for e in entries)})\n")

    def test_cw_sees_the_smokes_extra_variables_and_its_own_path(self):
        self.log.unlink(missing_ok=True)
        result = bash(self.variables() + self.extra(
            f"PATH={self.root}/bin:/usr/bin:/bin", f"CW_CONFIG_DIR={self.root}/c",
            "CODEWIRE_SERVER_URL=http://127.0.0.1:1", "NO_PROXY=127.0.0.1,localhost",
            "CODEWIRE_API_KEY=synthetic-platform-key") +
            "smoke_cw /usr/bin/env", env={**os.environ, "LOG": str(self.log)})
        self.assertEqual(result.returncode, 0, result.stderr)
        seen = [line.split("=", 1) for line in result.stdout.splitlines()]
        self.assertEqual([value for name, value in seen if name == "PATH"],
                         [f"{self.root}/bin:/usr/bin:/bin"], "one PATH, the smoke's")
        seen = dict(seen)
        self.assertEqual(seen["CW_CONFIG_DIR"], f"{self.root}/c")
        self.assertEqual(seen["CODEWIRE_SERVER_URL"], "http://127.0.0.1:1")
        self.assertEqual(seen["NO_PROXY"], "127.0.0.1,localhost")
        self.assertEqual(seen["HOME"], str(self.home))

    def test_extra_variables_that_leave_the_smoke_are_refused_before_root(self):
        for entries in (["GITHUB_TOKEN=synthetic"], ["SSH_AUTH_SOCK=/tmp/agent"],
                        [f"HOME={self.host_home}"], ["XDG_RUNTIME_DIR=/run/user/0"],
                        ["CW_CONFIG_DIR"], ["TERM=dumb", "TERM=xterm"],
                        ["PATH=/usr/local/bin:/usr/bin:/bin"], [f"PATH={self.root}/../bin:/usr/bin"],
                        ["PATH=/usr/bin:"], ["CODEWIRE_SERVER_URL=https://api.example.invalid"],
                        ["HTTPS_PROXY=http://192.0.2.1:3128"], ["ALL_PROXY=http://127.0.0.1:1/x"],
                        ["CODEWIRE_API_KEY=cw_live_not_a_placeholder"], ["CODEWIRE_API_KEY="],
                        [f"CW_CONFIG_DIR={self.host_runtime}/c"],
                        [f"CW_CONFIG_DIR={self.host_home}/.config/cw"], ["CW_CONFIG_DIR=/var/tmp/c"],
                        [f"CW_CONFIG_DIR={self.root}/../c"],
                        ["CODEWIRE_NATIVE_STATE_ROOT=/var/tmp/state"],
                        [f"CODEWIRE_NATIVE_STATE_ROOT={self.root}/../state"],
                        ["CODEWIRE_NATIVE_ARTIFACT_ROOT=/var/tmp/artifacts"],
                        ["CODEWIRE_NATIVE_ARTIFACT_LOCK=/var/tmp/artifacts.lock.json"],
                        ["CODEWIRE_LOCAL_CREDENTIAL_ROOT=/var/tmp/credentials-v1"],
                        [f"CODEWIRE_LOCAL_CREDENTIAL_ROOT={self.host_home}/.codewire/credentials-v1"]):
            with self.subTest(entries=entries):
                self.log.unlink(missing_ok=True)
                result = bash(self.variables() + self.extra(*entries) + "smoke_cw /usr/bin/echo ran",
                              env={**os.environ, "LOG": str(self.log)})
                self.assertEqual((result.returncode, result.stdout), (3, ""), result.stderr)
                self.assertFalse(self.log.exists(), "nothing ran as root")

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
        (self.host_home / ".config" / "cw").mkdir(parents=True)
        (self.host_home / ".config" / "cw" / "credentials.json").write_text("{}")
        result = self.cw("/usr/bin/echo ran")
        self.assertEqual((result.returncode, result.stdout), (125, ""))
        self.assertIn(".config/cw is not masked", result.stderr)
        (self.host_home / ".config" / "cw" / "credentials.json").unlink()
        result = self.cw("/usr/bin/echo ran", address=f"unix:path={self.host_runtime}/bus")
        self.assertEqual((result.returncode, result.stdout), (125, ""))
        self.assertIn("not the smoke's own", result.stderr)

    def test_the_self_check_refuses_remaining_capabilities(self):
        self.status(1 << 21)
        result = self.cw("/usr/bin/echo ran")
        self.assertEqual((result.returncode, result.stdout), (125, ""))
        self.assertIn("capabilities remain", result.stderr)

    def test_the_self_check_refuses_another_user(self):
        script = (self.variables() + 'bash --norc --noprofile -c "$SMOKE_SELF_CHECK" check '
                  f'{os.getuid() + 1} {os.getgid()} "{self.proc}/self/status" '
                  '"$SMOKE_HOST_RUNTIME" "$SMOKE_RUNTIME" '
                  '"$SMOKE_DBUS_ADDRESS" "$SMOKE_HOST_HOME" "" /etc/resolv.conf '
                  '--environment PATH=/usr/bin:/bin -- /usr/bin/echo ran')
        result = bash(script)
        self.assertEqual((result.returncode, result.stdout), (125, ""))
        self.assertIn("not the invoking user", result.stderr)

    def resolver(self, target_is_the_smokes):
        """The variables for a smoke that chose a resolver file, and that file.
        The namespace's own configuration is a link, as a host's often is; the
        fake mount binds nothing, so the test says whether the link already
        leads to the smoke's file."""
        resolver = self.root / "resolv.conf"
        resolver.write_text("nameserver 192.0.2.1\n")
        hosts = self.root / "host-resolv.conf"
        hosts.write_text("nameserver 127.0.0.53\n")
        link = self.root / "etc-resolv.conf"
        link.unlink(missing_ok=True)
        link.symlink_to(resolver if target_is_the_smokes else hosts)
        return (f'SMOKE_ROOT="{self.root}"\nSMOKE_RESOLVER="{resolver}"\n'
                f'SMOKE_RESOLVER_TARGET="{link}"\n'), resolver, hosts

    def test_a_chosen_resolver_is_bound_over_the_namespaces_own_and_checked(self):
        variables, resolver, hosts = self.resolver(target_is_the_smokes=False)
        self.log.unlink(missing_ok=True)
        result = bash(self.variables() + variables + "smoke_cw /usr/bin/echo ran",
                      env={**os.environ, "LOG": str(self.log)})
        # Root binds the file over what the link leads to, after the masks.
        calls = self.log.read_text().splitlines()
        self.assertEqual(calls[-2], f"mount --bind {resolver} {hosts}")
        # The fake bound nothing, so the command must not run on the host's resolver.
        self.assertEqual((result.returncode, result.stdout), (125, ""))
        self.assertIn("the resolver is not the smoke's own", result.stderr)
        variables, _, _ = self.resolver(target_is_the_smokes=True)
        result = bash(self.variables() + variables + "smoke_cw /usr/bin/echo ran",
                      env={**os.environ, "LOG": str(self.log)})
        self.assertEqual((result.returncode, result.stdout), (0, "ran\n"), result.stderr)

    def test_a_resolver_outside_the_smoke_root_or_a_link_is_refused_before_root(self):
        variables, resolver, hosts = self.resolver(target_is_the_smokes=True)
        elsewhere = tempfile.TemporaryDirectory(prefix="smk-")
        self.addCleanup(elsewhere.cleanup)
        outside = Path(elsewhere.name)
        (outside / "resolv.conf").write_text("nameserver 192.0.2.1\n")
        link = self.root / "linked-resolv.conf"
        link.symlink_to(resolver)
        for chosen in (outside / "resolv.conf", link, self.root / "missing"):
            with self.subTest(chosen=chosen):
                self.log.unlink(missing_ok=True)
                result = bash(self.variables() + variables + f'SMOKE_RESOLVER="{chosen}"\n'
                              "smoke_cw /usr/bin/echo ran",
                              env={**os.environ, "LOG": str(self.log)})
                self.assertEqual((result.returncode, result.stdout), (3, ""))
                self.assertIn("SMOKE_RESOLVER must be a regular file in the smoke root", result.stderr)
                self.assertFalse(self.log.exists(), "nothing ran as root")

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


class Runner(unittest.TestCase):
    """The Part A runner's arguments are closed before anything is made."""

    RUNNER = ROOT / "scripts/ci/verify/smoke-local-credentials.sh"

    def test_bad_arguments_are_refused_before_a_scope_or_root(self):
        scratch = scratch_directory(self, "smoke-runner-")
        for argv, status in (([], 1), (["--cw"], 2), (["--unknown"], 2),
                             (["--cw", "relative/cw", "--scratch", str(scratch)], 1),
                             (["--cw", "/usr/bin/true", "--scratch", "relative"], 1),
                             (["--cw", "/usr/bin/true", "--cw", "/usr/bin/true"], 2),
                             (["--cw", "/usr/bin/true", "--cw-sha256", "0" * 64,
                               "--scratch", str(scratch)], 1)):
            with self.subTest(argv=argv):
                result = subprocess.run([str(self.RUNNER), *argv], capture_output=True, text=True,
                                        timeout=30, env={**os.environ, "CODEWIRE_SMOKE_SCOPE": ""})
                self.assertEqual(result.returncode, status, result.stderr)
        self.assertEqual(list(scratch.iterdir()), [])

    def failed_run(self, status):
        """A run that ends with STATUS, its private root holding a home, a
        keyring and a credential store."""
        scratch = scratch_directory(self, "smoke-runner-")
        root = scratch / "smoke-local-credentials.test"
        for store in ("home/.local/share/keyrings", "home/.codewire/credentials-v1"):
            (root / store).mkdir(parents=True)
        (root / "home/.local/share/keyrings/login.keyring").write_text("synthetic-private-keyring")
        (root / "home/.codewire/credentials-v1/key").write_text("synthetic-private-key")
        (root / "cw.log").write_text("$ cw create\nsynthetic cw output\n")
        script = (f'source "{self.RUNNER}"\n'
                  'smoke_isolation_end() { return 0; }\nsmoke_cw() { return 0; }\n'
                  f'SCRATCH="{scratch}"\nSMOKE_DIR="{root}"\nLOG="{root}/cw.log"\nCW=/usr/bin/true\n'
                  f'trap cleanup EXIT\nexit {status}\n')
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        return scratch, result

    def test_a_failed_run_keeps_only_its_log_and_never_the_private_root(self):
        scratch, result = self.failed_run(1)
        self.assertEqual(result.returncode, 1, result.stderr)
        kept = list(scratch.iterdir())
        self.assertEqual(len(kept), 1, kept)
        self.assertTrue(kept[0].name.endswith(".log"))
        self.assertEqual(kept[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(kept[0].read_text(), "$ cw create\nsynthetic cw output\n")
        self.assertIn(str(kept[0]), result.stderr)

    def test_a_passing_run_keeps_nothing(self):
        scratch, result = self.failed_run(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(scratch.iterdir()), [])


FAKE_ATTACH = """#!/usr/bin/python3 -I
import os, subprocess, tty
print("Detach: Ctrl-B, then d", flush=True)
tty.setraw(0)
line = b""
while not line.endswith(b"\\r"):
    line += os.read(0, 1)
if os.environ["FAKE_SHELL"] == "live":
    shown = subprocess.run(["bash", "-c", line[:-1].decode()], capture_output=True).stdout
    os.write(1, shown.replace(b"\\n", b"\\r\\n"))
keys = b""
while not keys.endswith(b"\\x02d"):
    keys += os.read(0, 1)
os.write(1, b"Detached from vm/s; it keeps running.\\r\\n")
"""


class Attach(unittest.TestCase):
    """The runner attaches through a terminal: it types once cw shows how to
    detach, and passes only when a live shell printed the marker and cw
    detached."""

    def attach(self, shell):
        scratch = scratch_directory(self, "smoke-attach-")
        fake = scratch / "cw"
        fake.write_text(FAKE_ATTACH)
        fake.chmod(0o755)
        code = subprocess.run(["bash", "-c", 'source "$1"; printf %s "$PTY_ATTACH"', "test", str(Runner.RUNNER)],
                              capture_output=True, text=True, check=True, timeout=30).stdout
        return subprocess.run(["python3", "-I", "-c", code, "echo signed-$((2 + 3))", "signed-5",
                               str(fake), "--local", "attach", "vm", "--session", "s"],
                              capture_output=True, text=True, timeout=60,
                              env={**os.environ, "FAKE_SHELL": shell, "SMOKE_ATTACH_SECONDS": "5"})

    def test_a_live_shell_that_prints_the_marker_passes_and_detaches(self):
        result = self.attach("live")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("signed-5", result.stdout)
        self.assertIn("Detached from vm/s", result.stdout)

    def test_a_shell_that_never_answers_fails_at_the_deadline(self):
        result = self.attach("dead")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("signed-5", result.stdout)


class ProxyDown(unittest.TestCase):
    """smoke-proxy-down kills exactly this VM's helper of the cw under test, and
    judges the guest's probe lines as the journey says."""

    def setUp(self):
        self.root = scratch_directory(self, "smoke-proxy-down-")

    def runner(self, body):
        script = f'source "{Runner.RUNNER}"\n' + body
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                              env={**os.environ, "CODEWIRE_SMOKE_SCOPE": UNIT})

    def test_role_pids_finds_only_the_cw_under_tests_helper_for_this_environment(self):
        cw, other = self.root / "cw", self.root / "cw-other"
        for binary in (cw, other):
            binary.write_bytes(b"")
        egress = "__native-egress-broker"
        roots = Isolation.fake_scope(self, {
            41: ([str(cw), egress, "--environment-id", "env-a"], cw),
            42: ([str(cw), egress, "--environment-id", "env-b"], cw),
            43: ([str(other), egress, "--environment-id", "env-a"], other),
            44: ([str(cw), "__local-credential-broker", "--authority-fd", "3"], cw),
        })
        for query, found in ((f"{egress} env-a", "41\n"), ("__local-credential-broker", "44\n"),
                             (f"{egress} env-c", "")):
            with self.subTest(query=query):
                result = self.runner(roots + f'CW="{cw}"\nrole_pids {query}')
                self.assertEqual(result.stdout, found, result.stderr)

    def kill_target(self, cgroup_of_target):
        """A real process standing in for a helper, seen through a fake /proc
        whose scope holds it; CGROUP_OF_TARGET is what its own cgroup file says."""
        cw = self.root / "cw"
        cw.write_bytes(b"")
        target = subprocess.Popen(["sleep", "60"])
        self.addCleanup(lambda: (target.kill(), target.wait()))
        roots = Isolation.fake_scope(self, {target.pid: (
            [str(cw), "__native-egress-broker", "--environment-id", "env-a"], cw)})
        (self.root / "proc" / str(target.pid) / "cgroup").write_text(cgroup_of_target)
        log = self.root / "log"
        script = (roots + f'CW="{cw}"\nLOG="{log}"\n'
                  'kill_role smoke-proxy-down __native-egress-broker env-a')
        return target, self.runner(script)

    def test_kill_role_kills_the_matched_process_through_its_pidfd(self):
        scope = f"0::/user.slice/user-1000.slice/user@1000.service/app.slice/{UNIT}.scope\n"
        target, result = self.kill_target(scope)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith(f"{target.pid} "), result.stdout)
        self.assertEqual(target.wait(timeout=10), -9)

    def test_kill_role_refuses_a_process_no_longer_in_the_scope(self):
        target, result = self.kill_target("0::/user.slice/elsewhere.scope\n")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("could not be killed as matched", result.stderr)
        self.assertIsNone(target.poll())

    def judge(self, check, lines, killed="100.0", offset="0"):
        probes = self.root / "probes"
        probes.write_text("".join(f"{line}\n" for line in lines))
        return self.runner(f'{check} "{probes}" {killed} {offset}').returncode

    def test_the_agent_mends_when_it_answers_after_the_kill_and_never_fails_late(self):
        before, gap, back = "99.5 200 301 0", "100.1 200 301 2", "100.4 200 301 0"
        self.assertEqual(self.judge("agent_mended", [before, gap, back, "104.9 200 301 0"]), 0)
        self.assertNotEqual(self.judge("agent_mended", [before, gap, back, "105.2 200 301 2"]), 0)
        self.assertNotEqual(self.judge("agent_mended", [before, gap, "103.0 200 301 2"]), 0)

    def test_egress_is_closed_only_when_five_later_probes_got_no_answer_either_way(self):
        within_a_second = "100.5 200 301 0"
        closed = [f"{100 + second}.2 000 000 0" for second in range(1, 6)]
        self.assertEqual(self.judge("egress_closed", [within_a_second, *closed]), 0)
        self.assertNotEqual(self.judge("egress_closed", [*closed, "106.2 200 000 0"]), 0)
        self.assertNotEqual(self.judge("egress_closed", [*closed, "106.2 000 301 0"]), 0)
        self.assertNotEqual(self.judge("egress_closed", [within_a_second, *closed[:4]]), 0)

    def test_guest_times_are_shifted_into_the_hosts_clock(self):
        # The guest leads by 3 s: guest 103.4 is host 100.4, inside the first
        # second after the kill, so its answer does not count against egress.
        early = "103.4 200 301 0"
        closed = [f"{103 + second}.2 000 000 0" for second in range(1, 6)]
        self.assertEqual(self.judge("egress_closed", [early, *closed], offset="3"), 0)
        self.assertNotEqual(self.judge("egress_closed", [early, *closed], offset="0"), 0)
        # Guest 106.0 is host 103.0, under five seconds after the kill.
        late_by_guest = ["103.2 200 301 0", "106.0 200 301 2", "106.5 200 301 0"]
        self.assertEqual(self.judge("agent_mended", late_by_guest, offset="3"), 0)
        self.assertNotEqual(self.judge("agent_mended", late_by_guest, offset="0"), 0)

    def test_the_offset_comes_from_the_narrowest_measurement(self):
        samples = "10.0 13.9 12.0\n20.0 23.3 20.4\n30.0 33.5 31.0\n"
        result = subprocess.run(["bash", "-c", f'source "{Runner.RUNNER}"\nnarrowest_offset'],
                                input=samples, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.stdout, "3.100000 0.200000\n", result.stderr)

if __name__ == "__main__":
    unittest.main()
