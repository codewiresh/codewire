#!/usr/bin/env python3
"""Focused developer helper tests; synthetic files/processes, no SSH or Cargo."""

import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("macos_cli", Path(__file__).with_name("macos-cli.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

# Bounds a child Python run so a hang fails instead of stalling the run. It is
# never the expected duration: those runs take well under a second, and a slow
# CI slot can stall a process for many seconds (main run 24762).
HANG = 300


class HelperTests(unittest.TestCase):
    def test_owned_mount_fixture_synthetic_contract(self):
        contract = Path(__file__).resolve().parents[2] / "crates/codewire-local-vmm/src/darwin/path/test_mount_fixture.py"
        result = subprocess.run([sys.executable, str(contract), "-v"], capture_output=True, text=True, timeout=HANG)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Ran 8 tests", result.stderr)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cw-macos-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def repo(self):
        repo = self.root / "repo"
        repo.mkdir()
        for argv in (["init", "-q"], ["config", "user.name", "Fixture"],
                     ["config", "user.email", "fixture@example.invalid"],
                     ["config", "commit.gpgsign", "false"]):
            subprocess.run(["git", *argv], cwd=repo, check=True)
        (repo / "tracked").write_text("old")
        (repo / ".gitignore").write_text(".env\n")
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        # The inherited-signer fixture must also join automatic maintenance.
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
                        "-c", "maintenance.autoDetach=false", "-c", "gc.autoDetach=false",
                        "commit", "-qm", "fixture"], cwd=repo, check=True)
        return repo

    def test_working_bytes_staged_added_deleted_and_private_exclusions(self):
        repo = self.repo()
        (repo / "tracked").write_text("edited")
        (repo / "new").write_text("staged")
        (repo / "new").chmod(0o755)
        (repo / "link").symlink_to("new")
        subprocess.run(["git", "add", "new", "link"], cwd=repo, check=True)
        (repo / "new").write_text("edited after staging")
        (repo / ".env").write_text("synthetic-secret")
        (repo / "untracked").write_text("synthetic-secret")
        (repo / ".gitignore").unlink()
        archive = self.root / "source.tgz"
        first = helper.source_archive(repo, archive)
        with tarfile.open(archive) as source:
            self.assertEqual(set(source.getnames()), {"tracked", "new", "link"})
            self.assertEqual(source.extractfile("new").read(), b"edited after staging")
            self.assertEqual(source.getmember("new").mode, 0o755)
            self.assertTrue(source.getmember("link").issym())
        self.assertEqual(first, helper.source_archive(repo, archive))
        (repo / "tracked").write_text("changed again")
        self.assertNotEqual(first["source_sha256"], helper.source_archive(repo, archive)["source_sha256"])

    def test_synthetic_git_commits_do_not_invoke_inherited_signer(self):
        # /bin/false is a non-secret synthetic signer. Even an inherited
        # command-scope signing request must not reach it in either fixture
        # commit. This does not alter signing policy in the real checkout.
        with mock.patch.dict(os.environ, {
            "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "commit.gpgsign",
            "GIT_CONFIG_VALUE_0": "true", "GIT_CONFIG_KEY_1": "gpg.program",
            "GIT_CONFIG_VALUE_1": "/bin/false",
        }):
            self.test_git_seed_exports_objects_not_hooks_or_config()
        signature = helper.output(["git", "log", "-1", "--format=%G?"], cwd=self.root / "repo")
        self.assertEqual(signature, "N")

    def test_escaping_source_symlink_rejected(self):
        repo = self.repo()
        (repo / "tracked").unlink()
        (repo / "tracked").symlink_to("../outside")
        with self.assertRaisesRegex(ValueError, "escapes"):
            helper.source_archive(repo, self.root / "source.tgz")

    def test_conflict_and_gitlink_rejected(self):
        repo = self.repo()
        for metadata in (b"100644 deadbeef 2\ttracked\0", b"160000 deadbeef 0\tsubmodule\0"):
            with mock.patch.object(subprocess, "check_output", return_value=metadata):
                with self.assertRaisesRegex(ValueError, "unmerged.*submodule"):
                    helper.source_archive(repo, self.root / "source.tgz")

    def test_extraction_rejects_traversal_devices_and_link_parent(self):
        cases = [[("../outside", None)], [("/outside", None)], [(".git/config", None)],
                 [("link", "../outside")], [("link", "inside"), ("link/child", None)]]
        for index, entries in enumerate(cases):
            archive_path = self.root / f"bad-{index}.tar"
            with tarfile.open(archive_path, "w") as archive:
                for name, link in entries:
                    entry = tarfile.TarInfo(name)
                    if link:
                        entry.type, entry.linkname = tarfile.SYMTYPE, link
                    archive.addfile(entry, io.BytesIO(b""))
            destination = self.root / f"out-{index}"
            destination.mkdir()
            with self.assertRaises(ValueError):
                helper.extract(archive_path, destination, links=True)
        for kind in (tarfile.CHRTYPE, tarfile.LNKTYPE):
            archive_path = self.root / "device.tar"
            with tarfile.open(archive_path, "w") as archive:
                entry = tarfile.TarInfo("device")
                entry.type = kind
                archive.addfile(entry)
            with self.assertRaises(ValueError):
                helper.extract(archive_path, self.root / "unused")

    def test_sync_removes_stale_paths_preserves_unchanged_mtime(self):
        source, staged = self.root / "source", self.root / "staged"
        source.mkdir()
        staged.mkdir()
        for directory in (source, staged):
            (directory / "same").write_text("same")
        original = (source / "same").stat().st_mtime_ns
        (source / "gone").write_text("old")
        (source / "old-dir").mkdir()
        (source / "old-dir/file").write_text("old")
        (staged / "new").write_text("new")
        (staged / "link").symlink_to("new")
        helper.sync_source(staged, source)
        self.assertEqual((source / "same").stat().st_mtime_ns, original)
        self.assertEqual({path.name for path in source.iterdir()}, {"same", "new", "link"})
        self.assertEqual(os.readlink(source / "link"), "new")

    def test_seed_selects_locked_archives_checksums_and_index_only(self):
        cargo = self.root / "cargo"
        relative = f"registry/cache/{helper.REGISTRY}/fixture-1.0.0.crate"
        crate = cargo / relative
        crate.parent.mkdir(parents=True)
        crate.write_bytes(b"public fixture")
        (crate.parent / "private-1.0.0.crate").write_text("synthetic-secret")
        (cargo / "credentials.toml").write_text("synthetic-secret")
        index = cargo / f"registry/index/{helper.REGISTRY}/.cache/fi/xt/fixture"
        index.parent.mkdir(parents=True)
        index.write_bytes(b"public index")
        lock = ('[[package]]\nname="fixture"\nversion="1.0.0"\n'
                'source="registry+https://github.com/rust-lang/crates.io-index"\n'
                f'checksum="{helper.digest(crate)}"\n').encode()
        archive = self.root / "seed.tar.gz"
        self.assertEqual(helper.seed_archive(lock, cargo, archive), [])
        with tarfile.open(archive) as source:
            self.assertEqual(set(source.getnames()), {relative, str(index.relative_to(cargo)),
                f"registry/index/{helper.REGISTRY}/config.json", "git.json"})
        crate.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            helper.seed_archive(lock, cargo, archive)
        crate.unlink()
        self.assertEqual(helper.seed_archive(lock, cargo, archive), ["fixture-1.0.0"])

    def test_git_seed_exports_objects_not_hooks_or_config(self):
        repo = self.repo()
        commit = helper.output(["git", "rev-parse", "HEAD"], cwd=repo)
        cargo = self.root / "cargo"
        database = cargo / "git/db/connect-rust-fixture"
        database.parent.mkdir(parents=True)
        subprocess.run(["git", "clone", "--bare", "-q", str(repo), str(database)], check=True)
        (database / "hooks/secret").write_text("synthetic-secret")
        (repo / "tracked").write_text("synthetic private replacement")
        subprocess.run(["git", "add", "tracked"], cwd=repo, check=True)
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
                        "-c", "maintenance.autoDetach=false", "-c", "gc.autoDetach=false",
                        "commit", "-qm", "replacement"], cwd=repo, check=True)
        replacement = helper.output(["git", "rev-parse", "HEAD"], cwd=repo)
        subprocess.run(["git", f"--git-dir={database}", "-c", "maintenance.autoDetach=false",
                        "-c", "gc.autoDetach=false", "fetch", "-q", str(repo), replacement], check=True)
        subprocess.run(["git", f"--git-dir={database}", "replace", commit, replacement], check=True)
        lock = ('[[package]]\nname="fixture"\nversion="1.0.0"\n'
                f'source="git+https://github.com/connectrpc/connect-rust.git?rev={commit}#{commit}"\n').encode()
        archive = self.root / "seed.tar.gz"
        with mock.patch.dict(os.environ, {"GIT_OBJECT_DIRECTORY": "/nonexistent/synthetic-override",
                                         "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/nonexistent/synthetic-alternates"}):
            helper.seed_archive(lock, cargo, archive)
        destination = self.root / "seed"
        destination.mkdir()
        helper.extract(archive, destination)
        with tarfile.open(archive) as source:
            self.assertEqual(set(source.getnames()), {"packs/connect-rust-fixture.pack", "git.json",
                f"registry/index/{helper.REGISTRY}/config.json"})
        clean_cargo = self.root / "clean-cargo"
        helper.import_git_seeds(destination, clean_cargo, lambda argv: subprocess.run(
            argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        bare = clean_cargo / "git/db/connect-rust-fixture"
        self.assertEqual(helper.output(["git", f"--git-dir={bare}", "show", f"{commit}:tracked"]), "old")
        self.assertNotEqual(subprocess.run(["git", f"--git-dir={bare}", "cat-file", "-e", replacement],
                                          stderr=subprocess.DEVNULL).returncode, 0)
        (database / "objects/info/alternates").write_text(str(repo / ".git/objects"))
        with self.assertRaisesRegex(ValueError, "alternates"):
            helper.seed_archive(lock, cargo, archive)

    def test_overlap_fails_without_stealing_lock(self):
        with helper.cache_lock(self.root):
            with self.assertRaisesRegex(RuntimeError, "another developer build"):
                with helper.cache_lock(self.root):
                    self.fail("overlap acquired lock")
        with helper.cache_lock(self.root):
            pass

    def test_persistent_symlinks_are_not_followed_or_deleted(self):
        outside = self.root / "unrelated"
        outside.mkdir()
        protected = outside / "keep"
        protected.write_text("synthetic unrelated content")
        staged = self.root / "staged"
        staged.mkdir()
        for name in ("source", "cargo", "target"):
            path = self.root / name
            path.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "symlink"):
                helper.owned_directory(path)
        with self.assertRaisesRegex(ValueError, "symlink"):
            helper.sync_source(staged, self.root / "source")
        (self.root / "lock").symlink_to(protected)
        with self.assertRaises(OSError):
            with helper.cache_lock(self.root):
                self.fail("followed symlinked lock")
        self.assertEqual(protected.read_text(), "synthetic unrelated content")

    def test_command_failure_and_deadline_propagate(self):
        cancel = threading.Event()
        self.assertEqual(helper.run_command([sys.executable, "-c", "raise SystemExit(7)"],
            self.root, os.environ.copy(), self.root / "failure.log", cancel, time.monotonic() + 5), 7)
        self.assertEqual(helper.run_command([sys.executable, "-c", "import time; time.sleep(20)"],
            self.root, os.environ.copy(), self.root / "timeout.log", cancel, time.monotonic() + .2), 124)

    def test_natural_failure_does_not_require_signalling_an_exited_group(self):
        def absent_only(pid, signum):
            self.assertEqual(signum, 0, "must not signal an already reaped leader")
            raise ProcessLookupError

        with mock.patch.object(helper.os, "killpg", side_effect=absent_only):
            self.assertEqual(helper.run_command([sys.executable, "-c", "raise SystemExit(7)"],
                self.root, os.environ.copy(), self.root / "natural-failure.log", threading.Event(),
                time.monotonic() + 5), 7)

    def test_cleanup_does_not_escalate_after_term_reaps_leader(self):
        process = mock.Mock(pid=4242, returncode=None)

        def poll():
            if process.poll.call_count == 1:
                return None
            process.returncode = -signal.SIGTERM
            return process.returncode

        process.poll.side_effect = poll

        def signal_group(pid, signum):
            self.assertEqual(pid, 4242)
            self.assertNotEqual(signum, signal.SIGKILL)
            if signum == 0:
                raise ProcessLookupError

        with mock.patch.object(helper.os, "killpg", side_effect=signal_group):
            helper.stop_group(process)

    def test_cleanup_refuses_reaped_visible_or_unobservable_groups(self):
        for observation in (None, PermissionError(), OSError("synthetic observation failure")):
            with self.subTest(observation=type(observation).__name__):
                process = mock.Mock(pid=4242, returncode=0)
                process.poll.return_value = 0

                def observe(pid, signum):
                    self.assertEqual(signum, 0)
                    if observation is not None:
                        raise observation

                with mock.patch.object(helper.command_owner, "STOP_SECONDS", 0), \
                     mock.patch.object(helper.os, "killpg", side_effect=observe):
                    with self.assertRaises(helper.CleanupUnknown):
                        helper.stop_group(process)

    def test_cleanup_escalates_only_while_leader_remains_owned(self):
        process = mock.Mock(pid=4242, returncode=None)
        process.poll.side_effect = lambda: process.returncode
        signals = []

        def observe(pid, signum):
            if signum:
                signals.append(signum)
                if signum == signal.SIGKILL:
                    process.returncode = -signal.SIGKILL
            elif process.returncode is not None:
                raise ProcessLookupError

        with mock.patch.object(helper.command_owner, "STOP_SECONDS", 0), \
             mock.patch.object(helper.os, "killpg", side_effect=observe):
            helper.stop_group(process)
        self.assertEqual(signals, [signal.SIGTERM, signal.SIGKILL])

    def test_unknown_wait_never_authorizes_a_signal(self):
        process = mock.Mock(pid=4242, returncode=None)
        process.poll.side_effect = ChildProcessError("synthetic ECHILD")
        with mock.patch.object(helper.subprocess, "Popen", return_value=process), \
             mock.patch.object(helper.os, "killpg") as signal_group:
            with self.assertRaises(helper.CleanupUnknown):
                helper.run_command(["synthetic"], self.root, {}, self.root / "unknown.log",
                                   threading.Event(), time.monotonic() + 5)
            signal_group.assert_not_called()

    def test_command_resets_inherited_sigchld_autoreap(self):
        previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            result = helper.run_command([sys.executable, "-c", "raise SystemExit(7)"],
                self.root, os.environ.copy(), self.root / "autoreap.log", threading.Event(),
                time.monotonic() + 5)
            self.assertEqual(result, 7)
            self.assertEqual(signal.getsignal(signal.SIGCHLD), signal.SIG_DFL)
        finally:
            signal.signal(signal.SIGCHLD, previous)

    def test_unknown_cleanup_retains_runtime_and_blocks_cache_reuse(self):
        with helper.cache_lock(self.root):
            with self.assertRaises(helper.CleanupUnknown):
                with helper.isolated_runtime(self.root, self.root / "fixture-run") as runtime:
                    self.addCleanup(helper.shutil.rmtree, runtime)
                    (runtime / "keep").write_bytes(b"synthetic retained state")
                    marker = json.loads((self.root / "inflight.json").read_text())
                    self.assertEqual(marker["isolated_state"], str(runtime))
                    self.assertEqual(marker["run_id"], "fixture-run")
                    self.assertEqual((self.root / "inflight.json").stat().st_mode & 0o777, 0o600)
                    raise helper.CleanupUnknown("synthetic uncertainty; no process launched")
        self.assertEqual((runtime / "keep").read_bytes(), b"synthetic retained state")
        with self.assertRaisesRegex(RuntimeError, "cleanup is unconfirmed"):
            with helper.cache_lock(self.root):
                self.fail("unconfirmed state was reused")

    def test_confirmed_command_failure_removes_runtime_and_marker(self):
        with helper.cache_lock(self.root):
            with self.assertRaisesRegex(RuntimeError, "ordinary failure"):
                with helper.isolated_runtime(self.root, self.root / "fixture-run") as runtime:
                    raise RuntimeError("ordinary failure; no command remains")
        self.assertFalse(runtime.exists())
        self.assertFalse((self.root / "inflight.json").exists())
        with helper.cache_lock(self.root):
            pass

    def test_confirmed_cleanup_removes_read_only_test_leftovers(self):
        with helper.cache_lock(self.root):
            with helper.isolated_runtime(self.root, self.root / "fixture-run") as runtime:
                # A managed release store leaves read-only version directories.
                version = runtime / "tmp/store/versions/synthetic"
                version.mkdir(parents=True)
                (version / "identity.json").write_bytes(b"{}")
                version.chmod(0o555)
        self.assertFalse(runtime.exists())
        self.assertFalse((self.root / "inflight.json").exists())

    def test_cancel_kills_fixture_grandchild(self):
        cancel = threading.Event()
        marker = self.root / "escaped"
        ready = self.root / "grandchild-ready"
        child = (f"import time; from pathlib import Path; Path({str(ready)!r}).touch(); "
                 f"time.sleep(1); Path({str(marker)!r}).touch()")
        # TERM reaches both processes. The fixture parent must reap its own
        # child before exiting, not rely on the runner's PID 1 orphan reaper.
        parent = f'''import signal, subprocess, sys, time
cancelled = False
def stop(signum, frame):
    global cancelled
    cancelled = True
signal.signal(signal.SIGTERM, stop)
child = subprocess.Popen([sys.executable, '-c', {child!r}])
deadline = time.monotonic() + 20
while not cancelled and time.monotonic() < deadline:
    time.sleep(.01)
child.wait(timeout=2)
'''
        finished = threading.Event()

        def cancel_after_ready():
            deadline = time.monotonic() + 3
            while not ready.exists() and time.monotonic() < deadline:
                if finished.wait(.01):
                    return
            cancel.set()

        observer = threading.Thread(target=cancel_after_ready)
        observer.start()
        try:
            status = helper.run_command([sys.executable, "-c", parent], self.root, os.environ.copy(),
                                        self.root / "cancel.log", cancel, time.monotonic() + 5)
        finally:
            finished.set()
            observer.join()
        self.assertEqual(status, 130)
        self.assertTrue(ready.exists(), "cancellation must exercise a running grandchild")
        time.sleep(1)
        self.assertFalse(marker.exists())

    @unittest.skipUnless(sys.platform == "linux", "Linux orphan-reaper regression")
    def test_cancel_fixture_reaps_before_its_parent_exits(self):
        # A container's PID 1 need not promptly reap an orphan. Keep adoption
        # inside this disposable subprocess so the fixture cannot rely on it;
        # even an assertion failure reaps every adopted fixture child.
        probe = r'''
import ctypes, importlib.util, os, signal, sys, unittest
libc = ctypes.CDLL(None, use_errno=True)
assert libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER, this process only
signal.signal(signal.SIGCHLD, signal.SIG_DFL)
spec = importlib.util.spec_from_file_location("cancel_fixture", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
result = unittest.TestResult()
adopted = []
try:
    module.HelperTests("test_cancel_kills_fixture_grandchild").run(result)
finally:
    while True:
        try:
            child, status = os.waitpid(-1, 0)
        except ChildProcessError:
            break
        adopted.append(status)
assert result.wasSuccessful(), result.errors + result.failures
assert not adopted, "cancellation fixture orphaned a child"
print("cooperative cancellation: no adopted children")
'''
        result = subprocess.run([sys.executable, "-I", "-B", "-c", probe, __file__],
                                env={"PATH": os.defpath}, capture_output=True, text=True,
                                timeout=HANG)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "cooperative cancellation: no adopted children")

    def test_worker_failure_saves_evidence_not_success(self):
        run = self.root / "run"
        run.mkdir()
        (run / "request.json").write_text(json.dumps({"timeout": 10}))
        with mock.patch.object(sys, "stdin", io.StringIO("")), \
             mock.patch.object(signal, "signal"), \
             mock.patch.object(helper.platform, "system", return_value="Linux"):
            self.assertEqual(helper.worker(self.root, run), 1)
        result = json.loads((run / "result.json").read_text())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["commands"], [])
        self.assertEqual(result["artifacts"], {})

    def test_worker_unknown_cleanup_retains_state_and_refuses_next_sync(self):
        run = self.worker_fixture()
        with mock.patch.object(sys, "stdin", io.StringIO("")), \
             mock.patch.object(signal, "signal"), \
             mock.patch.object(helper.platform, "system", return_value="Darwin"), \
             mock.patch.object(helper.platform, "machine", return_value="arm64"), \
             mock.patch.object(helper, "output", return_value="fixture macOS"), \
             mock.patch.object(helper, "run_command", side_effect=helper.CleanupUnknown("fixture")):
            self.assertEqual(helper.worker(self.root, run), 1)
        result = json.loads((run / "result.json").read_text())
        runtime = Path(result["isolated_state"])
        self.addCleanup(helper.shutil.rmtree, runtime)
        self.assertTrue(runtime.is_dir())
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("exit_code", result["commands"][0])
        self.assertEqual(helper.evidence_status(run, "fixture"), "failed")
        following = self.root / "next-run"
        following.mkdir()
        (following / "request.json").write_bytes((run / "request.json").read_bytes())
        with mock.patch.object(sys, "stdin", io.StringIO("")), \
             mock.patch.object(signal, "signal"), \
             mock.patch.object(helper, "sync_source") as sync:
            self.assertEqual(helper.worker(self.root, following), 1)
            sync.assert_not_called()
        self.assertTrue((self.root / "inflight.json").is_file())
        self.assertEqual(json.loads((following / "result.json").read_text())["commands"], [])

    def worker_fixture(self, component="cli", action="verify"):
        run = self.root / "run"
        run.mkdir()
        request = {"run_id": "fixture", "source_sha256": "source", "lock_sha256": "lock",
                   "component": component,
                   "helper_sha256": "helper", "timeout": 10, "action": action, "intel": True}
        if component in helper.SWIFT_COMPONENTS:
            request["intel"] = False
        (run / "request.json").write_text(json.dumps(request))
        with tarfile.open(run / "source.tar.gz", "w:gz") as archive:
            helper.add_bytes(archive, "fixture", b"synthetic source")
        return run

    def test_worker_command_plan_and_artifact_collection(self):
        run = self.worker_fixture()
        reader, writer = os.pipe()
        stdin = os.fdopen(reader, "r")

        def fixture_command(argv, cwd, env, log, cancel, deadline):
            self.assertLess(len(env["TMPDIR"] + "fixture/test.sock"), 104)
            self.assertNotEqual(env["HOME"], str(Path.home()))
            log.write_text("fixture command, not actual macOS evidence")
            if argv[0] == "lipo":
                # -verify_arch consumes the remaining arguments as architectures;
                # placing the input after it fails on Apple's real lipo.
                self.assertTrue(Path(argv[1]).is_file())
                self.assertEqual(argv[2], "-verify_arch")
                self.assertIn(argv[3], ("arm64", "x86_64"))
            if argv[:2] == ["cargo", "build"]:
                target = argv[argv.index("--target") + 1]
                binary = Path(env["CARGO_TARGET_DIR"]) / target / "debug/cw"
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_bytes(b"synthetic Mach-O fixture")
            return 0

        try:
            with mock.patch.object(sys, "stdin", stdin), mock.patch.object(signal, "signal"), \
                 mock.patch.object(helper.platform, "system", return_value="Darwin"), \
                 mock.patch.object(helper.platform, "machine", return_value="arm64"), \
                 mock.patch.object(helper, "output", return_value="fixture macOS"), \
                 mock.patch.object(helper, "run_command", side_effect=fixture_command):
                self.assertEqual(helper.worker(self.root, run), 0)
        finally:
            os.close(writer)
            stdin.close()
        result = json.loads((run / "result.json").read_text())
        self.assertEqual(result["status"], "passed")
        commands = [item["argv"] for item in result["commands"]]
        self.assertIn(["python3", str(self.root / "source/crates/codewire-local-vmm/src/darwin/path/test_mount_fixture.py"), "-v"], commands)
        cargo = [argv for argv in commands if argv[0] == "cargo" and argv[1] != "-V"]
        self.assertEqual([argv[1] for argv in cargo],
                         ["build", "test", "test", "test", "test", "clippy", "clippy", "clippy", "build", "test"])
        self.assertEqual(cargo[2], ["cargo", "test", "--locked", "--offline", "--target",
                                   "aarch64-apple-darwin", "-p", "codewire-cw-release", "--",
                                   "--skip", "compiled_trust_is_an_exact_producer_and_artifact_graph_input"])
        self.assertEqual(cargo[1], ["cargo", "test", "--locked", "--offline", "--target",
                                   "aarch64-apple-darwin", "--no-fail-fast", "-p", "codewire-cli",
                                   "-p", "codewire-cli-bin"])
        self.assertEqual(cargo[3], ["cargo", "test", "--locked", "--offline", "--target",
                                   "aarch64-apple-darwin", "--no-fail-fast", "-p", "codewire-local-vmm",
                                   "--lib"])
        credential_crates = ["-p", "codewire-local-credentials", "-p", "codewire-credential-broker",
                             "--features", "codewire-credential-broker/ssh-agent"]
        self.assertEqual(cargo[4], ["cargo", "test", "--locked", "--offline", "--target",
                                   "aarch64-apple-darwin", "--no-fail-fast", *credential_crates, "--lib"])
        self.assertEqual(cargo[6], ["cargo", "clippy", "--locked", "--offline", "--target",
                                   "aarch64-apple-darwin", "-p", "codewire-local-vmm", "--lib", "--tests",
                                   "--", "-D", "warnings"])
        self.assertEqual(cargo[7], ["cargo", "clippy", "--locked", "--offline", "--target",
                                   "aarch64-apple-darwin", *credential_crates, "--all-targets",
                                   "--", "-D", "warnings"])
        self.assertEqual(cargo[9], ["cargo", "test", "--locked", "--offline", "--target",
                                   "x86_64-apple-darwin", "-p", "codewire-local-vmm", "--lib", "--no-run"])
        for argv in cargo:
            self.assertIn("--offline", argv)
            self.assertIn("--locked", argv)
            self.assertIn("--target", argv)
        self.assertTrue(all("x86_64" not in argv[0] for argv in commands))
        self.assertEqual(helper.evidence_status(run, "fixture"), "passed")
        self.assertFalse(Path(result["isolated_state"]).exists())

    def test_shared_native_library_failure_prevents_cli_test_success(self):
        self.check_native_library_failure("aarch64-apple-darwin")

    def test_intel_library_link_failure_prevents_cli_test_success(self):
        self.check_native_library_failure("x86_64-apple-darwin")

    def check_native_library_failure(self, target):
        run = self.worker_fixture(action="test")
        reader, writer = os.pipe()
        stdin = os.fdopen(reader, "r")

        def fixture_command(argv, cwd, env, log, cancel, deadline):
            log.write_text("synthetic shared-library failure")
            return 1 if "codewire-local-vmm" in argv and target in argv else 0

        try:
            with mock.patch.object(sys, "stdin", stdin), mock.patch.object(signal, "signal"), \
                 mock.patch.object(helper.platform, "system", return_value="Darwin"), \
                 mock.patch.object(helper.platform, "machine", return_value="arm64"), \
                 mock.patch.object(helper, "output", return_value="fixture macOS"), \
                 mock.patch.object(helper, "run_command", side_effect=fixture_command):
                self.assertEqual(helper.worker(self.root, run), 1)
        finally:
            os.close(writer)
            stdin.close()
        result = json.loads((run / "result.json").read_text())
        self.assertEqual(result["status"], "failed")
        failed = [item["argv"] for item in result["commands"] if item["exit_code"] != 0]
        self.assertEqual(len(failed), 1, failed)
        self.assertIn("codewire-local-vmm", failed[0])
        self.assertIn(target, failed[0])
        self.assertEqual(helper.evidence_status(run, "fixture"), "failed")
        if target == "aarch64-apple-darwin":
            # A failed suite does not hide the suites after it.
            self.assertIn("codewire-local-credentials", result["commands"][-1]["argv"])

    def test_vz_runner_worker_plan_and_artifact_collection(self):
        run = self.worker_fixture("vz-runner")
        reader, writer = os.pipe()
        stdin = os.fdopen(reader, "r")
        swiftc = self.root / "toolchain/usr/bin/swiftc"
        testing_plugin = self.root / "toolchain/usr/lib/swift/host/plugins/testing/libTestingMacros.dylib"
        swiftc.parent.mkdir(parents=True)
        testing_plugin.parent.mkdir(parents=True)
        swiftc.touch()
        testing_plugin.touch()

        def fixture_output(argv):
            return str(swiftc) if argv == ["xcrun", "--find", "swiftc"] else "fixture macOS"

        def fixture_command(argv, cwd, env, log, cancel, deadline):
            log.write_text("fixture command, not actual macOS evidence")
            if argv[:3] == ["xcrun", "swift", "build"]:
                scratch = Path(argv[argv.index("--scratch-path") + 1])
                binary = scratch / "debug/codewire-vz-runner"
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_bytes(b"synthetic Mach-O fixture")
            return 0

        try:
            with mock.patch.object(sys, "stdin", stdin), mock.patch.object(signal, "signal"), \
                 mock.patch.object(helper.platform, "system", return_value="Darwin"), \
                 mock.patch.object(helper.platform, "machine", return_value="arm64"), \
                 mock.patch.object(helper, "output", side_effect=fixture_output), \
                 mock.patch.object(helper, "run_command", side_effect=fixture_command):
                self.assertEqual(helper.worker(self.root, run), 0)
        finally:
            os.close(writer)
            stdin.close()
        result = json.loads((run / "result.json").read_text())
        commands = [item["argv"] for item in result["commands"]]
        self.assertEqual(commands[0][:2], ["xcrun", "swift"])
        self.assertEqual(commands[1][:2], ["xcrun", "--show-sdk-version"])
        self.assertEqual([argv[:2] for argv in commands[2:5]], [
            ["xcrun", "swift-format"], ["xcrun", "swift"], ["xcrun", "swift"],
        ])
        for argv in commands[3:5]:
            self.assertIn("-warnings-as-errors", argv)
            self.assertIn("-Werror", argv)
        self.assertNotIn("-load-plugin-library", commands[3])
        self.assertIn("-load-plugin-library", commands[4])
        self.assertTrue(commands[4][-1].endswith(
            "/lib/swift/host/plugins/testing/libTestingMacros.dylib"))
        self.assertNotIn("cargo", [argv[0] for argv in commands])
        self.assertEqual(set(result["artifacts"]), {"codewire-vz-runner-arm64"})
        self.assertEqual(helper.evidence_status(run, "fixture"), "passed")

    def test_vz_runner_build_does_not_require_testing_plugin(self):
        run = self.worker_fixture("vz-runner", "build")
        reader, writer = os.pipe()
        stdin = os.fdopen(reader, "r")

        def fixture_output(argv):
            self.assertNotEqual(argv, ["xcrun", "--find", "swiftc"])
            return "fixture macOS"

        def fixture_command(argv, cwd, env, log, cancel, deadline):
            log.write_text("fixture command, not actual macOS evidence")
            if argv[:3] == ["xcrun", "swift", "build"]:
                scratch = Path(argv[argv.index("--scratch-path") + 1])
                binary = scratch / "debug/codewire-vz-runner"
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_bytes(b"synthetic Mach-O fixture")
            return 0

        try:
            with mock.patch.object(sys, "stdin", stdin), mock.patch.object(signal, "signal"), \
                 mock.patch.object(helper.platform, "system", return_value="Darwin"), \
                 mock.patch.object(helper.platform, "machine", return_value="arm64"), \
                 mock.patch.object(helper, "output", side_effect=fixture_output), \
                 mock.patch.object(helper, "run_command", side_effect=fixture_command):
                self.assertEqual(helper.worker(self.root, run), 0)
        finally:
            os.close(writer)
            stdin.close()
        commands = [item["argv"] for item in json.loads((run / "result.json").read_text())["commands"]]
        self.assertIn(["xcrun", "swift", "build"], [argv[:3] for argv in commands])
        self.assertNotIn(["xcrun", "swift", "test"], [argv[:3] for argv in commands])

    def test_swift_components_reject_cargo_only_options_before_ssh(self):
        for component in ("vz-runner",):
            for option in (["--intel"], ["--seed-cargo"], ["--action", "clippy"]):
                stderr = io.StringIO()
                with self.subTest(component=component, option=option), \
                     mock.patch.object(sys, "argv", ["macos-cli.py", "--host", "user@mac.example.invalid",
                                                     "--component", component, *option]), \
                     mock.patch.object(helper, "ssh") as ssh, \
                     mock.patch.object(helper, "output") as output, \
                     contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as failure:
                        helper.main()
                    self.assertEqual(failure.exception.code, 2)
                    self.assertIn("Swift components accept", stderr.getvalue())
                    ssh.assert_not_called()
                    output.assert_not_called()

    def test_mac_destination_is_required_and_read_from_the_environment(self):
        environment = {key: value for key, value in os.environ.items() if key != "CODEWIRE_MAC_HOST"}
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, environment, clear=True), \
             mock.patch.object(sys, "argv", ["macos-cli.py"]), \
             mock.patch.object(helper, "ssh") as ssh, \
             mock.patch.object(helper, "output") as output, \
             contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as failure:
                helper.main()
        self.assertEqual(failure.exception.code, 2)
        self.assertIn("--host or CODEWIRE_MAC_HOST", stderr.getvalue())
        ssh.assert_not_called()
        output.assert_not_called()

        # The environment supplies the destination; validation still applies to it.
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"CODEWIRE_MAC_HOST": "-oProxyCommand=x"}), \
             mock.patch.object(sys, "argv", ["macos-cli.py"]), \
             mock.patch.object(helper, "ssh") as ssh, \
             mock.patch.object(helper, "output") as output, \
             contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as failure:
                helper.main()
        self.assertEqual(failure.exception.code, 2)
        self.assertIn("invalid SSH destination", stderr.getvalue())
        ssh.assert_not_called()

        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"CODEWIRE_MAC_HOST": "user@mac.example.invalid"}), \
             mock.patch.object(sys, "argv", ["macos-cli.py", "--component", "vz-runner", "--intel"]), \
             mock.patch.object(helper, "ssh") as ssh, \
             mock.patch.object(helper, "output") as output, \
             contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit):
                helper.main()
        self.assertIn("Swift components accept", stderr.getvalue())
        ssh.assert_not_called()

    def test_worker_stdin_eof_cancels_owned_command(self):
        run = self.worker_fixture()
        original = helper.run_command

        def sleeping_command(_argv, cwd, env, log, cancel, deadline):
            return original([sys.executable, "-c", "import time; time.sleep(20)"],
                            cwd, env, log, cancel, deadline)

        with mock.patch.object(sys, "stdin", io.StringIO("")), mock.patch.object(signal, "signal"), \
             mock.patch.object(helper.platform, "system", return_value="Darwin"), \
             mock.patch.object(helper.platform, "machine", return_value="arm64"), \
             mock.patch.object(helper, "output", return_value="fixture macOS"), \
             mock.patch.object(helper, "run_command", side_effect=sleeping_command):
            self.assertEqual(helper.worker(self.root, run), 1)
        result = json.loads((run / "result.json").read_text())
        self.assertEqual(result["commands"][0]["exit_code"], 130)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(Path(result["isolated_state"]).exists())

    def test_recover_only_evidence_and_can_refresh_partial_result(self):
        run = self.root / "remote-run"
        run.mkdir()
        (run / "artifacts").mkdir()
        (run / "artifacts/cw-aarch64-apple-darwin").write_bytes(b"fixture binary")
        (run / "request.json").write_text("{}")
        (run / "result.json").write_text('{"status":"running"}')
        (run / "command-00.log").write_text("actual command log")
        (run / "private.txt").write_text("synthetic-secret")
        (run / "command-link.log").symlink_to("private.txt")
        destination = self.root / "evidence"
        with mock.patch.object(helper, "ssh", side_effect=lambda _host, command, **kwargs:
                               subprocess.run(command, **kwargs)):
            helper.recover("unused", str(run), destination)
            self.assertEqual(json.loads((destination / "result.json").read_text())["status"], "running")
            (run / "result.json").write_text('{"status":"failed"}')
            helper.recover("unused", str(run), destination)
        self.assertEqual(json.loads((destination / "result.json").read_text())["status"], "failed")
        self.assertFalse((destination / "private.txt").exists())
        self.assertFalse((destination / "command-link.log").exists())
        self.assertEqual((destination / "artifacts/cw-aarch64-apple-darwin").read_bytes(), b"fixture binary")

    def test_evidence_missing_running_failed_mismatch_and_tampered_artifacts(self):
        request = {"run_id": "fixture", "source_sha256": "source", "lock_sha256": "lock",
                   "helper_sha256": "helper", "action": "build", "intel": False}
        with self.assertRaisesRegex(RuntimeError, "missing"):
            helper.evidence_status(self.root, "fixture")
        (self.root / "request.json").write_text(json.dumps(request))
        result_path = self.root / "result.json"
        for status in ("running", "failed"):
            result_path.write_text(json.dumps({**request, "status": status}))
            self.assertEqual(helper.evidence_status(self.root, "fixture"), status)
        with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
            helper.evidence_status(self.root, "other")
        artifact = self.root / "artifacts/cw-aarch64-apple-darwin"
        artifact.parent.mkdir()
        artifact.write_bytes(b"fixture binary")
        result = {**request, "status": "passed", "commands": [{"argv": ["fixture"], "exit_code": 0}],
                  "artifacts": {artifact.name: helper.digest(artifact)}}
        result_path.write_text(json.dumps(result))
        self.assertEqual(helper.evidence_status(self.root, "fixture"), "passed")
        artifact.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
            helper.evidence_status(self.root, "fixture")
        result["commands"][0]["exit_code"] = 1
        result_path.write_text(json.dumps(result))
        with self.assertRaisesRegex(RuntimeError, "successful command evidence"):
            helper.evidence_status(self.root, "fixture")


if __name__ == "__main__":
    unittest.main()
