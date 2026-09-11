#!/usr/bin/env python3
"""Synthetic only: actual harness/wrapper, absolute fake Docker, no provider IO."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("cache_probes", ROOT / "scripts/ci/verify/workspace-cache-probes.py")
probes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probes)
PIN = "docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5"

FAKE_DOCKER = r'''#!/usr/bin/python3
import hashlib, json, os, re, signal, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
root = Path(os.environ["FAKE_STATE"])
report = Path(os.environ["FAKE_REPORT"])
failure = os.environ.get("FAKE_FAILURE", "")
with (root / "calls.jsonl").open("a") as stream:
    stream.write(json.dumps(args) + "\n")
def option(name):
    return args[args.index(name) + 1]
def states():
    return [json.loads(p.read_text()) for p in root.glob("*.state")]
def save(state):
    (root / (state["container"] + ".state")).write_text(json.dumps(state))
def selected(value):
    matches = [s for s in states() if value in (s["builder"], s["container"], "buildx_buildkit_" + s["builder"] + "-node")]
    assert len(matches) == 1, (value, matches)
    return matches[0]
def nonce():
    return json.loads((report / "identity.json").read_text())["nonce"]
def export_log():
    print("#8 exporting cache to Amazon S3\n#8 DONE 0.1s")
def write_output(name, value):
    match = re.search(r"(?:^|,)dest=([^,]+)", option("--output"))
    path = Path(match[1])
    output = path / name
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(value)
    return output
if args[:2] == ["buildx", "create"]:
    builder = option("--name")
    container = hashlib.sha256(builder.encode()).hexdigest()
    save({"builder": builder, "container": container, "removed": False, "credential": False})
elif args[:2] == ["buildx", "inspect"]:
    selected(args[2])
elif args[:2] == ["container", "inspect"]:
    state = selected(args[2])
    fmt = option("--format")
    if fmt == "{{.Id}}":
        print(state["container"])
    elif fmt == "{{.Config.Image}}":
        print(os.environ["FAKE_PIN"])
    else:
        assert fmt == "{{json .Mounts}}"
        print(json.dumps([{"Type":"volume", "Destination":"/var/lib/buildkit",
                          "Name":"buildx_buildkit_" + state["builder"].lower() + "-node_state"}]))
elif args[:2] == ["exec", "--interactive"]:
    state = selected(args[2])
    projected = sys.stdin.buffer.read()
    original = Path(os.environ["FAKE_ORIGINAL_CREDENTIAL"]).read_bytes()
    state["credential"] = "original" if projected == original else "synthetic"
    save(state)
elif args[0] == "exec" and args[2:4] == ["rm", "-f"]:
    state = selected(args[1])
    state["credential"] = False
    save(state)
elif args[:2] == ["buildx", "rm"]:
    state = selected(args[-1])
    assert not state["credential"]
    state["removed"] = True
    save(state)
elif args[:2] == ["info", "--format"]:
    print("daemon-probe-worker")
elif args[:2] == ["container", "ls"]:
    if failure == "observer":
        raise SystemExit(71)
    for state in states():
        if not state["removed"]:
            print(state["container"])
elif args[:2] == ["volume", "ls"]:
    for state in states():
        if not state["removed"]:
            print("buildx_buildkit_" + state["builder"].lower() + "-node_state")
elif args[:2] == ["buildx", "ls"]:
    for state in states():
        if not state["removed"]:
            print(state["builder"])
elif args[:2] == ["buildx", "build"]:
    state = selected(option("--builder"))
    phase = next(p for p in ("native-cold", "native-warm", "native-malformed", "native-missing-blob",
                            "native-denied", "cw-control", "cw-edit", "tools", "cancel")
                 if "workspace-" + p + "." in state["builder"])
    if phase.startswith("native-"):
        cached = phase == "native-warm"
        if "--no-cache" not in args:
            client_key = Path(os.environ["AWS_SHARED_CREDENTIALS_FILE"])
            expected_key = "synthetic" if phase == "native-denied" else "original"
            assert state["credential"] == expected_key
            assert (client_key.read_bytes() == Path(os.environ["FAKE_ORIGINAL_CREDENTIAL"]).read_bytes()) \
                == (expected_key == "original")
            importer = option("--cache-from")
            print("#1 importing cache manifest from " + importer)
            if phase == "native-malformed":
                assert "manifests_prefix=blobs/,name=sha256:" in importer
                print("#1 ERROR: invalid character '\\x1f' looking for beginning of value")
            elif phase == "native-missing-blob":
                assert "blobs_prefix=blobs/probe-" + nonce() + "-missing/" in importer
                if failure != "masked-blob":
                    print("#1 ERROR: failed to load cache key: S3 GetObject NoSuchKey StatusCode: 404")
                    if failure == "native-timeout":
                        raise SystemExit(124)
                    raise SystemExit(51)
                cached = True
            elif phase == "native-denied":
                print("#1 ERROR: operation error S3: GetObject, https response error "
                      "StatusCode: 401, api error Unauthorized: Unauthorized")
                raise SystemExit(52)
        else:
            assert "--cache-from" not in args and "--cache-to" not in args
        print("#2 [1/1] COPY payload /payload")
        if cached and failure in ("lazy-native-hit", "wrong-lazy-native-hit"):
            observed = ("f" if failure == "lazy-native-hit" else "e") * 64
            print("#2 sha256:" + observed + " 0B / 8.39MB")
            print("#2 extracting sha256:" + observed + " 0.1s done")
            print("#2 DONE 0.2s")
        else:
            print("#2 CACHED" if cached else "#2 DONE 0.1s")
        write_output("payload", (Path(args[-1]) / "payload").read_bytes())
        if "--cache-to" in args:
            print("#8 exporting cache to Amazon S3\n#8 writing layer sha256:" + "f" * 64 + "\n#8 DONE 0.1s")
    elif phase.startswith("cw-"):
        assert option("--target") == "cw-builder"
        assert Path(option("--file")).resolve() == (Path(args[-1]) / "images/workspace/Dockerfile").resolve()
        assert option("--build-arg") == "CODEWIRE_SCCACHE_MODE=r2"
        print("#2 [cw-builder 1/1] RUN cargo build")
        if phase == "cw-edit" and failure == "cw-build":
            raise SystemExit(53)
        print("#2 CACHED" if phase == "cw-control" and failure != "control-miss" else "#2 DONE 0.1s")
        value = "cw 0.1.0" if phase == "cw-control" or failure == "stale-cw" else "codewire-cache-probe-" + nonce()
        binary = write_output("out/cw", ("#!/bin/sh\nprintf '%s\\n' '" + value + "'\n").encode())
        binary.chmod(0o755)
        export_log()
    elif phase == "tools":
        if "--metadata-file" in args:
            Path(option("--metadata-file")).write_text(json.dumps({"containerimage.digest":"sha256:" + "c" * 64}))
        else:
            assert option("--no-cache-filter") == "workspace-floating-tools"
            assert option("--build-context").endswith("@sha256:" + "c" * 64)
            print("#1 [workspace-floating-tools 1/2] RUN npm install\n#1 DONE 0.1s")
            print("#2 [workspace-floating-tools 2/2] RUN go install\n#2 DONE 0.1s")
            print("#3 [cw-builder 1/1] RUN cargo build\n#3 DONE 0.1s")
        export_log()
    else:
        print("#1 [1/1] RUN printf '%s\\n' 'CODEWIRE_CACHE_PROBE_READY=" + nonce() + "'; sleep 120")
        child = subprocess.Popen(["/usr/bin/sleep", "120"])
        (root / "cancel-child").write_text(str(child.pid))
        def stopped(number, frame):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            child.terminate()
            child.wait(timeout=3)
            raise SystemExit(143)
        signal.signal(signal.SIGTERM, stopped)
        signal.signal(signal.SIGINT, stopped)
        print("#1 0.1 CODEWIRE_CACHE_PROBE_READY=" + nonce(), flush=True)
        child.wait()
elif args[:2] == ["image", "inspect"]:
    print("sha256:" + "d" * 64)
elif args[0] == "run":
    assert all(state["removed"] and not state["credential"] for state in states())
    entry = option("--entrypoint")
    if entry == "bash":
        assert sys.stdin.read() == Path(os.environ["FAKE_CONTRACT"]).read_text()
        assert "--pids-limit=2048" in args
        if "--mounted-home-agents" in args:
            assert option("--tmpfs") == "/home/codewire:rw,exec,uid=1000,gid=1000,mode=0700,size=256m"
        if failure == "contract":
            raise SystemExit(41)
    elif entry == "cat":
        print("codewire-cache-probe-" + nonce())
    else:
        assert entry == "python3"
        sys.stdin.read()
        print(json.dumps({name:"synthetic 1" for name in ("npm","pnpm","yarn","bun","gopls","hcloud","poetry","uv","aider")}))
elif args[:2] == ["rm", "--force"]:
    pass
else:
    raise AssertionError(args)
'''


class ProbeFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="codewire-cache-probe-test-", dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.root = self.work / "source"
        self.root.mkdir()
        self.report = self.work / "report"
        self.credential = self.work / "codewire-sccache-r2.aws"
        self.credential.write_text("[default]\naws_access_key_id = synthetic-access\naws_secret_access_key = synthetic-secret\n")
        self.credential.chmod(0o600)

    def write(self, path, content):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def test_derivative_inventory_and_every_context_key_boundary(self):
        self.write(self.root / probes.MAIN, "fn main() {\n    run();\n}\n")
        self.write(self.root / probes.DOCKERFILE, (ROOT / probes.DOCKERFILE).read_text())
        archive = self.work / "source.tar"
        with tarfile.open(archive, "w") as output:
            for path in self.root.rglob("*"):
                output.add(path, arcname=path.relative_to(self.root), recursive=False)
        self.report.mkdir()
        probes.write(self.report / "identity.json", {"buildkit_image": PIN})
        derived = self.work / "derived"
        derived.mkdir()
        probes.derive(archive, derived, self.report, self.credential, "1" * 32)
        inventory = probes.read(self.report / "contexts.json")["inventories"]
        for name, expected in (("cw-edit", probes.MAIN), ("tools", probes.DOCKERFILE)):
            self.assertEqual([key for key in inventory["control"] if inventory["control"][key] != inventory[name][key]], [expected])
        for name in ("control", "cw-edit", "tools", "native", "cancel"):
            context = derived / "contexts" / name
            probes.private_key(self.credential, [context])
            key = context / "misplaced.aws"
            shutil.copy2(self.credential, key)
            with self.assertRaisesRegex(ValueError, "every source context"):
                probes.private_key(key, [context])
        link = self.work / "linked.aws"
        link.symlink_to(self.credential)
        with self.assertRaises(ValueError):
            probes.private_key(link, [self.root])

    def test_archive_escape_is_rejected(self):
        self.report.mkdir()
        probes.write(self.report / "identity.json", {"buildkit_image": PIN})
        archive = self.work / "source.tar"
        with tarfile.open(archive, "w") as output:
            entry = tarfile.TarInfo("../escape")
            entry.size = 1
            output.addfile(entry, io.BytesIO(b"x"))
        derived = self.work / "derived"
        derived.mkdir()
        with self.assertRaises(tarfile.TarError):
            probes.derive(archive, derived, self.report, self.credential, "1" * 32)
        self.assertFalse((self.work / "escape").exists())

    def test_readiness_requires_executed_output(self):
        log = self.work / "build.log"
        nonce = "a" * 32
        log.write_text("#1 [1/1] RUN echo CODEWIRE_CACHE_PROBE_READY=" + nonce + "\n")
        self.assertFalse(probes.ready(log, nonce))
        log.write_text("#1 0.1 CODEWIRE_CACHE_PROBE_READY=" + nonce + "\n")
        self.assertTrue(probes.ready(log, nonce))
        self.assertFalse(probes.ready(log, "b" * 32))

    def test_surviving_or_malformed_resource_observations_fail(self):
        directory = self.report / "native-cold"
        directory.mkdir(parents=True)
        owner = {"builder": "codewire-workspace-test", "container": "a" * 64, "volume": "owned-state"}
        probes.write(directory / "owner.json", owner)
        (directory / "docker-id").write_text("daemon-probe-worker\n")
        for name in ("containers", "volumes", "builders"):
            (directory / ("remaining-" + name)).write_text("")
        probes.cleaned(self.report, "native-cold")
        (directory / "remaining-containers").write_text("a" * 64 + "\n")
        with self.assertRaisesRegex(ValueError, "survived"):
            probes.cleaned(self.report, "native-cold")
        (directory / "remaining-containers").write_text("not an API observation\n")
        with self.assertRaisesRegex(ValueError, "malformed"):
            probes.cleaned(self.report, "native-cold")

    def test_discovered_volume_uses_observed_buildx_normalization(self):
        directory = self.report / "native-cold"
        directory.mkdir(parents=True)
        volume = "buildx_buildkit_codewire-workspace-native-cold.1ep1rb-node_state"
        probes.write(directory / "mounts.json", [{"Type": "volume", "Destination": "/var/lib/buildkit", "Name": volume}])
        with contextlib.redirect_stdout(io.StringIO()):
            probes.register(self.report, "native-cold", "codewire-workspace-native-cold.1eP1RB", "a" * 64)
        self.assertEqual(probes.read(directory / "owner.json")["volume"], volume)
        probes.write(directory / "mounts.json", [{"Type": "volume", "Destination": "/var/lib/buildkit", "Name": "unrelated"}])
        with self.assertRaisesRegex(ValueError, "exact owned"):
            probes.register(self.report, "native-cold", "codewire-workspace-native-cold.1eP1RB", "a" * 64)

    def test_actual_wrapper_replay_binds_observed_failure(self):
        self.report.mkdir()
        for index, (text, status, retried) in enumerate((
            ("ERROR: failed to build: failed to solve: failed to load cache: S3 GetObject NoSuchKey", 1, True),
            ("ERROR: failed to build: failed to solve: failed to load cache: S3 GetObject NoSuchKey", 51, False),
            ("ERROR: failed to build: failed to solve: failed to load cache: S3 GetObject NoSuchKey", 124, False),
            ("#1 ERROR: failed to import cache: S3 GetObject unavailable\nERROR: failed to build: failed to solve: process cargo failed", 1, False),
            ("ERROR S3 GetObject InvalidAccessKeyId", 1, False),
            ("ERROR invalid character during importing cache manifest", 0, False),
        )):
            directory = self.report / "native-missing-blob"
            directory.mkdir(exist_ok=True)
            (directory / "build.log").write_text(text)
            (directory / "status").write_text(str(status))
            work = self.work / str(index)
            work.mkdir()
            probes.replay(ROOT, self.report, "native-missing-blob", work, self.credential)
            value = probes.read(directory / "wrapper-replay.json")
            self.assertEqual(value["cold_retry"], retried)
            self.assertEqual(value["invocation_count"], 2 if retried else 1)
            self.assertEqual(value["input_log_sha256"], hashlib.sha256(text.encode()).hexdigest())

    def fixture_repository(self):
        paths = set(probes.artifact.INPUTS) | {
            probes.MAIN, probes.DOCKERFILE, "scripts/ci/images/workspace-cache.sh",
            "scripts/ci/tests/probe-workspace-r2-cache.sh", "scripts/ci/verify/workspace-cache-probes.py",
            "scripts/ci/setup/select-workspace-cache-experiment.py", "scripts/ci/verify/workspace-cache-report.py",
            "scripts/ci/verify/workspace-image-artifact.py", "scripts/ci/verify/workspace-agent-contract.sh"}
        for path in paths:
            self.write(self.root / path, (ROOT / path).read_text() if (ROOT / path).is_file() else "synthetic\n")
        for path in self.root.rglob("*.sh"):
            path.chmod(0o755)
        def git(*args):
            return subprocess.check_output(["git", "-C", str(self.root), *args], text=True, stderr=subprocess.DEVNULL).strip()
        git("init", "-q")
        git("add", ".")
        git("-c", "commit.gpgsign=false", "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid",
            "commit", "-qm", "synthetic fixture")
        source, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
        event = self.work / "event.json"
        probes.write(event, {"repository": {"full_name": "codewire/codewire"}, "pull_request": {
            "number": 2047, "base": {"ref": "main", "repo": {"full_name": "codewire/codewire"}},
            "head": {"ref": "experiment/workspace-r2-cache/fixture", "sha": source}, "labels": []}})
        fake = self.work / "docker"
        fake.write_text(FAKE_DOCKER)
        fake.chmod(0o700)
        state = self.work / "state"
        state.mkdir()
        identity = probes.artifact.source_identity(self.root)
        seed = {"schema_version": 1, "status": "passed", "case": "seed", "source_sha": source,
                "source_tree": tree, "cache_modes": {"compiler": "r2", "layers": "r2"},
                "seed_cache_id": "run-2047/tree-" + tree + "/seed-" + "1" * 64,
                "run_id": "2047", "architecture": identity["architecture"],
                "docker_daemon_id": "daemon-seed-worker", "pins": {
                    "buildkit_image": PIN,
                    "workspace_dockerfile_sha256": identity["inputs"][probes.DOCKERFILE]}}
        return {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                "CODEWIRE_EXPECTED_SOURCE_SHA": source, "CODEWIRE_EXPECTED_SOURCE_TREE": tree,
                "GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event),
                "GITHUB_REPOSITORY": "codewire/codewire", "GITHUB_REF": "refs/pull/2047/head",
                "GITHUB_SHA": source, "GITHUB_RUN_ID": "2047", "GITHUB_JOB": "workspace-cache-probes",
                "HOSTNAME": "fixture-job", "RUNNER_TEMP": str(self.work),
                "CODEWIRE_DOCKER_BIN": str(fake), "FAKE_STATE": str(state), "FAKE_REPORT": str(self.report),
                "FAKE_ORIGINAL_CREDENTIAL": str(self.credential),
                "FAKE_CONTRACT": str(self.root / "scripts/ci/verify/workspace-agent-contract.sh"),
                "FAKE_PIN": PIN, "CODEWIRE_SCCACHE_MODE": "r2", "CODEWIRE_BUILDKIT_CACHE_MODE": "r2",
                "SCCACHE_BUCKET": "example-ci-cache-untrusted",
                "SCCACHE_ENDPOINT": "https://00000000000000000000000000000000.r2.cloudflarestorage.com",
                "CODEWIRE_SCCACHE_PREFIX": "untrusted/codewire/v1",
                "AWS_SHARED_CREDENTIALS_FILE": str(self.credential), "AWS_PROFILE": "default",
                "AWS_EC2_METADATA_DISABLED": "true",
                "CODEWIRE_WORKSPACE_CACHE_SEED_REPORT": json.dumps(seed)}

    def run_harness(self, failure=""):
        environment = self.fixture_repository()
        environment["FAKE_FAILURE"] = failure
        process = subprocess.Popen(
            [str(self.root / "scripts/ci/tests/probe-workspace-r2-cache.sh"), str(self.credential), str(self.report)],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            output, _ = process.communicate(timeout=35)
        except subprocess.TimeoutExpired:
            # TERM the actual GNU timeout owner so it forwards cancellation and
            # lets the harness reap children; subprocess.run would KILL it first.
            process.terminate()
            output, _ = process.communicate(timeout=10)
            self.fail("synthetic probe timed out: " + output)
        completed = subprocess.CompletedProcess(process.args, process.returncode, output)
        (self.work / "harness.log").write_text(completed.stdout)
        states = [json.loads(path.read_text()) for path in (self.work / "state").glob("*.state")]
        self.assertTrue(states, completed.stdout)
        self.assertTrue(all(state["removed"] and not state["credential"] for state in states), completed.stdout)
        self.assertTrue(self.credential.is_file())
        self.assertEqual(subprocess.check_output(
            ["git", "-C", str(self.root), "status", "--porcelain", "--untracked-files=normal"], text=True), "")
        self.assertFalse((self.root / ".tmp/codewire-workspace-image-verification.json").exists())
        return completed, environment

    def test_complete_actual_harness_with_synthetic_docker_and_cancelled_child(self):
        completed, environment = self.run_harness()
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertFalse((self.report / "result.json").exists())
        with mock.patch.dict(os.environ, environment, clear=True), self.assertRaisesRegex(ValueError, "finisher"):
            probes.finalize(self.report)
        self.credential.unlink()
        with mock.patch.dict(os.environ, environment, clear=True), contextlib.redirect_stdout(io.StringIO()):
            probes.finalize(self.report)
        result = probes.read(self.report / "result.json")
        self.assertEqual([phase["phase"] for phase in result["phases"]], list(probes.PHASES))
        self.assertEqual(len({phase["owner"]["container"] for phase in result["phases"]}), 9)
        self.assertIn("actual expired OIDC rejection", result["remaining_live_gaps"])
        self.assertIn("induced network outage", result["remaining_live_gaps"])
        self.assertTrue(any("did not retry" in gap for gap in result["remaining_live_gaps"]))
        child = int((self.work / "state/cancel-child").read_text())
        try:
            state = Path(f"/proc/{child}/stat").read_text().split(") ", 1)[1].split()[0]
        except FileNotFoundError:
            pass
        else:
            # The host reaper may retain an already dead reparented descendant.
            # It cannot execute or access a credential; no live child may remain.
            self.assertEqual(state, "Z")
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch("builtins.print", side_effect=OSError("late output")):
            with self.assertRaises(OSError):
                probes.finalize(self.report)
        self.assertFalse((self.report / "result.json").exists())
        (self.report / "work-complete").unlink()
        with mock.patch.dict(os.environ, environment, clear=True), self.assertRaises(OSError):
            probes.finalize(self.report)
        self.assertFalse((self.report / "result.json").exists())

    def test_control_miss_is_inconclusive(self):
        completed, _ = self.run_harness("control-miss")
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse((self.report / "work-complete").exists())
        self.assertIn("expected executed/cached", completed.stdout)

    def test_exact_cold_blob_digest_is_accepted_as_native_warm_hit(self):
        completed, environment = self.run_harness("lazy-native-hit")
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.credential.unlink()
        with mock.patch.dict(os.environ, environment, clear=True), contextlib.redirect_stdout(io.StringIO()):
            probes.finalize(self.report)
        phases = {phase["phase"]: phase for phase in probes.read(self.report / "result.json")["phases"]}
        self.assertEqual(phases["native-warm"]["cache_observation"], "lazy-digest")

    def test_unrelated_lazy_digest_cannot_pass_as_native_warm_hit(self):
        completed, _ = self.run_harness("wrong-lazy-native-hit")
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse((self.report / "work-complete").exists())
        self.assertIn("expected executed/cached", completed.stdout)

    def test_stale_cw_cannot_pass(self):
        completed, _ = self.run_harness("stale-cw")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("stale/unexpected token", completed.stdout)

    def test_failed_cw_edit_build_restores_exact_checkout(self):
        completed, _ = self.run_harness("cw-build")
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertEqual((self.report / "cw-edit/status").read_text(), "53\n")
        self.assertFalse((self.report / "work-complete").exists())

    def test_locally_masked_missing_blob_cannot_pass(self):
        completed, _ = self.run_harness("masked-blob")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("fault category was not observed", completed.stdout)

    def test_native_timeout_is_not_recovered_or_accepted(self):
        completed, _ = self.run_harness("native-timeout")
        self.assertEqual(completed.returncode, 124)
        directory = self.report / "native-missing-blob"
        self.assertFalse((directory / "recovery-status").exists())
        self.assertFalse((self.report / "work-complete").exists())
        self.assertFalse((self.report / "result.json").exists())

    def test_native_timeout_signal_and_invocation_statuses_cannot_pass_report_validation(self):
        directory = self.report / "native-denied"
        directory.mkdir(parents=True)
        probes.write(self.report / "identity.json", {})
        owner = {"builder": "codewire-workspace-test", "container": "a" * 64, "volume": "owned-state"}
        probes.write(directory / "owner.json", owner)
        probes.write(directory / "cleanup.json", {"status": "removed", "docker_daemon_id": "daemon-test", **owner})
        (directory / "build.log").write_text("ERROR S3 GetObject InvalidAccessKeyId StatusCode: 403")
        (directory / "recovery-status").write_text("0\n")
        for status in (-1, 124, 125, 126, 127, 128, 130, 137, 143, 255):
            with self.subTest(status=status):
                (directory / "status").write_text(str(status))
                with self.assertRaisesRegex(ValueError, "timeout, interruption or invocation"):
                    probes.check_phase(self.report, "native-denied")
                self.assertFalse((directory / "result.json").exists())

    def test_cleanup_observer_failure_has_no_success_marker(self):
        completed, _ = self.run_harness("observer")
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse((self.report / "work-complete").exists())
        self.assertFalse((self.report / "result.json").exists())

    def test_contract_failure_has_no_normal_or_probe_receipt(self):
        completed, _ = self.run_harness("contract")
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse((self.report / "work-complete").exists())


class WorkflowContract(unittest.TestCase):
    def test_opt_in_dag_and_existing_authority_are_preserved(self):
        workflow = (ROOT / ".gitea/workflows/ci.yaml").read_text()
        body = workflow.split("\n  workspace-cache-probes:\n", 1)[1].split("\n  required-verification:", 1)[0]
        self.assertIn("    name: Opt-in workspace cache experiment probes\n", body)
        request = (
            "always() && needs.verification-selection.result == 'success' && "
            "needs.verification-selection.outputs.workspace_cache_experiment == 'true' && "
            "needs.workspace-cache-measurement.result == 'success' && "
            "((contains(needs.verification-selection.outputs.selection, '|kind|') && "
            "needs.kind-workspace.result == 'success' && needs.kind-workspace.outputs.workspace_cache_seed != '') || "
            "(!contains(needs.verification-selection.outputs.selection, '|kind|') && "
            "needs.workspace-image.result == 'success' && needs.workspace-image.outputs.workspace_cache_seed != ''))")
        self.assertEqual([line for line in body.splitlines() if line.startswith("    if: ")],
                         ["    if: " + chr(36) + "{{ " + request + " }}"])
        self.assertIn("needs.workspace-cache-measurement.result == 'success'", body)
        self.assertIn("workspace_cache_experiment == 'true'", body)
        self.assertIn("    needs: [verification-selection, workspace-image, kind-workspace, workspace-cache-measurement]", body)
        self.assertIn("    runs-on: ci-heavy\n", body)
        self.assertIn("    timeout-minutes: 55\n", body)
        self.assertNotIn("continue-on-error", body)
        self.assertEqual(body.count("run: scripts/ci/setup/select-untrusted-workspace-cache.sh "), 1)
        self.assertLess(body.index("Clean probe cache credential"), body.index("Finalize separate cache probe report"))
        self.assertIn("        if: " + chr(36) + "{{ always() }}", body)
        self.assertIn("          persist-credentials: false", body)
        for owner in ("kind-workspace", "workspace-image"):
            self.assertIn(f"needs.{owner}.result == 'success' && needs.{owner}.outputs.workspace_cache_seed != ''", body)
        ordinary = workflow.split("\n  required-verification:\n", 1)[1]
        dependencies = ordinary.split("    needs:\n", 1)[1].split("    steps:\n", 1)[0]
        self.assertEqual([line.strip().removeprefix("- ") for line in dependencies.splitlines()],
                         ["verification-selection", "cw-release-assets", "workspace-image", "policy", "standard",
                          "tooling", "rust-transport", "database", "services-control", "services-runtime", "edge-kind"])
        harness = (ROOT / "scripts/ci/tests/probe-workspace-r2-cache.sh").read_text()
        self.assertIn("--kill-after=150s 2700s", harness)
        self.assertIn('--file "$context/images/workspace/Dockerfile" --target cw-builder', harness)
        self.assertNotIn("cw-cache-probe-result", harness)
        self.assertNotIn('artifact_tool" seal', harness)
        self.assertNotIn("--push", harness)


if __name__ == "__main__":
    unittest.main()
