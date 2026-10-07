#!/usr/bin/env python3
"""Hermetic developer consumers: saved endpoints, artifact and process ownership."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CONSUMERS = Path(os.environ.get("CODEWIRE_KIND_DEV_PROFILE_CONSUMERS_DIR", ROOT))
MAKEFILE_SOURCE = (ROOT / "Makefile").read_text()
IMAGE_ID = "sha256:" + "a" * 64
FAKE_CORE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
state = pathlib.Path(os.environ["FAKE_STATE"])
args = sys.argv[1:]
name = args[args.index("--cluster") + 1]
with (state / "calls").open("a") as log:
    log.write(json.dumps({"tool": "profile", "args": args}) + "\n")
if args[0] == "env":
    fields = json.loads((state / name / "fields.json").read_text())
    mode = os.environ.get("FAKE_FIELD_MODE", "")
    if mode == "failure":
        sys.stdout.buffer.write(b"KIND_CLUSTER_NAME\0dev-a\0")
        sys.exit(41)
    if mode == "unknown": fields.append(["PATH", "untrusted"])
    if mode == "duplicate": fields.append(["KIND_CLUSTER_NAME", name])
    if mode == "missing": fields = [p for p in fields if p[0] != "KUBECONFIG"]
    if mode == "wrong-binding":
        fields = [[k, "kind-other" if k == "KUBE_CONTEXT" else v] for k, v in fields]
    if mode == "missing-alias":
        fields = [pair for pair in fields if pair[0] != "KIND_INGRESS_HOST_PORT"]
    if mode == "conflicting-alias":
        fields = [[k, "31199" if k == "KIND_INGRESS_HOST_PORT" else v] for k, v in fields]
    if mode == "literal":
        fields = [[k, "$(touch " + str(state / "executed") + ")" if k == "KIND_PUBLIC_ORIGIN" else v] for k, v in fields]
    if mode == "odd":
        sys.stdout.buffer.write(b"KIND_PROFILE\0")
        sys.exit(0)
    for key, value in fields:
        sys.stdout.buffer.write(key.encode() + b"\0" + value.encode() + b"\0")
elif args[0] == "verify-node":
    sys.exit(int(os.environ.get("FAKE_NODE_STATUS", "0")))
elif args[0] == "verify-artifacts":
    sys.exit(int(os.environ.get("FAKE_ARTIFACT_STATUS", "0")))
else:
    sys.exit(64)
'''

FAKE_TOOL = r'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, sys
state = pathlib.Path(os.environ["FAKE_STATE"])
tool = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
entry = {"tool": tool, "args": args, "cluster": os.environ.get("KIND_CLUSTER_NAME"),
         "kubeconfig": os.environ.get("KUBECONFIG"), "smokes": os.environ.get("CARGO_CI_DIR"),
         "watch_addr": os.environ.get("CODEWIRE_DASHBOARD_LISTEN_ADDR")}
if tool == "docker" and args[:2] == ["buildx", "build"]:
    entry["dockerfile"] = sys.stdin.read()
with (state / "calls").open("a") as log: log.write(json.dumps(entry) + "\n")
if tool == "kind":
    if args == ["get", "clusters"]:
        print("dev-a\ndev-b\ncodewire-e2e-ci\ncodewire-ux-2099")
    elif args[:2] != ["load", "docker-image"]: sys.exit(64)
elif tool == "kubectl":
    if "get" in args:
        if "pods" in args: print("pod/old-one\npod/old-two")
        elif any(a.startswith("go-template=") for a in args): print("app=selected,")
        elif any("command[0]" in a for a in args): print("/codewire-kind-fixtures/credential-service")
        elif any("FRONTEND_URL" in a or "CREDENTIAL_PUBLIC_ORIGIN" in a for a in args):
            print(os.environ.get("KIND_PUBLIC_ORIGIN", "http://legacy-review:4174"))
        elif any("SANDBOX_GATEWAY_IMAGE" in a for a in args): print("codewire-gateway:e2e")
        elif any(a.startswith("jsonpath=") and a.endswith(".image}") for a in args):
            if os.environ.get("FAKE_SAME_IMAGE") == "1": print((state / "last-image").read_text())
            else: print("codewire-services:e2e")
    elif "set" in args or "rollout" in args or "wait" in args:
        if os.environ.get("FAKE_KUBE_FAIL") and os.environ["FAKE_KUBE_FAIL"] in args: sys.exit(29)
    else: sys.exit(64)
elif tool == "docker":
    aliases_path = state / "aliases.json"
    aliases = json.loads(aliases_path.read_text()) if aliases_path.exists() else {}
    if args[:2] == ["image", "inspect"]:
        ref = args[-1]
        if ref.startswith("sha256:"): identity = ref
        elif ref.endswith(":e2e"): identity = "sha256:" + "a" * 64
        elif ref in aliases: identity = aliases[ref]
        else: sys.exit(1)
        if "--format" in args:
            if args[args.index("--format") + 1] == "{{.Id}}": print(identity)
    elif args[0] == "tag":
        aliases[args[2]] = args[1]
        aliases_path.write_text(json.dumps(aliases))
    elif args[:2] == ["buildx", "bake"]:
        outputs = [args[i + 1] for i, arg in enumerate(args[:-1])
                   if arg == "--set" and args[i + 1].startswith("kind-dev-binary.output=")]
        if len(outputs) != 1: sys.exit(64)
        output = outputs[0]
        destination = pathlib.Path(output.split("dest=", 1)[1])
        binary = destination / os.environ["KIND_DEV_BIN"]
        binary.write_text(os.environ.get("FAKE_BINARY_CONTENT", "synthetic-current-source"))
        binary.chmod(0o755)
        if "kind-dev-binary.args.KIND_DEV_FIXTURE_FEATURES=enrollment" in args and not os.environ.get("FAKE_MISSING_FIXTURE"):
            fixture = destination / "kind-fixtures" / os.environ["KIND_DEV_BIN"]
            fixture.parent.mkdir()
            fixture.write_text(os.environ.get("FAKE_FIXTURE_CONTENT", "synthetic-current-fixture"))
            fixture.chmod(0o755)
    elif args[:2] == ["buildx", "build"]:
        tag = args[args.index("-t") + 1]
        (state / "last-image").write_text(tag)
        aliases[tag] = "sha256:" + hashlib.sha256(entry["dockerfile"].encode()).hexdigest()
        aliases_path.write_text(json.dumps(aliases))
    elif args[:2] not in (["buildx", "inspect"], ["buildx", "create"]): sys.exit(64)
elif tool == "ss":
    if os.environ.get("FAKE_LISTENER") == "1":
        port = args[-1].rsplit(":", 1)[-1]
        print(f'LISTEN 0 128 127.0.0.1:{port} *:* users:(("codewire-dashbo",pid=777777,fd=8))')
elif tool == "curl": print("200", end="")
elif tool == "cat":
    if args == ["/proc/777777/comm"]: print("codewire-dashbo")
    else:
        for path in args: sys.stdout.write(pathlib.Path(path).read_text())
else: sys.exit(64)
'''

FAKE_SUITE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
with (pathlib.Path(os.environ["FAKE_STATE"]) / "calls").open("a") as log:
    log.write(json.dumps({"tool":"suite", "args":sys.argv[1:],
        "cluster":os.environ.get("KIND_CLUSTER_NAME"), "profile":os.environ.get("CLUSTER"),
        "kube_context":os.environ.get("KUBE_CONTEXT"),
        "kubeconfig":os.environ.get("KUBECONFIG"), "smokes":os.environ.get("CARGO_CI_DIR"),
        "lock_fd":os.environ.get("KIND_PROFILE_LOCK_FD")}) + "\n")
sys.exit(int(os.environ.get("FAKE_SUITE_STATUS", "0")))
'''


class DeveloperProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="kind-dev-profile.", dir=ROOT / ".tmp")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.tree = self.directory / "tree"
        self.state = self.directory / "state"
        self.tools = self.directory / "bin"
        for path in (self.tree / "scripts/dev/kind", self.tree / "scripts/ci/verify", self.state, self.tools):
            path.mkdir(parents=True, mode=0o700)
        self.calls_path = self.state / "calls"
        self.calls_path.touch()
        for name in ("dev-loop.sh", "deploy-service.sh", "test-selected.sh"):
            shutil.copy2(CONSUMERS / "scripts/dev/kind" / name, self.tree / "scripts/dev/kind" / name)
        shutil.copy2(ROOT / "scripts/dev/kind/profile.sh", self.tree / "scripts/dev/kind/profile.sh")
        self.write_program(self.tree / "scripts/dev/kind/cluster-profile.py", FAKE_CORE)
        self.write_program(self.tree / "scripts/ci/verify/kind-e2e.sh", FAKE_SUITE)
        for tool in ("kind", "docker", "kubectl", "ss", "curl", "cat"):
            self.write_program(self.tools / tool, FAKE_TOOL)
        # A Bash builtin kill is mocked too: a regression must never signal a
        # real PID, even when the old watcher code recognizes a synthetic name.
        self.bash_env = self.directory / "bash-env"
        self.bash_env.write_text(
            'kill() { printf "signal attempted\\n" >>"$FAKE_STATE/signals"; return 1; }\n'
            # The copied adapter uses process substitutions. Join each test
            # shell's children before exit without changing its command status.
            'trap \'fixture_status=$?; wait || :; exit "$fixture_status"\' EXIT\n'
        )
        self.home = self.directory / "home"
        self.home.mkdir(mode=0o700)
        self.env = {"PATH": f"{self.tools}:{os.environ['PATH']}", "FAKE_STATE": str(self.state),
                    "HOME": str(self.home), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "maintenance.auto", "GIT_CONFIG_VALUE_0": "false",
                    "GIT_CONFIG_KEY_1": "gc.auto", "GIT_CONFIG_VALUE_1": "0",
                    "BASH_ENV": str(self.bash_env), "CLUSTER": "dev-a", "KIND_PROFILE_LOCK_TIMEOUT_SECONDS": "1"}
        for name, offset in (("dev-a", 0), ("dev-b", 20)):
            self.create_profile(name, offset)

    @staticmethod
    def write_program(path: Path, source: str) -> None:
        path.write_text(source)
        path.chmod(0o755)

    def create_profile(self, name: str, offset: int) -> None:
        directory = self.state / name
        directory.mkdir(mode=0o700)
        lock = directory / "operation.lock"
        lock.touch(mode=0o600)
        kubeconfig = directory / "kubeconfig"
        kubeconfig.write_text("synthetic private kubeconfig\n")
        kubeconfig.chmod(0o600)
        artifact_root = directory / "artifacts"
        artifact = artifact_root / ("b" * 40 + "-" + "c" * 40)
        (artifact / "smokes").mkdir(parents=True, mode=0o700)
        values = {
            "KIND_PROFILE": "1", "KIND_PROFILE_PATH": str(directory / "profile.json"),
            "KIND_PROFILE_NONCE": ("d" if name == "dev-a" else "e") * 32,
            "KIND_PROFILE_DOCKER_ID": "synthetic-daemon", "KIND_PROFILE_STATE": "running",
            "KIND_PROFILE_LOCK_FILE": str(lock), "KIND_BUILD_PUBLICATION_LOCK_FILE": str(self.state / "build.lock"),
            "KIND_CLUSTER_NAME": name, "KUBE_CONTEXT": "kind-" + name, "KUBECONFIG": str(kubeconfig),
            "KIND_CONFIG": str(directory / "kind-config.yaml"), "RUN_DIR": str(directory / "run"),
            "KIND_PROFILE_ARTIFACT_ROOT": str(artifact_root), "KIND_PROFILE_ARTIFACT_DIR": str(artifact),
            "KIND_PROFILE_SMOKE_DIR": str(artifact / "smokes"), "KIND_PROFILE_IMAGE_MANIFEST": str(artifact / "manifest.json"),
            "KIND_PROFILE_SOURCE_HEAD": "b" * 40, "KIND_PROFILE_SOURCE_TREE": "c" * 40,
            "KIND_PROFILE_IMAGE_PREFIX": "codewire-kind-" + name + "-" + ("d" if name == "dev-a" else "e") * 12,
            "KIND_PROFILE_DASHBOARD_IMAGE_ID": IMAGE_ID, "KIND_PROFILE_SERVICES_IMAGE_ID": IMAGE_ID,
            "KIND_PROFILE_MESH_IMAGE_ID": IMAGE_ID, "KIND_PROFILE_GATEWAY_IMAGE_ID": IMAGE_ID,
        }
        for key, position in (("KIND_INGRESS_HTTP_HOST_PORT", 0), ("KIND_INGRESS_TLS_HOST_PORT", 1),
                              ("KIND_ORCHESTRATION_HOST_PORT", 2), ("KIND_COORDINATOR_HOST_PORT", 3),
                              ("KIND_TEMPORAL_HOST_PORT", 4), ("KIND_POSTGRES_HOST_PORT", 5), ("KIND_WATCH_HOST_PORT", 6)):
            values[key] = str(31100 + offset + position)
        values.update({
            "KIND_INGRESS_URL": f"http://127.0.0.1:{31100 + offset}",
            "KIND_INGRESS_TLS_URL": f"https://localhost:{31101 + offset}",
            "KIND_ORCHESTRATION_URL": f"http://127.0.0.1:{31102 + offset}",
            "KIND_COORDINATOR_DIRECT_URL": f"http://127.0.0.1:{31103 + offset}",
            "KIND_TEMPORAL_ADDRESS": f"http://127.0.0.1:{31104 + offset}",
            "KIND_DATABASE_URL": f"postgres://codewire:codewire@127.0.0.1:{31105 + offset}/codewire",
            "KIND_WATCH_ADDR": f"127.0.0.1:{31106 + offset}",
            "KIND_PUBLIC_ORIGIN": f"http://127.0.0.1:{31106 + offset}",
            "KIND_BROWSER_API_ORIGIN": f"http://127.0.0.1:{31100 + offset}",
        })
        values.update({"KIND_INGRESS_HOST_PORT": values["KIND_INGRESS_HTTP_HOST_PORT"],
                       "KIND_COORDINATOR_DIRECT_HOST_PORT": values["KIND_COORDINATOR_HOST_PORT"],
                       "KIND_ORCHESTRATION_HTTP_URL": values["KIND_ORCHESTRATION_URL"],
                       "KIND_TEMPORAL_FRONTEND_URL": values["KIND_TEMPORAL_ADDRESS"]})
        (directory / "fields.json").write_text(json.dumps(list(values.items())))
        if name == "dev-a": self.values = values

    def run_script(self, script: str, *args: str, **environment: str) -> subprocess.CompletedProcess[str]:
        env = self.env | environment
        return subprocess.run(["bash", str(self.tree / "scripts/dev/kind" / script), *args],
                              env=env, text=True, capture_output=True, timeout=8)

    def run_adapter(self, command: str, **environment: str) -> subprocess.CompletedProcess[str]:
        env = self.env | environment | {"FIXTURE_TREE": str(self.tree)}
        return subprocess.run(["bash", "-c", 'set -euo pipefail; source "$FIXTURE_TREE/scripts/dev/kind/profile.sh"; ' + command],
                              env=env, text=True, capture_output=True, timeout=8)

    def run_make_up(self, *arguments: str, dotenv: str = "", **environment: str) -> subprocess.CompletedProcess[str]:
        # Exercise the actual Makefile in a synthetic checkout. Never include
        # the workstation's .env or run its optional tool-discovery commands.
        (self.tree / "Makefile").write_text(MAKEFILE_SOURCE)
        (self.tree / ".env").write_text("AGENT_SANDBOX_SHA=synthetic\nBUF=synthetic-buf\nGO_BIN=/synthetic/bin\n" + dotenv)
        self.write_program(self.tree / "scripts/ci/verify/make-up-fixture.py", FAKE_SUITE)
        self.write_program(self.tree / "scripts/ci/verify/kind-e2e.sh", '''#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
source "$ROOT/scripts/dev/kind/profile.sh"
kind_profile_load "$ROOT" || exit $?
exec "$ROOT/scripts/ci/verify/make-up-fixture.py" "$@"
''')
        return subprocess.run(["make", "--no-print-directory", "kind-up", *arguments],
                              cwd=self.tree, env=self.env | environment,
                              text=True, capture_output=True, timeout=8)

    def calls(self, tool: str | None = None) -> list[dict[str, object]]:
        calls = [json.loads(line) for line in self.calls_path.read_text().splitlines()]
        return [call for call in calls if tool is None or call["tool"] == tool]

    def assert_no_runtime_calls(self) -> None:
        self.assertFalse([call for call in self.calls() if call["tool"] != "profile"], self.calls())

    def test_saved_endpoints_and_private_context(self) -> None:
        result = self.run_script("dev-loop.sh", "status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("http://127.0.0.1:31100/login", result.stdout)
        self.assertIn("127.0.0.1:31106/login", result.stdout)
        for call in self.calls("kubectl"):
            self.assertEqual(call["args"][1], "kind-dev-a")
            self.assertEqual(call["kubeconfig"], self.values["KUBECONFIG"])

    def test_actual_makefile_named_up_uses_saved_context(self) -> None:
        result = self.run_make_up("CLUSTER=dev-a")
        self.assertEqual(result.returncode, 0, result.stderr)
        launch, = self.calls("suite")
        self.assertEqual(launch["args"], ["up"])
        self.assertEqual(launch["profile"], "dev-a")
        self.assertEqual(launch["kube_context"], "kind-dev-a")
        self.assertEqual(launch["kubeconfig"], self.values["KUBECONFIG"])

    def test_actual_makefile_legacy_up_keeps_default_context(self) -> None:
        result = self.run_make_up("CLUSTER=")
        self.assertEqual(result.returncode, 0, result.stderr)
        launch, = self.calls("suite")
        self.assertEqual(launch["kube_context"], "kind-codewire")
        self.assertFalse(self.calls("profile"))

    def test_actual_makefile_preserves_explicit_context_conflicts(self) -> None:
        for arguments, dotenv, environment in [
            ([], "", {"KUBE_CONTEXT": "kind-other"}),
            (["KUBE_CONTEXT=kind-other"], "", {}),
            ([], "KUBE_CONTEXT=kind-other\n", {}),
        ]:
            with self.subTest(arguments=arguments, dotenv=dotenv, environment=environment):
                result = self.run_make_up("CLUSTER=dev-a", *arguments, dotenv=dotenv, **environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("KUBE_CONTEXT conflicts with saved", result.stderr)
        self.assert_no_runtime_calls()

    def test_legacy_review_origins_and_name_survive(self) -> None:
        result = self.run_script("dev-loop.sh", "status", CLUSTER="", KIND_CLUSTER_NAME="codewire-ux-2099",
                                 KIND_PUBLIC_ORIGIN="http://legacy-review:4174", KIND_WATCH_ADDR="127.0.0.1:5182")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("http://127.0.0.1:8090/login", result.stdout)
        self.assertIn("http://legacy-review:4174", result.stdout)
        self.assertFalse(self.calls("profile"))

    def test_selector_conflict_precedes_all_effects(self) -> None:
        for script, args in (("dev-loop.sh", ("status",)), ("deploy-service.sh", ("idp",)), ("test-selected.sh", ())):
            with self.subTest(script=script):
                result = self.run_script(script, *args, KIND_CLUSTER_NAME="dev-b", KIND_TEST_SUITES="credentials")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("different clusters", result.stderr)
        self.assertFalse(self.calls())

    def test_endpoint_context_and_kubeconfig_conflicts(self) -> None:
        for key, value in (("KIND_INGRESS_URL", "http://127.0.0.1:8090"), ("KIND_POSTGRES_HOST_PORT", "25432"),
                           ("KIND_PUBLIC_ORIGIN", "http://other:4174"), ("KUBE_CONTEXT", "kind-other"),
                           ("KUBECONFIG", "/synthetic/other-config")):
            with self.subTest(key=key):
                result = self.run_script("dev-loop.sh", "watch", **{key: value})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("conflicts with saved", result.stderr)
        self.assert_no_runtime_calls()

    def test_rejects_invalid_field_streams(self) -> None:
        for mode in ("unknown", "duplicate", "missing", "wrong-binding", "odd", "failure",
                     "missing-alias", "conflicting-alias"):
            with self.subTest(mode=mode):
                result = self.run_script("dev-loop.sh", "status", FAKE_FIELD_MODE=mode)
                self.assertNotEqual(result.returncode, 0)
        self.assert_no_runtime_calls()

    def test_profile_values_are_literal(self) -> None:
        result = self.run_adapter('kind_profile_load "$FIXTURE_TREE"; printf "%s\\n" "$KIND_PUBLIC_ORIGIN"',
                                  FAKE_FIELD_MODE="literal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("$(touch", result.stdout)
        self.assertFalse((self.state / "executed").exists())

    def test_helper_failure_does_not_assign_partial_fields(self) -> None:
        result = self.run_adapter('if kind_profile_load "$FIXTURE_TREE"; then exit 99; fi; printf "%s" "${KIND_CLUSTER_NAME-unset}"',
                                  FAKE_FIELD_MODE="failure")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "unset")

    def test_replaced_node_fails_before_cluster_commands(self) -> None:
        result = self.run_script("dev-loop.sh", "status", FAKE_NODE_STATUS="43")
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assert_no_runtime_calls()

    def test_inherited_operation_lock_does_not_deadlock(self) -> None:
        command = '''kind_profile_load "$FIXTURE_TREE"; kind_profile_lock "$FIXTURE_TREE";
        bash -c 'source "$FIXTURE_TREE/scripts/dev/kind/profile.sh"; kind_profile_load "$FIXTURE_TREE"; kind_profile_lock "$FIXTURE_TREE"; printf "child-lock-ok"' '''
        result = self.run_adapter(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "child-lock-ok")

    def test_lock_of_other_cluster_does_not_block(self) -> None:
        with Path(self.values["KIND_PROFILE_LOCK_FILE"]).open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.run_adapter('kind_profile_load "$FIXTURE_TREE"; kind_profile_lock "$FIXTURE_TREE"', CLUSTER="dev-b")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_same_cluster_lock_fails_before_mutation(self) -> None:
        with Path(self.values["KIND_PROFILE_LOCK_FILE"]).open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.run_script("deploy-service.sh", "idp")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("timed out", result.stderr)
        self.assert_no_runtime_calls()

    def test_listener_is_never_signalled(self) -> None:
        watcher = self.tree / "scripts/dev/dashboard-watch.py"
        watcher.write_text("raise SystemExit('fixture must not launch a watcher')\n")
        result = self.run_script("dev-loop.sh", "watch", FAKE_LISTENER="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already listening", result.stderr)
        self.assertFalse((self.state / "signals").exists())
        self.assertFalse(self.calls("docker"))
        self.assertFalse([call for call in self.calls("kubectl") if "rollout" in call["args"] or "patch" in call["args"]])

    def test_legacy_review_listener_is_never_signalled(self) -> None:
        (self.tree / "scripts/dev/dashboard-watch.py").write_text("raise SystemExit(99)\n")
        result = self.run_script("dev-loop.sh", "watch", CLUSTER="", KIND_CLUSTER_NAME="codewire-ux-2099",
                                 KIND_PUBLIC_ORIGIN="http://legacy-review:4174", FAKE_LISTENER="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already listening", result.stderr)
        self.assertFalse((self.state / "signals").exists())

    def test_retained_suite_uses_immutable_artifacts(self) -> None:
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="workspace-services credentials")
        self.assertEqual(result.returncode, 0, result.stderr)
        suites = self.calls("suite")
        self.assertEqual([call["args"] for call in suites], [["suite", "credentials"], ["suite", "workspace-services"]])
        for call in suites:
            self.assertEqual(call["cluster"], "dev-a")
            self.assertEqual(call["profile"], "dev-a")
            self.assertEqual(call["kubeconfig"], self.values["KUBECONFIG"])
            self.assertEqual(call["smokes"], self.values["KIND_PROFILE_SMOKE_DIR"])
            self.assertIsNotNone(call["lock_fd"])
        self.assertTrue([call for call in self.calls("profile") if call["args"][0] == "verify-artifacts"])

    def test_tampered_artifact_prevents_suite_and_deploy(self) -> None:
        for script, args in (("test-selected.sh", ()), ("deploy-service.sh", ("idp",))):
            with self.subTest(script=script):
                result = self.run_script(script, *args, KIND_TEST_SUITES="credentials", FAKE_ARTIFACT_STATUS="44")
                self.assertEqual(result.returncode, 44, result.stderr)
        self.assert_no_runtime_calls()

    def test_cw_runtime_selects_only_explicit_retained_route(self) -> None:
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="cw-runtime")
        self.assertEqual(result.returncode, 0, result.stderr)
        launch, = self.calls("suite")
        self.assertEqual(launch["args"], ["suite", "cw-runtime"])
        self.assertEqual(launch["profile"], "dev-a")
        self.assertEqual(launch["kubeconfig"], self.values["KUBECONFIG"])
        self.assertEqual(launch["smokes"], self.values["KIND_PROFILE_SMOKE_DIR"])
        self.assertIsNotNone(launch["lock_fd"])
        self.assertFalse(self.calls("docker"))

    def test_cw_managed_agents_selects_only_explicit_retained_route(self) -> None:
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="cw-managed-agents")
        self.assertEqual(result.returncode, 0, result.stderr)
        launch, = self.calls("suite")
        self.assertEqual(launch["args"], ["suite", "cw-managed-agents"])
        self.assertEqual(launch["profile"], "dev-a")
        self.assertIsNotNone(launch["lock_fd"])
        self.assertFalse(self.calls("docker"))

    def test_cw_runtime_failure_stops_selected_tail(self) -> None:
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="cw-runtime warm-pools", FAKE_SUITE_STATUS="28")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call["args"] for call in self.calls("suite")], [["suite", "cw-runtime"]])
        self.assertNotIn("all selected suites green", result.stderr)

    def test_shared_smoke_override_is_rejected(self) -> None:
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="credentials", CARGO_CI_DIR="/synthetic/shared-target/ci")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("immutable smoke", result.stderr)
        self.assertFalse(self.calls("suite"))

    def test_leaf_suite_failure_stops_remaining_suites(self) -> None:
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="credentials workspace-services", FAKE_SUITE_STATUS="27")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls("suite")), 1)
        self.assertNotIn("all selected suites green", result.stderr)

    def test_deploy_uses_exact_base_and_qualified_tag(self) -> None:
        result = self.run_script("deploy-service.sh", "idp")
        self.assertEqual(result.returncode, 0, result.stderr)
        docker = self.calls("docker")
        self.assertTrue([call for call in docker if call["args"] == ["image", "inspect", "--format", "{{.Id}}", IMAGE_ID]])
        tags = [call["args"] for call in docker if call["args"][0] == "tag"]
        self.assertEqual(len(tags), 1)
        self.assertTrue(tags[0][2].startswith(self.values["KIND_PROFILE_IMAGE_PREFIX"] + "-services:base-"))
        builds = [call for call in docker if call["args"][:2] == ["buildx", "build"]]
        self.assertIn("FROM " + tags[0][2], builds[0]["dockerfile"])
        output = (self.state / "last-image").read_text()
        self.assertTrue(output.startswith(self.values["KIND_PROFILE_IMAGE_PREFIX"] + "-services:dev-"))
        self.assertEqual(self.calls("kind")[-1]["args"], ["load", "docker-image", output, "--name", "dev-a"])
        kube = self.calls("kubectl")
        self.assertTrue([call for call in kube if call["args"][-4:] == ["set", "image", "deployment/codewire-idp", "idp=" + output]])
        self.assertTrue([call for call in kube if "wait" in call["args"] and "pod/old-one" in call["args"] and "pod/old-two" in call["args"]])
        self.assertFalse([call for call in kube if "restart" in call["args"]])

    def test_changed_binary_changes_output_tag(self) -> None:
        first = self.run_script("deploy-service.sh", "idp", FAKE_BINARY_CONTENT="source-one")
        self.assertEqual(first.returncode, 0, first.stderr)
        before = (self.state / "last-image").read_text()
        second = self.run_script("deploy-service.sh", "idp", FAKE_BINARY_CONTENT="source-two")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual((self.state / "last-image").read_text(), before)

    def test_service_deploy_preserves_prior_binaries(self) -> None:
        first = self.run_script("deploy-service.sh", "idp")
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.run_script("deploy-service.sh", "billing")
        self.assertEqual(second.returncode, 0, second.stderr)
        builds = [call for call in self.calls("docker") if call["args"][:2] == ["buildx", "build"]]
        self.assertIn("COPY codewire-idp /codewire-idp", builds[-1]["dockerfile"])
        self.assertIn("COPY codewire-billing /codewire-billing", builds[-1]["dockerfile"])

    def test_credential_fixture_is_current_and_retained_with_later_deploys(self) -> None:
        result = self.run_script("deploy-service.sh", "credential-service")
        self.assertEqual(result.returncode, 0, result.stderr)
        fixture = self.state / "dev-a/dev/codewire-services/fixtures/credential-service"
        self.assertEqual(fixture.read_text(), "synthetic-current-fixture")
        result = self.run_script("deploy-service.sh", "billing")
        self.assertEqual(result.returncode, 0, result.stderr)
        builds = [call for call in self.calls("docker") if call["args"][:2] == ["buildx", "build"]]
        self.assertIn("COPY --from=fixtures credential-service /codewire-kind-fixtures/credential-service", builds[-1]["dockerfile"])
        self.assertIn("fixtures=" + str(fixture.parent), builds[-1]["args"])

    def test_changed_fixture_changes_tag_with_unchanged_service_binary(self) -> None:
        first = self.run_script("deploy-service.sh", "credential-service", FAKE_FIXTURE_CONTENT="fixture-one")
        self.assertEqual(first.returncode, 0, first.stderr)
        before = (self.state / "last-image").read_text()
        second = self.run_script("deploy-service.sh", "credential-service", FAKE_FIXTURE_CONTENT="fixture-two")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual((self.state / "last-image").read_text(), before)

    def test_missing_rebuilt_fixture_prevents_image_delivery(self) -> None:
        result = self.run_script("deploy-service.sh", "credential-service", FAKE_MISSING_FIXTURE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("produced no credential-service fixture", result.stderr)
        self.assertFalse([call for call in self.calls("docker") if call["args"][:2] == ["buildx", "build"]])
        self.assertFalse([call for call in self.calls("kind") if call["args"][:2] == ["load", "docker-image"]])

    def test_linked_fixture_is_preserved_and_rejected_before_build(self) -> None:
        fixture_dir = self.state / "dev-a/dev/codewire-services/fixtures"
        fixture_dir.mkdir(parents=True, mode=0o700)
        for directory in (fixture_dir.parent, fixture_dir.parent.parent):
            directory.chmod(0o700)
        unrelated = self.directory / "unrelated-fixture"
        unrelated.write_text("preserve")
        fixture = fixture_dir / "credential-service"
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    fixture.symlink_to(unrelated)
                else:
                    os.link(unrelated, fixture)
                result = self.run_script("deploy-service.sh", "idp")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(unrelated.read_text(), "preserve")
                self.assertFalse([call for call in self.calls("docker") if call["args"][:2] == ["buildx", "bake"]])
                fixture.unlink()

    def test_mutable_cache_symlink_is_preserved_and_rejected(self) -> None:
        unrelated = self.directory / "unrelated"
        unrelated.mkdir()
        (unrelated / "keep").write_text("preserve")
        (self.state / "dev-a/dev").symlink_to(unrelated, target_is_directory=True)
        result = self.run_script("deploy-service.sh", "idp")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)
        self.assertEqual(list(unrelated.iterdir()), [unrelated / "keep"])
        self.assertFalse([call for call in self.calls("docker") if call["args"][0] == "tag" or call["args"][:2] == ["buildx", "bake"]])

    def test_source_qualified_base_collision_is_preserved(self) -> None:
        alias = self.values["KIND_PROFILE_IMAGE_PREFIX"] + "-services:base-" + "a" * 64
        (self.state / "aliases.json").write_text(json.dumps({alias: "sha256:" + "f" * 64}))
        result = self.run_script("deploy-service.sh", "idp")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("names a different image", result.stderr)
        self.assertEqual(json.loads((self.state / "aliases.json").read_text())[alias], "sha256:" + "f" * 64)
        self.assertFalse([call for call in self.calls("docker") if call["args"][0] == "tag"])

    def test_identical_named_deploy_restarts_once(self) -> None:
        result = self.run_script("deploy-service.sh", "idp", FAKE_SAME_IMAGE="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len([call for call in self.calls("kubectl") if "restart" in call["args"]]), 1)

    def test_daemon_deploy_updates_selected_renderer(self) -> None:
        result = self.run_script("deploy-service.sh", "daemon")
        self.assertEqual(result.returncode, 0, result.stderr)
        output = (self.state / "last-image").read_text()
        self.assertTrue(output.startswith(self.values["KIND_PROFILE_IMAGE_PREFIX"] + "-gateway:dev-"))
        kube = self.calls("kubectl")
        self.assertTrue([call for call in kube if "SANDBOX_GATEWAY_IMAGE=" + output in call["args"] and "deployment/codewire-orchestration" in call["args"]])
        self.assertTrue([call for call in kube if "wait" in call["args"]])

    def test_old_pod_cleanup_failure_is_not_success(self) -> None:
        result = self.run_script("deploy-service.sh", "idp", FAKE_KUBE_FAIL="wait")
        self.assertEqual(result.returncode, 29, result.stderr)
        self.assertNotIn("is running the current source", result.stderr)


if __name__ == "__main__":
    unittest.main()
