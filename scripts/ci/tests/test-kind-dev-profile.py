#!/usr/bin/env python3
"""Hermetic developer consumers: saved endpoints, artifact and process ownership."""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
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
         "watch_addr": os.environ.get("CODEWIRE_DASHBOARD_LISTEN_ADDR"),
         "skip_current": os.environ.get("KIND_DEPLOY_SKIP_CURRENT"),
         "crate": os.environ.get("KIND_DEV_CRATE"), "bins": os.environ.get("KIND_DEV_BIN"),
         "features": os.environ.get("KIND_DEV_FEATURES"), "cwd": os.getcwd()}
if tool == "docker" and args[:2] == ["buildx", "build"]:
    entry["dockerfile"] = sys.stdin.read()
with (state / "calls").open("a") as log: log.write(json.dumps(entry) + "\n")
if tool == "kind":
    if args == ["get", "clusters"]:
        print("dev-a\ndev-b\ncodewire-e2e-ci\ncodewire-ux-2099")
    elif args[:2] == ["get", "kubeconfig"]: print("synthetic kubeconfig")
    elif args[:2] != ["load", "docker-image"]: sys.exit(64)
elif tool == "kubectl":
    if "get" in args and "secret" in args:
        import base64
        name = args[args.index("secret") + 1]
        print(base64.b64encode((state / "roots" / f"{name}.pem").read_bytes()).decode(), end="")
    elif "get" in args and "codewire-config" in args and any("FRONTEND_URL" in a for a in args):
        print(os.environ.get("FAKE_FRONTEND_URL", os.environ.get("KIND_PUBLIC_ORIGIN", "")), end="")
    elif "get" in args and "configmap" in args:
        name = args[args.index("configmap") + 1]
        published = state / "configmaps" / f"{args[args.index('-n') + 1]}-{name}.pem"
        if published.exists(): sys.stdout.write(published.read_text())
    elif "create" in args and "configmap" in args:
        # The fake applies at once; `apply -f -` below only consumes the YAML.
        name = args[args.index("configmap") + 1]
        literal = next(arg for arg in args if arg.startswith("--from-literal=ca.crt="))
        (state / "configmaps").mkdir(exist_ok=True)
        (state / "configmaps" / f"{args[args.index('-n') + 1]}-{name}.pem").write_text(literal.split("=", 2)[2])
        print("kind: ConfigMap")
    elif "apply" in args: sys.stdin.read()
    elif "get" in args:
        if any("imageID" in a for a in args): print(os.environ.get("FAKE_POD_IMAGE", "sha256:" + "c" * 64))
        elif any(".metadata.annotations" in a for a in args):
            service = next(a for a in args if ".metadata.annotations" in a).split("source-", 1)[1].split('"', 1)[0]
            records = json.loads(os.environ.get("FAKE_RECORDS", "{}"))
            print(records.get(service, records.get("*", "<no value>")))
        elif "pods" in args: print("pod/old-one\npod/old-two")
        elif any(a.startswith("go-template=") for a in args): print("app=selected,")
        elif any("command[0]" in a for a in args): print("/codewire-kind-fixtures/credential-service")
        elif any("FRONTEND_URL" in a or "CREDENTIAL_PUBLIC_ORIGIN" in a for a in args):
            print(os.environ.get("KIND_PUBLIC_ORIGIN", "http://legacy-review:4174"))
        elif any("SANDBOX_DAEMON_IMAGE" in a for a in args): print("codewire-daemon:e2e")
        elif any(a.startswith("jsonpath=") and a.endswith(".image}") for a in args):
            if os.environ.get("FAKE_SAME_IMAGE") == "1": print((state / "last-image").read_text())
            else: print("codewire-services:e2e")
    elif "exec" in args: sys.stdout.write(os.environ.get("FAKE_LEFTOVERS", ""))
    elif "set" in args or "rollout" in args or "wait" in args or "annotate" in args:
        if os.environ.get("FAKE_KUBE_FAIL") and os.environ["FAKE_KUBE_FAIL"] in args: sys.exit(29)
    else: sys.exit(64)
elif tool == "docker" and args[0] == "port":
    ports = {"80": 8090, "443": 10443, "30733": 7233, "30084": 8084, "30090": 18092, "30432": 25432}
    ports.update(json.loads(os.environ.get("FAKE_NODE_PORTS", "{}")))
    print(f"0.0.0.0:{ports[args[2].split('/')[0]]}\n[::]:{ports[args[2].split('/')[0]]}")
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
        if os.environ.get("FAKE_BAKE_FAIL") == os.environ.get("KIND_DEV_CRATE"): sys.exit(23)
        output = outputs[0]
        destination = pathlib.Path(output.split("dest=", 1)[1])
        build_args = dict(args[i + 1].removeprefix("kind-dev-binary.args.").split("=", 1)
                          for i, arg in enumerate(args[:-1])
                          if arg == "--set" and args[i + 1].startswith("kind-dev-binary.args."))
        produced = [destination / name for name in os.environ["KIND_DEV_BIN"].split()]
        produced += [destination / "examples" / name for name in build_args.get("KIND_DEV_EXAMPLES", "").split()]
        if build_args.get("KIND_DEV_TEST"): produced.append(destination / "tests" / build_args["KIND_DEV_TEST"])
        for binary in produced:
            if binary.name == os.environ.get("FAKE_MISSING_OUTPUT"): continue
            binary.parent.mkdir(exist_ok=True)
            binary.write_text(os.environ.get("FAKE_BINARY_CONTENT", "synthetic-current-source"))
            binary.chmod(0o755)
        if "kind-dev-binary.args.KIND_DEV_FIXTURE_FEATURES=enrollment,kind-e2e" in args and not os.environ.get("FAKE_MISSING_FIXTURE"):
            fixture = destination / "kind-fixtures" / os.environ["KIND_DEV_BIN"]
            fixture.parent.mkdir()
            fixture.write_text(os.environ.get("FAKE_FIXTURE_CONTENT", "synthetic-current-fixture"))
            fixture.chmod(0o755)
    elif args[:2] == ["buildx", "build"]:
        tag = args[args.index("-t") + 1]
        (state / "last-image").write_text(tag)
        aliases[tag] = "sha256:" + hashlib.sha256(entry["dockerfile"].encode()).hexdigest()
        aliases_path.write_text(json.dumps(aliases))
    elif args[:2] == ["buildx", "inspect"]:
        builders = state / "builders"
        if not builders.exists() or args[2] not in builders.read_text().split(): sys.exit(1)
    elif args[:2] == ["buildx", "create"]:
        with (state / "builders").open("a") as builders: builders.write(args[args.index("--name") + 1] + "\n")
    else: sys.exit(64)
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
        "lock_fd":os.environ.get("KIND_PROFILE_LOCK_FD"),
        "postgres_port":os.environ.get("KIND_POSTGRES_HOST_PORT")}) + "\n")
sys.exit(int(os.environ.get("FAKE_SUITE_STATUS", "0")))
'''


# Stands in for service-sources.py, which needs a Git checkout and Cargo.
FAKE_SOURCES = r'''#!/usr/bin/env python3
import os, sys
if sys.argv[1] == "changes":
    if os.environ.get("FAKE_CHANGES_FAIL"): sys.exit(1)
    sys.stdout.write("".join(line + "\n" for line in os.environ.get("FAKE_CHANGES", "").split(";") if line))
elif sys.argv[1] == "digest":
    print(os.environ.get("FAKE_DIGEST", "d" * 64))
else:
    sys.exit(64)
'''

# Stands in for scripts/dev/kind/trust-roots.sh, which deploy-service.sh's own
# fixtures cover.
FAKE_TRUST_ROOTS = r'''#!/usr/bin/env python3
import json, os, pathlib
with (pathlib.Path(os.environ["FAKE_STATE"]) / "calls").open("a") as log:
    log.write(json.dumps({"tool": "trust-roots", "args": []}) + "\n")
'''

# Stands in for scripts/dev/preflight.sh --explain.
FAKE_PREFLIGHT = r'''#!/usr/bin/env bash
printf 'preflight classification: %s\n' "${FAKE_CLASSIFICATION:-changed}"
printf 'preflight required local mode: %s\n' "${FAKE_MODE:-default}"
printf 'preflight selection: |valid:v3|%s|complete|\n' "${FAKE_SELECTION:-}"
'''


def record_digest(service_digest: str, crate: str, features: str = "", fixture_features: str = "") -> str:
    """The digest deploy-service.sh records: the source digest and its build parameters."""
    return hashlib.sha256(f"{service_digest} {crate} {features} {fixture_features}\n".encode()).hexdigest()


# The smoke inventory the retained suites consume (common.sh).
SMOKE_INVENTORY = [
    "crd-smoke", "environment-setup-smoke", "exec-smoke", "exec-stream-smoke", "file-service-smoke",
    "prepare-stream-smoke", "log-stream-smoke", "temporal-smoke", "temporal-fencing-smoke", "reconciler-ttl-smoke",
    "cw", "examples/platform-run-smoke", "examples/environment-session-smoke", "examples/environment-cw-runtime-smoke",
    "examples/coordinator-ingress-smoke",
]


# deploy-service.sh build parameters: crate, features, fixture features.
BUILDS = {
    "idp": ("codewire-idp", "", ""), "orchestration": ("codewire-orchestration", "kind-e2e", ""),
    "credential-service": ("codewire-credential-service", "enrollment,kind-e2e", "enrollment,kind-e2e"),
    "billing": ("codewire-billing", "", ""), "coordinator": ("codewire-coordinator", "", ""),
    "mesh": ("codewire-mesh", "", ""), "dashboard": ("codewire-dashboard-web", "", ""),
    "daemon": ("codewire-cli-bin", "", ""),
}


def current_records(*stale: str, digest: str = "d" * 64, pod_image: str = "sha256:" + "c" * 64,
                    daemon: str = "codewire-daemon:e2e") -> str:
    """Deployment records saying the cluster runs this tree's source, except for STALE services."""
    # A named profile's daemon identity is the renderer's image, which the fake
    # reports; a legacy cluster's is the daemon tag's image ID.
    return json.dumps({service: f"{record_digest(digest, *build)} " + (daemon if service == "daemon" else pod_image)
                       for service, build in BUILDS.items() if service not in stale})


class DeveloperProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="kind-dev-profile.", dir=ROOT / ".tmp")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.tree = self.directory / "tree"
        self.state = self.directory / "state"
        self.tools = self.directory / "bin"
        for path in (self.tree / "scripts/dev/kind", self.tree / "scripts/ci/verify/kind", self.state, self.tools):
            path.mkdir(parents=True, mode=0o700)
        shutil.copy2(ROOT / "scripts/ci/verify/kind/credentials.sh",
                     self.tree / "scripts/ci/verify/kind/credentials.sh")
        # Distinct synthetic public roots for deploy-service.sh's republish step.
        (self.state / "roots").mkdir(mode=0o700)
        for name in ("codewire-kind-credential-broker-root", "codewire-kind-orchestration-internal-root",
                     "codewire-kind-coordinator-root", "previous-orchestration-internal-root"):
            self.certificate(self.state / "roots" / f"{name}.pem", name)
        self.calls_path = self.state / "calls"
        self.calls_path.touch()
        for name in ("dev-loop.sh", "deploy-service.sh", "test-selected.sh"):
            shutil.copy2(CONSUMERS / "scripts/dev/kind" / name, self.tree / "scripts/dev/kind" / name)
        # Consumers that predate the shared kind-dev builder do not have these.
        for name in ("dev-builder.sh", "build-smokes.sh"):
            if (CONSUMERS / "scripts/dev/kind" / name).exists():
                shutil.copy2(CONSUMERS / "scripts/dev/kind" / name, self.tree / "scripts/dev/kind" / name)
        shutil.copy2(ROOT / "scripts/dev/kind/profile.sh", self.tree / "scripts/dev/kind/profile.sh")
        self.write_program(self.tree / "scripts/dev/kind/cluster-profile.py", FAKE_CORE)
        self.write_program(self.tree / "scripts/ci/verify/kind-e2e.sh", FAKE_SUITE)
        self.write_program(self.tree / "scripts/dev/kind/service-sources.py", FAKE_SOURCES)
        self.write_program(self.tree / "scripts/dev/kind/trust-roots.sh", FAKE_TRUST_ROOTS)
        self.write_program(self.tree / "scripts/dev/preflight.sh", FAKE_PREFLIGHT)
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
                    "BASH_ENV": str(self.bash_env), "CLUSTER": "dev-a", "KIND_PROFILE_LOCK_TIMEOUT_SECONDS": "1",
                    "PREFLIGHT_BASE_SHA": "f" * 40, "FAKE_RECORDS": current_records()}
        for name, offset in (("dev-a", 0), ("dev-b", 20)):
            self.create_profile(name, offset)

    def certificate(self, path: Path, name: str) -> None:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", str(self.directory / f"{name}.key"), "-subj", f"/CN={name}",
                        "-days", "2", "-out", str(path)], check=True, capture_output=True)

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
            "KIND_PROFILE_MESH_IMAGE_ID": IMAGE_ID, "KIND_PROFILE_DAEMON_IMAGE_ID": IMAGE_ID,
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

    def run_script(self, script: str, *args: str, timeout: int = 30, **environment: str) -> subprocess.CompletedProcess[str]:
        env = self.env | environment
        # Started outside the tree, as from another worktree's directory.
        return subprocess.run(["bash", str(self.tree / "scripts/dev/kind" / script), *args],
                              env=env, text=True, capture_output=True, timeout=timeout, cwd=self.directory)

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

    def test_deploy_republishes_trust_roots_before_restart(self) -> None:
        roots = self.state / "roots"
        (self.state / "configmaps").mkdir()
        previous = (roots / "previous-orchestration-internal-root.pem").read_text().strip()
        stale = self.state / "configmaps" / "dev-sandboxes-codewire-orchestration-internal-roots.pem"
        stale.write_text(previous)
        result = self.run_script("deploy-service.sh", "orchestration")
        self.assertEqual(result.returncode, 0, result.stderr)
        current = (roots / "codewire-kind-orchestration-internal-root.pem").read_text().strip()
        published = stale.read_text()
        self.assertTrue(published.startswith(current), published)
        self.assertIn(previous, published)
        self.assertEqual(published.count("BEGIN CERTIFICATE"), 2)
        kube = self.calls("kubectl")
        creates = [i for i, call in enumerate(kube) if "create" in call["args"] and "configmap" in call["args"]]
        changes = [i for i, call in enumerate(kube) if "set" in call["args"] or "rollout" in call["args"]]
        self.assertEqual(len(creates), 4)
        self.assertTrue(changes and max(creates) < min(changes))
        self.assertFalse([call for call in kube if any("tls.key" in arg for arg in call["args"])])

    def test_identical_named_deploy_restarts_once(self) -> None:
        result = self.run_script("deploy-service.sh", "idp", FAKE_SAME_IMAGE="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len([call for call in self.calls("kubectl") if "restart" in call["args"]]), 1)

    def test_daemon_deploy_updates_selected_renderer(self) -> None:
        result = self.run_script("deploy-service.sh", "daemon")
        self.assertEqual(result.returncode, 0, result.stderr)
        output = (self.state / "last-image").read_text()
        self.assertTrue(output.startswith(self.values["KIND_PROFILE_IMAGE_PREFIX"] + "-daemon:dev-"))
        kube = self.calls("kubectl")
        self.assertTrue([call for call in kube if "SANDBOX_DAEMON_IMAGE=" + output in call["args"] and "deployment/codewire-orchestration" in call["args"]])
        self.assertTrue([call for call in kube if "wait" in call["args"]])

    def test_old_pod_cleanup_failure_is_not_success(self) -> None:
        result = self.run_script("deploy-service.sh", "idp", FAKE_KUBE_FAIL="wait")
        self.assertEqual(result.returncode, 29, result.stderr)
        self.assertNotIn("is running the current source", result.stderr)
        self.assertFalse([call for call in self.calls("kubectl") if "annotate" in call["args"]])

    def test_deploy_records_source_and_running_image(self) -> None:
        result = self.run_script("deploy-service.sh", "credential-service", FAKE_DIGEST="1" * 64,
                                 FAKE_POD_IMAGE="sha256:" + "2" * 64)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = record_digest("1" * 64, "codewire-credential-service", "enrollment,kind-e2e", "enrollment,kind-e2e")
        annotate, = [call["args"] for call in self.calls("kubectl") if "annotate" in call["args"]]
        self.assertEqual(annotate[-2:], ["deployment/codewire-credential-service",
                                         f"dev.codewire.kind-dev/source-credential-service={expected} sha256:{'2' * 64}"])
        # Recorded only after the replaced Pods are gone.
        calls = [call["args"] for call in self.calls("kubectl")]
        self.assertLess(max(i for i, args in enumerate(calls) if "wait" in args), calls.index(annotate))

    def test_deploy_skips_a_service_running_this_source(self) -> None:
        digest = record_digest("1" * 64, "codewire-idp")
        result = self.run_script("deploy-service.sh", "idp", KIND_DEPLOY_SKIP_CURRENT="1", FAKE_DIGEST="1" * 64,
                                 FAKE_RECORDS=json.dumps({"idp": f"{digest} sha256:{'2' * 64}"}), FAKE_POD_IMAGE="sha256:" + "2" * 64)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already runs this tree's source", result.stderr)
        self.assertFalse(self.calls("docker"))
        self.assertFalse(self.calls("kind")[1:])

    def test_deploy_rebuilds_when_source_image_or_request_differs(self) -> None:
        digest = record_digest("1" * 64, "codewire-idp")
        for name, environment in (
            ("changed source", {"KIND_DEPLOY_SKIP_CURRENT": "1", "FAKE_DIGEST": "3" * 64,
                                "FAKE_RECORDS": json.dumps({"idp": f"{digest} sha256:{'2' * 64}"}), "FAKE_POD_IMAGE": "sha256:" + "2" * 64}),
            ("replaced Pod image", {"KIND_DEPLOY_SKIP_CURRENT": "1", "FAKE_DIGEST": "1" * 64,
                                    "FAKE_RECORDS": json.dumps({"idp": f"{digest} sha256:{'2' * 64}"}), "FAKE_POD_IMAGE": "sha256:" + "4" * 64}),
            ("explicit deploy", {"FAKE_DIGEST": "1" * 64, "FAKE_RECORDS": json.dumps({"idp": f"{digest} sha256:{'2' * 64}"}),
                                 "FAKE_POD_IMAGE": "sha256:" + "2" * 64}),
        ):
            with self.subTest(name):
                self.calls_path.write_text("")
                result = self.run_script("deploy-service.sh", "idp", **environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("already runs", result.stderr)
                self.assertTrue([call for call in self.calls("docker") if call["args"][:2] == ["buildx", "bake"]])

    def test_record_only_records_the_running_image(self) -> None:
        result = self.run_script("deploy-service.sh", "orchestration", KIND_DEPLOY_RECORD_ONLY="1",
                                 FAKE_DIGEST="5" * 64, FAKE_POD_IMAGE="sha256:" + "6" * 64)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.calls("docker"))
        annotate, = [call["args"] for call in self.calls("kubectl") if "annotate" in call["args"]]
        expected = record_digest("5" * 64, "codewire-orchestration", "kind-e2e")
        self.assertEqual(annotate[-1], f"dev.codewire.kind-dev/source-orchestration={expected} sha256:{'6' * 64}")

    def test_builder_keeps_its_build_caches(self) -> None:
        result = self.run_script("deploy-service.sh", "idp")
        self.assertEqual(result.returncode, 0, result.stderr)
        create, = [call["args"] for call in self.calls("docker") if call["args"][:2] == ["buildx", "create"]]
        builder = create[create.index("--name") + 1]
        self.assertRegex(builder, "^" + re.escape(self.values["KIND_PROFILE_IMAGE_PREFIX"]) + r"-dev-[0-9a-f]{8}$")
        config = Path(create[create.index("--buildkitd-config") + 1]).read_text()
        self.assertIn("reservedSpace = \"40GB\"", config)
        self.assertNotIn("488", config)
        bake, = [call["args"] for call in self.calls("docker") if call["args"][:2] == ["buildx", "bake"]]
        self.assertEqual(bake[bake.index("--builder") + 1], builder)

    SMOKE_BUILDS = [
        ("codewire-orchestration", "kind-e2e",
         "crd-smoke environment-setup-smoke exec-smoke exec-stream-smoke file-service-smoke prepare-stream-smoke "
         "log-stream-smoke temporal-smoke temporal-fencing-smoke reconciler-ttl-smoke sidecar-smoke", "", ""),
        ("codewire-client", "", "", "platform-run-smoke environment-session-smoke environment-cw-runtime-smoke", ""),
        ("codewire-client", "kind-e2e", "", "coordinator-ingress-smoke", ""),
        ("codewire-cli-bin", "", "cw", "", ""),
        ("codewire-billing", "", "", "", "wire_contract"),
    ]

    def run_smokes(self, **environment: str) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        smokes, receipt = self.directory / "smokes", self.directory / "run" / "billing-contract-build.jsonl"
        result = subprocess.run(["bash", str(self.tree / "scripts/dev/kind/build-smokes.sh"), str(smokes), str(receipt)],
                                env=self.env | {"CLUSTER": "", "KIND_CLUSTER_NAME": "codewire-ux-2099"} | environment,
                                text=True, capture_output=True, timeout=30, cwd=self.directory)
        return result, smokes, receipt

    @staticmethod
    def bake_arg(bake: list[str], name: str) -> str:
        value, = [arg.split("=", 1)[1] for i, arg in enumerate(bake)
                  if i and bake[i - 1] == "--set" and arg.startswith(f"kind-dev-binary.args.{name}=")]
        return value

    def test_smokes_build_in_the_deploy_builder_and_target(self) -> None:
        result = self.run_script("deploy-service.sh", "idp", CLUSTER="", KIND_CLUSTER_NAME="codewire-ux-2099",
                                 FAKE_RECORDS=current_records("idp", daemon=IMAGE_ID))
        self.assertEqual(result.returncode, 0, result.stderr)
        deploy_call, = [call for call in self.calls("docker") if call["args"][:2] == ["buildx", "bake"]]
        deploy = deploy_call["args"]
        self.calls_path.write_text("")
        result, smokes, receipt = self.run_smokes()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CODEWIRE_CI_PHASE name=kind-smoke-binary-build seconds=", result.stdout)
        # The builder that exists already is reused, so no second builder.
        self.assertFalse([call for call in self.calls("docker") if call["args"][:2] == ["buildx", "create"]])
        bakes = [call for call in self.calls("docker") if call["args"][:2] == ["buildx", "bake"]]
        self.assertEqual([(call["crate"], call["features"], call["bins"], self.bake_arg(call["args"], "KIND_DEV_EXAMPLES"),
                           self.bake_arg(call["args"], "KIND_DEV_TEST")) for call in bakes], self.SMOKE_BUILDS)
        # Bake takes its build context from the working directory: both build
        # this worktree's source, whatever directory they were started from.
        self.assertEqual(deploy_call["cwd"], str(self.tree))
        for call in bakes:
            self.assertEqual(call["cwd"], str(self.tree))
            # The deploy's builder and the worktree's own target: a smoke only
            # links what the deploy compiled and never another tree's crates.
            self.assertEqual(call["args"][call["args"].index("--builder") + 1],
                             deploy[deploy.index("--builder") + 1])
            self.assertEqual(self.bake_arg(call["args"], "KIND_DEV_TREE"), self.bake_arg(deploy, "KIND_DEV_TREE"))
            self.assertEqual(self.bake_arg(call["args"], "KIND_DEV_TREE"),
                             hashlib.sha256(str(self.tree).encode()).hexdigest()[:16])
        installed = sorted(str(path.relative_to(smokes)) for path in smokes.rglob("*") if path.is_file())
        expected = sorted(SMOKE_INVENTORY + ["sidecar-smoke", "kind-smoke-tests/wire_contract"])
        self.assertEqual(installed, expected)
        # The suite selects the billing contract from the receipt with its own query.
        common = (ROOT / "scripts/ci/verify/kind/common.sh").read_text()
        query = common.split("binary=\"$(jq -ser '", 1)[1].split("'", 1)[0]
        selected = subprocess.run(["jq", "-ser", query, str(receipt)], text=True, capture_output=True, check=True)
        self.assertEqual(selected.stdout.strip(), str(smokes / "kind-smoke-tests/wire_contract"))

    def test_smokes_stop_at_a_failed_or_incomplete_build(self) -> None:
        for failure, environment, message in (
                ("failed build", {"FAKE_BAKE_FAIL": "codewire-client"}, ""),
                ("missing binary", {"FAKE_MISSING_OUTPUT": "temporal-smoke"}, "the build produced no temporal-smoke"),
                ("missing test", {"FAKE_MISSING_OUTPUT": "wire_contract"}, "the build produced no test wire_contract")):
            with self.subTest(failure):
                self.calls_path.write_text("")
                result, _, receipt = self.run_smokes(**environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(receipt.exists())
                self.assertNotIn("CODEWIRE_CI_PHASE", result.stdout)
        crates = [call["crate"] for call in self.calls("docker") if call["args"][:2] == ["buildx", "bake"]]
        self.assertEqual(crates, [build[0] for build in self.SMOKE_BUILDS])

    def test_smokes_refuse_relative_destinations(self) -> None:
        result = subprocess.run(["bash", str(self.tree / "scripts/dev/kind/build-smokes.sh"), "smokes", "receipt.jsonl"],
                                env=self.env | {"CLUSTER": ""}, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("usage: build-smokes.sh", result.stderr)
        self.assertFalse(self.calls("docker"))

    def test_dev_builds_use_the_local_kind_dev_profile(self) -> None:
        import tomllib
        # The workspace manifest, which CI and shipped builds read, does not
        # define it; only the kind-dev build passes this file with --config.
        self.assertNotIn("kind-dev", tomllib.loads((ROOT / "Cargo.toml").read_text())["profile"])
        profiles = tomllib.loads((ROOT / "scripts/dev/kind/cargo-profile.toml").read_text())["profile"]
        # It only lowers the workspace's own optimization; external crates keep
        # the ci profile's settings, share the compiler cache and keep the
        # services fast.
        self.assertEqual(list(profiles), ["kind-dev"])
        dev = dict(profiles["kind-dev"])
        packages = dev.pop("package")
        self.assertEqual(dev, {"inherits": "ci", "opt-level": 1, "codegen-units": 256})
        self.assertEqual(packages, {"*": {"opt-level": 3, "codegen-units": 16}})
        dockerfile = (ROOT / "deployments/docker/kind-dev-binary.Dockerfile").read_text()
        builder = dockerfile[:dockerfile.index("FROM scratch")]
        self.assertEqual(re.findall(r"cargo (?:build|test) --locked (--config \S+ --profile \S+)", builder),
                         ["--config scripts/dev/kind/cargo-profile.toml --profile kind-dev"] * 3)
        self.assertNotIn("$CARGO_TARGET_DIR/ci/", builder)
        self.assertEqual(builder.count("$CARGO_TARGET_DIR/kind-dev/"), 2)

    def test_every_copied_input_is_content_hashed(self) -> None:
        # Cargo judges freshness by modification time; the target's content
        # record is what keeps it from reusing a crate built from other source
        # (#2273). A copied input that is not hashed would escape it.
        dockerfile = (ROOT / "deployments/docker/kind-dev-binary.Dockerfile").read_text()
        builder = dockerfile[:dockerfile.index("FROM scratch")]
        copied = {source for line in builder.splitlines() if line.startswith("COPY ") and "--from" not in line
                  for source in line.split()[1:-1]}
        hashed = re.search(r"find (.*?) -type f -print0", builder.replace("\\\n", " "), re.S)
        self.assertIsNotNone(hashed)
        self.assertEqual(set(hashed.group(1).split()), copied)
        for guard in ('export CARGO_TARGET_DIR="/src/target/trees/$KIND_DEV_TREE"',
                      'grep -vxFf "$built" /tmp/kind-dev-sources.sha256 | cut -c67- | tr \'\\n\' \'\\0\' | xargs -0r touch -c',
                      'cp /tmp/kind-dev-sources.sha256 "$built"'):
            self.assertIn(guard, builder)
        self.assertTrue(builder.rstrip().endswith('cp /tmp/kind-dev-sources.sha256 "$built"'),
                        "the content record must be written only after every build step succeeded")

    def test_mesh_deploys_into_its_own_image(self) -> None:
        result = self.run_script("deploy-service.sh", "mesh")
        self.assertEqual(result.returncode, 0, result.stderr)
        output = (self.state / "last-image").read_text()
        self.assertTrue(output.startswith(self.values["KIND_PROFILE_IMAGE_PREFIX"] + "-mesh:dev-"))
        build, = [call for call in self.calls("docker") if call["args"][:2] == ["buildx", "build"]]
        self.assertIn("COPY codewire-mesh /usr/local/bin/codewire-mesh", build["dockerfile"])
        self.assertTrue([call for call in self.calls("kubectl")
                         if call["args"][-4:] == ["set", "image", "deployment/codewire-mesh", "mesh=" + output]])

    def test_selected_deploys_changed_services_before_suites(self) -> None:
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="workspace-services",
                                 FAKE_CHANGES="crate codewire-daemon;service orchestration;service daemon",
                                 FAKE_RECORDS=current_records("orchestration", "daemon"))
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        bakes = [i for i, call in enumerate(calls) if call["tool"] == "docker" and call["args"][:2] == ["buildx", "bake"]]
        self.assertEqual([calls[i]["crate"] for i in bakes], ["codewire-orchestration", "codewire-cli-bin"])
        self.assertTrue(all(calls[i]["skip_current"] == "1" for i in bakes))
        suite, = [i for i, call in enumerate(calls) if call["tool"] == "suite"]
        roots, = [i for i, call in enumerate(calls) if call["tool"] == "trust-roots"]
        self.assertLess(max(bakes), roots)
        self.assertLess(roots, suite)
        self.assertIn("suite workspace-services: requested", result.stderr)
        self.assertRegex(result.stderr, r"all selected suites green: deploy \d+s workspace-services \d+s")
        self.assertIn("idp already runs this tree's source", result.stderr)

    def test_selected_redeploys_a_service_left_on_other_source(self) -> None:
        # Every Deployment records a deploy from other source; none is current.
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="edge-contract", timeout=60,
                                 FAKE_RECORDS=json.dumps({"*": "0" * 64 + " sha256:" + "c" * 64}))
        self.assertEqual(result.returncode, 0, result.stderr)
        sources = load_service_sources()
        self.assertEqual([call["crate"] for call in self.calls("docker") if call["args"][:2] == ["buildx", "bake"]],
                         list(sources.SERVICES.values()))

    def test_selected_prints_each_suite_with_its_reasons(self) -> None:
        result = self.run_script("test-selected.sh", FAKE_SELECTION="rust|rust_pkg_codewire_billing|rust_pkg_codewire_tls",
                                 FAKE_CHANGES="crate codewire-billing;crate codewire-tls;service billing")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("suite edge-contract: rust_pkg_codewire_billing, rust_pkg_codewire_tls", result.stderr)
        self.assertIn("suite credentials: rust_pkg_codewire_tls", result.stderr)
        self.assertIn("suite integrated: rust_pkg_codewire_billing, rust_pkg_codewire_tls", result.stderr)
        self.assertLess(result.stderr.index("suite edge-contract:"), result.stderr.index("[kind-deploy]"))
        self.assertEqual([call["args"][1] for call in self.calls("suite")], ["edge-contract", "credentials", "integrated"])

    def test_selected_full_gate_runs_and_deploys_nothing(self) -> None:
        for name, environment, reason in (
            ("migration", {"KIND_TEST_SUITES": "credentials",
                           "FAKE_CHANGES": "crate codewire-server-core;migration crates/codewire-server-core/migrations/0099_x.sql;service idp"},
             "shared database"),
            ("server core", {"FAKE_SELECTION": "rust|rust_pkg_codewire_server_core|rust_pkg_codewire_orchestration",
                             "FAKE_CHANGES": "crate codewire-server-core;service idp"}, "every service compiles it"),
            ("unmapped crate", {"FAKE_SELECTION": "rust|rust_pkg_codewire_future_crate"}, "no retained suite is mapped"),
            ("unclassified", {"FAKE_CLASSIFICATION": "unclassified", "FAKE_SELECTION": "web"}, "cannot classify"),
            ("manifest only", {"FAKE_SELECTION": "deploy|policy"}, "no narrower suite"),
            ("Kind harness or ingress", {"FAKE_MODE": "kind", "FAKE_SELECTION": "policy|policy_shell"}, "no narrower suite"),
        ):
            with self.subTest(name):
                self.calls_path.write_text("")
                result = self.run_script("test-selected.sh", **environment)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertIn("only the full CI Kind gate covers this change", result.stderr)
                self.assertIn(reason, result.stderr)
                self.assertFalse([call for call in self.calls() if call["tool"] in ("docker", "kind", "suite")])

    def test_selected_workspace_pin_alone_is_observed_on_dev(self) -> None:
        selection = ("rust|rust_pkg_codewire_workspace_image|rust_pkg_codewire_server_core|"
                     "rust_pkg_codewire_orchestration|rust_pkg_codewire_dashboard_web|rust_pkg_codewire_cli")
        result = self.run_script("test-selected.sh", FAKE_SELECTION=selection, FAKE_CHANGES="crate codewire-workspace-image")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("a workspace image pin is observed on Dev", result.stderr)
        self.assertIn("nothing to run", result.stderr)
        self.assertFalse([call for call in self.calls() if call["tool"] in ("docker", "kind", "suite")])
        # A pin bump beside a real orchestration change still runs its suites.
        result = self.run_script("test-selected.sh", FAKE_SELECTION=selection,
                                 FAKE_CHANGES="crate codewire-workspace-image;crate codewire-orchestration;service orchestration")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("suite final-fencing: rust_pkg_codewire_orchestration", result.stderr)
        self.assertNotIn("rust_pkg_codewire_cli", result.stderr)

    def test_selected_unobservable_change_runs_nothing(self) -> None:
        result = self.run_script("test-selected.sh", FAKE_SELECTION="transport|transport_pkg_codewire_local_vmm",
                                 FAKE_CHANGES="crate codewire-local-vmm;service daemon")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not observable in Kind: transport_pkg_codewire_local_vmm", result.stderr)
        self.assertFalse([call for call in self.calls() if call["tool"] in ("docker", "kind", "suite")])

    def test_selected_stops_when_a_deploy_fails(self) -> None:
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="credentials",
                                 FAKE_CHANGES="service credential-service", FAKE_MISSING_FIXTURE="1",
                                 FAKE_RECORDS=current_records("credential-service"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deploying credential-service failed", result.stderr)
        self.assertFalse(self.calls("suite"))

    def test_service_sources_names_the_crate_each_deploy_builds(self) -> None:
        sources = load_service_sources()
        selected = (CONSUMERS / "scripts/dev/kind/test-selected.sh").read_text()
        services = re.search(r"^SERVICES=\(([^)]*)\)", selected, re.M)
        self.assertIsNotNone(services)
        self.assertEqual(services.group(1).split(), list(sources.SERVICES))
        for service, crate in sources.SERVICES.items():
            with self.subTest(service=service):
                self.calls_path.write_text("")
                result = self.run_script("deploy-service.sh", service)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([call["crate"] for call in self.calls("docker") if call["args"][:2] == ["buildx", "bake"]],
                                 [crate])

    def test_selected_refuses_live_leftover_environments(self) -> None:
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="credentials", FAKE_CHANGES="service idp",
                                 FAKE_LEFTOVERS="00000000-0000-4000-8000-0000000000aa kind-profile-1-2 running\n")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("refusing to start", result.stderr)
        self.assertIn("kind-profile-1-2 running", result.stderr)
        self.assertFalse([call for call in self.calls() if call["tool"] in ("docker", "kind", "suite")])
        query, = [call["args"] for call in self.calls("kubectl") if "exec" in call["args"]]
        self.assertIn("name LIKE 'kind-%' AND desired_state <> 'destroyed'", query[-1])

    def test_legacy_cluster_suites_use_its_published_ports(self) -> None:
        legacy = {"CLUSTER": "", "KIND_CLUSTER_NAME": "codewire-ux-2099", "KIND_TEST_SUITES": "workspace-services",
                  "FAKE_NODE_PORTS": json.dumps({"30432": 25433}), "FAKE_RECORDS": current_records(daemon=IMAGE_ID)}
        result = self.run_script("test-selected.sh", **legacy)
        self.assertEqual(result.returncode, 0, result.stderr)
        launch, = self.calls("suite")
        self.assertEqual(launch["postgres_port"], "25433")
        self.assertFalse([call for call in self.calls("docker") if call["args"][:2] == ["buildx", "bake"]])
        self.calls_path.write_text("")
        result = self.run_script("test-selected.sh", KIND_POSTGRES_HOST_PORT="25432", **legacy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("KIND_POSTGRES_HOST_PORT=25432 is not the port codewire-ux-2099 publishes (25433)", result.stderr)
        self.assertFalse(self.calls("suite"))

    def test_browser_suite_needs_the_ingress_origin(self) -> None:
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="dashboard-browser")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("dashboard-browser browses http://127.0.0.1:31100, but dev-a serves http://127.0.0.1:31106",
                      result.stderr)
        self.assertIn("make kind-credentials-fake", result.stderr)
        self.assertFalse([call for call in self.calls() if call["tool"] in ("docker", "suite")])
        (self.tree / "apps/dashboard/node_modules/.bin").mkdir(parents=True)
        self.write_program(self.tree / "apps/dashboard/node_modules/.bin/playwright", "#!/bin/sh\n")
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="dashboard-browser",
                                 FAKE_FRONTEND_URL="http://127.0.0.1:31100")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["args"] for call in self.calls("suite")], [["suite", "dashboard-browser"]])

    def test_selected_stops_when_changes_are_unknown(self) -> None:
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="credentials", FAKE_CHANGES_FAIL="1")
        self.assertEqual(result.returncode, 1)
        self.assertFalse([call for call in self.calls() if call["tool"] != "profile"])


def load_service_sources():
    spec = importlib.util.spec_from_file_location("service_sources", CONSUMERS / "scripts/dev/kind/service-sources.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SelectionTableTests(unittest.TestCase):
    def test_every_crate_has_its_own_suite_row(self) -> None:
        selected = (CONSUMERS / "scripts/dev/kind/test-selected.sh").read_text()
        table = selected[selected.index("map_token() {"):selected.index("rust_pkg_* | transport_pkg_*)")]
        # The selector reports these crates through another crate's token.
        aliases = {"codewire-ui": "codewire-desktop"}
        for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
            crate = aliases.get(manifest.parent.name, manifest.parent.name).replace("-", "_")
            with self.subTest(crate=manifest.parent.name):
                self.assertRegex(table, rf"(rust|transport)_pkg_{crate}\b")

    def test_inputs_are_what_the_kind_dev_build_copies(self) -> None:
        sources = load_service_sources()
        dockerfile = (ROOT / "deployments/docker/kind-dev-binary.Dockerfile").read_text()
        builder = dockerfile[:dockerfile.index("FROM scratch")]
        copied = {source for line in builder.splitlines() if line.startswith("COPY ") and "--from" not in line
                  for source in line.split()[1:-1]}
        declared = {"crates"} | {path for path in sources.SHARED_INPUTS if path not in sources.RECIPE_INPUTS}
        declared |= {path for paths in sources.CRATE_INPUTS.values() for path in paths}
        self.assertEqual(copied, declared)
        for path in sources.SHARED_INPUTS:
            self.assertTrue((ROOT / path).exists(), path)


SYNTHETIC_CRATES = {
    # name: (normal dependencies, dev-dependencies)
    "codewire-idp": (["codewire-server-core"], []),
    "codewire-orchestration": (["codewire-server-core"], []),
    "codewire-credential-service": (["codewire-server-core"], ["codewire-test-support"]),
    "codewire-billing": (["codewire-server-core"], []),
    "codewire-coordinator": ([], []),
    "codewire-mesh": (["codewire-server-core"], []),
    "codewire-dashboard-web": (["codewire-server-core"], []),
    "codewire-cli-bin": (["codewire-cli"], []),
    "codewire-cli": (["codewire-local-vmm"], ["codewire-billing"]),
    "codewire-local-vmm": ([], []),
    "codewire-server-core": (["codewire-workspace-image"], []),
    "codewire-workspace-image": ([], []),
    "codewire-test-support": (["codewire-email"], []),
    "codewire-email": ([], []),
}

FAKE_CARGO = r'''#!/usr/bin/env python3
import os, sys
assert sys.argv[1:5] == ["metadata", "--no-deps", "--offline", "--format-version"], sys.argv
sys.stdout.write(open(os.environ["FAKE_METADATA"]).read())
'''


class ServiceSourcesTests(unittest.TestCase):
    """The real helper against a synthetic checkout; Cargo metadata is canned."""

    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(prefix="kind-service-sources.", dir=ROOT / ".tmp")
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name) / "repo"
        tools = Path(temp.name) / "bin"
        tools.mkdir()
        (tools / "cargo").write_text(FAKE_CARGO)
        (tools / "cargo").chmod(0o755)
        packages = []
        for name, (normal, dev) in SYNTHETIC_CRATES.items():
            directory = self.repo / "crates" / name
            (directory / "src").mkdir(parents=True)
            (directory / "Cargo.toml").write_text(f'[package]\nname = "{name}"\n')
            (directory / "src/lib.rs").write_text(f"// {name}\n")
            packages.append({"name": name, "manifest_path": str(directory / "Cargo.toml"), "dependencies":
                             [{"name": dep, "kind": None, "path": str(self.repo / "crates" / dep)} for dep in normal]
                             + [{"name": dep, "kind": "dev", "path": str(self.repo / "crates" / dep)} for dep in dev]
                             + [{"name": "serde", "kind": None}]})
        (self.repo / "crates/codewire-server-core/migrations").mkdir()
        (self.repo / "crates/codewire-server-core/migrations/0001_init.sql").write_text("select 1;\n")
        for path in ("Cargo.toml", "Cargo.lock", "proto/codewire/v1/a.proto", "libs/daemon-proto/proto/b.proto",
                     "packages/codewire-design/styles.css", "apps/cli/install.sh", "apps/cli/GPG_PUBLIC_KEY.asc",
                     "deployments/docker/rust-base.Dockerfile", "deployments/docker/kind-dev-binary.Dockerfile",
                     "scripts/ci/images/run-rust-build.sh", "scripts/dev/kind/cargo-profile.toml",
                     "docs/README.md"):
            (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / path).write_text(path + "\n")
        (self.repo / ".gitignore").write_text("target/\n")
        helper = self.repo / "scripts/dev/kind/service-sources.py"
        helper.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CONSUMERS / "scripts/dev/kind/service-sources.py", helper)
        metadata = Path(temp.name) / "metadata.json"
        metadata.write_text(json.dumps({"packages": packages}))
        self.env = {"PATH": f"{tools}:{os.environ['PATH']}", "FAKE_METADATA": str(metadata),
                    "HOME": temp.name, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                    "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        self.git("init", "-q", "-b", "main")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")

    def git(self, *args: str) -> str:
        return subprocess.run(["git", "-C", str(self.repo), *args], env=self.env, check=True,
                              text=True, capture_output=True).stdout

    def helper(self, *args: str) -> str:
        result = subprocess.run(["python3", "-B", str(self.repo / "scripts/dev/kind/service-sources.py"), *args],
                                env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def changes(self) -> list[str]:
        return self.helper("changes", "--base", "main").splitlines()

    def edit(self, path: str, text: str = "changed\n") -> None:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def test_unchanged_checkout_feeds_nothing(self) -> None:
        self.assertEqual(self.changes(), [])

    def test_shared_crate_feeds_every_service_that_compiles_it(self) -> None:
        self.edit("crates/codewire-server-core/src/lib.rs")
        self.assertEqual(self.changes(), ["crate codewire-server-core"] + [
            f"service {name}" for name in ("idp", "orchestration", "credential-service", "billing", "mesh", "dashboard")])

    def test_untracked_migration_is_reported(self) -> None:
        self.edit("crates/codewire-server-core/migrations/0002_next.sql", "select 2;\n")
        self.assertIn("migration crates/codewire-server-core/migrations/0002_next.sql", self.changes())

    def test_root_dev_dependencies_count_but_transitive_ones_do_not(self) -> None:
        self.edit("crates/codewire-email/src/lib.rs")
        self.assertEqual(self.changes(), ["crate codewire-email", "service credential-service"])
        # Billing is only a dev-dependency of codewire-cli, never of the daemon binary.
        self.edit("crates/codewire-email/src/lib.rs", "// codewire-email\n")
        self.edit("crates/codewire-billing/src/lib.rs")
        self.assertEqual(self.changes(), ["crate codewire-billing", "service billing"])

    def test_embedded_design_feeds_only_the_dashboard(self) -> None:
        self.edit("packages/codewire-design/styles.css")
        self.assertEqual(self.changes(), ["service dashboard"])

    def test_protobuf_sources_feed_every_service(self) -> None:
        self.edit("proto/codewire/v1/a.proto")
        sources = load_service_sources()
        self.assertEqual(self.changes(), [f"service {name}" for name in sources.SERVICES])

    def test_build_recipe_feeds_every_service(self) -> None:
        # The compiler wrapper the toolchain image installs and the kind-dev
        # Cargo profile decide the build, like the Dockerfiles themselves.
        sources = load_service_sources()
        for path in sources.RECIPE_INPUTS + ("scripts/dev/kind/cargo-profile.toml",):
            with self.subTest(path=path):
                self.edit(path, f"changed {path}\n")
                self.assertEqual(self.changes(), [f"service {name}" for name in sources.SERVICES])
                self.git("checkout", "--", path)

    def test_workspace_image_pin_feeds_no_service(self) -> None:
        self.edit("crates/codewire-workspace-image/src/lib.rs")
        self.assertEqual(self.changes(), ["crate codewire-workspace-image"])

    def test_committed_branch_change_counts_from_the_merge_base(self) -> None:
        self.git("checkout", "-q", "-b", "feature")
        self.edit("crates/codewire-coordinator/src/lib.rs")
        self.git("commit", "-q", "-am", "coordinator")
        self.git("checkout", "-q", "main")
        self.edit("docs/README.md", "main moved\n")
        self.git("commit", "-q", "-am", "main moved")
        self.git("checkout", "-q", "feature")
        self.assertEqual(self.changes(), ["crate codewire-coordinator", "service coordinator"])

    def test_digest_follows_exactly_the_service_inputs(self) -> None:
        before = self.helper("digest", "idp").strip()
        self.assertRegex(before, r"^[0-9a-f]{64}$")
        self.edit("crates/codewire-coordinator/src/lib.rs")
        self.edit("target/build-output", "ignored\n")
        self.edit("docs/README.md", "unrelated\n")
        self.assertEqual(self.helper("digest", "idp").strip(), before)
        self.edit("crates/codewire-server-core/src/lib.rs")
        changed = self.helper("digest", "idp").strip()
        self.assertNotEqual(changed, before)
        self.edit("crates/codewire-server-core/src/lib.rs", "// codewire-server-core\n")
        self.assertEqual(self.helper("digest", "idp").strip(), before)
        self.assertNotEqual(self.helper("digest", "billing").strip(), before)
        # Reading the working tree never changes the checkout's own index.
        self.assertEqual(self.git("status", "--porcelain"), " M crates/codewire-coordinator/src/lib.rs\n M docs/README.md\n")


if __name__ == "__main__":
    unittest.main()
