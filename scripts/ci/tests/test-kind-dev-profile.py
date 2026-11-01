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
import sys
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
        "credential_stages":os.environ.get("KIND_CREDENTIAL_STAGES"),
        "dashboard_selection":os.environ.get("KIND_DASHBOARD_SELECTION"),
        "dashboard_workers":os.environ.get("CODEWIRE_KIND_DASHBOARD_WORKERS"),
        "smoke_run":os.environ.get("KIND_SMOKE_RUN"),
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

# Stands in for scripts/dev/kind/database.sh, which DatabaseTests cover.
FAKE_DATABASE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
with (pathlib.Path(os.environ["FAKE_STATE"]) / "calls").open("a") as log:
    log.write(json.dumps({"tool": "database", "args": sys.argv[1:]}) + "\n")
sys.exit(int(os.environ.get("FAKE_DATABASE_STATUS", "0")))
'''

# Stands in for scripts/dev/kind/dashboard-specs.py, which DashboardSpecTests cover.
FAKE_DASHBOARD_SPECS = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
with (pathlib.Path(os.environ["FAKE_STATE"]) / "calls").open("a") as log:
    log.write(json.dumps({"tool": "dashboard-specs", "args": sys.argv[1:]}) + "\n")
if os.environ.get("FAKE_DASHBOARD_SPECS_FAIL"): sys.exit(1)
print(os.environ.get("FAKE_DASHBOARD_SPECS", "all nothing mapped"))
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


# The smoke inventory every Kind smoke build reads: (group, crate, features,
# kind, name) rows.
INVENTORY = ROOT / "scripts/ci/verify/kind/smokes.txt"
INVENTORY_ROWS = [tuple(line.split()) for line in INVENTORY.read_text().splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]


def inventory_outputs(rows=INVENTORY_ROWS) -> dict[str, set[str]]:
    """Each inventory group's installed paths below the smoke directory."""
    outputs: dict[str, set[str]] = {}
    for group, _crate, _features, kind, name in rows:
        path = {"bin": name, "example": f"examples/{name}", "test": f"kind-smoke-tests/{name}"}[kind]
        outputs.setdefault(group, set()).add(path)
    return outputs


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
        shutil.copy2(INVENTORY, self.tree / "scripts/ci/verify/kind/smokes.txt")
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
        self.write_program(self.tree / "scripts/dev/kind/database.sh", FAKE_DATABASE)
        self.write_program(self.tree / "scripts/dev/kind/dashboard-specs.py", FAKE_DASHBOARD_SPECS)
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
        # The daemon's cw names the worktree's commit as its source revision.
        git = ["git", "-C", str(self.tree), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid"]
        subprocess.run([*git, "init", "-q"], env=self.env, check=True)
        subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "fixture"], env=self.env, check=True)
        self.revision = subprocess.run([*git, "rev-parse", "HEAD"], env=self.env, check=True,
                                       text=True, capture_output=True).stdout.strip()

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

    def run_script(self, script: str, *args: str, timeout: int = 300, **environment: str) -> subprocess.CompletedProcess[str]:
        env = self.env | environment
        # Started outside the tree, as from another worktree's directory.
        return subprocess.run(["bash", str(self.tree / "scripts/dev/kind" / script), *args],
                              env=env, text=True, capture_output=True, timeout=timeout, cwd=self.directory)

    def run_adapter(self, command: str, **environment: str) -> subprocess.CompletedProcess[str]:
        env = self.env | environment | {"FIXTURE_TREE": str(self.tree)}
        return subprocess.run(["bash", "-c", 'set -euo pipefail; source "$FIXTURE_TREE/scripts/dev/kind/profile.sh"; ' + command],
                              env=env, text=True, capture_output=True, timeout=300)

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
                              text=True, capture_output=True, timeout=300)

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

    def test_daemon_cw_is_the_static_musl_build_with_provenance(self) -> None:
        # The orchestration admits only a static musl cw with a source
        # provenance as a CW runtime identity; managed agents need it.
        for service, base, target, revision in (
                ("daemon", "codewire-cw-toolchain", "x86_64-unknown-linux-musl", self.revision),
                ("idp", "codewire-rust-base", "", "")):
            with self.subTest(service=service):
                self.calls_path.write_text("")
                result = self.run_script("deploy-service.sh", service)
                self.assertEqual(result.returncode, 0, result.stderr)
                bake, = [call["args"] for call in self.calls("docker") if call["args"][:2] == ["buildx", "bake"]]
                self.assertEqual(self.bake_arg(bake, "KIND_DEV_BASE"), base)
                self.assertEqual(self.bake_arg(bake, "KIND_DEV_TARGET"), target)
                self.assertEqual(self.bake_arg(bake, "KIND_DEV_SOURCE_REVISION"), revision)
        dockerfile = (ROOT / "deployments/docker/kind-dev-binary.Dockerfile").read_text()
        self.assertIn("ARG KIND_DEV_BASE=codewire-rust-base\nFROM ${KIND_DEV_BASE} AS builder\n", dockerfile)
        for line in (
            '      command=zigbuild && \\',
            '      set -- "$@" --target "$KIND_DEV_TARGET" && \\',
            '      out_dir="$CARGO_TARGET_DIR/$KIND_DEV_TARGET/kind-dev"; \\',
            "      printf '%s\\n' \"$KIND_DEV_SOURCE_REVISION\" | grep -Eqx '[0-9a-f]{40}' && \\",
            '        CODEWIRE_SOURCE_TREE_SHA256="$(sha256sum /tmp/kind-dev-sources.sha256 | cut -c1-64)" && \\',
        ):
            self.assertIn(line + "\n", dockerfile)
        bake = (ROOT / "docker-bake.hcl").read_text()
        toolchain = bake.split('target "cw-toolchain" {', 1)[1].split("}", 1)[0]
        self.assertIn('dockerfile = "images/cw-runtime/Dockerfile"', toolchain)
        self.assertIn('target     = "cw-toolchain"', toolchain)
        self.assertIn('codewire-cw-toolchain = "target:cw-toolchain"', bake)

    def test_daemon_deploy_needs_a_commit_to_name(self) -> None:
        shutil.rmtree(self.tree / ".git")
        result = self.run_script("deploy-service.sh", "daemon", GIT_CEILING_DIRECTORIES=str(self.directory))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("the worktree has no commit to name as the source revision", result.stderr)
        self.assertFalse([call for call in self.calls("docker") if call["args"][:2] == ["buildx", "bake"]])

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

    # One build per inventory group, in the inventory's order: crate,
    # features, bins, examples and test target.
    SMOKE_BUILDS = [
        (crate, "" if features == "-" else features,
         " ".join(row[4] for row in INVENTORY_ROWS if row[0] == group and row[3] == "bin"),
         " ".join(row[4] for row in INVENTORY_ROWS if row[0] == group and row[3] == "example"),
         " ".join(row[4] for row in INVENTORY_ROWS if row[0] == group and row[3] == "test"))
        for group, crate, features in dict.fromkeys(row[:3] for row in INVENTORY_ROWS)
    ]

    def run_smokes(self, *groups: str, **environment: str) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        smokes, receipt = self.directory / "smokes", self.directory / "run" / "billing-contract-build.jsonl"
        result = subprocess.run(["bash", str(self.tree / "scripts/dev/kind/build-smokes.sh"), str(smokes), str(receipt),
                                 *groups],
                                env=self.env | {"CLUSTER": "", "KIND_CLUSTER_NAME": "codewire-ux-2099"} | environment,
                                text=True, capture_output=True, timeout=300, cwd=self.directory)
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
        expected = sorted(set().union(*inventory_outputs().values()))
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

    def baked_crates(self) -> list[tuple[str, str]]:
        return [(call["crate"], call["features"]) for call in self.calls("docker") if call["args"][:2] == ["buildx", "bake"]]

    def test_smokes_build_only_the_named_groups_once_per_run(self) -> None:
        # #2973: a suite builds only its groups, and none twice in one make kind-test run.
        result, smokes, receipt = self.run_smokes("cli", KIND_SMOKE_RUN="run-a")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.baked_crates(), [("codewire-cli-bin", "")])
        self.assertTrue((smokes / "cw").exists())
        self.assertFalse(receipt.exists())
        self.calls_path.write_text("")
        result, _, receipt = self.run_smokes("orchestration", "client-kind-e2e", "cli", "billing", KIND_SMOKE_RUN="run-a")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cli smokes already built in this run", result.stderr)
        self.assertEqual(self.baked_crates(), [("codewire-orchestration", "kind-e2e"), ("codewire-client", "kind-e2e"),
                                               ("codewire-billing", "")])
        self.assertTrue(receipt.exists())
        self.calls_path.write_text("")
        result, _, _ = self.run_smokes("cli", "orchestration", KIND_SMOKE_RUN="run-a")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.baked_crates(), [])
        # Another run, or a caller that names no run, builds again.
        for environment in ({"KIND_SMOKE_RUN": "run-b"}, {}, {}):
            self.calls_path.write_text("")
            result, _, _ = self.run_smokes("cli", **environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.baked_crates(), [("codewire-cli-bin", "")])

    def test_smokes_record_only_a_group_that_built(self) -> None:
        result, _, _ = self.run_smokes("orchestration", "client", KIND_SMOKE_RUN="run-a", FAKE_BAKE_FAIL="codewire-client")
        self.assertNotEqual(result.returncode, 0)
        self.calls_path.write_text("")
        result, _, _ = self.run_smokes("orchestration", "client", KIND_SMOKE_RUN="run-a")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.baked_crates(), [("codewire-client", "")])

    def test_smokes_refuse_an_unknown_group(self) -> None:
        result, _, _ = self.run_smokes("cli", "smokes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown smoke group: smokes", result.stderr)
        self.assertFalse(self.calls("docker"))

    def test_one_selected_run_shares_one_smoke_run(self) -> None:
        for _ in range(2):
            result = self.run_script("test-selected.sh", KIND_TEST_SUITES="workspace-services credentials", CLUSTER="",
                                     KIND_CLUSTER_NAME="codewire-ux-2099")
            self.assertEqual(result.returncode, 0, result.stderr)
        runs = [call["smoke_run"] for call in self.calls("suite")]
        self.assertEqual(len(runs), 4)
        self.assertTrue(all(runs))
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[2], runs[3])
        self.assertNotEqual(runs[0], runs[2])

    def test_smokes_refuse_relative_destinations(self) -> None:
        result = subprocess.run(["bash", str(self.tree / "scripts/dev/kind/build-smokes.sh"), "smokes", "receipt.jsonl"],
                                env=self.env | {"CLUSTER": ""}, text=True, capture_output=True, timeout=300)
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
        self.assertEqual(re.findall(r"cargo (?:\"\$command\"|test) --locked (--config \S+ --profile \S+)", builder),
                         ["--config scripts/dev/kind/cargo-profile.toml --profile kind-dev"] * 3)
        self.assertNotIn("$CARGO_TARGET_DIR/ci/", builder)
        self.assertIn('    out_dir="$CARGO_TARGET_DIR/kind-dev" && \\\n', builder)
        self.assertEqual(builder.count('"$out_dir/'), 2)

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
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="edge-contract", timeout=300,
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

    def test_selected_cli_and_workspace_access_run_the_user_ssh_journey(self) -> None:
        # The workspace-services suite runs the user SSH journey (common.sh
        # workspace_user_ssh_smoke): the CLI and workspace-access crates select it.
        for token, crate in (("rust_pkg_codewire_cli", "codewire-cli"),
                             ("rust_pkg_codewire_workspace_access", "codewire-workspace-access")):
            with self.subTest(token=token):
                self.calls_path.write_text("")
                result = self.run_script("test-selected.sh", FAKE_SELECTION=f"rust|{token}",
                                         FAKE_CHANGES=f"crate {crate}")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertRegex(result.stderr, rf"suite workspace-services: (.*, )?{token}(,|\n|$)")
                self.assertIn("workspace-services", [call["args"][1] for call in self.calls("suite")])

    def test_selected_full_gate_runs_and_deploys_nothing(self) -> None:
        for name, environment, reason in (
            ("server core", {"FAKE_SELECTION": "rust|rust_pkg_codewire_server_core|rust_pkg_codewire_orchestration",
                             "FAKE_CHANGES": "crate codewire-server-core;service idp"}, "every service compiles it"),
            ("server core beside a migration",
             {"FAKE_SELECTION": "database|rust|rust_pkg_codewire_server_core",
              "FAKE_CHANGES": "crate codewire-server-core;migration crates/codewire-server-core/migrations/0099_x.sql;service idp"},
             "every service compiles it"),
            ("unmapped crate", {"FAKE_SELECTION": "rust|rust_pkg_codewire_future_crate"}, "no retained suite is mapped"),
            ("unclassified", {"FAKE_CLASSIFICATION": "unclassified", "FAKE_SELECTION": "web"}, "cannot classify"),
            ("manifest only", {"FAKE_SELECTION": "deploy|policy"}, "no narrower suite"),
            # Kind is no local mode any more; the local
            # selection carries the kind token of a Kind-relevant path.
            ("Kind harness or ingress", {"FAKE_SELECTION": "kind|policy|policy_shell"}, "no narrower suite"),
        ):
            with self.subTest(name):
                self.calls_path.write_text("")
                result = self.run_script("test-selected.sh", **environment)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertIn("only the full CI Kind gate covers this change", result.stderr)
                self.assertIn(reason, result.stderr)
                self.assertFalse([call for call in self.calls() if call["tool"] in ("docker", "kind", "suite")])

    def test_selected_migration_upgrades_the_cluster_database(self) -> None:
        migration = "crates/codewire-server-core/migrations/0041_claude_sign_in_credentials"
        changes = f"migration {migration}.up.sql;migration {migration}.down.sql;service idp;service orchestration"
        stale = current_records("idp", "orchestration")
        # The selector reports the migration as a server-core change; alone it
        # selects the edge contract, which reaches every upgraded service.
        result = self.run_script("test-selected.sh", FAKE_SELECTION="database|rust|rust_pkg_codewire_server_core",
                                 FAKE_CHANGES=changes, FAKE_RECORDS=stale, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("only the full CI Kind gate", result.stderr)
        self.assertIn("suite edge-contract: 0041_claude_sign_in_credentials.up.sql", result.stderr)
        self.assertEqual([call["args"] for call in self.calls("suite")], [["suite", "edge-contract"]])
        calls = self.calls()
        prepares = [i for i, call in enumerate(calls) if call["tool"] == "database"]
        bakes = [i for i, call in enumerate(calls) if call["tool"] == "docker" and call["args"][:2] == ["buildx", "bake"]]
        self.assertEqual([calls[i]["args"] for i in prepares], [["prepare"], ["prepare"]])
        self.assertEqual([calls[i]["crate"] for i in bakes], ["codewire-idp", "codewire-orchestration"])
        self.assertLess(prepares[0], bakes[0])
        self.assertLess(prepares[1], bakes[1])
        # Named suites run beside a migration as they would without one.
        self.calls_path.write_text("")
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="credentials", FAKE_CHANGES=changes,
                                 FAKE_RECORDS=stale, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["args"] for call in self.calls("suite")], [["suite", "credentials"]])

    def test_deploy_stops_when_the_database_is_ahead_of_the_tree(self) -> None:
        for service in ("idp", "orchestration", "billing", "coordinator", "mesh"):
            with self.subTest(service=service):
                self.calls_path.write_text("")
                result = self.run_script("deploy-service.sh", service, FAKE_DATABASE_STATUS="1")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual([call["args"] for call in self.calls("database")], [["prepare"]])
                # Nothing is built, loaded or restarted.
                self.assertFalse(self.calls("docker"))
                self.assertEqual([call["args"] for call in self.calls("kind")], [["get", "clusters"]])
                self.assertFalse(self.calls("kubectl"))
        # The others run no migrations and never consult the database.
        for service in ("credential-service", "dashboard", "daemon"):
            with self.subTest(service=service):
                self.calls_path.write_text("")
                result = self.run_script("deploy-service.sh", service, FAKE_DATABASE_STATUS="1")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(self.calls("database"))
        # A service already running this source restarts nothing and skips it.
        self.calls_path.write_text("")
        result = self.run_script("deploy-service.sh", "idp", KIND_DEPLOY_SKIP_CURRENT="1", FAKE_DATABASE_STATUS="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.calls("database"))

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

    def test_credential_stages_are_the_suites(self) -> None:
        selected = (CONSUMERS / "scripts/dev/kind/test-selected.sh").read_text()
        journey = (ROOT / "scripts/ci/verify/kind/suites/credential-journey.sh").read_text()
        stages = re.search(r"^CREDENTIAL_STAGES=\(([^)]*)\)", selected, re.M)
        order = re.search(r"^KIND_CREDENTIAL_STAGE_ORDER=\(([^)]*)\)", journey, re.M)
        self.assertIsNotNone(stages)
        self.assertIsNotNone(order)
        self.assertEqual(stages.group(1).split(), order.group(1).split())

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

    def run_browser_selection(self, **environment: str) -> subprocess.CompletedProcess[str]:
        playwright = self.tree / "apps/dashboard/node_modules/.bin/playwright"
        if not playwright.exists():
            playwright.parent.mkdir(parents=True)
            self.write_program(playwright, "#!/bin/sh\n")
        self.calls_path.write_text("")
        return self.run_script("test-selected.sh", FAKE_FRONTEND_URL="http://127.0.0.1:31100", **environment)

    def test_a_dashboard_change_runs_only_the_specs_it_affects(self) -> None:
        # #2974: the affected-spec map chooses the dashboard browser specs.
        result = self.run_browser_selection(FAKE_SELECTION="rust|rust_pkg_codewire_dashboard_web",
                                            FAKE_DASHBOARD_SPECS="specs ssr-dashboard.read.ssr.ts")
        self.assertEqual(result.returncode, 0, result.stderr)
        choose, = self.calls("dashboard-specs")
        self.assertEqual(choose["args"], ["select", "--base", "f" * 40])
        self.assertEqual([(call["args"], call["dashboard_selection"]) for call in self.calls("suite")],
                         [(["suite", "dashboard-browser"], "specs ssr-dashboard.read.ssr.ts")])
        self.assertIn("dashboard-browser specs ssr-dashboard.read.ssr.ts only: not the whole dashboard-browser suite",
                      result.stderr)
        self.assertIn("which is not the whole dashboard-browser suite", result.stderr)
        # Unmapped changes, named suites and DASHBOARD_TESTS=all run every spec.
        result = self.run_browser_selection(FAKE_SELECTION="web", FAKE_DASHBOARD_SPECS="all packages/x is not mapped")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("dashboard-browser runs every spec: packages/x is not mapped", result.stderr)
        self.assertEqual([call["dashboard_selection"] for call in self.calls("suite")], [""])
        for environment in ({"KIND_TEST_SUITES": "dashboard-browser"},
                            {"FAKE_SELECTION": "web", "KIND_DASHBOARD_TESTS": "all"}):
            with self.subTest(environment=environment):
                result = self.run_browser_selection(FAKE_DASHBOARD_SPECS="specs ssr-dashboard.read.ssr.ts",
                                                    **environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(self.calls("dashboard-specs"))
                self.assertEqual([call["dashboard_selection"] for call in self.calls("suite")], [""])

    def test_dashboard_tests_choose_smoke_or_light_runs(self) -> None:
        for tests in ("smoke", "light"):
            with self.subTest(tests=tests):
                result = self.run_browser_selection(KIND_TEST_SUITES="dashboard-browser credentials",
                                                    KIND_DASHBOARD_TESTS=tests)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([(call["args"][-1], call["dashboard_selection"]) for call in self.calls("suite")],
                                 [("credentials", ""), ("dashboard-browser", tests)])
        for environment, message in (
                ({"KIND_TEST_SUITES": "dashboard-browser", "KIND_DASHBOARD_TESTS": "fast"}, "unknown DASHBOARD_TESTS: fast"),
                ({"KIND_TEST_SUITES": "credentials", "KIND_DASHBOARD_TESTS": "smoke"}, "which this run does not select"),
                ({"FAKE_SELECTION": "web", "FAKE_DASHBOARD_SPECS_FAIL": "1"}, "could not choose the dashboard browser specs")):
            with self.subTest(environment=environment):
                result = self.run_browser_selection(**environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(self.calls("suite"))

    def test_browser_suite_runs_four_workers_unless_told_otherwise(self) -> None:
        # #2974: the per-worker identities let a local run use four workers, as CI does.
        (self.tree / "apps/dashboard/node_modules/.bin").mkdir(parents=True)
        self.write_program(self.tree / "apps/dashboard/node_modules/.bin/playwright", "#!/bin/sh\n")
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="dashboard-browser",
                                 FAKE_FRONTEND_URL="http://127.0.0.1:31100")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="dashboard-browser",
                                 FAKE_FRONTEND_URL="http://127.0.0.1:31100", CODEWIRE_KIND_DASHBOARD_WORKERS="2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["dashboard_workers"] for call in self.calls("suite")], ["4", "2"])

    def test_credential_stages_reach_only_the_credentials_suite(self) -> None:
        # #2890: rerun one credentials stage; it never reads as a green suite.
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="workspace-services credentials",
                                 KIND_CREDENTIAL_STAGES="claude-sign-in")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([(call["args"], call["credential_stages"]) for call in self.calls("suite")],
                         [(["suite", "credentials"], "claude-sign-in"), (["suite", "workspace-services"], "")])
        self.assertIn("credentials stages claude-sign-in only: not a green credentials suite", result.stderr)
        self.assertIn("credentials ran only stages claude-sign-in, which is not a green credentials suite",
                      result.stderr)
        self.assertNotIn("all selected suites green", result.stderr)
        self.assertNotIn("suite credentials green", result.stderr)
        # Named out of order, the stages run in suite order.
        self.calls_path.write_text("")
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="credentials",
                                 KIND_CREDENTIAL_STAGES="claude-sign-in native")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["credential_stages"] for call in self.calls("suite")], ["native claude-sign-in"])

    def test_credentials_suite_is_whole_by_default(self) -> None:
        # Unset, empty, or every stage named: the whole suite, reported as such.
        for stages in (None, "", "claude-sign-in claude-session native"):
            with self.subTest(stages=stages):
                self.calls_path.write_text("")
                environment = {"KIND_TEST_SUITES": "credentials"}
                if stages is not None:
                    environment["KIND_CREDENTIAL_STAGES"] = stages
                result = self.run_script("test-selected.sh", **environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([call["credential_stages"] for call in self.calls("suite")], [""])
                self.assertIn("suite credentials green", result.stderr)
                self.assertIn("all selected suites green", result.stderr)
                self.assertNotIn("not a green credentials suite", result.stderr)

    def test_credential_stages_are_refused_before_any_effect(self) -> None:
        for environment, message in (
                ({"KIND_TEST_SUITES": "credentials", "KIND_CREDENTIAL_STAGES": "claude"},
                 "unknown credentials stage: claude"),
                ({"KIND_TEST_SUITES": "workspace-services", "KIND_CREDENTIAL_STAGES": "claude-sign-in"},
                 "which this run does not select")):
            with self.subTest(**environment):
                self.calls_path.write_text("")
                result = self.run_script("test-selected.sh", FAKE_CHANGES="service idp",
                                         FAKE_RECORDS=current_records("idp"), **environment)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(message, result.stderr)
                self.assertFalse([call for call in self.calls() if call["tool"] in ("docker", "kind", "suite")])

    def test_make_kind_test_passes_credential_stages(self) -> None:
        (self.tree / "Makefile").write_text(MAKEFILE_SOURCE)
        (self.tree / ".env").write_text("AGENT_SANDBOX_SHA=synthetic\nBUF=synthetic-buf\nGO_BIN=/synthetic/bin\n")
        for arguments, stages in ((("SUITES=credentials", "CREDENTIAL_STAGES=claude-sign-in"), "claude-sign-in"),
                                  (("SUITES=credentials",), "")):
            with self.subTest(arguments=arguments):
                self.calls_path.write_text("")
                # A stage list exported in the shell does not leak into a run
                # that names none.
                result = subprocess.run(["make", "--no-print-directory", "kind-test", *arguments],
                                        cwd=self.tree, env=self.env | {"KIND_CREDENTIAL_STAGES": "native"},
                                        text=True, capture_output=True, timeout=300)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([call["credential_stages"] for call in self.calls("suite")], [stages])

    def test_selected_stops_when_changes_are_unknown(self) -> None:
        result = self.run_script("test-selected.sh", KIND_TEST_SUITES="credentials", FAKE_CHANGES_FAIL="1")
        self.assertEqual(result.returncode, 1)
        self.assertFalse([call for call in self.calls() if call["tool"] != "profile"])


def load_service_sources():
    spec = importlib.util.spec_from_file_location("service_sources", CONSUMERS / "scripts/dev/kind/service-sources.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_dashboard_specs():
    spec = importlib.util.spec_from_file_location("dashboard_specs", ROOT / "scripts/dev/kind/dashboard-specs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DashboardSpecTests(unittest.TestCase):
    """#2974: the Kind dashboard specs a change affects."""

    CRATE = "crates/codewire-dashboard-web"
    E2E = "apps/dashboard/e2e"
    COVERS = {
        "ssr-dashboard.read.ssr.ts": {"templates/dashboard.html", "src/routes/environments.rs"},
        "ssr-dashboard.organization.ssr.ts": {"src/routes/organizations.rs", "src/routes/environments.rs"},
        "ssr-dashboard.settings.ssr.ts": {"src/routes/credentials.rs"},
    }
    FIXTURES = {"ssr-dashboard.resize.ssr.ts"}

    def setUp(self) -> None:
        self.module = load_dashboard_specs()

    def select(self, *paths: str) -> tuple[str, list[str]]:
        return self.module.select(list(paths), self.COVERS, self.FIXTURES)

    def test_a_mapped_dashboard_change_selects_the_specs_covering_it(self) -> None:
        self.assertEqual(self.select(f"{self.CRATE}/templates/dashboard.html"),
                         ("specs", ["ssr-dashboard.read.ssr.ts"]))
        self.assertEqual(self.select(f"{self.CRATE}/src/routes/environments.rs", f"{self.CRATE}/src/routes/credentials.rs",
                                     "docs/TESTING.md"),
                         ("specs", ["ssr-dashboard.organization.ssr.ts", "ssr-dashboard.read.ssr.ts",
                                    "ssr-dashboard.settings.ssr.ts"]))

    def test_anything_unmapped_runs_every_spec(self) -> None:
        for paths in ([f"{self.CRATE}/src/routes/dashboard.rs"], [f"{self.CRATE}/templates/dashboard.html", f"{self.CRATE}/Cargo.toml"],
                      [f"{self.CRATE}/assets/htmx-2.0.10.min.js"], ["packages/codewire-design/src/tokens.css"],
                      ["crates/codewire-idp/src/lib.rs"], [f"{self.E2E}/global-setup.ts"], ["apps/dashboard/playwright.config.ts"],
                      [f"{self.E2E}/seed-users.ts"], []):
            with self.subTest(paths=paths):
                kind, _ = self.select(*paths)
                self.assertEqual(kind, "all")

    def test_a_browser_test_change_runs_what_playwright_finds_changed(self) -> None:
        for paths in ([f"{self.E2E}/ssr-dashboard.read.ssr.ts"], [f"{self.E2E}/helpers/org.ts"], [f"{self.E2E}/auth.setup.ts"],
                      [f"{self.E2E}/helpers/org.ts", f"{self.E2E}/helpers/org.test.ts", f"{self.E2E}/ssr-dashboard.resize.ssr.ts"]):
            with self.subTest(paths=paths):
                self.assertEqual(self.select(*paths), ("only-changed", []))
        # Playwright cannot add specs to the ones it finds changed.
        self.assertEqual(self.select(f"{self.E2E}/helpers/org.ts", f"{self.CRATE}/templates/dashboard.html")[0], "all")
        # A helper unit test or a design fixture never runs in Kind.
        self.assertEqual(self.select(f"{self.E2E}/helpers/org.test.ts", f"{self.CRATE}/templates/dashboard.html"),
                         ("specs", ["ssr-dashboard.read.ssr.ts"]))

    def test_every_kind_spec_is_mapped_to_files_that_exist(self) -> None:
        self.assertEqual(self.module.check(ROOT), [])
        covers = self.module.spec_covers(ROOT)
        fixtures = self.module.design_fixture_specs(ROOT)
        self.assertIn("ssr-dashboard.environment-lifecycle.ssr.ts", covers)
        self.assertFalse(set(covers) & fixtures)
        self.assertEqual(set(covers) | fixtures,
                         {path.name for path in (ROOT / self.E2E).glob("ssr-dashboard.*.ssr.ts")})

    def test_check_rejects_a_missing_stale_or_shared_mapping(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / ".tmp") as temporary:
            root = Path(temporary)
            (root / self.E2E / "helpers").mkdir(parents=True)
            shutil.copy2(ROOT / self.E2E / "helpers/design-fixtures.ts", root / self.E2E / "helpers/design-fixtures.ts")
            for relative in self.module.SHARED + ("templates/dashboard.html",):
                (root / self.CRATE / relative).parent.mkdir(parents=True, exist_ok=True)
                (root / self.CRATE / relative).write_text("")
            specs = {
                "ssr-dashboard.mapped.ssr.ts": "// covers: templates/dashboard.html\nimport x;\n",
                "ssr-dashboard.unmapped.ssr.ts": "import x;\n// covers: templates/dashboard.html\n",
                "ssr-dashboard.stale.ssr.ts": "// covers: templates/gone.html\n",
                "ssr-dashboard.shared.ssr.ts": "// covers: templates/sidebar.html\n",
                "ssr-dashboard.resize.ssr.ts": "",
            }
            for name, text in specs.items():
                (root / self.E2E / name).write_text(text)
            self.assertEqual(sorted(self.module.check(root)), [
                "ssr-dashboard.shared.ssr.ts covers the shared templates/sidebar.html; a change to it runs every spec",
                "ssr-dashboard.stale.ssr.ts covers templates/gone.html, which does not exist",
                "ssr-dashboard.unmapped.ssr.ts has no `// covers:` lines",
            ])

    def test_select_prints_the_merge_base_for_only_changed(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / ".tmp") as temporary:
            root = Path(temporary)
            git = ["git", "-C", str(root), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid"]
            subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
            (root / "base.txt").write_text("base\n")
            subprocess.run([*git, "add", "."], check=True)
            subprocess.run([*git, "commit", "-q", "-m", "base"], check=True)
            base = subprocess.run([*git, "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
            subprocess.run([*git, "switch", "-q", "-c", "change"], check=True)
            (root / "committed.txt").write_text("x\n")
            subprocess.run([*git, "add", "."], check=True)
            subprocess.run([*git, "commit", "-q", "-m", "change"], check=True)
            (root / "base.txt").write_text("edited\n")
            (root / "untracked.txt").write_text("new\n")
            merge_base, changed = self.module.changed_paths(root, "main")
            self.assertEqual(merge_base, base)
            self.assertEqual(changed, ["base.txt", "committed.txt", "untracked.txt"])


def shell_functions(*paths: Path) -> dict[str, str]:
    """Every top-level shell function's body, up to the next definition,
    without its comment lines."""
    functions: dict[str, str] = {}
    for path in paths:
        lines = [line for line in path.read_text().split("\n") if not line.lstrip().startswith("#")]
        starts = [(index, match.group(1)) for index, line in enumerate(lines)
                  if (match := re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*[{(]", line))]
        for position, (index, name) in enumerate(starts):
            end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
            functions[name] = "\n".join(lines[index + 1:end])
    return functions


class SmokeGroupTests(unittest.TestCase):
    # The builders themselves; every suite calls them.
    BUILDERS = {"build_retained_kind_smokes", "build_images_and_smokes", "use_kind_profile_smokes",
                "prepare_kind_profile_runtime_inputs"}

    def test_each_suite_builds_every_smoke_it_runs(self) -> None:
        # #2973: a suite builds only its groups, so its groups hold every
        # smoke binary its functions run, through any helper they call.
        kind = ROOT / "scripts/ci/verify/kind"
        functions = shell_functions(kind / "common.sh", *sorted(kind.glob("*.sh")), *sorted((kind / "suites").glob("*.sh")))
        runs = {name: set(re.findall(r'\$\{?CARGO_CI_DIR\}?/((?:examples/)?[a-z][a-z0-9-]*)', body))
                | ({"kind-smoke-tests/wire_contract"} if name not in self.BUILDERS
                   and "billing-contract-build.jsonl" in body else set())
                for name, body in functions.items()}
        calls = {name: {other for other in functions if other != name and other not in self.BUILDERS
                        and re.search(rf"(?<![\w-]){re.escape(other)}(?![\w-])", body)}
                 for name, body in functions.items()}

        def closure(name: str, seen: set[str]) -> set[str]:
            if name in seen:
                return set()
            seen.add(name)
            return runs[name].union(*(closure(other, seen) for other in calls[name]))

        outputs = inventory_outputs()
        self.assertEqual(set(outputs), {"orchestration", "client", "client-kind-e2e", "cli", "billing"})
        common = (kind / "common.sh").read_text()
        table = common[common.index("kind_suite_smoke_groups() {"):common.index("esac", common.index("kind_suite_smoke_groups() {"))]
        mapped = {}
        for suites, groups in re.findall(r"^\s+([a-z0-9| -]+)\)\s*printf '%s\\n' ([a-z0-9 -]+);;", table, re.M):
            for suite in suites.replace("|", " ").split():
                mapped[suite] = groups.split()
        entries = {
            "edge-contract": "run_retained_edge_contract_suite", "credentials": "run_retained_credentials_suite",
            "workspace-services": "run_retained_workspace_services_suite",
            "final-fencing": "run_retained_final_fencing_suite", "integrated": "run_retained_integrated_suite",
            "runtime-acceptance": "run_retained_runtime_acceptance_suite",
            "cw-runtime": "run_admitted_cw_runtime_journey", "cw-managed-agents": "run_retained_managed_agents_journey",
        }
        self.assertEqual(set(mapped), set(entries))
        for suite, entry in entries.items():
            with self.subTest(suite=suite):
                self.assertIn(f"build_retained_kind_smokes {suite}\n", functions[entry] + "\n")
                built = set().union(*(outputs[group] for group in mapped[suite]))
                needed = closure(entry, set())
                self.assertTrue(needed, f"{suite} runs no smoke binary")
                self.assertLessEqual(needed, built, f"{suite} runs smokes outside its groups")
        # And the inventory builds nothing no suite runs (sidecar-smoke was
        # built for every Kind run and run by none).
        run_anywhere = set().union(*(closure(entry, set()) for entry in entries.values()))
        unused = set().union(*outputs.values()) - run_anywhere
        self.assertFalse(unused, f"the smoke inventory builds programs no Kind suite runs: {sorted(unused)}")


class SelectionTableTests(unittest.TestCase):
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
                                env=self.env, text=True, capture_output=True, timeout=300)
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
        # It feeds every service that embeds it, but changes no crate's code.
        self.assertEqual(self.changes(), ["migration crates/codewire-server-core/migrations/0002_next.sql"] + [
            f"service {name}" for name in ("idp", "orchestration", "credential-service", "billing", "mesh", "dashboard")])
        self.edit("crates/codewire-server-core/src/lib.rs")
        self.assertIn("crate codewire-server-core", self.changes())

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


# Stands in for kubectl against the retained cluster's Postgres and services:
# FAKE_LEDGERS maps each existing database to its SQLx ledger rows.
FAKE_DATABASE_KUBECTL = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
state = pathlib.Path(os.environ["FAKE_STATE"])
args = sys.argv[1:]
stdin = sys.stdin.read() if "-i" in args else ""
with (state / "calls").open("a") as log:
    log.write(json.dumps({"args": args, "stdin": stdin}) + "\n")
ledgers = json.loads(os.environ["FAKE_LEDGERS"])
if os.environ.get("FAKE_KUBE_FAIL") and any(os.environ["FAKE_KUBE_FAIL"] in arg for arg in args): sys.exit(29)
if "exec" in args:
    command = args[args.index("--") + 1:]
    database = command[command.index("-d") + 1]
    sql = " ".join(command[i + 1] for i, arg in enumerate(command) if arg == "-c")
    if command[0] == "pg_dump": sys.stdout.write("archive of " + database)
    elif "FROM pg_database" in sql:
        if sql.split("datname = '")[1].split("'")[0] in ledgers: print(1)
    elif "to_regclass" in sql: print("t" if ledgers.get(database) else "f")
    elif "FROM _sqlx_migrations" in sql:
        for row in ledgers[database]: print(" ".join(str(field) for field in row))
elif "get" in args and "deployment" in " ".join(args):
    deployment = next(arg for arg in args if arg.startswith("deployment/")).split("/", 1)[1]
    if any("spec.replicas" in arg for arg in args):
        print(json.loads(os.environ.get("FAKE_REPLICAS", "{}")).get(deployment, 1), end="")
    else: print(f"app={deployment},", end="")
elif "get" in args and "pods" in args and args[args.index("-l") + 1].startswith("app="):
    print("pod/" + args[args.index("-l") + 1].split("=", 1)[1] + "-0")
'''


def sha384(text: str) -> str:
    return hashlib.sha384(text.encode()).hexdigest()


class DatabaseTests(unittest.TestCase):
    """scripts/dev/kind/database.sh: upgrade with a backup, refuse a downgrade, reset, restore."""

    MIGRATIONS = {
        "crates/codewire-server-core/migrations/0001_baseline.sql": "create table a();\n",
        "crates/codewire-server-core/migrations/0002_next.up.sql": "create table b();\n",
        "crates/codewire-server-core/migrations/0002_next.down.sql": "drop table b;\n",
        "crates/codewire-mesh/migrations/001_mesh.sql": "create table m();\n",
    }
    FIXTURES = {"tests/fixtures/billing/seed.sql": "-- billing seed\n",
                "tests/e2e/kind/coordinator-seed.sql": "-- coordinator seed\n",
                "tests/e2e/kind/credential-broker.sql": "-- credential login\n"}

    def setUp(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(prefix="kind-database.", dir=ROOT / ".tmp")
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.tree = self.directory / "tree"
        self.state = self.directory / "state"
        tools = self.directory / "bin"
        for path in (self.tree / "scripts/dev/kind", self.state, tools):
            path.mkdir(parents=True)
        for name in ("database.sh", "profile.sh"):
            shutil.copy2(CONSUMERS / "scripts/dev/kind" / name, self.tree / "scripts/dev/kind" / name)
        for path, text in (self.MIGRATIONS | self.FIXTURES).items():
            (self.tree / path).parent.mkdir(parents=True, exist_ok=True)
            (self.tree / path).write_text(text)
        DeveloperProfileTests.write_program(tools / "kubectl", FAKE_DATABASE_KUBECTL)
        self.calls_path = self.state / "calls"
        self.backups = self.directory / "home/.cache/codewire/kind/codewire-ux-2099/database-backups"
        self.env = {"PATH": f"{tools}:{os.environ['PATH']}", "FAKE_STATE": str(self.state),
                    "HOME": str(self.directory / "home"), "KIND_CLUSTER_NAME": "codewire-ux-2099",
                    "FAKE_LEDGERS": json.dumps(self.ledgers())}

    def ledgers(self, *extra: list[object], through: int = 2) -> dict[str, list[list[object]]]:
        """The ledgers of a cluster current with the tree through THROUGH, plus EXTRA codewire rows."""
        rows = [[1, sha384(self.MIGRATIONS["crates/codewire-server-core/migrations/0001_baseline.sql"]), "t", "baseline"],
                [2, sha384(self.MIGRATIONS["crates/codewire-server-core/migrations/0002_next.up.sql"]), "t", "next"]]
        return {"codewire": rows[:through] + list(extra),
                "codewire_mesh": [[1, sha384(self.MIGRATIONS["crates/codewire-mesh/migrations/001_mesh.sql"]), "t", "mesh"]]}

    def run_database(self, *args: str, **environment: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["bash", str(self.tree / "scripts/dev/kind/database.sh"), *args], stdin=subprocess.DEVNULL,
                              env=self.env | environment, text=True, capture_output=True, timeout=300, cwd=self.directory)

    def calls(self) -> list[dict[str, object]]:
        if not self.calls_path.exists():
            return []
        return [json.loads(line) for line in self.calls_path.read_text().splitlines()]

    def commands(self) -> list[str]:
        """Each call as one line: the kubectl verb and its SQL or target."""
        lines = []
        for call in self.calls():
            args = call["args"]
            if "exec" in args:
                command = args[args.index("--") + 1:]
                sql = [command[i + 1] for i, arg in enumerate(command) if arg == "-c"]
                lines.append(" ".join([command[0], command[command.index("-d") + 1]] + sql + ([call["stdin"]] if call["stdin"] else [])))
            else:
                # Without --context and the namespace, which every call names.
                namespace = args.index("-n")
                lines.append(" ".join(args[2:namespace] + args[namespace + 2:]))
        return lines

    def backup_names(self) -> list[str]:
        return sorted(path.name for path in self.backups.iterdir()) if self.backups.exists() else []

    def test_current_database_needs_no_backup(self) -> None:
        result = self.run_database("prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertFalse([line for line in self.commands() if line.startswith("pg_dump")])
        self.assertEqual(self.backup_names(), [])

    def test_new_migration_is_backed_up_before_the_deploy(self) -> None:
        result = self.run_database("prepare", FAKE_LEDGERS=json.dumps(self.ledgers(through=1)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("this deploy applies new migrations to codewire-ux-2099:\n[kind-db]   codewire 0002_next.up.sql\n",
                      result.stderr)
        backup, = self.backup_names()
        self.assertRegex(backup, r"^\d{8}T\d{6}Z-upgrade$")
        self.assertIn(f"backed up codewire-ux-2099's databases to {self.backups / backup}", result.stderr)
        self.assertEqual((self.backups / backup).stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.backups / backup / "codewire.dump").read_text(), "archive of codewire")
        self.assertEqual((self.backups / backup / "codewire_mesh.dump").read_text(), "archive of codewire_mesh")
        baseline = sha384(self.MIGRATIONS["crates/codewire-server-core/migrations/0001_baseline.sql"])
        mesh = sha384(self.MIGRATIONS["crates/codewire-mesh/migrations/001_mesh.sql"])
        self.assertEqual((self.backups / backup / "ledger").read_text(),
                         f"codewire 1 {baseline}\ncodewire_mesh 1 {mesh}\n")
        # Backing up only reads.
        commands = self.commands()
        self.assertEqual([line for line in commands if line.startswith("pg_dump")], ["pg_dump codewire", "pg_dump codewire_mesh"])
        self.assertTrue(all(line.startswith("pg_dump") or " SELECT " in line for line in commands), commands)

    def test_a_missing_database_is_not_backed_up(self) -> None:
        ledgers = self.ledgers(through=1)
        del ledgers["codewire_mesh"]
        result = self.run_database("prepare", FAKE_LEDGERS=json.dumps(ledgers))
        self.assertEqual(result.returncode, 0, result.stderr)
        backup, = self.backup_names()
        self.assertEqual(sorted(path.name for path in (self.backups / backup).iterdir()), ["codewire.dump", "ledger"])

    def test_only_the_newest_backups_are_kept(self) -> None:
        for second in range(6):
            (self.backups / f"20200101T00000{second}Z-upgrade").mkdir(parents=True)
        result = self.run_database("prepare", FAKE_LEDGERS=json.dumps(self.ledgers(through=1)))
        self.assertEqual(result.returncode, 0, result.stderr)
        names = self.backup_names()
        self.assertEqual(names[:4], [f"20200101T00000{second}Z-upgrade" for second in range(2, 6)])
        self.assertEqual(len(names), 5)
        result = self.run_database("prepare", FAKE_LEDGERS=json.dumps(self.ledgers(through=1)), KIND_DB_BACKUP_KEEP="0")
        self.assertEqual(result.returncode, 1)
        self.assertIn("KIND_DB_BACKUP_KEEP must be a positive integer", result.stderr)

    def test_a_database_ahead_of_the_tree_is_refused(self) -> None:
        ahead = json.dumps(self.ledgers([3, "ab" * 48, "t", "claude sign in credentials"]))
        result = self.run_database("prepare", FAKE_LEDGERS=ahead)
        self.assertEqual(result.returncode, 1)
        self.assertIn("codewire-ux-2099's database is ahead of this tree", result.stderr)
        self.assertIn("codewire has migration 3 (claude sign in credentials), which this tree lacks", result.stderr)
        self.assertIn("make kind-db-reset", result.stderr)
        self.assertNotIn("kind-db-restore", result.stderr)
        self.assertFalse([line for line in self.commands() if not line.startswith("psql")])
        self.assertEqual(self.backup_names(), [])
        # The newest backup whose every migration this tree has is offered.
        baseline = sha384(self.MIGRATIONS["crates/codewire-server-core/migrations/0001_baseline.sql"])
        for name, ledger in (("20260101T000000Z-upgrade", f"codewire 1 {baseline}\n"),
                             ("20260102T000000Z-upgrade", f"codewire 1 {baseline}\ncodewire 3 {'ab' * 48}\n")):
            (self.backups / name).mkdir(parents=True)
            (self.backups / name / "ledger").write_text(ledger)
        result = self.run_database("prepare", FAKE_LEDGERS=ahead)
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"make kind-db-restore BACKUP={self.backups / '20260101T000000Z-upgrade'}", result.stderr)

    def test_other_bytes_or_a_failed_migration_are_refused(self) -> None:
        for name, ledger, message in (
            ("other bytes", {"codewire": [[1, sha384("create table a();\n"), "t", "baseline"], [2, "cd" * 48, "t", "next"]]},
             "codewire applied migration 2 (next) from other bytes than this tree's 0002_next.up.sql"),
            ("mesh other bytes", self.ledgers() | {"codewire_mesh": [[1, "ef" * 48, "t", "mesh"]]},
             "codewire_mesh applied migration 1 (mesh) from other bytes than this tree's 001_mesh.sql"),
            ("failed", {"codewire": [[1, sha384("create table a();\n"), "f", "baseline"]]},
             "codewire records migration 1 (baseline) as failed"),
        ):
            with self.subTest(name):
                result = self.run_database("prepare", FAKE_LEDGERS=json.dumps(ledger))
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stderr)
                self.assertEqual(self.backup_names(), [])

    def test_an_unreadable_ledger_stops_the_deploy(self) -> None:
        result = self.run_database("prepare", FAKE_KUBE_FAIL="_sqlx_migrations ORDER BY")
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot read codewire's migration ledger", result.stderr)

    def test_reset_recreates_the_databases_and_reloads_the_fixtures(self) -> None:
        result = self.run_database("reset", FAKE_REPLICAS=json.dumps({"codewire-mesh": 0}))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(self.backup_names()[0], r"-before-reset$")
        services = ["codewire-idp", "codewire-billing", "codewire-mesh", "codewire-orchestration",
                    "codewire-coordinator", "codewire-credential-service"]
        lines = [line for line in self.commands()
                 if not line.startswith(("psql postgres SELECT", "psql codewire SELECT", "psql codewire_mesh SELECT"))]
        sandbox_kinds = ["sandboxclaims.extensions.agents.x-k8s.io", "sandboxes.agents.x-k8s.io", "pods", "services",
                         "persistentvolumeclaims", "secrets", "configmaps"]
        expected = ["pg_dump codewire", "pg_dump codewire_mesh"]
        for service in services:
            expected += [f"get deployment/{service} -o jsonpath={{.spec.replicas}}",
                         f"get deployment/{service} -o go-template={{{{range $k, $v := .spec.selector.matchLabels}}}}"
                         "{{$k}}={{$v}},{{end}}",
                         f"get pods -l app={service} -o name"]
        expected += ["scale " + " ".join(f"deployment/{service}" for service in services) + " --replicas=0",
                     "wait --for=delete " + " ".join(f"pod/{service}-0" for service in services) + " --timeout=180s"]
        for kind in sandbox_kinds:
            expected += [f"get {kind} -l codewire.sh/environment-id -o name",
                         f"delete {kind} -l codewire.sh/environment-id --ignore-not-found --wait=true --timeout=180s"]
        expected += ["psql postgres SET client_min_messages = warning DROP DATABASE IF EXISTS codewire WITH (FORCE) "
                     "DROP DATABASE IF EXISTS codewire_mesh "
                     "WITH (FORCE) DROP ROLE IF EXISTS codewire_credential_broker CREATE DATABASE codewire",
                     "scale deployment/codewire-idp --replicas=1",
                     "rollout status deployment/codewire-idp --timeout=300s"]
        expected += [f"psql codewire {text}" for text in self.FIXTURES.values()]
        started = [service for service in services[1:] if service != "codewire-mesh"]
        expected += [f"scale deployment/{service} --replicas=1" for service in started]
        expected += [f"rollout status deployment/{service} --timeout=300s" for service in started]
        self.maxDiff = None
        self.assertEqual(lines, expected)
        sandbox_calls = [call["args"] for call in self.calls() if "codewire.sh/environment-id" in call["args"]]
        self.assertEqual(len(sandbox_calls), 2 * len(sandbox_kinds))
        self.assertTrue(all(args[args.index("-n") + 1] == "dev-sandboxes" for args in sandbox_calls))
        self.assertIn("codewire is at migration 2 (next)", result.stderr)

    def test_restore_returns_to_a_backup(self) -> None:
        backup = self.backups / "20260101T000000Z-upgrade"
        backup.mkdir(parents=True)
        (backup / "codewire.dump").write_text("old codewire archive")
        result = self.run_database("restore", str(backup))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.backup_names()), 2)
        self.assertRegex(self.backup_names()[1], r"-before-restore$")
        lines = self.commands()
        restore = [line for line in lines if line.startswith(("psql postgres SET", "psql postgres CREATE", "pg_restore"))]
        self.assertEqual(restore, [
            "psql postgres SET client_min_messages = warning DROP DATABASE IF EXISTS codewire WITH (FORCE)",
            "psql postgres CREATE DATABASE codewire",
            "pg_restore codewire old codewire archive",
            "psql postgres SET client_min_messages = warning DROP DATABASE IF EXISTS codewire_mesh WITH (FORCE)"])
        self.assertLess(lines.index("scale " + " ".join(f"deployment/{service}" for service in (
            "codewire-idp", "codewire-billing", "codewire-mesh", "codewire-orchestration", "codewire-coordinator",
            "codewire-credential-service")) + " --replicas=0"), lines.index(restore[0]))
        self.assertGreater(lines.index("scale deployment/codewire-idp --replicas=1"), lines.index(restore[2]))
        for arguments, message in ((("restore",), "usage: make kind-db-restore BACKUP="),
                                   (("restore", str(self.directory)), "holds no codewire.dump")):
            result = self.run_database(*arguments)
            self.assertEqual(result.returncode, 1)
            self.assertIn(message, result.stderr)


def shard_suite(shard):
    """Every count-th test of the module, in test-id order, from index."""
    index, count = (int(part) for part in shard.split("/"))
    if not 0 <= index < count:
        raise SystemExit(f"invalid CODEWIRE_TEST_SHARD {shard!r}")

    def flatten(suite):
        for test in suite:
            if isinstance(test, unittest.TestSuite):
                yield from flatten(test)
            else:
                yield test

    tests = sorted(flatten(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])),
                   key=lambda test: test.id())
    return unittest.TestSuite(test for position, test in enumerate(tests) if position % count == index)


if __name__ == "__main__":
    # CODEWIRE_TEST_SHARD=INDEX/COUNT runs one of COUNT disjoint shards, so a
    # caller can run every shard side by side; together they run every test.
    if shard := os.environ.get("CODEWIRE_TEST_SHARD"):
        result = unittest.TextTestRunner().run(shard_suite(shard))
        sys.exit(0 if result.wasSuccessful() and result.testsRun else 1)
    unittest.main()
