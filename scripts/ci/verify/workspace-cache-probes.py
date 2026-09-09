#!/usr/bin/env python3
"""Value-blind preparation and assertions for explicitly requested cache probes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile

PHASES = ("native-cold", "native-warm", "native-malformed", "native-missing-blob",
          "native-denied", "cw-control", "cw-edit", "tools", "cancel")
MAIN = "crates/codewire-cli-bin/src/main.rs"
DOCKERFILE = "images/workspace/Dockerfile"
STAGES = """
FROM cw-toolchain AS cw-cache-probe-check
RUN --network=none \\
    --mount=type=bind,from=cw-builder,source=/out/cw,target=/tmp/cw-under-test,readonly \\
    mkdir -p /probe-result && \\
    /tmp/cw-under-test --version > /probe-result/version.txt && \\
    sha256sum /tmp/cw-under-test > /probe-result/cw.sha256

FROM scratch AS cw-cache-probe-result
COPY --from=cw-cache-probe-check /probe-result/ /
"""
GAPS = ["actual expired OIDC rejection", "induced network outage",
        "live production-wrapper/native-fault retry integration"]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


measurement = module("workspace_probe_measurement", Path(__file__).with_name("workspace-cache-report.py"))
artifact = module("workspace_probe_artifact", Path(__file__).with_name("workspace-image-artifact.py"))


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def write(path, value):
    Path(path).write_text(compact(value) + "\n")


def read(path):
    return json.loads(Path(path).read_text())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_key(path, contexts):
    """Inspect placement/metadata only; never read the credential contents."""
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path or path.is_symlink() \
            or not path.is_file() or stat.S_IMODE(path.stat().st_mode) not in (0o400, 0o600) \
            or not path.stat().st_size:
        raise ValueError("probe credential must be a canonical private regular file")
    for context in contexts:
        if path.is_relative_to(Path(context).resolve()):
            raise ValueError("probe credential must remain outside every source context")


def inventory(context):
    result = {}
    for path in sorted(Path(context).rglob("*")):
        relative = path.relative_to(context).as_posix()
        if path.is_symlink():
            if not path.resolve().is_relative_to(Path(context).resolve()):
                raise ValueError("source archive has an escaping symlink")
            result[relative] = {"link": os.readlink(path)}
        elif path.is_file():
            result[relative] = {"sha256": digest(path.read_bytes()),
                                "mode": stat.S_IMODE(path.stat().st_mode)}
        elif not path.is_dir():
            raise ValueError("source archive has an unsupported entry")
    return result


def derive(archive, work, report, credential, nonce):
    work, report = Path(work), Path(report)
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("invalid probe nonce")
    contexts = work / "contexts"
    contexts.mkdir()
    control = contexts / "control"
    control.mkdir()
    with tarfile.open(archive) as source:
        # The data filter rejects escaping names, links and special files.
        source.extractall(control, filter="data")
    original = inventory(control)
    for name in ("cw-edit", "tools"):
        shutil.copytree(control, contexts / name, symlinks=True)
    main = contexts / "cw-edit" / MAIN
    original_main = main.read_text()
    anchor = "fn main() {\n"
    if not original_main.startswith(anchor) or original_main.count(anchor) != 1:
        raise ValueError("CW probe insertion anchor changed")
    inserted = ('    if std::env::args_os().nth(1).is_some_and(|argument| argument == "--version") {\n'
                f'        println!("codewire-cache-probe-{nonce}");\n'
                '        return;\n    }\n')
    main.write_text(original_main.replace(anchor, anchor + inserted, 1))
    dockerfile = contexts / "tools" / DOCKERFILE
    original_dockerfile = dockerfile.read_text()
    tool_anchor = "    rm -rf /root/.bun\n"
    if original_dockerfile.count(tool_anchor) != 1:
        raise ValueError("floating tool probe insertion anchor changed")
    dockerfile.write_text(original_dockerfile.replace(
        tool_anchor, "    rm -rf /root/.bun && \\\n"
        f"    printf '%s\\n' 'codewire-cache-probe-{nonce}' > /usr/local/share/codewire-cache-probe-token\n"))
    (work / "cw-probe.Dockerfile").write_text(original_dockerfile + STAGES)
    inventories = {"control": original, "cw-edit": inventory(contexts / "cw-edit"),
                   "tools": inventory(contexts / "tools")}
    for name, expected in (("cw-edit", MAIN), ("tools", DOCKERFILE)):
        current = inventories[name]
        if set(current) != set(original) or [key for key in original if current[key] != original[key]] != [expected]:
            raise ValueError("private derivative changes unexpected source inputs")
    native = contexts / "native"
    native.mkdir()
    (native / "Dockerfile").write_text("FROM scratch\nCOPY payload /payload\n")
    (native / "payload").write_bytes(os.urandom(8 * 1024 * 1024))
    cancelled = contexts / "cancel"
    cancelled.mkdir()
    pin = read(report / "identity.json")["buildkit_image"]
    (cancelled / "Dockerfile").write_text(
        f"FROM {pin}\nRUN printf '%s\\n' 'CODEWIRE_CACHE_PROBE_READY={nonce}'; sleep 120\n")
    identities = work / "identities"
    identities.mkdir(mode=0o700)
    synthetic = identities / "denied.aws"
    synthetic.write_text("[default]\naws_access_key_id = " + secrets.token_hex(16)
                         + "\naws_secret_access_key = " + secrets.token_hex(32) + "\n")
    synthetic.chmod(0o600)
    roots = [control, contexts / "cw-edit", contexts / "tools", native, cancelled]
    private_key(credential, roots)
    private_key(synthetic, roots)
    write(report / "contexts.json", {
        "inventories": inventories, "archive_sha256": digest(Path(archive).read_bytes()),
        "probe_dockerfile_sha256": digest((work / "cw-probe.Dockerfile").read_bytes()),
        "native_payload_sha256": digest((native / "payload").read_bytes()),
        "cw_insert": inserted, "tool_dockerfile_sha256": digest(dockerfile.read_bytes())})


def prepare(root, report, pin, credential):
    root, report = Path(root), Path(report)
    identity = artifact.source_identity(root)
    if identity["source_sha"] != os.environ["CODEWIRE_EXPECTED_SOURCE_SHA"] \
            or identity["source_tree"] != os.environ["CODEWIRE_EXPECTED_SOURCE_TREE"]:
        raise ValueError("probe differs from workflow-selected source")
    seed = measurement.seed_report(os.environ["CODEWIRE_WORKSPACE_CACHE_SEED_REPORT"],
                                   identity["source_sha"], identity["source_tree"])
    if seed["run_id"] != os.environ["GITHUB_RUN_ID"] or seed["architecture"] != identity["architecture"] \
            or not seed["seed_cache_id"].startswith("run-" + os.environ["GITHUB_RUN_ID"] + "/tree-" + identity["source_tree"] + "/"):
        raise ValueError("probe producer run or architecture differs")
    selected = subprocess.check_output(
        ["python3", str(root / "scripts/ci/setup/select-workspace-cache-experiment.py")],
        text=True, timeout=30, env={**os.environ, "CODEWIRE_BUILDKIT_CACHE_REQUEST": "auto"})
    if json.loads(selected).get("selected") is not True:
        raise ValueError("probe requires the existing stored PR cost request")
    if not re.fullmatch(r"docker.io/moby/buildkit:v0.29.0@sha256:[0-9a-f]{64}", pin) \
            or pin != seed["pins"]["buildkit_image"]:
        raise ValueError("probe BuildKit pin differs from seed")
    write(report / "identity.json", {
        "source_sha": identity["source_sha"], "source_tree": identity["source_tree"],
        "architecture": identity["architecture"], "seed_cache_id": seed["seed_cache_id"],
        "seed_docker_daemon_id": seed["docker_daemon_id"], "run_id": os.environ["GITHUB_RUN_ID"],
        "job_id": os.environ["GITHUB_JOB"], "job_container_id": os.environ["HOSTNAME"],
        "buildkit_image": pin, "nonce": secrets.token_hex(16), "credential_file": str(credential),
        "cache_helper_sha256": digest((root / "scripts/ci/images/workspace-cache.sh").read_bytes())})


def register(report, phase, builder, container):
    report = Path(report)
    if phase not in PHASES or not re.fullmatch(r"codewire-workspace-[A-Za-z0-9_.-]+", builder) \
            or not re.fullmatch(r"[0-9a-f]{64}", container):
        raise ValueError("invalid owned probe builder")
    directory = report / phase
    mounts = read(directory / "mounts.json")
    if not isinstance(mounts, list) or any(not isinstance(value, dict) for value in mounts):
        raise ValueError("invalid owned builder mount observation")
    volumes = [value["Name"] for value in mounts if value.get("Type") == "volume"
               and value.get("Destination") == "/var/lib/buildkit"]
    # Buildx normalizes its state volume name even when the requested builder
    # contains mktemp's mixed-case suffix. The exact owned container supplies it.
    expected = "buildx_buildkit_" + builder.lower() + "-node_state"
    if volumes != [expected]:
        raise ValueError("probe builder state is not its exact owned volume")
    write(directory / "owner.json", {"builder": builder, "container": container, "volume": expected})
    print(expected)


def cleaned(report, phase):
    directory = Path(report) / phase
    owner = read(directory / "owner.json")
    for name, field, pattern in (("containers", "container", r"[0-9a-f]{64}"),
                                 ("volumes", "volume", r"[A-Za-z0-9][A-Za-z0-9_.-]*"),
                                 ("builders", "builder", r"[A-Za-z0-9][A-Za-z0-9_.-]*")):
        remaining = (directory / ("remaining-" + name)).read_text().splitlines()
        if any(not re.fullmatch(pattern, value) for value in remaining):
            raise ValueError("malformed owned-resource cleanup observation")
        if owner[field] in remaining or (field == "builder" and owner[field].lower() in [value.lower() for value in remaining]):
            raise ValueError("owned probe resource survived cleanup")
    daemon = (directory / "docker-id").read_text().strip()
    if not re.fullmatch(r"[A-Za-z0-9:_-]{8,128}", daemon):
        raise ValueError("cleanup has no responsive Docker daemon")
    write(directory / "cleanup.json", {"status": "removed", "docker_daemon_id": daemon, **owner})


def vertices(text):
    result = {}
    for line in text.splitlines():
        match = re.match(r"^(#\d+) (.*)$", line)
        if match:
            result.setdefault(match[1], []).append(match[2])
    return list(result.values())


def vertex(text, expression, cached, lazy_digest=None):
    found = [lines for lines in vertices(text) if any(re.search(expression, line) for line in lines)]
    if len(found) != 1:
        raise ValueError("expected executed/cached probe vertex was not observed")
    lines = found[0]
    literal_hit = "CACHED" in lines
    lazy_hit = lazy_digest is not None and any(
        line.split(maxsplit=1)[0] == lazy_digest for line in lines if line)
    completed = any(re.fullmatch(r"DONE [0-9.]+s", line) for line in lines)
    if cached:
        if not literal_hit and not (lazy_hit and completed):
            raise ValueError("expected executed/cached probe vertex was not observed")
        return "cached" if literal_hit else "lazy-digest"
    if literal_hit or not completed:
        raise ValueError("expected executed/cached probe vertex was not observed")
    return "executed"


def ready(log, nonce):
    return bool(re.search(r"(?m)^#\d+ [0-9.]+ CODEWIRE_CACHE_PROBE_READY=" + re.escape(nonce) + r"$",
                          Path(log).read_text()))


def replay(root, report, phase, work, synthetic):
    """Run the actual wrapper with an absolute fake client and synthetic key."""
    if phase not in ("native-malformed", "native-missing-blob", "native-denied"):
        raise ValueError("wrapper replay is only for a recorded native fault")
    root, report, work = Path(root), Path(report), Path(work)
    directory = report / phase
    native_status = int((directory / "status").read_text())
    replay_dir = work / ("replay-" + phase)
    replay_dir.mkdir(mode=0o700)
    fake = replay_dir / "docker"
    fake.write_text("""#!/usr/bin/python3
import json, os, sys
from pathlib import Path
if sys.argv[1:3] != ["buildx", "build"]:
    raise SystemExit(97)
calls = Path(os.environ["PROBE_REPLAY_CALLS"])
first = not calls.exists()
with calls.open("a") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\\n")
if first:
    print(Path(os.environ["PROBE_NATIVE_LOG"]).read_text(), end="")
    raise SystemExit(int(os.environ["PROBE_NATIVE_STATUS"]))
print("#1 [1/1] COPY payload /payload\\n#1 DONE 0.1s")
""")
    fake.chmod(0o700)
    helper = root / "scripts/ci/images/workspace-cache.sh"
    script = """
set -euo pipefail
source "$1"
workspace_cache_validate
builder=codewire-cache-local-replay
status=0
workspace_cache_build canary-replay 1111111111111111111111111111111111111111 amd64 "$2" --file synthetic || status=$?
printf '%s\\n' "$workspace_cache_fallback" >"$3"
exit "$status"
"""
    # Deliberately closed environment: the fake never receives the real key,
    # OIDC token or an opportunity to fall through to a live Docker binary.
    environment = {
        "PATH": "/usr/bin:/bin", "CODEWIRE_DOCKER_BIN": str(fake),
        "CODEWIRE_SCCACHE_MODE": "disabled", "CODEWIRE_BUILDKIT_CACHE_MODE": "r2",
        "CODEWIRE_SCCACHE_CREDENTIALS_FILE": str(synthetic),
        "SCCACHE_BUCKET": "example-ci-cache-untrusted",
        "SCCACHE_ENDPOINT": "https://00000000000000000000000000000000.r2.cloudflarestorage.com",
        "CODEWIRE_SCCACHE_PREFIX": "untrusted/codewire/v1",
        "PROBE_REPLAY_CALLS": str(replay_dir / "calls"),
        "PROBE_NATIVE_LOG": str(directory / "build.log"),
        "PROBE_NATIVE_STATUS": str(native_status)}
    completed = subprocess.run(["/usr/bin/bash", "-c", script, "probe-replay", str(helper),
                                str(replay_dir / "build.log"), str(replay_dir / "fallback")],
                               env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
    calls = [json.loads(line) for line in (replay_dir / "calls").read_text().splitlines()]
    retried = (replay_dir / "fallback").read_text() == "true\n"
    if len(calls) != (2 if retried else 1) \
            or completed.returncode != (0 if retried else native_status) \
            or (retried and ("--no-cache" not in calls[1] or any(
                flag in calls[1] for flag in ("--cache-from", "--cache-to", "--no-cache-filter")))):
        raise ValueError("actual local wrapper replay failed its retry contract")
    write(directory / "wrapper-replay.json", {
        "proof": "actual wrapper with absolute fake Docker and synthetic identity",
        "helper_sha256": digest(helper.read_bytes()),
        "input_log_sha256": digest((directory / "build.log").read_bytes()),
        "input_status": native_status, "result_status": completed.returncode,
        "cold_retry": retried, "invocation_count": len(calls)})


def check_phase(report, phase):
    report = Path(report)
    directory = report / phase
    identity = read(report / "identity.json")
    owner = read(directory / "owner.json")
    cleanup = read(directory / "cleanup.json")
    if cleanup != {"status": "removed", "docker_daemon_id": cleanup.get("docker_daemon_id"), **owner}:
        raise ValueError("probe cleanup evidence differs from ownership")
    status = int((directory / "status").read_text())
    text = (directory / "build.log").read_text()
    outcome = {"phase": phase, "build_status": status, "owner": owner, "cleanup": cleanup}
    if phase == "cancel":
        if status != 143 or not ready(directory / "build.log", identity["nonce"]) \
                or (directory / "unexpected-success").exists() \
                or (directory / "child-reaped").read_text() != "true\n":
            raise ValueError("cancelled build was not interrupted/reaped after executed readiness")
        outcome["effect"] = "owned build cancelled"
    elif phase.startswith("native-"):
        if not 0 <= status < 124:
            raise ValueError("native cache timeout, interruption or invocation failure is not an accepted fault")
        categories = {
            "native-malformed": r"invalid character|unexpected data after JSON object",
            "native-missing-blob": r"NoSuchKey|NotFound|StatusCode: 404|status code: 404",
            # Cloudflare R2 reports a synthetic S3 identity as HTTP 401 with
            # `api error Unauthorized`; other S3 implementations use 403 or
            # one of the named signature/access errors below.
            "native-denied": r"api error Unauthorized|AccessDenied|InvalidAccessKeyId|SignatureDoesNotMatch|StatusCode: 40[13]|status code: 40[13]",
        }
        if phase in categories:
            if not re.search(categories[phase], text, re.I) \
                    or not re.search(r"importing cache manifest|GetObject", text, re.I):
                raise ValueError("native cache fault category was not observed")
            if status:
                if (directory / "recovery-status").read_text() != "0\n":
                    raise ValueError("explicit probe cold recovery did not succeed")
                recovery = (directory / "recovery.log").read_text()
                if "importing cache manifest" in recovery or "exporting cache to Amazon S3" in recovery:
                    raise ValueError("probe cold recovery retained external cache")
                vertex(recovery, r"^\[.*\] COPY payload /payload$", False)
            else:
                vertex(text, r"^\[.*\] COPY payload /payload$", False)
            outcome["effect"] = phase.removeprefix("native-")
            replayed = read(directory / "wrapper-replay.json")
            if replayed["helper_sha256"] != identity["cache_helper_sha256"] \
                    or replayed["input_log_sha256"] != digest(text.encode()) \
                    or replayed["input_status"] != status \
                    or type(replayed["cold_retry"]) is not bool \
                    or replayed["invocation_count"] != (2 if replayed["cold_retry"] else 1) \
                    or replayed["result_status"] != (0 if replayed["cold_retry"] else status):
                raise ValueError("native observation is not bound to exact local wrapper proof")
            outcome["local_wrapper_proof"] = replayed
        else:
            if status != 0:
                raise ValueError("native positive control failed")
            lazy_digest = None
            if phase == "native-warm":
                lazy_digest = read(report / "native-cold" / "result.json").get("blob_digest")
                if not isinstance(lazy_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", lazy_digest):
                    raise ValueError("native cold control has no exact exported blob digest")
            outcome["cache_observation"] = vertex(
                text, r"^\[.*\] COPY payload /payload$", phase == "native-warm", lazy_digest)
            if phase == "native-cold":
                measurement.logs(directory / "build.log", "r2")
                blobs = set(re.findall(r"\bwriting layer (sha256:[0-9a-f]{64})\b", text))
                if len(blobs) != 1:
                    raise ValueError("native control did not identify one newly written blob")
                outcome["blob_digest"] = blobs.pop()
        expected = read(report / "contexts.json")["native_payload_sha256"]
        if (directory / "payload.sha256").read_text().strip() != expected:
            raise ValueError("native fault did not materialize the exact payload")
    elif phase in ("cw-control", "cw-edit"):
        if status != 0:
            raise ValueError("actual CW build failed")
        measurement.logs(directory / "build.log", "r2")
        vertex(text, r"^\[cw-builder [^]]+\] RUN\b", phase == "cw-control")
        value = (directory / "version.txt").read_text()
        token = "codewire-cache-probe-" + identity["nonce"] + "\n"
        if not value.strip() or (value == token) != (phase == "cw-edit"):
            raise ValueError("CW source derivative returned a stale/unexpected token")
        binary = (directory / "cw.sha256").read_text().split()[0]
        if not re.fullmatch(r"[0-9a-f]{64}", binary):
            raise ValueError("invalid CW binary hash")
        outcome["binary_sha256"] = binary
        if phase == "cw-edit" and binary == read(report / "cw-control" / "result.json")["binary_sha256"]:
            raise ValueError("CW source derivative retained the control binary")
    elif phase == "tools":
        if status != 0 or (directory / "contracts-status").read_text() != "0\n" \
                or (directory / "tool-marker").read_text() != "codewire-cache-probe-" + identity["nonce"] + "\n":
            raise ValueError("tool derivative or its unchanged contracts failed")
        measurement.logs(directory / "base-build.log", "r2")
        measurement.logs(directory / "build.log", "r2", workspace=True)
        versions = read(directory / "versions.json")
        if set(versions) != set(measurement.VERSION_COMMANDS) or any(not isinstance(v, str) or not v for v in versions.values()):
            raise ValueError("tool derivative version inventory is incomplete")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", (directory / "image-id").read_text().strip()):
            raise ValueError("tool derivative image identity is invalid")
        outcome["versions"] = versions
    else:
        raise ValueError("unknown probe phase")
    write(directory / "result.json", outcome)
    return outcome


def finalize(report):
    report = Path(report)
    result_path = report / "result.json"
    result_path.unlink(missing_ok=True)
    identity = read(report / "identity.json")
    if (report / "work-complete").read_text() != "true\n" \
            or identity["source_sha"] != os.environ["CODEWIRE_EXPECTED_SOURCE_SHA"] \
            or identity["source_tree"] != os.environ["CODEWIRE_EXPECTED_SOURCE_TREE"] \
            or identity["run_id"] != os.environ["GITHUB_RUN_ID"] \
            or os.environ.get("CODEWIRE_SCCACHE_MODE") != "r2" \
            or os.environ.get("CODEWIRE_BUILDKIT_CACHE_MODE") != "r2":
        raise ValueError("probe work, source or post-build modes differ")
    credential = Path(identity["credential_file"])
    if not credential.is_absolute() or credential.resolve() != credential:
        raise ValueError("probe credential cleanup path is not canonical")
    if credential.exists() or credential.is_symlink():
        raise ValueError("probe job credential finisher has not completed")
    phases = [check_phase(report, phase) for phase in PHASES]
    for field in ("builder", "container", "volume"):
        if len({phase["owner"][field] for phase in phases}) != len(PHASES):
            raise ValueError("native fault or CW control reused an owned daemon/state")
    daemons = {phase["cleanup"]["docker_daemon_id"] for phase in phases}
    if len(daemons) != 1 or identity["seed_docker_daemon_id"] in daemons:
        raise ValueError("probes did not run on one fresh worker")
    gaps = list(GAPS)
    for phase in phases:
        if phase["build_status"] and "local_wrapper_proof" in phase and not phase["local_wrapper_proof"]["cold_retry"]:
            gaps.append("production wrapper did not retry the observed " + phase["phase"] + " error in local replay")
    contexts = read(report / "contexts.json")
    inventories = contexts.pop("inventories")
    derivation = {
        **contexts, "context_inventory_sha256": {name: digest(compact(value).encode()) for name, value in inventories.items()},
        "changed_inputs": {name: {"path": path, "before": inventories["control"][path], "after": inventories[name][path]}
                           for name, path in (("cw-edit", MAIN), ("tools", DOCKERFILE))}}
    result = {"schema_version": 1, "status": "passed", "kind": "workspace-cache-probes",
              "identity": {key: value for key, value in identity.items() if key != "credential_file"},
              "derivation": derivation, "phases": phases, "remaining_live_gaps": gaps}
    def interrupted(number, _frame):
        raise SystemExit(128 + number)
    handlers = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        result_path.write_text(compact(result) + "\n")
        print("CODEWIRE_WORKSPACE_CACHE_PROBES=" + compact(result), flush=True)
    except BaseException:
        result_path.unlink(missing_ok=True)
        raise
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    try:
        command, *arguments = sys.argv[1:]
        if command == "prepare" and len(arguments) == 4:
            prepare(*arguments)
        elif command == "derive" and len(arguments) == 5:
            derive(*arguments)
        elif command == "key" and len(arguments) >= 2:
            private_key(arguments[0], arguments[1:])
        elif command == "register" and len(arguments) == 4:
            register(*arguments)
        elif command == "cleaned" and len(arguments) == 2:
            cleaned(*arguments)
        elif command == "check" and len(arguments) == 2:
            check_phase(*arguments)
        elif command == "replay" and len(arguments) == 5:
            replay(*arguments)
        elif command == "ready" and len(arguments) == 2:
            raise SystemExit(0 if ready(*arguments) else 1)
        elif command == "finalize" and len(arguments) == 1:
            finalize(*arguments)
        else:
            raise ValueError("invalid workspace cache probe command")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        print("workspace cache probes: " + str(error), file=sys.stderr)
        raise SystemExit(1) from None
