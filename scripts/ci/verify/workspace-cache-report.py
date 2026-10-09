#!/usr/bin/env python3
"""Bounded, value-blind workspace cache measurements; no provider API client."""
from datetime import datetime
from contextlib import closing, ExitStack
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
LIBRARY_ROOT = ROOT
MAX_HISTORY = 64 * 1024 * 1024
PRODUCER_FIELDS = {"status", "receipt", "producer_receipt", "image", "index_sha256", "payload",
                   "source", "profile", "version", "build_ref", "cache_qualified", "image_qualified"}
_consumer = None


def consumer_library():
    """Reuse the full held producer admission; importing it runs no solve."""
    global _consumer
    if _consumer is None:
        spec = importlib.util.spec_from_file_location(
            "workspace_cache_cw_consumer", LIBRARY_ROOT / "scripts/ci/images/cw-image-consumer.py")
        value = importlib.util.module_from_spec(spec)
        bytecode = sys.dont_write_bytecode
        try:
            sys.dont_write_bytecode = True
            spec.loader.exec_module(value)
        finally:
            sys.dont_write_bytecode = bytecode
        _consumer = value
    return _consumer


def owned_reference(reference, builder):
    if not isinstance(builder, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,160}", builder) \
            or not isinstance(reference, str) \
            or not re.fullmatch(re.escape(f"{builder}/{builder}-node/") + r"[a-z0-9]{20,32}", reference):
        raise ValueError("history does not belong to the owned builder and node")
    return reference


class ProducerEvidence:
    """Retain original compiled provenance and current source across reporting.

    reopen() is an observation, never compiler execution. Only this case's
    exact original solve history can qualify the measured compiler/cache path.
    """

    def __init__(self, directory, header, compiler_mode=None):
        self.pointer, self.retained = None, None
        self.consumer = consumer_library()
        producer = self.consumer.producer
        asset, release = producer.source.asset, producer.release
        try:
            mode = MODES[header["case"]][0] if compiler_mode is None else compiler_mode
            asset.require(mode in ("disabled", "r2"), "measurement compiler mode refused")
            self.pointer = asset.HeldFile(Path(directory) / "cw-image-work/cw-producer-result.json", 64 * 1024)
            asset.require(self.pointer.metadata["uid"] == os.geteuid()
                          and self.pointer.metadata["mode"] & 0o7777 == 0o400,
                          "producer result is not a private immutable owner file")
            pointer = release.parse_canonical(self.pointer.data, 64 * 1024)
            asset.require(type(pointer) is dict and set(pointer) == PRODUCER_FIELDS
                          and type(pointer["receipt"]) is dict
                          and release.is_hex(pointer["receipt"].get("sha256"), 64),
                          "producer result fields or receipt pin refused")
            version = self.consumer.effective_version(ROOT, None)
            self.retained = producer.reopen(pointer["receipt"]["path"], pointer["receipt"]["sha256"],
                                            ROOT, header["source_sha"], "release", version)
            summary = self.retained.summary
            asset.require(release.canonical(pointer) == release.canonical(
                {key: summary[key] for key in PRODUCER_FIELDS}), "producer pointer differs from its original build")
            asset.require(summary["current_source"]["revision"] == header["source_sha"]
                          and summary["current_source"]["git_tree"] == header["source_tree"],
                          "producer current source differs from the selected case")
            reference = owned_reference(summary["build_ref"], header["builder_name"])
            model = self.retained.model
            fixed = producer.fixed_arguments(self.retained.path / "source-context", self.retained.capsule.model,
                                              model["source_request_sha256"], self.retained.path,
                                              mode)
            producer.admit_solve_command(model["build"]["command"], fixed, header["builder_name"])
            self.identity = {"build_ref": reference, "pointer_sha256": self.pointer.sha256,
                             "build_receipt_sha256": summary["receipt"]["sha256"],
                             "producer_receipt_sha256": summary["producer_receipt"]["sha256"],
                             "build_log_sha256": self.retained.files["build_log"].sha256}
            self.revalidate()
        except (producer.release.ReleaseError, producer.finalizer.release.ReleaseError):
            self.close()
            raise ValueError("retained producer record or source admission failed") from None
        except BaseException:
            self.close()
            raise

    def revalidate(self):
        self.pointer.revalidate(content=True)
        self.retained.revalidate()
        self.pointer.revalidate(content=True)

    def close(self):
        if self.retained is not None:
            self.retained.close()
        if self.pointer is not None:
            self.pointer.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


MODES = {"seed": ("r2", "r2"), "cold": ("disabled", "disabled"),
         "compiler": ("r2", "disabled"), "warm-1": ("r2", "r2"), "warm-2": ("r2", "r2")}
VERSION_COMMANDS = {"npm": ["npm", "--version"],
                    # pnpm's npm-installed launcher currently relies on the
                    # interactive shell's ENOEXEC fallback. Measure the same
                    # supported workspace command path without profiles.
                    "pnpm": ["/bin/bash", "--noprofile", "--norc", "-c", "pnpm --version"],
                    "yarn": ["yarn", "--version"], "bun": ["bun", "--version"],
                    "gopls": ["gopls", "version"], "hcloud": ["hcloud", "version"],
                    "poetry": ["poetry", "--version"], "uv": ["uv", "--version"],
                    "aider": ["aider", "--version"]}
# Read the owned BuildKit container's public counters and backing filesystem
# capacity. No recursive directory walk, environment dump or credential read.
SAMPLE_COMMAND = r'''
memory=$(cat /sys/fs/cgroup/memory.current)
filesystem=$(df -Pk /var/lib/buildkit)
filesystem=$(printf '%s\n' "$filesystem" | awk 'NR == 2 {printf "%s %s %s", $2, $3, $4}')
network=$(awk 'NR>2 && $1 != "lo:" {rx+=$2; tx+=$10} END {printf "%.0f %.0f", rx, tx}' /proc/net/dev)
printf '%s %s %s\n' "$memory" "$filesystem" "$network"
'''


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def versions():
    result = {}
    for name, command in VERSION_COMMANDS.items():
        value = subprocess.check_output(command, text=True, timeout=30, stderr=subprocess.STDOUT).strip()
        if not value or len(value) > 2048:
            raise ValueError("invalid floating tool version output")
        result[name] = value
    print(compact(result))


def sample(docker, container, directory, once=False):
    stopped = False
    count = 0

    def stop(_signal, _frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    directory = Path(directory)
    # The caller's timeout owns this process group, including a blocked Docker
    # child. A stop signal never leaves an unsupervised sampler subprocess.
    with (directory / "resources.jsonl").open("a", buffering=1) as output:
        while not stopped:
            try:
                raw = subprocess.check_output([docker, "exec", container, "sh", "-eu", "-c", SAMPLE_COMMAND],
                                              text=True, timeout=8, stderr=subprocess.DEVNULL)
                values = raw.split()
                if len(values) != 6 or any(not re.fullmatch(r"[0-9]+", value) for value in values):
                    raise ValueError("invalid resource sample")
                memory, total, used, available, received, sent = map(int, values)
                output.write(compact({"time_ns": time.monotonic_ns(), "memory_bytes": memory,
                                      "backing_filesystem_total_bytes": total * 1024,
                                      "backing_filesystem_used_bytes": used * 1024,
                                      "backing_filesystem_available_bytes": available * 1024,
                                      "network_rx_bytes": received, "network_tx_bytes": sent}) + "\n")
                count += 1
            except (OSError, ValueError, subprocess.SubprocessError):
                if not stopped:
                    (directory / "metrics-error").write_text("required builder resource sampling failed\n")
                break
            if once:
                break
            for _ in range(30):
                if stopped:
                    break
                time.sleep(0.1)
    if not once:
        if stopped and (directory / "sampler-stop-request").is_file() and not (directory / "metrics-error").exists() and count:
            (directory / "sampler-complete.json").write_text(compact({"status": "stopped", "sample_count": count}) + "\n")
        else:
            (directory / "metrics-error").write_text("resource sampler ended without an intentional clean stop\n")


def history_identity(directory, builder):
    metadata = json.loads((Path(directory) / "workspace-metadata.json").read_text())
    reference = metadata.get("buildx.build.ref", "")
    owned_reference(reference, builder)
    image = metadata.get("containerimage.config.digest", "")
    if not isinstance(image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("workspace history metadata lacks its output image identity")
    return {"build_ref": reference, "workspace_image_id": image}


def capture_one_history(docker, builder, directory, prefix, identity):
    directory = Path(directory)
    owned_reference(identity["build_ref"], builder)
    marker = directory / f"{prefix}-history.json"
    marker.unlink(missing_ok=True)
    path = directory / f"{prefix}-progress.jsonl"
    # Buildx's history lookup takes the solve ID, not its builder/node prefix.
    # Its rawjson printer writes to stderr. Never substitute latest/^0.
    with path.open("wb") as output:
        subprocess.run([docker, "buildx", "history", "logs", "--builder", builder,
                        "--progress", "rawjson", identity["build_ref"].rsplit("/", 1)[1]],
                       stdout=subprocess.DEVNULL, stderr=output, check=True)
    with closing(consumer_library().asset.HeldFile(path, MAX_HISTORY)) as held:
        held.revalidate(content=True)
        return dict(identity, sha256=held.sha256)


def capture_producer_history(docker, builder, directory, evidence):
    """Capture only the already-admitted producer's original owned solve."""
    marker = Path(directory) / "cw-producer-history.json"
    marker.unlink(missing_ok=True)
    evidence.revalidate()
    capture = capture_one_history(docker, builder, directory, "cw-producer", evidence.identity)
    evidence.revalidate()
    marker.write_text(compact(capture) + "\n")


def capture_history(docker, builder, directory):
    directory = Path(directory)
    marker = directory / "workspace-history.json"
    marker.unlink(missing_ok=True)
    header = json.loads((directory / "identity.json").read_text())
    if header["builder_name"] != builder or header["architecture"] not in ("amd64", "arm64"):
        raise ValueError("history capture differs from the selected owned case")
    if header["architecture"] == "amd64":
        (directory / "cw-producer-history.json").unlink(missing_ok=True)
    identity = history_identity(directory, builder)
    with ExitStack() as custody:
        evidence = custody.enter_context(ProducerEvidence(directory, header)) if header["architecture"] == "amd64" else None
        if evidence is not None and evidence.identity["build_ref"] == identity["build_ref"]:
            raise ValueError("workspace and standalone producer histories must be distinct solves")
        capture = capture_one_history(docker, builder, directory, "workspace", identity)
        if evidence is not None:
            capture_producer_history(docker, builder, directory, evidence)
            evidence.revalidate()
        marker.write_text(compact(capture) + "\n")


def captured_vertices(directory, prefix, identity, custody):
    asset = consumer_library().asset
    marker = custody.enter_context(closing(asset.HeldFile(Path(directory) / f"{prefix}-history.json", 64 * 1024)))
    progress = custody.enter_context(closing(asset.HeldFile(Path(directory) / f"{prefix}-progress.jsonl", MAX_HISTORY)))
    if json.loads(marker.data) != dict(identity, sha256=progress.sha256):
        raise ValueError("history capture is incomplete or belongs to another output")
    vertices = history_vertices(progress.data)
    marker.revalidate(content=True)
    progress.revalidate(content=True)
    return vertices, (marker, progress)


def workspace_history(directory, header, receipt, custody):
    identity = history_identity(directory, header["builder_name"])
    if identity["workspace_image_id"] != receipt["workspace_image_id"]:
        raise ValueError("workspace history belongs to another image")
    vertices, files = captured_vertices(directory, "workspace", identity, custody)
    return identity, vertices, files


def history_vertices(raw):
    vertices = {}
    for line in raw.splitlines():
        status = json.loads(line)
        if not isinstance(status, dict) or not isinstance(status.get("vertexes", []), list):
            raise ValueError("malformed workspace history status")
        for vertex in status.get("vertexes", []):
            if not isinstance(vertex, dict) or vertex.get("error"):
                raise ValueError("workspace history contains a failed vertex")
            digest = vertex.get("digest", "")
            if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) \
                    or type(vertex.get("cached", False)) is not bool \
                    or not isinstance(vertex.get("name", ""), str) \
                    or not isinstance(vertex.get("inputs", []), list):
                raise ValueError("malformed workspace history vertex")
            if any(not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
                   for value in vertex.get("inputs", [])):
                raise ValueError("malformed workspace history dependency")
            for field in ("started", "completed"):
                stamp = vertex.get(field)
                if stamp is not None:
                    if not isinstance(stamp, str):
                        raise ValueError("malformed workspace history timestamp")
                    datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            vertices.setdefault(digest, []).append(vertex)
    return vertices


def compiler_vertex(vertices, cached=None):
    if cached is not None and type(cached) is not bool:
        raise ValueError("compiler cache expectation must be boolean")
    compiler = [(digest, events) for digest, events in vertices.items()
                if any(re.match(r"\[cw-builder [^]]+\] RUN\b", v.get("name", "")) for v in events)]
    if len(compiler) != 1:
        raise ValueError("workspace history lacks one exact compiler vertex")
    digest, events = compiler[0]
    if len({v["name"] for v in events if v.get("name")}) != 1:
        raise ValueError("workspace compiler history changes vertex identity")
    # BuildKit 0.29 LoadCache emits Cached=true, then lazy extraction can emit
    # further events for the same digest without Cached or Inputs. Preserve the
    # successful hit, but reject real Exec events (which retain dependency Inputs).
    # Repeated initial graph records do not reset a started vertex. Only a
    # later started interval can make its completion pending again.
    started = [v for v in events if v.get("started")]
    if not started or not started[-1].get("completed"):
        raise ValueError("workspace compiler history is incomplete")
    layer_cached = any(v.get("cached") is True and v.get("started") and v.get("completed") for v in events)
    executed = any(v.get("started") and v.get("inputs") and not v.get("cached", False) for v in events)
    if cached is True and (not layer_cached or executed):
        raise ValueError("warm workspace did not prove reuse of its compiler layer")
    if cached is False and (layer_cached or not executed):
        raise ValueError("measurement did not prove execution of its compiler layer")
    return {"compiler_vertex_digest": digest, "compiler_layer_cached": bool(layer_cached),
            "compiler_executed": bool(executed)}


def compiler_history(directory, header, receipt, custody):
    identity, vertices, files = workspace_history(directory, header, receipt, custody)
    cached = True if header["case"].startswith("warm-") else False if header["case"] in ("cold", "compiler") else None
    return dict(identity, **compiler_vertex(vertices, cached)), files


def producer_history(directory, evidence, cached=None):
    """Verify a measured producer solve, retaining lazy cache extraction semantics."""
    with ExitStack() as custody:
        result, files = held_producer_history(directory, evidence, cached, custody)
        for held in files:
            held.revalidate(content=True)
        evidence.revalidate()
        return result


def held_producer_history(directory, evidence, cached, custody):
    evidence.revalidate()
    vertices, files = captured_vertices(directory, "cw-producer", evidence.identity, custody)
    result = dict(evidence.identity, **compiler_vertex(vertices, cached))
    evidence.revalidate()
    return result, files


def logs(path, layers, workspace=False, compiler=None):
    return log_text(Path(path).read_text(), layers, workspace, compiler)


def producer_logs(evidence, layers):
    evidence.revalidate()
    result = log_text(evidence.retained.files["build_log"].data.decode("utf-8"), layers, compiler=True)
    evidence.revalidate()
    return result


def log_text(text, layers, workspace=False, compiler=None):
    if re.search(r"(?im)^#\d+ ERROR:|ignoring error|sccache: error|failed to configure s3 cache|"
                 r"error (?:reading|writing).*?(?:cache|blob|manifest)|failed to (?:export|import).*?cache", text):
        raise ValueError("cache IO/export failure in build log")
    for match in re.finditer(r"(?im)Cache (?:read errors|write errors|errors)\s+(\d+)", text):
        if int(match[1]):
            raise ValueError("sccache reported cache IO errors")
    vertices = {}
    for line in text.splitlines():
        match = re.match(r"^(#\d+) (.*)$", line)
        if match:
            vertices.setdefault(match[1], []).append(match[2])
    exports = [lines for lines in vertices.values() if "exporting cache to Amazon S3" in lines]
    if layers == "r2" and (len(exports) != 1 or not any(line.startswith("DONE") for line in exports[0])):
        raise ValueError("S3 cache export did not complete")
    if layers == "disabled" and (exports or "importing cache manifest" in text):
        raise ValueError("disabled layers performed external cache IO")
    floating = [lines for lines in vertices.values()
                if any(re.match(r"\[workspace-floating-tools [^]]+\] RUN\b", line) for line in lines)]
    compiler_vertices = [lines for lines in vertices.values()
                         if any(re.match(r"\[cw-builder [^]]+\] RUN\b", line) for line in lines)]
    if workspace:
        if len(floating) != 2 or any("CACHED" in lines or not any(line.startswith("DONE") for line in lines) for lines in floating):
            raise ValueError("both floating tool RUNs must execute")
    expected = 1 if compiler is True or compiler is None and workspace else 0 if compiler is False else None
    if expected is not None and len(compiler_vertices) != expected:
        raise ValueError("build log compiler vertices differ from the selected producer path")
    statistics = {key: int(value) for key, value in re.findall(
        r"(?im)(Cache hits(?: \(Rust\))?|Cache misses|Cache read errors|Cache write errors|Cache errors)\s+(\d+)", text)}
    def duration(lines):
        done = [float(match[1]) for line in lines if (match := re.fullmatch(r"DONE ([0-9.]+)s", line))]
        return done[-1] if done else None

    image_exports = [lines for lines in vertices.values() if any(line in ("exporting to docker image format", "importing to docker") for line in lines)]
    return {"s3_export_completed": bool(exports), "cached_vertices": sum("CACHED" in lines for lines in vertices.values()),
            "floating_runs_executed": len(floating), "compiler_layer_cached": bool(compiler_vertices and "CACHED" in compiler_vertices[0]),
            "compiler_vertex_seconds": duration(compiler_vertices[0]) if compiler_vertices else None,
            "floating_vertex_seconds": [duration(lines) for lines in floating],
            "image_export_load_vertex_seconds": [duration(lines) for lines in image_exports],
            "compiler_cache_statistics": statistics}


def seed_report(raw, source, tree):
    if len(raw) > 32768:
        raise ValueError("seed report exceeds its bound")
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("schema_version") != 1 or value.get("status") != "passed" or value.get("case") != "seed" \
            or value.get("source_sha") != source or value.get("source_tree") != tree \
            or value.get("cache_modes") != {"compiler": "r2", "layers": "r2"} \
            or not isinstance(value.get("seed_cache_id"), str) \
            or not re.fullmatch(r"run-[0-9]+/tree-[0-9a-f]{40}/seed-[0-9a-f]{64}", value["seed_cache_id"]):
        raise ValueError("invalid exact-source R2 seed report")
    return value


def finalize(directory, receipt_path):
    with ExitStack() as custody:
        finalize_held(directory, receipt_path, custody)


def finalize_held(directory, receipt_path, custody):
    directory = Path(directory)
    (directory / "result.json").unlink(missing_ok=True)
    credential = Path(os.environ["RUNNER_TEMP"]) / "codewire-sccache-r2.aws"
    if credential.exists() or credential.is_symlink():
        raise ValueError("job-owned cache credential cleanup has not completed")
    header = json.loads((directory / "identity.json").read_text())
    if header["source_sha"] != os.environ["CODEWIRE_EXPECTED_SOURCE_SHA"] \
            or header["source_tree"] != os.environ["CODEWIRE_EXPECTED_SOURCE_TREE"]:
        raise ValueError("measurement differs from the workflow-selected source")
    receipt = json.loads(Path(receipt_path).read_text())
    case = header["case"]
    expected_modes = dict(zip(("compiler", "layers"), MODES[case]))
    if receipt["source_sha"] != header["source_sha"] or receipt["source_tree"] != header["source_tree"] \
            or receipt["architecture"] != header["architecture"] or receipt["cache_modes"] != expected_modes \
            or receipt["layer_cache_fallback"] is not False \
            or os.environ.get("CODEWIRE_SCCACHE_MODE") != expected_modes["compiler"] \
            or os.environ.get("CODEWIRE_BUILDKIT_CACHE_MODE") != expected_modes["layers"]:
        raise ValueError("post-build identity or cache modes differ")
    if (directory / "metrics-error").exists():
        raise ValueError("required resource samples failed")
    lifecycle = json.loads((directory / "sampler-complete.json").read_text())
    if lifecycle.get("status") != "stopped" or type(lifecycle.get("sample_count")) is not int \
            or lifecycle["sample_count"] < 1 or not (directory / "sampler-stop-request").is_file():
        raise ValueError("resource sampler did not complete cleanly")
    samples = [json.loads(line) for line in (directory / "resources.jsonl").read_text().splitlines()]
    keys = ("memory_bytes", "backing_filesystem_total_bytes", "backing_filesystem_used_bytes",
            "backing_filesystem_available_bytes", "network_rx_bytes", "network_tx_bytes", "time_ns")
    if len(samples) != lifecycle["sample_count"] + 2 \
            or any(type(sample.get(key)) is not int or sample[key] < 0 for sample in samples for key in keys):
        raise ValueError("required resource samples are missing or malformed")
    for first, second in zip(samples, samples[1:]):
        if second["time_ns"] <= first["time_ns"] or any(second[key] < first[key] for key in ("network_rx_bytes", "network_tx_bytes")):
            raise ValueError("resource counters reset during the measurement")
        if second["backing_filesystem_total_bytes"] != first["backing_filesystem_total_bytes"]:
            raise ValueError("backing filesystem capacity changed during the measurement")
        if second["time_ns"] - first["time_ns"] > 20_000_000_000:
            raise ValueError("resource sampling coverage has a gap longer than twenty seconds")
    version_values = json.loads((directory / "versions.json").read_text())
    if set(version_values) != set(VERSION_COMMANDS) or any(not isinstance(v, str) or not v for v in version_values.values()):
        raise ValueError("floating tool inventory is incomplete")
    if header["architecture"] not in ("amd64", "arm64"):
        raise ValueError("measurement architecture is unsupported")
    amd64 = header["architecture"] == "amd64"
    phases = {"base": logs(directory / "base-build.log", expected_modes["layers"]),
              "workspace": logs(directory / "workspace-build.log", expected_modes["layers"],
                                workspace=True, compiler=not amd64)}
    evidence = None
    if amd64:
        evidence = custody.enter_context(ProducerEvidence(directory, header))
        workspace, _, workspace_files = workspace_history(directory, header, receipt, custody)
        if workspace["build_ref"] == evidence.identity["build_ref"]:
            raise ValueError("workspace and standalone producer histories must be distinct solves")
        phases["workspace"].update(workspace)
        phases["cw_producer"] = producer_logs(evidence, expected_modes["layers"])
        cached = True if case.startswith("warm-") else False if case in ("cold", "compiler") else None
        history, producer_files = held_producer_history(directory, evidence, cached, custody)
        phases["cw_producer"].update(history)
        summary = evidence.retained.summary
        phases["cw_producer"].update({key: summary[key] for key in
                                     ("source", "current_source", "payload", "profile", "version")})
        history_files = (*workspace_files, *producer_files)
        statistics = phases["cw_producer"]["compiler_cache_statistics"]
    else:
        history, history_files = compiler_history(directory, header, receipt, custody)
        phases["workspace"].update(history)
        statistics = phases["workspace"]["compiler_cache_statistics"]
    if case == "compiler" and statistics.get("Cache hits (Rust)", 0) <= 0:
        raise ValueError("compiler-only measurement did not prove reuse from its remote compiler cache")
    elapsed = float((directory / "elapsed-seconds").read_text())
    if not math.isfinite(elapsed) or elapsed < 0:
        raise ValueError("invalid elapsed measurement")
    result = dict(header, schema_version=1, status="passed", cache_modes=expected_modes,
                  workspace_image_id=receipt["workspace_image_id"], versions=version_values, phases=phases,
                  elapsed_seconds=elapsed,
                  metrics={"sample_count": len(samples), "observed_memory_max_bytes": max(s["memory_bytes"] for s in samples),
                           "backing_filesystem_total_bytes": samples[0]["backing_filesystem_total_bytes"],
                           "backing_filesystem_initial_used_bytes": samples[0]["backing_filesystem_used_bytes"],
                           "backing_filesystem_final_used_bytes": samples[-1]["backing_filesystem_used_bytes"],
                           "observed_backing_filesystem_max_used_bytes": max(s["backing_filesystem_used_bytes"] for s in samples),
                           "observed_backing_filesystem_min_available_bytes": min(s["backing_filesystem_available_bytes"] for s in samples),
                           "all_builder_network_rx_bytes": samples[-1]["network_rx_bytes"] - samples[0]["network_rx_bytes"],
                           "all_builder_network_tx_bytes": samples[-1]["network_tx_bytes"] - samples[0]["network_tx_bytes"]})
    if case != "seed":
        seed = seed_report(os.environ["CODEWIRE_WORKSPACE_CACHE_SEED_REPORT"], header["source_sha"], header["source_tree"])
        if seed["versions"] != result["versions"]:
            raise ValueError("floating tool versions drifted: comparison is inconclusive")
        if seed["architecture"] != result["architecture"] or seed["pins"] != result["pins"] \
                or seed["docker_daemon_id"] == result["docker_daemon_id"] \
                or seed["builder_container_id"] == result["builder_container_id"] \
                or seed["seed_cache_id"] != result["seed_cache_id"]:
            raise ValueError("measurement does not use a fresh matching worker and exact seed")
    # The job must succeed as well as emit this separate measurement report.
    # In particular, a late output-file failure cannot leave a success file or
    # log marker that looks like an accepted measurement.
    result_path = directory / "result.json"
    def interrupted(number, _frame):
        raise SystemExit(128 + number)

    handlers = {number: signal.signal(number, interrupted) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        if evidence is not None:
            evidence.revalidate()
        for held in history_files:
            held.revalidate(content=True)
        result_path.write_text(compact(result) + "\n")
        if evidence is not None:
            evidence.revalidate()
        for held in history_files:
            held.revalidate(content=True)
        if case == "seed":
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                output.write("workspace_cache_seed=" + compact(result) + "\n")
        print("CODEWIRE_WORKSPACE_CACHE_REPORT=" + compact(result), flush=True)
    except BaseException:
        result_path.unlink(missing_ok=True)
        raise
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)


def compare(paths):
    values = []
    for path in paths:
        lines = [line.split("CODEWIRE_WORKSPACE_CACHE_REPORT=", 1)[1] for line in Path(path).read_text().splitlines()
                 if "CODEWIRE_WORKSPACE_CACHE_REPORT=" in line]
        if len(lines) != 1:
            raise ValueError("each bound job log must contain one measurement report")
        values.append(json.loads(lines[0]))
    if len(values) != 5 or {value["case"] for value in values} != set(MODES):
        raise ValueError("comparison requires seed and all four cases")
    for key in ("source_sha", "source_tree", "architecture", "seed_cache_id"):
        if len({value[key] for value in values}) != 1:
            raise ValueError(f"comparison {key} differs")
    for key in ("pins", "versions"):
        if len({compact(value[key]) for value in values}) != 1:
            raise ValueError(f"comparison {key} drifted")
    for key in ("docker_daemon_id", "builder_container_id"):
        if len({value[key] for value in values}) != 5:
            raise ValueError(f"comparison reused {key}")
    if any(value["status"] != "passed" or value["cache_modes"] != dict(zip(("compiler", "layers"), MODES[value["case"]])) for value in values):
        raise ValueError("comparison contains an unsuccessful or incorrectly configured case")
    print(compact({"source_tree": values[0]["source_tree"], "cases": {v["case"]: {
        "elapsed_seconds": v["elapsed_seconds"], "metrics": v["metrics"]} for v in values}}))


if __name__ == "__main__":
    try:
        mode, *args = sys.argv[1:]
        if mode == "versions" and not args:
            versions()
        elif mode == "sample" and len(args) == 3:
            sample(*args)
        elif mode == "sample-once" and len(args) == 3:
            sample(*args, once=True)
        elif mode == "finalize" and len(args) == 2:
            finalize(*args)
        elif mode == "capture-history" and len(args) == 3:
            capture_history(*args)
        elif mode == "seed-id" and not args:
            value = seed_report(os.environ["CODEWIRE_WORKSPACE_CACHE_SEED_REPORT"],
                                os.environ["CODEWIRE_EXPECTED_SOURCE_SHA"], os.environ["CODEWIRE_EXPECTED_SOURCE_TREE"])
            if not value["seed_cache_id"].startswith("run-" + os.environ["GITHUB_RUN_ID"] + "/tree-" + value["source_tree"] + "/"):
                raise ValueError("seed belongs to another workflow run")
            print(value["seed_cache_id"])
        elif mode == "compare":
            compare(args)
        else:
            raise ValueError("invalid workspace cache report command")
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"workspace cache measurement: {error}", file=sys.stderr)
        sys.exit(1)
