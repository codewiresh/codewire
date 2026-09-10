#!/usr/bin/env python3
"""Bounded, value-blind workspace cache measurements; no provider API client."""
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

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
    if not isinstance(builder, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,160}", builder) \
            or not isinstance(reference, str) \
            or not re.fullmatch(re.escape(f"{builder}/{builder}-node/") + r"[a-z0-9]{20,32}", reference):
        raise ValueError("workspace history does not belong to the owned builder and node")
    image = metadata.get("containerimage.config.digest", "")
    if not isinstance(image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("workspace history metadata lacks its output image identity")
    return {"build_ref": reference, "workspace_image_id": image}


def capture_history(docker, builder, directory):
    directory = Path(directory)
    marker = directory / "workspace-history.json"
    marker.unlink(missing_ok=True)
    identity = history_identity(directory, builder)
    path = directory / "workspace-progress.jsonl"
    # Buildx's history lookup takes the solve ID, not its builder/node prefix.
    # Its rawjson printer writes to stderr. Never substitute latest/^0.
    with path.open("wb") as output:
        subprocess.run([docker, "buildx", "history", "logs", "--builder", builder,
                        "--progress", "rawjson", identity["build_ref"].rsplit("/", 1)[1]],
                       stdout=subprocess.DEVNULL, stderr=output, check=True)
    raw = path.read_bytes()
    if not raw or len(raw) > 64 * 1024 * 1024:
        raise ValueError("workspace history capture is empty or exceeds its bound")
    marker.write_text(compact(dict(identity, sha256=hashlib.sha256(raw).hexdigest())) + "\n")


def compiler_history(directory, header, receipt):
    directory = Path(directory)
    identity = history_identity(directory, header["builder_name"])
    marker = json.loads((directory / "workspace-history.json").read_text())
    raw = (directory / "workspace-progress.jsonl").read_bytes()
    if not raw or len(raw) > 64 * 1024 * 1024 \
            or marker != dict(identity, sha256=hashlib.sha256(raw).hexdigest()) \
            or identity["workspace_image_id"] != receipt["workspace_image_id"]:
        raise ValueError("workspace history capture is incomplete or belongs to another output")
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
    cached = any(v.get("cached") is True and v.get("started") and v.get("completed") for v in events)
    executed = any(v.get("started") and v.get("inputs") and not v.get("cached", False) for v in events)
    if header["case"].startswith("warm-") and (not cached or executed):
        raise ValueError("warm workspace did not prove reuse of its compiler layer")
    return dict(identity, compiler_vertex_digest=digest, compiler_layer_cached=bool(cached),
                compiler_executed=bool(executed))


def logs(path, layers, workspace=False):
    text = Path(path).read_text()
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
    compiler = [lines for lines in vertices.values()
                if any(re.match(r"\[cw-builder [^]]+\] RUN\b", line) for line in lines)]
    if workspace:
        if len(floating) != 2 or any("CACHED" in lines or not any(line.startswith("DONE") for line in lines) for lines in floating):
            raise ValueError("both floating tool RUNs must execute")
        if len(compiler) != 1:
            raise ValueError("workspace log lacks one compiler vertex")
    statistics = {key: int(value) for key, value in re.findall(
        r"(?im)(Cache hits(?: \(Rust\))?|Cache misses|Cache read errors|Cache write errors|Cache errors)\s+(\d+)", text)}
    def duration(lines):
        done = [float(match[1]) for line in lines if (match := re.fullmatch(r"DONE ([0-9.]+)s", line))]
        return done[-1] if done else None

    image_exports = [lines for lines in vertices.values() if any(line in ("exporting to docker image format", "importing to docker") for line in lines)]
    return {"s3_export_completed": bool(exports), "cached_vertices": sum("CACHED" in lines for lines in vertices.values()),
            "floating_runs_executed": len(floating), "compiler_layer_cached": bool(compiler and "CACHED" in compiler[0]),
            "compiler_vertex_seconds": duration(compiler[0]) if compiler else None,
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
    phases = {target: logs(directory / f"{target}-build.log", expected_modes["layers"],
                           workspace=target == "workspace") for target in ("base", "workspace")}
    phases["workspace"].update(compiler_history(directory, header, receipt))
    statistics = phases["workspace"]["compiler_cache_statistics"]
    if case == "compiler" and statistics.get("Cache hits (Rust)", statistics.get("Cache hits", 0)) <= 0:
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
        result_path.write_text(compact(result) + "\n")
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
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"workspace cache measurement: {error}", file=sys.stderr)
        sys.exit(1)
