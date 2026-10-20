#!/usr/bin/env python3
"""Managed Codex/Claude acceptance in an owned native Linux VM environment.

Run from the checked-in native VM/broker topology after the caller creates the
environment and provisions the matching guest cw:
  scripts/dev/test-cli-native-managed.py --cw /abs/cw --environment UUID
  scripts/dev/test-cli-native-managed.py --cw /abs/cw --environment UUID --synthetic-peers

The default drives the guest's own Codex and Claude through the environment's
already-selected synthetic protected profile. Steps that depend on the
upstream fixture send CW_FIXTURE_* prompt markers; the proof reports the exact
response each marker needs and fails closed when the fixture does not supply
it. A managed agent runs the client the guest user's shell runs, with no
pinned version. Before the first conversation the journey stages codex and
claude in the user's npm prefix, first on PATH as a user's own update would
be, each recording that it ran and then running the client the shell found
before it, and proves both managed agents ran those updates.

--synthetic-peers changes only this harness's expectations, for
fixtures/agent-peer.py staged as the guest codex and claude on PATH, which the
managed agents then run as the shell would. It is not a product override.

The caller's isolated CW_CONFIG_DIR, native state and artifact environment are
inherited unchanged. The host CLI launches every session, all uniquely
prefixed, and finally stops only those exact session IDs; the caller owns the
environment and VM. Login, profile and provider material are never read. A
message is never resent under a new ID, unknown outcomes stay unknown, and
agent replies are never printed. Guest agents cannot invoke host cw or spawn
sessions through the guest daemon; same-VM parent adoption is the
orchestration proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time
import unittest
import uuid

OVERALL_SECONDS = 1200
CLEANUP_RESERVE_SECONDS = 180
PEER_MARKER = "Synthetic native peers for the real cw managed-session acceptance journey"
TERMINAL_SESSION = {"Stopped", "Exited", "Failed", "Interrupted"}
TERMINAL_MESSAGE = {"completed", "error", "interrupted", "unknown"}
PRE_ACCEPT = {"requested", "pipe_written", "undelivered"}
UUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# Synthetic broker canaries and common provider token shapes. Matches are
# counted and fail the run; their values are never reported.
CANARY_SHAPES = re.compile(
    r"cw(?:local|workload|personal)[a-z]*[0-9a-f]{32}"
    r"|\bsk-[A-Za-z0-9_-]{20,}|\bgh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}")
LONG_TOKEN = re.compile(r"[A-Za-z0-9_+=.\-]{24,}")

COMMON_REQUIRED = (
    "preflight/environment-running/preexisting-sessions-recorded",
    "preflight/image-derived-cw/root-owned/read-only/digest-pinned/bootstrap-bound/readonly-launcher/before-first-agent",
    "sentinel/durable-terminal-running",
    "refusal/unmanaged-parent/missing-parent/unqualified-agent/no-session",
    "codex-lead/two-turns/native-ack/same-conversation",
    "managed/raw-send-and-key-rejected",
    "claude-worker/same-vm-parent/native-ack/deterministic-notification/parent-continuation",
    "history/inbox-order/wait-routing-by-message/unknown-message-refused/logs-readable",
    "claude-worker/stop-known-clean/restart-same-session/resume/notification-once",
    "notifications/deterministic-ids/exactly-once/parent-turns-completed",
    "own-sessions-stopped-known-clean/sentinel-terminal-live/preexisting-preserved/environment-running",
)
SYNTHETIC_REQUIRED = COMMON_REQUIRED + (
    "preflight/guest-agents-synthetic-peers-staged",
    "shell-client/synthetic-peers-run-from-path",
    "controls/codex-expected-turn-steer/mismatch-refused/claude-steer-refused/claude-interrupt",
    "driver-exit/lead-stop-in-flight-unknown-not-replayed/stopped-refuses-msg/parent-adopts-after-restart/resume",
    "driver-exit/native-startup-failure/task-error/parent-notified/session-ended/msg-refused",
)
ACTUAL_REQUIRED = COMMON_REQUIRED + (
    "preflight/protected-profile-selected",
    "preflight/guest-agents-actual-not-synthetic",
    "shell-client/user-updates-first-on-path",
    "shell-client/managed-agents-run-the-user-updates",
    "guest-tool-marker/actual-codex-shell-tool",
    "controls/actual-detected-capabilities/idle-and-unsupported-refused-without-record",
    "controls/actual-codex-held-turn-interrupt",
    "controls/actual-codex-held-turn-steer",
    "controls/actual-claude-held-turn-interrupt-or-undetected-refused",
    "driver-exit/lead-stop-idle-nothing-unknown/stopped-refuses-msg/parent-adopts-after-restart/resume",
    "custody/normal-stop/live-detached-doublefork-term-resistant/echild/driver-exit",
    "custody/cancelled-stop/durable-intent/local-caller-cancelled/same-operation-joined",
    "custody/driver-sigkill/unknown-fenced/echild-before-admission/one-safe-restart/no-replay",
    "custody/missing-and-stale-receipt/restart-refused/no-admission/exact-restoration",
    "custody/sentinel-live/owned-families-reaped/exact-fixture-files-removed",
)
# The upstream responses actual guest agents need from the protected-broker
# fixture. "Latest user text" is the newest user message in the request.
FIXTURE_EXPECTATIONS = (
    ("codex-reply", "any Codex Responses request without a CW_FIXTURE_* marker, including follow-up "
     "turns in one thread and turns whose user text starts with `[Codewire] Managed worker`",
     "a streamed assistant message and response.completed; any text",
     ("codex-lead/two-turns/native-ack/same-conversation",
      "claude-worker/same-vm-parent/native-ack/deterministic-notification/parent-continuation",
      "driver-exit/lead-stop-idle-nothing-unknown/stopped-refuses-msg/parent-adopts-after-restart/resume",
      "notifications/deterministic-ids/exactly-once/parent-turns-completed")),
    ("claude-reply", "any Claude Messages request without a CW_FIXTURE_* marker, before and after "
     "--resume of the same session",
     "a completed streamed assistant message; any text",
     ("claude-worker/same-vm-parent/native-ack/deterministic-notification/parent-continuation",
      "claude-worker/stop-known-clean/restart-same-session/resume/notification-once")),
    ("codex-tool-call", "a Codex request whose latest user text starts with `CW_FIXTURE_TOOL printf %s "
     "CW_TOOL_MARKER_<16 uppercase hex> > .cwnm-<8 hex>-tool-marker`",
     "one shell tool call running exactly the command after `CW_FIXTURE_TOOL ` on that line, in the "
     "session working directory; after its tool output, a completed assistant message",
     ("guest-tool-marker/actual-codex-shell-tool",)),
    ("codex-hold-interrupt", "a Codex request whose latest user text starts with `CW_FIXTURE_HOLD <8 hex>`",
     "start streaming and stay open without completing for at least 60 s, until Codex cancels it after "
     "turn/interrupt; the turn must end interrupted",
     ("controls/actual-codex-held-turn-interrupt",)),
    ("codex-hold-steer", "a Codex request whose latest user text starts with `CW_FIXTURE_STEERABLE <nonce>`, "
     "then the request in the same turn carrying the steer text `CW_FIXTURE_STEER <nonce>`",
     "keep the first stream open for at least 10 s so the harness can steer, then let the turn continue; "
     "answer the request carrying the steer text with assistant text `CW_STEERED <nonce>`; the turn must "
     "complete within 45 s of the steer",
     ("controls/actual-codex-held-turn-steer",)),
    ("claude-hold-interrupt", "a Claude Messages request whose latest user text starts with "
     "`CW_FIXTURE_HOLD <8 hex>`, sent only when the guest Claude confirmed native control requests",
     "start streaming and stay open for at least 60 s, until the Claude CLI cancels it after its native "
     "interrupt; the turn must end interrupted",
     ("controls/actual-claude-held-turn-interrupt-or-undetected-refused",)),
    ("codex-custody", "a Codex request whose latest user text starts with `CW_FIXTURE_CUSTODY <8 hex>`",
     "one offered shell tool running the fixture's fixed Python command; record exact births of detached "
     "and double-forked TERM-resistant children in .cwnm-<nonce>-custody.json; after its output hold the "
     "stream for 120 s without replaying the command, until the owned driver is stopped or killed",
     ("custody/normal-stop/live-detached-doublefork-term-resistant/echild/driver-exit",
      "custody/cancelled-stop/durable-intent/local-caller-cancelled/same-operation-joined",
      "custody/driver-sigkill/unknown-fenced/echild-before-admission/one-safe-restart/no-replay")),
)

# Fixed guest program, invoked only through an owned durable cw run + wait.
# It reads public /proc metadata and this journey's exact private custody
# files. No incoming prompt, command, arbitrary path or provider material is
# accepted. Mutations are restricted to a birth-bound driver SIGKILL, a
# stopped instance's receipt fault/restoration and exact nonce fixture files.
CUSTODY_PROBE = r'''import hashlib, json, os, re, signal, stat, sys, time
operation, environment, driver, session, nonce, expected_json, digest = sys.argv[1:]
uuid_re = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
assert re.fullmatch(uuid_re, environment) and re.fullmatch(uuid_re, driver)
assert re.fullmatch("session-" + uuid_re, session) and re.fullmatch("[0-9a-f]{8}", nonce)
assert operation in ("ready", "observe", "kill", "fault-missing", "fault-stale", "restore", "remove")
expected = json.loads(expected_json)
identity_keys = {"environment_id", "driver_id", "session_id", "instance_id", "driver_started_at", "boot_id", "driver_pid", "driver_start_ticks"}
assert set(expected) == identity_keys
assert expected["environment_id"] == environment and expected["driver_id"] == driver and expected["session_id"] == session
assert re.fullmatch(uuid_re, expected["instance_id"]) and re.fullmatch(uuid_re, expected["boot_id"])
assert type(expected["driver_pid"]) is int and expected["driver_pid"] > 1
assert type(expected["driver_start_ticks"]) is int and expected["driver_start_ticks"] > 0
boot = open("/proc/sys/kernel/random/boot_id").read().strip()
assert boot == expected["boot_id"]
flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
directory_flags = flags | os.O_DIRECTORY
root = os.open("/", directory_flags)
for component in ("home", "codewire", ".local", "state", "codewire", "managed-agents-v1", environment, "agents", driver):
    child = os.open(component, directory_flags, dir_fd=root)
    os.close(root)
    root = child
    metadata = os.fstat(root)
    if component in ("managed-agents-v1", environment, "agents", driver):
        assert metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700
cwd = os.open(".", directory_flags)
receipt_name = "peer-" + expected["instance_id"] + ".json"
journal_name = "peer-" + expected["instance_id"] + ".journal"
backup_name = "." + receipt_name + "-" + nonce + "-backup"
fault_name = "." + receipt_name + "-" + nonce + "-fault"
family_name = ".cwnm-" + nonce + "-custody.json"
tool_name = ".cwnm-" + nonce + "-tool-marker"
observed_files = {}

def stamp(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)

def guard_leaf(parent, name):
    assert stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == observed_files[(parent, name)], "owned leaf changed before mutation"

def read_private(parent, name, maximum=65536, absent=False, modes=(0o600,)):
    for attempt in range(5):
        try:
            fd = os.open(name, flags | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            if absent:
                return None
            raise
        try:
            before = os.fstat(fd)
            assert stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
            assert stat.S_IMODE(before.st_mode) in modes and before.st_nlink == 1 and before.st_size <= maximum
            data = b""
            while len(data) <= maximum:
                part = os.read(fd, min(65536, maximum + 1 - len(data)))
                if not part:
                    break
                data += part
            after = os.fstat(fd)
            assert len(data) <= maximum
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink):
                observed_files[(parent, name)] = stamp(after)
                return data
        finally:
            os.close(fd)
        time.sleep(0.02)
    raise AssertionError("private record changed throughout bounded read")

def birth(pid, ticks):
    try:
        parts = open("/proc/%d/stat" % pid).read().rsplit(") ", 1)[1].split()
        if int(parts[19]) != ticks:
            return {"present": False, "live": False}
        status = open("/proc/%d/status" % pid).read()
        ignored = int(next(line.split()[1] for line in status.splitlines() if line.startswith("SigIgn:")), 16)
        return {"present": True, "live": parts[0] not in ("Z", "X"), "state": parts[0], "ppid": int(parts[1]), "pgrp": int(parts[2]), "sid": int(parts[3]), "term_ignored": bool(ignored & (1 << (signal.SIGTERM - 1)))}
    except (FileNotFoundError, ProcessLookupError):
        return {"present": False, "live": False}

def receipt():
    raw = read_private(root, receipt_name)
    value = json.loads(raw)
    assert set(value) == {"version", "identity", "guardian_pid", "guardian_start_ticks", "provider_pid", "cleanup_unknown", "finished_at", "exit_code", "error"}
    assert value["version"] == 1 and value["identity"] == expected
    assert type(value["cleanup_unknown"]) is bool and value["cleanup_unknown"] == (value["finished_at"] is None)
    return raw, value

def family():
    raw = read_private(cwd, family_name, 4096, absent=True)
    if raw is None:
        return None
    value = json.loads(raw)
    assert set(value) == {"version", "nonce", "boot_id", "children"}
    assert value["version"] == 1 and value["nonce"] == nonce and value["boot_id"] == boot
    assert isinstance(value["children"], list) and len(value["children"]) == 2
    assert {item["role"] for item in value["children"]} == {"detached", "double_fork"}
    assert len({item["pid"] for item in value["children"]}) == 2
    for item in value["children"]:
        assert set(item) == {"role", "pid", "start_ticks"}
        assert type(item["pid"]) is int and item["pid"] > 1 and type(item["start_ticks"]) is int and item["start_ticks"] > 0
    return {"boot_id":boot, "nonce":nonce, "children":[dict(item, process=birth(item["pid"], item["start_ticks"])) for item in value["children"]]}

def clean(value):
    return not value["cleanup_unknown"] and value["finished_at"] is not None

def stale(raw):
    value = json.loads(raw)
    value["identity"]["boot_id"] = "00000000-0000-0000-0000-000000000000"
    return json.dumps(value, separators=(",", ":")).encode()

def private_write(name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
        observed_files[(root, name)] = stamp(os.fstat(stream.fileno()))

current = json.loads(read_private(root, "peer-current.json"))
if operation not in ("observe", "remove"):
    assert current == expected
if operation == "ready":
    end = time.monotonic() + 20
    while True:
        group = family()
        if group is not None:
            break
        assert time.monotonic() < end, "fixture family was not recorded"
        time.sleep(0.1)
elif operation == "kill":
    raw, value = receipt()
    assert value["cleanup_unknown"] and birth(expected["driver_pid"], expected["driver_start_ticks"])["live"]
    fd = os.pidfd_open(expected["driver_pid"], 0)
    try:
        assert birth(expected["driver_pid"], expected["driver_start_ticks"])["live"]
        signal.pidfd_send_signal(fd, signal.SIGKILL)
    finally:
        os.close(fd)
elif operation.startswith("fault-"):
    raw, value = receipt()
    assert clean(value) and not birth(expected["driver_pid"], expected["driver_start_ticks"])["live"]
    assert re.fullmatch("[0-9a-f]{64}", digest) and hashlib.sha256(raw).hexdigest() == digest
    private_write(backup_name, b"")
    guard_leaf(root, receipt_name)
    guard_leaf(root, backup_name)
    os.replace(receipt_name, backup_name, src_dir_fd=root, dst_dir_fd=root)
    if operation == "fault-stale":
        private_write(fault_name, stale(raw))
        guard_leaf(root, fault_name)
        assert read_private(root, receipt_name, absent=True) is None
        os.replace(fault_name, receipt_name, src_dir_fd=root, dst_dir_fd=root)
    os.fsync(root)
    print(json.dumps({"fault": operation, "receipt_sha256":digest, "original_inode":os.stat(backup_name, dir_fd=root, follow_symlinks=False).st_ino}))
    raise SystemExit(0)
elif operation == "restore":
    assert re.fullmatch("[0-9a-f]{64}", digest)
    saved = read_private(root, backup_name, absent=True)
    present = read_private(root, receipt_name, absent=True)
    # A fault probe interrupted after reserving its empty backup has not yet
    # changed the receipt. Remove only that reservation after proving this.
    if saved == b"" and present is not None and hashlib.sha256(present).hexdigest() == digest:
        guard_leaf(root, backup_name)
        os.unlink(backup_name, dir_fd=root)
        saved = None
    if saved is not None:
        assert hashlib.sha256(saved).hexdigest() == digest and json.loads(saved)["identity"] == expected
        assert present is None or present == stale(saved), "receipt changed outside this exact fault"
        guard_leaf(root, backup_name)
        if present is not None:
            guard_leaf(root, receipt_name)
        os.replace(backup_name, receipt_name, src_dir_fd=root, dst_dir_fd=root)
        os.fsync(root)
    raw, value = receipt()
    assert hashlib.sha256(raw).hexdigest() == digest and clean(value)
    leftover = read_private(root, fault_name, absent=True)
    if leftover is not None:
        assert leftover == stale(raw)
        guard_leaf(root, fault_name)
        os.unlink(fault_name, dir_fd=root)
    print(json.dumps({"restored":True, "receipt_sha256":digest, "receipt_inode":os.stat(receipt_name, dir_fd=root, follow_symlinks=False).st_ino}))
    raise SystemExit(0)
elif operation == "remove":
    raw, value = receipt()
    assert clean(value) and not birth(expected["driver_pid"], expected["driver_start_ticks"])["live"]
    group = family()
    if group is not None:
        assert all(not child["process"]["present"] for child in group["children"]), "owned family is not reaped"
        guard_leaf(cwd, family_name)
        os.unlink(family_name, dir_fd=cwd)
    marker = read_private(cwd, tool_name, 128, absent=True, modes=(0o600, 0o644))
    if marker is not None:
        assert re.fullmatch(rb"CW_TOOL_MARKER_[0-9A-F]{16}", marker)
        guard_leaf(cwd, tool_name)
        os.unlink(tool_name, dir_fd=cwd)
    assert read_private(root, backup_name, absent=True) is None and read_private(root, fault_name, absent=True) is None
    print(json.dumps({"removed":True, "family":group}))
    raise SystemExit(0)

raw, value = receipt()
journal = read_private(root, journal_name, absent=True) or b""
print(json.dumps({"peer":value, "current":current, "receipt_sha256":hashlib.sha256(raw).hexdigest(), "receipt_inode":os.stat(receipt_name, dir_fd=root, follow_symlinks=False).st_ino, "driver":birth(expected["driver_pid"], expected["driver_start_ticks"]), "family":family(), "echild":b"cleanup proven: waitpid reported no remaining children" in journal}))
'''


# Stages a user's own update of each client in the user's npm prefix, which
# the image puts first on PATH. Each records that it ran and then runs the
# client the shell found before it, so a conversation works as before. An
# existing file there is never replaced.
UPDATE_STAGE = r'''import os, re, sys
prefix, codex, claude = sys.argv[1:]
assert re.fullmatch(r"cwnm-[0-9a-f]{8}", prefix)
home = "/home/codewire"
directory = os.path.join(home, ".npm-global", "bin")
os.makedirs(directory, mode=0o755, exist_ok=True)
for name, original in (("codex", codex), ("claude", claude)):
    assert re.fullmatch(r"/[A-Za-z0-9._+/-]+", original) and not original.startswith(directory + "/")
    body = f"#!/bin/sh\n: > {home}/.{prefix}-update-{name}-ran\nexec {original} \"$@\"\n"
    fd = os.open(os.path.join(directory, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o755)
    with os.fdopen(fd, "w") as stream:
        stream.write(body)
'''
SHELL_CLIENTS = 'for name in codex claude; do printf "%s=%s\\n" "$name" "$(command -v "$name")"; done'

# Reads which staged updates ran. It changes nothing.
UPDATE_PROBE = r'''import json, os, re, sys
prefix, = sys.argv[1:]
assert re.fullmatch(r"cwnm-[0-9a-f]{8}", prefix)
home = "/home/codewire"
print(json.dumps({"ran": sorted(entry for entry in os.listdir(home) if entry.startswith(f".{prefix}-update-"))}))
'''

# Removes exactly the staged updates and the markers they wrote.
UPDATE_REMOVE = r'''import json, os, re, stat, sys
prefix, codex, claude = sys.argv[1:]
assert re.fullmatch(r"cwnm-[0-9a-f]{8}", prefix)
home = "/home/codewire"
removed, markers = [], []
for name, original in (("codex", codex), ("claude", claude)):
    path = os.path.join(home, ".npm-global", "bin", name)
    body = f"#!/bin/sh\n: > {home}/.{prefix}-update-{name}-ran\nexec {original} \"$@\"\n".encode()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        continue
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1
        assert stream.read(len(body) + 1) == body
    os.unlink(path)
    removed.append(name)
for entry in sorted(os.listdir(home)):
    if entry.startswith(f".{prefix}-update-") and entry.endswith("-ran"):
        os.unlink(os.path.join(home, entry))
        markers.append(entry)
print(json.dumps({"removed": removed, "markers": markers}))
'''

BOOT_ASSET_PROBE = r'''import hashlib, json, os, stat, sys
expected_index, expected_manifest, expected_cw, expected_environment, expected_bootstrap = sys.argv[1:]
flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
directory_flags = flags | os.O_DIRECTORY
root = os.open("/", directory_flags)
for component in ("run", "codewire-runtime", "cw"):
    child = os.open(component, directory_flags, dir_fd=root)
    os.close(root)
    root = child
def directory(fd):
    metadata = os.fstat(fd)
    assert stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == metadata.st_gid == 0
    assert stat.S_IMODE(metadata.st_mode) == 0o555
    assert os.fstatvfs(fd).f_flag & os.ST_RDONLY
def read(directory_fd, name, mode, bound):
    fd = os.open(name, flags | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        metadata = os.fstat(fd)
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == metadata.st_gid == 0
        assert stat.S_IMODE(metadata.st_mode) == mode and metadata.st_nlink == 1
        assert 0 < metadata.st_size <= bound and os.fstatvfs(fd).f_flag & os.ST_RDONLY
        with os.fdopen(fd, "rb", closefd=False) as source:
            data = source.read(bound + 1)
        assert len(data) == metadata.st_size
        return data
    finally:
        os.close(fd)
directory(root)
selection = json.loads(read(root, "selection.json", 0o444, 2 * 16 * 16384))
assert set(selection) == {"schema_version", "environment_id", "bootstrap_catalog_sha256", "revision", "previous_sha256", "catalog", "operations"}
assert selection["schema_version"] == 1 and selection["environment_id"] == expected_environment
assert selection["bootstrap_catalog_sha256"] == expected_bootstrap
assert selection["revision"] == 1 and selection["previous_sha256"] is None and selection["operations"] == []
catalog = selection["catalog"]
assert set(catalog) == {"schema_version", "active_sha256", "runtimes"}
assert catalog["schema_version"] == 1 and catalog["active_sha256"] == expected_cw
# The fresh selector embeds the immutable bootstrap catalog. Its Rust JSON
# encoding has ordered struct fields, compact separators and a final newline.
catalog_bytes = (json.dumps(catalog, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
assert hashlib.sha256(catalog_bytes).hexdigest() == expected_bootstrap
assert 1 <= len(catalog["runtimes"]) <= 16
digests = [runtime["payload"]["sha256"] for runtime in catalog["runtimes"]]
assert digests == sorted(set(digests)) and expected_cw in digests
assert set(os.listdir(root)) == {"selection.json", "cw", *digests}
selected = os.open(expected_cw, directory_flags, dir_fd=root)
directory(selected)
assert set(os.listdir(selected)) == {"cw", "provenance.json"}
provenance = json.loads(read(selected, "provenance.json", 0o444, 16384))
assert provenance == catalog["runtimes"][digests.index(expected_cw)]
assert provenance["image_index_sha256"] == expected_index
assert provenance["image_manifest"]["sha256"] == expected_manifest
assert provenance["payload"]["sha256"] == expected_cw
cw = read(selected, "cw", 0o555, 256 * 1024 * 1024)
assert len(cw) == provenance["payload"]["size"] and hashlib.sha256(cw).hexdigest() == expected_cw
launcher = read(root, "cw", 0o555, 256 * 1024 * 1024)
fixed = os.open("/", directory_flags)
for component in ("usr", "local", "bin"):
    child = os.open(component, directory_flags, dir_fd=fixed)
    metadata = os.fstat(child)
    assert stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == metadata.st_gid == 0
    assert stat.S_IMODE(metadata.st_mode) & 0o022 == 0
    os.close(fixed)
    fixed = child
assert read(fixed, "cw", 0o555, 256 * 1024 * 1024) == launcher
print(json.dumps({"cw_sha256": expected_cw, "image_manifest_sha256": expected_manifest, "bootstrap_catalog_sha256": expected_bootstrap, "selection_revision": 1, "read_only": True, "fixed_launcher_read_only": True}))
'''


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def decode_json(verb, stdout, expect):
    if not stdout.strip():
        require(expect != "ok", f"cw {verb} returned no JSON")
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as error:
        raise Failure(f"cw {verb} returned invalid JSON: {error}") from None


def is_uuid(value):
    return isinstance(value, str) and UUID_PATTERN.fullmatch(value) is not None


def is_session_id(value):
    """Durable daemon sessions use session-<uuid>; messages and drivers use bare UUIDs."""
    return isinstance(value, str) and is_uuid(value.removeprefix("session-"))


def scrub(text, limit=1500):
    text = CANARY_SHAPES.sub("[scrubbed]", str(text))

    def token(match):
        value = match.group(0)
        return value if is_session_id(value.strip(".-")) else "[scrubbed]"
    return LONG_TOKEN.sub(token, text)[:limit]


def notification_id(source_message_id):
    """The driver's deterministic parent notification ID for one worker message."""
    digest = hashlib.sha256(f"codewire-agent-notification:v1:{source_message_id}".encode()).digest()
    value = bytearray(digest[:16])
    value[6] = (value[6] & 0x0F) | 0x40
    value[8] = (value[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(value)))


def kill_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return process.communicate()


def terminate(signum, _frame):
    raise Failure(f"harness received signal {signum}")


def generation(view):
    value = view.get("launch_generation") if isinstance(view, dict) else None
    require(type(value) is int and value > 0, "session has no admitted positive launch generation")
    return value


def peer_identity(inbox, environment, driver, session):
    peer = inbox.get("peer") if isinstance(inbox, dict) else None
    identity = peer.get("identity") if isinstance(peer, dict) else None
    require(isinstance(identity, dict) and identity.get("environment_id") == environment and
            identity.get("driver_id") == driver and identity.get("session_id") == session and
            is_uuid(identity.get("instance_id")) and is_uuid(identity.get("boot_id")) and
            type(identity.get("driver_pid")) is int and identity["driver_pid"] > 1 and
            type(identity.get("driver_start_ticks")) is int and identity["driver_start_ticks"] > 0,
            "custody peer lacks the exact environment/session/instance/process birth")
    return identity


def require_live_family(proof, nonce):
    group = proof.get("family")
    require(isinstance(group, dict) and group.get("nonce") == nonce and
            group.get("boot_id") == proof["peer"]["identity"]["boot_id"],
            "fixture family is not bound to this nonce and boot")
    children = group.get("children")
    require(isinstance(children, list) and len(children) == 2 and
            {child.get("role") for child in children} == {"detached", "double_fork"} and
            len({child.get("pid") for child in children}) == 2,
            "fixture did not record both distinct descendant births")
    for child in children:
        process = child.get("process") or {}
        require(type(child.get("start_ticks")) is int and child["start_ticks"] > 0 and
                process.get("present") and process.get("live") and process.get("term_ignored") and
                process.get("sid") > 1 and process.get("pgrp") > 1,
                "fixture child was not live, birth-bound and TERM-resistant")
        require((process["sid"] == child["pid"]) == (child["role"] == "detached"),
                "fixture did not prove both detached and double-forked process shapes")


def require_shell_clients(proof, prefix):
    """Both managed agents ran the user's update first on PATH, as the
    user's shell would."""
    require(isinstance(proof, dict) and set(proof) == {"ran"} and isinstance(proof["ran"], list),
            "the shell client probe returned another proof shape")
    for name in ("codex", "claude"):
        require(f".{prefix}-update-{name}-ran" in proof["ran"],
                f"no managed {name} ran the user's update first on PATH")
    require(len(proof["ran"]) == 2, "the shell client probe found another marker")


def require_clean_custody(proof, expected, original_family):
    peer = proof.get("peer") or {}
    require(peer.get("identity") == expected and peer.get("cleanup_unknown") is False and
            bool(peer.get("finished_at")) and proof.get("echild") is True and
            not (proof.get("driver") or {}).get("live"),
            "custody lacks same-instance ECHILD receipt and actual driver exit")
    group = proof.get("family")
    require(group is not None and all(not child["process"]["present"] for child in group["children"]),
            "custody fixture descendant births were not reaped")
    def births(value):
        return {"boot_id": value["boot_id"], "nonce": value["nonce"],
                "children": [{key: child[key] for key in ("role", "pid", "start_ticks")}
                             for child in value["children"]]}
    require(births(group) == births(original_family), "cleanup changed the recorded owned descendant births")


class Journey:
    def __init__(self, cw, environment, synthetic, codex_model, claude_model, image_receipt=None):
        self.cw = cw
        self.environment = environment
        self.synthetic = synthetic
        self.codex_model = codex_model
        self.claude_model = claude_model
        self.env = dict(os.environ)
        self.image_receipt = image_receipt
        self.prefix = "cwnm-" + secrets.token_hex(4)
        self.started = time.monotonic()
        self.deadline = self.started + OVERALL_SECONDS - CLEANUP_RESERVE_SECONDS
        self.turn_timeout = 60 if synthetic else 180
        self.stage = "init"
        self.checks = []
        self.missing = []
        self.limitations = []
        self.ambiguous = []
        self.expected_unknown = []
        self.owned = {}
        self.drivers = {}
        self.final_sessions = []
        self.preexisting = {}
        self.notified = []
        self.canary_hits = 0
        self.agents = {"codex": {}, "claude": {}}
        self.fixture = {} if synthetic else {
            name: {"name": name, "request": request, "response": response, "checks": list(checks),
                   "status": "unobserved", "observed": None}
            for name, request, response, checks in FIXTURE_EXPECTATIONS}
        self.profile_selected = None
        self.sentinel = self.lead = self.worker = None
        self.lead_thread = self.worker_thread = None
        self.lead_turns = []
        self.routed = []
        self.guest_probe_count = 0
        self.custody_cases = []
        self.custody_evidence = []
        self.receipt_faults = {}
        self.pending_callers = []
        self.tool_file = None
        self.tool_token = None
        self.updates_staged = None

    # -- CLI -------------------------------------------------------------

    def budget(self, requested):
        remaining = self.deadline - time.monotonic()
        if remaining <= 2:
            raise Failure(f"overall acceptance deadline expired during {self.stage}")
        return max(1.0, min(float(requested), remaining))

    def call(self, *args, expect="ok", timeout=30):
        limit = self.budget(timeout)
        verb = args[0]
        process = subprocess.Popen([self.cw, *args], env=self.env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=limit)
        except subprocess.TimeoutExpired:
            self.scan(*kill_group(process))
            self.ambiguous.append({"kind": "cli-call", "command": verb, "stage": self.stage,
                                   "detail": f"no exit within {limit:.0f}s; outcome unknown, not retried"})
            raise Failure(f"cw {verb} did not finish within {limit:.0f}s; its outcome is unknown") from None
        except BaseException:
            kill_group(process)
            raise
        self.scan(stdout, stderr)
        if expect == "ok" and process.returncode != 0:
            detail = f"cw {verb} exited {process.returncode}: {scrub(stderr)}"
            if args[0] == "wait" and any(args[index:index + 2] == ("--output", "json")
                                         for index in range(len(args) - 1)):
                # wait emits retained session output before reporting a failed
                # exit. Keep its diagnostic, never arbitrary command stdout.
                try:
                    record = json.loads(stdout)
                except (ValueError, RecursionError):
                    record = None
                if isinstance(record, dict) and isinstance(record.get("output"), str) and record["output"]:
                    detail = (f"cw {verb} exited {process.returncode}: {scrub(stderr, 300)}\n"
                              f"retained session output:\n{scrub(record['output'], 1000)}")
            raise Failure(detail)
        if expect == "fail" and process.returncode == 0:
            raise Failure(f"cw {verb} unexpectedly succeeded")
        return process.returncode, stdout, stderr

    def scan(self, *texts):
        self.canary_hits += sum(len(CANARY_SHAPES.findall(text or "")) for text in texts)

    def data(self, *args, expect="ok", timeout=30):
        code, stdout, _ = self.call(*args, expect=expect, timeout=timeout)
        return code, decode_json(args[0], stdout, expect)

    def wait_seconds(self, requested):
        seconds = int(self.budget(requested + 15)) - 15
        require(seconds >= 1, f"overall acceptance deadline expired during {self.stage}")
        return seconds

    def check(self, name):
        self.checks.append(name)
        print(f"cli-native-managed: {name} PASS", file=sys.stderr, flush=True)

    def until(self, probe, predicate, timeout, what):
        end = time.monotonic() + self.budget(timeout)
        while time.monotonic() < end:
            value = probe()
            if predicate(value):
                return value
            time.sleep(0.5)
        raise Failure(f"{what} was not observed within {timeout}s")

    # -- Sessions --------------------------------------------------------

    def sessions(self):
        _, views = self.data("ls", self.environment, "--output", "json")
        require(isinstance(views, list), "cw ls did not return a session array")
        return {view["session_id"]: view for view in views}

    def own(self, view):
        require(isinstance(view, dict) and is_session_id(view.get("session_id")),
                "launch returned no canonical session ID")
        self.owned.setdefault(view["session_id"], view.get("name", ""))
        return view["session_id"]

    def adopt_name(self, name):
        """Owns a session whose launch outcome was ambiguous, by its unique name."""
        try:
            views = self.sessions()
        except Failure:
            return None
        for view in views.values():
            if view.get("name") == name:
                self.own(view)
                return view
        return None

    def launch_command(self, label, argv, tty=False):
        name = f"{self.prefix}-{label}"
        try:
            _, view = self.data("run", self.environment, "--name", name, "--detach", "--output", "json",
                                "--tty" if tty else "--no-tty", "--", *argv, timeout=60)
        except Failure:
            self.adopt_name(name)
            raise
        sid = self.own(view)
        require(view.get("name") == name, f"session {sid} did not keep its owned name")
        return sid

    def launch_agent(self, label, agent, parent=None, prompt=None, model=None, expect="ok"):
        name = f"{self.prefix}-{label}"
        args = ["run", self.environment, "--name", name, "--agent", agent, "--detach", "--output", "json"]
        args += ["--model", model] if model else []
        args += ["--parent", parent] if parent else []
        args += ["--prompt", prompt] if prompt else []
        try:
            _, stdout, _ = self.call(*args, expect=expect, timeout=90)
            launched = decode_json(args[0], stdout, expect)
        except Failure:
            self.adopt_name(name)
            raise
        if launched is None:
            created = self.adopt_name(name)
            require(expect == "fail", f"managed launch {name} returned no JSON")
            require(created is None, f"refused launch {name} still created a session")
            return None
        sid = self.own(launched["session"])
        require(launched["session"].get("name") == name and launched["agent"] == agent and
                is_uuid(launched["driver_id"]), f"managed launch {name} returned another identity")
        self.drivers[sid] = launched["driver_id"]
        return launched

    def guest(self, label, script, *argv):
        sid = self.launch_command(label, ["sh", "-c", script, "sh", *argv])
        seconds = self.wait_seconds(60)
        code, waited = self.data("wait", self.environment, sid, "--timeout", f"{seconds}s", "--output", "json",
                                 expect="any", timeout=seconds + 15)
        require(isinstance(waited, dict) and waited.get("eof") is True,
                f"guest {label} command did not reach a confirmed end")
        return code, waited.get("output", "")

    def custody_probe(self, case, operation="observe", digest=""):
        self.guest_probe_count += 1
        require(self.guest_probe_count <= 80, "custody probes exceeded their bounded session inventory")
        sid = self.launch_command(f"custody-probe-{self.guest_probe_count}", [
            "python3", "-I", "-c", CUSTODY_PROBE, operation, self.environment, self.drivers[case["sid"]],
            case["sid"], case["nonce"], json.dumps(case["peer"], separators=(",", ":")), digest])
        seconds = self.wait_seconds(35)
        code, waited = self.data("wait", self.environment, sid, "--timeout", f"{seconds}s", "--output", "json",
                                 expect="any", timeout=seconds + 15)
        require(code == 0 and isinstance(waited, dict) and waited.get("eof") is True and
                (waited.get("session") or {}).get("exit_code") == 0,
                f"owned guest custody {operation} probe did not finish successfully")
        try:
            proof = json.loads(waited.get("output", ""))
        except json.JSONDecodeError:
            raise Failure(f"owned guest custody {operation} probe returned no bounded JSON proof") from None
        require(isinstance(proof, dict), "custody probe returned another proof shape")
        return proof

    def begin_caller(self, verb, sid):
        """Starts `cw stop` or `cw restart` of session SID in the environment."""
        self.budget(60)
        process = subprocess.Popen([self.cw, verb, self.environment, "--session", sid, "--output", "json"],
                                   env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
        self.pending_callers.append(process)
        return process

    def finish_caller(self, process, sid):
        try:
            stdout, stderr = process.communicate(timeout=self.budget(60))
        except subprocess.TimeoutExpired:
            self.scan(*kill_group(process))
            raise Failure("owned local custody caller did not finish; its outcome remains unknown") from None
        self.scan(stdout, stderr)
        require(process.returncode == 0, f"owned local custody caller exited {process.returncode}: {scrub(stderr)}")
        try:
            views = json.loads(stdout)
        except json.JSONDecodeError:
            raise Failure("owned local custody caller returned invalid JSON") from None
        require(isinstance(views, list) and len(views) == 1 and views[0].get("session_id") == sid,
                "owned local custody caller returned another session")
        self.pending_callers.remove(process)
        return views[0]

    def stop(self, sid):
        code, views = self.data("stop", self.environment, "--session", sid, "--output", "json", expect="any", timeout=60)
        view = views[0] if isinstance(views, list) and views else None
        if code != 0 or not view or view.get("state") not in TERMINAL_SESSION or view.get("cleanup_unknown"):
            self.ambiguous.append({"kind": "session-stop", "session_id": sid,
                                   "state": view and view.get("state"),
                                   "cleanup_unknown": view and view.get("cleanup_unknown")})
            raise Failure(f"stop of owned session {sid} was not confirmed known-clean")
        return view

    def restart(self, sid):
        _, views = self.data("restart", self.environment, "--session", sid, "--output", "json", timeout=60)
        require(isinstance(views, list) and views and views[0]["session_id"] == sid,
                f"restart of {sid} returned another session identity")
        return views[0]

    # -- Managed messages ------------------------------------------------

    def inbox(self, sid):
        return self.data("inbox", self.environment, sid, "--output", "json")[1]

    def started_driver(self, sid, previous=None):
        def ready(view):
            driver = view.get("driver")
            return bool(driver) and driver["phase"] in ("idle", "busy") and driver["started_at"] != previous
        return self.until(lambda: self.inbox(sid), ready, self.turn_timeout, f"managed driver {sid} ready")

    def driver_phase(self, sid, phase):
        return self.until(lambda: self.inbox(sid), lambda v: (v.get("driver") or {}).get("phase") == phase,
                          30, f"managed driver {sid} phase {phase}")

    def held(self, sid, message_id, turn=True):
        def active(view):
            driver = view.get("driver") or {}
            return driver.get("active_message_id") == message_id and (driver.get("current_turn_id") or not turn)
        return self.until(lambda: self.inbox(sid), active, 30, f"held turn {message_id}")["driver"]

    def deliver(self, verb, sid, *values):
        code, record = self.data(verb, self.environment, sid, *values, "--output", "json",
                                 expect="any", timeout=60)
        if record is not None:
            require(isinstance(record, dict) and is_uuid(record.get("id")),
                    f"cw {verb} returned no canonical message ID")
            if record["state"] == "unknown":
                self.ambiguous.append({"kind": "message", "id": record["id"], "state": "unknown"})
                raise Failure(f"cw {verb} message {record['id']} delivery is unknown; not resent")
        return code, record

    def send(self, sid, text):
        code, record = self.deliver("msg", sid, text)
        require(code == 0 and record and record["action"] == "message" and
                record["state"] in ("accepted", "running", "completed"),
                f"cw msg to {sid} was not accepted")
        return record

    def wait_message(self, message_id, timeout=None, allow_open=False):
        """A terminal record, or with allow_open the still-open record at the deadline."""
        seconds = self.wait_seconds(timeout or self.turn_timeout)
        _, record = self.data("wait", "--message", message_id, "--timeout", f"{seconds}s", "--output", "json",
                              expect="any", timeout=seconds + 15)
        require(isinstance(record, dict) and record.get("id") == message_id,
                f"cw wait --message did not route to message {message_id}")
        if record["state"] not in TERMINAL_MESSAGE and not allow_open:
            self.ambiguous.append({"kind": "message", "id": message_id, "state": record["state"]})
            raise Failure(f"message {message_id} remained {record['state']}; outcome unknown, not retried")
        return record

    def expect_state(self, record, state):
        if record["state"] != state:
            if record["state"] == "unknown":
                self.ambiguous.append({"kind": "message", "id": record["id"], "state": "unknown"})
            raise Failure(f"message {record['id']} ended {record['state']}, expected {state}: "
                          f"{scrub(record.get('error') or '')}")
        return record

    def turn(self, sid, word, actual):
        """One completed native turn. Synthetic peers answer RESULT:<word>."""
        record = self.send(sid, word if self.synthetic else f"Reply with exactly {actual}. Do not use tools.")
        done = self.expect_state(self.wait_message(record["id"]), "completed")
        require(done["native_acknowledged"], f"message {done['id']} lacks native acknowledgement")
        if self.synthetic:
            require(done.get("result") == f"RESULT:{word}", f"message {done['id']} returned another result")
        return done

    def await_notification(self, source_id, source_session):
        expected = notification_id(source_id)
        timeout = self.turn_timeout + 30
        inbox = self.until(lambda: self.inbox(self.lead),
                           lambda v: any(m["id"] == expected for m in v["messages"]),
                           timeout, f"parent notification {expected}")
        matches = [m for m in inbox["messages"] if (m.get("source") or {}).get("message_id") == source_id]
        require(len(matches) == 1 and matches[0]["id"] == expected and matches[0]["action"] == "notification",
                f"worker message {source_id} did not map to exactly one deterministic notification")
        require(matches[0]["source"]["session_id"] == source_session,
                f"notification {expected} names another source session")
        self.notified.append((source_id, source_session))
        done = self.expect_state(self.wait_message(expected, timeout), "completed")
        require(done["native_acknowledged"], f"parent turn {expected} lacks native acknowledgement")
        if self.synthetic:
            require(done.get("result") == "PARENT_RECEIVED", "the parent did not continue from the notification")
        return done

    def message(self, inbox, message_id):
        found = [m for m in inbox["messages"] if m["id"] == message_id]
        require(len(found) == 1, f"inbox does not hold message {message_id} exactly once")
        return found[0]

    def hold(self, sid, text, codex):
        """Sends a hold-marked task; returns (held, message) after a 2 s active dwell or its end."""
        record = self.send(sid, text)
        held_since = None
        end = time.monotonic() + self.budget(30)
        while time.monotonic() < end:
            inbox = self.inbox(sid)
            message = self.message(inbox, record["id"])
            if message["state"] in TERMINAL_MESSAGE:
                return False, self.settled(message)
            driver = inbox.get("driver") or {}
            if driver.get("active_message_id") == record["id"] and (driver.get("current_turn_id") or not codex):
                held_since = held_since or time.monotonic()
                if time.monotonic() - held_since >= 2:
                    return True, message
            time.sleep(0.5)
        raise Failure(f"hold task {record['id']} neither became the active turn nor ended within 30 s")

    def settled(self, record):
        """Returns a terminal record for classification; unknown outcomes fail and stay recorded."""
        if record["state"] == "unknown":
            self.ambiguous.append({"kind": "message", "id": record["id"], "state": "unknown"})
            raise Failure(f"message {record['id']} outcome is unknown; not resent")
        require(record["state"] in TERMINAL_MESSAGE, f"message {record['id']} is still {record['state']}")
        return record

    def unmet(self, check, expectation, observed):
        """Fail-closed record of a fixture-dependent assertion; never a pass or a skip."""
        self.fixture[expectation].update(status="not satisfied", observed=observed)
        self.missing.append({"name": check, "fixture_expectation": expectation, "reason": observed})

    def met(self, check, expectation, observed):
        self.fixture[expectation].update(status="satisfied", observed=observed)
        self.check(check)

    # -- Journey ---------------------------------------------------------

    def run(self):
        self.stage = "preflight"
        _, info = self.data("info", "--local", self.environment, "--output", "json", timeout=60)
        require(info.get("id") == self.environment, "environment info reported another immutable ID")
        require(info.get("state") == "running", "the owned environment is not running")
        self.profile_selected = bool(info.get("access_profile"))
        views = self.sessions()
        self.preexisting = {sid: view["state"] for sid, view in views.items()}
        require(not any(view.get("name", "").startswith(self.prefix) for view in views.values()),
                "the random session prefix already exists")
        self.check("preflight/environment-running/preexisting-sessions-recorded")
        require(isinstance(self.image_receipt, dict), "VM journey requires the externally pinned cw image receipt")
        pins = [self.image_receipt.get(field) for field in ("index_sha256", "manifest_sha256", "cw_sha256")]
        require(all(isinstance(pin, str) and re.fullmatch("[0-9a-f]{64}", pin) for pin in pins), "invalid cw image receipt")
        _, runtime = self.data("runtime", "info", "--local", self.environment, "--output", "json", timeout=60)
        require(runtime.get("environment_id") == self.environment, "runtime info reported another environment")
        bootstrap = (runtime.get("selection") or {}).get("bootstrap_catalog_sha256")
        require(isinstance(bootstrap, str) and re.fullmatch("[0-9a-f]{64}", bootstrap), "runtime info omitted its bound bootstrap")
        sid = self.launch_command("boot-cw", ["/usr/bin/python3", "-I", "-B", "-c", BOOT_ASSET_PROBE, *pins, self.environment, bootstrap])
        _, waited = self.data("wait", self.environment, sid, "--timeout", "30s", "--output", "json", timeout=45)
        require(waited.get("eof") and (waited.get("session") or {}).get("exit_code") == 0,
                "startup cw asset is not the root-owned read-only image payload")
        proof = json.loads(waited.get("output", ""))
        require(proof == {"cw_sha256": pins[2], "image_manifest_sha256": pins[1],
                          "bootstrap_catalog_sha256": bootstrap, "selection_revision": 1,
                          "read_only": True, "fixed_launcher_read_only": True},
                "VM boot cw image identity changed")
        self.check("preflight/image-derived-cw/root-owned/read-only/digest-pinned/bootstrap-bound/readonly-launcher/before-first-agent")
        if self.synthetic:
            code, output = self.guest("agents", (
                'for name in codex claude; do path=$(command -v "$name") || '
                '{ printf "missing:%s\\n" "$name"; exit 3; }; grep -qF "$1" "$path" || '
                '{ printf "not-synthetic:%s\\n" "$name"; exit 4; }; done; printf "synthetic-peers-staged\\n"'),
                PEER_MARKER)
            require(code == 0 and output.strip() == "synthetic-peers-staged",
                    f"--synthetic-peers requires caller-staged guest peers: {scrub(output, 200)}")
            self.agents = {"codex": {"guest": "synthetic-peer"}, "claude": {"guest": "synthetic-peer"}}
            self.check("preflight/guest-agents-synthetic-peers-staged")
        else:
            require(self.profile_selected,
                    "protected-broker mode requires the environment's already-selected access profile")
            self.check("preflight/protected-profile-selected")
            code, output = self.guest("agents", (
                'for name in codex claude; do path=$(command -v "$name") || '
                '{ printf "missing:%s\\n" "$name"; exit 3; }; if grep -qF "$1" "$path"; then '
                'printf "synthetic:%s\\n" "$name"; exit 4; fi; done; '
                'printf "codex=%s\\n" "$(codex --version 2>/dev/null | head -n 1)"; '
                'printf "claude=%s\\n" "$(claude --version 2>/dev/null | head -n 1)"'), PEER_MARKER)
            require(code == 0, f"actual guest agents are missing or synthetic: {scrub(output, 200)}")
            versions = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
            for name in ("codex", "claude"):
                self.agents[name]["guest_version"] = scrub(versions.get(name, "").strip(), 80)
            self.check("preflight/guest-agents-actual-not-synthetic")
            self.stage_updates()

        self.sentinel = self.launch_command("sentinel", ["sh"], tty=True)
        self.until(lambda: self.sessions().get(self.sentinel), lambda v: v and v["state"] == "Running",
                   30, "sentinel terminal running")
        self.check("sentinel/durable-terminal-running")

        self.prove_refusals()
        self.prove_lead_turns()
        self.prove_tool_marker()
        self.prove_worker_notification()
        self.prove_history_and_routing()
        self.prove_controls()
        self.prove_lead_stop_and_adoption()
        self.prove_worker_restart()
        self.prove_startup_failure()
        self.prove_custody()
        self.prove_notification_accounting()
        self.prove_own_stop_and_sentinel()

    def prove_refusals(self):
        self.stage = "refusals"
        # A parent must be a running managed conversation in this environment.
        self.launch_agent("refused-unmanaged-parent", "claude", parent=self.sentinel,
                          prompt="never issued", expect="fail")
        self.launch_agent("refused-missing-parent", "claude", parent=f"session-{uuid.uuid4()}",
                          prompt="never issued", expect="fail")
        self.launch_agent("refused-kimi", "kimi", prompt="never issued", expect="fail")
        names = [view.get("name", "") for view in self.sessions().values()]
        require(not any(name.startswith(f"{self.prefix}-refused") for name in names),
                "a refused managed launch created a session")
        self.check("refusal/unmanaged-parent/missing-parent/unqualified-agent/no-session")

    def prove_lead_turns(self):
        self.stage = "codex-lead"
        launched = self.launch_agent("lead", "codex", model=self.codex_model)
        session = launched["session"]
        require(launched["message"] is None and "_agent-driver" in session["command"],
                "the lead is not a managed conversation without an initial task")
        self.lead = session["session_id"]
        self.agents["codex"]["model"] = launched["model"]
        inbox = self.started_driver(self.lead)
        require(inbox["session_id"] == self.lead and inbox["driver_id"] == self.drivers[self.lead] and
                inbox["environment_id"] == self.environment and inbox["agent"] == "codex" and
                inbox["parent"] is None, "lead inbox reports another conversation identity")
        capabilities = inbox["driver"]["capabilities"]
        require(capabilities["steer"] is True and capabilities["interrupt"] is True,
                "Codex app-server did not advertise expected-turn steering and interrupt")
        self.lead_thread = inbox["driver"]["native_thread_id"]
        require(bool(self.lead_thread), "the lead has no native conversation identity")
        first = self.turn(self.lead, "FIRST", "CW_TURN_ONE")
        second = self.turn(self.lead, "SECOND", "CW_TURN_TWO")
        require(first["turn_id"] and second["turn_id"] and first["turn_id"] != second["turn_id"],
                "two lead turns did not report distinct native turns")
        require(self.inbox(self.lead)["driver"]["native_thread_id"] == self.lead_thread,
                "the lead conversation identity changed between turns")
        self.lead_turns = [first["id"], second["id"]]
        self.check("codex-lead/two-turns/native-ack/same-conversation")
        self.call("send", self.environment, self.lead, "raw", expect="fail")
        self.call("send", self.environment, self.lead, "--key", "enter", expect="fail")
        self.check("managed/raw-send-and-key-rejected")

    def prove_tool_marker(self):
        if self.synthetic:
            self.limitations.append("synthetic peers execute no tools; the guest tool marker is required "
                                    "only in protected-broker mode")
            return
        self.stage = "guest-tool-marker"
        check = "guest-tool-marker/actual-codex-shell-tool"
        token = "CW_TOOL_MARKER_" + secrets.token_hex(8).upper()
        path = f".{self.prefix}-tool-marker"
        self.tool_file = path
        self.tool_token = token
        record = self.send(self.lead, (
            f"CW_FIXTURE_TOOL printf %s {token} > {path}\n"
            f"Use your shell command tool to run exactly the command after CW_FIXTURE_TOOL once in your "
            f"working directory. Run no other command and edit no other file. Then reply TOOL_MARKER_WRITTEN."))
        done = self.settled(self.wait_message(record["id"]))
        code, output = self.guest("tool-check", 'if [ -f "$1" ]; then cat -- "$1"; rm -f -- "$1"; fi', path)
        marker = "matching" if code == 0 and output == token else "absent" if code == 0 and not output else "different"
        if code == 0:
            self.tool_file = None
            self.tool_token = None
        if done["state"] == "completed" and done["native_acknowledged"] and marker == "matching":
            self.met(check, "codex-tool-call", "the guest marker file held the exact token")
        else:
            self.unmet(check, "codex-tool-call",
                       f"the tool turn ended {done['state']} and the guest marker file was {marker}")

    def prove_worker_notification(self):
        self.stage = "claude-worker"
        launched = self.launch_agent("worker", "claude", parent=self.lead, model=self.claude_model,
                                     prompt="WORKER" if self.synthetic else
                                     "Reply with exactly CW_WORKER_READY. Do not use tools.")
        session, initial = launched["session"], launched["message"]
        require(session["parent_session_id"] == self.lead,
                "the worker is not bound to the same-VM lead")
        require(initial and initial["action"] == "prompt", "the worker launch returned no initial message")
        self.worker = session["session_id"]
        self.agents["claude"]["model"] = launched["model"]
        done = self.expect_state(self.wait_message(initial["id"]), "completed")
        require(done["native_acknowledged"], "the worker task lacks native acknowledgement")
        if self.synthetic:
            require(done.get("result") == "RESULT:WORKER", "the worker returned another result")
        inbox = self.inbox(self.worker)
        require(inbox["parent"] == {"session_id": self.lead, "driver_id": self.drivers[self.lead]} and
                inbox["environment_id"] == self.environment, "worker parent identity is not canonical")
        capabilities = inbox["driver"]["capabilities"]
        require(capabilities["steer"] is False, "Claude advertised unqualified steering")
        require(isinstance(capabilities["interrupt"], bool), "Claude interrupt support is not a detection result")
        if self.synthetic:
            require(capabilities["interrupt"], "the synthetic Claude peer answers control probes")
        self.agents["claude"]["interrupt_detected"] = capabilities["interrupt"]
        self.worker_thread = inbox["driver"]["native_thread_id"]
        require(bool(self.worker_thread), "the worker has no native conversation identity")
        parent_turn = self.await_notification(initial["id"], self.worker)
        source = self.message(self.inbox(self.worker), initial["id"])
        require((source.get("notification") or {}).get("message_id") == notification_id(initial["id"]),
                "the worker outbox names another notification")
        continued = self.turn(self.lead, "AFTER_WORKER", "CW_LEAD_CONTINUED")
        require(self.inbox(self.lead)["driver"]["native_thread_id"] == self.lead_thread,
                "the lead continued in another conversation")
        self.lead_turns.append(continued["id"])
        self.routed = [(self.lead_turns[0], self.lead), (initial["id"], self.worker), (parent_turn["id"], self.lead)]
        self.check("claude-worker/same-vm-parent/native-ack/deterministic-notification/parent-continuation")
        if self.synthetic:
            self.check("shell-client/synthetic-peers-run-from-path")
        else:
            self.prove_shell_clients()

    def stage_updates(self):
        self.stage = "shell-client-updates"
        code, output = self.guest("shell-clients", SHELL_CLIENTS)
        originals = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        require(code == 0 and set(originals) == {"codex", "claude"} and
                all(re.fullmatch(r"/[A-Za-z0-9._+/-]+", path) and
                    not path.startswith("/home/codewire/.npm-global/") for path in originals.values()),
                f"the guest shell's clients cannot be updated in the user's npm prefix: {scrub(output, 200)}")
        sid = self.launch_command("update-stage", ["python3", "-I", "-c", UPDATE_STAGE, self.prefix,
                                                   originals["codex"], originals["claude"]])
        self.updates_staged = originals
        seconds = self.wait_seconds(20)
        code, waited = self.data("wait", self.environment, sid, "--timeout", f"{seconds}s", "--output", "json",
                                 expect="any", timeout=seconds + 15)
        require(code == 0 and waited.get("eof") and waited["session"]["exit_code"] == 0,
                "the user's npm prefix already holds codex or claude, or the updates could not be staged")
        code, output = self.guest("update-path", SHELL_CLIENTS)
        resolved = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        require(code == 0 and resolved == {name: f"/home/codewire/.npm-global/bin/{name}"
                                           for name in ("codex", "claude")},
                f"the updates are not first on the guest PATH: {scrub(output, 200)}")
        for name, path in originals.items():
            self.agents[name]["shell_client_before_update"] = path
        self.check("shell-client/user-updates-first-on-path")

    def prove_shell_clients(self):
        self.stage = "shell-clients"
        sid = self.launch_command("update-probe", ["python3", "-I", "-c", UPDATE_PROBE, self.prefix])
        seconds = self.wait_seconds(20)
        code, waited = self.data("wait", self.environment, sid, "--timeout", f"{seconds}s", "--output", "json",
                                 expect="any", timeout=seconds + 15)
        require(code == 0 and waited.get("eof") and waited["session"]["exit_code"] == 0,
                "the shell client probe did not finish successfully")
        require_shell_clients(json.loads(waited.get("output", "")), self.prefix)
        self.check("shell-client/managed-agents-run-the-user-updates")

    def prove_history_and_routing(self):
        self.stage = "history"
        inbox = self.inbox(self.lead)
        ids = [m["id"] for m in inbox["messages"]]
        require(inbox["messages_total"] == len(ids), "lead history was truncated")
        require(all(i in ids for i in self.lead_turns) and
                sorted(self.lead_turns, key=ids.index) == self.lead_turns,
                "lead history does not preserve message order")
        for message_id, target in self.routed:
            record = self.expect_state(self.wait_message(message_id, 30), "completed")
            require(record["target_session_id"] == target, f"wait routed {message_id} to another session")
        self.call("wait", "--message", str(uuid.uuid4()), "--timeout", "5s", "--output", "json",
                  expect="fail", timeout=30)
        views = self.sessions()
        require(views[self.worker]["parent_session_id"] == self.lead and
                all("_agent-driver" in views[sid]["command"] for sid in (self.lead, self.worker)),
                "cw ls does not show the managed parent linkage")
        self.call("logs", self.environment, "--session", self.lead, "--tail", "20", timeout=30)
        self.check("history/inbox-order/wait-routing-by-message/unknown-message-refused/logs-readable")

    def prove_controls(self):
        self.stage = "controls"
        if not self.synthetic:
            before = {sid: self.inbox(sid)["messages_total"] for sid in (self.lead, self.worker)}
            self.call("steer", self.environment, self.lead, "nothing active", expect="fail")
            self.call("interrupt", self.environment, self.lead, expect="fail")
            self.call("steer", self.environment, self.worker, "unsupported", expect="fail")
            self.call("interrupt", self.environment, self.worker, expect="fail")
            require(all(self.inbox(sid)["messages_total"] == count for sid, count in before.items()),
                    "a refused control created a message record")
            self.check("controls/actual-detected-capabilities/idle-and-unsupported-refused-without-record")
            self.prove_actual_interrupt(self.lead, "codex-hold-interrupt", "controls/actual-codex-held-turn-interrupt")
            self.prove_actual_steer()
            check = "controls/actual-claude-held-turn-interrupt-or-undetected-refused"
            if self.agents["claude"]["interrupt_detected"]:
                self.prove_actual_interrupt(self.worker, "claude-hold-interrupt", check)
            else:
                # Undetected support is advertised as unsupported, and the CLI refused it above.
                self.fixture["claude-hold-interrupt"].update(
                    status="not applicable", observed="the guest Claude did not confirm native control requests")
                self.limitations.append("the guest Claude did not confirm native control requests; "
                                        "interrupt is advertised unsupported and refused")
                self.check(check)
            return
        hold = self.send(self.lead, "HOLD")
        turn = self.held(self.lead, hold["id"])["current_turn_id"]
        _, mismatch = self.deliver("steer", self.lead, "bad", "--turn-id", "other-turn")
        require(mismatch is not None, "a mismatched steer created no durable record")
        self.expect_state(self.wait_message(mismatch["id"], 30), "error")
        driver = self.inbox(self.lead)["driver"]
        require(driver["active_message_id"] == hold["id"] and driver["current_turn_id"] == turn,
                "a mismatched steer changed the active turn")
        code, steer = self.deliver("steer", self.lead, "finish")
        require(code == 0 and steer and steer["expected_turn_id"] == turn, "steer did not target the active turn")
        result = self.expect_state(self.wait_message(hold["id"]), "completed")
        require(result.get("result") == "STEERED", "the held turn did not finish through steering")
        self.expect_state(self.wait_message(steer["id"]), "completed")
        before = self.inbox(self.worker)["messages_total"]
        self.call("steer", self.environment, self.worker, "unsupported", expect="fail")
        require(self.inbox(self.worker)["messages_total"] == before, "unsupported Claude steer created a record")
        hold = self.send(self.worker, "HOLD")
        self.held(self.worker, hold["id"], turn=False)
        code, interrupt = self.deliver("interrupt", self.worker)
        require(code == 0 and interrupt and interrupt["action"] == "interrupt", "Claude interrupt was not accepted")
        self.expect_state(self.wait_message(interrupt["id"]), "completed")
        self.expect_state(self.wait_message(hold["id"]), "interrupted")
        self.await_notification(hold["id"], self.worker)
        self.check("controls/codex-expected-turn-steer/mismatch-refused/claude-steer-refused/claude-interrupt")

    def interrupt_held(self, sid, message_id):
        """Interrupts a held turn; returns (interrupt record or None if refused, final turn record)."""
        _, interrupt = self.deliver("interrupt", sid)
        if interrupt is not None:
            # An interrupt racing a turn that just ended settles as error; only unknown is fatal.
            self.settled(self.wait_message(interrupt["id"], 60))
        return interrupt, self.settled(self.wait_message(message_id, 60))

    def prove_actual_interrupt(self, sid, expectation, check):
        held, message = self.hold(sid, f"CW_FIXTURE_HOLD {secrets.token_hex(4)}\n"
                                       f"Wait for further input before replying.", codex=sid == self.lead)
        interrupt = None
        if held:
            interrupt, message = self.interrupt_held(sid, message["id"])
        observed = (f"the turn ended {message['state']} without being held" if not held else
                    f"the turn ended {message['state']} before the interrupt was delivered" if interrupt is None
                    else f"the held turn ended {message['state']} after interrupt")
        if sid == self.worker:
            self.await_notification(message["id"], self.worker)
        if interrupt is not None and message["state"] == "interrupted":
            self.met(check, expectation, observed)
        else:
            self.unmet(check, expectation, observed)

    def prove_actual_steer(self):
        check, expectation = "controls/actual-codex-held-turn-steer", "codex-hold-steer"
        nonce = secrets.token_hex(4)
        held, message = self.hold(self.lead, f"CW_FIXTURE_STEERABLE {nonce}\nWait for further input before "
                                             f"replying.", codex=True)
        if not held:
            return self.unmet(check, expectation, f"the turn ended {message['state']} without being held")
        turn = self.inbox(self.lead)["driver"]["current_turn_id"]
        _, steer = self.deliver("steer", self.lead, f"CW_FIXTURE_STEER {nonce}\nFinish now and reply "
                                                    f"CW_STEERED {nonce}.")
        if steer is None:
            final = self.settled(self.wait_message(message["id"], 60))
            return self.unmet(check, expectation, f"the turn ended {final['state']} before the steer was delivered")
        require(steer["expected_turn_id"] == turn, "steer did not target the held turn")
        final = self.wait_message(message["id"], 45, allow_open=True)
        settling = final["state"] not in TERMINAL_MESSAGE
        if settling:
            # Settle the still-held turn through the advertised interrupt; nothing is resent.
            _, final = self.interrupt_held(self.lead, message["id"])
        final = self.settled(final)
        steered = self.settled(self.wait_message(steer["id"], 60))
        replied = f"CW_STEERED {nonce}" in (final.get("result") or "")
        observed = (f"the held turn ended {final['state']}{' after a settling interrupt' if settling else ''}, "
                    f"the steer ended {steered['state']}, and the steer reply marker was "
                    f"{'present' if replied else 'absent'}")
        if not settling and final["state"] == steered["state"] == "completed" and replied:
            self.met(check, expectation, observed)
        else:
            self.unmet(check, expectation, observed)

    def prove_lead_stop_and_adoption(self):
        self.stage = "lead-stop-restart"
        before = self.inbox(self.lead)
        started = before["driver"]["started_at"]
        settled = {m["id"]: m["state"] for m in before["messages"] if m["state"] in TERMINAL_MESSAGE}
        hold = None
        if self.synthetic:
            hold = self.send(self.lead, "HOLD")
            self.held(self.lead, hold["id"])
        self.stop(self.lead)
        if hold:
            self.expect_state(self.wait_message(hold["id"], 30), "unknown")
            self.expected_unknown.append({"id": hold["id"], "reason": "in-flight turn when its driver stopped"})
        stopped = self.driver_phase(self.lead, "stopped")
        require(all(self.message(stopped, i)["state"] == s for i, s in settled.items()),
                "stopping the lead changed a settled message")
        require(hold or not any(m["state"] == "unknown" for m in stopped["messages"]),
                "stopping an idle lead left an unknown message")
        self.call("msg", self.environment, self.lead, "refused while stopped", expect="fail")
        require(self.inbox(self.lead)["messages_total"] == stopped["messages_total"],
                "a refused message to a stopped conversation created a record")
        worker_turn = self.turn(self.worker, "WHILE_PARENT_STOPPED", "CW_PARENT_STOPPED")
        expected = notification_id(worker_turn["id"])
        pending = self.until(lambda: self.inbox(self.lead),
                             lambda v: any(m["id"] == expected for m in v["messages"]),
                             self.turn_timeout, "notification queued for the stopped parent")
        require(self.message(pending, expected)["state"] in PRE_ACCEPT,
                "a stopped parent accepted a notification")
        require(self.restart(self.lead)["session_id"] == self.lead, "restart changed the lead session identity")
        inbox = self.started_driver(self.lead, started)
        require(inbox["driver"]["native_thread_id"] == self.lead_thread, "the lead did not resume its conversation")
        self.await_notification(worker_turn["id"], self.worker)
        if hold:
            require(self.message(self.inbox(self.lead), hold["id"])["state"] == "unknown",
                    "an in-flight turn was replayed after restart")
        self.turn(self.lead, "AFTER_RESTART", "CW_LEAD_RESUMED")
        require(self.inbox(self.lead)["driver"]["native_thread_id"] == self.lead_thread,
                "the restarted lead changed conversation identity")
        self.check("driver-exit/lead-stop-in-flight-unknown-not-replayed/stopped-refuses-msg/"
                   "parent-adopts-after-restart/resume" if self.synthetic else
                   "driver-exit/lead-stop-idle-nothing-unknown/stopped-refuses-msg/"
                   "parent-adopts-after-restart/resume")

    def prove_worker_restart(self):
        self.stage = "worker-stop-restart"
        started = self.inbox(self.worker)["driver"]["started_at"]
        self.stop(self.worker)
        self.driver_phase(self.worker, "stopped")
        require(self.restart(self.worker)["session_id"] == self.worker, "restart changed the worker identity")
        inbox = self.started_driver(self.worker, started)
        require(inbox["driver"]["native_thread_id"] == self.worker_thread, "the worker did not resume its conversation")
        resumed = self.turn(self.worker, "CLAUDE_RESUMED", "CW_CLAUDE_RESUMED")
        require(self.inbox(self.worker)["driver"]["native_thread_id"] == self.worker_thread,
                "the resumed worker changed conversation identity")
        self.await_notification(resumed["id"], self.worker)
        self.check("claude-worker/stop-known-clean/restart-same-session/resume/notification-once")

    def prove_startup_failure(self):
        if not self.synthetic:
            self.limitations.append("actual agents have no deterministic startup-failure injection; driver "
                                    "exit is proven through owned stop, restart and refusal paths")
            return
        self.stage = "startup-failure"
        launched = self.launch_agent("startup-failure", "codex", parent=self.lead, prompt="never issued",
                                     model="fixture-startup-failure", expect="any")
        require(launched["message"], "the failing launch returned no durable task")
        sid, message_id = launched["session"]["session_id"], launched["message"]["id"]
        self.expect_state(self.wait_message(message_id, 60), "error")
        self.await_notification(message_id, sid)
        ended = self.until(lambda: self.sessions().get(sid), lambda v: v and v["state"] in TERMINAL_SESSION,
                           30, "failed driver session end")
        require(not ended["cleanup_unknown"], "the failed driver left unknown cleanup")
        self.call("msg", self.environment, sid, "refused after driver exit", expect="fail")
        driver = self.inbox(sid)["driver"]
        require(driver["phase"] == "failed" and driver["last_error"], "the failed driver did not record its exit")
        self.check("driver-exit/native-startup-failure/task-error/parent-notified/session-ended/msg-refused")

    def prove_notification_accounting(self):
        self.stage = "notification-accounting"
        inbox = self.inbox(self.lead)
        require(inbox["messages_total"] == len(inbox["messages"]), "lead history was truncated")
        expected = {notification_id(source): (source, session) for source, session in self.notified}
        require(len(expected) == len(self.notified), "a worker message was notified twice")
        notifications = [m for m in inbox["messages"] if m["action"] == "notification"]
        require(len(notifications) == len(expected), "the lead holds missing or duplicate notifications")
        for record in notifications:
            require(record["id"] in expected, f"notification {record['id']} has no known worker source")
            source, session = expected[record["id"]]
            require(record["source"] == {"session_id": session, "driver_id": self.drivers[session],
                                         "message_id": source}, f"notification {record['id']} names another source")
            require(record["state"] == "completed" and record["native_acknowledged"],
                    f"parent turn {record['id']} did not complete")
        self.check("notifications/deterministic-ids/exactly-once/parent-turns-completed")

    # -- Linux provider-family custody ----------------------------------

    def custody_case(self, label):
        launched = self.launch_agent(f"custody-{label}", "codex", model=self.codex_model)
        sid = launched["session"]["session_id"]
        inbox = self.started_driver(sid)
        identity = peer_identity(inbox, self.environment, self.drivers[sid], sid)
        view = self.sessions()[sid]
        case = {"sid": sid, "nonce": secrets.token_hex(4), "peer": identity,
                "generation": generation(view), "thread": inbox["driver"]["native_thread_id"],
                "started_at": inbox["driver"]["started_at"], "label": label, "removed": False}
        require(bool(case["thread"]), "custody conversation has no native thread identity")
        self.custody_cases.append(case)
        held, message = self.hold(sid, f"CW_FIXTURE_CUSTODY {case['nonce']}\n"
                                  "Run only the fixture's supplied shell tool command once; then wait.", codex=True)
        case["message"] = message["id"]
        require(held and message.get("native_acknowledged"), "custody marker did not remain a native held turn")
        proof = self.custody_probe(case, "ready")
        require_live_family(proof, case["nonce"])
        require(proof["peer"]["identity"] == identity and proof["current"] == identity and
                proof["peer"]["cleanup_unknown"] and proof["driver"]["live"],
                "custody did not start under this exact live driver instance")
        case["family"] = proof["family"]
        self.custody_evidence.append({"stage": label + "-live", "session_id": sid,
                                     "launch_generation": case["generation"], "proof": proof})
        return case

    def custody_clean(self, case):
        proof = self.until(lambda: self.custody_probe(case),
                           lambda value: not value["peer"]["cleanup_unknown"] and
                           not value["driver"]["live"] and value["echild"],
                           35, "same-instance ECHILD cleanup and driver exit")
        require_clean_custody(proof, case["peer"], case["family"])
        view = self.sessions()[case["sid"]]
        require(view["state"] in TERMINAL_SESSION and not view["cleanup_unknown"] and
                generation(view) == case["generation"],
                "old durable driver did not end known-clean in the captured generation")
        self.custody_evidence.append({"stage": case["label"] + "-clean", "session_id": case["sid"],
                                     "launch_generation": generation(view), "state": view["state"], "proof": proof})
        return proof

    def custody_unknown_message(self, case, reason):
        record = self.expect_state(self.wait_message(case["message"], 30), "unknown")
        require(record["native_acknowledged"], "stopped held turn lost its accepted native identity")
        require(self.inbox(case["sid"])["messages_total"] == 1,
                "custody conversation replayed or invented another message")
        self.expected_unknown.append({"id": record["id"], "reason": reason})

    def prove_receipt_fences(self, case, proof):
        for mode in ("missing", "stale"):
            self.stage = "custody-receipt-" + mode
            digest, inode = proof["receipt_sha256"], proof["receipt_inode"]
            # Record restoration authority before the mutation: even a lost
            # probe response can be recovered only at this exact backup path.
            self.receipt_faults[case["sid"]] = (case, digest)
            changed = self.custody_probe(case, "fault-" + mode, digest)
            require(changed.get("receipt_sha256") == digest and changed.get("original_inode") == inode,
                    "receipt fault did not preserve the exact original file")
            before = self.sessions()[case["sid"]]
            self.call("restart", self.environment, "--session", case["sid"], "--output", "json", expect="fail", timeout=15)
            refused = self.inbox(case["sid"])
            after = self.sessions()[case["sid"]]
            require(after["state"] == before["state"] and generation(after) == case["generation"] and
                    refused.get("peer") is None and bool(refused.get("peer_error")),
                    "missing/stale receipt admitted a replacement or lost its explicit fence")
            restored = self.custody_probe(case, "restore", digest)
            require(restored.get("restored") and restored.get("receipt_sha256") == digest and
                    restored.get("receipt_inode") == inode,
                    "receipt restoration changed the original bytes or inode")
            self.receipt_faults.pop(case["sid"])
            recovered = self.inbox(case["sid"])
            require(recovered.get("peer") == proof["peer"] and recovered.get("peer_error") is None,
                    "restored receipt no longer proves the exact stopped instance")
            self.custody_evidence.append({"stage": "receipt-" + mode + "-refused-and-restored",
                                         "session_id": case["sid"], "launch_generation": generation(after),
                                         "receipt_sha256": digest, "receipt_inode": inode})
        self.check("custody/missing-and-stale-receipt/restart-refused/no-admission/exact-restoration")

    def prove_cancelled_stop(self, case):
        self.stage = "custody-cancelled-stop"
        caller = self.begin_caller("stop", case["sid"])
        end = time.monotonic() + self.budget(15)
        admitted = None
        while time.monotonic() < end:
            require(caller.poll() is None, "stop caller finished before durable-intent cancellation was observed")
            inbox = self.inbox(case["sid"])
            request = inbox.get("shutdown")
            if isinstance(request, dict) and is_uuid(request.get("operation_id")):
                require(request.get("peer") == case["peer"] and request.get("cleanup_unknown") is True and
                        request.get("finished_at") is None,
                        "stop intent was not pending for the exact held instance")
                admitted = request
                break
            time.sleep(0.1)
        require(admitted is not None and caller.poll() is None, "durable stop intent was not seen while caller lived")
        self.scan(*kill_group(caller))
        require(caller.returncode == -signal.SIGKILL, "the local stop caller was not actually cancelled")
        self.pending_callers.remove(caller)
        # Completion joins the existing durable operation; no provider task is
        # resent and no new shutdown operation is admitted.
        stopped = self.stop(case["sid"])
        proof = self.custody_clean(case)
        joined = self.inbox(case["sid"]).get("shutdown") or {}
        require(joined.get("operation_id") == admitted["operation_id"] and joined.get("peer") == case["peer"] and
                joined.get("cleanup_unknown") is False and bool(joined.get("finished_at")) and
                generation(stopped) == case["generation"],
                "later stop did not join and complete the original durable intent")
        self.custody_unknown_message(case, "held turn stopped after its local caller was cancelled")
        self.custody_evidence.append({"stage": "cancelled-local-caller-joined", "session_id": case["sid"],
                                     "operation_id": admitted["operation_id"], "local_exit": caller.returncode,
                                     "launch_generation": generation(stopped), "echild": proof["echild"]})
        self.check("custody/cancelled-stop/durable-intent/local-caller-cancelled/same-operation-joined")

    def prove_crash_restart(self, case):
        self.stage = "custody-driver-sigkill"
        killed = self.custody_probe(case, "kill")
        require(killed["peer"]["cleanup_unknown"] and killed["peer"]["identity"] == case["peer"] and
                generation(self.sessions()[case["sid"]]) == case["generation"],
                "exact driver SIGKILL did not expose the old unknown-custody generation")
        self.custody_evidence.append({"stage": "driver-sigkill-unknown", "session_id": case["sid"],
                                     "launch_generation": case["generation"], "proof": killed})
        caller = self.begin_caller("restart", case["sid"])
        observed_unknown, old_clean = 1, None
        end = time.monotonic() + self.budget(45)
        while time.monotonic() < end:
            view = self.sessions()[case["sid"]]
            proof = self.custody_probe(case)
            current_generation = generation(view)
            require(current_generation in (case["generation"], case["generation"] + 1),
                    "crash recovery admitted more than one replacement generation")
            if proof["peer"]["cleanup_unknown"]:
                require(current_generation == case["generation"] and proof["current"] == case["peer"] and
                        caller.poll() is None,
                        "restart admitted a new peer/generation while old custody remained unknown")
                observed_unknown += 1
            else:
                require_clean_custody(proof, case["peer"], case["family"])
                old_clean = proof
            if caller.poll() is not None:
                require(old_clean is not None, "restart caller ended without observed old ECHILD cleanup")
                break
            time.sleep(0.1)
        else:
            raise Failure("guarded crash restart did not finish within the cleanup bound")
        restarted = self.finish_caller(caller, case["sid"])
        require(generation(restarted) == case["generation"] + 1 and restarted["state"] == "Running" and
                not restarted["cleanup_unknown"], "safe crash restart did not admit exactly one running generation")
        inbox = self.started_driver(case["sid"], case["started_at"])
        replacement = peer_identity(inbox, self.environment, self.drivers[case["sid"]], case["sid"])
        require(replacement != case["peer"] and replacement["instance_id"] != case["peer"]["instance_id"] and
                inbox["driver"]["native_thread_id"] == case["thread"],
                "crash restart reused old custody or changed the native conversation")
        self.custody_unknown_message(case, "issued turn became unknown after its exact driver was SIGKILLed")
        self.turn(case["sid"], "AFTER_CRASH", "CW_CUSTODY_RESUMED")
        history = self.inbox(case["sid"])
        require(self.message(history, case["message"])["state"] == "unknown" and
                history["messages_total"] == 2 and history["driver"]["native_thread_id"] == case["thread"],
                "crash restart replayed the old issued task")
        # Both old and replacement receipts retain inspection evidence. Stop
        # the replacement before deleting this nonce's descendant record.
        self.stop(case["sid"])
        replacement_case = dict(case, peer=replacement, generation=case["generation"] + 1,
                                started_at=inbox["driver"]["started_at"], label="crash-replacement")
        self.custody_clean(replacement_case)
        self.custody_evidence.append({"stage": "crash-guarded-restart", "session_id": case["sid"],
                                     "old_generation": case["generation"], "new_generation": generation(restarted),
                                     "unknown_samples": observed_unknown, "old_echild": old_clean["echild"],
                                     "old_peer": case["peer"], "new_peer": replacement})
        self.check("custody/driver-sigkill/unknown-fenced/echild-before-admission/one-safe-restart/no-replay")

    def sentinel_live(self):
        nonce = secrets.token_hex(4)
        self.call("send", self.environment, self.sentinel, f"echo SENTINEL_$((6*7))_{nonce}")
        self.until(lambda: self.call("logs", self.environment, "--session", self.sentinel, "--tail", "50")[1],
                   lambda output: f"SENTINEL_42_{nonce}" in output, 30, "sentinel terminal reply")
        require(self.sessions()[self.sentinel]["state"] == "Running", "unrelated sentinel stopped during custody cleanup")

    def prove_custody(self):
        if self.synthetic:
            self.limitations.append("synthetic peers offer no custody shell fixture; detached-family, caller "
                                    "cancellation, driver SIGKILL and receipt faults are actual-agent mode only")
            return
        self.stage = "custody-normal-stop"
        normal = self.custody_case("normal")
        self.stop(normal["sid"])
        proof = self.custody_clean(normal)
        self.custody_unknown_message(normal, "accepted held turn stopped with its provider family")
        self.check("custody/normal-stop/live-detached-doublefork-term-resistant/echild/driver-exit")
        self.prove_receipt_fences(normal, proof)
        cancelled = self.custody_case("cancelled")
        self.prove_cancelled_stop(cancelled)
        crash = self.custody_case("crash")
        self.prove_crash_restart(crash)
        for case in self.custody_cases:
            require_clean_custody(self.custody_probe(case), case["peer"], case["family"])
            removed = self.custody_probe(case, "remove")
            require(removed.get("removed") is True, "exact custody fixture files were not removed")
            case["removed"] = True
        self.sentinel_live()
        self.met("custody/sentinel-live/owned-families-reaped/exact-fixture-files-removed", "codex-custody",
                 "three live fixed tool families reaped with ECHILD; exact records removed; sentinel responsive")

    def prove_own_stop_and_sentinel(self):
        self.stage = "own-stop"
        views = self.sessions()
        for sid in list(self.owned):
            if sid != self.sentinel and views.get(sid, {}).get("state") not in TERMINAL_SESSION:
                self.stop(sid)
        self.sentinel_live()
        views = self.sessions()
        require(views[self.sentinel]["state"] == "Running", "the sentinel terminal stopped")
        require(all(views.get(sid, {}).get("state") == "Running"
                    for sid, state in self.preexisting.items() if state == "Running"),
                "an unrelated pre-existing session stopped")
        _, info = self.data("info", "--local", self.environment, "--output", "json", timeout=60)
        require(info.get("state") == "running", "the environment stopped")
        self.check("own-sessions-stopped-known-clean/sentinel-terminal-live/preexisting-preserved/environment-running")

    def cleanup(self):
        """Restores exact faults, joins owned stops and removes only owned fixture files."""
        self.stage = "cleanup"
        self.deadline = self.started + OVERALL_SECONDS - 5
        errors = []
        for process in list(self.pending_callers):
            try:
                if process.poll() is None:
                    self.scan(*kill_group(process))
                else:
                    self.scan(*process.communicate())
            except Exception as error:
                errors.append(f"owned local caller cleanup failed: {error}")
            self.pending_callers.remove(process)
        # Restore stopped receipts before any stop attempts. Never overwrite a
        # different instance or an unexpectedly changed receipt during recovery.
        for sid, (case, digest) in list(self.receipt_faults.items()):
            try:
                restored = self.custody_probe(case, "restore", digest)
                require(restored.get("restored") and restored.get("receipt_sha256") == digest,
                        "cleanup could not restore the exact owned receipt")
                self.receipt_faults.pop(sid)
            except Exception as error:
                errors.append(str(error))
        order = [sid for sid in self.owned if sid != self.sentinel][::-1]
        order += [self.sentinel] if self.sentinel in self.owned else []
        try:
            views = self.sessions()
        except Failure as error:
            views, errors = {}, [str(error)]
        for sid in order:
            try:
                if views.get(sid, {}).get("state") not in TERMINAL_SESSION:
                    self.stop(sid)
            except Failure as error:
                errors.append(str(error))
        for case in self.custody_cases:
            if case["removed"]:
                continue
            try:
                if "family" in case:
                    require_clean_custody(self.custody_probe(case), case["peer"], case["family"])
                removed = self.custody_probe(case, "remove")
                require(removed.get("removed") is True, "cleanup did not remove exact custody fixture files")
                case["removed"] = True
            except Exception as error:
                errors.append(str(error))
        if self.tool_file:
            try:
                sid = self.launch_command("tool-cleanup", ["python3", "-I", "-c", r'''import os, re, stat, sys
name, token = sys.argv[1:]
assert re.fullmatch(r"\.cwnm-[0-9a-f]{8}-tool-marker", name)
assert re.fullmatch(r"CW_TOOL_MARKER_[0-9A-F]{16}", token)
try:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except FileNotFoundError:
    raise SystemExit(0)
with os.fdopen(fd, "rb") as stream:
    metadata = os.fstat(stream.fileno())
    assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1
    assert stat.S_IMODE(metadata.st_mode) in (0o600, 0o644) and metadata.st_size <= 128
    assert stream.read(129) == token.encode()
    current = os.stat(name, follow_symlinks=False)
    assert (current.st_dev, current.st_ino, current.st_ctime_ns) == (metadata.st_dev, metadata.st_ino, metadata.st_ctime_ns)
    os.unlink(name)
''', self.tool_file, self.tool_token])
                seconds = self.wait_seconds(20)
                code, waited = self.data("wait", self.environment, sid, "--timeout", f"{seconds}s",
                                         "--output", "json", expect="any", timeout=seconds + 15)
                require(code == 0 and waited.get("eof") and waited["session"]["exit_code"] == 0,
                        "cleanup did not remove the exact owned tool marker")
                self.tool_file = self.tool_token = None
            except Exception as error:
                errors.append(str(error))
        if self.updates_staged:
            try:
                originals = self.updates_staged
                sid = self.launch_command("update-cleanup", ["python3", "-I", "-c", UPDATE_REMOVE, self.prefix,
                                                             originals["codex"], originals["claude"]])
                seconds = self.wait_seconds(20)
                code, waited = self.data("wait", self.environment, sid, "--timeout", f"{seconds}s",
                                         "--output", "json", expect="any", timeout=seconds + 15)
                require(code == 0 and waited.get("eof") and waited["session"]["exit_code"] == 0,
                        "cleanup did not remove the exact staged updates")
                self.updates_staged = None
            except Exception as error:
                errors.append(str(error))
        try:
            views = self.sessions()
        except Failure as error:
            views = {}
            errors.append(str(error))
        for sid, name in self.owned.items():
            view = views.get(sid)
            self.final_sessions.append({"session_id": sid, "name": name,
                                        "state": view and view["state"],
                                        "launch_generation": view and view.get("launch_generation"),
                                        "cleanup_unknown": view and view["cleanup_unknown"]})
            if not view or view["state"] not in TERMINAL_SESSION or view["cleanup_unknown"]:
                errors.append(f"owned session {sid} is not confirmed stopped known-clean")
        return errors


def contract_tests():
    """Source-only harness contracts: no cw, provider, VM, socket or signal calls."""
    import ast
    import copy
    from unittest import mock

    environment, driver, instance, boot = [f"00000000-0000-4000-8000-{number:012d}" for number in range(1, 5)]
    session = "session-00000000-0000-4000-8000-000000000005"
    identity = {"environment_id": environment, "driver_id": driver, "session_id": session,
                "instance_id": instance, "driver_started_at": "2026-10-01T00:00:00Z", "boot_id": boot,
                "driver_pid": 101, "driver_start_ticks": 99}
    live = {"peer": {"identity": identity, "cleanup_unknown": True, "finished_at": None},
            "driver": {"live": True}, "echild": False,
            "family": {"nonce": "0a1b2c3d", "boot_id": boot, "children": [
                {"role": "detached", "pid": 102, "start_ticks": 100,
                 "process": {"present": True, "live": True, "term_ignored": True, "sid": 102, "pgrp": 102}},
                {"role": "double_fork", "pid": 104, "start_ticks": 101,
                 "process": {"present": True, "live": True, "term_ignored": True, "sid": 103, "pgrp": 103}}]}}

    def clean_proof():
        value = copy.deepcopy(live)
        value["peer"].update(cleanup_unknown=False, finished_at="2026-10-01T00:00:01Z")
        value["driver"]["live"] = False
        value["echild"] = True
        for child in value["family"]["children"]:
            child["process"] = {"present": False, "live": False}
        return value

    class Contracts(unittest.TestCase):
        def failed_call(self, stdout, stderr="session exited with code 1\n", verb="wait", output="json"):
            journey = Journey("/not/executed/cw", environment, False, None, None)
            process = mock.Mock(returncode=1)
            process.communicate.return_value = stdout, stderr
            with mock.patch.object(subprocess, "Popen", return_value=process) as launch:
                with self.assertRaises(Failure) as caught:
                    journey.call(verb, environment, session, "--output", output)
            launch.assert_called_once()
            process.communicate.assert_called_once()
            return journey, str(caught.exception)

        def test_failed_wait_keeps_traceback_without_retry_or_success(self):
            traceback = 'Traceback (most recent call last):\n  File "<string>", line 17\nAssertionError\n'
            _, detail = self.failed_call(json.dumps({"session": {"exit_code": 1}, "eof": True,
                                                     "output": traceback}))
            self.assertIn("cw wait exited 1: session exited with code 1", detail)
            self.assertIn(traceback, scrub(detail))

        def test_failed_wait_redacts_and_bounds_both_streams_before_report(self):
            canary = "cwlocal" + "a" * 32
            token = "sk-" + "b" * 32
            traceback = "Traceback\n" + canary + "\n " + token + "\n" + "stack frame\n" * 200
            journey, detail = self.failed_call(json.dumps({"output": traceback}), "stderr\n" * 100)
            report = scrub(detail)
            self.assertLessEqual(len(report), 1500)
            self.assertIn("Traceback\n[scrubbed]\n [scrubbed]", report)
            self.assertNotIn(canary, detail)
            self.assertNotIn(token, detail)
            self.assertEqual(journey.canary_hits, 2)
            self.assertNotIn("stack frame\n" * 100, report)

        def test_failed_wait_does_not_report_unframed_or_other_command_stdout(self):
            for stdout in ("", "not JSON", "[]", "null", '{}', '{"output":null}',
                           '{"output":42}', '{"output":[]}'):
                with self.subTest(stdout=stdout):
                    _, detail = self.failed_call(stdout)
                    self.assertEqual(detail, "cw wait exited 1: session exited with code 1\n")
            for verb, output in (("wait", "text"), ("info", "json")):
                with self.subTest(verb=verb, output=output):
                    _, detail = self.failed_call('{"output":"unrelated stdout"}', verb=verb, output=output)
                    self.assertNotIn("unrelated stdout", detail)

        def test_expected_failed_wait_and_success_keep_original_result(self):
            stdout, stderr = '{"output":"retained output"}', "diagnostic"
            for code, expect in ((1, "fail"), (0, "ok")):
                with self.subTest(code=code, expect=expect):
                    journey = Journey("/not/executed/cw", environment, False, None, None)
                    process = mock.Mock(returncode=code)
                    process.communicate.return_value = stdout, stderr
                    with mock.patch.object(subprocess, "Popen", return_value=process) as launch:
                        result = journey.call("wait", environment, session, "--output", "json", expect=expect)
                    self.assertEqual(result, (code, stdout, stderr))
                    launch.assert_called_once()

        def test_generation_refuses_missing_zero_stale_types(self):
            self.assertEqual(generation({"launch_generation": 1}), 1)
            for value in (None, 0, -1, True, 1.0, "1"):
                with self.assertRaises(Failure):
                    generation({"launch_generation": value})

        def test_peer_requires_immutable_binding_and_birth(self):
            self.assertEqual(peer_identity({"peer": {"identity": identity}}, environment, driver, session), identity)
            for key, value in (("environment_id", driver), ("driver_id", environment), ("session_id", instance),
                               ("instance_id", "../unsafe"), ("boot_id", "missing"), ("driver_pid", 1),
                               ("driver_start_ticks", 0), ("driver_pid", True)):
                altered = dict(identity, **{key: value})
                with self.assertRaises(Failure):
                    peer_identity({"peer": {"identity": altered}}, environment, driver, session)

        def test_live_family_requires_both_births_and_process_shapes(self):
            require_live_family(live, "0a1b2c3d")
            for path, value in (("term_ignored", False), ("present", False), ("live", False), ("sid", 102)):
                altered = copy.deepcopy(live)
                altered["family"]["children"][1]["process"][path] = value
                # sid equal to the other child's PID still describes a
                # double fork; use its own PID to reject undetached shape.
                if path == "sid":
                    altered["family"]["children"][1]["process"][path] = 104
                with self.assertRaises(Failure):
                    require_live_family(altered, "0a1b2c3d")
            altered = copy.deepcopy(live)
            altered["family"]["children"][1]["pid"] = 102
            with self.assertRaises(Failure):
                require_live_family(altered, "0a1b2c3d")

        def test_clean_requires_echild_exact_instance_driver_exit_and_reaping(self):
            proof = clean_proof()
            require_clean_custody(proof, identity, live["family"])
            for field, value in (("echild", False), ("driver", {"live": True})):
                changed = copy.deepcopy(proof)
                changed[field] = value
                with self.assertRaises(Failure):
                    require_clean_custody(changed, identity, live["family"])
            for field, value in (("cleanup_unknown", True), ("finished_at", None), ("identity", dict(identity, driver_pid=201))):
                changed = copy.deepcopy(proof)
                changed["peer"][field] = value
                with self.assertRaises(Failure):
                    require_clean_custody(changed, identity, live["family"])
            changed = copy.deepcopy(proof)
            changed["family"]["children"][0]["process"]["present"] = True
            with self.assertRaises(Failure):
                require_clean_custody(changed, identity, live["family"])
            changed = copy.deepcopy(proof)
            changed["family"]["children"][0]["start_ticks"] += 1
            with self.assertRaises(Failure):
                require_clean_custody(changed, identity, live["family"])

        def test_probe_is_durable_run_wait_with_closed_identity_argv(self):
            journey = Journey("/not/executed/cw", environment, False, None, None)
            journey.drivers[session] = driver
            calls = []
            journey.launch_command = lambda label, argv: calls.append((label, argv)) or session
            def waited(*args, **kwargs):
                self.assertEqual(args[:3], ("wait", environment, session))
                return 0, {"eof": True, "session": {"exit_code": 0}, "output": "{}"}
            journey.data = waited
            case = {"sid": session, "nonce": "0a1b2c3d", "peer": identity}
            journey.custody_probe(case)
            journey.custody_probe(case)
            self.assertNotEqual(calls[0][0], calls[1][0])
            self.assertEqual(calls[0][1][:4], ["python3", "-I", "-c", CUSTODY_PROBE])
            self.assertEqual(calls[0][1][4:9], ["observe", environment, driver, session, "0a1b2c3d"])
            self.assertEqual(json.loads(calls[0][1][9]), identity)
            journey.guest_probe_count = 80
            with self.assertRaises(Failure):
                journey.custody_probe(case)

        def test_probe_refuses_nonzero_unfinished_or_unframed_result(self):
            journey = Journey("/not/executed/cw", environment, False, None, None)
            journey.drivers[session] = driver
            journey.launch_command = lambda *_: session
            case = {"sid": session, "nonce": "0a1b2c3d", "peer": identity}
            for code, result in ((1, {"eof":True, "session":{"exit_code":1}, "output":"{}"}),
                                 (0, {"eof":False, "session":{"exit_code":0}, "output":"{}"}),
                                 (0, {"eof":True, "session":{"exit_code":0}, "output":"not JSON"})):
                journey.data = lambda *args, **kwargs: (code, result)
                with self.assertRaises(Failure):
                    journey.custody_probe(case)

        def test_cleanup_restores_before_stop_preserves_neighbor(self):
            journey = Journey("/not/executed/cw", environment, False, None, None)
            case = {"sid": session, "nonce":"0a1b2c3d", "peer":identity, "removed":False}
            digest = "a" * 64
            journey.custody_cases.append(case)
            journey.receipt_faults[session] = (case, digest)
            journey.owned[session] = "exact-owned"
            neighbor = "session-00000000-0000-4000-8000-000000000006"
            views = {session:{"state":"Running", "cleanup_unknown":False, "launch_generation":1},
                     neighbor:{"state":"Running", "cleanup_unknown":False}}
            order = []
            journey.sessions = lambda: views
            def probe(_case, operation="observe", _digest=""):
                order.append(operation)
                return {"restored":True, "receipt_sha256":digest} if operation == "restore" else {"removed":True}
            journey.custody_probe = probe
            def stop(sid):
                self.assertEqual(sid, session)
                order.append("stop")
                views[sid]["state"] = "Stopped"
            journey.stop = stop
            self.assertEqual(journey.cleanup(), [])
            self.assertEqual(order, ["restore", "stop", "remove"])
            self.assertEqual(views[neighbor]["state"], "Running")

        def test_actual_acceptance_does_not_claim_custody_for_synthetic_peers(self):
            custody = {name for name in ACTUAL_REQUIRED if name.startswith("custody/")}
            self.assertEqual(len(custody), 5)
            self.assertFalse(custody.intersection(SYNTHETIC_REQUIRED))
            self.assertEqual(OVERALL_SECONDS, 1200)
            self.assertEqual(CLEANUP_RESERVE_SECONDS, 180)
            self.assertTrue(any(name == "codex-custody" for name, *_ in FIXTURE_EXPECTATIONS))

        def test_guest_probe_syntax_has_no_untrusted_code_or_raw_pid_signal(self):
            tree = ast.parse(CUSTODY_PROBE)
            calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
            self.assertFalse(any(isinstance(node.func, ast.Name) and node.func.id in ("exec", "eval") for node in calls))
            signal_calls = [node.func.attr for node in calls if isinstance(node.func, ast.Attribute) and
                            isinstance(node.func.value, ast.Name) and node.func.value.id in ("os", "signal") and
                            node.func.attr in ("kill", "killpg", "pidfd_open", "pidfd_send_signal")]
            self.assertEqual(sorted(signal_calls), ["pidfd_open", "pidfd_send_signal"])
            self.assertIn('assert current == expected', CUSTODY_PROBE)

        def test_launch_names_no_program_fallback_in_either_mode(self):
            # No client is pinned: the CLI never reports running one from
            # PATH instead, and a launch is recorded the same in both modes.
            source = (Path(__file__).resolve().parents[2] /
                      "crates/codewire-cli/src/commands/sessions/agents/native_host.rs").read_text()
            self.assertNotIn("not the image's pinned client", source)
            sid = "session-00000000-0000-4000-8000-000000000006"

            def launch(synthetic):
                journey = Journey("/not/executed/cw", environment, synthetic, None, None)
                launched = {"session": {"session_id": sid, "name": f"{journey.prefix}-worker"},
                            "agent": "claude", "driver_id": driver, "message": None}
                with mock.patch.object(journey, "call", return_value=(0, json.dumps(launched), "")), \
                        mock.patch.object(journey, "own", return_value=sid):
                    journey.launch_agent("worker", "claude")
                return journey

            for synthetic in (True, False):
                journey = launch(synthetic)
                self.assertEqual(journey.drivers, {sid: driver})
                self.assertNotIn("program_fallback", journey.agents["claude"])

        def test_shell_clients_require_both_user_updates_to_have_run(self):
            prefix = "cwnm-0a1b2c3d"
            ran = [f".{prefix}-update-claude-ran", f".{prefix}-update-codex-ran"]
            require_shell_clients({"ran": ran}, prefix)
            for proof in ({"ran": ran[:1]}, {"ran": ran[1:]}, {"ran": []},
                          {"ran": ran + [f".{prefix}-update-gemini-ran"]},
                          {"ran": [".cwnm-ffffffff-update-claude-ran", ran[1]]},
                          {"ran": ran, "extra": True}, {"ran": "codex"}):
                with self.subTest(proof=proof), self.assertRaises(Failure):
                    require_shell_clients(proof, prefix)

        def test_update_programs_are_fixed_and_cleanup_removes_only_the_staged_bytes(self):
            for program in (UPDATE_STAGE, UPDATE_PROBE, UPDATE_REMOVE):
                tree = ast.parse(program)
                calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
                self.assertFalse(any(isinstance(node.func, ast.Name) and node.func.id in ("exec", "eval")
                                     for node in calls))
                self.assertIn('assert re.fullmatch(r"cwnm-[0-9a-f]{8}", prefix)', program)
            body = 'f"#!/bin/sh\\n: > {home}/.{prefix}-update-{name}-ran\\nexec {original} \\"$@\\"\\n"'
            self.assertIn(body, UPDATE_STAGE)
            self.assertIn(body, UPDATE_REMOVE)
            self.assertIn("os.O_EXCL", UPDATE_STAGE)
            # The update runs only a plain absolute path outside the prefix.
            self.assertIn('assert re.fullmatch(r"/[A-Za-z0-9._+/-]+", original) and '
                          'not original.startswith(directory + "/")', UPDATE_STAGE)
            self.assertNotIn("unlink", UPDATE_PROBE)
            self.assertIn("shell-client/user-updates-first-on-path", ACTUAL_REQUIRED)
            self.assertIn("shell-client/managed-agents-run-the-user-updates", ACTUAL_REQUIRED)
            self.assertIn("shell-client/synthetic-peers-run-from-path", SYNTHETIC_REQUIRED)
            self.assertFalse({name for name in ACTUAL_REQUIRED if name.startswith("shell-client/")} &
                             set(SYNTHETIC_REQUIRED))

    result = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(Contracts))
    print(json.dumps({"status":"passed" if result.wasSuccessful() else "failed", "proof":"source-contracts",
                      "tests_run":result.testsRun, "vm_executed":False, "provider_calls":False}))
    return result.wasSuccessful()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cw", help="absolute built host cw")
    parser.add_argument("--environment", help="immutable native environment UUID")
    parser.add_argument("--cw-image-receipt", help="external public receipt for the image supplied on this VM's readonly runtime disk")
    parser.add_argument("--self-test", action="store_true", help="source-only contract tests; launch no cw or VM")
    parser.add_argument("--codex-model")
    parser.add_argument("--claude-model")
    parser.add_argument("--synthetic-peers", action="store_true",
                        help="expect fixtures/agent-peer.py staged as guest codex/claude by checked-in "
                             "verification; changes no product behavior")
    args = parser.parse_args()
    if args.self_test:
        parser.exit(0 if contract_tests() else 1)
    if not args.cw or not args.environment or not args.cw_image_receipt:
        parser.error("--cw, --environment and --cw-image-receipt are required for the native VM journey")
    if not sys.platform.startswith(("linux", "darwin")):
        parser.error("native Linux VM managed acceptance requires a Linux or macOS host")
    if not (os.path.isabs(args.cw) and os.path.isfile(args.cw) and os.access(args.cw, os.X_OK)):
        parser.error("--cw must be an absolute executable file")
    if not is_uuid(args.environment):
        parser.error("--environment must be a canonical lowercase UUID")
    with open(args.cw_image_receipt, "rb") as source:
        image_receipt = json.loads(source.read(16385))
    journey = Journey(args.cw, args.environment, args.synthetic_peers, args.codex_model, args.claude_model, image_receipt)
    failure = None
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        journey.run()
    except Exception as error:
        detail = str(error) if isinstance(error, Failure) else f"{type(error).__name__}: {error}"
        failure = {"stage": journey.stage, "detail": scrub(detail)}
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup_errors = journey.cleanup()
    required = SYNTHETIC_REQUIRED if args.synthetic_peers else ACTUAL_REQUIRED
    reported = {entry["name"] for entry in journey.missing}
    for name in required:
        if name not in journey.checks and name not in reported:
            journey.missing.append({"name": name, "reason": "not reached" if failure else "not proven"})
    for expectation in journey.fixture.values():
        if expectation["status"] == "unobserved":
            unproven = [check for check in expectation["checks"] if check not in journey.checks]
            expectation["status"] = "not proven" if unproven else "satisfied"
            expectation["observed"] = (f"dependent checks not passed: {', '.join(unproven)}" if unproven
                                       else "all dependent checks passed")
    journey.limitations += [
        "guest agents cannot invoke host cw run or spawn sessions through the guest daemon; the host CLI "
        "launches lead and worker, same-VM parent adoption is the orchestration proof, and "
        "cross-environment parents are not claimed",
        "message records are observed only through cw inbox and wait; result-outbox cut-point recovery "
        "remains covered by the trusted-host journey",
    ]
    if args.synthetic_peers:
        journey.limitations.append("deterministic peers replace the guest agents; this mode does not "
                                   "prove protected provider delivery")
    else:
        journey.limitations.append("the guest tool marker is required from the Codex lead only; Claude "
                                   "tool use is not exercised")
    passed = (failure is None and not cleanup_errors and not journey.missing and
              not journey.canary_hits and not journey.ambiguous)
    print(json.dumps({
        "status": "passed" if passed else "failed",
        "harness": "scripts/dev/test-cli-native-managed.py",
        "mode": "synthetic-peers" if args.synthetic_peers else "protected-broker-actual-agents",
        "environment_id": args.environment,
        "session_prefix": journey.prefix,
        "profile_selected": journey.profile_selected,
        "agents": journey.agents,
        "checks": journey.checks,
        "missing_acceptance": journey.missing,
        "fixture_expectations": list(journey.fixture.values()),
        "limitations": journey.limitations,
        "unknown_or_ambiguous": journey.ambiguous,
        "expected_unknown": journey.expected_unknown,
        "custody_evidence": journey.custody_evidence,
        "owned_sessions": journey.final_sessions,
        "cleanup_errors": [scrub(error, 300) for error in cleanup_errors],
        "canary_shaped_values_observed": journey.canary_hits,
        "failure": failure,
        "elapsed_seconds": round(time.monotonic() - journey.started, 1),
        "deadline_seconds": OVERALL_SECONDS,
    }, indent=2))
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
