#!/usr/bin/env python3
"""Linux-inspectable guard for the unreachable macOS VZ helper boundary."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[4]
PACKAGE = ROOT / "crates/codewire-local-vmm/macos-vz-runner"


def fail(message: str) -> None:
    print(f"macOS VZ runner contract: {message}", file=sys.stderr)
    raise SystemExit(1)


def source(relative: str) -> str:
    return (PACKAGE / relative).read_text(encoding="utf-8")


manifest = source("Package.swift")
if ".executable(name: \"codewire-vz-runner\"" not in manifest:
    fail("SwiftPM executable product is missing")
if ".package(" in manifest:
    fail("helper acquired an external package dependency")

configuration = source("Sources/CodewireVZRunnerProtocol/Configuration.swift")
required_configuration = [
    'schemaVersion = 1',
    'maxFrameBytes = 16 * 1024',
    "guestDaemonVsockPort: UInt32 = 7_777",
    "encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]",
    "daemonVsockPort == RunnerProtocol.guestDaemonVsockPort",
    'guestKernelCommandLine = "console=ttyS0 rdinit=/init panic=-1"',
    'Set(root.keys) == [',
    'seedDisk.size == 4096',
    'dataDisk.size >= 256 * 1024 * 1024',
    'dataDisk.size.isMultiple(of: 1024 * 1024)',
]
for required in required_configuration:
    if required not in configuration:
        fail(f"configuration lost required contract: {required}")
for forbidden in ("Path", "URL", "token", "credential", "secret", "egress", "docker", "share"):
    if re.search(rf"\b{re.escape(forbidden)}\b", configuration, re.IGNORECASE):
        fail(f"configuration gained forbidden authority field: {forbidden}")

ipc = source("Sources/CVZRunnerIPC/CVZRunnerIPC.c")
for required in (
    "SOCK_STREAM", "SCM_RIGHTS", "SO_PEERCRED", "getpeereid", "geteuid",
    "CW_VZ_FRAME_HEADER_BYTES", "payload_size",
    "MSG_TRUNC | MSG_CTRUNC", "FD_CLOEXEC", "close_message_descriptors",
    "cw_vz_descriptors_are_distinct_files", "st_dev", "st_ino",
):
    if required not in ipc:
        fail(f"IPC lost fail-closed primitive: {required}")
for forbidden_socket in ("SOCK_SEQPACKET", "SOCK_DGRAM"):
    if forbidden_socket in ipc:
        fail(f"IPC gained unsupported control transport: {forbidden_socket}")

runtime = source("Sources/CodewireVZRunnerRuntime/Runtime.swift")
for required in (
    "VZLinuxBootLoader", "VZGenericPlatformConfiguration",
    "VZDiskImageStorageDeviceAttachment", "VZVirtioBlockDeviceConfiguration",
    "VZVirtioEntropyDeviceConfiguration", "VZVirtioSocketDeviceConfiguration",
    'URL(fileURLWithPath: "/dev/fd/', "result.networkDevices = []",
    "result.directorySharingDevices = []", "result.graphicsDevices = []",
    "result.audioDevices = []", "result.usbControllers = []",
    "readExt4FilesystemUUID", "0x53, 0xef", "identity.filesystemUUID",
):
    if required not in runtime:
        fail(f"runtime lost fixed topology assertion: {required}")
for forbidden in (
    "VZNATNetworkDeviceAttachment", "VZBridgedNetworkDeviceAttachment",
    "VZFileHandleNetworkDeviceAttachment", "VZVirtioFileSystemDeviceConfiguration",
    "VZLinuxRosettaDirectoryShare", "Process(", "Docker", "Credential",
):
    if forbidden in runtime:
        fail(f"runtime gained prohibited capability: {forbidden}")

for relative in (
    "Cargo.toml",
    "crates/codewire-cli/Cargo.toml",
    "crates/codewire-cli-bin/Cargo.toml",
    "crates/codewire-local-vmm/src/lib.rs",
):
    if "codewire-vz-runner" in (ROOT / relative).read_text(encoding="utf-8"):
        fail(f"helper became reachable from {relative}")

for relative in (
    "Tests/CodewireVZRunnerTests/ConfigurationTests.swift",
    "Tests/CodewireVZRunnerTests/IPCTests.swift",
    "Tests/CodewireVZRunnerTests/RuntimeAdmissionTests.swift",
):
    test_source = source(relative)
    if "import Testing" not in test_source or "import XCTest" in test_source:
        fail(f"{relative} must use CLT-supported Swift Testing")

print("macOS VZ runner static boundary: OK")
