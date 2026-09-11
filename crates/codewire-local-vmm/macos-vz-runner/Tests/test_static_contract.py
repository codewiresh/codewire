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
    "inodeProbeVsockPort: UInt32 = 7_775",
    "encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]",
    "daemonVsockPort == RunnerProtocol.guestDaemonVsockPort",
    'guestKernelCommandLine = "console=ttyS0 rdinit=/init panic=-1"',
    '"console=ttyS0 rdinit=/init panic=-1 -- vz-inode-probe"',
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
    "cw_vz_receive_start", "frame[4] != 1", "CMSG_FIRSTHDR(&message) != NULL",
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
    'seed.blockDeviceIdentifier = "CWSEED1"',
    'data.blockDeviceIdentifier = "CWSTATE1"',
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

inode_probe = source("Sources/CodewireVZRunnerRuntime/InodeProbe.swift")
for required in (
    "VZVirtualMachine(configuration: configuration, queue: queue)",
    "VZVirtioSocketListener()", "device.setSocketListener(",
    "forPort: RunnerProtocol.inodeProbeVsockPort",
    "InodeProbeConnectionReceiver", "OneShotAdmissionGate",
    "withExtendedLifetime(connection)", 'Data("CWVSTG1\\0".utf8)',
    'sendResponse("descriptors-admitted"', 'sendResponse("guest-ready"',
    "HMAC<SHA256>.isValidAuthenticationCode", "Darwin.read(controlDescriptor",
):
    if required not in inode_probe:
        fail(f"inode probe lost lifecycle assertion: {required}")
for forbidden in (
    "VZNATNetworkDeviceAttachment", "VZBridgedNetworkDeviceAttachment",
    "VZVirtioFileSystemDeviceConfiguration", "device.connect(toPort:",
    "Process(", "Docker", "Credential",
):
    if forbidden in inode_probe:
        fail(f"inode probe gained prohibited capability: {forbidden}")

guest = (ROOT / "crates/codewire-vmm-guest-probe/src/guest.rs").read_text(encoding="utf-8")
for required in (
    "VsockStream::connect(VsockAddr::new(", "VMADDR_CID_HOST",
    "encode_vz_inode_probe_stage_frame", "VZ inode probe helper connection closed",
):
    if required not in guest:
        fail(f"guest inode probe lost reverse-vsock contract: {required}")
if re.search(
    r"VsockListener::bind\([^;]{0,200}VZ_INODE_PROBE_VSOCK_PORT", guest, re.DOTALL
):
    fail("guest inode probe restored the ambiguous host-connect listener")

for relative in (
    "Cargo.toml",
    "crates/codewire-cli/Cargo.toml",
    "crates/codewire-cli-bin/Cargo.toml",
    "crates/codewire-local-vmm/src/lib.rs",
):
    if "codewire-vz-runner" in (ROOT / relative).read_text(encoding="utf-8"):
        fail(f"helper became reachable from {relative}")

parent = (ROOT / "scripts/dev/macos-vz-inode-probe.py").read_text(encoding="utf-8")
for required in (
    "socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)",
    "socket.SCM_RIGHTS", 'expect_response(parent, "descriptors-admitted")',
    "for descriptor in descriptors:", "descriptors.clear()", "os.replace(decoy, path)",
    'parent.sendall(framed(b"\\x01"))', 'expect_response(parent, "guest-ready")',
    "os.kill(process.pid, signal.SIGKILL)", 'parent.recv(1) != b""',
    "os.killpg(process.pid, 0)",
    'entitlements.get("com.apple.security.virtualization") is not True',
    "helper_sha256 = exact_sha256",
    "kernel_sha256 = exact_sha256", "initramfs_sha256 = exact_sha256",
    "data_uuid = exact_uuid", "private_helper = root / \"codewire-vz-runner\"",
):
    if required not in parent:
        fail(f"inode-probe parent lost kill/swap assertion: {required}")
for forbidden in ('"codesign", "-s"', "ssh", "scp", "http://", "https://"):
    if forbidden in parent:
        fail(f"inode-probe parent gained prohibited operation: {forbidden}")

for relative in (
    "Tests/CodewireVZRunnerTests/ConfigurationTests.swift",
    "Tests/CodewireVZRunnerTests/IPCTests.swift",
    "Tests/CodewireVZRunnerTests/RuntimeAdmissionTests.swift",
):
    test_source = source(relative)
    if "import Testing" not in test_source or "import XCTest" in test_source:
        fail(f"{relative} must use CLT-supported Swift Testing")

print("macOS VZ runner static boundary: OK")
