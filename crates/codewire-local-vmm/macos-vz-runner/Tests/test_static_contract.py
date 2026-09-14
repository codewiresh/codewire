#!/usr/bin/env python3
"""Linux-inspectable guard for the unreachable macOS VZ helper boundary."""

from pathlib import Path
import plistlib
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
entitlements = plistlib.loads(source("developer-entitlements.plist").encode())
if (set(entitlements) != {"com.apple.security.virtualization"}
        or entitlements["com.apple.security.virtualization"] is not True):
    fail("developer signing acquired another entitlement")

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
    'sendResponse("descriptors-admitted"', '"boot-path-control-ready" : "guest-ready"',
    "HMAC<SHA256>.isValidAuthenticationCode", "Darwin.read(controlDescriptor",
    "PathBackedBootControl", 'appendingPathComponent("kernel"',
    'appendingPathComponent("initramfs"', "O_CREAT | O_EXCL | O_NOFOLLOW",
    "pread(sourceDescriptor", "Darwin.write(",
    "validateInodeProbeBootArtifacts(for: request)", "mkdir(directory.path, 0o700)",
    "fchmod(destinationDescriptor, 0o600)", "pathStatus.st_ino == status.st_ino",
    "== .diagnostic(.started)", "withExtendedLifetime(pathBackedBootControl)",
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
    'parent.sendall(framed(b"\\x01"))', "expect_response(parent, ready_result)",
    "os.kill(process.pid, signal.SIGKILL)", 'parent.recv(1) != b""',
    "os.killpg(process.pid, 0)",
    'return "inode-probe", "guest-ready"',
    'return "inode-probe-path-control", "boot-path-control-ready"',
    "NOT exact-inode proof", '"--path-backed-boot-control"',
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

main = source("Sources/CodewireVZRunner/main.swift")
for required in (
    '"inode-probe-path-control"',
    ".exactInode : .pathBackedBootControl",
):
    if required not in main:
        fail(f"runner entrypoint lost path-control separation: {required}")

console = source("Sources/CodewireVZRunnerProtocol/ConsolePair.swift")
for required in (
    "schemaVersion = 3", "cpuCount = 1", "memoryMiB: UInt64 = 512",
    "bindingBytes: UInt64 = 4096", "roleFrameBytes = 128",
    '"org.codewire.console-pair.packet"', '"org.codewire.console-pair.status"',
    '"org.codewire.console-pair.control"', '"CWCONSOLEPAIR1"',
    "cw_vz_descriptors_are_distinct_files", "cw_vz_receive_request",
    "encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]",
    "configuration.guestBinding.sha256 != configuration.serviceBinding.sha256",
):
    if required not in console:
        fail(f"console pair lost fixed admission contract: {required}")

console_runtime = source("Sources/CodewireVZRunnerRuntime/ConsolePairRuntime.swift")
for required in (
    "socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors)",
    "fileHandleForReading: packet, fileHandleForWriting: packet",
    "PathBackedBootControl.copyVerified", "VZVirtioConsoleDeviceConfiguration",
    "packetPort.isConsole = false", "statusPort.isConsole = false",
    "controlPort.isConsole = false", "configuration.socketDevices = []",
    "configuration.networkDevices = []", "configuration.directorySharingDevices = []",
    "configuration.serialPorts = []", "configuration.graphicsDevices = []",
    "VZVirtualMachine(configuration: configuration, queue: queue)",
    "let drained = machines.map { $0.drain() }", "guard input.isEmpty",
    "machines[index].snapshot().terminal", "virtualMachine === machine",
    "flags & O_ACCMODE == O_RDONLY", "ConsolePairLifecycle()",
):
    if required not in console_runtime:
        fail(f"console pair lost topology/ownership assertion: {required}")
for forbidden in (
    "VZNATNetworkDeviceAttachment", "VZBridgedNetworkDeviceAttachment",
    "VZFileHandleNetworkDeviceAttachment", "VZVirtioFileSystemDeviceConfiguration",
    "Process(", "device.connect(toPort:", "Darwin.read(packet", "Darwin.write(packet",
):
    if forbidden in console_runtime:
        fail(f"console pair gained prohibited host capability: {forbidden}")
if 'arguments[1] == "console-pair-fixture"' not in main:
    fail("console pair must remain a distinct developer-only command")

local_vmm = ROOT / "crates/codewire-local-vmm"
if '#[cfg(all(target_os = "linux", feature = "macos-console-pair-fixture"))]' not in (
    local_vmm / "src/lib.rs"
).read_text():
    fail("Linux console pair lost opt-in feature isolation")
if 'required-features = ["macos-console-pair-fixture"]' not in (
    local_vmm / "Cargo.toml"
).read_text():
    fail("console pair binary must require its developer feature")

product_binary = re.search(
    r'^\[\[bin\]\]\s*\nname = "codewire-macos-product-network-fixture"\n(.*?)(?=^\[|\Z)',
    (local_vmm / "Cargo.toml").read_text(), re.M | re.S,
)
if (product_binary is None or
        'required-features = ["macos-product-network-fixture"]' not in product_binary.group(1)):
    fail("product-network binary must require its distinct developer feature")
if '#[cfg(all(target_os = "linux", feature = "macos-product-network-fixture"))]' not in (
    local_vmm / "src/bin/codewire-macos-product-network-fixture.rs"
).read_text():
    fail("product-network entrypoint lost Linux opt-in feature isolation")

for relative in (
    "Tests/CodewireVZRunnerTests/ConfigurationTests.swift",
    "Tests/CodewireVZRunnerTests/IPCTests.swift",
    "Tests/CodewireVZRunnerTests/RuntimeAdmissionTests.swift",
):
    test_source = source(relative)
    if "import Testing" not in test_source or "import XCTest" in test_source:
        fail(f"{relative} must use CLT-supported Swift Testing")

production_protocol = source("Sources/CodewireVZRunnerProtocol/ProductionFixture.swift")
for required in (
    "schemaVersion = 2", "descriptorCount = 9", "maximumSetupBytes: UInt64 = 65 * 1024 * 1024 * 1024",
    "runtimeSeconds: Double = 180", "connectSeconds: Double = 120", "stopSeconds: Double = 5",
    '"network-connected"', '"progress-connected"', '"daemon-connected"',
    "cw_vz_validate_production_descriptors", "cw_vz_receive_production_request",
):
    if required not in production_protocol:
        fail(f"production fixture lost fixed protocol boundary: {required}")
production_configuration = source("Sources/CodewireVZRunnerRuntime/ProductionConfiguration.swift")
for required in (
    '"CWSTATE1", false', '"CWROOT1", false', '"CWSEED1", true', '"CWSETUP1", true',
    "RunnerProtocol.guestKernelCommandLine", "validateImmutable", "validateMutable",
    "result.networkDevices = []", "result.directorySharingDevices = []",
):
    if required not in production_configuration:
        fail(f"production fixture lost storage/topology boundary: {required}")
production_runtime = source("Sources/CodewireVZRunnerRuntime/ProductionFixtureRuntime.swift")
for required in (
    "device.connect(toPort: port)", "lifecycle.didConnect(role)", "cw_vz_bridge_streams",
    "lifecycle.progressClosed()", "cw_vz_control_event", "self.machine.stop",
    "workers.wait(timeout:", "role == .progress, result == 2",
):
    if required not in production_runtime:
        fail(f"production fixture lost lifecycle boundary: {required}")
for forbidden in (
    "VZNATNetworkDeviceAttachment", "VZBridgedNetworkDeviceAttachment",
    "VZFileHandleNetworkDeviceAttachment", "VZVirtioFileSystemDeviceConfiguration",
    "NetworkHostReady", "auth_token", '"guest-ready"', "Process(",
):
    if forbidden in production_configuration + production_runtime:
        fail(f"production fixture acquired unsupported authority: {forbidden}")
if "proc_pidfdinfo(getpid()" not in ipc or "SO_COOKIE" not in ipc:
    fail("production socket alias admission lost platform socket identities")
bridge = source("Sources/CVZRunnerIPC/ProductionBridge.c")
if "CW_VZ_BRIDGE_BUFFER_BYTES" not in bridge or "CLOCK_MONOTONIC" not in bridge:
    fail("production bridge lost resource bounds")

workload_protocol = source("Sources/CodewireVZRunnerProtocol/WorkloadNetwork.swift")
for required in (
    "schemaVersion = 4", "descriptorCount = 10",
    "case kernel, initialRamdisk, seedDisk, stateDisk, rootDisk, setupDisk",
    "case serviceInitialRamdisk, serviceBinding, progress, daemon",
    "Set(root.keys) == [", "try production.validate()", "serviceBinding.size == 4096",
    "cw_vz_validate_workload_network_descriptors", "cw_vz_receive_workload_network_request",
):
    if required not in workload_protocol:
        fail(f"workload-network lost exact ten-FD admission: {required}")
if "validate_artifacts_and_channels(control_fd, descriptors, 8, 2)" not in ipc:
    fail("workload-network requires eight artifacts and only two private channels")

workload_machine = source("Sources/CodewireVZRunnerRuntime/WorkloadNetworkMachine.swift")
for required in (
    "configuration.networkDevices = []", "configuration.directorySharingDevices = []",
    "configuration.socketDevices = []", "port.isConsole = false",
    "(0, ConsolePairProtocol.packetPort, nil as VZSerialPortAttachment?)",
    "virtualMachine === machine", "error == nil ? .stopSucceeded : .stopFailed",
):
    if required not in workload_machine:
        fail(f"workload-network lost service topology/stop boundary: {required}")

workload_runtime = source("Sources/CodewireVZRunnerRuntime/WorkloadNetworkRuntime.swift")
workload_lifecycle = source("Sources/CodewireVZRunnerRuntime/WorkloadNetworkLifecycle.swift")
for required in (
    "FileHandle(fileDescriptor: connection.fileDescriptor, closeOnDealloc: false)",
    "fileHandleForReading: handle, fileHandleForWriting: handle",
    "let connection = try self.connect(port: 7775)", "var bytes = held",
    "port.attachment == nil", "port.attachment = owned.attachment",
    "port.attachment = nil", "self.life.didDetach(consumerTerminal: self.service.snapshot().terminal)",
    "self.life.claimClose() { packet.connection.close() }",
    "for role in [WorkloadNetworkDescriptorRole.progress, .daemon]",
    "let states = [production.drain(), service.drain()]", "if event == 0 { actualStops.insert(role) }",
):
    if required not in workload_runtime:
        fail(f"workload-network lost borrowed-connection/lifecycle boundary: {required}")
if "actualStops == [1, 2] && daemonDrained" not in workload_lifecycle:
    fail("workload-network must drain poweroff response before helper completion")
workload_bridge = workload_runtime.split("private func bridge(", 1)[-1].split(
    "private func relay()", 1)[0]
if ("WorkloadNetworkProtocol.stopSeconds" in workload_bridge or
        "daemonStopDeadline" in workload_bridge):
    fail("normal daemon drain must not borrow the forced-cleanup stop budget")
for required in (
    "let deadline = workloadNow() + WorkloadNetworkProtocol.runtimeSeconds",
    "guard workloadNow() < deadline", "WorkloadNetworkLifecycle.mayComplete(",
    "actualStops: actualStops, daemonDrained: daemonDrainedNow",
    "let stopDeadline = workloadNow() + WorkloadNetworkProtocol.stopSeconds",
):
    if required not in workload_runtime:
        fail(f"workload-network lost central completion/cleanup bound: {required}")
for forbidden in (
    "VZNATNetworkDeviceAttachment", "VZBridgedNetworkDeviceAttachment",
    "VZFileHandleNetworkDeviceAttachment", "VZVirtioFileSystemDeviceConfiguration",
    "Process(", "Darwin.read(connection", "Darwin.write(connection",
    "Darwin.read(packet", "Darwin.write(packet", "handle.close(",
):
    if forbidden in workload_machine + workload_runtime:
        fail(f"workload-network acquired prohibited host authority: {forbidden}")
if 'arguments[1] == "workload-network-fixture"' not in main:
    fail("workload-network must remain a distinct developer-only command")

workload_binary = re.search(
    r'^\[\[bin\]\]\s*\nname = "codewire-macos-workload-network-fixture"\n(.*?)(?=^\[|\Z)',
    (local_vmm / "Cargo.toml").read_text(), re.M | re.S,
)
if (workload_binary is None or
        'required-features = ["macos-workload-network-fixture"]' not in workload_binary.group(1)):
    fail("workload-network binary must require its distinct developer feature")
guest_root = ROOT / "crates/codewire-vmm-guest-probe/src"
for path, pattern in (
    (guest_root / "lib.rs", r'#\[cfg\(feature = "macos-workload-network-fixture"\)\]\s*'
     r'pub mod macos_workload_network_fixture;'),
    (guest_root / "main.rs", r'#\[cfg\(feature = "macos-workload-network-fixture"\)\]\s*'
     r'Some\("macos-workload-network-client"\)'),
):
    if not re.search(pattern, path.read_text()):
        fail("workload client must remain excluded from the default guest")
workload_host = "\n".join(
    path.read_text() for path in sorted((local_vmm / "src/bin/vz_workload_network_fixture").glob("*.rs"))
    if path.name != "tests.rs"
)
for forbidden in ("run_network_session", "DenyBroker", '"--network-fd"'):
    if forbidden in workload_host:
        fail(f"workload verifier acquired a host packet engine: {forbidden}")

print("macOS VZ runner static boundary: OK")
