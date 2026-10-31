#!/usr/bin/env python3
"""Linux-inspectable guard for the macOS VZ helper boundary."""

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

vm_configuration = source("Sources/CodewireVZRunnerProtocol/VMConfiguration.swift")
for required in (
    "schemaVersion = 2", "maxShares = 16", 'shareTagPrefix = "cw-direct-"',
    "Set(root.keys) == Set(CodingKeys.allNames)",
    'Set($0.keys) == ["tag", "path", "readOnly", "device", "inode"]',
    "share.tag == Self.shareTag(index)", "share.inode != 0",
    "Set(shares.map(\\.path)).count == shares.count",
):
    if required not in vm_configuration:
        fail(f"product VM configuration lost share admission: {required}")
vm_runtime = source("Sources/CodewireVZRunnerRuntime/VMRuntime.swift")
for required in (
    "try verifySharedDirectories(request.shares)",
    "startedCheck: { (try? verifySharedDirectories(shares)) != nil }",
    "cw_vz_verify_shared_directory(share.path, share.device, share.inode)",
    "VZVirtioFileSystemDeviceConfiguration.validateTag(share.tag)",
    "VZVirtioFileSystemDeviceConfiguration(tag: share.tag)",
    "VZSingleDirectoryShare(", "readOnly: share.readOnly",
    "url: URL(fileURLWithPath: share.path, isDirectory: true)",
    "self.startCheckFailed = true",
):
    if required not in vm_runtime:
        fail(f"product VM lost exact shared-directory topology: {required}")
for required in (
    "cw_vz_apply_sandbox(configuration.sandboxProfile()) == 0",
    "throw RuntimeError.sandboxNotApplied",
):
    if required not in vm_runtime:
        fail(f"product VM lost its fail-closed confinement: {required}")
if not vm_runtime.index("cw_vz_apply_sandbox(") < vm_runtime.index("machine.start()"):
    fail("product VM must be confined before it starts")
profile = source("Sources/CodewireVZRunnerProtocol/VMSandboxProfile.swift")
for required in (
    '"(version 1)", "(deny default)"',
    'xpc-service-name \\"com.apple.Virtualization.VirtualMachine\\"',
    'extension-class \\"com.apple.virtualization.extension.fuse\\"',
):
    if required not in profile:
        fail(f"helper Seatbelt profile lost: {required}")
for forbidden in ("network", "process-", "(allow default)", "mach-register", "iokit-"):
    if forbidden in profile:
        fail(f"helper Seatbelt profile gained: {forbidden}")
if vm_runtime.count("VZSharedDirectory(") != 1:
    fail("product VM must share only the admitted request directories")
for forbidden in ("VZMultipleDirectoryShare", "VZLinuxRosettaDirectoryShare", "Process("):
    if forbidden in vm_runtime:
        fail(f"product VM gained prohibited capability: {forbidden}")
vm_bridge = source("Sources/CVZRunnerIPC/VMBridge.c")
for required in (
    "O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC", "F_GETPATH",
    "strcmp(current, path) == 0", "status.st_uid == geteuid()",
    "(uint32_t)status.st_dev == device", "(uint64_t)status.st_ino == inode",
):
    if required not in vm_bridge:
        fail(f"shared-directory admission lost exact identity check: {required}")
main = source("Sources/CodewireVZRunner/main.swift")
if 'arguments[1] == "vm", arguments[2] == "--config"' not in main:
    fail("the helper must have exactly its product command")
for forbidden in ("--control-fd", "fixture", "inode-probe"):
    if forbidden in main:
        fail(f"the helper regained a developer command: {forbidden}")
for forbidden in (
    "VZNATNetworkDeviceAttachment", "VZBridgedNetworkDeviceAttachment",
    "VZFileHandleNetworkDeviceAttachment", "Docker", "Credential",
):
    if forbidden in vm_runtime:
        fail(f"product VM gained prohibited capability: {forbidden}")

print("macOS VZ runner static boundary: OK")
