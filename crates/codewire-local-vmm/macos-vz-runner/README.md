# macOS VZ runner feasibility slice

## Product VM mode

`codewire-vz-runner vm --config FILE` is the macOS counterpart of the Cloud
Hypervisor process that the Linux runner owns. The JSON configuration
(`VMConfiguration`, schema 2) names the kernel, initial ramdisk, kernel
command line, CPU count, memory and virtio-blk disks by absolute path, with
each disk's serial and read-only flag, and the admitted direct shares. The
Rust runner admits every disk under its private state root before writing the
file. Unknown or missing fields fail closed; schema 1, which had no `shares`,
is refused.

Each share is `{tag, path, readOnly, device, inode}`: the guest's virtio-fs tag
`cw-direct-NN` in plan order (at most 16), the canonical directory the Rust
runner admitted (owned by the user, on APFS, outside broad system roots,
credential stores and Codewire's own state, not a mount root and without a
nested mount), and that directory's raw `st_dev` and `st_ino`. The helper
serves each one with Virtualization.framework's own virtio-fs device
(`VZVirtioFileSystemDeviceConfiguration` with one `VZSharedDirectory`),
read-only when `readOnly` is set; the guest also mounts it read-only. Because
that API shares a directory by path, the helper opens the path with
`O_NOFOLLOW_ANY` and requires the same device, inode, owner and `F_GETPATH`
name before it configures the VM, and again once the VM has started. A
mismatch before start fails the helper; a mismatch after start stops the VM
and exits 1. A guest symlink resolves inside the guest, never on the host.

The kernel, initial ramdisk and disks are also named by path, because
`VZLinuxBootLoader` and `VZDiskImageStorageDeviceAttachment` accept only URLs
for regular files (VZ's file-handle disk attachment is for block devices).
Linux's Cloud Hypervisor receives the same files by path. Each path is inside a
directory only the user can write: the admitted runtime root or the
environment's private state root. Replacing a file there needs the user's
own authority, which can already control the user's VMs and `cw` itself, so a
path grants the helper nothing the runner did not admit.

The helper binds the configured hybrid-vsock Unix socket owner-only and never
replaces an existing path. A client writes `CONNECT <port>\n`. The helper dials
that guest vsock port and answers `OK <n>\n`, then copies bytes both ways,
forwarding each EOF as a write shutdown. An unreachable port closes the
connection without an acknowledgement. This is the protocol the Rust
hybrid-vsock client already speaks to Cloud Hypervisor.

SIGTERM or SIGINT stops the VM, and so does the exit of the process that
spawned the helper (macOS has no parent-death signal). The process exits 0 after the guest powers off
or a requested stop completes, and 1 when the VM fails to start or stops with
an error. It removes the socket only if that path is still the one it bound.
The VM has no network, console or graphics device. The helper needs the
`com.apple.security.virtualization` entitlement. Every signature names the
identifier `sh.codewire.vz-runner` and carries the hardened runtime and exactly
`developer-entitlements.plist`; `scripts/dev/macos-local-runtime.py` refuses a
helper without them. Developer builds are signed ad hoc. A release's helper is
Developer ID signed and notarized, once per change of its sources
(`sign-macos-helper.sh`, #1905), and the pack accepts it only if it satisfies
the Developer ID requirement for team `PXQZM3GLP5`.

Posture, observed with `lsof`, `codesign` and `sandbox_check` while a VM ran
on macOS 26:
- The helper runs as the user, as a child of the runner, signed with the
  hardened runtime and that one entitlement (observed ad hoc; an
  rcodesign-signed build with a throwaway Developer ID-shaped certificate
  behaved the same). It holds `/dev/null` for
  standard I/O, its `vz.json`, the VM's `vm.lock` and three Unix sockets. It
  holds no internet socket and no other file, and writes no log of its own.
- The helper confines itself with Seatbelt (`sandbox_init`, the mechanism the
  packet worker uses) once its listener is bound and before the VM starts, and
  exits if the profile is not applied. Everything is denied except: reading the
  OS's own files (`/System`, `/usr/lib`, `/dev/null`) and sysctls; reading the
  kernel, the initial ramdisk and read-only disks; reading and writing writable
  disks; the granted shares, with the rights their mode gives; removing the
  socket it bound; and looking up the `com.apple.Virtualization.VirtualMachine`
  XPC service. A VM with shares may also issue what Virtualization.framework
  gives its service to serve them: a file extension for each share and the
  `com.apple.virtualization.extension.fuse` class. Without those the VM boots
  and the guest gets `EPERM` on every share.
- Virtualization.framework runs the VM in Apple's
  `com.apple.Virtualization.VirtualMachine` XPC service. That process is
  sandboxed by Apple, has the hardened runtime and holds exactly:
  - the kernel and the initial ramdisk;
  - the four VM disks;
  - the granted shares.
  It holds no internet socket.
- The helper does not parse guest data. It copies vsock bytes to and from
  connections on its owner-only socket, and it reads only `CONNECT <port>`
  lines, from those host-side clients.
- Releases sign the helper with the Developer ID and notarize it (#1905).

Both canonical guest archive formats include `/dev/null` as character device
1:3 before `/init`. With no console, the kernel can leave standard descriptors
closed; Rust needs this node before entering guest code to reopen them. This
does not add a VZ console or serial device. Earlier archives without the node
must be rebuilt with the matching packer and their reviewed digest/size
manifests refreshed. Canonical admission rejects mixing old and new layouts;
saved state-disk contents do not change.

## Developer fixture subcommands

The helper still carries the earlier fixed-topology developer subcommands
(`validate`, `inode-probe`, `inode-probe-path-control`,
`production-init-fixture`, `console-pair-fixture` and
`workload-network-fixture`, each with `--control-fd FD`). Nothing in the
product invokes them, and the service-VM networking topology some of them used
is superseded for the product by the #1905 decision (host packet worker and
egress broker under Seatbelt). Their Linux and Python parents, and the
developer features that built them, were removed (#3119). The subcommands go
with the helper's next notarized change, together with the guest probe's
`vz-inode-probe` mode that answers `inode-probe`. Until then the static guard
below still holds each of them to its fixed topology.

Run the portable protocol tests and boundary guard with:

```sh
swift test --package-path crates/codewire-local-vmm/macos-vz-runner \
  -Xswiftc -warnings-as-errors -Xcc -Werror
python3 crates/codewire-local-vmm/macos-vz-runner/Tests/test_static_contract.py
```

After the Mac Command Line Tools match the installed SDK, run the source-only
developer build loop against your Mac's SSH destination (`--host`, or
`CODEWIRE_MAC_HOST`) with:

```sh
python3 scripts/dev/macos-cli.py --host user@mac.example.invalid \
  --component vz-runner --action verify
```
