# macOS VZ helper

`codewire-vz-runner vm --config FILE` is the macOS counterpart of the Cloud
Hypervisor process that the Linux runner owns. The JSON configuration
(`VMConfiguration`, schema 2 or 3) names the kernel, initial ramdisk, kernel
command line, CPU count, memory and virtio-blk disks by absolute path, with
each disk's serial and read-only flag, and the admitted direct shares. The
Rust runner admits every disk under its private state root before writing the
file. Unknown or missing fields fail closed; schema 1, which had no `shares`,
is refused.

Schema 3 (#4654) adds four fields, all present together (schema 2 has none of
them), for VM checkpoints:
- `machineIdentifier`: base64 of the `VZGenericMachineIdentifier`'s data
  representation, or `null` on a VM's first start, when the framework makes
  one. A restore needs the identifier its state was saved with, so the runner
  keeps it per VM.
- `saveState`: the one file a save writes.
- `restoreState`: a saved state to restore and resume instead of starting, or
  `null`.
- `controlDescriptor`: the inherited control socket, 3 to 1023.

The sandbox profile embeds the two state paths as literals: `saveState` read and
write, `restoreState` read only. So decoding refuses either path, never
escaping it, unless it is absolute, normalized, strictly inside the VM's
directory (the one holding the configuration file) and made only of
`[A-Za-z0-9._/-]`. A restore path equal to the save path is refused too.

The control channel is one end of an unnamed `AF_UNIX` stream socketpair that
only the runner holds. Before confinement, the helper requires the descriptor
to be exactly that: a socket, `SOCK_STREAM`, `AF_UNIX`, unnamed. Otherwise it
exits 1 before the VM starts. Each message is one JSON line of at most 4 KiB:
- a request is exactly `{"id": N, "op": "pause" | "save" | "resume" | "stop"}`,
  with no path, descriptor or size, and `save` always writes `saveState`;
- each request gets one reply: `{"id","result":"done","ms"}`,
  `{"id","result":"failed","code"}` (the `VZError.Code`) or
  `{"id","result":"refused"}`, when the VM's state doesn't allow it;
- the one event is `{"event":"started","machineIdentifier"}`, sent once the VM
  runs: started, or restored and resumed.

A capture is pause, save, resume, and stop is allowed from any state. EOF, a
malformed or over-long line, or any ancillary data stops the VM. Descriptors
sent with ancillary data are closed unread. The exit statuses are unchanged; a
refused restore exits like a refused start.

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
or a requested stop completes, and 1 when it fails before starting the VM or
the VM stops with an error. When Virtualization.framework refuses to start the
VM, it exits 64 plus the refusal's `VZError.Code` for codes 1 to 63, and 64
for any other code (`VMExit`). The runner reads that status and reports
`vm_start_refused`, so the helper never writes the error's text (#4478). It
removes the socket only if that path is still the one it bound.
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
  OS's own files (`/System`, `/usr/lib`, `/dev/null`) and sysctls; the metadata
  of the `/var` symlink alone; reading the
  kernel, the initial ramdisk and read-only disks; reading and writing writable
  disks; the granted shares, with the rights their mode gives; removing the
  socket it bound; and looking up the `com.apple.Virtualization.VirtualMachine`
  XPC service. A VM with shares may also issue what Virtualization.framework
  gives its service to serve them: a file extension for each share and the
  `com.apple.virtualization.extension.fuse` class. Without those the VM boots
  and the guest gets `EPERM` on every share.
- Since macOS 27, Virtualization.framework looks up the user's cache
  directory as the VM starts. Confined, the helper can ask neither
  opendirectoryd for the user's UUID nor dirhelper for the directory, and the
  start fails with `VZErrorDomain` 1, "Failed to retrieve cache directory"
  (#4478). So the helper resolves the directory with `confstr` before it
  confines itself, and the framework's own lookup then needs only `/var`'s
  metadata. Observed on macOS 27.2.1 with this profile: without the early
  lookup, or without the `/var` rule, the start fails; with both it starts.
  The framework's other refused requests (`system-info vfs.disk-space`, the VM
  service's task name, opendirectoryd membership) do not stop the VM, and stay
  refused.
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

## Tests

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
