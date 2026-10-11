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
`com.apple.security.virtualization` entitlement; developer builds are signed
ad hoc with `developer-entitlements.plist`.

The sections below describe the earlier fixed-topology developer fixtures.

`codewire-vz-runner` is an additive, currently unreachable Swift helper for
validating a fixed Virtualization.framework configuration on macOS 26 or later
on Apple Silicon. It is not linked from Cargo, `codewire-local-vmm`, or `cw`, and
its default validation does not start a VM. The separately invoked developer
fixtures below own disposable VMs; none exposes a product environment path.

The separately invoked `inode-probe` subcommand is source for one synthetic
hardware fixture, not product lifecycle wiring. Its parent is
`scripts/dev/macos-vz-inode-probe.py`. The parent copies caller-supplied
reviewed kernel/initramfs and synthetic ext4 data bytes into a private
directory, generates a synthetic 4 KiB seed, sends exactly four descriptors,
waits for descriptor admission, closes its copies, and atomically replaces all
four pathnames with zero-filled decoys. Only then does it send the one-byte
start command. A dedicated PID-1 mode from the same initramfs returns native
vsock readiness authenticated by the original seed bytes and including the
original ext4 UUID. The parent then SIGKILLs the helper and requires both the
process result and control-channel EOF to classify ownership termination.

The harness never signs. It requires exact reviewed SHA-256 values for its
private helper copy, kernel and initramfs plus the exact synthetic ext4 UUID,
and refuses a helper without the development
`com.apple.security.virtualization` entitlement. Merely building or testing
this package therefore cannot start a VM. The synthetic PID-1 response is not
production guest readiness. The schema-2 fixture below implements the distinct
state, root, seed and setup descriptor contract; product lifecycle wiring and
production boot acceptance remain separate from the inode probe.

Both canonical guest archive formats include `/dev/null` as character device
1:3 before `/init`. With no console, the kernel can leave standard descriptors
closed; Rust needs this node before entering guest code to reopen them. This
does not add a VZ console or serial device. Earlier archives without the node
must be rebuilt with the matching packer and their reviewed digest/size
manifests refreshed. Canonical admission rejects mixing old and new layouts;
saved state-disk contents do not change.

The separate `inode-probe-path-control` subcommand is an explicit diagnostic
control, never an exact-inode proof. It immediately copies only the already
admitted kernel and initial-ramdisk descriptors into a helper-owned private
directory, verifies the copied sizes and SHA-256 values, and supplies those
ordinary paths to the URL-only VZ boot APIs. The parent still replaces every
original fixture pathname before start. The control succeeds only after the
guest connects over native vsock and answers a fresh challenge with the first
strictly ordered diagnostic frame. It then reports `boot-path-control-ready`,
which is distinct from `guest-ready`, and its terminal output includes `NOT
exact-inode proof`. This controlled comparison can distinguish a `/dev/fd`
boot handoff failure from a later guest/vsock failure without weakening or
substituting for the default exact-inode gate.

The parent supplies one bounded, sorted-key canonical JSON frame over an
inherited private connected `AF_UNIX` stream socket. A four-byte big-endian
length prefix gives the stream an explicit frame boundary. The first send
carries exactly four `SCM_RIGHTS` descriptors in this fixed order:

1. read-only Linux kernel
2. read-only initial ramdisk
3. read-only 4 KiB seed disk
4. read-write data disk

The JSON carries identities and bounded resource values, never filesystem
paths, secrets, credentials, network configuration, or host-share authority.
The helper checks the peer EUID, descriptor type, owner, mode, link count,
access mode and size. It also checks SHA-256 identities for immutable inputs.
The VZ topology has no network, shared directory, graphics, audio, input,
serial, console, USB, or balloon devices; its only host transport is native
virtio-vsock.

## Production-init developer fixture (schema 2)

See [preparation and execution](../../../docs/dev/MACOS-VZ-PRODUCTION-FIXTURE.md)
for the Rust verifier, private synthetic inputs and parent harness. The standalone
`developer-entitlements.plist` is the sole-entitlement ad-hoc signing input;
building the package does not sign it or start a VM.

`production-init-fixture --control-fd FD` is a separate, unreachable developer
entrypoint. The existing four-descriptor schema-1 inode probes are unchanged.
Its fixed nine `SCM_RIGHTS` descriptors are, in order:

1. read-only kernel
2. read-only initial ramdisk
3. read-only 4 KiB seed
4. read-write state ext4 disk (`CWSTATE1`)
5. read-write root ext4 disk (`CWROOT1`)
6. read-only setup pack (`CWSETUP1`)
7. private connected Unix network channel
8. private connected Unix progress channel
9. private connected Unix daemon channel

The canonical configuration fields are exactly `schemaVersion` (2), `vmID`,
`generation`, `cpuCount`, `memoryMiB`, `daemonVsockPort` (7777), `kernel`,
`initialRamdisk`, `seedDisk`, `stateDisk`, `rootDisk`, and `setupDisk`. Immutable
identities contain `size` and `sha256`; mutable identities contain `size` and
`filesystemUUID`. The setup pack is at least 64 KiB, aligned to 4096 bytes and
at most 65 GiB, matching the guest contract. File roles must refer to distinct
private regular inodes. Channels must be connected same-EUID Unix streams,
distinct from each other and the control socket; admission uses Darwin's
self-only opaque socket handles or Linux socket cookies, not Darwin inode
assumptions. All received descriptors are close-on-exec and helper-owned.

The parent constructs the real current guest seed with synthetic boot
authentication and a matching verified setup pack. The helper admits descriptor
identities, not seed credentials or workload semantics; unchanged production
PID 1 validates the complete seed/setup/root contract. No paths, tokens,
network destinations, shares, Docker, timeout knobs or provider authority can
be added to this configuration. This is a fresh-boot fixture, not recovery.

After schema-2 `descriptors-admitted`, the parent sends the existing framed
one-byte start command. The helper boots the unchanged production command line
and independently dials guest ports 7775/7776/7777, forwarding opaque bytes
through their respective channels. It serializes exactly one
`network-connected`, `progress-connected`, and `daemon-connected` response,
in any order. The parent starts each protocol only after its corresponding
marker, preserving the guest handshake deadline. There is no all-channel
barrier and the helper never generates `HostReady` or accepts guest readiness.

The guest progress service closes after a terminal frame. Only that channel
drains its buffered bytes, half-closes the Unix output and emits
`progress-closed`, while retaining the VM. The parent must validate the genuine
terminal progress frame and independently authenticate daemon readiness. Parent
channel/control EOF, unexpected control input, ordinary guest-channel EOF,
guest stop, errors or the fixed deadline end the fixture. The parent retains
its channels until cleanup. No helper response is named `guest-ready`.

Connections have a shared 120-second deadline and the runtime lasts at most
180 seconds, followed by at most five seconds for owned VZ stop and transport
joining. Every forwarding buffer is at most 32 KiB. Control admission/start
reads are bounded to 15 seconds and marker writes to one second. No network
device, real host dial, shared directory or product confinement claim is added.
Source/portable tests do not prove production boot on hardware; native compile
and the separate parent-owned guest/network/progress/daemon fixture qualify
that claim. Routine developer execution follows the repository's standing
authority; this command does not confer permission to use real credentials.

This source slice uses `/dev/fd/<n>` because Apple's public Linux boot and
regular disk-image VZ APIs accept URLs. The earlier schema-1 exact-inode swap
probe established this handoff on the designated Mac; that accepted evidence
does not qualify a changed helper or prove schema-2 production boot. The
path-backed control remains diagnostic evidence, never an exact-inode proof.

Bounded developer builds, ad-hoc development signing with the required
`com.apple.security.virtualization` entitlement, and disposable fixture runs
follow the repository's standing authority on owner-designated machines.
They do not require separate per-run approval. Source builds and tests do not
start a VM; hardware acceptance must record the exact helper and guest inputs
actually exercised, preserving the checked-in topology and assertions.

Run the portable protocol tests and boundary guard with:

```sh
swift test --package-path crates/codewire-local-vmm/macos-vz-runner \
  -Xswiftc -warnings-as-errors -Xcc -Werror
python3 crates/codewire-local-vmm/macos-vz-runner/Tests/test_static_contract.py
```

After the Mac Command Line Tools match the installed SDK, run the source-only
developer build loop with:

```sh
python3 scripts/dev/macos-cli.py --host user@mac.example.invalid \
  --component vz-runner --action verify
```
