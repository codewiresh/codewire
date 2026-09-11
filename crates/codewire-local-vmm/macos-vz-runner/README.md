# macOS VZ runner feasibility slice

`codewire-vz-runner` is an additive, currently unreachable Swift helper for
validating a fixed Virtualization.framework configuration on macOS 26 or later
on Apple Silicon. It is not linked from Cargo, `codewire-local-vmm`, or `cw`, and
it does not start or manage a VM.

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
and refuses a helper without the separately authorized
`com.apple.security.virtualization` entitlement. Merely building or testing
this package therefore cannot start a VM. The synthetic PID-1 response is not
production guest readiness; production still requires the distinct state,
root, and seed storage contract to be implemented.

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

This source slice uses `/dev/fd/<n>` only because Apple's public Linux boot and
regular disk-image VZ APIs accept URLs. That URL-to-open-file behavior is not a
hardware claim. VM validation or start remains blocked until an exact-inode
swap test proves that behavior, the current guest boot contract is reconciled,
and the repository owner separately authorizes the required
`com.apple.security.virtualization` entitlement signing step.

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
