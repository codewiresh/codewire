# Building the Codewire iOS App on Linux

Pure-Swift build via [xtool](https://github.com/xtool-org/xtool). There is no
Go carchive shell bridge in this app. Terminal support is disabled until the
Rust/mobile-native Mesh transport bridge lands.

## Prerequisites

1. **Swift 6.1+ for Linux** — https://swift.org/download/ or on Arch Linux via `chaotic-aur/swift-bin`.
   ```bash
   swift --version   # verify
   ```

2. **xtool 1.16+** — cross-platform Xcode replacement.
   ```bash
   # Download AppImage from https://github.com/xtool-org/xtool/releases
   chmod +x xtool-*.AppImage
   sudo mv xtool-*.AppImage /usr/local/bin/xtool
   xtool --version   # verify
   ```

3. **iOS SDK installed via xtool** — xtool extracts the iOS SDK and Darwin toolchain from an `Xcode.xip` or `Xcode.app` bundle. You download `Xcode.xip` from developer.apple.com (free Apple ID is sufficient to download, ~13 GB) and feed it to xtool once:
   ```bash
   xtool sdk install ~/Downloads/Xcode_16.x.xip
   xtool sdk list    # verify the iOS SDK is registered
   ```

4. **Apple Developer Account** (free or paid)
   - Free: personal signing, 7-day provisioning, 3-app limit per device
   - Paid: distribution, longer provisioning, no app limit

5. **Apple ID authentication for signing**
   ```bash
   xtool auth        # interactive, walks you through sign-in
   ```

6. **iOS device connected via USB**
   ```bash
   xtool devices     # verify your device is visible
   ```

## Host unit tests

Because `CodewireKit` (the platform-agnostic half of the app) has `.macOS(.v13)` in its `Package.swift` platforms list, you can run its unit tests directly on the Linux host:

```bash
cd apps/ios
TMPDIR=/home/user/tmp swift test
```

Expected: all CodewireKit tests pass (TokenStore, OIDCFlow, CodewireClient, Models).

`TMPDIR` must point at a filesystem without `noexec` — Swift's build tool execs small helper binaries out of `TMPDIR` and the default `/tmp` on many Arch installs is mounted with `noexec`.

## Build and run on device

```bash
cd apps/ios
xtool dev
```

This builds the app, signs it with your configured Apple ID, installs it on the connected device, and launches it. First launch on a free developer account will need a one-time "Trust this developer" prompt in Settings → General → VPN & Device Management.

## Terminal Shell Status

The old Go `libcwshell.a` bridge was retired with the Go CLI source. The current
`CwShellBridge` keeps the Swift app buildable and reports the shell as
unavailable at runtime.

The replacement should call into Rust/mobile-native transport primitives rather
than reintroducing a Go carchive. It must preserve the platform transport ladder:
direct WireGuard UDP, UDP relay, DERP, then WebSocket.

## Troubleshooting

### xtool can't find the iOS SDK

```bash
xtool sdk list       # is an iOS SDK registered?
xtool sdk install ~/Downloads/Xcode_16.x.xip   # re-run install if not
```

### Swift host build fails with `posix_spawn: Permission denied`

`/tmp` is likely mounted `noexec`. Re-run with an explicit `TMPDIR`:

```bash
TMPDIR=/home/user/tmp swift test
```

### `xtool auth` loop

xtool uses Apple's developer-services auth, which occasionally needs an app-specific password or 2FA code. If the browser flow doesn't complete, check the xtool docs for current auth troubleshooting at https://github.com/xtool-org/xtool.

### Device not found by `xtool devices`

- Check the USB cable (some are power-only).
- Unlock the device and tap "Trust this computer."
- On Linux you may need `usbmuxd` running — `sudo systemctl start usbmuxd`.

## What's not in this BUILD.md yet

This document covers the current pure-Swift app path. The app lists orgs and
environments, but it does not yet ship an in-app terminal session. The shell
needs the Rust/mobile-native Mesh bridge before it can be enabled again.
