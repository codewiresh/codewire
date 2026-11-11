# Building the Codewire iOS app

The app builds with [xtool](https://github.com/xtool-org/xtool) on Linux or
with Xcode on a Mac. Its terminal is Rust: `crates/codewire-client-ffi`, the
same shell `cw shell` runs, linked as an xcframework that only a Mac can build
today (see "The shell" below). Without that xcframework the app builds and runs
without a shell, and the host tests run as before.

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
   swift sdk list    # verify the iOS SDK is registered
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

## The shell

The terminal's connection is `codewire_client::hosted_shell`, the loop
`cw shell` runs: the environment's tailnet (direct UDP, then UDP relay, then
DERP), the API when the tailnet can't connect, and reattaching to the same shell
after a drop. `crates/codewire-client-ffi` puts it behind a UniFFI surface:
`Shell.dial`, `read`, `write`, `resize`, `close`, and the connection's state
through `ShellObserver`.

On a Mac with Xcode and the Rust targets `aarch64-apple-ios` and
`aarch64-apple-ios-sim`:

```bash
apps/ios/scripts/build-rust.sh          # release; `debug` for a faster build
```

This writes `Frameworks/CodewireClientFFI.xcframework` (git-ignored, about
530 MB before the app links and strips it). `Package.swift` declares the shell
only when that file exists, so the app then has a terminal. In the Simulator:

```bash
cd apps/ios
xcodebuild test -scheme Codewire -destination "platform=iOS Simulator,name=iPhone 18 Pro"
```

The Swift bindings (`Sources/CodewireClientFFI`, and the header and module map
in `FFI/include`) are generated and committed. After changing the crate's
exported surface, regenerate them on any host with Rust:

```bash
apps/ios/scripts/generate-bindings.sh
```

CI runs the same check without updating, and fails when they differ.

## Troubleshooting

### xtool can't find the iOS SDK

```bash
swift sdk list       # is an iOS SDK registered?
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

## Not yet

- Building the shell's xcframework with xtool on Linux (#3825).
- The Ghostty terminal in place of SwiftTerm (#3825).
