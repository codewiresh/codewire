---
title: Install and sign in
description: Install cw, sign in, check what your machine needs for local VMs, and uninstall.
updated: 2026-11-14
weight: 6
aliases: ["/guides/update"]
---

## Install

```sh
curl -fsSL https://get.codewire.sh | sh
```

```text
==> Installed cw v0.4.19 to /home/user/.local/bin/cw
```

`get.codewire.sh` redirects to the installer at `https://codewire.sh/install.sh`,
which you can also fetch directly. The installer needs only a POSIX shell,
`curl` and a SHA-256 tool. It downloads the stable release for your platform
(Linux x86_64 and arm64, macOS Apple Silicon and Intel), checks it against the
release's `SHA256SUMS`, and installs it as a managed `cw`: in
`/usr/local/bin` when you can write to it, otherwise in `~/.local/bin`. A
`NOTE` line names the directory to add to your `PATH` when it is missing.
Pass options after `sh -s --`:

```sh
curl -fsSL https://get.codewire.sh | sh -s -- --prefix ~/tools   # into ~/tools/bin
curl -fsSL https://get.codewire.sh | sh -s -- --version v0.4.19  # an exact release
```

### Shell completion

```sh
cw completion --install          # zsh, bash or fish, from $SHELL
eval "$(cw completion zsh)"      # or generate it yourself
```

## Sign in

Local VMs need no account. Hosted sandboxes need a Codewire
[account and organization](@/organizations/account.md); sign in once:

```sh
cw setup --local    # local VMs only: the VM runtime and the SSH config, no account
cw setup            # also signs you in in your browser and picks an organization
```

`cw login` signs in again, `cw whoami` shows who and which server you are
signed in to, and `cw logout` signs out. In scripts and CI, use an
[API key](@/organizations/api-keys.md) instead of a sign-in.

## Update

`cw upgrade` updates `cw` from signed releases and `cw upgrade rollback`
goes back to the previous version. See [Update and roll back](@/update.md).

## System requirements

`cw` itself runs on Linux (x86_64 and arm64) and macOS (Apple Silicon and
Intel), and that is all hosted sandboxes need. Local VMs need more;
`cw setup --local`, `cw create --local` and `cw start --local` check these
first and name every unmet one with its fix.

**Linux** (x86_64):

- KVM: Intel VT-x or AMD-V enabled, the `kvm_intel` or `kvm_amd` module
  loaded, and your user able to open `/dev/kvm` (usually the `kvm` group).
- `vhost_vsock` loaded, with `/dev/vhost-vsock` readable and writable by you.
- Linux 6.2 or later with Landlock. Ubuntu 22.04 HWE or 24.04, Debian 13 and
  Fedora work; the Debian 12 and Ubuntu 22.04 GA kernels are too old.
- `e2fsprogs` (`mkfs.ext4`, `e2fsck`, `resize2fs`, `debugfs`).
- `git` at `/usr/bin/git`, only to clone a repository into a VM.
- A Secret Service (GNOME Keyring, KWallet) running and unlocked, for local
  credentials and application secrets.
- Your own user: `cw` refuses to run local VMs as root.

**macOS**: an Apple Silicon Mac on macOS 26 or later. The runtime ships its
own `git` and `e2fsprogs`; nothing else is installed.

## Uninstall

1. Remove the environments you no longer want. Local VMs: `cw --local ls`,
   then `cw rm NAME`. Hosted sandboxes keep running, and are billed, until you
   remove them with `cw rm NAME` or from the dashboard.
2. Take `cw`'s block out of your SSH config:

   ```sh
   cw setup ssh remove
   ```

3. Delete `cw` and its files:

   ```sh
   rm -f ~/.local/bin/cw                 # or /usr/local/bin/cw, or PREFIX/bin/cw
   rm -rf ~/.local/share/codewire ~/.cache/codewire ~/.codewire ~/.config/cw
   ```

Local credentials keep their secret material in the Secret Service (Linux)
or the Keychain (macOS); remove the Codewire entries there too. Your
organization and its hosted data stay until an owner deletes them; see
[Account and organization](@/organizations/account.md).
