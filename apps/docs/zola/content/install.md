---
title: Install and sign in
description: Install cw, sign in, keep it current or roll back, check what your machine needs for local VMs, and uninstall.
updated: 2026-10-26
weight: 6
aliases: ["/guides/update"]
---

## Install

```sh
curl -fsSL https://get.codewire.sh | sh
```

```text
==> Installed cw v0.4.1 to /home/user/.local/bin/cw
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
curl -fsSL https://get.codewire.sh | sh -s -- --version v0.4.1   # an exact release
```

The entry `cw` is a symbolic link to one immutable version under
`~/.local/share/codewire/cli/versions/<sha256>/cw`. A running `cw` keeps its
bytes when the default changes, so a long session is never pulled out from
under you. `$XDG_BIN_HOME` and `$XDG_DATA_HOME` replace those defaults when
they are set.

### Shell completion

```sh
cw completion --install          # zsh, bash or fish, from $SHELL
eval "$(cw completion zsh)"      # or generate it yourself
```

## Sign in

Local VMs need no account. For hosted sandboxes, sign in once:

```sh
cw setup --local    # local VMs only: the VM runtime and the SSH config, no account
cw setup            # also signs you in in your browser and picks an organization
```

`cw login` signs in again, `cw whoami` shows who and which server you are
signed in to, and `cw logout` signs out. In scripts and CI, use an
[API key](@/organizations/api-keys.md) instead of a sign-in.

## Update

```sh
cw upgrade                       # at a terminal: choose the newer CLI and VM restarts
cw upgrade --cli                 # the stable channel without asking; refuses a downgrade
cw upgrade status --json
cw upgrade --version v0.3.400    # an explicit signed release, downgrade allowed
cw upgrade rollback              # the previous version
cw upgrade rollback --to 0.3.39  # a retained version by package version or digest prefix
```

Releases come from `releases.codewire.sh` and are signature-checked. Every
installed version is retained, so a rollback downloads nothing. A `cw` that is
running keeps its bytes: the upgrade only changes which version the
`~/.local/bin/cw` link points to.

At a terminal, bare `cw upgrade` checks for a newer stable `cw` and for local
VMs that would be left on an older one, and offers what applies as a
checklist: the CLI checked, the VM restart unchecked. Space toggles, Enter
applies, Escape or Ctrl-C changes nothing. In a script, bare `cw upgrade`
upgrades the CLI only. `cw upgrade` never changes an environment; that is
`cw update ENV`.

## Local VMs across an upgrade

`cw upgrade` never stops your local VMs unless you choose the restart. The
previous version's VM supervisor keeps serving them, and the new `cw` uses it
for everything that does not boot or reconfigure a VM: listing, `cw run`,
`cw shell`, sessions and logs, stopping, removing and host ports. Creating,
starting, restarting or resizing a VM needs the new supervisor, so while an
old VM still runs such a command says:

```text
your local VMs dev, web still run on the cw you updated from; this cw starts and changes local VMs once they stop (`cw --local stop NAME`)
cw: restart them with `cw upgrade --vms`
```

Once none of your VMs runs, the next such command switches over by itself and
installs the new runtime. To move running VMs now:

```sh
cw upgrade --vms          # restart them onto this cw; a restart ends the work in them
cw upgrade --cli --vms    # upgrade the CLI, then restart them
```

Each VM stops the ordinary way, the supervisors hand over, and it starts again
on the new `cw`. Without `--vms` (or the checked checklist item) an upgrade
only lists the VMs left on an older `cw`. After a rollback, `cw setup --local`
reinstalls the previous runtime from the copy it kept beside the current one.

`cw` works with VM supervisors back to v0.3.388's; an older one is refused
with a message that names it.

## Runtime inside the VM

The `cw` that runs inside a local VM, for sessions and managed agents, comes
from the runtime `cw setup --local` installed; a VM keeps the runtime it
started with until it restarts.

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

## FAQ

**Does `cw upgrade` stop my local VMs?** Only if you choose to restart them.
They keep running on the previous version until you check the restart in
`cw upgrade`'s checklist or run `cw upgrade --vms`.
