---
title: Install the CLI
description: Install a managed cw with one command, then keep it current with cw upgrade.
weight: 1
---

```sh
curl -fsSL https://get.codewire.sh | sh
```

`get.codewire.sh` redirects to the installer at `https://codewire.sh/install.sh`,
which you can also fetch directly. The installer needs only a POSIX shell,
`curl` and a SHA-256 tool. It downloads the stable release for your platform
(Linux x86_64 and arm64, macOS Apple Silicon and Intel), checks it against the
release's `SHA256SUMS`, and installs it as a managed `cw`.

Check the result:

```sh
cw --version
cw --help
```

`cw --help` groups every command: get started, environments, sessions, agents,
secrets and credentials, networking, organizations and billing, and `cw`
itself.

## What a managed install is

The entry `~/.local/bin/cw` is a symbolic link to one immutable version under
`~/.local/share/codewire/cli/versions/<sha256>/cw`. A running `cw` keeps its
bytes when the default changes, so a long session is never pulled out from
under you. `$XDG_BIN_HOME` and `$XDG_DATA_HOME` replace those defaults when
they are set.

Make sure `~/.local/bin` is on your `PATH`.

## Keep it current

```sh
cw upgrade            # choose the newer CLI (and any VM restarts) from a checklist
cw upgrade status     # what is installed and selected
cw upgrade rollback   # go back to the previous version
```

`cw upgrade` installs only signed releases and refuses a regression on the
stable channel. Local VMs keep running across an upgrade unless you choose
their restart; see
[Update cw](@/guides/update.md).

## Shell completion

```sh
cw completion --install          # zsh, bash or fish, from $SHELL
eval "$(cw completion zsh)"      # or generate it yourself
```

## Next

- [Your first local VM](@/getting-started/local-vm.md): `cw setup --local`
  installs the VM runtime your release pins.
- [Your first hosted sandbox](@/getting-started/hosted-sandbox.md): `cw setup`
  signs you in and picks an organization.
