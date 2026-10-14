# Local VMs on Linux

`cw env create --local` runs an environment in a VM on your own Linux machine:
Cloud Hypervisor on KVM, with a Codewire guest kernel and guest root. This page
covers what `cw setup --local` installs, what the host needs, running managed
agents in a local VM, and what to do when something fails. For the Mac, see
[MACOS-CLI.md](MACOS-CLI.md).

## Install

Install `cw`, then its local VM runtime:

```sh
curl -fsSL https://codewire.sh/install.sh | sh
cw setup --local
```

`cw setup --local` checks the host first (see [Host requirements](#host-requirements))
and then installs the runtime that this `cw` release pins. A release's `cw`
carries the exact digest of every runtime file, so setup downloads exactly
those files and checks each one before it is used. It prints
`Local VM runtime installed (<id>).`, or `Local VM runtime is installed and
intact (<id>).` when nothing was missing. Running it again downloads nothing.

The runtime lives in `~/.cache/codewire/local-vmm-v1/`:

| File | What it is |
| --- | --- |
| `artifacts/cloud-hypervisor` | Cloud Hypervisor v53.0, the upstream static build |
| `artifacts/virtiofsd` | virtiofsd v1.14.0, the upstream static build, for direct host folders |
| `artifacts/kernel` | the Codewire Linux 6.18.48 guest kernel |
| `artifacts/initramfs` | the Codewire guest root (guest init, BusyBox, runc) |
| `runtime.pack`, `cw-runtime.lock.json` | the `cw` that runs inside the VM, for sessions and managed agents |
| `artifacts.lock.json` | the exact size and digest of each file above |

The programs are mode 0500, the other files 0400, and the directories 0700.
You do not need to run setup before every create: creating or starting a local
VM installs the pinned runtime first when it is missing, damaged, or another
`cw` version's. VMs that are already running keep the runtime they started
with. After `cw update`, the next create or start (or `cw setup --local`)
moves to the new runtime, and the previous one is kept beside it, so
`cw update rollback` followed by `cw setup --local` downloads nothing.

A development build of `cw` pins no runtime. Give it a runtime directory built
from the same source with `cw setup --local --from DIR`. Setup refuses a
runtime built from other source, and `--replace` overwrites a different
installed runtime.

## Host requirements

Local VMs need an x86_64 Linux host with:

- **KVM**: hardware virtualization (Intel VT-x or AMD-V) enabled in the
  firmware and the `kvm_intel` or `kvm_amd` module loaded. Your user must be
  able to open `/dev/kvm`, usually by being in the `kvm` group. Inside a VM,
  nested virtualization must be on.
- **vhost-vsock**: the `vhost_vsock` module loaded, with `/dev/vhost-vsock`
  readable and writable by your user.
- **Linux 6.2 or later, with Landlock**: `cw` confines the host tools it runs
  with Landlock ABI 3. The Debian 12 and Ubuntu 22.04 GA kernels are too old.
  Ubuntu 22.04 HWE or 24.04, Debian 13 and Fedora work.
- **e2fsprogs**: `mkfs.ext4`, `e2fsck`, `resize2fs` and `debugfs` in
  `/usr/sbin` or `/usr/bin`, owned by root and writable only by root. Your
  distribution's `e2fsprogs` package provides them.
- **git** at `/usr/bin/git`, only for cloning a repository into a VM.
- **A Secret Service**, such as GNOME Keyring or KWallet, running and unlocked
  on your session bus, for local credentials and application secrets. On Linux
  they are stored only there.
- Your own user. `cw` refuses to run local VMs as root.

`cw setup --local`, `cw env create --local` and `cw env start --local` check
these first. If something is missing, they name every unmet requirement with
its fix, for example:

```text
this host cannot run local VMs yet:
  - you cannot open /dev/kvm. Fix: add yourself to its group: sudo usermod -aG kvm "$USER", then log out and back in.
  - vhost-vsock is not loaded (/dev/vhost-vsock does not exist). Fix: sudo modprobe vhost_vsock; to load it at every boot: echo vhost_vsock | sudo tee /etc/modules-load.d/vhost_vsock.conf.
```

A missing git is only a note, since other workspaces do not need it.

## Managed agents in a local VM

A managed agent (`cw run --agent codex` or `--agent claude`) in a local VM uses
a **local credential profile** selected when you create the VM. The provider
credential stays on your host. A broker on the host adds it to the agent's
provider requests, so the VM never holds it.

```sh
# Store a credential. API keys are read from stdin, never from arguments.
cw credentials --local connect codex --name my-codex      # Codex sign-in with a device code
printf '%s' "$OPENAI_API_KEY" | cw credentials --local add openai --name my-openai
printf '%s' "$ANTHROPIC_API_KEY" | cw credentials --local add anthropic --name my-anthropic

# Put it in a profile. The codex slot takes a Codex sign-in or an OpenAI API key.
cw credentials --local --profile work set codex my-codex
cw credentials --local --profile work set anthropic my-anthropic

# Create the VM with that profile, then start agents in it.
cw env create --local --name team --profile local:work --path .
cw run team --name lead --agent codex --detach --prompt 'Plan the change.'
cw inbox team lead
cw wait --message MESSAGE_ID --timeout 10m
```

Before `connect codex`, turn on "Enable device code authorization for Codex" in
ChatGPT's Security settings.

The agent runs the client pinned in the Codewire workspace image (Codex and
Claude Code at the image's versions), not one found on `PATH`. With an image
that has no pinned client, `cw run --agent` runs the client from `PATH` and
says so in one line on stderr. The Codewire `cw` that drives the agent inside
the VM comes from the runtime that `cw setup --local` installed.
[CLI-ORCHESTRATION.md](CLI-ORCHESTRATION.md) covers messaging, waiting and
parent and child agents, and [SECRETS.md](../SECRETS.md) covers credentials
and profiles.

## Troubleshooting

**`this host cannot run local VMs yet`**: fix each listed item, then rerun the
command. After `usermod`, log out and back in so the new group applies.

**`this cw needs its local VM runtime (...) ... install it with cw setup --local`**:
the runtime could not be downloaded when the VM was created or started.
Reconnect to the network and run `cw setup --local`. With an application
firewall, allow the `cw` executable (installed under
`~/.local/share/codewire/cli/versions/`) to reach `releases.codewire.sh` over
HTTPS for the runtime, and `ghcr.io` and `pkg-containers.githubusercontent.com`
for the workspace image (`ghcr.io/codewiresh/workspace`).

**`this cw is a development build with no pinned local VM runtime`**: install a
release with the install script, or pass `--from DIR` with a runtime directory
built from the same source.

**`Local VMs aren't available on Linux arm64 yet`**: this `cw` release has no
local VM runtime for your host. Local VMs run on x86_64 Linux and on Macs with
Apple silicon. Elsewhere, use hosted Sandboxes with `cw env create --platform`.

**`this local VM runtime was built from X, but this cw from Y`**: the directory
given to `--from` belongs to another build. Use the runtime from the same
release or source as your `cw`.

**`managed VM agents require a selected local credential profile`**: the VM has
no profile. Select one that has a `codex` slot for Codex or an `anthropic` slot
for Claude: `cw env update ENV --profile local:NAME`. If the error says the
profile has no `codex` (or `anthropic`) provider, add that slot with
`cw credentials --local --profile NAME set codex CREDENTIAL`. Editing a profile
makes a new revision, and a VM keeps the revision it selected, so run
`cw env update ENV --profile local:NAME` again afterwards.

**A credential command fails to reach the Secret Service**: start or unlock
your keyring. Over SSH or on a headless host, make sure a session bus and a
Secret Service run for your user.

**A stop takes a few seconds**: `cw env stop` gives every process in the VM
SIGTERM and up to 5 seconds to exit, kills what is left, and then unmounts the
VM's disks cleanly. A process that ignores SIGTERM makes the stop take about
5 seconds.

**Something else is left behind**: `cw doctor local` reports local VM files and
processes that no environment owns any more, without changing anything. Remove
a VM you no longer need with `cw env rm --local NAME --yes`.
