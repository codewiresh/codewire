# Local VMs on Linux

`cw create --local` runs an environment in a VM on your own Linux machine:
Cloud Hypervisor on KVM, with a Codewire guest kernel and guest root. This page
covers what `cw setup --local` installs, what the host needs, running managed
agents in a local VM, and what to do when something fails. For the Mac, see
[MACOS-CLI.md](MACOS-CLI.md).

## Install

Install `cw`, then its local VM runtime:

```sh
curl -fsSL https://get.codewire.sh | sh
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
| `artifacts/cloud-hypervisor` | Cloud Hypervisor v54.0, the upstream static build |
| `artifacts/virtiofsd` | virtiofsd v1.14.0, the upstream static build, for direct host folders |
| `artifacts/kernel` | the Codewire Linux 6.18.48 guest kernel |
| `artifacts/initramfs` | the Codewire guest root (guest init, BusyBox, runc) |
| `runtime.pack`, `cw-runtime.lock.json` | the `cw` that runs inside the VM, for sessions and managed agents |
| `artifacts.lock.json` | the exact size and digest of each file above |

The programs are mode 0500, the other files 0400, and the directories 0700.
You do not need to run setup before every create: creating or starting a local
VM installs the pinned runtime first when it is missing, damaged, or another
`cw` version's. VMs that are already running keep the runtime they started
with. After `cw upgrade`, the next create or start (or `cw setup --local`)
moves to the new runtime, and the previous one is kept beside it, so
`cw upgrade rollback` followed by `cw setup --local` downloads nothing.

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

`cw setup --local`, `cw create --local` and `cw start --local` check
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
cw create --local --name team --profile local:work --path .
cw run --in team --name lead --agent codex --detach --prompt 'Plan the change.'
cw inbox team --session lead
cw wait --message MESSAGE_ID --timeout 10m
```

Before `connect codex`, turn on "Enable device code authorization for Codex" in
ChatGPT's Security settings.

The agent runs the client the VM user's shell runs: the first `codex` or
`claude` on `PATH`, with no pinned version. That is the Codewire workspace
image's Codex and Claude Code until the user, or the client itself, updates
them in the home. The Codewire `cw` that drives the agent inside
the VM comes from the runtime that `cw setup --local` installed.
[CLI-ORCHESTRATION.md](CLI-ORCHESTRATION.md) covers messaging, waiting and
parent and child agents, and
[SECRETS-AND-CREDENTIALS.md](SECRETS-AND-CREDENTIALS.md) covers credentials
and profiles.

## Network policies

A network policy names the destinations an environment may reach. It is named,
reusable and stored on this host. Every edit makes a new revision with its own
digest. Two policies are built in: `open` (every public destination on TCP 22,
80 and 443, what every local VM uses today) and `locked` (nothing). `cw network`
is something else: it manages Mesh networks.

```sh
cw policy --local create work --allow github.com,'*.npmjs.org:443'
cw policy --local create work-plus --from work --allow extra.example.org:443
cw policy --local ls
cw policy --local allow work pypi.org:443     # a new revision
cw policy --local rm work '*.npmjs.org'       # a new revision
cw policy --local check work github.com:22    # Allowed / Refused, with the reason
cw policy --local delete work-plus            # refused while an environment selects it
```

A target is a DNS name, a `*.` pattern (every name under a domain, not the
domain itself) or a public CIDR, with an optional `:PORT`; repeat a target for
more ports. Without a port it allows 22, 80 and 443. Private, loopback,
link-local and metadata destinations can never be allowed. `check` judges a
name by its lookup and its dial port, for a name that answers public addresses.

A local VM selects a policy at create, and `cw update` changes it. A VM with
no selection uses `open`:

```sh
cw create --local --policy work --path .
cw update team --policy locked     # applies to the running VM at once
cw info team                       # Network policy: locked
```

Each start enforces the selected policy's current revision. An edit to a
policy, or a new selection, also applies at once to every running VM that
selects it: new lookups and connections follow the new revision, and every
open connection it refuses is ended. `cw policy allow` and `rm` name the
running VMs that now enforce the edit. A VM whose network could not take it
fails closed, keeps reporting the earlier revision in `cw info` (`· enforces
rev 3 until restarted`) and takes the selection at its next start.
`--policy` is unrelated to `--network`, which joins a Mesh network. A policy an
environment selects cannot be deleted.

## SSH keys in a local VM

A local VM has no SSH key unless its credential profile has one. The key stays
on your host: the VM's `ssh`, `scp` and Git use `SSH_AUTH_SOCK`, the local
credential authority makes each signature, and only signatures reach the VM.

```sh
# Generate a key and set it in profile work in one step; prints the public key
# and GitHub's "add SSH key" link.
cw credentials --local --profile work generate ssh --name work-ssh
# Or use a key you already have.
cw credentials --local add ssh --name my-key --key-file ~/.ssh/id_ed25519
cw credentials --local --profile work set ssh my-key
```

`cw create --local --profile local:NAME` in a terminal asks whether to add
an SSH key when that profile has none (the default is no), then lets you pick
one of your local SSH keys or generate a new one, and sets it in the profile.
Every VM that uses the profile then gets the key. There is no question
without a local profile, and scripts, `--yes` and JSON output never see it.

## Direct mounts

The VM can change anything in a read-write mount, which `--path-mode mount`
(the default) is, `.git` included. Git hooks and settings written there from
inside the VM run on your machine, as you, the next time you use git in that
folder. Mount only folders whose contents you trust the VM with, and use
`--path-mode clone` for code you don't trust.

A direct mount (`mounts:` with `mode: direct`) shares a host directory live
through virtiofsd. Admission binds the directory's device, inode, mount,
owner and filesystem. Every start reopens the path without following a
symlink and refuses a directory that was moved, removed or replaced while the
VM was stopped. A moved directory can be moved back. A removed one cannot
come back, even recreated at the same path, so create the environment again.

A filesystem can give a removed directory's inode number to the next one
created, and ext4 does, so a directory recreated at the same path can match
all of those. The supervisor therefore also records the directory's file
handle, which carries the inode's generation, and a start refuses a directory
whose handle differs. While a VM starts or runs, its shares are held open, so
their inode numbers cannot be reused.

Overlay (including overlay over ext4) gives no file handle. There a start
compares the device and inode alone, and a directory removed and created
again at the same path while the VM is stopped can be shared as if it were the
original. Copying a lower-layer directory up, as any write in it does, keeps
its identity and is not refused.

A share admitted before this check gets its handle recorded at the first
supervisor start after the upgrade, if it still matches then.

## Disk snapshots

A disk snapshot is a reusable copy of a stopped local VM's disks on this host.
Take one once a VM has your toolchain, then start as many environments from it
as you need, each with its own identity:

```sh
cw stop app
cw snapshot create app --name good-toolchain   # mode=reflink, about a second
cw create --local --snapshot good-toolchain --name app2
cw create --local --snapshot good-toolchain --count 3   # good-toolchain-1, -2, -3
cw snapshot ls
cw snapshot inspect good-toolchain
cw snapshot rm good-toolchain   # environments made from it are unaffected
```

**What it holds.** The VM's state disk (`/workspace` and the home; with a live
mount at `/workspace` itself, only the home and kept `vm_only` folders), its Docker
data disk (images, containers, volumes) and its image root with everything
installed into it. Where the state root's filesystem shares blocks between
files (btrfs, XFS), each disk is a reflink and the snapshot costs almost
nothing until the VM or a copy changes. Elsewhere it is a sparse copy, which
holds the disks' allocated bytes at once; `cw snapshot create` checks the free
space first and names what it needs. The snapshot records `consistency: clean`
when the guest shut down cleanly, and `crash` (what a power loss would have
left) after a forced stop. The copy leaves out the guest's selection of the cw
that runs inside the VM, which is bound to the source environment; an
environment made from the snapshot starts with the cw its own create binds.

**Only a stopped VM.** A running VM is refused (`cw stop app` first), and so is
one with an unfinished workspace, runtime or Docker disk change: start it once
so the change completes, then stop it. A previous root kept for a workspace
rollback does not block a snapshot: only the active root is copied, and an
environment made from the snapshot has no rollback root. The snapshot is an independent set of
files: deleting or changing the source never affects it.

**Sign-ins.** Capture removes Codewire's delivered Codex and Claude Code
sign-ins from its copy, never from the source, by the daemon's own rules,
zeroes their blocks, and punches every free block, unwritten extent and block
past a file's end out of the copy, checking each reads back as zeros. An
fs-verity file's Merkle tree, which ext4 keeps past its end, is kept. The first
boot of an environment made from a snapshot clears them again before anything
runs. A
Claude Code credentials file that holds Codewire's sign-in is removed whole, so
another sign-in Claude Code kept in it is not in the snapshot either. Anything
else the VM wrote, such as a `.env` file or shell history, is kept; a snapshot
stays on this host and is private to you. See
[SECRETS-AND-CREDENTIALS.md](SECRETS-AND-CREDENTIALS.md#direct-delivery-exceptions).

**Creating from one.** `cw create --local --snapshot NAME` starts without
provisioning, image install or setup: the image, workspace and disks are the
snapshot's, so `--image`, `--path`, repositories, `--disk` and source flags are
refused. vCPUs and memory are the source's unless `--cpu` or `--memory` says
otherwise. Everything else is decided by the create, as for any `cw create`:

- a new environment ID, machine-id, SSH host key and Mesh enrollment;
- the credential profile and secrets, resolved again under your current
  sign-in. The snapshot records the platform account `cw` was signed in to
  (server, organization and user) from its saved login, without a network
  call, or none when that cannot tell; a create signed in to a different one
  is refused, as a guard against mixing up accounts, not as access control.
  With either side signed out, nothing is compared, and snapshots work offline.
  A login from before this build records no account until your next
  `cw login`, and a re-login with an older `cw` can leave a stale record
  beside the new login (`cw logout` clears it);
- the Mesh network from `--network` or your selection;
- no host ports: publish them with `cw ports ENV --publish PORT`, so several
  copies can run beside the source;
- the network policy from `--policy`, else the source's.

`--count N` (up to 16) names them `NAME-1` onwards, skipping names in use, or
`--name-prefix PREFIX-1` onwards, and creates two at a time.

**Direct mounts.** A VM that mounts host folders directly would share them live
with every environment made from its snapshot, so that create is refused unless
you pass `--share-mounts`. The snapshot keeps each folder's identity, and a
start refuses a folder that was swapped since.

**Space.** A snapshot and the environments made from it share space only until
they change: each copy that diverges takes its own space, and a full host disk
can force a running VM's filesystem read-only. `cw snapshot inspect` shows each
disk's allocated and shared bytes. Snapshots never expire; `cw snapshot rm`
frees one. A removal marks the snapshot's directory first, so it finishes even
if the supervisor stops halfway or loses its snapshot index; a lost index is
otherwise rebuilt from each snapshot's verified manifest.

**Upgrades.** A snapshot keeps the runtime its root was built with, and
garbage collection keeps that runtime while the snapshot exists, so a snapshot
still starts after `cw upgrade`, even once its source is deleted, exactly as an
existing VM does after an upgrade. A disk snapshot holds no VMM state, so it
does not depend on the Cloud Hypervisor version: running VMs keep the VMM they
started with until they restart, the next `cw` release carries Cloud
Hypervisor v54.0, and a snapshot taken from a VM still on the previous one
starts on it.

Disk snapshots need Linux and this `cw`'s supervisor (protocol 19); an older
cw's supervisor still serving your VMs refuses them until `cw upgrade --vms`.
An older supervisor knows nothing of snapshots: after `cw upgrade rollback`, its
garbage collection can remove the runtime a snapshot's root was built with, and
a create from that snapshot then fails until that runtime is installed again.
A snapshot is not a VM checkpoint, which would also keep a running VM's
memory.

## After a cw upgrade

`cw upgrade` stops your local VMs only when you choose their restart. The previous cw's local VM supervisor
keeps serving them, and this cw uses it for everything that does not boot or
reconfigure a VM: listing, `cw run`, `cw shell`, sessions and logs, stopping,
removing and host ports. Starting, creating, restarting or resizing a VM,
updating its sources and refreshing its skills need this cw's own supervisor.
Once none of your VMs runs, the next such command switches over by itself,
without a message, and installs this cw's runtime. While one still runs, the
command says so instead:

```text
your local VMs dev, web still run on the cw you updated from; this cw starts and changes local VMs once they stop (`cw --local stop NAME`)
cw: restart them with `cw upgrade --vms`
```

At a terminal that command also offers to restart them now. To move them
yourself, run `cw upgrade --vms`: it restarts the VMs that still run on the
previous cw, and the flag is your consent, because a restart ends the work
running in them. Each stops the ordinary way, the previous supervisor hands
over, and each starts again on this cw. If a stop or the handover fails, the
VMs it already stopped start again on the previous cw. A VM in an error state
is stopped and stays stopped. Bare `cw upgrade` at a terminal offers the
restart as an unchecked checklist item beside the newer CLI, and
`cw upgrade --cli --vms` upgrades and restarts them without asking; without a
terminal or `--vms`, an upgrade only lists them and changes nothing.

Or stop them when it suits you and run the command again. `cw setup --local`
waits the same way, because the previous supervisor would start its next VM
from the new runtime's files. This cw works with supervisors back to
v0.3.388's; an older one, or a newer one after `cw upgrade rollback`, is
refused with a message that names it. A rollback to a cw without the
updater's VM hand-off (v0.3.389 and earlier) hands the state root to it
while no local VM runs. While one does, it names them: select the newer cw
again (`cw upgrade rollback`), stop them, then roll back.

A VM keeps the guest kernel and root it was created with, so neither an upgrade
nor a rollback moves it to another runtime. A VM created since that kernel
gained fs-verity (6.18.48-codewire3) has ext4's `verity` feature on its state
disk, and the guest seals its cw runtime there. It keeps starting after a
rollback, on its own kernel. A kernel without fs-verity cannot open a sealed
file, and a VM booted on one fails at "Starting the VM". A VM created earlier
keeps its disk as it was.

A supervisor started by a `cw` that is not an installed version, such as a
development build run with your own home directory, is one this cw cannot
verify, so it never uses or ends it. Every local VM command, `cw --local ls`
included, names it and its recovery instead of a retry:

```text
! Local VMs could not be listed: they are served by a cw this one cannot verify (process 4242, /src/codewire/target/debug/cw), not an installed cw version
→ List its VMs with `/src/codewire/target/debug/cw --local ls` and stop any with `/src/codewire/target/debug/cw --local stop NAME`, then end it with `kill 4242`; the next cw command starts this cw's own
```

`cw upgrade` still upgrades the CLI while it runs, and says the VMs were not
checked.

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

**`your local VMs ... still run on the cw you updated from`**: see
[After a cw upgrade](#after-a-cw-upgrade). Restart them on this cw with
`cw upgrade --vms`, or stop them, then rerun the command.

**`Bus error`, or `execute selected workload runtime: I/O error`, from `cw` in a
VM**, or `session exited with code 135` from the host: part of the guest's `cw`
is corrupted on the VM's state disk. The kernel refuses to run those bytes. The VM
still shows `running`, and `cw runtime info` still succeeds, so check the guest's
kernel log (`dmesg | grep "FILE CORRUPTED"`). Other commands keep working in the
VM, so copy your work out, then create the VM again; the disk under it may be
failing, so check that too.

**`this cw is a development build with no pinned local VM runtime`**: install a
release with the install script, or pass `--from DIR` with a runtime directory
built from the same source.

**`Local VMs aren't available on Linux arm64 yet`**: this `cw` release has no
local VM runtime for your host. Local VMs run on x86_64 Linux and on Macs with
Apple silicon. Elsewhere, use hosted Sandboxes with `cw --cloud create`.

**`this local VM runtime was built from X, but this cw from Y`**: the directory
given to `--from` belongs to another build. Use the runtime from the same
release or source as your `cw`.

**`managed VM agents require a selected credential profile`**: the VM has no
profile. Select a local or platform profile with a provider for the agent: a
`codex` slot (or, without one, an `openai` slot) for Codex, or an `anthropic`
slot for Claude: `cw update ENV --profile local:NAME` or
`--profile platform:NAME`. If the error says the profile has no "Codex or
OpenAI" (or "Anthropic") provider, add that slot, for a local profile with
`cw credentials --local --profile NAME set codex CREDENTIAL`. Editing a profile
makes a new revision, and a VM keeps the revision it selected, so run
`cw update ENV --profile local:NAME` again afterwards. A platform profile
counts the slots the VM pinned when its sources were selected.

**A credential command fails to reach the Secret Service**: start or unlock
your keyring. Over SSH or on a headless host, make sure a session bus and a
Secret Service run for your user.

**A stop takes a few seconds**: `cw stop` gives every process in the VM
SIGTERM and up to 5 seconds to exit, kills what is left, and then unmounts the
VM's disks cleanly. A process that ignores SIGTERM makes the stop take about
5 seconds.

**Something else is left behind**: `cw doctor local` reports local VM files and
processes that no environment owns any more, without changing anything. Remove
a VM you no longer need with `cw rm --local NAME --yes`.
