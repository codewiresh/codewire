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

### A runtime built from source

To boot a local VM on a change to the guest (its init, boot seed or `cw`),
build the runtime from the same commit as your `cw`. On an x86_64 Linux host
with Docker, from a clean checkout whose `HEAD` is that commit:

```sh
export TMPDIR=~/.cache/<scratch>/tmp   # executable; /tmp may be noexec
scripts/ci/release/build-local-runtime.sh linux --source-sha "$(git rev-parse HEAD)" \
  --version v0.1.0 --output ~/.cache/<scratch>/runtime
codewire-cpu build -- cargo build -p codewire-cli-bin </dev/null
target/debug/cw setup --local --from ~/.cache/<scratch>/runtime/linux-x86_64
```

- `build-local-runtime.sh linux` is what the release's "Build the local
  runtime's Linux side" job runs. It needs no credential. The kernels come
  from the release parts cache unless your change touches their inputs, and
  Cloud Hypervisor and virtiofsd are pinned downloads. It rebuilds both
  architectures' guest roots and sealed `cw` runtimes in the pinned
  containers, in the local VM slice. The output directory must not exist yet.
- `--version` is the version of the `cw` sealed into the guest. A development
  `cw` reports the workspace version, `0.1.0`.
- `DIR/linux-x86_64` is the runtime directory. A development `cw` built
  without `CODEWIRE_SOURCE_REVISION` warns that it cannot check the runtime's
  source, then installs it.
- Measured on 2026-11-14 at main 97dc3f473 on a 16-core workstation, with
  both kernels cached: the runtime build took 38 minutes and wrote 882 MB, and
  the installed runtime is 202 MB.

## Host requirements

Local VMs need an x86_64 Linux host with:

- **KVM**: hardware virtualization (Intel VT-x or AMD-V) enabled in the
  firmware and the `kvm_intel` or `kvm_amd` module loaded. Your user must be
  able to open `/dev/kvm`, usually by being in the `kvm` group. Inside a VM,
  nested virtualization must be on.
- **Linux 6.2 or later, with Landlock**: `cw` confines the host tools it runs
  with Landlock ABI 3. The Debian 12 and Ubuntu 22.04 GA kernels are too old.
  Ubuntu 22.04 HWE or 24.04, Debian 13 and Fedora work.
- **e2fsprogs**: `mkfs.ext4`, `e2fsck`, `resize2fs` and `debugfs` in
  `/usr/sbin` or `/usr/bin`, owned by root and writable only by root. Your
  distribution's `e2fsprogs` package provides them.
- **git** at `/usr/bin/git`, only for cloning a repository into a VM.
- **A Secret Service**, such as GNOME Keyring or KWallet, running and unlocked
  on your session bus, for local credentials and application secrets, unless
  the credential root uses the file store (`local_credential_store = "file"`,
  below).
- Your own user. `cw` refuses to run local VMs as root.

`cw setup --local`, `cw create --local` and `cw start --local` check
these first. If something is missing, they name every unmet requirement with
its fix, for example:

```text
this host cannot run local VMs yet:
  - you cannot open /dev/kvm. Fix: add yourself to its group: sudo usermod -aG kvm "$USER", then log out and back in.
  - e2fsprogs is missing: e2fsck, resize2fs not found in /usr/sbin or /usr/bin. Fix: install your distribution's e2fsprogs package.
```

A missing git is only a note, since other workspaces do not need it.

### What the qualification smoke checks

`codewire-local-vmm-smoke run` takes one VM through OCI provisioning, restarts
and a guest poweroff, and kills its network worker, egress broker and Mesh
transport to see the VM fail closed. Along the way it checks the VMM's
confinement and the guest's isolation. Nothing in CI runs it.

Its VMM checks are derived for Cloud Hypervisor v54.0, the exact pinned
release, and refuse to run against any other:

- **seccomp:** the VMM runs with exactly one `--seccomp true`. Its main
  thread, the VMM thread and the HTTP API thread each hold exactly one filter
  of their own. Every other thread holds at least two, the VMM thread's and
  its own. A new release needs that layout derived again from its source.
- **Landlock:** native Landlock is on, and its one broadening is write access
  to the VM's own checkpoint directory.

These follow Cloud Hypervisor's thread model and flags, not the host kernel.
They were last run on Linux 7.2.15 (#5748).

## Managed agents in a local VM

A managed agent (`cw run --agent codex` or `--agent claude`) in a local VM uses
a **local credential profile** selected when you create the VM. The provider
credential stays on your host. A broker on the host adds it to the agent's
provider requests, so the VM never holds it.

```sh
# Store a credential. API keys are read from stdin, never from arguments.
cw credentials --local connect codex --name my-codex      # Codex sign-in with a device code
cw credentials --local connect claude --name my-claude    # Claude sign-in: open the link, paste the code back
printf '%s' "$OPENAI_API_KEY" | cw credentials --local add openai --name my-openai
printf '%s' "$ANTHROPIC_API_KEY" | cw credentials --local add anthropic --name my-anthropic

# Put it in a profile. The codex slot takes a Codex sign-in or an OpenAI API key.
cw credentials --local --profile work set codex my-codex
cw credentials --local --profile work set anthropic my-anthropic   # or my-claude, the sign-in

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
80 and 443, what every local VM uses today) and `locked` (nothing, except the
model providers of the credentials you selected, below). `cw network`
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

The managed GitHub credential follows the policy (#4926). On a VM whose
profile has a GitHub connection, Git and `gh` reach GitHub through the
credential route on the host, outside the VM's network, so the policy is
applied to that route as well: it serves the GitHub connection only when the
selected policy allows both `github.com` and `api.github.com` on 443 by rule.
`open` does. `locked` does not, and neither does a policy that names one of the
two hosts, or only an address range. Git and `gh` then fail with a message
that names the network policy, no credential is leased, and GitHub is not
contacted. To use the connection under your own policy, allow both hosts:

```sh
cw policy --local allow work github.com:443
cw policy --local allow work api.github.com:443
```

A selected model credential is not under this rule (SPEC, the interception
paragraph; private-docs `designs/2026-11-10-egress-interception-design.md`,
section 3a). `locked` lets nothing in the environment reach the network by
itself. A model credential you selected for it still reaches its own
provider, and only that: Codewire sends those requests from outside the
environment, with the selected credential, on the paths its route serves.
That holds with interception on and with it off, on the loopback route. Not
yet proven by a test: that any other request to the provider's host is
refused like any other destination (#5215). The GitHub connection is not such
a credential: it follows the policy (#4926). To stop a provider as well,
revoke its credential with `cw credentials --local revoke NAME`, which stops
it at once everywhere that credential is used, not only in this VM. A per-VM
way, `cw policy --local deny HOST`, is #5456.

A change of policy applies to this at once, as it does to the network: the
credential broker that served under the earlier answer is stopped before its
replacement starts. The supervisor decides the answer, from the same selection
the VM's egress broker enforces, and the local credential authority passes it
to the broker it starts. After a `cw` update an earlier credential authority
keeps running while local VMs run, and it cannot apply this rule: under a
policy that does not allow GitHub such a VM gets no credential broker, and
the error says to stop the local VMs so the authority is replaced. The other
way round, a supervisor from before the update does not send the answer, and
the newer authority serves it as before until that supervisor exits.
Repositories the project file or `--repo` names are not under this rule.
Codewire fetches them at create, on the host, in an isolated one-shot
process that can only fetch, never push, and hands the VM a bundle without
the credential. That brings data in and sends none out, so `locked` does not
stop it. What the connection can reach once it is served is unchanged: every
repository it reaches (#4927 narrows that). Hosted Sandboxes do not apply
network policies yet. The journey step is `locked-refuses-managed-github` in
`docs/journeys/network-and-egress.md`.

## A VM that lost its network

Every running local VM has two host processes for its network: the network
worker, which carries the guest's packets, and the egress broker, which makes
each outbound connection and enforces the network policy. Neither is started
again while the VM runs. Losing either fails the VM closed, as on a Mac
([MACOS-CLI.md](MACOS-CLI.md)):

- If the broker ends, the environment turns `error` (`egress_broker_exit`).
- If the worker ends, the environment turns `error` (`network_worker_exit`).
- In both cases, from the second it ends, nothing the guest sends gets out,
  by name or straight to an address. `cw --local start NAME` restores it,
  and so does `cw --local stop NAME` then `cw --local start NAME`.

The credential broker is different: the credential service starts another,
and the agent answers again within seconds
([SECRETS-AND-CREDENTIALS.md](SECRETS-AND-CREDENTIALS.md)).

While the VM is in that state, `cw` says why and what to do:

- `cw --local info NAME` shows the code and how the process ended, for
  example `Error: egress_broker_exit (exited 72: egress_broker_protocol)`,
  then that the VM's network broker stopped, so nothing can leave the VM,
  and the next step, `cw --local start NAME`. For the worker it says the
  VM's network worker.
- `cw exec`, `cw shell` and `cw run` in that VM fail with the same sentence
  and next step.
- `cw ls --output json` carries the code in the VM's `error`, which is
  `null` for a VM with nothing wrong.
- A VM in `error` for any other cause is named too: those commands and
  `error` give its code, where the commands said only that the environment
  is not in the required state.

**Not yet built** (#5359). Today `cw --local info` shows the code line and
nothing under it, `cw exec` says `Failed_precondition: local environment is
not in the required state`, `cw shell` the same, and `cw ls --output json`
has `"error": null`. The VM does fail closed, and `cw --local start NAME`
does restore it (observed on `main`, 2026-11-18, for the broker; for the
worker only the state and the code are observed). The journey step is
`smoke-proxy-down` in `docs/journeys/local-vm-credentials-smoke.md`.

## Host ports

`cw ports ENV --publish PORT`, and `ports:` entries with `host_port` in
`codewire.yaml`, publish a guest port on `127.0.0.1:HOST_PORT`. The
per-environment runner owns those listeners. It carries each accepted
connection through the guest daemon's `ForwardTcp` to the guest port on the
workload's loopback (`127.0.0.1`, then `::1`), made as the workload user, the
same path `ssh -L` through `cw setup ssh` uses (#4347). A server in the VM
bound to `127.0.0.1` or `0.0.0.0` answers; one bound only to the VM's network
address does not. The network worker never sees a host connection.

A connection the daemon can't make is closed, and the runner log records
`host_port_forward_failed` with the guest port and one reason:
`nothing_listens`, `refused` (a platform listener such as the workspace SSH
port), `daemon_unreachable`, or `limit` (256 forwards open at once per VM).

### HTTPS hostnames

A labelled port is also served at `https://<label>-<env>.cw.localhost`
(#4316). The per-user supervisor runs one router (`local_https.rs`) on
`127.0.0.1`, and on `[::1]` where that is free, on port 443 or the port in
`<state root>/local-https/port`. It reads the server name from the
ClientHello and refuses any name that isn't a running environment's labelled
port. It then serves the request with the egress front door's TLS and HTTP
handling and sends it through the same `ForwardTcp` path. A task rebuilds the
name table after every operation and every five seconds, and listens only
while some environment has a labelled port. The CA is
`<state root>/local-https/ca.pem` with its key `ca-key.pem` (mode 0400, in a
0700 directory), name-constrained to `cw.localhost`. The supervisor log
records `local_https_state` with the state and port each time it changes.
Linux needs `net.ipv4.ip_unprivileged_port_start` at 443 or lower, which
`sudo cw local-https setup` sets.

## Docker in a VM

A local VM created without `--no-docker` runs its own Docker daemon inside
the guest, with its data on the VM's Docker disk (`--docker-disk`). Docker
mode gives the workspace root authority over the guest, by design (#2977):
the VM is the boundary, and nothing here changes that.

Inside the VM, Docker behaves as Docker does anywhere (#5418):

- `docker run` starts a container in its own root filesystem, with its own
  process table.
- `docker exec CONTAINER ...` runs in that container. It sees the files the
  container's processes wrote, they see what it writes, and its process
  table is the container's. It does not see the workspace, the guest's own
  files, or the guest's Codewire services and their sockets
  (`/run/codewire`, `/dev/vsock`), unless the container was given them (a
  volume, `--pid=host`).
- The same holds for a container that comes back with the VM: one started
  with `--restart=always` keeps its ID and its files across
  `cw --local stop` and `cw --local start`, and `docker exec` enters it as
  before.

What a process with the guest's root can reach on the host is the same
with or without this fault. No host service listens for the guest: on
Linux and on a Mac, every vsock connection of a local VM is opened from the
host into the guest, where Codewire's guest services listen (the daemon, the
network agent, boot progress, the checkpoint hook and the runtime
publisher), and the native smoke fails a VMM that holds a listener for the
other direction. A guest-root process can answer on those guest ports in
place of Codewire's services. The host does not trust what answers: it
dials only that VM's own socket, and it names the environment, the
generation and the delegation itself, refusing a guest that names another.
So everything in the guest, its root included, is served that VM's own
delegation and nothing more.

**Observed working** on Linux and on a Mac, 2026-11-19 (#5418), with the
steps the journey records. dockerd runs in its own mount namespace
whose root is its private root, moved over `/` as `switch_root` does, so
runc pivots each container into its own root. Before this change (v0.4.22,
and `main` on 2026-11-19, on Linux), `docker run` was right and `docker exec`
was not: it ran in the guest's root instead of the container's. In a
container whose main process writes `/heartbeat` every second, `docker diff`
listed the file and `docker exec CONTAINER cat /heartbeat` said there was
none. The command saw `/workspace`, `/state`, `/generation`, `/run/codewire`
and `/dev/vsock`, a process table of the whole guest with the guest's init as
PID 1, and what it wrote landed in the guest's root. It stayed inside the VM.
The fault itself was not checked on a Mac. The journey step is
`local-vm-docker-exec` in
`docs/journeys/local-vm-docker.md`.

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

**Git trusts the shares' repositories (#5478).** A share's files can belong
to someone other than the workload user. On a Mac they appear as root's, and
on Linux as the host user's uid. So Git would refuse every mounted repository
with "dubious ownership". At every boot of a local VM whose direct-share plan
has at least one share, the guest daemon writes `safe.directory = *` to a file
the product owns, `~/.codewire/gitconfig`. It then adds one `include.path` line
for that file to the workload user's global Git config, only if the line is
missing (`git config --global --fixed-value`). The rules:

- **As the workload user.** The write runs as the workload user, through the
  workload's own launch path (`PreparedProcess`, runc), in the environment a
  launched session gets, so a project's `HOME` or `GIT_CONFIG_GLOBAL` is
  honoured. It never runs from the root guest daemon directly: Git follows
  a symlinked `~/.gitconfig`, and root would write its target.
- **Global scope only.** Never a system file and never root's config. Root's
  Git keeps refusing a repository the workload controls, so nothing the
  platform runs as root trusts one. Under a `sudo` the workload runs
  itself, Git's own rule still trusts a repository owned by the user who
  ran sudo (`SUDO_UID`), with or without this. The product's line never
  reaches root (observed on #5659's walk).
- **Why `*` and not the share paths.** The image's Git (2.43) ignores a
  trailing `/*`, so exact paths would leave submodules, worktrees and a folder
  holding several repositories refused. What `*` trusts beyond the shares is
  a repository the workload user doesn't own: inside a local VM, root's or
  one made through sudo or Docker. The workload user is the least privileged
  principal there, so trusting those gains nobody anything. This holds only
  in a single-user local VM; it is not a pattern for a hosted Sandbox or any
  shared machine (cw-security, #5478).
- **The user's own lines stay.** A user's own `safe.directory` lines are never
  changed, reordered or removed. The product's line lives only in its own
  file, which is rewritten whole at every boot.
- **An image without Git at boot.** An image may get Git only later, for
  example through `apk add git`. Without `git`, the line is appended
  directly to the file Git reads as global: `GIT_CONFIG_GLOBAL`, or else
  `~/.gitconfig`. The Git installed later then trusts the shares too.
- **Failure.** The guest daemon starts before the workspace container, so
  the write is retried for up to 60 seconds. If it still fails, the daemon's
  recent log says so and the boot goes on. A VM without a share leaves Git's
  configuration alone.

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

Disk snapshots need this `cw`'s supervisor (protocol 19), on Linux or a Mac
(docs/dev/MACOS-CLI.md); an older
cw's supervisor still serving your VMs refuses them until `cw upgrade --vms`.
An older supervisor knows nothing of snapshots: after `cw upgrade rollback`, its
garbage collection can remove the runtime a snapshot's root was built with, and
a create from that snapshot then fails until that runtime is installed again.
A snapshot is not a VM checkpoint: `cw checkpoint` also saves a running VM's
memory and device state, so its processes continue after a restore or fork.

## After a cw upgrade

`cw upgrade` stops your local VMs only when you choose their restart. The previous cw's local VM supervisor
keeps serving them, and this cw uses it for everything that does not boot or
reconfigure a VM: listing, `cw run`, `cw shell`, sessions and logs, stopping,
removing and host ports, and taking, listing and removing VM checkpoints.
Starting, creating, restarting or resizing a VM, restoring a VM checkpoint,
updating its sources and refreshing its skills need this cw's own supervisor.
Once none of your VMs runs, the next such command switches over by itself,
without a message, and installs this cw's runtime. While one still runs, the
command says so instead:

```text
your local VMs dev, web still run on the cw you updated from; this cw starts and changes local VMs once they stop (`cw --local stop NAME`)
cw: restart them with `cw upgrade --vms`
```

A restore is refused the same way before it stops the VM it would restore
(#5243), so a refusal changes nothing. Once this cw's supervisor serves, a
VM checkpoint taken under a runtime with another guest ABI is listed as
unrestorable, with the reason; the previous cw, selected again while no VM
runs, restores it (`docs/journeys/local-vm-upgrade.md`).

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

### Credentials after an upgrade

The local credential service is a second long-lived process, apart from the
supervisor, and it outlives an upgrade the same way. Each running VM's
credential broker belongs to the service that started it, so the previous
cw's service keeps serving while a local VM may run. It starts every broker
from its own cw, and a broker serves only a runner that speaks the runner
protocol it was built with. A service from another cw therefore cannot give
a VM that this cw starts its credentials.

- **Which service is another cw's.** A credential service reports the
  runner protocol its brokers accept. This cw treats a running service as
  another cw's when its own protocol is lower than this cw's, when the runner
  protocol it reports is not this cw's, or when it reports none, as every cw
  before #5238 does. The second case is an earlier cw's service after an
  update, and a later cw's after `cw upgrade rollback`. The two protocols
  have separate numbers, and one can change without the other; reading the
  runner protocol from the service is what keeps a service whose brokers no
  runner of this cw accepts from being taken for this cw's own. A service
  whose own protocol is higher than this cw's is refused as before.
- **When it is replaced.** Once none of your VMs may run, the next command
  that boots or reconfigures a VM replaces that service by itself, without a
  message, as it switches the supervisor.
- **While a VM still runs,** a command that would start a VM with a
  credential profile is refused before it changes anything. `cw update`
  and a restart leave the VM they would have restarted running. The
  command names the VMs that still run, and the command that stops one:

  ```text
  your local VMs dev, web keep your local credentials with the cw you updated from, which can't give a VM started by this cw its credentials; it switches to this cw once they stop (`cw --local stop NAME`)
  cw: restart them with `cw upgrade --vms`
  ```

  With one VM it reads `your local VM dev keeps …` and `once it stops`.
  At a terminal the command also offers that restart, with the consent
  `cw upgrade --vms` asks for, since a restart ends the work running in
  them. Restarting the first VM on this cw also replaces the credential
  service, so once they run here the refused command runs again by hand
  and is served. A VM with no credential profile starts as before. One command is not
  refused: `cw --local restart NAME` when NAME is the only VM that keeps the
  other cw's service. Its own stop is what frees the service, so the check
  is made after the stop and the start replaces the service.
- **A sign-in while it serves.** `cw credentials --local connect` saves to
  the credential service that is running. When that is the previous cw's,
  which can't check its store first (#4826), the connect names the VMs that
  keep it and the one step that moves them, before any provider link:

  ```text
  ! Your local VMs dev, web still run on the cw you updated from, and so does your local credential store, so it can't be checked before you sign in. Restarting them on this cw moves it here.
  → cw upgrade --vms
  ```

  At a terminal it offers that restart first, with the same consent. When
  you accept, the VMs restart on this cw, its credential service replaces
  the previous one, and the connect checks the store and carries on in the
  same command. When you decline, or without a terminal, the connect carries
  on unchecked and saves to the previous cw's service, which keeps the
  credential when it is replaced. When no VM can be named, the connect says
  only that the store is still the previous cw's and switches once no local
  VM runs, and it offers nothing.
- **What the logs say.** A start that fails says why in two places, the
  runner's log (`logs/runner-ID.log` under the local VM state) and the
  credential service's broker log (`logs/brokers.log` under the credential
  state):
  - **The helper that ended.** When a helper process of the VM ended during
    the start, the runner's `vm_start_failed` line carries `helper_exit=`:
    the exit code (`code_72`) or the signal (`signal_9`), and after it the
    runner's name for a code it knows (`code_72_egress_broker_protocol`).
    A VMM that goes takes the guest's progress stream with it, and the
    runner usually notices the stream first: it then waits a quarter of a
    second for the exit and reports the exit (`detail=vmm_exited`), not the
    broken stream.
  - **Whether the broker came.** The supervisor tells the runner when it
    starts a credential broker for the generation, and the runner records
    that broker coming: it is the only one that takes a starting
    generation's daemon access from the runner. Every `vm_start_failed`
    line says `broker=connected`, `broker=never`, or `broker=none` for a
    VM no broker is started for, which is one with no credential profile.
  - **The cause, when the evidence is there.** A failed start is reported
    as `credential_broker_unavailable`, in `cw`'s error and the
    supervisor's line for the operation, only when all of this holds for the
    generation: the VM has a credential profile; the guest's daemon had
    answered, which is where the guest starts waiting for its broker; no
    broker had connected; and what the runner saw is not a failure the guest
    reported about itself (its setup, its workspace, missing Docker
    tooling). What the runner saw stays beside it, as `detail=` on the
    runner's line and as `observed=` on the supervisor's
    `operation_failed` line, for example `observed=egress_broker_exited`:
    the guest gives up when its broker never comes, and the other helpers
    end as it goes down. `cw` then fails with
    `start_credential_broker_unavailable` (`create_…` for a create), says
    that the VM's credentials could not be served, and names the broker
    log. Any earlier failure keeps its own code whatever the profile:
    the VMM ending at boot, a helper ending before the guest's daemon
    answers, a guest that shuts down on a bad image. A broker that connected
    and then ended is not covered by this rule.
  - **A helper before the front door.** A helper that ended before the
    front door stopped is the cause, and the front door's stop its
    consequence.
  - **The broker's own word.** A `broker_not_ready` line carries the
    broker's exit status and its last word (`stage`, `kind`) whenever the
    broker has ended: the service waits up to a quarter of a second for a
    broker whose channel closed to end, instead of recording
    `status=running` with no error. A broker that refuses its runner's
    protocol says `kind=runner.protocol_mismatch` with both numbers
    (`broker=14 runner=13`), and one whose runner never said its protocol
    says `kind=runner.no_protocol`. The log replaces every space and `=`
    of that word with `_`, as it does in any value.
  - **After a failed create.** The VM is removed, and the runner's log of
    the failed start is kept as `logs/runner-failed-create-NAME.log`, moved
    there by a rename. The next failed create of that name replaces it, and
    a create of that name that succeeds removes it, so a retry or a second
    create running beside it loses nothing.

**Built in part** (#5238). The first three points are built: a service
reports the runner protocol its brokers accept; one that reports another,
or none, is replaced once no VM may run; and while one still runs, a
command that would start a VM needing the service is refused before it
changes anything. `cw update` is refused whenever the VM's selection before
or after the update needs the service, so also when the update only takes a
profile away. Before the first two, a service
counted as another cw's only by its own protocol number, which v0.4.15 and
v0.4.21 share while their runner protocols differ: with v0.4.21 a service
left running by v0.4.15 is never replaced, not even with every VM stopped,
and from v0.4.22 only because that number happened to move.

**Built of this:** the broker's own word, the helper that ended, whether
the broker came, the cause, and the kept log. **Not yet built:** a helper
before the front door, and the restart that is not refused.
`cw --local restart` of the only VM that keeps the other cw's service is
refused and told to stop that same VM; `cw --local stop NAME` then
`cw --local start NAME` works. The journey step is
`local-vm-upgrade-credentials` in `docs/journeys/local-vm-upgrade.md`.

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

A development build refuses your own store (`.codewire/native-v1` under your
account's home directory, whatever `HOME` says) unless
`CODEWIRE_NATIVE_STATE_ROOT` names a root, so it never starts that supervisor
in the first place (#4819). Run it with its own `HOME`, or set the variable
to a scratch root, or to your store to use it on purpose.

A separate `HOME` or state root keeps VMs and settings apart, not
credentials (#5255). On Linux, local credentials go to the Secret Service on
your session bus, whatever `HOME` or the `CODEWIRE_` variables say. A
`cw` run from a scratch `HOME` stores what it adds in your own keyring, where
any process in your session can read it. Deleting the scratch root leaves
those entries behind: run `cw credentials --local delete NAME` for each
credential first, and the few entries the store keeps for itself still stay.
Every entry is named by a fresh random ID, so two roots never overwrite each
other. To keep a test or a walk out of your keyring, give its root
the file store: `local_credential_store = "file"` in that root's
`config.toml` keeps every credential in `protected-v1` inside the credential
root, so deleting the root deletes them, and needs no session bus. Those
files are not encrypted by `cw`: they are protected by their permissions and
your disk encryption, so use synthetic credentials there. Or run it in a
private session bus and keyring, as
`scripts/ci/verify/lib/local-smoke-isolation.sh` sets one up for the local
VM credentials smoke (#5220). Never script or loop calls to your own Secret
Service: a loop of short D-Bus reads has crashed a desktop keyring daemon
(#5256).

## Root and sudo in a VM

Inside a local VM the workload may become root; the VM is the boundary
(cw-security, 2026-11-19, #5464). With Docker on, the default, the workspace
user's passwordless `sudo` works in a session, an `install_command` and a
startup script, as in a hosted Sandbox, so `sudo apt-get install` does what
the workspace image's documentation says:

- **The workspace container** runs without no-new-privileges, and its
  capability bounding set is the OCI runtime's default: `AUDIT_WRITE`,
  `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `MKNOD`,
  `NET_BIND_SERVICE`, `NET_RAW`, `SETFCAP`, `SETGID`, `SETPCAP`, `SETUID`
  and `SYS_CHROOT`.
- **A session** still starts as the workspace user with no capabilities.
  Only a setuid program from the image, such as `sudo`, raises them. The
  image's root filesystem allows setuid, so the image's `sudo` runs, and
  only root can make a root-owned setuid file there. The workspace, the home
  folder and `/tmp` stay mounted `nosuid`, so nothing the workspace user
  writes there can be setuid.
- **Why it adds nothing:** the workspace user is in the `docker` group,
  which already lets it act as root in the VM through a privileged container
  ("Root inside a local VM" in the Docker guide). The guest holds no
  credential, CA key or network policy; those stay in processes on your
  machine.
- **Unchanged:** the container's namespaces, its masked and read-only paths,
  and the read-only control and plan mounts. Outside the container, the
  guest's init and its helpers, the VMM, the runner, the credential brokers
  and the front door keep no-new-privileges and their own capabilities. No
  seccomp filter is installed for the workload, so none depends on
  no-new-privileges.

With `--no-docker` the workload stays confined, as the Docker guide offers:
no root, the image's root stays `nosuid`, and `sudo` refuses with "no new
privileges". Create the VM with
Docker on to use `sudo`.

Observed on a Linux host and on a Mac, 2026-11-19 (#5464), in a session;
an `install_command` and a startup script are not yet observed. Before this
change every local VM's workload ran with no-new-privileges, and `sudo`
refused in it (reported on v0.4.21). The journey step is `local-vm-sudo` in
`docs/journeys/local-vm-limits.md`.

## Limits inside a VM

### Processes

Everything a VM's workspace runs shares one ceiling of 4,096 processes and
threads: the workspace's own processes and sessions, dockerd, and every
Docker container, however they are nested (#5384). Codewire's own services
in the guest (its init, the daemon and the network agent) are outside it, so
a workload that hits the ceiling cannot starve them. Docker containers
together may hold at most 1,536 of the 4,096, so a container that forks
without end leaves the workspace room to stop it.

- A program that forks past a ceiling gets `EAGAIN` ("Resource temporarily
  unavailable") and keeps running. The VM stays `running`, `cw` still reaches
  it, and the workspace disk is untouched.
- A container at Docker's ceiling is stopped from the workspace as usual:
  `cw exec --in NAME -- docker kill CONTAINER`.
- While the whole workload is at its ceiling, which a program in the
  workspace itself can reach, nothing new can start in it. That includes a
  `cw exec` or a new shell: they fail at once, saying that no process could
  be started, not with a timeout or a lost VM. They work again once
  processes end, and `cw --local restart NAME` clears it at once.
- The guest counts each refusal in the workload's `pids.events` files. The
  workspace does not see them; a privileged container that mounts the
  guest's cgroup hierarchy can read them, which is how the journey checks
  the count.

The ceilings are a guard against a program that runs away, not a boundary
against the VM's own user: whoever can run a privileged container in the VM
can change the guest's cgroups. They are the same for every VM size and on
Linux and macOS hosts, and the numbers are provisional until the headroom is
measured; an idle workload with one container holds about 50.

**Not yet built** (#5384). Today nothing bounds the workload's processes: on
v0.4.22, in a 2 vCPU, 4 GiB VM, a program that forked sleeping children had
about 6,400 alive when `cw exec` stopped answering, and the VM turned `error`
(`guest_shutdown`). `cw --local restart` recovered it and the workspace
survived. The journey step is `local-vm-fork-burst` in
`docs/journeys/local-vm-limits.md`.

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

**`environment_sources_guest_start_failed` or `start_guest_start_failed`
right after a cw upgrade, on a VM with a credential profile**, with
`egress_broker_exited` in the runner's log: the credential service still
running is another cw's, and its broker cannot serve this cw's runner
(see [Credentials after an upgrade](#credentials-after-an-upgrade)). Stop
every local VM (`cw --local stop NAME`) and start them again with v0.4.22 or
later; the first start replaces the service. Until #5238 is built, nothing
names this cause.

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

**A credential or a sign-in never reaches the VM** (Claude Code says "Not
logged in", or an agent has no key): run `cw --local daemon logs ENV` while the
VM is still running. Under `# guest daemon` are the guest daemon's recent
lines, each starting `guest: `; a login it checked reads `claude_login=` or
`codex_login=` and a state such as `Written`, `Denied` or `Unavailable`. Under
`# credential leases` is what the credential authority decided each time the
VM asked: the operation, the route and `admitted`, `denied` or `unavailable`.
No lease line means the VM never asked. The guest's lines are kept in the VM's
memory and the leases in the authority's, so a stop or a restart clears them.
A VM started before the `cw` update that brought this needs one restart.

**A stop takes a few seconds**: `cw stop` gives every process in the VM
SIGTERM and up to 5 seconds to exit, kills what is left, and then unmounts the
VM's disks cleanly. A process that ignores SIGTERM makes the stop take about
5 seconds.

**Something else is left behind**: `cw doctor local` reports local VM files and
processes that no environment owns any more, without changing anything. Remove
a VM you no longer need with `cw rm --local NAME --yes`.
