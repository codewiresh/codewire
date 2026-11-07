# macOS CLI developer loop

This guide covers `cw` and local VMs on an Apple Silicon Mac: installing,
what the local runtime does and does not do, the command boundary, and the
developer fixtures. [ARCHITECTURE.md](../ARCHITECTURE.md) describes the
product; successful fixtures are not product parity.

## Installing cw from source on a Mac

From a checkout on the Mac, `make cli-install` builds a release `cw` with its
source provenance and installs it as a managed installation behind
`~/.local/bin/cw`. It needs the Xcode Command Line Tools, the repository's Rust
toolchain through rustup, and Python 3.11 or newer for `scripts/dev/build-cw.py`.
The Command Line Tools' `/usr/bin/python3` is 3.9, so install a newer one first,
for example with `brew install python`, and put `~/.local/bin` on `PATH`.
A `cw` built by `cargo build` alone has no provenance and `cw install --managed`
refuses it.

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

Or stop them when it suits you and run the command again. On a Mac a
supervisor's exit stops its VMs, which is why the switch waits until none runs. `cw setup --local`
waits the same way, because the previous supervisor would start its next VM
from the new runtime's files. This cw works with supervisors back to
v0.3.388's; an older one, or a newer one after `cw upgrade rollback`, is
refused with a message that names it. A rollback to a cw without the
updater's VM hand-off (v0.3.389 and earlier) hands the state root to it
while no local VM runs. While one does, it names them: select the newer cw
again (`cw upgrade rollback`), stop them, then roll back.

## Current macOS command boundary

`cw create --local`, `cw ls`/`info`/`start`/`stop`/`rm` and `cw run`
drive real local VMs on Apple Silicon through the same supervisor,
runner, guest and daemon as Linux. The VMM is the signed
`codewire-vz-runner vm --config FILE` helper (Virtualization.framework) instead
of Cloud Hypervisor. It inherits the open `vm.lock`, stops its VM when its runner
exits, and serves guest vsock ports on one hybrid-vsock socket. Stop asks the
guest to power off, then sends SIGTERM, then SIGKILL.

Virtualization.framework does not count time in which the VM does not run,
so while the Mac sleeps a guest's clocks stop and then lag the host's (an idle
VM on a Mac that idle-sleeps fell 23 minutes behind in 83 minutes), while the
VM's PL031 RTC keeps the host's time. Launch projections carry a 30-second
deadline checked against the guest wall clock, so the guest follows the RTC:
once a second, when its wall clock is two or more seconds off, it sets it to
the RTC's next second. A VM that did so stayed within a second of the host
across the same sleeps. Monotonic clocks inside the guest still lose the time
the VM did not run.

A local VM needs:

- an artifact lock at `~/.cache/codewire/local-vmm-v1/artifacts.lock.json` with
  `vz_runner`, `kernel` and `initramfs` entries (arm64, exact size and SHA-256),
  beside an `artifacts/` directory holding those files. A release's cw pins
  its runtime (#2539): `cw setup --local` downloads exactly the files whose
  digests that cw embeds, from the release origin, and installs them. A
  development build pins nothing; `cw setup --local --from DIR` installs a
  runtime directory that `make macos-local-runtime` builds (see
  [Install the local VM runtime](#install-the-local-vm-runtime)). Before a
  local VM is created or started, a release's cw requires its own pinned
  runtime, including its cw runtime pack, and otherwise says to run
  `cw setup --local`. That is the check after `cw upgrade`. Running VMs keep
  the runtime they started with. The replaced runtime is kept beside the
  current one (`.runtime-previous`), and setup reuses any file the host already
  holds. So after `cw upgrade rollback`, `cw setup --local` reinstalls the
  previous runtime without downloading, and re-running setup downloads
  nothing. Setup never downloads the component sources a release publishes
  beside the runtime. The helper
  must be signed with `com.apple.security.virtualization`. A missing or
  unentitled helper fails create with `create_vz_helper_missing` or
  `create_vz_helper_unentitled`. Artifact admission is exact: the lock is mode
  0400, the helper and e2fsprogs programs 0500, the kernel, initramfs and
  `mke2fs.conf` 0400, and every directory 0700; anything else fails create with
  `create_failed`.
- nothing installed for ext4 disks or Git workspaces. The runtime ships a
  pinned e2fsprogs (`mkfs.ext4`, `e2fsck`, `resize2fs`, `debugfs` and
  `mke2fs.conf`) and git 2.56.0 (`git` and its `git-remote-https` helper,
  linked only to stock system libraries), admitted with the runtime and
  re-hashed before each use. Git runs with no system or user configuration,
  helpers only from the runtime (`GIT_EXEC_PATH`) and no templates; the Xcode
  Command Line Tools and Homebrew are never used. A missing or changed
  program fails with an instruction to reinstall the runtime. Linux hosts use
  their system git and e2fsprogs.
- for managed agents and the live in-guest cw runtime, a sealed aarch64
  `cw-runtime.lock.json` and `runtime.pack` beside the artifact lock, and a
  guest root with the trusted live cw publisher. Without them, create still
  works, but the VM has no cw runtime catalog (see
  [Managed agents and the cw runtime](#managed-agents-and-the-cw-runtime)).
- a state root whose socket paths fit Darwin's 103-byte limit; a longer root is
  refused before any effect.
- an image with a `linux/arm64` variant. An amd64-only image, such as the current
  default workspace image, fails with `create_registry_platform` and says so.
- `--no-docker` for an image without Docker tooling (for example
  `ubuntu:24.04`), exactly as on Linux. Without it the guest reports the
  missing `dockerd`/`xtables-nft-multi` before readiness and create fails with
  `create_guest_docker_tooling_missing`, suggesting `--no-docker`.

A failed create leaves nothing behind, as on Linux. The supervisor fails the
create and begins the ordinary delete of what it recorded (runner, VM
directory, disks, record) in one step, so a crash mid-cleanup resumes at the
next start. The CLI prints the create's own code and reason, then "Nothing was
kept." only once the environment is confirmed gone; if removal could not
finish, it names `cw --local rm NAME` instead. A create for a name that
already exists fails at once, records nothing, and names `cw --local rm`
or another `--name` as the fix.
Environments that a failed create left in `error` before this change are
removed the next time the supervisor starts.

### Workspaces, shares and disks

These follow the Linux contract and messages:

- `--path P` (default: the current directory) with
  `--path-mode mount|copy|clone|empty`. `mount`, the default, mounts
  the directory live and read-write at `/workspace/<directory name>` and starts
  there, so host and guest edit the same files; guest root can change or delete
  them. Linux needs `virtiofsd` in the runtime lock for this; without it the
  default falls back to a one-time `copy` and says so. `copy` copies the
  directory once as it is, including uncommitted and ignored files. `clone`
  uses `/usr/bin/git` and contains only the committed tree at `HEAD`; a dirty
  Git root is refused for `clone` (use `copy` instead). Copied or cloned
  content larger than `--disk` fails with "workspace content does not fit on
  the requested disk". `empty` starts with an empty `/workspace`.
- No mode mounts or copies a directory the share policy refuses: the home
  directory itself, a directory that contains it, a top-level system
  directory, or a credential store such as `~/.ssh`. Run from such a directory,
  the default starts with an empty `/workspace` and says why; an explicit mode
  fails.
- In a terminal, `cw create --local` shows the name (from the directory),
  workspace, image, resources, Docker, credentials and ports it will use and
  offers **Create environment**, **Edit settings** and **Cancel**. Editing
  chooses one setting at a time, with resolved values as defaults. Escape,
  Ctrl-C or closed input cancels before creating a VM. `--yes`, `-o json` and
  non-terminal input skip the review. While it works, one live line names the current stage (sources,
  disk, image, VM, boot) and elapsed time.
- Repositories declared in `codewire.yaml` (`repositories:` with `source`,
  optional `branch`, `destination`) are fetched by host Git into a
  digest-bound bundle. As on Linux, repeatable `cw create --local --repo
  URL[@branch][::/workspace/path]` (or positional URLs) selects the same
  isolated clones and replaces the file's list. An SSH source needs a selected credential
  profile with an SSH key and the server's `known_hosts` in `codewire.yaml`
  (a github.com source may omit them: GitHub's published keys are its default);
  the repository executor checks it out as on Linux (see below). Without a
  key, a github.com source in SSH form is fetched through the profile's GitHub
  connection instead, and its origin stays as written. A GitHub
  HTTPS repository that needs authentication needs a GitHub connection in the
  profile (`cw credentials --local connect github`, or a platform profile).
  Otherwise such a repository fails with "remote Git preparation failed".
- Direct mounts (`mounts:` with `mode: direct` and `read_only`) use
  Virtualization.framework's own virtio-fs device instead of virtiofsd, with
  the same guest tag (`cw-direct-NN`) and mount. Admission requires a
  canonical APFS directory owned by you, reached without any symlink,
  outside broad system roots (`/System`, `/Users`, `/private/tmp`, ...), your
  home directory itself, credential stores (`~/.ssh`, `~/Library/Keychains`,
  ...) and Codewire's own state, that is neither a mount root nor contains a
  mount. Read-only mounts refuse every write; a symlink inside a mount
  resolves in the guest, never on the Mac; hard links cannot cross mounts.
  The guest sees shared files as owned by root, and files it creates belong
  to you on the Mac. Because Virtualization.framework shares a directory by
  path, the runner and helper check the admitted device and inode before and
  after VM start. A source that is moved, removed or replaced while stopped
  fails start with `start_direct_share_changed`; put the original directory
  back to recover. While running, guest operations on a replaced root fail
  (EPERM) rather than reach the replacement, and the next `cw` command stops
  that VM and marks the environment `error`.
- Kept folders (`workspace.vm_only` patterns, default `node_modules`,
  `target` and `.venv`) work as on Linux: the same guest init expands the
  patterns at every start and binds a folder on the VM's disk over each
  match in the live mount, and a copy leaves the matches out. Patterns match
  case-sensitively while APFS looks names up without case, so a pattern
  without wildcards can bind a folder whose name differs only in case.
  Virtualization.framework caches lookups, so after the host deletes or
  replaces a kept folder the guest may take a little longer to notice and
  bind it again.
- `cw resize ENV --disk|--cpu|--memory` grows the disk offline with the
  runtime's pinned `e2fsck`/`resize2fs` and restores the prior running state;
  shrinking is refused. `cw refresh-skills` re-snapshots user and
  repository skills (including skills inside a direct mount).
- A dedicated Docker data disk (`--docker-disk`, 8 GiB by default) is a sparse
  ext4 image attached as `CWDOCKER1` and mounted at `/var/lib/docker`.

This is the product topology: the network worker and egress broker are host
processes under Seatbelt, and no service VM is used.

The network worker runs under a deny-all Seatbelt profile installed where Linux
installs Landlock and seccomp; it keeps only the descriptors it holds or
receives (and may still create an unnamed socketpair). A connected TCP stream it
receives after confinement stays usable. Each confined process refuses to start
when its profile is not applied; Seatbelt reports a refused profile as an error
and leaves the process unconfined, never partly confined
(`a_profile_seatbelt_refuses_is_an_error_and_confines_nothing`). The
`native_network_worker_confinement` test runs the real `cw` worker and broker,
completes the product bootstrap, and reads the serving worker's descriptor
table with libproc, as Linux reads `/proc/<pid>/fd`: standard I/O on
`/dev/null`, kqueues, and Unix sockets that lead only to the runner, the broker
or back into the worker; no file and no internet socket. `lsof` of a worker
serving a running VM shows the same table. The egress broker runs under its own
Seatbelt profile, installed at the same point: it may dial TCP to any address
and run its own DNS (bind a UDP port, send to port 53, receive the reply);
files, processes, signals, Mach services, Unix sockets, TCP listeners and UDP
to other ports are refused. The egress policy, not the profile, decides which
destinations it dials. `sandbox_check` against a live broker reports file
reads, writes, exec and fork as denied, and Seatbelt logs each as
`Sandbox: cw(PID) deny(1) ...`. Guest egress goes through
that broker under the developer policy: libc name resolution and HTTPS work,
while link-local metadata, private ranges and ports other than 22, 80 and 443
are refused. The broker dials before the guest's handshake completes, so a
refused destination, or one the broker cannot reach (a host firewall blocking
the broker, a closed port), is answered at once with RST: the guest sees a
refused connection, never a timeout or a reset after connecting (#3003).
BusyBox `nslookup` and libc resolution
both work. Losing either process fails the environment closed, and
`cw stop`/`start` restores egress. Observed on macOS 26 with a guest loop
probing HTTPS once a second:

- If the worker is killed, the environment turns `error`
  (`network_worker_exit`) and the broker exits with it.
- If the broker is killed, the environment turns `error` (`egress_broker_exit`);
  the confined worker remains but cannot dial.
- In both cases, from the second of the kill on, every probe fails, and no
  process of the environment holds an internet socket.

Host ports from `codewire.yaml` (`host_port`/`guest_port`), and those published
on a running environment with `cw --local ports ENV --publish PORT`, work as on
Linux: the runner listens on 127.0.0.1 only, so the LAN address is refused, a
stop or `cw --local ports ENV --unpublish PORT` releases the port, and the published set persists
across restarts. macOS lets a `SO_REUSEADDR` loopback listener sit beside
another program's `*:P` server and take its loopback clients, so after binding
127.0.0.1:P the runner also tries to bind `*:P` and refuses the port if that
fails. It keeps `SO_REUSEADDR` so that an immediate restart is not refused
for 30 seconds by its own connections in TIME_WAIT. A port held by another
program, on `*:P` or 127.0.0.1:P, fails create, start or `port add` with
`create_host_port_unavailable`, `start_host_port_unavailable` or
`host_port_unavailable` and says so; the other program keeps its port. On the
developer Mac, Little Snitch must allow the installed `cw` TCP 80/443 and
UDP 53.

Guest egress refuses addresses that are local to the host, on macOS and Linux
alike (#2614). The fixed protected ranges cannot know them, so the runner
tells the egress broker:

- every address on the host's own interfaces, read every five seconds;
- the public address the host's network is seen from, because a router or
  firewall answers its own public address for traffic from inside. The runner
  learns it with one STUN binding request (UDP) to `stun.codewire.sh:3478`
  when an environment starts, when an interface address changes and every
  five minutes. `CODEWIRE_LOCAL_STUN_SERVERS` (comma-separated `host:port`)
  names other servers.

Learning the public address is best effort and never delays a start. A host
firewall such as Little Snitch must allow the installed `cw` UDP to
`stun.codewire.sh` port 3478; while that is blocked, guests are refused only
the host's interface addresses, and the environment's runner log says so.
Public ranges that a site routes internally are not known to cw.

Mesh networks attach to macOS local environments through the same two host
processes as on Linux, each under its own Seatbelt profile installed where
Linux installs Landlock and seccomp. The one-shot enrollment issuer reads the
owner credential, then may only dial TCP to its Mesh origin's port. The Mesh
transport resolves the coordinator, DERP and STUN hosts before confinement,
then may dial TCP and send and receive UDP on one bound port to any address
(DERP, STUN, WireGuard and disco); files, processes, Mach services, named Unix
sockets and listeners are refused. Host DNS comes from the system's primary
resolver configuration, so scoped or VPN split resolvers are not consulted.
Direct UDP needs Little Snitch to allow the installed `cw` UDP to any port;
without it the transport can use only its DERP relay over TCP. This path is
implemented and unit-tested on the Mac but not yet observed with a real Mesh
login.

`cw mesh up` runs the standalone Mesh service on a Mac from the same code as on
Linux (#3797): the installed `cw` serves the Mesh (`cw __local-mesh`), which
starts and owns its DERP relay (`cw __local-derp`), so the relay ends with it.
The service holds an owner-only control socket. A later `cw` never adopts or
signals a recorded PID; it reaches the service only through that socket and
admits the peer as exactly the recorded process birth (PID, boot and start
time), so an in-place update of `cw` does not hide a running service. These are
owner processes, not a sandbox, so no Seatbelt profile applies. Separate
`codewire-mesh` and `codewire-derp` programs started by an earlier `cw` show
as `unknown` in `cw mesh status`; `cw mesh up` and `down` name them, and they
must be stopped by hand once.

Delegated member control (`cw control`, `cw member` and `--member`) is refused
on macOS hosts, with its reason. Member control must find and stop every
process a member session started, including descendants whose parent has
exited. Linux tracks that family with pidfds and a subreaper. macOS has no
public API that finds a process's descendants once their parent has exited,
and Codewire uses no private API, so a Mac host cannot be a member. Sessions in
a local VM run in its Linux guest.

Managed agents and the live in-guest cw runtime use the Linux route; see
[Managed agents and the cw runtime](#managed-agents-and-the-cw-runtime). A
folder protected by macOS privacy settings fails with a hint to grant your
terminal access.

Local application secrets and local credential profiles work as on Linux:
`cw create --local ... --profile local:NAME --secrets local:PROJECT
--user-secrets local`. Values stay in the selected local store (the login
Keychain by default, or the file store; see
[macOS local storage](SECRETS-AND-CREDENTIALS.md#macos-local-storage)).
Selected application secrets reach the workload only through the launch
projection, under their original names. Provider credentials stay on the
host: the local credential authority runs one broker per VM generation and
replaces it with an overlapping successor every 10 minutes (see
[SECRETS-AND-CREDENTIALS.md](SECRETS-AND-CREDENTIALS.md)). The broker reaches the guest daemon's credential
bridge over the VM's hybrid vsock socket and injects the selected credential
into the guest's proxied provider requests. The broker runs under a Seatbelt
profile that allows outbound TCP 443 (only when a provider is selected) and
reads of exactly the authority's store: the file store's entry directory, or
Apple's `/usr/bin/security` for the keychain. Other files, programs, network
and Mach services are denied. The broker exits with its authority and refuses
debugger attachment. As on
Linux local VMs, the developer egress policy still lets the guest open TCP
443 to a provider directly, so the broker keeps the credential out of the
workload but does not enforce provider mediation.

SSH keys selected by a local profile work in local VMs as on Linux. The
authority signs: for each signature it starts Apple's `/usr/bin/ssh-agent`
with only the selected key, which `/usr/bin/ssh-add` reads on stdin (a
passphrase goes through a private FIFO), signs once and stops and drains
the agent's process group. macOS has no per-user tmpfs, so each agent stages
in `signer` inside the credential root, in a 0700 directory that holds only
the agent socket and that FIFO; no key or passphrase byte is written to a
file. The guest's `ssh`, `scp` and Git use `SSH_AUTH_SOCK` from the guest
daemon, which reaches the authority through the VM's broker; only
signatures cross, and `ssh-add -l` lists exactly the selected key. Revoking
the credential refuses the next signature.

An SSH repository in `codewire.yaml` is checked out on the Mac by the
repository executor, an owned child of the authority started like the
broker (descriptor 3, empty environment, new session, no core files, umask
077, descriptors marked close-on-exec) that exits with the authority and
refuses debugger attachment. Git runs stock `/usr/bin/ssh` through the
`cw-git-ssh` trampoline with `-F /dev/null`, the pinned `known_hosts` and
the executor's relayed agent only; an unknown or changed host key fails
before authentication. Darwin has no parent-death signal, so Git, its
helpers and `ssh` stay in the executor's process group, which the
authority kills and drains as a whole; a killed executor fails the create
and leaves no process or staging. A GitHub executor serves its token to
`cw __local-git-credential-helper` once over a socket in the credential
root and reads it from the authority's store, as on Linux.

Platform sources and profiles for a local VM use the Linux platform-to-local
delegation: the authority's platform connector holds your saved platform
login, and the VM's broker runs as a relay under a deny-all Seatbelt profile
(no store reads, no network; only the bridge and authority descriptors it
already holds). This path is unit-tested on the Mac and not yet observed
with a real platform login. `connect codex|github --local` runs Codewire's
native device logins, which write no login file, and stores the tokens in
the selected store, as on Linux.

Neither the repository executor nor the signer's tools run under Seatbelt;
on Linux they run without Landlock or seccomp too. As on Linux, the guest
can still reach SSH and HTTPS hosts directly under the developer egress
policy; the signer keeps the key out of the guest but does not mediate
egress.

Launch projections and SSH agent requests carry deadlines that the guest
computes from its own wall clock, which follows the VM's RTC across host sleep
(see [Current macOS command boundary](#current-macos-command-boundary)). The
follower corrects only a skew of two seconds or more, and the guest clock is not
NTP-disciplined like the Mac's, so it can run slightly ahead between
corrections. Both requests therefore ask for 28 s, two seconds below the 30 s
the host enforces against its own clock.

Credential commands choose `--local` or `--cloud` explicitly; omitting the
placement never silently chooses one. Enrollment keeps the write-only input
and metadata-only output contracts. Explicit SSH private-key input must be a
regular file opened without following a final-component symlink and without
blocking on a FIFO.

Trusted host environments (`cw create --local --type host`) work on macOS
as on Linux. Sessions run directly on the Mac under the ordinary environment
daemon, with no VM. `cw stop`, `cw run` stop and daemon shutdown end the
whole owned session, including the separate process groups created by PTY job
control. macOS has no pidfd, so the daemon walks the process list with libproc
and rechecks each process's session ID with getsid just before signaling it. A
PID reused within that window could only belong to a process of the same user.

Managed agents (`cw run --agent`, `cw msg`, `cw steer`, `cw interrupt`,
`cw inbox`, `cw wait --message`) work on macOS host environments as on Linux.
After a helper run, run the host journey on the Mac from the synced source with
the helper's debug `cw`. It stages synthetic peers as `codex` and `claude` on
its own `PATH` and needs no network:

```sh
cd ~/.cache/codewire/macos-dev/<worktree-key>
/usr/bin/python3 source/scripts/dev/test-cli-host.py \
  --cw target/aarch64-apple-darwin/debug/cw
```

Darwin has no child subreaper, so the macOS journey runs as the leader of a new
session. At cleanup it requires that no live process remains in that session,
has its working directory inside the journey's private root, or names that
root in its arguments. A process that left the session, changed directory out
of the root and dropped the root from its arguments would escape this check.
Linux's subreaper check has no such gap. Delegated member control
(`cw control`, `cw member`) is refused on macOS hosts; see below for why.

## Install the local VM runtime

As on Linux, a developer installs the local VM inputs by hand: the signed
`codewire-vz-runner` helper, the pinned arm64 Linux kernel Image and the arm64
Codewire guest root, beside the Darwin artifact lock that `cw` reads.

1. On the Mac, build the pinned e2fsprogs the runtime ships. A stock Mac has
   none, and cw never uses Homebrew's. The tool needs the official 1.47.4
   source archive (it checks its SHA-256) and the Xcode Command Line Tools,
   builds `mke2fs`, `e2fsck`, `resize2fs` and `debugfs` linked only to
   libSystem, and formats probe images with the pinned `mke2fs.conf`:

   ```sh
   curl -fsSLO https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v1.47.4/e2fsprogs-1.47.4.tar.gz
   python3 scripts/dev/macos-ext4-tool.py --source-archive "$PWD/e2fsprogs-1.47.4.tar.gz" \
     --output /abs/private/e2fsprogs
   ```

   Then build the pinned git the runtime ships: the official 2.56.0 archive
   (checked by its SHA-256) built without translations, Perl, Python or Rust,
   linked only to stock system libraries (libcurl, zlib, iconv and the
   CoreFoundation/CoreServices frameworks):

   ```sh
   curl -fsSLO https://www.kernel.org/pub/software/scm/git/git-2.56.0.tar.xz
   python3 scripts/dev/macos-git-tool.py --source-archive "$PWD/git-2.56.0.tar.xz" \
     --output /abs/private/git
   ```

2. On an x86_64 Linux host, build the kernel and guest root from a checkout,
   then copy both files to the Mac (for example with `scp`). The kernel build
   needs the pinned `aarch64-linux-gnu` GCC and binutils cross toolchain and
   publishes `Image-6.18.48-codewire3`; the guest-root build accepts only the
   reviewed Alpine arm64 `busybox.static` and the official runc 1.5.1
   `runc.arm64`, whose digests the script names:

   ```sh
   python3 scripts/ci/verify/build-linux-vmm-kernel.py --arch arm64 \
     --source /abs/linux --bc /abs/busybox --output /abs/fresh/kernel
   scripts/ci/verify/build-local-vmm-initramfs.sh --verify-root \
     --target aarch64-unknown-linux-musl \
     --busybox /abs/busybox.static --busybox-sha256 <reviewed digest> \
     --runc /abs/runc.arm64 --runc-sha256 <reviewed digest> \
     --output /abs/initramfs-arm64.cpio
   ```

   For managed agents, also build the static aarch64 cw runtime and seal it,
   as on Linux but for `aarch64-unknown-linux-musl`. Build it natively on an
   arm64 Linux host, for example an Apple `container` arm64 Linux container on
   the Mac, never under emulation. `build-native-managed-agent.py` needs a Git
   checkout, records its `HEAD` and source digest, and builds offline from a
   populated Cargo cache:

   ```sh
   scripts/dev/build-native-managed-agent.py --target aarch64-unknown-linux-musl \
     --rust-tools /abs/rust/toolchain/bin --protoc /abs/protoc \
     --output /abs/fresh/cw-build
   python3 scripts/dev/cw-runtime-image.py build \
     --artifact /abs/fresh/cw-build/managed-agent-cw.json --output /abs/fresh/cw-image
   python3 scripts/dev/cw-runtime-image.py pack --image /abs/fresh/cw-image/cw.oci.tar \
     --index-sha256 <index_sha256 from image.json> --output /abs/fresh/cw-runtime
   ```

   The image is `linux/arm64`, and the runtime must target the host
   architecture: a Mac admits only an aarch64 cw, as an x86_64 Linux host
   admits only an x86_64 cw. The guest root must contain the trusted live cw
   publisher, which a guest root built from current source does.

3. On the Mac, from a checkout:

   ```sh
   make macos-local-runtime KERNEL=/abs/Image-6.18.48-codewire3 \
     INITRAMFS=/abs/initramfs-arm64.cpio E2FSPROGS=/abs/private/e2fsprogs/bundle \
     GIT_BUNDLE=/abs/private/git/bundle \
     CW_RUNTIME=/abs/fresh/cw-runtime
   ```

   This runs `scripts/dev/macos-local-runtime.py` with the system Python. It
   builds the helper with `swift build -c release`, signs it ad hoc with exactly
   `developer-entitlements.plist` (a release instead passes its Developer
   ID-signed helper with `--helper`), and checks that the kernel is an uncompressed
   arm64 Image, that the guest root is the exact canonical arm64 archive
   that admission accepts, and that each e2fsprogs program is a signed thin
   arm64 Mach-O linked only to libSystem and `mke2fs.conf` is the pinned one.
   It packs them as a runtime directory: `blobs/sha256/<digest>` and a
   canonical `local-runtime.json` (schema `local-runtime/v1`, stamped with this
   checkout's commit, with the `macos-aarch64` artifact lock). It is the same
   document a release's cw embeds, decoded with the same strict rules. Then `cw setup --local --from DIR`
   installs it: `cw` refuses a runtime built from a different commit than its
   own, fetches each file by digest into a private staging directory with its
   exact mode (`codewire-vz-runner` and the e2fsprogs programs 0500, `kernel`,
   `initramfs` and `mke2fs.conf` 0400; `mke2fs` is installed as `mkfs.ext4`),
   admits the staged set the way create does, swaps it into
   `~/.cache/codewire/local-vmm-v1/artifacts` and writes `artifacts.lock.json`
   (0400) last. `CODEWIRE_NATIVE_ARTIFACT_ROOT` and
   `CODEWIRE_NATIVE_ARTIFACT_LOCK` select other locations as they do for
   every `cw` command. Rerunning with the same inputs reports the runtime
   intact (a damaged installed file is fetched again); a different installed
   runtime is replaced only with `REPLACE=1`. A missing input, missing
   e2fsprogs or a host other than an Apple Silicon Mac fails before anything
   is written. `CW=/abs/cw` selects the installing `cw` (default: `cw` on
   `PATH`); `scripts/dev/macos-local-runtime.py --pack DIR` only writes the
   release directory, and `--source-revision COMMIT` names the commit of a
   source tree without Git metadata.
   `CW_RUNTIME` (optional) names the `pack` output directory. Its lock and pack
   are checked the way `cw` admits them (schema, size, SHA-256, framing, an
   aarch64 target bound to the image and a static aarch64 payload), the guest
   root must carry the live cw publisher, and `cw` installs both files (0400)
   beside `artifacts.lock.json`, pack first. An installed cw runtime that the
   release does not carry is different: rerun with the same `CW_RUNTIME`, or
   with `REPLACE=1` to remove it.

4. Until the arm64 default workspace image is published, name an image with a
   `linux/arm64` variant. An image without Docker tooling, such as
   `alpine:3.22`, needs `--no-docker`. Run create from the project directory:
   as on Linux, it copies or clones `.` unless `--path` names another one.

   ```sh
   cd /path/to/project
   cw create --local --image docker.io/library/alpine:3.22 --no-docker --name demo
   cw run --in demo -- uname -m    # aarch64
   cw rm --local demo --yes
   ```

## Local VM acceptance journey

After installing a runtime, run the observed local VM journey on the Mac with
the `cw` under test and a runtime directory packed for it:

```sh
/usr/bin/python3 scripts/dev/test-cli-local-vm-macos.py --cw /abs/cw --runtime /abs/runtime-dir
```

It runs under a private short root with its own HOME and a throwaway keychain.
It installs the runtime and creates an `alpine:3.22` VM, then checks:

- `cw run -- true` takes under 1 s (median of five);
- HTTP egress works;
- killing the packet worker or the egress broker fails the environment closed:
  - the environment turns `error`;
  - a guest probe fails from that moment;
  - no process of the environment holds an internet socket;
  - stop/start restores egress;
- a VM stopped for 20 s resumes with its clock within 2 s and a streaming
  session intact;
- the posture holds:
  - the helper holds no internet socket and has the hardened runtime;
  - the helper is confined by Seatbelt to this VM's own files: `sandbox_check`
    reports its disk as allowed, and an unrelated host file, exec, fork and
    the network as denied;
  - VZ's VM process is sandboxed.

It needs network egress and leaves no process or file behind.

### Private guest Docker (#1913)

The Docker journey covers #1913's acceptance list on Apple silicon. It uses a
`docker:28-dind` VM with a 1 GiB Docker disk, and a second runtime directory
packed from another source revision:

```sh
/usr/bin/python3 scripts/dev/test-cli-local-vm-docker-macos.py --cw /abs/cw \
    --runtime /abs/runtime-a --next-runtime /abs/runtime-b
```

It checks:

- `docker.raw` is its own disk, of the requested size;
- build, run, Compose and a public pull work;
- a private pull without a login is refused;
- `docker login` stays in the guest;
- `docker -p` publishes only inside the VM;
- an amd64-only image fails with `exec format error`;
- filling the Docker disk's bytes or inodes fails inside Docker only, logs stay
  bounded, and the workspace stays writable;
- images, volumes and the guest login persist across:
  - restart;
  - installing another runtime;
  - VMM death, runner death (`runner_exit`) and a dockerd crash, each
    reporting an error code and repaired with `cw --local daemon repair`;
- `cw rm` removes `docker.raw`.

The guest-side behaviour is shared with Linux. The Linux smoke
(`scripts/ci/verify/smoke-native-local-environment.sh`) covers it on every
qualifying run; this journey is run when the macOS backend changes.

## Managed agents and the cw runtime

With a cw runtime installed (step 3 above), a new local VM binds the installed
catalog at create, exactly as on Linux: its read-only catalog disk is attached
with the guest's `CWRUNTIME1` serial and mounted at `/codewire-cw`, and the
selected cw appears at `/run/codewire-runtime/cw/<sha256>/cw`. Managed agents
use the Linux host route and guest helpers unchanged:

```sh
cw run --in vm-team --name lead --agent codex --detach --prompt 'Coordinate.'
cw msg vm-team --session lead 'Include the recovery case.'
cw inbox vm-team --session lead
cw wait --message MESSAGE_ID --timeout 10m
```

As on Linux, a managed VM agent needs a selected credential profile, local or
platform, with a provider for the agent; without a profile, `cw run --agent` in
a local VM fails with "managed VM agents require a selected credential
profile", and without the provider with "the native environment's selected
credential profile has no Anthropic provider" (or "no Codex or OpenAI
provider").
The workspace image needs `/usr/bin/python3` for the verified launcher, as on
Linux. Managed agents run the client the VM user's shell runs, the first
`codex` or `claude` on PATH, with no pinned version, as on Linux. The
workspace image pin is amd64-only until it lists `linux/arm64`, so a Mac VM
runs another image, and the agents run that image's clients; see
[CLI-ORCHESTRATION.md](CLI-ORCHESTRATION.md). A VM created without an installed cw runtime has no catalog: `runtime
info` fails with "VM has no immutable cw bootstrap catalog", as on Linux.

The live runtime commands work on a running macOS local VM, without a restart:

```sh
cw --local runtime info vm-team --output json
cw --local runtime update vm-team \
  --source /abs/owner-private/cw-runtime/cw-runtime.lock.json \
  --image-sha256 <image index SHA256> --target-sha256 <cw SHA256> \
  --expected-revision 1
cw --local runtime rollback vm-team --expected-revision 2
cw --local runtime observe vm-team --request-id <request UUID>
```

The source directory must be owner-only (0700) and canonical (`/private/tmp`,
not `/tmp`). Darwin has no socket-derived process handle: the live publisher's
peer is admitted by its `LOCAL_PEERPID` and the VMM's recorded birth, and the
recorded runner and VMM are watched for exit, never adopted. A catalog disk is
built with the runtime's pinned `mkfs.ext4` and checked with its `debugfs`; Darwin has no
parent-death signal, so a formatter whose `cw` died finishes its bounded work
while still holding the publication lock.
