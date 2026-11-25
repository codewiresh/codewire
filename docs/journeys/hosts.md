# Hosts

A host is a computer, yours or your team's, that runs Codewire VMs for your
organization: `cw host` enrolls it and keeps its agent connected, `cw hosts`
lists the organization's hosts, and the dashboard's Hosts page shows them.
The contract is in [`SPEC.md`, section 5, Hosts](../../SPEC.md#hosts). This
file is the journey for the placement program #3609: slice 1 (hosts enroll,
connect and show their state) and slice 2 (environments created on a host). The commands are in the
CLI reference, `apps/docs/zola/content/reference/cli/hosts.md`. The format is
in [README.md](README.md).

## Where the journey stands

Updated 2026-11-24. Slice 1's CLI and agent are observed on Dev: enroll with
either key store, the agent's connection directly and through a proxy, the
user service across logout and reboot, and leave. The Hosts page waits for
the owner's browser walk. Slice 2's lifecycle is observed on Dev on a Linux
host: stop, delete, a stop across an agent restart and a delete on a
revoked host, and create and start in part: the environment runs, but the
CLI's create never returns and its start exits 1 (#6397). The host's
generation, the platform's own refusals (offline, not granted, out of
capacity, a request the host can't take) and the 25-minute bound are not
yet observed, and `host-attach` waits for the API tunnel. Nothing is
observed on Production.

| ID | Dev | Production |
| --- | --- | --- |
| `host-enroll` | observed 2026-11-13 on 37ea121f5 and 154d23a40 (#3609, #4432) | not yet observed |
| `host-run` | observed 2026-11-12 on 711e09ea4 (#3609) | not yet observed |
| `host-proxy` | observed 2026-11-12 on 711e09ea4, through a delivery of 2b4acf028 (#3609) | not yet observed |
| `host-service` | observed 2026-11-13 on 37ea121f5 and 154d23a40 (#3609, #4432) | not yet observed |
| `host-leave` | observed 2026-11-13 on 37ea121f5 and 154d23a40 (#3609, #4432) | not yet observed |
| `host-page` | not yet observed | not yet observed |
| `host-create` | partly observed 2026-11-24 on 013f98d865 to 4d9d003f3: runs on the host, but `cw create` never returns; the generation, the platform's refusals and the 25-minute bound are not yet observed (#3609, #6397) | not yet observed |
| `host-attach` | not yet observed | not yet observed |
| `host-stop` | observed 2026-11-24 on 013f98d865 to 4d9d003f3 (#3609, #6397) | not yet observed |
| `host-start` | partly observed 2026-11-24 on 013f98d865 to 4d9d003f3: runs again with its workspace kept, but `cw start` exits 1 (#3609, #6397) | not yet observed |
| `host-delete` | observed 2026-11-24 on 013f98d865 to 4d9d003f3 (#3609, #6397) | not yet observed |
| `host-agent-restart` | observed 2026-11-24 on 013f98d865 to 4d9d003f3 (#3609, #6397) | not yet observed |
| `host-revoked-delete` | observed 2026-11-24 on 013f98d865 to 4d9d003f3 (#3609, #6397) | not yet observed |

## Before the walk

- Walk on a computer that is yours to enroll, or on a disposable VM
  (`scripts/dev/selfhost-vm.sh` makes a stock Debian 12 one). The Dev walks
  below used the Dev smoke identity (`scripts/runtime/dev/with-dev-smoke-auth.sh`)
  and a scratch HOME, so neither the owner's keyring nor their `cw`
  configuration was touched. Its API key reaches a VM only on stdin.
- Keep Dev apart from a Production sign-in with `CW_CONFIG_DIR`, for example
  `CW_CONFIG_DIR=~/.config/cw-dev`.
- Record `cw version`, or the commit `cw` was built from, with every
  observation. The host side is `cw`; the server side is the source Dev had
  rolled out.
- Every host a walk enrolls is removed with `cw host leave --yes` at the end,
  and `cw hosts` confirms it is gone.

## Slice 1: hosts

### `host-enroll`: a computer becomes a host

- **Entry points:** `cw host enroll [--name NAME] [--key-store keyring|file]`.
- **States to exercise:** a desktop with a Secret Service or the Keychain
  (key in the OS keyring); a Linux server with no Secret Service (key in a
  file); `--key-store keyring` asked for where there is none.
- **Driving it:** run `cw host enroll --name NAME`, then `cw hosts` and
  `cw host status`.
- **Proof:** `cw hosts` lists the host, offline and never seen.
  `cw host status` names where the key is. With no Secret Service, the key is
  one `-rw-------` file in a `drwx------` `host-key` directory. With
  `--key-store keyring` and no keyring, enroll exits 1 with the sentence
  naming `--key-store file`, and nothing is enrolled.
- **Gotchas:** a Linux session with no session bus has no Secret Service even
  when gnome-keyring is installed; that is the headless case (#4432).
- **Observed:**
  - Dev, 2026-11-13 10:23Z, source 37ea121f5 (its promotion was at 10:16Z;
    when its rollout ended is not recorded): a Debian 12 VM with a Secret
    Service set up by hand; `cw` built from main 37ea121f5. Enrolled, "key is
    in the OS keyring" (#3609).
  - Dev, 2026-11-13 12:17Z, source 154d23a40: no session bus; `cw` built
    from the #4462 branch. `--key-store keyring` refused with exit 1 and the
    sentence; the default enrolled with the key in a file, with the modes
    above (#4432).

### `host-run`: the agent connects and the host shows online

- **Entry points:** `cw host run` (foreground); `cw hosts`;
  `cw host status`.
- **States to exercise:** running; stopped (Ctrl-C); the server restarting
  under it.
- **Driving it:** `cw host run`, then `cw hosts` and `cw host status` once a
  minute; Ctrl-C; `cw hosts` again a minute later.
- **Proof:** "Attached: this host is online"; `cw hosts` shows online with
  last seen advancing each minute; about 50 s after Ctrl-C it shows offline.
  A Dev delivery ends the stream and the agent attaches again within seconds.
- **Gotchas:** the server pings every 15 s, so a proxy or CDN never sees the
  stream idle.
- **Observed:**
  - Dev, 2026-11-12 21:33–21:45Z, source 711e09ea4; `cw` built from main
    2b4acf028. Online for 11 m 37 s with no session end; offline 50 s after
    the stop (#3609).

### `host-proxy`: the agent connects through an HTTP CONNECT proxy

- **Entry points:** `HTTPS_PROXY` for `cw host run`.
- **States to exercise:** connected through the proxy for longer than the
  proxy's idle timeout; the proxy restarting; a Dev delivery during the
  stream.
- **Driving it:** a stock Squid (CONNECT to 443 only), `HTTPS_PROXY` set,
  `cw host run`; restart the proxy; sample `cw hosts` once a minute.
- **Proof:** the proxy logs `CONNECT …:443` tunnels; the host stays online;
  after the proxy restarts the agent reports "reconnecting" and attaches
  again.
- **Gotchas:** owner, 2026-11-12: HTTPS first, and a WebSocket fallback only
  if this breaks. It has not broken.
- **Observed:**
  - Dev, 2026-11-12 21:46–22:03Z, source 711e09ea4, with Dev's delivery of
    2b4acf028 rolling during the walk. Online for 12 m 42 s through Squid
    6.10; attached again 88 s after a proxy restart, and 1 s after the
    delivery ended the stream, on the same CONNECT tunnel (#3609).

### `host-service`: the agent as a user service, across logout and reboot

- **Entry points:** `cw host service install|uninstall|status`;
  `loginctl enable-linger USER`.
- **States to exercise:** logged out with linger off and on; a reboot with
  nobody logged in; key in the keyring and key in a file.
- **Driving it:** `cw host service install`; `sudo loginctl enable-linger
  USER`; log out; reboot; read `cw hosts` from another computer.
- **Proof:** with the key in a file, the host is online seconds after boot
  with nobody logged in. With the key in a keyring on a headless host, it
  stays offline until a password login unlocks the keyring.
- **Gotchas:** an SSH key login never unlocks gnome-keyring; that is why a
  server keeps its key in a file (#4432). Linger is a system setting that
  `cw host service uninstall` leaves on.
- **Observed:**
  - Dev, 2026-11-13 10:23–10:39Z, source 37ea121f5 (as above), key in the
    keyring: offline after logout with linger off; online after logout with
    linger on; after a reboot, offline until one password login, then online
    with no command (#3609).
  - Dev, 2026-11-13 12:32–12:34Z, source 154d23a40, key in a file, a stock
    Debian 12 VM with no Secret Service, `cw` built from the #4462 branch at
    3874d3279: after a reboot with nobody logged in, the service started at
    12:33:39 and Dev showed the host online, five seconds after boot (#4432).

### `host-leave`: a host is removed with its key

- **Entry points:** `cw host leave [--yes]`; `cw host revoke` for an owner
  removing someone else's host.
- **States to exercise:** key in the keyring; key in a file; the service
  installed.
- **Driving it:** `cw host service uninstall`, then `cw host leave --yes`,
  then `cw hosts` and `cw host status`.
- **Proof:** "Removed host"; `cw hosts` no longer lists it; `cw host status`
  says not enrolled; the keyring item, or the key file and its directory, are
  gone.
- **Observed:**
  - Dev, 2026-11-13 10:39Z, source 37ea121f5 (as above), key in the keyring
    with the service installed: the keyring's Codewire items went from 1 to
    0, the unit was removed, and `cw hosts` no longer listed the host (#3609).
  - Dev, 2026-11-13 12:34Z, source 154d23a40, key in a file: removed;
    `~/.config/cw/` left empty, with the key file and its directory gone
    (#4432).

### `host-page`: the dashboard's Hosts page

- **Entry points:** `https://<deployment>/<org slug>/hosts/`, in the sidebar.
- **States to exercise:** no hosts; two hosts online; one stopped (offline);
  revoked; widths 1440 and 390 px.
- **Driving it:** the owner's walk on #3609: two computers enrolled and
  running `cw host run`, then the page, then Ctrl-C on one and a reload.
- **Proof:** under the page's title and description and above everything
  else, in every state (no hosts, a list, or the page's own error), a warning
  reads "Hosts are a preview and still being built: some host features don't
  work yet." (observed on Kind only, no-hosts state).
  A card "Hosts (2)" with one row per computer: name, platform,
  owner, "Not offering VMs", a green Online badge and last seen. After the
  stop, that row reads Offline within about a minute. At 390 px the rows stack
  and nothing scrolls sideways.
- **Gotchas:** it needs a real browser sign-in, so no synthetic identity can
  walk it.
- **Observed:**
  - Kind, standing in for Dev, 2026-11-21 20:06Z, source d006a323e (#5786),
    no-hosts state only: at 1440 and 390 px the warning sits under the title
    and description and above the "No hosts yet" card, and nothing scrolls
    sideways at 390 (#3609). Kind did what Dev will not: the synthetic owner
    `e2e-owner@codewire.sh` signed in, with no hosts enrolled, so the list,
    Offline and error states are not observed. Dev is not yet observed.

## Slice 2: environments on a host

The first walk is on Dev, on a Linux host, then on a Mac: create, run, stop,
start and delete an environment with an empty workspace. `--repo`, resize and
the platform-profile credential relay are later steps (#3609). Placement is
`cw create --on host:NAME`, and stop, start and delete are the ordinary
commands. Reaching the environment (`cw run`, `cw attach`, `cw shell`) needs
the API tunnel, which is not merged yet.

The first slice-2 walk ran on Dev on 2026-11-24, 21:40–22:38Z, as the Dev
smoke identity. Dev was at 013f98d865 and was promoted to 2b3298196 (22:06Z),
54dfbe967 (22:22Z) and 4d9d003f3 (22:33Z) during the walk; when each rollout
ended is not recorded. The agent's session ended twice during the walk, and
each time it attached again within seconds. The host was a Linux x86_64 KVM
workstation, enrolled with a scratch HOME and its key in a file, providing one
VM, with `cw` built from main d54f96c69d and a local runtime from the same
source.

### `host-create`: an environment created on a host

- **Entry points:** `cw create --on host:NAME` (NAME is a host's name or ID).
- **States to exercise:** the host online and providing; offline; not
  granted; out of capacity; a request the host can't take (another image,
  `--repo`, secrets, a credential profile, a network policy); a host that
  refuses or fails the create, whose own words are shown as one bounded
  line; a host that never answers, which ends in error after 25 minutes.
- **Proof:** the environment reaches running on the named host, and the
  host's report shows the same environment and generation. A refused create
  names its reason, and nothing is created on the platform or another host.
- **Gotchas:** the host refuses every operation while any directory above its
  native state root is not mode 0700, retrying every 5 s until it is. Today
  `cw create --on host:NAME` prints `Reconcile requested` and never returns,
  because it waits for a daemon readiness the platform can't give a host
  environment (#6397); read `cw info` instead.
- **Observed:**
  - Dev, 2026-11-24, the first slice-2 walk (above). Online, `cw host provide
    --max-vms 1`. The environment read `State: running` with `StartedAt`
    21:56:40Z, 2 min 50 s after the create, the same second the host's
    supervisor logged `record_running`; on the host, `cw ls --local` showed
    one running VM named after the platform's environment ID, its daemon
    ready. A second create, from cached layers, ran after 1 min 40 s. Both `cw
    create` commands were still waiting when the walk stopped them, at 30 and
    5 minutes (#6397). The host's generation was not read. An earlier create
    failed `create_registry_transport` because the walk's firewall blocked the
    registry; the platform showed the host's own reason, `this host's VM
    supervisor refused the operation (create_registry_transport)`, and the
    environment in error (#3609).

### `host-attach`: `cw run` and `cw attach` over the API tunnel

- **Entry points:** `cw run` and `cw attach`, which reach the VM's daemon
  through a tunnel from its host's session; `cw shell` doesn't yet (#3609).
- **States to exercise:** attach, disconnect, reconnect with the result kept.
- **Proof:** `cw run --agent …` runs in the host's VM; after a disconnect,
  `cw attach` shows the same session and its result.
- **Observed:** not yet observed.

### `host-stop`: an environment on a host stops

- **Entry points:** `cw stop ENV`.
- **Proof:** the environment reads stopped and the host's VM is no longer
  running.
- **Observed:**
  - Dev, 2026-11-24, the first slice-2 walk (above). Three stops, each
    `Environment h2-env stopped` in about 4 s, `StopReason: user`, and the
    host's VM stopped. The CLI still says `cloud VM` and suggests `cw --cloud
    start` (#6397).

### `host-start`: a stopped environment on a host starts again

- **Entry points:** `cw start ENV`.
- **Proof:** the environment reads running on the same host, with its
  workspace kept.
- **Gotchas:** `cw start` exits 1 after about 3 minutes with `daemon to become
  ready: sandbox backend not found`, though the environment is running
  (#6397).
- **Observed:**
  - Dev, 2026-11-24, the first slice-2 walk (above). Two starts: each read
    running 14 to 19 s later on the same host, while `cw start` exited 1 after
    3 min 14 s and 3 min 19 s (#6397). A file written into `/workspace` before
    a stop, through the host's own `cw exec --local`, read back the same after
    the next start.

### `host-delete`: an environment on a host is deleted

- **Entry points:** `cw rm ENV`.
- **Proof:** the environment is gone from the list, and the host reports it
  absent with its disk removed.
- **Observed:**
  - Dev, 2026-11-24, the first slice-2 walk (above). `cw info` said not found
    at once; within 5 s the host's `cw ls --local` listed no environments and
    its native state shrank from 9.4 GB to 2.4 GB, the VM's disk gone.
    Deleting the environment whose create had failed worked the same way.

### `host-agent-restart`: a lost reply resolves the original operation

- **Entry points:** `cw create --on host:NAME` or `cw stop ENV`, with
  `cw host run` restarted on the host meanwhile.
- **States to exercise:** the agent restarted, or its connection cut, while a
  create or stop is in flight.
- **Proof:** after the agent attaches again, the operation completes once
  with its first result, and the host has no second VM.
- **Observed:**
  - Dev, 2026-11-24, the first slice-2 walk (above). A stop, with the agent
    sent Ctrl-C 1.5 s after `cw stop` started and run again 6 s later: the
    host's supervisor stopped the VM once, under one operation ID, 0.8 s after
    the agent ended; the agent attached again at 22:31:55Z, and the
    environment read stopped at 22:31:56Z, `cw stop` exiting 0. The host kept
    one VM. A create across a restart is not yet observed.

### `host-revoked-delete`: an environment on a revoked host is deleted

- **Entry points:** `cw host revoke HOST`, then `cw rm ENV`.
- **States to exercise:** the host revoked while idle; revoked after it took
  a create or a delete and before it answered.
- **Proof:** the environment is gone from the list within about 20 seconds, without
  waiting for the host, and no later retry is needed. The host's VM is the
  owner's to remove (`cw host leave` on that computer).
- **Gotchas:** the control plane cannot reach a revoked host, so it does not
  claim the VM is gone from that computer.
- **Observed:**
  - Dev, 2026-11-24, the first slice-2 walk (above). Revoked while idle with
    one running environment: `cw rm` returned at once and `cw info` said not
    found within 1 s. The host's agent printed `this host was revoked; the
    agent stops` and exited; its VM kept running until `cw rm --local` removed
    it, and then `cw host leave --yes` said "Host `cw-hosts-h2` was revoked,
    so its record stays; this computer is no longer enrolled." `cw hosts`
    still showed the revoked host as providing `1 VMs` (#6397). Revoked
    mid-operation is not yet observed.
