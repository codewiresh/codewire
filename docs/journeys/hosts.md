# Hosts

A host is a computer, yours or your team's, that runs Codewire VMs for your
organization: `cw host` enrolls it and keeps its agent connected, `cw hosts`
lists the organization's hosts, and the dashboard's Hosts page shows them.
`SPEC.md` has no section for hosts yet, so this file is the journey for the
placement program #3609: slice 1 (hosts enroll, connect and show their state)
and slice 2 (environments created on a host). The commands are in the
CLI reference, `apps/docs/zola/content/reference/cli/hosts.md`. The format is
in [README.md](README.md).

## Where the journey stands

Updated 2026-11-13. Slice 1's CLI and agent are observed on Dev: enroll with
either key store, the agent's connection directly and through a proxy, the
user service across logout and reboot, and leave. The Hosts page waits for
the owner's browser walk. Slice 2 is not yet observed anywhere, and nothing is
observed on Production.

| ID | Dev | Production |
| --- | --- | --- |
| `host-enroll` | observed 2026-11-13 on 37ea121f5 and 154d23a40 (#3609, #4432) | not yet observed |
| `host-run` | observed 2026-11-12 on 711e09ea4 (#3609) | not yet observed |
| `host-proxy` | observed 2026-11-12 on 711e09ea4, through a delivery of 2b4acf028 (#3609) | not yet observed |
| `host-service` | observed 2026-11-13 on 37ea121f5 and 154d23a40 (#3609, #4432) | not yet observed |
| `host-leave` | observed 2026-11-13 on 37ea121f5 and 154d23a40 (#3609, #4432) | not yet observed |
| `host-page` | not yet observed | not yet observed |
| `host-create` | not yet observed | not yet observed |
| `host-attach` | not yet observed | not yet observed |
| `host-stop` | not yet observed | not yet observed |
| `host-start` | not yet observed | not yet observed |
| `host-delete` | not yet observed | not yet observed |
| `host-agent-restart` | not yet observed | not yet observed |

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
- **Proof:** a card "Hosts (2)" with one row per computer: name, platform,
  owner, "Not offering VMs", a green Online badge and last seen. After the
  stop, that row reads Offline within about a minute. At 390 px the rows stack
  and nothing scrolls sideways.
- **Gotchas:** it needs a real browser sign-in, so no synthetic identity can
  walk it.
- **Observed:** not yet observed.

## Slice 2: environments on a host

The first walk is on Dev, on a Linux host, then on a Mac: create, run, stop,
start and delete an environment with an empty workspace. `--repo`, resize and
the platform-profile credential relay are later steps (#3609). There is no
command for any of these yet: placement on a host (`--on host:NAME`) lands
with slice 2.

### `host-create`: an environment created on a host

- **Entry points:** no command yet (#3609).
- **States to exercise:** the host online and providing; offline; not
  granted; out of capacity, where the host's own refusal is shown verbatim.
- **Proof:** the environment reaches running on the named host, and the
  host's report shows the same environment and generation. A refused create
  names its reason, and nothing is created on the platform or another host.
- **Observed:** not yet observed.

### `host-attach`: `cw run` and `cw attach` over the API tunnel

- **Entry points:** no command yet (#3609).
- **States to exercise:** attach, disconnect, reconnect with the result kept.
- **Proof:** `cw run --agent …` runs in the host's VM; after a disconnect,
  `cw attach` shows the same session and its result.
- **Observed:** not yet observed.

### `host-stop`: an environment on a host stops

- **Entry points:** no command yet (#3609).
- **Proof:** the environment reads stopped and the host's VM is no longer
  running.
- **Observed:** not yet observed.

### `host-start`: a stopped environment on a host starts again

- **Entry points:** no command yet (#3609).
- **Proof:** the environment reads running on the same host, with its
  workspace kept.
- **Observed:** not yet observed.

### `host-delete`: an environment on a host is deleted

- **Entry points:** no command yet (#3609).
- **Proof:** the environment is gone from the list, and the host reports it
  absent with its disk removed.
- **Observed:** not yet observed.

### `host-agent-restart`: a lost reply resolves the original operation

- **Entry points:** no command yet (#3609).
- **States to exercise:** the agent restarted, or its connection cut, while a
  create or stop is in flight.
- **Proof:** after the agent attaches again, the operation completes once
  with its first result, and the host has no second VM.
- **Observed:** not yet observed.
