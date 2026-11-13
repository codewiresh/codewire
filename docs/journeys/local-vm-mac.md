# Local VMs on a Mac

A local VM on an Apple silicon Mac ([SPEC.md section 5](../../SPEC.md#5-local-vms-and-trusted-hosts)):
`cw` installs, creates a VM through Virtualization.framework, opens a shell in
it, runs a command, and stops and starts it. Launch step 11 (#4370) needs this
walk observed on macOS 27 and on macOS 26. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-13.

| ID | macOS 27 | macOS 26 |
| --- | --- | --- |
| `mac-vm-lifecycle` | observed on a development build of the #4478 fix; failure observed on v0.4.16 | observed on a development build of the #4478 fix |
| `mac-vm-refused-start` | refused create observed on a development build | not yet observed |

## Before the walk

- Use an Apple silicon Mac and record `sw_vers -productVersion` and
  `cw --version` with every observation.
- For a walk that leaves the Mac's own `cw` state alone, give it a throwaway
  `HOME` and keychain (`CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN`), as
  `scripts/dev/test-cli-local-vm-macos.py` does, and remove both afterwards.
  `cw`'s sockets go to a directory keyed by the state root, so two `HOME`s
  never share a supervisor.
- An application firewall must allow the installed `cw` to reach
  `releases.codewire.sh`, `ghcr.io` and `pkg-containers.githubusercontent.com`.
  Each `cw` version runs from its own path under
  `~/.local/share/codewire/cli/versions/`, so a firewall that decides per
  executable asks again after every upgrade.

## 1. `mac-vm-lifecycle`: install, create, shell, run, stop, start

Issues: #4478 (VMs did not start on macOS 27), #4370 (launch step 11).

- **Entry points:** `cw` in a terminal on the Mac. Local VMs have no
  dashboard entry point.
- **States to exercise:**
  - a fresh install, and `cw upgrade` from the previous release;
  - a first create, which pulls the image, and a create from cached layers;
  - a stopped VM started again, and a command run after the restart;
  - a start macOS refuses (`mac-vm-refused-start`).
- **Driving it:**
  1. Install: `curl -fsSL https://codewire.sh/install.sh | sh`, or
     `cw upgrade`. Then `cw --version`.
  2. `cw setup --local` prints `Local VM runtime installed (ID).`
  3. `cw create --local --name mac-walk --path-mode empty --yes` ends with
     `✓ Environment mac-walk created · local VM`.
  4. `cw --local shell mac-walk` opens a login shell in `/workspace`. Type
     `uname -m` (it prints `aarch64`), then `exit`.
  5. `cw run --in mac-walk --no-tty -- sh -c 'echo before-restart'`.
  6. `cw --local stop mac-walk`, then `cw --local ls` shows `stopped`.
  7. `cw --local start mac-walk` ends with `✓ Environment mac-walk started`.
     `cw run --in mac-walk --no-tty -- sh -c 'echo after-restart; uptime'`.
  8. `cw --local rm mac-walk`.
- **Proof:** the shell prints `aarch64`; `cw --local ls` reads `stopped` after
  step 6 and `running` after step 7; the command after the restart prints
  `after-restart` and an uptime under a minute.
- **Gotchas:**
  - A first create with the default workspace image pulls about a minute of
    layers; a slow pull is not a failure.
  - A `cw` built from source has no provenance. `cw setup --local --from DIR`
    installs a runtime directory from `make macos-local-runtime` and warns
    that it cannot check the runtime's source.
  - macOS 26 has no test Mac since the CI Mac moved to macOS 27 (owner,
    2026-11-13; no new hardware). It stays supported, and its last observation
    stands until the helper's Seatbelt profile or its use of
    Virtualization.framework changes, or a regression shows only on macOS 26;
    then this walk needs a macOS 26 Mac again.
- **Observed:**
  - macOS 27.2.1, release v0.4.16, 2026-11-13: failure observed. Every create
    failed at "Starting the VM" with `create_failed` (#4478).
  - macOS 27.2.1, a development build of main 3abfebe8b with the #4478 fix
    and v0.4.16's kernel, guest root and cw runtime, 2026-11-13: steps 3 to 7
    observed, after `cw setup --local --from DIR` in place of steps 1 and 2.
    The create took 126 s, 71 s of it the image pull; the stop took
    2 s and the start 3 s. With the helper from 3abfebe8b instead, and the same
    `cw`, the create failed at "Starting the VM" (#4478).
  - macOS 26.6.2, the same `cw` and runtime directory, 2026-11-13: steps 3 to
    8 observed, after `cw setup --local --from DIR`. The create took 195 s,
    about 2 minutes of it the image pull; the stop took 1 s and the start 4 s.

## 2. `mac-vm-refused-start`: a VM macOS refuses to start says so

Issues: #4478.

- **Entry points:** `cw create --local` and `cw --local start`.
- **States to exercise:** a refused create, and a refused start of a VM that
  ran before.
- **Driving it:** no command makes macOS refuse a start on purpose. A
  helper built without its macOS 27 cache-directory rule is refused on macOS
  27, which is how this state was produced for #4478.
- **Proof:** the create fails with `create_vm_start_refused`, or the start
  with `start_vm_start_refused`, and the message says macOS refused to start
  the VM, never `create_failed`.
- **Gotchas:** a helper from before #4478 exits 1 when it is refused, so it
  reports `create_failed`, and that `cw` cannot do better.
- **Observed:**
  - macOS 27.2.1, the development build above with its helper's `/var` rule
    removed, 2026-11-13: a refused create observed. It failed at "Starting
    the VM" with `create_vm_start_refused` and the hint "macOS's
    Virtualization framework refused to start the VM", and the supervisor
    logged `runner_error=vm_start_refused` (#4478).
  - A refused start of an existing VM: not yet observed.
