# Local VM credentials smoke

An automated walk of the credential and proxy sequences users hit on a Linux
local VM (#5220). It runs real local VMs under KVM in a throwaway HOME, with
synthetic credentials and synthetic providers only, nightly on `main` and
against every release candidate. Once a CI machine runs it, a release tag
needs it green for the candidate's commit. The behaviour it walks is specified in
[SECRETS-AND-CREDENTIALS.md](../dev/SECRETS-AND-CREDENTIALS.md) and
[LINUX-LOCAL-VMS.md](../dev/LINUX-LOCAL-VMS.md); the per-credential journeys a
person walks are in [credentials.md](credentials.md). The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-18. Every step not listed as observed is **not yet
observed**.

| ID | Linux local VM | Run by |
| --- | --- | --- |
| `smoke-profile-after-create` | observed, v0.4.22, 2026-11-18 (by hand) | `scripts/ci/verify/smoke-local-credentials.sh` |
| `smoke-credential-ssh` | not yet observed | no command yet (#5220) |
| `smoke-credential-github` | not yet observed | no command yet (#5220) |
| `smoke-credential-claude` | not yet observed | no command yet (#5220) |
| `smoke-credential-codex` | not yet observed | no command yet (#5220) |
| `smoke-attach-restart` | not yet observed | no command yet (#5220) |
| `smoke-upgrade` | not yet observed | no command yet (#5220) |
| `smoke-proxy-down` | not yet observed | no command yet (#5220) |

## Before the walk

- A Linux host with `/dev/kvm`, the `cw` under test and the local VM
  artifacts it admits. Until a CI machine can run local VMs (#5220), the
  smoke is run by hand on such a host for every release candidate, and its
  result is posted on the release issue as evidence. It is not a receipt
  requirement until it runs in CI; until then a release is not cut on a red
  run.
- A throwaway HOME and private state root; nothing reads the desktop
  keyring, an existing `~/.codewire` or a provider's own login.
- Only synthetic values: each carries its own randomness, so a leak is
  found by searching for it.

## Every step's checks

Each step below also proves, unless it says otherwise:

- **No real value in the guest:** every synthetic value is searched for in
  the guest's disk and in a VM checkpoint, as the existing protected-store
  smoke does, and is absent.
- **A readable failure:** a step that fails names the stage and the
  broker's or the runner's own reason, never only an exit status.

## 1. `smoke-profile-after-create`: add a credential profile to a running VM

A VM made with no credentials, then given a profile, with one `cw`
throughout. The same sequence after an older release left its credential
authority running is the owner's failure on v0.4.21, in step 4.

- **Entry points:** `cw create --local`, `cw credentials --local`,
  `cw update --local`.
- **States to exercise:** a VM with no profile; the managed restart that
  `--profile` requires; the VM after it.
- **Driving it:** `cw setup --local`; `cw create --local --name N --no-file
  --no-profile --yes`; a command in it with `cw exec`; `cw credentials --local
  generate ssh --name K`; `cw credentials --local --profile N set ssh K`;
  `cw update --local N --profile local:N --yes`.
- **Proof:** the restart completes and the VM runs; `cw exec` answers again;
  the guest's SSH agent lists the new key's public half.
- **Gotchas:**
  - the egress broker resolves through the host's stub resolver, so a host
    firewall must let the binary under test reach it;
  - `cw credentials --local generate ssh` stores the key in the operating
    system's keyring even with a private HOME, so the smoke runs against an
    isolated keyring of its own, and runs every `cw` in a private mount
    namespace where the host's runtime directory and the home's keyrings, SSH
    keys and Codewire state are empty, so the host keyring is unreachable. It
    never calls the host's Secret Service: a loop of D-Bus reads to it crashed
    it on 2026-11-17 (#5256);
  - on v0.4.21 a first VM start could spend two to three minutes in its
    network step; on v0.4.22 it took 0.3 s (hand runs on #5220).
- **Observed:** v0.4.22, 2026-11-18, by hand on a Linux host:
  `scripts/ci/verify/smoke-local-credentials.sh --cw <installed v0.4.22>
  --scratch <dir>` printed `ok smoke-profile-after-create`. The update's
  managed restart came back running and the guest's agent held the key's
  fingerprint; nothing was left on the host. Not yet run in CI (#5220).

## 2. `smoke-credential-<kind>`: each credential type end to end

One sub-step per kind: `ssh`, `github`, `claude`, `codex`. The GitHub, Claude
and Codex sign-ins are synthetic, served by synthetic providers on loopback.

- **Entry points:** `cw credentials --local` (generate, connect or add),
  `--profile P set`, `cw create --local --profile local:P`.
- **States to exercise:** in use; revoked while the VM runs; after a stop and
  start.
- **Driving it:** enrol the credential, select it in a profile, create a VM
  with that profile, then in the guest:
  - `ssh`: sign with the key through the agent;
  - `github`: a `git clone` of a fixture repository over HTTPS;
  - `claude`: `claude -p` against the synthetic provider;
  - `codex`: a Codex turn against the synthetic provider.

  Then `cw credentials --local revoke NAME`, the same request again, then
  `cw stop` and `cw start` and the request once more with a re-enrolled
  credential.
- **Proof:** the guest holds only the stand-in (a placeholder or a
  public key), the synthetic provider records the request with the real
  value the broker swapped in, revoke makes the next request fail with the
  broker's refusal and no provider call, and the request works again after
  stop, start and re-enrolment.
- **Observed:** not yet observed.

## 3. `smoke-attach-restart`: attach across a restart

- **Entry points:** `cw attach`, `cw stop`, `cw start`.
- **Driving it:** `cw attach` to a session in a VM with a profile, detach,
  `cw stop` and `cw start`, then `cw attach` again.
- **Proof:** the second attach reaches a live session in the restarted VM,
  and a credentialed request from it works.
- **Observed:** not yet observed.

## 4. `smoke-upgrade`: the previous release left things in place

Three cases, each with the previous release's `cw` first, then the
candidate's, in the same private HOME. The previous release is the latest
release before the candidate, whatever it is: the failure class is any two
releases whose runner protocols differ while their authority protocol is the
same (#5238).

- **Entry points:** the previous release's `cw`, then the candidate's.
- **States to exercise:**
  - **an authority left running.** The owner's failure (#5238): a credential
    authority started by an older `cw` keeps running, and the candidate's
    runner is not one its broker serves;
  - **a previous release's VM still running** at the upgrade, then given a
    profile;
  - **a previous release's VM, stopped.**
- **Driving it:**
  - **Authority left running:** with the previous release,
    `cw credentials --local list`, which starts its authority and leaves it
    running. Then, with the candidate, step 1's sequence through
    `cw update --local N --profile local:N --yes` and `cw start --local N`.
  - **A previous release's VM still running:** with the previous release,
    create a VM and leave it running. With the candidate, select a profile
    for it with `cw update --local N --profile local:N --yes`.
  - **A previous release's VM, stopped:** with the previous release, create a
    VM with a profile and stop it. With the candidate, `cw start` it, which
    moves it onto the installed runtime
    ([local-vm-upgrade.md](local-vm-upgrade.md)).
- **Proof:**
  - **Authority left running:** the candidate's restart and start never fail
    with the bare `environment_sources_guest_start_failed` or
    `start_guest_start_failed` and runner detail `egress_broker_exited`.
    v0.4.21 fails that way, with `broker_not_ready …
    reason=lease_closed_before_ready` in the authority's broker log and the
    egress broker's own reason recorded nowhere. With v0.4.22 as the
    candidate it passes outright: its create starts no VM and so replaces the
    older authority at once, and the update's restart comes up running with
    the profile. A HOME that has already failed under v0.4.21 looks
    different: v0.4.22 refuses its start in words, and the next start after
    `cw stop` replaces the authority and passes (seen by hand on 2026-11-17,
    #5238; not yet observed by the smoke).
  - **A previous release's VM still running:** once #5238 lands, the update is
    refused before it changes anything, in words naming the VMs to stop, and
    the VM keeps running (the `local-vm-upgrade-credentials` step of
    [local-vm-upgrade.md](local-vm-upgrade.md), with #5238).
  - **A previous release's VM, stopped:** the start succeeds, and every
    credential step above passes in the moved VM.

  After #5238, each of these passes, or is refused in the spec's words with
  the VM untouched.
- **Observed:** not yet observed by the smoke. By hand on a Linux local VM
  host with released binaries, 2026-11-17 (#5238):
  - the authority case with v0.4.15, then v0.4.21: failed as described;
  - the same case with v0.4.15, then v0.4.22: passed outright. Every step
    exited 0, the restart came up running at generation 2 with the profile,
    and the broker was ready after 0.4 s.

## 5. `smoke-proxy-down`: the proxy down fails closed

- **States to exercise:** the egress broker or the credential broker killed
  while the VM runs.
- **Driving it:** kill the process, make a credentialed request from the
  guest, then `cw stop` and `cw start`.
- **Proof:** the request fails within seconds with a readable refusal, and
  stop and start restore it. Nothing leaves the guest another way: the
  synthetic providers record no call while the process is down, and a direct
  connection from the guest to a provider's address, around the proxy, is
  refused.
- **Observed:** not yet observed.
