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

Updated 2026-11-23. Every step not listed as observed is **not yet
observed**.

| ID | Linux local VM | Run by |
| --- | --- | --- |
| `smoke-profile-after-create` | observed, v0.4.22, 2026-11-18 (by hand) | `scripts/ci/verify/smoke-local-credentials.sh` |
| `smoke-credential-ssh` | not yet observed | no command yet (#5220) |
| `smoke-credential-github` | not yet observed | no command yet (#5220) |
| `smoke-credential-claude` | not yet observed | no command yet (#5220) |
| `smoke-credential-codex` | not yet observed | no command yet (#5220) |
| `smoke-attach-restart` | observed, v0.4.22, 2026-11-18 (by hand) | `scripts/ci/verify/smoke-local-credentials.sh` |
| `smoke-upgrade` | not yet observed | no command yet (#5220) |
| `smoke-proxy-down` | observed, `main` at 1250f23ed, 2026-11-18 (by hand); the readable refusal (#5359) with a development build of its change, 2026-11-23 (by hand) | `scripts/ci/verify/smoke-local-credentials.sh` |
| `smoke-provider-unresolved` | observed, `main` at 4cae0f601, 2026-11-18 (by hand) | `scripts/ci/verify/smoke-local-credentials.sh` |

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
  start with the credential still revoked (#5545); after re-enrolment.
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
  - The refusal is a hosted Sandbox's (#5593): 403, `Codewire-Refusal:
    credential_revoked`, a body that names the provider, and a `Fix:` line
    naming `cw credentials --local list`. A withheld SSH identity's
    signature is denied. Not yet observed: the smoke's step still asserts
    the generic `denied` it had before #5593.
  - The start with the credential still revoked succeeds (#5545). It prints,
    before its next step, exactly `KIND 'NAME' in profile PROFILE is revoked;
    agents in this VM can't use it.` and the command that fixes it. The VM's
    other capabilities keep working, and the revoked one's request is still
    refused.
  - Re-enrolling the same credential serves the next request, with no stop
    or start in between, when it is the profile's only usable credential.
    With another usable credential in the profile, it serves from the next
    start, until #5615.
- **Observed:** `claude`, 2026-11-20, with #5541, #5512 and #5545 on a
  local tree: every state above passed, including the start with the sign-in
  still revoked. The start printed `Claude (sign-in) 'native-broker-claude'
  in profile native-claude is revoked; agents in this VM can't use it.` and
  its reconnect command, and the request after re-enrolling was answered
  without a restart. `ssh`, `github` and `codex` not yet observed.

## 3. `smoke-attach-restart`: attach across a restart

- **Entry points:** `cw attach`, `cw stop`, `cw start`.
- **Driving it:** `cw run --detach --tty` a shell in a VM with a profile,
  `cw attach` to it through a terminal, sign with the profile's key through
  the guest's agent, and detach with Ctrl-B then d. Then `cw stop` and
  `cw start`, and attach to a new session the same way. A session running at
  the stop is shown `Interrupted` after the start; attaching to it replays its
  saved output and says the session exited.
- **Proof:** each attach reaches a live shell, which prints a value only a
  running shell can compute, and the shell signs with the profile's key
  through its agent (`ssh-keygen -Y sign`). After the restart, the agent
  still holds the generated key's fingerprint.
- **Observed:** v0.4.22, 2026-11-18, by hand on a Linux host: the same run
  as step 1 printed `ok smoke-attach-restart`, and nothing was left on the
  host. Not yet run in CI (#5220).

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

- **States to exercise:** the credential broker killed while the VM runs,
  then the egress broker.
- **Driving it:** a loop in the guest, about four times a second, makes an
  HTTPS request to Codewire's release channel by name, an HTTP request
  straight to that host's IPv4 address, and asks the agent for its keys
  (`ssh-add -l`), logging each start time and result to the workspace. The
  host measures the guest clock's offset through `cw exec` (to within half a
  second), kills the one helper of that kind the `cw` under test runs for
  the VM, then reads the log in the host's clock. After the egress broker's
  kill, `cw ls --output json` and `cw exec`, then `cw start` alone.
- **Proof:**
  - **The credential broker mends by itself,** as
    [SECRETS-AND-CREDENTIALS.md](../dev/SECRETS-AND-CREDENTIALS.md) says:
    the credential service starts another, the agent answers again, and no
    agent request fails more than five seconds after the kill. No restart is
    needed.
  - **The egress broker fails closed:** no request the guest starts a
    second or more after the kill gets an answer, whether through the proxy
    or straight to an address, and the VM turns `error`. `cw start`
    restores HTTPS from the guest.
  - **A readable refusal** (#5359): after the egress broker's kill,
    `cw ls --output json` has `"error": "egress_broker_exit"` for the VM,
    and `cw exec` in it fails saying that the VM's network broker stopped,
    so nothing can leave the VM, with `cw --local start NAME` as its next
    step. `cw --local start NAME` alone then restores HTTPS from the guest,
    and the VM's `error` is `null` again. `cw --local info`, `cw shell` and
    `cw run` say the same; the smoke does not check those three.
  - **How it ended** (#4953): after the kill,
    `cw --local info NAME --output json` has `"runner_exit": {"status":
    null, "signal": 9}`, `cw --local info NAME` says the broker was ended by
    signal 9, and `cw --local daemon logs NAME` shows the same in its
    `# exit` part. Observed on Linux on 2026-11-22 with a development build
    of #4953's change, by a SIGKILL of the egress broker outside the smoke,
    which does not check this yet. `cw --local info` read `Error:
    egress_broker_exit (ended by signal 9)`, and the JSON was as above. The
    daemon logs read `# exit` then `egress_broker_exit: ended by signal 9`.
    After a stop and a start the VM ran again and showed no error and no
    `# exit` part.
  - **No provider call while it is down:** with synthetic providers, Part B
    (#5220).
- **Observed:** `main` at 1250f23ed, 2026-11-18, by hand on a Linux host,
  with a static `cw` built from it and a runtime built from main the same
  day: `smoke-local-credentials.sh --cw <it> --runtime-from <runtime>
  --scratch <dir>` printed `ok smoke-proxy-down` after the other steps, and
  nothing was left on the host. Exploring it with v0.4.22 the same day, one
  agent request failed in the 0.2 s after the credential broker's kill, and
  every request failed from the first one after the egress broker's.
  Against a `cw` built from `main` before #5359 the step failed with "cw ls
  --output json does not give egress_broker_exit as the error of the VM".
  With the readable refusal, 2026-11-23, a static `cw` built from #5359's
  change merged with `main`, and a runtime built from 6636e3589f the same
  day: the whole smoke printed `ok` for each of its four steps. By hand on the
  same build, after a SIGKILL of a VM's egress broker:
  - `cw --local info` read ``Error: egress_broker_exit (ended by signal 9):
    the VM's network broker stopped, so nothing can leave the VM;
    `cw --local start exw` starts it again``;
  - `cw ls --output json` had `"error": "egress_broker_exit"`;
  - `cw exec`, `cw shell` and `cw run` each failed with `✗ Local VM exw
    can't be reached: the VM's network broker stopped, so nothing can leave
    the VM` and `→ cw --local start exw`;
  - `cw --local start exw` alone brought it back in 19.7 s, a command ran,
    and its `error` was `null` again.

  Not yet run in CI (#5220).

## 6. `smoke-provider-unresolved`: a provider's name doesn't resolve when the VM starts

The automated form of `cred-provider-unresolved` in
[credentials.md](credentials.md) (#5286): the owner's failure on v0.4.22,
where one provider's lookup getting no answer failed the whole create.

- **Entry points:** `cw credentials --local add`, `cw create --local
  --profile`, `cw exec`, `cw stop` and `cw start`.
- **States to exercise:** every provider name in the profile unanswered for
  the credential service when the VM is created and when it starts again;
  the names resolving again while it runs.
- **Driving it:** two made-up API keys, Anthropic and OpenAI, in one profile.
  The credential service is started by the first `cw credentials` command in
  a mount namespace whose resolver configuration names an address nothing
  listens on (the isolation library's `SMOKE_RESOLVER`), and its brokers
  keep that resolver. `cw create` and the VM's image pull use the host's.
  Later the same file is rewritten in place with the host's configuration.
  Nothing is changed on the host, and no firewall rule is involved.
- **Proof:**
  - the create succeeds, and the credential service's broker log has
    `broker_ready` with `unresolved=api.anthropic.com/api.openai.com`;
  - a request on each provider's route from the guest gets 502 with
    `Codewire: PROVIDER couldn't be reached; try again.`;
  - `cw stop` and `cw start` bring the VM back running;
  - within two minutes of the file being rewritten, a later `broker_ready`
    has `unresolved=-`, with no restart.
- **Not in this step:** no request is made once the names resolve, so no
  provider is contacted; the guest disk search of
  [Every step's checks](#every-steps-checks) is not done here yet.
- **Gotchas:**
  - it needs a `cw` that resolves from `/etc/resolv.conf`, as the static
    `cw` a release ships does. A `cw` built against the system C library may
    ask the system's resolver service instead; the step then fails and says
    so;
  - it runs first, because the credential service keeps the resolver it was
    started with;
  - a host firewall must answer the broker's own lookups for the last proof.
- **Observed:** `main` at 4cae0f601, 2026-11-18, by hand on a Linux host, with
  a static `cw` and the local VM runtime both built from that commit:
  `scripts/ci/verify/smoke-local-credentials.sh --cw <cw> --runtime-from
  <runtime> --scratch <dir>` printed `ok smoke-provider-unresolved` and then
  `ok smoke-profile-after-create`, and left nothing on the host. The same
  command with the released v0.4.22 fails this step at the create, in
  `cw`'s words: `create_failed`, "the local VM runtime gave no cause". That
  is the failure #5286 fixed. Not yet run in CI (#5220).
