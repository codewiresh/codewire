# The launch walk

The public launch (#4370) is done when a new account, with no help from us,
walks these steps on Production and every one is observed working. This file
is the index of that walk: the order, what the launch asks of each step,
where each step's commands and observations are kept, and where the whole
walk stands. The format is in [README.md](README.md).

The steps and their numbers are #4370's. A step whose feature has its own
journey file points there and repeats nothing from it. A step without one
keeps its detail here until that file exists. Step 7 is out of the launch
since 2026-11-13; its number stays so that the others keep theirs. Use one
sandbox for steps 2 to 10; the examples call it `launch-walk`.

## Where the walk stands

Updated 2026-11-13. On Production, parts of step 9 are observed and nothing
else is.

| Step | ID | Detail | Dev | Production |
| --- | --- | --- | --- | --- |
| 1 | `launch-signup` | below | failure paths observed 2026-11-11 (#4062); a sign-up not yet observed | not yet observed |
| 2 | `launch-agent-push` | below | not yet observed; the fix (#4303) is released in `v0.4.17` | not yet observed |
| 3 | `launch-preview` | [previews-and-ports.md](previews-and-ports.md) | not yet observed | not yet observed |
| 4 | `launch-cp` | [cloud-sandbox.md](cloud-sandbox.md) | upload, resume and download observed 2026-11-13 with builds of the fixes (#4373, #4394); not yet with a released `cw` | not yet observed |
| 5 | `launch-invite` | [invitations.md](invitations.md) | invite and email observed 2026-11-13 (#3847); accept and remove not yet observed | not yet observed |
| 6 | `launch-buy-credit` | [billing-and-credits.md](billing-and-credits.md) | card, top-up, costs and refusal observed (#3381, #3954); Add credit and the receipt not yet observed | not yet observed |
| 7 | `launch-idle-wake` | out of the launch | out of the launch (owner, 2026-11-13) | out of the launch |
| 8 | `launch-password-reset` | below | not yet observed | not yet observed |
| 9 | `launch-node-reboot` | [node-reboot.md](node-reboot.md), and below for the restart notice | restart notice observed 2026-11-13 after a Pod delete (#4376) | two worker drains observed 2026-11-13 (#3542); a reboot, STUN and the relay, Mesh and the restart notice not yet observed |
| 10 | `launch-snapshot-fork` | below | a snapshot and three forks observed 2026-11-13 with `v0.4.17` (#4370) | not yet observed |
| 11 | `launch-mac-local-vm` | [local-vm-mac.md](local-vm-mac.md) | runs on a Mac: observed 2026-11-13 on macOS 27 and 26 with a development build (#4478); not yet with a released `cw` | does not apply |

The owner reported on 2026-11-13 that signing in with GitHub and with Google
works (#4062). The record does not name the surface or the release, so
neither column of step 1 counts it.

## Before the walk

- The walker is a new account that has never used Codewire. The Production
  smoke identity (`scripts/runtime/prod/with-prod-smoke-auth.sh`) may only
  create, inspect and remove its own environments, so it can rehearse the
  sandbox steps but cannot stand in for sign-up, payment or email.
- Rehearse on Dev first. `scripts/runtime/dev/with-dev-smoke-auth.sh --
  COMMAND` runs one command as the synthetic Dev identity; `--openbao-path`
  selects another synthetic identity, such as the billing rehearsal one.
- Install the released `cw` the public docs point to, and record
  `cw version` with every observation.
- An observation on Dev says nothing about Production: the two differ in
  payment mode, in storage nodes and in how many Mesh and NATS servers run.
- Step 11 needs an Apple silicon Mac on the current macOS and one on the
  previous release.

## 1. `launch-signup`: sign up, verify and start at the sign-up credit

Issues: #4062 (sign in with GitHub or Google), #4481 (an email sign-up is
verified by the person who chose its password), #3297 (sign-up and creation
rate limits), #3381 (compute credit; the sign-up credit is #3989).

The launch asks for sign-up with GitHub, with Google, and with an email and
password, with no access review, and a verified email. The new organization
is on the Regular rate card with whatever sign-up credit the platform is set
to give. #4062 plans a journey file for sign-up; until it exists the detail
stays here.

- **Entry points:** the sign-up and login pages in a browser; the browser
  page `cw login` opens.
- **States to exercise:**
  - a new GitHub identity, a new Google identity, and a new email and
    password;
  - a second sign-in with the same identity reaches the same account;
  - cancelling at the provider returns to the login page with "Sign-in was
    cancelled. Choose how you'd like to sign in.";
  - an identity whose email matches an existing account links only after
    that account signs in, never by the email alone;
  - an email-and-password sign-up cannot sign in until its address is
    verified.
- **Driving it:**
  1. On the sign-up page choose **Continue with GitHub**, or **Continue with
     Google**, and finish at the provider; or sign up with an email and a
     password and follow the verification email. The account is usable at
     once: access review is off at launch (owner, 2026-11-13, #3013). If it
     waits for review, review is still on and the step fails.
  2. Create an organization (**New Organization** in the organization
     switcher).
  3. From a terminal:

     ```sh
     cw login
     cw whoami
     cw cost
     ```

     `cw login` opens a page that offers the same two buttons. `cw whoami`
     names the account. `cw cost` prints the organization's `Balance`.
- **Proof:** `cw whoami` names the same account after the second sign-in,
  and `Balance` equals the sign-up credit the platform is set to give.
- **Gotchas:**
  - The sign-up credit is a platform setting, `signup_credit_cents`, that
    starts at 0. A new organization gets it once, when it is created, and
    sees it as the balance on its Billing page. While it is 0, a balance of
    0 is the correct result and proves nothing about the grant.
  - Only a real GitHub or Google account proves the provider states.
- **Observed:**
  - Dev, 2026-11-11, at `91d8c52e2` (#4062): the login page showed both
    provider buttons, each one redirected to its provider, and a cancelled
    sign-in returned to the login page with the message above. No account
    was created.
  - A sign-up, a repeat sign-in, linking and `cw login` through a provider:
    not yet observed on a named surface. The owner's report of 2026-11-13
    is above.
  - The sign-up credit was 0 on Dev and on Production when read on
    2026-11-12, so no grant has been seen.

## 2. `launch-agent-push`: a sandbox, an agent, and a Git push over 4 MiB

Issues: #4280 (the credential bridge buffers Git bodies; its fix is #4303),
#4427 (`cw run --no-tty` can return partial output), #4431 (a create whose
Pod breaks shows `creating` for a long time).

- **Entry points:** `cw create` and `cw run`; the dashboard's create page and
  browser terminal.
- **States to exercise:**
  - the agent clones, commits and pushes a branch;
  - a push whose pack is larger than 4 MiB;
  - an organization with no credit: `cw create` exits 1 and says the
    organization "has no compute credit, so it can't run cloud sandboxes."
- **Driving it:** connect GitHub to the account first, and use a repository
  the account can push to.

  ```sh
  cw create https://github.com/OWNER/REPO --name launch-walk
  cw run claude --in launch-walk
  ```

  Ask the agent to make a branch, commit a change and push it. Then push a
  pack that cannot fit in 4 MiB:

  ```sh
  cw exec --in launch-walk -w WORKDIR sh -c '
    git switch -c launch-walk-large &&
    head -c 6291456 /dev/urandom > large.bin &&
    git add large.bin &&
    git commit -m "launch walk: a 6 MiB file" &&
    git push -u origin launch-walk-large &&
    test "$(git rev-parse HEAD)" = \
      "$(git ls-remote origin refs/heads/launch-walk-large | cut -f1)"'
  ```

  `WORKDIR` is the repository's directory in the sandbox; `cw info
  launch-walk` prints it as `Working dir`. `cw exec` exits with the
  command's status, so 0 means the push arrived.
- **Proof:** the remote branch's commit equals the local `HEAD`, for the
  agent's branch and for the large one.
- **Gotchas:**
  - The remote must be HTTPS through the managed GitHub connection. An SSH
    remote with the user's own key never passes the 4 MiB limit and proves
    nothing here.
  - Random data is used because it does not compress; a large text file can
    pack to under 4 MiB.
  - No token or credential helper is needed: the sandbox's Git
    configuration sends `github.com` through the managed connection.
  - Delete both branches afterwards.
- **Observed:**
  - Dev and Production: not yet observed.
  - The failure before the fix is known from tests, not from a run: the
    bridge limited a request body to 4 MiB and its unit tests asserted the
    413 for a larger one (#4280).
  - Kind, 2026-11-12, the fix's branch at `337fc1054` (#4303, merged since
    and released in `v0.4.17`), stock `git` against a synthetic GitHub
    fixture: a 264 MiB clone and a 20,978,383-byte push both succeeded.
    That is not a real GitHub repository and not a hosted cluster.

## 3. `launch-preview`: a preview of a dev server, including one on localhost

Issue: #4357 (a cloud preview of a server bound to loopback).

The commands, the proof and the observations are
`preview-cloud-loopback` in [previews-and-ports.md](previews-and-ports.md).
The launch walks it on Production in the `launch-walk` sandbox, with the dev
server the agent started in step 2 where the project has one. `cw ports` on
a local VM (`ports-local-publish` in the same file) is not part of this
step.

The launch adds one state to that journey: a signed-out browser that opens a
`creator` preview is asked to sign in and is then returned to the page.

- **Observed:** not yet observed on Dev or Production. The signed-out state
  is not yet observed either. The Ports dialog is covered on Kind by
  `apps/dashboard/e2e/ssr-dashboard.preview-ports.ssr.ts`.

## 4. `launch-cp`: copy a file over 4 MiB in and out, and resume an upload

Issues: #3968 (`cw cp` sent a whole file as one message; its fix is #4393),
#4373 (a cloud upload over about 100 MB; its fix, uploads in resumable
parts, is #4416), #4394 (cloud downloads were slow), #4426 (a release
rollout cuts a copy in flight).

The commands, the proof and the observations are in
[cloud-sandbox.md](cloud-sandbox.md): `sandbox-cp-upload`,
`sandbox-cp-resume` and `sandbox-cp-download`. The launch walks all three on
Production in the `launch-walk` sandbox: a file over 4 MiB in and out with
equal checksums, and a 1 GiB upload that is interrupted and resumed by
running the same command again.

- **Gotchas:** resumable uploads (#4416) are on `main` and in no release
  yet. `v0.4.17` refuses a cloud upload over about 100 MB, so this step
  cannot pass on Production before a release that includes #4416.
- **Observed:**
  - Dev: all three are observed with builds of the fixes, on 2026-11-12 and
    2026-11-13. The evidence is in the file above.
  - With a released `cw`, and on Production: not yet observed.

## 5. `launch-invite`: invite a teammate, who accepts and can be removed

Issues: #3840 (accept an invitation and remove a member from `cw`), #3847
(the invitation email), #4457 (limits on invitations).

The commands, the proof and the observations are in
[invitations.md](invitations.md). The launch walks four of its
sub-features on Production, in this order: `invite-send`, `invite-email`,
`invite-accept` and `invite-remove`. The email has to arrive in the
teammate's own mailbox; handing the link over by hand skips half the step.

- **Observed:**
  - Dev, 2026-11-13, Dev at `6c3651dcf` and `cw` built from `27707e6c2`
    (#3847): `cw org invite` created an invitation and reported the email
    sent; a second invitation to the same address and one to an existing
    member were each refused; an invitation to a mailbox the owner reads
    arrived.
  - Accepting and removing: not yet observed.
  - The `cw` commands for accepting, listing and removing (#4453) are on
    `main` and in no release yet.
  - Production: not yet observed.

## 6. `launch-buy-credit`: buy credit, get a receipt, see correct costs

Issues: #3381 (compute credit on Production), #3954 (the Billing page shows
costs in credits), #3263 (Stripe to billing, proven continuously), #2053
(mail delivery on Production).

The commands, the proof and the observations are in
[billing-and-credits.md](billing-and-credits.md). The launch walks, on
Production: `billing-card`; then `billing-auto-top-up` or
`billing-add-credit`; `billing-receipt`; and `billing-costs`.
`billing-zero-refusal` is what step 2's organization with no credit meets.

- **Gotchas:**
  - On Production this step spends real money. It is the walker's own card
    and the walker's own decision.
  - Dev's payment provider is in test mode. A Dev walk proves the flow,
    not a real payment.
- **Observed:**
  - Dev: the card, the automatic top-up, costs in credits and the refusal
    at an empty balance are observed. **Add credit** and the receipt email
    are not. The dates and evidence are in the file above.
  - Production: not yet observed. Credit is not enforced there yet (#3381).

## 7. `launch-idle-wake`: out of the launch

The owner moved idle stop out of the launch on 2026-11-13: "Idle stop is
something that we can add later. It doesn't need to gate us for the launch."
(#3384, recorded on #3013). The step keeps its number so the others don't
move. Its design is on #3384, and its walk gets a journey of its own when
#3384 is built.

## 8. `launch-password-reset`: a reset email arrives and works

Issue: #2053 (mail delivery on Production).

- **Entry points:** **Forgot password?** on the login page; **Settings →
  Account → Security → Reset password**.
- **States to exercise:** a link used twice, and a link opened after its
  hour has passed.
- **Driving it:** on the login page choose **Forgot password?**, enter the
  walker's address and choose **Send reset link**; the page answers "Check
  your email". Open the link from the email and set a new password. This
  applies to an account that has a password; record what an account
  created through GitHub or Google is offered.
- **Proof:** the email arrives in a mailbox outside Codewire's own domain;
  the old password is refused and the new one signs in.
- **Gotchas:** the Kind spec binds a synthetic reset token. It proves the
  page flow, not that mail is delivered.
- **Observed:** not yet observed on Dev or Production; no delivered reset
  email can be cited (#2053). Related, and not this step: on Production
  on 2026-10-29 the sign-up access email reached an outside mailbox with
  DKIM, SPF and DMARC passing (#2053). The page flow is covered on Kind by
  `apps/dashboard/e2e/ssr-dashboard.auth.ssr.ts`.

## 9. `launch-node-reboot`: a node reboots and the user is told why

Issues: #3542 (Mesh and NATS survive a node reboot), #4461 (STUN and the
peer relay run on one node), #3772 (show why a sandbox restarted).

This step has two halves.

**Production keeps serving.** The commands, the proof and the observations
are in [node-reboot.md](node-reboot.md): `reboot-nats`,
`reboot-coordinator`, `reboot-sessions`, `reboot-spread`,
`reboot-stun-relay` and `reboot-mesh`. On 2026-11-13 two Production workers
were drained and the first three were observed through both drains; a
reboot, STUN and the relay, and Mesh are not yet observed, and the spread
check failed and was put right by hand.

**The sandbox on that node says why it restarted.** No journey file holds
this half yet, so it stays here.

- **Entry points:** none for the user. An operator reboots one Production
  node during the walk; the user reads `cw info`, `cw ls` and the
  dashboard.
- **States to exercise:** a sandbox on the rebooted node, with an SSH
  session and a preview held open across the reboot.
- **Driving it:** before the reboot, start a long-running session in the
  sandbox. While the node is down and after it returns:

  ```sh
  cw ls
  cw info launch-walk
  ```

  While the sandbox comes back, `cw info` shows `State: starting` and a
  `Notice:` that its runtime is being replaced, that its files are safe
  and that running processes were lost. Once it is back it shows `State:
  running` and `Notice: Restarted at HH:MM UTC after its runtime was
  replaced.`
- **Proof:** the sandbox on the rebooted node returns to `running`, and
  `cw info` and the dashboard both say that it restarted, when, and that
  running processes were lost.
- **Gotchas:** `scripts/runtime/dev/prove-dev-vm-death-recovery.sh` is the
  nearest Dev proof. It kills one sandbox's VM and proves recovery by a new
  guest boot ID and Pod UID. The node stays up, so it is not a node reboot.
- **Observed:**
  - Kind, 2026-10-31: a sandbox's container was stopped by hand and the
    CLI's wording for an unexpected stop was read through recovery (#3772,
    #3786). That is neither a node reboot nor a real kill.
  - Dev, 2026-11-12, at `37fad5f88`: a sandbox whose Pod was deleted while
    it ran stayed `running` and showed no notice. #4376 fixed that.
  - Dev, 2026-11-13, at `1c99c3a6b` (#4340 and #4376): the Pod of a
    running standard sandbox was deleted, which stands in for a node going
    away. `cw info --output json` reported `starting` with code
    `sandbox_replacing` after 5.9 s, and `running` with code
    `sandbox_restarted` and the reason "Restarted at 09:02 UTC after its
    runtime was replaced. Running processes were lost." after 14.1 s. The
    walk read the JSON fields; the printed `Notice:` lines are not yet
    observed with a released `cw`. The open session ended with "the
    session attachment ended unexpectedly" (#4342).
  - Production: not yet observed. The drains of 2026-11-13 did not record
    what a sandbox on the drained node showed.
  - The dashboard does not show the reason yet (#3772).

## 10. `launch-snapshot-fork`: take a snapshot and create a fork from it

Issue: #4370 (hosted snapshots on Production; forks landed in #3754).

- **Entry points:** `cw snapshot create` and `cw create --snapshot`, each
  with `--cloud`.
- **States to exercise:**
  - a snapshot of a running sandbox is refused: it must be stopped;
  - one fork, and several with `--count`;
  - a fork while the snapshot's node is unavailable (#4371);
  - a snapshot at zero credit is refused (#4379).
- **Driving it:**

  ```sh
  cw exec --in launch-walk sh -c 'date > /workspace/snapshot-marker'
  cw --cloud stop launch-walk
  cw --cloud snapshot create launch-walk --name launch-walk-snap
  cw --cloud create --snapshot launch-walk-snap --name launch-walk-fork
  cw exec --in launch-walk-fork cat /workspace/snapshot-marker
  ```

  `snapshot create` prints "Created snapshot launch-walk-snap." With #4387
  it adds that the snapshot is kept on the storage node that holds the
  sandbox's disk and is not backed up.
- **Proof:** the fork's marker file has the same content as the source's,
  and `cw ls` lists the fork as its own sandbox.
- **Gotchas:**
  - Limits accepted for launch (#4370, 2026-11-12): a snapshot stays on one
    storage node and is not backed up, so it is lost with that node;
    snapshots are not billed; an organization can hold 32.
  - A fork starts on the snapshot's node. While that node is unavailable, a
    fork waits (#4371).
  - Codewire's delivered sign-ins are cleared from a snapshot. Anything
    else on the disk, such as a `.env` file, is kept.
- **Observed:**
  - Dev, 2026-11-12, `cw` built from #4387's branch: `cw --cloud snapshot
    create` printed both lines above.
  - Dev, 2026-11-13 (#4379): a capture was refused at an empty balance and
    admitted once credit was restored.
  - Dev, 2026-11-13, `cw` built from `v0.4.17`, as the Dev smoke identity
    (#4370, "Step 10: the Production capture-and-fork walk, rehearsed on
    Dev"): `cw --cloud snapshot create` on a stopped sandbox printed both
    lines above in 18 s; `cw --cloud create --snapshot` with `--count 3`
    created three forks in 29 s, each running on the snapshot's node with
    the marker file intact. Everything was removed afterwards.
  - Production, 2026-11-12, storage only (#4370): a volume snapshot was
    taken and restored, including when the scheduler first chose another
    node. That is a prerequisite, not this step.
  - The user step on Production: not yet observed. Production turns
    snapshots on with the promotion that delivers deploy#242, which had not
    happened when read on 2026-11-13.

## 11. `launch-mac-local-vm`: a local VM on a Mac

Issues: #4478 (local VMs did not start on macOS 27; its fix is #4491),
#2880 (local VM and Mac release qualification).

The owner added this step on 2026-11-13: "100 % local VMs on the Mac have to
work" (#4478, recorded on #3013). It runs on the walker's own Mac, not on
Production. The commands, the proof and the observations are
`mac-vm-lifecycle` in [local-vm-mac.md](local-vm-mac.md). The launch asks
for it on the current macOS and on the previous one: install `cw`, create a
local VM, open a shell in it, run a command, stop it and start it again.

- **Observed:**
  - macOS 27 and macOS 26, 2026-11-13: the walk is observed with a
    development build of the fix, set up from a local runtime directory
    in place of the install steps. `v0.4.16` failed on macOS 27.
  - The fix (#4491) is on `main` and in no release yet. The walk with a
    released `cw`, install steps included: not yet observed.

## Beside the walk

#4370 also requires that the public source names no cluster or private host
and cites no document that exists only in private files (#1383, #2996).
That is checked in the source, not walked.
