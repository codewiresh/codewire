# The launch walk

The public launch (#4370) is done when a new account, with no help from us,
walks these ten steps on Production and every one is observed working. This
file is that walk: what to run at each step, what must be seen, and what has
been seen so far. The format is in [README.md](README.md).

The steps and their order are #4370's. Each step lists the issues that have
to land before it can pass. Use one sandbox for steps 2 to 10; the examples
call it `launch-walk`.

## Where the walk stands

Updated 2026-11-13. No step is observed working on Production.

| Step | ID | Dev | Production |
| --- | --- | --- | --- |
| 1 | `launch-signup` | not yet observed | not yet observed |
| 2 | `launch-agent-push` | not yet observed; the fix (#4303) passed on Kind 2026-11-12 and is released in `v0.4.17` | not yet observed |
| 3 | `launch-preview` | not yet observed | not yet observed |
| 4 | `launch-cp` | observed 2026-11-12 with a build of the fix (#4393), since released in `v0.4.17`; not yet observed with a released `cw` | not yet observed |
| 5 | `launch-invite` | not yet observed | not yet observed |
| 6 | `launch-buy-credit` | card, charge, invoice and refusal observed 2026-11-11 (#3381); Add credit and receipt email not observed | not yet observed |
| 7 | `launch-idle-wake` | not yet observed; work paused | not yet observed |
| 8 | `launch-password-reset` | not yet observed | not yet observed |
| 9 | `launch-node-reboot` | restart notice observed 2026-11-13 after a Pod delete (#4376); a node reboot not observed | not yet observed |
| 10 | `launch-snapshot-fork` | snapshot create observed 2026-11-12 (#4387); fork not observed | not yet observed |

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

## 1. `launch-signup`: sign up and get the free credit

Issues: #4062 (sign in with GitHub or Google), #3297 (abuse resistance),
#3381 (compute credit; the sign-up credit is #3989).

- **Entry points:** the sign-up and login pages in a browser; the browser
  page `cw login` opens.
- **States to exercise:**
  - a new GitHub identity, and a new Google identity;
  - a second sign-in with the same identity reaches the same account;
  - cancelling at the provider returns to the login page with "Sign-in was
    cancelled. Choose how you'd like to sign in.";
  - an identity whose email matches an existing account links only after
    that account signs in, never by the email alone.
- **Driving it:**
  1. On the sign-up page choose **Continue with GitHub**, or **Continue with
     Google**, and finish at the provider. Record whether the account is
     usable at once or waits for review.
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
    sees it as the balance on its Billing page. Until the amount is chosen
    for Production, a balance of 0 is the correct result and proves nothing
    about the grant.
  - Only a real GitHub or Google account proves this step.
- **Observed:** not yet observed. The provider flow is merged (#4160) and
  #4062 lists sign-up, repeat sign-in, linking and `cw login` through a
  provider as not yet walked. The sign-up credit was 0 on Dev and on
  Production when read on 2026-11-12, so no grant has been seen.

## 2. `launch-agent-push`: a sandbox, an agent, and a Git push over 4 MiB

Issue: #4280 (the credential bridge buffers Git bodies).

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
  - The failure on `main` is known from tests, not from a run: the bridge
    limits a request body to 4 MiB and its unit tests assert the 413 for a
    larger one (#4280).
  - Kind, 2026-11-12, the fix's branch at `337fc1054` (#4303, merged since
    and released in `v0.4.17`),
    stock `git` against a synthetic GitHub fixture: a 264 MiB clone and a
    20,978,383-byte push both succeeded. That is not a real GitHub
    repository and not a hosted cluster.

## 3. `launch-preview`: a preview of a dev server, including one on localhost

Issues: #4357 (a cloud preview of a server bound to loopback), #4347 (the
same for `cw ports` on a local VM).

- **Entry points:** `cw ports`; the **Ports** dialog on the dashboard's
  Sandbox page; a preview declared in `codewire.yaml`.
- **States to exercise:**
  - a server on `0.0.0.0`;
  - a server on `127.0.0.1` only, which is what most dev servers do;
  - a signed-out browser opening a `creator` preview is asked to sign in,
    then returned to the page;
  - a port with nothing listening.
- **Driving it:** have the agent start the project's dev server, or start
  one that listens only on loopback:

  ```sh
  cw run --in launch-walk --name web --detach -- \
    python3 -m http.server 3000 --bind 127.0.0.1
  cw ports launch-walk --publish 3000 --label web --access creator
  cw ports launch-walk
  ```

  The publish prints the preview URL. Open it in the signed-in browser.
- **Proof:** the page the server serves appears at the preview URL. An
  answer of 502 "preview backend unreachable" is the failure.
- **Gotchas:** the public docs' example binds `0.0.0.0`, which passes today
  and hides the loopback case. Run both.
- **Observed:**
  - Not yet observed working on any surface.
  - That a loopback-only server answers 502 on a hosted sandbox comes from
    reading the code (#4357). Nobody has run it.
  - Local VM, 2026-11-12, `cw` v0.4.15: `curl` against a loopback-only
    server published with `cw ports` got an empty reply (#4347).
  - Local VM on Linux, 2026-11-13, `cw` and runtime built from #4415 at
    `73d18becc` (merged since, in no release yet): a loopback-only server
    published with `cw ports --publish` and `--host-port` answered 200, as
    did a server on `0.0.0.0`. macOS: not yet observed. This is the local
    half (#4347); the hosted preview (#4357) is unchanged. Per #4415, a
    local VM started by an older runtime keeps the old path until it is
    stopped and started.
  - The Ports dialog itself is covered on Kind by
    `apps/dashboard/e2e/ssr-dashboard.preview-ports.ssr.ts`.

## 4. `launch-cp`: copy a file over 4 MiB in and out

Issues: #3968 (`cw cp` sends a whole file as one message; its fix is
#4393), #4373 (a cloud upload over about 100 MB; its fix is #4416).

- **Entry points:** `cw cp`. `scp`, `sftp` and `rsync` through `cw setup ssh`
  are a different path and do not count for this step.
- **States to exercise:** a file below 4 MiB, one above it, an interrupted
  transfer, and a download onto an existing file.
- **Driving it:**

  ```sh
  head -c 67108864 /dev/urandom > big.bin
  sha256sum big.bin
  cw cp big.bin launch-walk:/workspace/big.bin
  cw exec --in launch-walk sha256sum /workspace/big.bin
  cw cp launch-walk:/workspace/big.bin ./back.bin
  sha256sum back.bin
  ```

- **Proof:** the three checksums are equal.
- **Gotchas:**
  - On a slow link a large copy takes minutes. Record the time, and do not
    read a slow transfer as a failure.
  - A cloud upload over about 100 MB is refused with HTTP 413 before it
    reaches Codewire (#4373). The fix, uploads in resumable parts (#4416),
    is on `main` and in no release yet, and is not yet observed. The 64 MiB
    file above is under that limit on purpose.
- **Observed:**
  - Dev, 2026-11-08, `cw` v0.4.9: a 27 MB upload failed with `upload:
    message size 27124797 exceeds limit 4194304` (#3968). This is the
    failure the step exists to catch. Released `cw`, up to v0.4.16, still
    fails this way.
  - Dev, 2026-11-12, `cw` built from #4393's branch (merged since and
    released in `v0.4.17`): a 90 MiB upload took 32 s and a 1 GiB download
    372 s, with equal SHA-256 checksums both ways. A download interrupted
    with Ctrl-C left the destination unchanged and no partial file.
  - Local VM, 2026-11-12, the same build: a 1 GiB upload took 28 s and a
    1 GiB download 286 s, checksums equal. An interrupted upload left no
    file.
  - With a released `cw`, `v0.4.17` or later: not yet observed.

## 5. `launch-invite`: invite a teammate, who accepts and can be removed

Issues: #3840 (accept an invitation and remove a member from `cw`), #3847
(the invitation email).

- **Entry points:** **Settings → Members** on the dashboard; `cw org invite`.
- **States to exercise:**
  - the invitee has no account yet, and the invitee already has one;
  - the link opened by an account with a different email is refused;
  - a second invitation to the same email while one is pending;
  - a removed member loses access at once.
- **Driving it:**

  ```sh
  cw org invite teammate@example.com --role member --org SLUG
  ```

  This prints the invitation link once. The teammate must also receive an
  email (#3847), accept while signed in with that address, and appear on
  the Members page. An owner or admin then removes them there.

  No command yet: `cw` can invite but cannot list invitations, accept one,
  list members or remove one. #3840 adds those.
- **Proof:** the email arrives in the teammate's own mailbox; the teammate
  is listed as a member; after removal, the teammate's `cw org list` no
  longer shows the organization.
- **Gotchas:**
  - The link is shown once and is valid for 7 days.
  - Handing the link over by hand skips the email, which is half the step.
- **Observed:** not yet observed on any surface. On Dev on 2026-11-01,
  `cw org invite` created the invitation and sent no email (#3847). On
  `main` on 2026-11-13 that is still so, and `cw` still cannot accept an
  invitation or remove a member. The server side of listing and accepting
  your own invitations is merged (#4384) and released in `v0.4.17`; the `cw`
  commands are not. The dashboard's invitation pages are covered on Kind by
  `apps/dashboard/e2e/ssr-dashboard.governance.ssr.ts`.

## 6. `launch-buy-credit`: buy credit, get a receipt, see correct costs

Issues: #3381 (compute credit on Production), #4087 (a rejected credit
notice is retried every minute), #3954 (the Billing page shows costs in
credits), #3263 (Stripe to billing, proven continuously), #2053 (mail
delivery on Production).

- **Entry points:** the organization's **Billing** page; `cw cost`.
- **States to exercise:**
  - no card and no credit: creates and starts are refused, with the link to
    the Billing page;
  - a card that is charged;
  - a card that is declined;
  - a one-off purchase with **Add credit**, with a saved card and without
    one;
  - credit running out while a sandbox runs.
- **Driving it:**
  1. Run `cw cost` and note `Balance`.
  2. On the Billing page add a card. With an empty balance this charges
     the first automatic top-up at once.
  3. Choose **Add credit** and an amount. A saved card is charged
     directly; with no card, or when the bank asks for confirmation, the
     payment finishes on the payment provider's page.
  4. Run `cw cost` again, and `cw create` to see that creates work.
  5. Compare the page's costs with `This month` from `cw cost`.
- **Proof:** `Balance` rises by the amount paid; the Billing page lists a
  paid invoice for that amount; a receipt with the same invoice number
  arrives in the buyer's mailbox; the page's costs equal the CLI's.
- **Gotchas:**
  - Dev's payment provider is in test mode. A Dev walk proves the flow,
    not a real payment.
  - On Production this step spends real money. It is the walker's own card
    and the walker's own decision.
- **Observed:**
  - Dev, 2026-11-11, release candidate `b30889111`, synthetic billing
    identity (#3381): with no card, `cw create` was refused; adding a test
    card gave a balance of €20.00, one paid €20.00 invoice and an
    `invoice_paid` event; `cw create` then succeeded. The €20.00 was the
    first automatic top-up, not a grant.
  - Dev, 2026-11-11 (#4167): with a balance of −€7.14, one €20.00 top-up
    left +€12.86.
  - Dev, 2026-11-11 (#4096): the refusal at zero credit printed the
    wording in step 2.
  - **Add credit** (#4288): merged and released in `v0.4.17`, not yet observed.
  - Receipt email: not yet observed on any surface. Dev delivers mail only
    to the project's own address, so this waits for #2053.
  - Declined card: not yet observed. Costs in credits on the page (#3954):
    not yet observed.
  - Production: nothing observed. Credit is not enforced there yet
    (#3381).

## 7. `launch-idle-wake`: an idle sandbox stops, keeps its disk and wakes

Issue: #3384 (stop idle hosted sandboxes automatically).

- **Entry points:** none to stop it, which is the point. It wakes through
  `ssh`, `cw attach` and a signed-in preview.
- **States to exercise:**
  - idle past the timeout: the sandbox stops by itself;
  - an open `cw attach`, or a session that is using CPU, keeps it running;
  - a sandbox stopped with `cw stop` is not woken by SSH, and the message
    suggests `cw start`;
  - a signed-out request to a public preview does not wake it.
- **Driving it:** write a marker file, detach and wait.

  ```sh
  cw exec --in launch-walk sh -c 'date > /workspace/idle-marker'
  cw ls
  ```

  After the timeout, `cw ls` shows the sandbox stopped and says it was
  idle. Then connect with `ssh` (after `cw setup ssh`), with `cw attach`,
  and by opening the preview from step 3, each from a stopped sandbox.

  No command yet: the idle timeout and its setting do not exist. #3384's
  agreed design is a 30-minute timeout that is off by default and turned
  on for a sandbox or an organization, so the walk has to turn it on
  first.
- **Proof:** the marker file is intact after each wake; the organization's
  usage stops growing while the sandbox is stopped; the preview from step 3
  answers again after a wake.
- **Gotchas:** a woken sandbox has a new SSH host key. The wake has to
  connect without a host-key error.
- **Observed:** not yet observed. The design was agreed on 2026-11-12, no
  code has landed, and the work was paused on 2026-11-13.

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

Issues: #3542 (Mesh and NATS survive a node reboot), #3772 (show why a
sandbox restarted).

- **Entry points:** none for the user. An operator reboots one Production
  node during the walk; the user reads `cw info`, `cw ls` and the
  dashboard.
- **States to exercise:**
  - a sandbox on the rebooted node, and one on another node;
  - an SSH session and a preview held open across the reboot;
  - a new `cw create` while the node is down.
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
- **Proof:**
  - sandboxes on other nodes keep their sessions and stay reachable
    throughout, which is what shows Mesh and NATS kept serving;
  - the sandbox on the rebooted node returns to `running`, and `cw info`
    and the dashboard both say that it restarted, when, and that running
    processes were lost.
- **Gotchas:**
  - A reboot of a Production node is an operator action that needs the
    owner's approval each time.
  - Dev runs one Mesh and one NATS server on purpose, so a Dev reboot is
    not a rehearsal of this step (#3542).
  - `scripts/runtime/dev/prove-dev-vm-death-recovery.sh` is the nearest
    Dev proof. It kills one sandbox's VM and proves recovery by a new guest
    boot ID and Pod UID. The node stays up, so it says nothing about Mesh,
    NATS or other sandboxes.
- **Observed:**
  - A node reboot: not yet observed on any surface. No node has been
    drained or rebooted for #3542; its acceptance is a drain of each
    Production worker, once Production runs #4374, which is merged and
    released in `v0.4.17`.
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
  - Production, 2026-11-12, storage only (#4370): a volume snapshot was
    taken and restored, including when the scheduler first chose another
    node. That is a prerequisite, not this step.
  - The user step on Production: not yet observed. Production has
    snapshots turned off until a release that contains #4379.

## Beside the walk

#4370 also requires that the public source names no cluster or private host
and cites no document that exists only in private files (#1383, #2996).
That is checked in the source, not walked.
