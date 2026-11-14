# Invitations

An organization's owner or admin invites a teammate by email; the teammate
receives the email, accepts, appears as a member, and can be removed. This
file is that journey for `SPEC.md` "Organizations and members", with the
issues #3840 (accept, list and remove from `cw`), #3847 (the invitation
email) and #4457 (the invitation limits and the verified-inviter rule).
Launch step 5 (`launch-invite` in [launch.md](launch.md)) walks the same
feature on Production. The format is in [README.md](README.md).

## Where the journey stands

Updated 2026-11-14. Invite, email, accept and remove are observed on Dev
(source 6c3651dcf); the limits wait for Dev to run #4498. On Production
(v0.4.18, source a9dd8b270), the invitation and its email's send are
observed; the email's arrival is observed on Dev only.

| ID | Dev | Production |
| --- | --- | --- |
| `invite-send` | observed 2026-11-13 on 6c3651dcf (#3840) | observed 2026-11-14 on a9dd8b270 (#3847) |
| `invite-email` | observed 2026-11-13 on 6c3651dcf (#3847) | sent 2026-11-14 on a9dd8b270, arrival not observed (#3847) |
| `invite-accept` | observed 2026-11-13 on 6c3651dcf (#3840) | not yet observed |
| `invite-remove` | observed 2026-11-13 on 6c3651dcf (#3840) | not yet observed |
| `org-leave` | not yet observed | not yet observed |
| `invite-limits` | not yet observed | not yet observed |
| `invite-unverified` | not yet observed | not yet observed |

## Before the walk

- On Dev, two synthetic identities walk `invite-send`, `invite-accept`,
  `invite-remove` and `org-leave` with no person:
  - **The inviter** is the smoke identity, owner of `codewire-dev-smoke`
    (`scripts/runtime/dev/with-dev-smoke-auth.sh`).
  - **The invitee** is a password account with no organization
    (`scripts/runtime/dev/provision-dev-invitee-user.sh`, document
    `apps/codewire/dev/ci-invitee`).
  - `CW_BIN=… scripts/runtime/dev/invitations-journey.sh` runs those three
    steps. It prints each command with what it showed, and revokes every
    invitation it made.
- An API key is bound to one organization (`docs/dev/AUTH-POLICY.md`) and
  cannot list or accept invitations: `cw org invitations` with one answers
  "organization-scoped API key cannot perform account-global operations".
  So the invitee signs in through `cw login`'s device sign-in. The script
  approves the device code itself, with a password session that skips
  second-factor setup.
- The invitee's address is a mail provider simulator address, so the
  invitation email is accepted without reaching anyone and nothing bounces.
  The email's arrival still needs an address a person reads; see
  `invite-email`.
- The browser walk (the dashboard's invitation pages, and `invite-email`) uses
  e2e@codewire.sh as the invitee. It was created on Dev on 2026-11-13,
  verified, with two-factor, and owns `codewire-dev-e2e`. Its sign-in moves
  into OpenBao after the owner's enroll, which is pending.
- Record `cw version` with every observation. An observation on Dev counts
  only for the source Dev had rolled out.

## `invite-send`: an owner or admin invites by email

- **Entry points:** `cw org invite`; **Invite Member** on the organization's
  Members page in the dashboard.
- **States to exercise:**
  - a new invitation, as `member` and as `admin`;
  - a second invitation to the same email while one is pending: refused with
    "a pending invitation already exists for this email";
  - an email that is already a member: refused with "user is already a
    member of this organization";
  - a caller who is only a `member`: refused.
- **Driving it:**

  ```sh
  cw org invite INVITEE_EMAIL --role member --org SLUG
  ```

  It prints "Created an invitation for INVITEE_EMAIL as member. Its one-time
  link:", the link on its own line, and then what happened to the email
  (`invite-email`). On the dashboard, **Send Invite** shows "Invitation
  created" and the pending invitation under the members.
- **Proof:** the invitation is listed as pending on the Members page, and
  the invitee's `cw org invitations` lists the organization's slug.
- **Gotchas:** the link is printed once and is valid for 7 days. Revoke what
  the walk created (**Revoke** on the Members page) unless the next step
  uses it. `cw` cannot revoke yet (no command yet; #4508), so a walk
  without a dashboard session calls `OrganizationService.RevokeInvitation`
  with the same credential.
- **Observed:** Dev, 2026-11-13, source 6c3651dcf, `cw` built from 27707e6c2:
  the invitation, "Invitation email sent", and the duplicate refused, by
  `invitations-journey.sh` (#3840); the existing member refused, by hand
  (#3847). Production, 2026-11-14, v0.4.18 (source a9dd8b270), `cw` built
  from ecfe816e5, as the Production smoke identity in its own organization:
  the invitation to the mail provider's success simulator, "Invitation email
  sent", listed pending, the duplicate refused, then revoked by id and listed
  revoked (#3847).

## `invite-email`: the invitee receives the email

- **Entry points:** the email the platform sends; the outcome line after `cw
  org invite`.
- **States to exercise:**
  - the email is sent: "Invitation email sent to INVITEE_EMAIL. The link also
    works; the link is shown only once.";
  - sending failed or is waiting: the line says "Email not sent" or "Email
    not sent yet" with the reason, and to share the link instead;
  - an invitation refused by `invite-limits` or `invite-unverified` sends no
    email;
  - the email's button opens the invitation at `/accept-invite#t=<token>`
    (#3840, decided 2026-11-13). No command yet: the page and its token are
    not built (#3840, #4121);
  - the email uses the plain shared layout with a text part, from "Codewire
    <hello@codewire.sh>" (#4553). Not on main yet.
- **Driving it:** invite an address a person reads, and read the email
  there.
- **Proof:** the email arrives in that mailbox with the subject "You're
  invited to join an organization on Codewire". It names the organization,
  the inviter and the role, and the command `cw org accept SLUG`. Its
  **Sign in to Codewire** button opens the sign-in page. The CLI's
  "Invitation email sent" line says the platform handed the email to the
  mail provider; it does not prove arrival.
- **Gotchas:**
  - The email carries no one-time link. That link is printed once by `cw
    org invite` and shown once on the dashboard. Handing it over by hand
    skips this step.
  - A synthetic address proves the outcome line, never arrival. An address
    whose domain takes no mail bounces; use the mail provider's simulator
    addresses instead.
- **Observed:** Dev, 2026-11-13, source 6c3651dcf: an invitation to the
  owner's address arrived in that mailbox. The owner confirmed it, relayed by
  the orchestrator (#3847). On Dev on 2026-11-01, before #3847, `cw org
  invite` created an invitation and sent no email. Production, 2026-11-14,
  v0.4.18 (source a9dd8b270): an invitation to the mail provider's success
  simulator printed "Invitation email sent", and the IdP logged "sent
  invitation email" for it on the first attempt, which it logs only after the
  mail provider accepts the message. That is the send; arrival on Production
  is not observed (#3847).

## `invite-accept`: the invitee accepts

- **Entry points:** `cw org invitations` and `cw org accept`, as the email
  says; the one-time link from `invite-send` (`/accept-invite`) in the
  dashboard.
- **States to exercise:**
  - the invitee already has an account, and has none yet (signs up with the
    invited address, verifies it, then accepts);
  - the invitee's email is not verified: `cw org accept` says "your email
    address is not verified; verify it first", and the invitation stays
    pending;
  - the one-time link opened by an account with a different email:
    refused;
  - `cw org accept` naming an organization with no pending invitation lists
    the ones the invitee has;
  - from the email's button, `/accept-invite#t=<token>` (#3840, decided
    2026-11-13; no command yet, not built):
    - signed in as the invited, verified address: one click accepts;
    - signed out: asked to sign in or sign up, then returned to the
      invitation to accept;
    - signed in as a different account: refused with a clear message, and
      offered to switch account;
    - the link never signs anyone in by itself;
  - a new invitee who signs up from the invitation's link is admitted with no
    invite code and no access review, on hosted and self-hosted servers
    (#4121), and still verifies its email before it can sign in (#4481). No
    command yet: not built.
- **Driving it:** as the invitee:

  ```sh
  cw org invitations
  cw org accept SLUG
  ```

  `cw org accept` prints "Joined NAME (SLUG) as member.".
- **Proof:** the inviter's `cw org members --org SLUG` lists the invitee's
  email with its role, and the invitation is no longer pending.
- **Gotchas:**
  - `cw org invitations` lists invitations only for a verified address, so
    an unverified invitee sees none.
  - An invitee has no organization yet. `cw login` succeeds for it and says
    "You're not in an organization yet: see your invitations with 'cw org
    invitations', or create one with 'cw org create <name>'." (#4530; before
    it, `cw login` exited 1 here).
  - An organization invitation is not a sign-up invite code. On hosted, a
    new account waits for an admin to enable it unless its sign-up gave a
    sign-up invite code; the organization invitation does not enable it. A
    walk with an invitee who has no account records which of the two it
    used. Verification is needed either way (owner, 2026-11-13, on #4481).
- **Observed:** Dev, 2026-11-13, source 6c3651dcf, `cw` built from 27707e6c2:
  `cw login`, then `cw org invitations` listing the organization, then `cw org
  accept` joining as member, by `invitations-journey.sh` (#3840). With `cw`
  built from e8cad6589 (#4530), `cw login` exited 0 for the invitee and
  named `cw org invitations` (#4530). The unverified and different-email states are not yet observed on Dev. The
  dashboard's invitation page is covered
  on Kind by `apps/dashboard/e2e/ssr-dashboard.governance.ssr.ts`.

## `invite-remove`: an owner or admin removes the member

- **Entry points:** `cw org member rm`; **Remove** on the Members page.
- **States to exercise:**
  - removing a member, after the prompt and with `--yes`;
  - answering no to the prompt: "Not removed.";
  - a caller who is only a `member`: refused.
- **Driving it:** as the inviter:

  ```sh
  cw org member rm INVITEE_EMAIL --org SLUG
  cw org members --org SLUG
  ```

  The first asks "Remove INVITEE_EMAIL (member) from NAME?" and prints
  "Removed INVITEE_EMAIL from NAME.".
- **Proof:** `cw org members` no longer lists the invitee, and the
  invitee's own `cw org list`, signed in through `cw login`, no longer
  shows the organization.
- **Gotchas:** an API key bound to another organization is refused for this
  organization before and after removal, so it proves nothing about losing
  access. The invitee's side needs a `cw login` session, which is what
  `invitations-journey.sh` uses.
- **Observed:** Dev, 2026-11-13, source 6c3651dcf: `cw org member rm --yes`
  removed the invitee, `cw org members` no longer listed it, and the invitee's
  `cw org list` showed "No organizations found.", by
  `invitations-journey.sh` (#3840). The prompt and member-refused states are
  not yet observed on Dev.

## `org-leave`: a member leaves an organization

- **Entry points:** `cw org leave`; **Leave** in the Organizations card of
  Settings → Account (#4519).
- **States to exercise:**
  - a member leaves, after the prompt and with `--yes`;
  - an owner leaves while another owner remains;
  - the only owner is refused: "you are the organization's only owner; make
    someone else an owner first, or delete the organization". On the
    dashboard its Leave is disabled, with the same reason;
  - answering no to the prompt: "Not left.";
  - an account in no organization: the card says "You're not in an
    organization yet." and offers to create one or see your invitations.
- **Driving it:** as the member:

  ```sh
  cw org leave SLUG
  ```

  It asks "Leave NAME? You lose access to its sandboxes, secrets and
  billing." and prints "Left NAME (SLUG).". `invitations-journey.sh` walks it
  with the invitee, then makes its own organization for the walk to show the
  only-owner refusal, and deletes it.
- **Proof:** the inviter's `cw org members` no longer lists the member, and
  the member's own `cw org list` no longer shows the organization. The only
  owner's organization is still there after the refusal.
- **Gotchas:**
  - Never walk the only-owner refusal in the smoke organization: a bug would
    leave it without an owner. The script uses `codewire-dev-invitee-walk`.
  - Deleting an organization finishes in the background. A rerun soon after
    can still find `codewire-dev-invitee-walk` while it is being deleted.
- **Observed:** not yet observed.

## `invite-limits`: invitations stop at a limit and say when to try again

Limits (#4457, in the docs' organization members page): one account sends
at most 30 invitations an hour across its organizations; an organization
sends at most 60 an hour; an organization holds at most 200 pending
invitations.

- **Entry points:** `cw org invite`; **Send Invite** on the Members page.
- **States to exercise:**
  - the 31st invitation in an hour from one account;
  - the 201st pending invitation in one organization;
  - normal use under the limits is unaffected;
  - a refused invitation is not saved and sends no email.
- **Driving it:** as the inviter, in an organization made for the walk:

  ```sh
  for n in $(seq 1 31); do
    cw org invite "success+invite-walk-$n@simulator.amazonses.com" \
      --role member --org SLUG || break
  done
  ```

- **Proof:** the 31st invitation exits non-zero with "invitation limit
  reached: one account can send at most 30 invitations an hour; try again
  after" and a time in UTC; the Members page shows 30 pending invitations,
  not 31. The pending cap says "an organization can hold at most 200 pending
  invitations; revoke one or wait for one to expire" and when the next one
  expires.
- **Gotchas:**
  - The mail provider's simulator addresses take the 30 emails without
    reaching a person or counting as a bounce. Never use real or made-up
    domains for this.
  - The dashboard refuses at the same limit, but its Members page says only
    "The invitation could not be sent. Please try again." for every refusal
    it does not recognise. The limit's own sentence on the dashboard waits
    on a dashboard change for #4457; until then the dashboard proves the
    refusal, not its wording.
  - The count lasts an hour, and deleting the organization does not reset
    it. The walk's account cannot invite for the rest of that hour.
  - Reaching the pending cap takes 200 invitations, more than one account's
    hourly limit allows; it needs several inviters or several hours.
- **Observed:** not yet observed.

## `invite-unverified`: an unverified inviter is refused

- **Entry points:** `cw org invite`; **Send Invite** on the Members page.
- **States to exercise:** an inviter who signed up with email and password
  and has not verified the address; the same inviter after verifying.
- **Driving it:** as an unverified owner, run `cw org invite` as in
  `invite-send`.
- **Proof:** the CLI exits non-zero with "verify your email address before
  inviting members"; the dashboard refuses too (with the generic sentence
  described under `invite-limits`); no invitation is saved and no email is
  sent. After verifying, the same invitation succeeds.
- **Gotchas:** accounts made through GitHub or Google sign-in are verified
  at sign-up, and so are the synthetic Dev identities. This state needs a
  new email and password account.
- **Observed:** not yet observed.
