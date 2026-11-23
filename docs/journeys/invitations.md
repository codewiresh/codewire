# Invitations

An organization's owner or admin invites a teammate by email; the teammate
receives the email, accepts, appears as a member, and can be removed. This
file is that journey for `SPEC.md` "Organizations and members", with the
issues #3840 (accept, list and remove from `cw`), #3847 (the invitation
email) and #4457 (the invitation limits and the verified-inviter rule).
Launch step 5 (`launch-invite` in [launch.md](launch.md)) walks the same
feature on Production. The format is in [README.md](README.md).

## Where the journey stands

Updated 2026-11-22. Invite, email, accept and remove are observed on Dev
(source 6c3651dcf), and leaving from `cw` on Dev (source 20f2f4b0a). On
Production (v0.4.18, source a9dd8b270), the invitation and its email's send
are observed; the email's arrival is observed on Dev only. The account's
hourly limit is observed on Dev and on Production (v0.4.19, source
92672c5c4). The organization's hourly limit, and the dashboard's refusal for
both, are observed on Dev (source e8e593b86). The pending cap and the
unverified-inviter refusal are observed on Kind (source 35bacfcbb).

| ID | Dev | Production |
| --- | --- | --- |
| `invite-send` | observed 2026-11-13 on 6c3651dcf (#3840) | observed 2026-11-14 on a9dd8b270 (#3847) |
| `invite-email` | observed 2026-11-13 on 6c3651dcf (#3847) | sent 2026-11-14 on a9dd8b270, arrival not observed (#3847) |
| `invite-accept` | observed 2026-11-13 on 6c3651dcf (#3840); from the invitation page in a browser 2026-11-22 on bb84688d14 (#5911) | not yet observed |
| `invite-remove` | observed 2026-11-13 on 6c3651dcf (#3840) | not yet observed |
| `org-leave` | the CLI observed 2026-11-15 on 20f2f4b0a (#4519); the account page observed on Kind 2026-11-22, main's dashboard 253add63cd | not yet observed |
| `invite-limits` | the account's hourly limit observed 2026-11-14 on 09c05f268; the organization's limit and the dashboard refusal observed 2026-11-15 on e8e593b86 (#4457); the pending cap observed on Kind only, 2026-11-15 on 35bacfcbb (#4457) | the account's hourly limit observed 2026-11-14 on 92672c5c4 (#4457); the rest not yet observed |
| `invite-unverified` | observed on Kind only, 2026-11-15 on 35bacfcbb (#4457) | not yet observed |
| `invite-signup` | not yet observed | not yet observed |

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
  verified, with two-factor, and owns `codewire-dev-e2e`. Its sign-in
  (password and second factor) is in OpenBao at
  `apps/codewire/dev/ci-browser-auth`, written 2026-11-13.
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
    (#3840, decided 2026-11-13). The page is built for the copied link
    (`invite-accept`). The email's own token and its sign-up admission
    exist (#4624); the page doesn't resolve it yet, and the email doesn't
    carry it yet (#3840);
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
  says; the one-time link from `invite-send`, `/accept-invite#t=<token>`,
  in the dashboard.
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
  - the one-time link, `/accept-invite#t=<token>` (#3840, decided
    2026-11-13):
    - signed in as the invited, verified address: one click accepts;
    - signed in as the invited address, not verified yet: offered the
      verification email;
    - signed out: asked to sign in or sign up, then returned to the
      invitation to accept;
    - signed in as a different account: refused with a clear message, and
      offered to switch account;
    - a used, revoked, expired or unknown link: "not found", the same for
      each;
    - an old `?token=` link: the out-of-date page;
    - the link never signs anyone in by itself;
  - the same page from the email's button, by the email's own token: the
    token exists (#4624), but the page doesn't resolve it yet (#3840);
  - a new invitee who signs up from the link: on an invite-only server it is
    admitted with no invite code, reason, challenge or access review, at the
    invited address only. The page shows the address masked as a hint, and
    the invitee types it (#4121, #3840). It still verifies its email before
    it can sign in, unless the server has no mail (#4481). A hosted server
    admits it the same way (#4624, `invite-signup`), not yet observed;
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
    "You're not in an organization yet; create one with `cw org create
    NAME`, or accept an invitation with `cw org invitations`." (#4530, from
    v0.4.19; before it, `cw login` exited 1 here).
  - An invitee with no account signs up through the invitation's link
    (`invite-signup`). It is admitted at once at the invited address, with no
    sign-up invite code or review (#4121), and still verifies its address
    first (owner, 2026-11-13, on #4481). A sign-up without the link, even at
    the invited address, goes through the server's normal sign-up.
- **Observed, from the invitation page:** Dev, 2026-11-22, promote source
  bb84688d14 (with #5911), headless Chromium as the synthetic Dev invitee
  signed in with its password session, the smoke identity inviting it into
  `codewire-dev-smoke` with `cw org invite` (v0.4.26): the open post carried
  `Origin: https://codewire-dev.sh` (303, then 200); the page offered **Accept
  invitation**, naming the address masked; accepting showed "Welcome to the
  team", and the inviter's `cw org members` listed the invitee, who was then
  removed. Before #5911 the page's own posts were refused in a real browser
  (403 "The form expired or came from another site"), seen on Kind.
- **Observed:** Dev, 2026-11-13, source 6c3651dcf, `cw` built from 27707e6c2:
  `cw login`, then `cw org invitations` listing the organization, then `cw org
  accept` joining as member, by `invitations-journey.sh` (#3840). With `cw`
  built from e8cad6589 (#4530), `cw login` exited 0 for the invitee and
  named `cw org invitations` (#4530). Dev, 2026-11-14, source b84376346,
  with the released `cw` v0.4.19: the same script passed, and `cw login`
  exited 0 for the invitee with the sentence above (#4530). The unverified
  and different-email states are not yet observed on Dev. The dashboard's
  invitation page is covered on Kind by
  `apps/dashboard/e2e/ssr-dashboard.governance.ssr.ts`. The one-time link's
  page and sign-up from it are not yet observed on Dev (#3840).

## `invite-signup`: an invitee with no account signs up by the link

Issues: #4121 (an invitation link admits a sign-up on every server) and #3840
(the invitation email's link).

- **Entry points:** the invitation's link, copied by the inviter or, once the
  invitation email carries it, in the email. It opens `/accept-invite`, which
  offers sign-up, names the invited address masked (`s•••@example.com`) and
  asks for it: a link holder is never shown the full address (#5907).
- **States to exercise:**
  - a sign-up at the invited address, admitted at once with no code, review
    or reason, then email verification, sign-in and Accept;
  - the same link at another address, refused with "This invitation is no
    longer valid. Ask for a new one.";
  - a resent invitation email's older link, refused the same way;
  - a link whose invitation was revoked, refused the same way;
  - a second sign-up at the address after the first, refused as taken.
- **Driving it:** with a fresh mail provider simulator address for each
  walk, since an address that already has an account can't sign up again.
  It needs the dashboard to carry the link's token to sign-up (#4121's
  dashboard page, and the `/accept-invite` page's sign-up branch).
- **Proof:** the invitee's account is enabled but unverified until the
  verification email is opened. `cw org members` lists it only after Accept.
- **Gotchas:** the link never signs anyone in or accepts anything. Signing up
  by it and then signing in with GitHub or Google at the same address links
  nothing until the address is verified.
- **Observed:** not yet observed.

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
    dashboard its Leave is disabled, and the card, under the organization's
    name, says "You're its only owner. Make someone else an owner first, or
    delete the organization." (#5910);
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
- **Observed, the account page:** the retained Kind cluster, 2026-11-22,
  main's dashboard 253add63cd against an older orchestration, headless
  Chromium with scratch accounts: a member's **Leave** asked "Leave ORG? You
  lose access to its sandboxes, secrets and billing at once. …" and then said
  "You left the organization." with "You're not in an organization yet." and
  its two offers; the inviter's `cw org members` then listed only the owner;
  the only owner's **Leave** is disabled, its reason reading "You're its only
  owner. Make someone else an owner first, or delete the organization.", as
  this step says. Whether the account page's removal needs
  current orchestration is untested; rewalk on Dev.
- **Observed:** Dev, 2026-11-15, source 20f2f4b0a (deploy-dev run 50777),
  `cw` built from 528ac2680, by `invitations-journey.sh`: the invitee joined
  again and left with `--yes` ("Left Codewire Dev Smoke
  (codewire-dev-smoke)."); the inviter's `cw org members` then listed only
  the owner, and the invitee's `cw org list` said "You're not in an
  organization yet.". In its own `codewire-dev-invitee-walk` the invitee was
  refused as the only owner, the organization was still listed, and it was
  deleted (#4519). Not yet observed: the prompt and "Not left.", an owner
  leaving while another remains (covered by the database tests), and the
  account page's card.

## `invite-limits`: invitations stop at a limit and say when to try again

Limits (#4457, in the docs' organization members page): one account sends
at most 30 invitations an hour across its organizations; an organization
sends at most 60 an hour; an organization holds at most 200 pending
invitations.

- **Entry points:** `cw org invite`; **Send Invite** on the Members page.
- **States to exercise:**
  - the 31st invitation in an hour from one account;
  - the 61st invitation in an hour from one organization's admins;
  - the 201st pending invitation in one organization;
  - each refusal on the dashboard as well as in `cw`;
  - normal use under the limits is unaffected;
  - a refused invitation is not saved and sends no email.
- **Driving it:** as the inviter, in an organization made for the walk:

  ```sh
  for n in $(seq 1 31); do
    cw org invite "success+invite-walk-$n@simulator.amazonses.com" \
      --role member --org SLUG || break
  done
  ```

  For the organization's limit, a second admin sends 30 the same way, and
  the next invitation from either is refused. On Dev the second admin is the
  synthetic invitee, invited as admin for the walk and removed afterwards.
  On the dashboard, enter a simulator address on the Members page and press
  **Send Invite** past each limit.

- **Proof:** the 31st invitation exits non-zero with "invitation limit
  reached: one account can send at most 30 invitations an hour; try again
  after" and a time in UTC; the Members page shows 30 pending invitations,
  not 31. The organization's limit says "invitation limit reached: an
  organization can send at most 60 invitations an hour; try again after"
  and a time. The organization's limit is checked first, so once the
  organization has sent 60, the next invitation from any admin gets this
  sentence. The Members page shows the same sentence, with its first letter
  capitalized and a full stop, above the form, and no new pending row.
  The pending cap says "an organization can hold at most 200 pending
  invitations; revoke one or wait for one to expire" and when the next one
  expires.
- **Gotchas:**
  - The mail provider's simulator addresses take the 30 emails without
    reaching a person or counting as a bounce. Never use real or made-up
    domains for this.
  - The dashboard's limit sentences are #4517's. A dashboard older than
    source `43e718411` says only "The invitation could not be sent. Please
    try again." for these refusals.
  - The dashboard needs a signed-in session for an admin. An
    organization-bound API key does not give one. On Dev the synthetic
    invitee, as admin, has a session.
  - The count lasts an hour, and deleting the organization does not reset
    it. The walk's account cannot invite for the rest of that hour.
  - A revoked invitation still counts toward its hour. An account that
    already sent some is refused that many invitations sooner, and the
    refusal names the time the oldest one leaves the hour.
  - Reaching the pending cap takes 200 invitations. With the organization's
    limit of 60 an hour, that is more than three hours of real invitations.
    Walk it on Kind, whose database is disposable, by inserting 199 pending
    invitations into the walk's organization. Never seed Dev's or
    Production's database.
  - A synthetic identity that signs in with an organization-bound API key
    cannot make an organization for the walk. It walks in its own, and the
    walk's invitations count toward that organization's hour too.
- **Observed:**
  - Dev, 2026-11-14, Dev running source `09c05f268`, `cw` v0.4.17, as the
    Dev smoke identity in its own organization (#4457): invitations 1 to
    30 to the mail provider's simulator were accepted, and the 31st exited
    1 with "invite: invitation limit reached: one account can send at most
    30 invitations an hour; try again after Nov 14 20:14 UTC". Straight
    after, the organization held 30 pending invitations and none for the
    31st address; 30 emails were recorded as sent and none for the 31st
    address. All 30 were then revoked.
  - The pending cap of 200, Kind, 2026-11-15, the retained profile
    `cw-abuse-review` on source `35bacfcbb` with its owner's uncommitted
    patches, none of which touches invitations; the profile's own `cw`; as
    `e2e-owner` in an organization made for the walk (#4457):
    - 199 pending invitations were inserted into Kind's database.
    - The 200th, by `cw org invite`, was accepted.
    - The 201st exited 1 with "invite: invitation limit reached: an
      organization can hold at most 200 pending invitations; revoke one or
      wait for one to expire (the next expires Nov 22 11:44 UTC)".
    - The 202nd, by **Send Invite**, answered HTTP 422 with the same
      sentence, capitalized, with a full stop.
    - Neither refused address had an invitation or an email row. The
      organization was then deleted.
    - On Dev or Production: not yet observed. The database tests in
      `crates/codewire-orchestration/src/api/organizations/invitation_limit_database_tests.rs`
      also cover it.
  - Production, 2026-11-14, v0.4.19 (source `92672c5c4`), `cw` v0.4.17, as
    the Production smoke identity in its own organization (#4457): the
    account had sent one invitation at 18:43 UTC, since revoked.
    Invitations 1 to 29 to the mail provider's simulator were accepted, and
    the 30th, the account's 31st in the hour, exited 1 with "invite:
    invitation limit reached: one account can send at most 30 invitations
    an hour; try again after Nov 14 19:43 UTC", the minute the earlier
    invitation's hour ended. The organization then held 29 invitations from
    the walk and none for the 30th address. All 29 were revoked by ID.
    Whether an email was recorded for the refused address was not read.
  - Dev, 2026-11-15, Dev running source `e8e593b86`, `cw` v0.4.19, in
    `codewire-dev-smoke`, with the Dev smoke identity and the synthetic
    invitee (joined as admin for the walk) as inviters (#4457). An earlier
    attempt had used one invitation of the organization's hour.
    - The invitee sent 30 with `cw`, all accepted.
    - Its next invitation, by **Send Invite** on the Members page, answered
      HTTP 422 with "Invitation limit reached: one account can send at
      most 30 invitations an hour; try again after Nov 15 12:30 UTC.".
    - The smoke identity then sent 28, all accepted, bringing the
      organization's hour to 60. Its next `cw org invite` exited 1 with
      "invite: invitation limit reached: an organization can send at most
      60 invitations an hour; try again after Nov 15 12:25 UTC".
    - The invitee's **Send Invite** then showed the same organization
      sentence.
    - None of the three refused addresses was saved in any state, and
      Dev's database held no email row for them. All 58 accepted
      invitations had email rows marked sent.
    - All 58 were revoked by ID, and the invitee was removed.
    - The dashboard was driven by its own form, as a browser without
      scripts submits it, not in a rendered browser.
  - The organization's limit on Production: not yet observed. A second
    inviter there falls outside the Production smoke identity's own
    organization.
  - The dashboard refusal on Production: not yet observed.

## `invite-unverified`: an unverified inviter is refused

- **Entry points:** `cw org invite`; **Send Invite** on the Members page.
- **States to exercise:** a signed-in owner whose address is not verified;
  the same owner after verifying; on a server without mail, an owner whose
  address is vouched for, who may invite (#4805).
- **Driving it:** as an unverified owner, run `cw org invite` as in
  `invite-send`, and press **Send Invite** on the Members page.
- **Proof:** the CLI exits non-zero with "verify your email address before
  inviting members"; the Members page says "Verify your email address
  before inviting members." (#4517); no invitation is saved and no email is
  sent. After verifying, the same invitation succeeds.
- **Gotchas:**
  - Since #4481 an unverified address cannot sign in on a server with
    mail, so a fresh sign-up never reaches this state. It is reached by an
    account from before #4481 that still holds a session or key. Walk it
    on Kind by setting a signed-in account's `email_verified` to false in
    Kind's disposable database, and back to true afterwards.
  - On a server without mail, accounts are vouched for instead of
    verified (#4121), and a vouched account, the admin included, may invite
    as a verified one does (#4805).
- **Observed:**
  - Kind, 2026-11-15, the retained profile `cw-abuse-review` on source
    `35bacfcbb` (as under `invite-limits`), as `e2e-owner` with its `cw` and
    dashboard sessions kept (#4457). The account was flipped with `UPDATE
    users SET email_verified = false`.
    - `cw org invite` exited 1 with "invite: verify your email address
      before inviting members".
    - **Send Invite** answered HTTP 422 with "Verify your email address
      before inviting members.".
    - Neither refused address had an invitation or an email row.
    - After `email_verified` was set back to true, the same `cw org invite`
      was accepted.
  - Dev and Production: not yet observed.
