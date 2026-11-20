# Feedback

`cw feedback` sends one message to the Codewire team, signed in or anonymous,
and the platform stores it for its admins to read (#4061). It is how a beta
user reaches us, so it is a launch item beside the launch walk
([launch.md](launch.md), "Beside the walk"), not one of its numbered steps.
What users are told is in the docs' CLI reference
(`apps/docs/zola/content/reference/cli/cw.md`, "cw feedback") and the
security page (`apps/docs/zola/content/reference/security.md`, "Feedback").
The limits and the refusal wording are in
`crates/codewire-orchestration/src/api/feedback.rs`. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-20. Nothing here is observed on Production. The owner
checks feedback on Production in person (owner, 2026-11-14, #4061): no walk
sends feedback there, and the Production column is the owner's to fill.

| ID | Dev | Production |
| --- | --- | --- |
| `feedback-signed-in` | observed 2026-11-14, the stored row included (#4061) | not yet observed |
| `feedback-anonymous` | observed 2026-11-14, the stored row included (#4061); the reply address with `--email` 2026-11-20 (#5466) | not yet observed |
| `feedback-limits` | anonymous limit observed 2026-11-11 (#4061); account limit and ceiling not yet observed | not yet observed |
| `feedback-operator-email` | observed 2026-11-20, the operator's inbox included (#5466); the cap and failure states not yet observed | not yet observed |
| `feedback-admin-page` | not yet observed | not yet observed |

## Before the walk

- Use the released `cw` the public docs point to, and record `cw version`
  with every observation.
- Mark every message as a walk, with the date, so that an admin reading the
  list can ignore it. A stored message cannot be removed by its sender.
- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one
  command as the synthetic Dev identity. It hands the key to the command as
  `CODEWIRE_DEV_SMOKE_API_KEY`; `cw` reads `CODEWIRE_API_KEY`. No walk sends
  feedback on Production, so there is no Production command here.
- Give `cw` a throwaway `HOME`, so the walk never touches the walker's own
  sign-in.
- Send with `-o json` and keep the `id` it prints. Reading the stored rows
  back means reading the platform's database, which only an operator can do,
  and only for those IDs: every other row is someone else's message.

## `feedback-signed-in`: a signed-in sender

- **Entry points:** `cw feedback "MESSAGE"`; `cw feedback` at a terminal,
  which reads the message until Ctrl-D; a message piped on stdin with
  `--yes`.
- **States to exercise:**
  - a message on the command line, signed in;
  - the same typed at the terminal, and cancelled with Escape;
  - a message over 10 KB, which is refused before anything is sent;
  - a sign-in that no longer works, which is refused, not sent anonymously;
  - `--environment ID`, which sends that ID and nothing else about it.
- **Driving it:**

  ```sh
  cw feedback --yes -o json "Journey walk YYYY-MM-DD, signed in. Please ignore."
  ```

  Without `--yes`, `cw` first shows who the feedback is from and what is
  attached, and asks:

  ```text
  Feedback for the Codewire team at SERVER
    From      the API key in CODEWIRE_API_KEY, organization ORGANIZATION
    Attached  cw VERSION, OS ARCHITECTURE
    Message   N bytes
  ```

- **Proof:** exit 0 and `"signed_in": true` with an `id`. The stored row with
  that `id` names the sender's account and organization, holds the message
  as sent, the `cw` version, the operating system and the architecture, and
  holds a keyed hash where a network address would be.
- **Gotchas:** `-o json` needs `--yes`, because there is no terminal to ask
  in. The placement is empty unless `--local` or `--cloud` is given or an
  environment is selected.
- **Observed:**
  - Dev, 2026-11-14, `cw` v0.4.17, Dev running source `97dc3f473`, as the
    Dev smoke identity (#4061): the command above exited 0 with
    `"signed_in": true`. Its row, read back by ID, named an account and an
    organization, held the message as sent, `v0.4.17`, `linux`, `x86_64`,
    no placement and no environment, and a 64-character address hash.
  - Typed at a terminal, cancelled, over 10 KB, a dead sign-in and
    `--environment`: not yet observed.
  - Production: not yet observed.

## `feedback-anonymous`: an anonymous sender

- **Entry points:** `cw feedback --anonymous`; `cw feedback` when signed
  out; `--email ADDRESS`.
- **States to exercise:**
  - `--anonymous` while signed in, and a signed-out `cw`;
  - at a terminal, `cw` asks for an email address to reply to, which is
    optional: Enter skips it (#5466; owner, 2026-11-19: "just ask for email
    if they aren't signed in so we have something for anons");
  - `--email ADDRESS` gives it without the question, for scripts and with
    `--yes`;
  - an address that is not one email address is refused before anything is
    sent;
  - `--email` while signed in is refused: a signed-in sender is never asked,
    and an answer goes to their account's address.
- **Driving it:**

  ```sh
  cw feedback --anonymous --yes -o json \
    "Journey walk YYYY-MM-DD, anonymous. Please ignore."
  ```

  `cw` says "From      anonymous (--anonymous): no account or
  organization" before it sends. Without `--yes` and `--email`, it then asks
  "Email address for a reply (optional):".

  ```sh
  cw feedback --anonymous --yes --email walker@example.com -o json \
    "Journey walk YYYY-MM-DD, anonymous with a reply address. Please ignore."
  ```

- **Proof:** exit 0 and `"signed_in": false` with an `id`; in text, `cw`
  prints "Thanks, we read every message." The stored row with that `id`
  names no account and no organization, and still holds the address hash
  that limits the sender. It holds the reply address when one was given, and
  none when the question was skipped.
- **Observed:**
  - Dev, 2026-11-14, `cw` v0.4.17, Dev running source `97dc3f473` (#4061):
    the command above exited 0 with `"signed_in": false`. Its row, read back
    by ID, named no account and no organization, held the message as sent
    and a 64-character address hash.
  - A signed-out `cw`: not yet observed.
  - Dev, 2026-11-20, `cw` built from `b1a024b6db` (it reports `cw 0.1.0`;
    no release has `--email` yet), Dev running source `b1a024b6db` (#5466):
    `--email walk-reply-20261120@example.test` exited 0 with
    `"signed_in": false`, and the summary showed "Reply to" with that
    address. `--email walk-reply@example` and `--email` while signed in
    were each refused with exit 1 before anything was sent. The address
    appeared in no IdP or orchestration log.
  - The reply address asked for at a terminal: not yet observed.
  - Production: not yet observed.

## `feedback-limits`: a sender past the limit is told when to try again

The limits are 10 messages an hour for an account, 5 an hour anonymously
from one address, and 500 an hour for everyone together.

- **Entry points:** the same commands.
- **States to exercise:**
  - a sixth anonymous message within the hour from one address;
  - an eleventh message within the hour from one account;
  - an anonymous sender on another network, who has an allowance of their
    own;
  - a signed-in sender whose address has used its anonymous allowance, who
    is not held by it.
- **Driving it:** repeat the anonymous command six times.
- **Proof:** the sixth exits 1 with "anonymous feedback is limited to 5 an
  hour from one address; try again in N seconds, or sign in". An account
  past its limit reads "feedback is limited to 10 an hour per account; try
  again in N seconds".
- **Gotchas:**
  - Every accepted message is a stored row an admin will see, and its
    sender cannot remove it.
  - Two machines behind one router share an address, and so one anonymous
    allowance.
  - No command reaches the ceiling for everyone; it is covered by tests
    only.
- **Observed:**
  - Dev, 2026-11-11, `cw` built from `b587e749c`, Dev running source
    `57c673f96` (#4061): five anonymous messages were accepted and the sixth
    and seventh refused with the wording above, naming 3600 seconds. A
    signed-in message was then accepted from the same address. One
    anonymous request from a Dev sandbox, on another network, was accepted
    while the first address was still refused.
  - The account limit and the ceiling: not yet observed.
  - Production: not yet observed.

## `feedback-operator-email`: the operator gets each message by email

Issue: #5466 (owner, 2026-11-19: "also lets make feedbacks get emailed to
me so i can reply to user via email."). The IdP sends it, as it sends the
operator's sign-up notice (#5358) and from the same `CODEWIRE_OPERATOR_EMAIL`;
the rules are in `docs/CONFIGURATION.md`, "Operator notices".

- **Entry points:** `cw feedback`, signed in and anonymous; the operator's
  inbox; Reply in the operator's mail client.
- **States to exercise:**
  - signed in, with a verified account address: Reply-To is that address;
  - signed in, with an address nobody verified: no Reply-To, and the address
    is marked "(not verified)";
  - anonymous with a reply address: the body shows it, marked "(given with
    the feedback, not verified)", beside "Nobody has checked this address;
    don't share account or billing details in a reply.", and there is no
    Reply-To;
  - anonymous without one: no Reply-To, and the email says so;
  - a message, a name and an organization name holding line breaks, lines
    that look like email headers (`Bcc: someone@example.com`), control
    characters and right-to-left overrides;
  - more than 10 messages in an hour, from any senders together: the 11th
    sends one "More feedback is waiting" email, and the rest send none;
  - the email provider failing, and `CODEWIRE_OPERATOR_EMAIL` unset.
- **Driving it:**
  1. Signed in, as in `feedback-signed-in`:
     `cw feedback --yes -o json "Journey walk YYYY-MM-DD, operator email. Please ignore."`
  2. Anonymous, as in `feedback-anonymous`, once with `--email` and once
     without, with the same kind of message.
  3. In the operator's inbox, open the email for each `id`, and press Reply
     on the first.
- **Proof:**
  - each `cw feedback` exits 0 at once, whatever the email does;
  - within a minute the operator's inbox has one email per message, subject
    `Codewire feedback <id>` with the `id` `cw` printed;
  - the body names the sender (name and email marked "(verified)" or
    "(not verified)", or "Anonymous"), the organization, what `cw` attached (version, operating system,
    architecture, placement), the environment when one was named, and the
    time in UTC, then the message as sent, then a link to Admin → Feedback
    on the server's configured address. Control characters other than line
    breaks and tabs, and the Unicode direction overrides and isolates, are
    dropped from what the email shows, and the message it shows is never
    longer than feedback's stored maximum (10 KB);
  - Reply on the signed-in one addresses the sender's account email; the
    anonymous ones have no Reply-To, and the one sent with `--email` shows
    that address in its body;
  - each message sends exactly one email, to the operator: Codewire never
    emails a reply address itself, no receipt and no confirmation, so nobody
    can make it mail an address of their choosing; only the operator's own
    reply reaches it;
  - the email is plain text only: no HTML part. From is the server's fixed
    sender and the subject is fixed wording plus the `id`; no header holds
    anything the sender typed, the name or the organization name. It holds
    no token, session, network address or address hash;
  - past the cap every message is still stored and still on the admin page,
    and the inbox gets at most 10 emails and one "More feedback is waiting"
    in the hour, which holds only how many arrived and the Admin → Feedback
    link; with the provider failing or the address unset,
    `cw feedback` still succeeds and the message is still stored. The IdP's
    log names the feedback's `id`, a fixed reason and the provider's error
    code, never the message, a name or an address.
- **Gotchas:**
  - Only someone who reads the operator's inbox can check the email.
  - The cap counts every sender on the server together, so other feedback in
    the same hour counts against the walk's.
  - Reply-To is only ever the account's verified address when the email is
    sent, never an address nobody verified: not an account's unverified
    address, which could be someone else's typed at sign-up, not the address
    an anonymous sender typed, and not one written in the message. The
    operator answers an anonymous sender by copying the address from the
    body (cw-security, 2026-11-19, #5466).
- **Observed:**
  - Dev, 2026-11-20, `cw` built from `b1a024b6db`, Dev running source
    `b1a024b6db` (#5466): one signed-in message as the Dev smoke identity
    and two anonymous ones, with `--email` and without, each exited 0. The
    IdP logged `sent feedback email` for each `id` on its first attempt,
    seconds after each submit, and neither the IdP's logs nor
    orchestration's held the reply address. The owner read the operator's
    inbox and reported the three emails received and correct (owner,
    2026-11-20: "feedback emails were received and everything looks good.").
  - The cap, a failing provider, an unset `CODEWIRE_OPERATOR_EMAIL` and
    hostile message text: not yet observed.
  - Production: not yet observed.

## `feedback-admin-page`: a platform admin reads the feedback

- **Entry points:** the dashboard's admin section. No command yet: the page
  is not on `main` (#4061). The admin API behind it, `ListFeedback`, shipped
  with `cw feedback`.
- **States to exercise:** the list newest first; signed-in and anonymous
  messages told apart; an account that is not a platform admin, which is
  refused; no feedback at all.
- **Proof:** a message sent in the steps above appears with its time, its
  sender or "Anonymous", its text and what `cw` attached. A member who is
  not a platform admin cannot open the page or call the API.
- **Observed:** not yet observed on Dev or Production.
