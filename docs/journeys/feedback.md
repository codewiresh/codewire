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

Updated 2026-11-14. Nothing here is observed on Production.

| ID | Dev | Production |
| --- | --- | --- |
| `feedback-signed-in` | observed 2026-11-14, the stored row included (#4061) | not yet observed |
| `feedback-anonymous` | observed 2026-11-14, the stored row included (#4061) | not yet observed |
| `feedback-limits` | anonymous limit observed 2026-11-11 (#4061); account limit and ceiling not yet observed | not yet observed |
| `feedback-admin-page` | not yet observed | not yet observed |

## Before the walk

- Use the released `cw` the public docs point to, and record `cw version`
  with every observation.
- Mark every message as a walk, with the date, so that an admin reading the
  list can ignore it. A stored message cannot be removed by its sender.
- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one
  command as the synthetic Dev identity. It hands the key to the command as
  `CODEWIRE_DEV_SMOKE_API_KEY`; `cw` reads `CODEWIRE_API_KEY`. On Production,
  `scripts/runtime/prod/with-prod-smoke-auth.sh -- COMMAND` does the same for
  the Production smoke identity, as `CODEWIRE_PROD_SMOKE_API_KEY`.
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
  out.
- **States to exercise:** `--anonymous` while signed in, and a signed-out
  `cw`.
- **Driving it:**

  ```sh
  cw feedback --anonymous --yes -o json \
    "Journey walk YYYY-MM-DD, anonymous. Please ignore."
  ```

  `cw` says "From      anonymous (--anonymous): no account or
  organization" before it sends.
- **Proof:** exit 0 and `"signed_in": false` with an `id`. The stored row
  with that `id` names no account and no organization, and still holds the
  address hash that limits the sender.
- **Observed:**
  - Dev, 2026-11-14, `cw` v0.4.17, Dev running source `97dc3f473` (#4061):
    the command above exited 0 with `"signed_in": false`. Its row, read back
    by ID, named no account and no organization, held the message as sent
    and a 64-character address hash.
  - A signed-out `cw`: not yet observed.
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
  - Every accepted message is a stored row an admin will see. On Production,
    walk this state only when the rows are wanted.
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
