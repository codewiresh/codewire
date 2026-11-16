# Deleting an account or an organization

This walk proves that deleting is said to be permanent, before it happens,
wherever a user can delete: the account-deletion page and `cw org delete`
(#4823). Leftover credit is forfeited and kept in the ledger (#4858), but the
user isn't told about money (owner, 2026-11-15). The format is in
[README.md](README.md).

## `delete-account-page`: the account-deletion page

Issue: #4823. Code: `crates/codewire-dashboard-web/templates/settings-delete-account.html`.

- **Entry points:** Settings → Delete account (`/settings/delete-account`).
- **States to exercise:**
  - an account that owns an organization deleted with it;
  - an account that owns none;
  - an account that only leaves organizations others also own;
  - an account blocked by an organization that has other members.
- **Driving it:** sign in as each account and open the page.
- **Proof:**
  - With an owned organization, the card lists it under "Deleted with your
    account" and says "Deleting your account permanently removes it, the
    organizations under "Deleted with your account" and all their
    resources. This can't be undone."
  - With none, including an account that only leaves organizations, it says
    "Deleting your account permanently removes it. This can't be undone."
    The organizations it leaves are listed under "You leave".
  - Nothing on the page mentions credit or money.
- **Observed:** not yet observed.

## `org-delete-cli`: `cw org delete`

Issue: #4823. Code: `crates/codewire-cli/src/commands/organizations.rs`.

- **Entry points:** `cw org delete ID_OR_SLUG [--yes] [-o json]`.
- **States to exercise:**
  - text at a terminal;
  - text with `--yes`;
  - `-o json` with `--yes`;
  - `-o json` without `--yes`.
- **Driving it:** create a scratch organization, then:

  ```sh
  cw org delete SCRATCH            # answer the prompt
  cw org delete SCRATCH2 --yes
  cw org delete SCRATCH3 --yes -o json
  cw org delete SCRATCH4 -o json
  ```

- **Proof:**
  - Both text forms print "Deleting this organization permanently removes it
    and all its resources. This can't be undone." on stderr before deleting,
    the first before its prompt.
  - JSON prints only `{organization_id, operation_id, state}` on stdout.
  - Without `--yes`, JSON fails at once and names `--yes`, and deletes
    nothing.
  - No output mentions credit or money.
- **Observed:** not yet observed.
