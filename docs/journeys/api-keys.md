# API keys

An organization's API key carries permissions and an expiry chosen when it
is made, is made only from a sign-in, shows its last use, and is audited
(#5688). The rules are in [`docs/dev/AUTH-POLICY.md`](../dev/AUTH-POLICY.md),
"API key permissions and expiry". This journey was written before the code,
and the flags in it are the ones that section proposes. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-23. Written first; every step is not yet observed.

| ID | Dev | Production |
| --- | --- | --- |
| `key-create` | not yet observed | not yet observed |
| `key-permissions` | not yet observed | not yet observed |
| `key-existing` | not yet observed | not yet observed |
| `key-revoke` | not yet observed | not yet observed |
| `key-audit` | not yet observed | not yet observed |

## Before the walk

- **Two walk accounts** on Dev in one organization: A, an admin, and M, a
  member. Remove every key and environment the walk makes by exact name
  afterwards.
- **A scratch `cw` home** for each account (`HOME` and `CW_CONFIG_DIR` under
  the walk's scratch directory), so no step uses a maintainer's own sign-in
  or keyring.
- **What to record:** `cw version` and the source Dev was running.

## `key-create`: making a key

- **Entry points:** `cw api-keys create`; Settings → API keys.
- **States to exercise:**
  - `--expires 30` and `--expires never`: the key shows that expiry;
  - a permission M's role lacks, asked for by M: refused whole, no key made;
  - asked for with an API key instead of a sign-in: refused;
  - the secret is shown once;
  - `cw api-keys create` and the dashboard's form say that every key can run
    commands, use files and run agents in the environments A can reach.
- **Driving it:** no command yet (#5688). The proposed forms are
  `cw api-keys create NAME --expires DAYS|never` and `--permission NAME`
  (repeatable).
- **Proof:** `cw api-keys list --output json` shows each key's permissions,
  expiry and last use as made.

## `key-permissions`: what a key may do

- **States to exercise:**
  - a key with only `write:environments` creates and stops an environment,
    and is refused deleting it, with a message naming `delete:environments`;
  - a key with no permissions lists environments and runs a command, a
    shell and a file copy in one A can reach, and is refused creating one;
  - a key made with no `--permission` flags has every permission A's role
    allows;
  - a key of A's, after A's role is lowered to member, is refused what
    members can't do, whatever its permissions;
  - a key asked for a personal credential profile: refused, naming the user
    token.
- **Driving it:** no command yet (#5688). Each case through `cw` with
  `CODEWIRE_API_KEY` set, and through one SDK.
- **Proof:** each call's answer. A refusal is `permission_denied` and names
  the permission or the role.

## `key-existing`: a key made before permissions

- **States to exercise:** a key made before the change keeps doing what it
  did; its listing shows every permission; it can no longer make a key.
- **Driving it:** no command yet (#5688). Make a key on the source before
  the change, deliver the change, then repeat the same calls.
- **Proof:** the same answers before and after, except the refused key
  creation.

## `key-revoke`: what ends a key

- **States to exercise:**
  - disabled, then deleted: refused within seconds, and a live `cw shell`
    over the API ends within 30 seconds;
  - expired: refused;
  - M leaves the organization: M's keys stop;
  - M's account is disabled: every key of M's stops;
  - M resets their password: every key keeps working;
  - A disables M's key.
- **Driving it:** no command yet (#5688).
- **Proof:** the same call before and after each change, and its answer.
- **What the page says:** a key's Delete dialog says "All connections using
  this key are dropped when it is deleted." on both API key pages. Browser
  tests hold it (`ssr-dashboard.personal-api-keys.ssr.ts` and
  `ssr-dashboard.governance.ssr.ts`); the Dev walk does not read it (#3586).

## `key-audit`: every key change and refusal is recorded

- **States to exercise:** making, disabling, enabling and deleting a key;
  a permission refusal, repeated within a minute.
- **Driving it:** no command yet (#5688). Read the organization's audit log
  after the steps above.
- **Proof:** one row for each, naming the key's id. The repeated refusal
  writes one row. No row holds a key's secret.
