# Signing in from the environment

An SDK program, a script or `cw` authenticates with an API key or with a
person's user token, from code, the environment or a `.env` file, and with a
user token binds that person's credential profiles (#5687, #5688). The rules
are in [`docs/dev/AUTH-POLICY.md`](../dev/AUTH-POLICY.md), "Signing in from
the environment". This journey was written before the code, and the commands
and names in it are the ones that section proposes. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-26. `user-token` and `user-token-bind` observed on Dev, except the parts the table names; the rest not yet observed.

| ID | Dev | Production |
| --- | --- | --- |
| `sdk-config` | not yet observed | not yet observed |
| `user-token` | observed 2026-11-26 (#5688), except a password reset and an account disable | not yet observed |
| `user-token-bind` | observed 2026-11-26 through `cw` (#5688); the SDK create (#5687) and the Codex or Claude sign-in comparison not yet | not yet observed |
| `cli-env` | not yet observed | not yet observed |

## Before the walk

- **A walk account** on Dev with a credential profile holding a made-up
  Anthropic API key, and an API key of its own. Remove every token, key and
  environment the walk makes by exact name afterwards.
- **A scratch `cw` home** (`HOME` and `CW_CONFIG_DIR` under the walk's
  scratch directory), so no step uses a maintainer's own sign-in or keyring.
- **The four SDKs** built from the source under walk, and the run-agent
  example in `libs/sdk-examples/run-agent`.
- **What to record:** `cw version`, the source Dev was running, and each
  SDK's version.

## `sdk-config`: where a client finds its settings

- **Entry points:** each SDK's client built with no arguments, and with the
  same fields as options.
- **States to exercise:**
  - only `CODEWIRE_API_KEY` set: the client acts with the key;
  - only `CODEWIRE_JWT_TOKEN` and `CODEWIRE_ORGANIZATION_ID` set: the client
    acts as the person; `CODEWIRE_ORG_ID` instead works the same;
  - a key and a token set in the same source: the key is used;
  - a token passed in code and `CODEWIRE_API_KEY` in the environment or a
    `.env` file: the token is used, and the client reports the ignored key
    by name, never its value;
  - a token and organization in `.env` while the environment sets only
    `CODEWIRE_ORGANIZATION_ID`: the environment's organization is used, with
    `.env`'s token, and nothing is reported;
  - a token passed in code with no organization in code, and
    `CODEWIRE_ORGANIZATION_ID` in the environment (or, in Python and
    TypeScript, only in `.env`): that organization is used, and the client
    reports where it came from by name, never its value;
  - neither set: refused, naming both variables;
  - a token with no organization: refused, naming
    `CODEWIRE_ORGANIZATION_ID`;
  - in Python and TypeScript, the key only in `.env` in the working
    directory: used; the same in `.env.local` beside a different `.env`:
    `.env.local` wins; the process environment beats both;
  - `CODEWIRE_API_URL` in a `.env` file: ignored, and the client reports it;
  - the server passed in code beats the environment.
- **Driving it:** no command yet (#5687). Each SDK's example lists
  environments under each setting.
- **Proof:** the identity the server records for each call (the key's id,
  or the person and the token's parent sign-in), and the server each call
  went to. Each refusal comes before any request.

## `user-token`: getting a user token, and what ends it

- **Entry points:** `cw auth token`; Settings.
- **States to exercise:**
  - into a pipe after `cw login`, with `--expires 30` and with
    `--expires never`: the token works, and Settings lists it with its
    expiry, marking the one that never expires;
  - with no `--expires`: it expires in 1 day;
  - in a terminal: refused, and no token printed;
  - signed out: refused, saying to run `cw login`;
  - used to make an API key, change a second factor or delete the account:
    refused by its kind;
  - `cw logout`, revoking it in Settings, a password reset and an account
    disable: each ends it at once;
  - presented to the exchange again: refused.
- **Driving it:** `cw auth token` from the scratch `cw` home, captured
  (`T=$(cw auth token --expires 30)`) and at the terminal; Settings for
  the list and each revocation.
- **Proof:** the token works before each change and answers
  `unauthenticated` after it. Settings shows its last use. The audit log has
  a row for each one issued and each revocation. A capture of the walk's
  terminal holds no token.

## `user-token-bind`: binding a profile with a user token

- **Entry points:** each SDK's environment create, with a profile and the
  confirmation.
- **States to exercise:**
  - with a user token: the create binds the person's profile, and the
    Sandbox holds only placeholders;
  - a profile holding a Codex or Claude sign-in, bound with a user token: no
    Codex `auth.json` or Claude `.credentials.json` login is written into
    the Sandbox, and the agent works through the proxy; the same profile
    bound from a `cw login` sign-in still gets its direct delivery;
  - the confirmation left out: refused before anything is created;
  - an API key asked for a profile: refused before anything is created,
    naming the user token.
- **Driving it:** no command yet (#5687). The run-agent example with
  `CODEWIRE_PROFILE` set, once in each SDK.
- **Proof:** `cw ls` shows the environment with the profile and its
  revision. Inside it, the provider variables hold `cwp1_` placeholders and
  the made-up key appears nowhere. A refused create leaves no environment.

## `cli-env`: `cw` with a key in the environment

- **States to exercise:** with a saved sign-in, `CODEWIRE_API_KEY` and
  `CODEWIRE_API_URL` set: `cw ls` acts with the key; the same with
  `CODEWIRE_SERVER_URL`; with the variables unset again, the saved sign-in.
- **Driving it:** `cw ls` under each setting.
- **Proof:** the identity the server records for each call.
