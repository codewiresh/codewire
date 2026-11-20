# Local and cloud CLI parity

Every `cw` command behaves the same with `--local` and `--cloud`, unless it
can't. This page records, command by command, where the two placements differ
and whether that is **intended** (with the reason and what the user is told) or
a **gap** (with the item that fixes it). The audit and its fixes are tracked in
#4717; the Claude credentials in #4714.

A gap is fixed with one implementation that both placements call, where only
the store differs: the local credential authority (the operating system's
protected store) or the platform credential service. Never a second copy.

## Where it stands (2026-11-19)

The tables below are the audit as it ran on 2026-11-15. Since then:

- **Same in both now:**
  - C1, C4's refusal sentences and C5 (#5097);
  - C2 and C3: one `connect` flow and one GitHub connection (#4904), and the
    reconnect question with no ID or revision, its result on stdout and
    `--output json` (#5277);
  - a `connect` whose save is refused says why in the same words in both
    placements (#4826, #5269);
  - C6: `delete` and `revoke` revoke first and say what the provider still
    holds (#4908, #4966, #4991), and the dashboard's GitHub disconnect does
    the same (#5252);
  - C8, a local default profile (#4924);
  - `connect github` with the Codewire GitHub App installed on no account
    the approving login can use says so, with the install link of the App
    the connection uses and to connect again, in the same sentence in both
    placements (#5479; the cloud not yet observed).
- **Open:**
  - C6's local placement asking OpenAI itself (#4982);
  - C7, the cloud's profile revisions;
  - the same name under two providers (#4928);
  - C9, an older `cw` against a newer authority saying what to do;
  - local store waits and refusals in words (#5271), and a Linux store kept
    inside its credential root (#5255).

A row below keeps its 2026-11-15 wording until the change that closes it
updates it.

## How the audit runs

- **Binary:** the released `cw` (v0.4.18 for the first pass), not a build.
- **Local:** an isolated `HOME` and a private Secret Service (its own
  `dbus-daemon` and `gnome-keyring-daemon`, as
  `scripts/ci/verify/smoke-native-local-environment.sh` starts them), so the
  workstation keyring is never read or written.
- **Cloud:** Dev, signed in with `cw login` in that same isolated `HOME`. An
  API key can't run these commands: credentials and profiles are
  account-global, and an API key is organization-scoped ("organization-scoped
  API key cannot perform account-global operations").
- **Values:** synthetic only, every name starting `parity-`, all removed
  afterwards. A device or browser sign-in is recorded up to the provider step
  and then cancelled. On a Dev account that isn't disposable, a step that
  changes an account setting (the default profile) restores it straight after.

First pass: 2026-11-14, `cw` v0.4.18, every row below run in both placements
unless it says *read, not run*: those need a completed provider sign-in or an
existing OAuth credential, and were read from the code.

## Credentials (`cw credentials`)

### Where the code is

| Layer | Local | Cloud | Shared today |
| --- | --- | --- | --- |
| Command handler | `commands/credentials.rs` | `commands/platform_credentials.rs`, `commands/platform_profiles.rs` | no: two handlers |
| Guided choices | `commands/guided_credentials.rs` | same file | yes: one list per picker, the set its command takes in both placements, and a test holds them equal (#5446) |
| Prompts and parsing | `commands/credential_input.rs` | same file | yes |
| Codex and GitHub device login | the CLI, `commands/provider_login.rs` | the credential service | yes: both call `codewire-credential-broker` `provider_oauth::{codex, github}` |
| Claude sign-in | none | the credential service, `mutation/claude.rs` | `provider_oauth::claude` exists, only the cloud calls it |
| Store | `codewire-local-credentials` | `codewire-platform-credentials` | no, and needn't be |

The provider protocols are already one implementation. What differs is the
command layer around them: two handlers that each check the name, confirm a
reconnect, show the provider step and print the result in their own way.

### Providers

| Command | Local | Cloud | Status |
| --- | --- | --- | --- |
| `add openai`, `add anthropic` (API key) | Prompts `Credential material:` at a terminal, or reads stdin. Prints `Local credential "NAME" added (ID).` on stderr | Same prompt and stdin. Prints the credential's metadata line on stdout | **Gap C1** (result output). The prompt wording is #4715 |
| `connect claude-token` (a `claude setup-token` token; today `add claude-subscription`) | Refused before any prompt: "Claude subscription tokens are stored only in your Codewire account; use --cloud". Not offered in the guided `add` list | Guidance ("Run `claude setup-token` …"), then a no-echo `Paste the token from claude setup-token:` prompt; stored with a one-year expiry | **Gap** #4714, and the command's name #4945 |
| `connect claude` (browser sign-in, paste the code back) | Refused: "Claude sign-ins are stored only in your Codewire account; use --cloud". Not offered in the guided `connect` list | Link screen, browser opens, paste `code#state` | **Gap** #4714 |
| `connect codex` | Guidance, then one line: `Open URL and enter this one-time code: CODE` / `Continue only if you started this Codex login in Codewire.` No browser. Prints `Local Codex credential "NAME" connected (ID).` | Same guidance, then the link screen (link copied by OSC 52, browser opened), `Enter this code: CODE`, then the `Logged in as ACCOUNT` screen and the metadata line | **Gap C2** (one connect flow) |
| `connect github` | As Codex, no guidance. A second connection under another name reconnects the existing one in place | As Codex. A second connection under another name is refused by the service before any challenge (one GitHub connection per user), but the CLI reports it as "GitHub enrollment acknowledgement is unknown; reconcile the credential by name before retrying": `codewire-client` maps every error before the challenge to that text | **Gap C2**, and **C3** (the second-connection rule and its message) |
| `connect` reconnect prompt (*read, not run*) | "Reconnect local OAuth credential … the credential will become active and its hard expiry will be preserved." | "Reconnect platform … credential … Its identity, profile bindings and hard expiry will be kept." Both stores reactivate | **Gap C2** (one message) |
| `generate ssh` | Metadata line, public key, fingerprint, then the GitHub hint | Same content in the cloud's metadata format | **Gap C1** (format only) |
| `add ssh --key-file FILE` | Name checked before the file is read | Same | same |
| `add ssh` without `--key-file`, no terminal | "missing required input; …" | Same (shared guided check) | same |
| `add PROVIDER` for an unsupported provider | "provider mistral does not support API-key enrollment" | "API-key enrollment supports openai or anthropic; use add claude-subscription …" | **Gap C4** (one message) |
| `add … --account-hint` | Accepted and listed | Refused: "platform API keys do not use --account-hint" | **Gap C5** |
| `add` with a name already in use | Raw store error: "add local credential: code: 'Some entity that we attempted to create already exists', message: "local credential record already exists"" | "add platform API key; inspect by name before retrying an uncertain acknowledgement: credential name already exists" | **Gap C4** |
| A name another provider's credential has (#4928) | `connect`, `add`, `generate` and `rename` take it; a name this provider's credential has is refused before any sign-in or key prompt, naming that credential's kind and a free `NAME-2` | Same, by name and provider; a name the service refuses that the CLI could not read says only the provider | same |
| A bare name two providers share (#4928) | `get`, `rename`, `rotate`, `revoke`, `delete` and `connect --name` refuse it before anything changes, listing the providers; `PROVIDER/NAME` names one, and `set SLOT NAME` needs no prefix | Same words, from the service's `CREDENTIAL_NAME_AMBIGUOUS` | same |

### Credential lifecycle

| Command | Local | Cloud | Status |
| --- | --- | --- | --- |
| `list`, `get` (text) | A column table: ID, PLACEMENT, PROVIDER, KIND, NAME, HINT, STATUS, STORE, GENERATION. No expiry | One line per credential: ID, "NAME", provider (naming the Claude form), status (an active credential past its expiry reads `expired`), revision; an `expires` line | **Gap C1** |
| `list`, `get` (`--output json`) | `id, placement, owner, provider, authentication_kind, name, account_hint, status, expires_at_unix, revocation_generation, protected_store_persistence, cleanup_pending, created_at_unix_ms, updated_at_unix_ms` | The service's message, with its own field names | **Gap C1**: a script can't read both |
| `list` GitHub status (*read, not run*) | Shown only after `connect github` | Also checks each installation's pending permissions on every `list` and `get` | **Gap C1** |
| `get` an unknown name | `local credential name "NAME" was not found` | `credential not found` | **Gap C4** |
| `rename` | `Local credential renamed to "NEW".` | The metadata line | **Gap C1** |
| `rotate` an API key | No notice. Reactivates a revoked key; omitting `--expires-at` clears the expiry. Prints `rotated to generation N` | Prints what rotation does first ("sets its status to Active (including if revoked) and clears the hard expiry"), then the metadata line | **Gap C1** (notice and result); same behaviour |
| `rotate` an SSH key | "enroll a new SSH identity with generate ssh or add ssh, …" | "rotate supports OpenAI/Anthropic API keys and Claude subscription tokens; use connect …" | **Gap C4** |
| `rotate` an OAuth credential (*read, not run*) | "OAuth credential material cannot be entered manually; use credentials connect …" | The same message as SSH above | **Gap C4** |
| `rotate` a Claude subscription token | Not possible (no such local credential) | Replaces the token, restarts its one-year expiry | **Gap** #4714 |
| `revoke` | The metadata line (table), JSON with `--output json` | The metadata line, JSON | **Gap C1** (format only) |
| `delete` an active credential | Deleted | Refused: "revoke the platform credential before deleting its stored record" | **Gap C6** |
| `delete` a credential a profile uses | Refused, as a raw store error: "local credential is selected by an access profile or environment; unset it from the profile (cw credentials --local --profile NAME unset PROVIDER) or remove the environment first" | Refused only after a revoke: "… credential is referenced by a profile or binding", which doesn't say how to free it | **Gap C4**, C6 |
| `delete` without `--yes` at a terminal | `Delete local credential "NAME"? [y/N]` | `Delete platform credential "NAME"? [y/N]` | same (placement word only) |

### Profiles

| Command | Local | Cloud | Status |
| --- | --- | --- | --- |
| `--profile P set SLOT NAME` | Creates the profile on first set. Prints `Local access profile "P" updated to revision N.` | Creates on first set. Prints the profile: ID, `platform:user/P`, revision, then one line per slot, always including `github account connection` | **Gap C1** |
| `set` a credential of the wrong kind | "this provider identity/capability has no supported runtime adapter" | Same (shared check) | same |
| `set github`, `unset github` | "every profile includes your one GitHub connection; …" | Same (shared) | same |
| `unset` a slot the profile doesn't select | "local access profile "P" does not select slot ssh" | "platform profile does not select that capability slot" | **Gap C4** |
| `--profile P get --revision N` | Shows that revision | Shows that revision | same |
| `--profile P revisions` | Lists every revision | Refused: "platform history listing is not supported; use --profile=NAME get --revision REVISION" | **Gap C7** |
| `profiles default P` | Refused: "local credential profiles have no default; the default is a cloud credential profile (use --cloud)" | Sets the default; the default can't be deleted | **Gap C8** |
| `--profile P generate ssh` | Generates and sets it in the profile | Same | same (format C1) |
| `--profile P delete` | `Delete local access profile "P"? [y/N]`, then `Local access profile "P" deleted.` | Refuses the default (""P" is your default credential profile and cannot be deleted; make another profile the default first: …"); otherwise `Delete platform user profile "P" (ID) at revision N?`, then `Platform access profile deleted.` without the name | **Gap C1**, C8 |
| An organization profile reference | "local storage supports user profiles only" | "organization platform profiles are not supported by the metadata API yet" | intended for local: a local store has one user. Cloud: not yet built |

### The gaps

C3, C6 and C8 were decided on #4717 (2026-11-14) under the rule that the two
placements behave the same unless they truly can't.

| Item | What changes | Fix |
| --- | --- | --- |
| #4714 | `connect claude` and `add claude-subscription` work locally, through `provider_oauth::claude` and the same prompts; the local authority admits both forms; a local VM projects Claude Code's subscription mode as a hosted Sandbox does | First fix PR |
| C1 | One renderer for credential and profile results, text and JSON, used by both handlers: the same columns, the same JSON fields, placement as a field | Shared output module |
| C2 | One `connect` driver: name check, reconnect confirmation, provider step screen (link, browser, code), success screen, result. The store runs the provider protocol: the CLI for local, the service for cloud | Codex and GitHub unified, after #4714 |
| C3 | The cloud's rule in both: one GitHub connection per user. A second `connect github` under another name is refused with "GitHub is already connected as NAME; run `cw credentials connect github --name NAME --yes` to reconnect it". The cloud client passes the service's message on instead of "acknowledgement is unknown" | With C2; the message is a client fix |
| C4 | The same refusal text for the same refusal, with the placement word the only difference; no raw store error reaches the user | With C1 |
| C5 | `--account-hint` either works in both or neither | With C1 |
| C6 | In both: `delete` on an active credential asks once, then revokes and deletes it in one step. A credential a profile uses is refused with the exact `unset` command that frees it | Small PR, with C4 |
| C7 | Profile revision listing in the cloud (needs a service listing) | Service and CLI |
| C8 | Local gets a default profile as the cloud has: `cw credentials --local profiles default P`. `create --local` uses it when `--profile` isn't given, and the default can't be deleted until another is chosen | Local store and `create` |
| C9 | A `cw` older than the local authority that a newer `cw` left running says what to do, in plain words: use the newer `cw`, or stop the local VMs so the authority can be replaced. Today every local command fails with "local credential authority protocol is incompatible" and no next step | CLI error text |

Each fix adds or extends the credentials journey,
`docs/journeys/credentials.md`, with the same steps for `--local` and
`--cloud`.

### Done when

From cw-credentials-ux's walk (2026-11-15, relayed by cw-pm). Each gap is
done when what its walk found is gone, on both placements:

- **C1** (cw-cli, track C). The walk found:
  - local `list` is 171 columns wide and shows ID, PLACEMENT, STORE
    `operating_system` and GENERATION, with no expiry;
  - profiles show their credentials as UUIDs (`anthropic=861184f5-…`);
  - cloud `list` shows a Codex sign-in and an OpenAI key both as `openai`,
    sorted by ID;
  - creating a profile prints "updated to revision 1".

  Done when the default `list` is narrow (name, provider with a Codex
  sign-in told apart from an OpenAI key, status, expiry), IDs and the store
  appear only under `--wide` or `--output json`, profiles show credential
  names, a new profile says it was created, and both lists name the Claude
  kinds `Claude (token)` and `Claude (sign-in)` (#4945).
- **C4** (cw-cli, track C; #4928 is cw-parity's). The same name under another
  provider gets the store's raw text ("Some entity that we attempted to
  create already exists…"). Done when the same name is allowed under
  different providers in both stores, as the approved list shows
  (`n@example.com` as both `Claude (sign-in)` and `Codex`), and any refusal
  that remains is one sentence naming the existing credential and the next
  step.
- **C6** (cw-selfhost, track E). `delete` with no terminal and no `--yes`
  prints the prompt, then "Canceled.", and exits 0; `revoke` at a terminal
  asks nothing. Done when that `delete` exits 1 and names `--yes`, and
  `revoke` at a terminal confirms first.
- **The approved screens** (owner, 2026-11-15: "yes credentials design is
  perfect land it"; private-docs `designs/2026-11-15-credentials-screens.html`,
  proposed parts included) are each step's expected output, and
  `docs/journeys/credentials.md` quotes them:
  - every connect: the title `Connect PROVIDER as NAME, on this computer`
    (or `in your Codewire account`), two-space indent, then one result line
    `✓ PROVIDER connected as ACCOUNT` (C2, #4904 and #4945);
  - a device code: `Open this link to sign in:` and the link, then
    `Enter this code:` and the code alone on the next line; the copy key and
    the waiting line are #4885's;
  - Claude (sign-in): `Paste the code Claude shows after you sign in >`,
    then `Got it (N characters).`;
  - Claude (token): ``Run `claude setup-token`, then paste what it prints.``,
    `Token >`, `Got it (N characters).`, then
    `✓ Claude (token) connected as NAME · expires 15 Nov 2027` (#4945);
  - the list: `NAME  KIND  STATUS  EXPIRES  PROFILES` under `On this
    computer` and `In your Codewire account`, no IDs (C1, #4928).
- **C9** (cw-parity). Done when an older `cw` against a newer authority names
  the way out instead of "protocol is incompatible".

### What #4714 changes

The guest side and the refresh engine already handle both Claude forms for any
placement. What's missing is all on the local host:

1. The local authority admits Anthropic OAuth (the setup token) and Claude
   sign-in (`codewire-local-credentials` `add_credential_inner`, the
   `TODO(native-claude-subscription-form)`), and its refresh journal accepts the
   sign-in kind.
2. `--local connect claude` calls `provider_oauth::claude::ClaudeSignIn`
   `start` and `complete` in the CLI, as the credential service does; `--local
   add claude-subscription` takes the same pasted token. Both share the cloud's
   prompts.
3. A local profile picks the Claude form from the credential's kind, as the
   platform-profile route already does (`codewire-local-vmm`
   `supervisor/sources/platform.rs`), instead of always the API-key form.
4. The local broker leases and refreshes the sign-in through the existing
   `claude_login`, `exchange_claude_oauth_refresh` and `commit_local_refresh`,
   as it does for Codex. No keep-alive process; a stale idle login shows in
   `list`.

## Credentials by setup

The owner's ask on #4717 (2026-11-15): for each credential, what isn't the same in the two placements, and the plan to share the code. One block per setup, local beside cloud. **Same** means one implementation; **gap** means the item that fixes it; **intended** comes with its reason.

Terms used below:
- **Proxy:** the broker adds the credential to the agent's provider requests, so the VM never holds it.
- **Signer:** the broker signs for the VM; only SSH works this way.
- **Login delivery:** the listed direct delivery exception (`docs/dev/SECRETS-AND-CREDENTIALS.md`). The agent's own login file holds a short-lived access token, never a refresh token.

### GitHub (`connect github`)

| | Local | Cloud | Status |
| --- | --- | --- | --- |
| Enrol, protocol | The CLI runs `provider_oauth::github` | The credential service runs `provider_oauth::github` | same |
| Enrol, screens | One plain line | Link screen, browser, success screen | gap: C2, plus #4850 for the screen |
| Second connection | Reconnects the existing one in place | Refused (one per user); the client shows "acknowledgement is unknown" | gap: C3 |
| No App installation | After the approval: "the Codewire GitHub App is not installed on any account this GitHub login can use; install it, choose the accounts and repositories, then connect again: https://github.com/apps/codewire-sh/installations/new". Nothing saved | The service refuses the approved login (`CREDENTIAL_GITHUB_INSTALLATION_REQUIRED`, with its own App's install link as `install_url`) and the client says the same sentence with that link, or without a link when none or a malformed one arrives, after the `enroll platform OAuth credential:` label every cloud GitHub refusal carries until #4631 | same (#5479); before it the cloud said "acknowledgement is unknown" |
| App not set up on the server | Doesn't arise: `cw` carries the App's public identity | Refused before any code: "GitHub App authorization is not configured on this Codewire server; no platform credential was changed; ask an administrator to finish the GitHub App setup" (`CREDENTIAL_GITHUB_APP_NOT_CONFIGURED`) | intended: only the cloud depends on server settings; the server's own check is #5303 |
| Store | Local authority | Platform credential service | intended: two stores |
| Profile, default | In every profile; `set github` refused; no default profile | The same; has a default profile | the GitHub rule is the same; the default is gap C8 |
| Delivery | Broker GitHub route: git over HTTPS and `gh` | The same route | same |
| Refresh | On demand in the broker | On demand, plus a keep-alive in the service | intended: local runs no background process (cw-network, 2026-11-14) |
| Revoke at GitHub | Not possible: needs the GitHub App's client secret | Possible (the service holds the secret); not done today | intended locally, with plain wording; cloud: C6 |
| Delete, list, JSON | Deletes an active credential; local table and JSON | Needs a revoke first; cloud table and JSON | gap: C6, C1 |

### Codex ChatGPT sign-in (`connect codex`)

| | Local | Cloud | Status |
| --- | --- | --- | --- |
| Enrol, protocol | The CLI runs `provider_oauth::codex` | The service runs `provider_oauth::codex` | same |
| Enrol, screens | One plain line | Link screen, browser, success screen | gap: C2, #4850 |
| Store | Local authority | Platform | intended |
| Delivery | Proxy, plus login delivery (`auth.json`) from a local profile | Proxy, plus login delivery from a platform profile | same predicate shape (`local_codex_login_admissible`) |
| Refresh | On demand (`exchange_codex_oauth_refresh`, `commit_local_refresh`) | On demand, plus keep-alive | intended, as for GitHub |
| Login lease during a refresh | Denied, and the delivered login is removed until the next check | Served | gap: #4714 follow-up 4 |
| Revoke at OpenAI | Not done today; OpenAI publishes an RFC 7009 endpoint with public clients allowed | Not done | gap: C6 |
| Delete, list, JSON | As GitHub | As GitHub | gap: C6, C1 |

### OpenAI API key (`add openai`)

| | Local | Cloud | Status |
| --- | --- | --- | --- |
| Enrol | Shared prompt (`Credential material:`); prints a sentence | Same prompt; prints the metadata line | prompt: #4715; output: C1 |
| `--account-hint` | Accepted | Refused | gap: C5 |
| Delivery | Proxy (Codex's API-key route, `openai` slot) | Proxy | same |
| Rotate | No notice; reactivates; clears the expiry | Notice, then the same behaviour | gap: C1 (notice) |
| Revoke at OpenAI | Only in OpenAI's console | Only in the console | intended; both must say so (C6) |
| Delete, list, JSON | | | gap: C6, C1 |

### Anthropic API key (`add anthropic`)

As the OpenAI key, with Claude Code's API-key form: a placeholder `ANTHROPIC_AUTH_TOKEN` and the broker's Anthropic route, in both placements (`with_anthropic_kind(ApiKey)`). Its gaps are the same: C1, C4, C5, C6.

### Claude setup token (`connect claude-token`)

Both Claude subscription forms are connected with `connect` (owner,
2026-11-15, #4945): `connect claude` signs in with the browser, and
`connect claude-token` takes the token `claude setup-token` prints, at a
hidden prompt or from stdin. Help, the guided picker and the dashboard call
them "Claude (sign-in)" and "Claude (token)", both your Claude subscription,
and lists use the same names: the sign-in shows your plan and usage, the token
lasts a year, for automation, with model requests only. A token is replaced by
repeating `connect claude-token --name NAME`, which asks first; `rotate` stays
for API keys and says so. `add claude-subscription` stays a hidden alias for
one release, printing one `→` line with the exact new command; `add` is for
API keys and SSH keys. These details were settled on #4945 (cw-pm,
2026-11-15).

| | Local | Cloud | Status |
| --- | --- | --- | --- |
| Enrol | Refused ("use --cloud") | `add claude-subscription`: guidance, then a hidden paste; expires after one year | gap: #4714 PR 2; both become `connect claude-token` through one implementation (#4945) |
| Delivery | — | Proxy in token form (`CLAUDE_CODE_OAUTH_TOKEN=codewire-managed`); never delivered | gap: PR 2 projects the same form (`with_anthropic_kind(OAuth)`, already shared) |
| Rotate | — | Replaces the token and restarts the year | gap: PR 2 |
| Revoke at Anthropic | — | No published endpoint; the year runs out | intended: say so plainly (C6) |

### Claude sign-in (`connect claude`)

| | Local (#4798) | Cloud | Status |
| --- | --- | --- | --- |
| Enrol, protocol | The CLI runs `provider_oauth::claude` | The service runs it | same |
| Enrol, screens | `login_screen::claude_sign_in_code` | The same function | same |
| Store check before the browser step | Protocol and feature (`AuthorityFeature::ClaudeSignIn`); not yet a write probe | Server-side | gap: store-write probe (protocol 18) |
| Delivery | Login delivery (`claudeAiOauth`), base URL only | The same | same: walked on Linux, 2026-11-15 |
| Refresh | On demand (`exchange_claude_oauth_refresh`) | On demand, plus keep-alive | intended |
| Revoke at Anthropic | No published endpoint | None | intended: "sign out of other sessions in Claude's settings" (C6) |

### SSH key (`generate ssh`, `add ssh`)

| | Local | Cloud | Status |
| --- | --- | --- | --- |
| Generate, import | `ssh_material::{generate_ed25519, import_openssh}` | The same functions | same |
| Delivery | Signer (the broker's ssh-agent route) | Signer | same |
| Rotate | Refused: enrol a new key | Refused, in other words | gap: C4 |
| Delete, list, JSON | | | gap: C6, C1 |

### The plan

Each item is one implementation that both placements call; only the store differs. In order:

| # | PR | Shared code | Depends on | Target |
| --- | --- | --- | --- | --- |
| 1 | #4798: local Claude sign-in | `provider_oauth::claude`, `login_screen`, `with_anthropic_kind`, `is_refreshable_login` | review and CI (done; merging) | 2026-11-15 |
| 2 | #4868: macOS store names the login keychain (#4864) | `keychain.rs` | #4798 | 2026-11-16 |
| 3 | Store-write probe before every sign-in, an uncertain code for a post-commit failure, a login lease that waits during a refresh | a new authority call, protocol 18 | #4868 | 2026-11-17 |
| 4 | #4714 PR 2 and #4945: `connect claude-token` in both placements, the local setup token, and the `add claude-subscription` alias | the cloud's prompt, argument checks and one-year expiry, moved to `credential_input`, behind the one connect flow (#5) | #5; a store protocol number at merge | 2026-11-18 |
| 5 | C2 + C3: one `connect` flow for Codex, GitHub and Claude; one GitHub rule; the client stops dropping "already connected" | a new shared connect module that calls #4850's screen, with cancellation before publication | #4850 (cw-cli) | 2026-11-19 |
| 6 | C1 + C4 + C5: one renderer for results, text and JSON; one sentence per refusal; `--account-hint` the same | a shared output module | #5 | 2026-11-20 |
| 7 | C6: one delete rule, and revocation at the provider where one exists (Codex RFC 7009; GitHub from the cloud); plain wording where it doesn't | `provider_oauth::codex` revoke | #6; cw-network review (a new outbound call) | 2026-11-21 |
| 8 | C7 + C8: cloud profile revisions; a local default profile that `create --local` uses | the service listing; the authority default | #6 | 2026-11-22 |

A setup is **done** when walked in a Linux local VM, a Mac local VM (cw-dogfood on the M3) and a hosted Sandbox on Dev, and recorded in `docs/journeys/credentials.md`.

**Sign-ins the walks need from the owner.** Everything else is prepared first, and each is asked for once:

| Walk | Sign-in | Where |
| --- | --- | --- |
| Codex ChatGPT, local | Approve one device code | Linux workstation; M3 |
| GitHub, local | Approve one device code | Linux workstation; M3 |
| Claude sign-in, local | Browser sign-in, paste the code | M3 (Linux done 2026-11-15) |
| Claude setup token, local | Run `claude setup-token` and paste the token into `cw` | Linux workstation; M3 (after #4) |
| OpenAI and Anthropic API keys, local | Paste each key into `cw`'s prompt (never into a chat) | Linux workstation; M3 |
| Hosted Sandbox, all setups | None | The owner's Dev account already holds a GitHub connection, a Codex login, a Claude sign-in and an SSH key; the walk uses them and a Dev sign-in |

## Other command groups

Not audited yet; each will get its own table as above. Known differences are
listed so they aren't lost.

| Group | Commands | Status |
| --- | --- | --- |
| Secrets | `secrets` | not yet audited |
| Network policy | `policy` | not yet audited |
| Create and run | `create`, `run`, `init`, `update`, `export`, `preset` | not yet audited |
| Lifecycle | `start`, `stop`, `restart`, `rm`, `extend`, `protect`, `unprotect`, `cancel-delete`, `prune`, `nuke` | not yet audited. `restart` is local only by its help text |
| Inventory | `ls`, `info`, `use`, `current` | not yet audited |
| Sessions | `exec`, `shell`, `attach`, `logs`, `msg`, `inbox`, `send`, `wait`, `interrupt`, `steer`, `resize` | not yet audited |
| Ports and previews | `ports`, `share`, `access`, `vscode`, `cp` | not yet audited |
| Snapshots and checkpoints | `snapshot`, `checkpoint` | not yet audited. Mac VM checkpoints are #4654 |
| Setup and health | `setup`, `doctor`, `login`, `logout`, `whoami` | not yet audited |
| Billing | `cost` | not yet audited; billing on a local VM is expected to be intended |
| Organizations | `org` | platform only (an organization has no local store). Separately, a **CLI-versus-dashboard gap**: `cw org invite` sends an invitation, but no command lists or revokes an organization's pending invitations; `ListInvitations` and `RevokeInvitation` exist in `proto/codewire/v1/organization.proto`, and only the dashboard calls them. `cw org invitations` lists invitations sent to you |
| Platform only | `api-keys`, `member`, `host`, `hosts`, `mesh`, `control` | to classify: account and organization administration has no local store |
| Local only | `daemon`, `runtime`, `network`, `agent`, `install`, `config` | to classify |
