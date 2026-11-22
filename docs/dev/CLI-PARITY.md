# Local and cloud CLI parity

Every `cw` command behaves the same with `--local` and `--cloud`, unless it
can't. This page records, command by command, where the two placements differ
and whether that is **intended** (with the reason and what the user is told) or
a **gap** (with the item that fixes it). The audit and its fixes are tracked in
#4717; the Claude credentials in #4714.

A gap is fixed with one implementation that both placements call, where only
the store differs: the local credential authority (the operating system's
protected store) or the platform credential service. Never a second copy.

## Where it stands (2026-11-22)

The second pass (2026-11-21, `cw` v0.4.26) audited every other command group:
secrets, network policy, create and run, lifecycle, inventory, sessions, ports
and previews, snapshots and checkpoints, setup and health, and billing. Each
has its own table and gap list below the credentials ones; two differences
that run through all of them are under "Across groups". The organizations,
platform-only and local-only groups are classified at the end, not walked.
Since then (2026-11-22), not yet observed on a surface:

- **Same in both now:** R1 (242addf606), S3 (19a51afe40), K3 (2e2960920c), S4
  (ff0d91d276), P3 (07ad66bb3f), L1 (d3505ab915), N1's missing program
  (c9b80bf7c8) and L7 (bffcb26313); then R3 (e5aece4c8c), R2
  (868eae223d), H1 (643b739dbc), B1 (a5a66569a6), R8 (b5078084f3) and N2
  (ef334abf33).
- **Open:** every other gap below, and N1's `exec -t` blank line.

The credentials tables are the audit as it ran on 2026-11-15. Since then:

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

A credentials row keeps its 2026-11-15 wording until the change that closes
it updates it.

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

Second pass: 2026-11-21, `cw` v0.4.26, for the other command groups:

- **Local:** the local-smoke isolation
  (`scripts/ci/verify/lib/local-smoke-isolation.sh`): its own `HOME`, a
  private Secret Service and a private mount namespace, a fresh root each run.
  One local VM at a time, created with `--no-file --no-profile`.
- **Cloud:** Dev, as the smoke identity with its organization API key, in a
  fresh `HOME`. Dev has organization network policies turned off, so the
  cloud's stored-policy rows are read from the code.
- **Names:** every environment, policy, secret, project, snapshot and preset
  starts with `parity-`, and each was removed by exact name (the three
  same-named cloud environments of R1 by ID).
- A command with no placement (`init`, `preset`, `current`, `whoami`,
  `doctor`, `cost`) was run once not signed in, in the local isolation, and
  once signed in to Dev. `prune` and `nuke` were run only where they touch
  nothing but the audit's own objects; the rest is *read, not run*.

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

## Across groups

Two differences run through every group below, so each is listed once here.

| Item | What differs | Fix |
| --- | --- | --- |
| A1 | The cloud's messages say "platform" where the flags and help say "cloud": "Platform environment "X" not found", "Platform secret project was not found …", `Delete platform secret project …`, `Secrets: platform:NAME`, `Environment: ID (platform)`. Local messages say "native" in places: "Native local preview does not yet support: --env", `Update native environment …`, "non-interactive native resize", and the cloud's "Restart is supported only for native local environments" | One placement noun, "local" or "cloud", from one display of the placement that both handlers use |
| A2 | Cloud results name the environment by ID where local ones name it: `cp` (`Uploaded FILE -> ID:/workspace/FILE`), `resize` (`Environment: ID`), `rm --output json` (`"environment": ID`), `snapshot inspect` (`Source: ID`) | The shared name resolution returns the name and the ID; both handlers print the name |

Same in both, and not a parity item: an error that starts with a name has its
first letter raised (`Parity-c1 has 7 sessions …`, `Codewire.yaml already
exists …`).

## Secrets (`cw secrets`)

One command module (`commands/secrets.rs`) parses the scope and the placement
for both. The local store is the local credential authority and the cloud
store the platform's secret service, and each branch prints its own results.
`preview` already uses one renderer (`print_secret_resolution`).

| Command | Local | Cloud | Same or gap |
| --- | --- | --- | --- |
| Any key command without `--local` or `--cloud` | "Storage placement is required: pass --local or --cloud (noninteractive and JSON commands never prompt)", exit 1 | Same | same |
| `list` without a scope | "Key operations require exactly one of --project=NAME, --user, or --organization; no project is inferred" | Same | same |
| `--user list`, nothing there | "No local user secrets found.", exit 0 | "No user secrets found.", exit 0 | same; neither names the command that adds one |
| `--user list`, text and `--output json` | KEY, CREATED, UPDATED; times in RFC 3339 with milliseconds. JSON `key`, `created_at`, `updated_at` | Same columns and fields; times to the second | **Gap S1** (time format) |
| `--user set KEY`, value on stdin | `Local user secret KEY set.` on stderr | `Secret KEY set.` | **Gap S1** |
| `set` an empty value, or nothing on stdin | "Workload-secret value must be non-empty UTF-8 without NUL bytes and at most 65536 bytes", exit 1 | Same | same |
| `set` a key that isn't a variable name | Parser error, exit 2 | Same | same |
| `rename`, `delete` | `Local user secret A renamed to B.`, `… deleted.` | `Secret A renamed to B.`, `… deleted.` | **Gap S1** |
| `rename` a key that isn't there | Raw store error: `Rename local user secret: code: 'Some requested entity was not found', message: "local credential record was not found"` | "Rename user secret: secret not found" | **Gap S2** |
| `delete` a key that isn't there | "There is no local user secret KEY, so nothing was deleted", `→ cw --local secrets --user list`, exit 1 | The same, `cloud`; the service answers NotFound | Same in both now (19a51afe40); was S3: the raw store error locally, `Secret KEY deleted.` and exit 0 in the cloud |
| `--organization` (list, set, delete) | "Organization workload secrets are unsupported locally; use --cloud", exit 1 | Works | intended: a local store has one user and no organization. The message is plain, but "workload secrets" is an internal word; help says "application secrets" |
| Guided `set` at a terminal | "Where should this secret live?": A project, Your account | Same, plus Organization | intended, as above |
| `projects list`, nothing there | "No secret projects found." | Same | same |
| `projects create NAME` | `Local secret project "NAME" created (ID).` | `Secret project "NAME" created. (id: ID)` | **Gap S1** |
| `projects create` a name in use | Raw store error ending "local credential record already exists" | "Create secret project: secret project with this name already exists" | **Gap S2** |
| `projects create 'bad name'` | Refused before the store: "a secret project name starts with a letter or digit and has only letters, digits, '-', '_' and '.', at most 64 characters" | The same, before the store; the service refuses the same names | Same in both now (ff0d91d276); was S4: the raw store error locally, a project named `bad name` in the cloud |
| `projects list`, text and JSON | NAME, SECRETS, CREATED. JSON has `org_id: ""` and `secret_count` | Same columns. JSON leaves out `secret_count` when it is 0 | **Gap S1** |
| A project that doesn't exist | "Local secret project was not found" | "Platform secret project was not found in the selected organization" | **Gap S2** (neither names it), A1 |
| `--project P set`, `list`, `delete` | `Local secret KEY set in project "P".` | `Secret KEY set in project "P".` | **Gap S1** |
| `projects delete` without `--yes`, no terminal | "Project deletion requires --yes when noninteractive", exit 1 | Same | same |
| `projects delete` at a terminal | `Delete local secret project "P" (ID) and all its keys? [y/N]`; `n` prints `Canceled.`, exit 0 | `Delete platform secret project "P" (ID) in organization ORG_ID and all its keys? [y/N]` | **Gap S1** (the raw organization ID), A1 |
| `preview --file` | PLACEMENT, KEY, SOURCE, OVERRIDDEN; JSON the same fields | Same renderer | same |
| `preview` of a file that selects organization secrets | "Organization workload secrets are unsupported in local preview; use --cloud" | "No workload secrets selected." when the organization has none | intended, as `--organization` |

### The gaps

- **S1.** One renderer for secret results, lists and prompts, text and JSON,
  that both stores call. The placement word is the only difference; times use
  the CLI's vocabulary; JSON has the same fields.
- **S2.** Both stores' "not found" and "already exists" become one typed
  error with one sentence that names the key or project and the command that
  lists them. No store error text reaches the user.
- **S3.** One rule, in the shared layer, for deleting a key that isn't there:
  say nothing was deleted (the local answer, in words), never "deleted".
  Same in both now (19a51afe40).
- **S4.** One project-name check before either store
  (`parse_secret_project_name`, the local grammar), and the service refuses the
  same names. Same in both now (ff0d91d276): the grammar is
  `codewire_workload_secrets::validate_secret_project_name`.

## Network policy (`cw policy`)

`commands/policy.rs` holds the parser, the built-in policies and the
renderers (`print_policy`, `print_policies`, `print_check`). The cloud handler
(`commands/policy/platform.rs`) calls the same renderers, but passes the
service's own message through for every refusal.

Dev has organization network policies turned off, so every cloud command that
reads or writes a stored policy is refused there. Checks against the built-in
policies and target validation need no store and were run in both; the other
cloud rows are *read, not run*.

| Command | Local | Cloud | Same or gap |
| --- | --- | --- | --- |
| Any command without `--local` or `--cloud` | Uses this computer's store. A text `list` first says "Policies on this computer; your organization's are in `cw --cloud policy ls`:" | — | intended: scripts written before organization policies keep their meaning (#4594) |
| A stored-policy command on Dev | — | "Organization network policies are not enabled on this deployment; keep the policy on this host with `cw --local policy`", exit 1; the same sentence under `--output json` | intended on this deployment; plain |
| `list` | `open` and `locked`, then `NAME  rev N · TARGET (PORTS), …` per policy | Same renderer (*read, not run*) | same |
| A local `list`, `--local` or none | Reads the store without the supervisor; none stored lists `open` and `locked`. Starts nothing | Starts nothing | Same in both now (07ad66bb3f); was P3: it started the supervisor and left it running |
| `create NAME --allow …` | `Created network policy NAME · rev 1` and its rules. JSON: id, `reference` (`local:id:…`), revision, digest, rules, `enforced_in` | Same renderer, then "Stored. Hosted sandboxes don't enforce network policies yet, so this changes nothing a sandbox can reach." (*read, not run*) | same output; enforcement is **P1** |
| `create` with a private range or a bad pattern | "Invalid allow target: the range includes protected addresses"; "… not a host name, a *.domain pattern or a CIDR" | Same, before the store | same |
| `create` without NAME, no terminal | "Missing required input; name the policy: `cw --local policy create NAME` …" | Same, naming `--cloud` | same |
| `create open`, `allow open …`, `delete open` | "Open is a built-in policy and cannot be changed; create your own with `cw policy create NAME --allow TARGET` …" | Same, naming `--cloud` | same |
| A name in use; `--from`, `allow`, `rm`, `check` or `delete` of a missing policy; `allow` of a rule it has | "Create the network policy: a local network policy named X already exists"; "… no local network policy is named X"; "Change the network policy: X already allows exactly that" | The action, then the service's message (*read, not run*) | **Gap P2** |
| `allow` on a policy an environment uses | `Changed network policy X · rev 2`, then `Enforced now in: ENV` | The stored line above (*read, not run*) | **P1** |
| `check POLICY DEST` | `Allowed: example.com:443 by X rev 4, when the name answers public addresses` or `Refused: … (name not allowed)`, exit 0 either way; JSON `allowed`, `reason`, `revision` | Same for `open` and `locked`; a stored policy *read, not run* | same |
| `delete` a policy an environment selects | "Delete the network policy: local network policy X is selected by ENV" | *read, not run* | **Gap P2** |
| `create --policy X`, `update ENV --policy X` | Selected and enforced; `info` shows `X · rev 1`. `update --policy` applies at once, without asking, even at a terminal | On Dev, `create`: "Create environment: platform network policies are not enabled on this deployment"; `update`: "Organization network policies are not enabled on this deployment", with no next step | **P1**, **Gap P4** |

### The gaps

- **P1.** A cloud sandbox doesn't enforce its policy yet, as `create --help`
  says. Hosted enforcement (#4000) applies the same compiled rules a local VM
  enforces.
- **P2.** The cloud passes the service's refusal text through. One mapping
  from the store's refusal codes to the local sentences ("no cloud network
  policy is named X", "X is selected by ENV").
- **P3.** A local policy read starts the local VM supervisor and leaves it
  running. A read starts nothing, as the cloud's doesn't. Same in both now
  (07ad66bb3f).
- **P4.** The disabled-deployment refusal has three wordings (`policy`,
  `create --policy`, `update --policy`). One mapping of
  `NETWORK_POLICIES_DISABLED`, with the next step, used by all three.

## Create and run (`create`, `run`, `init`, `update`, `export`, `preset`)

`create` has a local path (`commands/native.rs`) and a cloud path
(`commands/environment/platform_create.rs`) behind `launch_setup.rs`, and both
print their result through `lifecycle_output.rs`. Source confirmation has two
copies (`native/sources.rs` and `environment/sources.rs`). `run`, `init` and
`export` are shared.

| Command | Local | Cloud | Same or gap |
| --- | --- | --- | --- |
| `create --name N --yes`, result | `✓ Environment N created · local VM`, the size, Credentials, Secrets, Network, `→ cw --local shell N` | The same lines, `cloud VM` | same |
| Default size | 2 vCPU · 4 GiB RAM · 20 GiB disk | 2 vCPU · 8 GiB RAM · 80 GiB disk | intended: a local VM uses this computer's memory and disk |
| Progress | Preparing sources, Checking the VM runtime, Preparing the image, Starting the VM, Booting the workspace. The first create downloads the runtime (219 MiB) and says so | Creating sandbox, Waiting for SSH access, Waiting for the workspace daemon, Configuring environment | intended: different machinery, each in the user's terms |
| A name already in use | Refused before anything: `local environment "N" already exists (remove it with cw --local rm N or choose another --name)` | Refused by the service, under the organization lock, in the same sentence: `cloud environment "N" already exists (remove it with cw --cloud rm N or choose another --name)`. A removed environment's name is free | Same in both now (242addf606); was R1: the cloud created a second `N` |
| Without `--yes`, no terminal | Creates when there is nothing to confirm; with a secret project, refuses: "native source selection requires --yes …" (*read*) | Created, with nothing to confirm | same rule, in two copies (R4) |
| `-e KEY=VALUE` | Taken, over codewire.yaml's value; the VM's sessions get it | Taken; the variable reaches `exec` | Same in both now (868eae223d); was R2: "Native local preview does not yet support: --env", exit 1 |
| `--cpu 0.5`, `500m`, `lots` | The cloud's grammar, before the supervisor starts or the configuration is shown. A VM boots whole vCPUs, so a fraction rounds up (0.5 and 500m are 1 vCPU), at most 32; `--help` says so. `lots`: `Invalid CPU quantity "lots"; use values such as 500m, 0.5, or 4` | Before anything: the same refusal | Same in both now (e5aece4c8c); was R3: 0.5 and 500m refused locally, and `lots` refused after the configuration lines in other words |
| `--secrets` a missing project | "Source was not found in the eligible authenticated stores" | "Platform secret project was not found in the selected organization" | **R4**, S2 |
| `--secrets P`, the confirmation block | `Create native environment "N" with these exact sources:`, `Secret project: "local:id:ID"`; the result says `Secrets: local:P` | `Create environment "N" on platform "URL", organization "ORG_ID".`, `Application-secret project: "platform:id:ID"`; the result says `Secrets: platform:P` | **Gap R4**, A1 |
| `--policy P` | Selected and enforced | Refused on Dev | P1, P4 |
| `run --in ENV -- CMD` | The output, then `✓ Started session ENV/echo · local VM` | The same, then `via direct UDP` | same; the transport line is intended: only the cloud has a network path |
| `run --detach --name S`; a name in use; `--output json` | The same results and refusal; JSON the same fields | Same | same (`working_dir` is `/workspace/workspace` locally and `/workspace` in the cloud: intended, a local create mounts the folder at `/workspace/NAME`) |
| `run` with no command; an option after the command; a missing ENV | The same sentences | Same | same |
| `run --agent claude` with no credential profile | "Managed VM agents require a selected credential profile" | "Selected agent has no qualified provider proxy in this environment; create it with --profile PROFILE … and check `cw agent info ENV`" | **Gap R5** |
| `run` at a terminal, nothing named | The agent picker ("Open an agent in a new or existing environment") | Same | same |
| `run --name S -- sh` at a terminal | Attaches, with the detach and reconnect hints | The same, plus an OSC 7501 session-state sequence | **Gap R6** |
| `init` | `--local` and `--cloud` refused ("does not apply to `cw init`"). Writes the same file signed in or not | Same | same |
| `preset` | `--local` and `--cloud` refused. Signed out, every subcommand fails: "No server configured (set --server, CODEWIRE_SERVER_URL, run 'cw setup', or run 'cw login')" | Presets live on the server: `list`, `create`, `info` work. `rm` takes only the ID; `rm SLUG` says "preset not found" though `info SLUG` finds it | **Gap R7** |
| `update --idle-stop` | "--idle-stop applies to cloud sandboxes; a local VM is never stopped for being idle" | Sets it, without a restart | intended: idle stop saves cloud compute; plain |
| `update --secrets`, `--clear-secrets` | `Update native environment "N" ("ID"), generation 1.`, Current and Replacement, a managed restart, then the whole `info`. With nothing selected, `--clear-secrets` fails: "Update native sources; conflicts require a fresh exact preview: native environment request is invalid" | `Update environment Some("N") ("ID") on platform "URL", organization "ORG_ID", operation 1.`, Current and Replacement, then the restart's progress, as `cw start` shows a start's, and "Environment source selection stored; the environment restarted with it." | **Gap R4**; the wait is the same in both now (b5078084f3); was R8: it returned at once, and the next `update` failed ("Source updates require a running or stopped environment; wait for the current operation to finish") until the restart ended |
| `update` with no change; a missing ENV | The same sentences | Same | same |
| `export ENV` | `✓ Exported local VM N to codewire.yaml`, then "! Not exported: the local workspace's host folder …" and "! Local only: secret and credential references are exact IDs as saved …" | `✓ Exported cloud environment N …`, then "! Not exported: environment values …" | intended: each names what its placement can't carry ("cloud environment" here, "cloud VM" in `create`: A1) |
| `export` over an existing file; a missing ENV | The same sentences | Same | same |

### The gaps

- **R1.** The service refuses the name of a live environment in the
  organization, with the local sentence, and the CLI's create checks it the
  same way for both. Same in both now (242addf606): the create checks the name
  under the organization row lock its quota check already takes, so no
  migration was needed.
- **R2.** A local VM takes environment values through the same
  `ProjectSpec.environment` the cloud create sends. Same in both now (868eae223d):
  the refusal dated from the first local preview (#1942), and a local VM
  already applied codewire.yaml's values.
- **R3.** One resource parser for both, run before the configuration is
  shown; a local VM takes what `--help` promises (2, 0.5, 500m) or the help
  says what it takes. Same in both now (e5aece4c8c): `environment::cpu`, with a
  fraction rounded up to whole vCPUs locally; a local resize and
  codewire.yaml's `resources.cpu` take it too.
- **R4.** One source preview, confirmation and result for both, in the user's
  words: no "native", no "platform", no raw organization ID and no Rust
  `Some(…)`. A clear with nothing selected says so.
- **R5.** One refusal for an agent with no profile, from the shared `run`
  path, naming `--profile` and `cw agent info`.
- **R6.** One attach client that reports session state the same way for both
  placements.
- **R7.** Presets have no local store, so a local user can't keep one. A local
  preset store behind the same commands, as secrets have; until then, signed
  out, say presets live in your Codewire account and name `cw login`. `rm`
  takes the slug, as `info` does.
- **R8.** A cloud `update` that restarts waits for the restart, as a local
  one and `cw start` do. Same in both now (b5078084f3): one `follow_platform_start`
  for both, within the daemon wait's bounds.

## Lifecycle (`start`, `stop`, `restart`, `rm`, `extend`, `protect`, `unprotect`, `cancel-delete`, `prune`, `nuke`)

The environment commands share one dispatcher (`commands/environment.rs`).
Commands with no local meaning are refused with "`cw NAME` is available only
for cloud environments", and `prune --local` goes to its own handler
(`local_images.rs`). Results print through `lifecycle_output.rs`. `prune` and
`nuke` were run only where they touch nothing but the audit's own objects:
`prune --local` in the isolated root, `prune --cloud` with `--dry-run`.

| Command | Local | Cloud | Same or gap |
| --- | --- | --- | --- |
| `stop ENV` | `✓ Environment N stopped`, `local VM · environment disk retained`, `→ cw --local start N` | `✓ Environment N stopped`, `cloud VM`, `→ cw --cloud start N` | same |
| `stop` a stopped environment | `Environment N is already stopped.`, exit 0 | Same | Same in both now (d3505ab915); was L1: the whole result again locally, "must be running to stop" and exit 1 in the cloud |
| `start ENV` | `✓ Environment N started · local VM` with its progress | The same shape; the progress includes "desired state -> started" | same (the server's words are a CLI-design item) |
| `start` a running environment; `start --output json` | `Environment N is already running.`, exit 0; JSON is the `info` record | The same line; JSON `{"status": "running"}`, as a finished start | Same in both now (d3505ab915); was L1: a second start locally, the plan then a refusal and exit 1 in the cloud |
| `restart ENV` | `✓ Environment N restarted · local VM`, about 13 s | "Restart is supported only for native local environments" | **Gap L2**, A1 |
| `extend ENV` | "`cw extend` is available only for cloud environments" | `Environment N: ttl_extended (1 hours added).` | intended: a local VM has no time to live. The cloud's result shows the state word `ttl_extended` |
| `protect`, `unprotect` | "`cw protect` is available only for cloud environments"; `rm --yes` removed the VM at once | `Environment N: protected.`, JSON `{"status": "protected"}`; `rm --yes` is then refused: "Environment N is protected, so nothing was removed; remove the protection first with `cw --cloud unprotect N`" | **Gap L3** |
| `cancel-delete` | Refused, as `extend` | "Cancel deletion: no pending deletion to cancel" | intended: only a cloud removal waits; a local one is finished when `rm` returns |
| `rm` without `--yes`: no terminal, `--output json`, at a terminal | "N was not removed: `cw rm` asks first, and there is no terminal to ask at; add `--yes` to remove it"; the JSON refusal; "Remove N (local VM) and everything on its disk? [y/N]" | Same, `cloud VM` | same (one confirmation, #4595) |
| `rm --yes` | `✓ Environment N removed`, `local VM · environment disk removed`, `→ cw ls` | `✓ Removal started: N`, `cloud VM · state: destroying`, `→ cw --cloud ls` | intended: a cloud removal finishes after the command. **Gap L4** for the wording |
| `rm` a missing environment | `Local environment "N" not found` | `Platform environment "N" not found` | A1 |
| `prune` | Frees the workspace images kept after the last VM: `Images kept for the next local VM: …`, `Would free 1.9 GiB (dry run).` | Deletes environments stuck in error, creating or pending: "No environments to prune." | **Gap L5** |
| `prune`, `nuke` without `--yes`, no terminal | `prune --local` refuses at once: "nothing was pruned: `cw prune` asks first, and there is no terminal to ask at; add `--yes` to prune", exit 1 | The same for `prune`, and for `nuke` ("nothing was nuked …") | Same in both now, and by the rule (bffcb26313); was L7: both read the answer from stdin and exited 0 at end of input |
| `nuke` | "`cw nuke` is available only for cloud environments" | Deletes every environment in the organization after a typed confirmation (run once, with none there: "No environments to nuke.") | **Gap L6** |

### The gaps

- **L1.** One rule in the shared lifecycle code: stopping a stopped
  environment, or starting a running one, says it already is, and exits 0.
  Same in both now (d3505ab915).
- **L2.** `cw restart ENV` restarts a cloud environment too, as a stop and a
  start through the same lifecycle path.
- **L3.** Deletion protection is an environment setting both stores keep, and
  the one `rm` path checks it.
- **L4.** One `rm` result: the same next step for both (`cw --PLACEMENT ls`),
  and no server state word.
- **L5.** `prune` removes stuck environments in both placements; a local VM in
  error is pruned too, and the kept images move to their own flag.
- **L6.** `nuke --local` removes every local VM, with the same typed
  confirmation.
- **L7.** `prune` and `nuke` without `--yes` and without a terminal fail at
  once and name `--yes`, as `rm` does. Same in both now (bffcb26313); it changes
  scripted use, so it ships with a release note.

## Inventory (`ls`, `info`, `use`, `current`)

`ls` and `use` print the same for both placements. `info` has one printer per
placement (`environment/info.rs`, `native/info_text.rs`).

| Command | Local | Cloud | Same or gap |
| --- | --- | --- | --- |
| `ls` | NAME, LOCATION, STATE, SESSIONS, NETWORK, then `→ Sessions: cw ls N` | Same | same |
| `ls`, nothing there | `No local environments yet.`, `→ cw --local run claude` | `No cloud environments yet.`, `→ cw --cloud run claude` | same |
| `ls --output json` | Each environment: id, name, placement, state, running, selected, session_count, sessions, daemon_health, error | The same fields | same |
| `ls --state`, `--type host` | Filtered; nothing matches: the empty line above | Same | same |
| `ls -a` | The same list | Adds destroyed environments | intended: a removed local VM leaves no record |
| `ls ENV` | NAME, STATE, MODE, PARENT, SESSION, COMMAND | Same | same |
| `ls ENV` while it isn't running | `Local environment N is stopped`, `→ cw --local start N`; exit 1 | `Cloud environment N is stopped`, `→ cw --cloud start N`; exit 1 | Same in both now (ef334abf33); was N2: "N is stopped; its sessions are listed while it runs (`cw start N`)" locally, "The environment isn't running" in the cloud |
| `info ENV`, text | Environment, Backend (`cloud-hypervisor`), State, CPU `2`, Memory `4Gi`, Disk `20Gi`, Workspace with the full plan hash, Working dir, Access, Install, Env vars, Agents, Docker, Network policy, Generation, Secrets as `local:id:ID`, Credentials | ID, Name, Type, State, DesiredState, PresetID, CPU `2000m`, Isolation, Memory `8192MB`, Disk `80GB`, CreatedBy (a user ID), CreatedAt and StartedAt in RFC 3339, IdleStop, Recoverable, TotalRunning | **Gap I1** |
| `info --output json` | backend, cpu, memory, disk, generation, workspace_plan, source_selection, network_policy, … | cpu_millicores, memory_mb, disk_gb, desired_state, org_id, preset_id, created_by, … | **Gap I1** |
| `info`, `ls ENV` of a missing environment | `Local environment "X" not found` | `Platform environment "X" not found` | A1 |
| `use ENV` | `✓ Current environment: N`, `local VM · running`, the size, Credentials, `→ cw --local shell N` | Same, `cloud VM` | same |
| `use` at a terminal | "Choose an environment": NAME, LOCATION, STATE, vCPU, RAM, DISK, CREDENTIALS; Esc: "Selection canceled; the current environment is unchanged" | Same | same |
| `use` without ENV, no terminal; a missing ENV | "An environment is required outside an interactive terminal …"; `No local VM is named "X" (cw --local ls lists them)` | The same; `No cloud environment is named "X" …` | same |
| `current` | `--local` and `--cloud` refused ("does not apply to `cw current`"). Nothing selected: `No environment selected.`, `→ cw use`; JSON `{"selected": false}` | Same | same (with a selection: not run) |

### The gaps

- **I1.** One `info` view for both: name, placement, state, size in the
  shared vocabulary (`2 vCPU · 4 GiB RAM · 20 GiB disk`), policy, secrets and
  credentials by name, local or relative times. IDs, hashes, the backend and
  generations only under `-v` or in JSON, and one JSON shape with placement as
  a field.
- **N2** (sessions, below) covers `ls ENV` on an environment that isn't
  running. Same in both now (ef334abf33).

## Sessions (`exec`, `shell`, `attach`, `logs`, `msg`, `inbox`, `send`, `wait`, `interrupt`, `steer`, `resize`)

The session commands print the same for both placements, apart from the rows
below. They were walked twice in each placement: once with live sessions, and
once after a restart had ended them.

| Command | Local | Cloud | Same or gap |
| --- | --- | --- | --- |
| `exec --in ENV -- CMD`: output, exit status, `-e`, `-w`, stdin, the selected environment, an option after the command | Same results and refusals | Same | same |
| `exec` a program that doesn't exist | "definitely-not-a-command: command not found", exit 127 | "cw: 1: exec: definitely-not-a-command: not found", exit 127 | Same in both now (c9b80bf7c8); was N1: "guest probe failed" and exit 1 locally |
| `exec -t -- tty` | A blank line, then `/dev/pts/0` | `/dev/pts/0` | **Gap N1** |
| `exec`, `logs`, `msg` in a stopped environment | `Local environment N is stopped`, `→ cw --local start N` | `Cloud environment N is stopped`, `→ cw --cloud start N`, `msg` too | Same in both now (ef334abf33); was N2: "Failed_precondition: local environment is not in the required state" locally, and "The environment isn't running" for a cloud `msg` |
| `shell ENV` at a terminal | A login shell; its exit status is cw's | The same, plus `via direct UDP` | same |
| `shell ENV`, no terminal | Prints a prompt and waits until it is killed; a login-shell session stays running | Same | same |
| `attach ENV --session S`; Ctrl-B d; a missing session; ENV with several sessions | `→ Attaching to ENV/S · local VM`; the same refusals ("N has 7 sessions; name one: …") | Same, plus the OSC 7501 state sequence (R6) | same |
| `logs --session`, `--tail`, `--follow` | The session's output | Same | same |
| `logs ENV --setup` | "Setup logs are kept for cloud environments; a local environment shows its setup as `cw start` or `cw create` runs" | The provisioning steps, including server words ("state transition pending -> creating") | **Gap N4** |
| `msg` to a terminal session | `Sent to terminal ENV/S.`; JSON delivery, environment, session, session_id, submitted | Same | same |
| `send` text, `--no-newline`, `--key` | `Input written to session-ID`; `--key` on a session without a terminal: "--key requires a PTY session; it is a terminal control byte" | Same | same (both show the session's ID, not its name) |
| `inbox` of a terminal session | "ENV/S is a terminal session; it has no structured inbox." and the logs and attach commands; JSON the same fields | Same | same |
| `wait --session` | The output, then "Session exited with code 3", exit 1; `--timeout 3s`: "Wait timed out; no completion confirmed: deadline has elapsed" | Same | same |
| A session ended by an environment restart (`update`, `resize`) | `Exited`, exit code 143: `wait` says "Session exited with code 143"; `msg` "ENV/S is exited; …" | `Stopped`: "Session reached terminal state Stopped without an exit code: stopped with the environment"; `msg` "ENV/S is stopped; …" | **Gap N3** |
| `interrupt` a terminal session | "Session is not a managed agent conversation" | "Original platform agent operation is unavailable" | **Gap N5** |
| `steer` a terminal session | "ENV/S is a terminal session, not a managed agent conversation; …" | Same | same |
| `stop --session`, `restart --session` | The session table | Same | same |
| `resize` without a size, without `--yes` | "Non-interactive resize requires at least one of --cpu, --memory, or --disk and --yes"; "… requires --yes after explicit resource validation" | Same | same |
| `resize --cpu N --yes` | With running sessions: "Active sessions would be terminated; non-interactive native resize requires --force". The result: `Environment: N (local · Cloud Hypervisor)`, Current and Desired, then the whole `info` | "This resize requires workspace Pod replacement (runtime class commodity fixes the workspace VM's vCPUs …); non-interactive use requires --allow-restart", and `--force` as well with sessions running. The result: `Environment: ID (platform)`, Current and Requested, Execution, Reason, warnings, `Resize completed: CPU 3, memory 8 Gi, disk 80 Gi.` | **Gap N6** |

### The gaps

- **N1.** `exec` behaves as `ssh HOST COMMAND` in both: a missing program
  exits 127 with the shell's message, and `-t` adds nothing to the output.
  The missing program is the same in both now (c9b80bf7c8); `-t` is open.
- **N2.** One refusal for a stopped environment in every session command and
  `ls ENV`: "N is stopped", `→ cw --PLACEMENT start N`. No
  `Failed_precondition` or "required state". Same in both now (ef334abf33):
  `refusal::state_error` words it for both placements, and a local VM's
  refusal is explained by its state as a cloud one is.
- **N3.** A session that an environment restart ends has one end state and
  one sentence in both.
- **N4.** A local VM keeps its create and start progress as its setup log,
  shown by the same renderer; the cloud's leaves out server state names.
- **N5.** `interrupt` refuses a terminal session with `steer`'s sentence, in
  both.
- **N6.** One resize plan and result for both, in the user's words. One flag
  says "end the sessions" (`--force`) and one says "restart the environment"
  (`--allow-restart`), with the same meaning in both placements.

## Ports and previews (`ports`, `share`, `access`, `vscode`, `cp`)

A local port is a binding on this computer's 127.0.0.1; a cloud port is a
preview URL. `ports` picks the store from ENV; each store prints its own
results.

| Command | Local | Cloud | Same or gap |
| --- | --- | --- | --- |
| `ports ENV`, none | "N publishes no host ports" | "No ports registered." | **Gap W1** (neither names `--publish`) |
| `ports --publish P` | `Published http://127.0.0.1:8080 -> N:8080`, a note that nothing listens there yet, then the list | `* Port 8080 registered as port-8080`, `URL: …`, `Access: creator` | intended: a host binding against a preview URL. The format is **W1** |
| `ports ENV`, with ports | `127.0.0.1:8080 -> 8080` | Tab-separated PORT, LABEL, ACCESS, PREVIEW URL | **Gap W1** |
| `--publish` a port already published | "host port 8080 is already published; withdraw it first" | "create port: port or label already registered for this environment" | **Gap W2** |
| `--host-port` in the cloud; `--label` or `--access` locally | "--label and --access apply to cloud preview ports; a local port is published on 127.0.0.1 only" | "--host-port applies to local environments; a cloud port is published as a preview URL" | intended; plain |
| `--unpublish` | `Withdrew 127.0.0.1:8080 -> N:8080`; not published: "N does not publish guest port 8080" | `* Port 8080 (port-8080) removed`; not published: "No preview publishes port 8080" | **W1** for the result; the refusals mean the same |
| `--publish` in a stopped environment | "N is not running; start it with `cw start N`, then publish the port" | "N is stopped; start it with `cw start N`, then publish the port" | same |
| `share list`, `grant`, `revoke` | "Environment sharing is available only with --cloud" | Works: a list of user IDs, permission and time; grant and revoke refuse in plain words | intended: a local VM has one user |
| `access ENV` | `Environment`, `Placement: local`, `Access profile: none`; JSON | "Environment credential-profile inspection is not yet available for platform environments" | **Gap W3** |
| `vscode ENV` | "→ Opening VS Code for N · /workspace", exit 0, with no VS Code installed | Same | same (both claim to open it) |
| `cp` to and from `/workspace` | `Uploaded FILE -> N:/workspace/FILE`; `Downloaded … (10 bytes)`; makes missing folders | The same, naming the environment by ID (A2) | same |
| `cp` a remote file that isn't there | "Download: not_found: local file was not found" | "Download: file not found" | **Gap W4** |
| `cp` to `/tmp` or `/proc` | "Upload: invalid_argument: local file path is invalid or denied" | "Upload: file path is invalid or denied" | same rule; wording **W4** |

### The gaps

- **W1.** One ports renderer for both: the same empty state with
  `→ cw ports N --publish PORT`, and one list and result shape that shows the
  binding or the URL.
- **W2.** One refusal for a port already published, naming `--unpublish`.
- **W3.** `access` reads a cloud environment's credential-profile binding,
  through the same inspection.
- **W4.** One `cp` error mapping: the remote path, said as remote, and no raw
  codes.

## Snapshots and checkpoints (`snapshot`, `checkpoint`)

`commands/snapshot.rs` sends a snapshot command to the local store, or to
`snapshot/platform.rs` for the cloud, and each prints its own results. VM checkpoints are local only.

| Command | Local | Cloud | Same or gap |
| --- | --- | --- | --- |
| `snapshot ls`, none | "No snapshots. Make one from a stopped local VM with `cw snapshot create ENV`." | "No snapshots. Create one with: cw --cloud snapshot create ENV" | same |
| `snapshot create ENV --name S` | `Snapshot S of N: mode=reflink consistency=clean disks=3 apparent=60.0 GiB in 0.26 s`, and a note on shared space | `Created snapshot S.`, and "It is kept on the storage node that holds this environment's disk and is not backed up …" | **Gap K1** |
| `snapshot create` a running environment | "N is running; stop it first (`cw stop N`), or snapshot it later with a VM checkpoint" | "Snapshot create: environment must be stopped to snapshot it" | **Gap K2** |
| `snapshot create` a name in use; a missing environment | "a snapshot named S already exists; choose another name or remove it first (`cw snapshot rm S`)"; "no local environment is named X; list them with `cw ls --local`" | "Snapshot create: you already have a snapshot with this name"; `Environment "X" not found` | **Gap K2** |
| `snapshot create` at a terminal, no ENV | A picker of stopped environments; none: "No eligible stopped environments; …" | The same picker | same |
| `snapshot ls` | NAME, SOURCE, CREATED (RFC 3339), DISKS, IMAGE, MODE | ID, STATE, SIZE, NAME | **Gap K1** |
| `snapshot inspect`, text and JSON | Source by name, created, consistency, resources, each disk, what it holds, direct mounts, removed sign-ins; JSON the same | ID, State, Source (an ID), Size; JSON id, name, source_environment_id, state, size_bytes, location | **Gap K1**, A2 |
| `snapshot inspect`, `rm` of a missing snapshot | "no local snapshot is named S; list them with `cw snapshot ls`" | "No snapshot named S" | **Gap K2** |
| `snapshot rm S` | `Removed snapshot S; …`; again: "no local snapshot is named S; list them with `cw snapshot ls`" | `Removing snapshot S; …`; again, while it is still being deleted: "no cloud snapshot is named S; list them with `cw --cloud snapshot ls`", exit 1 | Same in both now (2e2960920c); was K3: the cloud's second `rm` printed the same line and exited 0 |
| `create --snapshot S` | Refuses `--no-file` and `--no-profile`; a snapshot of a VM that mounted a folder needs `--share-mounts` | Takes both flags; the new environment gets the default size, not the source's | **Gap K4**; `--share-mounts` is intended: only a local VM mounts this computer's folders |
| `checkpoint create`, `ls`, `inspect`, `restore`, `rm` | Work on Linux and on a Mac (#4654). `restore` of a running VM without `--yes` refuses and names it | "VM checkpoints are local only for now; cloud environments cannot be checkpointed yet", exit 1, `ls` included | intended: a feature only local VMs have; plain. An empty `ls` should still exit 0 |

### The gaps

- **K1.** One snapshot renderer for results, lists and `inspect`, text and
  JSON: name, source by name, size, state, created in local time; the store's
  details under `-v` or in JSON.
- **K2.** One set of snapshot refusals, from the local sentences, which name
  the next command.
- **K3.** One rule for removing a snapshot that is already gone or going, as
  S3. Same in both now (2e2960920c).
- **K4.** `create --snapshot` takes the same flags in both and keeps the
  source's size in both.

## Setup and health (`setup`, `doctor`, `login`, `logout`, `whoami`)

Only `setup` takes a placement. `doctor`, `login`, `logout` and `whoami`
refuse both flags ("--local does not apply to `cw whoami`"), so they were run
without one: in the local isolation (not signed in) and on Dev with the API
key.

| Command | Local | Cloud | Same or gap |
| --- | --- | --- | --- |
| `setup` | `--local`: "Downloading the local VM runtime (6 files, 219 MiB)...", `Local VM runtime installed (ID).`; again: "Local VM runtime is installed and intact (ID)." | `--cloud`: a device sign-in. With no terminal it prints the link and the code and waits, and opens no browser; at a terminal it shows the link, the code, the copy key and the waiting line. With `CODEWIRE_API_KEY` set: "Using the API key in CODEWIRE_API_KEY, so there is nothing to sign in to.", no request, then the SSH section and "Setup complete." | intended: each sets up its own placement. The sign-in is fixed (643b739dbc); was H1: "Opening browser" with no terminal, and a sign-in with an API key set |
| `setup --local --skip-ssh` (or `--org`, `--create-org`) | "--org, --create-org, --org-slug and --skip-ssh apply to sign-in, not to `cw setup --local`" | Taken | intended; plain |
| `setup ssh --dry-run` | The same section, with `cw-local-*` and `cw-cloud-*` hosts | Same | same |
| `whoami`, signed out | "No server configured (set --server, CODEWIRE_SERVER_URL, run 'cw setup', or run 'cw login')", exit 1 | Signed in: User and Server; JSON the user record | **Gap H2** for the signed-out words |
| `doctor`, `--output json`, `doctor local` | One report: cw, platform, org, completion, ssh config, local VM egress, local credential store | Same | same |
| `login` | Refuses both flags | Same; the sign-in itself is the one `setup --cloud` starts | same |
| `logout` | "No sign-in was saved on this machine; removed the saved configuration." | The same, after "CODEWIRE_API_KEY is set: cw logout does not end API keys. …" | same |

### The gaps

- **H1.** `setup` signs in with the `login` screen in every mode: no "Opening
  browser" when none opens, and with `CODEWIRE_API_KEY` set it says that key
  is used and asks nothing. Fixed (643b739dbc), in `cw login`'s screen too.
- **H2.** One signed-out state everywhere: "Not signed in" with `→ cw login`,
  as `cw ls` already says. Today `whoami`, `cost` and `preset` say "No server
  configured (…)", and `secrets` says "Not signed in (run `cw login`, or set
  CODEWIRE_API_KEY)".

## Billing (`cost`)

| Command | Local | Cloud | Same or gap |
| --- | --- | --- | --- |
| `cost --local`, `cost --cloud` | "--local does not apply to `cw cost`" | Same | same: `cost` is the account's |
| `cost` | Signed out: the "No server configured" error, exit 1 (H2) | The organization's balance, this month's cost and usage; JSON the billing record | intended: local VMs aren't billed, and `cost` doesn't count them |
| `cost --org` an organization that doesn't exist | — | `Organization "X" not found`, `→ cw org list`, exit 1 | fixed (a5a66569a6); was B1: printed nothing, exit 0 |

### The gaps

- **B1.** `cost --org X` for an organization you aren't in says so and names
  `cw org list`. Fixed (a5a66569a6).

## Other command groups

Classified from `--help` and one read-only probe with each flag; not walked.

| Group | Commands | With `--local` / `--cloud` | Class |
| --- | --- | --- | --- |
| Organizations | `org` | Both refused ("does not apply to `cw org`") | platform only: an organization has no local store. Separately, a **CLI-versus-dashboard gap**: `cw org invite` sends an invitation, but no command lists or revokes an organization's pending invitations; `ListInvitations` and `RevokeInvitation` exist in `proto/codewire/v1/organization.proto`, and only the dashboard calls them. `cw org invitations` lists invitations sent to you |
| Account and organization administration | `api-keys`, `hosts`, `host`, `member` | Both refused | platform only: they administer the account, or let this computer serve the organization |
| This computer | `mesh`, `config`, `local-https`, `install` | `mesh`, `config` and `local-https` refuse both; `install` lists both in its help | local only: they configure this computer's `cw` |
| Trusted host access | `control` | Needs `--environment`; not probed further | local only (Linux): grants on this host |
| Environment runtime | `daemon`, `runtime`, `network` | Both accepted | both placements; not yet audited. `runtime info --local` with no local VM running prints a raw socket error ("Connect to existing native runtime publisher: filesystem operation failed for …/supervisor.sock …") |
| Cloud environment evidence | `agent`, `report` | `--local` refused: "Cw agent requires a cloud environment", "`cw report` is available only for cloud environments" | cloud only for now; not yet audited |
| Skills | `refresh-skills` | Help says local; `--cloud` also resolves a cloud environment | to audit |
