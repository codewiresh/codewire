# Secrets and credentials

How Codewire stores application secrets and provider credentials, how an
environment selects them, and how they reach a hosted Sandbox or a local VM.
This document describes shipped behaviour; where it and the code differ, the
code is right and this document is the bug.

## Product model

- **Application secrets** are named application values, such as `DATABASE_URL`.
  Selecting a source injects its values into managed processes under their
  original names. Those processes and environment root can read the values.
- **Provider credentials** are named Codex/OpenAI, GitHub, Anthropic (API key,
  Claude subscription token or Claude sign-in) and SSH identities. Private material remains
  outside the sandbox behind a credential proxy, signer or repository executor,
  except where a [direct delivery exception](#direct-delivery-exceptions) is
  listed.
- **Credential profiles** select named provider identities only. They contain
  no application-secret mappings, exposure rules or stored-service entries.
- Storing a value or identity does not attach it to an environment. No selected
  sources means no application secrets; no profile means no provider access.
- A local environment may select local or platform sources/profiles. A platform
  environment rejects local selections. Origin is independent of execution
  placement. Never copy provider material between stores or silently fall back.

Application secrets are not proxied: there is no `cw secrets run`, no
exposure flag and no per-key mapping. macOS stores local values and its local
VMs consume local sources and profiles; see
[macOS local storage](#macos-local-storage). Docker and Compose inside
environments are supported.

## Invariants

These rules bind every change to secrets, credentials and their delivery. They
were the "Repository invariants" of `AGENTS.md` until 2026-10-29; this section
is now their one home, and `AGENTS.md` points here.

- A managed agent in a local VM qualifies and routes credentials exactly as in
  a hosted Sandbox, from a platform profile or a local one, with the same
  in-VM setup for every slot. When a VM lacks a placement's setup, port and
  share the hosted code; never narrow what the VM accepts below the platform
  (owner, 2026-10-15, cited on #2880).
- Application secrets and provider credentials are separate product concepts.
  Storing either does not attach it to an environment. Selecting an application
  secret source authorizes ordinary child-visible environment projection under
  the original names; selecting a credential profile authorizes its typed
  proxy, signer, or executor, never raw provider material except the listed
  direct delivery exceptions. Never infer the category from a key name or
  value. Profiles contain provider identities only, not secret mappings or
  exposure policies. Reuse the owning environment operation identity; do not
  create a separate secret generation.
- Provider credential delivery keeps private material outside the sandbox. A
  sandbox may receive endpoints, public trust material, placeholders, and a
  bounded runtime capability, but not a provider credential or general
  secret-read API, except a listed direct delivery exception. Application
  secrets are intentionally visible to their receiving workload and root; do
  not promise secrecy from those processes. Keep resolved launch values out of
  durable configuration, control events and session metadata. Credential
  non-disclosure is not enforced egress mediation; claim the latter only where
  the placement proves direct provider bypass is denied.
- Direct delivery of provider material into a sandbox is allowed only where the
  proxy cannot work, with owner approval, listed with its reason under
  [Direct delivery exceptions](#direct-delivery-exceptions) and cited at the
  delivering code. The only exceptions are the environment creator's own
  personal sign-ins for Codex and Claude Code, in a hosted Sandbox and in the
  creator's own local VM: the Codex ChatGPT access token and ID token, written
  as Codex's `auth.json`, and the Claude access token, written as Claude
  Code's `~/.claude/.credentials.json` (`claudeAiOauth`), each with a
  non-empty placeholder refresh token, because each agent enables `/usage` and
  its plan and account features only with its own login. The Claude token
  carries exactly the six scopes Claude Code's own login has (`user:inference`,
  `user:profile`, `user:sessions:claude_code`, `user:mcp_servers`,
  `user:file_upload`, `user:plugins`) and never a scope beyond them; the owner
  accepted that on 2026-10-14 so Claude Code in a Sandbox behaves like their
  own login. Refresh tokens, API keys, Claude setup tokens, GitHub and SSH
  material and organization-owned credentials are never delivered. A delivered
  token is a bearer token for the creator's account, usable from anywhere, and
  stays valid at the provider until it expires (about 8 hours for Claude); every
  process in the Sandbox or VM, and anyone who can open its terminal, can read
  it, and a stopped local VM keeps it on its state disk until its next boot's
  check removes it or it expires.
- **Approved direction, not yet shipped** (owner, 2026-11-10 and 2026-11-15;
  Program #3997). Agents will reach the real provider hosts through a TLS
  front door outside the environment, holding only placeholders. The base-URL
  routes for agents (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, Codex's managed
  provider) are retired with it, and so are the direct delivery exceptions
  above; retiring the base-URL routes is required, not optional, because an
  agent's plan display, `/usage` and account features depend on the agent
  talking to its real host with its own login. Until #3999 (local VMs) and
  #4000 to #4002 (hosted Sandboxes) turn each behaviour on, the rules above
  describe what ships. The change that turns a behaviour on rewrites the rule
  it replaces in the same change; never describe the front door as on before
  that.
  - **The agent's own token refresh** (#3999 plan change 7). When the
    environment's Anthropic slot holds a Claude sign-in, the front door also
    terminates Claude's token host, `platform.claude.com`. On it, only
    `POST /v1/oauth/token` carrying Codewire's managed refresh token is
    answered by Codewire. Every other request there that carries no Codewire
    value follows the network policy and is forwarded untouched. A refresh
    carrying Codewire's managed refresh token
    (`codewire-managed-no-refresh-token-` and 32 hex characters) never
    reaches the provider. The broker answers it with the environment's
    placeholder access token (the same one every time), a new managed
    refresh token, a far-future expiry and exactly the stored sign-in's
    granted scopes. Before answering, it refreshes the stored sign-in itself,
    outside the environment, through its usual refresh journal, if that
    sign-in is near expiry. A refresh token that isn't Codewire's (the
    user's own `claude /login`) carries no Codewire value, so it follows
    the network policy, as every such request on an intercepted host does
    (#3999; `agent-own-key`): it's forwarded untouched where the policy
    allows the host, and refused otherwise (#5555). A request carrying
    a placeholder or managed value anywhere else is refused, never
    forwarded. A sign-in that can't be used is answered `invalid_grant`,
    and a passing failure `temporarily_unavailable`, so a short outage
    doesn't make the agent drop its login.
- A hosted platform broker bridge epoch may reuse one authority decision (its
  runtime session and derived grants, never material) for at most 60 seconds,
  and releases nothing under an older one. Only epoch admission creates it, and
  a lease evaluates it again inline, one evaluation at a time. Every lease of a
  granted slot rereads its credential's record by id and owner, and evaluates
  again at once when that record is missing, inactive or of another revocation
  generation than its grant. A refused slot is answered from the decision unless
  its withheld credential is usable again or the GitHub connection it follows
  changed. So a credential change applies to the next request, and a membership,
  organization, environment, binding, personal-credential confirmation or Pod
  lineage change within 60 seconds. Decrypted provider material may be reused
  only within one bridge epoch (hosted or owner-local delegation), for at most
  two minutes, for exactly the record that lease admitted. Codex and Claude
  login delivery, owner-local delegation leases, SSH signing, OAuth refresh
  admission and keep-alive, and environment projection keep full per-call
  authority checks. SSH signing, OAuth keep-alive refresh and direct delivery
  never reuse material; an on-demand OAuth refresh uses the request's own
  lease, whose exact generation refresh admission rechecks. Do not add a
  process-wide or persistent material or decision cache
  (`scripts/checks/repo_policy/material_cache.py` guards it).

## CLI

Secret and credential management choose exactly one store, `--local` or
`--cloud`. If omitted, prompt on an interactive terminal before accepting
sensitive input. Noninteractive and JSON invocations require a flag. Both flags
are an error. Never save this choice as a default.

Long options accept both `--flag=value` and `--flag value`. Environment
selection uses `--secrets` and `--profile`; secret management uses `--project`
to identify the collection being edited. Help, examples and dashboard labels
keep this distinction. The retired `--secrets-project` spelling is refused;
it is not an alias.

### Application secrets

```sh
cw secrets --cloud projects create development
cw secrets --cloud --project=development set DATABASE_URL
cw secrets --cloud --project=development list
cw secrets --cloud --project=development delete DATABASE_URL
cw secrets --local --user set APP_TOKEN
cw secrets --cloud --organization set SENTRY_DSN
```

A project is one named collection, not a repository or an additional stage.
Project key operations require `--project`. Personal and organization key
operations explicitly select `--user` or `--organization`; local organization
storage is unsupported. No saved project default, YAML-derived write target or
retargeting through `cw use` is permitted. Validate placement/scope/authority
before reading a value. Values use a protected prompt or stdin, never argv.

Keep key set/list/delete/rename separate from `projects create/list/delete`.
Missing, empty or whitespace-only keys cannot mean project deletion. Collection
deletion displays the resolved target and impact, defaults to no, rejects EOF
as consent and requires affirmative confirmation or explicit `--yes`.

A tailnet auth key for the user's own tailnet (SPEC.md, "A user's own
tailnet") is an application secret like any other, not provider material.
Every process in the sandbox can read it, so it must be one-use, ephemeral,
tagged and short-lived. Store it shortly before the sandbox starts, and
delete it after the join. Deleting it doesn't remove it from a running
sandbox's environment; being one-use is what makes the copy left there
worthless. Codewire has no credential kind for it and doesn't broker it.
After the join, the node is open to every process through the loopback proxy,
so the sandbox tag's ACL is the trust boundary.

### Provider credentials and profiles

Before connecting Codex, turn on **Enable device code authorization for Codex**
in [ChatGPT Security settings](https://chatgpt.com/#settings/Security).
For a managed workspace, an administrator may need to allow device code login.
This applies to local and platform enrollment; see the
[official authentication guide](https://learn.chatgpt.com/docs/auth#preferred-device-code-authentication-beta).

```sh
cw credentials --cloud connect codex --name work-codex
cw credentials --cloud connect github --name work-github
cw credentials --cloud generate ssh --name work-ssh
cw credentials --cloud add ssh --name imported-ssh --key-file ./id_ed25519
cw credentials --cloud add openai --name work-openai
cw credentials --cloud add anthropic --name work-anthropic
cw credentials --cloud connect claude-token --name work-claude
cw credentials --cloud connect claude --name claude-login
cw credentials --cloud rename work-openai personal-openai
cw credentials --cloud rotate personal-openai

cw credentials --cloud --profile=work set codex work-codex
cw credentials --cloud --profile=work set ssh work-ssh
```

There is no `github` slot: the account's GitHub connection is part of every
profile, and `set github` is refused.

At a terminal, `connect` and `add` with no provider, and `set` with no slot,
ask with a guided picker. Each picker offers exactly what its command takes,
in that placement, and nothing it refuses; both placements take the same set,
so their pickers are the same rows in the same order. A test holds each
picker's rows to its command's accepted set in each placement, so a provider
or kind can't be added to a command without its row (#5446):

- `connect` asks "What do you want to connect?": Codex, GitHub, Claude
  (sign-in) and Claude (token), as the approved credentials screens show
  them (owner, 2026-11-15, #4717). API keys are not `connect` rows.
- `add` asks "Which provider?": OpenAI API key, Anthropic API key and SSH
  private key. `add claude-subscription`, the one-release alias of
  `connect claude-token`, is not a row.
- `set` asks "Which provider should this profile use?": codex, openai,
  anthropic and ssh, every slot but GitHub's.

```sh
```

The first profile `set` creates the profile if absent. Enrollment does not
silently select an identity. Profiles retain immutable revisions and current
user/organization authorization. Editing a profile does not advance existing
environment bindings. Codewire revocation stops Codewire use at once. Where
the provider offers a revocation Codewire can ask for, revoking also asks it,
and `cw` reports the answer ([Revoking at the provider](#revoking-at-the-provider));
it is never a promise of provider-side logout.

For CLI OAuth reconnect, repeat `connect codex|github|claude --name NAME`. The GitHub
CLI command uses the Codewire GitHub App's device flow for a terminal or
headless client; the dashboard uses the same App's browser authorization. Both
end in the same user and installation checks. If the name already
exists, resolve and display that exact identity and require explicit
replacement confirmation before login. Cancellation or failed login preserves
the prior credential. When a completed login is not published, Codewire drops
its tokens from memory; nothing revokes them, so the issued refresh token stays
valid at the provider until it expires. Replacement must be fenced against concurrent changes;
it must not silently create another identity or retarget a profile. API-key
providers have one authentication kind, so `add` needs no `--kind` flag.

`rename NAME NEW_NAME` changes only the label, keeping the identity, material
and profile links. `rotate NAME` accepts a replacement API key through protected
input. Explicit rotation sets status Active, even if the old key was revoked;
omitting `--expires-at` clears the hard expiry. The CLI explains that before
asking for the key. A stale identity revision or renamed record cannot be
silently overwritten. OAuth reconnect and automatic refresh remain separate
operations; automatic refresh never reactivates a revoked identity.

#### Credential names (in progress, #4928)

People label credentials by account, often their email address, and use the
same label for each provider they sign in with. A credential's name is unique
per owner and **provider**, case-insensitively, in both stores (design agreed
on #4928, 2026-11-17, with cw-security's conditions):

- The provider is the stored provider id: `anthropic` (Claude sign-in, Claude
  setup token and Anthropic API key), `openai` (Codex and OpenAI API key),
  `github` and `ssh`. A Claude sign-in and a Codex sign-in can both be
  `n@example.com`; a Claude sign-in and a Claude token can't share a name.
- The owner is the signed-in user, or for a cloud credential an organization
  holds, that organization. Local and cloud credentials are separate stores,
  so the same name in each is never ambiguous: `--local` and `--cloud` pick
  the store.
- When a name is already taken in the same provider and the command is not a
  reconnect of that credential (`connect … --name` repeated, above), the
  refusal, before any sign-in or prompt for a key, names the credential that
  holds it by its kind (the glossary's kind words) and suggests the first free
  `NAME-2`, `NAME-3`, … in that provider: `"walk" is in use in anthropic by
  a Claude (sign-in) credential; choose another name, for example walk-2`.
  `connect`, `add`, `generate` and `rename` check it the same way in both
  placements.
- The holder is named only to a caller who may read it (cw-security's
  addition on #4928, 2026-11-19). When the store or the service refuses a name as taken and the
  command could read no credential holding it, such as an organization's
  credential the caller may not read, it says only the provider: `That name
  is in use in anthropic; choose another name` (for a sign-in, `That name is
  in use in openai, so your Codex sign-in wasn't saved`). The cloud
  credential commands are personal today, so the CLI names a holder only
  when its own lookup by name and provider found it.
- A new or renamed credential's name may not start with a provider id
  followed by `/` (`anthropic/`, `openai/`, `github/`, `ssh/`), in either
  store: `A credential's name can't start with github/, which reads as a
  provider; choose another name`. The CLI checks it before any sign-in or
  prompt; the stores refuse it too, with reason
  `CREDENTIAL_NAME_RESERVES_PROVIDER`, which the CLI words the same way. A
  credential an older Codewire saved with such a name keeps it and keeps
  working, and a rename that keeps its name is no new name.

Every command that takes a credential name (`get`, `rename`, `rotate`,
`revoke`, `delete`, and `connect --name` when it reconnects) also accepts
`PROVIDER/NAME`:

- A prefix is read as a provider only when it is one of the four ids,
  exactly as stored (lowercase); any other name containing `/` is a whole
  name. `name:NAME` is always the literal name, never `PROVIDER/NAME`.
- `connect PROVIDER --name NAME` looks only in that provider, so another
  provider's credential of that name is neither reconnected nor a collision;
  `connect codex --name openai/walk` reconnects OpenAI's `walk`.
- A bare name that matches one credential acts on it. A bare name that matches
  more than one is refused before anything changes, with the choice, in both
  placements: `"n@example.com" names more than one credential (anthropic,
  openai); name one, for example anthropic/n@example.com`. The cloud's
  refusal is `FAILED_PRECONDITION` with ErrorInfo reason
  `CREDENTIAL_NAME_AMBIGUOUS` and the providers, comma-joined, in its
  `providers` metadata; the local store's carries the same reason and
  `codewire-store-refusal-providers`. The CLI resolves a local name from the
  store's listing and a cloud name with `GetCredentialRequest.provider`, and
  words both the same.
- A name with two readings, such as a literal `github/work` an older Codewire
  saved beside a GitHub credential named `work`, acts only when exactly one
  credential matches either reading; otherwise it is refused naming both:
  `"github/work" names more than one credential (github "work", ssh
  "github/work"); name one, for example ssh/github/work`. The CLI looks up
  both readings in both placements.
- `--profile P set SLOT NAME` needs no prefix: the slot fixes the provider
  (`codex` and `openai` take OpenAI's, `anthropic` Anthropic's, `ssh` the SSH
  keys). A name only another provider has is still found, so the slot refuses
  it in its own words.
- A command that suggests running itself again, such as a `delete` whose
  revoke succeeded, names the credential as `PROVIDER/NAME`.
- `list`, `get` and the dashboard show the provider beside each name.

Names are resolved only at the CLI and the API edge. Profile entries, grants,
the broker's leases, refresh journals and revocations refer to a credential by
its ID in both stores (local `profile_entries.credential_id`, cloud
`platform_access_profile_entries.credential_id` and
`credential_revocations.credential_id`), and nothing stores a name to resolve
later, so renaming a credential never moves a binding.

In the cloud, the ambiguity refusal comes after authorization. A caller who may
not read an organization's credentials gets the same answer as for a name that
doesn't exist, never the list of providers; the list names only providers of
credentials the caller may already read. `GetCredentialRequest` carries an
optional `provider` beside the name. A name that matches more than one
credential without it answers `FAILED_PRECONDITION`, whose ErrorInfo reason
lists the matching providers and no IDs, so an older `cw` that sends a bare
ambiguous name is refused rather than given a guess. Enrolment's "name in use"
check is scoped to the provider, as is the dashboard add form's.

The cloud migration is forward-only. It creates unique indexes on
`(user_id, provider, lower(display_name))` and
`(organization_id, provider, lower(display_name))` before it drops
`platform_credentials_user_display_name_key` and
`platform_credentials_organization_display_name_key`, so uniqueness never
lapses, and every existing row stays valid. Rolling back recreates the old
indexes, which fails once two providers share a name: rename one of them
first.

The migration applies only over servers that already look a name up by
provider (#5524, in v0.4.25 and later). Before #5524 the server's
`GetCredential` by name returned whichever matching row it read first. Once
two providers share a name, that would let a command that finds a
credential by name, such as a delete, act on the other provider's
credential. Since #5524 the same request with a bare shared name is
refused with `CREDENTIAL_NAME_AMBIGUOUS`. So the release that carries the
migration follows v0.4.25 or later, in Dev and Production alike, and no
replica that resolves a bare name to an arbitrary row serves while the
migration is applied. A `cw` from before #5524 sends a bare name and gets
that refusal, never a guess.

A local store moves to schema 7, whose `credentials` table is unique on
`(provider, display_name COLLATE NOCASE)` instead of `display_name`. The
upgrade copies every row unchanged; every schema 6 store is already unique.
The authority's name lookups take the provider, as the cloud's do. A new
authority protocol and `AuthorityFeature::NamesPerProvider` mark the change; a
`cw` that needs it replaces an older authority only while no local VM runs, as
#4798's path does. It needs it only for a `connect`, `add`, `generate` or
`rename` whose name another provider's credential already has: names are
resolved in the CLI from the listing, and an older store can hold no name two
providers share, so every other command keeps working with an older
authority that still serves a running VM.

Renaming a platform profile (`AccessProfileService.RenameAccessProfile`, or
**Rename** in a profile's menu in Settings → Credentials) changes only its
label. It uses Create profile's name rules, publishes no revision and keeps the
entries and every Sandbox binding, which pin an ID and revision. The request
names the revision and name it observed, as a credential rename does. A stale
revision or name, including one left by another rename from the same view, or
a name another of the owner's profiles uses is rejected; renaming to the
current name changes nothing. A project spec that selects a profile by name
resolves that name at its next admission, so update it after a rename.

Each user with a platform profile has exactly one default profile (#3550), a
mark on the profile row (`platform_access_profile_defaults`), not part of a
revision. The first profile becomes it; `SetDefaultAccessProfile` (or
`cw credentials --cloud profiles default NAME`) moves it to another of the
user's own profiles, and there is no clear. Deleting the default is refused
(`FAILED_PRECONDITION`, and the database's foreign key), so a user's only
profile stays until another one is made the default. The default is a standing
selection the user's clients apply, never the API: a cloud `cw create` that
names no profile (no `--profile`, no `credentials.profile` in `codewire.yaml`)
sends the default as its explicit selection with personal-credential
confirmation, and `--no-profile` sends none; the dashboard create form
preselects it. `CreateEnvironment` without a selection still means no
provider access. Lists show the default first.

A local store keeps one default the same way (#4717): `default_profiles` in
its SQLite (schema 6), served from authority protocol 18 by
`SetDefaultAccessProfile` and `is_default` on every profile read, and moved
with `cw credentials --local profiles default NAME`. The store's first
profile becomes it, deleting it is refused, and a local `cw create` that names
no profile selects it with the same line as the cloud. A store made before
schema 6 starts with none, and a profile added to it later does not become
the default on its own: an upgrade never widens what an unchanged
`cw create --local` hands a VM (#4717). Such a
create selects no profile and says how to set a default.

No ambient Codex, GitHub, Claude, SSH or keyring import is allowed. Explicit SSH
file import is owner-selected; passphrases and API keys use protected input.
Local connect runs the same native device logins as the platform, from the
`cw` process: OpenAI's Codex device flow as the Codex client, and the Codewire
GitHub App's device flow with only its public client ID, which `cw` carries
built in. No provider CLI runs and no login file is written; the tokens go
straight to the local protected store. Existing saved logins are never
imported. An expiring App login is refreshed by the environment's local broker
with the client ID alone, serialized through the local refresh journal like
Codex; the broker rereads the record for every request.

A local store opens after a crash, a power loss or a stopped authority at any
point of a refresh, for a Codex sign-in, a GitHub App login and a Claude
sign-in alike (#5177). A refresh that was reserved but never started is
dropped, and the credential stays as it was. One that started without a stored
result is failed, because the provider may already have rotated the refresh
token: the credential reads **Reconnect needed**, and the old refresh token is
never sent again. One whose result was stored is published, as its commit
would have done. A published refresh whose old material was not yet removed
removes it. A rate-limited refresh the store stopped before cancelling counts
as started without a stored result.

A running broker whose refresh got the provider's answer but could not store
it, after its retries, records the attempt as failed (#5537). The credential
reads **Reconnect needed**, only the request that needed it is refused, and
the broker's bridge epoch goes on serving every other credential. The epoch
ends only when the authority can't record that failure: it is unavailable,
or a result was stored after all, which recovery publishes.

OAuth logins are personal. An organization may hold API keys and SSH keys,
but never an OAuth credential: no Codex (ChatGPT) login, GitHub OAuth
connection or GitHub App user connection. GitHub is each account's one
connection and Codex is connected by each person; enrollment always makes the
signed-in account the owner. The platform credential store refuses to
register or reconnect an organization OAuth credential, and no profile,
personal or organizational, may select one. Profile edits, bindings and
runtime admission refuse such a selection as a whole; it is never marked
Reconnect. A row written before this rule can still be revoked and deleted.
Only the Sandbox creator's personal Codex login may ever be delivered directly
to a Sandbox.

### Claude subscription token

A Claude subscription token lets Claude Code in a Sandbox or a local VM use
its owner's Claude Pro, Max, Team or Enterprise plan instead of an Anthropic
API key. It is the Anthropic provider's OAuth authentication kind. A profile's
one Anthropic slot holds an API key, a subscription token or a Claude sign-in.

Both subscription forms are connected with `connect` (owner, 2026-11-15,
#4945): `connect claude` signs in with the browser, and `connect claude-token`
takes the token `claude setup-token` prints. Help, the guided picker and the
dashboard call them **Claude (sign-in)** and **Claude (token)**, both the
user's Claude subscription, and lists show the same names. The sign-in shows
the plan and usage; the token lasts a year, suits automation and makes model
requests only. A token is replaced by connecting it again under its name,
which asks first, as every `connect` does; `rotate` is for API keys only and
says so. `add claude-subscription` is a hidden alias of `connect claude-token`
for one release: it prints one `→` line with the exact new command, then does
the same. `add` is for API keys and SSH keys.

Enrollment is by paste; Codewire never runs Claude Code's OAuth client. Run
`claude setup-token` on your own machine or in any Sandbox terminal. It opens
the browser authorization and prints a one-year token without saving it
([Claude Code authentication](https://code.claude.com/docs/en/authentication)).
Then add the printed token at once. Paste a freshly generated token: one
printed earlier stops working before the one-year expiry Codewire records.

```sh
claude setup-token
cw credentials --cloud connect claude-token --name work-claude
cw credentials --cloud --profile=work set anthropic work-claude
```

The dashboard equivalent is **Settings → Credentials → Add credential →
Claude (token)**. The CLI reads the token from a no-echo prompt or stdin,
never argv; with no terminal, a token piped to stdin is used and nothing is
asked. Codewire checks only its shape (16 to 1024 printable
characters, no whitespace) and makes no provider call when it is added. The
token is opaque, so Codewire records a hard expiry one year after it is added;
the dashboard shows **Expires soon** in its last 30 days and **Expired** after
it. `--local` stores the same token, with the same checks and expiry, in the
local credential store, and a local VM's Claude Code uses it in the same token
form as a Sandbox: `CLAUDE_CODE_OAUTH_TOKEN` holds Codewire's placeholder and
the host's broker adds the token to each request, so it never enters the VM. Deleting
a token removes Codewire's copy only: it keeps working at Anthropic until it
expires or is revoked in the owner's Claude account, and `delete` says so.

The token stays in Codewire and is never delivered to a Sandbox. It needs no
[direct delivery exception](#direct-delivery-exceptions): it "can only make
model requests", and the credential proxy serves all of those. As with an
Anthropic API key, anyone who can run processes in the Sandbox, including
others with terminal access, can use the owner's plan through the proxy; they
never see the token. A hosted Sandbox whose bound profile revision selects a
subscription token receives only:

| Name | Value |
|---|---|
| `ANTHROPIC_BASE_URL` | `http://127.0.0.1:38081/_codewire/anthropic`, the managed route |
| `CLAUDE_CODE_OAUTH_TOKEN` | `codewire-managed`, a placeholder |

An API key projects only `ANTHROPIC_BASE_URL` and
`ANTHROPIC_AUTH_TOKEN=codewire-managed`, and a [Claude sign-in](#claude-sign-in)
`ANTHROPIC_BASE_URL` alone. In every form the other Anthropic names
(`ANTHROPIC_API_KEY`, and the other forms' variables) are absent, not empty:
they stay reserved while the Anthropic client is selected, so a declared value
is refused and an image's value is removed on every placement.
An empty value would read as set to a Claude Code that treats empty as set.
The form follows the pinned revision's credential, whose
kind never changes; it is recorded in the managed-client selection
(`CODEWIRE_MANAGED_CREDENTIAL_CLIENTS`, for example `v2:24`, or `v2:44` for a
sign-in).

In every form, the hosted daemon marks Claude Code's onboarding complete in
`~/.claude.json` (`hasCompletedOnboarding`, `hasAcknowledgedCostThreshold`), so
the managed credential is used without the first-run login picker. Whatever
clients are selected, it also marks trusted
(`projects[FOLDER].hasTrustDialogAccepted`) the workspace root and every Git
repository under it, each by its own root, because Claude Code stops looking
upward at a repository's root. So `claude` starts in any checkout without asking
whether you trust the folder, and loads the repository's own project settings,
such as hooks, without that question. Other folders, such as the home
directory, still ask. A local VM's guest daemon does the same for the workload
user.

Target, not shipped (#5813): `claude` in a Sandbox, a cloud Sandbox or a local
VM, starts with no screen at all, in bypass permissions mode. Whatever clients are selected, the same pass also
sets in `~/.claude/settings.json`:
- `permissions.defaultMode: "bypassPermissions"`, so plain `claude` runs every
  tool without asking, as `--dangerously-skip-permissions` does;
- `skipDangerousModePermissionPrompt: true`, so neither that default nor the
  flag stops at the "Bypass Permissions mode … No, exit" screen;
- `enableAllProjectMcpServers: true`, so a repository's own `.mcp.json` servers
  start without the "New MCP server found in this project" question. The
  reasoning is the same as for trust: the workspace holds the user's own
  checkouts. "Own" means the user cloned it, not that they wrote it: a cloned
  repository's `.mcp.json` runs its servers' commands as soon as `claude`
  starts there.

Each key is set only where it is missing, and a value the user set is never
changed. That includes their own `permissions.defaultMode` and an
administrator's `permissions.disableBypassPermissionsMode`, which still turns
bypass off. These keys are written only on a Sandbox placement, never by `cw`
on a trusted host; a test pins that. The file rules are those of
`~/.claude.json` above: mode 0600, no
symlink followed, and no token, credential or placeholder ever written.
Checked against Claude Code 2.1.308 and 2.1.330 in a Dev Sandbox with a
throwaway home: with these keys, `claude` and `claude
--dangerously-skip-permissions` in a repository start and answer with no
screen. Without `skipDangerousModePermissionPrompt`, both stop at the bypass
screen. Not yet observed through the daemon
([claude-in-a-sandbox.md](../journeys/claude-in-a-sandbox.md)).

Limitation: a native local VM that uses a platform profile still receives the
API-key projection, because its platform source authority carries slot names
only. It is safe (the Sandbox holds only the placeholder and the platform
broker injects the token), but Claude Code runs there in API-key mode, without
its subscription features.

Claude Code then runs in its subscription mode and sends the placeholder as
`Authorization: Bearer codewire-managed`. The broker drops that placeholder,
injects the stored token as the bearer and makes sure `anthropic-beta` carries
`oauth-2025-04-20`, which the provider requires with an OAuth bearer.
Everything else is the [transparent provider route](#transparent-provider-routes)
both forms share: Claude Code's own headers, paths and bodies reach the
provider unchanged, so server-side auto mode and plan rate limits work as they
do without Codewire. The token is in the redaction set.

A setup token is inference-only. Managed and interactive turns work. Claude
Code reads no plan from it, so its header shows "Claude API" in place of the
plan name. `/usage` is not available: Claude Code reads usage straight from
`api.anthropic.com` with its own token, not through `ANTHROPIC_BASE_URL`, so
in a Sandbox it sends only the placeholder. The usage endpoint also requires
the `user:profile` scope, which a setup token lacks; through the route the
provider answers 403 "OAuth token does not meet scope requirement
user:profile".

Claude Code's credential precedence is: a cloud provider, then
`ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY`, `apiKeyHelper`,
`CLAUDE_CODE_OAUTH_TOKEN`, Anthropic profiles, and last `/login`. A selected
subscription token therefore outranks your own `/login` inside the Sandbox:
while it is selected, Claude Code uses it, not a login saved in the Sandbox.
Setting `ANTHROPIC_AUTH_TOKEN` or `ANTHROPIC_API_KEY` yourself overrides it in
that shell.

There is no refresh and no keep-alive, and no provider answer changes the
stored token. When the recorded expiry passes, the broker withholds the
Anthropic capability, `cw credentials list` shows it expired and the dashboard
shows **Expired**. When the provider refuses the token earlier (it expired
early or was revoked at claude.ai), its 401 reaches Claude Code unchanged, as
it does for an API key; the token stays Active, since a process in the
Sandbox shapes the request and must not be able to disable it. In either
case, run `claude setup-token` again and replace the token with
`cw credentials --cloud connect claude-token --name work-claude` or **Replace
token** in the dashboard. Replacement keeps the identity and profile bindings, sets it Active
and restarts the one-year expiry. Like rotating an API key, it applies to the
next request, also in a running Sandbox: every lease rereads the token's
record, and a request already reading the replaced token never releases it
(see [Runtime boundaries](#runtime-boundaries)). Like every OAuth login, a
subscription token is personal: an organization cannot hold one, and no
profile can select one that an organization holds.

### Claude sign-in

A Claude sign-in is Claude Code's own claude.ai login, run by Codewire as
Claude Code's public OAuth client. Unlike a subscription token it carries the
`user:profile` scope and a refresh token, and Codewire reads the account's
plan (Max, Pro, Team or Enterprise) and rate-limit tier from Claude's OAuth
profile. It is its own credential kind for the Anthropic slot,
`claude_sign_in` in `cw credentials --output json`
(`CREDENTIAL_AUTHENTICATION_KIND_CLAUDE_SIGN_IN` in the API); a profile's one
Anthropic slot holds an API key, a subscription token or a sign-in. Sign-ins are platform
credentials only; `--local` refuses them.

```sh
cw credentials --cloud connect claude --name claude-login
cw credentials --cloud --profile=work set anthropic claude-login
```

`connect claude` asks the credential service to start a sign-in, shows a
login screen laid out like Claude Code's own with the link to Claude's
authorize page (`https://claude.com/cai/oauth/authorize`) alone on its line
(at a terminal also copied to the clipboard with OSC 52 and opened in the
browser, fully detached so the browser's own messages never reach the prompt)
and reads the code Claude shows after you sign in from a no-echo prompt
("Paste the code Claude shows after you sign in >") or stdin, never argv. Codex and GitHub
connects show the same screen with their device code. Once connected, the
screen names the account that signed in (the credential's account hint). Sign in with the account whose
plan you want to use. The prompt accepts Claude's `code#state` with
surrounding whitespace and a line ending, or the full callback URL of Claude's
code page (`…/oauth/code/callback?code=…&state=…`), and sends `code#state`.
Nothing shows while you paste; once read, the CLI confirms only the length
("Got it (87 characters).").
At a terminal, a value of any other shape is refused before Claude is
contacted, with one chance to paste again. The service checks that the pasted state is this
sign-in's, exchanges the code at `platform.claude.com/v1/oauth/token` with the
sign-in's PKCE verifier, reads `api.anthropic.com/api/oauth/profile` once with
the new access token, and stores the login. It asks for Claude Code's claude.ai
scopes (`user:profile user:inference user:sessions:claude_code
user:mcp_servers user:file_upload user:plugins`), never `org:create_api_key`,
and keeps both `user:inference` and `user:profile` or refuses the login. A
login granted `org:create_api_key`, which can mint lasting API keys, is
refused before it is stored, at sign-in and on every refresh; delivery still
admits only the six sign-in scopes. A
sign-in must be completed within 15 minutes of its start; a pasted code from
another sign-in, or a malformed one, is refused before Claude is contacted.

Start creates the PKCE verifier and state and returns them in an opaque handle
with the authorize URL; nothing is stored. The handle is sealed with the
credential store's KEK (a fresh data key and AES-256-GCM, as for stored
material), with associated data naming its purpose, the person who started the
sign-in and its issue time. Complete therefore refuses another person's
handle, an altered one and one issued 15 minutes ago or more before Claude is
contacted. The client that started the sign-in keeps the handle private and
returns it with the pasted code, so either of the credential service's
replicas can complete it. The verifier redeems nothing without the code Claude
issues to the person who signed in. A failed or
cancelled completion stores nothing and drops the tokens from memory; nothing
revokes them, so an issued refresh token stays valid at Claude until it
expires. The stored record has no hard expiry; its account hint is the
profile's email. Repeating `connect claude` with an existing sign-in's name
reconnects that identity after confirmation, keeping its profile bindings and
reading the plan again.

The access token lives about 8 hours. The broker refreshes it at Claude's token
endpoint when a request finds it within five minutes of expiry, through the
same durable refresh journal as Codex: the refresh asks for exactly the
granted scopes, keeps the previous refresh token when Claude returns none,
and refuses a rotation that drops `user:inference` or `user:profile` or adds
`org:create_api_key`. When Claude answers a request with 401, the broker
refreshes the sign-in once more, the same way, and sends the request once
again; a second 401 is returned as it is. A 401 forces such a refresh only of
a sign-in last refreshed ten minutes ago or more, by the time stored with the
sign-in, because a process in the Sandbox shapes the request and can provoke
one. The 401 of a sign-in refreshed more recently is returned as it is, and
so is Claude's 401 when the forced refresh fails. A retry Codewire refuses
to lease again, or whose refresh the authority refuses to begin, is Codewire's
denial of the request, since Claude never saw that refresh (#4974). A refused
or uncertain refresh is terminal and the credential reads **Reconnect needed**;
the old refresh token is never sent again. A refresh Claude rate-limited is
neither
([A refresh the provider rate-limited](#a-refresh-the-provider-rate-limited)).
Idle sign-ins are kept alive (see
[Idle OAuth keep-alive](#idle-oauth-keep-alive)). The plan is read only at
sign-in and reconnect. Revocation in Codewire applies to the next request.

In a hosted Sandbox a sign-in has its own form. The Sandbox receives
`ANTHROPIC_BASE_URL` only, and the workspace daemon writes the creator's
access token as Claude Code's own login, `claudeAiOauth` in
`~/.claude/.credentials.json`, with a placeholder refresh token: a
[direct delivery exception](#direct-delivery-exceptions). Claude Code then
shows the plan and `/usage`, whose account calls go straight to
`api.anthropic.com`. Its turns still go through the managed route, where the
broker drops the guest's bearer and injects the stored token, the same one or
a fresher one, with the OAuth beta. The refresh token never enters the
Sandbox. The selection digest is the same in every Anthropic form, so a
running Sandbox switches form at its next restart.

For a Claude sign-in the broker's pinned transport admits `platform.claude.com`:
its own refresh at the token endpoint and, while the environment's front door
intercepts that host, any request it forwards untouched; one that carries a
Codewire placeholder or marker is refused before it is sent. The credential
service's separate sign-in transport admits only that endpoint and the one
profile read. Claude itself (`claude.com`) is reached only by your browser.

### Dashboard GitHub connection and repositories

In Settings → Credentials, **Connect GitHub** starts GitHub App user
authorization, not device authorization. **Install/manage repository access**
opens the App's separate installation screen, where the user chooses allowed
repositories. The dashboard and `cw credentials --cloud connect github` tell
users to choose **Only select repositories**: the App requests exactly Contents
(read and write) and Pull requests (read and write), plus Metadata (read), so
a connection can read, push to and open pull requests in every repository the
installation covers that the signed-in GitHub user can also reach (GitHub
gives a user token only what both can reach), and a Sandbox using it can do
the same through the managed route. Authorization returns to this dashboard's explicitly selected,
registered callback. The isolated credential service exchanges the
callback code, verifies the GitHub user and that this exact App is installed,
and names the credential from the verified GitHub username. There is no
separate name field. The browser never receives a GitHub token. Add that
identity to a credential profile; connecting an account alone does not attach
its access to a Sandbox.

GitHub keeps each installation of the App on the permissions it last accepted:
when the App asks for more, nothing changes until the installation's owner
accepts the request on the installation's settings page, and authorizing or
reconnecting the user never asks. Codewire compares each installation's
granted permissions from `/user/installations` with what it needs (`contents`
and `pull_requests`: write, `metadata`: read) and names an installation that
falls short, with its settings page. `actions`: read is requested too but is
not needed: an installation that hasn't accepted it keeps everything else,
and only its Actions reads are refused (#5737). The settings page is:
`https://github.com/settings/installations/ID` for a user,
`https://github.com/organizations/LOGIN/settings/installations/ID` for an
organization, built only from the validated login and numeric ID under the
fixed `github.com` prefix. An enterprise installation has no such page and is
only named: its owner accepts in the enterprise's own settings (#2712).

The App itself must hold exactly those four permissions (`actions`: read
beside the three above), because the GitHub route was reviewed for them and
no others: `administration`, for one, would let a Sandbox create
repositories through the managed credential. Adding `actions`: read makes
each installation's owner accept the request once; until then that
installation's Actions reads get GitHub's own 403, which `gh` shows. The App's
settings live at GitHub, so a scheduled workflow
(`.gitea/workflows/github-app-permissions.yaml`) reads the App's public record
once a day, with no credential, and fails when the set differs, naming each
difference. A day GitHub cannot be read ends in a warning and the line
`app-permissions: unread` instead (#4926).

- **Connect and reconnect** (the dashboard callback,
  `cw credentials --cloud connect github` and local
  `cw credentials connect github`) make the comparison with the new token. An
  installation that falls short still connects, since reads keep working. The
  dashboard callback saves the connection and then redirects (303) to the
  first user or organization installation's settings page; the CLI prints
  each one and, at a terminal, opens the first in the browser as `cw login`
  does.
- **What local connect says it can reach:** local `cw credentials connect
  github` names each account its `/user/installations` answer lists. The
  signed-in user's own account (its login equal to the verified login,
  ignoring letter case, as GitHub does) keeps the installation's selection:
  `LOGIN (all repositories)` or `LOGIN (selected repositories)`. Any other
  account, another user's or an organization's, is named only as
  `repositories you can access in ACCOUNT`: that installation's selection is
  its owner's choice, and this sign-in reaches only what the user can already
  reach there. No repository list is read for it (#5443).
- **The credentials page** shows the status for as long as GitHub holds the
  earlier grant and stops once the owner accepts: "GitHub is waiting for you
  to accept Codewire's updated permissions on LOGIN", with **Review on
  GitHub**. The page itself asks nothing of GitHub (#5206): for a person whose
  GitHub connection is active it carries a placeholder, and the page's own
  script fetches the notice after load. The check is
  `GithubRepositoryService.ListGithubPendingPermissions`, which runs under
  exactly `ListGithubRepositories`' authority: the original exact-Origin
  browser session or `codewire.api` OAuth bearer (organization API keys are
  denied), the owner's single active GitHub connection read by exact id and
  version, the same durable App-token renewal and the same record recheck
  after GitHub answers. Unlike discovery it never renews ahead of expiry: a
  token GitHub still accepts is used as it is, and one GitHub refuses (401)
  renews once, so a check never rotates a working token. It answers login,
  installation ID and account kind only, never a token, permission set or
  provider response, and stores nothing. Being advisory, it never holds
  anything up: it has three slots of its own (never discovery's), a
  two-second budget, and answers nothing at once when its slots are full or
  another renewal of the same credential is running. A renewal it starts
  moves to the tracked worker and completes durably for the next read. The
  dashboard's fragment `GET /settings/credentials/_fragments/github-permissions`
  runs it with a two-second bound; any error or timeout shows nothing, and
  the span of the call records only how it ended: `ok`, the Connect code, or
  `timed_out`, never a message. The fragment is a state change behind a GET,
  because the check can renew a person's GitHub token, and it is acceptable
  only because of its refusal: it answers 403 (`private, no-store`, no CORS
  headers) unless the browser says `Sec-Fetch-Site: same-origin` and the
  request carries htmx's own header, so a missing `Sec-Fetch-Site`, `same-site`,
  `none` and `cross-site` are all refused before anything is read, and a link
  on another site cannot make the dashboard call GitHub or renew a token. It
  also sits behind the page's own gate: one session cookie, no `Authorization`
  header, a valid session and two-factor; a session the page turns away gets
  an empty answer and no check. A page load another site started carries no
  placeholder, including GitHub's Setup URL return, and the person's next visit
  shows the status. The dashboard asks at most once per person per 45
  seconds, in the process's memory only, never shared between people and
  capped at 4096 people: other requests in the window get that person's last
  answer, or none while the first is running, and a completed GitHub connect
  ends that person's window. With more than one replica the window is
  per replica.
  `cw credentials --cloud list` and `get` print the same lines in text
  output under the same rule. Only the first page of 100 installations is
  compared. A transient failure of a renewal that has started still ends the
  connection, as every renewal does today (#2729).

Create Sandbox offers **Choose from GitHub** and **Custom Git URL**. The GitHub
dialog uses the account in the selected profile, shows paginated public/private
repository metadata, and filters the current page. Choosing a profile there also
selects the Sandbox's exact provider-profile revision. Choosing a repository
fills its canonical HTTPS URL, default branch and suggested mount directory.
Choosing an already-added URL does not overwrite an edited branch or mount.
Custom Git URLs remain independently editable. Cancel, Escape and backdrop
dismissal preserve the Sandbox draft.

The browser calls the same-origin dashboard BFF; only the isolated credential
service contacts GitHub. `GithubRepositoryService.ListGithubRepositories`
rechecks the original account authority, exact current profile revision and
credential around protected-store/provider I/O. A cursor is not a grant. Raw
provider JSON, temporary clone tokens and selected credential material are
never part of the response contract. Revoked or changed selections fail closed.

A GitHub repository can be written in any of the four forms Git accepts for
github.com: `https://github.com/<owner>/<repository>`,
`git@github.com:<owner>/<repository>`,
`ssh://git@github.com/<owner>/<repository>`, or the retired anonymous
`git://github.com/<owner>/<repository>`. A github.com source in an SSH form
needs no `known_hosts` entry: without one it is pinned to GitHub's published
host keys (below), and explicit pins are kept as written. Any other SSH host
still needs its pins.

Hosted initial checkout of a canonical `https://github.com/<owner>/<repository>`
(or `git://github.com/…`) source prefers a selected SSH key. When the profile selects one, setup clones
`git@github.com:<owner>/<repository>` inside the Sandbox through its SSH signer
(`/codewire/run/ssh-agent.sock`, the socket the user's shell uses), trusting
only GitHub's published host keys (`codewire_project::GITHUB_SSH_KNOWN_HOSTS`,
bound to GitHub's documented fingerprints by a test). The saved origin is that
SSH URL, so later fetches and pushes use the same key. After a successful SSH
clone, setup appends any of the verified host keys missing from
`/home/codewire/.ssh/known_hosts` (directory 0700, file 0600); existing lines are
never rewritten, and nothing is written when the clone fails.

If GitHub refuses the key or the repository over SSH (`Permission denied
(publickey)`, `Repository not found`), setup falls back to the HTTPS URL:
through the GitHub connection when it is selected, otherwise anonymously. It
records the warning "SSH key not accepted by GitHub; cloned over HTTPS", and the
saved origin stays the HTTPS URL. A network or host-key failure never falls
back; it fails the checkout. With a key selected, an `ssh://` or `git@` source
always uses SSH and never falls back.

Without an SSH key, setup routes a GitHub-selected source in any of the four
forms through the existing managed Git bridge using command-local
configuration, so a profile with only the GitHub connection can create a
Sandbox from `git@github.com:<owner>/<repository>`. The saved origin remains
the original URL, as written. Any other SSH source needs the SSH key; create
refuses it without one, before anything is recorded. With neither credential
the clone is
anonymous, which works only for public repositories; its failure says that
no SSH key or GitHub connection is selected. Private keys/tokens and global Git
configuration are not written into the workspace. This supports smart Git
fetch, including bounded gzip negotiation requests, with no redirect or LFS
support. The size limits are those of the managed Git route below: none when
the host streams request bodies, otherwise 4 MiB request bytes and 256 MiB
response bytes.

A local VM's create applies the same SSH-first rule on the host (#2723). With
an SSH key in the profile, an SSH source is fetched by the credential
authority's SSH transport, with no fallback. Without one, a github.com source
in SSH form is fetched as its canonical `https://github.com/<owner>/<repository>`
path over the GitHub connection's `github-https` route. The stored source and
origin stay in SSH form, and Git in the VM reaches them through the managed
route. Other SSH hosts still need the key. The supervisor reads whether the
profile has a key from a platform profile's slots, or from the local
profile's exact revision, and asks only for a github.com source in SSH form.

After checkout, Git inside a workspace (local VM or hosted Sandbox) uses
whichever Git credential its profile selects for any github.com URL form, with
no login step. This replaces the former rule that only the checkout command
was rewritten and the workspace received no Git configuration. The workspace
environment carries only Git's own configuration: `GIT_CONFIG_COUNT=<n>` and,
for each rewritten form, `GIT_CONFIG_KEY_<i>=url.<base>.insteadOf` and
`GIT_CONFIG_VALUE_<i>=<form>`, where `<base>` is the managed GitHub route
`http://127.0.0.1:38081/_codewire/github/` or, for the SSH key,
`git@github.com:`:

| Selected | Rewritten |
|---|---|
| GitHub connection only | `https://github.com/`, `git://github.com/`, `git@github.com:` and `ssh://git@github.com/` to the managed route |
| SSH key only | `git://github.com/` to `git@github.com:`; `https://github.com/` stays anonymous |
| both | `https://github.com/` and `git://github.com/` to the managed route; the SSH forms keep using the key |
| neither | nothing |

An SSH key alone never takes over `https://github.com/`. A key GitHub does
not accept (a deploy key, a key for another host) would otherwise break every
public HTTPS fetch, dependency managers included. Its only rewrite is GitHub's
retired `git://` protocol. With only a key, a private repository uses a
`git@github.com:` or `ssh://git@github.com/` remote, or the profile adds the
GitHub connection.

`insteadOf` changes only where Git connects: every remote, including the
saved origin, keeps the URL as written, and other hosts are never rewritten.
On the managed route the broker adds the owner's GitHub login outside the
workspace and refreshes it when due; over SSH the key stays behind the signer
socket. No token, credential helper or file is written. `git fetch`, `pull`
and `push` work within the GitHub App's permissions. Public repositories
also go through the owner's login (or the key); when the connection is revoked
or inactive, GitHub remotes on the managed route fail closed until it is
reconnected.

Git bodies on the managed route stream (#4280). A Git POST (`git-upload-pack`,
`git-receive-pack`) sends its body in `CredentialBridgeRequestBody` frames of
at most 64 KiB, ended by `CredentialBridgeRequestEnd`, when the epoch's host
lists the `request-body-stream` capability in its Open. The host grants credit
in frames (`CredentialBridgeRequestCredit`): 16 when the request starts and one
for each frame it hands to GitHub, so neither side holds more than 1 MiB of a
body. Such a request has no request or response size limit; time bounds it
instead. Either side fails it after 60 seconds with no body bytes in either
direction; the host also fails it when GitHub takes no body frame for 60
seconds, so a connection that stops reading mid-push, or a push the guest
cancelled, is not held open. GitHub may take up to 10 minutes to start its response after the
body is complete (it can be silent while it indexes a large pack), and the
whole-request 15-minute provider timeout does not apply. Connect timeouts do.
The local broker and the platform broker list the capability; a
platform-delegated local broker does not yet, so its guest sends whole bodies.
Against a host that does not list it, and from a guest that predates it, every
request carries its whole body: a push whose body exceeds 4 MiB is refused with
413 and `body_too_large` ([Refusals](#refusals-an-agent-or-a-person-can-read-5057)),
and a response stops at 256 MiB. A streamed push is sent to GitHub once: a 401
is returned rather than replayed after a GitHub App refresh, though the refresh
due before sending still runs. A body frame or end the host is not expecting
(for a whole-body request, an unknown request, after the end, or past the
credit) ends the epoch as a protocol error; frames for a streamed request that
already finished or was cancelled are dropped, because they race that answer
or cancel. The Anthropic and OpenAI routes never stream and
keep their 4 MiB request limit.

When GitHub answers a request on the managed route with 401, the broker
rotates a GitHub App sign-in at most once per request and sends the request
once again; a second 401 is returned as it is. A 401 forces such a rotation
only of a sign-in last rotated ten minutes ago or more, because a process in
the Sandbox shapes the request and can provoke one, and a rotation can end
the token another session is using (#5078). The time of the last rotation is
taken from the access token's stored expiry and GitHub's eight-hour lifetime
for such a token. Every rotation writes that expiry with the rotated tokens,
so the bound holds for one sign-in across every broker that serves it and
across their restarts, and the stored form did not have to change: a broker
that predates the bound still reads every sign-in. If GitHub issues another
lifetime, the bound moves by the difference (a shorter lifetime loosens it,
a longer one tightens it) and nothing else changes; the broker logs
`github_app_token_lifetime_changed` when it sees one. The 401 of a sign-in
rotated more recently is returned as it is. So is GitHub's 401 when the
forced rotation's own exchange is refused or its outcome is uncertain; that
sign-in then reads **Reconnect needed**, as after any failed rotation. A
request that no longer has the credential when the rotation is tried (its
re-lease or binding is refused) gets that denial, never the 401. Each broker
also tries a forced rotation of one sign-in at most once in ten minutes, in
its own memory, so a rotation that cannot start is not tried on every 401. A
streamed push is still sent once and never replayed. A personal access token
is never rotated.

Storing the rotation time in the sign-in itself, as the Codex and Claude
sign-ins do, would break brokers already shipped: they refuse a GitHub App
bundle that has a field they do not know. This release's reader accepts a
reserved `refreshed_at_unix` and nothing writes it. A later release may
write it, once every supported reader accepts it.

While the SSH key is selected, no connection to github.com trusts a host key
on first use. Before the workspace starts, `~/.ssh/known_hosts` in the
workspace user's home lists GitHub's published host keys
(`codewire_access::GITHUB_SSH_KNOWN_HOSTS`). A hosted Sandbox's daemon writes
them, and a local VM's guest writes them into its persistent home. A missing
`~/.ssh` (0700) and file (0600) are created with the workspace user as owner.
An existing file of that user gets only the lines it lacks, appended; its own
lines are never rewritten, reordered or removed. A symlinked or foreign
`~/.ssh` or file is the user's and is left alone. The lines are public trust,
not a credential, and stay when the key is later deselected. Non-interactive
tools such as agents, `go`, `cargo` and `npm` Git dependencies therefore never
stop at "Host key verification failed" for github.com. Because the keys are
compiled in, a GitHub host-key rotation needs a Codewire release.

While GitHub is selected, a `codewire.yaml` environment entry or application
secret named `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_0` or `GIT_CONFIG_VALUE_0` is
refused, never merged or overwritten. Those three names are bound into each
environment's projection selection, so the further entries
(`GIT_CONFIG_KEY_1` to `_3`, `GIT_CONFIG_VALUE_1` to `_3`), and every entry of
the SSH key's rewrite, are not reserved: like the `gh` names, the projected
value replaces a declared or inherited one, and only an explicit value for a
single command outranks it. With only the SSH key selected, a declared
`GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_0` or `GIT_CONFIG_VALUE_0` is therefore
replaced as well. A running Sandbox picks up this environment on its next
start. Other Git variables stay the workload's own. A
workload can still override this configuration for itself at run time, which
only bypasses Codewire (no credential is exposed).

Every personal profile includes the account's GitHub connection, so its Git
and `gh` names are reserved whether or not the connection exists. Whether a
workspace is configured for GitHub is decided at each start, from the
connection then: a hosted Sandbox when its Pod starts, a local VM when it
boots. A local VM with a platform profile asks the platform as its creator,
through the host's credential authority, whether that account's GitHub
connection is active; with a local profile the local authority's grant
answers. A connection made or repaired later applies at the next start. When
the question cannot be answered (the platform is unreachable, or the saved
login is not the creator's), that start omits GitHub; it never fails the start
and never routes GitHub remotes to a connection that cannot serve them. A local
VM created before this rule, while the connection was missing, has no GitHub
names reserved and keeps no GitHub until its sources are selected again.

The start's answer configures the guest; it does not limit authority. The
platform delegation authorizes GitHub whenever the creator's connection is
active, so a guest process can reach the managed GitHub route directly once
the connection becomes active, before the next start configures Git and `gh`
for it, as in a hosted Sandbox. It is still only the creator's own connection
from their personal profile.

On a local VM the network policy does limit it (#4926). Selecting a credential
must not widen a network policy, and the managed route runs on the host,
outside the VM's network. So the supervisor, which holds the VM's selected
policy, decides whether a rule of that policy allows both `github.com` and
`api.github.com` on 443 (`CompiledPolicy::allows_managed_github`), and the
local credential authority passes the answer to the broker it starts. When the
answer is no, a request on the GitHub slot is refused before any lease with
status 403 and the code `network_policy_refuses_github`, as plain text for Git
and JSON for the API, and one log line records it; a VM on a platform profile
is refused the same way by its local relay, because the hosted credential
service has no network policy in hand. A broker launched without the answer
refuses GitHub. The answer is authority protocol 20: a supervisor from an
earlier `cw` does not send it and is served as before, and a supervisor that
finds an earlier authority still running, under a policy that does not allow
GitHub, starts no credential broker for that VM and says to stop the local
VMs so the authority is replaced. A change of policy stops the running broker
before its replacement starts, so none serves under the earlier answer. Hosted Sandboxes do not apply
network policies yet; the same decision applies there when they do. The
intercepted route asks the same function per connection (#3999).

Stock `gh` uses the same connection. While GitHub is selected, every session
and managed agent also gets `GH_TOKEN=codewire-managed`, a public placeholder
that only makes `gh` send requests, and `GH_CONFIG_DIR` naming a directory
Codewire owns: `/codewire/run/gh` in a hosted Sandbox, written by the
workspace daemon, and `/run/codewire-host/gh` in a local VM, written by the
guest on its read-only control mount (directory 0700, file 0600, the
workspace user's). Its one file, `config.yml`, names the workspace's
credential ingress socket and nothing else:

```yaml
version: 1
http_unix_socket: /codewire/run/credentials.sock
```

`gh` then sends its `api.github.com` requests to that socket, where the broker
admits its closed GitHub operations and adds the owner's login outside the
workspace. No token, host entry or helper is written, and the placeholder is
dropped by the broker like any guest authorization. While GitHub is selected
your own `gh` settings (`~/.config/gh`: hosts, aliases, extensions and
`git_protocol`) are not read. The two names are not reserved, so declaring
them is not refused; on both placements the managed values win over declared
ones and over application secrets of those names, and only a value given for
one session (`cw run --env`) outranks them.

What works is what the closed operations admit: `gh pr create`, `gh pr list`,
`gh pr view`, `gh pr checks`, `gh pr diff`, `gh issue list` and other GraphQL
commands; `gh api user`, `gh auth status` (the API root) and `gh repo view`
(the repository's README, see
[the exception below](#accepted-exception-the-readme-download-url-token)); and
the issue and pull request REST calls; and `gh run list`, `gh run view` and
`gh run view --log`, which read a repository's workflow runs, jobs and job
logs ([the Actions reads below](#actions-reads-and-the-one-redirect-the-broker-follows),
#5737; not yet observed). Anything else, such as a re-run, release uploads
or `gh api` for another REST path, fails with HTTP 403 and
`request_not_forwarded` ([Refusals](#refusals-an-agent-or-a-person-can-read-5057)). `gh` finds the repository from an SSH origin (`git@github.com:owner/repo`). In a
checkout whose origin is `https://github.com/...`, Git reports the rewritten
bridge URL, so `gh` does not recognize it as GitHub: pass `-R owner/repo` or
set `GH_REPO`.

Every managed HTTP route (Codex, OpenAI, Anthropic and GitHub) is the
workspace's own loopback ingress, and its requests carry prompts and
repository content. So while any of those clients is selected, every session
and managed agent, on a hosted Sandbox and a local VM alike, gets
`127.0.0.1,localhost,::1` appended to `NO_PROXY` and to `no_proxy`. A proxy
the image or `codewire.yaml` declares (`HTTP_PROXY`, `HTTPS_PROXY`,
`ALL_PROXY`) then still serves everything else, and never receives a managed
request. A declared exemption list keeps its own entries; the loopback ones
are added after them, once. These two names are not reserved, so declaring
them is never refused. While such a client is selected, an application secret
named `NO_PROXY` or `no_proxy` is not applied over the list (declare extra
entries in the environment configuration instead), so it cannot drop the
loopback ones. A local VM's own image, install and startup steps take the
extended list too, but an application secret of either name still replaces it
there today. A client that ignores `NO_PROXY` is outside this guarantee.

Deployment must configure a GitHub App with the callback
`<public-origin>/api/v1/github/oauth/callback` registered. The web dashboard
uses GitHub's authorization-code flow with an explicit `redirect_uri`. The CLI
uses the same App's device flow, so the App must also have **Enable Device
Flow** turned on; device login sends only the client ID. Register each
supported dashboard origin separately,
including `https://codewire-dev.sh/api/v1/github/oauth/callback` for Dev.
The checked-in local Kind dashboard uses
`http://127.0.0.1:8080/api/v1/github/oauth/callback`; its ingress routes that
path to the dashboard. The standalone `make web` dashboard instead uses
`http://127.0.0.1:5173/api/v1/github/oauth/callback`, and the managed Kind E2E
fixture uses port 8090. Register the origin actually serving the dashboard;
a port-8080 registration alone does not cover standalone `make web`. No ad-hoc
callback proxy is needed. Kind's checked-in synthetic App identifiers are test
fixtures, not real GitHub registration: actual local authorization requires
the separately configured public App identifiers and matching service bundle.

Disable **Request user authorization (OAuth) during installation**: that
installation shortcut always selects the first registered callback instead of
the dashboard's explicit origin. The dashboard separately links to the App's
installation/repository-access screen. If the authorized account has no matching
installation, no credential is saved: install the App for the account or
organization, then return to Codewire and start a fresh authorization attempt.
`cw credentials --cloud connect github` meets the same check after the device
approval, as `CREDENTIAL_GITHUB_INSTALLATION_REQUIRED`. That refusal's
ErrorInfo carries the server's own install link as metadata `install_url`:
exactly `https://github.com/apps/SLUG/installations/new`, built from the
service's `CREDENTIAL_GITHUB_APP_SLUG`, which must be lowercase letters,
digits and inner hyphens, at most 100 characters, or the service refuses to
start. Every reader of `install_url` accepts only that exact form (`https`,
host `github.com`, no port, user, query or fragment, and a slug under the same
rule). Today the only reader is the CLI; the dashboard builds its link from
its own slug and ignores the metadata. The CLI prints the local path's
sentence with it: the App isn't installed on any account this
GitHub login can use; install it, choose the accounts and repositories, then
connect again. Without the metadata, or with any other value, it prints that
sentence without a link and never the value it received. It never substitutes
the Codewire App's link, because a self-hosted server's App is its own
(#5479). The local `cw` carries the Codewire App's public identity, so its
sentence always ends with that App's link.
A **Setup URL** is optional. If one is set, it must name the credentials page
of the production dashboard origin of whichever deployment owns that App
(`<public-origin>/settings/credentials/`), never another environment's:
GitHub accepts one Setup URL per App, and it sends everyone who installs or
updates that App there, `cw` users included. With **Redirect on update**
selected, GitHub returns a person there after installing the App or updating
an installation, adding `installation_id` and `setup_action=install` or
`setup_action=update`, and the page shows the fixed message "GitHub App
installed." or "GitHub permissions updated.". Anyone can craft that link, so
the page checks nothing, vouches for nothing and ignores `installation_id`.
GitHub documents an update as adding or removing repositories; whether
accepting a permission request also redirects is not documented. Without a
Setup URL the person returns to Codewire themselves, and the credentials
page's live status shows what is still short. The Setup URL is a landing page
only, never a replacement for the authorization callback.
See GitHub's [callback guidance](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-user-authorization-callback-url).
The App may enable **Expire user authorization tokens**. When GitHub returns
an `expires_in` and rotating refresh-token pair, credential-service stores one
versioned protected App bundle, renews it before access-token expiry, and makes
at most one retry after an authenticated GitHub rejection. Refresh is a durable
credential-service-only operation: it re-verifies the same GitHub user and App
installation before publication, admits only the direct credential successor,
and fails closed on revoked, ambiguous, or invalid outcomes. Neither the
browser nor a Sandbox receives the access or refresh token. Each renewal
replaces the previous finished attempt, so a connection keeps renewing until it
is revoked or its refresh token expires. Non-expiring App tokens remain
supported. `cw credentials --cloud connect github` uses the same App's
device flow, so its tokens follow the same expiry setting.
`CODEWIRE_PUBLIC_ORIGIN` and `CREDENTIAL_PUBLIC_ORIGIN` must name that same
public origin, and checked-in ingress/Caddy routing must send the exact callback
path to the dashboard ahead of the broad orchestration `/api` fallback. Neither
the callback origin nor App identity is taken from browser input or proxy headers.
The dashboard receives the public `GITHUB_APP_CLIENT_ID` and `GITHUB_APP_SLUG` from
`codewire-dashboard-public-config`; credential-service receives the all-or-none
`CREDENTIAL_GITHUB_APP_CLIENT_ID`, `CREDENTIAL_GITHUB_APP_CLIENT_SECRET`, and
`CREDENTIAL_GITHUB_APP_SLUG` values from the dedicated
`codewire-github-app-authorization` Secret. That Secret is only the App's
client credentials and slug: never use the GitHub mirror credential, a user
PAT, or an SSH deploy key. Both the public and service-side client ID/slug values
must match. With either public identifier missing,
the dashboard explains that App authorization is unavailable; credential-service
refuses partial App configuration rather than exchanging a callback code.

A dashboard-only deployment or a local stack without its isolated credential
service cannot complete enrollment or discovery. Synthetic browser and provider
tests do not establish real GitHub authorization or hosted deployment success.

The managed Kind browser journey exercises connection, exact profile selection,
repository discovery and normal Sandbox creation together. Its in-process
synthetic provider serves only one authenticated, deterministic repository using
stock Git's smart-HTTP backend. The install command verifies the checkout before
writing a marker; normal execution verifies that marker, the canonical origin
and bounded user Git/GitHub configuration. Normal destruction precedes profile
and credential cleanup. This remains synthetic hosted proof, not live GitHub or
OpenBao acceptance. Git's fixture-only server helpers come from the existing
pinned build image and are absent from production services images.

## Environment configuration and lifecycle

Both placement adapters consume the same file, with explicit flags overriding
YAML. `cw create` finds the nearest `codewire.yaml` from the current directory
(or `--path`) up to its Git repository's root, names it before creating, and
`--file` selects another file. Starting an existing environment uses its
saved configuration, never a changed file:

```yaml
image: workspace

environment:
  LOG_LEVEL: info

secrets:
  project: platform:development

credentials:
  profile: platform:work

install_command: npm ci
startup_script: npm run dev
```

```sh
cw create --local --name app-local
cw create --cloud --name app-dev
cw create --local --name app-local --secrets=platform:development --profile=platform:work
cw update --local app-local --secrets=platform:development --profile=platform:work
cw update --local app-local --clear-secrets --clear-profile
```

Optional `--user-secrets=local|platform` and `--org-secrets` select personal
and current platform-organization sources. `--secrets` selects one named secret
project; it never contains a secret value. `--profile` selects provider identities.
The YAML retains the explicit nested `secrets.project` and `credentials.profile`
shape. Clearing all selected app sources and clearing the credential profile
remain separate actions.

Unique bare names are accepted. `local:NAME` and `platform:NAME` identify origin;
ambiguity requires an exact qualified selection. Failed backend queries do not
prove uniqueness. Persist resolved backend/account/organization/owner/ID, not
only a display name. Optional `secrets.user` explicitly chooses `local` or
`platform`; organization selection is the current platform organization.

Preserve precedence: organization, project, personal, then ordinary declared
environment configuration. Inspect winning and overridden names without values.
Reject collisions with managed provider-routing configuration instead of
silently breaking the protected route. YAML never holds secret values, key-file
paths or protected-store references. The retired `access.profile` key has no
compatibility alias; use `credentials.profile`.

Create and update preview source ownership, profile revision and impact before
the confirmation prompt or `--yes`; there is no consent ID to copy. Update
changes and clears only these selections; it does not edit the rest of the
environment's specification. Selection changes use a confirmed managed restart,
invalidate old grants and retain workspace data. Secret-value changes affect
the next managed launch; existing processes retain inherited values. Install
completion follows the existing setup identity/marker rules; startup runs per
boot. Profile edits alone never rebind an environment.

`cw use` selects execution only. Saved platform selections must bind the exact
server/organization; stale local or platform selections must not fall back to a
different environment. Cached local-only environments retain offline operation;
platform-backed material needs its platform authority online.

## Runtime boundaries

Application-secret values reach a launch through one bounded, typed
launch-projection operation; there is no general value getter. Authorization
and source precedence are resolved before any material is fetched, and the
whole projection is delivered at the actual launcher for setup, install,
startup, ordinary workloads, exec, PTY and durable-session relaunch.

Resolved values must not enter ProjectSpec, Temporal inputs/results/history,
durable session.env, VM seeds, external argv or persistent launcher files. Use
the pinned sealed-box implementation for temporary recipient-bound payloads on
the authenticated channel. Bind environment operation, source identities,
recipient and deadline. Encryption does not replace sender authorization or
establish hardware attestation. Bound framing, allocation and actual exec size;
incomplete, denied, unavailable or oversized projections launch nothing.

Provider credential lifecycle is not a launch fence. In a hosted Sandbox, a
selected credential whose refresh failed, or that was revoked or expired,
withholds only its own capability. Sessions, terminals and the environment
projection keep launching, and the other capabilities keep working. The
withheld capability reads no material; its HTTP route answers 403 with a fixed
explanation, such as `Codex needs Reconnect in Codewire Settings → Credentials.`
Reconnecting the same identity restores it on the next request, without a
restart or rebind. For the same reason, creating a Sandbox or editing its
sources with such a profile succeeds, with that capability unavailable.
`cw create --cloud` and `cw update --cloud` then print the same line per
withheld credential as a local VM's commands (below), with `--cloud` in the
fix and `agents in this Sandbox`, read from the profile revision the Sandbox
pinned (#5594). That read is best effort and bounded: when it fails, the
command still succeeds and prints nothing for it. A
selected credential that no longer exists still refuses the whole runtime:
bound credentials cannot be deleted, so that is integrity damage.
Platform-to-local launches still admit their exact selection as a whole.

A local VM is the user's own machine, and the same holds there (#5545). A
profile credential that was revoked, expired or needs reconnecting withholds
only its own capability: `cw create --local`, `cw start --local` and
`cw update --local` with that profile succeed, its requests are refused as
they are while the VM runs, and every other capability keeps working. Each
of those commands prints one line on stderr per withheld credential, for
example `Claude (sign-in) 'walk' in profile work is revoked; agents in this
VM can't use it.`, then the fix: a sign-in is reconnected under its own name
(`cw credentials --local connect claude --name walk`), and any other
credential is replaced in the profile (`cw credentials --local --profile work
set SLOT NAME`). An expired one `has expired` and a failed one `needs
reconnecting`. Reconnecting the same credential restores it on the next
request, with no stop or start, when it is the profile's only usable
credential: no broker ran, and the next request starts one with its provider
(observed for a Claude sign-in withheld at start, #5545). When another of the
profile's credentials keeps the VM's broker running, the reconnected one is
used from the next start instead: a broker's providers are fixed for its
generation, and the authority refuses a changed set (#5615 lifts that). What
the VM set up at start keeps its form until the next
start: with its Anthropic slot withheld, Claude Code starts in its API-key
form, and starts in its sign-in form again after a start.

A withheld capability's request is answered as in a hosted Sandbox (#5593):
403 with `credential_revoked`, `credential_expired` or
`credential_needs_reconnect` (below). The body names the credential's
provider, and its `Fix:` line names `cw credentials --local list` for a
local VM. The local authority refuses that slot's lease with the reason, and
the lease channel carries it to the broker as metadata on the denial
(`codewire-credential-withheld`: `revoked`, `expired` or `needs_reconnect`),
never an id. A refresh of a withheld credential is refused as a plain
denial: its owner reconnects it. An SSH signature has no refusal body, so a
withheld SSH identity's request stays a denial, audited as one.

The credential service's broker evaluates a hosted Sandbox's authority once per
bridge epoch: one runtime authority resolve and the grant evaluation. The
epoch's leases reuse that decision for at most 60 seconds from the start of its
resolve, on a monotonic clock; the first lease after that evaluates again
inline, and concurrent leases wait for that one evaluation. A lease whose
decision aged while it read is admitted again by a young one before it releases
anything. Every lease of a granted slot rereads its credential's record, one
indexed statement by id and owner, and evaluates again once when that record is
missing, no longer active, expired or of another revocation generation than the
decision's grant; a material read that fails its version fence evaluates again
and retries once. Rotation, Reconnect, revocation and refresh all advance that
generation. A slot the decision refuses is answered from it without an
evaluation: one the profile does not select costs no read; one withheld for
Reconnect rereads only that credential's record and evaluates again once it is
usable; an ungranted GitHub slot rereads only the account's active connection
and evaluates again once it changed. So requests to an unselected slot cannot
force evaluations, and Reconnect still applies to the next request. A denied
evaluation installs nothing and clears the epoch's material cache. The decision
belongs to the epoch, holds no material and ends with it. Owner-local
delegation, Codex and Claude login delivery, SSH signing, OAuth refresh
admission and keep-alive, and environment projection keep their full per-call
checks.

What applies when, for a running hosted Sandbox:

| Change | Applies |
|---|---|
| Rotate or replace material, Reconnect, revoke, delete, an OAuth refresh | The next request |
| Organization membership or role, organization deletion, rebinding the running environment, personal-credential confirmation, environment state, Pod lineage | Within 60 seconds |
| Switch to a different profile | Through the restart it already triggers |
| SSH key change or revocation | The next signature |
| Codex or Claude login direct delivery | Unchanged: every delivery runs full checks |

The broker may also reuse a decrypted provider value within one platform
broker bridge epoch (hosted or owner-local delegation) for at most two minutes
from when it was read; a reuse never extends that. A reuse replaces only the
protected-material read (its database reads and the OpenBao Transit unwrap),
and only for exactly the credential record the lease admitted, generations
included: a hosted lease's reread record, or both record reads of a lease with
full checks. Revocation, replacement, refresh and Reconnect change those
generations, so they take effect on the next request. The cache belongs
to the epoch and ends with it. It holds at most eight values of at most 16 KiB
each; a larger value is read through every time. Only a lease that succeeded
fills it, and a value is dropped at its two-minute expiry even while the epoch
is idle. A failed lease drops its credential's value, and so does a committed
refresh; a runtime authority or grant denial clears the whole epoch cache; and
each grant evaluation drops values of credentials that no current grant names.
SSH signing, OAuth keep-alive refresh and the Codex and Claude logins always read through
the store, and the local placement broker keeps no cache. The service process
is not dumpable and has a zero core-file limit; the helpers it executes
(`ssh-agent`, `ssh-add`) are dumpable again after `exec` but
inherit the zero core-file limit. Proxied-request timing lines report `cache`
as `hit`, `miss` or `bypass`, and `authority` as `reused` (no resolve or grant
evaluation), `evaluated` or `none` (no lease). Every proxied
request crosses the workspace daemon's loopback ingress (stock Codex's proxy
provider), which holds one long-lived bridge epoch. The Kind credentials suite
proves the reuse on that path, that Reconnect and revocation reach that
connected epoch on the very next request, and that a membership change and a
rebind of the running environment reach it within 65 seconds.

Incident note: revoking the credential service's OpenBao access leaves up to
120 seconds of cached use in epochs that already read a value, and a material
row deleted outside the store, without a generation change, can likewise stay
usable for up to 120 seconds. Removing a member, changing a role or deleting
an organization reaches connected epochs within 60 seconds. Restarting the
credential-service pods ends every epoch, flushing every cache and decision at
once. Revoking or replacing a credential in Codewire still takes effect on the
next request.

A front-door stream joins an admitted hosted epoch; it is never a second way
in (#4001). Each admitted `CredentialBridge` response carries one
`x-codewire-credential-bridge-epoch-bin` header: 32 random bytes, unique to
that epoch, for the relay only. `FrontDoorBridge` admits a stream only when the
caller presents, in this order, the relay's own token and the epoch's workspace
authorization, exactly as for `CredentialBridge`, and then that handle. The
handle is looked up only among the live epochs of the binding the
authorization names and compared in constant time, so a handle is refused once
its epoch ends, as is another binding's or the same binding's previous one; a
handle grants nothing alone and is never logged. An epoch takes one front-door
stream at a time (a second gets `ALREADY_EXISTS`), which holds a slot of the
same stream budget until it ends. The stream runs on the epoch's broker as a
front-door entry, with that epoch's decision, material cache and single
refresh, and lists only the `front-door.v1` and `request-body-stream`
capabilities. It ends with its epoch; when it ends, the loopback session keeps
serving and the next front-door stream may join. It also ends once it has had
no request in flight, no open WebSocket or pending handshake, and nothing
received for 120 seconds (#4963), cleanly, as its front door closing would,
freeing its slot; cw-egress opens another on demand. Only the broker's runner
holds every in-flight request and open socket, so only it can tell. A request
in flight keeps the stream open within the request's own bounds, and an open
socket for as long as it is open. The loopback session never ends for
idleness, and neither does a local front door, which cannot open another
session. The relay opens them for `EgressService.FrontDoorSession`
("Front-door session through a relay" below).

Native authentication is ready before private checkout and install; the
environment becomes ready only after setup succeeds. Credential delivery uses
the environment operation's identity, cancellation, fencing and cleanup; there
is no separate secret generation.

Platform-to-local access uses an owner-authenticated delegation in the trusted
host process, bound to the exact platform sources, profile revision and local
environment operation. Both authorities are rechecked, and the delegation
expires and renews within the grant limits. Provider operations stay at the
platform broker; application values reach only the authorized launcher. There
is no Pod impersonation and no persistent copy of platform provider material.
The platform trusts authenticated host assertions about local VM identity;
this is not independent VM attestation.

### Revoking at the provider

Codewire's own revoke commits first. Only then is the provider asked, once,
and its answer is only reported: `cw` says a provider revoked something only
when it confirmed it (#4717). Nothing retries.

- **What can be asked:** a Codex (ChatGPT) sign-in, at OpenAI's RFC 7009
  endpoint, in both placements. A GitHub App connection's access token, in the
  platform only, because only the platform holds the App's secret. GitHub keeps
  the user's authorization of Codewire until they revoke it in GitHub's
  settings, and `cw` names that page. API keys and a pre-App raw GitHub token
  have no revocation Codewire can ask for: they stay valid at the provider
  until revoked there.
- **Platform:** the credential service reads the token, publishes the
  revoke, then asks, over one-route transports (`CodexTokenRevocation`,
  `GitHubAppTokenRevocation`) with an 8 s bound. The revoke response carries
  `provider_revocation`.
- **Local:** the credential authority makes no request. For an active Codex
  sign-in it starts one confined one-shot executor,
  `cw __local-provider-revocation-executor`, after the revoke has committed:
  - **How it starts:** confined as the repository executor is, with an empty
    environment, only its lease stream on FD 3, not dumpable, and a
    parent-death signal on Linux or the process-group drain on macOS. It
    checks that setup at entry.
  - **What it holds:** one lease, the revoked credential's ID and material
    generation (a revoked credential keeps its material until delete).
  - **Its store reach:** it opens the OS store itself, Secret Service on
    Linux or the selected backend on macOS, as the GitHub repository executor
    does, and reads only that generation's entry. It does not receive the
    value over FD 3 yet; #4984 passes it there for both executors.
  - **Its one route:** it asks OpenAI over a transport that admits only
    `CodexTokenRevocation`.
  - **What it reports:** only the outcome class and the HTTP status. The token
    is never sent back, printed or kept.
  - **Its bound:** the authority stops and reaps it within 20 s, whatever it
    reported, and an executor that never reports is NOT_READ. It needs no
    directory, because it writes nothing.
  - **A locked store:** on Linux, reading a locked Secret Service item asks
    the desktop to unlock it. The executor waits for that, and if nobody
    unlocks it, the 20 s bound ends the run with NOT_READ.
  - **Older authorities:** the CLI asks only an authority that serves
    `AuthorityFeature::ProviderRevocation`. An older one revokes without
    asking, and `cw` says the provider wasn't asked.
- **A refresh in flight:** a refresh exchange may already have rotated the
  stored token, and OpenAI answers 200 about a token it no longer knows. The
  local authority reads the credential's refresh marker under the same
  connection hold as the revoke. If a refresh had started, no executor runs,
  and the answer is NOT_READ.
- **The synthetic transport:** under the non-shipping
  `local-broker-synthetic-smoke` feature, the executor answers in process. The
  release `cw` is built from `codewire-cli-bin`, which has no default features,
  with no `--features` (`scripts/ci/release/package-cw-release.sh`). Release
  admission refuses a `cw` built with the feature: `cw_release.py`'s
  `check_build_inputs` refuses a dep-info that lists the feature's module
  (#4986). A build with the feature never starts a browser for a sign-in:
  `cw credentials --local connect` prints the link with a note that the build
  answers it, and neither it nor its GitHub follow-up opens a page, so no
  provider page is loaded with the person's own cookies (#5592).

### Transparent provider routes

The Anthropic and OpenAI/Codex HTTP routes are transparent proxies to their
one pinned provider host (#2536). A stock client in
a Sandbox talks to Codewire's loopback ingress exactly as it would to the
provider, and every request under its managed base path is forwarded:

| Client | Managed base | Provider base |
|---|---|---|
| Claude Code (`ANTHROPIC_BASE_URL`) | `/_codewire/anthropic` | `https://api.anthropic.com` |
| OpenAI API key slot (`OPENAI_BASE_URL`) | `/_codewire/openai/v1` | `https://api.openai.com/v1` |
| Codex (its managed provider) | `/v1` | `https://api.openai.com/v1`, or `https://chatgpt.com/backend-api/codex` for a ChatGPT login |

These base-URL routes are what ships today. For agents they are being retired
(owner, 2026-11-15, #3997): #3999 and #4000 to #4002 replace them with the TLS
front door, so an agent keeps its provider's real host. See
[Invariants](#invariants).

Any `GET`, `HEAD`, `POST`, `PUT`, `PATCH` or `DELETE`, any path below the base
and any query pass through, with every header and the body byte for byte. The
broker changes only:

- the credential: the guest's own `authorization`, `x-api-key`, `cookie` and
  `proxy-authorization` are dropped and the selected credential is injected
  (plus `chatgpt-account-id` and `x-openai-fedramp` from a ChatGPT login, and
  the OAuth beta flag for a Claude subscription token);
- framing: `host`, `content-length` and hop-by-hop headers, which the transport
  sets;
- `accept-encoding`, fixed to `identity` so responses stay redactable.

Responses return every header except framing, hop-by-hop and `set-cookie`, and
every returned header value and body byte passes the injected credential's
redaction. So new provider features, endpoints, beta flags, request fields such
as Claude Code's `safeguards` and response fields such as `safeguard_results`
work without a broker change. Do not add per-feature paths or header lists.

What stays fixed: the pinned host and port, no redirects, a per-request lease
with the authority checks above, each route's one operation in grants
(`messages` on `anthropic-api`, `responses` on `openai-api`), and AV's 4 MiB
request limit, which is below Anthropic's own. The loopback routes carry no
WebSockets.

WebSockets cross only the TLS front door (#3999), and only for Codex's model
call, `GET chatgpt.com/backend-api/codex/responses`; any other upgrade is
refused before a lease. The swap rule and the route's response policy cover
the handshake: the placeholder is swapped for the sign-in, a 401 is
refreshed and retried once under the same rule as a request's (#4974), and
the `101`'s headers pass the response policy
without `set-cookie`. A `101` that echoes the injected credential fails the
upgrade. After the `101` the socket's bytes are neither read nor redacted, so a
credential the agent puts inside a frame reaches the provider as it is. While
a swapped socket is open the broker leases its credential again every 30
seconds; a refusal, a lease that does not answer within 5 seconds, another
credential or a newer revocation resets it. A refresh moves only the
credential's material generation, so an open socket survives it; a Reconnect
moves the revocation generation too and ends the credential's open sockets. A
front-door session holds at most 16 open sockets beside its 16 requests in
flight. Redaction matches
the credential's raw, JSON-escaped, percent and base64 forms; it does not decode
other encodings of a larger value, so a provider that reflected the credential
inside an opaque encoding would not be caught, in a header or in a body. GitHub
keeps its closed families and exact operations, since `git` and `gh` go through
its signer and executor.

### Agent host interception (in progress, #3999)

Local VMs are gaining a TLS front door outside the VM that terminates
connections to the agent hosts and swaps a per-environment placeholder for
the credential (Program #3997). It is off by default, and with it off a boot
is exactly as described above. What exists today:

- **The switch, temporary and per host.** The file `egress-intercept` in the
  local VM state root (`~/.codewire/native-v1` by default, or
  `CODEWIRE_NATIVE_STATE_ROOT`) switches interception on
  for every boot the supervisor starts while its whole content is exactly
  `on`, with an optional trailing newline. Anything else is off and logged.
  The supervisor reads it once per boot and logs `egress_intercept` with what
  the boot used. D3 removes it once interception is the default (#3997).
- **What a boot with it on does.** The runner binds the hosts the boot's
  selected credentials name (below) on 443 in the egress broker and carries
  the front door's CA certificate, never its key, to the guest in the seed.
  The front door makes the CA in its own memory for each boot,
  name-constrained to those hosts. A boot whose selection names no host
  binds nothing and starts no front door.
- **A host is proxied when something selected names it** (#5215). A
  credential declares the hosts it is for. A host is proxied
  in an environment exactly when something selected for that environment
  names it; every other host is ordinary traffic under the network policy,
  never through the front door. Today's credential kinds name fixed hosts:
  an Anthropic credential `api.anthropic.com`, and a Claude sign-in Claude's
  token host as well; an OpenAI API key `api.openai.com`; a Codex sign-in
  `chatgpt.com` and the Codex names under it; a GitHub connection GitHub's
  two hosts, once they are intercepted. A later kind, or a secret selected
  for proxying, names its own hosts under the same rule. The set is the
  union of the hosts the environment's managed-client selection names,
  `codewire_access::front_door_hosts` (#5463), which a local boot and a
  hosted Sandbox both read. "Your own key" is anything that is not a
  selected credential: an environment variable or application secret, a
  sign-in made inside the environment, or a key in a file. On a host
  nothing selected names, it reaches the host under the network policy.
- **When the set is decided.** With the selection, which is fixed for a
  boot and for a Pod: a local boot binds the set its selection names when
  it starts, and a hosted Sandbox's assignment carries the set its live
  binding names. Changing the selection is a managed restart locally and a
  replacement Pod hosted ("Switch to a different profile" above; a binding
  whose managed clients changed is not current, so orchestration recovers
  the environment onto a new Pod, `worker/create.rs`), so a host is never
  added to or removed from a live front-door session or epoch: a new set
  arrives with a new boot or Pod, and with its own front door and epochs.
  `cw-egress` never changes a pair's bindings in place; a bound Pod whose
  assignment carries a different set ends its pair, front door and session
  included, and the guest's redial starts a new one (`supervisor/pod.rs`,
  `a_change_to_a_pairs_front_door_ends_the_pair`). So no host stays bound,
  and refusing, once nothing selected names it. A hosted binding whose
  selection names no host gets an assignment with interception off, so its
  pair runs without a front door rather than failing closed; its trust frame
  and delivery still follow its stored decision.
- **The front door.** The runner starts it in `prepare()`, as its own process,
  confined (no new privileges, a deny-all Landlock domain and a seccomp
  floor it shares with the credential broker) before it makes the CA. Only
  the certificate leaves it. The egress broker hands it each connection to a
  bound host, and it serves those through this boot's credential broker,
  which pairs with it over a private socket before reporting ready. If it
  cannot start or pair, the start fails. The credential authority replaces
  the broker every 600 seconds with an overlapping successor, which pairs
  again and takes all new work while its predecessor finishes what it
  already has, so a broker replaced by its successor keeps interception.
  Only the runner's end, or the front door's exit, ends it for the boot. A
  boot that has no local credential broker, or whose running credential
  authority predates boot secrets, does not intercept, and the supervisor's
  log and `cw` say why (below). Nor does a boot whose credentials come from
  the platform on macOS, or against an authority that does not join the
  platform's front-door session (#4909; see "A local VM on a platform
  profile" below). On macOS a boot with the switch on is refused and names
  the file, until the front door is confined there.
- **What `cw` shows (#4912).** The supervisor sends the boot's decision to
  its runner with the start, and the runner reports it while the boot runs.
  `cw --local info` shows it on its own line under the `Credentials` row
  that names the profile, and so do the results of `cw start`, `cw restart`
  and `cw create`.
  `--output json` carries it as `"interception": {"state", "reason"}`, the
  shape a hosted Sandbox will report too (#4001). A stopped VM, or a boot an
  older supervisor started, has none.
  - `intercepted`: `placeholders only: agents never hold your tokens`.
  - `not_intercepted` with `platform_credentials`: `no placeholders: they
    come from the platform`, for a platform profile's boot on macOS or
    against an authority that does not join the platform's front-door
    session (#4909).
  - `not_intercepted` with `no_credentials`: `no placeholders: none are
    selected`.
  - `not_intercepted` with `nothing_to_intercept`: `no placeholders: none of
    its credentials is intercepted yet`. The runner reports it, never the
    supervisor: a boot told to intercept that runs no front door, because
    none of its selected credentials goes through one yet (GitHub's does
    not, #5087). `intercepted` is reported only while the boot runs a front
    door (#5670).
  - `not_intercepted` with `credential_service_outdated`: `no placeholders:
    the local credential service that is running is from an earlier cw; stop
    your local VMs so cw replaces that service, then start this one`. That is
    the sentence #4926's refusal uses, from one constant.
  - `off`, with the switch off: no line, only JSON, until interception is
    the default (D3).
  - `lost`, once the front door has ended without a stop being asked for:
    `! agents can't reach their providers; restart the VM`, then
    `→ cw --local restart NAME` (#5216).
- **The pairing secret.** A broker pairs by presenting 32 random bytes the
  runner mints for the boot, held only in its memory, compared in constant
  time; the daemon token, which the guest knows, is refused. The supervisor
  asks the runner for it (`GetBootSecrets`, owner-only, the current
  generation of an intercepting boot only) at each broker ensure and passes
  it to the credential authority, which holds it in memory for the
  generation. The authority gives each broker it starts, successors
  included, its own socket on descriptor 4 carrying the secret; the broker
  makes it close-on-exec, reads it once before pairing or confinement, and
  closes it. It is never in the seed, a file, an argument, the environment,
  a log, or any answer's printed form. An authority restarted within the
  generation gets it again from the runner.
- **What the guest trusts.** PID 1 publishes the CA alone as
  `/run/codewire-host/egress-ca.pem` and sets `NODE_EXTRA_CA_CERTS` to it
  (Claude Code), unless the image or project sets that name; then it is kept
  and logged, and that tool's intercepted connections fail their TLS
  handshake. It also publishes `/run/codewire-host/ca-certificates.crt`, the
  image's own system bundle (read only from inside the image's root) followed
  by the CA. While the Codex client is selected, `CODEX_CA_CERTIFICATE` names
  that bundle, unless the image or project sets the name (kept and logged, as
  for Node). Codex ignores the Node variable, and the bundle serves whether
  Codex adds the file to its roots or replaces them with it. Without it, every
  intercepted Codex request fails its handshake (#5447). Nothing else names
  the bundle: `SSL_CERT_FILE` and the like replace a trust store for every
  tool, so a CA the user adds after boot would silently stop being trusted.
  Nothing is mounted over the image's trust store and its layer is never
  written. A restored boot publishes from its own seed before the workspace
  thaws.
- **The agent's login.** Claude Code's login writer accepts this
  environment's placeholder as the access token; the broker delivering it is
  the next step, and until then the direct delivery exception below applies.
- **GitHub's two hosts.** The front door, the bridge and the broker can
  serve `github.com` and `api.github.com` whole, so that Git and `gh` use
  GitHub's own names. No boot binds them yet: that needs the boot chain to
  bind hosts by the environment's clients (#4809), the projection to hand
  Git and `gh` the placeholder, and their trust in the boot's CA. The
  broker's rule for a request to either host, in order:
  1. The environment's network policy must allow GitHub's hosts by rule, or
     nothing is sent, with or without a credential (#4926). Today that is
     the answer the broker is started with; the egress broker's signed
     decision for the connection replaces it.
  2. A placeholder beside another credential is refused
     (`credential_conflict`).
  3. A request with no placeholder-shaped value is forwarded as it was sent,
     on any path, with no lease: an anonymous clone and the user's own token
     work as theirs. Its destination check is its own (the two hosts, HTTPS,
     443, the six plain methods); a request that carries leased material
     keeps the route's exact check.
  4. A placeholder-shaped value on a request outside the route's grammar
     (Git fetch and push, and the API operations the route grants) is
     refused without a lease (`placeholder_outside_route`), whoever's
     placeholder it looks like. Git LFS is one such request.
  5. On the grammar, this environment's placeholder is served exactly as the
     loopback route serves it, and any other value is forwarded untouched.

  The path and query reach GitHub byte for byte. A forwarded body streams
  whatever its size; a Git request given the credential streams as on the
  loopback route; an API request given the credential keeps the 4 MiB bound
  and is answered 413 above it.

### Per-environment placeholders

When a local VM's agent hosts go through the TLS front door, which is off by
default, the guest holds a per-environment placeholder for each credential in
place of the fixed `codewire-managed`. Before such a boot starts, the
supervisor asks the authority for the placeholder of the selected Anthropic
form (an API key or a subscription token; the sign-in form's comes with its
login), and the runner carries it to the guest in the seed beside the CA. Guest
init gives it to the workspace's own processes and to the guest daemon, which
projects it to every session and managed agent. A boot without interception,
or one whose credentials come from the platform, carries none.

- **The value.** `cwp1_` and 43 base64url characters, an HMAC over the
  environment, the selected binding's profile revision, the slot and the
  credential, under a key the credential authority keeps in its protected
  store. It is derived and never stored. No environment can read the key, so
  an environment cannot compute another environment's placeholder. A
  placeholder grants nothing by itself; it only names, to that environment's
  own broker, the credential it stands for.
- **What changes it.** The binding's profile revision, not the VM
  generation. A VM checkpoint restored in place boots a new generation with
  the same binding, so its running agents keep their placeholder. A fork is
  another environment and gets new placeholders. Any rebind to another
  revision or credential changes them.
- **Who can ask for one.** The authority's
  `GetEnvironmentCredentialPlaceholders` call returns, for each requested
  slot the environment's selected binding grants, the placeholder that
  generation's leases carry. It returns none for an ungranted slot, refuses a
  binding that is no longer the environment's, and logs nothing. It is served
  on the authority's owner-only socket, and the local supervisor is its
  caller.
- **What the guest gets.** With interception on, the Anthropic projection
  carries no `ANTHROPIC_BASE_URL`, so Claude Code talks to the real
  `api.anthropic.com` through the front door. `ANTHROPIC_AUTH_TOKEN` (API key)
  or `CLAUDE_CODE_OAUTH_TOKEN` (subscription token) carries the placeholder;
  the sign-in form projects no variable. `ANTHROPIC_API_KEY` is never set,
  because the swap rule refuses a placeholder sent beside a second credential
  header. Without interception, the projection is exactly the one above.
- **What Git and `gh` will get.** Once a boot binds `github.com` and
  `api.github.com`, the GitHub projection sends nothing to the loopback
  ingress, so `git remote -v` prints an HTTPS remote as written. Git prints
  a rewritten form after its rewrite, so a `git://` remote, and an SSH-form
  remote on a profile without a key, print as `https://github.com/…`; the
  stored URL stays as written:
  - no rewrite names the managed route. An HTTPS remote goes to GitHub as it
    is. On a profile without an SSH key the `git://` and the two SSH forms
    are rewritten to `https://github.com/`; with a key, the SSH forms keep
    the key and only `git://` is rewritten;
  - Git's credential helper for `https://github.com`, and for no other
    host, answers `x-access-token` and the placeholder; a helper configured
    earlier for that URL is cleared first;
  - `GH_TOKEN` is the placeholder, and `gh`'s generated configuration names
    no socket. If the user sets `GH_HOST`, `gh` sends the placeholder to
    that host instead. That gives the host nothing: a placeholder is not a
    credential, and only this environment's own front door and broker
    exchange it for one.

  Without a placeholder neither the helper nor `GH_TOKEN` is projected, so
  the fixed `codewire-managed` never reaches the real host. The function
  exists (`ManagedCredentialClientProjection::intercepted_github`); no boot
  calls it yet, because nothing delivers a GitHub placeholder to a guest.

- **Hosted (#4001).** The same derivation, under one key per environment in
  `platform_placeholder_keys`:
  - Created by the credential service on that environment's first lease while
    hosted placeholders are on. **Kept until the environment is destroyed:**
    orchestration's destroy statement deletes the row in the transaction that
    marks the environment destroyed, joined to that statement's own target. So
    only an environment that statement marks destroyed, with no live binding
    and no active dispatch, loses its key, and no other environment's key is
    touched. The broker has no `DELETE`. A lease already in the credential
    service when the destroy commits can still insert the key once more,
    because the environment's row outlives its destroy; nothing reads that
    row, and the foreign key's cascade removes it with the environment's row.
  - Sealed like credential material: a DEK wrapped by the credential-material
    KEK, scoped to the environment's organization.
    The envelope's associated data names the environment, so a sealed key
    copied into another environment's row does not open.
  - Two first uses that race insert with `ON CONFLICT (environment_id) DO
    NOTHING`, and each then uses the stored row, never a key that lost.
  - `codewire_credential_broker` has `SELECT` and `INSERT` on the table and
    nothing else, and the migration revokes everything from `PUBLIC`. What is
    checked here: the Kind grants check refuses the broker `UPDATE`, `DELETE`,
    `TRUNCATE` and references on it, and with placeholders on the credential
    service refuses to start unless its login holds both `SELECT` and
    `INSERT`. Dev's and Production's grants and their audit are infra's
    credential database grants (#4001 step M).
  - **A key never changes.** Placeholders rotate through the derivation's
    inputs, not the key. A key thought compromised is deleted and created again
    by an operator with the schema owner's role, which changes every
    placeholder of that environment; a stale placeholder then matches nothing
    and fails closed. No helper does this yet: it is to come under #4001.
    Until the new placeholder is delivered again, the running environment's
    agents hold one that matches nothing.
  - A lease that derives a placeholder reads and opens the key itself and
    drops it once the placeholder is derived. Its bridge epoch keeps the
    derived placeholder, which is not secret, in its epoch placeholder cache
    (`EpochPlaceholders`): scoped to that epoch, holding derived values only,
    keyed by exactly the derivation's inputs (so a rebind within the epoch
    derives again), and deciding no admission. Later leases of that epoch read
    no key. Nothing keeps a key, in a process or across leases (see
    [Invariants](#invariants)).
  - A key that cannot be read or created marks the lease's placeholder
    failed. A placeholder never decides admission, but the front door's swap
    refuses a request whose lease failed, whatever value it presents, since it
    can tell neither this environment's placeholder nor a foreign one; the
    failure is never remembered, so each request reads the key again until it
    can. It is logged at warn with the environment and one closed reason
    (`NotFound`, `ProviderUnavailable` or `CorruptRecord`), and labels the
    request's timing line (`placeholder`), never with the row or a provider's
    error.
  - Off by default: until the credential service's optional
    `CREDENTIAL_HOSTED_PLACEHOLDERS_ENABLED` is `true` (it accepts only `true`
    or `false`), hosted leases carry none, and no key is created or read. With
    it on, the service refuses to start unless its login holds `SELECT` and
    `INSERT` on the table. An owner-local epoch's leases never carry one.

### Refusals an agent or a person can read (#5057)

Codewire refuses some of an agent's traffic itself, on every managed route:
an intercepted host's front door, the loopback ingress of the base-URL
route, and Git's route. One rendering serves them all. This section is the
one list of those refusals: what the agent receives, the `Codewire-Refusal`
reason, and what the guest's refusal list (#4015) and the owner's
`cw policy log` (#5058) show. A new refusal is added here first.

**Not yet built** (#5057 builds it): the guest's bridge, the TLS front door,
the local VM's credential forwarder and the broker answer with this
rendering, and the bridge protocol carries the reason
(`CredentialBridgeRefusal`). The broker sends `credential_revoked`,
`credential_expired`, `credential_needs_reconnect` and
`no_credential_selected` from the credential's lifecycle and the bound
profile; any other denial stays `denied` (403) and names no cause. The local
CLI's own refusals (#4717) and an unserved `chatgpt.com` path (#4898), still
refused as the broker's denial (403) and not yet as `path_not_served` (404),
come next.

**Two kinds.** Only a request the TLS front door has taken (an intercepted
host, its connection handed off) can be answered in HTTP. Everything refused
at the connection gets no answer from Codewire: the agent sees its lookup
fail or its connection reset, and the reason appears only in the refusal
lists. Codewire never terminates TLS for a host it refuses just to explain
it.

**Answered refusals.** A plain-text body (`text/plain; charset=utf-8`,
`cache-control: no-store`) of the sentence below, then one line
`Fix: …` where the row has a fix, and the header
`Codewire-Refusal: <reason>`. Claude Code shows the body as it is.

One exception: where the client parses the answer as a protocol's error, the
body keeps that protocol's shape. The OAuth token endpoint
(`platform.claude.com/v1/oauth/token`) answers an RFC 6749 error, which
Claude Code acts on (`invalid_grant` ends its login,
`temporarily_unavailable` keeps it running): `invalid_request`
(`request_not_forwarded`), `invalid_grant` with the description "Codewire:
this environment's Claude sign-in needs to be renewed"
(`credential_needs_reconnect`), and `temporarily_unavailable`
(`upstream_failed`). The same header and body rules apply. Its rows come
with #4971.

| Reason | Status | When | Body |
| --- | --- | --- | --- |
| `credential_revoked` | 403 | the slot's credential was revoked or deleted | "Codewire: the PROVIDER credential this environment uses was revoked." Fix: in a local VM, run `cw credentials --local list` on the computer that runs it; in a hosted Sandbox, run `cw credentials --cloud list` wherever you're signed in to Codewire; then connect it again |
| `credential_expired` | 403 | the credential passed its hard expiry | "Codewire: the PROVIDER credential this environment uses has expired." Fix as for `credential_revoked` |
| `credential_needs_reconnect` | 403 | the credential is marked for reconnecting: the provider refused it, or a refresh was refused or its outcome is unknown, which is terminal | "Codewire: the PROVIDER credential this environment uses needs reconnecting." Fix as for `credential_revoked` |
| `no_credential_selected` | 403 | a request carries this environment's placeholder for a slot its profile no longer fills. Without a placeholder the request isn't a credential request at all and follows the network policy (interception design, 3a) | "Codewire: this environment's profile no longer has a PROVIDER credential." Fix: `cw credentials --local profiles list` on the computer that runs the VM, or `cw credentials --cloud profiles list` for a hosted Sandbox |
| `credential_unavailable` | 503 | the credential authority or the broker doesn't answer now | "Codewire: the PROVIDER credential can't be used right now; try again." |
| `credential_conflict` | 400 | the placeholder is sent beside another credential header, or more than one placeholder | "Codewire: this request carries the Codewire placeholder and another credential; send only one." |
| `path_not_served` | 404 | the host's route doesn't cover this path (for example `chatgpt.com` outside `/backend-api/codex`, #4898) | "Codewire: this path on HOST isn't one Codewire forwards." |
| `websocket_not_served` | 403 | a WebSocket the route doesn't carry yet (#3999 changes 9 and 10) | "Codewire: WebSockets to HOST aren't carried yet." |
| `route_not_served` | 403 | an intercepted host whose credential route the front door doesn't serve yet (today every slot but Anthropic) | "Codewire: requests to HOST can't use this environment's credentials yet." |
| `request_not_forwarded` | 400, 403, 408 or 421, as today | a request the front door or bridge won't forward as it is: CONNECT, a malformed target, a host that isn't this connection's (421), a bad upgrade, an unsafe path, a method outside GET, HEAD, POST, PUT, PATCH and DELETE, an oversized query, a header it can't carry, or a streamed body the client broke off (400) or stopped sending (408) | "Codewire: this request to HOST isn't one Codewire forwards." |
| `placeholder_outside_route` | 403 | a request to `github.com` or `api.github.com` carries a placeholder-shaped value and is not one the GitHub route serves with the managed credential: anything but Git fetch and push and the API operations the route grants (Git LFS, for one). Until #5057 renders it, the API host answers JSON with `message` and `code`, which `gh` shows, and the Git host plain text, as `network_policy_refuses_github` does | "Codewire's GitHub connection serves Git fetch and push and a fixed set of GitHub API operations. This request is not one of them, so it was not sent. Git LFS is not served." Fix: use your own GitHub token for this request |
| `body_too_large` | 413 | a body over 4 MiB on a host that doesn't stream, or a GitHub API request over 4 MiB that carries the placeholder | "Codewire: this request's body is over the 4 MiB Codewire forwards to HOST." |
| `busy` | 503 | the bridge's limits on requests or WebSockets in flight | "Codewire: too many requests are in flight; try again." |
| `upstream_failed` | 502, or 504 when no answer came in time | PROVIDER couldn't be reached, or answered in a way Codewire won't pass on. In a local VM that includes a provider whose name did not resolve when the VM's credential broker started (#5286) | "Codewire: PROVIDER couldn't be reached; try again." |
| `name_not_allowed` | 403 | a request on an intercepted host without a Codewire value, which the network policy refuses (design 3a) | "Codewire: this environment's network policy doesn't allow this request to HOST." Fix: to send it, select a network policy with a rule that allows HOST on port 443; for a Codex workspace host one label under `chatgpt.com`, the rule it names is `*.chatgpt.com`, since a rule for one such name doesn't count until #4931's signed decision. The owner's `cw policy log` will show it once #5058 lands |
| `selected_credential_only` | 403 | in a hosted Sandbox, a request on an intercepted host that carries none of the Sandbox's placeholders: the user's own key, another environment's placeholder, or no credential. It is never sent, whatever the network policy, until such a request can leave through the Sandbox's own egress (#5555) | "Codewire: in a hosted Sandbox, requests to HOST must carry the Sandbox's Codewire credential." No fix line |
| `unavailable` | 503 | the request can't be checked against the network policy now: the signed policy decision is missing or doesn't match | "Codewire: this request to HOST can't be checked against the network policy right now; try again." |

A response that has already started when its stream fails can't change its
status or headers; the stream ends with an error, and the refusal lists
record `upstream_failed`.

**Not on this list: the provider's own answers.** A provider's response
passes through unchanged and isn't a Codewire refusal. That includes a 401
the provider gives a managed credential after Codewire's one forced refresh
failed (#4972); "never 401" below is about Codewire's own refusals, and the
next request gets `credential_needs_reconnect`.

**Rows still owed.** #4971 (the token host's answers and refusals) and
#4947 (a routed origin's refusals) each add their rows here when they land.

**Refused at the connection** (no answer; the agent sees a failed lookup or
a reset): `name_not_allowed`, `port_not_allowed`, `address_not_allowed`,
`lease_expired`, and, when the front door itself is down, `unavailable`.
These are the guest reasons of the egress broker's `RefusalReason`
(`protected_answers_only` and `protected_address` fold into the matching
not-allowed reason, `intercept_unavailable` into `unavailable`), so a refusal
never tells an environment which names or ranges are protected. The owner's
`cw policy log` shows the raw reason; the credential and request reasons
above are the same in both views.

**Why these statuses.** Never 401: an agent answers a 401 by starting its
own token refresh, with a placeholder it can't refresh. 403 for what a retry
won't change, 503 for what it may, 502 for the provider's side, and the
request errors keep the status they have today (400, 404, 413, 421).

**What a body may say** (cw-security's ruling of 2026-11-16, recorded on
#5057):
- always: the provider (PROVIDER: Anthropic, OpenAI or GitHub), HOST, PORT,
  the kind of failure and the kind of fix. HOST is the canonical bound name
  from the interceptable-host table that took the connection (for a suffix
  binding, the suffix itself), never the request's Host, SNI or `:authority`,
  which the sender chooses; PORT is the bound port. On the loopback ingress
  no host was bound, and the sentence leaves out "to HOST" or "on HOST".
  Before a request's route is known, or where the answer is written before
  the request is read, no provider is known either, and the sentence says
  "the credential" or "the provider";
- the owner's labels (a credential's or a profile's name) only where the
  environment can already read that exact label through a channel this spec
  names. None does today, so bodies say "the PROVIDER credential this
  environment uses" and point to the owner's own `cw`, where the names are;
- never: internal ids (credential, binding, lease, environment), an
  organization's name, another member's name, an email or a provider account
  name; nothing from the provider's answer or the request is ever echoed.

`Codewire-Refusal` carries exactly one reason from the two lists above, or
`denied` (below), never free text. The set is versioned by this table: a
reader that meets a reason it doesn't know, from a newer broker, treats it as
`unavailable`. A refusal from an older broker that sends no reason at all
keeps today's status (403 for a denial) with the body "Codewire: this request
was refused." and `Codewire-Refusal: denied`, never a 503, which would invite
an agent to retry a refusal that won't change.

Git's route keeps the statuses it has today (Git treats 401 and 403 itself)
and never answers 401; its body is the same sentence, at most two lines,
since Git prints it after `remote:`. Tests match every body
against its fixed template, check that no label appears, and place a canary
in the request, including one in a Host subname under a suffix binding, that
must never come back.

### A provider that can't be looked up when a local VM starts (#5286)

A local VM's credential broker looks up its providers' addresses once, at
its start, before it confines itself, and dials only those addresses for as
long as it serves. A request can then never be steered by a second lookup,
and the confined broker does no DNS. So whether a provider's name resolves
is settled at a broker's start. It never settles whether the VM starts:
reaching a provider is the workload's business, and a VM with a credential
profile boots offline as one without does.

- **The broker starts whatever resolves.** A name that does not resolve, or
  resolves only to addresses Codewire will not dial, is a host this broker
  has no address for; the broker still starts and serves the VM. That
  covers every lookup a broker makes at its start, the GitHub App's refresh
  endpoint among them, which is looked up apart from the others. The
  lookups run at the same time, each on a thread that has ended before the
  broker confines itself, so the start waits for them at most one resolver
  timeout in all, whatever the number of providers: five seconds with the
  released `cw`, whose own resolver sends each lookup to the system's.
- **Which providers are unserved.** A slot's provider is unserved by a
  broker when any host its requests or its refreshes go to has no address
  there, not only the host a request names. A Claude sign-in needs
  `api.anthropic.com` and its token host `platform.claude.com`; a ChatGPT
  sign-in needs `chatgpt.com` and `auth.openai.com`; the GitHub connection
  needs `api.github.com` and `github.com`. With one of a slot's hosts
  missing the whole slot is unserved, so a request is never let through to
  an API host only to need a refresh at a token host the broker cannot
  dial.
- **A request to an unserved provider** is refused as `upstream_failed`
  (502) before any credential is leased. No refresh is begun for it either,
  whatever would begin one: a lease whose token is due, a provider's 401
  that forces one, or the front door's token endpoint. A refresh that fails
  in transport is recorded as an attempt of unknown outcome, which ends a
  sign-in, so one is never begun toward a host the broker cannot dial. The
  profile's other providers, and its SSH key, are served.
- **It mends by itself.** While a broker has an unserved provider, the
  credential service starts a replacement, first after five seconds and
  then at intervals that double up to a minute. A replacement takes over
  only if it resolves every name the serving broker has and at least one
  more; otherwise it ends before it opens the guest's bridge, and the
  serving broker goes on. So the provider's requests work again within
  about a minute of its name resolving, with no restart of the VM. The
  broker it replaces finishes the requests already sent to it for at most
  90 seconds, as after a regular replacement.
- **The regular replacement** every 600 seconds takes over only if it
  resolves every name the serving broker has. When it cannot, the serving
  broker goes on to the end of its lifetime, as before, and a new broker
  then starts with whatever resolves.
- **What is recorded.** The credential service's broker log names the
  unresolved hosts on a broker's `broker_ready` line (`unresolved=`, the
  hosts joined by `/`, or `-` when every one resolved), and again when a
  replacement has them back. Each `broker_spawned` line says which start it
  was (`lookup=first`, `regular` or `early`). An `early` broker that got no
  host back ends without becoming ready: its `broker_not_ready` line is
  expected, not a fault.

Released v0.4.22 and earlier fail the VM's create or start instead, with
`create_failed` or `start_guest_start_failed` and no cause, each broker
ending `CW_BROKER_EXIT stage=provider.resolve` (#5286). The journey step is
`cred-provider-unresolved` in `docs/journeys/credentials.md`.

### Diagnosing delivery in a local VM

`cw --local daemon logs ENV` is the one place to see why a credential did not
reach a local VM (#4882). It prints three parts: the supervisor's operation
lines, the guest daemon's recent log and the credential leases. Each part has
a heading line, and a part that cannot be read says why in one line instead.

- **Guest daemon.** The guest daemon keeps its most recent log lines in
  memory, at most 32 KiB with the oldest dropped first, and nowhere else: not
  on a guest disk and not on a console. They are the lines a hosted daemon
  writes to its Pod log, so a login writer appears as a closed state such as
  `claude_login=Written` or `claude_login=Denied`, never a token, a file's
  content or a path. The host reads them over the daemon connection the
  supervisor already holds, authorized as every daemon call is; nothing
  inside the VM gets a new way to read them. The guest is not trusted with
  the owner's terminal:
  - the supervisor accepts at most 32 KiB, within a deadline; a larger or a
    late answer shows the part as unavailable, and the other parts still
    print;
  - every line is prefixed `guest: `, so none can pass for `cw`'s own output;
  - bytes that are not UTF-8 are replaced, and so is every control character
    except the line break: the C0 controls (carriage return included), DEL,
    the C1 controls (U+0080 to U+009F), and the bidirectional overrides and
    isolates.

  A stopped VM has no lines, and a restarted one starts empty.
- **Credential leases.** The authority's recent decisions for this
  environment, oldest first. A line holds the time, the environment
  generation, the slot, the operation, the route, the decision (`admitted`,
  `denied` or `unavailable`) and whether a credential was selected, and
  nothing else: no credential's id, name or value. A denial reads `denied`
  only: the reason names of
  [Refusals an agent or a person can read](#refusals-an-agent-or-a-person-can-read-5057)
  are not in the authority's record yet (#5211 adds them to the broker). The
  list is the
  authority's bounded in-memory record, so it is empty after the authority
  starts (#1922 owns durable audit). The supervisor reads it through its
  material-free client, and only from an authority that is already running;
  the command never starts one.

A hosted Sandbox's daemon lines are in its Pod log, which `cw daemon logs ENV`
already prints.

### Front-door session through a relay

A front door reaches the broker that holds an environment's credentials
through a relay in two placements: a hosted Sandbox, and a local VM on a
platform profile. Both use one mechanism: a second stream that joins a relay
epoch already admitted, by that epoch's handle, never a second way in.

**Hosted (#4001).** `EgressService.FrontDoorSession` is the hosted TLS front
door's way into the credential broker, beside a Sandbox's loopback ingress.
It is served only while hosted interception is on
(`CODEWIRE_HOSTED_INTERCEPTION_ENABLED`, which needs hosted egress on);
otherwise it answers `UNIMPLEMENTED` to an authenticated caller, and no relay
epoch takes a session. Its only client is `cw-egress` (**The client**
below):

- **Who opens it:** only `cw-egress`, with its own projected token (audience
  `codewire.internal.egress-node.v1`, its ServiceAccount and namespace), for
  an admitted Pod on its own node. Orchestration reads the node from the
  caller's live Pod, and refuses with `PERMISSION_DENIED`, before any relay
  work, a Pod that is on another node, is not admitted, has another UID or has
  no live binding. The Sandbox's workspace binding token cannot open one: a
  loopback session never becomes a front-door session.
- **The environment** comes only from that Pod's live workspace binding, never
  from a request field.
- **It joins the binding's current relay epoch.** The relay epoch that the
  broker admitted most recently for that binding (environment, Pod UID and
  generation) opens the broker's `FrontDoorBridge` with its own relay token,
  the daemon's workspace authorization and the epoch's handle; none of them
  reach `EgressService`. Orchestration answers `attached`, then the host Open,
  which lists exactly the capabilities the broker listed for that first
  stream; they are pinned for the session.
- **One session across renewals.** The session holds cw-egress's stream for
  its whole life while the relay epochs behind it renew; each epoch it joins
  is an upstream. New requests go to the binding's current epoch, joined at the
  session's next frame after it is admitted, and every later frame of a request follows it to
  the upstream it opened on. So a renewal ends no request in flight, unless
  the epoch that request started on expires first. An older upstream is
  closed once it holds no request. A session holds at most two upstreams, so
  a third epoch waits until the draining one is gone. A successor listing
  fewer capabilities than the pin is not used, and one whose join fails is
  tried again after 1 second, doubling to 30. At most 256 requests are open
  at once, and an id over 128 bytes is a malformed envelope. The routing is
  `codewire-credential-bridge`'s `front_door_router`, which the
  platform-profile carrier shares:
  - an id opens once, and cannot be opened again while it is live or within
    60 seconds of finishing;
  - a frame for an id never opened, or forgotten, gets the bridge's own error
    answer for that id;
  - a frame racing a finished request's answer is dropped;
  - at most 4,096 finished ids are remembered;
  - a response for an id an upstream does not hold ends that upstream, and its
    requests get the error answer;
  - a frame needing a capability outside the pin is answered.

  Only a bad frame, an unreadable envelope or a second Ready ends the
  session. The session reads each message's frame type and `request_id`,
  never a payload, and refusals are counted by reason with no id.
- **Ready.** The broker reads a stream's Ready before it answers, and the
  front door sends its own only after the Open written from that answer. So
  the relay opens each upstream with the Ready of the binding it
  authenticated: the protocol version, the environment id and the
  generation, never anything the front door claims. The front door's own
  Ready, its first frame, is checked once per session and must equal it byte
  for byte. It is consumed, never sent upstream, including after a renewal;
  a mismatch, any frame before it, or none within 30 seconds ends the
  session, counted by a fixed class. So a `cw-egress` on another bridge
  protocol version fails every hosted front-door session closed: cw-egress
  and orchestration roll out together. The broker still checks the Ready
  against the workspace authorization.
- **The frames** are carried unchanged: each `bridge` field is exactly one
  front-door.v1 frame, a four-byte big-endian length and then that many
  protobuf bytes, at most the bridge's maximum message size. Orchestration
  reads only that length and refuses a length of zero, over the maximum, or
  not equal to the bytes that follow, which ends that session. Injection,
  redaction, refresh and every authority check stay in the broker.
- **Bounds.** Each upstream's frames toward the broker hold a stream budget
  of their own inside the environment's, and a broker that takes none for 30
  seconds ends that upstream. A `cw-egress` that takes no frame for 30 seconds
  ends its session; one whose socket is out of credit is not stalled, since
  the broker then sends nothing. The loopback session keeps serving either
  way.
- **It ends** when cw-egress closes it, when the token cw-egress opened it
  with expires, or on a stall. With no epoch left, new requests get the error
  answer. After 60 seconds with no epoch and no upstream, the session ends
  `UNAVAILABLE`, so cw-egress opens it again and the Pod's binding is read
  again: after an unbind or a new generation, this binding's epochs do not
  return. Each upstream ends with
  its epoch, so the epoch's reuse limits above bound everything sent on it.
  An epoch serves one upstream at a time; a second is `ALREADY_EXISTS`.
- **`UNAVAILABLE` means no epoch is running for the Pod's current binding on
  this process yet:** the environment is not admitted, a rebind is replacing
  its relay, or this is not the orchestration replica whose relay holds it.
  The relay is leader-gated, and orchestration runs one replica; scaling it
  out needs the session routed to the leader first. `cw-egress` retries
  `UNAVAILABLE` and `ALREADY_EXISTS` with bounded, capped backoff.
- **Idle.** The broker ends the joined front-door stream once nothing has
  been in flight or received for 120 seconds (#4963; the joined stream in
  "Runtime boundaries" above), which frees the epoch's place for the next
  one; `cw-egress` opens another on demand.
- **The client** (`codewire-egress-node`'s `front_door_session`). `cw-egress`
  keeps one session open for each
  Pod whose front door runs, from the front door's start until the Pod's
  egress pair ends:
  - **Opening.** It reads its token again for every open, never caching it,
    and sends `open` with the Pod's name and UID from that Pod's own
    admission. After `attached` it writes the credential-session tag on its
    own end of a fresh socket pair, then hands the front door the other end;
    the front door admits only a connected stream socket whose tag arrives
    within 2 seconds, so nothing from the network decides that read. The
    hand-off has its own socket, at descriptor 5 in the front door, which
    carries nothing else: `CWHF1 credentials` with that one descriptor,
    answered `CWHF1 session serving` or `CWHF1 session dropped` and a fixed
    code (`kind`, `tag` or `busy`). The front door's syscall filter doesn't
    change: it already receives the descriptors it is handed, and its own
    denials are pinned by a test. A sessions socket that closes or carries
    anything else ends the front door, so the Pod's egress pair restarts
    rather than serving on with no session; a `busy` answer, which one relay
    at a time never causes, ends the pair too.
  - **Relaying.** Toward the front door, each `bridge` payload is written
    unchanged. Toward orchestration, the front door's bytes are cut into
    whole frames, each one `bridge` message; a length of zero or over the
    bridge's maximum ends the relay. It holds at most one frame each way and
    reads no further until that frame is taken, and when either side ends,
    the other is ended at once. The relay parses nothing else, the front
    door's Ready included, and logs only fixed reasons and counts.
  - **One at a time.** When a session ends, its socket closes and the front
    door drains it; only then is the next one opened. So the front door holds
    at most the session draining and the new one.
  - **Reopening.** A Sandbox can end its own session by what it sends, so
    the reopen rate is bounded: the backoff starts at 1 second, doubles to a
    cap of 30, and resets only once a session has stayed attached for 60
    seconds. A clean end of a session that stayed that long, as at the
    token's expiry, reopens within 2 seconds, at a random point, so a node's
    sessions don't all return at once; an earlier end of any kind takes the
    next backoff. `UNAVAILABLE`, `ALREADY_EXISTS` and a transport error take
    that backoff. `PERMISSION_DENIED`, `FAILED_PRECONDITION` and
    `INVALID_ARGUMENT` wait 60 seconds, and `UNIMPLEMENTED` 5 minutes. Every
    wait but the healthy reopen is drawn from the upper half of its interval,
    so none comes out near zero, and each refusal is logged at most once per
    interval and counted.
  - **A second session for the same Pod**, from the same node: orchestration
    ends the first, counted, and the second takes its place in the epoch
    rather than getting `ALREADY_EXISTS`. One from another node is refused
    before any relay work, as above. So a `cw-egress` restarted before its
    old session stalled out is served at once.
  - **Meanwhile,** with no session attached, the front door fails every
    intercepted request closed and the Sandbox's other egress carries on.

**A local VM on a platform profile (#4909).** Such a VM has no local
credential engine: its confined local relay forwards the guest's bridge to
the platform's broker over the owner-local delegation channel, one
delegation epoch at a time. On Linux, against an authority that joins the
platform's front-door session, the supervisor intercepts such a boot and
the front-door session crosses the delegation. On macOS, or against an
older authority, it starts without interception, its log says
`skipped=platform_credentials`, and `cw --local info` says `no
placeholders: they come from the platform` ("Agent host interception"
above). These rules hold:

- **Who opens it:** only the boot's own front door, paired with the local
  relay exactly as with a local broker: the boot's pairing secret, then the
  `C` role tag. The relay joins `DelegateFrontDoor` on its own inherited
  channel, which accepts it only for that channel's admitted delegation and
  only while it lives. The authority keeps the platform's epoch handle (the
  32 bytes of `front_door_epoch`, never logged; any other length is refused)
  and joins `CredentialDelegationService.FrontDoorDelegation` with it, so the
  handle never reaches the relay. An unknown, ended or other owner's handle
  is refused the same way for each, and counted. The guest's loopback
  session can never open a front-door session or name an intercepted host
  (#4221).
- **The environment** comes from the delegation's admitted selection, never
  from a frame.
- **The platform's broker serves it** as `BridgeEntry::FrontDoor` on the
  same broker as the loopback session: one lease set, one refresh, the swap
  rule (#4722). The entry is decided by the method called,
  `FrontDoorDelegation`, never by a frame. The relay adds no engine, lease,
  decision or material of its own.
- **The relay writes the session's Open itself, from a fixed pin.** The
  runner reads the pairing secret within 2 seconds of the connect, before
  the relay's delegation can be admitted, so the relay pairs at once, before
  confinement: the secret, then the role tag. Its Open lists a fixed set,
  `CREDENTIAL_BRIDGE_DELEGATED_FRONT_DOOR_CAPABILITIES` (the front door and
  streamed request bodies, what the platform's front-door entry serves; no
  WebSockets, which it doesn't). The relay holds that Open until its first
  join is accepted, or 8 seconds after the tag, inside the front door's 10:
  the front door gives all new work to the newest session as soon as it
  opens, so a session opened before its join would answer every new request
  unavailable at each rotation while its predecessor still served. The
  front door's first frame must then be exactly this binding's Ready, byte
  for byte as on hosted, within 30 seconds. The relay checks each frame's
  length against the bridge's limit in both directions.
- **A join is used only when it admits at least the pin.** The relay joins
  only after its delegation is admitted, through the authority, which allows
  one live join per channel, bounded by 10 seconds and never on the
  loopback session's path. An admission that lands after the Open's hold
  (its own bound is 15 seconds) is picked up by the next request, which
  joins then. A join admitting less than the pin is never used:
  the relay logs the missing capability, intercepted requests are answered
  unavailable, and it tries again only after a backoff.
- **An older platform** returns no `front_door_epoch`. The relay then has no
  session to attach, and the boot's logins stay refused: it fails closed.
- **One session per relay process.** A delegated relay is one delegation
  epoch: the authority replaces it with an overlapping successor before 600
  seconds, as it replaces a local broker. Each relay pairs with the front
  door when it starts, writing the credential role tag before its bridge
  Open. The front door gives all new work to the newest session, and the one
  it replaces finishes only the requests already sent on it (#4884). A relay
  never moves a request to another epoch, and once replaced it opens no new
  upstream stream.
- **Within its epoch** the relay keeps at most one upstream stream. The
  platform ends a joined stream after 120 idle seconds; the relay then holds
  the next request while it joins again, bounded by 10 seconds and spaced by
  a backoff from 1 second doubling to 30, so the pause costs the agent no
  failed call. Every join is spaced: one that is accepted but ends sooner
  than the backoff counts as failed, so a guest's frames can't drive joins
  faster than that, and only a join that lasts the backoff resets it. A
  request that arrives while no join can be made is answered unavailable.
  Each join is a new upstream, so a late frame from an ended
  stream never reaches the next one. When an upstream ends with requests
  open, one still waiting for its response gets the bridge's error response,
  and a response already streaming ends early. Every upstream ends with its
  epoch, so the 60-second authority and 2-minute material limits hold, and
  no cache outlives an epoch.
- **Rotation fails closed, and its drain is bounded.** The authority pairs
  the successor before it ends the predecessor, and a predecessor runs until
  its open requests have answered or its epoch expires. Nothing is queued
  between sessions: with no session paired, a request fails closed at the
  front door. The front door keeps at most two sessions, so a third pairing
  ends the oldest. A request that outlives two rotations, or its own epoch,
  is cut: one still waiting for its response gets the error response, and a
  response already streaming ends early. A long streamed response is the case
  this reaches.
- **Logins are placeholders from the first request.** The relay of an
  intercepting boot sets `front_door` in its delegation's Open, which the
  admission echoes exactly. The platform then seals that epoch's agent
  logins with placeholders from admission, before any front door joins, and
  issues the epoch's handle. A front door that never joins leaves the agent
  with placeholders that work nowhere: it fails closed. Unset, logins are
  delivered as for a boot without interception, and no front door can join.
- **Without a front door the boot fails closed:** a request to an
  intercepted host is refused by the egress broker and counted, never dialled
  directly.
- **With the switch off** (`egress-intercept`), the VM behaves exactly as
  today: base-URL routes through the relay.

**The relay's router (both carriers, agreed with cw-security on #4909 and
#4001, 2026-11-15 and 2026-11-16).** The relay routes each request to the
upstream it opened on: the local relay within its own delegation epoch (an
idle reopen, or an upstream that ended), and the hosted relay, once it
routes, across epochs as well. It does so as follows:

- **It reads one field.** Each guest frame's request id, only after the
  frame's length is bounded. It never decodes a payload, and nothing from a
  payload reaches a log or a metric.
- **Opening:** a guest `Request` or `Upgrade` with an id that isn't live opens
  it on the current upstream. A live id, or one finished within the last 60
  seconds, can't be opened again: the reuse is dropped and counted, never
  answered or forwarded, since the id's own request would read the answer.
  So is a frame of the other kind for a live id (a `Cancel` on a socket, say);
  the id goes on as it was.
- **Frames the front-door entry never serves** (`EnvironmentProjection`,
  `Ssh`, `CodexLogin`, `ClaudeLogin`) are refused by the router with the
  error response for their id, so no SSH or login flow crosses this carrier.
- **Following:** a request's later frames (body, end, cancel, stream data,
  credit, close) go to the upstream its id opened on.
- **What it can't route gets the bridge's own error response for that id,**
  counted by reason, and the session stays open: an id never opened, an id
  whose upstream has ended, and a frame that needs a capability outside the
  pin. A frame for an id finished within the last 60 seconds is dropped and
  counted, since it races that id's answer. That memory is capped by count
  as well as time, and an id it forgot is treated as never opened.
- **A live request's own frame outside the pin ends that request:** it is
  answered once, its upstream is sent a `Cancel` (a socket's reset), and the
  upstream's later frames for it are dropped for 60 seconds without ending
  that upstream; one later still ends it, failing closed.
- **Responses stay with their upstream.** A response for an id its upstream
  doesn't own is dropped, and that upstream is ended: its open ids get the
  error response, and the session continues on the others.
- **Draining** an old upstream is bounded by its epoch's expiry. Requests
  still open then get the error response.
- **Capabilities are pinned** from the first upstream's admission
  (`front-door.v1`, `request-body-stream`, and `websocket.v1` only where
  served), advertised exactly in the session's one Open, which the relay
  writes itself. A successor that lists fewer is not used: new requests stay
  on the current upstream until it expires, then get the error response
  until a pinned-equal upstream is admitted.
- **Only an unreadable frame ends the session:** a bad length, a length over
  the bridge's frame limit, an envelope that can't be parsed, or a second
  `Ready`, which has no id to answer. Every other refusal is per id.

### Hosted interception (not yet built, #4001)

With hosted interception on, a hosted Sandbox's agent credentials go through
the proxy as a local VM's do with its front door, and the Sandbox holds no
real token (owner, 2026-11-19, #4001). It is a deployment switch,
`CODEWIRE_HOSTED_INTERCEPTION_ENABLED` on orchestration, off by default, and it
takes effect at a Sandbox's next start, never during its life: orchestration
decides it once, at the Pod's first bind (the switch, and the Pod being a
broker-mode Sandbox), and stores it on the binding. The bind, every rebind
and every credential relay epoch of that Pod read the stored decision, and
so does orchestration's egress service for the Pod's interception CA, its
assignment's host bindings and its leaves, so none can disagree
(cw-security, 2026-11-19, #4001). A Pod stored as
intercepted stays so if the switch is later turned off: its epochs still
serve the front door, and anything it lacks refuses, never falling back to
the loopback credentials. A Pod stored as not intercepted stays so if the
switch is later turned on, until it is replaced. Pods bound before the
decision was stored count as not intercepted, which they were. A Pod with no
stored decision has no credential epoch. While the switch is off, the
credential relay stores "not intercepted" for such a Pod with the same
write-once, since the bind would decide the same; that covers a Pod an older
orchestration bound during a rollout, whose daemon binds only once per start.
With the switch on, only the bind decides, since only the bind sees the Pod:
such a Pod's egress admission is then refused too, so it fails closed until
it is replaced. An unbound warm member has no decision yet, and the switch,
which its first bind will store, decides its CA.

- **The path.** The Sandbox's egress broker in `cw-egress` sends each agent
  host on 443 to the Sandbox's front door. The front door decrypts with a leaf
  of the Pod's interception CA (below) and hands the request, holding only
  the placeholder, through orchestration's credential relay to the
  credential service as a front-door session joined to the Sandbox's
  admitted epoch. The credential service checks authority, swaps in the real
  token, redacts the reply and refreshes, exactly as a local broker does.
  `cw-egress` holds certificates and no credential, and a front door never
  acts for another Sandbox.
- **Every connected agent credential.** The Claude sign-in, with `/usage` and
  the plan display working; a Claude subscription token; an Anthropic API
  key; the Codex sign-in, with Codex's account routing; an OpenAI API key;
  and GitHub (the App login and a personal access token), for Git over HTTPS
  and `gh`. A credential the Sandbox's profile does not select is not bound.
- **Placeholders, in the local shape.** Each placement carries a
  per-environment placeholder derived as above, under a key the credential
  service holds for that environment (#5017), never stored. It keeps its
  form's provider prefix (#5159): `sk-ant-oat01-cwp1_` and 43 base64url
  characters in Claude Code's login file, `CLAUDE_CODE_OAUTH_TOKEN` and
  `ANTHROPIC_AUTH_TOKEN`; `sk-ant-api03-cwp1_` and 43 in `ANTHROPIC_API_KEY`.
  Codex's login keeps its unsigned JWT shape, and GitHub its own grammar
  (#5149). A placeholder is recognised by its whole value's length and
  charset, never by a prefix, and one sent outside the route table is
  refused, never forwarded.
- **What the Sandbox projects.** Exactly what a local guest's seed carries:
  the placeholder of the `anthropic` slot, which the API-key and
  subscription-token forms take as a variable. The sign-in form's and
  Codex's placeholders travel in their delivered logins, an OpenAI API key
  keeps its loopback route as it does locally, and GitHub keeps today's
  hosted route while its hosts are not intercepted (Git and `gh` go through
  the loopback ingress as before). The credential service derives the set
  at the intercepted epoch's admission, from the grant the binding gives
  that slot, as that epoch's leases derive theirs, so it arrives with the
  epoch's admission and never apart from it (cw-security, 2026-11-19,
  #4001). A grant evaluation that fails, or a placeholder key the
  credential service can't read, refuses the admission, so no Open is sent
  at all; a credential service whose hosted placeholders are off projects
  none. The admission's response carries the set to orchestration's relay
  in one header value, `x-codewire-credential-bridge-placeholders`, only
  for an epoch the relay said is intercepted; the relay copies it into the
  daemon's `CredentialBridgeOpen.placeholders` whole, or leaves the epoch
  unadmitted, and never logs or forwards the header. A client of credential
  delegation never sets the field, and an Open from one that does is
  refused. The daemon refuses placeholders on an Open when its bind is not
  intercepted, and an unknown, repeated or malformed slot refuses the whole
  Open, never a partial projection. With its bind's interception on, the
  daemon projects as a local guest does with its front door: no loopback
  base URL, and the form's variable holding the placeholder of the active
  epoch. A launch waits for an active epoch, the first or the next after
  one was lost, as long as it waits for its host, so a launch in that gap
  is delayed, never started without its placeholder. Every epoch of one binding gives the same placeholder,
  since no epoch is a derivation input; a rebind to another credential or
  profile revision gives a new one, and a process started before it
  carries the old one, which the front door then refuses with 401 until
  that process restarts. With no placeholder (none granted, or hosted
  placeholders off), it projects no Anthropic bearer at all, never the
  loopback routes. `NODE_EXTRA_CA_CERTS` and `CODEX_CA_CERTIFICATE` point
  at the bundle it installs from the egress trust, never over an image's
  own value. No placeholder appears in a log.
- **Delivery follows the front door.** A hosted epoch that serves the
  Sandbox's front door delivers Claude and Codex logins with placeholders
  only, or refuses them; it never delivers a real login beside a front door,
  and an epoch that would is refused at admission. A Sandbox whose binding
  turns interception on has its earlier real login file removed.
- **The relay says it on every epoch.** Orchestration's relay sends the
  binding's stored decision as `x-codewire-credential-bridge-intercepted`,
  exactly `true` or `false`; a repeated or other value refuses the epoch. A
  missing one comes from a relay older than the header, while a deploy rolls
  the credential service before orchestration or orchestration alone is
  rolled back. While the credential service's hosted placeholders are off
  (`CREDENTIAL_HOSTED_PLACEHOLDERS_ENABLED`) it reads as `false`, so such a
  deploy changes nothing; with them on, it refuses the epoch.
- **The sign-in exception ends.** With the switch on, the two hosted rows of
  [Direct delivery exceptions](#direct-delivery-exceptions) no longer apply:
  no real Codex or Claude sign-in token is written into the Sandbox (#4002).
- **Own keys** (#5555). A request to a bound host that carries
  none of the Sandbox's placeholders (the user's own key, another
  Sandbox's placeholder, or no credential) is refused
  `selected_credential_only` before anything is sent, whatever the network
  policy, until such a request can leave through the Sandbox's own egress.
  The credential service would otherwise send it from the platform's side,
  past the Sandbox's policy and `cw-egress`. Only a host something selected
  names is bound (#5215): on a host nothing selected
  names, the user's own key leaves through the Sandbox's own egress under
  its network policy. To use their own key for a provider, a user leaves
  its managed credential unselected. An own key on a host a selected
  credential names stays refused; serving both is a later decision with
  its own issue.
- **Off is today.** With the switch off, every hosted path is exactly as
  before.

**Not yet built.** Merged: the front-door stream joining an admitted epoch
(#4934), `EgressService.FrontDoorSession` (#4906), the per-Pod CA and its
admission to the guest's trust frame (#5051, #5603), the placeholder keys
and their failed-read refusal (#5017, #5087), the bindings, the switch and
the stored decision with delivery following the front door (#5013, #5023,
#5496), the relay session and its router (#5021, #5439, #5056), the
credential service's CA ensure, leaf signing and sweep (#5170, #5071), the
idle end (#5125), `cw-egress` asking for its front doors' leaves (#5669), and
the Open's placeholders with the daemon's projection of them (#5530), one
per-client host selection for local and hosted (#5463), and orchestration's
egress service reading each binding's stored decision. Still open:
orchestration signing those leaves through the Pod's relay epoch (it answers
`UNAVAILABLE` until then). `cw-egress` keeps each front door's session open
and reopens it (**The client** above). The switch's gates are #4001's
switch-on checklist. The journey is `agent-hosted` in
`docs/journeys/network-and-egress.md`.

### Hosted interception CA (not yet served)

With hosted interception on (#4001), each Sandbox Pod has one interception
CA, and only the credential service holds its key. Nothing creates one yet.
These rules, ruled by cw-security on #4001, hold from the start. The
`agent-hosted` journey walks them: a rollout, a restart, a warm claim and a
signer outage (#5032).

- **One per Pod, for its whole life.** It's a random ECDSA P-256 key pair,
  generated by the credential service at the Pod's first admission, bound or
  not, and never derived from a root. The guest keeps the trust of its first
  session (#5006), so the same CA serves the Pod across every `cw-egress`
  that serves it.
- **Its certificate** is a CA with path length 0, keyCertSign and crlSign. A
  critical name constraint excludes every IPv4 and IPv6 address and permits
  no DNS subtree, since the signer's binding record is the host limit. It's
  valid for 400 days. Status shows a Pod within 30 days of its CA's end, and
  past the end interception fails closed.
- **Sealed per Pod.** The private key is sealed in `platform_interception_cas`
  under a DEK in the `platform` scope for that Pod UID. Its AES-GCM
  associated data names the Pod UID, so a row copied to another Pod doesn't
  open. Only this table uses the `platform` scope. The certificate is stored
  in the clear, with the Pod's namespace and name, by which the sweep reads
  whether the Pod still exists.
- **Its environment** is empty while the Pod is unbound. The credential
  service always inserts it empty, or filled from the Pod's live binding if
  one exists. The bind's own transaction attaches it, once; a second attach
  is refused.
- **Who gets what.** Orchestration's `EnsureInterceptionCa` creates the CA
  and returns its certificate only, for the Pod's first session. It's
  idempotent by Pod UID and refuses a Pod whose binding was released. The key
  is opened only to sign a leaf, and only for an attached row whose Pod UID
  and environment match what the Pod's relay epoch authenticated.
  Orchestration asks only for a Pod that intercepts: a bound Pod whose
  stored decision is intercepted, or an unbound warm member while the switch
  is on. A Pod stored as not intercepted gets no CA, and a bound Pod with no
  stored decision is refused while the switch is on.
- **Leaves** are signed for a public key the front door sends, for the hosts
  the signer passes: exact DNS names, or one `*.<suffix>` for a suffix in
  Codewire's interceptable-host table, which covers one label only. A leaf is
  serverAuth only, never a CA, and lives at most an hour, never past its CA.
  An unbound Pod gets none. The signer takes its hosts from the hosts the
  session's grants reach, never from the request, which names none. Since
  the CA permits every DNS name, that is the only host limit: an intercepting
  Pod whose selection names no host gets no leaf.
- **The Pod check.** Before a CA is created, the credential service reads the
  Pod by name in the sandbox namespace (`CREDENTIAL_SANDBOX_NAMESPACE`, its own
  setting, never a request's). It must be the named UID, carry
  `codewire.sh/egress=broker`, and not be terminating. A missing Pod or another
  UID is a denial; an unanswered read is unavailable, and worth a retry.
- **Gone with the Pod.** The binding's release deletes the row in the same
  transaction. Every 5 minutes, a sweep reads each unbound row's Pod by the
  namespace and name stored with it. It forgets the row 10 minutes after the
  first sweep that found the Pod absent. Absent means only a definite
  not-found, or another UID at that name. An API error, timeout or refusal
  neither starts nor advances that clock, because a wrongly forgotten CA
  strands a live Sandbox's interception (cw-test-health, #5030). Without
  `CREDENTIAL_SANDBOX_NAMESPACE`, the check refuses as unavailable and no sweep
  runs. The credential service's role can insert and read rows, but delete
  none.
- **Never logged:** no key, envelope or leaf key appears in a log or an error.

### Hosted interception leaves (not yet served)

How the CA above reaches `cw-egress`, and how its front door gets leaves
(#4001 N2). `cw-egress` holds only leaves and their keys, never a CA key or a
credential, and never serves under a CA it made itself.

- **The CA at admission.** At every `Admit` of a Pod that intercepts, bound
  or not, orchestration calls the credential service's
  `EnsureInterceptionCa` with its relay identity, for the Pod `Admit`
  authenticated. It returns the certificate, which
  `AdmitResponse.ca_certificate_der` carries and `cw-egress` sends unchanged
  as the stream's trust frame, so a later bind changes nothing the guest
  sees. A bound Pod intercepts when its binding recorded that at its first
  bind (C5); an unbound warm member when the switch is on, as its first bind
  will record. Until the binding stores that decision (#5496), a bound Pod
  is decided by the switch too. The field is empty only for a Pod that does
  not intercept. An
  intercepting Pod whose CA can't be had is refused `UNAVAILABLE`, never
  admitted with an empty frame: the guest keeps its first session's trust
  for the Pod's life (#5006), so an empty one would refuse every later
  session that carries the CA. It redials instead, and `cw-egress` likewise
  refuses a stream whose certificate the frame cannot carry. `EnsureInterceptionCa` is the one method that takes
  orchestration's relay token alone; every other method still demands the
  whole chain below. It is rate-limited per caller (the relay Pod) and per
  Pod, since the Pod check's API reads cost even when the Pod is real
  (cw-security, #5071).
- **Where.** Both methods are on `broker.v1.CredentialBrokerService`, served
  only on the credential service's private TLS listener.
- **Asking for leaves.** `cw-egress`'s half of the node calls
  `EgressService.SignInterceptionLeaves` with the Pod and the front door's
  P-256 public key, and nothing that names a host. Orchestration
  authenticates the caller as every `EgressService` method does: a bound Pod
  on the caller's node, with interception on. It then asks the credential
  service through that Pod's current relay epoch, authenticated exactly as a
  front-door stream is: the relay token, the Pod's workspace authorization,
  then the epoch's handle. So the environment and Pod UID come only from that
  authentication, and orchestration's own identity alone gets no leaf. Before
  the epoch is admitted, the call answers `UNAVAILABLE`. `cw-egress` asks once
  the guest's self-check passes, and relays only a P-256 key: any other key
  fails the pair's start at the node. It installs every leaf of an answer at
  once and asks again at `renew_at_unix`. A failed ask or a refused install
  is retried after 5 seconds, doubling to a minute, never past the end of
  the leaves installed; a `renew_at_unix` already past or more than an hour
  ahead is retried the same way, never slept on. Until a set is installed,
  the front door's hosts fail closed, and the asking ends with the pair.
- **Which hosts.** Only those in Codewire's interceptable-host table that
  the route of a credential this session is authorized for reaches; a caller
  cannot name one. A session with no such credential, and so an unbound Pod,
  gets none. Suffix wildcards stay refused until the table carries suffix
  bindings. The key must be a P-256 public key.
- **Lifetime.** A leaf ends with its epoch, after an hour, or with its CA,
  whichever comes first. `renew_at_unix` is its half-life. A rebind reissues
  the leaves on the next call. One live set per Pod, epoch, key and host set:
  a repeated call returns that set until `renew_at_unix`, and a grant that
  changes mid-epoch gets a new one at once.
- **Rates.** Per Pod, each limit is 10 calls per 60 seconds; per relay Pod,
  which every Sandbox admission on that orchestration replica shares, 600, so
  a burst of starts fits. Each is held in memory by each credential-service
  replica, so the effective bound is the replica count (two) times that. Shared limits replace them if replicas grow past a
  handful (cw-security, #4001).
- **Records.** Each issuance records the Pod UID, the key's SHA-256
  fingerprint, the hosts and the expiry, and nothing secret.
- **Failing closed.** A signer that cannot issue answers `UNAVAILABLE`, and
  `cw-egress` refuses those hosts with the reason `interception_unavailable`.

### Provider matrix

| Provider | Operations |
|---|---|
| Codex/OpenAI | ChatGPT OAuth and OpenAI API key, the transparent route: every API request, streaming, account header, serialized refresh/recovery and bounded early-401 retry |
| GitHub | OAuth enrollment, protected HTTPS clone/fetch/push, stock gh API/repository/issue/PR workflows through admitted routes |
| Anthropic | API key, Claude subscription token or Claude sign-in (refreshed by the broker), the transparent route: every Claude Code API request, including enterprise accounts using the same API |
| SSH | Ed25519 generation, standard Ed25519/RSA OpenSSH import, initial private checkout, ssh/scp/sftp/Git-over-SSH |

A Codex sign-in's request, or its WebSocket handshake through the front door,
that the provider answers with 401 forces one refresh and one resend only of a
sign-in last refreshed ten minutes ago or more, by the time stored with the
sign-in, as for a Claude sign-in (#4974): a process in the environment shapes
the request, and every forced exchange rotates the refresh token. The 401 of a
sign-in refreshed more recently is returned as it is, and so is the provider's
401 when the forced refresh fails.
A retry Codewire refuses to lease again, or whose refresh the authority
refuses to begin, is Codewire's denial of the request, as on the Claude route.

av-credential-proxy provides injection and redaction (and GitHub's closed HTTP
policy); Codewire owns the transparent routes and authorization, storage,
refresh, transport and lifecycle. Unsupported hosts and protocols fail closed. The Claude
subscription token is Claude Code's documented `CLAUDE_CODE_OAUTH_TOKEN` login,
proxied like an API key, and the Claude sign-in is Claude Code's own claude.ai
login, refreshed by the broker and delivered as a
[direct delivery exception](#direct-delivery-exceptions). The sign-in token the
route injects carries every scope the sign-in granted (`user:profile`,
`user:sessions:claude_code`, `user:mcp_servers`, `user:file_upload` and
`user:plugins` besides `user:inference`), and the route admits any
`api.anthropic.com` path, so a Sandbox process reaches the whole claude.ai
account through the route, not only inference, as the transparent route
intends. There is no other
subscription-OAuth workaround or raw provider fallback.

### Direct delivery exceptions

Provider material stays behind the proxy, signer or executor wherever they
work. Delivering provider material into a Sandbox is allowed only where the
proxy cannot work, with owner approval, listed here with its reason, and cited
at the delivering code. This table is the complete list.

| Delivered | Where | Why | Readable by | Revocation | Never delivered |
|---|---|---|---|---|---|
| The environment creator's own personal Codex ChatGPT access token, ID token and account ID, with the non-empty placeholder refresh token `codewire-managed-no-refresh-token` | Codex's `auth.json` (mode 0600): `~/.codex/auth.json` in a hosted Sandbox, written by the workspace daemon; in the creator's own local VM, Codewire's native Codex home (`/run/codewire-agent/codex/auth.json`), written by the guest daemon for the workload user | Codex enables `/usage`, analytics and account routing only with its own ChatGPT login and has no hook for a login held elsewhere, so the proxy cannot provide them | Every process in the Sandbox or VM, the creator, org owners/admins of a hosted Sandbox and anyone granted terminal access | Delivery stops at the next check. Codewire deletes its `auth.json` within 2 minutes when the broker denies delivery, and within about 14 minutes when the environment loses credential authority entirely (the first failed check within 2 minutes, then 10 minutes of failed checks, then the next check within 2 minutes). A stopped local VM keeps it on its state disk until its next boot, which removes it unless that boot's writer keeps it, and always when the disk boots as another environment. A VM checkpoint of the local VM holds it in the guest's memory until the provider's expiry; it stays on the creator's host and is never exported (owner, 2026-10-25). The token stays valid at the provider until its `exp` | The refresh token, API keys, GitHub and SSH material, organization-owned credentials, another user's login, and a login for any local VM but the creator's own |
| The environment creator's own personal Claude sign-in access token, with its expiry, its scopes (exactly `user:inference`, `user:profile`, `user:sessions:claude_code`, `user:mcp_servers`, `user:file_upload` and `user:plugins`, the scopes of Claude Code's own login; a stored scope beyond them is never delivered), plan and tier, and a per-delivery placeholder refresh token `codewire-managed-no-refresh-token-<nonce>` | `claudeAiOauth` in `~/.claude/.credentials.json` (mode 0600), other keys kept: in a hosted Sandbox, merged into the file by the workspace daemon; in the creator's own local VM, in the workload user's home, by the guest daemon | Claude Code shows `/usage` and the plan only with its own claude.ai login; the proxy cannot answer those calls. In a hosted Sandbox they were observed going straight to `api.anthropic.com` while `ANTHROPIC_BASE_URL` was set. That does not hold everywhere: in a local VM with this delivery the usage view was reported failing while `ANTHROPIC_BASE_URL` pointed at the host broker (#4877, owner, 2026-11-15; cause not confirmed), and with only a token variable and a custom `ANTHROPIC_BASE_URL`, Claude Code 2.1.309 on a host labelled the session "Claude API" and requested neither `/api/oauth/usage` nor `/api/oauth/profile` from that base URL (#4877). The front door (#3999) removes the base URL for agents | Every process in the Sandbox or VM, the creator, org owners and admins of a hosted Sandbox, and anyone granted terminal access | Delivery stops at the next check. Codewire removes its `claudeAiOauth` within 2 minutes when the broker denies delivery, and within about 14 minutes when the environment loses credential authority (as for Codex). A stopped local VM keeps it on its state disk until its next boot, which removes it unless that boot's writer keeps it, and always when the disk boots as another environment. A VM checkpoint of the local VM holds it in the guest's memory until `expiresAt`; it stays on the creator's host and is never exported (owner, 2026-10-25). The token stays valid at the provider until `expiresAt` (about 8 hours) | The refresh token, Claude setup tokens, API keys, GitHub and SSH material, organization-owned credentials, another user's login, and a login for any local VM but the creator's own |

The broker delivers the login only when all of these hold: the environment
is a hosted Sandbox, or a local VM whose platform delegation is authenticated
by the creator's own OAuth login (`sub` equals the VM's pinned creator; never
a `cw_` API key) and selected a profile; its Codex selection comes from the
creator's own profile (for a hosted Sandbox, one whose personal-owner consent
the creator confirmed; for a local VM, the creator's personal platform
profile); the Codex grant carries its
dedicated `codex-login` permission; and the credential is the creator's own
Active ChatGPT (OAuth) login, not an API key and not one that needs Reconnect.
Organizations never hold OAuth logins. The broker checks this around every
material read, again after any refresh, and before sealing. It refreshes first
unless the access token stays valid for 30 minutes (capped at half the token's
lifetime), through the same serialized refresh proxied requests use. It seals
the login to a fresh recipient key the daemon holds, bound to the environment,
its generation, the request, the recipient, a deadline of at most 30 seconds
and the exact credential version; the sealed format has no refresh-token
field. Orchestration's credential relay passes on only ciphertext. The daemon
asks only on a bridge epoch whose broker advertised `codex-login`, which the
relay copies into the epoch's Open, so a broker that does not serve it never
receives the request.

The broker delivers the Claude login under the same conditions, with the
Anthropic slot in place of the Codex slot: a hosted Sandbox, or the creator's
own local VM through its platform delegation as above; an Anthropic selection
from the creator's own personal platform profile (for a hosted Sandbox, one
whose personal-owner consent the creator confirmed) or, for a local VM, from
its selected local profile as for Codex (#4714); the Anthropic grant's
dedicated `claude-login` permission;
and the creator's own Active Claude sign-in, never an Anthropic API key, a
Claude subscription token (`claude setup-token`) or one that needs Reconnect.
It refreshes, checks and seals exactly as for Codex, through the sign-in's own
rotation journal; the sealed format carries the access token, its expiry, the
granted scopes, the plan, the rate-limit tier and the refresh time, and has no
refresh-token field. The daemon asks only on an epoch whose broker advertised
`claude-login`.

The delivered access token is a bearer token for the creator's ChatGPT or
Claude account. Whoever reads it can use it from anywhere, not only through
the agent in this Sandbox, until it expires (about 8 hours for Claude). A
Sandbox others can open still receives the creator's login: every process in
the Sandbox, and anyone with terminal access, can read the token, and use it
from anywhere until it expires. Delivery does not depend on who else has
access. The Claude token carries all six of Claude Code's own login scopes, so
Claude Code in a Sandbox behaves like the creator's own login.

A local VM's delivered login lives on the VM's state disk: a stopped VM keeps
it until its next boot or its expiry (about 8 hours for Claude), and any copy of
that disk carries it too. At every boot the daemon removes Codewire's Codex and
Claude logins that no writer keeps for that boot and owner, whatever the reason:
the agent is not selected, there is no bridge, or the home is of another
placement. The guest also records which environment the disk last booted as
(`/state/codewire/login-environment`); when a disk boots as another
environment, such as a copy, it removes both before any writer or workload runs,
so a copy never serves the source's login, not even while a writer would keep
it. Each removal recognises only a file Codewire wrote; the user's own logins
stay. Whoever holds the creator's saved `cw` login on the host
can obtain the token, as they already can by creating a hosted Sandbox.

A local disk snapshot (`cw snapshot create`, on Linux or a Mac) is a durable
copy of a stopped VM's disks, so it must never hold a delivered login. It holds
copies of the VM's state disk (`/workspace`, the workload user's home,
Codewire's native Codex home), its Docker data disk and its active image root;
never the seed, the host-side SSH host key, any Mesh state, or a Mac VM's
helper configuration and machine identifier. Capture clears its private copy of
the state disk, never the source, with e2fsprogs confined to that one copy: on
Linux the host's, under Landlock and seccomp; on a Mac the local VM runtime's
pinned build, admitted and re-hashed before each use, under a deny-default
Seatbelt profile. Capture finds every program it needs before it copies
anything:

- a settling `e2fsck -f -p` first, which also replays a journal a forced stop
  left, so no later replay can undo a removal;
- in the native Codex home, `auth.json`, and in the home's `.claude`,
  `.credentials.json`, each removed when it is Codewire's by the daemon's own
  rules (the same functions the daemon removes by): Codex's in ChatGPT mode
  with the refresh token `codewire-managed-no-refresh-token`; Claude Code's
  with the refresh token `codewire-managed-no-refresh-token-` and its
  32-character nonce, or an empty refresh token beside the `codewireManaged`
  marker (Claude Code's copy once Codewire's login was refused);
- beside each, the daemon's temporaries (`.auth.json.codewire.*` and
  `.credentials.json.codewire.*`): a write in progress (`.new`) removed
  unread, any other removed when it holds Codewire's login;
- each removed file's blocks are zeroed first; every debugfs call fails the
  capture on any error it reports, and a path is taken as absent only from its
  parent's own listing;
- a second settling `e2fsck -f -p`, then every free range in the block bitmaps
  is punched out of the copy (`FALLOC_FL_PUNCH_HOLE` on Linux, `F_PUNCHHOLE`
  on a Mac, which refuses a range that is not whole blocks of the host
  filesystem), and so is every unwritten extent and every block past a file's
  end (the guest reads neither), and samples of each range are read back as
  zeros, so a token an earlier rewrite or deletion left in a freed block, even
  one since given to another file without being written, is gone too. Every
  file is read from one confined debugfs session, which must answer each
  in-use inode exactly once; a file mapped by indirect blocks is handled as
  one mapped by extents. An fs-verity file keeps its Merkle tree and
  descriptor from its size rounded up to 64 KiB, where ext4 puts them and the
  kernel reads them to verify every page; its blocks between its end and
  there, and its unwritten extents, are punched like any file's.

Punching changes only the copy. Where the copy is a clone (btrfs, XFS,
APFS), the source VM's disk keeps its own blocks, and blocks the host frees
keep their data until reused, protected only by the host's disk encryption
(FileVault on a Mac).

A recognised Claude Code store is removed whole: any other member Claude Code
kept in it, such as an MCP sign-in, is not in the snapshot. The user's own
logins, and anything else the VM wrote (a `.env` file, shell history, the
command lines of its sessions), stay in the snapshot, which is private to the
creator on that host. A snapshot that cannot be cleared is not kept. An
environment created from a snapshot boots as a new environment: the guest
clears both agents' Codewire logins at its first boot, before any writer or
workload runs, and the new environment's own selection delivers a fresh login
under its own authority. Its credential profile and sources are resolved again
from its own create request. Capture records the platform account the `cw` is
signed in to (server, organization and user), read from its saved login
alone, or none when that cannot tell (an API key, a server override, no saved
login); a create from the snapshot is refused when both it and the snapshot
record an account and the two differ. This guards against an accidental
mix-up of accounts on one host; it is not an authorization boundary: the
supervisor's socket is the owner's alone, and the client supplies the account.
`cw login` and `cw setup` keep the verified account in `account.json` beside
the platform config: they remove the old record before saving the new login,
then write the new one atomically, so a failed login leaves no account rather
than another user's. A value the supervisor would refuse (empty, over 256
characters, surrounding space or a control character) records no account. A
login saved before this record existed records no account until the next
`cw login`, and a re-login with an older `cw`, which does not know the file,
can leave a stale one beside the new login; `cw logout` removes it.

A hosted disk snapshot (`cw --cloud snapshot create`) is a kept copy of a
stopped hosted environment's workspace volume, private to its creator. Capture
never edits the source. It restores a raw snapshot of the volume into a clearing
Sandbox, a Kata VM with no network, credentials, service-account token or
binding, whose only process is a fixed `cw` command. That command recognises
Codewire's files by the daemon's own rules, as local capture does: in `~/.codex`,
`auth.json` and `.auth.json.codewire.*`; in `~/.claude`, `.credentials.json` and
`.credentials.json.codewire.*`. Each is overwritten with zeros, flushed, then
unlinked, and a recognised Claude Code store goes whole. It also unlinks, without
zeroing, the source's sessions (`~/.codewire/daemon/sessions`, with their command
lines and output), managed agents' books and temporary files (`~/.codewire/tmp`,
where a Block workspace keeps `/tmp` and `/var/tmp`). A symbolic link at any of those paths,
or at an agent's home, and a login file over 1 MiB, fail the capture: the daemon
delivers through neither, but clearing can't show that nothing is there. Any error
fails the capture, and the capture then deletes the raw snapshot, the clearing
volume and anything else it made, retrying until they are gone. Only after the
clearing Pod is gone is the kept snapshot taken. Only the environment's creator may
capture it, because the exception below assumes the snapshotter owns the
credentials on the disk.

`cw --cloud create --snapshot` makes a new environment from a kept snapshot, and
only the snapshot's creator may. Its disk is restored from the snapshot, its guest
starts identity-free and binds as any cold create does, so its environment id,
daemon token and Mesh node are its own, and its credential profile and sources
come from its own create request. Before any login writer starts, a bound hosted
daemon reads the environment id recorded in `~/.codewire/login-environment`. When
that isn't its own, it removes both agents' Codewire logins by the daemon's own
rules, as a local guest does at its first boot as another environment, then records
its id. The environment's own selection delivers fresh logins under its own
authority.

**Exception, owner, 2026-10-30 (#3046):** unlike local capture, which punches every
free range, hosted capture clears the current token files only, so an older copy
of a delivered token that an earlier rewrite left in a free block of the volume
stays in the kept snapshot and in every environment made from it, and so may the
blocks of the unlinked sessions and books. The owner's
reason: "if someone's snapshotting something, then they should expect for those
credentials to be in it. I don't think that we need to spend, like, super long
time to zero it out." This holds because of three properties, and a change to any
of them reopens the decision:

- a guest reaches a commodity volume only over virtio-fs, as files, so it can't
  read a free block;
- the snapshot stays on its volume's own LUKS key at rest, private to its creator
  (its fork shares that key);
- no copy of it leaves as raw blocks: the planned R2 copy copies files, and block
  backups (#2238) aren't enabled for it.

A left-over copy stays valid at the provider until it expires: about 8 hours for
Claude. OpenAI publishes no lifetime for the Codex token. One measured token lived
10 days (`exp - iat` = 864000 s), read on 2026-10-31 from a workstation Codex CLI
sign-in whose file was last written on 2026-10-24. It was not a Codewire-delivered
token, whose lifetime may differ, so the code reads each token's own `exp` rather
than assuming one. Neither is shortened by this path.
Confidential environments are never snapshotted.

A Block workspace volume (#3718), which the guest formats and reads block by
block, breaks the first of those properties, so the exception does not apply to
it. Its raw snapshot records the source's volume mode, and its restore reaches
the clearing VM as a device. Inside that VM, never on the host, the clearing
command settles the filesystem with `e2fsck -f -p`, clears its files by the
rules above through `debugfs` on the unmounted device (zeroing each removed
login's blocks and proving each removal from its directory's listing; a symbolic
link at an agent's home, at a login or on the way to a cleared tree fails the
capture, as does a name in a cleared tree holding `"`, `\`, a control character
or bytes that are not UTF-8, which `debugfs` can't be handed back, and a cleared
tree of more than 100,000 entries), settles it again, and then wipes every block a guest cannot read through the filesystem:
each free range, and each file's unwritten extents and blocks past its end. A range
is discarded, and its discard proven by canaries written over its first and last
aligned granule beforehand. A range whose canary survives, a range too small to
hold a whole granule, a range's unaligned edges and a device that takes no
discard are overwritten with zeros instead, and every byte written is read back
from the device as zeros. Nothing mounts the device, so the container holds no
`SYS_ADMIN` (#4013). An `e2fsck` that cannot fix the filesystem without asking,
a removal that can't be proven, and any wipe or read-back failure fail the
capture; nothing is retried
with `e2fsck -y`. The Filesystem path, and with it the exception, goes when the
virtio-fs workspace path is removed at the Block cutover.

A VM checkpoint (`cw checkpoint create`, Linux) is a running local VM's
memory, device state and disks at one instant. Memory cannot be cleared the
way a disk copy is, so a checkpoint may hold the creator's own delivered Codex
or Claude Code sign-in: in the daemon's memory, in the page cache of its
files and in any agent process that read it. The owner accepted that on
2026-10-25: a checkpoint holds it until the provider's expiry (about 8 hours
for Claude), is private to the creator, stays on the creator's host
(`locations` is always `local`) and is never exported. Its disk half is not
scrubbed either: the memory refers to the disks exactly as they were. When a
checkpoint is restored or forked, the guest resumes with its workload frozen,
reseeds its RNG with host entropy, and moves to the new boot's identity before
anything runs: the daemon's token and credential bridge identity, the network
key and the machine-id are re-keyed, every connection admitted with the old
token ends, and the old token is refused. A fork is a new environment: before
it thaws, the guest removes Codewire-written logins, as a disk's first boot as
another environment does, and the fork's own selection delivers fresh ones
under its own authority. An in-place restore keeps its environment's logins,
and the writer rechecks them under the new generation. Agent processes that
were running at capture keep the copy they held until it expires. The
manifest records only references and hashes, never resolved values.

The platform broker admits a local VM's login for any delegation
authenticated by the creator's own OAuth login (`oauth_bearer_only`; never a
`cw_` API key) that selected the creator's personal profile: the platform
cannot tell which process holds that login. That the login reaches only the
creator's own VM is enforced by the host's `cw`, which opens a VM's
delegation only with the saved OAuth login whose `sub` is the VM's pinned
creator, never with an API key. The host's broker lists both logins on the
VM's bridge epoch and passes each request through that delegation to the
platform broker. The VM's guest daemon (root) writes Codex's login in
Codewire's native Codex home and Claude Code's in the workload user's
`~/.claude/.credentials.json`, giving every file it creates to that user
before anything is written, and only ever reading or replacing that user's
files. A local profile serves the store owner's own Codex sign-in and Claude
sign-in: the local authority admits each only as the owner's Active login in
its slot (Codex, Anthropic) of the VM's selected local profile, and the local
broker checks the same again before leasing it
(`codewire-local-credentials` `broker_channel/login.rs`).

The workspace daemon writer follows these rules for
the files it owns:

- Your own login wins. An `auth.json` whose refresh token is not Codewire's
  placeholder is never touched.
- `codex logout` stays logged out until Codex is re-selected or the Sandbox
  restarts.
- While Codex is selected, Codewire's `config.toml` is always there and
  sets `sandbox_mode = "danger-full-access"`, so Codex started any way
  (`cw run codex`, `cw exec … codex`, a shell) runs without its own inner
  sandbox: the environment is the boundary, as for managed Codex, and Codex's
  sandbox would otherwise deny the SSH agent socket and the network (#4956).
  So the agent can sign with the SSH agent (for example, to push) and reach
  what the network policy allows, as any process in the environment can.
  It leaves `approval_policy` at Codex's default, so a person in Codex's
  terminal UI keeps its approval prompts; managed Codex's `never` stays in
  its own launch. Codex flags such as `--sandbox` still override the file.
- When no login is delivered, the same file also names the proxy as Codex's
  provider; with a delivered login it holds only the sandbox line, so Codex
  uses its built-in provider. Codewire owns that file only while its first
  line is `# Managed by Codewire. Delete this line to manage this file
  yourself.`
- A denied delivery (an API key, a credential needing Reconnect, a revoked or
  organization-owned credential, Codex not selected) removes Codewire's
  `auth.json` at the next check, within 2 minutes.
- When the whole runtime loses credential authority (the creator leaves the
  organization, consent is withdrawn, the environment stops running), the
  broker ends each bridge epoch instead of answering, so the daemon sees only
  unavailability. It therefore deletes Codewire's `auth.json` after 10 minutes
  of failed checks while the bridge keeps failing, about 14 minutes at most
  after authority is lost (the first failed check comes within 2 minutes and
  the removing one within 2 minutes after the 10), and at once when the
  delivered token has expired. A brief unavailability changes nothing.
- A crash or revocation in the middle of a write can leave a temporary copy
  beside the file. The daemon removes such Codewire temporaries when it
  starts; a file set aside because it was yours stays.

For Claude Code's `~/.claude/.credentials.json` the writer applies the same
rules to `claudeAiOauth`:

- Codewire's part of the file is `claudeAiOauth` and a top-level
  `codewireManaged` marker. Every other key in the file (for example
  `mcpOAuth`) is read and kept; the file is replaced atomically with mode
  0600, never through a symlink.
- Your own login wins. A `claudeAiOauth` whose refresh token is not
  Codewire's placeholder (after `claude /login` in the Sandbox, for example)
  is never touched.
- Each newly delivered token gets a new placeholder nonce, because Claude Code
  remembers a refused refresh token for the life of its process. Claude Code
  refreshes on its own within 5 minutes of `expiresAt`, or when Anthropic
  answers one of its own account calls (profile, settings, `/usage`) with
  401. Every delivered token keeps at least about 25 minutes of life and is a
  token Anthropic accepts, so while delivery works it never tries the
  placeholder. If it does, that refresh fails and Claude Code clears its own
  copy; the next delivery restores it. Claude Code rereads the file when it
  changes, so a running session picks up a rotated token without a restart.
  After clearing its own copy, the first request it builds from the restored
  file can still lack the OAuth beta header; the managed route adds that
  header, so inference is unaffected.
- `/logout` (which deletes `claudeAiOauth`) stays logged out until Claude is
  re-selected or the Sandbox restarts.
- A denied delivery (an API key, a setup token, a credential needing
  Reconnect, a revoked credential, Claude not selected in its sign-in form)
  removes Codewire's `claudeAiOauth` at the next check, within 2 minutes, and
  the same lapse, expiry and leftover rules as for Codex apply.
- The broker delivers only the six scopes above. If a refresh ever stores a
  scope beyond them, delivery is denied (and Codewire's login removed) until
  that is reviewed.

A Claude sign-in selects the Anthropic client's sign-in form, which projects
`ANTHROPIC_BASE_URL` only; `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY` and
`ANTHROPIC_AUTH_TOKEN` are reserved and removed, because they would outrank
the delivered login. Inference still goes through the managed route, where the
broker replaces the guest's bearer with the same or a fresher token.

### Accepted exception: the README download URL token

The direct delivery exceptions above list provider material that Codewire
holds. This one is different: a value GitHub mints, which reaches a Sandbox
through an admitted GitHub API request. It is accepted so that plain
`gh repo view` works.

- **What:** `GET /repos/{owner}/{repo}/readme` on `api.github.com`, GET only and
  with no query (no other ref or directory), is admitted for stock `gh`. For a
  private repository GitHub's answer includes a `download_url` carrying a
  short-lived token that GitHub minted for that one file. Anyone holding the URL
  can download that file from anywhere until the token expires.
- **How it arrives:** in the README response body, through the GitHub API
  route. The broker does not rewrite response bodies; it redacts only the
  credential it injected (the owner's GitHub login), which never appears.
- **Why it is accepted:** the token reads only that one file, which the
  checkout already holds through Git, and it expires quickly. It grants
  nothing else: no other file, no write, no other repository, and not the
  owner's login.
- **Nowhere else:** no other admitted route returns such a token. The contents
  API is not admitted, and the pull request files listing returns `raw_url`
  and `contents_url`, which carry none. Whether GraphQL (admitted as one
  family) or an HTML body media type exposes signed attachment URLs has not
  been checked.

The policy entries in the credential-bridge ingress classifier and the
broker's GitHub grammar cite this section.

### Actions reads and the one redirect the broker follows

An agent reads why a check failed with `gh run list` and `gh run view --log`
(#5737). A job's log is repository data the agent may read; nothing here
writes.

- **What is admitted:** GET only, on any repository the GitHub connection
  reaches, as the pull request paths are: a repository's workflow runs, one
  run, its jobs and an attempt's jobs, one job, its workflows and one
  workflow, a check run's annotations, and the two log downloads (one job's
  log and one run's logs). No re-run, cancel, dispatch, artifact, cache,
  secret or variable path. The query names `gh` sends for runs (`branch`,
  `event`, `status`, `actor`, `created`, `head_sha`, `exclude_pull_requests`
  and `filter`) join the existing bounded list.
- **The log redirect.** GitHub answers both log downloads with a 302 to a
  short-lived signed URL on another host. Anyone holding that URL can read
  the log until it expires, so it is a credential, and it never reaches the
  guest. The broker follows that one redirect itself:
  - only from a 3xx answer to GET on the two log paths, and only once: a
    redirect from the second request is refused;
  - only to `https` on port 443 with no userinfo, to a host matched exactly
    from a fixed list of GitHub's log hosts. Azure blob storage hosts are
    listed by their exact account names, the ones GitHub was seen
    redirecting to, never by a pattern or the `blob.core.windows.net`
    suffix: account names are first-come, so a pattern would accept an
    account anyone can register. A same-shape name outside the list is
    refused, and a test pins that;
  - as a fresh GET carrying no credential, cookie or header from the guest or
    the first request, through the same client, with its address resolved,
    classified and pinned per request as the first hop's are, and with its
    own deadline;
  - streaming the body back under the existing response cap and redaction.
    The guest gets the body, the final status, and `Content-Type` and
    `Content-Length` only, never `Location` or the signed URL, in a
    response, an error or a log line. The signed URL's query is never
    logged or put in a trace.
- **Where it needs egress.** On a computer, the broker dials the log hosts
  from the host. A hosted credential service needs egress that names those
  hosts, since Azure's address ranges move.
- **The App permission:** `actions`: read, accepted once by each
  installation's owner, as above. The daily permission check expects it from
  the change that asks for it.
- **The rollout:** this spec and journey, then the broker code with its
  tests, then the daily check's new set, then the App's new permission at
  GitHub, then the walk on a local VM and a hosted Sandbox.

### A refresh the provider rate-limited

A refresh the provider answered 429, whose whole response was read within the
bound, was not processed: the sign-in keeps its refresh token and stays usable
while its access token lasts, and its next refresh waits for the provider's
`Retry-After`, at least one minute and at most ten. A refresh refused again
after such a wait, a 5xx, a timeout, a dropped connection or a response not
read in full stays uncertain and terminal, and the old refresh token is never
sent again (owner, 2026-11-18, #4975). This holds for a Codex sign-in, a Claude
sign-in and a GitHub App login, on demand and in the keep-alive, in both
placements.

- A 429 means the provider limited the request rather than processing it, and
  a response read in full rules out the transport doubt that makes the other
  failures unknown. If a provider did rotate the token and still answered
  429, the refresh after the wait sends a used refresh token, the provider
  refuses it, and the sign-in reads **Reconnect needed**: today's outcome, one
  step later. That is why one wait is allowed and any failure after it is
  terminal.
- The started refresh is closed by its exact attempt as rate-limited, with
  the time its wait ends: in the local authority's refresh journal, and on
  the platform as a `rate_limited` attempt. That record is the sign-in's, so
  every broker that serves it, and one that restarted, waits the same, and
  the refresh after the wait is the one retry: any failure of it, a second
  429 included, is terminal. A retry cancelled or lapsed before it started
  leaves the next refresh the retry; so does a revoke that fenced the waiting
  attempt and did not complete, which ends the wait early.
- While the sign-in waits, a request whose access token has not expired is
  sent with that token. One whose token has expired is answered 429 with the
  time left as `Retry-After`, saying the provider is rate-limiting Codewire's
  refresh of the sign-in; it is not **Reconnect needed**.
- No 429 is provoked to test this, since that means flooding a provider's
  token endpoint with a real sign-in. The broker logs
  `refresh_rate_limited`, with no value, and the outcome of the refresh after
  the wait; that record on Dev and Production is how it is observed (owner,
  2026-11-18, #4975).

**Not yet built** (#4975). Today a 429 is terminal like any other failure
after the refresh started.

### Idle OAuth keep-alive

The broker refreshes OAuth material on demand only when a request finds its
access token about to expire, so an unused connection could outlive its
refresh token. Credential-service therefore also keeps idle rotating OAuth
credentials alive. Every 30 minutes (jittered by a quarter either way) it
selects, without reading material, active and unexpired OAuth credentials of a
live owner that have no live reservation and no started, staged or unknown
refresh attempt.
It then reads each candidate's protected material once per exact version and
refreshes it when the material's own refresh time is older than the provider's
keep-alive age: 7 days for Codex (inside Codex CLI's own 8-day `last_refresh`
habit), 30 days for an expiring GitHub App user token (GitHub refresh tokens
last six months), and for a Claude sign-in the earlier of 7 days and half of
the refresh token's lifetime when Claude reports one (it publishes none).
Non-expiring GitHub tokens are never touched. A Claude subscription token,
which has no refresh, is a different credential kind from a Claude sign-in and
is never selected or read. A sign-in whose refresh token has already expired is
never sent. A sweep reads at most 32 materials and starts at most 8 refreshes,
2 seconds apart.

A keep-alive refresh is an ordinary durable refresh: the same journal,
provider exchange, rotated-material validation, publication and closed
failure logging as on demand. PostgreSQL serializes it with other replicas and
with on-demand refresh, so a credential is never refreshed twice. Any failure
after Start is terminal exactly as on demand, except a rate limit, as on
demand ([A refresh the provider rate-limited](#a-refresh-the-provider-rate-limited)),
and Settings → Credentials then shows the credential as **Reconnect needed**
with its Reconnect action on the row. Shutdown stops new selection and waits for a started refresh to finish.
No material, token or provider response is logged; each sweep that does work
logs only counts.

Optional credential-service inputs, absent by default:

- `CREDENTIAL_OAUTH_KEEPALIVE_ENABLED`: `true` (default) or `false`.
- `CREDENTIAL_OAUTH_KEEPALIVE_INTERVAL_SECONDS`: 10 to 86400; default 1800.
- `CREDENTIAL_OAUTH_KEEPALIVE_CODEX_AGE_SECONDS`: 60 to 691200 (8 days);
  default 604800.
- `CREDENTIAL_OAUTH_KEEPALIVE_GITHUB_AGE_SECONDS`: 60 to 7776000 (90 days);
  default 2592000.
- `CREDENTIAL_OAUTH_KEEPALIVE_CLAUDE_AGE_SECONDS`: 60 to 691200 (8 days);
  default 604800.
- `CREDENTIAL_HOSTED_PLACEHOLDERS_ENABLED`: `true` or `false` (default); see
  [Per-environment placeholders](#per-environment-placeholders).

A present value must be a plain decimal in range, even when disabled; anything
else stops startup. Short values are for local observation only. The Kind
credential fixture reads the same inputs; its defaults never touch the gate's
freshly enrolled credentials.

For initial checkout into a local environment, a platform GitHub profile keeps
its OAuth credential on the platform. The local Git helper receives only a
short-lived capability for that one repository. The checkout uses the same
environment ID that creation will record; cancelling it discards its output.
The shared platform bridge limits each HTTP response to 256 MiB, so larger pack
responses fail closed. This is distinct from the local bundle-size limit.

A profile configures only its selected provider clients. The local VM also keeps
its existing fixed Codex home for skills and session history, even without a
profile. That directory is not a credential: provider configuration is installed
only when Codex is selected and removed when it is cleared. Native `CODEX_HOME`
is runtime-owned; other unselected provider settings remain ordinary values.

### Managed agents

A managed agent (`cw run --in ENV --agent codex` or `--agent claude`) runs in the
session environment an interactive terminal gets, from the same builder: the
GitHub route (`GIT_CONFIG_*`) and stock `gh` (`GH_TOKEN`, `GH_CONFIG_DIR`),
the SSH signer (`SSH_AUTH_SOCK`), the selected provider variables, and your `HOME`, `PATH` and declared environment. Git
therefore works for it as it does for you, over HTTPS and over SSH, with your
Git identity and `known_hosts`. Nothing is cleared, and it has no credential
route of its own.

It also receives the application-secret environment projection, exactly as a
session you start does, on a hosted Sandbox and a local VM alike. The daemon
starts the agent's driver through the same launcher as every session; that
launcher asks for the projection, with the full authority check, for this one
launch, and the driver, its guardian and the agent inherit the result. No
selected source means nothing is added. The projection is evaluated when the
driver starts and again at each managed Restart, never per turn. As for a
long-running shell, a changed secret value reaches the agent at its next launch
and the running one keeps what it inherited; a changed selection restarts the
Sandbox and ends the conversation's driver. Nothing resolved is stored by
Codewire: the values exist only in the launcher and the processes it becomes,
never in the session record, the driver's records or an argument.

Two consequences follow:

- **A denied, unavailable or late projection fails the managed launch.** The
  agent does not start, and `cw run --agent` or a managed Restart reports the
  failed launch, as starting a terminal session does in the same state. There
  is no fallback to an agent without the values.
- **What the agent prints from those values is kept.** The agent can read
  them, as any process in the Sandbox can. Anything it puts in a reply is
  stored in that reply's message record, which is durable, is kept in the
  Sandbox and is returned by `cw inbox` and the platform API; anything a tool
  it runs prints goes to the session output. A terminal
  transcript holds printed values in the same way. The broker's redaction
  covers provider credentials only, never application secrets.

Only a managed Codex agent's login is locked down, in a hosted Sandbox. It gets
its own private Codex home (`CODEX_HOME`) whose fixed configuration names one
broker route. With a Codex credential in the profile, that is the Codex route
(`/v1`), where the broker adds the ChatGPT sign-in or the API key. Otherwise
it is the OpenAI API-key route (`/_codewire/openai/v1`). The file is
`forced_login_method = "api"` and `cli_auth_credentials_store = "file"`
followed by the provider configuration every placement generates
(`codewire-access::CodexProviderProjection`), byte for byte, and the same
settings are passed again as `-c` overrides. It never reads the
delivered `auth.json`, and no credential reaches its home, arguments or
environment. A local VM applies no lockdown: its managed Codex agent uses the
guest's own Codex home.

A managed Claude agent has no lockdown on any placement. It runs as `claude`
does when you type it in that Sandbox: your `~/.claude` settings, MCP
configuration and permission rules, the repository's project settings, and
the API-key or subscription form the session has. As in your terminal, those
session variables outrank a login saved in the Sandbox (see
[Claude subscription token](#claude-subscription-token)), so by default it
uses the selected credential through the broker. That is a default, not a
guarantee. Your and the repository's Claude settings apply as they do for
`claude` in that Sandbox, so an `env` or `apiKeyHelper` entry there, or a
declared `CLAUDE_CODE_USE_BEDROCK`, can move it to another provider or
credential. No Codewire-held material is involved either way: the Sandbox
holds only the placeholder. On a Sandbox placement it starts with
`--permission-mode auto`; target, not shipped (#5813), it starts with
`--permission-mode bypassPermissions`. See
[CLI-ORCHESTRATION.md](CLI-ORCHESTRATION.md) for what that argument outranks.

### Codex home in hosted Sandboxes

In a hosted Sandbox, Codex's home is Codex's own default, `~/.codex`
(`/home/codewire/.codex`), on the persistent home volume, as on a laptop:
sessions, history and your own settings survive Stop/Start. Codewire keeps no
Kubernetes object for it, and no init container touches it.

Before it listens, the workspace daemon writes Codewire's credential-free
`config.toml` there while Codex is selected (directory 0700, file 0600, never
through a symlink) and removes it when Codex is cleared. The file's first line
is:

```text
# Managed by Codewire. Delete this line to manage this file yourself.
```

Codewire writes, replaces or removes `config.toml` only when it is absent, or
when it is a regular file owned by the daemon's user whose first line is
exactly that header. Delete the line, or write your own file, and Codewire
never touches it again; Codex then uses your configuration. A symlinked
`config.toml` or `~/.codex` is also yours. While Codex is selected,
`CODEX_HOME` is set to the same path, so an image whose user has a different
home still reaches it.

Once it listens, while Codex is selected, the daemon asks the broker for the
creator's login ([Direct delivery exceptions](#direct-delivery-exceptions))
at start and every 2 minutes, sooner with jittered backoff while no bridge
epoch is admitted. It writes a delivered login as Codex's standard ChatGPT
`auth.json` (0600) and replaces Codewire's `config.toml` with one that holds
only the sandbox line (see below), so Codex uses its built-in provider and
talks to chatgpt.com directly; this holds even when
your own login is in `auth.json`, so your login is the one Codex uses. A
denial, an expired login or 10 minutes of bridge failure removes Codewire's
`auth.json` and brings back Codewire's `config.toml` with the provider. `auth.json` is
Codewire's only while it is a regular file of the daemon's user that parses,
has `auth_mode` `chatgpt` and holds exactly the placeholder refresh token;
anything else, including a file Codex is rewriting in place at that moment,
is yours. Every write and removal is relative to `~/.codex` opened without
following a symlink: a new file is created exclusively, synced and renamed
into place, and a removal renames the file aside, checks it is still
Codewire's and puts it back if a concurrent `codex login` replaced it. The
`codex logout` record lives in the container's `/tmp/codewire-codex-login`,
keyed by environment generation and credential, so a restarted daemon keeps
it and a restarted Sandbox or re-selected Codex starts fresh. The daemon logs
only closed states such as `codex_login=Written`, never a token or file
content. Nothing else in `~/.codex` is touched.

A managed Codex agent does not use `~/.codex`; see
[Managed agents](#managed-agents).

Every hosted tier uses the same daemon writer: commodity and confidential
(the daemon runs in the workspace container, which alone mounts the encrypted
disk). A Sandbox created with the earlier memory home converges on its next
start: the per-environment `cw-credential-codex-*` ConfigMap volume, the memory
home and its init copy leave its Pod spec, so the next Pod has none of them and
certifies as current. Destroying the environment removes its old ConfigMap.

SSH signing uses an isolated OpenSSH agent outside the sandbox that holds only
the selected key. The bridge supports bounded identity and sign operations and
rejects key management, unselected keys and unsupported extensions. Host
verification stays on: an unknown host needs public host-key configuration,
and a changed key fails. The public key is shown for registration with the
provider. Private keys are never mounted and ambient agents are never
imported. Revocation blocks new signatures, not established SSH connections.
The signer enforces no repository path, remote command or egress policy.

Initial SSH checkout needs the server's public host key before it can connect.
Platform creation also requires an explicitly selected credential profile with
an SSH key for SSH repositories, including repositories inherited from a
preset, except that a github.com source in an SSH form (`git@github.com:` or
`ssh://git@github.com/`) may instead use the profile's active GitHub
connection. A missing profile, or a profile with neither, is rejected before
creation, so nothing is recorded; ownership, revision and signing still pass
through the existing admission and signer checks. A github.com source needs no
pinned key in any form: GitHub's published keys are built in (see the hosted
initial checkout above). An SSH source at `github.com` on the default port
with no `known_hosts` is canonicalized to exactly those keys
(`codewire_project::canonical_repository_known_hosts`), so
`cw create --repo git@github.com:<owner>/<repository>` works without a
project file; explicit pins are kept as written. Every adapter that requires
already-canonical trust therefore receives GitHub's keys, never an empty list,
for such a source.
For any other SSH host, put that public trust in `codewire.yaml`, alongside the repository; it is not a
secret or another credential profile. Obtain the key through a trusted channel,
not from an unverified first connection. For example, replacing the placeholder
with the verified server public key:

```yaml
repositories:
  - source: git@git.example.com:team/app.git
    destination: /workspace/app
    known_hosts:
      - "git.example.com ssh-ed25519 <server-public-key>"
credentials:
  profile: platform:work
```

Use `cw create --local` or `cw create --cloud` from the directory holding
the file, or a subdirectory of its Git repository; `--file` selects another file.
SSH repository flags alone cannot provide host trust for a host other than
github.com; use the YAML form. Each
line pins that exact source host, or `[host]:port` for a nonstandard port.
Unknown or changed keys fail closed. HTTPS repositories reject `known_hosts`;
neither placement imports the owner's SSH configuration or trust files.

## macOS local storage

`cw secrets --local` and `cw credentials --local` store values on macOS as on
Linux: application secrets, API keys, Claude subscription tokens, SSH import
and generation, and profiles. List and get output stays metadata only.
`connect codex|github --local` works on macOS as on Linux: the native device
login writes no file, so it needs no private tmpfs, and the tokens go straight
to the selected store (the login Keychain or the file store).

macOS local VMs consume local sources and profiles as on Linux: the selected
application secrets reach launches through the sealed environment projection,
the per-generation broker proxies the selected HTTP providers, the authority
signs for a selected SSH key, and the repository executor checks out SSH
(and GitHub HTTPS) repositories on the Mac. Platform sources and profiles
use the same platform-to-local delegation, with the broker as a relay.

On macOS the SSH signer and the repository executor run Apple's OpenSSH and
`/usr/bin/git` with these differences from Linux:

- Each signature's agent stages in `signer` inside the credential root
  (macOS has no per-user tmpfs). Its 0700 directory holds only the agent
  socket and the passphrase FIFO: the key reaches `ssh-add` on stdin and the
  passphrase through the FIFO, so no key or passphrase byte is written.
- The repository executor is started like the broker and checks the same
  setup at entry (no root, no core files, a new session, an empty
  environment); it exits with the authority through kqueue and refuses
  debugger attachment. Darwin has no parent-death signal, so Git, its
  helpers and stock SSH stay in the executor's process group, and the
  authority kills and drains that group (stderr EOF from every member) for
  either transport. A GitHub executor reads its token from the authority's
  own store and serves it once over a socket in the credential root; the
  authority removes such a socket directory left by a killed executor when
  it starts.
- A platform relay broker installs a deny-all Seatbelt profile where Linux
  installs Landlock and then seccomp: it keeps the guest bridge and
  authority channel it holds and reads no store.
- Every child the authority, executor or signer starts first marks inherited
  descriptors close-on-exec, because Darwin sets that flag in a second call
  for some descriptors.

The store is the `local_credential_store` key in the local config,
`~/.codewire/config.toml` (or `$CW_MESH_DATA_DIR/config.toml`), shown by
`cw config inspect`:

```toml
local_credential_store = "file"  # macOS: "keychain" (default) or "file"
```

Linux accepts `secret-service` (the default) or `file`; see
[Linux file store](#linux-file-store-5255).

- **keychain** — the login Keychain, as Claude Code uses it. Generic-password
  items have service `sh.codewire.credentials` and the exact entry ID as
  account. Codewire drives Apple's `/usr/bin/security` over stdin
  (`security -i`), never argv, and links no Security framework. Each item
  trusts that stable Apple tool, so a `cw` upgrade does not prompt again.
  Exposure equals Linux Secret Service: while the keychain is unlocked, any
  process of the same user can read these items. A locked keychain fails with
  "local protected storage is locked or inaccessible; unlock it and retry"
  (an SSH session cannot show the unlock prompt). The unlock belongs to the
  security session that unlocked the keychain: an authority started from
  another session, such as a separate SSH login, sees it locked and refuses
  to start, and its brokers read through the authority's session. `security -i` reads one
  4095-byte line per command, so a larger value is stored as base64 split
  across `ENTRY`, `ENTRY:1`, ...; the head item records the chunk count and
  SHA-256, and a torn or foreign item reads as corrupt.
- **file** — one 0600 file per entry in `protected-v1` (0700) inside the
  credential root, written by atomic replace, opened without following links
  and excluded from Time Machine. At-rest protection is FileVault and file
  permissions, not a login-password key, like Codex's and Claude Code's file
  stores.

The authority records its store in its metadata. When it starts with a
different configured store it copies each entry the metadata references,
reads it back and compares it, records the new store, and only then deletes
the old copies; old copies it could not delete stay listed and are retried at
every start. A failure before that record changes nothing and is reported,
for example "local credentials could not move to the configured store (file):
operating-system protected storage is locked or inaccessible". A store that is
locked when the authority starts is reported the same way, at once. The next
local command
restarts an authority that was started under an earlier setting. Switching
back to a store whose old copies still await deletion is refused until they
are gone.

The authority starts through `posix_spawn` in a new session, with only
stdin/stdout/stderr open on `/dev/null` (`POSIX_SPAWN_CLOEXEC_DEFAULT`), an
empty environment and umask 077; it refuses to run as root and accepts only
same-user socket peers.

Its broker for a local VM generation is an owned child that keeps only the
authority channel (descriptor 3) and standard descriptors on `/dev/null`,
with an empty environment, a new session, no core files and umask 077. It
exits when the authority exits and refuses debugger attachment
(`PT_DENY_ATTACH`). It resolves its providers' addresses, opens the guest
daemon's credential bridge over the VM's hybrid vsock socket, and then
installs one Seatbelt profile before any lease: outbound TCP 443 only when an
HTTP provider is selected, and reads of exactly the authority's store. For
the file store that is the `protected-v1` directory; for the keychain it is
running Apple's `/usr/bin/security` with read access to the system libraries,
that keychain (or, for the login keychain, `~/Library/Keychains` and the
keychain search list) and the security server and user database services.
Every other file, program, network destination and Mach service is denied. As
on Linux, the broker reads the value of each lease from the store itself; the
authority sends only the exact entry reference. A broker that can run
`security` can read every Codewire item in an unlocked keychain, as a Linux
broker can read the unlocked Secret Service collection. Tests and synthetic acceptance set
`CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN` to a throwaway keychain file for the
keychain backend; it must not be under `Library/Keychains` or reached through
a symlink, and the recorded store includes that path.

## Linux file store (#5255)

A Linux credential root can keep its credentials inside itself, as on macOS,
so a scratch root does not write to the desktop keyring and deleting the root
deletes them. cw-security agreed this design on #5255 (2026-11-18).

- **The setting.** `local_credential_store = "file"` is accepted on Linux,
  beside `secret-service`. The store is the same `file` backend as on macOS:
  one 0600 file per entry in `protected-v1` (0700) inside the credential
  root, owned by the user, written by atomic replace and opened without
  following links. A wrong mode, owner or file type is refused, never
  repaired. A `file` root needs no session bus or keyring.
- **Not encrypted by `cw`.** Entries are plaintext; at-rest protection is file
  permissions and disk encryption. `cw credentials --local list` and `get`
  say so on stderr for a `file` store, on Linux and macOS alike (`Store:
  files in ROOT/protected-v1, not encrypted by cw (protected by file
  permissions and your disk encryption)`), and their `--output json` gives
  each credential `"protected_store": "file"`. `cw doctor` reports the store
  with its local store check (#5271).
- **Only where it is set.** There is no automatic default: every root, from
  a released or a development build, uses Secret Service unless its
  `local_credential_store` says `file` (cw-security, 2026-11-18, #5255).
  Scripts and smokes that make a scratch root set it themselves. No upgrade
  moves anyone's credentials from the keyring into files.
- **Changing it.** Setting it switches a root's store by the copy, read-back
  and compare described above for macOS.
- **The keyring warning.** A `--local` command that writes a credential from
  a root that is not the account's own, while that root's store is Secret
  Service, first prints one line on stderr: `Saving to your desktop keyring
  (Secret Service), not inside ROOT. Set local_credential_store = "file" to
  keep this root's credentials with it.` With `--output json` it is still on
  stderr, so stdout stays JSON. A root is the account's own when it is
  `~/.codewire/credentials-v1` under the account's home directory, whatever
  `HOME` says, links included.
- **Children.** The authority names its store on every broker's and
  repository executor's command line, on Linux as on macOS
  (`--protected-store`, and for `file` its `protected-v1` directory), and a
  child opens exactly that store, read-only: a child's store refuses every
  write, since the authority alone writes. A refresh's bundle is no
  exception (#5539):
  - **The child sends it in Commit, and the authority stages it.** The entry,
    the generation and the deadline come from the authority's own Started
    record; the request names only the refresh. The bundle is written into
    the credential's next material generation before the refresh's
    execution deadline, only into an empty entry or one already holding the
    same bytes, then promoted. Other bytes already there are refused and left
    to the refresh journal.
  - **The write holds no database lock** (#5413). The credential's refresh
    ownership keeps reconcile away meanwhile: a Begin or delete for it is
    refused as in progress, and a channel releases its refreshes only after
    its writes have returned, even when the child has gone.
  - **A locked or slow store is answered `unavailable`**, and the child sends
    the same Commit again until the execution deadline. A Commit the
    authority answered and refused hands the refresh back to be failed; one
    that timed out may still be writing, so its channel ends instead and the
    journal settles it.
  - **Every root refreshes this way**: Secret Service, a macOS keychain,
    which the broker's Seatbelt profile only reads, and a `file` store, which
    its Landlock domain only reads. A rotated refresh token is lost only if
    the child or the authority stops between the provider's answer and the
    authority's write.
  - **The bundle is bounded** by the channel's message limit (320 KiB on a
    broker's, 128 KiB on a repository executor's) and again by the store's
    1 MiB, before anything else is read; an empty one is refused.
  - **What it doesn't close, locally:** a child holding a started refresh
    still chooses the bytes of that credential's next generation, so a
    compromised local broker can replace a credential it is refreshing, for
    every environment that uses it. Closing that needs the authority to make
    or check the provider call. A hosted refresh has no such gap: the
    credential service's own broker makes the exchange, and no Sandbox-side
    process chooses the next generation.

  A `file` store's children get no
  session bus address (`DBUS_SESSION_BUS_ADDRESS`); a GitHub repository
  executor keeps `XDG_RUNTIME_DIR` for its runtime directory. A Secret Service
  root's children keep the bus address their authority has.
- **The broker's Landlock domain** gains, for a `file` store only, one rule
  allowing reading files and listing directories beneath that
  `protected-v1` directory, and nothing else: no write, and no other path.
  Seccomp is unchanged. As on macOS, the broker only reads the store; the
  authority writes it.
- **Admission.** A `cw` that admits an already running authority uses the
  configured store, so a `file` root is never reopened on Secret Service.

## Store calls and the metadata lock (#5413)

The local authority never calls its protected store while it holds its
metadata connection. That connection is held only for SQL, so a keyring
that stops answering, behind an unlock prompt nobody sees, holds up only the
request that called it. Listing, profiles, environment admission and a
running VM's lease never wait on it. cw-network and cw-security agreed this
on #5413 (2026-11-20).

**What keeps a credential from being `ready` without its material** is three
things together. It used to be one lock held from the checks to `ready`.
- **A `pending_write` row that nothing reads or changes.** Listing and
  leases see only `ready` rows, deletion refuses a pending one, and only
  start-up recovery, which runs before any request and only deletes, removes
  one.
- **The checks made again at publication.** An SSH enrollment's checks
  (its admission, shutdown, its 30-second deadline and its caller still being
  there) run when the pending row is created and again in the same hold that
  marks it `ready`. An enrollment whose checks fail then is not published:
  its material is deleted, then its row. So a caller told it failed never
  finds the credential afterwards. Two things follow:
  - an enrollment whose caller has gone by publication is undone;
  - its deadline now covers the store write, so a keyring that answers after
    it (an unlock prompt answered late) saves nothing, where it used to
    publish.

  An ordinary add has no such checks: it publishes once its write succeeds,
  even during shutdown.
- **Final updates guarded by the state they expect,** and the refresh-owner
  lock for every path that changes a credential's material.

**An add:**
- **Its id.** The authority makes the credential's id, so its entry is fresh,
  and the collision check needs no lock.
- **Its steps.** It inserts the pending row, writes the store, and marks the
  row `ready` (or undoes it), with no lock held across the write.
- **Its outcome.** It ends in exactly one of: `ready`; its material and row
  deleted; or, when the store doesn't answer, its row left for start-up
  recovery (#5271). The service runs it on a blocking worker, so a caller
  that goes away doesn't stop it.
- **A second add during the write.** While one add is writing, a second add
  of the same name or of a second GitHub connection is refused at once: the
  refusal says another add is still saving, and to wait for it
  (`LOCAL_CREDENTIAL_ADD_IN_PROGRESS`). The authority knows which adds are
  writing. A pending row that none is writing (its write and its cleanup
  both failed, #5271) is refused as an earlier add that never finished
  (`LOCAL_CREDENTIAL_ADD_UNFINISHED`), never as one to wait for. Only the
  authority's next start removes that row.

**The store probe** (`cw doctor`'s write check) is ordered only against
other probes.

**This behaviour has its own authority protocol step,** so a `cw` with it
replaces a running authority from before it once no local VM runs.

**The material paths' connection.** The paths that change a credential's
material run on a second connection to the same database:
- rotation, deletion, the journal's reconcile, refresh admission
  (`prepare_credential_refresh`), refresh abort
  (`abort_environment_credential_refresh`) and refresh promotion;
- one function opens both connections with the same flags and pragmas.

These rules hold on it:
- **Its own exclusion.** Each path takes that connection only while holding
  the refresh-owner exclusion it already had: the refresh-owner mutex for
  rotation and deletion, and its own refresh entry for a refresh. It never
  takes it while holding the metadata connection.
- **No store call inside a transaction.** Its store calls go through one
  wrapper, which refuses any call made inside an open transaction
  (`StoreCallInTransaction`). So no store call holds the database's write
  lock, and nothing on the metadata connection waits on a keyring.
- **Every write transaction is IMMEDIATE,** on both connections, so a write
  that meets the other's waits its turn within the busy timeout instead of
  failing at once. Busy past that timeout is a failed step: an admission or
  a lease refuses, and a material path rolls back as below.
- **One change, one transaction, one connection.** A check and the change it
  permits share a transaction: deletion's check that nothing references the
  credential, with its move out of `ready`; and refresh admission's grant,
  with its reservation.
- **A revoke wins.** It runs on the metadata connection and never waits. A
  rotation whose guarded update then changes no row rolls back what it
  wrote:
  - only its own next entry, never the current one;
  - the entry first, then its journal row, and the row only once the entry
    is gone, so a row left behind is start-up recovery's;
  - it returns `StaleCredentialRevision` when the revision moved and
    `CredentialUnavailable` when the credential left `ready`.
- **Material changes queue.** Every material path holds the one material
  connection across its store calls, so changes to different credentials'
  material now wait behind one another's store calls, and a deletion also
  waits behind a rotation through the refresh-owner mutex. A metadata
  request never waits on them.

**The material connection has its own authority protocol step too,** so a
`cw` with it replaces a running authority that has only the add's step once
no local VM runs.

**Workload secrets** follow the same rule:
- **Writers on the material connection.** Setting, deleting and a secret
  project's delete run on the material connection, under its mutex, with
  their store calls outside any transaction. Each first finishes what an
  earlier write left, so a write cut short is cleaned up by the next one, or
  by start-up recovery.
- **Reads touch no store.** Listing, metadata resolution and rename run on
  the metadata connection and make no store call. A listing reads one
  snapshot and shows only `ready` secrets: during a first set its key is not
  listed until the value is stored, and during a delete it is already gone.
  A rename of a secret being written or deleted is refused as not found.
- **A launch's projection reads one generation.** Sealing a VM's workload
  secrets runs on the material connection: it captures the selection in one
  read transaction, ends it, then reads each winner's value through the
  store. Secret writers hold the same connection, so no winner's generation
  is retired or replaced during the read. The selection is a launch-time
  snapshot: a change after it applies to the next launch. If any winner's
  value can't be read, nothing is sealed, never a partial set.
- **Any later value read** follows the same rule: no metadata connection held
  across its store call, and it fails closed if the generation it read was
  retired in between.

**Workload secrets on the material connection have their own authority
protocol step,** so a `cw` with them replaces a running authority that has
only the material connection's step once no local VM runs.

## Dashboard

The dashboard uses the same platform services as `cw --cloud`, and its forms
are write-only: a stored value is never shown again. It never reads local
stores.

- **Settings → Secrets** and the organization's secrets pages list, set,
  rename and delete application secrets in the personal and organization
  scopes and in secret projects, and manage the organization's secret
  projects. Only key names and update times are readable.
- **Settings → Credentials** adds credentials (**Connect Codex**,
  **Connect GitHub**, OpenAI and Anthropic API keys, a Claude subscription
  token, and a generated or imported SSH key) and shows each one's status.
  A credential's menu renames, rotates an API key, replaces a token,
  reconnects, revokes and deletes it; an SSH key offers **Copy public key**.
  **Profiles** creates, renames and deletes identity-only profiles and edits
  their identities.
- **Create Sandbox** and **Edit Sandbox sources** select and clear the
  application-secret sources and the credential profile at an exact revision.
  The Sandbox list shows its sources, the bound profile revision and any
  credential that needs attention. Changing selections restarts a running
  Sandbox after confirmation and keeps its workspace data; a stopped Sandbox
  stays stopped.

## Acceptance

The acceptance journeys cover local runtime with local sources, local runtime
with platform sources, platform runtime with platform sources, and the
platform's refusal of local sources. Synthetic HTTP-provider success stays in
isolated local and Kind fixtures; a live provider journey needs a fresh
enrollment by the account's owner and never reads a saved login.

### Composed acceptance runner

Use the checked-in dispatcher for the final Linux/Dev evidence instead of
combining manual command results:

```sh
make accept-secrets-credentials
```

It serializes the existing native-local, local-with-platform-sources, Dev
all-scope application, Dev generated-SSH and disposable named-Mesh journeys.
The baseline `local-platform` journey explicitly disables named networking;
`local-platform-mesh` is the separate network journey. Each child retains its
own auth, topology, assertion and cleanup contract. The dispatcher reports the
final exit of each child after cleanup; a nonzero child stops later work because
its cleanup state is unknown. Retry one child independently, for example:

```sh
ACCEPTANCE_NORMAL_CW_BIN=/absolute/normal/cw \
LOCAL_PLATFORM_ARTIFACT_ROOT=/absolute/prepared/artifacts \
LOCAL_PLATFORM_ARTIFACT_LOCK=/absolute/prepared/artifacts.lock.json \
LOCAL_PLATFORM_IMAGE='registry.example/workspace@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
CODEWIRE_SERVER_URL=https://codewire-dev.sh \
EXPECTED_CODEWIRE_DEV_SERVER_URL=https://codewire-dev.sh \
EXPECTED_CODEWIRE_ADMIN_EMAIL=owner@example.com \
EXPECTED_CODEWIRE_ORGANIZATION_ID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
XDG_RUNTIME_DIR=/run/user/1000 \
SMOKE_TMP_PARENT=/var/tmp \
scripts/runtime/dev/run-secrets-credentials-acceptance.sh --only local-platform
```

The full matrix additionally requires separate explicit
`ACCEPTANCE_NORMAL_CW_BIN` and `ACCEPTANCE_SYNTHETIC_CW_BIN` paths; the native
`ACCEPTANCE_NATIVE_DATA_PLANE_SMOKE_BIN`,
`ACCEPTANCE_NATIVE_CREDENTIAL_BRIDGE_SMOKE_BIN`,
`ACCEPTANCE_NATIVE_STATE_PROBE_BIN` and
`ACCEPTANCE_NATIVE_WORKSPACE_IMAGE_IMPORT_BIN`; and
`ACCEPTANCE_NATIVE_ARTIFACT_ROOT`,
`ACCEPTANCE_NATIVE_ARTIFACT_LOCK` and `ACCEPTANCE_NATIVE_SCRATCH_PARENT`.
Actual Dev children require `CODEWIRE_SERVER_URL` and
`EXPECTED_CODEWIRE_DEV_SERVER_URL`. The Dev provider-SSH child also uses the
existing topology variables required by
`scripts/ci/verify/runtime-dev-commodity-smoke.sh`: `KUBECONFIG`, `KUBE_CONTEXT`,
`CODEWIRE_SERVER_NAMESPACE`, `SANDBOX_NAMESPACE`, `EXPECTED_NODE`,
`EXPECTED_TAILNET_PATH_TRANSPORT`,
`EXPECTED_TAILNET_PEER_RELAY_ENDPOINT`, `EXPECTED_UDP_RELAY_BIND_ADDRS`,
`EXPECTED_UDP_RELAY_ALLOCATOR_URL`, `EXPECTED_TAILNET_DIRECT_UDP_LB_IP`,
`EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE` and
`EXPECTED_RUNTIME_TRANSPORT_REGION`. The all-scope child receives no Kubernetes
identity or topology inputs and also needs
`EXPECTED_CODEWIRE_ADMIN_USER_ID`; all owner-login children need
`EXPECTED_CODEWIRE_ADMIN_EMAIL`, and the scope/local children need
`EXPECTED_CODEWIRE_ORGANIZATION_ID`. Supply `XDG_RUNTIME_DIR` and
`SMOKE_TMP_PARENT` explicitly. The named-Mesh child additionally requires a
canonical executable `LOCAL_PLATFORM_MESH_PROBE_BIN`. `--help` lists the same
runner and child input names.

Run the all-scope child only after the operator has separately authorized the
dedicated personal and organization scope access. The dispatcher cannot infer
conversation or Program authority; the child enforces the exact expected
account, organization and initially empty dedicated scopes. The provider-SSH
child requires
`ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR` to name its own canonical,
owner-0700 fresh OAuth login directory under the caller's tmpfs
`XDG_RUNTIME_DIR`. The dispatcher inspects only directory identity and mode;
it never reads login contents or reuses the temporary logins owned and deleted
by other journeys.

The `initial-private-checkout` journey uses the same isolated Linux VM/login
lifecycle, with a newly generated platform SSH identity and a host-loopback
synthetic Git server. Build its non-installed test fixture once:

```sh
cargo build --locked -p codewire-workspace-access --example initial_private_checkout_fixture
```

Set `LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN` to the canonical absolute path of that
executable, alongside the local-platform inputs above, and run the dispatcher
with `--only initial-private-checkout`. The normal `cw create --local`
consumes a `repositories` entry with pinned host trust and an exact commit;
there is no `--path` copy or later clone. The install command checks that the
private checkout already exists. Missing profile/trust must be rejected, and
the server must observe authentication using the selected public key. Only
the public key reaches this fixture; platform signing material stays remote.
The fixture listens before host-side repository preparation, needs no guest
network or tunnel, and drains its connections and Git processes at cleanup.

The `live-codex` journey uses the same local-platform inputs and isolated VM
lifecycle. Select it with `--only live-codex` (or pass `--live-codex` directly to
the local-platform smoke). After fresh Codewire login, approve the fresh Codex
device login started by `cw credentials --cloud connect codex --name NAME`.
No saved provider credential is read or imported. The journey creates a unique
one-credential profile, attaches it to the VM, and invokes the stock pinned
Codex CLI through Codewire's managed configuration. It does not override the
provider, model or authentication. The fixed request asks for one harmless
marker and no tools; unexpected tool activity or provider failure fails the test.

Guest output stays in private, size-capped tmpfs files under a fixed timeout;
only a validated public receipt reaches the host. Overall success requires VM
deletion and absence, profile/credential deletion and fresh Codewire logout.
The command timeout alone does not prove all guest descendants have exited;
deleting the VM owns that boundary. This proves one actual Codex request via
platform credentials in a Linux-local VM, not forced refresh, other providers,
hosted placement or enforced egress mediation.

The `live-anthropic` journey uses those same local-platform inputs and isolated
VM lifecycle. Select `--only live-anthropic` (or `--live-anthropic` directly).
After fresh Codewire login, enter a newly supplied Anthropic API key through
`cw credentials --cloud add anthropic --name NAME`; input goes directly to
the CLI's protected prompt, not a smoke capture or environment variable.
The journey creates one exact revision-1 profile and runs the guest's Claude
Code client using its generated Anthropic routing and public placeholder.
It reuses the native smoke's bounded, tool-disabled Claude request contract.
Private output reduction and parent cleanup must complete before its named PASS.
This is a separate owner-operated provider test, not permission to read saved
keys or proof of hosted placement, other providers or complete acceptance.

The `live-openai` journey reuses the same isolated VM and public API-key enrollment
with `add openai`. Set `LOCAL_PLATFORM_OPENAI_MODEL` to an exact model snapshot
available to the freshly supplied key; there is no default or model substitution.
Missing or malformed input is `NOT RUN` before login. Select `--only live-openai`
(or `--live-openai` directly). This sends one ordinary non-streaming
[Responses HTTP request](https://developers.openai.com/api/reference/typescript/resources/responses/methods/create)
through the generated OpenAI endpoint and public placeholder. Tools, background
execution and response storage are disabled; response bytes stay bounded in
memory and only a fixed result escapes. The response must acknowledge that exact
model and contain the expected assistant text. This is not SDK, streaming or
agent compatibility proof; the existing synthetic streaming test remains separate.
Cleanup must finish before the named PASS.

The bounded synthetic stock-`gh` transport test runs in CI's Rust feature-graph
shard whenever the daemon is selected, against the `gh` that
`scripts/ci/setup/fetch-pinned-gh.sh` fetches from the workspace image's own pin
(`images/base/Dockerfile`). Run it locally with the absolute path to that `gh`:

```sh
CODEWIRE_TEST_GH_BIN=/absolute/verified/gh cargo test -p codewire-daemon credential_bridge::tests::stock_gh_rest_and_graphql_use_authenticated_unix_ingress -- --ignored --exact
```

This uses isolated public Unix-socket configuration and synthetic REST/GraphQL
responses through the authenticated daemon ingress. It does not prove automatic
selected-profile configuration, provider authorization, Git subprocess support,
or live/hosted GitHub acceptance. Missing or mismatched binaries fail this entrypoint.

The hosted `dev-initial-private-checkout` journey uses the same generated
platform SSH identity and normal repository/install path, with a temporary
synthetic Git server in Dev. Set `DEV_CHECKOUT_WORKSPACE_IMAGE` to the existing
published workspace image's immutable digest; the fixture and environment use
that same image, without package downloads or a separate build. Supply the
dedicated browser-auth inputs, explicit Dev Kubernetes context and sandbox
namespace. The checked-in public `scripts/runtime/dev/testdata/acceptance-identity.json`
must separately admit the actual test account and organization before any
authentication or fixture mutation. Caller-supplied expected IDs are not admission.
The fixture-only additive policy permits workspace Pods in that dedicated test
organization to reach only the nonce fixture on TCP22222 during its bounded
lifetime. Existing production policies remain unchanged. The journey requires
initial checkout before install, exact pinned host trust and commit, setup
completion, managed execution and owned-resource cleanup before PASS. Local
checkout does not prove hosted checkout.

`--only live-github` runs the GitHub journey with a fresh GitHub device
approval. The default matrix needs fresh Codex approval and fresh
OpenAI/Anthropic API-key input, and always ends with `aggregate result:
INCOMPLETE; full acceptance: NOT CLAIMED`. A passing `--only` run reports
`selected result: PASS` and proves only that named journey; local checkout
does not prove hosted checkout.

For unattended Dev testing, the same runner accepts
`DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE`, `DEV_SMOKE_BROWSER_AUTH_BUN_BIN` and
`DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN`. These are canonical file paths, not
credential values. Also provide the exact expected account ID, email and
organization ID. Do not supply a saved OAuth directory in this mode.

The credential file is owner-0600 JSON with `version` equal to
`codewire-dev-smoke-browser-auth-v1` and keys `userId`, `email`,
`organizationId`, `password`, and `totpSecret`. It belongs to the dedicated Dev
test account, is supplied by the protected runner, and must never be committed
or uploaded with test artifacts. One-time account/2FA provisioning and its
protected-store integration are operational prerequisites, not implemented by
the acceptance runner.

Each journey opens a fresh normal CLI device grant, signs in through the normal
Dev browser password/2FA flow, approves that grant, checks the exact account and
organization, and signs the browser out. The journey owns the resulting CLI
login and logs it out during cleanup. Browser and login state stay in private
tmpfs; failure to revoke a session fails the run even when local files have
been removed. No shared refresh-token store or alternate authentication grant
is used. This automates Codewire login, not real provider enrollment.

The helper lives under `apps/dashboard/scripts/` so it uses the existing pinned
Playwright and OTPAuth dependencies. Install the locked workspace dependencies
before running; the CI contract tests use a fake browser and synthetic CLI,
not Dev or the dashboard E2E database seeders. Run the real helper only through
the smoke entrypoint, which disables ambient Bun configuration and dotenv
loading. The automated device interaction requires the current eight-input UI
to be deployed.
