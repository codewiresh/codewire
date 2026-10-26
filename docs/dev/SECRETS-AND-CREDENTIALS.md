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
cw credentials --cloud add claude-subscription --name work-claude
cw credentials --cloud connect claude --name claude-login
cw credentials --cloud rename work-openai personal-openai
cw credentials --cloud rotate personal-openai

cw credentials --cloud --profile=work set codex work-codex
cw credentials --cloud --profile=work set ssh work-ssh
```

There is no `github` slot: the account's GitHub connection is part of every
profile, and `set github` is refused.

```sh
```

The first profile `set` creates the profile if absent. Enrollment does not
silently select an identity. Profiles retain immutable revisions and current
user/organization authorization. Editing a profile does not advance existing
environment bindings. Codewire revocation stops Codewire use; it is not a
promise of provider-side logout.

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

Renaming a platform profile (`AccessProfileService.RenameAccessProfile`, or
**Rename** in a profile's menu in Settings → Credentials) changes only its
label. It uses Create profile's name rules, publishes no revision and keeps the
entries and every Sandbox binding, which pin an ID and revision. The request
names the revision and name it observed, as a credential rename does. A stale
revision or name, including one left by another rename from the same view, or
a name another of the owner's profiles uses is rejected; renaming to the
current name changes nothing. A project spec that selects a profile by name
resolves that name at its next admission, so update it after a rename.

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

A Claude subscription token lets Claude Code in a Sandbox use its owner's
Claude Pro, Max, Team or Enterprise plan instead of an Anthropic API key. It is
the Anthropic provider's OAuth authentication kind. A profile's one Anthropic
slot holds either an API key or a subscription token.

Enrollment is by paste; Codewire never runs Claude Code's OAuth client. Run
`claude setup-token` on your own machine or in any Sandbox terminal. It opens
the browser authorization and prints a one-year token without saving it
([Claude Code authentication](https://code.claude.com/docs/en/authentication)).
Then add the printed token at once. Paste a freshly generated token: one
printed earlier stops working before the one-year expiry Codewire records.

```sh
claude setup-token
cw credentials --cloud add claude-subscription --name work-claude
cw credentials --cloud --profile=work set anthropic work-claude
```

The dashboard equivalent is **Settings → Credentials → Add credential →
Claude subscription token**. The CLI reads the token from a no-echo prompt or
stdin, never argv. Codewire checks only its shape (16 to 1024 printable
characters, no whitespace) and makes no provider call when it is added. The
token is opaque, so Codewire records a hard expiry one year after it is added;
the dashboard shows **Expires soon** in its last 30 days and **Expired** after
it. Subscription tokens are platform credentials only; `--local` refuses them.

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
the managed credential is used without the first-run login picker. It also
marks the workspace root `/workspace` trusted (`projects["/workspace"]
.hasTrustDialogAccepted`). Claude Code applies that trust to every folder
beneath it, including every checked-out repository, so it starts without asking
whether you trust the folder, and loads the repository's own project settings,
such as hooks, without that question. Other folders, such as the home
directory, still ask. Local VMs do not do this.

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
`cw credentials --cloud rotate work-claude` or **Replace token** in the
dashboard. Replacement keeps the identity and profile bindings, sets it Active
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
`CREDENTIAL_AUTHENTICATION_KIND_CLAUDE_SIGN_IN`; a profile's one Anthropic slot
holds an API key, a subscription token or a sign-in. Sign-ins are platform
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
("Paste code here if prompted >") or stdin, never argv. Codex and GitHub
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
and refuses a rotation that drops `user:inference` or `user:profile`. A refused
or uncertain refresh is terminal and the credential reads **Reconnect needed**;
the old refresh token is never sent again. Idle sign-ins are kept alive (see
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

The broker's pinned transport admits `platform.claude.com` for the token
endpoint only; the credential service's separate sign-in transport admits that
endpoint and the one profile read. Claude itself (`claude.com`) is reached only
by your browser.

### Dashboard GitHub connection and repositories

In Settings → Credentials, **Connect GitHub** starts GitHub App user
authorization, not device authorization. **Install/manage repository access**
opens the App's separate installation screen, where the user chooses allowed
repositories. The dashboard and `cw credentials --cloud connect github` tell
users to choose **Only select repositories**: the App requests exactly Contents
(read and write) and Pull requests (read and write), plus Metadata (read), so
a connection can read, push to and open pull requests in every repository the
installation covers, and a Sandbox using it can do the same through the managed
route. Authorization returns to this dashboard's explicitly selected,
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
falls short, with its settings page:
`https://github.com/settings/installations/ID` for a user,
`https://github.com/organizations/LOGIN/settings/installations/ID` for an
organization, built only from the validated login and numeric ID under the
fixed `github.com` prefix. An enterprise installation has no such page and is
only named: its owner accepts in the enterprise's own settings (#2712).

- **Connect and reconnect** (the dashboard callback,
  `cw credentials --cloud connect github` and local
  `cw credentials connect github`) make the comparison with the new token. An
  installation that falls short still connects, since reads keep working. The
  dashboard callback saves the connection and then redirects (303) to the
  first user or organization installation's settings page; the CLI prints
  each one and, at a terminal, opens the first in the browser as `cw login`
  does.
- **The credentials page** checks live on every render, so it shows the
  status for as long as GitHub holds the earlier grant and stops once the
  owner accepts: "GitHub is waiting for you to accept Codewire's updated
  permissions on LOGIN", with **Review on GitHub**. The check is
  `GithubRepositoryService.ListGithubPendingPermissions`, which runs under
  exactly `ListGithubRepositories`' authority: the original exact-Origin
  browser session or `codewire.api` OAuth bearer (organization API keys are
  denied), the owner's single active GitHub connection read by exact id and
  version, the same durable App-token renewal and the same record recheck
  after GitHub answers. Unlike discovery it never renews ahead of expiry: a
  token GitHub still accepts is used as it is, and one GitHub refuses (401)
  renews once, so a page render never rotates a working token. It answers login,
  installation ID and account kind only, never a token, permission set or
  provider response, and stores nothing. Being advisory, it never holds
  anything up: it has three slots of its own (never discovery's), a
  two-second budget, and answers nothing at once when its slots are full or
  another renewal of the same credential is running. A renewal it starts
  moves to the tracked worker and completes durably for the next read. The
  dashboard runs it beside the page's metadata reads and gives it two
  seconds; any error or timeout shows nothing. A page load another site
  started (`Sec-Fetch-Site: cross-site`, or another cross value without a
  referrer from the dashboard) renders without it, so a link elsewhere cannot
  make the dashboard call GitHub or renew a token; this includes GitHub's
  Setup URL return, and the person's next visit shows the status.
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
fetch, including bounded gzip negotiation requests; existing limits remain
4 MiB request bytes and 256 MiB response bytes, with no redirect or LFS support.
These limits are not a claim that arbitrary-size repositories are supported.

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
and `push` work within the GitHub App's permissions and the same limits: a
push whose compressed pack exceeds 4 MiB fails closed. Public repositories
also go through the owner's login (or the key); when the connection is revoked
or inactive, GitHub remotes on the managed route fail closed until it is
reconnected.

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
the issue and pull request REST calls. Anything else, such as `gh run list`,
release uploads or `gh api` for another REST path, fails with HTTP 403 and the
body `credential route unavailable`. `gh` finds the repository from an SSH origin (`git@github.com:owner/repo`). In a
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
sources with such a profile succeeds, with that capability unavailable. A
selected credential that no longer exists still refuses the whole runtime:
bound credentials cannot be deleted, so that is integrity damage.
Platform-to-local launches still admit their exact selection as a whole.

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
(`messages` on `anthropic-api`, `responses` on `openai-api`), no WebSockets,
and AV's 4 MiB request limit, which is below Anthropic's own. Redaction matches
the credential's raw, JSON-escaped, percent and base64 forms; it does not decode
other encodings of a larger value, so a provider that reflected the credential
inside an opaque encoding would not be caught, in a header or in a body. GitHub
keeps its closed families and exact operations, since `git` and `gh` go through
its signer and executor.

### Provider matrix

| Provider | Operations |
|---|---|
| Codex/OpenAI | ChatGPT OAuth and OpenAI API key, the transparent route: every API request, streaming, account header, serialized refresh/recovery and bounded early-401 retry |
| GitHub | OAuth enrollment, protected HTTPS clone/fetch/push, stock gh API/repository/issue/PR workflows through admitted routes |
| Anthropic | API key, Claude subscription token or Claude sign-in (refreshed by the broker), the transparent route: every Claude Code API request, including enterprise accounts using the same API |
| SSH | Ed25519 generation, standard Ed25519/RSA OpenSSH import, initial private checkout, ssh/scp/sftp/Git-over-SSH |

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
| The environment creator's own personal Codex ChatGPT access token, ID token and account ID, with the non-empty placeholder refresh token `codewire-managed-no-refresh-token` | Codex's `auth.json` (mode 0600): `~/.codex/auth.json` in a hosted Sandbox, written by the workspace daemon; in the creator's own local VM, Codewire's native Codex home (`/run/codewire-agent/codex/auth.json`), written by the guest daemon for the workload user | Codex enables `/usage`, analytics and account routing only with its own ChatGPT login and has no hook for a login held elsewhere, so the proxy cannot provide them | Every process in the Sandbox or VM, the creator, org owners/admins of a hosted Sandbox and anyone granted terminal access | Delivery stops at the next check. Codewire deletes its `auth.json` within 2 minutes when the broker denies delivery, and within about 14 minutes when the environment loses credential authority entirely (the first failed check within 2 minutes, then 10 minutes of failed checks, then the next check within 2 minutes). A stopped local VM keeps it on its state disk until its next boot, which removes it unless that boot's writer keeps it, and always when the disk boots as another environment. The token stays valid at the provider until its `exp` | The refresh token, API keys, GitHub and SSH material, organization-owned credentials, another user's login, and a login for any local VM but the creator's own |
| The environment creator's own personal Claude sign-in access token, with its expiry, its scopes (exactly `user:inference`, `user:profile`, `user:sessions:claude_code`, `user:mcp_servers`, `user:file_upload` and `user:plugins`, the scopes of Claude Code's own login; a stored scope beyond them is never delivered), plan and tier, and a per-delivery placeholder refresh token `codewire-managed-no-refresh-token-<nonce>` | `claudeAiOauth` in `~/.claude/.credentials.json` (mode 0600), other keys kept: in a hosted Sandbox, merged into the file by the workspace daemon; in the creator's own local VM, in the workload user's home, by the guest daemon | Claude Code shows `/usage` and the plan only with its own claude.ai login; those calls go straight to `api.anthropic.com` and ignore `ANTHROPIC_BASE_URL`, so the proxy cannot answer them | Every process in the Sandbox or VM, the creator, org owners and admins of a hosted Sandbox, and anyone granted terminal access | Delivery stops at the next check. Codewire removes its `claudeAiOauth` within 2 minutes when the broker denies delivery, and within about 14 minutes when the environment loses credential authority (as for Codex). A stopped local VM keeps it on its state disk until its next boot, which removes it unless that boot's writer keeps it, and always when the disk boots as another environment. The token stays valid at the provider until `expiresAt` (about 8 hours) | The refresh token, Claude setup tokens, API keys, GitHub and SSH material, organization-owned credentials, another user's login, and a login for any local VM but the creator's own |

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
whose personal-owner consent the creator confirmed; a local profile has no
Claude sign-in); the Anthropic grant's dedicated `claude-login` permission;
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
files. A local profile serves only the owner's own Codex sign-in: it has no
Claude sign-in.

The workspace daemon writer follows these rules for
the files it owns:

- Your own login wins. An `auth.json` whose refresh token is not Codewire's
  placeholder is never touched.
- `codex logout` stays logged out until Codex is re-selected or the Sandbox
  restarts.
- When no login is delivered, Codex uses the proxy through a Codewire
  `config.toml`. Codewire owns that file only while its first line is
  `# Managed by Codewire. Delete this line to manage this file yourself.`
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
after Start is terminal exactly as on demand, and Settings → Credentials then
shows the credential as **Reconnect needed** with its Reconnect action on the
row. Shutdown stops new selection and waits for a started refresh to finish.
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
`--permission-mode auto`; see
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
`auth.json` (0600) and removes Codewire's `config.toml`, so Codex uses its
built-in provider and talks to chatgpt.com directly; this holds even when
your own login is in `auth.json`, so your login is the one Codex uses. A
denial, an expired login or 10 minutes of bridge failure removes Codewire's
`auth.json` and brings Codewire's `config.toml` back. `auth.json` is
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

Linux accepts only `secret-service`: its brokers and repository executors read
Secret Service directly.

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
`ACCEPTANCE_NATIVE_MESH_BIN`, `ACCEPTANCE_NATIVE_DERP_BIN`,
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

The bounded synthetic stock-`gh` transport test can be run explicitly with the
absolute path to `gh 2.97.0` from the checksum-verified Codewire image toolchain:

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
