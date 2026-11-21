# Credentials

Connecting provider credentials with `cw credentials` and using them in an
environment, the same with `--local` (the operating system's protected store)
and `--cloud` (the platform credential service), as the local and cloud
parity audit records (#4717). Each setup is walked on three surfaces: a local
VM on Linux, a local VM on a Mac, and a hosted Sandbox on Dev. A walk on one
surface proves nothing about another. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-21. Every step not listed as observed is **not yet
observed**.

| ID | Linux local VM | Mac local VM | Hosted Sandbox (Dev) |
| --- | --- | --- | --- |
| `cred-github` | not yet observed | not yet observed | not yet observed |
| `cred-codex-sign-in` | not yet observed | not yet observed | not yet observed |
| `cred-openai-key` | not yet observed | not yet observed | not yet observed |
| `cred-anthropic-key` | not yet observed | not yet observed | not yet observed |
| `cred-claude-setup-token` | not yet observed | not yet observed | not yet observed |
| `cred-claude-sign-in` | observed, #4798 at f5657302c, 2026-11-15 (steps 1–4; the plan and `/usage`, step 5, not yet observed) | observed, cw v0.4.24 on macOS 27.2.1, 2026-11-19 (every step: the login file holds only a placeholder, `claude -p` answers, `/status` names the plan and `/usage` shows its weekly usage; #3999 comment 117487) | link screen and paste prompt observed, v0.4.18, 2026-11-14; a completed sign-in not yet observed |
| `cred-ssh-key` | not yet observed | not yet observed | not yet observed |
| `cred-sign-in-screen` | partly observed, #4885 at aea6abdb8, 2026-11-16 (steps 1 and 2 for Claude and Codex at a pty; GitHub, `cw login`, piped, `TERM=dumb` and SSH not yet observed) | not yet observed | not yet observed |
| `profile-revisions` | not yet observed | not yet observed | not yet observed |
| `profile-default` | not yet observed | not yet observed | not yet observed |
| `cred-delivery-diagnosis` | observed, #5237 at a8c2d9625, 2026-11-17 (the token, no-profile and stopped states; the sign-in and older-guest states not yet observed) | not yet observed | local VMs only |
| `cred-provider-unresolved` | observed, #5286: #5295 at bdcb89c00, the early replacements on that build plus their change, and `main` at 4cae0f601 through the smoke, 2026-11-18 (a name that resolves only to an address Codewire won't dial, and a sign-in's token host, not walked) | observed, #5286: main's tree at 57b68c6be (#5295 and #5312), 2026-11-18, with a name resolving only to private addresses; the provider came back at the regular replacement, not the early ones (a sign-in's token host not walked) | local VMs only |
| `cred-file-store` | partly observed, #5552 on main 22bcc705e, 2026-11-20, and main 8880d56e7, 2026-11-21 (a local VM from a `file` root is served a lease on both routes; a new `file` root keeps its key in `protected-v1` alone, 0700 and 0600; a root with nothing set uses Secret Service and says so first; the upgraded root, the 0644 refusal and a due refresh not yet observed) | the macOS file store; not part of this check | local stores only |
| `cred-same-name` | observed, #4928 on released v0.4.26, 2026-11-21 (steps 1 to 6, with an Anthropic and an OpenAI API key in place of the two sign-ins; a store holding a literal `github/work` not walked) | not yet observed (#4928) | not yet observed (#4928) |
| `cred-wording` | not yet observed | not yet observed | not yet observed |
| `cred-pickers` | not yet observed | not yet observed | not yet observed |
| `cred-github-notice` | not applicable | not applicable | not yet observed (dashboard) |

## Before the walk

- **Local, Linux:** never walk against the workstation's own keyring. A
  throwaway `HOME` alone doesn't keep `cw` out of it (#5255). Give the walk a
  private Secret Service too, its own `dbus-daemon` and
  `gnome-keyring-daemon` on a private `XDG_RUNTIME_DIR`, as
  `scripts/ci/verify/lib/local-smoke-isolation.sh` starts them. `cw`'s
  authority reads only `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS`, so
  that pair selects the store. Never script or loop calls to the
  workstation's own Secret Service (#5256). The runtime is built from the same source as
  `cw` (`docs/dev/LINUX-LOCAL-VMS.md`).
- **Local, Mac:** cw-dogfood's `cw` on the M3, in a session where the login
  keychain is unlocked (a GUI or rex shell; over SSH, `security
  unlock-keychain` first), as in [local-vm-mac.md](local-vm-mac.md).
- **Hosted:** Dev, signed in with `cw login --server https://codewire-dev.sh`
  in the same `HOME`. An API key can't run credential commands: they are
  account-global, and an API key is organization-scoped. The owner's Dev
  account already holds a GitHub connection, a Codex sign-in, a Claude
  sign-in and an SSH key; a hosted walk uses those through a profile and adds
  only synthetic credentials.
- **Secrets:** nobody pastes a real API key or token into a chat or a
  command line. API keys and the Claude setup token are walked with synthetic
  values, which prove every step up to the provider refusing them. Only the
  provider sign-ins (the Codex and GitHub device codes, the Claude browser
  sign-in) need a person, asked for once in a batch.
- Name everything the walk creates with one prefix, delete exactly those
  names afterwards, and put back any account setting the walk changes, such
  as the default profile.

## Every setup's steps

Each setup below runs the same five steps on each surface. The section lists
only what differs.

1. **Enrol:** `cw credentials --local|--cloud …` as the section says. Expect
   the same prompts and screens in both placements, as the owner approved
   them (2026-11-15, private-docs `designs/2026-11-15-credentials-screens.html`):
   a title line `Connect PROVIDER as NAME, on this computer` (or `in your
   Codewire account`), the step, then one result line
   `✓ PROVIDER connected as ACCOUNT`. Each section shows its screen.
   The result line is on stdout and the screen on stderr. With
   `--output json`, stdout holds only the credential, in `list --output
   json`'s shape. Connecting a name that already exists asks once, the same
   in both placements (#4717, C2), naming no ID or revision:
   `Reconnect Codex "NAME" on this computer? It stays in its profiles and
   becomes active; its expiry is kept.` A status other than active follows
   the name (`"NAME" (expired)`), and a Claude token's question ends `its
   one-year expiry restarts`. `--yes` answers it; with no terminal and no
   `--yes`, `connect` stops at once and names `--yes`. Not yet observed.
   Locally, a `connect` checks that the store accepts a write before the
   provider step: an older store with a local VM running, or a missing or
   locked keychain, stops `cw` before any code or link appears, saying what
   to do, and nothing is saved.
   Locally, a keyring that doesn't answer (a hidden unlock prompt, a stuck
   daemon) is shown within a second, on stderr: `Waiting for your keyring
   (Secret Service) to answer · unlock it if it asks`, or `your login
   keychain` on macOS. The same line shows while a command waits behind a
   store call another command left unanswered (a `cw doctor` that gave up,
   say): the name check before the key is asked for, a rotate's lookup, and
   a connect's checks before the provider step (#5271; not yet observed).
   When it gives up (the keyring's bound is 2 minutes, so a
   person can still answer a prompt), every local connect, add, generate and
   rotate says `your keyring (Secret Service) didn't answer within 2 minutes,
   so your WHAT wasn't saved; unlock it, or restart it, then run this again`,
   with `→ systemctl --user restart gnome-keyring-daemon` (on macOS, the login
   keychain and `→ security unlock-keychain`). It shows no gRPC or transport
   text and exits non-zero. The authority never made that write ready, so
   nothing lists or uses it; a stray value can stay in the keyring until the
   pending row's cleanup removes it, and is never used (cw-network,
   2026-11-18, #5271). `cw doctor` asks a local credential authority that is
   already running (never starting one) for a test write: a missing, locked
   or unanswering local store is a warning with the same next step, and one
   that doesn't answer within 10 s says so. Piped, the waiting line is one
   plain line; with `--output json` there is none. Walk it only inside a private
   D-Bus session (`scripts/ci/verify/lib/local-smoke-isolation.sh`) with its
   keyring stopped, never the host's keyring (#5271). Not yet observed.
   A save refused after the provider step says why in fixed words and that
   nothing was saved, with one `→` command, the same in both placements:
   the name is in use, the credential was deleted or changed during the
   sign-in, GitHub is already connected, or (on this computer) the keychain
   is locked or missing, naming the file `CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN`
   sets. Any other refusal says only that the store refused it and nothing
   was saved. Only a lost connection or a timeout leaves the outcome
   unknown ("may or may not be saved", `→ cw credentials --local list`). No
   RPC code, internal name or store or service text is shown (#4826). Not
   yet observed.
2. **List:** `cw credentials --local|--cloud list` and `list --output json`.
   Expect the credential with its provider, kind, status `active` and, where
   the provider gives one, an account hint.
3. **Profile:** `cw credentials --local|--cloud --profile P set SLOT NAME`,
   then `--profile P get`. Expect the slot to name the credential.
4. **Use:** a local VM created with `cw create --local --profile local:P …`,
   or a hosted Sandbox created with `cw create --cloud --profile P …`, then
   the section's check inside the environment. When one of P's credentials
   is revoked, expired or needs reconnecting, the create, and `cw update`
   with that profile, still succeed and print on stderr, before the next
   step, one line per such credential: for example `Claude (sign-in) 'walk'
   in profile work is revoked; agents in this Sandbox can't use it.`, then
   its fix with `--cloud` (`--local` and `agents in this VM` for a local VM,
   #5545). The hosted lines are not yet observed (#5594).
5. **Remove:** `cw credentials --local|--cloud delete NAME`.
   - A credential a profile selects is refused, with the exact
     `--profile P unset SLOT` that frees it.
   - Otherwise `cw` asks once ("Revoke and delete local credential "NAME"?"
     for an active one). `--yes` goes ahead without asking. With no terminal,
     or with `--output json`, it refuses and names `--yes`.
   - An active credential is revoked first, then deleted. If the revoke
     succeeds and the delete fails or may not have landed, `cw` says it was
     revoked but may not have been deleted, and to run `delete` again.

   Expect it gone from `list`, and one line saying what remains at the
   provider; the section says what that is. `revoke NAME` asks the same
   way.

## 1. `cred-github`: connect GitHub

- **Enrol:** `connect github --name NAME`. A device code, approved by a person
  at github.com/login/device. Expect, with the code alone on its line (bold
  at a terminal):

  ```text
  Connect GitHub as NAME, on this computer

    Open this link to sign in:
    https://github.com/login/device

    Enter this code:
    K7QF-2M9X
  ```

  then `✓ GitHub connected as LOGIN`. The copy key and the waiting line
  under the code come with #4885. Locally, the next line names what the
  sign-in can reach: your own account as `LOGIN (all repositories)` or
  `LOGIN (selected repositories)`, and every other account where the App is
  installed, another person's or an organization's, only as "repositories
  you can access in ACCOUNT", never with that installation's own selection.
  Walk it with a login that is a collaborator on one repository of another
  user's account where that user installed the App on all repositories
  (#5443). Not yet observed. A second connection under another name is
  refused, saying "GitHub is already connected as NAME" and how to
  reconnect it.
- **No App installation:** with the Codewire GitHub App installed on no
  account the approving GitHub login can use, both placements stop after the
  approval, save nothing, and say the same sentence (in the cloud after the
  `enroll platform OAuth credential:` label, until #4631):

  ```text
  the Codewire GitHub App is not installed on any account this GitHub login can use; install it, choose the accounts and repositories, then connect again: https://github.com/apps/codewire-sh/installations/new
  ```

  The link is the install page of the App the connection uses: locally the
  Codewire App's, which `cw` carries; in the cloud the one the server sends
  for its own App, which on Dev and Production is the Codewire App, so the
  line is the same. A server that sends no link, or one that isn't exactly a
  GitHub App install page, gets the sentence without the `: LINK` ending,
  never another App's link. After installing it there, the same
  `connect github` succeeds. In the cloud it never says "acknowledgement is
  unknown" for this (#5479). A
  Codewire server whose GitHub App settings are missing refuses before any
  code with "GitHub App authorization is not configured on this Codewire
  server; no platform credential was changed; ask an administrator to finish
  the GitHub App setup" (#5303). Not yet observed.
- **Ctrl-C:** pressed after approving the device code and before the save,
  it saves nothing and says so ("canceled; no credential was changed").
  Not yet observed.
- **Profile:** every profile includes the one GitHub connection; `set github`
  is refused.
- **Use:** `git clone` of a private repository the connection can read, inside
  the environment, through the broker's GitHub route. Expect the clone to
  succeed, with no GitHub token in the environment or on its disk.
- **A failed check's log** (#5737): in the environment, for a repository with
  a failed workflow run, `gh run list -R OWNER/REPO` lists it and
  `gh run view RUN -R OWNER/REPO --log-failed` prints the failing job's log.
  Expect:
  - the log text, with no signed URL, `Location` header or GitHub token in
    the output, the environment or the broker's log;
  - the same under the `locked` network policy with GitHub allowed by rule,
    since the broker, not the guest, fetches the log;
  - `gh run rerun RUN` refused with `request_not_forwarded`;
  - before an installation's owner accepts the App's `actions`: read, GitHub's
    own 403 from `gh run list`, and every other GitHub command working.

  Walk it on a local VM and a hosted Sandbox with codewire-e2e's test
  repository. Not yet observed.
- **Remove:**
  - In the cloud, deleting a connection made through the GitHub App asks
    GitHub to revoke its access token, and `cw` says whether GitHub confirmed
    it.
  - Locally, `cw` can't ask (it needs the GitHub App's secret).
  - Either way, GitHub keeps your authorization of Codewire until you revoke
    it at github.com/settings/apps/authorizations, and `cw` names that page.
  - In the dashboard, Settings › Credentials › **Disconnect GitHub** does the
    same: it revokes the connection first, which asks GitHub to revoke its
    access token, then removes it, and says whether GitHub confirmed. It says
    the Codewire app stays installed on GitHub and names
    github.com/settings/installations to uninstall it. If the revoke fails,
    nothing is removed. If the revoke succeeds but the removal fails, the
    dialog says GitHub is disconnected but Codewire couldn't remove its
    record, and to disconnect again to finish; until then the card reads
    Disconnected. Not yet observed.

## 2. `cred-codex-sign-in`: connect Codex with ChatGPT

- **Enrol:** `connect codex --name NAME`. "Enable device code authorization
  for Codex" in ChatGPT's Security settings first, then a device code,
  approved by a person. Expect the GitHub screen with
  `Connect Codex as NAME, …`, the link `https://auth.openai.com/codex/device`
  and its code, then `✓ Codex connected as ACCOUNT`.
- **Ctrl-C:** pressed after approving the device code and before the save,
  it saves nothing and says so ("canceled; no credential was changed").
  Not yet observed.
- **Profile:** `set codex NAME`.
- **Stopped mid-refresh:** as for a Claude sign-in (section 6), #5177. Not
  yet observed.
- **Use:** `codex` in the environment. Expect Codex signed in with the
  ChatGPT plan (`/status`), a model answer through the broker, and Codex's
  `auth.json` holding no refresh token.
- **A 401 the broker returns:** where the broker serves Codex (the proxy
  route, with no delivered login, or interception), a provider 401 to a
  sign-in refreshed in the last ten minutes reaches Codex as the provider
  sent it, with no forced refresh (#4974, walked on Kind). What Codex then
  shows a person is not yet observed. In the Kind suite's session, which
  forces the proxy provider beside a delivered login, Codex waited on its own
  token refresh until the session timed out.
- **Remove:** in both placements, delete (and revoke) also asks OpenAI to
  revoke the sign-in, and `cw` says whether OpenAI confirmed it. Locally the
  authority asks through a confined one-shot executor, never itself. An older
  authority doesn't ask, and `cw` says the sign-in stays valid until it
  expires, and that you can sign out of all ChatGPT devices under Settings →
  Security.

## 3. `cred-openai-key`: add an OpenAI API key

- **Enrol:** `add openai --name NAME`, with a synthetic key from stdin.
- **Profile:** `set openai NAME`.
- **Use:** a Codex request on the API-key route in the environment. Expect the
  broker to forward it with the synthetic key and OpenAI to refuse it as
  invalid, with no key in the environment.
- **Remove:** `cw` says the key itself is revoked only in OpenAI's console.

## 4. `cred-anthropic-key`: add an Anthropic API key

- **Enrol:** `add anthropic --name NAME`, with a synthetic key from stdin.
- **Profile:** `set anthropic NAME`.
- **Use:** `claude -p "hi"` in the environment. Expect Claude Code in its
  API-key form, the broker forwarding the synthetic key and Anthropic
  refusing it, with no key in the environment.
- **Remove:** as for OpenAI, the console.

## 5. `cred-claude-setup-token`: connect a Claude setup token

Issues: #4945 (the command), #4714 (local).

- **Enrol:** `connect claude-token --name ci`. Expect:

  ```text
  Connect Claude (token) as ci, on this computer

    Run `claude setup-token`, then paste what it prints.
    Token > (hidden)
    Got it (108 characters).

  ✓ Claude (token) connected as ci · expires 15 Nov 2027
  ```

  with a synthetic `sk-ant-oat01-…` token at the prompt, or piped to stdin
  with no terminal (no prompt then). The date is one year from now, and
  `list` shows it with the kind `Claude (token)`. Locally, the store is
  checked before the prompt, as for every connect.
- **Replace:** `connect claude-token --name NAME` again asks once (or takes
  `--yes`), naming the token it replaces, and restarts the year. `rotate
  NAME` refuses and prints that `connect` as its `→` line.
- **Alias:** `add claude-subscription --name NAME` prints
  `→ cw credentials --local connect claude-token --name NAME` (or `--cloud`),
  then does the same.
- **Help:** `cw credentials connect --help` and the guided picker
  ("What do you want to connect?") list `Claude (sign-in)  your subscription;
  shows your plan and usage` and `Claude (token)  your subscription; lasts a
  year, for automation, model requests only`, after Codex and GitHub (step 15).
- **Profile:** `set anthropic NAME`.
- **Use:** `claude -p "hi"`. Expect Claude Code in its token form
  (`CLAUDE_CODE_OAUTH_TOKEN` set to Codewire's placeholder, no token on
  disk), the broker forwarding the synthetic token and Anthropic refusing
  it.
- **Remove:** after `Local credential "NAME" deleted.` (or `Cloud
  credential …`), `cw` says "That removed Codewire's copy only: the token
  keeps working at Anthropic until it expires, or until you revoke it in your
  Claude account."

## 6. `cred-claude-sign-in`: connect Claude by signing in

Issues: #4714 (local), #2559 (cloud).

- **Enrol:** `connect claude --name NAME`. Both placements show the same
  screen:

  ```text
  Connect Claude (sign-in) as NAME, on this computer

    Open this link to sign in:
    https://claude.com/cai/oauth/authorize?code=true&client_id=…&state=…

    Paste the code Claude shows after you sign in > (hidden)
    Got it (87 characters).

  ✓ Claude (sign-in) connected as ACCOUNT
  ```

  A person signs in with a Pro, Max, Team or Enterprise plan and pastes the
  `code#state` Claude shows. The copy key under the link comes with #4885.
  Locally, the store is checked before the link appears, as for every
  connect (see "Every setup's steps").
- **List:** KIND `Claude (sign-in)` in both placements, and
  `"authentication_kind": "claude_sign_in"` in both placements' JSON, with
  the Claude account's email as its `account_hint`.
- **Profile:** `set anthropic NAME`.
- **Use:** in the environment, `~/.claude/.credentials.json` holds
  `claudeAiOauth` with the plan's `subscriptionType`, exactly Claude Code's
  six scopes, and Codewire's placeholder refresh token. Then:
  - `claude -p "hi"` answers;
  - Claude Code's `/status` names the plan;
  - `/usage` shows the subscription's usage.
- **States:** a reconnect of the same name asks first (or takes `--yes`); a
  value that isn't `code#state` gets one retry, then a refusal; an expired
  sign-in says to start again; Ctrl-C after pasting the code and before the
  save saves nothing and says so ("canceled; no credential was changed"),
  not yet observed.
- **Store check after a `cw` update** (#4826), locally, with a store the
  earlier `cw` left running, which can't check itself first:
  - with a local VM running, piped or declined: before the link, `cw`
    prints `! Your local VMs NAME still run on the cw you updated from, and
    so does your local credential store, so it can't be checked before you
    sign in. Restarting them on this cw moves it here.` and
    `→ cw upgrade --vms`; the store
    stays, and the connect goes on without the check. After the VM is moved,
    `cw credentials --local list` still shows the credential;
  - with a local VM running, at a terminal: `cw` offers the restart; on yes
    the VM restarts on this cw, the store is replaced, the check runs and
    the same connect goes on to the link (`docs/dev/LINUX-LOCAL-VMS.md`,
    "Credentials after an upgrade", #5238);
  - with no local VM running: the store is replaced before the link, and the
    check runs; with the login keychain locked, the connect stops there,
    saying the keychain is locked and how to unlock it, before any link.

  Observed on a Linux host, 2026-11-19 (#5238), #5461 at e2a402b342 against
  VMs left on released v0.4.22, in the credentials smoke's private HOME and
  Secret Service: piped, the notice and `→ cw upgrade --vms` came before the
  link and the VM kept running; at a terminal, declined, the same; accepted,
  `old-run` stopped, started on this cw, and the connect went on to the
  link, where Ctrl-C saved nothing; `credentials --local list` still showed
  the earlier key; a second connect, once the store was this cw's, printed
  no notice. Not yet observed: a store the earlier `cw` left with no VM
  running, the locked keychain, and a Mac.
- **Stopped mid-refresh:** a local store whose authority stopped during the
  sign-in's refresh (killed, a crash or a power loss) still opens, and
  `cw credentials --local list` shows the sign-in refreshed, as it was, or
  `refresh_failed`, with `cw create` and `cw start` saying it "needs
  reconnecting" (#5177). Observed 2026-11-21 on a Linux local VM, main at
  a7b8429ab5, with the featured build's synthetic sign-in: the authority killed
  with the refresh started, the store reopened listing `refresh_failed`, a
  guest call refused `credential_needs_reconnect`, and the VM stopped and
  started.
- **Rate-limited refresh** (#4975): a refresh the provider answers 429 keeps
  the sign-in, `cw credentials list` shows it as before, and the next refresh
  waits for the provider's `Retry-After`; a refusal after that wait reads
  **Reconnect needed**. The same for Codex and a GitHub App login. Observed
  through the broker's `refresh_rate_limited` log lines and the outcome after
  the wait on Dev and Production, never by provoking a 429. Not yet observed.
- **Remove:** `cw` says the sign-in keeps working at Claude until it expires,
  or until you sign out of other sessions in Claude's settings.
- **Gotchas:** after a `cw` update, the first local `connect claude` may
  replace the credential store the previous `cw` left running (starting the
  local VM supervisor, as a VM command does); with a local VM running, it
  offers to restart the VMs on this `cw` first, as above.
- **Observed:**
  - Linux local VM, #4798 at f5657302c, 2026-11-15, isolated HOME and Secret
    Service:
    - steps 1–4: the owner's sign-in, listed as `claude_sign_in` with a
      hint; a VM with `--no-network` got the login file (subscription `max`,
      the six scopes, the placeholder refresh) and only `ANTHROPIC_BASE_URL`;
      `claude -p` answered through the broker with no API key in the store;
    - against a store a v0.4.18 `cw` had left running, the check replaced it
      before the browser step (at 5781cec6e the same run had completed the
      sign-in and been refused);
    - `/status` and `/usage`: not yet observed.
  - Mac local VM (M3, cw-dogfood), 2026-11-15:
    - at 0d133e2e0 (#4868 before its fix, with a diagnostic guest): stored,
      but Claude Code reported "Not logged in". The store admitted every
      login lease, yet the guest got "unavailable" for each, because the
      broker's Seatbelt profile denied the `/usr/bin/id` that #4868's
      keychain lookup ran; those denials were the only ones for `cw`;
    - at b4541bf05 (the store opened before Seatbelt), after the authority
      restarted: the guest wrote the login (`delivered`, `checked: Written`,
      then `Current`), and `~/.claude/.credentials.json` (0600) held
      `claudeAiOauth` in a diagnostic VM and in one on the shipped guest; no
      Seatbelt denials;
    - `claude -p`, `/status` and `/usage`: not yet observed; the guest had
      no network (#4948).
  - Mac local VM (M3), cw v0.4.24 from the published installer, macOS
    27.2.1, 2026-11-19, a scratch HOME and a throwaway keychain, a real
    sign-in, with the front door on (#3999 comment 117487): the login
    file's `accessToken` is a `cwp1_` placeholder and no `ANTHROPIC_*`
    variable is set; `claude -p` answered `ok`; `/status` showed "Login
    method: Claude Ultra account"; `/usage`
    showed the plan's weekly usage per model, with reset times.

## 7. `cred-ssh-key`: generate or import an SSH key

- **Enrol:** `generate ssh --name NAME`, or `add ssh --name NAME --key-file
  FILE` with a synthetic key. Expect the public key and fingerprint, and the
  GitHub hint.
- **Profile:** `set ssh NAME`.
- **Use:** `ssh -T git@github.com` in the environment after the public key is
  added to a test account, or `ssh-add -l` showing the key through the
  broker's agent route. Expect no private key in the environment.
- **Remove:** `rotate` is refused (enrol a new key instead). Delete removes
  it; the public key stays wherever it was added.

## 8. `cred-sign-in-screen`: the sign-in link, the copy key and the wait

Issues: #4850, #4717 (C2). The screens are the approved screens 3 and 4.

- **Entry points:** every browser sign-in, in both placements: `connect
  claude`, `connect codex` and `connect github`, and `cw login`.
- **States to exercise:** at a terminal; piped (`| cat` on stdout and
  stderr); `TERM=dumb`; `--output json`; over SSH; a code pasted at Claude's
  prompt that starts with `c`; one Ctrl-C and then a second one while a
  Codex or GitHub login waits; Esc at Claude's prompt.
- **Driving it:**
  1. At a terminal, `connect claude --name NAME`. Under "Open this link to
     sign in:" the link is clickable, and `Press c to copy the link` is
     under it. Press `c` before pasting: `✓ Copied`, and the link is on the
     clipboard. Over SSH it lands on the clipboard of the computer you type
     on. A pasted code that starts with `c` is taken as the code.
  2. `connect codex --name NAME`, then `connect github`. The same link and
     hint, "Enter this code:" with the code alone on the next line, then
     `◐ Waiting for you to approve in the browser… 0:14 · Ctrl-C to cancel`,
     counting. `c` copies the link. One Ctrl-C cancels and saves nothing; a
     second one ends `cw` at once (exit 130) with the terminal as it was.
  3. `cw login` at a terminal: its three stdout lines are unchanged, the
     link is clickable, and the hint and the waiting line are on stderr.
     The server's sign-in page must be an `https://` link, or `http://` to
     `127.0.0.1` or `[::1]` as written (a local Kind cluster); any other,
     an `http://` LAN address or a look-alike such as
     `http://127.0.0.1.example.com/` included, stops `cw login` with `the
     server sent a sign-in page that isn't a plain https link; nothing was
     opened`, and nothing is opened (#5422; not yet observed against Kind).
  4. Each again piped and with `TERM=dumb`: the plain URL, no hint, no
     waiting line, no escape sequences, and keys aren't read.
- **Proof:** pty output with escapes shown holds the OSC 8 hyperlink around
  the URL, and, after `c`, the OSC 52 sequence whose base64 payload is the
  URL, then `✓ Copied`. Piped output holds no ESC byte.
- **Gotchas:** `c` copies only before anything is typed; a code typed by
  hand that starts with `c` loses its first letter, but codes are pasted. A
  terminal that ignores OSC 52 shows `✓ Copied` without copying; on the
  desktop `pbcopy`, `wl-copy` or `xclip` copies as well. The link is no
  longer copied when the screen appears.
- **Observed:**
  - Linux local VM, #4885 at aea6abdb8 (built `cw`), 2026-11-16, a
    pseudo-terminal with `TERM=xterm-kitty` and a throwaway HOME and state;
    no sign-in was completed and nothing was saved:
    - step 1, `--local connect claude --name walk`: screen 4 as approved,
      with the OSC 8 link alone on its line and the hint under it. `c` at
      the empty prompt sent one OSC 52 and printed `✓ Copied`, then redrew
      the prompt. Bracketed paste was on while the prompt read and off after
      it. Esc cancelled with exit 1;
    - step 2, `--local connect codex --name walk`: screen 3 as approved, with
      the first-time note and its settings link under the title, the link
      and hint, the code alone under "Enter this code:", and the waiting
      line counting. `c` printed `✓ Copied` above the waiting line. One
      Ctrl-C printed `✗ Login cancelled; no credential was changed` and
      exited 1 at once, so a second Ctrl-C found `cw` already gone. The 130
      exit applies only while a cancel is slow, and that is not yet observed;
    - no OSC 52 was sent before `c`, in either walk.
  - GitHub, `cw login`, piped, `TERM=dumb`, over SSH, the cloud placement and
    the Mac: not yet observed.

## 9. `profile-revisions`: a profile's revisions, listed

- **Entry points:** `cw credentials --local --profile NAME revisions` and
  `cw credentials --cloud --profile NAME revisions`, each with `--output
  json`.
- **States to exercise:**
  - a profile with one revision;
  - a profile changed twice, so three revisions;
  - a profile name that does not exist, which exits non-zero in both.
- **Driving it:** with a throwaway `HOME` and a synthetic credential named
  `parity-revisions`, for each placement:

  ```sh
  cw credentials --PLACEMENT --profile parity-revisions set codex parity-revisions
  cw credentials --PLACEMENT --profile parity-revisions unset codex
  cw credentials --PLACEMENT --profile parity-revisions set codex parity-revisions
  cw credentials --PLACEMENT --profile parity-revisions revisions
  cw credentials --PLACEMENT --profile parity-revisions revisions --output json
  cw credentials --PLACEMENT --profile parity-missing revisions
  ```

  Then delete the profile and the credential.
- **Proof:** both placements print revisions 1, 2 and 3 oldest first, in
  the columns REVISION and CREDENTIALS, what each held by kind and name.
  Revisions 1 and 3 hold "Codex: parity-revisions". Revision 2 holds "none
  yet" locally, and in the cloud only "GitHub: account connection", which
  every cloud profile includes. IDs appear only in `--output json`, whose
  rows have the same fields in both, except that a cloud row has
  `github_connection` and no `owner`. One revision is shown with `--profile
  parity-revisions get --revision 2`.
- **Gotchas:**
  - The cloud walk needs a `cw login` session, not an organization API key.
    Profiles are personal, and the service refuses organization keys.
  - A cloud build from before #4887 refuses `revisions` with "cloud
    profiles have no revision list yet" ("platform history listing is not
    supported" before #5183). Check the CLI and Dev's source.
- **Observed:** not yet observed.

## 10. `profile-default`: the default profile a create uses

- **Entry points:** `cw credentials --local profiles default NAME` and
  `cw credentials --cloud profiles default NAME`; `cw credentials
  --PLACEMENT profiles list`; `cw create --local` and `cw create --cloud`
  with no `--profile`.
- **States to exercise:**
  - a store with no profiles: create says nothing about a profile;
  - the store's first profile: it becomes the default;
  - a second profile made the default: create uses it, and `--no-profile`
    selects none;
  - deleting the default: refused;
  - local only, a store from before defaults (schema 5) with profiles: no
    default, so create uses no profile and says so, and a profile added
    afterwards does not become the default (#4717).
- **Driving it:** with a throwaway `HOME` and synthetic credentials named
  `parity-default-*`, for each placement:

  ```sh
  cw credentials --PLACEMENT --profile parity-default-a set codex parity-default-a
  cw credentials --PLACEMENT profiles list
  cw credentials --PLACEMENT --profile parity-default-b set codex parity-default-b
  cw credentials --PLACEMENT profiles default parity-default-b
  cw credentials --PLACEMENT --profile parity-default-b delete
  cw --PLACEMENT create --name parity-default-env
  cw --PLACEMENT create --name parity-default-bare --no-profile
  ```

  A bare word after `create` is read as a repository, so the name takes
  `--name`. Locally without a terminal, `create` also needs `--yes` to
  confirm its source selection (found in #5237's walk). Then delete the
  environments, make `parity-default-a` the default, and
  delete both profiles' credentials and `parity-default-b`.
- **Proof:**
  - `profiles list` lists `parity-default-a` first, marked default.
  - After `profiles default`, both placements print `Default profile:
    "parity-default-b".` with their own placement word.
  - The delete exits non-zero with `"parity-default-b" is your default
    profile and can't be deleted; make another profile the default first:
    cw credentials --PLACEMENT profiles default NAME`.
  - The first create prints `Credential profile: parity-default-b (your
    default; --no-profile creates without one)`, and its environment
    selects that profile. The second selects none.
  - On an upgraded local store with profiles, create prints `Credential
    profile: none (no default; set one with cw credentials --local
    profiles default NAME)` and selects none.
- **Gotchas:**
  - The local default needs authority protocol 18. A `cw` update while a
    local VM runs keeps the older authority, which has no default: stop
    the VMs and run the command again.
  - A cloud profile cannot be deleted while it is the default either. The
    walk's last profile stays until another is made the default.
- **Observed:** not yet observed.

## 11. `cred-delivery-diagnosis`: see why a credential didn't reach a local VM

Issue: #4882. The rules are in `docs/dev/SECRETS-AND-CREDENTIALS.md`,
"Diagnosing delivery in a local VM". Local VMs only: a hosted Sandbox's daemon
lines are in its Pod log.

- **Entry points:** `cw --local daemon logs ENV`.
- **States to exercise:**
  - a running VM whose profile holds a Claude sign-in: the writer's outcome
    and the admitted lease are both shown;
  - a running VM whose profile holds a synthetic Claude token: no login is
    written, and the lease for the model request is shown;
  - a running VM with no profile: the guest daemon part has lines, and the
    leases part says none are recorded;
  - a stopped VM: the guest daemon part says the VM is not running, and the
    leases recorded while it ran are still listed;
  - a VM still running on the guest it was started with before the `cw`
    update that brought this command: the guest daemon part says the guest is
    older and that a restart brings the lines. Drive it as
    [local-vm-upgrade.md](local-vm-upgrade.md) does: start the VM on v0.4.22
    or earlier, update `cw` without `--vms`, then run the command;
  - no credential authority running: the leases part says so, and the command
    starts none. No command stops an authority while a VM runs, so a test
    holds this state and the walk skips it.
- **Driving it:** with the throwaway `HOME` and store of
  [Before the walk](#before-the-walk), a synthetic token named
  `diag-token`, and environments named `diag-*`. The token is made in a
  shell variable and piped in, so it is never typed, echoed or recorded:

  ```sh
  DIAG_TOKEN="sk-ant-oat01-$(head -c 96 /dev/urandom | base64 | tr -dc A-Za-z0-9 | head -c 95)"
  printf '%s' "$DIAG_TOKEN" | cw credentials --local connect claude-token --name diag-token
  cw credentials --local --profile diag-profile set anthropic diag-token
  cw --local create --name diag-env --profile local:diag-profile --yes
  cw --local exec --in diag-env -- claude -p hi
  cw --local daemon logs diag-env
  cw --local create --name diag-bare --no-profile
  cw --local daemon logs diag-bare
  cw --local stop diag-env
  cw --local daemon logs diag-env
  ```

  A create that selects a profile shows its sources and asks before it
  submits them; `--yes` answers that where there is no terminal. In a fresh
  store `diag-profile` becomes the default profile
  (`profile-default`), so `diag-bare` needs its `--no-profile`. The sign-in
  state uses the profile from `cred-claude-sign-in` in place of
  `diag-profile`. Afterwards remove `diag-env`, `diag-bare`, `diag-profile`
  and `diag-token`, and unset `DIAG_TOKEN`.
- **Proof:**
  - The output has three heading lines, in this order: operations, guest
    daemon, credential leases. Every guest daemon line starts with `guest: `.
  - With the sign-in, the guest daemon part holds a line with
    `claude_login=Written` (or `Current` on a later check), and the leases
    part a line with the `claude-login` operation and route and the decision
    `admitted`.
  - With the synthetic token, the leases part holds a line for the model
    request with the decision `admitted`, at the environment's current
    generation, after Anthropic refused the token.
  - `diag-bare` lists no lease, and none of `diag-env`'s.
  - The three `daemon logs` outputs hold no part of the synthetic token, no
    credential name and no credential id: `grep -c -F -e diag-token -e
    "${DIAG_TOKEN:13:12}"` over them prints 0. Record the count, never the
    token. `cw`'s own connect and profile lines name `diag-token`; no output
    of any step holds the token.
  - The stopped VM's output says the VM is not running where the guest
    daemon lines were, and still lists `diag-env`'s leases.
- **Gotchas:**
  - Guest daemon lines live in the VM's memory: a stop or restart clears
    them, so read them before stopping a VM that failed.
  - Lease decisions live in the authority's memory: after it restarts the
    part is empty until the VM asks again.
  - A VM started before the update keeps its older guest until it restarts.
- **Observed:**
  - Linux local VM, #5237 at a8c2d9625, 2026-11-17, a `cw` and a runtime
    built from that commit, a throwaway `HOME` and Secret Service, both VMs
    with `--cpu 2 --memory 4GB`; the outputs are on #5237:
    - the token: `claude -p hi` exited 1 with Anthropic's "401 OAuth access
      token is invalid"; `daemon logs` showed the three headings, six
      `guest: ` lines (the logins cleared, onboarding prepared) and four
      lease lines, `slot=anthropic operation=messages route=anthropic-api
      decision=admitted credential=selected` at generation 1;
    - no profile: six `guest: ` lines, and "no lease decisions recorded for
      this environment since the credential authority started";
    - stopped: "guest daemon log unavailable: the VM is not running", with
      the same four lease lines;
    - the count over the three `daemon logs` outputs was 0, and no step's
      output held the token;
    - not yet observed: the sign-in state (`claude_login=Written` beside a
      `claude-login` lease), and a VM on the guest from before the update.

## 12. `cred-provider-unresolved`: a provider's name doesn't resolve when a local VM starts

Issue: #5286. The rules are in `docs/dev/SECRETS-AND-CREDENTIALS.md`, "A
provider that can't be looked up when a local VM starts". Local VMs only: a
hosted Sandbox's broker is the platform's.

- **Entry points:** `cw create --local --profile`, `cw --local start`, and
  the agent's requests in the VM.
- **States to exercise:**
  - a profile with one API key whose provider's name does not resolve on the
    host: create, and start after a stop;
  - a profile with two providers, one resolving and one not, and an SSH key;
  - the name resolving again while the VM runs;
  - the name resolving only to an address Codewire will not dial (a private
    one);
  - the host offline altogether.
- **Driving it:** with the throwaway `HOME` and private store of
  [Before the walk](#before-the-walk), synthetic keys, and the name made
  unresolvable for the host's `cw` (a resolver that does not answer for it).
  `scripts/ci/verify/smoke-local-credentials.sh` runs the core of it as
  `smoke-provider-unresolved`
  ([local-vm-credentials-smoke.md](local-vm-credentials-smoke.md)): steps 1,
  2 and 5, the refusals of step 3, and the broker's recovery of step 4. By
  hand:
  1. `cw credentials --local add anthropic --name unres-anthropic` and
     `add openai --name unres-openai`, keys from stdin; `set` both in
     profile `unres`, with an SSH key.
  2. `cw create --local --name unres-env --no-file --profile local:unres
     --yes`, with one provider's name unresolvable.
  3. In the VM, a request on each provider's route, and `ssh -T` through the
     profile's key.
  4. Make the name resolvable, wait a minute and a half, and repeat the
     request.
  5. `cw --local stop unres-env`, `cw --local start unres-env` with the name
     unresolvable again; then remove the VM, the profile and the keys.
- **Proof:**
  - step 2 succeeds, in the time a create with `--no-profile` takes plus at
    most five seconds;
  - the resolving provider's request reaches it (a synthetic key gets the
    provider's own 401), SSH signs, and the other provider's request gets
    502 with `Codewire: PROVIDER couldn't be reached; try again.`;
  - the credential service's `brokers.log` has `broker_ready` with
    `unresolved=` naming exactly the unresolvable host;
  - after step 4 the request reaches the provider with no restart, and the
    log has a later `broker_ready` without that host;
  - with a sign-in in the profile and its token host unresolvable, the
    sign-in is still usable once the name resolves: no refresh was begun
    while it did not.
- **Gotchas:**
  - A host firewall that filters by process may answer the broker's lookup
    and not another `cw` process's, or the other way round: the lookup that
    counts is the broker's own (`cw __local-credential-broker`).
  - A `cw` built against the system C library uses its resolver, whose
    timeout may be longer than five seconds.
- **Observed:**
  - Linux, released v0.4.22, 2026-11-18: failure observed, the symptom #5286
    fixes. In the smoke library's private store, with a synthetic Anthropic
    key in the profile and the broker's lookup of `api.anthropic.com`
    dropped by the host's firewall, `cw create --local --profile` failed
    twice with `create_failed` and "the local VM runtime gave no cause";
    each broker ended `CW_BROKER_EXIT stage=provider.resolve kind=other`
    5.02 s after its start, and `brokers.log` read `broker_not_ready
    reason=lease_closed_before_ready … error=-`. With the lookup answered,
    the same create started and `broker_ready` came after 0.2 s.
  - Linux, a static `cw` built from #5295 at bdcb89c00, 2026-11-18, in the
    smoke library's private store with made-up keys, the host's firewall
    dropping this `cw`'s broker lookups of `api.anthropic.com` and
    `api.openai.com`. Step 2 succeeded; `broker_ready` came after 5.07 s
    with `unresolved=api.anthropic.com/api.openai.com`. Both routes answered
    502 `Codewire: PROVIDER couldn't be reached; try again.`, and `ssh-add
    -l` in the VM listed the profile's key. With `api.openai.com` answered
    again, the regular replacement 510 seconds after the broker's start came
    up with `unresolved=api.anthropic.com`, and OpenAI answered the made-up
    key itself (401) with no restart. Step 5: the start took 15 s, with the
    same `unresolved=` and the same two answers. With every name answered,
    the same `cw` had `unresolved=-` after 0.3 s and both providers' own
    401s.
  - Linux, the early replacements (bdcb89c00 plus their change), 2026-11-18,
    same setup with
    only `api.anthropic.com` dropped. Early brokers started 5, 10, 20 and
    40 seconds apart (`broker_spawned`), each ending after its 5-second
    lookup while the name stayed dropped. The name was answered again 13
    seconds before the fourth, which came up in 0.08 s with `unresolved=-`:
    Anthropic then answered the made-up key itself (401), with no restart.
  - Linux, `main` at 4cae0f601 (a static `cw` and the runtime from that
    commit), 2026-11-18, through `smoke-provider-unresolved`: with both
    names unanswered for the credential service inside the smoke's own
    namespace, the create succeeded, both routes answered 502 in Codewire's
    words, a stop and start came back running, and a broker served both
    providers again within two minutes of the names resolving. Released
    v0.4.22 fails the same step at the create.
  - macOS 27.2.1, a development build of main's tree at 57b68c6be (#5295
    with #5312's compile fix), 2026-11-18, by cw-mac, in a scratch `HOME`
    with a throwaway keychain (`CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN`),
    synthetic Anthropic and OpenAI keys and a generated SSH key in profile
    `unres`, and `api.openai.com` pointed at `10.255.255.1` and `fd00::1`
    in `/etc/hosts`. One IPv4 line was not enough: DNS still gave the name
    public IPv6 addresses. The create took 57.9 s, against 59.3 s with
    `--no-profile`. In the VM, Anthropic answered the synthetic key with its
    own 401, OpenAI's route got 502 `Codewire: OpenAI couldn't be reached;
    try again.`, and the agent offered the profile's SSH key. `brokers.log`
    read `broker_ready … elapsed_ms=447 unresolved=api.openai.com`. With the
    lines removed, the route got OpenAI's 401 at 423 s, with no restart, and
    a later `broker_ready … unresolved=-`: the regular replacement, since
    the early ones are not in that tree. A stop, then a start with the name
    unreachable again, started in 6.2 s with `unresolved=api.openai.com`.
    Commands and outputs: #5286.
  - Not walked on Linux: a name that resolves only to an address Codewire
    will not dial (walked on the Mac above), and on both, a sign-in whose
    token host is unresolvable. Unit tests cover
    both (`resolution_for_a_start_leaves_a_failed_host_unresolved_and_serves_the_rest`,
    `a_forced_refresh_is_not_begun_toward_a_provider_with_no_address`,
    `a_github_app_refresh_is_not_begun_toward_an_endpoint_with_no_address`).

## 13. `cred-file-store`: a Linux root that keeps its credentials inside itself

The spec is
[Linux file store](../dev/SECRETS-AND-CREDENTIALS.md#linux-file-store-5255).

- **Entry points:** `local_credential_store = "file"` in the root's
  `config.toml`, and `cw credentials --local list`.
- **States to exercise:**
  - a new root with `file` set: credentials go to `ROOT/protected-v1` and
    nowhere else;
  - a second root with nothing set, from a released or a development
    build: Secret Service, and the one-line keyring warning before each
    write;
  - an existing Secret Service root after the update, setting unset: it
    stays on Secret Service;
  - a `protected-v1` file or directory with the wrong mode or owner:
    refused, not repaired;
  - a local VM started from a `file` root: its broker serves a lease from
    the file store;
  - a sign-in due for refresh in a VM from a `file` root (#5539): the
    broker only reads `protected-v1`, so it sends the refreshed bundle in
    Commit and the authority stages it. A due Claude or Codex sign-in's
    request goes through with the refreshed login, and a due GitHub login
    renews before `git` runs.
- **Driving it:** Linux only, with a throwaway `HOME`, synthetic credentials
  named `parity-file-*`, and no session bus for the `file` states (unset
  `DBUS_SESSION_BUS_ADDRESS`). The Secret Service states run only in the
  private keyring of [Before the walk](#before-the-walk).

  ```sh
  (umask 077 && printf 'local_credential_store = "file"\n' >> "$HOME/.codewire/config.toml")
  chmod 600 "$HOME/.codewire/config.toml"
  printf '%s' "$SYNTHETIC_KEY" | cw credentials --local add anthropic --name parity-file-key
  cw credentials --local list
  ls -l "$HOME/.codewire/credentials-v1/protected-v1"
  ```
- **Proof:**
  - `list` says on stderr `Store: files in ROOT/protected-v1, not
    encrypted by cw (protected by file permissions and your disk
    encryption)`, and `list --output json` gives each credential
    `"protected_store": "file"`.
  - `protected-v1` is 0700 and each entry 0600, all owned by the user.
  - With no session bus, the add succeeds and nothing asks for a keyring.
  - The upgraded Secret Service root lists the same store before and after
    the update.
  - A `chmod 0644` entry makes the next read fail with the store's refusal,
    and the mode stays 0644.
  - Removing the throwaway `HOME` leaves no Codewire entry in the private
    keyring.
  - The due sign-in's request succeeds, `brokers.log` shows no broker
    ending, the credential is at material generation 2, and the journal has
    no refresh row left: the authority staged and promoted the bundle.
- **Gotchas:**
  - entries are plaintext: never walk it with a real credential;
  - `config.toml` must be the user's alone (0600): a file the default umask
    makes 0644, or one a reused `HOME` already had, is refused before
    anything runs;
  - `cw credentials` commands read only metadata, so a `chmod 0644` entry is
    refused at the next read of its material, a VM's lease, not by `list`.
- **Observed:** partly, on a Linux local VM (x86_64, KVM), 2026-11-20, with
  `cw` from main 22bcc705e (#5552) and the guest runtime of main 8f3a2d502,
  a throwaway `HOME` with no session bus and one synthetic Anthropic API key.
  `list` printed the file-store line, and a local VM from the `file` root
  was served a lease: with interception on, the placeholder request reached
  Anthropic with the stored key swapped in (Anthropic's own 401 for an
  invalid key), and with it off, the loopback route did the same. On main
  before #5552 both routes answered `CredentialUnavailable` within
  milliseconds.

  On 2026-11-21, with `cw` from main 8880d56e7 (plus #5817, which changes
  orchestration only) in the local smoke isolation (a private `HOME`, D-Bus
  and Secret Service, inside a mount namespace) and synthetic Anthropic keys:
  - a new `file` root put the key in `protected-v1` and nowhere else (the
    directory 0700, the entry 0600, both the user's); `list` printed the
    file-store line and `--output json` gave `"protected_store": "file"`;
    the private keyring held no item before, after or at the end;
  - a root with nothing set printed the one-line Secret Service warning
    before the write, listed `"protected_store": "secret-service"` with no
    material under its `credentials-v1`, held one item in the private
    keyring, and a delete left none.

  Not yet observed: an existing Secret Service root after the update, a
  `chmod 0644` entry's refusal (it needs a VM's lease to read the material),
  and a due sign-in's refresh in a VM from a `file` root.

## 14. `cred-same-name`: one name for a credential of each provider

Issue: #4928. The rules are in `docs/dev/SECRETS-AND-CREDENTIALS.md`,
"Credential names". The owner labels credentials by account: a Claude
sign-in and a Codex sign-in both named after their email address.

- **Entry points:** `cw credentials --local|--cloud connect`, `add`, `get`,
  `rename`, `delete` and `--profile P set`, and the dashboard's credential
  list and add form.
- **States to exercise:**
  - the same name under two providers, in each placement;
  - a bare name that matches more than one credential;
  - `PROVIDER/NAME` acting on the named one only;
  - a name already taken in the same provider (a Claude sign-in and a Claude
    token);
  - a store made before the change, holding a credential literally named
    `github/work` beside a GitHub credential named `work`;
  - in the cloud, an organization's credential looked up by someone who
    isn't a member.
- **Driving it:** the throwaway `HOME` and private store of
  [Before the walk](#before-the-walk). The owner's own steps use real
  sign-ins, removed at the end; the rest use synthetic keys from stdin.
  1. `cw credentials --local connect claude --name walk`, then
     `cw credentials --local connect codex --name walk`.
  2. `cw credentials --local list`, and `get walk`.
  3. `get openai/walk`, then `rename openai/walk walk-codex` and back.
  4. `cw credentials --local connect claude-token --name walk`.
  5. `--profile same set anthropic walk` and `--profile same set codex walk`,
     then `cw create --local --profile local:same` and a request on each
     provider's route in the VM.
  6. `delete openai/walk` while the profile selects it, then
     `--profile same unset openai`, `delete openai/walk` and `list`.
  7. Steps 1 to 6 again with `--cloud` on Dev, and the dashboard's list.
  8. On Dev, a second account that isn't a member of the organization runs
     `get NAME` for a name two of the organization's credentials share.
- **Proof:**
  - step 1: both connects succeed; neither says the name is in use;
  - step 2: `list` shows both, each with its provider; `get walk` changes
    nothing and answers `"walk" names more than one credential (anthropic,
    openai); name one, for example anthropic/walk`;
  - step 3: only the Codex credential is shown and renamed;
  - step 4: refused, naming the Claude sign-in that holds `walk` and
    suggesting a free name;
  - step 5: each slot takes its own provider's `walk`, and each request
    reaches its provider;
  - step 6: the first delete is refused, naming profile `same` and the
    `unset` that frees it; after the unset, only the Codex credential is gone;
  - step 7: the same in the cloud, and the dashboard shows the provider
    beside each name;
  - step 8: `not found`, exactly as for a name that doesn't exist, with no
    provider listed.
- **Observed** on Linux, released v0.4.26, 2026-11-21, in the isolation of
  `scripts/ci/verify/lib/local-smoke-isolation.sh`, with made-up API keys:
  - steps 1 and 2: `add anthropic --name walk` and `add openai --name walk`
    both succeeded; `list` showed `walk` as an Anthropic API key and as an
    OpenAI API key; `get walk` answered `✗ "walk" names more than one
    credential (anthropic, openai); name one, for example anthropic/walk`
    and the next `list` was unchanged;
  - step 3: `get openai/walk` showed only the OpenAI key, and the rename
    there and back moved only it;
  - step 4: `connect claude-token --name walk`, and `add anthropic --name
    WALK`, each answered `✗ "walk" is in use in anthropic by an Anthropic
    API key; choose another name, for example walk-2`; `add anthropic --name
    github/x` was refused as reading as a provider;
  - step 5: profile `same` held `Anthropic API key: walk, OpenAI API key:
    walk`; in the VM, `$ANTHROPIC_BASE_URL/v1/models` and
    `$OPENAI_BASE_URL/models` each answered 401 from the provider itself
    for the made-up key;
  - step 6: as the proof above.
- **Gotchas:**
  - A `cw` older than the change, talking to a store that already holds the
    same name twice, is refused by the store rather than given one of them.
  - Names are case-insensitive: `Walk` and `walk` are the same name in one
    provider.

## 15. `cred-wording`: the words every step shows

Issue: #4938. The words are in `docs/GLOSSARY.md`, "Words users see:
credentials", from the approved credentials screens; cw-web walks the
dashboard's half.

- **Entry points:** every step above, CLI and dashboard; `cw credentials
  --help` and each subcommand's `--help`.
- **States to exercise:** each refusal C4 lists, a cancelled prompt, nothing
  entered, a profile slot given the wrong kind, and `--expires-at` with a
  date.
- **Driving it:** walk steps 1 to 9 again in both placements, reading every
  line for wording rather than behaviour; run
  `python3 scripts/checks/repo_checks.py credential-words`.
- **Proof:** no line on screen uses a word from the glossary's "Never on
  screen" column; the check passes; every option's `--help` line says what
  it takes; a cancelled prompt reads "Cancelled; nothing was changed."
- **Gotchas:** the check reads only the files its contract lists
  (`scripts/checks/contracts/credential-words.json`) and skips the
  exceptions it names; a word outside those files is caught only by the
  walk.
- **Observed:** not yet observed.

## 15. `cred-pickers`: what each guided picker offers

Issues: #5446 (the rule and its test), #4985 (the four `connect` rows), #4717
(the approved credentials screens). The owner's report on #5446, a `connect`
picker with only Codex and GitHub, came from an installed v0.4.18; v0.4.22 is
the first release with the four rows.

- **Entry points:** `cw credentials --local|--cloud connect` and `add` with
  no provider, and `cw credentials --local|--cloud --profile P set` with no
  slot, at a terminal. The placement may also follow the subcommand
  (`cw credentials connect --local`).
- **States to exercise:** each placement; no credentials yet and some
  already saved (the pickers hide nothing); Esc at a picker, which changes
  nothing.
- **Driving it:**
  - `connect` with no provider. Expect "What do you want to connect?" with
    four rows, label then detail, in this order, in both placements:
    `Codex  sign in with your ChatGPT account`, `GitHub  sign in with your
    GitHub account`, `Claude (sign-in)  your subscription; shows your plan
    and usage` and `Claude (token)  your subscription; lasts a year, for
    automation, model requests only`. Pick Claude (sign-in), give a name,
    and it connects as step 6 shows.
  - `add` with no provider. Expect "Which provider?" with `OpenAI API key`,
    `Anthropic API key` and `SSH private key`, in that order, in both
    placements. API keys are under `add`, not `connect`; `add
    claude-subscription`, the alias of `connect claude-token` (#4945), is
    not a row.
  - `--profile P set` with no slot. Expect "Which provider should this
    profile use?" with `codex`, `openai`, `anthropic` and `ssh`: every slot
    but GitHub's, which every profile includes.
- **Proof:** each picker shows exactly the rows above, in that order, in
  both placements, and picking Claude (sign-in) ends in `✓ Claude (sign-in)
  connected as ACCOUNT`. `cargo test -p codewire-cli picker` holds each
  picker's rows to the set its command accepts in each placement, and fails
  when a provider is accepted but not offered.
- **Gotchas:** walk a released `cw`, the one the owner installs, and record
  its `cw --version`: no release before v0.4.22 has the Claude (token) row,
  and v0.4.18 and v0.4.20 show only Codex and GitHub locally.
  Locally, walk only against a private keyring, as "Before the walk" says.
- **Observed:** not yet observed. The walk on a Mac and in the cloud, on a
  released `cw` (v0.4.22 or later), is still to do.

## 16. `cred-github-notice`: GitHub's pending permissions, on the dashboard's Credentials page

The dashboard's Credentials page tells a person whose GitHub connection has not
yet accepted Codewire's updated permissions (#2712). The notice used to be part
of the page, so every render of the page waited on a live call to GitHub: on
Production 574 to 648 ms, and 2 s when the call hit its bound (#5206). It now
appears after the page has loaded.

- **Entry points:** the dashboard at `/settings/credentials/`, signed in. Only
  the dashboard shows it; `cw credentials` is not part of this step.
- **States to exercise:**
  - no GitHub connection: no notice, and no request for it;
  - a GitHub connection that has accepted the permissions: the page loads, and
    no notice appears;
  - a connection with an update pending: the page loads first, then the notice
    "GitHub is waiting for you to accept Codewire's updated permissions on
    ACCOUNT", with its "Review on GitHub" link, appears in place within 2 s,
    in a polite live region, without moving focus or closing a dialog that a
    `?dialog=` link opened;
  - the check is slow or fails: no notice, and never GitHub's error text, a
    token fragment or a scope the person cannot already see; the page's trace
    has a `github_pending_permissions` span whose `outcome` says why (`ok`,
    the Connect code, or `timed_out`);
  - a session the page turns away (no two-factor, a second session cookie, an
    `Authorization` header): an empty answer, and no call to GitHub;
  - reloads within 45 s: the page does not ask GitHub again, and the notice
    shows what the same person's last check found, or nothing. A GitHub
    connect or reconnect that completes ends that person's window, so the
    notice reflects the new connection on the next load;
  - a load another site started, and a request without `Sec-Fetch-Site:
    same-origin` or without the fragment header: refused, and no call to GitHub;
  - JavaScript off: the page works and the notice never shows. It is advisory.
- **Driving it:** on Dev, as a person whose GitHub App connection lacks the
  current permissions. Load `/settings/credentials/` in a browser, read the
  `Server-Timing` header of the page (#5217), then watch the notice appear;
  reload ten times in a row; and request the fragment from another origin.
- **Proof:**
  - the page's `Server-Timing` total is under 500 ms, and has no `github`
    phase;
  - the notice appears within 2 s of the load, in the page's own markup;
  - the credential service logged at most one `ListGithubPendingPermissions`
    call for that person in each 45 s, however many times the page loaded;
  - the cross-site and header-less requests answer 403 and add no
    `ListGithubPendingPermissions` line;
  - the edge's p95 for `/settings/credentials/` on Dev is under 500 ms.
- **Gotchas:** a pending update needs a GitHub App installation that lacks the
  new permission, which only the owner's GitHub account can set up, so a walk
  without one can prove everything but the notice itself. The fragment is a GET
  that can cause GitHub to renew a token, which is acceptable only because of
  the same-origin refusal.
- **Observed:** not yet observed.

