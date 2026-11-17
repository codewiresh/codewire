# Credentials

Connecting provider credentials with `cw credentials` and using them in an
environment, the same with `--local` (the operating system's protected store)
and `--cloud` (the platform credential service), as the local and cloud
parity audit records (#4717). Each setup is walked on three surfaces: a local
VM on Linux, a local VM on a Mac, and a hosted Sandbox on Dev. A walk on one
surface proves nothing about another. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-15. Every step not listed as observed is **not yet
observed**.

| ID | Linux local VM | Mac local VM | Hosted Sandbox (Dev) |
| --- | --- | --- | --- |
| `cred-github` | not yet observed | not yet observed | not yet observed |
| `cred-codex-sign-in` | not yet observed | not yet observed | not yet observed |
| `cred-openai-key` | not yet observed | not yet observed | not yet observed |
| `cred-anthropic-key` | not yet observed | not yet observed | not yet observed |
| `cred-claude-setup-token` | not yet observed | not yet observed | not yet observed |
| `cred-claude-sign-in` | observed, #4798 at f5657302c, 2026-11-15 (steps 1–4; the plan and `/usage`, step 5, not yet observed) | failed 2026-11-15: stored, but the login never reached the VM (#4714) | link screen and paste prompt observed, v0.4.18, 2026-11-14; a completed sign-in not yet observed |
| `cred-ssh-key` | not yet observed | not yet observed | not yet observed |
| `profile-default` | not yet observed | not yet observed | not yet observed |

## Before the walk

- **Local, Linux:** never walk against the workstation's own keyring. Give the
  walk a throwaway `HOME` and a private Secret Service, its own
  `dbus-daemon` and `gnome-keyring-daemon` on a private `XDG_RUNTIME_DIR`, as
  `scripts/ci/verify/smoke-native-local-environment.sh` starts them. `cw`'s
  authority reads only `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS`, so
  that pair selects the store. The runtime is built from the same source as
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
2. **List:** `cw credentials --local|--cloud list` and `list --output json`.
   Expect the credential with its provider, kind, status `active` and, where
   the provider gives one, an account hint.
3. **Profile:** `cw credentials --local|--cloud --profile P set SLOT NAME`,
   then `--profile P get`. Expect the slot to name the credential.
4. **Use:** a local VM created with `cw create --local --profile local:P …`,
   or a hosted Sandbox created with `cw create --cloud --profile P …`, then
   the section's check inside the environment.
5. **Remove:** `cw credentials --local|--cloud delete NAME`. Expect it gone
   from `list`. The section says what remains at the provider.

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
  under the code come with #4885. A second connection under another name is
  refused, saying "GitHub is already connected as NAME" and how to
  reconnect it.
- **Ctrl-C:** pressed after approving the device code and before the save,
  it saves nothing and says so ("canceled; no credential was changed").
  Not yet observed.
- **Profile:** every profile includes the one GitHub connection; `set github`
  is refused.
- **Use:** `git clone` of a private repository the connection can read, inside
  the environment, through the broker's GitHub route. Expect the clone to
  succeed, with no GitHub token in the environment or on its disk.
- **Remove:** in the cloud, delete also revokes the authorization at GitHub.
  Locally `cw` can't (it needs the GitHub App's secret) and says to revoke it
  in GitHub's settings.

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
- **Use:** `codex` in the environment. Expect Codex signed in with the
  ChatGPT plan (`/status`), a model answer through the broker, and Codex's
  `auth.json` holding no refresh token.
- **Remove:** delete also revokes the sign-in at OpenAI in both placements.

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
  year, for automation, model requests only`, after Codex and GitHub.
- **Profile:** `set anthropic NAME`.
- **Use:** `claude -p "hi"`. Expect Claude Code in its token form
  (`CLAUDE_CODE_OAUTH_TOKEN` set to Codewire's placeholder, no token on
  disk), the broker forwarding the synthetic token and Anthropic refusing
  it.
- **Remove:** after `Local credential "NAME" deleted.` (or `Platform
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
  Locally, the store is checked before the link appears: an older store with
  a local VM running stops `cw` first, saying what to do. A missing or locked
  keychain is checked there too once the store probe lands (#4717, track
  A3); until then it is refused after the sign-in, and nothing is saved.
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
- **Remove:** `cw` says the sign-in keeps working at Claude until it expires,
  or until you sign out of other sessions in Claude's settings.
- **Gotchas:** after a `cw` update, the first local `connect claude` may
  replace the credential store the previous `cw` left running (starting the
  local VM supervisor, as a VM command does); with a local VM running, it
  stops and asks you to stop the VMs first.
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
  - Mac local VM (M3, cw-dogfood, #4798 + #4868), 2026-11-15: stored, but
    Claude Code reported "Not logged in"; the login file never arrived.
    Being diagnosed on #4714.

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

## 9. `profile-default`: the default profile a create uses

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
  cw --PLACEMENT create parity-default-env
  cw --PLACEMENT create parity-default-bare --no-profile
  ```

  Then delete the environments, make `parity-default-a` the default, and
  delete both profiles' credentials and `parity-default-b`.
- **Proof:**
  - `profiles list` lists `parity-default-a` first, marked default.
  - After `profiles default`, both placements print `Default credential
    profile: "parity-default-b".` with their own placement word.
  - The delete exits non-zero with `"parity-default-b" is your default
    credential profile and cannot be deleted; make another profile the
    default first: cw credentials --PLACEMENT profiles default NAME`.
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
