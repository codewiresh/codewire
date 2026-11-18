# Credentials

Connecting provider credentials with `cw credentials` and using them in an
environment, the same with `--local` (the operating system's protected store)
and `--cloud` (the platform credential service), as the local and cloud
parity audit records (#4717). Each setup is walked on three surfaces: a local
VM on Linux, a local VM on a Mac, and a hosted Sandbox on Dev. A walk on one
surface proves nothing about another. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-18. Every step not listed as observed is **not yet
observed**.

| ID | Linux local VM | Mac local VM | Hosted Sandbox (Dev) |
| --- | --- | --- | --- |
| `cred-github` | not yet observed | not yet observed | not yet observed |
| `cred-codex-sign-in` | not yet observed | not yet observed | not yet observed |
| `cred-openai-key` | not yet observed | not yet observed | not yet observed |
| `cred-anthropic-key` | not yet observed | not yet observed | not yet observed |
| `cred-claude-setup-token` | not yet observed | not yet observed | not yet observed |
| `cred-claude-sign-in` | observed, #4798 at f5657302c, 2026-11-15 (steps 1–4; the plan and `/usage`, step 5, not yet observed) | login file observed, #4868 at b4541bf05, 2026-11-15 (steps 1–3 and the file; `claude -p`, `/status` and `/usage` not yet observed: the guest had no network, #4948) | link screen and paste prompt observed, v0.4.18, 2026-11-14; a completed sign-in not yet observed |
| `cred-ssh-key` | not yet observed | not yet observed | not yet observed |
| `cred-sign-in-screen` | partly observed, #4885 at aea6abdb8, 2026-11-16 (steps 1 and 2 for Claude and Codex at a pty; GitHub, `cw login`, piped, `TERM=dumb` and SSH not yet observed) | not yet observed | not yet observed |
| `profile-default` | not yet observed | not yet observed | not yet observed |
| `cred-delivery-diagnosis` | not yet observed | not yet observed | local VMs only |
| `cred-provider-unresolved` | observed, #5286: #5295 at bdcb89c00, and the early replacements on that build plus their change, 2026-11-18 (a name that resolves only to an address Codewire won't dial, and a sign-in's token host, not walked) | not yet observed | local VMs only |

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
   keychain` on macOS. When it gives up (the keyring's bound is 2 minutes, so a
   person can still answer a prompt), the command says the keyring didn't
   answer and gives the next step: unlock it, or restart it, then run the
   command again, or keep the credential on the platform. It shows no gRPC or
   transport text and exits non-zero. `cw doctor` reports a missing, locked
   or unanswering local store as a warning with the same next step. Walk it only inside a private D-Bus
   session (`scripts/ci/verify/lib/local-smoke-isolation.sh`) with its keyring
   stopped, never the host's keyring (#5271). Not yet observed.
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
   the section's check inside the environment.
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
    nothing is removed. Not yet observed.

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
- **Remove:** in the cloud, delete also asks OpenAI to revoke the sign-in,
  and `cw` says whether OpenAI confirmed it. Locally `cw` doesn't ask yet
  (#4717, C6 part b2) and says the sign-in stays valid until it expires, and
  that you can sign out of all ChatGPT devices under Settings → Security.

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
  - with a local VM running: the store stays, the connect goes on without
    the check, and `cw` prints `! Couldn't check the local credential store
    first: it's still the one the cw you updated from started, while local
    VMs run.` before the link;
  - with no local VM running: the store is replaced before the link, and the
    check runs; with the login keychain locked, the connect stops there with
    the store's own sentence, before any link.

  Not yet observed.
- **Stopped mid-refresh:** a local store whose authority stopped during the
  sign-in's refresh (killed, a crash or a power loss) still opens, and
  `cw credentials --local list` shows the sign-in refreshed, as it was, or
  **Reconnect needed** (#5177). Not yet observed.
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

## 10. `cred-delivery-diagnosis`: see why a credential didn't reach a local VM

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
  cw --local create diag-env --profile local:diag-profile
  cw --local exec --in diag-env -- claude -p hi
  cw --local daemon logs diag-env
  cw --local create diag-bare --no-profile
  cw --local daemon logs diag-bare
  cw --local stop diag-env
  cw --local daemon logs diag-env
  ```

  In a fresh store `diag-profile` becomes the default profile
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
  - The whole output holds no part of the synthetic token, no credential
    name and no credential id: `grep -c -F -e diag-token -e
    "${DIAG_TOKEN:13:12}"` over it prints 0. Record the count, never the
    token.
  - The stopped VM's output says the VM is not running where the guest
    daemon lines were, and still lists `diag-env`'s leases.
- **Gotchas:**
  - Guest daemon lines live in the VM's memory: a stop or restart clears
    them, so read them before stopping a VM that failed.
  - Lease decisions live in the authority's memory: after it restarts the
    part is empty until the VM asks again.
  - A VM started before the update keeps its older guest until it restarts.
- **Observed:** not yet observed.

## 11. `cred-provider-unresolved`: a provider's name doesn't resolve when a local VM starts

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
  unresolvable for the host's `cw` (a resolver that does not answer for it):
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
  - Not walked: a name that resolves only to an address Codewire will not
    dial, and a sign-in whose token host is unresolvable. Unit tests cover
    both (`resolution_for_a_start_leaves_a_failed_host_unresolved_and_serves_the_rest`,
    `a_forced_refresh_is_not_begun_toward_a_provider_with_no_address`,
    `a_github_app_refresh_is_not_begun_toward_an_endpoint_with_no_address`).
