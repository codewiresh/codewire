# Credentials

Connecting provider credentials with `cw credentials` and using them in an
environment, the same with `--local` (the operating system's protected store)
and `--cloud` (the platform credential service), as the local and cloud
parity audit records (#4717). Each setup is walked on three surfaces: a local
VM on Linux, a local VM on a Mac, and a hosted Sandbox on Dev. A walk on one
surface proves nothing about another. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-17. Every step not listed as observed is **not yet
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
