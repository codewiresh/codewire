---
title: Provider credentials
description: Connect Codex, add OpenAI and Anthropic keys, a Claude subscription token or sign-in, SSH keys and GitHub, then build the credential profile an environment uses.
weight: 3
---

A provider credential is stored once, then selected through a credential
profile. Its private material never enters an environment; see
[Secrets and credentials](@/concepts/secrets-and-credentials.md).

Every credential command names its store: `--cloud` for the platform (used by
hosted sandboxes, usable by local VMs) or `--local` for the protected store on
your machine (the Secret Service on Linux, the Keychain on macOS; local VMs
only). Put the flag before the subcommand. At a terminal, `cw` asks when you
omit it; scripts and `--output json` must pass one. API keys and tokens are
read from a hidden prompt or standard input, never from the command line.

## Codex (ChatGPT sign-in)

First turn on **Enable device code authorization for Codex** in ChatGPT's
Security settings. Then:

```sh
cw credentials --cloud connect codex --name work-codex
```

`cw` shows a code and a URL, waits for you to approve in the browser, and
stores the login. Repeat the command with the same name to reconnect (`--yes`
skips the confirmation). Sign-ins are personal: an organization cannot hold
one.

## API keys

```sh
printf '%s' "$OPENAI_API_KEY" | cw credentials --cloud add openai --name work-openai
printf '%s' "$ANTHROPIC_API_KEY" | cw credentials --cloud add anthropic --name work-anthropic
cw credentials --cloud rotate work-openai        # replace the key; clears a hard expiry unless --expires-at
```

## Claude subscription token or sign-in

A Claude Pro, Max, Team or Enterprise plan can serve Claude Code instead of an
API key. Both forms are platform credentials (`--cloud`).

**Subscription token**: run `claude setup-token` on your own machine, then add
the printed token at once:

```sh
claude setup-token
cw credentials --cloud add claude-subscription --name work-claude
```

Codewire records a one-year expiry and shows **Expires soon** in the last 30
days. Managed and interactive turns work; Claude Code shows "Claude API"
instead of your plan name and `/usage` is unavailable. Replace it with
`cw credentials --cloud rotate work-claude` or **Replace token** in the
dashboard.

**Sign-in**: `cw credentials --cloud connect claude --name claude-login` opens
Claude's authorization page and asks you to paste the code Claude shows. A
sign-in carries your plan, so `/usage` and plan features work in the sandbox;
the access token is delivered to the sandbox as Claude Code's own login file.
See the [security model](@/security.md).

The dashboard offers the API key and the subscription token under
**Settings → Credentials → Add credential**.

## SSH keys

```sh
cw credentials --cloud generate ssh --name work-ssh          # Ed25519; prints the public key
cw credentials --cloud add ssh --name my-key --key-file ~/.ssh/id_ed25519
```

Inside an environment, `ssh`, `scp` and Git use `SSH_AUTH_SOCK`; the key never
leaves the store, only signatures do. A GitHub repository clones over SSH
when the profile has a key.

## GitHub

```sh
cw credentials --cloud connect github --name work-github
```

This connects your GitHub account to the Codewire GitHub App and prints the
installation link; install the App with **Only select repositories**. Your
GitHub connection is included in every profile automatically. See
[Private repositories](@/guides/private-repositories.md).

## Build a profile

A profile has one identity per slot: `codex`, `openai`, `anthropic`, `ssh`.
The first `set` creates it.

```sh
cw credentials --cloud --profile work set codex work-codex
cw credentials --cloud --profile work set anthropic work-claude
cw credentials --cloud --profile work set ssh work-ssh
cw credentials --cloud --profile work get
cw credentials --cloud profiles list
```

Managed Codex uses the `codex` slot, or the `openai` slot without one; Claude
Code uses the `anthropic` slot. Setting a slot again makes a new revision;
environments keep the revision they selected.

## Use it in an environment

```sh
cw create --name app --image workspace --profile platform:work
cw create --local --name app --path . --profile local:work
cw update app --profile platform:work      # a confirmed restart; workspace data stays
cw update app --clear-profile
```

In the dashboard, **Create Sandbox** has a credential profile picker, and a
Sandbox's **Edit secrets and credentials** changes it later. The credentials
page shows **Needs attention** when an identity needs reconnecting.

## Inspect, revoke, delete

```sh
cw credentials --cloud list
cw credentials --cloud get work-codex
cw credentials --cloud rename work-openai personal-openai
cw credentials --cloud revoke work-openai     # stops Codewire's use at the next request
cw credentials --cloud delete work-openai     # after revoke, on the platform
```

Revocation in Codewire does not log the identity out at the provider.

## Local VMs and the Secret Service

A local VM uses `local:NAME` or `platform:NAME` profiles. The local store needs
a running, unlocked Secret Service on Linux; on macOS it is the Keychain.
`cw credentials --local connect codex` and `connect github` run the same
device logins as the platform from the `cw` process; Claude subscription
tokens and sign-ins are platform-only. When you create a local VM with a
profile that has no SSH key, `cw` asks whether to add one.
