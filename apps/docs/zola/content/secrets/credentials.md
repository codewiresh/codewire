---
title: Credentials
description: Connect Codex, add OpenAI and Anthropic keys, a Claude subscription token or sign-in, SSH keys and GitHub, then build the credential profile an environment uses.
updated: 2026-11-20
weight: 1
aliases: ["/guides/credentials"]
---

A provider credential is stored once, then selected through a credential
profile. Its private material never enters an environment; see
[Secrets and credentials](@/secrets/_index.md).

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
cw credentials --cloud rotate work-openai        # replace the key; clears its expiry date unless --expires-at
```

## Claude subscription: sign-in or token

A Claude Pro, Max, Team or Enterprise plan can serve Claude Code instead of an
API key, in two forms, both connected with `connect` and both your Claude
subscription: **Claude (sign-in)** shows your plan and usage; **Claude
(token)** lasts a year, for automation, and makes model requests only. Both
work with `--local` and `--cloud`.

**Token**: run `claude setup-token` on your own machine, then connect the
printed token at once (from a hidden prompt, or piped to stdin):

```sh
claude setup-token
cw credentials connect claude-token --name work-claude
```

Codewire records a one-year expiry and shows **Expires soon** in the last 30
days. Managed and interactive turns work; Claude Code shows "Claude API"
instead of your plan name and `/usage` is unavailable. Replace it by
connecting it again, `cw credentials connect claude-token --name work-claude`,
or with **Replace token** in the dashboard. `cw credentials add
claude-subscription` still works for one release and prints the new command.

**Sign-in**: `cw credentials connect claude --name claude-login` opens
Claude's authorization page and asks you to paste the code Claude shows, the
same with `--cloud` and `--local`. A
sign-in carries your plan, so `/usage` and plan features work in the sandbox;
the access token is delivered to the sandbox as Claude Code's own login file.
See the [security model](@/reference/security.md).

The dashboard offers the API key and the token under
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
[Git repositories](@/access/git.md).

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

Your first cloud profile is your default: a cloud `cw create` that names no
profile uses it, and `cw create --no-profile` uses none. Change it with
`cw credentials --cloud profiles default NAME`. The default can't be deleted
while it is the default; make another profile the default first.

In the dashboard, **Create Sandbox** has a credential profile picker, and a
Sandbox's **Edit secrets and credentials** changes it later. The credentials
page shows **Needs attention** when an identity needs reconnecting.

A selected credential is used only for the requests that carry Codewire's
placeholder for it. In a local VM, a request with your own key follows the
network policy instead: untouched under `open`, refused under `locked` unless
a rule allows the provider's host ([Egress policies](@/networking/egress.md)).

## Inspect, revoke, delete

```sh
cw credentials --cloud list
cw credentials --cloud get work-codex
cw credentials --cloud rename work-openai personal-openai
cw credentials --cloud revoke work-openai     # stops Codewire's use at the next request
cw credentials --cloud delete work-openai     # revokes it first if it's active
```

Both ask first at a terminal; a script passes `--yes`. Revoking a Codex
sign-in also asks OpenAI to revoke it, and `cw` says whether OpenAI confirmed.
For a GitHub connection made through Codewire's GitHub App, Codewire asks
GitHub to revoke its access token; GitHub keeps your authorization of Codewire
until you revoke it in your GitHub settings. An API key keeps working at its provider
until you revoke it in the provider's console. After each revoke or delete,
`cw` says which of these applies.

## Local VMs and the Secret Service

A local VM uses `local:NAME` or `platform:NAME` profiles. The local store needs
a running, unlocked Secret Service on Linux; on macOS it is the Keychain.
`cw credentials --local connect codex`, `connect github` and `connect claude`
run the same sign-ins as the platform from the `cw` process; Claude
subscription tokens are still platform-only. When you create a local VM with a
profile that has no SSH key, `cw` asks whether to add one.
