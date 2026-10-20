---
title: FAQ
description: Short answers to common questions about Codewire.
weight: 3
---

## General

**What is Codewire?** Isolated development environments for developers and
AI coding agents. Each environment is its own VM with its own kernel, with
durable sessions, SSH, a browser terminal, file transfer and preview URLs.

**Which agents work?** Codewire manages Codex and Claude Code conversations
(`cw run --agent`), and noel on a trusted Linux host. Any tool that runs in a
Linux terminal runs in an environment as an ordinary session.

**Do I need an account?** Not for a local VM or a trusted host session. A
hosted sandbox needs an account and an organization.

**Do I need to know Kubernetes?** No. The platform runs the infrastructure;
you create an environment and use it.

## Account

**How do I get access?** Open [codewire.sh/signup](https://codewire.sh/signup).
With an invite code the account is enabled at once; without one it is an
access request that Codewire reviews after you verify your email.

**I did not get the verification email.** Check spam, then submit the sign-up
form again with the same email: a pending request resends it.

**I forgot my password.** **Forgot password?** on the login page emails a
reset link valid for one hour.

**Can I turn off two-factor authentication?** No. You can replace the
authenticator or regenerate recovery codes from Settings → Account → Security.

**How do I sign out a lost device?** Settings → Account → Active sessions,
then **Sign out session** on that browser.

## Organizations

**Can I belong to several organizations?** Yes, with a different role in
each. `cw org set SLUG` chooses the current one.

**Can I transfer ownership?** An owner can make another member an owner;
ownership is not otherwise transferable from the dashboard or CLI.

**Can I change the organization's name or slug?** No; both are fixed at
creation.

## Environments

**Can I change an environment after creating it?** Resize it
(`cw resize`), change its selected secrets and credential profile
(`cw update ENV`), and publish ports (`cw ports ENV --publish PORT`). For a
different image or repositories, create a new one.

**What happens to my data when I stop an environment?** Workspace storage is
kept and compute is released. Deleting removes the storage.

**What does an agent see?** The environment's files, the application secrets
you selected (by name), and a local route to the providers in its credential
profile. Never the provider credentials themselves; see the
[security model](@/security.md).

**An environment is stuck.** `cw info ENV` shows the state and error
code; `cw daemon status ENV` and `cw daemon repair ENV` inspect and
reconcile the daemon; otherwise stop and start it.

**Does `cw upgrade` stop my local VMs?** Only if you choose to restart them.
They keep running on the previous version until you check the restart in
`cw upgrade`'s checklist or run `cw upgrade --vms`.

## Billing

**How is a hosted sandbox billed?** Per second of running compute, within
the organization's plan allowance; see
[Plans and billing](@/reference/subscription-plans.md).

**Do agents count as seats?** No. Seats are human developers.

## Support

Email [hello@codewire.sh](mailto:hello@codewire.sh). For an environment
problem, include the environment ID and the error code from `cw info`.
