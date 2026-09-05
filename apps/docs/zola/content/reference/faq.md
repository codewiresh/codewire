---
title: FAQ
description: Frequently asked questions about Codewire
---

## General

<details>
<summary>What is Codewire?</summary>

Codewire provides cloud machines for AI coding agents. Every agent gets its own hardware-isolated VM with a dedicated kernel and full root access. Launch Claude Code, Codex, or any tool on isolated machines — and run them in parallel.

</details>

<details>
<summary>What AI tools work with Codewire?</summary>

Any tool that runs in a terminal or development environment: Claude Code, OpenAI Codex, Cursor, GitHub Copilot, Aider, and more. If it runs on Linux, it runs in Codewire.

</details>

<details>
<summary>How does isolation work?</summary>

Each environment runs with VM-backed isolation. Unlike container-only systems that share a kernel, Codewire environments isolate agent workloads from each other.

</details>

<details>
<summary>How is Codewire different from GitHub Codespaces?</summary>

Isolation and AI agent support are the main differences. Codespaces uses shared-kernel containers; Codewire uses isolated sandbox environments whose supervised daemons own durable agent sessions.

</details>

<details>
<summary>Can I use the CLI without the web dashboard?</summary>

Yes. Native local environments work without a Codewire account. Platform environments add hosted lifecycle, organizations, billing, and remote access while using the same session grammar.

</details>

<details>
<summary>Do I need to know Kubernetes to use Codewire?</summary>

No. Codewire handles runtime infrastructure, storage, ingress, certificates, and DNS automatically. You create an environment and start using it.

</details>

<details>
<summary>How long does provisioning take?</summary>

Typically 2-5 minutes. You can watch progress in real time on the environment detail page.

</details>

## Accounts

<details>
<summary>How do I get an invite code?</summary>

Codewire is in private beta. Invite codes are distributed by existing users or the Codewire team. Contact hello@codewire.sh if you'd like early access.

</details>

<details>
<summary>I didn't receive my verification email</summary>

Check your spam/junk folder. You can resend the verification email from the login page. Make sure you entered the correct email during signup.

</details>

<details>
<summary>I forgot my password</summary>

Go to the [login page](https://codewire.sh/login), click **Forgot password?**, and enter your email. You'll receive a link to set a new password.

</details>

<details>
<summary>What happens when I delete my account?</summary>

Account deletion has a 30-day grace period. During that time you can cancel. After 30 days, your environments, subscriptions, sessions, and data are permanently deleted.

</details>

## Organizations

<details>
<summary>How do I create an organization?</summary>

Navigate to the dashboard and click **New Organization**. Enter a name and slug, then click **Create**.

</details>

<details>
<summary>Can I belong to multiple organizations?</summary>

Yes. You can be a member of multiple organizations with different roles in each.

</details>

<details>
<summary>How many members can I have?</summary>

There is no limit on organization members. Seat pricing is $18 per developer per month. AI agents don't count as seats.

</details>

<details>
<summary>Can I transfer organization ownership?</summary>

Not self-service currently. Contact hello@codewire.sh for ownership transfers.

</details>

## Environments

<details>
<summary>Can I change an environment after creating it?</summary>

You can edit environment settings where the dashboard exposes them. For structural changes, create a new environment from the same repository.

</details>

<details>
<summary>What happens when provisioning fails?</summary>

Check the lifecycle timeline on the environment detail page for error details. If the environment continues to fail, contact hello@codewire.sh with the event details.

</details>

<details>
<summary>Can I have multiple environments?</summary>

Yes. You can create multiple environments within an organization. Each environment is isolated from the others.

</details>

<details>
<summary>How do platform updates work?</summary>

Codewire rolls out platform updates through the managed service. Environment runtime changes are handled through presets and image updates.

</details>

<details>
<summary>How does Mesh access fit into Codewire?</summary>

Mesh connectivity is part of the network and CLI story, not a separate provisioned resource in the dashboard. Use hosted Codewire Mesh at `mesh.codewire.sh` or run `codewire-mesh` yourself for advanced self-hosted setups.

</details>

<details>
<summary>How do I recover a stuck environment?</summary>

Check lifecycle events and logs first. If the environment is stuck, stop/start it or create a replacement environment from the same repository.

</details>

## Billing

<details>
<summary>What happens when my trial expires?</summary>

Environment access may be suspended. Add a payment method and subscribe to resume.

</details>

<details>
<summary>How does billing work?</summary>

Billing is organization-based: plans cover environment capacity, usage, and human developer seats. Plans include a 14-day free trial.

</details>

<details>
<summary>How are overages calculated?</summary>

Usage is tracked in 5-minute intervals and aggregated monthly. Overages are billed at: CPU $0.03/core-hour, Memory $0.01/GB-hour, Disk $0.05/GB-hour.

</details>

<details>
<summary>Do AI agents count as seats?</summary>

No. Seat pricing ($18/developer/month) is for human developers only. You can run as many AI agents as your environment capacity supports.

</details>

## Environment data

<details>
<summary>Where do I create environments?</summary>

Use the dashboard **New Environment** flow or `cw env create`.

</details>

<details>
<summary>What happens to my data when an environment is stopped?</summary>

Persistent data is retained according to the active plan and environment policy. Compute is released while the environment is stopped.

</details>

## Security

<details>
<summary>What 2FA methods are supported?</summary>

Codewire supports TOTP (Time-based One-Time Password) via authenticator apps like Google Authenticator, Authy, or 1Password. 10 backup codes are provided as a fallback. 2FA is mandatory — it's set up during onboarding.

</details>

<details>
<summary>How do I revoke access from a lost device?</summary>

Go to [Settings → Sessions](https://codewire.sh/settings/sessions) and revoke the session for that device. You can also click **Revoke All Other Sessions** to sign out everywhere except your current device.

</details>

## Support

<details>
<summary>How do I get help?</summary>

Email hello@codewire.sh. For billing or account issues, include your organization name and the email associated with your account.

</details>
