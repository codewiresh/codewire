---
title: FAQ
description: Account, organization and billing questions. Questions about a feature are answered on that feature's page.
updated: 2026-10-26
weight: 7
---

Questions about using a feature are answered at the end of its page:
[Quickstart](@/quickstart.md#faq), [Run and orchestrate](@/agents/run.md#faq),
[Lifecycle](@/environments/lifecycle.md#faq),
[Secrets and credentials](@/secrets/_index.md#faq) and
[Install and sign in](@/install.md#faq).

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

## Billing

**How is a hosted sandbox billed?** Per second of running compute, within
the organization's plan allowance; see
[Usage and costs](@/organizations/usage.md).

**Do agents count as seats?** No. Seats are human developers.

## Support

Email [hello@codewire.sh](mailto:hello@codewire.sh). For an environment
problem, include the environment ID and the error code from `cw info`.
