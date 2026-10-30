---
title: Account and organization
description: Request access, sign in with two-factor authentication, create the organization that owns your hosted sandboxes, and delete your account.
updated: 2026-10-29
weight: 1
aliases: ["/getting-started/account", "/guides/account"]
---

Local VMs and trusted host sessions need no account. Hosted sandboxes do.

## Request access

Open [codewire.sh/signup](https://codewire.sh/signup) and fill in your name,
email, a password and what you would like to build. The password is 12 to 128
characters with an uppercase letter, a lowercase letter, a digit and a symbol.

- **With an invite code**, the account is enabled at once and you continue to
  two-factor setup.
- **Without one**, this is an access request. Codewire emails a verification
  link, valid for 24 hours. Once you have verified the address, the request is
  reviewed; another email tells you when access is ready.

## Sign in

Sign in at [codewire.sh/login](https://codewire.sh/login) with your email and
password. With two-factor authentication enabled you then enter the 6-digit
code from your authenticator, or one of your recovery codes.

**Forgot password?** on the login page emails a reset link that is valid for
one hour. Five failed passwords or codes lock the account for 15 minutes.

## Two-factor authentication

Codewire uses TOTP and offers to set it up at every sign-in until you do.
**Set up later** skips it for the current browser session only.

1. Open your authenticator app and scan the QR code, or enter the setup key.
2. Enter the current 6-digit code.
3. **Save your recovery codes.** Codewire shows 10 one-time codes once.

{% aside(kind="caution") %}
  Recovery codes are shown only once and each works once. If you lose your
  authenticator, a recovery code is the only way to sign in.
{% end %}

Once enabled, two-factor authentication cannot be turned off. From
**Settings → Account → Security** you can:

- **Replace authenticator** when you move to a new phone. Enter your password
  and a current code or an unused recovery code, then scan the new QR code.
  Your other browsers are signed out, and Codewire emails you.
- **Regenerate recovery codes**. The previous codes stop working, and Codewire
  emails you.
- **Reset password**, which sends the same reset link as the login page.

**Settings → Account → Active sessions** lists the browsers signed in to your
account; a session lasts 8 hours. **Sign out session** ends another browser's
session; **Sign out of this browser** ends yours.

## Create an organization

Hosted sandboxes, members, application secrets, presets, API keys and billing
all belong to an organization. From the organization switcher at the top of
the dashboard sidebar choose **New Organization**, then enter:

- a **name**;
- a **slug**, 3 to 48 characters of lowercase letters and digits in
  hyphen-separated groups. It must be unique and appears in URLs.

Neither can be changed afterwards. You become the organization's **owner**.
From the CLI: `cw org create NAME --slug SLUG`, or
`cw setup --create-org NAME`.

See [Organizations](@/organizations/_index.md) for roles, and
[Members and sharing](@/organizations/members.md) to invite your team.

## Delete your account

**Settings → Account → Delete account** opens a page that lists what goes.
Type your account's email address to confirm. Deleting your account:

- deletes every organization **only you** belong to, with its environments,
  their storage, its secrets and credentials, and its Stripe customer and
  payment methods. Remaining credit in those organizations is forfeited;
- removes you from organizations that have other members. Environments you
  created there stay with the organization;
- signs you out everywhere at once and stops your API keys and CLI sign-ins;
- deletes your personal secrets, credentials and access profiles.

When the deletion is done, Codewire emails a confirmation. You can then sign
up again with the same address.

{% aside(kind="caution") %}
  Deleting your account cannot be undone. While you are the only owner of an
  organization with other members, the page lists it instead: make another
  member an owner in **Members**, or delete the organization, first.
{% end %}

## Next

The [Quickstart](@/quickstart.md#9-the-same-on-the-platform) picks up from
`cw setup`.
