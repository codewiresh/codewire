---
title: Security
description: Two-factor authentication, sessions, and your password
---

Manage your account's security from [Settings → Account](https://codewire.sh/settings/).

## Two-factor authentication (2FA)

Codewire uses TOTP two-factor authentication, and we strongly recommend it. After you sign in, Codewire offers to set it up. Choose **Set up later** to continue without it for this sign-in: you'll be asked again the next time you sign in, and you can set it up any time from **Settings → Account → Security**.

To set it up:

1. Open an authenticator app (Google Authenticator, Authy, 1Password, and so on).
2. Scan the QR code, or enter the setup key shown under it.
3. Enter the current **6-digit code** from your authenticator.
4. **Save your recovery codes.** Codewire shows 10 one-time codes after the code is verified.

{% aside(kind="caution") %}
  Recovery codes are shown only once. Save them somewhere safe: if you lose your authenticator, a recovery code is how you sign in.
{% end %}

Once two-factor authentication is enabled, every sign-in asks for a code. Changing or removing an enrolled authenticator isn't available in the dashboard yet.

## Active sessions

**Settings → Account → Active sessions** lists the browsers signed in to your account, with when each signed in and when it expires. **This browser** is the one you're using now.

- **Sign out session** signs another browser out after you confirm. Its Sandbox terminals keep running.
- **Sign out of this browser** signs you out here.

## Password

Choose **Reset password** under **Security** to get a reset link by email.
