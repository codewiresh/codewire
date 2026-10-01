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

Once two-factor authentication is enabled, every sign-in asks for a code. You can't turn it off from the dashboard, but you can replace the authenticator or make new recovery codes.

### Replace your authenticator

Use this when you move to a new phone or a different authenticator app.

1. Choose **Replace authenticator** under **Security**.
2. Enter your password and either the current code from your authenticator or one unused recovery code.
3. Scan the new QR code, or enter the setup key shown under it. The key is shown only once and expires after 10 minutes.
4. Enter the 6-digit code from the **new** authenticator, then choose **Replace authenticator**.
5. **Save the new recovery codes** that Codewire shows.

Your current authenticator and recovery codes keep working until the new code is accepted. After that:

- your old authenticator and old recovery codes stop working;
- every other browser signed in to your account is signed out;
- this browser stays signed in.

API keys and connected apps keep working.

If the new code doesn't match, check the new Codewire entry in your app and try again. After five wrong codes, or after 10 minutes, start again from step 1. Starting again replaces any unfinished replacement.

### Make new recovery codes

Choose **Regenerate recovery codes** under **Security**. Enter your password and either the current code from your authenticator or one unused recovery code. Codewire shows 10 new codes once, and your previous recovery codes stop working. Your authenticator and your sessions are unchanged.

{% aside(kind="note") %}
  A code you've already used, to sign in or for another change, can't confirm a change. If Codewire says a code didn't match right after you used it, wait for the next one. Five wrong passwords or codes, at sign-in or when you confirm it's you, lock your account for 15 minutes.
{% end %}

Codewire also emails you when your authenticator is replaced or new recovery codes are made. If you didn't make the change, reset your password right away.

## Active sessions

**Settings → Account → Active sessions** lists the browsers signed in to your account, with when each signed in and when it expires. **This browser** is the one you're using now.

- **Sign out session** signs another browser out after you confirm. Its Sandbox terminals keep running.
- **Sign out of this browser** signs you out here.

## Password

Choose **Reset password** under **Security** to get a reset link by email.
