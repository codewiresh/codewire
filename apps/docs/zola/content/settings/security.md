---
title: Security
description: Two-factor authentication, sessions, and account management
---


Codewire provides several security features to protect your account.

## Two-factor authentication (2FA)

Codewire uses TOTP-based two-factor authentication. **2FA is mandatory** — it's set up during account onboarding (after email verification, before accessing the dashboard).

If you need to reconfigure 2FA:

1. Go to [Settings → Security](https://codewire.sh/settings/security)
2. Click **Enable Two-Factor Authentication**
3. Confirm your password
4. Add your account to an authenticator app:
   - Copy the manual entry key, or scan the QR code (from your authenticator app)
   - Supported apps: Google Authenticator, Authy, 1Password, etc.
5. Enter the **6-digit code** from your authenticator to verify
6. **Save your backup codes** — you'll receive 10 one-time backup codes

{% aside(kind="caution") %}
  Backup codes are shown only once. Save them in a secure location. If you lose access to your authenticator app, backup codes are the only way to sign in.
{% end %}

### Disable 2FA

1. Go to Settings → Security
2. Click **Disable Two-Factor Authentication**
3. Confirm your password
4. 2FA is removed immediately

{% aside(kind="note") %}
  Account settings and sessions pages are being migrated — some features may appear as stubs during the transition.
{% end %}

## Active sessions

View and manage all devices signed in to your account.

1. Go to [Settings → Sessions](https://codewire.sh/settings/sessions)
2. Each session shows:
   - Device type (desktop, mobile, tablet)
   - Browser and operating system
   - IP address
   - Last active time
   - Your current session is marked with a green badge

### Revoke a session

Click **Revoke** next to any session to sign it out immediately.

### Revoke all other sessions

Click **Revoke All Other Sessions** to sign out everywhere except your current device.

## Account management

From [Settings → Account](https://codewire.sh/settings/account):

### Export your data

Download a JSON file containing your profile, sessions, memberships, environments, and audit logs.

### Delete your account

{% aside(kind="caution") %}
  Account deletion is permanent after the grace period. Your environments, sessions, and related data will be destroyed.
{% end %}

1. Click **Delete Account**
2. Review what will be deleted:
   - Environments you own
   - Environment data and sessions
   - Active subscriptions
   - All sessions
3. Type your email to confirm
4. Your account enters a **30-day grace period**

During the grace period, you can cancel the deletion request from the same page. After 30 days, your account and all associated data are permanently deleted.

## Password

Change your password from Settings → Security. The same 12-character minimum requirement applies.
