---
title: Create an account
description: Sign up for CodeWire with an invite code
---


CodeWire is currently in **private beta**. You need an invite code to create an account.

## Sign up

1. Go to [codewire.sh/signup](https://codewire.sh/signup)
2. Fill in the form:
   - **Invite code** — provided by your organization or CodeWire
   - **Name** — your display name
   - **Email** — used for login and notifications
   - **Password** — minimum 12 characters

### Password requirements

Your password must be at least 12 characters. A strength indicator shows whether you've included:

- Uppercase letter
- Lowercase letter
- Number
- Special character

## Verify your email

After signing up, you'll receive a verification email. Click the link to activate your account.

{% aside(kind="caution") %}
  You must verify your email before you can sign in. If you try to log in before verifying, you'll see a prompt to check your inbox.
{% end %}

### Didn't receive the email?

- Check your spam or junk folder
- Use the **Send verification email again** option on the login page
- Make sure you entered the correct email address during signup

## Set up two-factor authentication

After verifying your email and signing in, you'll be redirected to `/setup-2fa` to configure two-factor authentication. **2FA is mandatory** — you cannot access the dashboard without it.

1. Open your authenticator app (Google Authenticator, Authy, 1Password, etc.)
2. Scan the QR code or enter the manual key
3. Enter the **6-digit code** from your authenticator to verify
4. **Save your backup codes** — you'll receive 10 one-time codes

{% aside(kind="caution") %}
  Backup codes are shown only once. Save them in a secure location. If you lose access to your authenticator app, backup codes are the only way to sign in.
{% end %}

## What's next?

Once 2FA is set up, you'll be taken to the dashboard to [create your first organization](@/getting-started/create-organization.md).
