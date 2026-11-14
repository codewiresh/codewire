# The self-hosted walk

A self-hosted Codewire (#4121) is done when someone installs it on a machine
of their own, makes the first account, lets other people in, and every step
below is observed working. This file is that walk. The format is in
[README.md](README.md).

The surface is the disposable Debian VM that `scripts/dev/selfhost-vm.sh`
makes. It stands in for an operator's own server, and it has no mail unless
the walk configures a provider.

## Where the walk stands

Updated 2026-11-13. Nothing here is observed working yet.

| ID | What | Local VM |
| --- | --- | --- |
| `selfhost-install` | Install and start the server | not yet observed |
| `selfhost-first-admin` | Setup creates the admin | not yet observed |
| `selfhost-invite` | An invite link lets one person in | not yet observed |
| `selfhost-uninvited` | A sign-up without an invite, in each of the four combinations | not yet observed |

## Sign-up settings

A self-hosted server is configured through the same settings the hosted
service uses. Setup writes the default, invite-only; the operator can opt
into Turnstile and into asking a reason.

| Setting | Where | Default when self-hosted | Meaning |
| --- | --- | --- | --- |
| `IDP_SIGNUP` | IdP | `invite-only` | Invite links let people in. A sign-up without one waits, disabled, for the admin. Hosted runs `open`. |
| `TURNSTILE_SECRET_KEY` and `TURNSTILE_SITE_KEY` | IdP and dashboard | unset | With both set, a sign-up without an invite passes a Turnstile challenge; one from a per-address invite link skips it (decided on #4121). Unset, there is none. |
| `IDP_SIGNUP_REASON` | IdP | unset | `required` asks a sign-up without an invite what they want to build, and the admin reads the answer. |
| `CODEWIRE_ADMIN_EMAIL` and `CODEWIRE_ADMIN_PASSWORD_FILE` | setup | unset | A scripted install's admin. Without them, setup asks for the email and password at the terminal. |
| Mail: SMTP (`CODEWIRE_SMTP_HOST`, `CODEWIRE_SMTP_PORT`, `CODEWIRE_SMTP_USERNAME`, `CODEWIRE_SMTP_PASSWORD`, `CODEWIRE_SMTP_FROM`), or SES (`CODEWIRE_SES_*`) | IdP | unset | SMTP needs TLS: implicit on port 465, STARTTLS otherwise, never plain. With mail, every new account, the admin included, verifies its address before it can sign in (#4481), and invite links are emailed. Without mail, the admin's approval stands in for that proof. |

The four combinations for a sign-up without an invite, with and without
mail:

| Combination | What the person sees | What the admin sees at Admin → Account Access |
| --- | --- | --- |
| Default: neither option | Name, email, password. Then "Your account is waiting for the admin." Signing in says the same until the admin enables it. With mail, the address is verified first. | The account as Disabled. Without mail, Enable is available, and its row says nothing has proved who owns the address. With mail, Enable waits for verification. |
| Turnstile on | The same, after the challenge. | The same. |
| Reason on | The same, plus "What would you like to build?" | The same, with the answer in the Request column. |
| Both | The challenge and the reason. | The answer in the Request column. |

A sign-up from an invite link is the same in all four: it never passes the
challenge, never asks a reason and never waits.

## `selfhost-install`: install and start the server

- **Entry points:** setup on the operator's machine.
- **Driving it:**
  1. `scripts/dev/selfhost-vm.sh create <state-dir>` makes the VM;
     `scripts/dev/selfhost-vm.sh ssh <state-dir>` opens a shell.
  2. Setup and start: no command yet. This is the Compose package of #4121.
- **Proof:** the dashboard answers at the server's address, and setup has
  created the admin.
- **Observed:** not yet observed.

## `selfhost-first-admin`: setup creates the admin

- **Entry points:** setup on the server: a terminal prompt, or the settings
  of a scripted install.
- **States to exercise:**
  - a scripted install with `CODEWIRE_ADMIN_EMAIL` and
    `CODEWIRE_ADMIN_PASSWORD_FILE` asks nothing;
  - a second setup run creates no second admin and says one exists;
  - a missing or weak password is refused, with the password rules, and no
    account is made;
  - with mail, the admin verifies the address before signing in;
  - the server accepts no sign-up before the admin exists.
- **Driving it:**
  1. Run setup, and give the admin's email and password when asked. Setup
     itself: no command yet (the Compose package, #4121). It calls
     `codewire-idp create-admin --email <address>`, which reads the password
     on stdin.
  2. Without mail, sign in at once. With mail, open the verification email,
     then sign in.
  3. Create the first organization at `/organizations/new`.
- **Proof:** the account opens Admin → Account Access, which only an admin
  can, and a second `create-admin` run leaves one admin.
- **Observed:** not yet observed.

## `selfhost-invite`: an invite link lets one person in

- **Entry points:** the organization's Members page. The link is emailed when
  the server has mail and shown to copy either way.
- **States to exercise:**
  - the link is for one address: another address is refused, with the same
    words as a wrong link;
  - it works once, and is refused when revoked or past its expiry: without
    mail, 24 hours after it was issued;
  - an address that already has an account is told to sign in;
  - without mail the copied link is the admin's approval: the page next to
    it says that anyone with the link can join as that address.
- **Driving it:**
  1. As the admin, invite an address from Members and copy the link.
  2. In another browser, open it and choose Create account. The sign-up page
     shows the invited address, fixed, and asks only a name and a password.
     The dashboard page: no command yet (#4121, the dashboard change).
  3. Without mail, the person is signed in; with mail, they verify first.
     Then they accept the invitation.
  4. With mail, the invite arrives by email; the rest is the same.
- **Proof:** the person appears on Members with the invitation's role. Admin
  → Account Access shows how they joined: the organization, the inviter and
  the time.
- **Observed:** not yet observed.

## `selfhost-uninvited`: a sign-up without an invite

- **Entry points:** the sign-up page with no link.
- **States to exercise:** each of the four combinations in the table above,
  with and without mail.
- **Driving it:**
  1. Set the combination in the IdP's and the dashboard's environment, and
     restart them.
  2. Sign up without a link, and try to sign in.
  3. As the admin, find the account at Admin → Account Access and enable it.
     Sign in again.
- **Proof:** before Enable, sign-in is refused with the waiting message. After
  it, sign-in works. With the reason on, the admin's row shows the answer.
- **Gotchas:** Turnstile needs both keys. A site key without the secret
  shows a challenge that the IdP never checks.
- **Observed:** not yet observed.
