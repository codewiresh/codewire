---
title: Organizations
description: setup, login, logout, whoami, org, api-keys and cost.
updated: 2026-11-13
weight: 7
aliases: ["/cli/account"]
---

## cw setup

```sh
cw setup [--org ID_OR_SLUG | --create-org NAME [--org-slug SLUG]] [--skip-ssh]
cw setup --local [--from DIR] [--replace]
```

The hosted wizard: choose the server (`--server`, `CODEWIRE_SERVER_URL`, the
saved configuration, or `https://codewire.sh`), sign in through the browser
(the URL and code are printed), save credentials, choose or create the default
organization, and write the OpenSSH integration (as `cw setup ssh` does)
unless `--skip-ssh`. With one organization
it is picked automatically; with several, `--org` or a picker.

`--local` installs and verifies the local VM runtime this release pins
instead of signing in. `--from DIR` installs a runtime directory built from
the same source (development builds), and `--replace` overwrites a different
installed runtime.

Example:

```sh
cw setup --local
```

```text
Downloading the local VM runtime (6 files, 186 MiB)...
Local VM runtime installed (e818b56a224a).
```

## cw login, logout, whoami

```sh
cw login [--org ID_OR_SLUG]
cw logout
cw whoami [--output json]
```

`login` needs a configured server (run `setup` once, or pass `--server`).
`logout` asks the server to end the sign-in, then removes it and the saved
configuration from this machine. It says "Logged out" only when the server
confirmed the sign-in ended. When it could not confirm (the server was
unreachable or refused), the sign-in is still removed from this machine, but
`logout` exits non-zero, names the reason, and says until when the sign-in's
access token stays valid. `logout` never ends an API key: with
`CODEWIRE_API_KEY` set it says so; delete the key with `cw api-keys delete`.

## cw org

```sh
cw org list [--output json]            # alias: ls
cw org current
cw org set [ID_OR_SLUG]                # also: cw org, with one organization
cw org create [NAME] [--slug SLUG]
cw org invite [EMAIL] [--role owner|admin|member] [--org ID_OR_SLUG]   # emails the invitee; prints the link once
cw org invitations [--output json]     # your pending invitations
cw org accept ORG                      # ORG: the slug, name or ID that invitations lists
cw org members [--org ID_OR_SLUG] [--output json]
cw org member rm USER [--org ID_OR_SLUG] [--yes]   # USER: user ID or email; alias: remove
cw org delete ID_OR_SLUG [--yes]       # owner only; asks you to type the name
```

`invite` creates the invitation, prints its one-time link on standard output,
then waits a few seconds for the invitation email and says what became of
it: sent, not sent with the reason, or not sent yet. Share the link yourself
when the email does not arrive; it is not shown again.

`invitations` lists the pending invitations addressed to your email address,
and only once that address is verified. `accept` joins the organization you
name from that list; it needs no link or token, only that you are signed in
with the invited, verified address. Unverified, it asks you to verify your
address and run it again.

`members` lists the current organization's members, or those of `--org`.
`member rm` asks before removing someone; `--yes` skips the question. Owners
and admins remove members, and anyone can remove themselves to leave. An
owner cannot be removed, and an admin cannot remove another admin.

Example:

```sh
cw org invitations
cw org accept acme
```

```text
ORGANIZATION             SLUG                     ROLE     EXPIRES
Acme Labs                acme                     member   2026-11-20T09:14:02Z
Joined Acme Labs (acme) as member.
```

## cw api-keys

```sh
cw api-keys create [NAME] [--expires DAYS]   # 0 = never; the key is printed once
cw api-keys list
cw api-keys delete KEY_ID
```

Keys act in the current organization. Use one with `CODEWIRE_API_KEY`.

## cw cost

```sh
cw cost [--org SLUG_OR_ID] [--output json]
```

Usage and billing overview for the organization.

At an interactive terminal, omitting the organization name, invitation email,
or API-key name opens a walkthrough. Invitations offer a role menu; API keys
offer expiry choices. The walkthrough shows the owning organization and asks
for confirmation before creating anything. Supplied flags skip their questions.
`cw org set` without a target offers a searchable organization list.
Without a terminal, name these values explicitly; stdin is never consumed as
metadata.
