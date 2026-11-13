---
title: Members and sharing
description: Invite people to an organization, change roles, remove members, and share one environment with a specific user.
updated: 2026-11-13
weight: 2
aliases: ["/guides/members"]
---

## Invite someone

Owners and admins invite from the organization's **Settings → Members** page:
enter the email address and choose **Member** or **Admin**. From the CLI:

```sh
cw org invite someone@example.com --role member --org my-org
```

Codewire emails the invitee, naming you, the organization and the role. The
email holds no link to the invitation itself: it asks the invitee to sign in
with that address and accept. Codewire also shows an invitation link once;
share it yourself if the email does not arrive.

The invitation is valid for 7 days, only one invitation per email can be
pending, and the invitee must accept it while signed in with that same email
address, verified. Someone without an account signs up with that address and
verifies it first. Revoke a pending invitation from the same page; it can no
longer be accepted, and an email not yet sent is not sent.

## Accept an invitation

Sign in with the invited address, then list your invitations and accept one
by its organization's slug or name:

```sh
cw org invitations
cw org accept my-org
```

The shared invitation link works too: open it while signed in with the
invited address.

Roles are described in [Organizations](@/organizations/_index.md).

## Change a role or remove a member

Owners and admins change roles and remove members from **Settings →
Members**. From the CLI:

```sh
cw org members --org my-org
cw org member rm someone@example.com --org my-org
```

- an admin cannot promote anyone to owner or change another admin or owner;
- an owner cannot be removed, and the last owner cannot be demoted;
- a removed member loses access to the organization and its environments at
  once; invite them again to bring them back.

## Share one environment

Every member of the organization can see its environments. To give a specific
user more on one environment:

```sh
cw share grant my-app --user USER_ID --permission viewer
cw share grant my-app --user USER_ID --permission operator
cw share grant my-app --user USER_ID --permission owner    # may delete it
cw share list my-app
cw share revoke my-app --user USER_ID
```

Deleting an environment is for its creator, an organization owner or admin,
or a user with an `owner` grant.

## Leave or delete an organization

To leave an organization, remove yourself with
`cw org member rm YOUR_EMAIL --org SLUG`; an owner cannot leave this way.
Only an owner can delete the organization, with `cw org delete SLUG`, which
asks you to type its name.
