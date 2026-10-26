---
title: Members and sharing
description: Invite people to an organization, change roles, remove members, and share one environment with a specific user.
updated: 2026-10-26
weight: 2
aliases: ["/guides/members"]
---

## Invite someone

Owners and admins invite from the organization's **Settings → Members** page:
enter the email address and choose **Member** or **Admin**. Codewire shows an
invitation link once; share it yourself. From the CLI:

```sh
cw org invite someone@example.com --role member --org my-org
```

The link is valid for 7 days, only one invitation per email can be pending,
and the invitee must accept it while signed in with that same email address.
Someone without an account signs up first, then opens the link again. Revoke a
pending invitation from the same page; the link stops working at once.

Roles are described in [Organizations](@/organizations/_index.md).

## Change a role or remove a member

Owners and admins change roles and remove members from **Settings →
Members**:

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

Removing yourself is an API operation; ask an owner or admin to remove you.
Only an owner can delete the organization, with `cw org delete SLUG`, which
asks you to type its name.
