---
title: Organizations
description: "The account boundary for hosted sandboxes: members, roles, sharing, secrets, presets, API keys and billing."
weight: 6
---

An organization owns hosted environments, their application secrets, presets,
API keys and billing, and has members with roles. Local VMs and trusted hosts
belong to no organization. You can belong to several organizations with
different roles; `cw org set SLUG` chooses the current one.

## Roles

| | Owner | Admin | Member |
| --- | :-: | :-: | :-: |
| See and create environments | yes | yes | yes |
| Delete any environment | yes | yes | own, or with an owner grant |
| Invite members, revoke invitations | yes | yes | no |
| Change roles, remove members | yes | yes, except owners and other admins | no |
| Organization secrets, presets, API keys, billing | yes | yes | no |
| Delete the organization | yes | no | no |

The creator is the first owner; an owner can make other owners, and the last
owner cannot be demoted. Ownership is not transferable from the dashboard or
the CLI. Deleting an organization is `cw org delete SLUG` and asks you to type
its name.

## Members and invitations

Owners and admins invite from the organization's **Settings → Members**, or
with `cw org invite EMAIL --role member|admin --org SLUG`. An invitation is a
link shown once, valid for 7 days, that must be accepted while signed in with
the same email address. See [Members and sharing](@/guides/members.md).

## Environment access

Every member sees the organization's environments. Deleting one is for its
creator, an owner or admin, or someone with an `owner` grant on it:

```sh
cw env share grant my-app --user USER_ID --permission viewer|operator|owner
cw env share list my-app
cw env share revoke my-app --user USER_ID
```

Removing a member removes their access to the organization and its
environments.

## Secrets, presets, API keys

- **Secrets**: the organization scope and named secret projects, managed by
  owners and admins. See [Application secrets](@/guides/application-secrets.md).
- **Presets**: creation defaults (image, commands, resources, TTL) with a
  slug: `cw preset list`, `cw preset create SLUG --image ...`,
  `cw env create --preset SLUG`.
- **API keys**: `cw api-keys create NAME [--expires DAYS]` prints a `cw_` key
  once. Set `CODEWIRE_API_KEY` to use it instead of a browser sign-in; it acts
  in the organization it was created in.

## Billing

The platform meters running compute per second and bills the organization
monthly. Owners and admins manage the payment method from the organization's
**Billing** page; `cw cost` shows usage. See
[Plans and billing](@/reference/subscription-plans.md).
