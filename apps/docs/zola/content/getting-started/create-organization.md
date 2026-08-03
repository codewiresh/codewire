---
title: Create an organization
description: Set up your first organization to group environments and team members
---


Organizations are the top-level container in Codewire. Each organization has its own members, roles, billing, secrets, and environments.

## Create your first organization

1. From the [dashboard](https://codewire.sh/dashboard), click **New Organization**
2. Enter an **organization name** (e.g., "Acme Engineering")
3. Choose a **slug** — this is used in URLs and must be unique
4. Click **Create**

You're now the **owner** of this organization and can start creating environments and inviting members.

After creating your org, connect GitHub and create your first environment.

## Slug format

Slugs must be 3–48 characters, lowercase letters, numbers, and hyphens only. Choose carefully — slugs cannot be changed after creation.

## What's in an organization?

- **Environments** — sandbox development machines for agents and developers
- **Members** — Team members with role-based access (owner, admin, member)
- **Billing** — Organization subscriptions and usage tracking

## Roles

| Role | Manage members | Create/delete environments | Change settings | View environments |
|------|:---:|:---:|:---:|:---:|
| **Owner** | Yes | Yes | Yes | Yes |
| **Admin** | Yes | Yes | Yes | Yes |
| **Member** | No | No | No | Yes |

{% aside(kind="note") %}
  The user who creates an organization is automatically the owner. Ownership can be transferred later.
{% end %}

## Next steps

{{ card_grid(
  titles=["Create an environment", "Invite members"],
  hrefs=["/docs/getting-started/create-your-first-environment", "/docs/organizations/invite-members"],
  descriptions=["Launch your first sandbox.", "Add your team to the organization."]
) }}
