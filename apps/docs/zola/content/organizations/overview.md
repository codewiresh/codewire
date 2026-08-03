---
title: Organizations
description: Manage your team and environments within an organization
---


Organizations are the core grouping in Codewire. Each organization has its own members, roles, environments, secrets, and billing.

## What's in an organization?

- **Environments** — sandbox development machines for agents and developers
- **Members** — Team members with role-based access control
- **Billing** — Subscription and usage tracking managed at the organization level

## Roles

Organizations use three roles with different permission levels:

| Permission | Owner | Admin | Member |
|------------|:-----:|:-----:|:------:|
| View environments | Yes | Yes | Yes |
| Create environments | Yes | Yes | Yes |
| Delete environments | Yes | Yes | No |
| Send invitations | Yes | Yes | Yes |
| Manage members (roles, removal) | Yes | Yes | No |
| Change organization settings | Yes | Yes | No |
| View admin credentials | Yes | No | No |
| Transfer ownership | Yes | No | No |
| Delete organization | Yes | No | No |

{% aside(kind="note") %}
  The user who creates an organization is automatically the **owner**. There is exactly one owner per organization.
{% end %}

## Organization lifecycle

1. **Create** — Any user can create an organization from the dashboard
2. **Create environments** — Launch sandboxes for repos and agents
3. **Invite members** — Send email invitations to collaborators
4. **Manage** — Adjust roles, billing, secrets, and environment access as needed

## Related guides

{{ card_grid(
  titles=["Invite members", "Manage members", "Billing", "Create an environment"],
  hrefs=["/docs/organizations/invite-members", "/docs/organizations/manage-members", "/docs/organizations/billing", "/docs/environments/create-environment"],
  descriptions=["Send invitations to your team.", "Change roles and remove members.", "Manage subscriptions and usage.", "Launch a new sandbox."]
) }}
