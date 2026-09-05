---
title: Navigate the dashboard
description: Understanding the Codewire dashboard layout
---

The dashboard at [codewire.sh/dashboard](https://codewire.sh/dashboard) is your home base for managing organizations and environments.

## Home

The home page shows all your organizations, each displaying:

- **Organization name**
- **Environment count** — total environments in the org
- **Running count** — how many environments are currently running

### Setup checklist

After creating your first organization, a setup checklist guides you through:

1. Create an organization
2. Create an environment

Completed steps are checked off automatically.

## Sidebar

The sidebar is the primary navigation. It contains:

### Organization groups

Each organization you belong to appears as an expandable group. Expand an org to see:

- **Environments** — listed with status dots (green = running, yellow = creating, red = failed)
- **Sessions** — persistent agent sessions running inside environments

### Per-org quick links

Each organization group has quick links:

- **New Environment** — open the [AI-assisted environment creator](@/getting-started/create-your-first-environment.md)
- **Secrets** — manage generic, write-only [stored values](@/organizations/secrets.md)

### Bottom links

- **Billing** — organization billing and subscription management
- **Settings** — account and organization settings
- **Docs** — link to this documentation
- **Sign Out** — sign out of your account

## Environment cards

Click an organization to see its environments. Each environment card shows:

- **Name** — the environment name
- **Repository** — the source repo, when present
- **Status badge** — current state (Running, Provisioning, Failed, Suspended)
- **Recent activity** — latest lifecycle or session state

### Status colors

| Color | Status | Meaning |
|-------|--------|---------|
| Green | Running | Environment is healthy and accessible |
| Yellow | Creating | Runtime is being set up |
| Red | Failed | Provisioning encountered an error |
| Orange | Suspended | Suspended due to billing or policy |

## Environment detail page

Click an environment card to open its detail page. See [Manage environments](@/environments/manage-environments.md) for full details.

## Navigation

- **Codewire logo** — returns to the home page
- **Sidebar** — primary navigation for orgs, environments, and sessions
- **Dashboard button** (navbar) — returns to the dashboard
