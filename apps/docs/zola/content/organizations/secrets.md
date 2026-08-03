---
title: Secrets
description: Manage organization-level secrets for environment provisioning
---


Organization secrets store credentials used during environment provisioning — private repo access, container registry auth, and AI agent API keys.

## Accessing secrets

1. Navigate to your organization in the sidebar
2. Click **Secrets** in the org's quick links

## Available secrets

| Secret | Purpose |
|--------|---------|
| **GitHub Token** | Access private repositories during environment creation |
| **DockerHub Username** | Authenticate with DockerHub for container images |
| **DockerHub Token** | DockerHub authentication token |
| **Claude API Key** | API key for Claude Code in environments |
| **Claude OAuth Token** | OAuth token for Claude Code authentication |

Each secret shows its current status: **configured** or **not configured**.

## Set a secret

1. Find the secret you want to configure
2. Enter the value in the inline password input
3. Click **Set**

The value is encrypted and stored at the organization level.

## Delete a secret

1. Find the configured secret
2. Click **Delete**
3. The secret is removed immediately

{% aside(kind="caution") %}
  Deleting a secret may affect running environments that depend on it. New environments created after deletion won't have access to the removed credential.
{% end %}

## How secrets are used

Secrets are injected during environment provisioning:

- **GitHub Token** — clones private repos during environment setup
- **DockerHub credentials** — pulls private container images without rate limiting
- **Claude API Key / OAuth Token** — configures Claude Code inside environments so agents can authenticate automatically

## Related

{{ card_grid(
  titles=["Create an environment", "GitHub integration"],
  hrefs=["/docs/getting-started/create-your-first-environment", "/docs/settings/github-integration"],
  descriptions=["Create sandbox environments that use these secrets.", "Set up GitHub access for private repositories."]
) }}
