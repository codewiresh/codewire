---
title: Secrets
description: Store generic write-only values and inspect their metadata
---

Secrets are named, opaque values. Codewire stores the value associated with a
key; it does not infer a provider, credential type, or intended use from the
key or value. `DATABASE_URL`, `OPENAI_API_KEY`, and an application-specific
signing key all use the same storage contract.

## Storage scopes

The dashboard groups stored values by scope:

- **Organization** — shared metadata owned by the selected organization
- **User** — personal metadata owned by the signed-in user
- **Secret project** — a named collection owned by the organization

Open an organization and choose **Secrets** to select a scope or manage secret
projects.

## Value-blind reads

Setting a secret sends its value through a write-only request and stores it
encrypted. Subsequent lists return only metadata such as the key and
timestamps. The stored value is not displayed or returned by a read API.

## Set a secret

1. Choose the organization, user, or secret-project scope.
2. Enter a valid environment-style key, such as `DATABASE_URL`.
3. Enter the value in the password field.
4. Choose **Save Secret**.

Setting the same key again replaces its stored value. Use rename when only the
key should change.

## Delete a secret

Delete removes the stored value and its readable metadata. Deleting a secret
project removes every value in that project.

{% aside(kind="caution") %}
  Values are write-only. If you need a value later, keep the authoritative copy
  in your own password manager or secrets system.
{% end %}

## Environment delivery

Storage is not delivery. In the current hosted release, saved secrets cannot be
attached to an environment and are not automatically injected, exposed, or
proxied to workloads. Environment creation rejects secret-bearing project
configuration rather than silently copying a value into a sandbox.

Saving a repository token here therefore does not enable private-repository
cloning. See [Repository access](@/settings/github-integration.md) for the
current repository boundary.

## CLI

Use an explicit placement and scope. `set` prompts for the value without
placing it in the command line:

```bash
cw secrets --platform list
cw secrets --platform organization set DATABASE_URL
cw secrets --platform organization delete DATABASE_URL
```

## Related

{{ card_grid(
  titles=["Create an environment", "Repository access"],
  hrefs=["/docs/getting-started/create-your-first-environment", "/docs/settings/github-integration"],
  descriptions=["Create a secret-free sandbox environment.", "Review the supported repository boundary."]
) }}
