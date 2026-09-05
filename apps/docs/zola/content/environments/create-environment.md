---
title: Create an environment
description: Launch a sandbox environment from a repository
---


Use the dashboard or CLI to create a sandbox environment for a repository.

## Dashboard

1. Open the dashboard and select an organization.
2. Choose **New Environment**.
3. Enter a clean public HTTP(S) repository URL.
4. Let Codewire analyze the repo and review the detected preset, install command, startup command, ports, and environment variables.
5. Adjust the settings if needed.
6. Create the environment.

Codewire provisions the sandbox and streams progress while the environment starts.

{% aside(kind="note") %}
  Hosted private-repository access is not connected to environment creation in
  the current release. Repository URLs containing embedded credentials are
  rejected.
{% end %}

## CLI

```bash
cw env create https://github.com/owner/public-repo
```

The CLI uses the same repository detection flow as the dashboard.

## After creation

When the environment reaches **Running**, you can:

- open a browser terminal,
- connect over SSH,
- browse files,
- open detected preview ports,
- start persistent agent sessions with `cw run`.
