---
title: Create your first environment
description: Launch your first Codewire sandbox
---


After you create an organization, create an environment from a repository.

## Steps

1. Open your organization in the dashboard.
2. Choose **New Environment**.
3. Enter a repository URL.
4. Review the detected preset, commands, ports, and variables.
5. Create the environment and wait for it to reach **Running**.

For CLI usage:

```bash
cw env create github.com/your-org/your-repo
```

## Next steps

{{ card_grid(
  titles=["Connect to an environment", "Manage environments"],
  hrefs=["/docs/environments/connect", "/docs/environments/manage-environments"],
  descriptions=["Use terminal, SSH, previews, files, and sessions.", "Start, stop, inspect, and delete environments."]
) }}
