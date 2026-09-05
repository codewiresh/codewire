---
title: Repository access
description: Create environments from public repository URLs
---

Codewire accepts clean HTTP(S) repository URLs. Public GitHub repositories do
not require a platform integration or repository credential.

## Create from a public repository

Enter the complete repository URL when you create the environment:

```text
https://github.com/owner/repository
```

Repository URLs containing embedded usernames, passwords, or tokens are
rejected.

## Private repositories

Hosted private-repository credentials are not connected to environment
creation in the current release. Saving a repository credential as a secret
does not enable cloning, and there is no hosted GitHub credential setup.

The former GitHub-specific CLI command group is retired. Use a repository that
is accessible without authentication for now.
