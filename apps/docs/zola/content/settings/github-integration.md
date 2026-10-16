---
title: Repository access
description: Create environments from public and private GitHub repositories
---

Codewire accepts clean HTTP(S) repository URLs. Public GitHub repositories do
not require a platform integration or repository credential. Private GitHub
repositories use your GitHub connection.

## Create from a public repository

Enter the complete repository URL when you create the environment:

```text
https://github.com/owner/repository
```

Repository URLs containing embedded usernames, passwords, or tokens are
rejected.

## Private GitHub repositories

Connect GitHub once, then select it in the credential profile your environments
use:

1. In **Settings → Credentials**, choose **Add credential**, then **GitHub**.
2. Open **Install/manage repository access**. On GitHub, install the Codewire
   GitHub App on your account or organization and choose **Only select
   repositories**. Pick the repositories your environments need.
3. Return to Codewire and choose **Continue to GitHub** to connect your
   account.
4. Add the GitHub connection to a credential profile, and create the
   environment with that profile.

From the CLI, `cw credentials --cloud connect github` connects the same
account and prints the installation link.

**Why only select repositories.** The App can read and push code and open pull
requests in every repository its installation covers. An environment that uses
your connection, and the agents running in it, can do the same. Choosing only
the repositories you need keeps that reach small. Change the selection on
GitHub at any time; the next request uses it.

Your GitHub token never enters the environment. Saving a repository token as a
secret does not enable cloning.
