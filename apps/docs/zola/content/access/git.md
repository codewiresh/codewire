---
title: Git repositories
description: Create environments from private GitHub repositories through the Codewire GitHub App or an SSH key, without a token in the environment.
updated: 2026-10-26
weight: 3
aliases: ["/guides/private-repositories"]
---

A public repository needs nothing: pass its HTTPS URL. A private GitHub
repository needs your GitHub connection or an SSH key in the environment's
credential profile.

## Connect GitHub once

In the dashboard, **Settings → Credentials → Add credential → GitHub**, or:

```sh
cw credentials --cloud connect github --name work-github
```

Both end on GitHub's installation screen for the Codewire GitHub App. Choose
**Only select repositories** and pick the ones your environments need. The App
asks for Contents (read and write), Pull requests (read and write) and
Metadata (read): an environment that uses your connection, and the agents in
it, can read, push to and open pull requests in every repository the
installation covers. Change the selection on GitHub at any time; the next
request uses it. The credentials page tells you when an installation is
waiting for you to accept updated permissions.

Your GitHub connection is part of every credential profile automatically.
Connecting alone attaches nothing to an environment: the environment must
select a profile.

## Create the environment

```sh
cw create --name app --repo https://github.com/owner/private-repo --profile platform:work
cw create --name app --repo git@github.com:owner/private-repo@main --profile platform:work
```

GitHub sources may be written as `https://github.com/owner/repo`,
`git@github.com:owner/repo` or `ssh://git@github.com/owner/repo`. URLs with
embedded usernames, passwords or tokens are rejected. In the dashboard,
**Create Sandbox** offers **From GitHub**, a picker over the repositories your
connection can see, and **Add custom Git URL**.

How the checkout happens:

- With an SSH key in the profile, a `github.com` source clones over SSH
  through the SSH signer, trusting only GitHub's published host keys. If
  GitHub refuses the key, setup falls back to HTTPS through your GitHub
  connection and records a warning.
- Without a key, any of the forms above goes through the GitHub route with
  your connection. `git fetch`, `git push` and `gh` inside the environment use
  the same route.
- With neither, the clone is anonymous and works for public repositories
  only.

Your GitHub token never enters the environment, and saving a token as an
application secret does not enable cloning.

## Local VMs

A local VM takes repositories from `codewire.yaml` or from repeatable
`--repo`, as a cloud environment does:

```yaml
repositories:
  - source: git@github.com:owner/private-repo
    branch: main
    destination: private-repo
```

An HTTPS GitHub source that needs authentication uses the profile's GitHub
connection (`cw credentials --local connect github`, or a platform profile).
An SSH source uses the profile's SSH key; without a key, a `github.com`
source in SSH form goes through the GitHub connection, and its origin stays
as written. Other SSH hosts need the key and their `known_hosts` lines in the
project file. See [`codewire.yaml`](@/environments/codewire-yaml.md).
