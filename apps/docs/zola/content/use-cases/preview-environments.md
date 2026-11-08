---
title: Preview environments
description: A hosted sandbox for each branch or pull request, with the app running in a session and an HTTPS preview URL, that deletes itself after a lifetime you choose.
updated: 2026-11-08
weight: 2
aliases: ["/use-cases/preview-per-pull-request"]
---

Give every pull request its own running copy of the app at its own URL, for
reviewers who would rather click than check out a branch. Each sandbox is
created from the branch, serves the app from a session, and deletes itself
after a lifetime you choose.

The output below is from a real run against a small public repository. Your
IDs, organization and preview domain will differ.

## 1. Create a sandbox from the branch

```sh
cw create --name pr-42 --image workspace \
  --repo https://github.com/octocat/Hello-World@master --ttl 2h
```

```text
pr-42 · cloud VM
  2 vCPU · 8 GiB RAM · 80 GiB disk
  ✓ Cloning repositories  2s
  ✓ scheduled shutdown after ttl 7200s
  ✓ Setup complete
  ✓ Workspace daemon ready  0.2s
✓ Environment pr-42 created · cloud VM
```

`--repo URL@branch` clones that branch into `/workspace/<repository>`.
`--ttl 2h` deletes the sandbox two hours after creation;
`cw extend pr-42 --hours 4` gives it more time. A private repository needs the
[Codewire GitHub App](@/access/git.md).

## 2. Start the app in a session

```sh
cw run --in pr-42 --name web --detach -- python3 -m http.server 3000 --directory /workspace/Hello-World
cw logs pr-42 --session web
```

```text
✓ Started session pr-42/web · cloud
Serving HTTP on 0.0.0.0 port 3000 (http://0.0.0.0:3000/) ...
```

Start a server as a session, not with `--startup`: setup waits for the
startup script to finish, so a server there keeps the sandbox in setup and
refuses sessions.

## 3. Publish the preview

```sh
cw ports pr-42 --publish 3000 --label web --access org_members
```

```text
  * Port 3000 registered as web
  URL: https://web-fbe24-{organization-slug}.{preview domain}
  Access: org_members
```

`org_members` asks a reviewer to sign in with an account in your
organization. `creator` (the default) is only you, and `public` is anyone
with the link. See [Ports and preview URLs](@/access/ports.md).

## 4. Clean up

The sandbox deletes itself when its lifetime ends. To remove it as soon as
the pull request closes:

```sh
cw rm pr-42
```

## In CI

Run the same commands from your CI system with an
[API key](@/organizations/api-keys.md), naming the sandbox after the pull
request number, and post the `URL:` line as a comment on the pull request.

## Related

- [Ports and preview URLs](@/access/ports.md): labels, access and the
  dashboard's Ports dialog.
- [`codewire.yaml`](@/environments/codewire-yaml.md): declare the repository, the
  install command and the preview in `codewire.yaml`, so every sandbox gets
  them.
