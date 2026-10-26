---
title: Files
description: Copy files into and out of an environment with cw cp, or with scp, sftp and rsync through the SSH proxy.
updated: 2026-10-26
weight: 4
---

A project usually reaches an environment through its repositories, or, for a
local VM, by mounting or copying the project directory when you create it.
For anything else, copy files in and out.

## With cw cp

```sh
cw cp notes.txt cpt:/workspace/notes.txt
cw cp cpt:/workspace/result.txt ./result.txt
```

```text
Uploaded notes.txt -> cpt:/workspace/notes.txt
Downloaded cpt:/workspace/result.txt -> ./result.txt (6 bytes)
```

Exactly one side names an environment. This works for hosted sandboxes and
local VMs. On a local VM the environment side must be under `/workspace`; a
path elsewhere, such as `/tmp`, fails with `local file path is invalid or
denied`.

## With scp, sftp and rsync

After `cw setup ssh`, every environment is an OpenSSH host, so the usual tools
work and keep their own options:

```sh
scp ./fixture.json cw-cloud-my-app:/workspace/
rsync -av cw-cloud-my-app:/workspace/out/ ./out/
sftp cw-local-my-vm
```

See [SSH and VS Code](@/access/ssh-and-vscode.md) for the host names and
what the proxy checks.

## Related

- [Git repositories](@/access/git.md): clone private repositories without a
  key in the environment.
- [`codewire.yaml`](@/environments/codewire-yaml.md): the repositories and
  project path an environment starts with.
