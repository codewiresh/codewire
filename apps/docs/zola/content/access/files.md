---
title: Files
description: Copy files into and out of an environment with cw cp, or with scp, sftp and rsync through the SSH proxy.
updated: 2026-11-13
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

### Large files and interruptions

`cw cp` streams a file each way, so a file of any size moves without being
held in memory. A download is written beside its destination and renamed into
place only when complete: if it fails or you press Ctrl-C, an existing
destination is left as it was.

A cloud upload larger than 64 MiB goes up in parts. If it is interrupted,
run the same `cw cp` again and it resumes where the environment's copy stops:

```text
Resuming the upload at 402653184 of 1073741824 bytes
Uploaded big.tar -> cpt:/workspace/big.tar
```

The destination appears only once every part has arrived. An upload that is
never finished is removed after 24 hours. Changing the local file starts a
new upload.

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
