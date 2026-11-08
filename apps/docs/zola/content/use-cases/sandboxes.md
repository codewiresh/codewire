---
title: Sandboxes
description: Run code you do not trust yet, a script, a dependency, a stranger's repository or an agent with full permissions, in a VM with a copy of your project and no credentials.
updated: 2026-11-08
weight: 5
aliases: ["/use-cases/untrusted-code"]
---

Run something you do not trust yet, such as an install script, a new
dependency, a repository from a stranger, or an agent with full permissions,
where it cannot touch your files or your keys. Give it a VM with a one-time
copy of the project instead of a live mount, and remove the VM when you are
done.

The output below is from a real run on Linux.

## 1. Create a VM with a copy of the project

```sh
cw create --local --name scratch --path . --path-mode copy
```

```text
Create a local sandbox
  Name         scratch
  Config       flags only, no codewire.yaml found; default workspace image
  Workspace    one-time copy of ~/my-app
  Image        Codewire workspace (default)
  Resources    2 vCPU · 4 GiB RAM · 20 GiB disk
  Docker       on (8 GiB data disk)
  Credentials  none
  App secrets  none
  Policy       open
  Ports        none
Create with these settings?
› Create environment
  Edit settings
  Cancel
```

`--path-mode copy` copies the folder once, as it is now, uncommitted work
included, into `/workspace` on the VM's own disk. Nothing the VM does reaches
the original. Compare the default live mount, whose review warns that guest
root can change and delete files in the mounted directory.

`Credentials  none` means no provider credentials, SSH keys or application
secrets are available inside. Add them only when the code has earned them.

## 2. Let it do its worst

```sh
cw run --in scratch --name look --no-tty -- ls -A /workspace
cw run --in scratch --name wipe --no-tty -- sh -c 'rm -rf /workspace/index.html && ls -A /workspace'
```

```text
✓ Started session scratch/look · local VM
index.html
✓ Started session scratch/wipe · local VM
```

The VM's copy is gone. Your folder is not:

```sh
ls
```

```text
index.html
node_modules
target
```

The VM has its own kernel, so a process that escalates to root inside it is
root in the VM, not on your machine. Docker inside the VM is the VM's own
daemon; your machine's Docker is never mounted into it.

## 3. Remove it

```sh
cw rm scratch
```

```text
✓ Environment scratch removed
  local VM · environment disk removed
```

## What it does not protect

- **The network.** The VM can reach the internet, so code in it can download
  more code or send out what it can read. It cannot read your files or keys,
  because it does not have them.
- **What you hand it.** A live mount (`--path .`), application secrets and a
  credential profile are each a choice to share; the
  [security model](@/reference/security.md) says exactly what each exposes.
- **A trusted host session** (`--type host`) has no containment at all.

To keep the code off your machine entirely, use a hosted sandbox: the same
commands without `--local`.

## Related

- [Environments](@/environments/_index.md#where-it-runs)
- [Security model](@/reference/security.md)
