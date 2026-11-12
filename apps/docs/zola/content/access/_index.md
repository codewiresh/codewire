---
title: Access
description: "Every way into an environment, for you and for your agents: terminal sessions, SSH and VS Code, Git, files and ports."
weight: 30
sort_by: weight
---

An environment is reachable only through the ways in that Codewire provides,
and each one works the same for a person at a terminal and for an agent or
script. A hosted sandbox is reached over an encrypted tunnel from anywhere you
are signed in; a local VM only from your own machine.

| To | Use |
| --- | --- |
| run a shell, a command or a long job that survives disconnects | [Terminal sessions](@/access/sessions.md) |
| use `ssh`, `scp`, `rsync` or VS Code Remote | [SSH and VS Code](@/access/ssh-and-vscode.md) |
| run commands and attach to sessions from Rex's command palette | [Rex](@/access/rex.md) |
| clone or push private repositories without a key in the environment | [Git repositories](@/access/git.md) |
| move files in or out | [Files](@/access/files.md) |
| open a server running inside, from a browser or another machine | [Ports and preview URLs](@/access/ports.md) |

How the tunnel itself works is in [Networking](@/networking/_index.md).
