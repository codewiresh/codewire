---
title: Connect to an environment
description: Terminal, SSH, files, previews, and agent sessions
---

Once an environment is running, Codewire exposes several connection paths.

## Browser terminal

Open the terminal from the environment detail page for an interactive shell in the sandbox.

## SSH

Use the dashboard SSH action or CLI session helpers to connect from your local terminal.

## Files and exec

The dashboard and CLI can browse files, download files, upload files, and run commands in the environment.

## Preview ports

When a development server starts inside the environment, expose its port from the environment detail page and open the generated preview URL.

## Agent sessions

Run agents from your terminal:

```bash
cw run -- claude "fix the tests"
```

Sessions keep running in the environment and can be reattached later.
