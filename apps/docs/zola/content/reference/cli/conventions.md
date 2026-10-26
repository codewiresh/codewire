---
title: Conventions
description: The global options, placement flags, names, output formats and help that every cw command shares.
updated: 2026-10-26
weight: 1
aliases: ["/cli/conventions"]
---

## Global options

| Option | Meaning |
| --- | --- |
| `-s, --server URL` | Platform server URL override for this invocation |
| `--member NAME` | Run a session command against a pinned trusted host member (Linux); conflicts with `--server` |
| `--local`, `--cloud` | Target local or cloud environments; see Placement below |
| `-h, --help`, `-V, --version` | |

## Placement, names, output and help

- **Placement.** `--local` or `--cloud` goes before or after the command
  (`cw --cloud stop app` is `cw stop --cloud app`). Environment commands,
  `cw use` and `cw setup` read it as the placement and never fall back to the
  other one; `cw secrets` and `cw credentials` read it as the storage to use.
  Without either, environment commands resolve a name across trusted hosts,
  local VMs and the current organization and refuse an ambiguous one; secret
  and credential commands ask at a terminal and fail without a flag
  otherwise. Commands that do not read a placement refuse the flag.
- **ENV and SESSION.** An environment is a name or ID; a session is a name
  or ID within an environment, and `session-<uuid>` matches by ID only.
  Session commands default to the environment selected with `cw use`.
- **Output.** `--output json` (or `-o json` where offered) prints machine
  output and never prompts; the default is `text`.
- **Secrets on stdin.** API keys, tokens and secret values are read from a
  hidden prompt or standard input, never from arguments.
- **Help.** `cw --help` shows the everyday commands; `cw help --all` lists
  every command, and `cw help COMMAND` shows one.

## Examples

```sh
cw --cloud stop app            # the same as cw stop --cloud app
cw ls app --output json        # machine output, never prompts
cw help create                 # one command's help
```
