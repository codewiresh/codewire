---
title: Integrations
description: "Use the Rex and Orca plugins, run coding agents in persistent sessions, and compose Codewire with your own developer tools."
weight: 35
sort_by: weight
---

Compose Codewire with the tools you already use. A plugin can put environments
and sessions in your terminal or editor, while the CLI, SDKs and ordinary SSH
connections let you build your own workflow.

## Plugins

The Rex plugin adds Codewire actions to the command palette. The Orca plugin
gives each new workspace its own local VM or cloud sandbox.

| To | Use |
| --- | --- |
| run commands and attach to sessions from Rex's command palette | [Install the Rex plugin](@/integrations/rex.md#install-the-codewire-plugin) |
| keep Rex sessions running inside an environment | [Run a Rex server in an environment](@/integrations/rex.md#run-a-rex-server-in-an-environment) |
| run Orca workspaces in environments, or connect Orca to one | [Install the Orca plugin](@/integrations/orca.md#install-the-codewire-plugin) |
| open shells and agents in environments from herdr | [herdr](@/integrations/herdr.md) |

## Agents and libraries

Run Claude Code, Codex, Cursor, Kimi, Pi, Gemini CLI, Amp, or any other terminal
agent in a [persistent Codewire session](@/agents/supported.md). The environment
keeps running when you disconnect; install additional tools inside it as needed.

[pi-durable](https://github.com/earendil-works/pi/tree/main/packages/durable)
is an application runtime, rather than a Codewire plugin. Run your pi-durable
app in an environment and compose it with Codewire's [CLI](@/reference/cli/_index.md)
or [SDKs](@/reference/sdks.md), just as you would any other development tool.
