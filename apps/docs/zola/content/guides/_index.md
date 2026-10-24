+++
title = "Guides"
description = "One task per page, grouped by what you are working on: agents, environments, access and networking, secrets and credentials, teams, and operating cw."
weight = 30
sort_by = "weight"
+++

Each guide assumes you have [installed cw](@/getting-started/install.md) and
created an environment.

## Agents

{{ card_grid(
  titles=["Orchestrate agents"],
  hrefs=["/docs/guides/run-agents"],
  descriptions=["A lead and two workers, tasks, results, steering, interruption and recovery."]
) }}

## Environments

{{ card_grid(
  titles=["The project file"],
  hrefs=["/docs/guides/project-file"],
  descriptions=["Describe an environment once in codewire.yaml."]
) }}

## Access and networking

{{ card_grid(
  titles=["SSH, VS Code and files", "Ports and previews"],
  hrefs=["/docs/guides/ssh-and-vscode", "/docs/guides/previews"],
  descriptions=["OpenSSH, scp and rsync, VS Code Remote-SSH, cw cp and the browser terminal.", "HTTPS preview URLs for hosted sandboxes; 127.0.0.1 ports for local VMs."]
) }}

## Secrets and credentials

{{ card_grid(
  titles=["Provider credentials", "Private repositories", "Application secrets"],
  hrefs=["/docs/guides/credentials", "/docs/guides/private-repositories", "/docs/guides/application-secrets"],
  descriptions=["Connect Codex, add API keys and SSH keys, and build a credential profile.", "Create environments from private GitHub repositories with the Codewire GitHub App.", "Store DATABASE_URL-style values and select which ones an environment receives."]
) }}

## Teams

{{ card_grid(
  titles=["Members and sharing"],
  hrefs=["/docs/guides/members"],
  descriptions=["Invite people, set roles, and share one environment."]
) }}

## Operate

{{ card_grid(
  titles=["Update cw", "Troubleshoot local VMs"],
  hrefs=["/docs/guides/update", "/docs/guides/troubleshoot-local-vms"],
  descriptions=["Keep cw current and move running local VMs to the new version.", "What the local VM error messages mean and what to do."]
) }}
