+++
title = "How-to guides"
description = "One task per page: agents, access, credentials, secrets, ports, the project file, members, updates and troubleshooting."
weight = 30
sort_by = "weight"
+++

Each guide assumes you have [installed cw](@/getting-started/install.md) and
created an environment.

{{ card_grid(
  titles=["Orchestrate agents", "SSH, VS Code and files", "Provider credentials", "Private repositories", "Application secrets", "Ports and previews", "The project file", "Members and sharing", "Update cw", "Troubleshoot local VMs"],
  hrefs=["/docs/guides/run-agents", "/docs/guides/ssh-and-vscode", "/docs/guides/credentials", "/docs/guides/private-repositories", "/docs/guides/application-secrets", "/docs/guides/previews", "/docs/guides/project-file", "/docs/guides/members", "/docs/guides/update", "/docs/guides/troubleshoot-local-vms"],
  descriptions=["A lead and two workers, tasks, results, steering, interruption and recovery.", "OpenSSH, scp and rsync, VS Code Remote-SSH, cw cp and the browser terminal.", "Connect Codex, add API keys and SSH keys, and build a credential profile.", "Create environments from private GitHub repositories with the Codewire GitHub App.", "Store DATABASE_URL-style values and select which ones an environment receives.", "HTTPS preview URLs for hosted sandboxes; 127.0.0.1 ports for local VMs.", "Describe an environment once in codewire.yaml.", "Invite people, set roles, and share one environment.", "Keep cw current and move running local VMs to the new version.", "What the local VM error messages mean and what to do."]
) }}
