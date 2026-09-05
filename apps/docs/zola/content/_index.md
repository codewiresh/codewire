---
title: What is Codewire?
description: Cloud machines for AI coding agents
template: section.html
sort_by: none
in_search_index: true
---


Codewire gives every AI coding agent its own dedicated cloud environment. Launch Claude Code, Codex, or any tool on isolated machines — and run them in parallel.

No shared kernels. No noisy neighbors. Each environment gets an isolated VM with dedicated runtime resources.

## Key concepts

### Organizations

Group your team, environments, secrets, and billing together. Each organization has its own members, roles, and sandbox environment inventory.

### Environments

Isolated development machines where agents run. Each environment has its own runtime, tools, repository checkout, ports, files, terminal access, SSH access, previews, and persistent sessions.

## How it works

### From the web

1. **Sign up** with an invite code and set up 2FA
2. **Create an organization**
3. **Create an environment** from a public repository URL
4. **Connect** — open a terminal, preview, files, SSH, or an agent session

### From the CLI

During the private preview, run this from an authorized source checkout:

```bash
make cli-install
cw setup
cw env create https://github.com/owner/public-repo
cw run -- claude "fix the tests"
```

## Codewire vs alternatives

| | Codewire | Self-managed Kubernetes | GitHub Codespaces |
|---|---|---|---|
| **Setup** | Create an environment from a repo | Configure clusters, storage, ingress, auth, and billing | Instant but limited config |
| **Isolation** | VM-backed sandbox environments | Depends on your infrastructure | Shared kernel containers |
| **AI agents** | First-class support: launch, orchestrate, monitor | Build your own orchestration | Not designed for parallel agents |
| **Maintenance** | Automatic upgrades, monitoring, backups | You manage everything | Managed by GitHub |
| **Team management** | Built-in orgs, invitations, roles, and access grants | Bring your own auth and policy | GitHub org/team permissions |
| **Infrastructure** | Runtime, ingress, secrets, previews, and sessions managed together | You provision and operate it | Shared hosted infrastructure |
| **Billing** | Organization plans and usage tracking | Your infrastructure cost model | Per-minute compute pricing |

## Next steps

{{ card_grid(
  titles=["Quickstart", "CLI quickstart", "Create an account"],
  hrefs=["/docs/quickstart", "/docs/cli/overview", "/docs/getting-started/create-account"],
  descriptions=["Get your first environment running in 5 minutes.", "Install the CLI and launch agents from your terminal.", "Sign up and verify your email."]
) }}
