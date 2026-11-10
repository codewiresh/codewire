---
title: codewire.yaml keys
description: Every key codewire.yaml accepts, with its type and limits.
updated: 2026-11-10
weight: 2
---

How Codewire finds and uses the file is in
[`codewire.yaml`](@/environments/codewire-yaml.md).

Unknown keys are rejected. The same keys apply in `codewire.local.yaml` and
in every file merged with repeated `--file`; see
[Override files](@/environments/codewire-yaml.md#override-files).

| Key | Type | Notes |
| --- | --- | --- |
| `version` | integer | `1` |
| `preset` | string | a preset slug the platform resolves |
| `image` | string | `workspace` for the Codewire image, or any OCI reference |
| `repositories` | list | `source`, optional `branch` or `revision`, `destination` under `/workspace`, optional `known_hosts` lines for SSH sources other than `github.com`; up to 64; a destination may lie inside another repository's, which is cloned first |
| `working_directory` | string | default `/workspace` |
| `install_command`, `startup_script` | string | install runs once at setup; startup runs at every boot |
| `environment` | map | plain variables, up to 256; never secret values |
| `secrets` | object | `organization: true`, `user: local|platform`, `project: NAME` |
| `credentials` | object | `profile: NAME`, `local:NAME` or `platform:NAME` |
| `ports` | list | `port` with `label` and `access` for a preview; `host_port` and `guest_port` for a local VM port |
| `cpu`, `memory`, `disk` | quoted strings | `100m` to `256` CPUs; `128Mi` to `1Ti`; whole GiB from `1Gi` to `16384Gi` |
| `agents` | object | `install: bool` and `tools: [ids]`; `claude-code` and `codex` are the agents Codewire manages |
| `skills` | list | `source: repository` with `path` (relative to `/workspace`), or `source: user` with `name` (from `~/.codewire/skills`); optional `agents`; needs `agents.tools`. See [Agent skills](@/agents/skills.md) |
| `mounts` | list | local VMs only: `source`, `destination`, `mode: copy|direct`, `read_only` (required for `direct`) |
| `workspace.vm_only` | list | local VMs only: folders kept on the VM disk under a live mount; default `node_modules`, `target`, `.venv` |
| `workspace.path_mode` | string | local VMs only: `mount`, `copy`, `clone` or `empty`, the default for `--path-mode`, which overrides it; with repositories, `mount` or `clone` |

Keep secret values, key file paths and store references out of this file:
`secrets` and `credentials` select sources by name only.
