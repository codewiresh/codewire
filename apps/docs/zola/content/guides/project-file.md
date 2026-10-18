---
title: The project file
description: Describe an environment once in codewire.yaml so that cw env create builds it the same way every time, locally or on the platform.
weight: 7
---

`codewire.yaml` in a project's root describes the environment that project
wants. `cw env create --local --path .` reads it from the directory; the
platform reads it from `--file codewire.yaml` or from the repository. Explicit
flags override the file.

```sh
cw init                                                   # writes codewire.yaml from the current directory
cw init --image workspace --install 'pnpm install' --startup 'pnpm dev'
cw env create --local --name app --path .
cw env create --name app --file codewire.yaml
cw env create --name app --image workspace --write-preset  # write the resolved preset back
```

`cw init` refuses to overwrite an existing file without `--force`. Given only
direct inputs (image, commands, resources, variables) it works offline;
resolving a preset, a repository or a branch needs a signed-in platform.

## Example

```yaml
version: 1
image: workspace
working_directory: /workspace/app

repositories:
  - source: https://github.com/owner/app
    branch: main
    destination: app

install_command: pnpm install
startup_script: pnpm dev

environment:
  LOG_LEVEL: info

secrets:
  organization: true
  project: development

credentials:
  profile: platform:work

ports:
  - port: 3000
    label: web
    access: org_members

cpu: "2"
memory: 4Gi
disk: 20Gi

workspace:
  vm_only:
    - node_modules
    - target
    - .venv
```

## Keys

Unknown keys are rejected.

| Key | Type | Notes |
| --- | --- | --- |
| `version` | integer | `1` |
| `preset` | string | a preset slug the platform resolves |
| `image` | string | `workspace` for the Codewire image, or any OCI reference |
| `repositories` | list | `source`, optional `branch` or `revision`, `destination` under `/workspace`, optional `known_hosts` lines for SSH sources other than `github.com`; up to 64 |
| `working_directory` | string | default `/workspace` |
| `install_command`, `startup_script` | string | install runs once at setup; startup runs at every boot |
| `environment` | map | plain variables, up to 256; never secret values |
| `secrets` | object | `organization: true`, `user: local|platform`, `project: NAME` |
| `credentials` | object | `profile: NAME`, `local:NAME` or `platform:NAME` |
| `ports` | list | `port` with `label` and `access` for a preview; `host_port` and `guest_port` for a local VM port |
| `cpu`, `memory`, `disk` | quoted strings | `100m` to `256` CPUs; `128Mi` to `1Ti`; whole GiB from `1Gi` to `16384Gi` |
| `agents` | object | `install: bool` and `tools: [ids]`; `claude-code` and `codex` are the agents Codewire manages |
| `skills` | list | `source: repository` with `path`, or `source: user` with `name`; optional `agents` |
| `mounts` | list | local VMs only: `source`, `destination`, `mode: copy|direct`, `read_only` (required for `direct`) |
| `workspace.vm_only` | list | local VMs only: folders kept on the VM disk under a live mount; default `node_modules`, `target`, `.venv` |

Keep secret values, key file paths and store references out of this file:
`secrets` and `credentials` select sources by name only.

## Local-only behaviour

`--repo` is refused for a local VM; declare repositories in the file and the
host's Git fetches them. `mounts` and `workspace.vm_only` apply to local VMs,
where `--path` is mounted live by default. `cw env create --local` shows the
resolved settings and asks before creating.
