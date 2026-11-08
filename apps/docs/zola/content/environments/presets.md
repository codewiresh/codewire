---
title: Images and presets
description: Save an image, install and startup commands, resources and a lifetime once in the organization, and create hosted sandboxes from it.
updated: 2026-11-08
weight: 4
aliases: ["/guides/presets"]
---

A preset is a named starting point for hosted sandboxes, shared by the whole
organization: an image, install and startup commands, default resources and
a lifetime. Members choose it in `cw create --preset` or in the dashboard's
**Create Sandbox** form.

The output below is from a real run on a Codewire platform. Your IDs will differ.

## Create one

Suppose every web sandbox needs `redis-cli`, which the
[workspace image](@/environments/workspace-image.md) does not include, and
16 GiB of memory:

```sh
cw preset create team-web --name 'Team web' --image workspace \
  --install 'sudo apt-get update && sudo apt-get install -y redis-tools' \
  --memory 16384 --ttl 4h --description 'Workspace image with redis-cli, 16 GiB'
```

```text
Preset created: Team web.
  ID:    f6c03f9f-b621-41bd-b667-b31bdae01521
```

| Flag | Meaning |
| --- | --- |
| `SLUG` | The name members use with `--preset` |
| `--name` | Display name; defaults to the slug |
| `--image` | Container image; `workspace` is the Codewire workspace image, and `go`, `node` and `python` are shorthands |
| `--install`, `--startup` | The install command, run once at setup, and a startup script that finishes; start servers in a session, not here |
| `--cpu`, `--memory`, `--disk` | Default CPU cores, MB and GB |
| `--ttl` | Default lifetime, for example `2h`; the sandbox is removed when it ends |
| `--description` | Shown in lists and the dashboard |

## Look at one

```sh
cw preset info team-web
```

```text
ID:        f6c03f9f-b621-41bd-b667-b31bdae01521
Name:      Team web
Slug:      team-web
Language:  --
Image:     ghcr.io/codewiresh/workspace@sha256:{digest}
Official:  false
Build:     ready
CPU:      --m
Memory:   16384MB
Disk:     --GB
```

The preset pins the image to its digest when you create it, so every
sandbox starts from the same bytes until you change the preset. A `--`
means the default. `cw preset list` lists the organization's presets.

## Create a sandbox from it

```sh
cw create --name ana-web --preset team-web --repo https://github.com/octocat/Hello-World
cw run --in ana-web --name check --no-tty -- redis-cli --version
```

```text
ana-web · cloud VM
  2 vCPU · 16 GiB RAM · 80 GiB disk
✓ Started session ana-web/check · cloud
redis-cli 7.0.15
```

The sandbox got the preset's memory and install command; `--repo` adds the
repositories to clone, which a preset does not hold.

## Save or delete

- `cw create ... --save-preset NAME` saves the settings a create resolved as
  a new preset on the server; `--write-preset` writes them to
  `./codewire.yaml` instead.
- `cw preset rm ID` deletes a preset. It takes the ID, not the slug, and is
  refused while an environment created from it still exists.

A `codewire.yaml` in the repository does the same job as a preset and
travels with the code; see [`codewire.yaml`](@/environments/codewire-yaml.md).
Presets are for hosted sandboxes; a local VM reads only `codewire.yaml` and
flags.
