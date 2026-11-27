---
title: Images and presets
description: Save an image, install and startup commands, resources and a lifetime once in the organization, and create hosted sandboxes from it.
updated: 2026-11-27
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
| `--install`, `--startup` | The install command, run once at setup, and a startup script that finishes, starting servers in the background ([Services after a start](@/environments/services.md)) |
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

The preset pins its image to a digest when you create it. Another image
then starts every sandbox from the same bytes until you change the preset.
The Codewire workspace image is the exception: a sandbox from the preset
starts on the current workspace image, so it gets each new release's tools
and `cw`. A `--` means the default. `cw preset list` lists the organization's presets.

## Create a sandbox from it

```sh
cw create --name ana-web --preset team-web --repo https://github.com/octocat/Hello-World
cw run --in ana-web --name check --no-tty -- redis-cli --version
```

```text
ana-web · cloud VM
  2 vCPU · 16 GiB RAM · 120 GiB disk
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

## A preset for Amp's self-hosted orbs

Amp's self-hosted orbs run on an image with glibc, git 2.34 or later,
`/usr/local/bin/amp`, and a `user` account whose home is `/home/user` and who
has passwordless sudo. The workspace image has all but the account and the
`amp` path: it ships `amp`, and its own `codewire` user already has
passwordless sudo. A startup script adds the rest:

```sh
cat > amp-orb-startup.sh <<'SCRIPT'
set -eu
kept=/workspace/.amp-orb
for path in "$kept" "$kept/home"; do
  if [ -L "$path" ]; then echo "amp-orb: $path is a link; refusing" >&2; exit 1; fi
done
sudo mkdir -p "$kept/home"
for path in "$kept" "$kept/home"; do
  if [ -L "$path" ]; then echo "amp-orb: $path is a link; refusing" >&2; exit 1; fi
done
getent group user >/dev/null || sudo groupadd --gid 1100 user
id -u user >/dev/null 2>&1 || sudo useradd --uid 1100 --gid 1100 \
  --no-create-home --home-dir /home/user --shell /bin/bash user
sudo chown -h user:user "$kept/home"
sudo find "$kept/home" -maxdepth 0 -type d -exec chmod 0700 {} +
sudo ln -sfn "$kept/home" /home/user
staged=$(sudo mktemp /etc/sudoers.d/.amp-orb.XXXXXX)
printf 'user ALL=(ALL) NOPASSWD:ALL\n' | sudo tee "$staged" >/dev/null
sudo chown root:root "$staged"
sudo chmod 0440 "$staged"
sudo visudo -cf "$staged" >/dev/null || { sudo rm -f "$staged"; exit 1; }
sudo mv -f "$staged" /etc/sudoers.d/90-amp-orb
sudo ln -sfn /opt/codewire/agents/npm/bin/amp /usr/local/bin/amp
SCRIPT
cw preset create amp-orb --name 'Amp orb' --image workspace \
  --startup "$(cat amp-orb-startup.sh)" --description "Meets Amp's orb image contract"
```

Why each step is there:

- **It's a startup script, not an install command.** Only the workspace
  storage, `/workspace` and `/home/codewire`, is kept when a sandbox stops.
  The account, the sudoers file and the links are on the image's own
  filesystem, so they're made again on every start. Each command checks
  first or replaces what it makes, so running it again changes nothing.
- **`/home/user` points into `/workspace`.** Amp pauses an orb with
  `cw stop` and resumes it with `cw start`, and expects its home to be
  kept, so the home lives in the kept storage.
- **A fixed uid and gid, 1100.** The account made on each start owns the
  same files in that kept home.
- **Passwordless sudo for `user`** gives it exactly what `codewire` already
  has. A sandbox's network policy and credential broker are enforced
  outside it, so root inside it changes neither.
- **No links are followed in the kept storage.** Anything in the sandbox can
  write `/workspace`, and the script runs as root there, so it refuses a
  link where it expects a folder and changes the owner of the folder
  itself (`chown -h`, and `chmod` only through `find -type d`, which never
  matches a link).
- **The sudoers file is checked, then put in place in one step.** `visudo`
  checks a staged copy, owned by root with mode 0440, and only a valid one
  replaces `90-amp-orb`. sudo ignores a name with a dot, such as the staged
  copy.
- **`/usr/local/bin/amp`** is the image's `amp`.

The orb's home is part of the kept storage, so it's in every snapshot of
the sandbox and in every sandbox forked from one. Amp's per-thread
`ORB_TOKEN` reaches an orb only in the environment of the run that starts
it. Never write it into the preset, a startup script or a file in the
sandbox.
