---
title: The workspace image
description: "What the Codewire workspace image holds: Ubuntu, language toolchains, Docker, Git, GitHub CLI and the coding agents, and how to add more."
updated: 2026-11-12
weight: 3
---

Every environment starts from the Codewire workspace image unless its
`codewire.yaml` or preset names another (`image: workspace` is the default).
It is Ubuntu with the common toolchains, Docker and the coding agents already
installed, so most projects need only their own dependencies.

The list below is from a real run on a local VM created by `cw` v0.4.1.
Versions move with each release; check yours with `cw run --in ENV -- TOOL --version`.

```sh
cw run --in wsimg --name probe --no-tty -- sh -lc '. /etc/os-release; echo "OS: $PRETTY_NAME"
  for t in python3 node npm pnpm yarn bun rustc cargo gcc make git gh docker uv poetry pipx claude codex gemini aider; do
    echo "$t | $($t --version 2>&1 | head -1)"; done'
```

```text
OS: Ubuntu 24.04.4 LTS
python3 | Python 3.12.3
node | v22.23.2
npm | 12.2.0
pnpm | 12.9.0
yarn | 1.22.22
bun | 1.4.4
rustc | rustc 1.99.0 (b940084d7 2026-09-28)
cargo | cargo 1.99.0 (5f94df478 2026-08-27)
gcc | gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
make | GNU Make 4.3
git | git version 2.43.0
gh | gh version 2.97.0 (2026-07-31)
docker | Docker version 29.7.1, build e9452d6
uv | uv 0.13.5 (x86_64-unknown-linux-gnu)
poetry | Poetry (version 2.5.1)
pipx | 1.4.3
claude | 2.1.288 (Claude Code)
codex | codex-cli 0.160.0
gemini | 0.62.0
aider | aider 0.86.2
```

## What it holds

| | |
| --- | --- |
| System | Ubuntu 24.04, `build-essential`, `curl`, `jq`, `tmux`, `vim`, `rsync`, `strace`, `gdb`, the PostgreSQL client, terminfo for kitty, alacritty, wezterm, foot and most other terminals (`ncurses-term`, `kitty-terminfo`) |
| Python | Python 3.12 with `venv` and `pip`, `pipx`, `uv`, `poetry` |
| JavaScript | Node.js 22, `npm`, `pnpm`, `yarn`, `bun` |
| Go | Go 1.27 |
| Rust | Rust 1.99 with `rustfmt` and `clippy` |
| Containers | Docker Engine with Buildx and Compose; the daemon runs in the VM, see [Docker inside](@/environments/docker.md) |
| Git | `git`, GitHub CLI (`gh`) |
| Agents | Claude Code (`claude`), Codex (`codex`), Gemini CLI (`gemini`), Aider (`aider`) |

You work as the `codewire` user (UID 1000) in `/workspace`, with
passwordless `sudo`. The home directory is kept across stops and starts.

## Adding more

- **For one environment**, install as usual: `sudo apt-get install`, `pip`,
  `npm` or `cargo`. It stays until the environment is removed.
- **For every environment of a project**, put the commands in
  `install_command` in [`codewire.yaml`](@/environments/codewire-yaml.md); it
  runs once when the environment is created.
- **For the whole organization**, save them in a preset; see
  [Images and presets](@/environments/presets.md).
- **Newer agent versions**: an agent you update yourself installs into your
  own prefix, without `sudo`, and takes precedence on `PATH`.

`apt-get` installs from a fixed Ubuntu snapshot, so every environment gets
the same package versions.

Codewire manages Claude Code and Codex conversations (`cw run --agent`); the
other agents run as ordinary terminal sessions. See
[Supported agents](@/agents/supported.md).

Claude Code opens full screen, with its input box on the bottom rows, as with
its `"tui": "fullscreen"` setting: the image sets `CLAUDE_CODE_NO_FLICKER=1`.
The variable outranks Claude's own `"tui"` setting, so for its inline renderer
add `unset CLAUDE_CODE_NO_FLICKER` to your shell's rc file.

Claude Code trusts `/workspace` in Codewire environments: it starts in the
workspace, and in every Git repository up to three levels under it, without
asking whether you trust the folder. That question guards against a folder's
own Claude settings, such as hooks and MCP servers, running when Claude Code
starts; the workspace holds your own checkouts. Claude Code stops looking for a trusted folder at a
repository's root, so the environment marks the workspace and each repository
root trusted in `~/.claude.json`, keeping everything else in the file. It
does so when it starts and again before each session, so a repository you
clone later is covered from your next session on. Folders outside the
workspace, such as your home directory, still ask.
