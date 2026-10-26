---
title: Skills
description: Give Claude Code and Codex in a local VM the same skills every time, from your project or from your own skill folder, and refresh them without recreating the VM.
updated: 2026-10-26
weight: 4
aliases: ["/guides/skills"]
---

A skill is a folder with a `SKILL.md` that tells an agent how to do one job,
such as writing release notes or reviewing a change. List skills in
`codewire.yaml` and Codewire copies a snapshot of each into the VM, where
Claude Code and Codex look for them. The VM gets a copy, never a live link to
your machine, so an agent cannot change your skills.

The output below is from a real run on a local VM.

## 1. Write the skills

A project skill lives in the repository, for everyone who works on it:

```text
skills-demo/.agents/skills/release-notes/SKILL.md
```

A personal skill lives in your Codewire skill folder, for every project:

```text
~/.codewire/skills/review-style/SKILL.md
```

Each `SKILL.md` starts with a name and a description:

```markdown
---
name: review-style
description: Review a change for naming and comments.
---

Check names and comments against the surrounding code.
```

## 2. List them in codewire.yaml

```yaml
version: 1
agents:
  tools: [claude-code, codex]
skills:
  - source: repository
    path: skills-demo/.agents/skills/release-notes
  - source: user
    name: review-style
```

Two rules, both easy to miss:

- **`agents.tools` is required.** It names the agents that receive the
  skills. Without it, the create fails with `create_skill_snapshot`.
- **A repository `path` starts at `/workspace`,** not at the project folder.
  A project mounted at `/workspace/skills-demo` names its skill
  `skills-demo/.agents/skills/release-notes`.

Add `agents: [codex]` to one skill to give it to one agent only.

## 3. Create the VM

```sh
cw create --local --name skills-demo
cw info skills-demo
```

`cw info` shows the agents and the snapshot:

```text
Agents:      claude-code, codex
Skills:      2 snapshot(s), generation 1, plan 32c6555b145818a7654b6ed0d590ded3a5b5b20953ea37143142812d90901f17
```

Inside the VM, each agent finds them where it looks:

```sh
cw run --in skills-demo --name look --no-tty -- sh -c 'ls ~/.claude/skills; ls "${CODEX_HOME:-$HOME/.codex}/skills"'
```

```text
✓ Started session skills-demo/look · local VM
release-notes
review-style
release-notes
review-style
```

## 4. Refresh after a change

The VM keeps the snapshot it was created with. After you edit a skill, take
a new snapshot without recreating the VM:

```sh
cw refresh-skills skills-demo
```

```text
Skills:      2 snapshot(s), generation 2, plan f104872c97e7399c4c8338a6af153e1d36699f501064047b2f1b28fcbf230409
```

The generation goes up, and the agents see the new text on their next read.
A snapshot holds at most 64 MiB and 100,000 files.

## Related

- [`codewire.yaml`](@/reference/codewire-yaml.md): the `skills` and
  `agents` keys.
- [Run and orchestrate](@/agents/run.md)
