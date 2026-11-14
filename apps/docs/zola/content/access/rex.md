---
title: Rex
description: Run commands, open shells and attach to sessions from Rex's command palette, and see each session's state with its pane.
updated: 2026-11-14
weight: 6
---

[Rex](https://superlogical.com) is a terminal multiplexer with a command
palette. `cw setup rex` adds Codewire to it:

```sh
cw setup rex
```

It writes a Lua plugin beside Rex's config (`~/.config/rex/init.lua`, or
`REX_CONFIG`) and a managed block in the config that loads it, checks the
result with `rex config check`, and reloads Rex's config. Open the palette in
Rex and type Codewire. `cw setup rex remove` takes both out again.

## Actions

The actions work in the environment `cw use` selected and name it, for
example Codewire: Open Shell in app. `cw use` and `cw rm` update them in Rex
as the selection changes. Each opens beside the pane you are in.

| Action | Shown | Does |
| --- | --- | --- |
| Codewire: Run Once in ENV… | Always | Asks for a command and runs it once with `cw exec`, in a pane that stays open to show how it ended. No session is left. With nothing selected it opens `cw use` first |
| Codewire: Start in ENV… | Always | Asks for something that keeps running, such as a server or an agent, and starts it as a session with `cw run -- sh -c COMMAND`. `claude` or `codex`, with or without arguments, opens that agent's own terminal UI instead. With nothing selected it opens `cw use` first |
| Codewire: Open Shell in ENV | Always | `cw shell`: a login shell that ends when you leave it, as `ssh` does, or 10 minutes after a lost connection; with nothing selected, `cw use` first |
| Codewire: Choose Environment… | Always | `cw use` in a floating panel: every environment, or an offer to create one when there are none |
| Codewire: List Environments | Always | `cw ls` in a floating panel |
| Codewire: Attach to a Session in ENV… | An environment is selected | `cw attach`: its only session, a choice among them, or a new shell |
| Codewire: Message This Session… | An environment is selected | Asks for text and sends it with `cw msg` to the session attached in the focused pane: typed into a terminal session, or a managed agent's next task |
| Codewire: Ports of ENV | A local VM or cloud environment is selected | `cw ports` in a floating panel |
| Codewire: Open ENV in VS Code | A local VM or cloud environment is selected | `cw vscode` |

Rex can also run them by name with arguments, for example from a key binding
in your own `init.lua` or from a script:

```sh
rex do codewire_exec 'command=npm test' env=my-app
rex do codewire_run 'command=npm run dev' env=my-app
rex do codewire_attach env=my-app session=lead
```

The actions run `cw` on the machine of the Rex server, so they refuse a Rex
session on another host.

## Session state in Rex

A session attached in a Rex pane, by `cw attach` or `cw run`, reports itself
to Rex with an OSC 7501 program status record, `codewire/session`, which Rex
shows with the pane:

| State | Means |
| --- | --- |
| idle, `ENV/SESSION`, `local VM`, `cloud` or `host` | Attached to a running session |
| working, `reconnecting to ENV` | The connection was lost; `cw` is reconnecting |
| done, `exited` | The session exited with status 0 |
| error, `exited with status N` | The session failed or exited with another status |

Detaching withdraws the record. Outside Rex, or when output is not a terminal,
`cw` writes nothing.
