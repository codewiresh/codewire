# Claude Code starts in a Sandbox with no screen

`claude` in a cloud sandbox or a local VM starts straight into work, in bypass
permissions mode, with no first-run screen, whether a person types it or a
detached session starts it (#5813). The contract is the Claude home paragraph
of [`SECRETS-AND-CREDENTIALS.md`](../dev/SECRETS-AND-CREDENTIALS.md) and the
permission-mode table in [`CLI-ORCHESTRATION.md`](../dev/CLI-ORCHESTRATION.md).
This journey was written before the code. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-21. Written first; every step is not yet observed.

| ID | Dev (cloud sandbox) | Local VM (Linux) | Production |
| --- | --- | --- | --- |
| `claude-starts-interactive` | not yet observed | not yet observed | not yet observed |
| `claude-starts-detached` | not yet observed | not yet observed | not yet observed |
| `claude-starts-managed` | not yet observed | not yet observed | not yet observed |
| `claude-starts-user-values-kept` | not yet observed | not yet observed | not yet observed |
| `claude-starts-admin-off` | not yet observed | not yet observed | not yet observed |

## Before the walk

- A fresh environment, created from a project whose repository has its own
  `.mcp.json` (this repository's has one), with the Anthropic client selected
  in any form.
- On Dev, walk as the Dev smoke identity
  (`scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND`), or as the owner in
  their own organization when the owner walks it.
- Record `cw version`, the source the surface was running, and
  `claude --version` in the environment. Claude Code can update itself in a
  Sandbox, so record the version each step actually ran.
- Walk this journey again whenever the image's Claude Code version changes.
  The keys are Claude Code's own and can be renamed between versions.
- A repository's `.mcp.json` runs code when `claude` starts: its servers'
  commands start with no question once `enableAllProjectMcpServers` is set.
  Walk with a repository whose `.mcp.json` you have read.

## `claude-starts-interactive`: typed in a repository

- **Driving it:** `cw shell ENV`, then `cd /workspace/REPO` and `claude`.
  Then the same again with `claude --dangerously-skip-permissions`.
- **Proof:**
  - Neither stops at a screen: no login picker, no folder trust question, no
    "New MCP server found in this project", and no "Bypass Permissions mode …
    No, exit". The prompt is ready at once.
  - The mode shown is bypass permissions, and a tool such as `git status` runs
    without a prompt.
  - `~/.claude/settings.json` holds `permissions.defaultMode`,
    `skipDangerousModePermissionPrompt` and `enableAllProjectMcpServers`, and
    nothing else Codewire wrote. It is mode 0600 and holds no token or
    placeholder.

## `claude-starts-detached`: a detached session works from its first line

- **Driving it:**
  `cw run --in ENV --name s --detach -- sh -c 'cd /workspace/REPO && claude "Run git status and reply with the branch name"'`,
  then `cw attach ENV --session s` after 30 seconds.
- **Proof:** the session has answered the task. It is not waiting at a
  screen, and it did not exit at one.

## `claude-starts-managed`: a managed agent in bypass mode

- **Driving it:** `cw run --in ENV --agent claude --name m --detach --prompt
  'Run git status and reply with the branch name'`, then `cw inbox ENV
  --session m`.
- **Proof:**
  - The turn completes, using Bash with no control request refused.
  - The reported policy names bypass permissions mode.
  - On a trusted host the same command passes no mode, and `cw` writes none
    of the three keys there.

## `claude-starts-user-values-kept`: the user's own settings win

- **Driving it:** in a fresh environment, before the first session, write
  `{"permissions":{"defaultMode":"default"},"enableAllProjectMcpServers":false}`
  to `~/.claude/settings.json`. Then restart the environment and start
  `claude`.
- **Proof:**
  - Both of the user's values are unchanged. Only
    `skipDangerousModePermissionPrompt` was added.
  - `claude` starts in default mode and asks about the project's MCP server,
    as the user chose.
  - A symlinked or another user's `settings.json` is left untouched.

## `claude-starts-admin-off`: an administrator can still turn bypass off

- **Driving it:** a managed `permissions.disableBypassPermissionsMode:
  "disable"` (for example in the image's managed settings), then `claude` and
  the managed agent.
- **Proof:** both start in default mode, with no bypass screen and no crash.
  The managed agent's tools that need approval are refused, as
  `CLI-ORCHESTRATION.md` says for a disabled mode.
