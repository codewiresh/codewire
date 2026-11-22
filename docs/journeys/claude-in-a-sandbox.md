# Claude Code starts in a Sandbox with no screen

`claude` in a cloud sandbox or a local VM starts straight into work, in bypass
permissions mode, with no first-run screen, whether a person types it or a
detached session starts it (#5813). The contract is the Claude home paragraph
of [`SECRETS-AND-CREDENTIALS.md`](../dev/SECRETS-AND-CREDENTIALS.md) and the
permission-mode table in [`CLI-ORCHESTRATION.md`](../dev/CLI-ORCHESTRATION.md).
This journey was written before the code. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-22. The first walk on Dev found two gaps: a repository cloned
inside another is not trusted (#5882), and Claude Code 2.1.330 offers to make
auto mode the default (#5883). Both are fixed, and the fixes are not yet
observed.

| ID | Dev (cloud sandbox) | Local VM (Linux) | Production |
| --- | --- | --- | --- |
| `claude-starts-interactive` | observed in a top-level repository; a nested repository and the auto-mode offer not yet observed | not yet observed | not yet observed |
| `claude-starts-detached` | observed; the auto-mode offer not yet observed | not yet observed | not yet observed |
| `claude-starts-managed` | observed on the Sandbox; the trusted-host half is pinned by a test only | not yet observed | not yet observed |
| `claude-starts-user-values-kept` | observed but the MCP question and a foreign file | not yet observed | not yet observed |
| `claude-starts-admin-off` | not yet observed | not yet observed | not yet observed |

## Before the walk

- A fresh environment, created from a project whose repository has its own
  `.mcp.json` (this repository's has one), with the Anthropic client selected
  in any form. Walk at least one repository cloned inside another, as a
  workspace file that clones repositories into a root checkout does.
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
  Then the same again with `claude --dangerously-skip-permissions`, and both
  again in a repository cloned inside another.
- **Proof:**
  - Neither stops at a screen: no login picker, no folder trust question, no
    "New MCP server found in this project", no "Bypass Permissions mode …
    No, exit", and no "Make auto mode your default permission mode?". The
    prompt is ready at once.
  - The mode shown is bypass permissions, and a tool such as `git status` runs
    without a prompt.
  - `~/.claude/settings.json` holds `permissions.defaultMode`,
    `skipDangerousModePermissionPrompt` and `enableAllProjectMcpServers`, and
    nothing else Codewire wrote. It is mode 0600 and holds no token or
    placeholder. `~/.claude.json` holds `hasSeenAutoDefaultNudge: true` and
    each repository's trust, the nested one included.
- **Gotchas:** a detached `cw run` session has a terminal only with `-t`.
  Without one, `claude` falls back to print mode and exits with "Input must be
  provided either through stdin or as a prompt argument when using --print".
- **Observed:** 2026-11-22 on Dev, services and daemon from source
  bc73bbac2f (accepted by promote-dev), `cw` 0.4.26, as the owner's Dev login,
  which the owner chose for this work (#5735). The Sandbox was created from the
  root workspace file, which clones a root checkout at `/workspace/codewire`
  and three repositories inside it. On its first run, `claude` updated itself
  from the image's 2.1.308 to 2.1.330. `settings.json` held exactly the three
  keys, mode 0600, and `CLAUDE_CODE_OAUTH_TOKEN` was the placeholder. In the
  root checkout, `claude` started in "bypass permissions on" with no trust or
  bypass screen. Two screens remained:
  - In `/workspace/codewire/codewire`, nested in the root checkout, it stopped
    at the folder trust question, because the daemon had trusted only
    `/workspace` and `/workspace/codewire` (#5882).
  - "Make auto mode your default permission mode? ❯ Yes …" appeared at start
    (#5883).

  Not yet observed: the fixes for both, the MCP question (the root checkout
  has no `.mcp.json`, and the nested one stopped at trust first), and
  `--dangerously-skip-permissions`.

## `claude-starts-detached`: a detached session works from its first line

- **Driving it:**
  `cw run --in ENV --name s --detach -t -- sh -c 'cd /workspace/REPO && claude "Run git status and reply with the branch name"'`,
  then `cw logs ENV --session s` after 30 seconds. Then
  `cw msg ENV --session s "Reply with the word done"` and read
  `~/.claude/settings.json` again.
- **Proof:** the session has answered the task. It is not waiting at a
  screen, and it did not exit at one. After the second message,
  `permissions.defaultMode` is still `bypassPermissions`.
- **Observed:** 2026-11-22 on Dev, same source and Sandbox as above, Claude
  Code 2.1.330, in the root checkout. The task ran `git status` with no prompt
  and answered "The branch is main." Then the auto-mode offer appeared, with
  "Yes" selected (#5883), so the second message was not sent: its Enter would
  have rewritten the default to `auto`. Not yet observed: the fix.

## `claude-starts-managed`: a managed agent in bypass mode

- **Driving it:** `cw run --in ENV --agent claude --name m --detach --prompt
  'Run git status and reply with the branch name'`, then `cw inbox ENV
  --session m`.
- **Proof:**
  - The turn completes, using Bash with no control request refused.
  - The reported policy names bypass permissions mode.
  - On a trusted host the same command passes no mode, and `cw` writes none
    of the three keys there.
- **Observed:** 2026-11-22 on Dev, same source and Sandbox as above, with the
  prompt naming `/workspace/codewire/codewire`. The message completed with
  "The branch is `main`. It's up to date with `origin/main` and has no
  uncommitted changes." `driver.policy` began "Sandbox execution: installed
  Claude CLI in bypass permissions mode (--permission-mode
  bypassPermissions)". The trusted-host half is pinned by the daemon
  conformance test `a_trusted_hosts_daemon_never_writes_claude_code_settings`
  and the CLI's launch tests. It was not walked.

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
- **Observed:** 2026-11-22 on Dev, same source as above, in the walked
  Sandbox rather than a fresh one. After `cw stop` and `cw start`, the file
  held the user's `defaultMode: "default"` and `enableAllProjectMcpServers:
  false` unchanged, plus only `skipDangerousModePermissionPrompt: true`, mode
  0600, in a new inode. `claude` started in "manual mode on". The auto-mode
  offer also appeared here (#5883). Not yet observed: the MCP question (no
  trusted repository with an `.mcp.json` was reachable before #5882's fix) and
  a symlinked or foreign file, which the unit tests pin.

## `claude-starts-admin-off`: an administrator can still turn bypass off

- **Driving it:** a managed `permissions.disableBypassPermissionsMode:
  "disable"` (for example in the image's managed settings), then `claude` and
  the managed agent.
- **Proof:** both start in default mode, with no bypass screen and no crash.
  The managed agent's tools that need approval are refused, as
  `CLI-ORCHESTRATION.md` says for a disabled mode.
- **Gotchas:** the managed settings file is root's. The workload user can't
  write it in a running Sandbox, so this step needs an image that carries it.
