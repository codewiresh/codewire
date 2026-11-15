# Agent login file formats

The login files Codewire writes for the coding agents, as the agent versions
pinned in `images/workspace/agents/package.json` read them. Neither format is
documented by its vendor, and both drift between releases, so each is recorded
here and checked (#3999).

- `claude-code.credentials.json`: Claude Code's `~/.claude/.credentials.json`.
- `codex.auth.json`: Codex's `auth.json` for a ChatGPT sign-in.
- `manifest.json`: the agent version each file was checked against.

Values that differ on every write are shown by name: the nonce in Claude's
placeholder refresh token, and Codex's two JWTs.

What fails, and what to do:

- **A writer no longer produces a file here** (`cargo test -p codewire-daemon
  recorded_for_the_pinned`): the change alters what an agent is given. Check it
  against the pinned agent before changing the file.
- **A pin moved** (`recorded_format_is_for`, and
  `scripts/ci/verify/workspace-agents.sh` on a lockfile-only change): check the
  new agent version still reads each file, then record the version in
  `manifest.json`.
