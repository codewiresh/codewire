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
- **Claude Code no longer does what Codewire expects with its file**
  (`scripts/ci/verify/claude-login-compat.py`, run by
  `scripts/ci/verify/workspace-agents.sh`): the pinned Claude Code is run with
  no network against a fake provider, starting from
  `claude-code.credentials.json` with its access token run out, and then
  with no file and the placeholder in each environment variable it reads an
  Anthropic credential from (`CLAUDE_CODE_OAUTH_TOKEN`,
  `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY`). The failure names what
  changed: the refresh request, where the placeholder is sent, what the
  agent wrote back, or a variable whose placeholder it no longer sends. The
  placeholders it makes up have the shape
  `crates/codewire-access/tests/fixtures/claude-oauth-token/refresh-response.json`
  states. The broker swaps the placeholder on every path
  of the API host, so the script's path lists are its alarm for a new pin,
  not a rule the broker enforces: look at what a new path is before adding
  it.
- **Codex no longer refreshes as Codewire answers it**
  (`scripts/ci/verify/codex-login-compat.py`, run by
  `scripts/ci/verify/workspace-agents.sh`): the pinned Codex is run with no
  network against a fake provider, starting from `codex.auth.json` with an
  old `last_refresh`, a refused refresh, a recent login, and a provider that
  answers 401 until a refresh. Each case must end with its turn answered
  (`ok`, exit 0), and each refresh must be the request
  `crates/codewire-access/tests/fixtures/codex-oauth-token/refresh-request.json`
  records, at `POST auth.openai.com/oauth/token`: the only request the
  broker answers on Codex's token host (#6197). A new endpoint, host or
  grant means the token host's rule must change before the pin moves.
