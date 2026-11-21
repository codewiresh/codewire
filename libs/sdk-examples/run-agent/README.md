# Run a coding agent

Gives a coding agent a small task in an environment and prints the change it
made, without a terminal:

1. Creates an environment from the Codewire workspace image, which carries
   Claude Code, git and Python, and waits until it is ready.
2. Uploads a two-file Python project whose test fails, commits it as a
   baseline, and checks that the test does fail.
3. Runs the agent in the project: by default
   `claude -p "<task>" --permission-mode acceptEdits`, asked to make the test
   pass without changing it.
4. Prints `git diff`, then checks that the test passes.
5. Deletes the environment, whether or not those steps succeeded.

```sh
export CODEWIRE_API_KEY=cw_...
export CODEWIRE_ORG_ID=...
```

For a server other than the hosted one, set its URL as the
[quickstart](../quickstart/) describes; each SDK reads its own variable.

| Language | Run it |
| --- | --- |
| Go | `cd go && go run .` |
| Python | `python python/run_agent.py`, with the SDK installed |
| TypeScript | `cd typescript && npm ci --install-links && npm start`, after `npm run build` in `libs/sdk-ts` |
| Rust | `cargo run -p codewire --example run_agent` |

Claude Code needs a Claude credential in the environment. A program signed
in with an API key can't bind a profile to the environment today, so it
can't give Claude Code your sign-in (#5687).

`RUN_AGENT_COMMAND` replaces the agent command, run with `sh -c` in the
project. CI sets it to a fixed edit that makes the test pass, so the whole
flow runs there with no provider credential; nothing that stand-in prints is
the agent's output. With Claude, expect `uploaded the project; its test
fails`, then the diff Claude made to `greeting.py`, then `the test passes`.
