---
title: API keys
description: Drive hosted sandboxes from CI or a script with an API key, JSON output and exit codes that fail the job.
updated: 2026-10-26
weight: 3
aliases: ["/use-cases/ci-and-scripts", "/guides/scripts-and-ci"]
---

Run checks, agents or previews from a CI job or a script. A script signs in
with an API key instead of a browser, reads JSON instead of tables, and
relies on `cw wait` to fail when the command in the sandbox fails.

The output below is from a real run. Your IDs will differ.

## 1. Create an API key

Once, from a signed-in terminal:

```sh
cw api-keys create ci --expires 90
```

`cw` prints the key once and nothing else, so you can pipe it straight into
your CI system's secret store. The key acts in your current organization;
`--expires 0` never expires. `cw api-keys list` and
`cw api-keys delete KEY_ID` manage keys.

## 2. Use it in the job

Set two variables in the job's environment:

```sh
export CODEWIRE_API_KEY=...                    # from your CI secret store
export CODEWIRE_SERVER_URL=https://codewire.sh
```

With these set, `cw` needs no `cw setup` and no saved configuration. Install
it in the job with the same one-line installer as on your machine.

## 3. Run a check and fail on failure

```sh
cw run --in pr-42 --name check --no-tty --detach -- sh -c 'test -f /workspace/Hello-World/README && echo README found'
cw wait pr-42 --session check --timeout 2m
```

```text
✓ Started session pr-42/check · cloud
README found
```

`cw wait` streams the session's output and exits 0 only after the command
exits 0. When the command fails, `cw wait` fails too:

```sh
cw run --in pr-42 --name check-missing --no-tty --detach -- sh -c 'test -f /workspace/Hello-World/package.json'
cw wait pr-42 --session check-missing --timeout 2m
```

```text
session exited with code 1
```

and its exit code is 1, which fails the CI step. `cw logs pr-42 --session check`
prints the saved output again later.

## 4. Read JSON

Every listing and launch takes `--output json`:

```sh
cw run --in pr-42 --name check-json --no-tty --detach --output json -- sh -c 'test -f /workspace/Hello-World/README && echo README found'
```

```json
{
  "session_id": "session-7d4cf562-2f47-49c0-9b7b-114f1f4497fa",
  "name": "check-json",
  "parent_session_id": "",
  "cleanup_unknown": false,
  "launch_generation": 1,
  "state": "Running",
  "command": [
    "sh",
    "-c",
    "test -f /workspace/Hello-World/README && echo README found"
  ],
  "working_dir": "/workspace/Hello-World",
  "pty": false,
  "exit_code": null,
  "output_end_offset": 0,
  "output_start_offset": 0,
  "status_message": "session running"
}
```

`cw ls pr-42 --output json` returns each session's `state`, `exit_code` and
`mode` (`normal` or `managed`).

## 5. Run an agent from CI

A managed agent conversation returns IDs you can wait on:

```sh
cw run --in pr-42 --name review --agent claude --detach \
  --prompt 'Read /workspace/Hello-World and say in one sentence what the repository contains. Do not edit files.'
```

```text
request 9f403fc3-1977-4580-8dc1-3ce48e24acdd	session session-9f403fc3-1977-4580-8dc1-3ce48e24acdd	message f78df504-2dbb-8f7e-9c2b-3f714849dddc	completed
```

```sh
cw wait --message f78df504-2dbb-8f7e-9c2b-3f714849dddc --timeout 10m
```

```text
The repository contains a single `README` file with the text "Hello World!"
```

The line is tab-separated, so `cut -f3 | cut -d' ' -f2` extracts the message
ID. `completed` means the launch completed; `cw wait --message` returns the
agent's reply and fails on a timeout or an error.

The sandbox needs a [credential profile](@/secrets/credentials.md) with a
provider for the agent. An API key acts for the organization, so it cannot
attach your personal profile: create the sandbox with `--profile` from a
signed-in terminal (or from a preset), then the job can start agents in it.
Trying it with a key fails with `organization-scoped API key cannot perform
account-global operations`.

## Related

- [Preview environments](@/use-cases/preview-environments.md)
- [Run and orchestrate](@/agents/run.md)
- [CLI reference: Account and organizations](@/reference/cli/organizations.md) for API keys.
