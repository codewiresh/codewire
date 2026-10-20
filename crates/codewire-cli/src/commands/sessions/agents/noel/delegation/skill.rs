//! The delegation skill's text.
//!
//! It is a string in Rust source, not a Markdown file read with `include_str!`:
//! a release admits only compiled inputs that the source digest covers, and
//! that digest takes Rust sources by pattern and every other file by name.

/// The skill as written. `{{cw}}` stands for the running `cw`.
pub(super) const TEXT: &str = r##"---
name: codewire-delegation
description: Delegate work to other agents with cw (Codewire). Launch Codex, Claude or noel workers under this conversation, get their results, follow up and stop them. Use when the user asks for delegation, sub-agents or parallel workers, or when a task clearly splits into independent parts.
---

# Delegating work with cw

Codewire manages this conversation, so its `bash` tool can launch other agents
as its workers. `{{cw}}` is the `cw` that runs this conversation: use that path.
Delegate only when the user asked for it or the work clearly splits into
independent parts: each worker is a full model session with its own cost.
`CW_ENVIRONMENT` and `CW_SESSION_ID` name this conversation. If either is
unset, delegation is unavailable here: say so instead of guessing values.

## Launch a worker

```sh
{{cw}} run "$CW_ENVIRONMENT" --agent codex --parent "$CW_SESSION_ID" --name NAME --detach --prompt 'TASK'
{{cw}} run "$CW_ENVIRONMENT" --agent claude --parent "$CW_SESSION_ID" --name NAME --detach --prompt 'TASK'
{{cw}} run "$CW_ENVIRONMENT" --agent noel --model PROVIDER/ID --parent "$CW_SESSION_ID" --name NAME --detach --prompt 'TASK'
```

- `TASK` is all the worker needs to know: it does not see this conversation.
  Inside the quotes, write a single quote as `'\''`.
- `NAME` comes from the task, never from chance: its words in lowercase joined
  by hyphens, at most 64 characters, such as `review-auth-tests`.
- noel needs `--model`; Codex and Claude have their own default.
- The command returns at once and prints `MESSAGE_ID<tab>STATE`.
- A name is used once. Launching the same task again starts nothing and fails
  with `session name is already retained: NAME`: that worker exists. Do not
  pick another name for it; read the worker's state or send it a follow-up.

## Results arrive by themselves

When a worker's task ends, its result is delivered to this conversation as a
message that begins `[Codewire] Managed worker NAME`, once per task, with how
it ended (`completed`, `error`, `interrupted` or `unknown`) and its reply. So
go on with your own part or end your turn. Do not poll and do not sleep.

## Follow, steer and stop

```sh
{{cw}} wait --message MESSAGE_ID --timeout 10m
{{cw}} inbox "$CW_ENVIRONMENT" NAME
{{cw}} msg "$CW_ENVIRONMENT" NAME 'TEXT'
{{cw}} steer "$CW_ENVIRONMENT" NAME 'TEXT'
{{cw}} interrupt "$CW_ENVIRONMENT" NAME
{{cw}} stop "$CW_ENVIRONMENT" --session NAME
{{cw}} stop "$CW_ENVIRONMENT" --session NAME --all
```

- `wait` blocks on one result when your next step needs it: it prints the reply
  and exits 0 only for a completed task. `inbox` shows a worker's state at once.
- `msg` gives the worker another task; its result arrives the same way.
- `steer` adds guidance to the running task and `interrupt` ends it. Both fail
  when no task is running, and a Claude worker refuses `steer`.
- `stop` ends the worker, which then accepts no more messages. There is no
  terminal here, so nothing prompts: `stop` leaves the worker's own running
  workers alone and names them; `stop ... --all` stops them too.
- Use these only on conversations you launched.
"##;
