---
name: codewire-cli-design
description: Codewire CLI presentation rules - what cw prints and asks, and how it looks. Use for any change to cw's help text, command output, errors and next-step hints, tables, prompts and pickers, progress, empty and first-run states, colour or terminal art, and JSON or piped output, under crates/codewire-cli. Do not use for dashboard UI (codewire-design) or Rust structure (codewire-rust).
---

# Codewire CLI design

This skill is the one home of the CLI presentation rules, as `codewire-design`
is for the dashboard (owner, 2026-11-13: "we should have design specs for cli,
just like ui"; cited on #3013). The reasoning and the command-by-command
requirements are in `private-docs: designs/2026-10-18-cli-launch-and-managed-agent-ux.md`
("Shared command output", "Lifecycle output and progress", "Help and command
discovery"). `crates/codewire-cli/src/output.rs` is the one renderer that
implements these rules: use its primitives rather than printing escapes,
glyphs or spinners by hand. Output that breaks a rule here is a bug in the
output, not a reason to change the rule quietly.

The goal is polish and feel: a new user finds the next step without reading
the docs, and nothing on screen is internal.

## Streams and terminals

- Durable results go to stdout. Progress, pickers and prompts go to stderr.
  `--output json` prints only its schema: no progress, colour, glyphs,
  prompts or hints, and the same exit statuses as text.
- `output::Capabilities` decides what a stream may draw. Colour only when that
  stream is a terminal, `TERM` is not `dumb` and `NO_COLOR` is unset or empty.
  Live redraw only when stderr is a terminal. Reduced motion
  (`CODEWIRE_REDUCED_MOTION`) keeps the status, not the motion. ASCII glyphs
  for `TERM=dumb` and for a non-UTF-8 locale.
- Piped text is the same text with no escape sequences. A command that never
  takes over the terminal (`--no-tty`, piped, JSON) writes no terminal-mode
  sequences, not even resets.

## Status, colour and art

- Six statuses, each readable without colour: `✓` done (green), `◐` active
  (cyan; the rotating circle is the only motion, on the one row doing work),
  `!` attention (yellow), `✗` failed (red), `→` next command (cyan), `›`
  selected. ASCII: `+`, the spinner's ASCII frames, `!`, `x`, `->`, `>`.
- Dim is for secondary detail such as timing, location and source. Bold is for
  headings and the one thing the eye should find first: a name, a code, a URL
  to open.
- Text uses the 16-colour roles in `output::Role`. 24-bit colour is only for
  brand art (the wordmark, the upgrade wire), and only when `COLORTERM` says
  truecolor, with a 256-colour fallback. Art is decoration on stderr, drawn
  only when the stream is live, never in a pipe, a log or JSON.
- Reads are neutral. A list or `info` has no `✓` per row.

## Help

- Grouped help is generated from the one parser: `cw --help` shows the
  everyday groups and `cw help --all` adds the rest (launch design, "Help and
  command discovery").
- At a terminal, section headings are bold and command and flag names are
  highlighted, and descriptions stay plain (#4578). Help is plain when piped,
  under `NO_COLOR` and with `TERM=dumb`.
- A command's help reads in this order: a one-line summary, examples for an
  everyday command (`setup`, `login`, `create`, `run`, `shell`, `ls`), the
  command's own options grouped under headings by purpose, then the global
  options last, under their own heading. Advanced flags such as `--member` stay
  out of the default help.
- Every argument has a description. The environment argument is `ENV` in every
  command.
- One machine-output flag: `--output json|text`, with `-o` on every command
  that has it. Where `--json` remains (`cw upgrade`, `cw install`, `cw member
  up`), it moves to `--output json` and stays a hidden alias for one release.

## Results and next steps

- A lifecycle command prints one outcome line (`✓ Environment app created ·
  local VM`), the size line, the credential, secret and network lines, then
  one `→` line with the most useful next command.
- Sizes and times have one vocabulary everywhere, `info` included: `2 vCPU ·
  4 GiB RAM · 20 GiB disk`, and local or relative times. Text output never
  shows millicores, `8192MB`, raw RFC 3339 times or user IDs.
- Progress names stages the user understands (`Pulling the image`, `Starting
  the VM`). Server-side events and state names (`state transition creating ->
  running`) never appear.
- Internals (plan hashes, generations, backend names, full digests) appear
  only with `-v` or in JSON. In text, a digest or ID is shortened to 12
  characters.
- A step that takes more than a few seconds says what it is waiting for, and
  keeps its elapsed time on the active row.

## Errors

- An error says what failed in the user's terms, then a `→` line with the one
  command or flag that helps. The top-level printer owns the shape: `✗` (red
  at a terminal), the outermost message in sentence case, the next step the
  error carries, and the cause chain only with `-v`. Commands return messages
  as lowercase fragments that compose into the chain, and never print `✗`
  themselves. Until #4609 lands, `main` prints `{err:#}`, the chain joined
  with ": ", and this shape is the target.
- Parser errors from unknown commands and flags take the same shape, and
  suggest the nearest command (`did you mean ls?`, #4604).
- Name the flag or input the user gave, not every flag that could be wrong.
- No internal call names, raw request URLs or library error chains
  (`discover OAuth device flow: error sending request for url …`). Say what to
  check, naming the server. The chain goes under `-v`.
- Offer a retry only for a failure that a retry can fix. "Not signed in" is not
  one of them.
- A network step says where it connects before it waits, and fails with a
  timeout the user can read, within the step's bound. It is never silent.

## Empty and first-run states

- An expected state is not an error. Signed out, no organization yet, and
  nothing to list are plain messages with a `→` next step, and a read such as
  `ls`, `cost` or `org list` exits 0 for them. A command exits non-zero only
  when it could not do what was asked.
- The same state has the same words everywhere: `Not signed in` → `cw login`;
  `You're not in an organization yet` → `cw org create NAME` or `cw org
  invitations`.
- Every empty list says it is empty and offers the command that fills it. No
  command prints nothing.

## Prompts and pickers

- Ask only at an interactive terminal, never under `--output json` or `--yes`.
  A command that needs an answer it cannot ask for fails at once and names the
  flag that gives it.
- A picker offers only choices that can succeed now. With one possible choice,
  take it and say so.
- A list never asks where to store something: it lists every store, or says
  which one it read.
- A destructive command (`rm`, `nuke`, `prune`, …) confirms at a terminal with
  the resolved target and its location, unless `--yes`. Without a terminal and
  without `--yes` it fails at once and names `--yes`. That changes scripted
  use, so such a change ships with a release note (#4595). Help never promises
  a prompt that the command does not show.
- An unasked notice, such as the update notice (#4534), is one stderr line,
  only at a terminal, at most once a day, never under JSON, a pipe or CI, and
  it says how to turn it off.
- A prompt for a secret says in plain words what to paste and, for a known
  provider, where to get it ("Paste your Anthropic API key (from
  console.anthropic.com/settings/keys)"). The input stays hidden. Internal
  words such as "material", "slot" and "projection" never appear in a prompt
  or a message; say "key", "token", "value" or "provider" (#4715).
- A wait for the user, such as device sign-in, shows what it is waiting for, the
  code in bold, a URL that already carries the code where the server supports
  it, and how to cancel. It never says it is opening a browser when it cannot.

## Tables

- Column widths come from the content and fit the terminal. A long value never
  pushes the next column out of line. Long references such as image digests
  are shortened in the middle.
- A footnote that explains a column appears only when that column shows a value
  it explains.

## Words

- Product terms come from `docs/GLOSSARY.md`. Commands in messages are in
  backticks (`cw login`), never single quotes. Messages are sentences, and
  hints are commands. Use `…`, not `...`.

## Checking a change

- Run each changed command at a terminal, piped, with `NO_COLOR=1` and with
  `TERM=dumb`. Compare all four, and check the piped and JSON forms are plain.
- Walk the states it touches as a new user: signed out, signed in with no
  organization, with an organization, and an empty list. Use a throwaway
  `HOME`, never the owner's.
- The renderer's pty tests (`output/pty_tests.rs`) and the command's own tests
  cover the shape. A new message shape gets a test that asserts its text and
  that piped output has no escapes.
