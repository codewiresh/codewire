---
name: codewire-rust
description: Codewire Rust structure rules that no lint can check - file and function splits, enum state, data-carrying variants, typed errors, row structs and syscall wrappers. Use for any change that adds or edits Rust under crates/, including new modules, error types, SQL queries, unsafe blocks and state handling. Do not use for dashboard templates or CSS (codewire-design) or CI changes (ci).
---

# Codewire Rust

This skill is the one home of the Rust structure rules (owner, 2026-11-11;
cited on #3013). Clippy is the gate for everything a lint can catch: the
levels are in `[workspace.lints]` in `Cargo.toml`, the thresholds in
`clippy.toml`, and `scripts/ci/verify/compile-all-targets.sh` runs them. Do
not restate a lint here. These are the rules a lint cannot see.

## The ratchet

- The rules bind new and touched code. Never make a measure worse: a file or
  function over its limit does not grow, and a banned pattern gets no new
  instance.
- When a change would break the ratchet, restructure first in its own commit
  with no behaviour change, then make the change.
- Do not refactor untouched code to meet these rules inside an unrelated
  change.
- A crate root that predates a lint carries a crate-level `#![allow]` for
  it, listed in `scripts/checks/repo_policy/workspace_lints.py` (#4125).
  Remove the allow and its entry when the root is clean. Never add one: the
  check fails it. An integration test or example may keep
  `#![allow(clippy::unwrap_used)]`.

## Size

- A file has one concern. Past 1,500 production lines it does not grow: new
  code goes in a submodule beside it.
- A function does one thing a reader can name. Past 150 lines it does not
  grow. A loop that carries more than three mutable locals between
  iterations gets a struct for them and one function per arm.
- Tests for a module over 500 lines live in a sibling `tests.rs`, declared
  with `#[cfg(test)] mod tests;`, never `include!`.

## State and invariants

- A value with a closed set of states is an enum, never a `String`. Convert
  once at the database or wire boundary and match on the enum inside; never
  write a new `state == "running"` comparison. `StoredEnvironmentState` in
  `codewire-local-vmm` is the model.
- If a match arm needs data, the variant carries it. Never write
  `.expect("X requires Y")` to recover data the type could have held.
- Parse external input once, at the edge, into a type that cannot hold an
  invalid value. Do not validate it again downstream.

## Errors

- Library and service logic returns a `thiserror` enum the caller can branch
  on. `anyhow` is for a binary's `main`, CLI command handlers and tests.
- `.expect()` only for an invariant established in the same function, with a
  message that names it.
- Never discard a fallible result with `let _ =` unless a comment on the line
  says why failure is acceptable there; otherwise handle or log it.
- A lock shared between requests recovers a poisoned guard
  (`unwrap_or_else(PoisonError::into_inner)`) when the data stays valid after
  a panic, so one panic does not fail every later caller. Never
  `lock().unwrap()` there.

## Unsafe and syscalls

- A `// SAFETY:` comment states the invariant that makes the block sound,
  not what the call does. Read the block before writing one; a block you
  cannot justify is a finding to report.
- Use `rustix` for any syscall it covers. Raw `libc` only where it does not
  (`sendmsg` control messages, the TUN ioctl), behind a small safe function
  in one module, never inline in business logic.
- A new crate starts with `#![forbid(unsafe_code)]` unless it needs unsafe.

## SQL

- A new query decodes into a named `FromRow` struct, never a positional
  tuple wider than one column.
- A query that changes with a migration has a database test in the same
  change (`docs/dev/DATABASE-MIGRATIONS.md`).

## Numbers

- No new `as` that can truncate or change sign: use `From`, `try_from` or
  the explicit `wrapping_`/`saturating_` method that says what happens on
  overflow. `as` stays for FFI types the platform fixes, with the reason on
  the line.

## Proof

Run `scripts/ci/verify/compile-all-targets.sh` and the affected crate's
tests. A split-only commit shows the same test count before and after.
