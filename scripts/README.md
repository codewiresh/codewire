# Codewire scripts

Scripts are grouped by execution boundary:

- `checks/` — source, contract, and security guards run by local preflight and
  CI.
- `ci/` — Gitea workflow entrypoints, selectors, verification runners, release,
  deploy, image, setup, and script self-tests.
- `dev/` — local developer entrypoints and local-kind helpers.
- `runtime/` — dev/prod runtime smoke, API key, confidential-computing, and
  Kata diagnostics.

No executable entrypoints live at the `scripts/` root.
Repository checks use shell, Python, or Rust-owned binaries; do not add
JavaScript script entrypoints under `scripts/`.
