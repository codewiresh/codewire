# Contributing

## DCO

This repository uses the Developer Certificate of Origin instead of a CLA. Sign off every commit with `git commit -s` so each commit includes a `Signed-off-by:` line.

By contributing, you certify the DCO and agree that your contribution is licensed under the repository's AGPL-3.0 license.

## Build, Test, Run

Apply pending application migrations through SQLx:

```bash
make db-init
```

Run the local Rust control plane in KIND:

```bash
make up
make e2e-kind
```

For focused Rust service work, run the service binary directly; examples live
in `docs/dev/LOCAL-DEV.md`.

Run the bounded Go/Tailscale support tests when changing those surfaces:

```bash
(cd libs/tailnet && GOWORK=off go test -short ./...)
(cd tests/contract && GOWORK=off go test ./...)
```

Useful repo-level checks:

```bash
bun run build
bun run rust:check
bun run types:generate
cw env --local create --backend lima --name codewire-dev
```

## Pre-push gate

CI selects the smallest product-verification families that cover the changed
paths. Run the same selector locally before pushing:

```bash
bun run preflight
```

Install a `pre-push` hook so this runs automatically — pushes fail fast if the local tree wouldn't pass CI:

```bash
bun run hooks:install
```

The hook lives at `.githooks/pre-push` and is set via an absolute
`core.hooksPath`. Linked worktrees can share that physical hook; it resolves
and runs `scripts/dev/preflight.sh` from the worktree that invoked `git push`.
Bypass with `git push --no-verify` only when you know what you're doing.

`PREFLIGHT_CHANGED_FILES` is an explicit diagnostic/CI interface for
reproducing path selection. Set it to a file containing one repository-relative
path per line, or to `-` to read the list from stdin. Ordinary local pushes
must leave it unset so the hook derives paths from the invoking worktree.
Supplying an empty list does not bypass verification: empty or unknown
comparisons continue to select the full preflight.

## Backend runtime work is Rust

The backend service policy is:

> **A new backend service is a new binary owning a new bounded context (a new
> deployment unit, e.g. `codewire-billing`). New services are written in Rust on
> top of `codewire-server-core`.**

That policy is now broader for product/runtime work:

- New product services, runtime binaries, API ownership, CLI runtime behavior,
  gateway, daemon, mesh, and orchestration work belongs in Rust.
- Remaining Go is limited to SDK/client surfaces, generated clients, real
  Tailscale-client interoperability, and the bounded Tailnet oracle.
- Do not add a new Go product runtime path without first updating the Gitea
  migration issues and `docs/dev/GO-RUST-RETIREMENT-LEDGER.md`.

For *new* services start by reading `crates/README.md`; the
`codewire-server-core` crate provides the HTTP scaffold, error envelope, auth
middleware, tracing, and DB/NATS helpers every service shares.

See `docs/ARCHITECTURE.md` for the full phase plan.

## Plans And Docs

Design plans, execution reports, and restructuring notes live in `docs/plans/`. Start with the newest dated document that matches the area you are changing.

Deeper engineering documentation lives in `docs/dev/`.

## Pull Requests

`main` is protected: direct pushes are blocked, so all changes land via pull
request. Gitea (`git.example.invalid/codewire/codewire`) is the source of truth for
issues, pull requests, merges, CI, images, and deploys. GitHub is the public
mirror.

PRs should keep the build green and include any needed doc or generated-type updates for the surface they change.

Expectations:

- the selected verification families pass
- relevant builds still pass for the changed area
- commits use conventional commit style such as `feat:`, `fix:`, or `chore:`

## License

All contributions to this repository are accepted under AGPL-3.0.
