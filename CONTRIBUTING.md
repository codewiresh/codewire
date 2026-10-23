# Contributing

Codewire is not accepting issues or pull requests yet. This guide describes
how the project is built and tested, and the terms that will apply once
contributions open (see [License](#license)). The
[code of conduct](CODE_OF_CONDUCT.md) applies to every project space.
[SPEC.md](SPEC.md) describes the system; [docs/README.md](docs/README.md)
maps the rest of the documentation.

## Build, test, run

The Rust build needs a Rust toolchain (`rustup`) and `protoc`, the Protocol
Buffers compiler, on `PATH`; set `PROTOC` to its path otherwise:

```bash
sudo apt-get install protobuf-compiler   # Debian/Ubuntu
sudo pacman -S protobuf                  # Arch
brew install protobuf                    # macOS
```

`docs/dev/LOCAL-DEV.md` lists the rest of the tooling for the control plane and
dashboard.

Build and install the CLI from your checkout:

```bash
make cli-install                              # managed install behind ~/.local/bin/cw
cargo build -p codewire-cli-bin --bin cw      # unmanaged development binary
```

Run the Rust checks for the crates you touch:

```bash
cargo fmt --all
cargo clippy -p <crate> --all-targets
cargo test -p <crate>
```

For the control plane and dashboard, `docs/dev/LOCAL-DEV.md` describes the
local loop: Postgres from Docker Compose (`make dev`, `make db-init`), the
dashboard dev server (`make web`), focused Rust service binaries, and the
local Kind cluster (`make kind-up`, then `make kind-deploy SERVICE=...` and
`make kind-test`). `docs/TESTING.md` covers the dashboard browser suite.

Run the bounded Go/Tailscale support tests when changing those surfaces:

```bash
(cd libs/tailnet && GOWORK=off go test -short ./...)
(cd tests/contract && GOWORK=off go test ./...)
```

Useful repo-level checks:

```bash
bun run build
bun run typecheck
bun run rust:check
make proto-drift-check
make test-sdk
```

## Pre-push gate

CI selects the smallest product-verification families that cover the changed
paths. Run the same selector locally before pushing:

```bash
bun run preflight
```

Install the `pre-push` hook so pushes are checked for their exact tree:

```bash
bun run hooks:install
```

The installer copies the tracked `.githooks/pre-push` dispatcher into the
repository's common Git directory and sets that stable directory as
`core.hooksPath`. The dispatcher survives deletion of the worktree that ran
the installer and runs `scripts/dev/pre-push.sh` from the worktree that
invoked `git push`.
Re-run `bun run hooks:install` after pulling a dispatcher change.

Every branch push runs the fast push check: the environment precheck,
formatting, clippy and unit tests for the changed crates, and quick checks for
changed file types. Run it yourself with `scripts/dev/preflight.sh --for-push`.

Pull-request CI is the merge gate: a pull request merges when its required
statuses are green on its exact head. To run the families a change selects
locally first:

```bash
scripts/dev/preflight.sh --all
```

It runs the selected families (compile first, then parallel lanes) and never
Kind, and it records nothing. `main` takes changes only through pull requests.
Push one ref at a time.

`PREFLIGHT_CHANGED_FILES` is an explicit diagnostic/CI interface for
reproducing path selection. Set it to a file containing one repository-relative
path per line, or to `-` to read the list from stdin. Ordinary local pushes
must leave it unset so the hook derives paths from the invoking worktree.
Supplying an empty list does not bypass verification: empty or unknown
comparisons continue to select the full preflight.

## Backend runtime work is Rust

The product runtime is Rust: the services in `crates/`, the daemon, the
`cw` CLI and the local VM runtime. A new backend service is a new binary
owning a new bounded context, written on top of `codewire-server-core`, which
provides the HTTP scaffold, error envelope, auth middleware, tracing, and
DB/NATS helpers every service shares. Start with `crates/README.md`.

Go is limited to the SDK and generated-client modules under `libs/`, the
Tailscale-client interoperability suite and the contract tests under
`tests/contract`. Do not add a Go product runtime path.

`docs/ARCHITECTURE.md` describes the current system; `docs/README.md` indexes
the rest of the documentation.

## Docs and plans

Shipped behaviour is documented under `docs/`. Design plans and proposals
live in the maintainers' private design repository; a pull request that
changes behaviour updates the public docs for the surface it changes.

## Pull requests

The project does not take pull requests yet. The canonical repository is the
maintainers' Forgejo instance, which mirrors to GitHub; a maintainer reviews
and lands each change against `main`, and `main` accepts no direct pushes.

Expectations for a change:

- the selected verification families pass
- relevant builds still pass for the changed area
- commits use conventional commit style such as `feat:`, `fix:`, or `chore:`
- no attribution or co-author trailers

Maintainer-only workflow (Forgejo tooling, the retained Kind cluster,
delivery and release steps) is described in `AGENTS.md` and
`docs/dev/AGENT-WORKFLOW.md`.

## License

Once the project accepts contributions, each contribution is licensed under the
license of the part it changes: AGPL-3.0-only for the application, and MIT for
the SDK packages. A few packages carry another license: `crates/README.md`
lists each crate's license, and every package directory carries its license
text.
