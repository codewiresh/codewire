# Installing cw with Homebrew

The tap `codewiresh/homebrew-codewire` installs the released `cw` with
Homebrew on macOS and Linux (#5407; owner, 2026-11-19: "lets add `brew trust
codewiresh/codewire` / `brew install codewiresh/codewire/codewire` to the
docs, and then automate this"). It packages the same bytes `install.sh`
installs, fetched by digest from `releases.codewire.sh`. The tap stays its
own repository (owner, 2026-11-19).

```sh
brew trust codewiresh/codewire
brew install codewiresh/codewire/codewire
```

Homebrew 7 loads formulae only from official taps and taps the user trusts;
`brew trust` records the tap in `~/.homebrew/trust.json` (or under
`$XDG_CONFIG_HOME/homebrew/`). It is needed once per user.

## The formula

The tap holds one formula, `Formula/codewire.rb`, for the four release
targets:

| Homebrew platform | Release target |
| --- | --- |
| macOS, Apple silicon | `aarch64-apple-darwin` |
| macOS, Intel | `x86_64-apple-darwin` |
| Linux, arm64 | `aarch64-unknown-linux-gnu` |
| Linux, x86_64 | `x86_64-unknown-linux-musl` |

Each platform's `url` is `https://releases.codewire.sh/cw/v1/blobs/sha256/<digest>`
and its `sha256` is the same digest, which is that target's entry in the
release's signed `SHA256SUMS`. Homebrew refuses a download whose SHA-256
differs. The formula installs the download as `bin/cw` unchanged, writes
`cw completion`'s bash, zsh and fish scripts, and its test runs
`cw --version`, which must print the formula's version. It has no
dependencies.

On a Linux whose glibc is older than Homebrew's floor, Homebrew installs its
own `glibc` and `gcc` before any formula it does not pour from a bottle,
`codewire` included: about 700 MB in the `homebrew/brew` image, which is based
on Ubuntu 22.04 (2026-11-19). `cw` needs neither, and `brew uninstall
codewire` removes them again. `install.sh` installs nothing beside `cw`.

## Updating

A Homebrew `cw` is updated by Homebrew: `brew upgrade codewire`.

Today `cw upgrade` on a Homebrew `cw` with no managed store refuses and points
at `install.sh` (observed 2026-11-19 on Linux: "This cw
(…/Cellar/codewire/0.4.24/bin/cw) is not a managed installation …"). Beside a managed store left by an earlier `install.sh`, it
would select a managed `cw` in `~/.local/bin` that shadows, or is shadowed by,
the Homebrew one, depending on `PATH`.

Target, not shipped (#2916): `cw upgrade` and `cw upgrade rollback` refuse
before any store, entry or selection change when the running `cw`, resolved
through links, is inside a Homebrew Cellar (`…/Cellar/codewire/<version>/bin/cw`)
and is not a managed version. The refusal names `brew upgrade codewire`, as
the Nix refusal names Nix's command ([CLI-NIX-INSTALL.md](CLI-NIX-INSTALL.md),
"Updating"). The daily update notice names it too.

## How a release moves the tap

Target, not shipped (#5407; the GitHub App route, owner via the orchestrator,
2026-11-19).

The tap updates itself; a release only asks it to. After `cli-release`
confirms that `cw upgrade` offers the release (`cw_release_r2.py offered`),
its last job mints a GitHub App installation token and dispatches the tap's
`update-formula.yml` with the release tag. The tap's workflow then, on
GitHub's runners with the tap's own `GITHUB_TOKEN` (`contents: write`):

1. Downloads the release's `SHA256SUMS` and `SHA256SUMS.asc` from
   `releases.codewire.sh`, verifies the signature with the release key
   committed in the tap and pinned by its fingerprint in the workflow, and
   refuses unless the stable channel names the dispatched tag.
2. Renders `Formula/codewire.rb` with the version and each target's digest
   from the signed `SHA256SUMS`, and refuses a version older than the one on
   the tap's `main`, so the formula never moves backwards. A tap already on
   this version changes nothing.
3. Runs `brew audit --strict --online`, `brew install` and `brew test` of the
   rendered formula on `ubuntu-24.04` and `macos-15`, with the tap trusted.
4. Only when all of them pass, pushes one commit to the tap's `main` that
   changes only `Formula/codewire.rb`, with the subject `codewire <version>`.

The release job waits for that run's conclusion and reports it. A failure
anywhere leaves the release published and the stable channel moved: the job
fails, and its summary says the tap is behind and names the version. The next
release, or a dispatch of the tap's workflow for this tag, moves it. Rolling a
bad formula back is a revert commit on the tap.

The same workflow runs `brew audit`, `brew install` and `brew test` on every
push and pull request to the tap, without committing. Its actions are pinned
by commit. It changes only by a person's commit to the tap: the App can't
write to the repository.

## The credential

A dedicated GitHub App, owned by the `codewiresh` organization and installed
only on `codewiresh/homebrew-codewire`, with the repository permission
Actions: read and write and nothing else, and no webhook. It can start and
read the tap's workflow runs, and can't push, open pull requests or change a
workflow. It is separate from the mirror's App, so each can be revoked alone
(#5407).

Its App ID, installation ID and private key live in OpenBao, written there by
the owner by hand; no agent reads them. One OpenBao role pair, bound by
Forgejo OIDC to `cli-release.yaml` on protected `main`, can read them. The job
mints, in memory, one installation token, which carries only the App's
Actions permission on the tap and which GitHub expires within an hour; neither the key
nor the token appears in arguments, output or a file another step can read.
The minter is the mirror's (`scripts/ci/release/mint-github-app-token.sh`).

The tap's `update-formula.yml` is the workflow above, and it holds no stored
credential: it commits with its own `GITHUB_TOKEN`. A by-hand dispatch moved
the tap to v0.4.25 with it (2026-11-20, run 44776138549). The personal token
its earlier version read (`HOMEBREW_TAP_TOKEN`) is referenced nowhere, and the
owner removed it; the tap holds no repository secret (2026-11-20, #5407).
