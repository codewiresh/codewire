# Installing cw with Homebrew

People who manage their tools with Homebrew install `cw` from the tap
`codewiresh/homebrew-codewire`, and every release moves it (#5407; owner,
2026-11-19). The design is [CLI-HOMEBREW-INSTALL.md](../dev/CLI-HOMEBREW-INSTALL.md);
what users are told is the docs' install page ("Install with Homebrew"). The
format is in [README.md](README.md).

## Where the journey stands

Updated 2026-11-22.

| ID | Linux x86_64 | Linux arm64 | macOS Apple silicon | macOS Intel |
| --- | --- | --- | --- | --- |
| `brew-install` | observed 2026-11-19 | not yet observed | install observed 2026-11-22 in the tap run; `PATH` not checked | not yet observed |
| `brew-bytes` | observed 2026-11-19 | not yet observed | not yet observed | not yet observed |
| `brew-test-audit` | observed 2026-11-19 | not yet observed | observed 2026-11-22 (tap run) | not yet observed |
| `brew-uninstall` | observed 2026-11-19 | not yet observed | not yet observed | not yet observed |
| `brew-local-vm` | not applicable | not applicable | not yet observed | not applicable |
| `brew-upgrade-refusal` | not yet observed | not yet observed | not yet observed | not yet observed |
| `brew-release-moves` | observed 2026-11-22 | not applicable | not applicable | not applicable |

The Linux x86_64 walk ran as `linuxbrew` in the `homebrew/brew` image after
`brew update` (Homebrew 7.0.15, Ubuntu 22.04 base), against the tap at
`e5c3fd9` (`cw` v0.4.24). macOS Apple silicon is observed in v0.4.27's tap
run 44955753810. Its `Homebrew checks (macos-15)` job, on a fresh
GitHub-hosted Apple silicon Mac, ran `brew trust codewiresh/codewire`,
`brew audit --strict --online`, `brew install` and `brew test` on
`codewiresh/codewire/codewire` at 0.4.27, and all passed. The macOS
`brew-bytes`, `brew-uninstall` and `brew-local-vm` steps aren't walked yet.
#5407's done-when needs macOS Apple silicon and Linux; the other two are
walked when a machine is at hand.

## Before the walk

- A clean machine: Homebrew 7 or newer, no `cw` on `PATH`, no
  `~/.local/share/codewire`, and the tap neither tapped nor trusted. A
  throwaway `homebrew/brew` container, after `brew update`, is clean.
- Record `brew --version` and the current stable release:
  `curl -fsSL https://releases.codewire.sh/cw/v1/channels/stable.json | jq -r .pointer.release_tag`.

## `brew-install`: install it

- **Do:** `brew trust codewiresh/codewire`, then
  `brew install codewiresh/codewire/codewire`, then a new shell,
  `command -v cw` and `cw --version`.
- **See:** `brew trust` prints `Trusted tap: codewiresh/codewire`. The install
  ends with the caveat `Get started with: cw setup`. `cw` resolves to Homebrew's
  `bin/cw`, a link into `Cellar/codewire/<version>/bin/cw`, and prints the
  stable version.
- **Observed 2026-11-19, Linux x86_64:** as above;
  Homebrew's `bin/cw` → `…/Cellar/codewire/0.4.24/bin/cw`,
  `cw v0.4.24`. Homebrew first installed its own `glibc` and `gcc` and their
  libraries, because the image's glibc is older than Homebrew's floor
  (CLI-HOMEBREW-INSTALL.md, "The formula").
- **Observed 2026-11-22, macOS Apple silicon (tap run 44955753810,
  `macos-15`):** `brew trust codewiresh/codewire` and
  `brew install codewiresh/codewire/codewire` (0.4.27) exited 0. The
  formula's `brew test` then ran the Cellar's `bin/cw --version` and matched
  `cw v0.4.27`. But the log wasn't read: GitHub serves job logs only to a
  signed-in user. So the `Trusted tap` line, the caveat and `command -v cw`
  resolving to Homebrew's `bin/cw` weren't seen.

## `brew-bytes`: the installed cw is the released cw

- **Do:** `sha256sum "$(readlink -f "$(command -v cw)")"` (`shasum -a 256` on a
  Mac), and compare with the release's `SHA256SUMS` entry for the platform's
  target. On a Mac, also `codesign --verify --strict --verbose=2` on that file.
- **See:** the same SHA-256 as the release. On a Mac the signature is valid on
  disk and satisfies its Designated Requirement.
- **Observed 2026-11-19, Linux x86_64:** `f9ee04db706c19fcc750d00842f6b9a939b73b02fec84edc891b9b0d33d15e8d`,
  v0.4.24's `x86_64-unknown-linux-musl` entry.

## `brew-test-audit`: Homebrew's own checks pass

- **Do:** `brew test codewiresh/codewire/codewire` and
  `brew audit --strict --online codewiresh/codewire/codewire`.
- **See:** both exit 0.
- **Observed 2026-11-19, Linux x86_64:** both exit 0.
- **Observed 2026-11-22, macOS Apple silicon (tap run 44955753810,
  `macos-15`):** `brew audit --strict --online` and `brew test` on
  `codewiresh/codewire/codewire` 0.4.27 both exit 0. The job's step passed.

## `brew-uninstall`: it leaves nothing behind

- **Do:** `brew uninstall codewire`, `hash -r`, `command -v cw`.
- **See:** no `cw` on `PATH` and no `Cellar/codewire`. Anything Homebrew
  installed only for it is removed too.
- **Observed 2026-11-19, Linux x86_64:** as above; Homebrew removed the
  `glibc`, `gcc` and libraries it had installed.

## `brew-local-vm`: a local VM from a Homebrew cw on a Mac

- **Do:** with the Homebrew `cw` first on `PATH`, `cw setup --local`, then
  `cw create --local brew-walk`, `cw exec brew-walk -- uname -a`,
  `cw stop brew-walk`, `cw start brew-walk` and `cw rm brew-walk`.
- **See:** each step succeeds as in [local-vm-mac.md](local-vm-mac.md), and
  nothing was written under the Homebrew prefix. Then `brew upgrade codewire`
  to a newer release and `cw start brew-walk` again: it starts.

## `brew-upgrade-refusal`: cw upgrade defers to Homebrew

Target, not shipped (#2916).

- **Do:** with the Homebrew `cw`, run `cw upgrade --cli`, `cw upgrade` and
  `cw upgrade rollback`. Then create a managed store as an earlier
  `install.sh` would, put the Homebrew `cw` first on `PATH` again, and repeat.
- **See:** each one refuses, naming `brew upgrade codewire`, and exits
  non-zero. Nothing changes: `~/.local/bin/cw` and
  `~/.local/share/codewire/cli/selection.json` are byte-for-byte as before,
  or still absent. The daily update notice names `brew upgrade codewire`.
- **Observed at the base, 2026-11-19, Linux x86_64 (v0.4.24):** `cw upgrade`
  refuses with "This cw (…/Cellar/codewire/0.4.24/bin/cw) is not a managed
  installation …; reinstall with `curl -fsSL https://codewire.sh/install.sh | sh`",
  which is the wrong advice for a Homebrew install.

## `brew-release-moves`: a release moves the tap

- **Do:** after the next release's `cli-release` succeeds, open its tap job's
  log and the tap's Actions page.
- **See:** the job dispatched the tap's `update-formula.yml` for the release's
  tag and reports its run green. That run verified the signed `SHA256SUMS`,
  ran `brew audit --strict`, `brew install` and `brew test` on Linux and
  macOS, and pushed one commit, `codewire <version>`, changing only
  `Formula/codewire.rb`. Then `brew update && brew upgrade codewire` installs
  the new release, and nobody edited the formula by hand.
- **Observed 2026-11-22 (v0.4.27):** cli-release 68982's tap job logged "the
  tap is moving to v0.4.27 in run 44955753810", then "the tap moved its
  formula to v0.4.27 in run 44955753810", and passed. In that run, the
  rendered formula was checked against the signed release. `brew audit`,
  `brew install` and `brew test` passed on `ubuntu-24.04` and `macos-15`. The
  run pushed one commit, `codewire 0.4.27` (`e88a78e530`, by
  `github-actions[bot]`), changing only `Formula/codewire.rb`. Nobody touched
  it. `brew upgrade codewire` on an existing install wasn't walked.
