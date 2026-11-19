# Installing cw with Nix

People who manage their tools with Nix install `cw` from the repository's
flake: `nix run` and `nix profile install`, and every release moves it
(#5399; owner, 2026-11-18). The design is
[CLI-NIX-INSTALL.md](../dev/CLI-NIX-INSTALL.md); what users are told is the
docs' install page ("Install with Nix"). The format is in
[README.md](README.md).

## Where the journey stands

Updated 2026-11-18. Written first; every step is not yet observed.

| ID | x86_64-linux (NixOS) | aarch64-linux | aarch64-darwin | x86_64-darwin |
| --- | --- | --- | --- | --- |
| `nix-run` | not yet observed | not yet observed | not yet observed | not yet observed |
| `nix-profile` | not yet observed | not yet observed | not yet observed | not yet observed |
| `nix-bytes` | not yet observed | not yet observed | not yet observed | not yet observed |
| `nix-local-vm` | not applicable | not applicable | not yet observed | not applicable |
| `nix-upgrade-refusal` | not yet observed | not yet observed | not yet observed | not yet observed |
| `nix-release-moves` | not yet observed | not applicable | not applicable | not applicable |
| `nix-check-refuses` | not yet observed (CI) | not applicable | not applicable | not applicable |

The done-when needs `x86_64-linux` on NixOS and `aarch64-darwin`. The other two
are walked when a machine is at hand, and say so until then.

## Before the walk

- A clean machine: Nix with flakes on (`experimental-features = nix-command
  flakes`), no `cw` on `PATH`, no `~/.local/share/codewire` and no
  `~/.nix-profile/bin/cw`. A fresh NixOS VM, and a Mac user account that has
  never run `cw`, are clean.
- Record `nix --version` and the current stable release:
  `curl -fsSL https://releases.codewire.sh/cw/v1/channels/stable.json | jq -r .pointer.release_tag`.
- Nix caches a `github:` flake for an hour. After a release, add `--refresh`
  to see the newest one.

## `nix-run`: run cw without installing it

- **Do:** `nix run github:codewiresh/codewire -- version`.
- **See:** the stable version recorded above, and nothing installed:
  `command -v cw` finds nothing afterwards.

## `nix-profile`: install it

- **Do:** `nix profile install github:codewiresh/codewire`, then a new shell,
  `command -v cw` and `cw version`.
- **See:** `cw` resolves to `~/.nix-profile/bin/cw` (or the profile's
  equivalent) and prints the stable version. `nix profile list` shows one
  element for it; record its name, which the refusal in
  `nix-upgrade-refusal` must name.

## `nix-bytes`: the installed cw is the released cw

- **Do:** `sha256sum "$(readlink -f "$(command -v cw)")"` (`shasum -a 256` on a
  Mac), and compare with `nix/release.json` at the flake's revision.
- **See:**
  - **macOS and x86_64-linux:** the same SHA-256 as the release. On a Mac,
    `codesign --verify --strict --verbose=2` on that file says it is valid
    on disk and satisfies its Designated Requirement.
  - **aarch64-linux:** a different SHA-256, because only the interpreter is
    patched; `readelf -l` names an interpreter under `/nix/store/`, and
    `cw version` runs.

## `nix-local-vm`: a local VM from a Nix cw on a Mac

- **Do:** with the Nix `cw` first on `PATH`, `cw setup --local`, then
  `cw create --local nix-walk`, `cw exec nix-walk -- uname -a`, `cw stop nix-walk`,
  `cw start nix-walk`, and `cw rm nix-walk`.
- **See:** each step succeeds as in [local-vm-mac.md](local-vm-mac.md). The
  runtime it unpacked is under the user's Codewire data directory, and nothing
  was written under `/nix/store`. `cw setup ssh` writes a config that names the
  profile link, not a `/nix/store` path, so it still works after the profile
  moves.
- **Then:** `nix profile upgrade` to a newer release (or roll the profile back
  and forward), `nix-collect-garbage`, and `cw start nix-walk` again. It
  starts, because nothing kept the old store path.

## `nix-upgrade-refusal`: cw upgrade defers to Nix

- **Do:** with the Nix `cw`, run `cw upgrade --cli`, `cw upgrade`, and
  `cw upgrade rollback`. Then create a managed store as an earlier
  `install.sh` would (`curl -fsSL https://get.codewire.sh | sh`), put the
  Nix `cw` first on `PATH` again, and repeat.
- **See:** each one refuses with the message in CLI-NIX-INSTALL.md
  ("Updating"), naming the element name recorded in `nix-profile`, and exits
  non-zero. Nothing changes: `~/.local/bin/cw` and
  `~/.local/share/codewire/cli/selection.json` are byte-for-byte as before,
  or still absent. `cw upgrade --vms` still runs. The daily update notice
  names the Nix command.

## `nix-release-moves`: a release moves the flake

- **Do:** after the next release's `cli-release` succeeds, find the
  `automation/nix-release-pin` pull request.
- **See:** it changes only `nix/release.json`, and its body lists the four
  systems with the signed `SHA256SUMS` hash, the hash written and
  `exact match`. Its Nix check is green. After it lands,
  `nix run --refresh github:codewiresh/codewire -- version` prints the new
  release, and nobody edited the file by hand.

## `nix-check-refuses`: a wrong hash fails the check

- **Do:** on a throwaway pull request, change one `sha256` in
  `nix/release.json` by one digit.
- **See:** the Nix check fails and names that system and both hashes. Close
  the pull request.
