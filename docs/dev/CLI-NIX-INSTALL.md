# Installing cw with Nix

The repository's `flake.nix` installs the released `cw` and nothing else
(#5399; owner, 2026-11-18: "i think just for the cw install"). It is not a
development shell and does not build Codewire from source. It packages the
same bytes `install.sh` installs, fetched by digest from `releases.codewire.sh`.

```sh
nix run github:codewiresh/codewire -- version
nix profile install github:codewiresh/codewire
```

## Outputs

For `x86_64-linux`, `aarch64-linux`, `x86_64-darwin` and `aarch64-darwin`:

| Output | What |
| --- | --- |
| `packages.<system>.cw` | The released `cw` for that system, as `bin/cw` |
| `packages.<system>.default` | The same package |
| `apps.<system>.cw`, `apps.<system>.default` | Runs `bin/cw` |

The package's `meta.mainProgram` is `cw`. No other output is offered.

## Where the bytes come from

`nix/release.json` names one release and the executable for each system:

```json
{
  "schema": "codewire.cw.nix/v1",
  "release_tag": "v0.4.24",
  "targets": {
    "x86_64-linux":   { "target": "x86_64-unknown-linux-musl", "sha256": "<64 hex>", "size": 119890384 },
    "aarch64-linux":  { "target": "aarch64-unknown-linux-gnu", "sha256": "<64 hex>", "size": 107037432 },
    "x86_64-darwin":  { "target": "x86_64-apple-darwin",       "sha256": "<64 hex>", "size": 101742928 },
    "aarch64-darwin": { "target": "aarch64-apple-darwin",      "sha256": "<64 hex>", "size": 92595456 }
  }
}
```

Each value is copied from the signed release record
(`cw/v1/releases/<tag>/release.json`, whose `SHA256SUMS` is signed by the
release key): `sha256` and `size` are that target's `executable`. The flake
fetches `https://releases.codewire.sh/cw/v1/blobs/sha256/<sha256>` as a
fixed-output download, so Nix refuses any other bytes. The flake holds no
version or hash of its own. Beside the pin, `nix/SHA256SUMS` and
`nix/SHA256SUMS.asc` are that release's signed checksums, byte for byte, so
the pin can be proved without the network ("The pin's proof"). These three
files are the only ones a release changes.

`flake.lock` pins nixpkgs, which the flake uses only for `stdenv`, `patchelf`
and glibc. Moving it is an ordinary reviewed change. A configuration that
already has nixpkgs can pass `inputs.nixpkgs.follows`.

## The package

- **macOS, both architectures.** The executable is copied to `bin/cw`
  unchanged. Fixup is off (no strip, no patch), because any change breaks its
  Developer ID signature. The installed file's SHA-256 equals the release's.
- **Linux x86_64.** The release is a static musl executable and runs on NixOS
  as it is. Copied unchanged, fixup off, the same digest as the release.
- **Linux arm64.** The release is `aarch64-unknown-linux-gnu`, linked to glibc
  alone (`libc`, `libm`, `libpthread`, `libdl`, `libutil`, `ld-linux`), with
  `/lib/ld-linux-aarch64.so.1` as its interpreter, which NixOS doesn't have.
  The package sets the interpreter and run path to nixpkgs' glibc with
  `patchelf` and changes nothing else. Its bytes therefore differ from the
  release's; the fixed-output download still proves the input. It is not
  rebuilt for musl: that would change the release target, and `cw upgrade`
  refuses a release for another target, so every arm64 Linux install from
  `install.sh` would stop updating.

`cw version` prints the release's version from the build record compiled
into it, on every system.

State never goes into the Nix store. The local VM runtime that `cw` unpacks
at first use, its credentials and its configuration go where they go for any
`cw`, in the user's state and data directories.

## Updating

A Nix-installed `cw` can't replace itself. `cw upgrade` and
`cw upgrade rollback` refuse when the running `cw` is under `/nix/store/` and
is not a managed version, before any store, entry or selection change:

```text
this cw (/nix/store/…-cw-0.4.24/bin/cw) is installed by Nix and can't replace itself.
Update it with Nix: `nix profile upgrade codewire` for a profile install, or update
the flake input that names github:codewiresh/codewire in your NixOS or Home Manager
configuration. Local VMs left on an older cw restart with `cw upgrade --vms`.
```

The profile element name (`codewire`) is the one Nix gives
`github:codewiresh/codewire`; the journey's `nix-upgrade-refusal` step
confirms it before the message ships. `cw upgrade --vms` still restarts local
VMs left on an older `cw`. The daily
update notice names the Nix command instead of `cw upgrade`. An explicit
`--store` is unaffected.

Today, without this refusal, a Nix `cw` with no managed store refuses and
points at `install.sh`, and one beside a managed store left by an earlier
`install.sh` selects a new managed `cw` in `~/.local/bin`, which then shadows
or is shadowed by the Nix one depending on `PATH`.

## How a release moves the flake

`codewire-release-pin-bot` and its OpenBao roles `codewire-source-release-pin-propose`
and `-schedule` were provisioned on 2026-11-18 through infra's checked-in helpers
(infra#2771; the commands and results are recorded on #5399). Without the
stored token or the role the job fails closed, and a rerun of the job alone
recovers it; the flake stays on its last pin meanwhile.

After `cli-release` confirms that `cw upgrade` offers the release
(`cw_release_r2.py offered`), its last job proposes the pin
(`scripts/ci/release/propose-nix-release-pin.sh`; decision on #5399,
cw-orchestrator, 2026-11-18):

1. It reads the public stable channel and the release it names, verifies
   `SHA256SUMS.asc` with the release key, and refuses unless the channel names
   this run's tag.
2. It writes `nix/release.json` from that record, and refuses unless every
   `sha256` appears in the signed `SHA256SUMS` for that target's asset. It
   writes that `SHA256SUMS` and `SHA256SUMS.asc` beside it, and the proposal
   refuses any other changed file.
3. It pushes the one branch `automation/nix-release-pin` and opens or updates
   its pull request as `codewire-release-pin-bot`, in the same way
   `propose-workspace-image-pin.sh` does. The bot can push that branch and open
   the pull request, not merge it. Its token has its own OpenBao path, readable
   only through a role bound to this one job on protected main, and never
   appears in arguments or output. A dedicated bot, not the workspace-pin bot,
   keeps its blast radius, revocation and authorship separate (cw-security,
   2026-11-18, on #5399); creating it needs the owner's yes.
4. The pull request body is the step's own recomputation: for each system, the
   asset, the hash in the signed `SHA256SUMS`, the hash written, and
   `exact match`.

cw-review approves it as routine and it lands through the merge queue. A
newer release rewrites the same branch, and the Supply-chain scan refuses an
older pin than main's, so the flake never moves backwards.
The flake therefore trails the release by that review. Approving it with a
verifier instead of a person would widen what lands on main without a review,
and waits for the owner.

## The pin's proof

Any pull request that changes `nix/` must carry a pin the release key signed,
whoever pushed it: either bot's token, or a person. The branch can't be
protected so that only the release-pin bot may push it, because Forgejo 17
refuses every force push to a protected branch and has no force-push
allowlist. So the required Supply-chain scan proves the pin instead
(cw-security, 2026-11-18, on #5399).

`source-approval.yml` runs on `pull_request_target`, from the protected base.
Its step "Prove the Nix pin against the signed release" runs the base's
`nix_release_pin.py verify` over the candidate checked out as data; none of
the candidate's code runs. Offline, with the base's release key
(`apps/cli/GPG_PUBLIC_KEY.asc`) and fingerprint (`cw_release.py`), it refuses:

- `nix/SHA256SUMS` whose `nix/SHA256SUMS.asc` isn't a valid signature by that
  key;
- a pinned `sha256` that isn't the one the signed `SHA256SUMS` lists for
  `cw-<release_tag>-<target>`, and a pin of anything but the four systems and
  their targets, in the rendered layout;
- a `release_tag` older than the base's pin;
- a candidate that changes `nix/` together with the release key or
  fingerprint. Changing the key needs cw-security, in a pull request of its
  own.

A candidate whose `nix/` and key are byte for byte the base's is not checked,
so the step never holds an unrelated pull request. cw-review's approval of the
exact head and the GitHub check after merge are the second and third gates.

## The check

`.github/workflows/nix-flake.yml` runs on GitHub, on the public mirror's main,
when `flake.nix`, `flake.lock`, `nix/**` or the workflow itself changes, and on
dispatch. It runs where Nix users install from, so Codewire's own runners need
no Nix image and no new egress (cw-orchestrator, 2026-11-18, on #5399). The
mirror carries only main, so the check follows a merge; before it, the pin's
pull request carries the release step's recomputation for review. It:

- evaluates every system's package (`nix flake check --all-systems`);
- on GitHub-hosted Linux x86_64 and macOS arm64, installs `cw` from the flake,
  runs `cw version`, which must print the pinned `release_tag`, and compares
  the installed file's SHA-256 with the pin; on macOS it also verifies the
  signature with `codesign --verify --strict`;
- recomputes the pin from the signed release with `nix_release_pin.py check
  --blobs`, which also downloads each of the four executables and compares
  its SHA-256 and size.

Nix runs with `accept-flake-config = false`, `sandbox = true`,
`require-sigs = true`, only the default cache and its key, and the runner's
user not trusted, so a flake can't widen what Nix trusts (cw-security,
2026-11-18, on #5399). Nix comes from its own installer at one release
(`releases.nixos.org/nix/nix-<version>/install`), which runs only if its
SHA-256 is the pinned one. The installer then checks its tarball's SHA-256.
It is a daemon install, so only root is a trusted Nix user. The workflow uses
no action but `actions/checkout`. The jobs only read the repository and hold
no secret.
