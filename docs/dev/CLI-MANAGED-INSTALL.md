# Managed cw installation and updates

A managed installation lets a new `cw` become the default without replacing
the bytes or path of any running `cw` process. It is an ordinary-user
installation, not a trusted managed-helper source.

## Layout

```text
~/.local/bin/cw -> ~/.local/share/codewire/cli/versions/<sha256>/cw
~/.local/bin/.cw.cw-update.lock      shared entry coordination (0600)

~/.local/share/codewire/cli/
  store.json        managed entry and platform (0444)
  selection.json    generation, current, previous and any pending intent
  lock              advisory store lock
  versions/<sha256>/cw              executable (0555, one link)
  versions/<sha256>/identity.json   recorded identity (0444)
```

`$XDG_DATA_HOME` and `$XDG_BIN_HOME` replace the defaults when they are
absolute. The entry is a symbolic link to exactly one stored version. Because
a running cw's canonical executable path names an immutable version directory,
commands it saved keep naming the same bytes after the default changes. Every
admitted version is retained; this slice has no garbage collection.
The inventory is bounded to 1,024 versions. At that limit an existing valid
version can still be selected or reused, but a new version is refused.

## Commands

```sh
make cli-install                      # build, then `cw install --managed`
cw update status [--json]
cw update --from DIR --sha256 HEX     # pinned local release: DIR/cw + DIR/cw-runtime.json
cw update rollback [--to VERSION]     # previous, or a digest, 8+ digit prefix or package version
```

`--expect-generation N` refuses a change unless the selection generation is
still `N`. `cw update` without `--from` reports that public releases are not
available. Public fetching stays disabled until a release signing key is
admitted; a synthetic test key is never production trust.

`cw-runtime.json` is the schema-2 cw identity (`schema_version`,
`protocol_version`, `record_version`, `package_version`, `target`,
`source_revision`, `source_tree_sha256`, `rustc`, `sha256`, `size`). Its
target must be the host's release target, and its protocol and record
versions must be ones this cw understands. The explicit `--sha256` pin, the
identity and the bytes must all agree before anything is published.

## Self-install identity

`cw install --managed` derives the same schema-2 identity for itself before
any store or entry change:

- `package_version`, `target`, `rustc`, `source_revision` and
  `source_tree_sha256` come from the one build record compiled into this cw;
  `cw --version` reports that record's version.
- `sha256` and `size` come from the exact running executable
  (`/proc/self/exe` on Linux).
- That executable must contain this build record exactly once.

`make cli-install` builds through `scripts/dev/build-cw.py`, which passes the
checkout's revision and source digest explicitly. It admits the result only
when the record, the unchanged source and every compiled input agree (see
[cw release delivery](../runbooks/cw-release-delivery.md#build-record)). Set
`CODEWIRE_VERSION` to override the effective version.

Self-install refuses, before any store or entry change:

- a cw built without source provenance, such as a plain `cargo build`;
- a record for another platform's target;
- an executable that does not hold its record exactly once;
- a stored version with the same bytes that records a different identity.

The store's self-install record format is unchanged (no `payload`), so older
cw versions can still read and roll back to it. The derived identity is shown
on install and in `--json` output as `identity`.

## Guarantees and refusals

- Publication writes a private staging directory, verifies size, digest and
  executable header, and moves it into `versions/` with a no-replace rename.
  Republishing identical bytes is accepted; different bytes for a stored
  digest are refused as corruption.
- Selection holds the shared entry lock before the store lock, so different
  stores cannot select over each other. It records an intent and rechecks the
  observed entry before publication. First selection uses an atomic
  no-replace rename; later selections replace only the observed managed link.
  The next mutation resolves an interrupted selection from the entry and
  fully verifies the observed target or previous version before clearing
  intent. Missing or corrupt bytes and unknown entries preserve the intent
  and refuse recovery. Status does not recover or create a missing lock.
- An observed regular-file `cw` entry is refused, because running
  processes and saved commands may use that path. Stop them and move the file
  aside yourself, or keep the previous overwrite behavior with
  `make -C apps/cli install-user-unmanaged`.
- An entry directory must be owned by the current user, writable by that
  owner, and not writable by group or others. An unwritable directory is
  refused before candidate publication, including reinstalling into an
  existing store. A foreign entry link, an unsafe lock, a group- or
  world-writable store, or a version whose owner, mode, membership or digest
  changed is refused. Identity, executable and state admission reject special
  files and links without waiting for FIFO writers; only a Linux self-install
  may follow its own `/proc/self/exe` image link.

The owner can still modify this store directly. It is not an OS-enforced
immutable boundary, and it never admits a native managed helper; that path
keeps its separate sealed, root-owned custody.
The entry lock coordinates cooperating cw updaters. A process with the same
UID can bypass it and race direct filesystem changes after the final
observation; this store does not claim an atomic compare-and-swap against its
owner. Running daemon and helper protocols are not hot-swapped by selection.

The repository's A/B process fixture uses copies of a test executable. It
checks store selection and process retention; actual cw command acceptance
is a separate product journey.
