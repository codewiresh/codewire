# Durable terminal history retention

The environment daemon keeps a bounded recent transcript, not a permanent log.
Trimming output does not stop or restart the shell, change its session identity,
or renumber byte offsets.

## Limits

- Each session compacts after its retained output exceeds 8 MiB or 4,096 capture
  frames. It keeps the newest 4 MiB (plus at most one 32 KiB capture frame),
  limited to 2,048 frames. This also bounds the in-memory output index for tiny
  writes. Atomic compaction temporarily needs space for the replacement file.
- New session admission allows at most 128 records. The oldest confirmed-ended
  records are retired to make room. Live sessions, interrupted sessions, and
  failures with unconfirmed process cleanup are never deleted automatically.
  A failure before any process was spawned is eligible for retirement.
- Startup compacts inherited transcripts and prunes excess confirmed-ended
  records. An older store with more than 128 unresolved records is preserved;
  new admission is refused until safe room exists. This exception preserves
  recovery obligations rather than claiming an unconditional migration quota.
- Retirement renames the record before deleting its files. Startup and every
  admission retry unfinished retired-directory cleanup; cleanup failure blocks
  admission so hidden transcripts cannot accumulate behind the inventory limit.

## Browser tabs and names

The dashboard opens at most eight terminal tabs. Rename changes only the display
name, not the shell, session identity, or connection. Names are limited to 64
characters without control characters and are saved in this browser tab's
session storage, alongside session IDs and the active selection. They are not
shared between browsers; do not put secrets in names.

Metadata is scoped to the authenticated account, organization, and environment.
Restoration uses fresh authorized session inventory. Revalidation hides labels
and clears an open rename editor; an account change or authorization failure
clears terminal references. Closing or removing a tab removes its saved label.
Browser storage never receives transcripts, commands, credentials, or replay
cursors. Existing records without names remain supported.

## Cursor gaps and clients

Session records expose `output_start_offset` and `output_end_offset` as absolute
byte cursors. A unary read must explicitly set `allow_history_gap` to accept
partial history. Reading before the retained start without opting in fails with
`FailedPrecondition` and the retained cursor; older clients therefore fail
visibly. Opted-in reads return `history_gap`, the `retained_start_offset`, and
output beginning at that cursor. An Attach stream
sends its `history_gap` event **before** any resumed output. A cursor beyond the
output end remains invalid; retention does not turn it into a successful read.

Clients must show that older output is unavailable and advance to the retained
cursor before rendering replay. The CLI reports the gap on stderr, never as
shell output. Browser integration must use the same gap contract and must not
store transcripts in browser storage.

The public and daemon contracts, generated clients, bridge, and CLI ship
together. A peer predating the gap event cannot provide complete-history
semantics: an old bridge rejects the unknown Attach frame rather than silently
claiming successful replay. Matching client/bridge/workspace builds are required
for gap-aware replay. Unary clients predating the opt-in flag cannot silently
accept partial replay because the default remains false.

## Crash and concurrency behavior

Compaction retains complete contiguous frames and their absolute cursors. It
syncs the replacement file, atomically renames it, publishes its matching index,
syncs the directory, and persists the new start cursor. Recovery reads the first
frame's cursor when an output rename outlives the metadata update. Readers open
the file while holding the metadata lock, pinning the inode matching their index
so a concurrent rename cannot reinterpret old physical offsets.

Launch and Restart share an admission lock with pruning. A Restart waiting for
pruning rechecks the record after acquiring that lock and cannot resurrect a
retired session. Process output and live-session identity remain separate from
history retention.
