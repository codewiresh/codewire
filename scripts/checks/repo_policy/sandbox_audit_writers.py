"""Only orchestration's audit module writes the Sandbox audit log.

`sandbox_audit_events` and `sandbox_audit_pending` hold what happened to each
hosted Sandbox (#6189; SPEC.md "Sandbox audit log"). Only orchestration
writes them, and events are only inserted: only the expiry function and the
organization's deletion remove one. The services run as the database's owner
(#5166), so no grant can hold that; this check does, as for the credential
revocation log. A forged or removed event would mislead every reader of the
log.

It refuses, anywhere in tracked Rust or SQL except the migrations that define
the tables and test files:
- an INSERT, UPDATE, DELETE, MERGE, TRUNCATE or COPY into either table, or a
  month's partition, outside `crates/codewire-orchestration/src/audit`;
- an UPDATE, DELETE, MERGE, TRUNCATE or COPY into the events, even there;
- a call of the flush or expiry function outside that module;
- a DROP or ALTER of either table or a partition, and a DROP of the trigger
  or its function that refuse updates, even there: each would remove events
  or unlock them.
"""

from __future__ import annotations

from .shared import *

MIGRATIONS = "crates/codewire-server-core/migrations/"
WRITER = re.compile(r"^crates/codewire-orchestration/src/audit(?:\.rs$|/)")
SOURCE = re.compile(r"\.(?:rs|sql)$")
TEST_PATH = re.compile(r"(?:^|/)tests/|(?:^|/|_)tests\.rs$")
# A Rust string continues across `\` and a newline, so a statement split over
# lines still reads as one.
CONTINUATION = re.compile(r"\\\r?\n\s*")
TABLE = r"(?:ONLY\s+)?(?:\"?public\"?\s*\.\s*)?\"?sandbox_audit_(?P<table>events|pending)(?:_\d{4}_\d{2})?\b"
WRITE = re.compile(
    r"\b(?P<verb>INSERT\s+INTO|UPDATE|DELETE\s+FROM|MERGE\s+INTO|TRUNCATE(?:\s+TABLE)?|COPY)\s+"
    + TABLE,
    re.IGNORECASE,
)
CALL = re.compile(r"\bcodewire_(?:flush|expire)_sandbox_audit\b", re.IGNORECASE)
SCHEMA = re.compile(
    r"\b(?:(?:DROP|ALTER)\s+TABLE(?:\s+IF\s+EXISTS)?\s+" + TABLE
    + r"|DROP\s+TRIGGER(?:\s+IF\s+EXISTS)?\s+\"?sandbox_audit_events_never_updated\b"
    + r"|DROP\s+FUNCTION(?:\s+IF\s+EXISTS)?\s+(?:\"?public\"?\s*\.\s*)?\"?codewire_refuse_sandbox_audit_update\b)",
    re.IGNORECASE,
)


def exempt(path: str) -> bool:
    return path.startswith(MIGRATIONS) or bool(TEST_PATH.search(path))


def writes(path: str, text: str) -> list[str]:
    if exempt(path):
        return []
    joined = CONTINUATION.sub(" ", text)
    writer = bool(WRITER.search(path))
    failures = []
    for match in WRITE.finditer(joined):
        statement = " ".join(match.group(0).split())
        removes_event = match.group("table").lower() == "events" and not match.group(
            "verb"
        ).upper().startswith("INSERT")
        if removes_event:
            failures.append(
                f"{path} changes sandbox audit events ({statement!r}); events are only "
                f"inserted, and only codewire_expire_sandbox_audit removes them (#6189)"
            )
        elif not writer:
            failures.append(
                f"{path} writes the Sandbox audit log ({statement!r}); only "
                f"crates/codewire-orchestration/src/audit may (#6189)"
            )
    if not writer:
        failures.extend(
            f"{path} calls {match.group(0)}; only crates/codewire-orchestration/src/audit may (#6189)"
            for match in CALL.finditer(joined)
        )
    failures.extend(
        f"{path} changes the Sandbox audit log's schema ({' '.join(match.group(0).split())!r}); "
        f"only its migrations may (#6189)"
        for match in SCHEMA.finditer(joined)
    )
    return failures


def self_test() -> list[str]:
    failures: list[str] = []

    def expect(condition: object, message: str) -> None:
        if not condition:
            failures.append(f"sandbox audit writers self-test: {message}")

    service = "crates/codewire-orchestration/src/api/thing.rs"
    writer = "crates/codewire-orchestration/src/audit/store.rs"
    for statement in (
        'sqlx::query("INSERT INTO sandbox_audit_events (id) VALUES ($1)")',
        'sqlx::query("insert into public.sandbox_audit_pending values (1)")',
        'sqlx::query("UPDATE sandbox_audit_pending SET count = count + 1")',
        'sqlx::query("DELETE FROM \\\n     sandbox_audit_pending WHERE id = $1")',
        'sqlx::query("INSERT INTO sandbox_audit_events_2026_11 (id) VALUES ($1)")',
        'sqlx::query("SELECT codewire_flush_sandbox_audit(now(), $1)")',
        'sqlx::query("SELECT codewire_expire_sandbox_audit($1)")',
    ):
        expect(len(writes(service, statement)) == 1, f"a write was admitted: {statement!r}")
    for statement in (
        'sqlx::query("UPDATE sandbox_audit_events SET count = 2")',
        'sqlx::query(r#"DELETE FROM ONLY "public"."sandbox_audit_events""#)',
        'sqlx::query("DELETE FROM sandbox_audit_events_2026_11")',
        'sqlx::query("TRUNCATE TABLE sandbox_audit_events")',
        'sqlx::query("MERGE INTO sandbox_audit_events AS e USING x ON true")',
    ):
        expect(len(writes(writer, statement)) == 1,
               f"the writer changed events: {statement!r}")
        expect(len(writes(service, statement)) == 1, f"a change was admitted: {statement!r}")
    for statement in (
        'sqlx::query("DROP TABLE sandbox_audit_events_2026_05")',
        'sqlx::query("DROP TABLE IF EXISTS public.sandbox_audit_pending")',
        'sqlx::query("ALTER TABLE sandbox_audit_events DETACH PARTITION sandbox_audit_events_2026_05")',
        'sqlx::query("ALTER TABLE ONLY sandbox_audit_events DISABLE TRIGGER sandbox_audit_events_never_updated")',
        'sqlx::query("DROP TRIGGER sandbox_audit_events_never_updated ON sandbox_audit_events")',
        'sqlx::query("DROP FUNCTION public.codewire_refuse_sandbox_audit_update()")',
    ):
        expect(len(writes(writer, statement)) == 1, f"a schema change was admitted: {statement!r}")
        expect(len(writes(service, statement)) == 1, f"a schema change was admitted: {statement!r}")
    expect(not writes(service, 'sqlx::query("ALTER TABLE environments ADD COLUMN x int")'),
           "another table's change was refused")
    expect(writes("deploy/sql/repair.sql", "DELETE FROM sandbox_audit_pending;"),
           "a write in tracked SQL outside the migrations was admitted")
    for allowed in (
        'sqlx::query("INSERT INTO sandbox_audit_events (id) VALUES ($1)")',
        'sqlx::query("INSERT INTO sandbox_audit_pending (id) VALUES ($1) ON CONFLICT DO UPDATE")',
        'sqlx::query("UPDATE sandbox_audit_pending SET last_at = $1")',
        'sqlx::query("SELECT codewire_flush_sandbox_audit(now(), $1)")',
    ):
        expect(not writes(writer, allowed), f"the writer was refused: {allowed!r}")
    expect(not writes("crates/codewire-orchestration/src/audit.rs",
                      'sqlx::query("INSERT INTO sandbox_audit_pending (id) VALUES ($1)")'),
           "the module root was refused")
    for allowed in (
        'sqlx::query("SELECT id, kind FROM sandbox_audit_events WHERE environment_id = $1")',
        'sqlx::query("UPDATE environments SET state = $1")',
        'sqlx::query("INSERT INTO sandbox_audit_eventsx VALUES (1)")',
    ):
        expect(not writes(service, allowed), f"a non-write was refused: {allowed!r}")
    write = "DELETE FROM sandbox_audit_events WHERE first_at < cutoff;"
    expect(not writes(MIGRATIONS + "0055_sandbox_audit_log.sql", write),
           "the defining migration was refused")
    for test in (
        "crates/codewire-server-core/src/migrate/tests/sandbox_audit_log.rs",
        "crates/codewire-orchestration/src/audit/tests.rs",
        "crates/codewire-orchestration/src/audit/store_database_tests.rs",
    ):
        expect(not writes(test, write), f"a test file was refused: {test}")
    return failures


def check_sandbox_audit_writers(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("sandbox audit writers", self_test()):
            return 1
        print("sandbox audit writers: OK (self-test)")
        return 0
    paths = sorted(path for path in git_source_files() if SOURCE.search(path))
    failures: list[str] = []
    for path in paths:
        failures.extend(writes(path, read_text(path)))
    if report("sandbox audit writers", failures):
        return 1
    print(f"sandbox audit writers: OK ({len(paths)} Rust and SQL files)")
    return 0
