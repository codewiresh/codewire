"""Only database code writes the credential revocation log.

`credential_revocations` records each loss of authority that ends a stream
already admitted (#3586; docs/dev/AUTH-POLICY.md, "Account access
revocation"). Triggers write it, and the refresh-token reuse path calls
`codewire_revoke_oauth_grant`. The services run as the database's owner
(#5166), so no grant can stop service code from writing the log; this check
does instead (cw-security, 2026-11-17). A forged row would end a stream, a
missing one would leave it open.

It refuses an INSERT, UPDATE, DELETE, MERGE, TRUNCATE or COPY into the log
anywhere in tracked Rust or SQL except the migrations that define it and test
files, which age and inspect rows on purpose.
"""

from __future__ import annotations

from .shared import *

TABLE = "credential_revocations"
MIGRATIONS = "crates/codewire-server-core/migrations/"
SOURCE = re.compile(r"\.(?:rs|sql)$")
TEST_PATH = re.compile(r"(?:^|/)tests/|(?:^|/|_)tests\.rs$")
# A Rust string continues across `\` and a newline, so a statement split over
# lines still reads as one.
CONTINUATION = re.compile(r"\\\r?\n\s*")
WRITE = re.compile(
    r"\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|MERGE\s+INTO|TRUNCATE(?:\s+TABLE)?|COPY)"
    r"\s+(?:ONLY\s+)?(?:\"?public\"?\s*\.\s*)?\"?" + TABLE + r"\b",
    re.IGNORECASE,
)


def exempt(path: str) -> bool:
    return path.startswith(MIGRATIONS) or bool(TEST_PATH.search(path))


def writes(path: str, text: str) -> list[str]:
    if exempt(path):
        return []
    joined = CONTINUATION.sub(" ", text)
    return [
        f"{path} writes {TABLE} ({' '.join(match.group(0).split())!r}); only its triggers and "
        f"codewire_revoke_oauth_grant may (#3586, AUTH-POLICY \"Account access revocation\")"
        for match in WRITE.finditer(joined)
    ]


def self_test() -> list[str]:
    failures: list[str] = []

    def expect(condition: object, message: str) -> None:
        if not condition:
            failures.append(f"revocation log writers self-test: {message}")

    service = "crates/codewire-orchestration/src/api/thing.rs"
    for statement in (
        'sqlx::query("INSERT INTO credential_revocations (kind) VALUES ($1)")',
        'sqlx::query("insert into public.credential_revocations values (1)")',
        'sqlx::query("UPDATE credential_revocations SET kind = $1")',
        'sqlx::query("DELETE FROM \\\n     credential_revocations WHERE seq = $1")',
        'sqlx::query("TRUNCATE TABLE credential_revocations")',
        'sqlx::query("MERGE INTO credential_revocations AS r USING x ON true")',
        'sqlx::query("COPY credential_revocations FROM STDIN")',
        'sqlx::query(r#"DELETE FROM ONLY "public"."credential_revocations""#)',
    ):
        expect(len(writes(service, statement)) == 1, f"a write was admitted: {statement!r}")
    expect(writes("deploy/sql/repair.sql", "DELETE FROM credential_revocations;"),
           "a write in tracked SQL outside the migrations was admitted")
    for allowed in (
        'sqlx::query("SELECT seq, kind FROM credential_revocations WHERE seq > $1")',
        'sqlx::query("SELECT codewire_revoke_oauth_grant($1, $2)")',
        'sqlx::query("UPDATE sessions SET expires_at = now()")',
        'sqlx::query("INSERT INTO credential_revocations_archive VALUES (1)")',
    ):
        expect(not writes(service, allowed), f"a non-write was refused: {allowed!r}")
    write = "INSERT INTO credential_revocations (kind) VALUES ('user');"
    expect(not writes(MIGRATIONS + "0035_credential_revocations.sql", write),
           "the defining migration was refused")
    for test in (
        "crates/codewire-server-core/src/migrate/tests/credential_revocations.rs",
        "crates/codewire-server-core/src/revocation/database_tests.rs",
        "crates/codewire-server-core/src/revocation/tests.rs",
        "crates/codewire-idp/tests/db_flow.rs",
    ):
        expect(not writes(test, write), f"a test file was refused: {test}")
    expect(writes("crates/codewire-server-core/src/revocation.rs", write),
           "the fence's own source was exempted")
    return failures


def check_revocation_log_writers(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("revocation log writers", self_test()):
            return 1
        print("revocation log writers: OK (self-test)")
        return 0
    paths = sorted(path for path in git_source_files() if SOURCE.search(path))
    failures: list[str] = []
    for path in paths:
        failures.extend(writes(path, read_text(path)))
    if report("revocation log writers", failures):
        return 1
    print(f"revocation log writers: OK ({len(paths)} Rust and SQL files)")
    return 0
