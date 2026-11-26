"""Every path that ends a user's `cw` access also ends their user tokens.

A user token (#5688; docs/dev/AUTH-POLICY.md, "User tokens and the CLI")
is exchanged for a `cw` sign-in's access token and lives in its own table,
`oidc_user_tokens`. Whatever deletes a user's access tokens (a password
reset, account deletion, refresh-token reuse) must delete their user tokens
in the same place, or a token copied into an environment outlives the
access it came from (cw-security, 2026-11-24).

This check refuses a production source file that deletes from
`oidc_access_tokens` by user without also deleting from `oidc_user_tokens`
by user, whatever names the user: a bind parameter, or `NEW.id` in a trigger
function. The migrations are read as one history, because a later migration
replaces an earlier function: the baseline's account-disable function is
replaced in the migration that adds the table. Removing expired rows is not
a revocation and is not counted.
"""

from __future__ import annotations

from .shared import *

SOURCE = re.compile(r"\.(?:rs|sql|go|py|ts)$")
TEST_PATH = re.compile(
    r"(?:^|/)(?:tests|Tests|e2e)/|(?:^|/|_)tests\.rs$|_tests?\.rs$|_test\.(?:go|py)$"
)
USER = r"user_id\s*=\s*(?:\$\d+|(?:NEW|OLD)\.\w+|[A-Za-z_]\w*)"
ACCESS_BY_USER = re.compile(
    rf"DELETE\s+FROM\s+(?:public\.)?oidc_access_tokens\s+WHERE\s+{USER}"
    r"(?!\s+AND\s+expires_at\s*<=)",
    re.IGNORECASE,
)
USER_TOKENS_BY_USER = re.compile(
    rf"DELETE\s+FROM\s+(?:public\.)?oidc_user_tokens\s+WHERE\s+{USER}",
    re.IGNORECASE,
)
MIGRATIONS = "crates/codewire-server-core/migrations/"
# This check names the statements to look for them.
CHECKS = "scripts/checks/"


def uses(path: str, text: str) -> list[str]:
    if TEST_PATH.search(path) or path.startswith(CHECKS):
        return []
    if ACCESS_BY_USER.search(text) and not USER_TOKENS_BY_USER.search(text):
        return [
            f"{path} deletes a user's OAuth access tokens but not their user tokens; add "
            f"DELETE FROM oidc_user_tokens WHERE user_id = ... beside it (#5688)"
        ]
    return []


def self_test() -> list[str]:
    failures: list[str] = []

    def expect(condition: object, message: str) -> None:
        if not condition:
            failures.append(f"user token deletes self-test: {message}")

    reset = "crates/codewire-idp/src/email_password.rs"
    access = '"DELETE FROM oidc_access_tokens WHERE user_id = $1",'
    user_tokens = '"DELETE FROM oidc_user_tokens WHERE user_id = $1",'
    expect(uses(reset, access), "an access-token delete alone was admitted")
    expect(not uses(reset, access + "\n" + user_tokens), "the paired delete was refused")
    expect(
        uses(reset, "delete from public.oidc_access_tokens where user_id=$2 and client_id = $3"),
        "a per-client delete alone was admitted",
    )
    expect(
        not uses(
            "crates/codewire-idp/src/expired_rows.rs",
            "DELETE FROM oidc_access_tokens WHERE user_id = $1 AND expires_at <= NOW()",
        ),
        "removing expired rows was refused",
    )
    expect(
        not uses("crates/codewire-idp/tests/db_flow.rs", access),
        "a test file was refused",
    )
    expect(
        not uses(reset, '"DELETE FROM oidc_access_tokens WHERE token_hash = $1",'),
        "a delete by digest was refused",
    )
    trigger = "DELETE FROM public.oidc_access_tokens WHERE user_id = NEW.id;"
    expect(uses(f"{MIGRATIONS}0001_baseline.sql", trigger),
           "a trigger function's delete alone was admitted")
    expect(
        not uses(f"{MIGRATIONS}history",
                 trigger + "\nDELETE FROM public.oidc_user_tokens WHERE user_id = NEW.id;"),
        "a later migration replacing the function was refused",
    )
    return failures


def check_user_token_deletes(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("user token deletes", self_test()):
            return 1
        print("user token deletes: OK (self-test)")
        return 0
    paths = sorted(path for path in git_source_files() if SOURCE.search(path))
    failures: list[str] = []
    history: list[str] = []
    for path in paths:
        if path.startswith(MIGRATIONS):
            history.append(read_text(path))
        else:
            failures.extend(uses(path, read_text(path)))
    # The migrations in order, as the database applies them.
    failures.extend(uses(f"{MIGRATIONS}*.sql", "\n".join(history)))
    if report("user token deletes", failures):
        return 1
    print(f"user token deletes: OK ({len(paths)} source files)")
    return 0
