"""Only the Connect auth layer refuses with BEARER_REFUSED.

A native client refreshes once and sends a unary call again only when its
401 carries the `ErrorInfo` reason `BEARER_REFUSED` (#6145;
docs/dev/AUTH-POLICY.md, "Native sign-in lifetimes"). The auth layer gives
it to its own refusal of a presented bearer, which comes before any handler
runs. A handler that answered with it after acting would make the client
repeat a write, so nothing else may produce it (cw-security, 2026-11-23).

The code is defined once, as `BEARER_REFUSED_CODE` in server-core's
`error.rs`, and only `connect/admission.rs` raises it. This check refuses
the constant anywhere else, and the string, in any case, anywhere but its
definition, the client code that reads it (`READERS`) and tests.
"""

from __future__ import annotations

from .shared import *

DEFINITION = "crates/codewire-server-core/src/error.rs"
RAISER = "crates/codewire-server-core/src/connect/admission.rs"
# Client code that reads the reason to decide on its one retry. A reader
# compares the string; it never builds an error with it.
READERS: frozenset[str] = frozenset({
    "crates/codewire/src/transport.rs",
    "apps/ios/Sources/CodewireKit/Networking/CodewireClient.swift",
})
SOURCE = re.compile(r"\.(?:rs|swift|ts|tsx|js|py|go)$")
TEST_PATH = re.compile(r"(?:^|/)(?:tests|Tests|e2e)/|(?:^|/|_)tests\.rs$|_test\.(?:go|py)$")
CONSTANT = re.compile(r"\bBEARER_REFUSED_CODE\b")
STRING = re.compile(r"bearer_refused", re.IGNORECASE)
# This check and its wiring name the reason to look for it.
CHECKS = "scripts/checks/"


def uses(path: str, text: str) -> list[str]:
    if TEST_PATH.search(path) or path.startswith(CHECKS):
        return []
    failures = []
    if path not in (DEFINITION, RAISER) and CONSTANT.search(text):
        failures.append(
            f"{path} uses BEARER_REFUSED_CODE; only the Connect auth layer's admission "
            f"({RAISER}) may raise it (#6145, AUTH-POLICY \"Native sign-in lifetimes\")"
        )
    stripped = CONSTANT.sub("", text)
    if path not in (DEFINITION, *READERS) and STRING.search(stripped):
        failures.append(
            f"{path} names the BEARER_REFUSED reason; a client retries a call on it, so only "
            f"the auth layer produces it, and only listed readers may compare it (#6145)"
        )
    return failures


def self_test() -> list[str]:
    failures: list[str] = []

    def expect(condition: object, message: str) -> None:
        if not condition:
            failures.append(f"bearer refused reason self-test: {message}")

    handler = "crates/codewire-orchestration/src/connect/environments.rs"
    for text in (
        'AppError::Coded { status, code: "bearer_refused", detail }',
        'ErrorInfo { reason: "BEARER_REFUSED".into(), ..Default::default() }',
        "code: codewire_server_core::error::BEARER_REFUSED_CODE,",
        'reason = "Bearer_Refused"',
    ):
        expect(uses(handler, text), f"a handler producing the reason was admitted: {text!r}")
    expect(not uses("crates/codewire/src/transport.rs",
                    'const BEARER_REFUSED: &str = "BEARER_REFUSED";'),
           "the CLI's reader was refused")
    expect(uses("crates/codewire/src/transport.rs", "code: BEARER_REFUSED_CODE,"),
           "the CLI's reader raising the constant was admitted")
    expect(not uses("apps/ios/Sources/CodewireKit/Networking/CodewireClient.swift",
                    'info.reason == "BEARER_REFUSED" && info.domain == "codewire.sh"'),
           "the iOS client's reader was refused")
    expect(uses("apps/ios/Sources/CodewireKit/Networking/Retry.swift",
                'if info.reason == "BEARER_REFUSED" {'),
           "an unlisted reader was admitted")
    expect(not uses(DEFINITION, 'pub(crate) const BEARER_REFUSED_CODE: &str = "bearer_refused";'),
           "the definition was refused")
    expect(not uses(RAISER, "code: BEARER_REFUSED_CODE,"), "the auth layer was refused")
    expect(uses(RAISER, 'code: "bearer_refused",'),
           "the auth layer spelling the string itself was admitted")
    for test in (
        "crates/codewire-server-core/tests/connect_auth.rs",
        "crates/codewire-client/src/auth/tests.rs",
        "apps/ios/Tests/CodewireKitTests/RetryTests.swift",
    ):
        expect(not uses(test, 'assert_eq!(info.reason, "BEARER_REFUSED");'),
               f"a test file was refused: {test}")
    expect(not uses(handler, 'reason: "SESSION_EXPIRED"'), "another reason was refused")
    return failures


def check_bearer_refused_reason(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("bearer refused reason", self_test()):
            return 1
        print("bearer refused reason: OK (self-test)")
        return 0
    paths = sorted(path for path in git_source_files() if SOURCE.search(path))
    failures: list[str] = []
    for path in paths:
        failures.extend(uses(path, read_text(path)))
    for required in (DEFINITION, RAISER):
        if not CONSTANT.search(read_text(required)):
            failures.append(f"{required} no longer holds BEARER_REFUSED_CODE; update this check")
    if report("bearer refused reason", failures):
        return 1
    print(f"bearer refused reason: OK ({len(paths)} source files)")
    return 0
