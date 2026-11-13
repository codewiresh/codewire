"""Every HTTP client of a Codewire deployment starts from ClientConfig.

`cw login --ca-file` pins a self-hosted deployment's own CA for its host
(#4121). codewire_client::ClientConfig::http_client_builder is the one place
that applies the pin, so a reqwest client built any other way in codewire-cli
or codewire-client would reach a pinned deployment without it. The reviewed
clients below reach something other than a deployment's origin, or are the
default for a caller that passes none, and each says which.

Disabling certificate checks is refused everywhere in both crates. The one
custom verifier is the pinned-host verifier, which only chooses between two
full WebPKI verifiers; it is installed through rustls's `dangerous()` builder,
the only way rustls takes one, and only in VERIFIER_OWNER.
"""

from .database_pools import TEST_FILE, production_source
from .shared import *

CRATE_SOURCES = ("crates/codewire-cli/src/", "crates/codewire-client/src/")
BUILDER_OWNER = "crates/codewire-client/src/config.rs"
VERIFIER_OWNER = "crates/codewire-client/src/config/deployment_ca.rs"
REVIEWED_CLIENTS = {
    "crates/codewire-client/src/auth.rs":
        "the OAuth constructors' default for a caller with no pinned CA; the CLI passes its own",
    "crates/codewire-cli/src/mesh.rs":
        "the Mesh origin, which a pin does not name until stage 4 adds it as an exact host",
    "crates/codewire-cli/src/commands/member_control/transport.rs":
        "a trusted host member's origin, not a Codewire deployment",
    "crates/codewire-cli/src/public_fetch/http.rs":
        "public URLs only, never a deployment",
}
BARE_CLIENT = re.compile(
    r"\breqwest\s*::\s*(?:Client\s*::\s*(?:new|builder)|ClientBuilder\s*::\s*new)\b"
    r"|(?<![\w:])(?:Client\s*::\s*(?:new|builder)|ClientBuilder\s*::\s*new)\s*\(\s*\)"
)
DISABLED_VERIFICATION = re.compile(r"\bdanger_accept_invalid_(?:certs|hostnames)\b")
CUSTOM_VERIFIER = re.compile(r"\.\s*dangerous\s*\(\s*\)")


def violations_from(sources: dict[str, str]) -> list[str]:
    """SOURCES maps repository paths in the two crates to their Rust text."""
    failures: list[str] = []
    seen: set[str] = set()
    for path, source in sorted(sources.items()):
        if not path.startswith(CRATE_SOURCES) or TEST_FILE.search(path):
            continue
        production = production_source(source)
        for match in BARE_CLIENT.finditer(production):
            if path == BUILDER_OWNER:
                continue
            if path in REVIEWED_CLIENTS:
                seen.add(path)
                continue
            failures.append(
                f"{path}:{line_number(production, match.start())}: build a deployment's HTTP "
                "client from ClientConfig::http_client_builder, which applies a pinned CA (#4121)")
        for match in DISABLED_VERIFICATION.finditer(production):
            failures.append(
                f"{path}:{line_number(production, match.start())}: certificate checks are never "
                "disabled (#4121)")
        for match in CUSTOM_VERIFIER.finditer(production):
            if path != VERIFIER_OWNER:
                failures.append(
                    f"{path}:{line_number(production, match.start())}: the only custom TLS "
                    f"verifier is the pinned-host verifier in {VERIFIER_OWNER} (#4121)")
    failures.extend(
        f"{path}: listed in REVIEWED_CLIENTS but builds no client of its own"
        for path in sorted(set(REVIEWED_CLIENTS) - seen))
    return failures


def self_test() -> None:
    reviewed = {path: "let c = reqwest::Client::new();" for path in REVIEWED_CLIENTS}
    production = "crates/codewire-cli/src/commands/example.rs"
    for label, source, expected in [
        ("bare new", "let c = reqwest::Client::new();", 1),
        ("bare builder", "let b = reqwest::Client::builder().no_proxy();", 1),
        ("client builder type", "let b = reqwest::ClientBuilder::new();", 1),
        ("imported Client", "use reqwest::Client;\nlet b = Client::builder();", 1),
        ("the constructor", "let b = config.http_client_builder()?.no_proxy();", 0),
        ("another client type", "let c = HostAgentClient::new(config)?;", 0),
        ("a path ending in Client", "let c = rpc::CodewireClient::new(config, t)?;", 0),
        ("disabled checks", "builder.danger_accept_invalid_certs(true)", 1),
        ("disabled names", "builder.danger_accept_invalid_hostnames(true)", 1),
        ("custom verifier", "rustls::ClientConfig::builder().dangerous()", 1),
        ("comment", "// reqwest::Client::new()\n/* .danger_accept_invalid_certs(true) */", 0),
        ("string", 'let s = "reqwest::Client::builder()";', 0),
        ("test module", "#[cfg(test)]\nmod tests { fn f() { reqwest::Client::new(); } }", 0),
        ("test function", "#[tokio::test]\nasync fn f() { reqwest::Client::builder(); }", 0),
        ("code after a test module", "#[cfg(test)] mod t { fn f() {} }\nfn g() { reqwest::Client::new(); }", 1),
    ]:
        failures = violations_from({production: source, **reviewed})
        assert len(failures) == expected, f"{label}: {failures}"
    other_crate = "crates/codewire-orchestration/src/api.rs"
    assert violations_from({other_crate: "reqwest::Client::new()", **reviewed}) == []
    test_file = "crates/codewire-cli/src/commands/tests/core.rs"
    assert violations_from({test_file: "reqwest::Client::new()", **reviewed}) == []
    assert violations_from({BUILDER_OWNER: "reqwest::Client::builder()", **reviewed}) == []
    assert violations_from({VERIFIER_OWNER: ".dangerous()", **reviewed}) == []
    owner_disabled = violations_from({VERIFIER_OWNER: ".danger_accept_invalid_certs(true)", **reviewed})
    assert len(owner_disabled) == 1, owner_disabled
    stale = next(iter(sorted(REVIEWED_CLIENTS)))
    failures = violations_from({**reviewed, stale: "config.http_client_builder()"})
    assert len(failures) == 1 and "REVIEWED_CLIENTS" in failures[0], failures


def check_deployment_http_clients(args: argparse.Namespace) -> int:
    if args.self_test:
        self_test()
        print("deployment HTTP clients self-test: OK")
        return 0
    sources = {
        path: read_text(path)
        for path in git_source_files()
        if path.startswith(CRATE_SOURCES) and path.endswith(".rs")
    }
    failures = violations_from(sources)
    for failure in failures:
        print(f"::error::deployment HTTP clients: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(
        f"deployment HTTP clients: OK ({len(sources)} Rust files, "
        f"{len(REVIEWED_CLIENTS)} reviewed clients)")
    return 0
