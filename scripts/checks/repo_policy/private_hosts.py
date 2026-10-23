"""Keep the live forge and registry host names out of the source tree.

Workflows and scripts take the forge from Forgejo's job context
(`github.server_url`, `GITHUB_SERVER_URL`) and the registry and storage
endpoints from repository Actions variables (docs/dev/CI-CONFIGURATION.md).
Action references are short (`noel/<action>@<sha>`) and resolve through
Forgejo's `DEFAULT_ACTIONS_URL`. Tests use `git.example.invalid`,
`registry.example.invalid` and other `*.example.invalid` names. No file is
excepted; the hosted Dev and Production values live in the private deploy
repository.
"""

from __future__ import annotations

from .shared import *


# The two live host names, also written with escaped or bracketed dots as
# they appear in shell, Python and CEL patterns. Built from parts so that
# this file does not contain the literal names it refuses.
_DOT = r"(?:\\{0,2}\.|\[\.\])"
PRIVATE_HOST = re.compile(r"(?<![\w.-])(?:git|registry)" + _DOT + "noel" + _DOT + r"sh(?![\w-])")
# A literal Cloudflare R2 account endpoint; configuration supplies it.
R2_ACCOUNT_ENDPOINT = re.compile(r"(?<![0-9A-Fa-f])[0-9a-f]{32}" + _DOT + r"r2" + _DOT + "cloudflarestorage")

def private_host_findings(rel: str, text: str) -> list[str]:
    findings: list[str] = []
    for label, pattern in (("private host", PRIVATE_HOST), ("R2 account endpoint", R2_ACCOUNT_ENDPOINT)):
        for match in pattern.finditer(text):
            findings.append(f"{rel}:{line_number(text, match.start())}: {label}")
    return findings


def scan_private_hosts(paths: list[str]) -> list[str]:
    findings: list[str] = []
    for rel in paths:
        data = (ROOT / rel).read_bytes()
        if b"\0" in data:
            continue
        findings.extend(private_host_findings(rel, data.decode("utf-8", errors="replace")))
    return findings


def private_host_self_test() -> None:
    forge = "git" + "." + "noel" + "." + "sh"
    registry = "registry" + "." + "noel" + "." + "sh"
    account = "0123456789abcdef" * 2
    rejected = {
        "forge URL": f"uses: https://{forge}/noel/actions-checkout@{'1' * 40}",
        "forge SSH remote": f"git@{forge}:codewire/codewire.git",
        "registry image": f"FROM {registry}/oci-approved/busybox@sha256:{'2' * 64}",
        "escaped registry pattern": "^" + registry.replace(".", "\\.") + "/codewire/",
        "double-escaped forge pattern": forge.replace(".", "\\\\."),
        "bracketed registry pattern": registry.replace(".", "[.]"),
        "R2 account endpoint": f"https://{account}.r2.cloudflarestorage.com",
    }
    accepted = {
        "neutral forge": "https://git.example.invalid/codewire/codewire.git",
        "neutral registry": "registry.example.invalid/codewire/workspace@sha256:" + "3" * 64,
        "configured registry": '"$CODEWIRE_IMAGE_REGISTRY/codewire/base"',
        "short action reference": f"uses: noel/actions-checkout@{'4' * 40}",
        "public product hosts": "ghcr.io/codewiresh/workspace releases.codewire.sh",
        "neutral R2 endpoint": "https://r2-cache.example.invalid",
        "longer host name": "registry." + "noel" + ".shop " + "xgit." + "noel" + ".sh",
    }
    for label, text in rejected.items():
        if not private_host_findings("scripts/fixture.sh", text):
            raise RuntimeError(f"self-test accepted {label}")
    for label, text in accepted.items():
        findings = private_host_findings("scripts/fixture.sh", text)
        if findings:
            raise RuntimeError(f"self-test rejected {label}: {findings}")
    for path in ("deployments/k8s/overlays/local-kind/x.yaml", "crates/x/src/lib.rs", ".gitea/workflows/x.yaml"):
        if not private_host_findings(path, f"https://{forge}"):
            raise RuntimeError(f"self-test excepted {path}")


def check_private_host_literals(args: argparse.Namespace) -> int:
    try:
        if args.self_test:
            private_host_self_test()
        findings = scan_private_hosts(git_source_files())
    except Exception as error:  # noqa: BLE001 - repo check script
        print(f"private host literals: {error}", file=sys.stderr)
        return 1
    if findings:
        print("private host literals: live forge, registry or R2 names found", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(
            "Use ${{ github.server_url }} or GITHUB_SERVER_URL for the forge, the "
            "CODEWIRE_IMAGE_REGISTRY and CODEWIRE_R2_* configuration for the registry "
            "and storage, short noel/<action>@<sha> action references, and "
            "*.example.invalid names in tests (docs/dev/CI-CONFIGURATION.md).",
            file=sys.stderr,
        )
        return 1
    print("private host literals: OK")
    return 0
