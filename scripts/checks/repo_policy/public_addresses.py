"""Keep live infrastructure addresses out of the public source tree.

Tests, examples and documentation use the documentation ranges: RFC 5737
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) for IPv4, and RFC 3849
(`2001:db8::/32`) or RFC 9637 (`3fff::/20`) for IPv6. Any other publicly
routable literal must be a well-known third-party address listed below with
its reason. Live deployment values belong to the private deploy repository.
"""

from __future__ import annotations

import ipaddress

from .shared import *


IPV4_LITERAL = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?!\w|\.\d)")
# Global unicast IPv6 (2000::/3) always writes its first group with four hex
# digits, so this ignores slices, Rust paths and clock times.
IPV6_LITERAL = re.compile(r"(?<![\w:.])([23][0-9A-Fa-f]{3}:[0-9A-Fa-f:]*[0-9A-Fa-f])(?![\w:])")
SECTION_PREFIXES = ("§", "section-")

GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")
DOCUMENTATION_V6 = (
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("3fff::/20"),
)

ALLOWED_ADDRESSES: dict[str, str] = {
    "1.1.1.1": "Cloudflare public DNS resolver, a well-known external target",
    "8.8.8.8": "Google public DNS resolver, a well-known external target",
    "2606:4700:4700::1111": "Cloudflare public DNS resolver, a well-known external target",
    "1.2.3.4": "conventional placeholder shared with upstream tailnet fixtures and version strings",
    "2.3.4.5": "conventional placeholder in upstream-derived disco tests",
    "5.6.7.8": "conventional placeholder in forwarded-header and STUN tests",
    "8.0.0.0": "public /8 network base in egress CIDR tests",
    "93.0.0.0": "public /8 network base in egress CIDR tests",
    "93.184.216.34": "former example.com address, an IANA example domain",
    "100.128.0.1": "first address above shared space 100.64.0.0/10, a boundary test",
    "203.0.114.1": "first address above TEST-NET-3, a boundary test",
    "140.82.121.33": "ghcr.io address quoted in captured registry error fixtures",
    "2001:4860::1": "address just outside 2001:db8::/32, a boundary test",
    "2a01:4f8::1": "non-documentation global unicast example for endpoint filters",
    "2a09:8280:1::1111": "public anycast STUN result in upstream-derived tracker tests",
    "2a09:8280:1::2222": "public anycast STUN result in upstream-derived tracker tests",
}

def public_address(literal: str) -> bool:
    try:
        address = ipaddress.ip_address(literal)
    except ValueError:
        return False
    if address.version == 4:
        return address.is_global and not address.is_multicast
    if address not in GLOBAL_UNICAST_V6 or not address.is_global:
        return False
    return not any(address in network for network in DOCUMENTATION_V6)


def public_address_findings(rel: str, text: str) -> list[str]:
    findings: list[str] = []
    for pattern in (IPV4_LITERAL, IPV6_LITERAL):
        for match in pattern.finditer(text):
            literal = match.group(1)
            if text[max(0, match.start(1) - 8):match.start(1)].endswith(SECTION_PREFIXES):
                continue
            if literal in ALLOWED_ADDRESSES or not public_address(literal):
                continue
            findings.append(f"{rel}:{line_number(text, match.start(1))}: {literal}")
    return findings


def scan_public_addresses(paths: list[str]) -> list[str]:
    self_path = Path(__file__).relative_to(ROOT).as_posix()
    findings: list[str] = []
    for rel in paths:
        if rel == self_path:
            continue
        data = (ROOT / rel).read_bytes()
        if b"\0" in data:
            continue
        findings.extend(public_address_findings(rel, data.decode("utf-8", errors="replace")))
    return findings


def public_address_self_test() -> None:
    rejected = {
        "public IPv4": 'endpoint = "9.9.9.9:53"',
        "public IPv4 at a sentence end": "advertises 9.9.9.9.",
        "IPv4-mapped public IPv4": '"[::ffff:9.9.9.9]:41641"',
        "public IPv6": '"[2a00:1450:4001::1]:443"',
        "public IPv4 in CIDR": "cidr: 9.9.9.0/24",
    }
    accepted = {
        "documentation IPv4": "203.0.113.5 198.51.100.7 192.0.2.10",
        "documentation IPv6": "[2001:db8::1]:41641 3fff::1",
        "private and special IPv4": "10.60.0.1 100.64.0.1 127.0.0.1 169.254.1.1 224.0.0.251",
        "private and special IPv6": "fe80::1 fd7a:115c:a1e0::1 ff02::1 64:ff9b::1",
        "version strings": "v9.9.9.9 1.2.3.4.5 9.9.9.9.1",
        "specification sections": "RFC 6749 §4.1.2.1 rfc5280#section-4.2.1.3",
        "slices and paths": "argv[1::2] use aead::Aead; 12:30:45",
        "allowlisted address": "resolver 1.1.1.1:53",
    }
    for label, text in rejected.items():
        if not public_address_findings("fixture", text):
            raise RuntimeError(f"self-test accepted {label}")
    for label, text in accepted.items():
        findings = public_address_findings("fixture", text)
        if findings:
            raise RuntimeError(f"self-test rejected {label}: {findings}")
    for literal, reason in ALLOWED_ADDRESSES.items():
        if not public_address(literal) or not reason:
            raise RuntimeError(f"allowlist entry {literal} is not a reasoned public address")


def check_public_address_literals(args: argparse.Namespace) -> int:
    try:
        if args.self_test:
            public_address_self_test()
        findings = scan_public_addresses(git_source_files())
    except Exception as error:  # noqa: BLE001 - repo check script
        print(f"public address literals: {error}", file=sys.stderr)
        return 1
    if findings:
        print("public address literals: unlisted public IP literals found", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(
            "Use 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 or 2001:db8::/32 in "
            "tests and docs; keep live values in the private deploy repository; or "
            "list a well-known third-party address with its reason in "
            "scripts/checks/repo_policy/public_addresses.py.",
            file=sys.stderr,
        )
        return 1
    print("public address literals: OK")
    return 0
