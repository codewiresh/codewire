#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
from xml.etree import ElementTree


CANONICAL_ORIGIN = "https://codewire.sh"
EXPECTED_ROUTE_COUNT = 39


def fail(message: str) -> None:
    raise RuntimeError(message)


def canonical_path(value: str) -> str:
    path = urlparse(value).path.rstrip("/")
    return path or "/docs"


class DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.canonical: str | None = None
        self.resources: list[tuple[str, str]] = []
        self.links: list[str] = []
        self.ids: set[str] = set()
        self.active_navigation = 0
        self.h1_count = 0
        self.csp: str | None = None
        self.markdown_alternate: str | None = None
        self.refresh: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        if "id" in values:
            self.ids.add(values["id"])
        if tag == "h1":
            self.h1_count += 1
        if tag == "a":
            href = values.get("href")
            if href:
                self.links.append(href)
            if values.get("aria-current") == "page":
                self.active_navigation += 1
        if tag == "link":
            rel = set(values.get("rel", "").split())
            href = values.get("href")
            if "canonical" in rel:
                self.canonical = href
            if "alternate" in rel and values.get("type") == "text/markdown":
                self.markdown_alternate = href
            if href and rel.intersection({"stylesheet", "icon", "preload", "modulepreload"}):
                self.resources.append((tag, href))
        if tag in {"script", "img", "iframe", "source", "video", "audio"}:
            source = values.get("src")
            if source:
                self.resources.append((tag, source))
        if tag == "meta" and values.get("http-equiv", "").lower() == "content-security-policy":
            self.csp = values.get("content")
        if tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            self.refresh = values.get("content")


def parse_document(path: Path) -> tuple[DocumentParser, str]:
    text = path.read_text(encoding="utf-8")
    parser = DocumentParser()
    parser.feed(text)
    return parser, text


def source_documents(content_root: Path) -> set[str]:
    # Every page and every section landing page (`_index.md`) is a route.
    return {
        f"content/{path.relative_to(content_root).as_posix()}"
        for path in content_root.rglob("*.md")
    }


def front_matter(path: Path) -> dict[str, object]:
    # Section landing pages use TOML; pages use flat YAML whose values are
    # scalars, quoted strings or JSON-style lists.
    text = path.read_text(encoding="utf-8")
    if text.startswith("+++\n"):
        return tomllib.loads(text[4 : text.index("\n+++\n", 4)])
    if not text.startswith("---\n"):
        fail(f"missing front matter in {path}")
    values: dict[str, object] = {}
    for line in text[4 : text.index("\n---\n", 4)].splitlines():
        key, _, value = line.partition(":")
        value = value.strip()
        if value.startswith("["):
            values[key.strip()] = json.loads(value)
        elif len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            values[key.strip()] = value[1:-1]
        else:
            values[key.strip()] = value
    return values


def markdown_path(canonical: str) -> str:
    return "/docs/index.md" if canonical == "/docs" else f"{canonical}.md"


def route_aliases(site_root: Path, routes: list[dict[str, str]]) -> dict[str, str]:
    """Every old URL a page keeps, mapped to the page's canonical path."""
    canonical_routes = {route["canonical"] for route in routes}
    aliases: dict[str, str] = {}
    for route in routes:
        for alias in front_matter(site_root / route["source"]).get("aliases", []):
            old = "/docs" + "/" + str(alias).strip("/")
            if old in canonical_routes or old in aliases:
                fail(f"alias {alias} of {route['source']} collides with a route or another alias")
            aliases[old] = route["canonical"]
    return aliases


def verify_routes(site_root: Path, output_root: Path) -> tuple[list[dict[str, str]], dict[str, DocumentParser]]:
    manifest = tomllib.loads((site_root / "routes.toml").read_text(encoding="utf-8"))
    routes = manifest.get("routes", [])
    if manifest.get("schema") != 1 or manifest.get("base_path") != "/docs":
        fail("route manifest schema/base_path is invalid")
    if len(routes) != EXPECTED_ROUTE_COUNT:
        fail(f"expected {EXPECTED_ROUTE_COUNT} routes, found {len(routes)}")

    canonical_routes = {route["canonical"] for route in routes}
    if len(canonical_routes) != EXPECTED_ROUTE_COUNT:
        fail("route manifest contains duplicate canonical paths")
    if any(not route.startswith("/docs") or route.endswith("/") for route in canonical_routes):
        fail("canonical documentation paths must begin with /docs and omit trailing slashes")

    redirects = {route["redirect_from"] for route in routes}
    if len(redirects) != EXPECTED_ROUTE_COUNT:
        fail("route manifest contains duplicate trailing-slash redirects")
    for route in routes:
        if route["redirect_from"] != f'{route["canonical"]}/':
            fail(f"redirect does not map directly to canonical route: {route['canonical']}")

    manifest_sources = {route["source"] for route in routes}
    actual_sources = source_documents(site_root / "content")
    if manifest_sources != actual_sources:
        fail(f"route/source mismatch: missing={sorted(actual_sources - manifest_sources)} extra={sorted(manifest_sources - actual_sources)}")

    aliases = route_aliases(site_root, routes)
    alias_outputs = {f'{old.removeprefix("/docs/")}/index.html': target for old, target in aliases.items()}
    expected_outputs = {route["output"] for route in routes} | set(alias_outputs)
    actual_outputs = {
        path.relative_to(output_root).as_posix()
        for path in output_root.rglob("index.html")
    }
    if expected_outputs != actual_outputs:
        fail(f"rendered route mismatch: missing={sorted(expected_outputs - actual_outputs)} extra={sorted(actual_outputs - expected_outputs)}")

    for output, target in alias_outputs.items():
        parser, _ = parse_document(output_root / output)
        if parser.refresh != f"0; url={target}":
            fail(f"alias page {output} does not redirect to {target}: {parser.refresh!r}")
        if parser.canonical != f"{CANONICAL_ORIGIN}{target}":
            fail(f"alias page {output} names the wrong canonical URL: {parser.canonical!r}")
        if not parser.csp or "default-src 'none'" not in parser.csp:
            fail(f"alias page {output} is missing its script-free CSP")

    parsed: dict[str, DocumentParser] = {}
    combined_html = ""
    for route in routes:
        output = output_root / route["output"]
        parser, html = parse_document(output)
        combined_html += html
        expected_canonical = f'{CANONICAL_ORIGIN}{route["canonical"]}'
        if parser.canonical != expected_canonical:
            fail(f"wrong canonical URL in {route['output']}: {parser.canonical!r}")
        if parser.h1_count != 1:
            fail(f"expected one h1 in {route['output']}, found {parser.h1_count}")
        if parser.active_navigation != 1:
            fail(f"expected one active navigation item in {route['output']}, found {parser.active_navigation}")
        if not parser.csp or "default-src 'self'" not in parser.csp or "connect-src 'self'" not in parser.csp:
            fail(f"missing restrictive CSP in {route['output']}")
        if parser.markdown_alternate != markdown_path(route["canonical"]):
            fail(f"wrong Markdown alternate in {route['output']}: {parser.markdown_alternate!r}")
        for tag, resource in parser.resources:
            parsed_resource = urlparse(resource)
            if parsed_resource.scheme and f"{parsed_resource.scheme}://{parsed_resource.netloc}" != CANONICAL_ORIGIN:
                fail(f"external browser resource in {route['output']}: {tag} {resource}")
            if not parsed_resource.scheme and not resource.startswith(("/docs/", "data:")):
                fail(f"resource escapes the documentation origin in {route['output']}: {resource}")
        parsed[route["canonical"]] = parser

    if "docs-card-grid" not in combined_html or "docs-aside" not in combined_html:
        fail("shortcode output is missing from rendered documentation")
    if re.search(r"<(?:Aside|CardGrid|LinkCard)\b|@astrojs/starlight", combined_html):
        fail("Astro/Starlight markup leaked into rendered documentation")

    for route, parser in parsed.items():
        for href in parser.links:
            parsed_href = urlparse(href)
            if href.startswith("#"):
                if href[1:] and href[1:] not in parser.ids:
                    fail(f"missing local anchor {href} on {route}")
                continue
            if parsed_href.scheme and parsed_href.netloc != "codewire.sh":
                continue
            if parsed_href.path.startswith("/docs"):
                if parsed_href.path.endswith("/"):
                    fail(f"trailing-slash internal documentation link on {route}: {href}")
                target = canonical_path(parsed_href.path)
                if target not in canonical_routes:
                    if (output_root / target.removeprefix("/docs/")).is_file():
                        continue
                    fail(f"broken internal documentation link on {route}: {href}")
                if parsed_href.fragment and parsed_href.fragment not in parsed[target].ids:
                    fail(f"broken internal documentation anchor on {route}: {href}")

    return routes, parsed


def verify_markdown(routes: list[dict[str, str]], site_root: Path, output_root: Path) -> None:
    markdown_urls = {f"{CANONICAL_ORIGIN}{markdown_path(route['canonical'])}" for route in routes}
    linked_markdown = re.compile(r"\]\((?P<url>https://codewire\.sh/docs[^)#\s]*)")
    full = (output_root / "llms-full.txt").read_text(encoding="utf-8")
    index = (output_root / "llms.txt").read_text(encoding="utf-8")
    for route in routes:
        path = output_root / markdown_path(route["canonical"]).removeprefix("/docs/")
        if not path.is_file():
            fail(f"missing Markdown copy of {route['canonical']}")
        text = path.read_text(encoding="utf-8")
        title = front_matter(site_root / route["source"])["title"]
        if not text.startswith(f"# {title}\n"):
            fail(f"Markdown copy of {route['canonical']} does not start with its title")
        source_line = f"\nSource: {CANONICAL_ORIGIN}{route['canonical']}\n"
        if source_line not in text:
            fail(f"Markdown copy of {route['canonical']} has no Source line")
        if full.count(source_line) != 1:
            fail(f"llms-full.txt does not hold {route['canonical']} exactly once")
        url = f"{CANONICAL_ORIGIN}{markdown_path(route['canonical'])}"
        if index.count(f"]({url})") != 1:
            fail(f"llms.txt does not list {url} exactly once")
        for leftover in ("](@/", "{{", "{%"):
            if leftover in text:
                fail(f"unconverted Zola syntax {leftover!r} in the Markdown copy of {route['canonical']}")
        for match in linked_markdown.finditer(text):
            target = match.group("url")
            if target not in markdown_urls and not (output_root / urlparse(target).path.removeprefix("/docs/")).is_file():
                fail(f"broken link {target} in the Markdown copy of {route['canonical']}")


def verify_search(routes: list[dict[str, str]], site_root: Path, output_root: Path) -> None:
    index_path = output_root / "search_index.en.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if len(index) != EXPECTED_ROUTE_COUNT:
        fail(f"expected {EXPECTED_ROUTE_COUNT} search entries, found {len(index)}")
    indexed_routes = [canonical_path(entry["url"]) for entry in index]
    expected_routes = {route["canonical"] for route in routes}
    if set(indexed_routes) != expected_routes or len(set(indexed_routes)) != len(indexed_routes):
        fail("search index does not map one-to-one to the route manifest")
    for entry in index:
        if not all(entry.get(field) for field in ("title", "description", "body", "path")):
            fail(f"search entry is missing required local fields: {entry.get('url')}")
        if urlparse(entry["url"]).netloc != "codewire.sh":
            fail(f"search entry escapes canonical origin: {entry['url']}")
        if urlparse(entry["url"]).path.endswith("/"):
            fail(f"search entry uses a trailing-slash URL: {entry['url']}")

    search_script = (site_root / "static/search.js").read_text(encoding="utf-8")
    forbidden = ("innerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "http://", "https://", "unpkg", "jsdelivr")
    for token in forbidden:
        if token in search_script:
            fail(f"unsafe or external search implementation token: {token}")
    for required in ("textContent", "replaceChildren", "aria-activedescendant", "ArrowDown", "ArrowUp", "credentials: \"same-origin\""):
        if required not in search_script:
            fail(f"search accessibility/safety behavior missing: {required}")


def verify_sitemap(routes: list[dict[str, str]], output_root: Path) -> None:
    root = ElementTree.parse(output_root / "sitemap.xml").getroot()
    locations = {
        element.text
        for element in root.findall("{http://www.sitemaps.org/schemas/sitemap/0.9}url/{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
    }
    expected = {f'{CANONICAL_ORIGIN}{route["canonical"]}' for route in routes}
    if locations != expected:
        fail("sitemap URLs do not exactly match the no-trailing-slash route manifest")


def verify_supply_chain(site_root: Path) -> None:
    docs_root = site_root.parent
    dockerfile_path = site_root.parent.parent / "dashboard" / "Dockerfile"
    dockerfile = dockerfile_path.read_text(encoding="utf-8")
    checksums = (site_root / "tests/provenance/zola-v0.22.1.sha256").read_text(encoding="utf-8")
    required_digests = {
        "0ca09aa40376aaa9ddfb512ff9ad963262ef95edb0d0f2d5ec6961b6f5cf22ef",
        "8af437ec6352f33ccd24d7a1cfcb54a3db95d3ce376dc69525b4ef3fb6b8c1d1",
    }
    if "debian:bookworm-slim@sha256:" not in dockerfile:
        fail("Zola dev container base image is not digest-pinned")
    if "ADD --checksum=sha256:" not in dockerfile or "apt-get" in dockerfile:
        fail("Zola dev container must verify remote ADD and avoid mutable package installation")
    if not required_digests.issubset(set(re.findall(r"[0-9a-f]{64}", dockerfile))):
        fail("Zola dev container is missing an approved release digest")
    if not required_digests.issubset(set(re.findall(r"[0-9a-f]{64}", checksums))):
        fail("Zola checksum inventory is incomplete")
    for digest in required_digests:
        bundle = site_root / f"tests/provenance/sha256-{digest}.jsonl"
        if not bundle.is_file() or bundle.stat().st_size < 1000:
            fail(f"checked-in Sigstore bundle is missing: {digest}")
    license_path = site_root / "tests/provenance/ZOLA-LICENSE-EUPL-1.2.txt"
    if hashlib.sha256(license_path.read_bytes()).hexdigest() != "6fc9e709ccbfe0d77fbffa2427a983282be2eb88e47b1cdb49f21a83b4d1e665":
        fail("Zola release license is missing or changed")
    highlighting = site_root / "static/giallo.css"
    if hashlib.sha256(highlighting.read_bytes()).hexdigest() != "fb6bfef1747cf20d61d5beef4eb3a65992abbb3cff35a6b71c53c182df7e3341":
        fail("generated github-dark syntax theme is missing or changed")
    if "/usr/share/licenses/zola/LICENSE" not in dockerfile:
        fail("Zola dev container does not retain the verified release license")

    prohibited = re.compile(r"unpkg|jsdelivr|fonts\.googleapis|cdn\.jsdelivr|\bnpx\b|\bbunx\b|\bbun\s+x\b", re.IGNORECASE)
    scanned_paths = [site_root / "config.toml", site_root / "routes.toml", dockerfile_path]
    for directory in ("content", "templates", "sass", "static"):
        scanned_paths.extend(path for path in (site_root / directory).rglob("*") if path.is_file())
    for path in scanned_paths:
        text = path.read_text(encoding="utf-8")
        if prohibited.search(text):
            fail(f"prohibited external dependency or dynamic runner in {path.relative_to(site_root)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--site-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    site_root = args.site_root.resolve()
    output_root = args.output.resolve()

    routes, _ = verify_routes(site_root, output_root)
    verify_markdown(routes, site_root, output_root)
    verify_search(routes, site_root, output_root)
    verify_sitemap(routes, output_root)
    verify_supply_chain(site_root)

    digest = hashlib.sha256((site_root / "routes.toml").read_bytes()).hexdigest()
    print(f"verified {len(routes)} routes; route-manifest-sha256={digest}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
