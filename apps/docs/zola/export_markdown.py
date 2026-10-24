#!/usr/bin/env python3
"""Write the machine-readable documentation next to the rendered site.

Every route in routes.toml gets a Markdown copy at its canonical path plus
`.md` (`/docs` itself is `/docs/index.md`). `llms.txt` indexes them and
`llms-full.txt` holds every page in one file. Pages are read from their
sources, with Zola's internal links made absolute and its shortcodes turned
into plain Markdown, so the output depends only on the checked-in content.
"""
from __future__ import annotations

import argparse
import ast
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path


CANONICAL_ORIGIN = "https://codewire.sh"

CARD_GRID = re.compile(r"\{\{\s*card_grid\((?P<args>.*?)\)\s*\}\}", re.DOTALL)
ASIDE = re.compile(r'\{%\s*aside\(kind="(?P<kind>\w+)"\)\s*%\}(?P<body>.*?)\{%\s*end\s*%\}', re.DOTALL)
INTERNAL_LINK = re.compile(r"\]\(@/(?P<source>[^)#\s]+\.md)(?P<fragment>#[^)\s]*)?\)")
DOCS_LINK = re.compile(r"\]\((?P<path>/docs(?:/[^)#\s]*)?)(?P<fragment>#[^)\s]*)?\)")


@dataclass(frozen=True)
class Page:
    source: str
    canonical: str
    title: str
    description: str
    weight: int
    body: str

    @property
    def markdown_path(self) -> str:
        return markdown_path(self.canonical)

    @property
    def section(self) -> str:
        parts = self.source.removeprefix("content/").split("/")
        return parts[0] if len(parts) > 1 else ""

    @property
    def is_section_index(self) -> bool:
        return self.source.endswith("/_index.md") or self.source == "content/_index.md"


def markdown_path(canonical: str) -> str:
    return "/docs/index.md" if canonical == "/docs" else f"{canonical}.md"


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def split_front_matter(text: str, source: str) -> tuple[dict[str, object], str]:
    if text.startswith("+++\n"):
        end = text.index("\n+++\n", 4)
        return tomllib.loads(text[4:end]), text[end + 5 :]
    if text.startswith("---\n"):
        end = text.index("\n---\n", 4)
        values: dict[str, object] = {}
        for line in text[4:end].splitlines():
            key, separator, value = line.partition(":")
            if not separator:
                raise ValueError(f"unsupported front matter line in {source}: {line!r}")
            values[key.strip()] = unquote(value)
        return values, text[end + 5 :]
    raise ValueError(f"{source} has no front matter")


def card_grid(match: re.Match[str]) -> str:
    call = ast.parse(f"card_grid({match.group('args')})", mode="eval").body
    assert isinstance(call, ast.Call)
    arguments = {keyword.arg: ast.literal_eval(keyword.value) for keyword in call.keywords}
    rows = zip(arguments["titles"], arguments["hrefs"], arguments["descriptions"], strict=True)
    return "\n".join(f"- [{title}]({href}): {description}" for title, href, description in rows)


def aside(match: re.Match[str]) -> str:
    lines = [line.strip() for line in match.group("body").strip().splitlines()]
    text = " ".join(line for line in lines if line)
    return f"> **{match.group('kind').capitalize()}:** {text}"


def convert(body: str, canonical_by_source: dict[str, str], routes: set[str]) -> str:
    body = CARD_GRID.sub(card_grid, body)
    body = ASIDE.sub(aside, body)

    def internal(match: re.Match[str]) -> str:
        source = f"content/{match.group('source')}"
        if source not in canonical_by_source:
            raise ValueError(f"internal link to an unknown page: @/{match.group('source')}")
        fragment = match.group("fragment") or ""
        return f"]({CANONICAL_ORIGIN}{markdown_path(canonical_by_source[source])}{fragment})"

    def docs(match: re.Match[str]) -> str:
        path = match.group("path").rstrip("/") or "/docs"
        target = markdown_path(path) if path in routes else path
        return f"]({CANONICAL_ORIGIN}{target}{match.group('fragment') or ''})"

    body = INTERNAL_LINK.sub(internal, body)
    body = DOCS_LINK.sub(docs, body)
    for leftover in ("{{", "{%", "](@/"):
        if leftover in body:
            raise ValueError(f"unconverted Zola syntax {leftover!r} remains")
    return body.strip() + "\n"


def load_pages(site_root: Path) -> list[Page]:
    manifest = tomllib.loads((site_root / "routes.toml").read_text(encoding="utf-8"))
    canonical_by_source = {route["source"]: route["canonical"] for route in manifest["routes"]}
    routes = set(canonical_by_source.values())
    pages = []
    for source, canonical in canonical_by_source.items():
        front_matter, body = split_front_matter((site_root / source).read_text(encoding="utf-8"), source)
        try:
            converted = convert(body, canonical_by_source, routes)
        except ValueError as error:
            raise ValueError(f"{source}: {error}") from error
        pages.append(
            Page(
                source=source,
                canonical=canonical,
                title=str(front_matter["title"]),
                description=str(front_matter.get("description", "")),
                weight=int(front_matter.get("weight", 0)),
                body=converted,
            )
        )
    return pages


def ordered(pages: list[Page]) -> list[tuple[Page, list[Page]]]:
    """Sections in sidebar order, each followed by its pages by weight."""
    indexes = {page.section: page for page in pages if page.is_section_index}
    root = indexes.pop("")
    groups = [(root, sorted((page for page in pages if page.section == "" and page is not root), key=lambda page: (page.weight, page.source)))]
    for name, index in sorted(indexes.items(), key=lambda item: (item[1].weight, item[0])):
        members = sorted((page for page in pages if page.section == name and page is not index), key=lambda page: (page.weight, page.source))
        groups.append((index, members))
    return groups


def render_page(page: Page) -> str:
    lines = [f"# {page.title}", ""]
    if page.description:
        lines += [f"> {page.description}", ""]
    lines += [f"Source: {CANONICAL_ORIGIN}{page.canonical}", "", page.body]
    return "\n".join(lines)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--site-root", type=Path, required=True)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    pages = load_pages(args.site_root)
    groups = ordered(pages)
    root = groups[0][0]

    for page in pages:
        write(args.output / page.markdown_path.removeprefix("/docs/"), render_page(page))

    index = [
        "# Codewire",
        "",
        f"> {root.description}",
        "",
        f"Every page below is Markdown. The whole documentation is one file at {CANONICAL_ORIGIN}/docs/llms-full.txt.",
        "",
    ]
    full = []
    for section_index, members in groups:
        heading = "Overview" if section_index is root else section_index.title
        index += [f"## {heading}", ""]
        for page in [section_index, *members]:
            index.append(f"- [{page.title}]({CANONICAL_ORIGIN}{page.markdown_path}): {page.description}")
            full.append(render_page(page))
        index.append("")
    write(args.output / "llms.txt", "\n".join(index))
    write(args.output / "llms-full.txt", "\n".join(full))


if __name__ == "__main__":
    main()
