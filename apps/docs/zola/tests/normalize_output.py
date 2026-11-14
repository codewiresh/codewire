#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def canonical_url(value: str) -> str:
    parsed = urlsplit(value)
    path = parsed.path.rstrip("/") or "/docs"
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    index = args.output / "search_index.en.json"
    entries = json.loads(index.read_text(encoding="utf-8"))
    for entry in entries:
        entry["url"] = canonical_url(entry["url"])
    entries.sort(key=lambda entry: entry["url"])
    temporary = index.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(entries, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.replace(index)

    trailing_docs_href = re.compile(
        r'href="https://codewire\.sh(?P<path>/docs(?:/[^"#?]*)?)/(?P<suffix>(?:[#?][^"]*)?)"'
    )
    for html in args.output.rglob("*.html"):
        source = html.read_text(encoding="utf-8")
        normalized = trailing_docs_href.sub(
            lambda match: f'href="{match.group("path")}{match.group("suffix")}"',
            source,
        )
        if normalized != source:
            temporary_html = html.with_suffix(".html.tmp")
            temporary_html.write_text(normalized, encoding="utf-8")
            temporary_html.replace(html)

    # The docs load no font (their CSP is font-src 'none'), but the shared
    # design stylesheet they import declares the site's Geist Mono, so every
    # page asked for a font its own policy refuses (#4674). The docs CSS drops
    # that declaration and keeps the system fonts it renders with today.
    stylesheet = args.output / "docs.css"
    css = stylesheet.read_text(encoding="utf-8")
    font_face = re.compile(r"@font-face\{[^}]*\}")
    declarations = font_face.findall(css)
    if len(declarations) != 1 or "geist-mono" not in declarations[0]:
        raise SystemExit(f"docs.css: expected the one Geist Mono @font-face, found {declarations}")
    temporary_css = stylesheet.with_suffix(".css.tmp")
    temporary_css.write_text(font_face.sub("", css), encoding="utf-8")
    temporary_css.replace(stylesheet)


if __name__ == "__main__":
    main()
