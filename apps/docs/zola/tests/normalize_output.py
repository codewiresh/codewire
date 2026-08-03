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


if __name__ == "__main__":
    main()
