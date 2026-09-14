#!/usr/bin/env python3
"""Serve the editable design system with production font asset paths."""

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DESIGN_ROOT = REPOSITORY_ROOT / "packages" / "codewire-design"
FONT_ROOT = REPOSITORY_ROOT / "crates" / "codewire-dashboard-web" / "assets" / "fonts"
FONT_ROUTES = {
    "/assets/codewire/fonts/ibm-plex-mono-regular-2.5.0.woff2": "IBMPlexMono-Regular-2.5.0.woff2",
    "/assets/codewire/fonts/ibm-plex-mono-medium-2.5.0.woff2": "IBMPlexMono-Medium-2.5.0.woff2",
    "/assets/codewire/fonts/ibm-plex-mono-semibold-2.5.0.woff2": "IBMPlexMono-SemiBold-2.5.0.woff2",
}
TERMINAL_ASSET_ROOT = REPOSITORY_ROOT / "crates" / "codewire-dashboard-web" / "assets" / "xterm"
TERMINAL_ASSET_ROUTES = {
    f"/assets/codewire/{name}": name for name in (
        "xterm-6.0.0.js", "xterm-6.0.0.css", "addon-fit-0.11.0.js", "addon-web-links-0.12.0.js"
    )
}


class DesignSystemHandler(SimpleHTTPRequestHandler):
    """Keep the production font URLs valid in the static authoring preview."""

    def translate_path(self, path: str) -> str:
        font_name = FONT_ROUTES.get(urlsplit(path).path)
        if font_name is not None:
            return str(FONT_ROOT / font_name)
        terminal_asset = TERMINAL_ASSET_ROUTES.get(urlsplit(path).path)
        if terminal_asset is not None:
            return str(TERMINAL_ASSET_ROOT / terminal_asset)
        return super().translate_path(path)


def main() -> None:
    handler = partial(DesignSystemHandler, directory=str(DESIGN_ROOT))
    with ThreadingHTTPServer(("127.0.0.1", 4174), handler) as server:
        print("Codewire design system: http://127.0.0.1:4174/reference/fixtures/")
        server.serve_forever()


if __name__ == "__main__":
    main()
