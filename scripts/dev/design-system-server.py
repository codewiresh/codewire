#!/usr/bin/env python3
"""Serve the editable design system with production browser asset paths."""

import argparse
import errno
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
HTMX_ASSET = REPOSITORY_ROOT / "crates" / "codewire-dashboard-web" / "assets" / "htmx-2.0.10.min.js"


class DesignSystemHandler(SimpleHTTPRequestHandler):
    """Keep the production font URLs valid in the static authoring preview."""

    def translate_path(self, path: str) -> str:
        if urlsplit(path).path == "/assets/codewire/htmx-2.0.10.min.js":
            return str(HTMX_ASSET)
        font_name = FONT_ROUTES.get(urlsplit(path).path)
        if font_name is not None:
            return str(FONT_ROOT / font_name)
        terminal_asset = TERMINAL_ASSET_ROUTES.get(urlsplit(path).path)
        if terminal_asset is not None:
            return str(TERMINAL_ASSET_ROOT / terminal_asset)
        return super().translate_path(path)


class DesignSystemServer(ThreadingHTTPServer):
    """Never share a port with another listener; bind() moves to the next one."""

    allow_reuse_port = False


def port_range(value: str) -> range:
    """Parse PORT or FIRST-LAST into the ports to try in order."""
    first, _, last = value.partition("-")
    try:
        ports = range(int(first), int(last or first) + 1)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected PORT or FIRST-LAST, got {value!r}") from None
    if not ports or ports.start < 0 or ports.stop > 65536:
        raise argparse.ArgumentTypeError(f"invalid port range {value!r}")
    return ports


def bind(ports: range, handler) -> DesignSystemServer:
    """Bind the first free loopback port, so concurrent previews can coexist."""
    for port in ports:
        try:
            return DesignSystemServer(("127.0.0.1", port), handler)
        except OSError as error:
            if error.errno != errno.EADDRINUSE:
                raise
    raise SystemExit(f"no free loopback port in {ports.start}-{ports.stop - 1}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port",
        type=port_range,
        default=port_range("4174"),
        help="loopback PORT or FIRST-LAST range; the first free port is used (default: 4174)",
    )
    args = parser.parse_args()
    handler = partial(DesignSystemHandler, directory=str(DESIGN_ROOT))
    with bind(args.port, handler) as server:
        port = server.server_address[1]
        print(f"Codewire design system: http://127.0.0.1:{port}/reference/fixtures/", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
