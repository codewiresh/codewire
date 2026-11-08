# Codewire Zola documentation

This directory is the source of the documentation served by the Rust web
runtime. Zola is a pinned build dependency and is not present in the final
image.

## Trusted local build

Use Zola 0.22.1 only. Before extracting or executing a downloaded archive,
verify it with the checked-in checksum and offline Sigstore bundle:

```bash
apps/docs/zola/tests/verify-zola-release.sh /path/to/zola-v0.22.1-x86_64-unknown-linux-gnu.tar.gz
```

After extracting the verified binary, build through the deterministic wrapper:

```bash
ZOLA_BIN=/path/to/zola apps/docs/zola/build.sh /tmp/codewire-docs
ZOLA_BIN=/path/to/zola apps/docs/zola/tests/verify.sh
```

The wrapper normalizes Zola's nondeterministic Fuse index ordering and emits
the no-trailing-slash link contract consumed by the Rust server. `routes.toml`
is the exact route mount and redirect manifest: one entry per page and per
section landing page, and `tests/verify_site.py` pins the count.

Pages use YAML front matter (`title`, `description`, `weight`); section
landing pages (`_index.md`) use TOML front matter and render with
`section.html`. The sidebar in `templates/base.html` lists every route by
hand, so adding a page means adding its route, its sidebar entry and the
count in `tests/verify_site.py` and `tests/browser.mjs`. Within a section,
`weight` follows the sidebar order, which is also the order of `llms.txt`.

A page that moves keeps its old URL with `aliases: ["/old/path"]` (relative
to `/docs`). Zola writes a redirect page there from
`templates/internal/alias.html`: a relative meta refresh, since the docs CSP
forbids scripts. `tests/verify_site.py` checks every alias and its target.

After Zola, `build.sh` runs `export_markdown.py`, which writes the
machine-readable documentation from the page sources: every route as
Markdown at its canonical path plus `.md` (`/docs/index.md` for the
overview), `llms.txt` (an index) and `llms-full.txt` (every page in one
file). Internal `@/` links become absolute links to the Markdown copies and
shortcodes become plain Markdown; a shortcode the exporter does not know fails
the build. The Rust server also serves the two text files at `/llms.txt` and
`/llms-full.txt`.

The OpenSSF page is the one HTML exception to checked-in-only content: its
shortcode fetches the public Scorecard and Best Practices APIs at build time.
An unavailable API produces a source-linked fallback, never a failed build or a
browser request to OpenSSF. The Markdown copy links to those authoritative
results instead. `tests/verify.sh` disables remote loading for its two
reproducibility builds, then uses the checked-in JSON fixtures to verify the
populated report and the unavailable state. `CODEWIRE_OPENSSF_OFFLINE=1` also
disables remote loading for an offline local build. The snapshot records
`CODEWIRE_BUILD_TIMESTAMP`; `build.sh` sets it from UTC when the caller has not
provided a reproducible-build timestamp.

## Production-equivalent container

The dashboard image uses a digest-pinned Debian build stage, checksum-bound
official Zola archives, no package installation, and a non-root distroless
runtime:

```bash
docker buildx bake --file docker-bake.hcl --pull --load \
  --set 'dashboard.tags=codewire-dashboard:local' dashboard
docker run --rm -p 5173:5173 \
  -e CODEWIRE_PUBLIC_ORIGIN=http://127.0.0.1:5173 \
  codewire-dashboard:local
```

The generated site is mounted at `/docs` using `routes.toml`. The production
image contains only that output and the Rust server, never Zola or a compiler.

The browser verification uses the repository's already-locked Playwright
dependency directly. It rejects requests to any host outside the configured
preview origin and writes desktop/mobile evidence only to the selected
temporary directory.
