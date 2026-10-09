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
is the exact 30-route mount and redirect manifest.

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
