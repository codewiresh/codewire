# Zola 0.22.1 provenance

Only the official `getzola/zola` release archives listed in
`zola-v0.22.1.sha256` are accepted. The release artifacts were verified on
2026-08-02 before extraction or execution.

- Release: `https://github.com/getzola/zola/releases/tag/v0.22.1`
- Source repository: `https://github.com/getzola/zola`
- Source and signer digest: `29540e9897dbe8aca388b13f7bdf615985f6ca2c`
- Source ref: `refs/tags/v0.22.1`
- Certificate identity: `https://github.com/getzola/zola/.github/workflows/release.yml@refs/tags/v0.22.1`
- OIDC issuer: `https://token.actions.githubusercontent.com`
- Workflow: `Release` in `.github/workflows/release.yml`
- Runner environment: GitHub-hosted
- Invocation: `https://github.com/getzola/zola/actions/runs/21242246369/attempts/1`
- Transparency log: `https://rekor.sigstore.dev`
- Rekor integrated times: `2026-01-22T09:05:45Z` (arm64) and
  `2026-01-22T09:06:27Z` (x86_64)
- Extracted binary SHA-256: `8582915b9949adaad6a2127530295f9b5ebcea15da56f047229e9a59ffdf68c7`
  (arm64) and `45de6b2559aba4df42199dc6b0161acb914d37be4ccaa03297cd4a26c8e14042`
  (x86_64)

The checked-in JSONL files are the signed Sigstore bundles downloaded from
GitHub's artifact-attestation API. `verify-zola-release.sh` verifies the
archive checksum, subject digest, exact certificate identity, release ref,
source/signer commit, GitHub OIDC issuer, and hosted-runner boundary without
fetching a new attestation. The Docker build independently binds each remote
`ADD` to the same SHA-256 before extracting or executing Zola.

`ZOLA-LICENSE-EUPL-1.2.txt` is copied byte-for-byte from both verified release
archives (SHA-256 `6fc9e709ccbfe0d77fbffa2427a983282be2eb88e47b1cdb49f21a83b4d1e665`)
and is retained in the development image at `/usr/share/licenses/zola/LICENSE`.

Zola is a build/development tool. WI-9 must copy only generated documentation
into the production Rust image; the Zola binary and its Debian build image do
not cross the runtime boundary.
