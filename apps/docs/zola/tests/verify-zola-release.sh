#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/official-zola-archive" >&2
  exit 2
fi

archive="$1"
archive_name="$(basename "$archive")"
case "$archive_name" in
  zola-v0.22.1-aarch64-unknown-linux-gnu.tar.gz)
    digest="8af437ec6352f33ccd24d7a1cfcb54a3db95d3ce376dc69525b4ef3fb6b8c1d1"
    expected_binary_digest="8582915b9949adaad6a2127530295f9b5ebcea15da56f047229e9a59ffdf68c7"
    ;;
  zola-v0.22.1-x86_64-unknown-linux-gnu.tar.gz)
    digest="0ca09aa40376aaa9ddfb512ff9ad963262ef95edb0d0f2d5ec6961b6f5cf22ef"
    expected_binary_digest="45de6b2559aba4df42199dc6b0161acb914d37be4ccaa03297cd4a26c8e14042"
    ;;
  *)
    echo "unapproved Zola archive: $archive_name" >&2
    exit 1
    ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
actual_digest="$(sha256sum "$archive" | cut -d' ' -f1)"
if [[ "$actual_digest" != "$digest" ]]; then
  echo "Zola archive checksum mismatch" >&2
  exit 1
fi
actual_binary_digest="$(tar -xOf "$archive" zola | sha256sum | cut -d' ' -f1)"
if [[ "$actual_binary_digest" != "$expected_binary_digest" ]]; then
  echo "Zola binary checksum mismatch" >&2
  exit 1
fi
actual_license_digest="$(tar -xOf "$archive" LICENSE | sha256sum | cut -d' ' -f1)"
if [[ "$actual_license_digest" != "6fc9e709ccbfe0d77fbffa2427a983282be2eb88e47b1cdb49f21a83b4d1e665" ]]; then
  echo "Zola release license checksum mismatch" >&2
  exit 1
fi

bundle="$script_dir/provenance/sha256-${digest}.jsonl"
gh attestation verify "$archive" \
  --bundle "$bundle" \
  --repo getzola/zola \
  --source-ref refs/tags/v0.22.1 \
  --source-digest 29540e9897dbe8aca388b13f7bdf615985f6ca2c \
  --signer-digest 29540e9897dbe8aca388b13f7bdf615985f6ca2c \
  --cert-identity 'https://github.com/getzola/zola/.github/workflows/release.yml@refs/tags/v0.22.1' \
  --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --deny-self-hosted-runners >/dev/null

printf 'verified %s archive-sha256:%s binary-sha256:%s\n' "$archive_name" "$digest" "$actual_binary_digest"
