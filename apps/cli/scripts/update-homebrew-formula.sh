#!/bin/bash
# Update Homebrew formula with checksums from a release
set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v0.1.0"
    exit 1
fi

VERSION="$1"
FORMULA_FILE="Formula/codewire.rb"

echo "Updating Homebrew formula for ${VERSION}..."

# Download checksums
echo "Downloading SHA256SUMS..."
curl -fsSL -o /tmp/SHA256SUMS "https://github.com/codewiresh/codewire/releases/download/${VERSION}/SHA256SUMS"

# Extract checksums
ARM64_MAC=$(grep "aarch64-apple-darwin" /tmp/SHA256SUMS | awk '{print $1}')
X64_MAC=$(grep "x86_64-apple-darwin" /tmp/SHA256SUMS | awk '{print $1}')
ARM64_LINUX=$(grep "aarch64-unknown-linux-gnu" /tmp/SHA256SUMS | awk '{print $1}')
X64_LINUX=$(grep "x86_64-unknown-linux-musl" /tmp/SHA256SUMS | awk '{print $1}')

echo ""
echo "Checksums found:"
echo "  macOS ARM64:   ${ARM64_MAC}"
echo "  macOS x86_64:  ${X64_MAC}"
echo "  Linux ARM64:   ${ARM64_LINUX}"
echo "  Linux x86_64:  ${X64_LINUX}"
echo ""

# Update formula
echo "Updating ${FORMULA_FILE}..."

# Update version
sed -i.bak "s/version \".*\"/version \"${VERSION#v}\"/" "$FORMULA_FILE"

# Update checksums
sed -i.bak "s/sha256 \"PUT_ARM64_SHA256_HERE\"/sha256 \"${ARM64_MAC}\"/" "$FORMULA_FILE"
sed -i.bak "s/sha256 \"PUT_X86_64_SHA256_HERE\"/sha256 \"${X64_MAC}\"/" "$FORMULA_FILE"
sed -i.bak "s/sha256 \"PUT_LINUX_ARM64_SHA256_HERE\"/sha256 \"${ARM64_LINUX}\"/" "$FORMULA_FILE"
sed -i.bak "s/sha256 \"PUT_LINUX_X86_64_SHA256_HERE\"/sha256 \"${X64_LINUX}\"/" "$FORMULA_FILE"

# Clean up backup
rm -f "${FORMULA_FILE}.bak"

echo "✓ Formula updated successfully!"
echo ""
echo "Next steps:"
echo "  1. Test the formula: brew install --build-from-source ./Formula/codewire.rb"
echo "  2. Verify it works: cw --help"
echo "  3. Commit changes: git add Formula/codewire.rb && git commit -m 'Update formula to ${VERSION}'"
echo "  4. Push to tap repo"
