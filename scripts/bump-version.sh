#!/usr/bin/env bash
set -euo pipefail

# Ensure script is run from project root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <new-version> (e.g. 0.2.3 or v0.2.3)"
    exit 1
fi

NEW_VERSION="${1#v}"

if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "Error: Version '$NEW_VERSION' is not a valid SemVer string (e.g. 0.2.3)."
    exit 1
fi

OLD_VERSION=$(grep -E '^version = ' Cargo.toml | head -1 | cut -d '"' -f 2)

if [ "$OLD_VERSION" == "$NEW_VERSION" ]; then
    echo "Version is already $NEW_VERSION. Nothing to do."
    exit 0
fi

echo "==> Bumping workspace version from ${OLD_VERSION} to ${NEW_VERSION}..."

# Update root Cargo.toml [workspace.package] version
sed -i.bak -E "s/^version = \"${OLD_VERSION}\"/version = \"${NEW_VERSION}\"/" Cargo.toml
rm -f Cargo.toml.bak

# Update internal dependency version strings for inter-crate paths in Cargo.toml
sed -i.bak -E "s/(zmanager-[a-z-]+ = \{ path = \"[^\"]+\", version = \")[^\"]+(\" \})/\1${NEW_VERSION}\2/g" Cargo.toml
rm -f Cargo.toml.bak

# Update version references with strict anchors to prevent unintended replacements

if [ -f docs/INSTALL.md ]; then
    sed -i.bak -E "s/(ZMANAGER_VERSION=v)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" docs/INSTALL.md
    sed -i.bak -E "s/(releases\/download\/v)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" docs/INSTALL.md
    sed -i.bak -E "s/^([[:space:]]*)v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?[[:space:]]*\\\\/\1v${NEW_VERSION} \\\\/g" docs/INSTALL.md
    rm -f docs/INSTALL.md.bak
fi

if [ -f RELEASE.md ]; then
    sed -i.bak -E "s/(git tag v)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" RELEASE.md
    sed -i.bak -E "s/^([[:space:]]*)v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?[[:space:]]*\\\\/\1v${NEW_VERSION} \\\\/g" RELEASE.md
    sed -i.bak -E "s/(releases\/download\/v)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" RELEASE.md
    sed -i.bak -E "s/(TzapOrg\.ZManagerCLI\\\\)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" RELEASE.md
    sed -i.bak -E "s/(release-notes\/)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" RELEASE.md
    sed -i.bak -E "s/(\`v)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\` GitHub release)/\1${NEW_VERSION}\3/g" RELEASE.md
    rm -f RELEASE.md.bak
fi

if [ -f crates/zmanager-cli/tests/help_cli.rs ]; then
    sed -i.bak -E "s/(assert_eq!\(env!\(\"CARGO_PKG_VERSION\"\), \")[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\"\);)/\1${NEW_VERSION}\3/g" crates/zmanager-cli/tests/help_cli.rs
    rm -f crates/zmanager-cli/tests/help_cli.rs.bak
fi

if [ -f .github/workflows/update-homebrew-tap.yml ]; then
    sed -i.bak -E "s/(e\.g\. v)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?/\1${NEW_VERSION}/g" .github/workflows/update-homebrew-tap.yml
    rm -f .github/workflows/update-homebrew-tap.yml.bak
fi

echo "==> Updating root Cargo.lock..."
cargo check --workspace

echo "==> Updating fuzz/Cargo.lock..."
cargo check --manifest-path fuzz/Cargo.toml

echo "==> Verifying --locked compatibility..."
cargo check --workspace --locked
cargo check --manifest-path fuzz/Cargo.toml --locked

echo "Successfully bumped workspace version to ${NEW_VERSION}!"
