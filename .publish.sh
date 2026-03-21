#!/bin/bash
# Release automation script for dig-rs

set -e

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

echo "Preparing release for version $VERSION"

# Update version in Cargo.toml
sed -i "s/^version = .*/version = \"$VERSION\"/" Cargo.toml
sed -i "s/^version = .*/version = \"$VERSION\"/" crates/dig/Cargo.toml
sed -i "s/^version = .*/version = \"$VERSION\"/" crates/dig-core/Cargo.toml
sed -i "s/^version = .*/version = \"$VERSION\"/" crates/dig-output/Cargo.toml

# Update CHANGELOG
cat > CHANGELOG.md.new << EOF
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [$VERSION] - $(date +%Y-%m-%d)

### Added
- Version $VERSION release

### Changed
- N/A

### Deprecated
- N/A

### Removed
- N/A

### Fixed
- N/A

### Security
- N/A

[Unreleased]: https://github.com/tianrking/dig-rs/compare/v$VERSION...HEAD
[$VERSION]: https://github.com/tianrking/dig-rs/releases/tag/v$VERSION
EOF

mv CHANGELOG.md.new CHANGELOG.md

# Commit changes
git add -A
git commit -m "Release version $VERSION"

# Create tag
git tag -a "v$VERSION" -m "Version $VERSION"

# Push to GitHub
echo "Release prepared! Review the changes then:"
echo "  git push origin main"
echo "  git push origin v$VERSION"
