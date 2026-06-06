#!/bin/bash 

set -euo pipefail

VERSION="$(jq -r '.version' manifest.json)"
PACKAGE_NAME="hash-passwords-${VERSION}.zip"

rm -rf dist
mkdir -p dist/package/icons

# Explicit allowlist keeps CLI and unrelated files out of the release artifact.

FILES=(
manifest.json
popup.html
popup.js
popup.css
md5.js
pwdhash-core.js
domain-extractor.js
hashed-password.js
LICENSE
PRIVACY.md
THIRD_PARTY_LICENSES.md
)

for file in "${FILES[@]}"; do
  [[ -f "$file" ]] || { echo "Missing required file: $file"; exit 1; }
  cp "$file" dist/package/
done

cp -r icons/. dist/package/icons/

(
  cd dist/package
  zip -r "../${PACKAGE_NAME}" .
)
