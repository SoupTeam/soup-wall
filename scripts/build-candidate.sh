#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

EXPECTED_RUSTC="1.89.0"
NODE_VERSION="v22.22.0"
NODE_TAR="node-${NODE_VERSION}-linux-x64.tar.xz"
NODE_URL="https://nodejs.org/dist/${NODE_VERSION}/${NODE_TAR}"
NODE_SHA256="9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37"

KIT_NAME="soup-wall-linux-amd64"
TARGET_DIR="$(pwd)/target/${KIT_NAME}"
MANIFEST_FILE="${TARGET_DIR}/manifest.json"

CURRENT_RUSTC=$(rustc --version | awk '{print $2}')
if [[ "$CURRENT_RUSTC" != "$EXPECTED_RUSTC" ]]; then
    echo "CRITICAL: Compiler identity drift. Expected $EXPECTED_RUSTC, got $CURRENT_RUSTC"
    exit 1
fi

rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR/bin" "$TARGET_DIR/assets" "$TARGET_DIR/scripts" "$TARGET_DIR/profiles/mcp" "$TARGET_DIR/npm-cache"

cargo build --release --locked --workspace

for binary in agentfw llm-firewall soup-wall-bench; do
    if [ ! -x "target/release/${binary}" ]; then
        echo "CRITICAL: Required executable ${binary} is missing!"
        exit 1
    fi
    cp "target/release/${binary}" "$TARGET_DIR/bin/"
done

"$TARGET_DIR/bin/agentfw" classifier-package build --classifier rev2 --source . --out "$TARGET_DIR/assets/baseline.classifier"
cp -R rule_baseline "$TARGET_DIR/rule_baseline"

curl -sL -o "$TARGET_DIR/$NODE_TAR" "$NODE_URL"
if ! echo "$NODE_SHA256  $TARGET_DIR/$NODE_TAR" | sha256sum -c -; then
    echo "CRITICAL: Node archive digest mismatch"
    exit 1
fi

echo "=> Populating NPM cache..."
tar -xf "$TARGET_DIR/$NODE_TAR" -C target
export PATH="$(pwd)/target/node-${NODE_VERSION}-linux-x64/bin:$PATH"
(cd profiles/mcp/filesystem-readonly-v1 && npm ci --cache "$TARGET_DIR/npm-cache" --prefer-offline)

cp "$(which bwrap)" "$TARGET_DIR/bin/bwrap"
cp scripts/install-sou62-filesystem-profile.py "$TARGET_DIR/scripts/"
cp -R profiles/mcp/filesystem-readonly-v1 "$TARGET_DIR/profiles/mcp/"
cp LICENSE NOTICE README.md "$TARGET_DIR/" 2>/dev/null || true

SOURCE_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
CARGO_LOCK_HASH=$(sha256sum Cargo.lock | awk '{print $1}')

cat <<EOF > "$MANIFEST_FILE"
{
  "schema_version": 2,
  "identities": {
    "compiler": "rustc ${CURRENT_RUSTC}",
    "source_commit": "${SOURCE_COMMIT}",
    "cargo_lock_sha256": "${CARGO_LOCK_HASH}"
  },
  "files": {
EOF

find "$TARGET_DIR" -type f ! -name "manifest.json" | sort | while read -r filepath; do
    rel_path="${filepath#$TARGET_DIR/}"
    hash_val=$(sha256sum "$filepath" | awk '{print $1}')
    echo "    \"$rel_path\": \"$hash_val\"," >> "$MANIFEST_FILE"
done

sed -i '$ s/,$//' "$MANIFEST_FILE"
cat <<EOF >> "$MANIFEST_FILE"
  }
}
EOF

tar -czf "target/${KIT_NAME}.tar.gz" -C target "${KIT_NAME}"