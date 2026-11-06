#!/usr/bin/env bash
# Build argus-crypto-stack for every platform Argus ships and install the
# resulting shared libraries over the vendored signer files.
#
# Requirements: rustup targets for the four platforms and `cargo-zigbuild`
# (`cargo install cargo-zigbuild`) for the cross builds.
#
# Usage:
#   tools/build_and_install.sh
#   ARGUS_DIR=/path/to/Argus tools/build_and_install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARGUS="${ARGUS_DIR:-$ROOT/../Argus}"
SIGNERS="$ARGUS/argus/perpetuals/lighter/signers"

GO_BACKUP="${GO_SIGNER_BACKUP:-$HOME/.cache/argus-crypto-stack/go-signer-darwin-arm64.orig.dylib}"

cd "$ROOT"

# Keep the Go oracle for tools/diff_harness.py, but only if the vendored file
# is still the Go build (never overwrite a good backup with ACS).
SRC="$SIGNERS/lighter-signer-darwin-arm64.dylib"
if [ -f "$SRC" ] && ! nm -gU "$SRC" 2>/dev/null | grep -q HlSignAction; then
    mkdir -p "$(dirname "$GO_BACKUP")"
    cp "$SRC" "$GO_BACKUP"
    echo "==> backed up Go signer to $GO_BACKUP"
fi

echo "==> darwin-arm64 (native)"
cargo build --release
echo "==> darwin-amd64"
cargo zigbuild --release --target x86_64-apple-darwin
echo "==> linux-amd64"
cargo zigbuild --release --target x86_64-unknown-linux-gnu
echo "==> linux-arm64"
cargo zigbuild --release --target aarch64-unknown-linux-gnu

install -m 755 target/release/libargus_crypto_stack.dylib \
    "$SIGNERS/lighter-signer-darwin-arm64.dylib"
install -m 755 target/x86_64-apple-darwin/release/libargus_crypto_stack.dylib \
    "$SIGNERS/lighter-signer-darwin-amd64.dylib"
install -m 755 target/x86_64-unknown-linux-gnu/release/libargus_crypto_stack.so \
    "$SIGNERS/lighter-signer-linux-amd64.so"
install -m 755 target/aarch64-unknown-linux-gnu/release/libargus_crypto_stack.so \
    "$SIGNERS/lighter-signer-linux-arm64.so"

echo "Installed argus-crypto-stack into $SIGNERS"
