#!/usr/bin/env bash
# Install DeviceCryptor CLI into ~/.local/bin (Linux).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PREFIX="${PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
mkdir -p "$BIN_DIR"
echo "building release dc…"
cargo build -p dc-cli --release
install -m 755 "$ROOT/target/release/dc" "$BIN_DIR/dc"
echo "installed: $BIN_DIR/dc"
echo "ensure $BIN_DIR is on your PATH"
"$BIN_DIR/dc" --version
