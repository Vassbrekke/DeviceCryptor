#!/usr/bin/env bash
# Install DeviceCryptor CLI, GUI, man page, and desktop launcher (Linux).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PREFIX="${PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
MAN_DIR="$PREFIX/share/man/man1"
APP_DIR="$PREFIX/share/applications"
mkdir -p "$BIN_DIR" "$MAN_DIR" "$APP_DIR"

echo "building release dc and devicecryptor…"
cargo build -p dc-cli -p dc-gui --release
install -m 755 "$ROOT/target/release/dc" "$BIN_DIR/dc"
install -m 755 "$ROOT/target/release/devicecryptor" "$BIN_DIR/devicecryptor"
install -m 644 "$ROOT/dist/dc.1" "$MAN_DIR/dc.1"

DESKTOP="$APP_DIR/devicecryptor.desktop"
sed "s|@BIN@|$BIN_DIR/devicecryptor|" "$ROOT/dist/devicecryptor.desktop" > "$DESKTOP"
chmod 644 "$DESKTOP"

echo "installed:"
echo "  $BIN_DIR/dc"
echo "  $BIN_DIR/devicecryptor"
echo "  $MAN_DIR/dc.1"
echo "  $DESKTOP"
echo "ensure $BIN_DIR is on your PATH"
"$BIN_DIR/dc" --version
