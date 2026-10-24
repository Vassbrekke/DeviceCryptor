#!/usr/bin/env bash
# Locked Linux release build: path remap, SHA256 sums, CycloneDX SBOM.
# `repro` builds dc twice and requires the hashes to match on this toolchain.
# Cross-distro bit-identical binaries are not claimed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f Cargo.lock ]]; then
  echo "Cargo.lock is required" >&2
  exit 1
fi

SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0

RUSTFLAGS_IN="${RUSTFLAGS:-}"
unset RUSTFLAGS

rustflags_for() {
  local flags="--remap-path-prefix=${ROOT}=/build"
  if [[ -n "${1:-}" ]]; then
    flags="--remap-path-prefix=${1}=/build/target ${flags}"
  fi
  if [[ -n "$RUSTFLAGS_IN" ]]; then
    flags="${flags} ${RUSTFLAGS_IN}"
  fi
  printf '%s' "$flags"
}

mode="${1:-build}"

if [[ "$mode" == "repro" ]]; then
  build_cli() {
    local rel="$1"
    local abs="$ROOT/$rel"
    RUSTFLAGS="$(rustflags_for "$abs")" \
      CARGO_TARGET_DIR="$abs" \
      cargo build --release --locked -p dc-cli
  }
  build_cli target/repro-a
  build_cli target/repro-b
  hash_a="$(sha256sum target/repro-a/release/dc | awk '{print $1}')"
  hash_b="$(sha256sum target/repro-b/release/dc | awk '{print $1}')"
  echo "repro-a ${hash_a}"
  echo "repro-b ${hash_b}"
  if [[ "$hash_a" != "$hash_b" ]]; then
    echo "release dc binaries differ on this toolchain" >&2
    exit 1
  fi
  echo "same-toolchain dc hashes match"
  exit 0
fi

if [[ "$mode" != "build" ]]; then
  echo "usage: $0 [build|repro]" >&2
  exit 2
fi

RUSTFLAGS="$(rustflags_for)" cargo build --release --locked -p dc-cli -p dc-gui
mkdir -p dist
sha256sum target/release/dc target/release/devicecryptor | tee dist/SHA256SUMS

if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
  cargo install cargo-cyclonedx --locked
fi
# Writes <package>.cdx.json beside each member Cargo.toml. Path separators are not allowed in the name.
cargo cyclonedx --format json --spec-version 1.5
cp crates/dc-cli/dc-cli.cdx.json dist/dc-cli.cdx.json
cp crates/dc-gui/dc-gui.cdx.json dist/dc-gui.cdx.json
find crates -name '*.cdx.json' -delete
echo "wrote dist/SHA256SUMS dist/dc-cli.cdx.json dist/dc-gui.cdx.json"
