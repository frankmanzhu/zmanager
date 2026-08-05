#!/usr/bin/env bash
# Generates the Kotlin and Swift UniFFI bindings from the zmanager-ffi UDL.
#
# Used by:
#   - scripts/regenerate-bindings.sh — writes into the zmanager-mobile repo
#   - CI (.github/workflows/regenerate-uniffi-bindings.yml) — writes into
#     crates/zmanager-ffi/bindings/
#
# Set REGEN_KOTLIN_DIR and REGEN_SWIFT_DIR to the output directories:
#   - Kotlin: the java source root (the package path from uniffi.toml is
#     appended, e.g. org/tzap/zmanager/mobile/bridge/generated/)
#   - Swift:  the directory that receives the generated module files directly
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="$ROOT/crates/zmanager-ffi"
UDL_FILE="$CRATE_DIR/src/zmanager_ffi.udl"
CONFIG_FILE="$CRATE_DIR/uniffi/uniffi.toml"

REGEN_KOTLIN_DIR="${REGEN_KOTLIN_DIR:-}"
REGEN_SWIFT_DIR="${REGEN_SWIFT_DIR:-}"
if [[ -z "$REGEN_KOTLIN_DIR" || -z "$REGEN_SWIFT_DIR" ]]; then
  echo "usage: REGEN_KOTLIN_DIR=<java-root> REGEN_SWIFT_DIR=<swift-dir> $0" >&2
  exit 1
fi

mkdir -p "$REGEN_KOTLIN_DIR" "$REGEN_SWIFT_DIR"

(
  cd "$CRATE_DIR"
  cargo run --bin uniffi-bindgen generate \
    --language kotlin \
    --out-dir "$REGEN_KOTLIN_DIR" \
    --config "$CONFIG_FILE" \
    --no-format \
    "$UDL_FILE"
  cargo run --bin uniffi-bindgen generate \
    --language swift \
    --out-dir "$REGEN_SWIFT_DIR" \
    --no-format \
    "$UDL_FILE"
)

echo "Kotlin bindings: $REGEN_KOTLIN_DIR"
echo "Swift bindings: $REGEN_SWIFT_DIR"
