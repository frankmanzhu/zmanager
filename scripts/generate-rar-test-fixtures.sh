#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVES="$ROOT/fixtures/archives"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zmanager-rar-fixtures.XXXXXX")"
SOURCE="$WORK/rar-fixture"

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

if ! command -v rar >/dev/null 2>&1; then
  echo "rar is required to generate the checked-in RAR test fixtures." >&2
  exit 1
fi

mkdir -p "$SOURCE/docs" "$SOURCE/data"
printf 'RAR multipart fixture\n' > "$SOURCE/docs/readme.txt"
printf '{"fixture":"zmanager"}\n' > "$SOURCE/data/manifest.json"
# Store a known, volume-spanning payload. The core/FFI/CLI tests compare all
# 196608 bytes, so a successful command alone cannot mask truncation.
dd if=/dev/zero of="$SOURCE/data/stream.bin" bs=65536 count=3 status=none
touch -t 202001010000 "$SOURCE/docs/readme.txt" "$SOURCE/data/manifest.json" "$SOURCE/data/stream.bin"

rm -f "$ARCHIVES"/rar5-multipart.part*.rar "$ARCHIVES"/rar5-passworded-multipart.part*.rar
(
  cd "$WORK"
  rar a -idq -ma5 -m0 -v64k "$ARCHIVES/rar5-multipart.rar" rar-fixture
  rar a -idq -ma5 -m0 -v64k -hpzmanager-rar-fixture-password \
    "$ARCHIVES/rar5-passworded-multipart.rar" rar-fixture
)

echo "Generated RAR test fixtures in $ARCHIVES"
