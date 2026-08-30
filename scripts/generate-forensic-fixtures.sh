#!/usr/bin/env bash
# Regenerates the forensic / virtual-disk fixtures in fixtures/archives.
#
# Every one of them decodes to the same canonical `payload/` tree as
# `basic.vdi`, so a single expected listing covers the whole family and any
# format whose decode drifts shows up as a payload mismatch rather than a
# format-specific assertion.
#
# Derivation chain:
#
#   basic.vdi  --qemu-img-->  basic.raw  (truncated to the allocated region)
#   basic.raw  --copy------>  basic.dd, basic.dsk, basic.img
#   basic.raw  --qemu-img-->  basic.vhdx, basic.qcow2 (-> copy basic.qcow)
#   basic.raw  --python---->  basic.e01 (EWF1), basic.ex01 (EWF2)
#   basic.raw  --python---->  basic.aff4 (physical AFF4 ImageStream)
#   (cargo)                   basic.ad1, basic-logical.aff4
#
# `basic.dar` is not regenerated here: DAR has no writer in this toolchain, so
# it is a committed fixture. See fixtures/archives/manifest.tsv for provenance.
#
# Requires `qemu-img` (brew install qemu / apt install qemu-utils) and python3.
# The committed fixtures are the source of truth; this script only reproduces
# them, so a machine without qemu-img can still build and test normally.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVES="$ROOT/fixtures/archives"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zmanager-forensic-fixtures.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if ! command -v qemu-img >/dev/null 2>&1; then
  echo "error: qemu-img not found (brew install qemu / apt install qemu-utils)" >&2
  exit 1
fi

# The VDI declares a 64 MiB disk but allocates only ~1 MiB; carrying the zero
# tail would put 64 MiB in the working tree for no extra coverage. 2 MiB keeps
# every allocated sector, which the payload comparison below proves.
RAW_BYTES=2097152

echo "==> basic.raw (from basic.vdi)"
qemu-img convert -f vdi -O raw "$ARCHIVES/basic.vdi" "$WORK/full.raw"
head -c "$RAW_BYTES" "$WORK/full.raw" > "$ARCHIVES/basic.raw"

echo "==> basic.dd / basic.dsk / basic.img (raw aliases)"
for alias in dd dsk img; do
  cp "$ARCHIVES/basic.raw" "$ARCHIVES/basic.$alias"
done

echo "==> basic.vhdx / basic.qcow2 / basic.qcow"
rm -f "$ARCHIVES/basic.vhdx" "$ARCHIVES/basic.qcow2" "$ARCHIVES/basic.qcow"
qemu-img convert -f raw -O vhdx -o block_size=1M,log_size=1M "$ARCHIVES/basic.raw" "$ARCHIVES/basic.vhdx"
qemu-img convert -f raw -O qcow2 -c "$ARCHIVES/basic.raw" "$ARCHIVES/basic.qcow2"
cp "$ARCHIVES/basic.qcow2" "$ARCHIVES/basic.qcow"

echo "==> basic.e01 / basic.ex01"
python3 "$ROOT/scripts/make_ewf_fixtures.py" "$ARCHIVES/basic.raw" "$ARCHIVES/basic.e01" "$ARCHIVES/basic.ex01"

echo "==> basic.aff4 (physical)"
python3 "$ROOT/scripts/make_aff4_fixture.py" "$ARCHIVES/basic.raw" "$ARCHIVES/basic.aff4"

echo "==> basic.ad1 / basic-logical.aff4"
cargo run -q --manifest-path "$ROOT/Cargo.toml" -p zmanager-core --example make_forensic_fixtures

echo "==> refreshing the manifest checksums for these fixtures"
# qemu-img stamps a fresh random GUID into every VHDX it writes, so the mint is
# not byte-reproducible even though the payload is identical. Rewrite the sha256
# column for the rows this script owns rather than leaving the manifest stale.
python3 - "$ARCHIVES/manifest.tsv" "$ARCHIVES" <<'PYEOF'
import hashlib, pathlib, sys
manifest, archives = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
owned = {
    "basic.raw", "basic.dd", "basic.dsk", "basic.img", "basic.vhdx", "basic.qcow2",
    "basic.qcow", "basic.e01", "basic.ex01", "basic.aff4", "basic-logical.aff4",
    "basic.ad1", "basic.dar",
}
lines = []
for line in manifest.read_text().splitlines():
    fields = line.split("\t")
    if len(fields) >= 6 and fields[0] in owned:
        fields[4] = hashlib.sha256((archives / fields[0]).read_bytes()).hexdigest()
        line = "\t".join(fields)
    lines.append(line)
manifest.write_text("\n".join(lines) + "\n")
print(f"    refreshed {len(owned)} manifest rows")
PYEOF

echo "==> verifying every fixture decodes to the canonical payload"
cargo build -q --manifest-path "$ROOT/Cargo.toml" -p zmanager-cli --bin zm
ZM="$ROOT/target/debug/zm"
"$ZM" extract "$ARCHIVES/basic.vdi" -C "$WORK/expected" >/dev/null
status=0
for fixture in basic.raw basic.dd basic.dsk basic.img basic.vhdx basic.qcow2 basic.qcow basic.e01 basic.ex01 basic.aff4; do
  rm -rf "$WORK/got"
  if "$ZM" extract "$ARCHIVES/$fixture" -C "$WORK/got" >/dev/null 2>&1 && diff -r "$WORK/expected" "$WORK/got" >/dev/null 2>&1; then
    echo "    ok   $fixture"
  else
    echo "    FAIL $fixture: payload does not match basic.vdi" >&2
    status=1
  fi
done
# AD1 and the logical AFF4 carry the payload as a captured file tree rather than
# a mounted filesystem, so they are checked by the Rust suites, not by diff here.
for fixture in basic.ad1 basic-logical.aff4 basic.dar; do
  if "$ZM" test "$ARCHIVES/$fixture" >/dev/null 2>&1; then
    echo "    ok   $fixture"
  else
    echo "    FAIL $fixture: zm test failed" >&2
    status=1
  fi
done
exit "$status"
