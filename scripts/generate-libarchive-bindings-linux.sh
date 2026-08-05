#!/usr/bin/env bash
# Regenerates crates/zmanager-libarchive-sys/bindings/linux-musl.rs.
#
# The checked-in bindings let static-musl builds skip bindgen entirely (the
# Alpine packaging container cannot dlopen libclang), mirroring
# bindings/windows-msvc.rs for Windows hosts. Run this on a Linux host that
# has:
#   - Rust (cargo)
#   - clang + libclang (e.g. `sudo apt-get install clang libclang-dev`)
#
# The generator mirrors build.rs::generate_bindings exactly: same wrapper
# header, same allowlists, same -fsigned-char normalization.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="$ROOT/crates/zmanager-libarchive-sys/vendor/libarchive"
OUT="$ROOT/crates/zmanager-libarchive-sys/bindings/linux-musl.rs"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/zm-bindgen-linux.XXXXXX")"

# Resolve the vendored source by version-agnostic glob: bumping the vendor
# directory (libarchive-<version>) must not require touching this script.
SOURCE_DIRS=()
while IFS= read -r -d '' d; do
  SOURCE_DIRS+=("$d")
done < <(find "$VENDOR_DIR" -maxdepth 1 -type d -name "libarchive-*" -print0 2>/dev/null)
if [[ ${#SOURCE_DIRS[@]} -ne 1 ]]; then
  echo "error: expected exactly one libarchive-* directory under $VENDOR_DIR (found ${#SOURCE_DIRS[@]})" >&2
  exit 1
fi
INC="${SOURCE_DIRS[0]}/libarchive"

cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/src"

cat > "$TMP/Cargo.toml" <<EOF
[package]
name = "zm-bindgen-linux"
version = "0.1.0"
edition = "2021"

[build-dependencies]
bindgen = "0.70"
EOF

echo 'fn main() {}' > "$TMP/src/main.rs"

cat > "$TMP/build.rs" <<EOF
fn main() {
    let wrapper = std::env::var("OUT_DIR").unwrap() + "/wrapper.h";
    std::fs::write(&wrapper, "#include <archive.h>\n#include <archive_entry.h>\n").unwrap();
    let inc = "$INC";
    let bindings = bindgen::Builder::default()
        .header(&wrapper)
        .clang_arg("-fsigned-char")
        .allowlist_function("archive_.*")
        .allowlist_type("archive_.*|la_.*|__LA_.*")
        .allowlist_var("ARCHIVE_.*|AE_.*|__LA_.*")
        .clang_arg(format!("-I{inc}"))
        .generate()
        .expect("bindgen failed");
    bindings.write_to_file("$OUT").expect("write failed");
}
EOF

(
  cd "$TMP"
  cargo run --quiet
)

# Bindgen writes the file from scratch; prepend the explanatory header so it
# survives regeneration. Keep this text in sync with the checked-in file.
HEADER='// Pre-generated libarchive bindings for linux-musl targets.
//
// bindgen dlopens libclang while generating bindings, which a static-musl
// build host (the Alpine packaging container) cannot do, so these bindings
// are checked in and used by build.rs whenever CARGO_CFG_TARGET_ENV is musl.
//
// NOTE: the glibc-internal structs (struct stat, _IO_FILE) emitted by bindgen
// are shaped by the host that ran it (x86_64 on CI, aarch64 otherwise).
// Nothing in zmanager dereferences them, so the file stays valid on both
// archs; if that ever changes, generate per-arch.
//
// Regenerate with scripts/generate-libarchive-bindings-linux.sh, or the
// "Regenerate libarchive bindings" workflow (auto-runs on
// vendor/libarchive/** or build.rs changes).
'

TMP_FILE="$(mktemp "${TMPDIR:-/tmp}/zm-bindgen-linux.XXXXXX")"
{
  printf '%s\n' "$HEADER"
  cat "$OUT"
} > "$TMP_FILE"
mv "$TMP_FILE" "$OUT"

echo "Generated $OUT"
