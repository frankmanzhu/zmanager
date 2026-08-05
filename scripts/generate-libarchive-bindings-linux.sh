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
INC="$ROOT/crates/zmanager-libarchive-sys/vendor/libarchive/libarchive-3.8.9/libarchive"
OUT="$ROOT/crates/zmanager-libarchive-sys/bindings/linux-musl.rs"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/zm-bindgen-linux.XXXXXX")"

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
echo "Generated $OUT"
