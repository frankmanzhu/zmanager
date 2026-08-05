# Regenerates crates/zmanager-libarchive-sys/bindings/windows-msvc.rs.
#
# The checked-in bindings let Windows builds skip bindgen entirely (no
# libclang needed on the build machine), mirroring bindings/linux-musl.rs
# for static-musl hosts. Run this on a Windows machine that has:
#   - Rust (cargo)
#   - libclang.dll on PATH (VS "C++ Clang tools for Windows" component, or LLVM)
#
# The generator mirrors build.rs::generate_bindings exactly: same wrapper
# header, same allowlists, same -fsigned-char normalization.
param()

$ErrorActionPreference = "Stop"

$root = Split-Path $PSScriptRoot -Parent
$out = Join-Path $root "crates\zmanager-libarchive-sys\bindings\windows-msvc.rs"
$tmp = Join-Path $env:TEMP "zm-bindgen-win"

# Resolve the vendored source by version-agnostic glob: bumping the vendor
# directory (libarchive-<version>) must not require touching this script.
$vendorDir = Join-Path $root "crates\zmanager-libarchive-sys\vendor\libarchive"
$sourceDirs = @(Get-ChildItem -Path $vendorDir -Directory -Filter "libarchive-*" -ErrorAction SilentlyContinue)
if ($sourceDirs.Count -ne 1) {
    throw "expected exactly one libarchive-* directory under $vendorDir (found $($sourceDirs.Count))"
}
$inc = Join-Path $sourceDirs[0].FullName "libarchive"

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path (Join-Path $tmp "src") -Force | Out-Null

Set-Content -Path (Join-Path $tmp "Cargo.toml") -Value @"
[package]
name = "zm-bindgen-win"
version = "0.1.0"
edition = "2021"

[build-dependencies]
bindgen = "0.70"
"@
Set-Content -Path (Join-Path $tmp "src\main.rs") -Value "fn main() {}"

$incForward = $inc.Replace("\", "/")
$outForward = $out.Replace("\", "/")
Set-Content -Path (Join-Path $tmp "build.rs") -Value @"
fn main() {
    let wrapper = std::env::var("OUT_DIR").unwrap() + "/wrapper.h";
    std::fs::write(&wrapper, "#include <archive.h>\n#include <archive_entry.h>\n").unwrap();
    let inc = "$incForward";
    let bindings = bindgen::Builder::default()
        .header(&wrapper)
        .clang_arg("-fsigned-char")
        .allowlist_function("archive_.*")
        .allowlist_type("archive_.*|la_.*|__LA_.*")
        .allowlist_var("ARCHIVE_.*|AE_.*|__LA_.*")
        .clang_arg(format!("-I{inc}"))
        .generate()
        .expect("bindgen failed");
    bindings.write_to_file("$outForward").expect("write failed");
}
"@

Push-Location $tmp
try {
    cargo run --quiet
    if ($LASTEXITCODE -ne 0) {
        throw "cargo run (bindgen) failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

# Bindgen writes the file from scratch; prepend the explanatory header so it
# survives regeneration. Keep this text in sync with the checked-in file.
$header = @'
// Pre-generated libarchive bindings for windows-msvc targets.
//
// These let Windows builds skip bindgen entirely (no libclang needed on the
// build machine), mirroring bindings/linux-musl.rs for static-musl hosts.
// build.rs uses them whenever CARGO_CFG_TARGET_ENV is msvc and the file
// exists, falling back to bindgen otherwise.
//
// Regenerate with scripts/generate-libarchive-bindings-windows.ps1, or the
// "Regenerate libarchive bindings" workflow (auto-runs on
// vendor/libarchive/** or build.rs changes).
'@
[System.IO.File]::WriteAllText($out, $header + [Environment]::NewLine + [System.IO.File]::ReadAllText($out))

Write-Host "Generated $out"
