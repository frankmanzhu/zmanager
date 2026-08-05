# Linux Build Notes

Linux release binaries target `*-unknown-linux-musl` and are fully static:
one binary per architecture that runs on any Linux distribution — Ubuntu,
Debian, Fedora, Alpine, containers — with zero runtime dependencies. glibc
builds cannot deliver that (glibc itself stays dynamically linked, and
binaries carry a glibc-version floor), which is why the release pipeline
compiles every dependency into the binary, the same way the Windows release
statically links everything through vcpkg.

## Build Mechanism

Both musl targets are packaged inside an **Alpine container**
(`rust:1-alpine3.22`, the same image for both architectures), because Alpine
ships musl-native static libraries for every codec. The toolchain is the
container's own musl gcc — no zig cross-compilation is needed.

- `scripts/package-release-alpine.sh <target>` — the Alpine container wrapper
  (used by the release workflow for both `aarch64-unknown-linux-musl` and
  `x86_64-unknown-linux-musl`)
- `scripts/package-release.sh` — the common packaging script run inside the
  container

## Dependencies (what is picked, and why)

The musl libarchive build enables these codecs and support libraries, all
linked statically from Alpine `*-static` packages:

| Library | Alpine packages | Why |
| --- | --- | --- |
| zlib | `zlib-dev zlib-static` | ZIP deflate, gzip, XAR TOC decompression |
| bzip2 | `bzip2-dev bzip2-static` | `.tar.bz2` and bzip2 streams |
| lzma | `xz-dev xz-static` | `.tar.xz`, 7z (LZMA), lzma streams |
| zstd | `zstd-dev zstd-static` | `.tar.zst` and zstd streams |
| lz4 | `lz4-dev lz4-static` | lz4 streams |
| expat | `expat-dev expat-static` | XML parser — required by libarchive's XAR reader |
| nettle | `nettle-dev nettle-static` | Crypto backend: AES (encrypted archives) + MD5/SHA1 (XAR checksums, encrypted zip) |

### Why nettle and not OpenSSL or mbedtls

- **OpenSSL**: Alpine 3.22+ no longer ships `openssl-static` (the static
  archives were dropped), so OpenSSL cannot be linked statically on Alpine.
- **mbedtls**: available, and provides AES — but libarchive's *digest*
  backends (`ARCHIVE_HAS_MD5` / `ARCHIVE_HAS_SHA1`) only recognize
  nettle, OpenSSL, or Windows CNG. mbedtls alone leaves those macros
  undefined, which silently disables the XAR reader (see below).
- **nettle** satisfies both sides of libarchive's crypto layer: AES
  (`ARCHIVE_CRYPTOR_USE_NETTLE`) and MD5/SHA1.

### Static link details

`build.rs` emits `cargo:rustc-link-lib=static:+whole-archive=...` for the
codec and crypto archives. The `+whole-archive` modifier is required: GNU
ld's `--as-needed` (which rustc enables) drops static archives that are
placed before the rlibs referencing them, which silently produced undefined
symbols (e.g. `LZ4_decompress_safe`). The musl branch also adds
`cargo:rustc-link-search=native=/usr/lib` because rustc only searches
explicit `-L` paths for `static=` libraries.

## Diagnosis History (why these choices exist)

The musl build was originally configured with **every codec and crypto
backend disabled** for simplicity, and the gaps shipped unnoticed because no
CI job built or tested musl. The following issues were found and fixed in
August 2026 — each failure mode is worth remembering:

### 1. Split ZIP, encrypted ZIP, and 7z volumes failed to read

With all codecs off, libarchive could not decompress anything:

```
Unsupported ZIP compression method (8: deflation)
Decryption is unsupported due to lack of crypto library
LZMA codec is unsupported
```

The tests missed it because the split-ZIP tests only used `Store`
(uncompressed) entries — no codec was ever exercised — and no CI job built
musl. A compression-range test (`split_zip_compression_range_round_trips_
through_libarchive`) now covers Store + Deflate levels 1/3/6/9 through the
libarchive path.

### 2. TZAP creation was completely broken on musl

`std::fs::Metadata::created()` (birth time) returns `Err(Unsupported)` on
musl targets — the statx/`STATX_BTIME` path is not exposed there. The tzap
writer emitted the `TZAP.unix.ctime-observed` record unconditionally but only
declared its `linux-backup-v1` profile when the birth time existed — so on
musl every archive failed validation:

```
native primary metadata is not a valid v45 declaration
```

Fixed in tzap-core (`capture_linux_times`): the `linux-backup-v1` profile is
now always selected when the ctime record is emitted. zmanager additionally
falls back to ctime as the creation timestamp when the birth time is
unavailable (`tzap_backend.rs`), so musl-created archives still carry a
creation timestamp.

### 3. XAR archives were unrecognized

`basic.xar` produced `Unrecognized archive format` on musl while working
everywhere else. Root cause: libarchive compiles the XAR reader as a stub
(`"Xar not supported on this platform"`) unless the build provides an XML
parser (libxml2/expat/xmllite/bsdxml) **plus** zlib **plus** MD5/SHA1:

```c
#if (!defined(HAVE_LIBXML_XMLREADER_H) && !defined(HAVE_BSDXML_H) &&
     !defined(HAVE_EXPAT_H) && !defined(HAVE_XMLLITE_H)) || \
    !defined(HAVE_ZLIB_H) || !defined(ARCHIVE_HAS_MD5) || !defined(ARCHIVE_HAS_SHA1)
```

The musl build had no XML parser (both libxml2 and expat were disabled) and,
with mbedtls, no digest macros. Enabling `ENABLE_EXPAT` and switching the
crypto backend to `ENABLE_NETTLE` restored the reader. (Windows works via
xmllite + CNG; macOS/glibc via libxml2 + OpenSSL.)

### 4. Checked-in bindgen bindings

Static-musl build hosts (the Alpine container) cannot run bindgen — it
dlopens libclang, which is not available there. `bindings/linux-musl.rs` and
`bindings/windows-msvc.rs` are checked in, generated by the
"Regenerate libarchive bindings" workflow (automatic on vendor changes), and
`build.rs` copies them when `CARGO_CFG_TARGET_ENV` is `musl` or `msvc`.

## Verification

The full workspace test suite passes on the musl build (Alpine 3.22 chroot):

```
cargo test --workspace   # 481 passed, 0 failed
```

A faithful local reproduction environment can be set up with an Alpine
minirootfs chroot (see the musl sections in the repo history/PRs for the
toolchain details), or by running `scripts/package-release-alpine.sh` with
docker.

## Related

- `docs/WINDOWS_BUILD.md` — the Windows static-link equivalent (vcpkg)
- `tzap-rev.txt` — tzap is a sibling repository; the tzap-core fix above must
  be committed there and the pin bumped for releases to include it.
