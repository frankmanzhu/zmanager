# Fixture Archive Corpus

These fixtures are intentionally small and redistributable. They are generated from a temporary `payload/` tree containing:

- `README.txt`
- `nested/file.txt`
- `nested/empty-dir/`
- `nested/readme-link.txt` as a symlink when the local filesystem supports symlinks
- `dir with spaces/file with spaces.txt`
- `unicode/こんにちは.txt`

Regenerate them with:

```sh
bash scripts/generate_fixtures.sh
# Requires the proprietary RAR creator; refreshes only the multipart RAR corpus.
bash scripts/generate-rar-test-fixtures.sh
```

`manifest.tsv` records the expected SHA-256 for each fixture. The CLI fixture
tests verify those hashes before listing or extraction so accidental fixture
drift is caught early.

## Included Fixtures

| File | Format | Created by | Notes |
| --- | --- | --- | --- |
| `basic.zip` | ZIP Deflate | `zmanager-cli zip-create` | Symlink is skipped by the ZIP v1 writer. |
| `basic.7z` | 7Z LZMA2 solid | `zmanager-cli source-small` | Symlink is skipped by the 7z v1 writer. |
| `basic.tar.gz` | TAR.GZ | `bsdtar -czf` | Preserves directory structure and symlink. |
| `basic.tar.xz` | TAR.XZ | `bsdtar -cJf` | Preserves directory structure and symlink. |
| `basic.tar.zst` | TAR.ZST | `zmanager-cli source-fast` | Preserves directory structure and symlink. |
| `basic.cpio` | CPIO | `bsdtar --format=cpio` | Broad libarchive fixture. |
| `basic.xar` | XAR | macOS `xar` | Apple package-adjacent archive fixture. |
| `basic.iso` | ISO 9660/Joliet | macOS `hdiutil makehybrid` | Disk/container listing and extraction fixture; generated without symlink because ISO/Joliet is not the symlink-preserving path. |
| `basic.deb` | Debian package | `bsdtar --format=ar` plus tar members | Package/container fixture; extraction exposes package members. |
| `basic.dmg` | DMG disk image | macOS `hdiutil create -format UDZO` | Apple disk image fixture. HFS+ symlink targets live in the resource fork, which the reader cannot expose, so the symlink is skipped with a warning instead of materializing a broken empty link. |
| `basic.pkg` | Apple package | macOS `pkgbuild` | Apple package fixture. macOS adds a `com.apple.provenance` xattr to every new file, so pkgbuild emits `._` AppleDouble payload entries; the backend extracts them as plain files. |
| `rar5-multipart.part1.rar`–`part4.rar` | RAR5 multipart | RAR | Checked-in multi-volume fixture with a 192 KiB spanning file; core, FFI, and CLI tests verify every extracted byte. |
| `rar5-passworded-multipart.part1.rar`–`part4.rar` | Passworded RAR5 multipart | RAR | Same corpus with encrypted headers and data; tests require the exact password and ensure it never appears in diagnostics. |

## Not Included By Default

- ZIPX: requires a compatible creator such as 7-Zip with ZIPX/Zstd/Deflate64 options.
- CAB: no stock macOS creator is available.
- WIM: requires `wimlib-imagex` or equivalent.
- RPM: requires an RPM build toolchain and package metadata setup.

Compatibility tests skip optional external validation tools when they are not installed.
