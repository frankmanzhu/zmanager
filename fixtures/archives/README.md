# Fixture Archive Corpus

These fixtures are intentionally small and redistributable. The container
fixtures are generated from a temporary `payload/` tree containing:

- `README.txt`
- `nested/file.txt`
- `nested/empty-dir/`
- `nested/readme-link.txt` as a symlink when the local filesystem supports symlinks
- `dir with spaces/file with spaces.txt`
- `unicode/こんにちは.txt`

The standalone AR fixture contains one portable README member, and the MTREE
fixture is a checked-in manifest because MTREE records filesystem metadata but
does not carry payload bytes.

The corpus also includes representative CAB, RAR, LHA, RPM, WARC, TZAP, Apple
Archive, and every raw-stream suffix supported by the detector. The LHA fixture
is generated with Debian's `jlha-utils` inside Docker because macOS has no
maintained native LHA creator in the standard toolchain.

Regenerate them with:

```sh
bash scripts/generate_fixtures.sh
# Requires the proprietary RAR creator; refreshes only the multipart RAR corpus.
bash scripts/generate-rar-test-fixtures.sh
```

`manifest.tsv` records the expected SHA-256 for each fixture. The CLI fixture
tests verify those hashes before listing or extraction so accidental fixture
drift is caught early.

Unix CI additionally uses the committed small fixtures as external-tool test
inputs. It asks `unzip`, 7-Zip, and a tar reader to list and extract the
portable archive fixtures, including CAB, RAR, LHA, every compressed-TAR
variant, and CPIO, then compares those trees and listings with ZManager. This
keeps compatibility coverage available even when fixture creators are not
installed on a developer machine.

## Included Fixtures

| File | Format | Created by | Notes |
| --- | --- | --- | --- |
| `basic.zip` | ZIP Deflate | `zmanager-cli zip-create` | Symlink is skipped by the ZIP v1 writer. |
| `basic.7z` | 7Z LZMA2 solid | `zmanager-cli source-small` | Symlink is skipped by the 7z v1 writer. |
| `basic.tar` | TAR | `bsdtar -cf` | Plain TAR fixture for mandatory list/test/extract coverage. |
| `basic.tar.gz` | TAR.GZ | `bsdtar -czf` | Preserves directory structure and symlink. |
| `basic.tar.bz2` | TAR.BZ2 | `bsdtar -cjf` | bzip2-compressed TAR fixture. |
| `basic.tar.xz` | TAR.XZ | `bsdtar -cJf` | Preserves directory structure and symlink. |
| `basic.tar.lzma` | TAR.LZMA | `bsdtar` plus `xz --format=lzma` | Legacy LZMA-compressed TAR fixture. |
| `basic.tar.lz` | TAR.LZ | `bsdtar` plus `lzip` | lzip-compressed TAR fixture. |
| `basic.tar.lzo` | TAR.LZO | `bsdtar` plus `lzop` | lzop-compressed TAR fixture. |
| `basic.tar.Z` | TAR.Z | `bsdtar` plus `compress` | Unix `compress`-compressed TAR fixture. |
| `basic.tar.lz4` | TAR.LZ4 | `bsdtar` plus `lz4` | LZ4-compressed TAR fixture. |
| `basic.tar.zst` | TAR.ZST | `zmanager-cli source-fast` | Preserves directory structure and symlink. |
| `basic.cpio` | CPIO | `bsdtar --format=cpio` | External-oracle fixture for the native CPIO adapter. |
| `basic.cab` | CAB | `gcab -c` | Small Cabinet fixture for list/test/extract coverage. |
| `basic.rar` | RAR5 | `rar` | Small single-volume RAR fixture for list/test/extract coverage. |
| `basic.lha` | LHA | `jlha-utils` in Docker | Small LHA fixture; Docker supplies the creator on macOS/Linux hosts. |
| `basic.rpm` | RPM | `rpmbuild` | Small noarch RPM package fixture. |
| `basic.xar` | XAR | macOS `xar` | Apple package-adjacent archive fixture. |
| `basic.warc` | WARC | `bsdtar --format=warc` | Small WARC container fixture. |
| `basic.iso` | ISO 9660/Joliet | macOS `hdiutil makehybrid` | Disk/container listing and extraction fixture; generated without symlink because ISO/Joliet is not the symlink-preserving path. |
| `basic.deb` | Debian package | `bsdtar --format=ar` plus tar members | Package/container fixture; extraction exposes package members. |
| `basic.ar` | AR | platform `ar` | Standalone AR fixture for mandatory list/test/extract coverage. |
| `basic.dmg` | DMG disk image | macOS `hdiutil create -format UDZO` | Apple disk image fixture. HFS+ symlink targets live in the resource fork, which the reader cannot expose, so the symlink is skipped with a warning instead of materializing a broken empty link. |
| `basic.pkg` | Apple package | macOS `pkgbuild` | Apple package fixture. macOS adds a `com.apple.provenance` xattr to every new file, so pkgbuild emits `._` AppleDouble payload entries; the backend extracts them as plain files. |
| `basic.msi` | Windows Installer | `wixl` (msitools, `brew install msitools`) | MSI fixture. MSI has no symlink entries, and wixl cannot encode non-ASCII File table names, so the unicode file is absent; the backend extracts `File`-table files through `Directory`-table resolution, verified entry-for-entry against `msiextract`. |
| `basic.vhd` | VPC disk image (MBR + NTFS) | `qemu-img -O vpc`; NTFS authored in a privileged Ubuntu container (`mkntfs` + loop mount, no FUSE) | VHD fixture. Requires `qemu-img` (brew `qemu`), `mtools`, and a running Docker daemon to regenerate. The NTFS vfs adapter surfaces `$MFT`/`$Bitmap`-style system metadata at the volume root (filtered by the backend) and — with the patched ntfs-core fork — decodes `IntxLNK`/reparse symlinks, so the symlink is kept. |
| `basic.vmdk` | VMware disk image (superfloppy FAT32) | `qemu-img -O vmdk`; populated with `mformat`/`mcopy` (mtools, no mount) | VMDK fixture. FAT has no symlinks, so the symlink is stripped; unicode and spaces-in-names are preserved. |
| `basic.udf` | UDF 2.01 optical image | `mkudffs --media-type=hd --udfrev=0x0201` in a privileged Ubuntu container, populated via loop mount | UDF fixture. Requires a running Docker daemon. **Keeps the symlink**: the patched udf-forensic adapter (frankmanzhu fork) decodes PATH_COMPONENT symlinks, verified against macOS's native resolution. macOS reads the image natively (`hdiutil attach` oracle); 7-Zip 26.02 does not list it reliably. |
| `basic.mtree` | MTREE manifest | `bsdtar --format=mtree` | Manifest fixture with directories, declared file sizes, and a symlink. Extraction materializes the declared filesystem shape using sparse placeholder files because MTREE contains no payload bytes. |
| `basic.tzap` | TZAP | `zmanager-cli create --format tzap` | Checked-in native TZAP fixture for CI list/test/extract coverage. |
| `basic.aar` | Apple Archive | macOS `aa archive` | Small LZ4 Apple Archive fixture; skipped on non-Apple targets. |
| `basic.txt.gz` … `basic.txt.b64` | Raw streams | platform compressors | One tiny checked-in fixture for each supported raw stream suffix. |
| `basic.tar.uu`, `basic.tar.b64` | TAR.UU/TAR.B64 | `uuencode`/`base64` plus `bsdtar` | Encoded TAR fixtures for both supported TAR stream wrappers. |
| `rar5-multipart.part1.rar`–`part4.rar` | RAR5 multipart | RAR | Checked-in multi-volume fixture with a 192 KiB spanning file; core, FFI, and CLI tests verify every extracted byte. |
| `rar5-passworded-multipart.part1.rar`–`part4.rar` | Passworded RAR5 multipart | RAR | Same corpus with encrypted headers and data; tests require the exact password and ensure it never appears in diagnostics. |

## Not Included By Default

- ZIPX: requires a compatible creator such as 7-Zip with ZIPX/Zstd/Deflate64 options.
- WIM: requires `wimlib-imagex` or equivalent.

The external-fixture test skips unavailable tools for local runs; Unix CI checks
the required commands first, so the committed-fixture validation is mandatory
there.
