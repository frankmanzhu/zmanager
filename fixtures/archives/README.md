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
Archive, every raw-stream suffix, and every other filename extension supported
by the detector. Alias files contain the same small valid payload as their
primary fixture; this keeps the corpus compact while exercising extension
detection in CI. The LHA fixture is generated with Debian's `jlha-utils` inside
Docker because macOS has no maintained native LHA creator in the standard
toolchain.

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
portable archive fixtures, including CAB, LHA, every compressed-TAR variant,
and CPIO, then compares those trees and listings with ZManager. Ubuntu 22.04's
7-Zip 21.07 cannot read the RAR5 stream emitted by the supported RAR creator,
so the RAR fixture is validated by the native UnRAR-backed tests instead. This
keeps compatibility coverage available even when fixture creators are not
installed on a developer machine.

## Included Fixtures

| File | Format | Created by | Notes |
| --- | --- | --- | --- |
| `basic.zip` … `basic.epub` | ZIP family | `zmanager-cli zip-create` | One Deflate fixture under every supported ZIP-family extension; symlink is skipped by the ZIP v1 writer. |
| `basic.7z` | 7Z LZMA2 solid | `zmanager-cli source-small` | Symlink is skipped by the 7z v1 writer. |
| `basic.cb7`, `basic.sevenz` | 7Z aliases | copied from `basic.7z` | Alias spellings exercise 7z detection. |
| `basic.cbr` | RAR5 alias | copied from `basic.rar` | Alias spelling exercises RAR detection. |
| `basic.tar` | TAR | `bsdtar -cf` | Plain TAR fixture for mandatory list/test/extract coverage. Carries the full `payload/` tree and preserves the symlink, like every other TAR-family fixture. |
| `basic.tar.gz`, `basic.tgz` | TAR.GZ | `bsdtar -czf` | Both supported TAR.GZ spellings. |
| `basic.tar.bz2`, `basic.tbz2`, `basic.tbz` | TAR.BZ2 | `bsdtar -cjf` | All supported bzip2-compressed TAR spellings. |
| `basic.tar.xz`, `basic.txz` | TAR.XZ | `bsdtar -cJf` | Both supported XZ-compressed TAR spellings. |
| `basic.tar.lzma`, `basic.tlzma` | TAR.LZMA | `bsdtar` plus `xz --format=lzma` | Both supported legacy LZMA TAR spellings. |
| `basic.tar.lz` | TAR.LZ | `bsdtar` plus `lzip` | lzip-compressed TAR fixture. |
| `basic.tar.lzo` | TAR.LZO | `bsdtar` plus `lzop` | lzop-compressed TAR fixture. |
| `basic.tar.Z`, `basic-lowercase.tar.z`, `basic.taz` | TAR.Z | `bsdtar` plus `compress` | All supported Unix `compress` TAR spellings; the distinct name avoids macOS case-insensitive collisions. |
| `basic.tar.lz4` | TAR.LZ4 | `bsdtar` plus `lz4` | LZ4-compressed TAR fixture. |
| `basic.tar.zst` | TAR.ZST | `zmanager-cli source-fast` | Preserves directory structure and symlink. |
| `basic.cpio` … `basic.cpio.zst` | CPIO | `bsdtar --format=cpio` plus compressors | Uncompressed and every supported compressed CPIO spelling. |
| `basic.cab` | CAB | `gcab -c` | Small Cabinet fixture for list/test/extract coverage. |
| `basic.rar` | RAR5 | `rar` | Small single-volume RAR fixture for list/test/extract coverage. |
| `basic.lha`, `basic.lzh` | LHA | `jlha-utils` in Docker | Both supported LHA spellings; Docker supplies the creator on macOS/Linux hosts. |
| `basic.rpm` | RPM | `rpmbuild` | Small noarch RPM package fixture. |
| `basic.xar` | XAR | macOS `xar` | Apple package-adjacent archive fixture. |
| `basic.warc` | WARC | `bsdtar --format=warc` | Small WARC container fixture. |
| `basic.iso` | ISO 9660/Joliet | macOS `hdiutil makehybrid` | Disk/container listing and extraction fixture; generated without symlink because ISO/Joliet is not the symlink-preserving path. |
| `basic.deb` | Debian package | `bsdtar --format=ar` plus tar members | Package/container fixture; extraction exposes package members. |
| `basic.ar`, `basic.a`, `basic.lib` | AR | platform `ar` | All supported AR spellings. |
| `basic.dmg` | DMG disk image | macOS `hdiutil create -format UDZO` | Apple disk image fixture. HFS+ symlink targets live in the resource fork, which the reader cannot expose, so the symlink is skipped with a warning instead of materializing a broken empty link. |
| `basic.pkg` | Apple package | macOS `pkgbuild` | Apple package fixture. macOS adds a `com.apple.provenance` xattr to every new file, so pkgbuild emits `._` AppleDouble payload entries; the backend extracts them as plain files. |
| `basic.msi` | Windows Installer | `wixl` (msitools, `brew install msitools`) | MSI fixture. MSI has no symlink entries, and wixl cannot encode non-ASCII File table names, so the unicode file is absent; the backend extracts `File`-table files through `Directory`-table resolution, verified entry-for-entry against `msiextract`. |
| `basic.vhd` | VPC disk image (MBR + NTFS) | `qemu-img -O vpc`; NTFS authored in a privileged Ubuntu container (`mkntfs` + loop mount, no FUSE) | VHD fixture. Requires `qemu-img` (brew `qemu`), `mtools`, and a running Docker daemon to regenerate. The NTFS vfs adapter surfaces `$MFT`/`$Bitmap`-style system metadata at the volume root (filtered by the backend) and — with the patched ntfs-core fork — decodes `IntxLNK`/reparse symlinks, so the symlink is kept. |
| `basic.vmdk` | VMware disk image (superfloppy FAT32) | `qemu-img -O vmdk`; populated with `mformat`/`mcopy` (mtools, no mount) | VMDK fixture. FAT has no symlinks, so the symlink is stripped; unicode and spaces-in-names are preserved. |
| `basic.udf` | UDF 2.01 optical image | `mkudffs --media-type=hd --udfrev=0x0201` in a privileged Ubuntu container, populated via loop mount | UDF fixture. Requires a running Docker daemon. **Keeps the symlink**: the patched udf-forensic adapter (frankmanzhu fork) decodes PATH_COMPONENT symlinks, verified against macOS's native resolution. macOS reads the image natively (`hdiutil attach` oracle); 7-Zip 26.02 does not list it reliably. |
| `basic.mtree` | MTREE manifest | `bsdtar --format=mtree` | Manifest fixture with directories, declared file sizes, and a symlink. Extraction materializes the declared filesystem shape using sparse placeholder files because MTREE contains no payload bytes. |
| `basic.tzap` | TZAP | `zmanager-cli create --format tzap` | Checked-in native TZAP fixture for CI list/test/extract coverage. |
| `basic.aar`, `basic.aea` | Apple Archive | macOS `aa archive` | Small LZ4 Apple Archive fixture under both supported spellings; skipped on non-Apple targets. |
| `basic.txt.gz` … `basic.txt.b64` | Raw streams | platform compressors | One tiny checked-in fixture for each supported raw stream suffix. |
| `basic.tar.uu`, `basic.tar.b64` | TAR.UU/TAR.B64 | `uuencode`/`base64` plus `bsdtar` | Encoded TAR fixtures for both supported TAR stream wrappers. |
| `rar5-multipart.part1.rar`–`part4.rar` | RAR5 multipart | RAR | Checked-in multi-volume fixture with a 192 KiB spanning file; core, FFI, and CLI tests verify every extracted byte. |
| `rar5-passworded-multipart.part1.rar`–`part4.rar` | Passworded RAR5 multipart | RAR | Same corpus with encrypted headers and data; tests require the exact password and ensure it never appears in diagnostics. |
| `basic.squashfs`, `basic.sqfs`, `basic-xz.squashfs`, `basic-gzip.squashfs`, `basic-zstd.squashfs` | SquashFS | `mksquashfs` | `basic.squashfs`/`basic.sqfs` are copies of the xz variant. Rooted at the archive root (no `payload/` prefix). This is the one format whose payload tree is *not* the plain `$SRC` copy: `scripts/generate_fixtures.sh` adds an executable `run.sh` to a private copy before calling `mksquashfs`, so extraction is checked against a real executable member, not just plain files. |
| `basic.AppImage` | Type-2 AppImage | `scripts/make_appimage_fixture.py` over `basic-gzip.squashfs` | ELF runtime with the SquashFS image appended after the section-header table; carries `run.sh` for the same reason as the SquashFS family above. |
| `basic.wim`, `basic-none.wim`, `basic-LZX.wim`, `basic-XPRESS.wim` | WIM | `wimlib-imagex capture --compress=none/LZX/XPRESS` | `basic.wim` is a copy of `basic-none.wim`. Rooted at the archive root like SquashFS; carries the symlink but not `run.sh`. |
| `multi-image.wim` | WIM, two images | `wimlib-imagex capture` + `append` | The two images carry **different** content by design: image 1 has `unicode/こんにちは.txt` and no marker file; image 2 has `second-image-only.txt` and no `unicode/`. This is deliberate — identical images would let a decoder silently emit image 1 twice under both `image1/`/`image2/` prefixes and still pass a same-content check. Exposed under `imageN/` path prefixes. |
| `split.swm` (+ `split2.swm`) | Split WIM set | `wimlib-imagex split basic-none.wim … 0.001` | A copy of `basic-none.wim`'s content split across two `.swm` parts. `split2.swm` must be present alongside `split.swm` for either part to open — `cli_rejects_a_split_wim_missing_its_second_part` in `fixture_cli.rs` asserts that opening part 1 alone fails, so a future change that silently makes the reader tolerate a missing part is caught. |
| `lzx-longmatch.wim` | WIM (LZX stress corpus) | `wimlib-imagex capture --compress=LZX` over a generated corpus | Deliberately repetitive data (3000-byte runs, a repeated 64 KiB block, repeated prose) to drive long LZX matches the small `basic-LZX.wim` never reaches. See `crates/zmanager-wim/tests/reference_wim.rs`. |
| `basic.vdi` | VirtualBox disk image (superfloppy FAT32) | `qemu-img -O vdi`; populated with `mtools` | Source image the rest of the forensic/virtual-disk family (`basic.raw`/`.dd`/`.dsk`/`.img`, `.vhdx`, `.qcow2`/`.qcow`, `.e01`/`.ex01`, `.aff4`) is derived from — see `scripts/generate-forensic-fixtures.sh`'s derivation chain comment. FAT32 has no symlinks. |
| `basic.raw`, `basic.dd`, `basic.dsk`, `basic.img` | Raw sector dump | truncated `qemu-img convert -O raw` of `basic.vdi` | Same bytes under four extensions. |
| `basic.vhdx` | Hyper-V VHDX | `qemu-img convert -O vhdx` over `basic.raw` | |
| `basic.qcow2`, `basic.qcow` | QEMU qcow2 | `qemu-img convert -O qcow2 -c` over `basic.raw` | `.qcow` is a copy under the legacy extension. |
| `basic.e01`, `basic.ex01` | EWF (EnCase v1/v2) | `scripts/make_ewf_fixtures.py` over `basic.raw` | Two different on-disk segment-file layouts behind one `FormatId`. |
| `basic.aff4` | Physical AFF4 (`aff4:ImageStream`) | `scripts/make_aff4_fixture.py` over `basic.raw` | Sector-stream leg of the AFF4 reader — distinct code path from the logical container below. |
| `basic-logical.aff4` | Logical AFF4 (`aff4:FileImage`) | `crates/zmanager-core/examples/make_forensic_fixtures.rs` (hand-built turtle + ZIP, following `aff4-core`'s own single-entry `testutil::test_aff4_logical` template) | Carries the whole canonical payload tree (4 files) as a flat AFF4-L file list. AFF4-L has no directory nodes (the tree is derived from `/`-separated names), so there is no empty directory to carry. |
| `basic.ad1` | FTK Imager AD1 | `crates/zmanager-core/examples/make_forensic_fixtures.rs` (`ad1-core`'s `testfix` builder) | Carries the whole canonical payload tree including the empty directory. **No symlink**: AD1's `Node` builder has no symlink variant (`ad1-core`'s `vfs.rs` doc comment: AD1 does not surface symlink targets), so this is a format limitation, not a fixture gap. |
| `basic.dar` | DAR (single slice) | checked in; minted with the `dar` CLI 2.8.5, no writer in this toolchain | Carries `hello.txt`, `sub_note.txt`, `sub/deep.txt` — **not** the shared payload tree (no Unicode name, no spaces-in-name, no empty dir, no symlink). Regenerating a richer DAR fixture needs a machine with the `dar` CLI installed; nothing in this repo can mint one. |

## Optical disc formats built at test time, not committed

NRG, CUE/BIN, CCD/IMG, and MDF are exercised by
`cli_lists_tests_and_extracts_optical_disc_fixtures` in
`crates/zmanager-cli/tests/fixture_cli.rs`, which builds each container's small
format-specific header/sidecar around `basic.iso`'s bytes at test time rather
than shipping it as a binary fixture — there is no macOS-available writer for
Nero/CloneCD/Alcohol images. **CDI is the same trick** (confirmed against the
reader: `list_cdi`/`list_mdf` are both `list_virtual_disk_inner` — CDI has no
DiscJuggler-specific header this backend parses, so raw ISO bytes under the
`.cdi` extension exercise the real code path exactly like MDF does), and is
covered the same way in that test.

Because none of these five live in `fixtures/archives`, they are **not**
covered by `fixture_manifest_covers_every_supported_extension`'s sweep over
`manifest.tsv` — that check only validates the committed binary corpus. This is
an intentional scope boundary, not an oversight: the sweep exists to catch a
committed fixture going stale, which does not apply to a container built fresh
in the test body every run.

**ISZ** is not exercised through `fixtures/archives` or the CLI tests at all,
but it is not uncovered: `crates/zmanager-core/src/virtual_disk_backend.rs`
carries its own internal `#[cfg(test)] build_isz` encoder and a dedicated test
suite (`isz_roundtrip_list_test_and_extract`,
`isz_decodes_byte_identically_to_the_source_image`, malformed-header rejection)
that builds real ISZ byte streams — both supported chunk-pointer widths, all
four documented chunk types — against `basic.iso`'s payload and drives list,
test, and extract through the real parser. If you are looking for ISZ
coverage, look there, not in this directory.

The external-fixture test skips unavailable tools for local runs; Unix CI checks
the required commands first, so the committed-fixture validation is mandatory
there.
