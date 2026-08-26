#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVES="$ROOT/fixtures/archives"
MANIFEST="$ARCHIVES/manifest.tsv"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zmanager-fixtures.XXXXXX")"
SRC="$WORK/payload"

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$ARCHIVES"
rm -f "$ARCHIVES"/basic.zip \
  "$ARCHIVES"/basic.zipx "$ARCHIVES"/basic.jar "$ARCHIVES"/basic.war "$ARCHIVES"/basic.ipa "$ARCHIVES"/basic.apk "$ARCHIVES"/basic.appx "$ARCHIVES"/basic.xpi "$ARCHIVES"/basic.cbz "$ARCHIVES"/basic.epub \
  "$ARCHIVES"/basic.7z \
  "$ARCHIVES"/basic.cb7 "$ARCHIVES"/basic.sevenz \
  "$ARCHIVES"/basic.cbr \
  "$ARCHIVES"/basic.tar \
  "$ARCHIVES"/basic.cbt "$ARCHIVES"/basic.pax "$ARCHIVES"/basic.ustar \
  "$ARCHIVES"/basic.tar.gz \
  "$ARCHIVES"/basic.tar.bz2 \
  "$ARCHIVES"/basic.tbz2 "$ARCHIVES"/basic.tbz \
  "$ARCHIVES"/basic.tar.xz \
  "$ARCHIVES"/basic.txz \
  "$ARCHIVES"/basic.tar.lzma \
  "$ARCHIVES"/basic.tlzma \
  "$ARCHIVES"/basic.tar.lz \
  "$ARCHIVES"/basic.tar.lzo \
  "$ARCHIVES"/basic.tar.Z \
  "$ARCHIVES"/basic-lowercase.tar.z "$ARCHIVES"/basic.taz \
  "$ARCHIVES"/basic.tar.lz4 \
  "$ARCHIVES"/basic.tar.zst \
  "$ARCHIVES"/basic.cpio \
  "$ARCHIVES"/basic.cpio.gz "$ARCHIVES"/basic.cpgz "$ARCHIVES"/basic.cpio.bz2 "$ARCHIVES"/basic.cpio.xz "$ARCHIVES"/basic.cpio.lzma "$ARCHIVES"/basic.cpio.zst \
  "$ARCHIVES"/basic.cab \
  "$ARCHIVES"/basic.rar \
  "$ARCHIVES"/basic.rpm \
  "$ARCHIVES"/basic.lha \
  "$ARCHIVES"/basic.lzh \
  "$ARCHIVES"/basic.xar \
  "$ARCHIVES"/basic.warc \
  "$ARCHIVES"/basic.iso \
  "$ARCHIVES"/basic.deb \
  "$ARCHIVES"/basic.ar \
  "$ARCHIVES"/basic.a "$ARCHIVES"/basic.lib \
  "$ARCHIVES"/basic.dmg \
  "$ARCHIVES"/basic.pkg \
  "$ARCHIVES"/basic.msi \
  "$ARCHIVES"/basic.vhd \
  "$ARCHIVES"/basic.vmdk \
  "$ARCHIVES"/basic.udf \
  "$ARCHIVES"/basic.mtree \
  "$ARCHIVES"/basic.tzap \
  "$ARCHIVES"/basic.tzst "$ARCHIVES"/basic.tgz "$ARCHIVES"/basic.aea \
  "$ARCHIVES"/basic.aar \
  "$ARCHIVES"/basic.txt.gz \
  "$ARCHIVES"/basic.txt.bz2 \
  "$ARCHIVES"/basic.txt.xz \
  "$ARCHIVES"/basic.txt.lzma \
  "$ARCHIVES"/basic.txt.zst \
  "$ARCHIVES"/basic.txt.lz \
  "$ARCHIVES"/basic.txt.br \
  "$ARCHIVES"/basic.txt.lz4 \
  "$ARCHIVES"/basic.txt.lzo \
  "$ARCHIVES"/basic.txt.Z \
  "$ARCHIVES"/basic.txt.uu \
  "$ARCHIVES"/basic.txt.b64 \
  "$ARCHIVES"/basic.tar.uu \
  "$ARCHIVES"/basic.tar.b64

mkdir -p "$SRC/nested/empty-dir"
mkdir -p "$SRC/dir with spaces"
mkdir -p "$SRC/unicode"

printf 'ZManager fixture payload\n' > "$SRC/README.txt"
printf 'nested fixture file\n' > "$SRC/nested/file.txt"
printf 'spaces in path\n' > "$SRC/dir with spaces/file with spaces.txt"
printf 'unicode path fixture\n' > "$SRC/unicode/こんにちは.txt"

if ln -s "../README.txt" "$SRC/nested/readme-link.txt" 2>/dev/null; then
  :
fi

(
  cd "$ROOT"
  cargo run -p zmanager-cli --bin zmanager-cli -- create "$ARCHIVES/basic.zip" "$SRC" --method deflate
  cargo run -p zmanager-cli --bin zmanager-cli -- create "$ARCHIVES/basic.7z" "$SRC" --format 7z --solid
  cargo run -p zmanager-cli --bin zmanager-cli -- create "$ARCHIVES/basic.tar.zst" "$SRC" --format tar.zst --level 1
  cargo run -p zmanager-cli --bin zmanager-cli -- create "$ARCHIVES/basic.tzap" "$SRC" --format tzap
)

aa archive -d "$WORK" -o "$ARCHIVES/basic.aar" -a lz4 >/dev/null

cp "$SRC/README.txt" "$WORK/README.md"
bsdtar -czf "$ARCHIVES/basic.tar.gz" -C "$WORK" payload
bsdtar -cjf "$ARCHIVES/basic.tar.bz2" -C "$WORK" payload
bsdtar -cf "$ARCHIVES/basic.tar" -C "$WORK" README.md
bsdtar -cJf "$ARCHIVES/basic.tar.xz" -C "$WORK" payload
bsdtar -cf - -C "$WORK" payload | xz --format=lzma -c > "$ARCHIVES/basic.tar.lzma"
bsdtar -cf - -C "$WORK" payload | lzip -c > "$ARCHIVES/basic.tar.lz"
bsdtar -cf - -C "$WORK" payload | lzop -c > "$ARCHIVES/basic.tar.lzo"
bsdtar -cf - -C "$WORK" payload | compress -c > "$ARCHIVES/basic.tar.Z"
bsdtar -cf - -C "$WORK" payload | lz4 -q -c > "$ARCHIVES/basic.tar.lz4"
bsdtar --format=cpio -cf "$ARCHIVES/basic.cpio" -C "$WORK" payload
gzip -c "$ARCHIVES/basic.cpio" > "$ARCHIVES/basic.cpio.gz"
cp "$ARCHIVES/basic.cpio.gz" "$ARCHIVES/basic.cpgz"
bzip2 -c "$ARCHIVES/basic.cpio" > "$ARCHIVES/basic.cpio.bz2"
xz -c "$ARCHIVES/basic.cpio" > "$ARCHIVES/basic.cpio.xz"
xz --format=lzma -c "$ARCHIVES/basic.cpio" > "$ARCHIVES/basic.cpio.lzma"
zstd -q -c "$ARCHIVES/basic.cpio" > "$ARCHIVES/basic.cpio.zst"

# LHA has no maintained native creator in Homebrew. jlha-utils is a small
# Java implementation available in Debian/Ubuntu, so use Docker when the
# corpus is regenerated on macOS or another host without an LHA writer.
docker run --rm -v "$WORK:/work" ubuntu:24.04 bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq default-jre-headless jlha-utils >/dev/null 2>&1
  cd /work
  jlha c basic.lha payload/README.txt payload/nested/file.txt >/dev/null
'
cp "$WORK/basic.lha" "$ARCHIVES/basic.lha"

(
  cd "$WORK"
  gcab -c "$ARCHIVES/basic.cab" payload
  rar a -idq -ma5 -m0 "$ARCHIVES/basic.rar" payload
)
bsdtar --format=warc -cf "$ARCHIVES/basic.warc" -C "$WORK" payload/README.txt

RPM="$WORK/rpm"
mkdir -p "$RPM"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cat > "$RPM/SPECS/zmanager-fixture.spec" <<'SPEC'
Name: zmanager-fixture
Version: 1.0
Release: 1
Summary: ZManager compatibility fixture
License: Apache-2.0
BuildArch: noarch

%description
Small ZManager compatibility fixture.

%install
mkdir -p %{buildroot}/usr/share/zmanager-fixture
printf 'ZManager fixture payload\n' > %{buildroot}/usr/share/zmanager-fixture/README.txt

%files
/usr/share/zmanager-fixture/README.txt
SPEC
rpmbuild --define "_topdir $RPM" --define '_build_id_links none' -bb "$RPM/SPECS/zmanager-fixture.spec" >/dev/null
cp "$RPM/RPMS/noarch/zmanager-fixture-1.0-1.noarch.rpm" "$ARCHIVES/basic.rpm"

RAW="$WORK/raw"
mkdir -p "$RAW"
printf 'ZManager raw stream fixture\n' > "$RAW/payload.txt"
gzip -c "$RAW/payload.txt" > "$ARCHIVES/basic.txt.gz"
bzip2 -c "$RAW/payload.txt" > "$ARCHIVES/basic.txt.bz2"
xz -c "$RAW/payload.txt" > "$ARCHIVES/basic.txt.xz"
xz --format=lzma -c "$RAW/payload.txt" > "$ARCHIVES/basic.txt.lzma"
zstd -q -c "$RAW/payload.txt" > "$ARCHIVES/basic.txt.zst"
lzip -c "$RAW/payload.txt" > "$ARCHIVES/basic.txt.lz"
brotli -c "$RAW/payload.txt" > "$ARCHIVES/basic.txt.br"
lz4 -q -c "$RAW/payload.txt" > "$ARCHIVES/basic.txt.lz4"
lzop -q -c "$RAW/payload.txt" > "$ARCHIVES/basic.txt.lzo"
compress -c "$RAW/payload.txt" > "$ARCHIVES/basic.txt.Z"
uuencode "$RAW/payload.txt" basic.txt > "$ARCHIVES/basic.txt.uu"
{
  printf 'begin-base64 644 basic.txt\n'
  base64 < "$RAW/payload.txt"
  printf '====\n'
} > "$ARCHIVES/basic.txt.b64"
COPYFILE_DISABLE=1 bsdtar -cf "$RAW/basic.tar" -C "$WORK" payload
uuencode "$RAW/basic.tar" basic.tar > "$ARCHIVES/basic.tar.uu"
{
  printf 'begin-base64 644 basic.tar\n'
  base64 < "$RAW/basic.tar"
  printf '====\n'
} > "$ARCHIVES/basic.tar.b64"

# MTREE is intentionally kept to the two regular files and one symlink used
# by the native manifest tests; the broader payload tree would change the
# declared byte total when optional fixture files are added.
mkdir -p "$WORK/mtree/payload/nested"
cp "$SRC/README.txt" "$WORK/mtree/payload/README.txt"
cp "$SRC/nested/file.txt" "$WORK/mtree/payload/nested/file.txt"
if [ -L "$SRC/nested/readme-link.txt" ]; then
  ln -s "../README.txt" "$WORK/mtree/payload/nested/readme-link.txt"
fi
bsdtar --format=mtree -cf "$ARCHIVES/basic.mtree" -C "$WORK/mtree" payload

(
  cd "$WORK"
  xar -cf "$ARCHIVES/basic.xar" payload
)

ISO_SRC="$WORK/iso-payload"
mkdir -p "$ISO_SRC/nested/empty-dir"
mkdir -p "$ISO_SRC/dir with spaces"
mkdir -p "$ISO_SRC/unicode"
cp "$SRC/README.txt" "$ISO_SRC/README.txt"
cp "$SRC/nested/file.txt" "$ISO_SRC/nested/file.txt"
cp "$SRC/dir with spaces/file with spaces.txt" "$ISO_SRC/dir with spaces/file with spaces.txt"
cp "$SRC/unicode/こんにちは.txt" "$ISO_SRC/unicode/こんにちは.txt"
hdiutil makehybrid -iso -joliet -o "$ARCHIVES/basic.iso" "$ISO_SRC" >/dev/null

DEB="$WORK/deb"
mkdir -p "$DEB/control" "$DEB/data/usr/share/zmanager-fixture"
printf '2.0\n' > "$DEB/debian-binary"
cat > "$DEB/control/control" <<'CONTROL'
Package: zmanager-fixture
Version: 0.1.0
Architecture: all
Maintainer: ZManager <fixtures@example.invalid>
Description: Small archive fixture for ZManager compatibility tests
CONTROL
cp "$SRC/README.txt" "$DEB/data/usr/share/zmanager-fixture/README.txt"
bsdtar -czf "$DEB/control.tar.gz" -C "$DEB/control" control
bsdtar -cJf "$DEB/data.tar.xz" -C "$DEB/data" .
bsdtar --format=ar -cf "$ARCHIVES/basic.deb" -C "$DEB" debian-binary control.tar.gz data.tar.xz
# Use bsdtar's portable AR writer: Darwin's `ar` adds a linker symbol-table
# member even for this non-object payload, hiding the fixture member from
# readers that intentionally expose every archive entry.
bsdtar --format=ar -cf "$ARCHIVES/basic.ar" -C "$WORK" README.md

# DMG fixture: hdiutil treats the -srcfolder directory as the volume root,
# so stage the payload tree in a dedicated directory to keep the payload/
# prefix consistent with the tar family fixtures.
DMG_SRC="$WORK/dmg-src"
mkdir -p "$DMG_SRC"
cp -PR "$SRC" "$DMG_SRC/"
hdiutil create -format UDZO -ov -srcfolder "$DMG_SRC" "$ARCHIVES/basic.dmg" >/dev/null

# PKG fixture: stage the payload tree under a root directory so the cpio
# payload carries the same payload/ prefix as every other fixture. Strip
# extended attributes first so pkgbuild does not emit ._ AppleDouble
# payload entries.
PKG_ROOT="$WORK/pkg-root"
mkdir -p "$PKG_ROOT"
xattr -cr "$SRC" 2>/dev/null || true
cp -PR "$SRC" "$PKG_ROOT/"
pkgbuild --root "$PKG_ROOT" --identifier com.zmanager.fixture --version 0.1.0 "$ARCHIVES/basic.pkg" >/dev/null 2>&1 || {
  # Fall back to showing pkgbuild diagnostics on failure
  pkgbuild --root "$PKG_ROOT" --identifier com.zmanager.fixture --version 0.1.0 "$ARCHIVES/basic.pkg"
}

# MSI fixture: built with wixl from msitools (brew install msitools). The
# Directory table maps TARGETDIR -> payload -> nested / dir with spaces, so
# extraction resolves the same payload/ prefix as every other fixture. MSI
# has no symlink entries, and wixl cannot encode non-ASCII File table names,
# so the unicode file is intentionally absent from this fixture.
if ! command -v wixl >/dev/null 2>&1; then
  echo "wixl not found (brew install msitools); cannot regenerate basic.msi" >&2
  exit 1
fi
cat > "$WORK/basic.wxs" <<'WXS'
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Name="ZManager Fixture" Manufacturer="ZManager" Language="1033" Version="0.1.0"
           Id="11111111-2222-3333-4444-555555555555" UpgradeCode="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee">
    <Package Description="Small MSI fixture for ZManager compatibility tests"
             Comments="fixture" InstallerVersion="200" Compressed="yes"/>
    <Media Id="1" Cabinet="basic.cab" EmbedCab="yes"/>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="PAYLOADDIR" Name="payload">
        <Directory Id="NESTEDDIR" Name="nested">
          <Component Id="NestedFiles" Guid="99999999-8888-7777-6666-555555555554">
            <File Id="filetxt" Name="file.txt" Source="payload/nested/file.txt"/>
          </Component>
        </Directory>
        <Directory Id="SPACEDIR" Name="dir with spaces">
          <Component Id="SpaceFiles" Guid="99999999-8888-7777-6666-555555555553">
            <File Id="spaces" Name="file with spaces.txt" Source="payload/dir with spaces/file with spaces.txt"/>
          </Component>
        </Directory>
        <Component Id="PayloadFiles" Guid="99999999-8888-7777-6666-555555555555">
          <File Id="readme" Name="README.txt" Source="payload/README.txt"/>
        </Component>
      </Directory>
    </Directory>
    <Feature Id="DefaultFeature" Title="Main Feature" Level="1">
      <ComponentRef Id="PayloadFiles"/>
      <ComponentRef Id="NestedFiles"/>
      <ComponentRef Id="SpaceFiles"/>
    </Feature>
  </Product>
</Wix>
WXS
(
  cd "$WORK"
  wixl -o "$ARCHIVES/basic.msi" basic.wxs >/dev/null 2>&1 || {
    # Fall back to showing wixl diagnostics on failure
    wixl -o "$ARCHIVES/basic.msi" basic.wxs
  }
)

# Virtual-disk fixtures (VHD/VMDK/UDF): block-device formats whose files live
# inside an inner filesystem. The extraction backend (forensic-vfs-engine)
# resolves container -> partition table -> filesystem in one call. The symlink
# is stripped from the FAT payload (FAT has no symlinks) but kept for NTFS
# and UDF: the patched ntfs-core adapter decodes reparse-point/'IntxLNK'
# symlinks and the patched udf-forensic adapter decodes PATH_COMPONENT links
# (frankmanzhu forks).
DISK_SRC="$WORK/disk-src"
mkdir -p "$DISK_SRC"
cp -PR "$SRC" "$DISK_SRC/"
rm -f "$DISK_SRC/payload/nested/readme-link.txt"

if ! command -v qemu-img >/dev/null 2>&1; then
  echo "qemu-img not found (brew install qemu); cannot regenerate basic.vhd/basic.vmdk" >&2
  exit 1
fi
if ! command -v mformat >/dev/null 2>&1 || ! command -v mcopy >/dev/null 2>&1; then
  echo "mtools not found (brew install mtools); cannot regenerate basic.vmdk" >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "docker not found or daemon not running (install Docker Desktop and start it); cannot regenerate basic.vhd/basic.udf" >&2
  exit 1
fi

# VMDK fixture: superfloppy FAT32 populated with mtools (no mount, no root).
# 64 MiB clears the FAT32 minimum volume size; mcopy -s preserves the nested
# tree including the empty directory.
dd if=/dev/zero of="$WORK/raw-fat.img" bs=1m count=64 status=none
mformat -F -i "$WORK/raw-fat.img" ::
mcopy -s -i "$WORK/raw-fat.img" "$DISK_SRC/payload" ::
qemu-img convert -f raw -O vmdk "$WORK/raw-fat.img" "$ARCHIVES/basic.vmdk"

# VHD fixture: MBR + NTFS. ntfs-3g's tools are Linux-only on recent versions,
# so the NTFS volume is authored inside a privileged Ubuntu container (loop
# mount, mkntfs, cp -a — no FUSE). The MBR wrapper is written with printf/dd
# (one 0x07 partition at LBA 2048, 524288 sectors, 0x55AA signature), then
# qemu-img converts raw -> VPC (dynamic).
docker run --rm --privileged -v "$WORK:/work" ubuntu:24.04 bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq ntfs-3g >/dev/null 2>&1
  dd if=/dev/zero of=/work/ntfs.img bs=1M count=256 status=none
  LOOP=$(losetup -f); losetup $LOOP /work/ntfs.img
  mkntfs -F -L ZMANAGER $LOOP >/dev/null 2>&1
  mkdir -p /mnt/ntfs && mount -t ntfs-3g $LOOP /mnt/ntfs
  cp -a /work/payload /mnt/ntfs/
  sync; umount /mnt/ntfs; losetup -d $LOOP
' >/dev/null
dd if=/dev/zero of="$WORK/raw-mbr.img" bs=1m count=257 status=none
printf '\x80\xfe\xff\xff\x07\xfe\xff\xff\x00\x08\x00\x00\x00\x00\x08\x00' | dd of="$WORK/raw-mbr.img" bs=1 seek=446 conv=notrunc status=none
printf '\x55\xaa' | dd of="$WORK/raw-mbr.img" bs=1 seek=510 conv=notrunc status=none
dd if="$WORK/ntfs.img" of="$WORK/raw-mbr.img" bs=1m seek=1 conv=notrunc status=none
qemu-img convert -f raw -O vpc "$WORK/raw-mbr.img" "$ARCHIVES/basic.vhd"

# UDF fixture: a populated physical-partition UDF 2.01 volume authored inside
# the same container (mkudffs + loop mount). Note: --utf8 is fine for the
# engine's UDF probe, but mkudffs requires it to be the FIRST argument
# (else it errors out and leaves a zero-filled file). The engine mounts this
# image as UDF;
# macOS reads it natively (hdiutil oracle).
docker run --rm --privileged -v "$WORK:/work" ubuntu:24.04 bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq udftools >/dev/null 2>&1
  dd if=/dev/zero of=/work/basic.udf bs=1M count=8 status=none
  mkudffs --media-type=hd --udfrev=0x0201 /work/basic.udf >/dev/null 2>&1
  LOOP=$(losetup -f); losetup $LOOP /work/basic.udf
  mkdir -p /mnt/udf && mount -t udf $LOOP /mnt/udf
  cp -a /work/payload /mnt/udf/
  sync; umount /mnt/udf; losetup -d $LOOP
' >/dev/null
cp "$WORK/basic.udf" "$ARCHIVES/basic.udf"

# Every supported extension spelling gets a checked-in copy of the smallest
# valid representative for that backend. Git stores identical copies as one
# blob, while the distinct names exercise path detection in CI.
for extension in zipx jar war ipa apk appx xpi cbz epub; do
  cp "$ARCHIVES/basic.zip" "$ARCHIVES/basic.$extension"
done
for extension in cb7 sevenz; do
  cp "$ARCHIVES/basic.7z" "$ARCHIVES/basic.$extension"
done
cp "$ARCHIVES/basic.rar" "$ARCHIVES/basic.cbr"
for extension in cbt pax ustar; do
  cp "$ARCHIVES/basic.tar" "$ARCHIVES/basic.$extension"
done
for extension in tbz2 tbz; do
  cp "$ARCHIVES/basic.tar.bz2" "$ARCHIVES/basic.$extension"
done
cp "$ARCHIVES/basic.tar.xz" "$ARCHIVES/basic.txz"
cp "$ARCHIVES/basic.tar.lzma" "$ARCHIVES/basic.tlzma"
cp "$ARCHIVES/basic.tar.Z" "$ARCHIVES/basic-lowercase.tar.z"
cp "$ARCHIVES/basic.tar.Z" "$ARCHIVES/basic.taz"
cp "$ARCHIVES/basic.lha" "$ARCHIVES/basic.lzh"
for extension in a lib; do
  cp "$ARCHIVES/basic.ar" "$ARCHIVES/basic.$extension"
done
cp "$ARCHIVES/basic.tar.zst" "$ARCHIVES/basic.tzst"
cp "$ARCHIVES/basic.tar.gz" "$ARCHIVES/basic.tgz"
cp "$ARCHIVES/basic.aar" "$ARCHIVES/basic.aea"


sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    echo "missing SHA-256 tool; install shasum or sha256sum" >&2
    exit 1
  fi
}

append_manifest() {
  local filename="$1"
  local format="$2"
  local extract="$3"
  local password="$4"
  local notes="$5"
  local checksum
  checksum="$(sha256_file "$ARCHIVES/$filename")"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$filename" "$format" "$extract" "$password" "$checksum" "$notes" >> "$MANIFEST"
}

printf '# filename\tformat\textract\tpassword\tsha256\tnotes\n' > "$MANIFEST"
append_manifest "basic.zip" "ZIP" "true" "" "ZIP Deflate fixture created by ZManager"
for extension in zipx jar war ipa apk appx xpi cbz epub; do
  append_manifest "basic.$extension" "ZIP" "true" "" "ZIP Deflate fixture under the .$extension extension"
done
append_manifest "basic.7z" "7Z" "true" "" "7Z LZMA2 solid fixture created by ZManager"
for extension in cb7 sevenz; do
  append_manifest "basic.$extension" "7Z" "true" "" "7Z fixture under the .$extension extension"
done
append_manifest "basic.cbr" "RAR" "true" "" "RAR5 fixture under the .cbr extension"
append_manifest "basic.tar" "TAR" "true" "" "TAR fixture created by bsdtar"
for extension in cbt pax ustar; do
  append_manifest "basic.$extension" "TAR" "true" "" "TAR fixture under the .$extension extension"
done
append_manifest "basic.tar.gz" "TAR.GZ" "true" "" "Tar fixture compressed with gzip"
append_manifest "basic.tgz" "TAR.GZ" "true" "" "Tar.GZ fixture under the .tgz extension"
append_manifest "basic.tar.bz2" "TAR.BZ2" "true" "" "Tar fixture compressed with bzip2"
for extension in tbz2 tbz; do
  append_manifest "basic.$extension" "TAR.BZ2" "true" "" "Tar.BZ2 fixture under the .$extension extension"
done
append_manifest "basic.tar.xz" "TAR.XZ" "true" "" "Tar fixture compressed with xz"
append_manifest "basic.txz" "TAR.XZ" "true" "" "Tar.XZ fixture under the .txz extension"
append_manifest "basic.tar.lzma" "TAR.LZMA" "true" "" "Tar fixture compressed with legacy LZMA"
append_manifest "basic.tlzma" "TAR.LZMA" "true" "" "Tar.LZMA fixture under the .tlzma extension"
append_manifest "basic.tar.lz" "TAR.LZ" "true" "" "Tar fixture compressed with lzip"
append_manifest "basic.tar.lzo" "TAR.LZO" "true" "" "Tar fixture compressed with lzop"
append_manifest "basic.tar.Z" "TAR.Z" "true" "" "Tar fixture compressed with Unix compress"
append_manifest "basic-lowercase.tar.z" "TAR.Z" "true" "" "Tar.Z fixture under the lowercase .tar.z extension"
append_manifest "basic.taz" "TAR.Z" "true" "" "Tar.Z fixture under the .taz extension"
append_manifest "basic.tar.lz4" "TAR.LZ4" "true" "" "Tar fixture compressed with LZ4"
append_manifest "basic.tar.zst" "TAR.ZST" "true" "" "Tar fixture compressed with zstd"
append_manifest "basic.cpio" "CPIO" "true" "" "CPIO fixture created by bsdtar"
append_manifest "basic.cpio.gz" "CPIO" "true" "" "CPIO fixture compressed with gzip"
append_manifest "basic.cpgz" "CPIO" "true" "" "CPIO fixture compressed with gzip under the .cpgz extension"
append_manifest "basic.cpio.bz2" "CPIO" "true" "" "CPIO fixture compressed with bzip2"
append_manifest "basic.cpio.xz" "CPIO" "true" "" "CPIO fixture compressed with xz"
append_manifest "basic.cpio.lzma" "CPIO" "true" "" "CPIO fixture compressed with legacy LZMA"
append_manifest "basic.cpio.zst" "CPIO" "true" "" "CPIO fixture compressed with zstd"
append_manifest "basic.cab" "CAB" "true" "" "CAB fixture created by gcab"
append_manifest "basic.rar" "RAR" "true" "" "RAR5 fixture created by the RAR tool"
append_manifest "basic.lha" "LHA" "true" "" "LHA fixture created by jlha-utils in Docker"
append_manifest "basic.lzh" "LHA" "true" "" "LHA fixture under the .lzh extension"
append_manifest "basic.rpm" "RPM" "true" "" "RPM package fixture created by rpmbuild"
append_manifest "basic.xar" "XAR" "true" "" "XAR fixture created by macOS xar"
append_manifest "basic.warc" "WARC" "true" "" "WARC fixture created by bsdtar"
append_manifest "basic.iso" "ISO" "true" "" "ISO fixture created by hdiutil makehybrid"
append_manifest "basic.deb" "DEB" "true" "" "Debian ar package fixture"
append_manifest "basic.ar" "AR" "true" "" "AR fixture created by the platform ar tool"
append_manifest "basic.a" "AR" "true" "" "AR fixture under the .a extension"
append_manifest "basic.lib" "AR" "true" "" "AR fixture under the .lib extension"
append_manifest "basic.dmg" "DMG" "true" "" "Disk image fixture created by hdiutil create -srcfolder"
append_manifest "basic.pkg" "PKG" "true" "" "Apple package fixture created by pkgbuild"
append_manifest "basic.msi" "MSI" "true" "" "Windows Installer fixture created by wixl (msitools)"
append_manifest "basic.vhd" "VHD" "true" "" "VPC disk image fixture: MBR + NTFS, qemu-img -O vpc (docker ntfs-3g populates)"
append_manifest "basic.vmdk" "VMDK" "true" "" "VMware disk image fixture: superfloppy FAT32, qemu-img -O vmdk (mtools populates)"
append_manifest "basic.udf" "UDF" "true" "" "UDF 2.01 optical fixture authored by mkudffs (docker) with a populated payload"
append_manifest "basic.mtree" "MTREE" "true" "" "MTREE manifest fixture with directories, files, sizes, and a symlink"
append_manifest "basic.tzap" "TZAP" "true" "" "TZAP fixture created by zmanager-cli"
append_manifest "basic.tzst" "TAR.ZST" "true" "" "Tar.ZST fixture under the .tzst extension"
append_manifest "basic.aea" "AAR" "true" "" "Apple Archive fixture under the .aea extension"
append_manifest "basic.aar" "AAR" "true" "" "Apple Archive fixture created by macOS aa"
append_manifest "basic.txt.gz" "RAW" "true" "" "Raw gzip stream fixture"
append_manifest "basic.txt.bz2" "RAW" "true" "" "Raw bzip2 stream fixture"
append_manifest "basic.txt.xz" "RAW" "true" "" "Raw xz stream fixture"
append_manifest "basic.txt.lzma" "RAW" "true" "" "Raw legacy LZMA stream fixture"
append_manifest "basic.txt.zst" "RAW" "true" "" "Raw zstd stream fixture"
append_manifest "basic.txt.lz" "RAW" "true" "" "Raw lzip stream fixture"
append_manifest "basic.txt.br" "RAW" "true" "" "Raw Brotli stream fixture"
append_manifest "basic.txt.lz4" "RAW" "true" "" "Raw LZ4 stream fixture"
append_manifest "basic.txt.lzo" "RAW" "true" "" "Raw lzop stream fixture"
append_manifest "basic.txt.Z" "RAW" "true" "" "Raw Unix compress stream fixture"
append_manifest "basic.txt.uu" "RAW" "true" "" "Raw uuencode stream fixture"
append_manifest "basic.txt.b64" "RAW" "true" "" "Raw base64 stream fixture"
append_manifest "basic.tar.uu" "TAR.UU" "true" "" "Tar fixture encoded with uuencode"
append_manifest "basic.tar.b64" "TAR.B64" "true" "" "Tar fixture encoded with base64"

echo "Generated fixtures in $ARCHIVES"
