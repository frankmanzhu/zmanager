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
  "$ARCHIVES"/basic.7z \
  "$ARCHIVES"/basic.tar.gz \
  "$ARCHIVES"/basic.tar.xz \
  "$ARCHIVES"/basic.tar.zst \
  "$ARCHIVES"/basic.cpio \
  "$ARCHIVES"/basic.xar \
  "$ARCHIVES"/basic.iso \
  "$ARCHIVES"/basic.deb \
  "$ARCHIVES"/basic.dmg \
  "$ARCHIVES"/basic.pkg \
  "$ARCHIVES"/basic.msi \
  "$ARCHIVES"/basic.vhd \
  "$ARCHIVES"/basic.vmdk \
  "$ARCHIVES"/basic.udf

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
)

bsdtar -czf "$ARCHIVES/basic.tar.gz" -C "$WORK" payload
bsdtar -cJf "$ARCHIVES/basic.tar.xz" -C "$WORK" payload
bsdtar --format=cpio -cf "$ARCHIVES/basic.cpio" -C "$WORK" payload

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
append_manifest "basic.7z" "7Z" "true" "" "7Z LZMA2 solid fixture created by ZManager"
append_manifest "basic.tar.gz" "TAR.GZ" "true" "" "Tar fixture compressed with gzip"
append_manifest "basic.tar.xz" "TAR.XZ" "true" "" "Tar fixture compressed with xz"
append_manifest "basic.tar.zst" "TAR.ZST" "true" "" "Tar fixture compressed with zstd"
append_manifest "basic.cpio" "CPIO" "true" "" "CPIO fixture created by bsdtar"
append_manifest "basic.xar" "XAR" "true" "" "XAR fixture created by macOS xar"
append_manifest "basic.iso" "ISO" "true" "" "ISO fixture created by hdiutil makehybrid"
append_manifest "basic.deb" "DEB" "true" "" "Debian ar package fixture"
append_manifest "basic.dmg" "DMG" "true" "" "Disk image fixture created by hdiutil create -srcfolder"
append_manifest "basic.pkg" "PKG" "true" "" "Apple package fixture created by pkgbuild"
append_manifest "basic.msi" "MSI" "true" "" "Windows Installer fixture created by wixl (msitools)"
append_manifest "basic.vhd" "VHD" "true" "" "VPC disk image fixture: MBR + NTFS, qemu-img -O vpc (docker ntfs-3g populates)"
append_manifest "basic.vmdk" "VMDK" "true" "" "VMware disk image fixture: superfloppy FAT32, qemu-img -O vmdk (mtools populates)"
append_manifest "basic.udf" "UDF" "true" "" "UDF 2.01 optical fixture authored by mkudffs (docker) with a populated payload"

echo "Generated fixtures in $ARCHIVES"
