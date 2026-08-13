//! Format identity and descriptors for the archive engine seam (ARC-100).

use crate::archive_format::ArchiveFormatKind;
use std::fmt;

/// Stable identifier for an archive format (e.g. `FormatId("zip")`).
///
/// `FormatId` decouples format identity from implementation availability.
/// `Unknown` is deliberately omitted; unrecognized or unsupported formats fail
/// adapter lookup at construction or open time.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FormatId(pub &'static str);

impl Default for FormatId {
    fn default() -> Self {
        Self::ZIP
    }
}

impl FormatId {
    /// Catch-all identity used for explicit libarchive probing of unknown
    /// filename spellings.
    pub const UNKNOWN: FormatId = FormatId("unknown");
    pub const ZIP: FormatId = FormatId("zip");
    pub const SPLIT_ZIP: FormatId = FormatId("split_zip");
    pub const SEVEN_Z: FormatId = FormatId("7z");
    pub const TAR_ZST: FormatId = FormatId("tar.zst");
    pub const TAR_GZ: FormatId = FormatId("tar.gz");
    pub const TAR: FormatId = FormatId("tar");
    pub const TAR_BZ2: FormatId = FormatId("tar.bz2");
    pub const TAR_XZ: FormatId = FormatId("tar.xz");
    pub const TAR_LZMA: FormatId = FormatId("tar.lzma");
    pub const TAR_LZ: FormatId = FormatId("tar.lz");
    pub const TAR_LZO: FormatId = FormatId("tar.lzo");
    pub const TAR_COMPRESS: FormatId = FormatId("tar.compress");
    pub const TAR_LZ4: FormatId = FormatId("tar.lz4");
    pub const TAR_LRZ: FormatId = FormatId("tar.lrz");
    pub const ISO: FormatId = FormatId("iso");
    pub const CAB: FormatId = FormatId("cab");
    pub const CPIO: FormatId = FormatId("cpio");
    pub const RPM: FormatId = FormatId("rpm");
    pub const XAR: FormatId = FormatId("xar");
    pub const PKG: FormatId = FormatId("pkg");
    pub const DMG: FormatId = FormatId("dmg");
    pub const LHA: FormatId = FormatId("lha");
    pub const AR: FormatId = FormatId("ar");
    pub const WARC: FormatId = FormatId("warc");
    pub const MTREE: FormatId = FormatId("mtree");
    pub const TZAP: FormatId = FormatId("tzap");
    pub const RAR: FormatId = FormatId("rar");
    pub const APPLE_ARCHIVE: FormatId = FormatId("apple_archive");
    pub const DEB: FormatId = FormatId("deb");
    pub const MSI: FormatId = FormatId("msi");
    pub const VHD: FormatId = FormatId("vhd");
    pub const VMDK: FormatId = FormatId("vmdk");
    pub const UDF: FormatId = FormatId("udf");
    pub const RAW_STREAM: FormatId = FormatId("raw_stream");

    /// Converts a canonical archive-format kind into its engine identity.
    #[must_use]
    pub const fn from_archive_format_kind(kind: ArchiveFormatKind) -> Option<Self> {
        match kind {
            ArchiveFormatKind::Unknown => Some(Self::UNKNOWN),
            ArchiveFormatKind::Zip => Some(Self::ZIP),
            ArchiveFormatKind::SplitZip => Some(Self::SPLIT_ZIP),
            ArchiveFormatKind::SevenZ => Some(Self::SEVEN_Z),
            ArchiveFormatKind::TarZst => Some(Self::TAR_ZST),
            ArchiveFormatKind::TarGz => Some(Self::TAR_GZ),
            ArchiveFormatKind::Tar => Some(Self::TAR),
            ArchiveFormatKind::TarBz2 => Some(Self::TAR_BZ2),
            ArchiveFormatKind::TarXz => Some(Self::TAR_XZ),
            ArchiveFormatKind::TarLzma => Some(Self::TAR_LZMA),
            ArchiveFormatKind::TarLz => Some(Self::TAR_LZ),
            ArchiveFormatKind::TarLzo => Some(Self::TAR_LZO),
            ArchiveFormatKind::TarCompress => Some(Self::TAR_COMPRESS),
            ArchiveFormatKind::TarLz4 => Some(Self::TAR_LZ4),
            ArchiveFormatKind::TarLrz => Some(Self::TAR_LRZ),
            ArchiveFormatKind::Iso => Some(Self::ISO),
            ArchiveFormatKind::Cab => Some(Self::CAB),
            ArchiveFormatKind::Cpio => Some(Self::CPIO),
            ArchiveFormatKind::Rpm => Some(Self::RPM),
            ArchiveFormatKind::Xar => Some(Self::XAR),
            ArchiveFormatKind::Pkg => Some(Self::PKG),
            ArchiveFormatKind::Dmg => Some(Self::DMG),
            ArchiveFormatKind::Lha => Some(Self::LHA),
            ArchiveFormatKind::Ar => Some(Self::AR),
            ArchiveFormatKind::Warc => Some(Self::WARC),
            ArchiveFormatKind::Mtree => Some(Self::MTREE),
            ArchiveFormatKind::Tzap => Some(Self::TZAP),
            ArchiveFormatKind::Rar => Some(Self::RAR),
            ArchiveFormatKind::AppleArchive => Some(Self::APPLE_ARCHIVE),
            ArchiveFormatKind::Deb => Some(Self::DEB),
            ArchiveFormatKind::Msi => Some(Self::MSI),
            ArchiveFormatKind::Vhd => Some(Self::VHD),
            ArchiveFormatKind::Vmdk => Some(Self::VMDK),
            ArchiveFormatKind::Udf => Some(Self::UDF),
            ArchiveFormatKind::RawStream => Some(Self::RAW_STREAM),
        }
    }

    /// Returns the underlying str representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Debug for FormatId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FormatId({})", self.0)
    }
}

impl fmt::Display for FormatId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl From<ArchiveFormatKind> for Option<FormatId> {
    fn from(kind: ArchiveFormatKind) -> Self {
        match kind {
            ArchiveFormatKind::Zip => Some(FormatId::ZIP),
            ArchiveFormatKind::SplitZip => Some(FormatId::SPLIT_ZIP),
            ArchiveFormatKind::SevenZ => Some(FormatId::SEVEN_Z),
            ArchiveFormatKind::TarZst => Some(FormatId::TAR_ZST),
            ArchiveFormatKind::TarGz => Some(FormatId::TAR_GZ),
            ArchiveFormatKind::Tar => Some(FormatId::TAR),
            ArchiveFormatKind::TarBz2 => Some(FormatId::TAR_BZ2),
            ArchiveFormatKind::TarXz => Some(FormatId::TAR_XZ),
            ArchiveFormatKind::TarLzma => Some(FormatId::TAR_LZMA),
            ArchiveFormatKind::TarLz => Some(FormatId::TAR_LZ),
            ArchiveFormatKind::TarLzo => Some(FormatId::TAR_LZO),
            ArchiveFormatKind::TarCompress => Some(FormatId::TAR_COMPRESS),
            ArchiveFormatKind::TarLz4 => Some(FormatId::TAR_LZ4),
            ArchiveFormatKind::TarLrz => Some(FormatId::TAR_LRZ),
            ArchiveFormatKind::Iso => Some(FormatId::ISO),
            ArchiveFormatKind::Cab => Some(FormatId::CAB),
            ArchiveFormatKind::Cpio => Some(FormatId::CPIO),
            ArchiveFormatKind::Rpm => Some(FormatId::RPM),
            ArchiveFormatKind::Xar => Some(FormatId::XAR),
            ArchiveFormatKind::Pkg => Some(FormatId::PKG),
            ArchiveFormatKind::Dmg => Some(FormatId::DMG),
            ArchiveFormatKind::Lha => Some(FormatId::LHA),
            ArchiveFormatKind::Ar => Some(FormatId::AR),
            ArchiveFormatKind::Warc => Some(FormatId::WARC),
            ArchiveFormatKind::Mtree => Some(FormatId::MTREE),
            ArchiveFormatKind::Tzap => Some(FormatId::TZAP),
            ArchiveFormatKind::Rar => Some(FormatId::RAR),
            ArchiveFormatKind::AppleArchive => Some(FormatId::APPLE_ARCHIVE),
            ArchiveFormatKind::Deb => Some(FormatId::DEB),
            ArchiveFormatKind::Msi => Some(FormatId::MSI),
            ArchiveFormatKind::Vhd => Some(FormatId::VHD),
            ArchiveFormatKind::Vmdk => Some(FormatId::VMDK),
            ArchiveFormatKind::Udf => Some(FormatId::UDF),
            ArchiveFormatKind::RawStream => Some(FormatId::RAW_STREAM),
            ArchiveFormatKind::Unknown => Some(FormatId::UNKNOWN),
        }
    }
}
