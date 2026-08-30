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
    pub const TAR_UU: FormatId = FormatId("tar.uu");
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
    pub const SQUASHFS: FormatId = FormatId("squashfs");
    pub const APPIMAGE: FormatId = FormatId("appimage");
    pub const WIM: FormatId = FormatId("wim");
    pub const VDI: FormatId = FormatId("vdi");
    pub const NRG: FormatId = FormatId("nrg");
    pub const MDF: FormatId = FormatId("mdf");
    pub const CDI: FormatId = FormatId("cdi");
    pub const ISZ: FormatId = FormatId("isz");
    pub const CCD: FormatId = FormatId("ccd");
    pub const CUE: FormatId = FormatId("cue");
    pub const RAW_STREAM: FormatId = FormatId("raw_stream");

    /// Converts a canonical archive-format kind into its engine identity.
    #[must_use]
    pub const fn from_archive_format_kind(kind: ArchiveFormatKind) -> Option<Self> {
        match kind {
            ArchiveFormatKind::Unknown => None,
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
            ArchiveFormatKind::TarUu => Some(Self::TAR_UU),
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
            ArchiveFormatKind::Squashfs => Some(Self::SQUASHFS),
            ArchiveFormatKind::AppImage => Some(Self::APPIMAGE),
            ArchiveFormatKind::Wim => Some(Self::WIM),
            ArchiveFormatKind::Vdi => Some(Self::VDI),
            ArchiveFormatKind::Nrg => Some(Self::NRG),
            ArchiveFormatKind::Mdf => Some(Self::MDF),
            ArchiveFormatKind::Cdi => Some(Self::CDI),
            ArchiveFormatKind::Isz => Some(Self::ISZ),
            ArchiveFormatKind::Ccd => Some(Self::CCD),
            ArchiveFormatKind::Cue => Some(Self::CUE),
            ArchiveFormatKind::RawStream => Some(Self::RAW_STREAM),
        }
    }

    /// Returns the underlying str representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// Maps this format to the extraction job-kind label used by product
    /// progress surfaces.
    ///
    /// Pure display data: consumers never use the result for backend
    /// selection or dispatch, so the format→label knowledge lives once on
    /// the engine identity instead of being re-derived per consumer.
    #[must_use]
    pub fn extract_job_kind(self) -> crate::jobs::JobKind {
        use crate::jobs::JobKind;
        match self {
            Self::ZIP | Self::SPLIT_ZIP => JobKind::ZipExtract,
            Self::SEVEN_Z => JobKind::SevenZExtract,
            Self::TAR_ZST => JobKind::TarZstdExtract,
            Self::TZAP => JobKind::TzapExtract,
            Self::RAR => JobKind::RarExtract,
            Self::APPLE_ARCHIVE => JobKind::AppleArchiveExtract,
            Self::RAW_STREAM => JobKind::RawStreamExtract,
            _ => JobKind::ArchiveExtract,
        }
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
        FormatId::from_archive_format_kind(kind)
    }
}
