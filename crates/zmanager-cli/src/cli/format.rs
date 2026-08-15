pub(crate) const FORMAT_ZIP: &str = "zip";
pub(crate) const FORMAT_TAR_ZST: &str = "tar.zst";
pub(crate) const FORMAT_TZAP: &str = "tzap";
pub(crate) const FORMAT_APPLE_ARCHIVE: &str = "aar";
pub(crate) const FORMAT_MSI: &str = "msi";
pub(crate) const FORMAT_VHD: &str = "vhd";
pub(crate) const FORMAT_VMDK: &str = "vmdk";
pub(crate) const FORMAT_UDF: &str = "udf";
pub(crate) const FORMAT_SEVEN_Z: &str = "7z";
pub(crate) const FORMAT_TGZ: &str = "tgz";
pub(crate) const FORMAT_TAR: &str = "tar";
pub(crate) const FORMAT_ISO: &str = "iso";
pub(crate) const FORMAT_CAB: &str = "cab";
pub(crate) const FORMAT_CPIO: &str = "cpio";
pub(crate) const FORMAT_RPM: &str = "rpm";
pub(crate) const FORMAT_XAR: &str = "xar";
pub(crate) const FORMAT_LHA: &str = "lha";
pub(crate) const FORMAT_AR: &str = "ar";
pub(crate) const FORMAT_WARC: &str = "warc";
pub(crate) const FORMAT_MTREE: &str = "mtree";
pub(crate) const FORMAT_RAW_STREAM: &str = "raw-stream";
pub(crate) const TZAP_DEFAULT_RECOVERY_PERCENTAGE: u8 = 5;
pub(crate) const TZAP_SINGLE_VOLUME_LOSS_TOLERANCE: u8 = 0;
pub(crate) const TZAP_SPLIT_VOLUME_LOSS_TOLERANCE: u8 = 1;

pub(crate) const TEMP_ARCHIVE_PREFIX: &str = ".";
pub(crate) const TEMP_ARCHIVE_MARKER: &str = ".tmp";
pub(crate) const SIZE_UNIT_KIB: u64 = 1024;
pub(crate) const SIZE_UNIT_MIB: u64 = SIZE_UNIT_KIB * 1024;
pub(crate) const SIZE_UNIT_GIB: u64 = SIZE_UNIT_MIB * 1024;
pub(crate) const SIZE_UNIT_TIB: u64 = SIZE_UNIT_GIB * 1024;

pub(crate) const TAR_ZST_FORMAT_ALIASES: &[&str] = &[FORMAT_TAR_ZST, "tzst", "zst"];
pub(crate) const TZAP_FORMAT_ALIASES: &[&str] = &[FORMAT_TZAP];
pub(crate) const APPLE_ARCHIVE_FORMAT_ALIASES: &[&str] = &[FORMAT_APPLE_ARCHIVE, "apple-archive"];
pub(crate) const TGZ_FORMAT_ALIASES: &[&str] = &[FORMAT_TGZ, "tar.gz", "gz"];

// Extension lists are canonical in `zmanager_core::archive_format` (CR-114);
// this crate re-exports them for display and option validation.
pub(crate) use zmanager_core::archive_format::{
    APPLE_ARCHIVE_EXTENSIONS, AR_EXTENSIONS, CAB_EXTENSIONS, CPIO_EXTENSIONS, DEB_EXTENSIONS, ISO_EXTENSIONS, LHA_EXTENSIONS, MSI_EXTENSIONS, MTREE_EXTENSIONS,
    RAR_EXTENSIONS, RPM_EXTENSIONS, SEVEN_Z_EXTENSIONS, TAR_BZ2_EXTENSIONS, TAR_EXTENSIONS, TAR_LZMA_EXTENSIONS, TAR_XZ_EXTENSIONS, TAR_ZST_EXTENSIONS,
    TGZ_EXTENSIONS, TZAP_EXTENSIONS, UDF_EXTENSIONS, VHD_EXTENSIONS, VMDK_EXTENSIONS, WARC_EXTENSIONS, XAR_EXTENSIONS, ZIP_FAMILY_EXTENSIONS,
};

pub(crate) const ZIP_CREATE_EXTENSIONS: &[&str] = &[".zip"];
#[derive(Clone, Copy)]
pub(crate) struct FormatDescriptor {
    pub(crate) name: &'static str,
    pub(crate) extensions: &'static [&'static str],
    /// Core format kind, used to query backend availability for listings.
    pub(crate) kind: ArchiveFormatKind,
}

pub(crate) const CREATE_FORMATS: &[FormatDescriptor] = &[
    FormatDescriptor { name: FORMAT_ZIP, extensions: ZIP_CREATE_EXTENSIONS, kind: ArchiveFormatKind::Zip },
    FormatDescriptor { name: FORMAT_TAR_ZST, extensions: TAR_ZST_EXTENSIONS, kind: ArchiveFormatKind::TarZst },
    FormatDescriptor { name: FORMAT_TZAP, extensions: TZAP_EXTENSIONS, kind: ArchiveFormatKind::Tzap },
    FormatDescriptor { name: FORMAT_APPLE_ARCHIVE, extensions: APPLE_ARCHIVE_EXTENSIONS, kind: ArchiveFormatKind::AppleArchive },
    FormatDescriptor { name: FORMAT_SEVEN_Z, extensions: SEVEN_Z_EXTENSIONS, kind: ArchiveFormatKind::SevenZ },
    FormatDescriptor { name: FORMAT_TGZ, extensions: TGZ_EXTENSIONS, kind: ArchiveFormatKind::TarGz },
];

pub(crate) const EXTRACT_FORMATS: &[FormatDescriptor] = &[
    FormatDescriptor { name: FORMAT_ZIP, extensions: ZIP_FAMILY_EXTENSIONS, kind: ArchiveFormatKind::Zip },
    FormatDescriptor { name: FORMAT_TAR_ZST, extensions: TAR_ZST_EXTENSIONS, kind: ArchiveFormatKind::TarZst },
    FormatDescriptor { name: FORMAT_TZAP, extensions: TZAP_EXTENSIONS, kind: ArchiveFormatKind::Tzap },
    FormatDescriptor { name: FORMAT_APPLE_ARCHIVE, extensions: APPLE_ARCHIVE_EXTENSIONS, kind: ArchiveFormatKind::AppleArchive },
    FormatDescriptor { name: FORMAT_SEVEN_Z, extensions: SEVEN_Z_EXTENSIONS, kind: ArchiveFormatKind::SevenZ },
    FormatDescriptor { name: FORMAT_TGZ, extensions: TGZ_EXTENSIONS, kind: ArchiveFormatKind::TarGz },
    FormatDescriptor { name: FORMAT_TAR, extensions: TAR_EXTENSIONS, kind: ArchiveFormatKind::Tar },
    FormatDescriptor { name: FORMAT_TAR, extensions: TAR_BZ2_EXTENSIONS, kind: ArchiveFormatKind::TarBz2 },
    FormatDescriptor { name: FORMAT_TAR, extensions: TAR_XZ_EXTENSIONS, kind: ArchiveFormatKind::TarXz },
    FormatDescriptor { name: FORMAT_TAR, extensions: TAR_LZMA_EXTENSIONS, kind: ArchiveFormatKind::TarLzma },
    FormatDescriptor { name: FORMAT_TAR, extensions: zmanager_core::archive_format::TAR_LZ_EXTENSIONS, kind: ArchiveFormatKind::TarLz },
    FormatDescriptor { name: FORMAT_TAR, extensions: zmanager_core::archive_format::TAR_LZO_EXTENSIONS, kind: ArchiveFormatKind::TarLzo },
    FormatDescriptor { name: FORMAT_TAR, extensions: zmanager_core::archive_format::TAR_COMPRESS_EXTENSIONS, kind: ArchiveFormatKind::TarCompress },
    FormatDescriptor { name: FORMAT_TAR, extensions: zmanager_core::archive_format::TAR_LZ4_EXTENSIONS, kind: ArchiveFormatKind::TarLz4 },
    FormatDescriptor { name: FORMAT_TAR, extensions: zmanager_core::archive_format::TAR_UU_EXTENSIONS, kind: ArchiveFormatKind::TarUu },
    FormatDescriptor { name: FORMAT_ISO, extensions: ISO_EXTENSIONS, kind: ArchiveFormatKind::Iso },
    FormatDescriptor { name: FORMAT_CAB, extensions: CAB_EXTENSIONS, kind: ArchiveFormatKind::Cab },
    FormatDescriptor { name: FORMAT_CPIO, extensions: CPIO_EXTENSIONS, kind: ArchiveFormatKind::Cpio },
    FormatDescriptor { name: FORMAT_RPM, extensions: RPM_EXTENSIONS, kind: ArchiveFormatKind::Rpm },
    FormatDescriptor { name: FORMAT_XAR, extensions: XAR_EXTENSIONS, kind: ArchiveFormatKind::Xar },
    FormatDescriptor { name: FORMAT_MSI, extensions: MSI_EXTENSIONS, kind: ArchiveFormatKind::Msi },
    FormatDescriptor { name: FORMAT_VHD, extensions: VHD_EXTENSIONS, kind: ArchiveFormatKind::Vhd },
    FormatDescriptor { name: FORMAT_VMDK, extensions: VMDK_EXTENSIONS, kind: ArchiveFormatKind::Vmdk },
    FormatDescriptor { name: FORMAT_UDF, extensions: UDF_EXTENSIONS, kind: ArchiveFormatKind::Udf },
    FormatDescriptor { name: FORMAT_LHA, extensions: LHA_EXTENSIONS, kind: ArchiveFormatKind::Lha },
    FormatDescriptor { name: FORMAT_AR, extensions: AR_EXTENSIONS, kind: ArchiveFormatKind::Ar },
    FormatDescriptor { name: FORMAT_WARC, extensions: WARC_EXTENSIONS, kind: ArchiveFormatKind::Warc },
    FormatDescriptor { name: FORMAT_MTREE, extensions: MTREE_EXTENSIONS, kind: ArchiveFormatKind::Mtree },
    FormatDescriptor { name: FORMAT_RAW_STREAM, extensions: zmanager_core::engine::raw_stream_suffixes(), kind: ArchiveFormatKind::RawStream },
];
// Path-based format detection delegates to the core detector (CR-114); the
// extension predicates no longer live here so consumers cannot drift.
use zmanager_core::archive_format::{ArchiveFormatKind, detect_archive_format};

pub(crate) fn is_zip_family_archive(path: &str) -> bool {
    matches!(detect_archive_format(path), ArchiveFormatKind::Zip | ArchiveFormatKind::SplitZip)
}

pub(crate) fn is_tar_zst_archive(path: &str) -> bool {
    matches!(detect_archive_format(path), ArchiveFormatKind::TarZst)
}

pub(crate) fn is_tgz_archive(path: &str) -> bool {
    matches!(detect_archive_format(path), ArchiveFormatKind::TarGz)
}

pub(crate) fn is_tzap_archive(path: &str) -> bool {
    matches!(detect_archive_format(path), ArchiveFormatKind::Tzap)
}

pub(crate) fn is_apple_archive(path: &str) -> bool {
    matches!(detect_archive_format(path), ArchiveFormatKind::AppleArchive)
}

pub(crate) fn is_deb_archive(path: &str) -> bool {
    matches!(detect_archive_format(path), ArchiveFormatKind::Deb)
}

pub(crate) fn path_has_known_extension(path: &str, extensions: &[&str]) -> bool {
    extensions.iter().any(|extension| path_ends_with_ignore_ascii_case(path, extension))
}

fn path_ends_with_ignore_ascii_case(path: &str, suffix: &str) -> bool {
    let path = path.as_bytes();
    let suffix = suffix.as_bytes();
    path.len() >= suffix.len() && path[path.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

pub(crate) fn strip_suffix_ignore_ascii_case<'a>(value: &'a str, suffix: &str) -> Option<&'a str> {
    if path_ends_with_ignore_ascii_case(value, suffix) { value.get(..value.len() - suffix.len()) } else { None }
}
