use std::path::Path;
pub(crate) const FORMAT_ZIP: &str = "zip";
pub(crate) const FORMAT_TAR_ZST: &str = "tar.zst";
pub(crate) const FORMAT_TZAP: &str = "tzap";
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) const FORMAT_APPLE_ARCHIVE: &str = "aar";
pub(crate) const FORMAT_DMG: &str = "dmg";
pub(crate) const FORMAT_PKG: &str = "pkg";
pub(crate) const FORMAT_SEVEN_Z: &str = "7z";
pub(crate) const FORMAT_TGZ: &str = "tgz";
pub(crate) const FORMAT_RAR: &str = "rar";
pub(crate) const FORMAT_DEB: &str = "deb";
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
pub(crate) const FORMAT_LIBARCHIVE: &str = "libarchive";
pub(crate) const BACKEND_DEB_NESTED: &str = "deb-nested";
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
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) const APPLE_ARCHIVE_FORMAT_ALIASES: &[&str] = &[FORMAT_APPLE_ARCHIVE, "apple-archive"];
pub(crate) const TGZ_FORMAT_ALIASES: &[&str] = &[FORMAT_TGZ, "tar.gz", "gz"];

// Extension lists are canonical in `zmanager_core::archive_format` (CR-114);
// this crate re-exports them for display and option validation.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) use zmanager_core::archive_format::APPLE_ARCHIVE_EXTENSIONS;
pub(crate) use zmanager_core::archive_format::{
    AR_EXTENSIONS, CAB_EXTENSIONS, CPIO_EXTENSIONS, DEB_EXTENSIONS, ISO_EXTENSIONS, LHA_EXTENSIONS, MTREE_EXTENSIONS, RAR_EXTENSIONS, RPM_EXTENSIONS,
    SEVEN_Z_EXTENSIONS, TAR_BZ2_EXTENSIONS, TAR_EXTENSIONS, TAR_LZMA_EXTENSIONS, TAR_XZ_EXTENSIONS, TAR_ZST_EXTENSIONS, TGZ_EXTENSIONS, TZAP_EXTENSIONS,
    WARC_EXTENSIONS, XAR_EXTENSIONS, ZIP_FAMILY_EXTENSIONS,
};

pub(crate) const ZIP_CREATE_EXTENSIONS: &[&str] = &[".zip"];
// Placeholder extensions for the libarchive fallback handler, which accepts
// formats the other backends cannot parse (DEB, RAR, raw streams, ...).
const LIBARCHIVE_FALLBACK_EXTENSIONS: &[&str] = &["fallback"];

#[derive(Clone, Copy)]
pub(crate) struct FormatDescriptor {
    pub(crate) name: &'static str,
    pub(crate) extensions: &'static [&'static str],
}

pub(crate) const CREATE_FORMATS: &[FormatDescriptor] = &[
    FormatDescriptor { name: FORMAT_ZIP, extensions: ZIP_CREATE_EXTENSIONS },
    FormatDescriptor { name: FORMAT_TAR_ZST, extensions: TAR_ZST_EXTENSIONS },
    FormatDescriptor { name: FORMAT_TZAP, extensions: TZAP_EXTENSIONS },
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    FormatDescriptor { name: FORMAT_APPLE_ARCHIVE, extensions: APPLE_ARCHIVE_EXTENSIONS },
    FormatDescriptor { name: FORMAT_SEVEN_Z, extensions: SEVEN_Z_EXTENSIONS },
    FormatDescriptor { name: FORMAT_TGZ, extensions: TGZ_EXTENSIONS },
];

pub(crate) const EXTRACT_FORMATS: &[FormatDescriptor] = &[
    FormatDescriptor { name: FORMAT_ZIP, extensions: ZIP_FAMILY_EXTENSIONS },
    FormatDescriptor { name: FORMAT_TAR_ZST, extensions: TAR_ZST_EXTENSIONS },
    FormatDescriptor { name: FORMAT_TZAP, extensions: TZAP_EXTENSIONS },
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    FormatDescriptor { name: FORMAT_APPLE_ARCHIVE, extensions: APPLE_ARCHIVE_EXTENSIONS },
    FormatDescriptor { name: FORMAT_SEVEN_Z, extensions: SEVEN_Z_EXTENSIONS },
    FormatDescriptor { name: FORMAT_TGZ, extensions: TGZ_EXTENSIONS },
    FormatDescriptor { name: FORMAT_TAR, extensions: TAR_EXTENSIONS },
    FormatDescriptor { name: FORMAT_TAR, extensions: TAR_BZ2_EXTENSIONS },
    FormatDescriptor { name: FORMAT_TAR, extensions: TAR_XZ_EXTENSIONS },
    FormatDescriptor { name: FORMAT_TAR, extensions: TAR_LZMA_EXTENSIONS },
    FormatDescriptor { name: FORMAT_ISO, extensions: ISO_EXTENSIONS },
    FormatDescriptor { name: FORMAT_CAB, extensions: CAB_EXTENSIONS },
    FormatDescriptor { name: FORMAT_CPIO, extensions: CPIO_EXTENSIONS },
    FormatDescriptor { name: FORMAT_RPM, extensions: RPM_EXTENSIONS },
    FormatDescriptor { name: FORMAT_XAR, extensions: XAR_EXTENSIONS },
    FormatDescriptor { name: FORMAT_LHA, extensions: LHA_EXTENSIONS },
    FormatDescriptor { name: FORMAT_AR, extensions: AR_EXTENSIONS },
    FormatDescriptor { name: FORMAT_WARC, extensions: WARC_EXTENSIONS },
    FormatDescriptor { name: FORMAT_MTREE, extensions: MTREE_EXTENSIONS },
    FormatDescriptor { name: FORMAT_RAW_STREAM, extensions: zmanager_core::raw_stream_backend::RAW_STREAM_SUFFIXES },
    FormatDescriptor { name: FORMAT_LIBARCHIVE, extensions: LIBARCHIVE_FALLBACK_EXTENSIONS },
];
// Path-based format detection delegates to the core detector (CR-114); the
// extension predicates no longer live here so consumers cannot drift.
use zmanager_core::archive_format::{ArchiveFormatKind, detect_archive_format};

pub(crate) fn is_zip_family_archive(path: &str) -> bool {
    matches!(detect_archive_format(path), ArchiveFormatKind::Zip | ArchiveFormatKind::SplitZip)
}

pub(crate) fn is_split_zip_archive_path(path: &str) -> bool {
    zmanager_core::libarchive_backend::is_split_zip_path(Path::new(path))
}

pub(crate) fn is_7z_archive(path: &str) -> bool {
    matches!(detect_archive_format(path), ArchiveFormatKind::SevenZ)
}

pub(crate) fn is_rar_archive(path: &str) -> bool {
    matches!(detect_archive_format(path), ArchiveFormatKind::Rar)
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

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn is_apple_archive(path: &str) -> bool {
    matches!(detect_archive_format(path), ArchiveFormatKind::AppleArchive)
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub(crate) fn is_apple_archive(_path: &str) -> bool {
    false
}

pub(crate) fn is_dmg_archive(path: &str) -> bool {
    matches!(detect_archive_format(path), ArchiveFormatKind::Dmg)
}

pub(crate) fn is_pkg_archive(path: &str) -> bool {
    matches!(detect_archive_format(path), ArchiveFormatKind::Pkg)
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
