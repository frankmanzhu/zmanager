//! Canonical archive-format detection by path (CR-114).
//!
//! Historically every consumer (the CLI's format helpers, the archive
//! browser, and the extraction/list/test dispatch chains) carried its own
//! extension predicates, and they drifted. This is the single detector;
//! callers dispatch on [`ArchiveFormatKind`].

use std::path::Path;

/// Canonical extension lists for path-based format detection.
pub const ZIP_FAMILY_EXTENSIONS: &[&str] = &[".zip", ".zipx", ".jar", ".war", ".ipa", ".apk", ".appx", ".xpi"];
pub const SEVEN_Z_EXTENSIONS: &[&str] = &[".7z"];
pub const RAR_EXTENSIONS: &[&str] = &[".rar", ".cbr"];
pub const TAR_ZST_EXTENSIONS: &[&str] = &[".tar.zst", ".tzst"];
pub const TGZ_EXTENSIONS: &[&str] = &[".tgz", ".tar.gz"];
pub const TZAP_EXTENSIONS: &[&str] = &[".tzap"];
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const APPLE_ARCHIVE_EXTENSIONS: &[&str] = &[".aar", ".aea"];
pub const DEB_EXTENSIONS: &[&str] = &[".deb"];

/// Archive format kind detected from a path.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ArchiveFormatKind {
    /// Single-file ZIP family (zip/zipx/jar/…).
    Zip,
    /// Split ZIP volume set (`.z01`, `.z02`, …, `.zip`).
    SplitZip,
    /// 7z, including numbered `.7z.001` volumes.
    SevenZ,
    /// `.tar.zst` / `.tzst`.
    TarZst,
    /// `.tgz` / `.tar.gz` — handled by the libarchive backend.
    TarGz,
    /// TZAP, including numbered volumes.
    Tzap,
    /// RAR (`.rar`, `.cbr`).
    Rar,
    /// Apple Archive (`.aar`, `.aea`).
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    AppleArchive,
    /// `.deb` package.
    Deb,
    /// Raw single-file compression stream.
    RawStream,
    /// Not recognized as any archive format.
    Unknown,
}

/// Detects the archive format from a path.
///
/// Raw-stream detection runs first because it deliberately excludes container
/// spellings such as `.tar.gz`; the remaining extension sets are disjoint.
#[must_use]
pub fn detect_archive_format(path: impl AsRef<Path>) -> ArchiveFormatKind {
    let path = path.as_ref();
    if crate::raw_stream_backend::detect_raw_stream_format(path).is_some() {
        return ArchiveFormatKind::RawStream;
    }
    if ends_with_any(path, ZIP_FAMILY_EXTENSIONS) {
        return if crate::libarchive_backend::is_split_zip_path(path) {
            ArchiveFormatKind::SplitZip
        } else {
            ArchiveFormatKind::Zip
        };
    }
    if ends_with_any(path, SEVEN_Z_EXTENSIONS) || crate::sevenz_backend::is_7z_volume_path(path) {
        return ArchiveFormatKind::SevenZ;
    }
    if ends_with_any(path, RAR_EXTENSIONS) {
        return ArchiveFormatKind::Rar;
    }
    if ends_with_any(path, TAR_ZST_EXTENSIONS) {
        return ArchiveFormatKind::TarZst;
    }
    if ends_with_any(path, TGZ_EXTENSIONS) {
        return ArchiveFormatKind::TarGz;
    }
    if crate::tzap::is_tzap_archive_path(path) {
        return ArchiveFormatKind::Tzap;
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    if ends_with_any(path, APPLE_ARCHIVE_EXTENSIONS) {
        return ArchiveFormatKind::AppleArchive;
    }
    if ends_with_any(path, DEB_EXTENSIONS) {
        return ArchiveFormatKind::Deb;
    }
    ArchiveFormatKind::Unknown
}

fn ends_with_any(path: &Path, suffixes: &[&str]) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else { return false };
    suffixes.iter().any(|suffix| crate::strings::ends_with_ignore_ascii_case(name, suffix))
}
