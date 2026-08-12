//! Canonical archive-format detection by path (CR-114).
//!
//! Historically every consumer (the CLI's format helpers, the archive
//! browser, and the extraction/list/test dispatch chains) carried its own
//! extension predicates, and they drifted. This is the single detector;
//! callers dispatch on [`ArchiveFormatKind`].

use std::path::Path;

/// Canonical extension lists for path-based format detection.
pub const ZIP_FAMILY_EXTENSIONS: &[&str] = &[".zip", ".zipx", ".jar", ".war", ".ipa", ".apk", ".appx", ".xpi", ".cbz", ".epub"];
pub const SEVEN_Z_EXTENSIONS: &[&str] = &[".7z", ".cb7"];
pub const RAR_EXTENSIONS: &[&str] = &[".rar", ".cbr"];
pub const TAR_EXTENSIONS: &[&str] = &[".tar", ".cbt"];
pub const TAR_BZ2_EXTENSIONS: &[&str] = &[".tar.bz2", ".tbz2", ".tbz"];
pub const TAR_XZ_EXTENSIONS: &[&str] = &[".tar.xz", ".txz"];
pub const TAR_LZMA_EXTENSIONS: &[&str] = &[".tar.lzma", ".tlzma"];
pub const ISO_EXTENSIONS: &[&str] = &[".iso"];
pub const CAB_EXTENSIONS: &[&str] = &[".cab"];
pub const CPIO_EXTENSIONS: &[&str] = &[".cpio"];
pub const RPM_EXTENSIONS: &[&str] = &[".rpm"];
pub const XAR_EXTENSIONS: &[&str] = &[".xar"];
pub const PKG_EXTENSIONS: &[&str] = &[".pkg"];
pub const DMG_EXTENSIONS: &[&str] = &[".dmg"];
pub const LHA_EXTENSIONS: &[&str] = &[".lha", ".lzh"];
pub const AR_EXTENSIONS: &[&str] = &[".a", ".ar", ".lib"];
pub const WARC_EXTENSIONS: &[&str] = &[".warc"];
pub const MTREE_EXTENSIONS: &[&str] = &[".mtree"];
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
    /// Uncompressed `.tar`.
    Tar,
    /// `.tar.bz2` / `.tbz2` / `.tbz`.
    TarBz2,
    /// `.tar.xz` / `.txz`.
    TarXz,
    /// `.tar.lzma` / `.tlzma`.
    TarLzma,
    /// ISO disk image (`.iso`).
    Iso,
    /// Windows Cabinet (`.cab`).
    Cab,
    /// CPIO archive (`.cpio`).
    Cpio,
    /// RPM package (`.rpm`).
    Rpm,
    /// XAR archive (`.xar`).
    Xar,
    /// Apple Installer Package (`.pkg`).
    Pkg,
    /// Apple Disk Image (`.dmg`).
    Dmg,
    /// LHA/LZH archive.
    Lha,
    /// AR archive (`.a`, `.ar`, `.lib`).
    Ar,
    /// WARC archive (`.warc`).
    Warc,
    /// Mtree hierarchy (`.mtree`).
    Mtree,
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
        return if crate::libarchive_backend::is_split_zip_path(path) { ArchiveFormatKind::SplitZip } else { ArchiveFormatKind::Zip };
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
    if ends_with_any(path, TAR_EXTENSIONS) {
        return ArchiveFormatKind::Tar;
    }
    if ends_with_any(path, TAR_BZ2_EXTENSIONS) {
        return ArchiveFormatKind::TarBz2;
    }
    if ends_with_any(path, TAR_XZ_EXTENSIONS) {
        return ArchiveFormatKind::TarXz;
    }
    if ends_with_any(path, TAR_LZMA_EXTENSIONS) {
        return ArchiveFormatKind::TarLzma;
    }
    if ends_with_any(path, ISO_EXTENSIONS) {
        return ArchiveFormatKind::Iso;
    }
    if ends_with_any(path, CAB_EXTENSIONS) {
        return ArchiveFormatKind::Cab;
    }
    if ends_with_any(path, CPIO_EXTENSIONS) {
        return ArchiveFormatKind::Cpio;
    }
    if ends_with_any(path, RPM_EXTENSIONS) {
        return ArchiveFormatKind::Rpm;
    }
    if ends_with_any(path, XAR_EXTENSIONS) {
        return ArchiveFormatKind::Xar;
    }
    if ends_with_any(path, PKG_EXTENSIONS) {
        return ArchiveFormatKind::Pkg;
    }
    if ends_with_any(path, DMG_EXTENSIONS) {
        return ArchiveFormatKind::Dmg;
    }
    if ends_with_any(path, LHA_EXTENSIONS) {
        return ArchiveFormatKind::Lha;
    }
    if ends_with_any(path, AR_EXTENSIONS) {
        return ArchiveFormatKind::Ar;
    }
    if ends_with_any(path, WARC_EXTENSIONS) {
        return ArchiveFormatKind::Warc;
    }
    if ends_with_any(path, MTREE_EXTENSIONS) {
        return ArchiveFormatKind::Mtree;
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
