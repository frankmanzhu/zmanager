//! Path validation helpers and archive format classification/labels.

use std::fs;
use std::io;
use std::path::Path;

use zmanager_core::archive_browser::BrowserEntryKind;
#[cfg(feature = "tzap-online")]
use zmanager_core::engine::{has_existing_tzap_input_volume, is_tzap_archive_path};

use crate::ffi::error::{ERROR_INVALID_REQUEST, ERROR_NOT_FOUND, bridge_error, hint, map_io_error};
use crate::ffi::types::{ArchiveEntryKind, ArchiveFormat, BridgeError, BridgeSeverity, ZmanagerGuiError};

pub(crate) fn password_ref(password: &Option<String>) -> Option<&str> {
    password.as_deref().filter(|value| !value.is_empty())
}

/// Shared first half of the path validators: trim, reject empty values, and
/// reject provider-scheme URIs. Each caller supplies its own field label and
/// provider hint, and keeps its own follow-up checks and error wording.
fn sanitize_path_value(value: String, field: &str, provider_hint: &str) -> Result<String, ZmanagerGuiError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(bridge_error(ERROR_INVALID_REQUEST, format!("{field} cannot be empty"), None, BridgeSeverity::Warning, false));
    }

    if value.contains("://") {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            format!("{field} must be an app-controlled filesystem path"),
            hint(provider_hint),
            BridgeSeverity::Warning,
            false,
        ));
    }

    Ok(value)
}

pub(crate) fn ensure_non_empty_entry_path(value: String) -> Result<String, ZmanagerGuiError> {
    if value.is_empty() {
        return Err(bridge_error(ERROR_INVALID_REQUEST, "entryPath cannot be empty", None, BridgeSeverity::Warning, false));
    }

    Ok(value)
}

pub(crate) fn usize_from_u64(value: u64, field: &str) -> Result<usize, ZmanagerGuiError> {
    usize::try_from(value)
        .map_err(|_| bridge_error(ERROR_INVALID_REQUEST, format!("{field} is too large for this device"), None, BridgeSeverity::Warning, false))
}

pub(crate) fn ensure_existing_file_path(value: String, field: &str) -> Result<String, ZmanagerGuiError> {
    let value = sanitize_path_value(value, field, "Copy provider-backed files into app cache before calling the Rust bridge.")?;

    let path = Path::new(&value);
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            // Volume-set archives are addressed by their logical base path;
            // the engine owns discovery of the physical numbered volumes.
            if zmanager_core::engine::has_existing_tzap_input_volume(path) || zmanager_core::engine::has_existing_7z_input_volume(path) {
                return Ok(value);
            }
            return Err(bridge_error(
                ERROR_NOT_FOUND,
                format!("{field} does not exist"),
                hint("Choose an archive that has already been copied into app-controlled storage."),
                BridgeSeverity::Warning,
                false,
            ));
        }
        Err(source) => return Err(map_io_error(path.to_path_buf(), source)),
    };

    if !metadata.is_file() {
        return Err(bridge_error(ERROR_INVALID_REQUEST, format!("{field} must point to a file"), None, BridgeSeverity::Warning, false));
    }

    Ok(value)
}

/// Validates an existing archive path for the tzap service endpoints.
///
/// Unlike [`ensure_existing_file_path`], a missing path is accepted when it
/// names a TZAP archive (or one of its numbered volumes) whose volumes exist
/// beside it — a multi-volume archive is addressed by its non-existent base
/// name (e.g. `sample.tzap`), and the core discovery resolves the volumes.
#[cfg(feature = "tzap-online")]
pub(crate) fn ensure_existing_tzap_archive_path(value: String, field: &str) -> Result<String, ZmanagerGuiError> {
    let value = sanitize_path_value(value, field, "Copy provider-backed files into app cache before calling the Rust bridge.")?;

    let path = Path::new(&value);
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(value),
        Ok(_) => Err(bridge_error(ERROR_INVALID_REQUEST, format!("{field} must point to a file"), None, BridgeSeverity::Warning, false)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            if is_tzap_archive_path(path) && has_existing_tzap_input_volume(path) {
                Ok(value)
            } else {
                Err(bridge_error(
                    ERROR_NOT_FOUND,
                    format!("{field} does not exist"),
                    hint("Choose an archive that has already been copied into app-controlled storage."),
                    BridgeSeverity::Warning,
                    false,
                ))
            }
        }
        Err(source) => Err(map_io_error(path.to_path_buf(), source)),
    }
}

/// Classifies a path into the FFI's [`ArchiveFormat`], delegating recognition
/// to the canonical detector in `zmanager-core` (CR-114) and refining the few
/// cases the FFI enum expresses more precisely than core kinds: split-ZIP
/// sidecar volumes (`.zNN` without the final `.zip`), multipart RAR volumes
/// (`.partNN.rar` / `.rNN` sidecars), the raw-stream codec split, and XIP.
pub(crate) fn classify_archive_path(path: &Path) -> (ArchiveFormat, Vec<BridgeError>) {
    let file_name = path.file_name().and_then(|value| value.to_str()).unwrap_or_default().to_ascii_lowercase();
    let extension = path.extension().and_then(|value| value.to_str()).unwrap_or_default().to_ascii_lowercase();

    let kind = zmanager_core::archive_format::detect_archive_format(path);
    let format = match kind {
        zmanager_core::archive_format::ArchiveFormatKind::SplitZip => ArchiveFormat::SplitZip,
        zmanager_core::archive_format::ArchiveFormatKind::Zip => ArchiveFormat::Zip,
        zmanager_core::archive_format::ArchiveFormatKind::SevenZ => ArchiveFormat::SevenZ,
        zmanager_core::archive_format::ArchiveFormatKind::Rar if file_name.contains(".part") => ArchiveFormat::MultipartRar,
        zmanager_core::archive_format::ArchiveFormatKind::Rar => ArchiveFormat::Rar,
        zmanager_core::archive_format::ArchiveFormatKind::TarZst => ArchiveFormat::TarZst,
        zmanager_core::archive_format::ArchiveFormatKind::TarGz => ArchiveFormat::TarGz,
        zmanager_core::archive_format::ArchiveFormatKind::Tar => ArchiveFormat::Tar,
        zmanager_core::archive_format::ArchiveFormatKind::TarBz2 => ArchiveFormat::TarBz2,
        zmanager_core::archive_format::ArchiveFormatKind::TarXz => ArchiveFormat::TarXz,
        zmanager_core::archive_format::ArchiveFormatKind::TarLzma => ArchiveFormat::TarLzma,
        zmanager_core::archive_format::ArchiveFormatKind::TarLz => ArchiveFormat::TarLz,
        zmanager_core::archive_format::ArchiveFormatKind::TarLzo => ArchiveFormat::TarLzo,
        zmanager_core::archive_format::ArchiveFormatKind::TarCompress => ArchiveFormat::TarCompress,
        zmanager_core::archive_format::ArchiveFormatKind::TarLz4 => ArchiveFormat::TarLz4,
        zmanager_core::archive_format::ArchiveFormatKind::TarUu => ArchiveFormat::TarUu,
        zmanager_core::archive_format::ArchiveFormatKind::Iso => ArchiveFormat::Iso,
        zmanager_core::archive_format::ArchiveFormatKind::Cab => ArchiveFormat::Cab,
        zmanager_core::archive_format::ArchiveFormatKind::Cpio => ArchiveFormat::Cpio,
        zmanager_core::archive_format::ArchiveFormatKind::Rpm => ArchiveFormat::Rpm,
        zmanager_core::archive_format::ArchiveFormatKind::Xar => ArchiveFormat::Xar,
        zmanager_core::archive_format::ArchiveFormatKind::Pkg => ArchiveFormat::Pkg,
        zmanager_core::archive_format::ArchiveFormatKind::Dmg => ArchiveFormat::Dmg,
        zmanager_core::archive_format::ArchiveFormatKind::Lha => ArchiveFormat::Lha,
        zmanager_core::archive_format::ArchiveFormatKind::Ar => ArchiveFormat::Ar,
        zmanager_core::archive_format::ArchiveFormatKind::Warc => ArchiveFormat::Warc,
        zmanager_core::archive_format::ArchiveFormatKind::Mtree => ArchiveFormat::Mtree,
        zmanager_core::archive_format::ArchiveFormatKind::Deb => ArchiveFormat::Deb,
        zmanager_core::archive_format::ArchiveFormatKind::Msi => ArchiveFormat::Msi,
        zmanager_core::archive_format::ArchiveFormatKind::Vhd => ArchiveFormat::Vhd,
        zmanager_core::archive_format::ArchiveFormatKind::Vmdk => ArchiveFormat::Vmdk,
        zmanager_core::archive_format::ArchiveFormatKind::Udf => ArchiveFormat::Udf,
        zmanager_core::archive_format::ArchiveFormatKind::Squashfs => ArchiveFormat::Squashfs,
        zmanager_core::archive_format::ArchiveFormatKind::AppImage => ArchiveFormat::AppImage,
        zmanager_core::archive_format::ArchiveFormatKind::Wim => ArchiveFormat::Wim,
        zmanager_core::archive_format::ArchiveFormatKind::Vdi => ArchiveFormat::Vdi,
        zmanager_core::archive_format::ArchiveFormatKind::Nrg => ArchiveFormat::Nrg,
        zmanager_core::archive_format::ArchiveFormatKind::Mdf => ArchiveFormat::Mdf,
        zmanager_core::archive_format::ArchiveFormatKind::Cdi => ArchiveFormat::Cdi,
        zmanager_core::archive_format::ArchiveFormatKind::Isz => ArchiveFormat::Isz,
        zmanager_core::archive_format::ArchiveFormatKind::Ccd => ArchiveFormat::Ccd,
        zmanager_core::archive_format::ArchiveFormatKind::Cue => ArchiveFormat::Cue,
        zmanager_core::archive_format::ArchiveFormatKind::Vhdx => ArchiveFormat::Vhdx,
        zmanager_core::archive_format::ArchiveFormatKind::Qcow2 => ArchiveFormat::Qcow2,
        zmanager_core::archive_format::ArchiveFormatKind::Ewf => ArchiveFormat::Ewf,
        zmanager_core::archive_format::ArchiveFormatKind::Ad1 => ArchiveFormat::Ad1,
        zmanager_core::archive_format::ArchiveFormatKind::Dar => ArchiveFormat::Dar,
        zmanager_core::archive_format::ArchiveFormatKind::Aff4 => ArchiveFormat::Aff4,
        zmanager_core::archive_format::ArchiveFormatKind::RawDisk => ArchiveFormat::RawDisk,
        zmanager_core::archive_format::ArchiveFormatKind::Tzap => ArchiveFormat::Tzap,
        zmanager_core::archive_format::ArchiveFormatKind::AppleArchive => ArchiveFormat::AppleArchive,
        zmanager_core::archive_format::ArchiveFormatKind::RawStream => match extension.as_str() {
            "gz" => ArchiveFormat::Gzip,
            "bz2" => ArchiveFormat::Bzip2,
            "xz" => ArchiveFormat::Xz,
            "zst" => ArchiveFormat::Zstd,
            _ => ArchiveFormat::RawStream,
        },
        // Core reports Unknown for volume sidecars without their final file;
        // the FFI still recognizes them so callers can plan a volume set.
        zmanager_core::archive_format::ArchiveFormatKind::Unknown if is_split_zip_extension(&extension) => ArchiveFormat::SplitZip,
        zmanager_core::archive_format::ArchiveFormatKind::Unknown if is_rar_sidecar_extension(&extension) => ArchiveFormat::MultipartRar,
        zmanager_core::archive_format::ArchiveFormatKind::Unknown if extension == "xip" => ArchiveFormat::Xip,
        // Unknown paths use the generic product classification.
        _ => ArchiveFormat::Other,
    };

    (format, Vec::new())
}

/// Capability triple for the FFI's [`ArchiveFormat`]: (can_list, can_extract, can_create).
///
/// XIP and Other are handled here because they are FFI-only surface concepts;
/// everything else flows through the core registry via
/// [`format_capabilities_for_kind`], which keeps platform gating (Apple
/// Archive off-Apple) in one place.
pub(crate) fn format_capabilities(format: ArchiveFormat) -> (bool, bool, bool) {
    match format {
        ArchiveFormat::Xip => (false, false, false),
        ArchiveFormat::Other => (false, false, false),
        _ => {
            let kind = kind_for_format(format);
            match zmanager_core::archive_format::format_status(kind) {
                zmanager_core::archive_format::BackendStatus::Available => format_capabilities_for_kind(kind),
                zmanager_core::archive_format::BackendStatus::UnsupportedPlatform | zmanager_core::archive_format::BackendStatus::Unavailable { .. } => {
                    (false, false, false)
                }
            }
        }
    }
}

pub(crate) fn kind_for_format(format: ArchiveFormat) -> zmanager_core::archive_format::ArchiveFormatKind {
    use zmanager_core::archive_format::ArchiveFormatKind;
    match format {
        ArchiveFormat::Zip => ArchiveFormatKind::Zip,
        ArchiveFormat::SplitZip => ArchiveFormatKind::SplitZip,
        ArchiveFormat::Rar | ArchiveFormat::MultipartRar => ArchiveFormatKind::Rar,
        ArchiveFormat::SevenZ => ArchiveFormatKind::SevenZ,
        ArchiveFormat::Tar => ArchiveFormatKind::Tar,
        ArchiveFormat::TarGz => ArchiveFormatKind::TarGz,
        ArchiveFormat::TarBz2 => ArchiveFormatKind::TarBz2,
        ArchiveFormat::TarXz => ArchiveFormatKind::TarXz,
        ArchiveFormat::TarZst => ArchiveFormatKind::TarZst,
        ArchiveFormat::TarLzma => ArchiveFormatKind::TarLzma,
        ArchiveFormat::TarLz => ArchiveFormatKind::TarLz,
        ArchiveFormat::TarLzo => ArchiveFormatKind::TarLzo,
        ArchiveFormat::TarCompress => ArchiveFormatKind::TarCompress,
        ArchiveFormat::TarLz4 => ArchiveFormatKind::TarLz4,
        ArchiveFormat::TarUu => ArchiveFormatKind::TarUu,
        ArchiveFormat::Iso => ArchiveFormatKind::Iso,
        ArchiveFormat::Cab => ArchiveFormatKind::Cab,
        ArchiveFormat::Cpio => ArchiveFormatKind::Cpio,
        ArchiveFormat::Rpm => ArchiveFormatKind::Rpm,
        ArchiveFormat::Xar => ArchiveFormatKind::Xar,
        ArchiveFormat::Pkg => ArchiveFormatKind::Pkg,
        ArchiveFormat::Dmg => ArchiveFormatKind::Dmg,
        ArchiveFormat::Lha => ArchiveFormatKind::Lha,
        ArchiveFormat::Ar => ArchiveFormatKind::Ar,
        ArchiveFormat::Warc => ArchiveFormatKind::Warc,
        ArchiveFormat::Mtree => ArchiveFormatKind::Mtree,
        ArchiveFormat::Deb => ArchiveFormatKind::Deb,
        ArchiveFormat::Msi => ArchiveFormatKind::Msi,
        ArchiveFormat::Vhd => ArchiveFormatKind::Vhd,
        ArchiveFormat::Vmdk => ArchiveFormatKind::Vmdk,
        ArchiveFormat::Udf => ArchiveFormatKind::Udf,
        ArchiveFormat::Squashfs => ArchiveFormatKind::Squashfs,
        ArchiveFormat::AppImage => ArchiveFormatKind::AppImage,
        ArchiveFormat::Wim => ArchiveFormatKind::Wim,
        ArchiveFormat::Vdi => ArchiveFormatKind::Vdi,
        ArchiveFormat::Nrg => ArchiveFormatKind::Nrg,
        ArchiveFormat::Mdf => ArchiveFormatKind::Mdf,
        ArchiveFormat::Cdi => ArchiveFormatKind::Cdi,
        ArchiveFormat::Isz => ArchiveFormatKind::Isz,
        ArchiveFormat::Ccd => ArchiveFormatKind::Ccd,
        ArchiveFormat::Cue => ArchiveFormatKind::Cue,
        ArchiveFormat::Vhdx => ArchiveFormatKind::Vhdx,
        ArchiveFormat::Qcow2 => ArchiveFormatKind::Qcow2,
        ArchiveFormat::Ewf => ArchiveFormatKind::Ewf,
        ArchiveFormat::Ad1 => ArchiveFormatKind::Ad1,
        ArchiveFormat::Dar => ArchiveFormatKind::Dar,
        ArchiveFormat::Aff4 => ArchiveFormatKind::Aff4,
        ArchiveFormat::RawDisk => ArchiveFormatKind::RawDisk,
        ArchiveFormat::Gzip | ArchiveFormat::Bzip2 | ArchiveFormat::Xz | ArchiveFormat::Zstd | ArchiveFormat::RawStream => ArchiveFormatKind::RawStream,
        ArchiveFormat::Tzap => ArchiveFormatKind::Tzap,
        ArchiveFormat::AppleArchive => ArchiveFormatKind::AppleArchive,
        ArchiveFormat::Xip | ArchiveFormat::Other => ArchiveFormatKind::Unknown,
    }
}

/// Capability triple for a core format kind: (can_list, can_extract, can_create).
///
/// The FFI reports the same operation set as the native engine registry. This
/// keeps bridge capability gates from drifting when an adapter is added,
/// removed, or platform-gated.
pub(crate) fn format_capabilities_for_kind(kind: zmanager_core::archive_format::ArchiveFormatKind) -> (bool, bool, bool) {
    let Some(format) = zmanager_core::engine::FormatId::from_archive_format_kind(kind) else {
        return (false, false, false);
    };
    let Ok(engine) = zmanager_core::engine::create_default_engine() else {
        return (false, false, false);
    };
    let Some(capabilities) = engine.registry().capabilities_for_format(format) else {
        return (false, false, false);
    };
    (
        capabilities.operations.contains(&zmanager_core::engine::ArchiveOperation::List),
        capabilities.operations.contains(&zmanager_core::engine::ArchiveOperation::Extract),
        capabilities.operations.contains(&zmanager_core::engine::ArchiveOperation::Create),
    )
}

/// Display label for a core format kind, used by `listFormats`. The FFI's
/// [`format_label`] keeps its own strings for the corresponding
/// `ArchiveFormat` enum values.
pub(crate) fn kind_label(kind: zmanager_core::archive_format::ArchiveFormatKind) -> &'static str {
    use zmanager_core::archive_format::ArchiveFormatKind;
    match kind {
        ArchiveFormatKind::Zip => "ZIP",
        ArchiveFormatKind::SplitZip => "Split ZIP",
        ArchiveFormatKind::SevenZ => "7z",
        ArchiveFormatKind::TarZst => "TAR.ZST",
        ArchiveFormatKind::TarGz => "TAR.GZ",
        ArchiveFormatKind::Tar => "TAR",
        ArchiveFormatKind::TarBz2 => "TAR.BZ2",
        ArchiveFormatKind::TarXz => "TAR.XZ",
        ArchiveFormatKind::TarLzma => "TAR.LZMA",
        ArchiveFormatKind::TarLz => "TAR.LZ",
        ArchiveFormatKind::TarLzo => "TAR.LZO",
        ArchiveFormatKind::TarCompress => "TAR.Z",
        ArchiveFormatKind::TarLz4 => "TAR.LZ4",
        ArchiveFormatKind::TarUu => "TAR.UU",
        ArchiveFormatKind::Iso => "ISO",
        ArchiveFormatKind::Cab => "CAB",
        ArchiveFormatKind::Cpio => "CPIO",
        ArchiveFormatKind::Rpm => "RPM",
        ArchiveFormatKind::Xar => "XAR",
        ArchiveFormatKind::Pkg => "PKG",
        ArchiveFormatKind::Dmg => "DMG",
        ArchiveFormatKind::Msi => "MSI",
        ArchiveFormatKind::Vhd => "VHD",
        ArchiveFormatKind::Vmdk => "VMDK",
        ArchiveFormatKind::Udf => "UDF",
        ArchiveFormatKind::Squashfs => "SquashFS",
        ArchiveFormatKind::AppImage => "AppImage",
        ArchiveFormatKind::Wim => "WIM",
        ArchiveFormatKind::Vdi => "VDI",
        ArchiveFormatKind::Nrg => "NRG",
        ArchiveFormatKind::Mdf => "MDF/MDS",
        ArchiveFormatKind::Cdi => "CDI",
        ArchiveFormatKind::Isz => "ISZ",
        ArchiveFormatKind::Ccd => "CCD/IMG",
        ArchiveFormatKind::Cue => "CUE/BIN",
        ArchiveFormatKind::Lha => "LHA",
        ArchiveFormatKind::Ar => "AR",
        ArchiveFormatKind::Warc => "WARC",
        ArchiveFormatKind::Mtree => "MTREE",
        ArchiveFormatKind::Tzap => "TZAP",
        ArchiveFormatKind::Rar => "RAR",
        ArchiveFormatKind::AppleArchive => "AppleArchive / AAR",
        ArchiveFormatKind::Deb => "DEB",
        ArchiveFormatKind::Vhdx => "VHDX",
        ArchiveFormatKind::Qcow2 => "QCOW2",
        ArchiveFormatKind::Ewf => "EWF",
        ArchiveFormatKind::Ad1 => "AD1",
        ArchiveFormatKind::Dar => "DAR",
        ArchiveFormatKind::Aff4 => "AFF4",
        ArchiveFormatKind::RawDisk => "Raw Disk",
        ArchiveFormatKind::RawStream => "Raw stream",
        ArchiveFormatKind::Unknown => "Unknown",
    }
}

pub(crate) fn format_label(format: ArchiveFormat) -> &'static str {
    match format {
        ArchiveFormat::Zip => "ZIP",
        ArchiveFormat::SplitZip => "Split ZIP",
        ArchiveFormat::Rar => "RAR",
        ArchiveFormat::MultipartRar => "Multipart RAR",
        ArchiveFormat::SevenZ => "7z",
        ArchiveFormat::Tar => "TAR",
        ArchiveFormat::TarGz => "TAR.GZ",
        ArchiveFormat::TarBz2 => "TAR.BZ2",
        ArchiveFormat::TarXz => "TAR.XZ",
        ArchiveFormat::TarZst => "TAR.ZST",
        ArchiveFormat::TarLzma => "TAR.LZMA",
        ArchiveFormat::TarLz => "TAR.LZ",
        ArchiveFormat::TarLzo => "TAR.LZO",
        ArchiveFormat::TarCompress => "TAR.Z",
        ArchiveFormat::TarLz4 => "TAR.LZ4",
        ArchiveFormat::TarUu => "TAR.UU",
        ArchiveFormat::Iso => "ISO",
        ArchiveFormat::Cab => "CAB",
        ArchiveFormat::Cpio => "CPIO",
        ArchiveFormat::Rpm => "RPM",
        ArchiveFormat::Xar => "XAR",
        ArchiveFormat::Pkg => "PKG",
        ArchiveFormat::Dmg => "DMG",
        ArchiveFormat::Lha => "LHA",
        ArchiveFormat::Ar => "AR",
        ArchiveFormat::Warc => "WARC",
        ArchiveFormat::Mtree => "MTREE",
        ArchiveFormat::Deb => "DEB",
        ArchiveFormat::Msi => "MSI",
        ArchiveFormat::Vhd => "VHD",
        ArchiveFormat::Vmdk => "VMDK",
        ArchiveFormat::Udf => "UDF",
        ArchiveFormat::Squashfs => "SquashFS",
        ArchiveFormat::AppImage => "AppImage",
        ArchiveFormat::Wim => "WIM",
        ArchiveFormat::Vdi => "VDI",
        ArchiveFormat::Nrg => "NRG",
        ArchiveFormat::Mdf => "MDF/MDS",
        ArchiveFormat::Cdi => "CDI",
        ArchiveFormat::Isz => "ISZ",
        ArchiveFormat::Ccd => "CCD",
        ArchiveFormat::Cue => "CUE/BIN",
        ArchiveFormat::Vhdx => "VHDX",
        ArchiveFormat::Qcow2 => "QCOW2",
        ArchiveFormat::Ewf => "EWF",
        ArchiveFormat::Ad1 => "AD1",
        ArchiveFormat::Dar => "DAR",
        ArchiveFormat::Aff4 => "AFF4",
        ArchiveFormat::RawDisk => "Raw Disk",
        ArchiveFormat::Gzip => "GZIP",
        ArchiveFormat::Bzip2 => "BZIP2",
        ArchiveFormat::Xz => "XZ",
        ArchiveFormat::Zstd => "Zstd",
        ArchiveFormat::Tzap => "TZAP",
        ArchiveFormat::AppleArchive => "AppleArchive / AAR",
        ArchiveFormat::Xip => "XIP",
        ArchiveFormat::RawStream => "Raw stream",
        ArchiveFormat::Other => "Archive",
    }
}

fn is_split_zip_extension(extension: &str) -> bool {
    let Some(number) = extension.strip_prefix('z') else {
        return false;
    };
    number.len() == 2 && number.chars().all(|value| value.is_ascii_digit())
}

fn is_rar_sidecar_extension(extension: &str) -> bool {
    let Some(number) = extension.strip_prefix('r') else {
        return false;
    };
    number.len() == 2 && number.chars().all(|value| value.is_ascii_digit())
}

pub(crate) fn map_browser_entry_kind(entry: BrowserEntryKind) -> ArchiveEntryKind {
    match entry {
        BrowserEntryKind::File | BrowserEntryKind::FileCopy => ArchiveEntryKind::File,
        BrowserEntryKind::Directory => ArchiveEntryKind::Directory,
        BrowserEntryKind::Symlink => ArchiveEntryKind::Symlink,
        BrowserEntryKind::Hardlink => ArchiveEntryKind::Hardlink,
        BrowserEntryKind::Special => ArchiveEntryKind::Special,
    }
}
