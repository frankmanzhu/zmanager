//! Path validation helpers and archive format classification/labels.

use std::fs;
use std::io;
use std::path::Path;

use zmanager_core::archive_browser::BrowserEntryKind;
use zmanager_core::tzap_backend::{has_existing_tzap_input_volume, is_tzap_archive_path};

use crate::ffi::error::{ERROR_INVALID_REQUEST, ERROR_NOT_FOUND, bridge_error, hint, map_io_error};
use crate::ffi::types::{ArchiveEntryKind, ArchiveFormat, BridgeError, BridgeSeverity, CreateArchiveFormat, ZmanagerGuiError};

/// Empty passwords are treated as absent: callers that own the value use
/// this, callers that only borrow it use [`password_ref`].
pub(crate) fn sanitize_password(password: Option<String>) -> Option<String> {
    password.filter(|value| !value.is_empty())
}

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

pub(crate) fn ensure_destination_root_path(value: String) -> Result<String, ZmanagerGuiError> {
    let value = sanitize_path_value(value, "destinationRoot", "Resolve provider destinations to app-controlled staging before calling the Rust bridge.")?;

    let path = Path::new(&value);
    match fs::metadata(path) {
        Ok(metadata) if !metadata.is_dir() => {
            Err(bridge_error(ERROR_INVALID_REQUEST, "destinationRoot must point to a directory when it already exists", None, BridgeSeverity::Warning, false))
        }
        Ok(_) => Ok(value),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(value),
        Err(source) => Err(map_io_error(path.to_path_buf(), source)),
    }
}

pub(crate) fn ensure_existing_source_paths(values: Vec<String>) -> Result<Vec<String>, ZmanagerGuiError> {
    if values.is_empty() {
        return Err(bridge_error(ERROR_INVALID_REQUEST, "sourcePaths cannot be empty", None, BridgeSeverity::Warning, false));
    }

    values.into_iter().enumerate().map(|(index, value)| ensure_existing_source_path(value, &format!("sourcePaths[{index}]"))).collect()
}

pub(crate) fn ensure_existing_source_path(value: String, field: &str) -> Result<String, ZmanagerGuiError> {
    let value = sanitize_path_value(value, field, "Copy provider-backed files into app cache before calling the Rust bridge.")?;

    let path = Path::new(&value);
    fs::metadata(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            bridge_error(
                ERROR_NOT_FOUND,
                format!("{field} does not exist"),
                hint("Choose sources that have already been copied into app-controlled storage."),
                BridgeSeverity::Warning,
                false,
            )
        } else {
            map_io_error(path.to_path_buf(), source)
        }
    })?;

    Ok(value)
}

pub(crate) fn ensure_destination_archive_path(value: String) -> Result<String, ZmanagerGuiError> {
    let value =
        sanitize_path_value(value, "destinationArchivePath", "Use an app-controlled staging path for archive creation, then let the native shell commit it.")?;

    let path = Path::new(&value);
    if path.parent().is_none_or(|parent| parent.as_os_str().is_empty()) {
        return Err(bridge_error(ERROR_INVALID_REQUEST, "destinationArchivePath must include a parent directory", None, BridgeSeverity::Warning, false));
    }

    if let Some(parent) = path.parent() {
        match fs::metadata(parent) {
            Ok(metadata) if !metadata.is_dir() => {
                return Err(bridge_error(ERROR_INVALID_REQUEST, "destinationArchivePath parent must be a directory", None, BridgeSeverity::Warning, false));
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(bridge_error(
                    ERROR_NOT_FOUND,
                    "destinationArchivePath parent does not exist",
                    hint("Create the app-controlled staging directory before calling the bridge."),
                    BridgeSeverity::Warning,
                    false,
                ));
            }
            Err(source) => return Err(map_io_error(parent.to_path_buf(), source)),
        }
    }

    if let Ok(metadata) = fs::metadata(path)
        && metadata.is_dir()
    {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            "destinationArchivePath must point to an archive file, not a directory",
            None,
            BridgeSeverity::Warning,
            false,
        ));
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
    let metadata = fs::metadata(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            bridge_error(
                ERROR_NOT_FOUND,
                format!("{field} does not exist"),
                hint("Choose an archive that has already been copied into app-controlled storage."),
                BridgeSeverity::Warning,
                false,
            )
        } else {
            map_io_error(path.to_path_buf(), source)
        }
    })?;

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
        // Kinds with no FFI variant (TarLzma, Iso, Cab, Cpio, Rpm, Xar, Pkg,
        // Dmg, Msi, Lha, Ar, Warc, Mtree, Deb) and unknown paths: generic fallback.
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
        ArchiveFormat::Other => (true, true, false),
        _ => format_capabilities_for_kind(kind_for_format(format)),
    }
}

fn kind_for_format(format: ArchiveFormat) -> zmanager_core::archive_format::ArchiveFormatKind {
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
        ArchiveFormat::Gzip | ArchiveFormat::Bzip2 | ArchiveFormat::Xz | ArchiveFormat::Zstd | ArchiveFormat::RawStream => ArchiveFormatKind::RawStream,
        ArchiveFormat::Tzap => ArchiveFormatKind::Tzap,
        ArchiveFormat::AppleArchive => ArchiveFormatKind::AppleArchive,
        ArchiveFormat::Xip | ArchiveFormat::Other => ArchiveFormatKind::Unknown,
    }
}

/// Capability triple for a core format kind: (can_list, can_extract, can_create).
///
/// Availability consults the compile-time registry (`format_status`); creation
/// is limited to the kinds with a create backend. Kinds without a dedicated
/// row report as listable/extractable so the libarchive fallback can try them.
pub(crate) fn format_capabilities_for_kind(kind: zmanager_core::archive_format::ArchiveFormatKind) -> (bool, bool, bool) {
    use zmanager_core::archive_format::ArchiveFormatKind;
    match kind {
        ArchiveFormatKind::AppleArchive => {
            let available = zmanager_core::archive_format::format_status(kind) == zmanager_core::archive_format::BackendStatus::Available;
            (available, available, false)
        }
        ArchiveFormatKind::Zip | ArchiveFormatKind::SevenZ | ArchiveFormatKind::TarZst | ArchiveFormatKind::Tzap => (true, true, true),
        ArchiveFormatKind::Rar
        | ArchiveFormatKind::SplitZip
        | ArchiveFormatKind::Tar
        | ArchiveFormatKind::TarGz
        | ArchiveFormatKind::TarBz2
        | ArchiveFormatKind::TarXz
        | ArchiveFormatKind::TarLzma
        | ArchiveFormatKind::RawStream
        | ArchiveFormatKind::Iso
        | ArchiveFormatKind::Cab
        | ArchiveFormatKind::Cpio
        | ArchiveFormatKind::Rpm
        | ArchiveFormatKind::Xar
        | ArchiveFormatKind::Pkg
        | ArchiveFormatKind::Dmg
        | ArchiveFormatKind::Msi
        | ArchiveFormatKind::Vhd
        | ArchiveFormatKind::Vmdk
        | ArchiveFormatKind::Udf
        | ArchiveFormatKind::Lha
        | ArchiveFormatKind::Ar
        | ArchiveFormatKind::Warc
        | ArchiveFormatKind::Mtree
        | ArchiveFormatKind::Deb
        | ArchiveFormatKind::Unknown => (true, true, false),
    }
}

/// Display label for a core format kind, used by `listFormats`. The FFI's
/// [`format_label`] keeps its own strings for the `ArchiveFormat` enum; this
/// covers the kinds that have no FFI variant.
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
        ArchiveFormatKind::Lha => "LHA",
        ArchiveFormatKind::Ar => "AR",
        ArchiveFormatKind::Warc => "WARC",
        ArchiveFormatKind::Mtree => "MTREE",
        ArchiveFormatKind::Tzap => "TZAP",
        ArchiveFormatKind::Rar => "RAR",
        ArchiveFormatKind::AppleArchive => "AppleArchive / AAR",
        ArchiveFormatKind::Deb => "DEB",
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

pub(crate) fn create_format_label(format: CreateArchiveFormat) -> &'static str {
    match format {
        CreateArchiveFormat::Zip => "ZIP",
        CreateArchiveFormat::SevenZ => "7z",
        CreateArchiveFormat::TarZst => "TAR.ZST",
        CreateArchiveFormat::Tzap => "TZAP",
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
        BrowserEntryKind::File => ArchiveEntryKind::File,
        BrowserEntryKind::Directory => ArchiveEntryKind::Directory,
        BrowserEntryKind::Symlink => ArchiveEntryKind::Symlink,
        BrowserEntryKind::Hardlink => ArchiveEntryKind::Hardlink,
        BrowserEntryKind::Special => ArchiveEntryKind::Special,
    }
}
