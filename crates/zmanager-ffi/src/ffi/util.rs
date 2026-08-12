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

pub(crate) fn classify_archive_path(path: &Path) -> (ArchiveFormat, Vec<BridgeError>) {
    let file_name = path.file_name().and_then(|value| value.to_str()).unwrap_or_default().to_ascii_lowercase();
    let extension = path.extension().and_then(|value| value.to_str()).unwrap_or_default().to_ascii_lowercase();

    let format = if zmanager_core::libarchive_backend::is_split_zip_path(path) {
        ArchiveFormat::SplitZip
    } else if matches!(extension.as_str(), "zip" | "zipx" | "jar" | "war" | "ipa" | "apk" | "appx" | "xpi") {
        ArchiveFormat::Zip
    } else if is_split_zip_extension(&extension) {
        ArchiveFormat::SplitZip
    } else if extension == "rar" {
        if file_name.contains(".part") { ArchiveFormat::MultipartRar } else { ArchiveFormat::Rar }
    } else if is_rar_sidecar_extension(&extension) {
        ArchiveFormat::MultipartRar
    } else if extension == "7z" || zmanager_core::sevenz_backend::is_7z_volume_path(path) {
        ArchiveFormat::SevenZ
    } else if extension == "tar" {
        ArchiveFormat::Tar
    } else if matches!(extension.as_str(), "tgz") || file_name.ends_with(".tar.gz") {
        ArchiveFormat::TarGz
    } else if matches!(extension.as_str(), "tbz" | "tbz2") || file_name.ends_with(".tar.bz2") {
        ArchiveFormat::TarBz2
    } else if matches!(extension.as_str(), "txz") || file_name.ends_with(".tar.xz") {
        ArchiveFormat::TarXz
    } else if extension == "tzst" || file_name.ends_with(".tar.zst") {
        ArchiveFormat::TarZst
    } else if extension == "gz" {
        ArchiveFormat::Gzip
    } else if extension == "bz2" {
        ArchiveFormat::Bzip2
    } else if extension == "xz" {
        ArchiveFormat::Xz
    } else if extension == "zst" {
        ArchiveFormat::Zstd
    } else if extension == "tzap" {
        ArchiveFormat::Tzap
    } else if extension == "aar" {
        ArchiveFormat::AppleArchive
    } else if extension == "xip" {
        ArchiveFormat::Xip
    } else if matches!(extension.as_str(), "lzma" | "lz" | "br" | "lz4" | "lzo" | "z" | "lrz") {
        ArchiveFormat::RawStream
    } else {
        ArchiveFormat::Other
    };

    (format, Vec::new())
}

pub(crate) fn format_capabilities(format: ArchiveFormat) -> (bool, bool, bool) {
    match format {
        ArchiveFormat::Xip => (false, false, false),
        ArchiveFormat::AppleArchive => (true, true, false),
        ArchiveFormat::Rar | ArchiveFormat::MultipartRar | ArchiveFormat::SplitZip => (true, true, false),
        ArchiveFormat::Zip | ArchiveFormat::SevenZ | ArchiveFormat::TarZst | ArchiveFormat::Tzap => (true, true, true),
        ArchiveFormat::Tar
        | ArchiveFormat::TarGz
        | ArchiveFormat::TarBz2
        | ArchiveFormat::TarXz
        | ArchiveFormat::Gzip
        | ArchiveFormat::Bzip2
        | ArchiveFormat::Xz
        | ArchiveFormat::Zstd
        | ArchiveFormat::RawStream
        | ArchiveFormat::Other => (true, true, false),
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
