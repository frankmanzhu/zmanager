//! Error-code constants and the backend-error → `ZmanagerGuiError` mapping.

use std::io;
use std::path::PathBuf;

use zmanager_core::apple_archive_backend::AppleArchiveError;
use zmanager_core::archive_browser::ArchiveBrowserError;
use zmanager_core::engine::{ArchiveError, ErrorKind};
use zmanager_core::libarchive_backend::LibarchiveError;
use zmanager_core::manifest::PlanError;
use zmanager_core::rar_backend::RarBackendError;
use zmanager_core::raw_stream_backend::RawStreamError;
use zmanager_core::sevenz_backend::SevenZError;
use zmanager_core::tar_zst_backend::TarZstdError;
use zmanager_core::tzap_backend::TzapError;
use zmanager_core::zip_backend::ZipBackendError;

use crate::ffi::types::{BridgeError, BridgeSeverity, ZmanagerGuiError};
#[cfg(feature = "auth")]
use crate::ffi::util::ensure_existing_tzap_archive_path;

pub(crate) const ERROR_INVALID_REQUEST: &str = "invalid_request";
pub(crate) const ERROR_NOT_FOUND: &str = "not_found";
pub(crate) const ERROR_PASSWORD_REQUIRED: &str = "password_required";
pub(crate) const ERROR_INVALID_PASSWORD: &str = "invalid_password";
pub(crate) const ERROR_UNSAFE_ARCHIVE: &str = "unsafe_archive";
pub(crate) const ERROR_IO_ERROR: &str = "io_error";
pub(crate) const ERROR_UNSUPPORTED_FORMAT: &str = "unsupported_format";
pub(crate) const ERROR_DAMAGED_ARCHIVE: &str = "damaged_archive";
pub(crate) const ERROR_CANCELLED: &str = "cancelled";
pub(crate) const ERROR_OPERATION_FAILED: &str = "operation_failed";
pub(crate) const WARNING_GENERIC: &str = "warning";
pub(crate) const WARNING_LAUNCH_GATED_FORMAT: &str = "launch_gated_format";

/// Turns a path-validation error into the JSON error envelope the tzap
/// service endpoints use, since they are declared without `[Throws]`.
#[cfg(feature = "auth")]
pub(crate) fn return_tzap_error(error: ZmanagerGuiError) -> String {
    let message = match error {
        ZmanagerGuiError::Bridge { user_message, .. } => user_message,
    };
    format!("{{\"ok\":false,\"message\":{}}}", serde_json::to_string(&message).unwrap_or_default())
}

/// Validates an existing archive path for the tzap service endpoints and
/// returns it, or the JSON error envelope as `Err` on validation failure.
/// The service endpoints are declared without `[Throws]`, so callers must
/// return the envelope as the function value instead of continuing with it.
#[cfg(feature = "auth")]
pub(crate) fn existing_archive_path_or_tzap_error(value: String) -> Result<String, String> {
    ensure_existing_tzap_archive_path(value, "archivePath").map_err(return_tzap_error)
}

pub(crate) fn map_archive_browser_error(error: ArchiveBrowserError) -> ZmanagerGuiError {
    match error {
        ArchiveBrowserError::Zip(source) => map_zip_error(source),
        ArchiveBrowserError::TarZst(source) => map_tar_zst_error(source),
        ArchiveBrowserError::SevenZ(source) => map_7z_error(source),
        ArchiveBrowserError::Rar(source) => map_rar_error(source),
        ArchiveBrowserError::Tzap(source) => map_tzap_error(source),
        ArchiveBrowserError::AppleArchive(source) => map_apple_archive_error(source),
        ArchiveBrowserError::Libarchive(source) => map_libarchive_error(source),
        ArchiveBrowserError::RawStream(source) => map_raw_stream_error(source),
        ArchiveBrowserError::Engine { source, .. } => map_archive_engine_error(source),
        ArchiveBrowserError::Io { path, source } => map_io_error(path, source),
        ArchiveBrowserError::Safety(source) => {
            bridge_error(ERROR_UNSAFE_ARCHIVE, format!("Entry blocked by safety policy: {source}"), None, BridgeSeverity::Warning, false)
        }
        ArchiveBrowserError::EntryNotFound { path } => bridge_error(
            ERROR_NOT_FOUND,
            format!("Archive entry not found: {path}"),
            hint("Open a different archive or choose a different entry."),
            BridgeSeverity::Warning,
            false,
        ),
        ArchiveBrowserError::UnsupportedEntry { path, .. } => {
            bridge_error(ERROR_UNSUPPORTED_FORMAT, format!("Entry cannot be extracted or previewed here: {path}"), None, BridgeSeverity::Warning, false)
        }
        ArchiveBrowserError::Cancelled | ArchiveBrowserError::UnsupportedOperation(_) => {
            bridge_error(ERROR_OPERATION_FAILED, "Operation cancelled or unsupported.".to_string(), None, BridgeSeverity::Warning, false)
        }
    }
}

pub(crate) fn map_archive_engine_error(error: ArchiveError) -> ZmanagerGuiError {
    let message = error.message;
    match error.kind {
        ErrorKind::PasswordRequired => bridge_error(ERROR_PASSWORD_REQUIRED, message, hint("Enter the archive password."), BridgeSeverity::Warning, true),
        ErrorKind::WrongPassword => bridge_error(ERROR_INVALID_PASSWORD, message, None, BridgeSeverity::Warning, true),
        ErrorKind::SafetyViolation => bridge_error(ERROR_UNSAFE_ARCHIVE, message, None, BridgeSeverity::Warning, false),
        ErrorKind::Io => map_io_error(error.path.unwrap_or_default(), io::Error::other(message)),
        ErrorKind::CorruptData => damaged_archive(message),
        ErrorKind::InvalidFormat | ErrorKind::UnsupportedOperation | ErrorKind::ResourceLimitExceeded => {
            bridge_error(ERROR_UNSUPPORTED_FORMAT, message, None, BridgeSeverity::Warning, false)
        }
    }
}

pub(crate) fn map_plan_error(error: PlanError) -> ZmanagerGuiError {
    match error {
        PlanError::MissingFileName { path } => {
            bridge_error(ERROR_INVALID_REQUEST, format!("Source path has no archive name: {}", path.display()), None, BridgeSeverity::Warning, false)
        }
        PlanError::Metadata { path, source } | PlanError::ReadDir { path, source } => map_io_error(path, source),
    }
}

pub(crate) fn map_zip_error(error: ZipBackendError) -> ZmanagerGuiError {
    match error {
        ZipBackendError::PasswordRequired => bridge_error(
            ERROR_PASSWORD_REQUIRED,
            "This ZIP archive is encrypted and requires a password.",
            hint("Enter the archive password."),
            BridgeSeverity::Warning,
            true,
        ),
        ZipBackendError::InvalidPassword => bridge_error(ERROR_INVALID_PASSWORD, "The ZIP password was incorrect.", None, BridgeSeverity::Warning, true),
        ZipBackendError::Io { path, source } => map_io_error(path, source),
        ZipBackendError::Safety(source) => {
            bridge_error(ERROR_UNSAFE_ARCHIVE, format!("Entry blocked by safety policy: {source}"), None, BridgeSeverity::Warning, false)
        }
        ZipBackendError::UnsupportedSplitZip { .. } => {
            bridge_error(ERROR_UNSUPPORTED_FORMAT, "ZIP split archives are unsupported for this operation in this path.", None, BridgeSeverity::Warning, false)
        }
        ZipBackendError::Zip(source) => damaged_archive(format!("ZIP archive could not be read: {source}")),
        ZipBackendError::Cancelled => bridge_error(ERROR_CANCELLED, "ZIP job was cancelled.", None, BridgeSeverity::Info, true),
        source => operation_failed(format!("ZIP operation failed: {source}")),
    }
}

pub(crate) fn map_tar_zst_error(error: TarZstdError) -> ZmanagerGuiError {
    match error {
        TarZstdError::Io { path, source } => map_io_error(path, source),
        TarZstdError::Safety(source) => {
            bridge_error(ERROR_UNSAFE_ARCHIVE, format!("Entry blocked by safety policy: {source}"), None, BridgeSeverity::Warning, false)
        }
        TarZstdError::Cancelled => bridge_error(ERROR_CANCELLED, "TAR/ZST job was cancelled.", None, BridgeSeverity::Info, true),
        source => operation_failed(format!("TAR/ZST operation failed: {source}")),
    }
}

pub(crate) fn map_7z_error(error: SevenZError) -> ZmanagerGuiError {
    match error {
        SevenZError::PasswordRequired => bridge_error(
            ERROR_PASSWORD_REQUIRED,
            "This 7z archive is encrypted and requires a password.",
            hint("Enter the archive password."),
            BridgeSeverity::Warning,
            true,
        ),
        SevenZError::InvalidPassword => bridge_error(ERROR_INVALID_PASSWORD, "The 7z password was incorrect.", None, BridgeSeverity::Warning, true),
        SevenZError::Io { path, source } => map_io_error(path, source),
        SevenZError::Safety(source) => {
            bridge_error(ERROR_UNSAFE_ARCHIVE, format!("Entry blocked by safety policy: {source}"), None, BridgeSeverity::Warning, false)
        }
        SevenZError::Cancelled => bridge_error(ERROR_CANCELLED, "7z job was cancelled.", None, BridgeSeverity::Info, true),
        source => operation_failed(format!("7z operation failed: {source}")),
    }
}

pub(crate) fn map_tzap_error(error: TzapError) -> ZmanagerGuiError {
    match error {
        TzapError::PasswordRequired => {
            bridge_error(ERROR_PASSWORD_REQUIRED, "This TZAP archive requires a password.", hint("Enter the archive password."), BridgeSeverity::Warning, true)
        }
        TzapError::RecipientKeyRequired => bridge_error(
            ERROR_UNSUPPORTED_FORMAT,
            "This TZAP archive requires a recipient key that mobile has not been given.",
            None,
            BridgeSeverity::Warning,
            false,
        ),
        TzapError::Format(source) => damaged_archive(format!("TZAP archive could not be verified: {source}")),
        TzapError::X509RootAuth(_) => damaged_archive("TZAP root-auth verification failed."),
        TzapError::KeyWrap(_) => damaged_archive("TZAP recipient key wrapping failed."),
        TzapError::Io { path, source } => map_io_error(path, source),
        TzapError::Safety(source) => {
            bridge_error(ERROR_UNSAFE_ARCHIVE, format!("Entry blocked by safety policy: {source}"), None, BridgeSeverity::Warning, false)
        }
        TzapError::Cancelled => bridge_error(ERROR_CANCELLED, "TZAP job was cancelled.", None, BridgeSeverity::Info, true),
        source => operation_failed(format!("TZAP operation failed: {source}")),
    }
}

pub(crate) fn map_apple_archive_error(error: AppleArchiveError) -> ZmanagerGuiError {
    match error {
        AppleArchiveError::Plan(source) => map_plan_error(source),
        AppleArchiveError::Native(message) => operation_failed(format!("AppleArchive operation failed: {message}")),
        AppleArchiveError::Unsupported => {
            bridge_error(ERROR_UNSUPPORTED_FORMAT, "Apple Archive is not supported on this platform", None, BridgeSeverity::Warning, false)
        }
        AppleArchiveError::Io { path, source } => map_io_error(path, source),
        AppleArchiveError::Safety(source) => {
            bridge_error(ERROR_UNSAFE_ARCHIVE, format!("Entry blocked by safety policy: {source}"), None, BridgeSeverity::Warning, false)
        }
        AppleArchiveError::MissingLinkTarget { path } => damaged_archive(format!("AppleArchive symlink entry has no target: {path}")),
        AppleArchiveError::MissingFileData { path } => damaged_archive(format!("AppleArchive file entry has no data blob: {path}")),
        AppleArchiveError::EntryNotFound { path } => bridge_error(
            ERROR_NOT_FOUND,
            format!("Archive entry not found: {path}"),
            hint("Open a different archive or choose a different entry."),
            BridgeSeverity::Warning,
            false,
        ),
        AppleArchiveError::StdoutSelectionNotSingleFile { selected_files } => bridge_error(
            ERROR_INVALID_REQUEST,
            format!("AppleArchive stdout extraction needs exactly one file, found {selected_files}."),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        AppleArchiveError::Cancelled => bridge_error(ERROR_CANCELLED, "AppleArchive job was cancelled.", None, BridgeSeverity::Info, true),
    }
}

pub(crate) fn map_rar_error(error: RarBackendError) -> ZmanagerGuiError {
    match error {
        RarBackendError::Io { path, source } => map_io_error(path, source),
        RarBackendError::Safety(source) => {
            bridge_error(ERROR_UNSAFE_ARCHIVE, format!("Entry blocked by safety policy: {source}"), None, BridgeSeverity::Warning, false)
        }
        RarBackendError::Unrar(source) => {
            let message = source.to_string();
            let lower_message = message.to_ascii_lowercase();
            if lower_message.contains("password") {
                bridge_error(
                    ERROR_INVALID_PASSWORD,
                    "The RAR password was missing or incorrect.",
                    hint("Enter the archive password and try again."),
                    BridgeSeverity::Warning,
                    true,
                )
            } else {
                damaged_archive(format!("RAR archive could not be read: {message}"))
            }
        }
        source => operation_failed(format!("RAR operation failed: {source}")),
    }
}

pub(crate) fn map_libarchive_error(error: LibarchiveError) -> ZmanagerGuiError {
    match error {
        LibarchiveError::Archive(source) => damaged_archive(format!("Archive could not be read: {source}")),
        LibarchiveError::RawStream(source) => map_raw_stream_error(source),
        LibarchiveError::Io { path, source } => map_io_error(path, source),
        LibarchiveError::Safety(source) => {
            bridge_error(ERROR_UNSAFE_ARCHIVE, format!("Entry blocked by safety policy: {source}"), None, BridgeSeverity::Warning, false)
        }
        LibarchiveError::EntryNotFound { path } => bridge_error(
            ERROR_NOT_FOUND,
            format!("Archive entry not found: {path}"),
            hint("Open a different archive or choose a different entry."),
            BridgeSeverity::Warning,
            false,
        ),
        LibarchiveError::Cancelled => bridge_error(ERROR_CANCELLED, "Archive job was cancelled.", None, BridgeSeverity::Info, true),
        source => operation_failed(format!("Archive operation failed: {source}")),
    }
}

pub(crate) fn map_raw_stream_error(error: RawStreamError) -> ZmanagerGuiError {
    match error {
        RawStreamError::Io { path, source } => map_io_error(path, source),
        RawStreamError::Safety(source) => {
            bridge_error(ERROR_UNSAFE_ARCHIVE, format!("Entry blocked by safety policy: {source}"), None, BridgeSeverity::Warning, false)
        }
        RawStreamError::ExternalToolUnavailable { tool, .. } => {
            bridge_error(ERROR_UNSUPPORTED_FORMAT, format!("Required decoder tool is unavailable: {tool}"), None, BridgeSeverity::Warning, false)
        }
        RawStreamError::ExternalToolFailed { tool, .. } => damaged_archive(format!("{tool} could not decode this stream.")),
        source => operation_failed(format!("Raw stream operation failed: {source}")),
    }
}

pub(crate) fn map_io_error(path: PathBuf, source: io::Error) -> ZmanagerGuiError {
    if source.kind() == io::ErrorKind::NotFound {
        bridge_error(
            ERROR_NOT_FOUND,
            format!("Path not found: {}", path.display()),
            hint("Choose an archive that has already been copied into app-controlled storage."),
            BridgeSeverity::Warning,
            false,
        )
    } else {
        bridge_error(ERROR_IO_ERROR, format!("I/O failed for {}: {source}", path.display()), None, BridgeSeverity::Error, is_retryable_io_error(source.kind()))
    }
}

pub(crate) fn operation_failed(message: impl Into<String>) -> ZmanagerGuiError {
    bridge_error(ERROR_OPERATION_FAILED, message, None, BridgeSeverity::Error, false)
}

pub(crate) fn damaged_archive(message: impl Into<String>) -> ZmanagerGuiError {
    bridge_error(ERROR_DAMAGED_ARCHIVE, message, hint("Choose a different archive or verify the source file."), BridgeSeverity::Warning, false)
}

pub(crate) fn cancelled_bridge_error(message: impl Into<String>) -> ZmanagerGuiError {
    bridge_error(ERROR_CANCELLED, message, None, BridgeSeverity::Info, true)
}

pub(crate) fn bridge_error_from_mobile(error: ZmanagerGuiError) -> BridgeError {
    match error {
        ZmanagerGuiError::Bridge { code, user_message, recovery_hint, severity, retryable } => {
            BridgeError { code, message: user_message, recovery_hint, severity, retryable }
        }
    }
}

pub(crate) fn bridge_warning(message: impl Into<String>) -> BridgeError {
    bridge_warning_with_code(WARNING_GENERIC, message)
}

pub(crate) fn bridge_warning_with_code(code: impl Into<String>, message: impl Into<String>) -> BridgeError {
    BridgeError { code: code.into(), message: message.into(), recovery_hint: None, severity: BridgeSeverity::Warning, retryable: false }
}

pub(crate) fn bridge_error(
    code: impl Into<String>,
    message: impl Into<String>,
    recovery_hint: Option<String>,
    severity: BridgeSeverity,
    retryable: bool,
) -> ZmanagerGuiError {
    BridgeError { code: code.into(), message: message.into(), recovery_hint, severity, retryable }.into()
}

pub(crate) fn hint(value: impl Into<String>) -> Option<String> {
    Some(value.into())
}

pub(crate) fn is_retryable_io_error(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::UnexpectedEof)
}
