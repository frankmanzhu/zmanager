//! Error-code constants and the backend-error → `ZmanagerGuiError` mapping.

use std::io;
use std::path::PathBuf;

use zmanager_core::archive_browser::ArchiveBrowserError;
use zmanager_core::engine::{ArchiveError, ErrorKind};
use zmanager_core::manifest::PlanError;

use crate::ffi::types::{BridgeError, BridgeSeverity, ZmanagerGuiError};
#[cfg(feature = "tzap-online")]
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
#[cfg(feature = "tzap-online")]
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
#[cfg(feature = "tzap-online")]
pub(crate) fn existing_archive_path_or_tzap_error(value: String) -> Result<String, String> {
    ensure_existing_tzap_archive_path(value, "archivePath").map_err(return_tzap_error)
}

pub(crate) fn map_archive_browser_error(error: ArchiveBrowserError) -> ZmanagerGuiError {
    match error {
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
        ErrorKind::InvalidFormat | ErrorKind::UnsupportedOperation | ErrorKind::ResourceLimitExceeded | ErrorKind::SourceChanged => {
            bridge_error(ERROR_UNSUPPORTED_FORMAT, message, None, BridgeSeverity::Warning, false)
        }
        ErrorKind::Cancelled => bridge_error(ERROR_OPERATION_FAILED, message, None, BridgeSeverity::Warning, true),
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
