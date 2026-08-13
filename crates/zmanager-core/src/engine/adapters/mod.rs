//! Archive format adapters for the core engine.

use std::path::Path;

use crate::engine::types::{ArchiveError, ErrorKind, ExtractReport, SessionDisposition};
use crate::safety::ExtractionSafetyError;

pub(crate) fn extract_report(written_entries: usize, skipped_entries: usize, written_bytes: u64, warnings: Vec<String>) -> ExtractReport {
    ExtractReport {
        written_entries: u64::try_from(written_entries).unwrap_or(u64::MAX),
        skipped_entries: u64::try_from(skipped_entries).unwrap_or(u64::MAX),
        written_bytes,
        warnings,
    }
}

pub(crate) fn extract_error(path: &Path, error: impl std::fmt::Display) -> ArchiveError {
    let message = error.to_string();
    let lower = message.to_lowercase();
    let kind = if lower.contains("resource") || lower.contains("limit") {
        ErrorKind::ResourceLimitExceeded
    } else if lower.contains("safety") || lower.contains("unsafe") {
        ErrorKind::SafetyViolation
    } else if lower.contains("unsupported") {
        ErrorKind::UnsupportedOperation
    } else {
        ErrorKind::Io
    };
    ArchiveError {
        kind,
        message,
        disposition: if kind == ErrorKind::SafetyViolation { SessionDisposition::Unusable } else { SessionDisposition::Usable },
        path: Some(path.to_path_buf()),
    }
}

pub(crate) fn safety_error_kind(error: &ExtractionSafetyError) -> ErrorKind {
    match error {
        ExtractionSafetyError::ExpandedSizeLimitExceeded { .. }
        | ExtractionSafetyError::ExpansionRatioLimitExceeded { .. }
        | ExtractionSafetyError::EntryCountLimitExceeded { .. } => ErrorKind::ResourceLimitExceeded,
        _ => ErrorKind::SafetyViolation,
    }
}

pub mod create;
#[cfg(feature = "libarchive-fallback")]
pub mod libarchive;
pub mod native;
pub mod zip;
