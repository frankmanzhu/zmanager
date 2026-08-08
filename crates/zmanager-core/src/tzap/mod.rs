//! TZAP backend implementation.
//!
//! This module tree hosts the code previously contained in
//! `tzap_backend.rs`. The historical `crate::tzap_backend::...` paths are
//! preserved by the re-export facade in `tzap_backend.rs`.

mod display;
mod extract;
mod listing;
mod metadata;
mod open;
mod write;
mod x509;

#[cfg(test)]
mod tests;

pub use display::{
    TzapPublicDisplaySummary, TzapPublicSignatureStatus, inspect_tzap_public_footer_signature,
    summarize_tzap_public_display,
};
pub use extract::{
    TzapExtractKeySource, TzapExtractReport, TzapExtractRequest, TzapFileExtractReport, TzapRestoreOptions,
    TzapRestorePolicy, copy_tzap_file_to_writer, copy_tzap_files_to_writer, extract_tzap,
    extract_tzap_file_to_destination,
};
pub use listing::{
    TzapEntry, TzapEntryKind, TzapIndexEntry, TzapIndexListing, TzapListing,
    list_tzap_directory_with_optional_password, list_tzap_index_with_optional_password,
    list_tzap_index_with_recipient_key, list_tzap_with_optional_password, list_tzap_with_password,
    list_tzap_with_recipient_key,
};
pub use open::is_tzap_archive_path;
pub use open::{
    TzapPublicFormatSummary, TzapPublicMetadataSummary, TzapPublicVolumeSummary, summarize_tzap_public_metadata,
};
pub use write::{TzapCreateOptions, TzapCreateReport, TzapKeySource, create_tzap_from_manifest_with_context};
pub use x509::{
    TzapTestReport, TzapX509SignerInspection, TzapX509SigningOptions, TzapX509TrustOptions, TzapX509VerificationReport,
    inspect_tzap_x509_public_no_key_signer, inspect_tzap_x509_signer,
    test_tzap_with_optional_password_filter_and_x509_trust, test_tzap_with_password_filter,
    test_tzap_with_password_filter_and_x509_trust, test_tzap_with_recipient_key_filter_and_x509_trust,
    tzap_x509_signing_options_from_inventory, verify_tzap_x509_public_no_key,
};

pub(crate) const TZAP_EXTENSION: &str = "tzap";
pub(crate) const TZAP_EXTENSION_SUFFIX: &str = ".tzap";
pub(crate) const TZAP_VOLUME_MARKER: &str = ".vol";
pub(crate) const TZAP_VOLUME_INDEX_WIDTH: usize = 3;

/// `.tzap` backend error.
#[derive(Debug)]
pub enum TzapError {
    /// Manifest planning failed.
    Plan(PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Archive format, cryptographic, or metadata validation failed.
    Format(FormatError),
    /// X.509 `RootAuth` signing or verification failed.
    X509RootAuth(String),
    /// X.509 recipient key wrapping failed.
    KeyWrap(String),
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// A passphrase-protected `.tzap` archive was opened without a password.
    PasswordRequired,
    /// A recipient-wrapped `.tzap` archive was opened without a recipient private key.
    RecipientKeyRequired,
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for TzapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "{source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Format(source) => write!(f, "{source}"),
            Self::X509RootAuth(message) | Self::KeyWrap(message) => write!(f, "{message}"),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::PasswordRequired => write!(f, "tzap password required"),
            Self::RecipientKeyRequired => write!(f, "tzap recipient private key required"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for TzapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Format(source) => Some(source),
            Self::Safety(source) => Some(source),
            Self::X509RootAuth(_)
            | Self::KeyWrap(_)
            | Self::PasswordRequired
            | Self::RecipientKeyRequired
            | Self::Cancelled => None,
        }
    }
}

impl From<FormatError> for TzapError {
    fn from(source: FormatError) -> Self {
        Self::Format(source)
    }
}

impl From<PlanError> for TzapError {
    fn from(source: PlanError) -> Self {
        Self::Plan(source)
    }
}

impl From<ExtractionSafetyError> for TzapError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

impl From<JobCancelled> for TzapError {
    fn from(_source: JobCancelled) -> Self {
        Self::Cancelled
    }
}

pub(crate) fn io_error(path: &Path, kind: io::ErrorKind, message: impl Into<String>) -> TzapError {
    TzapError::Io { path: path.to_path_buf(), source: io::Error::new(kind, message.into()) }
}

use crate::jobs::JobCancelled;
use crate::manifest::PlanError;
use crate::safety::ExtractionSafetyError;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use tzap_core::format::FormatError;
