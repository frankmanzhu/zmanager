//! Normalized read domain types and errors for the core engine (ARC-103).

use crate::archive_browser::BrowserEntryKind;
use crate::engine::format::FormatId;
use crate::engine::source::{ArchiveSource, SourceAccess};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};

/// Session-scoped entry identifier (ARC-103).
///
/// `EntryId` is issued during listing and uniquely identifies physical entry
/// records within one opened `ArchiveHandle` session. Duplicate paths retain
/// distinct `EntryId` values. `EntryId` is invalidated when the handle closes.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct EntryId(pub u64);

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// Archive format and source layout detected by the engine.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DetectedArchive {
    /// Detected format identifier.
    pub format: FormatId,
    /// Resolved source descriptor.
    pub source: ArchiveSource,
}

/// Immutable credentials and source options bound to an opened archive handle.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct OpenOptions {
    /// Optional password for encrypted headers or entries.
    pub password: Option<String>,
    /// Optional private key used to unwrap recipient-encrypted TZAP archives.
    pub recipient_key: Option<PathBuf>,
}

impl OpenOptions {
    /// Returns the optional recipient key path as a borrowed path.
    #[must_use]
    pub fn recipient_key_path(&self) -> Option<&Path> {
        self.recipient_key.as_deref()
    }
}

/// One normalized entry record returned by engine listing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EngineEntry {
    /// Session-scoped physical entry handle.
    pub id: EntryId,
    /// Normalized archive path (forward slashes, trimmed leading `./`).
    pub path: String,
    /// Portable entry type.
    pub kind: BrowserEntryKind,
    /// Uncompressed size when known.
    pub size: Option<u64>,
    /// Compressed size when known.
    pub compressed_size: Option<u64>,
    /// Modification time string.
    pub modified: Option<String>,
    /// Unix permission bits when available.
    pub mode: Option<u32>,
    /// Encryption status.
    pub encrypted: Option<bool>,
    /// Compression algorithm or method name.
    pub method: Option<String>,
    /// Checksum (e.g. CRC-32) when available.
    pub crc: Option<u32>,
    /// Entry comment when available.
    pub comment: Option<String>,
    /// Symlink or hardlink target path when applicable.
    pub link_target: Option<String>,
    /// Creation time string when available.
    pub created: Option<String>,
    /// Access time string when available.
    pub accessed: Option<String>,
    /// Solid archive member indicator.
    pub solid: Option<bool>,
    /// Format-specific attribute flags.
    pub attributes: Option<String>,
    /// User identifier.
    pub uid: Option<u32>,
    /// Group identifier.
    pub gid: Option<u32>,
    /// Owner username.
    pub owner: Option<String>,
    /// Group name.
    pub group: Option<String>,
}

impl Default for EngineEntry {
    fn default() -> Self {
        Self {
            id: EntryId(0),
            path: String::new(),
            kind: BrowserEntryKind::File,
            size: None,
            compressed_size: None,
            modified: None,
            mode: None,
            encrypted: None,
            method: None,
            crc: None,
            comment: None,
            link_target: None,
            created: None,
            accessed: None,
            solid: None,
            attributes: None,
            uid: None,
            gid: None,
            owner: None,
            group: None,
        }
    }
}

/// Archive listing returned by an opened engine handle.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArchiveListing {
    /// Entries in archive order.
    pub entries: Vec<EngineEntry>,
}

/// Options for a normalized archive integrity test.
#[derive(Debug, Clone, Default)]
pub struct TestOptions {
    /// Exact archive paths to verify. An empty list verifies every entry.
    pub selected_paths: Vec<String>,
    /// Optional recipient key used by encrypted TZAP archives.
    pub recipient_key: Option<PathBuf>,
    /// Optional X.509 trust policy for TZAP root-auth verification.
    pub tzap_x509_trust: Option<crate::tzap_backend::TzapX509TrustOptions>,
    /// Cooperative cancellation flag checked before and during test work.
    pub cancellation: Option<Arc<AtomicBool>>,
}

impl TestOptions {
    /// Returns whether an entry path is selected by this request.
    #[must_use]
    pub fn selects(&self, path: &str) -> bool {
        self.selected_paths.is_empty() || self.selected_paths.iter().any(|selected| selected == path)
    }

    /// Returns whether the operation was cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.as_ref().is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
    }
}

/// Normalized data-verification report shared by every test adapter.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TestReport {
    /// Number of entries whose payload or integrity metadata was verified.
    pub tested_entries: u64,
    /// Number of entries excluded by the request or not meaningfully testable.
    pub skipped_entries: u64,
    /// Number of decoded regular-file bytes consumed during verification.
    pub tested_bytes: u64,
    /// Non-fatal diagnostics produced by the adapter.
    pub warnings: Vec<String>,
}

/// Archive operation supported by the engine seam.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ArchiveOperation {
    /// List entries in the archive.
    List,
    /// Data verification / integrity test.
    Test,
    /// Full extraction to destination directory.
    Extract,
    /// Selected single or batch entry extraction.
    SelectedExtract,
    /// Copy single entry payload to writer.
    CopyToWriter,
    /// Create new archive from manifest.
    Create,
}

/// Session disposition after an operation or error (ARC-103).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum SessionDisposition {
    /// Session remains usable for subsequent operations.
    Usable,
    /// Session cursor or parser state is corrupted/uncertain; subsequent operations must fail.
    Unusable,
}

/// Category of operation error.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ErrorKind {
    /// Unsupported or unrecognized format.
    InvalidFormat,
    /// Password required to read header or payload.
    PasswordRequired,
    /// Provided password was rejected.
    WrongPassword,
    /// Data corruption or checksum failure.
    CorruptData,
    /// Resource or security limit exceeded.
    ResourceLimitExceeded,
    /// Extraction safety policy violation.
    SafetyViolation,
    /// Underlying filesystem I/O error.
    Io,
    /// Operation not supported by this format/adapter.
    UnsupportedOperation,
    /// Operation was cooperatively cancelled.
    Cancelled,
}

/// Structured error returned by the archive engine interface.
#[derive(Debug)]
pub struct ArchiveError {
    /// Category of error.
    pub kind: ErrorKind,
    /// User-facing descriptive message.
    pub message: String,
    /// Handle session state disposition after this error.
    pub disposition: SessionDisposition,
    /// Optional underlying path.
    pub path: Option<PathBuf>,
}

impl ArchiveError {
    /// Creates a usable session error.
    #[must_use]
    pub fn usable(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into(), disposition: SessionDisposition::Usable, path: None }
    }

    /// Creates an unusable session error.
    #[must_use]
    pub fn unusable(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into(), disposition: SessionDisposition::Unusable, path: None }
    }

    /// Attaches an associated file path to this error.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(f, "{}: {} ({})", self.kind_str(), self.message, path.display())
        } else {
            write!(f, "{}: {}", self.kind_str(), self.message)
        }
    }
}

impl ArchiveError {
    fn kind_str(&self) -> &'static str {
        match self.kind {
            ErrorKind::InvalidFormat => "invalid format",
            ErrorKind::PasswordRequired => "password required",
            ErrorKind::WrongPassword => "wrong password",
            ErrorKind::CorruptData => "corrupt data",
            ErrorKind::ResourceLimitExceeded => "resource limit exceeded",
            ErrorKind::SafetyViolation => "safety violation",
            ErrorKind::Io => "I/O error",
            ErrorKind::UnsupportedOperation => "unsupported operation",
            ErrorKind::Cancelled => "cancelled",
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<io::Error> for ArchiveError {
    fn from(err: io::Error) -> Self {
        Self::unusable(ErrorKind::Io, err.to_string())
    }
}

/// Immutable capability summary reported by an engine handle or registry snapshot.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HandleCapabilities {
    /// Format identifier.
    pub format: FormatId,
    /// Source access capability.
    pub source_access: SourceAccess,
    /// Supported operations.
    pub operations: Vec<ArchiveOperation>,
    /// Whether header or payload encryption is supported.
    pub encryption_supported: bool,
}

/// One immutable capability row for a canonical format registry snapshot.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FormatCapabilities {
    /// Canonical engine format identity.
    pub format: FormatId,
    /// Whether the canonical detector recognizes this format.
    pub recognized: bool,
    /// Whether the current build can execute a registered operation.
    pub platform_available: bool,
    /// Stable reason when the format is recognized but unavailable.
    pub unavailable_reason: Option<String>,
    /// Registered operations for this format.
    pub operations: Vec<ArchiveOperation>,
    /// Source access required by the registered adapters.
    pub source_access: Option<SourceAccess>,
    /// Whether any registered adapter supports encryption.
    pub encryption_supported: bool,
}
