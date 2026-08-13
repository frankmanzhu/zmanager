//! Normalized read domain types and errors for the core engine (ARC-103).

use crate::archive_browser::BrowserEntryKind;
use crate::engine::format::FormatId;
use crate::engine::source::{ArchiveSource, SourceAccess};
use std::fmt;
use std::io;
use std::path::PathBuf;

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
}

/// Archive listing returned by an opened engine handle.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArchiveListing {
    /// Entries in archive order.
    pub entries: Vec<EngineEntry>,
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
