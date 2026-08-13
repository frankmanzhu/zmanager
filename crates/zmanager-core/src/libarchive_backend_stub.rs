//! Disabled-profile libarchive compatibility surface.
//!
//! The full implementation is compiled only with `libarchive-fallback`.
//! Keeping the small report/error vocabulary available lets shared callers
//! compile in reduced artifacts without carrying the native dependency.

use crate::extract_materialize::DeferredHardlink;
use crate::jobs::JobContext;
use crate::safety::{ExtractionPolicy, ExtractionSafetyError, OverwriteResolver};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LibarchiveListEntry {
    pub path: String,
    pub kind: LibarchiveEntryKind,
    pub size: i64,
    pub mode: u32,
    pub modified: Option<SystemTime>,
    pub data_encrypted: bool,
    pub metadata_encrypted: bool,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub link_target: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LibarchiveEntryKind {
    File,
    Directory,
    Symlink,
    Hardlink,
    Device,
    Special,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LibarchiveListing {
    pub entries: Vec<LibarchiveListEntry>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LibarchiveExtractReport {
    pub written_entries: usize,
    pub skipped_entries: usize,
    pub written_bytes: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LibarchiveTestReport {
    pub tested_entries: usize,
    pub skipped_entries: usize,
    pub tested_bytes: u64,
}

#[derive(Debug)]
pub enum LibarchiveError {
    Archive(String),
    RawStream(crate::raw_stream_backend::RawStreamError),
    Io { path: PathBuf, source: std::io::Error },
    Safety(ExtractionSafetyError),
    MissingPath,
    MissingLinkTarget { path: String },
    EntryNotFound { path: String },
    Cancelled,
    StdoutSelectionNotSingleFile { selected_files: usize },
    Unsupported,
}

impl fmt::Display for LibarchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Archive(source) => write!(f, "libarchive operation failed: {source}"),
            Self::RawStream(source) => write!(f, "compressed tar decode failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected an entry: {source}"),
            Self::MissingPath => f.write_str("libarchive entry has no path"),
            Self::MissingLinkTarget { path } => write!(f, "libarchive link entry has no target: {path}"),
            Self::EntryNotFound { path } => write!(f, "archive entry not found: {path}"),
            Self::Cancelled => f.write_str("job cancelled"),
            Self::StdoutSelectionNotSingleFile { selected_files } => write!(f, "stdout selection resolved to {selected_files} files"),
            Self::Unsupported => f.write_str("libarchive fallback is disabled in this artifact profile"),
        }
    }
}

impl std::error::Error for LibarchiveError {}

impl From<ExtractionSafetyError> for LibarchiveError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

fn unsupported<T>() -> Result<T, LibarchiveError> {
    Err(LibarchiveError::Unsupported)
}

pub fn list_archive(_path: impl AsRef<Path>) -> Result<LibarchiveListing, LibarchiveError> {
    unsupported()
}
pub fn list_archive_with_password(_path: impl AsRef<Path>, _password: Option<&str>) -> Result<LibarchiveListing, LibarchiveError> {
    unsupported()
}
pub fn extract_archive(
    _archive_path: impl AsRef<Path>,
    _destination: impl AsRef<Path>,
    _policy: ExtractionPolicy,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    unsupported()
}
pub fn extract_archive_with_password(
    _archive_path: impl AsRef<Path>,
    _destination: impl AsRef<Path>,
    _policy: ExtractionPolicy,
    _password: Option<&str>,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    unsupported()
}
pub fn extract_archive_with_password_and_context(
    _archive_path: impl AsRef<Path>,
    _destination: impl AsRef<Path>,
    _policy: ExtractionPolicy,
    _password: Option<&str>,
    _context: &mut JobContext<'_>,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    unsupported()
}
pub fn extract_archive_with_overwrite_resolver_and_password(
    _archive_path: impl AsRef<Path>,
    _destination: impl AsRef<Path>,
    _policy: ExtractionPolicy,
    _password: Option<&str>,
    _resolver: &mut dyn OverwriteResolver,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    unsupported()
}
pub fn extract_archive_entry(
    _archive_path: impl AsRef<Path>,
    _entry_path: &str,
    _destination: impl AsRef<Path>,
    _policy: ExtractionPolicy,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    unsupported()
}
pub fn extract_archive_entry_with_password(
    _archive_path: impl AsRef<Path>,
    _entry_path: &str,
    _destination: impl AsRef<Path>,
    _policy: ExtractionPolicy,
    _password: Option<&str>,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    unsupported()
}
pub fn extract_archive_entry_by_index(
    _archive_path: impl AsRef<Path>,
    _destination: impl AsRef<Path>,
    _policy: ExtractionPolicy,
    _password: Option<&str>,
    _entry_index: usize,
    _resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    unsupported()
}
pub fn copy_archive_files_to_writer<W: Write>(
    _archive_path: impl AsRef<Path>,
    _password: Option<&str>,
    _selected: impl FnMut(&str) -> bool,
    _output: &mut W,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    unsupported()
}
pub fn copy_archive_entry_by_index<W: Write + ?Sized>(
    _archive_path: impl AsRef<Path>,
    _password: Option<&str>,
    _entry_index: usize,
    _output: &mut W,
) -> Result<u64, LibarchiveError> {
    unsupported()
}
pub fn test_archive_with_password_filter(
    _archive_path: impl AsRef<Path>,
    _password: Option<&str>,
    _selected: impl FnMut(&str) -> bool,
) -> Result<LibarchiveTestReport, LibarchiveError> {
    unsupported()
}
#[must_use]
pub fn is_split_zip_path(_path: &Path) -> bool {
    false
}

#[allow(dead_code)]
fn _keep_shared_type_references(_: Option<DeferredHardlink>) {}
