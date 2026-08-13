//! Native LHA/LZH reader backed by `delharc`.

use crate::archive_browser::BrowserEntryKind;
use crate::engine::types::TestOptions;
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// One normalized LHA entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LhaEntry {
    /// Retained archive-order entry ID.
    pub index: usize,
    /// Normalized archive path.
    pub path: String,
    /// Portable entry kind.
    pub kind: BrowserEntryKind,
    /// Declared uncompressed size.
    pub size: u64,
    /// Whether the compression method is supported by `delharc`.
    pub supported: bool,
}

/// Native LHA operation report.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct LhaReport {
    /// Entries written or verified.
    pub entries: usize,
    /// Entries skipped by selection or policy.
    pub skipped_entries: usize,
    /// Regular-file bytes written or verified.
    pub bytes: u64,
    /// Non-fatal diagnostics.
    pub warnings: Vec<String>,
}

/// Native LHA operation error.
#[derive(Debug)]
pub enum LhaError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// The archive or one of its members is malformed or unsupported.
    Invalid { path: PathBuf, message: String },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// The caller cancelled the operation.
    Cancelled,
}

impl fmt::Display for LhaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Invalid { path, message } => write!(f, "invalid LHA {}: {message}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected LHA entry: {source}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for LhaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Invalid { .. } | Self::Cancelled => None,
        }
    }
}

impl From<ExtractionSafetyError> for LhaError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Lists entries from an LHA/LZH archive.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<LhaEntry>, LhaError> {
    let path = path.as_ref();
    let mut reader = open(path)?;
    let mut entries = Vec::new();
    loop {
        let header = reader.header().clone();
        let normalized = normalize_path(&header.parse_pathname_to_str())?;
        let kind = if header.is_directory() { BrowserEntryKind::Directory } else { BrowserEntryKind::File };
        if entries.iter().any(|entry: &LhaEntry| entry.path == normalized) {
            return Err(invalid(path, format!("duplicate path {normalized}")));
        }
        entries.push(LhaEntry {
            index: entries.len(),
            path: normalized,
            kind,
            size: header.original_size,
            supported: header.is_directory() || reader.is_decoder_supported(),
        });
        if !reader.next_file().map_err(|error| invalid(path, error))? {
            break;
        }
    }
    Ok(entries)
}

/// Verifies selected LHA members and their CRC-16 values.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<LhaReport, LhaError> {
    let path = path.as_ref();
    let mut reader = open(path)?;
    let mut report = LhaReport::default();
    loop {
        if options.is_cancelled() {
            return Err(LhaError::Cancelled);
        }
        let header = reader.header().clone();
        let entry_path = normalize_path(&header.parse_pathname_to_str())?;
        if !options.selects(&entry_path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
        } else if header.is_directory() {
            report.entries = report.entries.saturating_add(1);
        } else {
            ensure_supported(path, &reader)?;
            let bytes = io::copy(&mut reader, &mut io::sink()).map_err(|source| io_error(path, source))?;
            reader.crc_check().map_err(|error| invalid(path, error))?;
            if bytes != header.original_size {
                return Err(invalid(path, format!("{entry_path} decoded to {bytes} bytes, expected {}", header.original_size)));
            }
            report.entries = report.entries.saturating_add(1);
            report.bytes = report.bytes.saturating_add(bytes);
        }
        if !reader.next_file().map_err(|error| invalid(path, error))? {
            break;
        }
    }
    Ok(report)
}

/// Extracts an LHA archive through the shared safety planner.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<LhaReport, LhaError> {
    let path = path.as_ref();
    let destination = destination.as_ref();
    let root = crate::safety::prepare_destination_root(destination).map_err(|source| io_error(destination, source))?;
    let mut reader = open(path)?;
    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&root, policy, resolver);
    let mut report = LhaReport::default();
    loop {
        if cancellation.is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(LhaError::Cancelled);
        }
        let header = reader.header().clone();
        let entry_path = normalize_path(&header.parse_pathname_to_str())?;
        let entry_kind = if header.is_directory() { ExtractionEntryKind::Directory } else { ExtractionEntryKind::File };
        let safety_entry = ExtractionEntry {
            archive_path: entry_path.clone(),
            kind: entry_kind,
            uncompressed_size: Some(header.original_size),
            compressed_size: Some(header.compressed_size),
        };
        let decision = planner.validate_entry(&safety_entry)?;
        let ExtractionDecision::Write { destination_path, replace_existing, .. } = decision else {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            if !reader.next_file().map_err(|error| invalid(path, error))? {
                break;
            }
            continue;
        };
        if header.is_directory() {
            if replace_existing {
                crate::safety::remove_destination_for_replace(&destination_path).map_err(|source| io_error(&destination_path, source))?;
            }
            std::fs::create_dir_all(&destination_path).map_err(|source| io_error(&destination_path, source))?;
            report.entries = report.entries.saturating_add(1);
        } else {
            ensure_supported(path, &reader)?;
            let mut output = crate::atomic_file::AtomicOutputFile::create(&destination_path).map_err(|source| io_error(&destination_path, source))?;
            let bytes = io::copy(&mut reader, output.file_mut().map_err(|source| io_error(&destination_path, source))?)
                .map_err(|source| io_error(&destination_path, source))?;
            reader.crc_check().map_err(|error| invalid(path, error))?;
            if bytes != header.original_size {
                return Err(invalid(path, format!("{entry_path} decoded to {bytes} bytes, expected {}", header.original_size)));
            }
            output.commit_with_replace(replace_existing).map_err(|source| io_error(&destination_path, source))?;
            report.entries = report.entries.saturating_add(1);
            report.bytes = report.bytes.saturating_add(bytes);
        }
        if !reader.next_file().map_err(|error| invalid(path, error))? {
            break;
        }
    }
    Ok(report)
}

/// Copies one retained regular LHA file to a caller-owned writer.
pub fn copy(path: impl AsRef<Path>, entry_index: usize, writer: &mut dyn io::Write) -> Result<u64, LhaError> {
    let path = path.as_ref();
    let mut reader = open(path)?;
    for index in 0..=entry_index {
        if index != 0 && !reader.next_file().map_err(|error| invalid(path, error))? {
            return Err(invalid(path, "retained LHA entry ID is not present"));
        }
    }
    if reader.header().is_directory() {
        return Err(invalid(path, "retained LHA entry is not a regular file"));
    }
    ensure_supported(path, &reader)?;
    let expected = reader.header().original_size;
    let bytes = io::copy(&mut reader, writer).map_err(|source| io_error(path, source))?;
    reader.crc_check().map_err(|error| invalid(path, error))?;
    if bytes != expected {
        return Err(invalid(path, format!("decoded to {bytes} bytes, expected {expected}")));
    }
    Ok(bytes)
}

fn open(path: &Path) -> Result<delharc::LhaDecodeReader<File>, LhaError> {
    delharc::parse_file(path).map_err(|source| io_error(path, source))
}

fn ensure_supported(path: &Path, reader: &delharc::LhaDecodeReader<File>) -> Result<(), LhaError> {
    if reader.is_decoder_supported() {
        Ok(())
    } else {
        Err(invalid(path, format!("unsupported compression method {:?}", reader.header().compression_method())))
    }
}

fn normalize_path(raw: &str) -> Result<String, LhaError> {
    crate::safety::normalize_archive_path(raw).map_err(LhaError::Safety)
}

fn invalid(path: &Path, error: impl fmt::Display) -> LhaError {
    LhaError::Invalid { path: path.to_path_buf(), message: error.to_string() }
}

fn io_error(path: &Path, source: io::Error) -> LhaError {
    LhaError::Io { path: path.to_path_buf(), source }
}
