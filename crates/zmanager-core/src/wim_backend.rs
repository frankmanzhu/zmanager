#![allow(clippy::cast_possible_truncation, clippy::missing_panics_doc)]

//! Core integration for the read-only WIM library.
//!
//! WIM parsing and resource decoding live in [`zmanager_wim`]. This module
//! adapts its entries to the shared `ZManager` extraction, cancellation, and
//! reporting policies.

use crate::engine::types::TestOptions;
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use sha1::{Digest as _, Sha1};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub use zmanager_wim::{WimArchive, WimCompression, WimEntry, WimEntryKind};

crate::backend_error_from_impls!(WimBackendError);

/// Normalized WIM operation report.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct WimReport {
    /// Entries written or verified.
    pub entries: usize,
    /// Entries skipped by selection or policy.
    pub skipped_entries: usize,
    /// Regular-file bytes written or verified.
    pub bytes: u64,
    /// Non-fatal diagnostics.
    pub warnings: Vec<String>,
}

/// Error returned by native WIM operations.
#[derive(Debug)]
pub enum WimBackendError {
    /// Manifest planning failed.
    Plan(crate::manifest::PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// WIM format or decompression error.
    Invalid { path: PathBuf, message: String },
    /// The WIM is well-formed but uses a feature this backend does not decode.
    Unsupported { path: PathBuf, message: String },
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for WimBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::Invalid { path, message } => write!(f, "invalid WIM {}: {message}", path.display()),
            Self::Unsupported { path, message } => write!(f, "unsupported WIM {}: {message}", path.display()),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for WimBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Invalid { .. } | Self::Unsupported { .. } | Self::Cancelled => None,
        }
    }
}

impl From<zmanager_wim::WimError> for WimBackendError {
    fn from(error: zmanager_wim::WimError) -> Self {
        match error {
            zmanager_wim::WimError::Io { path, source } => Self::Io { path, source },
            zmanager_wim::WimError::Invalid { path, message } => Self::Invalid { path, message },
            zmanager_wim::WimError::Unsupported { path, message } => Self::Unsupported { path, message },
        }
    }
}

fn io_error(path: impl AsRef<Path>, source: io::Error) -> WimBackendError {
    WimBackendError::Io { path: path.as_ref().to_path_buf(), source }
}

fn invalid(path: impl AsRef<Path>, message: impl Into<String>) -> WimBackendError {
    WimBackendError::Invalid { path: path.as_ref().to_path_buf(), message: message.into() }
}

fn open_and_collect(path: &Path) -> Result<(WimArchive, Vec<WimEntry>), WimBackendError> {
    let mut archive = WimArchive::open(path)?;
    let entries = archive.entries()?;
    Ok((archive, entries))
}

fn read_entry_stream(archive: &mut WimArchive, entry: &WimEntry) -> Result<Option<Vec<u8>>, WimBackendError> {
    archive.read_entry_data(entry).map_err(Into::into)
}

/// Lists every entry of every image in a WIM.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<WimEntry>, WimBackendError> {
    let path = path.as_ref();
    let (_, entries) = open_and_collect(path)?;
    Ok(entries)
}

/// Verifies selected or all WIM files, checking each stream against its
/// recorded SHA-1.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<WimReport, WimBackendError> {
    let path = path.as_ref();
    let (mut archive, entries) = open_and_collect(path)?;

    let mut report = WimReport::default();
    for entry in entries {
        if options.is_cancelled() {
            return Err(WimBackendError::Cancelled);
        }
        if !options.selects(&entry.path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        if entry.kind == WimEntryKind::File
            && let Some(data) = read_entry_stream(&mut archive, &entry)?
        {
            if data.len() as u64 != entry.size {
                return Err(invalid(path, format!("WIM entry {} decoded to {} bytes, expected {}", entry.path, data.len(), entry.size)));
            }
            let digest: [u8; 20] = Sha1::digest(&data).into();
            if digest != entry.sha1 {
                return Err(invalid(
                    path,
                    format!("WIM entry {} hashes to {}, but the lookup table records {}", entry.path, hex::encode(digest), hex::encode(entry.sha1)),
                ));
            }
            report.bytes = report.bytes.saturating_add(data.len() as u64);
        }
        report.entries = report.entries.saturating_add(1);
    }
    Ok(report)
}

/// Extracts every WIM entry through the shared safety planner and atomic output.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<WimReport, WimBackendError> {
    let path = path.as_ref();
    let destination = destination.as_ref();
    let root = crate::safety::prepare_destination_root(destination).map_err(|source| io_error(destination, source))?;
    let (mut archive, entries) = open_and_collect(path)?;

    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&root, policy, resolver);
    let mut report = WimReport::default();

    for entry in entries {
        if cancellation.is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(WimBackendError::Cancelled);
        }
        let kind = match entry.kind {
            WimEntryKind::File => ExtractionEntryKind::File,
            WimEntryKind::Directory => ExtractionEntryKind::Directory,
            WimEntryKind::Symlink => {
                let Some(target) = entry.link_target.clone().filter(|target| !target.is_empty()) else {
                    report.skipped_entries = report.skipped_entries.saturating_add(1);
                    report.warnings.push(format!("skipped reparse point {}: the image does not expose a usable link target", entry.path));
                    continue;
                };
                ExtractionEntryKind::Symlink { target: PathBuf::from(target) }
            }
        };
        let safety_entry = ExtractionEntry { archive_path: entry.path.clone(), kind, uncompressed_size: Some(entry.size), compressed_size: None };
        let decision = planner.validate_entry(&safety_entry)?;
        let ExtractionDecision::Write { destination_path, replace_existing, .. } = decision else {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        };
        match &safety_entry.kind {
            ExtractionEntryKind::Directory => {
                if replace_existing {
                    crate::safety::remove_destination_for_replace(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                }
                std::fs::create_dir_all(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                report.entries = report.entries.saturating_add(1);
            }
            ExtractionEntryKind::File => {
                let data = read_entry_stream(&mut archive, &entry)?.unwrap_or_default();
                let mut output = crate::atomic_file::AtomicOutputFile::create(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                let file_out = output.file_mut().map_err(|source| io_error(&destination_path, source))?;
                file_out.write_all(&data).map_err(|source| io_error(&destination_path, source))?;
                output.commit_with_replace(replace_existing).map_err(|source| io_error(&destination_path, source))?;
                report.entries = report.entries.saturating_add(1);
                report.bytes = report.bytes.saturating_add(data.len() as u64);
            }
            ExtractionEntryKind::Symlink { target } => {
                if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
                    report.skipped_entries = report.skipped_entries.saturating_add(1);
                    report.warnings.push(crate::safety::unsupported_symlink_warning(&entry.path));
                    continue;
                }
                if replace_existing {
                    crate::safety::remove_destination_for_replace(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                }
                crate::extract_materialize::write_symlink(target, &destination_path).map_err(|source| io_error(&destination_path, source))?;
                report.entries = report.entries.saturating_add(1);
            }
            _ => unreachable!("WIM entries map only to files, directories, and symlinks"),
        }
    }
    Ok(report)
}

/// Copies one file entry to the writer.
pub fn copy_to_writer(path: impl AsRef<Path>, target_path: &str, writer: &mut dyn Write) -> Result<u64, WimBackendError> {
    let path = path.as_ref();
    let (mut archive, entries) = open_and_collect(path)?;

    let Some(entry) = entries.into_iter().find(|entry| entry.path == target_path && entry.kind == WimEntryKind::File) else {
        return Err(invalid(path, format!("file '{target_path}' not found in WIM")));
    };
    let Some(data) = read_entry_stream(&mut archive, &entry)? else { return Ok(0) };
    writer.write_all(&data).map_err(|source| io_error(path, source))?;
    Ok(data.len() as u64)
}
