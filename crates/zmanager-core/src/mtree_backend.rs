//! Native MTREE manifest reader.
//!
//! MTREE describes filesystem metadata and optional digests; it does not
//! contain the file payloads. Extraction therefore materializes the declared
//! filesystem shape and file sizes (as sparse placeholder files), while list
//! and test report the manifest entries and declared metadata.

use crate::archive_browser::BrowserEntryKind;
use crate::engine::types::TestOptions;
use crate::extract_loop::{EntryAction, ExtractReport as ExtractReportTrait, process_extraction_entry};
use crate::jobs::{CancellationToken, JobCancelled};
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Cursor, Read as _, Write as _};
use std::path::{Path, PathBuf};

const MAX_MTREE_BYTES: u64 = 64 * 1024 * 1024;

/// One normalized MTREE manifest entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MtreeEntry {
    /// Retained manifest-order entry ID.
    pub index: usize,
    /// Normalized relative manifest path.
    pub path: String,
    /// Portable entry kind.
    pub kind: BrowserEntryKind,
    /// Declared regular-file size, when present.
    pub size: Option<u64>,
    /// Declared file type name.
    pub file_type: String,
    /// Symbolic-link target when the manifest declares one.
    pub link_target: Option<PathBuf>,
}

/// Native MTREE operation report.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct MtreeReport {
    /// Manifest entries parsed or verified.
    pub entries: usize,
    /// Entries skipped by selection.
    pub skipped_entries: usize,
    /// Declared regular-file bytes covered by the operation.
    pub bytes: u64,
    /// Non-fatal diagnostics.
    pub warnings: Vec<String>,
}

/// Native MTREE operation error.
#[derive(Debug)]
pub enum MtreeError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// The manifest is malformed or cannot be normalized safely.
    Invalid { path: PathBuf, message: String },
    /// A manifest path violated shared path safety rules.
    Safety(ExtractionSafetyError),
    /// The caller cancelled the operation.
    Cancelled,
}

impl From<ExtractionSafetyError> for MtreeError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

impl From<JobCancelled> for MtreeError {
    fn from(_: JobCancelled) -> Self {
        Self::Cancelled
    }
}

impl ExtractReportTrait for MtreeReport {
    fn skipped_entries_mut(&mut self) -> &mut usize {
        &mut self.skipped_entries
    }

    fn warnings_mut(&mut self) -> &mut Vec<String> {
        &mut self.warnings
    }
}

impl fmt::Display for MtreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Invalid { path, message } => write!(f, "invalid MTREE {}: {message}", path.display()),
            Self::Safety(source) => write!(f, "MTREE path rejected by extraction safety: {source}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for MtreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Invalid { .. } | Self::Cancelled => None,
        }
    }
}

/// Lists MTREE manifest records.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<MtreeEntry>, MtreeError> {
    let path = path.as_ref();
    let bytes = read_manifest(path)?;
    let mut entries = Vec::new();
    let mut used_paths = Vec::new();
    for result in mtree::MTree::from_reader(Cursor::new(bytes)) {
        let entry = result.map_err(|source| invalid(path, source))?;
        let normalized = normalize_path(entry.path())?;
        if used_paths.iter().any(|existing| existing == &normalized) {
            return Err(invalid(path, format!("duplicate path {normalized}")));
        }
        used_paths.push(normalized.clone());
        let file_type = entry.file_type().unwrap_or(mtree::FileType::File);
        entries.push(MtreeEntry {
            index: entries.len(),
            path: normalized,
            kind: map_kind(file_type),
            size: entry.size(),
            file_type: file_type.to_string(),
            link_target: entry.link().map(Path::to_path_buf),
        });
    }
    Ok(entries)
}

/// Validates selected MTREE manifest records and their declared metadata.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<MtreeReport, MtreeError> {
    let path = path.as_ref();
    let entries = list(path)?;
    let mut report = MtreeReport::default();
    for entry in entries {
        if options.is_cancelled() {
            return Err(MtreeError::Cancelled);
        }
        if !options.selects(&entry.path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        report.entries = report.entries.saturating_add(1);
        if entry.kind == BrowserEntryKind::File {
            report.bytes = report.bytes.saturating_add(entry.size.unwrap_or(0));
        }
    }
    Ok(report)
}

/// Materializes the filesystem shape declared by an MTREE manifest.
///
/// MTREE is a manifest, not a payload container. Regular files are therefore
/// created as sparse placeholders with their declared size; their original
/// contents are not available in the manifest. Symbolic links are restored
/// from their declared targets, and directories are created normally.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn crate::safety::OverwriteResolver>,
    cancellation: Option<&CancellationToken>,
) -> Result<MtreeReport, MtreeError> {
    let path = path.as_ref();
    let entries = list(path)?;
    let mut report = MtreeReport::default();
    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(destination.as_ref(), policy, overwrite_resolver);

    for entry in entries {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(MtreeError::Cancelled);
        }

        let safety_entry = ExtractionEntry {
            archive_path: entry.path.clone(),
            kind: match entry.kind {
                BrowserEntryKind::File => ExtractionEntryKind::File,
                BrowserEntryKind::Directory => ExtractionEntryKind::Directory,
                BrowserEntryKind::Symlink => ExtractionEntryKind::Symlink {
                    target: entry.link_target.clone().ok_or_else(|| invalid(path, format!("symbolic-link entry {} has no link target", entry.path)))?,
                },
                BrowserEntryKind::Hardlink => ExtractionEntryKind::Hardlink {
                    target: entry.link_target.clone().ok_or_else(|| invalid(path, format!("hard-link entry {} has no link target", entry.path)))?,
                },
                BrowserEntryKind::Special | BrowserEntryKind::FileCopy => ExtractionEntryKind::Special,
            },
            uncompressed_size: (entry.kind == BrowserEntryKind::File).then_some(entry.size.unwrap_or(0)),
            compressed_size: None,
        };

        process_extraction_entry(&mut report, None, &mut planner, &safety_entry, &mut |action, report, _context| {
            let EntryAction::Write(decision) = action else {
                return Ok(0);
            };

            if decision.replace_existing {
                crate::safety::remove_destination_for_replace(decision.destination_path).map_err(|source| io_error(decision.destination_path, source))?;
            }

            let written = match &safety_entry.kind {
                ExtractionEntryKind::Directory => {
                    fs::create_dir_all(decision.destination_path).map_err(|source| io_error(decision.destination_path, source))?;
                    0
                }
                ExtractionEntryKind::File => {
                    let mut output = crate::atomic_file::AtomicOutputFile::create(decision.destination_path)
                        .map_err(|source| io_error(decision.destination_path, source))?;
                    output
                        .file_mut()
                        .map_err(|source| io_error(decision.destination_path, source))?
                        .set_len(entry.size.unwrap_or(0))
                        .map_err(|source| io_error(decision.destination_path, source))?;
                    output.commit_with_replace(decision.replace_existing).map_err(|source| io_error(decision.destination_path, source))?;
                    entry.size.unwrap_or(0)
                }
                ExtractionEntryKind::Symlink { target } => {
                    crate::extract_materialize::write_symlink(target, decision.destination_path)
                        .map_err(|source| io_error(decision.destination_path, source))?;
                    0
                }
                ExtractionEntryKind::Hardlink { .. } | ExtractionEntryKind::Device | ExtractionEntryKind::Special => {
                    return Err(invalid(path, format!("unsupported MTREE entry type for {}", entry.path)));
                }
            };
            report.entries = report.entries.saturating_add(1);
            report.bytes = report.bytes.saturating_add(written);
            Ok(written)
        })?;
    }

    Ok(report)
}

fn normalize_path(path: &Path) -> Result<String, MtreeError> {
    let current_dir = std::env::current_dir().map_err(|source| io_error(Path::new("<MTREE>"), source))?;
    let raw = path.strip_prefix(&current_dir).unwrap_or(path).to_string_lossy();
    crate::safety::normalize_archive_path(&raw).map_err(MtreeError::Safety)
}

fn read_manifest(path: &Path) -> Result<Vec<u8>, MtreeError> {
    let file = File::open(path).map_err(|source| io_error(path, source))?;
    let mut bytes = Vec::new();
    file.take(MAX_MTREE_BYTES.saturating_add(1)).read_to_end(&mut bytes).map_err(|source| io_error(path, source))?;
    if bytes.len() as u64 > MAX_MTREE_BYTES {
        return Err(invalid(path, format!("manifest exceeds {MAX_MTREE_BYTES} byte limit")));
    }
    if bytes.split(|byte| *byte == b'\n').map(<[u8]>::trim_ascii_start).any(|line| line.starts_with(b"/unset")) {
        return Err(invalid(path, "the selected MTREE parser does not support /unset directives"));
    }
    Ok(bytes)
}

fn map_kind(file_type: mtree::FileType) -> BrowserEntryKind {
    match file_type {
        mtree::FileType::Directory => BrowserEntryKind::Directory,
        mtree::FileType::SymbolicLink => BrowserEntryKind::Symlink,
        mtree::FileType::File => BrowserEntryKind::File,
        mtree::FileType::BlockDevice | mtree::FileType::CharacterDevice | mtree::FileType::Fifo | mtree::FileType::Socket => BrowserEntryKind::Special,
    }
}

fn invalid(path: &Path, error: impl fmt::Display) -> MtreeError {
    MtreeError::Invalid { path: path.to_path_buf(), message: error.to_string() }
}

fn io_error(path: &Path, source: io::Error) -> MtreeError {
    MtreeError::Io { path: path.to_path_buf(), source }
}
