use crate::jobs::JobContext;
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

crate::backend_error_from_impls!(PkgBackendError);

/// `.pkg` extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PkgExtractReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of entries skipped by policy.
    pub skipped_entries: usize,
    /// Number of file bytes extracted.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

impl crate::extract_loop::ExtractReport for PkgExtractReport {
    fn skipped_entries_mut(&mut self) -> &mut usize {
        &mut self.skipped_entries
    }

    fn warnings_mut(&mut self) -> &mut Vec<String> {
        &mut self.warnings
    }
}

/// `.pkg` backend error.
#[derive(Debug)]
pub enum PkgBackendError {
    /// Manifest planning failed.
    Plan(crate::manifest::PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Underlying XAR error.
    Xara(String),
    /// Underlying PBZX error.
    Pbzx(String),
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for PkgBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::Xara(message) => write!(f, "XAR backend error: {message}"),
            Self::Pbzx(message) => write!(f, "PBZX backend error: {message}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for PkgBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Xara(_) | Self::Pbzx(_) | Self::Cancelled => None,
        }
    }
}

/// Extracts a `.pkg` archive with an overwrite resolver.
pub fn extract_pkg_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<PkgExtractReport, PkgBackendError> {
    extract_pkg_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a `.pkg` archive with context.
pub fn extract_pkg_with_context(archive_path: impl AsRef<Path>, destination: impl AsRef<Path>, policy: ExtractionPolicy, context: &mut JobContext<'_>) -> Result<PkgExtractReport, PkgBackendError> {
    extract_pkg_inner(archive_path, destination, policy, Some(context), None)
}

#[allow(clippy::too_many_lines)]
fn extract_pkg_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    mut context: Option<&mut JobContext<'_>>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<PkgExtractReport, PkgBackendError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root = crate::safety::prepare_destination_root(destination).map_err(|source| PkgBackendError::Io { path: destination.to_path_buf(), source })?;

    let file = std::fs::File::open(archive_path).map_err(|source| PkgBackendError::Io { path: archive_path.to_path_buf(), source })?;
    let mut pkg = dpp::xara::PkgReader::open(file).map_err(|e| PkgBackendError::Xara(e.to_string()))?;

    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&destination_root, policy, overwrite_resolver);
    let mut report = PkgExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() };

    let components = pkg.components();
    for component in components {
        let Ok(payload_bytes) = pkg.payload(&component) else {
            continue; // Some components might not have a payload, just skip
        };

        let cursor = std::io::Cursor::new(payload_bytes);
        let pbzx_archive = dpp::pbzx::Archive::from_reader(cursor).map_err(|e| PkgBackendError::Pbzx(e.to_string()))?;
        let entries = pbzx_archive.entries().map_err(|e| PkgBackendError::Pbzx(e.to_string()))?;

        for cpio_entry in entries {
            if let Some(ctx) = context.as_deref_mut() {
                ctx.check_cancelled()?;
            }
            let archive_entry_path = cpio_entry.path.strip_prefix('/').unwrap_or(&cpio_entry.path).to_string();
            if archive_entry_path.is_empty() {
                continue;
            }

            let size = cpio_entry.size;

            let kind = if cpio_entry.is_dir {
                ExtractionEntryKind::Directory
            } else if cpio_entry.is_symlink {
                let target = PathBuf::from(String::from_utf8_lossy(cpio_entry.data.as_ref().unwrap_or(&Vec::new())).into_owned());
                ExtractionEntryKind::Symlink { target }
            } else {
                ExtractionEntryKind::File
            };

            let safety_entry = ExtractionEntry { archive_path: archive_entry_path, kind, uncompressed_size: Some(size), compressed_size: None };

            crate::extract_loop::process_extraction_entry(&mut report, context.as_deref_mut(), &mut planner, &safety_entry, &mut |action, report, mut context| match action {
                crate::extract_loop::EntryAction::Skip => Ok::<u64, PkgBackendError>(0),
                crate::extract_loop::EntryAction::Write(decision) => {
                    let replace_existing = decision.replace_existing;
                    let destination_path = decision.destination_path;

                    if replace_existing && !matches!(safety_entry.kind, ExtractionEntryKind::File) {
                        crate::safety::remove_destination_for_replace(destination_path).map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                    }

                    match &safety_entry.kind {
                        ExtractionEntryKind::Directory => {
                            std::fs::create_dir_all(destination_path).map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            Ok::<u64, PkgBackendError>(0)
                        }
                        ExtractionEntryKind::File => {
                            let mut output = crate::atomic_file::AtomicOutputFile::create(destination_path).map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            let file = output.file_mut().map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;

                            if let Some(data) = &cpio_entry.data {
                                file.write_all(data).map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            }

                            output.commit_with_replace(replace_existing).map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;

                            if let Some(ctx) = context.as_deref_mut() {
                                ctx.bytes_processed(Some(&safety_entry.archive_path), size);
                            }

                            report.written_entries += 1;
                            Ok(size)
                        }
                        ExtractionEntryKind::Symlink { target } => {
                            if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
                                crate::extract_loop::skip_entry(report, context, crate::safety::unsupported_symlink_warning(&safety_entry.archive_path));
                                return Ok(0);
                            }

                            #[cfg(unix)]
                            {
                                crate::extract_materialize::write_symlink(Path::new(target), destination_path)
                                    .map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            }
                            #[cfg(not(unix))]
                            {
                                let _ = target;
                            }
                            Ok::<u64, PkgBackendError>(0)
                        }
                        _ => Ok::<u64, PkgBackendError>(0),
                    }
                }
            })?;
        }
    }

    Ok(report)
}
