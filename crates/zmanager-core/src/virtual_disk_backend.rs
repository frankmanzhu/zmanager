//! Virtual disk image extraction backends (`.vhd`, `.vmdk`, `.udf`).
//!
//! `VHD` (Virtual PC/Hyper-V), `VMDK` (`VMware`), and `UDF` (optical) are block-device
//! formats: the files live inside an inner filesystem (NTFS, FAT/exFAT, ext4,
//! UDF), usually behind an MBR/GPT partition table. The `forensic-vfs-engine`
//! crate resolves the whole stack in one call — container → volume system →
//! filesystem — and exposes the result as a read-only `forensic_vfs::FileSystem`
//! (`Arc<dyn FileSystem>`), which this backend walks and streams out through the
//! standard extraction pipeline.
//!
//! All three formats share 100% of the pipeline; the public entry points only
//! differ by name so the CLI can route by detected kind.
//!
//! ## Non-disk-input guard
//!
//! The underlying VFS resolver also recognizes embedded archive containers, so
//! a plain zip renamed `foo.vhd` resolves as a browsable archive tree with
//! `fs: Some(...)`. [`mount_disk`] rejects those with
//! [`VirtualDiskBackendError::NotDiskImage`] (locator `Archive` layer check plus
//! a logical-container kind check).
//!
//! ## Known limitations
//!
//! - Only the default data stream is extracted (no NTFS ADS / resource forks).
//! - Symlinks are supported on NTFS (reparse-point buffers and the ntfs-3g
//!   `IntxLNK` form, patched in the ntfs-core fork) and UDF (`PATH_COMPONENT`
//!   decode, patched in the udf-forensic fork); FAT has no symlinks.
//! - NTFS system metadata files (`$MFT`, `$Bitmap`, …) are filtered from the
//!   volume root by exact name.
//! - Deleted/recovered entries (`Allocation::Deleted`/`Orphan`) are skipped with
//!   a warning when surfaced; the FAT adapter already hides them.
//! - Multi-volume disks resolve to the first *mountable* filesystem (the
//!   resolver skips unmountable slots such as MSR partitions); per-volume
//!   extraction into labeled directories is a future option via the engine's
//!   `open_all`.

use crate::engine::types::{TestOptions, TestReport};
use crate::jobs::JobContext;
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver};
use forensic_vfs::{Allocation, FsKind, Layer, NodeKind, StreamId};
use forensic_vfs_engine::{Evidence, Vfs};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

crate::backend_error_from_impls!(VirtualDiskBackendError);

/// Entry kind reported by the listing APIs.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VirtualDiskEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symlink.
    Symlink,
}

/// Entry reported by [`list_vhd`] / [`list_vmdk`] / [`list_udf`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VirtualDiskListEntry {
    /// Path inside the disk image (the mounted filesystem's tree).
    pub path: String,
    /// Entry kind.
    pub kind: VirtualDiskEntryKind,
    /// Declared uncompressed size.
    pub size: u64,
    /// Relative target for a symbolic-link entry.
    pub link_target: Option<String>,
}

/// Disk-image extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VirtualDiskExtractReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of entries skipped by policy.
    pub skipped_entries: usize,
    /// Number of file bytes extracted.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

impl crate::extract_loop::ExtractReport for VirtualDiskExtractReport {
    fn skipped_entries_mut(&mut self) -> &mut usize {
        &mut self.skipped_entries
    }

    fn warnings_mut(&mut self) -> &mut Vec<String> {
        &mut self.warnings
    }
}

/// Disk-image backend error.
#[derive(Debug)]
pub enum VirtualDiskBackendError {
    /// Manifest planning failed.
    Plan(crate::manifest::PlanError),
    /// Filesystem I/O failed (destination side).
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// The engine failed to decode the image (corrupt/truncated container,
    /// unrecognized filesystem). The message carries the engine's layer/offset
    /// context.
    Vfs(String),
    /// The file is not a supported disk image: no filesystem was found inside,
    /// or it resolved to a non-disk (archive) tree.
    NotDiskImage(String),
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for VirtualDiskBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::Vfs(message) => write!(f, "disk image backend error: {message}"),
            Self::NotDiskImage(message) => write!(f, "not a supported disk image: {message}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for VirtualDiskBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Vfs(_) | Self::NotDiskImage(_) | Self::Cancelled => None,
        }
    }
}

/// NTFS system metadata files surfaced by the ntfs-core vfs adapter at the
/// volume root. Filtered by exact name (never by `$` prefix — `$Recycle.Bin`
/// and `$WinREAgent` are legitimate user-visible directories).
const NTFS_METADATA_NAMES: &[&str] = &["$AttrDef", "$BadClus", "$Bitmap", "$Boot", "$Extend", "$LogFile", "$MFT", "$MFTMirr", "$Secure", "$UpCase", "$Volume"];

/// Reserved volume entries cannot exist as real paths (raw names containing
/// NUL bytes — the same rule the DMG backend applies to HFS+ Finder metadata).
fn is_reserved_volume_entry(path: &str) -> bool {
    path.contains('\0')
}

/// True when the path's first component is a known NTFS metadata file. Covers
/// both the root entries and everything under `$Extend/…`.
fn is_ntfs_metadata_path(path: &str) -> bool {
    path.split('/').next().is_some_and(|root| NTFS_METADATA_NAMES.contains(&root))
}

/// Logical-container kinds the VFS resolver can produce (zip/7z/tar/dar/aff4/ad1).
/// A file that resolves to one of these is an
/// archive tree, not a disk image.
fn is_logical_container_kind(kind: FsKind) -> bool {
    matches!(kind.as_str(), "zip" | "7z" | "tar" | "dar" | "aff4" | "ad1")
}

/// Opens `archive_path` through the engine and guards against non-disk inputs.
/// Returns the mounted read-only filesystem and its locator.
fn mount_disk(archive_path: &Path) -> Result<(forensic_vfs::DynFs, forensic_vfs::Locator), VirtualDiskBackendError> {
    let evidence: Evidence = Vfs::new().open(archive_path).map_err(|error| VirtualDiskBackendError::Vfs(error.to_string()))?;

    let Some(fs) = &evidence.fs else {
        return Err(VirtualDiskBackendError::NotDiskImage(format!("{}: no supported filesystem found in the image", archive_path.display())));
    };

    // An archive *wrapping* a nested image would mount the inner filesystem
    // through the packaging peel; that is a different extraction model.
    if evidence.root.layers().iter().any(|layer| matches!(layer, Layer::Archive { .. })) {
        return Err(VirtualDiskBackendError::NotDiskImage(format!("{}: resolved to an archive wrapper, not a disk image", archive_path.display())));
    }

    if is_logical_container_kind(fs.kind()) {
        return Err(VirtualDiskBackendError::NotDiskImage(format!("{}: resolved to a {} tree, not a disk image", archive_path.display(), fs.kind().as_str())));
    }

    Ok((std::sync::Arc::clone(fs), evidence.root))
}

/// Maps one walked engine entry to the safety layer's entry kind.
fn map_entry_kind(fs: &forensic_vfs::DynFs, id: forensic_vfs::FileId, kind: NodeKind) -> Result<ExtractionEntryKind, VirtualDiskBackendError> {
    match kind {
        NodeKind::File => Ok(ExtractionEntryKind::File),
        NodeKind::Dir => Ok(ExtractionEntryKind::Directory),
        NodeKind::Symlink => {
            let target_bytes = fs.read_link(id, 4096).map_err(|error| VirtualDiskBackendError::Vfs(format!("read_link: {error}")))?;
            Ok(ExtractionEntryKind::Symlink { target: PathBuf::from(String::from_utf8_lossy(&target_bytes).into_owned()) })
        }
        // Devices and unknown nodes fall to the safety planner's
        // `UnsafeFilePolicy` (default `Reject`). `NodeKind` is
        // `#[non_exhaustive]`, so future kinds stay safe by default.
        NodeKind::Device | NodeKind::Other | _ => Ok(ExtractionEntryKind::Device),
    }
}

/// Walks the mounted filesystem and maps every entry to the safety layer's
/// shape, applying the deleted/reserved/metadata filters. Entries filtered by
/// the reserved/metadata rules are dropped; `skip_warning` receives a warning
/// message for each filtered entry when extraction runs (listing drops them
/// silently, mirroring `list_dmg`). The engine's `FileId` is carried alongside
/// each entry so file bytes can be streamed without re-walking the tree.
fn collect_entries_with_path_map(
    fs: &forensic_vfs::DynFs,
    skip_warning: &mut Option<&mut dyn FnMut(String)>,
    path_map: Option<&HashMap<u32, String>>,
) -> Result<Vec<(ExtractionEntry, forensic_vfs::FileId)>, VirtualDiskBackendError> {
    let walked = forensic_vfs_engine::walk(fs.as_ref()).map_err(|error| VirtualDiskBackendError::Vfs(error.to_string()))?;

    let mut entries = Vec::with_capacity(walked.len());
    for entry in walked {
        let walked_path = entry.path.iter().map(|component| String::from_utf8_lossy(component).into_owned()).collect::<Vec<_>>().join("/");
        let path = match (path_map, entry.id) {
            (Some(map), forensic_vfs::FileId::IsoExtent { block }) => map.get(&block).cloned().unwrap_or(walked_path),
            _ => walked_path,
        };
        if path.is_empty() {
            continue;
        }
        if is_reserved_volume_entry(&path) {
            if let Some(warn) = skip_warning.as_deref_mut() {
                warn(format!("skipped {path}: reserved filesystem entry"));
            }
            continue;
        }
        if is_ntfs_metadata_path(&path) {
            if let Some(warn) = skip_warning.as_deref_mut() {
                warn(format!("skipped {path}: NTFS system metadata file"));
            }
            continue;
        }
        if matches!(entry.meta.allocated, Allocation::Deleted | Allocation::Orphan) {
            if let Some(warn) = skip_warning.as_deref_mut() {
                warn(format!("skipped {path}: recovered deleted entry"));
            }
            continue;
        }

        let kind = map_entry_kind(fs, entry.id, entry.meta.kind)?;
        entries.push((ExtractionEntry { archive_path: path, kind, uncompressed_size: Some(entry.meta.size), compressed_size: None }, entry.id));
    }
    Ok(entries)
}

fn iso_path_map(archive_path: &Path) -> Result<HashMap<u32, String>, VirtualDiskBackendError> {
    let file = std::fs::File::open(archive_path).map_err(|source| VirtualDiskBackendError::Io { path: archive_path.to_path_buf(), source })?;
    let mut reader = iso::IsoReader::open(file).map_err(|error| VirtualDiskBackendError::Vfs(format!("open ISO9660 reader: {error}")))?;
    let walked = reader.walk().map_err(|error| VirtualDiskBackendError::Vfs(format!("walk ISO9660 reader: {error}")))?;
    Ok(walked.into_iter().map(|entry| (entry.record.lba, entry.path)).collect())
}

fn path_map_for_filesystem(fs: &forensic_vfs::DynFs, archive_path: &Path) -> Result<Option<HashMap<u32, String>>, VirtualDiskBackendError> {
    if fs.kind().as_str() == "iso9660" { Ok(Some(iso_path_map(archive_path)?)) } else { Ok(None) }
}

/// Lists the entries of a `.vhd` archive without extracting them.
pub fn list_vhd(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of a `.vmdk` archive without extracting them.
pub fn list_vmdk(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of a `.udf` archive without extracting them.
pub fn list_udf(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of an ISO 9660 image without extracting them.
pub fn list_iso(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Verifies selected ISO 9660 file payloads through the forensic VFS reader.
pub fn test_iso(archive_path: impl AsRef<Path>, options: &TestOptions) -> Result<TestReport, VirtualDiskBackendError> {
    let archive_path = archive_path.as_ref();
    let (fs, _) = mount_disk(archive_path)?;
    let path_map = path_map_for_filesystem(&fs, archive_path)?;
    let mut no_warning = None;
    let entries = collect_entries_with_path_map(&fs, &mut no_warning, path_map.as_ref())?;
    let mut report = TestReport::default();
    for (entry, file_id) in entries {
        if options.is_cancelled() {
            return Err(VirtualDiskBackendError::Cancelled);
        }
        if !options.selects(&entry.archive_path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        if matches!(entry.kind, ExtractionEntryKind::File) {
            let mut sink = io::sink();
            let bytes = stream_file(&fs, file_id, &entry.archive_path, &mut sink)?;
            if Some(bytes) != entry.uncompressed_size {
                return Err(VirtualDiskBackendError::Vfs(format!(
                    "test {}: filesystem declares {} bytes but yielded {bytes}",
                    entry.archive_path,
                    entry.uncompressed_size.unwrap_or(0)
                )));
            }
            report.tested_bytes = report.tested_bytes.saturating_add(bytes);
        }
        report.tested_entries = report.tested_entries.saturating_add(1);
    }
    Ok(report)
}

/// Copies one retained ISO 9660 regular file to a caller-owned writer.
pub fn copy_iso(archive_path: impl AsRef<Path>, entry_index: usize, writer: &mut dyn io::Write) -> Result<u64, VirtualDiskBackendError> {
    let archive_path = archive_path.as_ref();
    let (fs, _) = mount_disk(archive_path)?;
    let path_map = path_map_for_filesystem(&fs, archive_path)?;
    let mut no_warning = None;
    let entries = collect_entries_with_path_map(&fs, &mut no_warning, path_map.as_ref())?;
    let (entry, file_id) = entries.get(entry_index).ok_or_else(|| VirtualDiskBackendError::Vfs("retained ISO entry ID is not present".to_owned()))?;
    if !matches!(entry.kind, ExtractionEntryKind::File) {
        return Err(VirtualDiskBackendError::Vfs("retained ISO entry is not a regular file".to_owned()));
    }
    stream_file(&fs, *file_id, &entry.archive_path, writer)
}

/// Copies one retained ISO file by path and duplicate occurrence.
pub fn copy_iso_by_path_occurrence(
    archive_path: impl AsRef<Path>,
    selected_path: &str,
    selected_occurrence: usize,
    writer: &mut dyn io::Write,
) -> Result<u64, VirtualDiskBackendError> {
    let archive_path = archive_path.as_ref();
    let mut occurrence = 0_usize;
    let entry_index = list_iso(archive_path)?
        .into_iter()
        .enumerate()
        .find_map(|entry| {
            let (entry_index, entry) = entry;
            if entry.path != selected_path {
                return None;
            }
            let matches = occurrence == selected_occurrence;
            occurrence = occurrence.saturating_add(1);
            matches.then_some(entry_index)
        })
        .ok_or_else(|| VirtualDiskBackendError::Io {
            path: archive_path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::NotFound, "retained ISO entry is not present"),
        })?;
    copy_iso(archive_path, entry_index, writer)
}

fn list_virtual_disk_inner(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    let archive_path = archive_path.as_ref();
    let (fs, _) = mount_disk(archive_path)?;
    let path_map = path_map_for_filesystem(&fs, archive_path)?;
    let mut no_warning = None;
    let entries = collect_entries_with_path_map(&fs, &mut no_warning, path_map.as_ref())?;
    Ok(entries
        .into_iter()
        .map(|(entry, _)| {
            let link_target = match &entry.kind {
                ExtractionEntryKind::Symlink { target } => Some(target.to_string_lossy().into_owned()),
                _ => None,
            };
            VirtualDiskListEntry {
                path: entry.archive_path,
                kind: match entry.kind {
                    ExtractionEntryKind::Directory => VirtualDiskEntryKind::Directory,
                    ExtractionEntryKind::Symlink { .. } => VirtualDiskEntryKind::Symlink,
                    _ => VirtualDiskEntryKind::File,
                },
                size: entry.uncompressed_size.unwrap_or(0),
                link_target,
            }
        })
        .collect())
}

/// Extracts a `.vhd` archive into `destination`.
pub fn extract_vhd_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a `.vmdk` archive into `destination`.
pub fn extract_vmdk_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a `.udf` archive into `destination`.
pub fn extract_udf_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts an ISO 9660 image into `destination` with caller-controlled overwrites.
pub fn extract_iso_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a virtual disk without job progress callbacks.
pub fn extract_virtual_disk(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, None)
}

/// Streaming writer that checks cancellation and reports bytes through the
/// job context on every write (mirrors the MSI backend's `ProgressWriter`).
struct ProgressWriter<'a, 'b, W: io::Write> {
    inner: W,
    context: Option<&'a mut JobContext<'b>>,
    archive_path: &'a str,
}

impl<W: io::Write> io::Write for ProgressWriter<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        if let Some(ctx) = self.context.as_deref_mut() {
            if ctx.check_cancelled().is_err() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "job cancelled"));
            }
            ctx.bytes_processed(Some(self.archive_path), written as u64);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn extract_virtual_disk_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    mut context: Option<&mut JobContext<'_>>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| VirtualDiskBackendError::Io { path: destination.to_path_buf(), source })?;

    let (fs, _) = mount_disk(archive_path)?;

    let mut warnings = Vec::new();
    let path_map = path_map_for_filesystem(&fs, archive_path)?;
    let mut warning_sink = |warning| warnings.push(warning);
    let mut warning_callback: Option<&mut dyn FnMut(String)> = Some(&mut warning_sink);
    let entries = collect_entries_with_path_map(&fs, &mut warning_callback, path_map.as_ref())?;

    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&destination_root, policy, overwrite_resolver);
    let mut report = VirtualDiskExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings };

    for (safety_entry, file_id) in entries {
        if let Some(ctx) = context.as_deref_mut() {
            ctx.check_cancelled()?;
        }

        crate::extract_loop::process_extraction_entry(&mut report, context.as_deref_mut(), &mut planner, &safety_entry, &mut |action, report, mut context| {
            match action {
                crate::extract_loop::EntryAction::Skip => Ok::<u64, VirtualDiskBackendError>(0),
                crate::extract_loop::EntryAction::Write(decision) => {
                    let replace_existing = decision.replace_existing;
                    let destination_path = decision.destination_path;

                    if replace_existing && !matches!(safety_entry.kind, ExtractionEntryKind::File) {
                        crate::safety::remove_destination_for_replace(destination_path)
                            .map_err(|source| VirtualDiskBackendError::Io { path: destination_path.to_path_buf(), source })?;
                    }

                    match &safety_entry.kind {
                        ExtractionEntryKind::Directory => {
                            std::fs::create_dir_all(destination_path)
                                .map_err(|source| VirtualDiskBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            Ok::<u64, VirtualDiskBackendError>(0)
                        }
                        ExtractionEntryKind::File => {
                            let mut output = crate::atomic_file::AtomicOutputFile::create(destination_path)
                                .map_err(|source| VirtualDiskBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            let file = output.file_mut().map_err(|source| VirtualDiskBackendError::Io { path: destination_path.to_path_buf(), source })?;

                            // The engine exposes byte-range reads, not a stream;
                            // loop in fixed-size chunks through the progress
                            // writer when a context is present.
                            let expected = safety_entry.uncompressed_size.unwrap_or(0);
                            let written_bytes = if context.is_some() {
                                let mut writer = ProgressWriter { inner: file, context: context.as_deref_mut(), archive_path: &safety_entry.archive_path };
                                stream_file(&fs, file_id, &safety_entry.archive_path, &mut writer)?
                            } else {
                                let mut file = file;
                                stream_file(&fs, file_id, &safety_entry.archive_path, &mut file)?
                            };

                            output
                                .commit_with_replace(replace_existing)
                                .map_err(|source| VirtualDiskBackendError::Io { path: destination_path.to_path_buf(), source })?;

                            report.written_entries += 1;
                            report.written_bytes += written_bytes;
                            if written_bytes != expected {
                                // The filesystem's declared size was a lie; the
                                // file is materialized as-is, so warn.
                                report
                                    .warnings
                                    .push(format!("{}: extracted {} bytes, filesystem declares {}", safety_entry.archive_path, written_bytes, expected));
                            }
                            Ok(written_bytes)
                        }
                        ExtractionEntryKind::Symlink { target } => {
                            // The engine exposes symlink targets through
                            // read_link; skip rather than materialize a broken
                            // empty symlink if a target is still missing.
                            if target.as_os_str().is_empty() {
                                crate::extract_loop::skip_entry(
                                    report,
                                    context,
                                    format!("symlink {} skipped: disk image does not expose the symlink target", safety_entry.archive_path),
                                );
                                return Ok(0);
                            }
                            if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
                                crate::extract_loop::skip_entry(report, context, crate::safety::unsupported_symlink_warning(&safety_entry.archive_path));
                                return Ok(0);
                            }

                            #[cfg(unix)]
                            {
                                crate::extract_materialize::write_symlink(Path::new(target), destination_path)
                                    .map_err(|source| VirtualDiskBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            }
                            #[cfg(not(unix))]
                            {
                                let _ = target;
                            }
                            report.written_entries += 1;
                            Ok::<u64, VirtualDiskBackendError>(0)
                        }
                        _ => Ok::<u64, VirtualDiskBackendError>(0),
                    }
                }
            }
        })?;
    }

    Ok(report)
}

/// Streams one file's bytes from the engine into `writer` via chunked
/// `read_at` calls on the walked `FileId`.
fn stream_file<W: io::Write + ?Sized>(
    fs: &forensic_vfs::DynFs,
    file_id: forensic_vfs::FileId,
    archive_path: &str,
    writer: &mut W,
) -> Result<u64, VirtualDiskBackendError> {
    let mut written: u64 = 0;
    let mut buf = vec![0u8; crate::DEFAULT_IO_BUFFER_BYTES];
    let mut offset: u64 = 0;
    loop {
        let n =
            fs.read_at(file_id, StreamId::Default, offset, &mut buf).map_err(|error| VirtualDiskBackendError::Vfs(format!("read {archive_path}: {error}")))?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).map_err(|source| VirtualDiskBackendError::Io { path: PathBuf::from(archive_path), source })?;
        written += n as u64;
        offset += n as u64;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::{
        VirtualDiskBackendError, VirtualDiskEntryKind, extract_udf_with_overwrite_resolver, extract_vhd_with_overwrite_resolver,
        extract_vmdk_with_overwrite_resolver, is_logical_container_kind, is_ntfs_metadata_path, is_reserved_volume_entry, list_udf, list_vhd, list_vmdk,
    };
    use crate::safety::{ExtractionPolicy, OverwriteConflict, OverwriteDecision, OverwritePolicy, OverwriteResolver};
    use crate::test_support::TestDir;
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    struct AlwaysReplace;
    impl OverwriteResolver for AlwaysReplace {
        fn decide(&mut self, _conflict: &OverwriteConflict) -> OverwriteDecision {
            OverwriteDecision::Replace
        }
    }

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name)
    }

    fn disk_format_of(name: &str) -> DiskFixtureFormat {
        match Path::new(name).extension().and_then(|ext| ext.to_str()).map(str::to_ascii_lowercase).as_deref() {
            Some("vhd") => DiskFixtureFormat::Vhd,
            Some("vmdk") => DiskFixtureFormat::Vmdk,
            _ => DiskFixtureFormat::Udf,
        }
    }

    fn extract_all(archive: &Path, name: &str, out: &Path) -> crate::virtual_disk_backend::VirtualDiskExtractReport {
        let policy = ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() };
        let result = match disk_format_of(name) {
            DiskFixtureFormat::Vhd => extract_vhd_with_overwrite_resolver(archive, out, policy, &mut AlwaysReplace),
            DiskFixtureFormat::Vmdk => extract_vmdk_with_overwrite_resolver(archive, out, policy, &mut AlwaysReplace),
            DiskFixtureFormat::Udf => extract_udf_with_overwrite_resolver(archive, out, policy, &mut AlwaysReplace),
        };
        result.unwrap_or_else(|error| panic!("extract {archive:?} failed: {error}"))
    }

    fn list_all(archive: &Path, name: &str) -> Result<Vec<crate::virtual_disk_backend::VirtualDiskListEntry>, VirtualDiskBackendError> {
        match disk_format_of(name) {
            DiskFixtureFormat::Vhd => list_vhd(archive),
            DiskFixtureFormat::Vmdk => list_vmdk(archive),
            DiskFixtureFormat::Udf => list_udf(archive),
        }
    }

    #[derive(Clone, Copy)]
    enum DiskFixtureFormat {
        Vhd,
        Vmdk,
        Udf,
    }

    #[test]
    fn checked_in_vhd_vmdk_udf_fixtures_list_with_normalized_paths() {
        for name in ["basic.vhd", "basic.vmdk", "basic.udf"] {
            let archive = fixture(name);
            assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");
            let listing = list_all(&archive, name).unwrap_or_else(|error| panic!("list {name} failed: {error}"));
            let paths = listing.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>();
            assert!(paths.contains(&"payload/README.txt"), "{name}: {paths:?}");
            assert!(paths.contains(&"payload/nested/file.txt"), "{name}: {paths:?}");
            assert!(paths.contains(&"payload/dir with spaces/file with spaces.txt"), "{name}: {paths:?}");
            assert!(paths.contains(&"payload/unicode/こんにちは.txt"), "{name}: {paths:?}");
            assert!(paths.contains(&"payload/nested/empty-dir"), "{name}: {paths:?}");
            assert!(listing.iter().all(|entry| !entry.path.starts_with('/') && !entry.path.starts_with("./")), "{name} paths must be normalized: {paths:?}");
            assert!(
                listing.iter().all(|entry| entry.size > 0 || entry.kind == VirtualDiskEntryKind::Directory),
                "{name}: non-directory entries must declare sizes"
            );
            // NTFS system metadata must never surface (the vhd fixture is MBR+NTFS).
            assert!(!listing.iter().any(|entry| entry.path.starts_with('$')), "{name}: NTFS metadata leaked: {paths:?}");
        }
    }

    #[test]
    fn checked_in_vhd_vmdk_udf_fixtures_extract_with_byte_accurate_report() {
        for name in ["basic.vhd", "basic.vmdk", "basic.udf"] {
            let archive = fixture(name);
            assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");
            let listing = list_all(&archive, name).unwrap();
            let temp = TestDir::new(&format!("virtual-disk-{name}"));
            let out = temp.path("out");
            let report = extract_all(&archive, name, &out);

            // The NTFS/UDF fixtures carry one symlink: materialized on unix,
            // skipped with a warning elsewhere (the FAT vmdk has none). The
            // NTFS-metadata filter warns but does not count toward
            // skipped_entries.
            let skipped_symlink = usize::from(!cfg!(unix) && name != "basic.vmdk");
            assert_eq!(report.skipped_entries, skipped_symlink, "{name}: warnings: {:?}", report.warnings);
            assert_eq!(
                report.written_entries,
                listing.iter().filter(|entry| entry.kind != VirtualDiskEntryKind::Directory).count() - skipped_symlink,
                "{name}"
            );
            let declared_file_bytes: u64 = listing.iter().filter(|entry| entry.kind == VirtualDiskEntryKind::File).map(|entry| entry.size).sum();
            assert_eq!(report.written_bytes, declared_file_bytes, "{name}: written bytes must sum the declared sizes of all listed files");

            assert_eq!(fs::read_to_string(out.join("payload/README.txt")).unwrap(), "ZManager fixture payload\n", "{name}");
            assert_eq!(fs::read_to_string(out.join("payload/nested/file.txt")).unwrap(), "nested fixture file\n", "{name}");
            assert_eq!(fs::read_to_string(out.join("payload/dir with spaces/file with spaces.txt")).unwrap(), "spaces in path\n", "{name}");
            assert_eq!(fs::read_to_string(out.join("payload/unicode/こんにちは.txt")).unwrap(), "unicode path fixture\n", "{name}");
            assert!(out.join("payload/nested/empty-dir").is_dir(), "{name}");
            // The NTFS and UDF fixtures carry the symlink (patched adapters
            // decode reparse/IntxLNK and PATH_COMPONENT targets); FAT strips it.
            if matches!(name, "basic.vhd" | "basic.udf") {
                #[cfg(unix)]
                {
                    assert_eq!(fs::read_link(out.join("payload/nested/readme-link.txt")).unwrap(), PathBuf::from("../README.txt"), "{name}");
                }
            } else {
                assert!(!out.join("payload/nested/readme-link.txt").exists(), "{name}");
            }
        }
    }

    #[test]
    fn empty_file_is_rejected_as_not_a_disk_image() {
        let temp = TestDir::new("virtual-disk-empty");
        fs::write(temp.path("empty.vhd"), b"").unwrap();
        let error = list_vhd(temp.path("empty.vhd")).unwrap_err();
        assert!(matches!(error, VirtualDiskBackendError::NotDiskImage(_)), "{error}");
    }

    #[test]
    fn garbage_bytes_are_rejected_as_not_a_disk_image() {
        let temp = TestDir::new("virtual-disk-garbage");
        fs::write(temp.path("garbage.vmdk"), b"this is not a disk image at all, just some junk bytes").unwrap();
        let error = list_vhd(temp.path("garbage.vmdk")).unwrap_err();
        assert!(matches!(error, VirtualDiskBackendError::NotDiskImage(_)), "{error}");
    }

    #[test]
    fn truncated_vhd_errors() {
        let archive = fixture("basic.vhd");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");
        let bytes = fs::read(&archive).unwrap();
        let temp = TestDir::new("virtual-disk-truncated");
        fs::write(temp.path("truncated.vhd"), &bytes[..bytes.len() / 2]).unwrap();
        assert!(list_vhd(temp.path("truncated.vhd")).is_err());
    }

    #[test]
    fn vhd_with_corrupt_footer_errors() {
        let archive = fixture("basic.vhd");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");
        let mut bytes = fs::read(&archive).unwrap();
        // The VHD footer (last 512 bytes) carries the "conectix" cookie at its start.
        let footer_start = bytes.len() - 512;
        bytes[footer_start..footer_start + 8].copy_from_slice(b"XXXXXXIX");
        let temp = TestDir::new("virtual-disk-corrupt-footer");
        fs::write(temp.path("corrupt.vhd"), &bytes).unwrap();
        assert!(list_vhd(temp.path("corrupt.vhd")).is_err());
    }

    #[test]
    fn zeroed_ntfs_boot_sector_inside_vhd_errors() {
        let archive = fixture("basic.vhd");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");
        let bytes = fs::read(&archive).unwrap();
        // The NTFS boot sector OEM id is the 8 bytes "NTFS    " (4 + 4 spaces).
        let oem = b"NTFS    ";
        let offset = bytes.windows(oem.len()).position(|window| window == oem).expect("NTFS boot sector must be present in the fixture");
        let mut patched = bytes;
        patched[offset..offset + oem.len()].fill(0);
        let temp = TestDir::new("virtual-disk-zeroed-boot");
        fs::write(temp.path("boot.vhd"), &patched).unwrap();
        assert!(list_vhd(temp.path("boot.vhd")).is_err());
    }

    #[test]
    fn zip_named_vhd_is_rejected_by_the_disk_guard() {
        let temp = TestDir::new("virtual-disk-zip-guard");
        let zip_path = temp.path("fake.vhd");
        let file = fs::File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        writer.start_file("payload/README.txt", zip::write::SimpleFileOptions::default()).unwrap();
        writer.write_all(b"ZManager fixture payload\n").unwrap();
        writer.finish().unwrap();

        let error = list_vhd(&zip_path).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("not a disk image"), "{message}");
    }

    #[test]
    fn reserved_metadata_and_logical_filters_are_pure_functions() {
        assert!(is_reserved_volume_entry("payload/\0secret"));
        assert!(!is_reserved_volume_entry("payload/README.txt"));
        assert!(is_ntfs_metadata_path("$MFT"));
        assert!(is_ntfs_metadata_path("$Extend/$ObjId"));
        assert!(!is_ntfs_metadata_path("$Recycle.Bin"));
        assert!(!is_ntfs_metadata_path("payload/README.txt"));
        for (name, expected) in [
            ("zip", true),
            ("7z", true),
            ("tar", true),
            ("dar", true),
            ("aff4", true),
            ("ad1", true),
            ("ntfs", false),
            ("fat", false),
            ("udf", false),
            ("ext", false),
        ] {
            assert_eq!(is_logical_container_kind(forensic_vfs::FsKind::from_name(name)), expected, "{name}");
        }
    }
}
