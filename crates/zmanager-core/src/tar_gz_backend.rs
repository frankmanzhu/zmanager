//! Native `.tar.gz` / `.tgz` archive creation and extraction.

use crate::extract_materialize::DeferredHardlink;
use crate::jobs::{JobCancelled, JobContext};
use crate::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PlanError, PlanOptions, plan_archive};
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use tar::{Builder, EntryType, Header};

/// Options for `.tar.gz` / `.tgz` creation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarGzCreateOptions {
    /// Gzip compression level (0-9).
    pub level: i32,
    /// Preserve portable metadata such as mode bits and modification time.
    pub preserve_metadata: bool,
    /// Replace an existing destination archive at commit time.
    pub replace_existing: bool,
}

impl Default for TarGzCreateOptions {
    fn default() -> Self {
        Self { level: 6, preserve_metadata: true, replace_existing: false }
    }
}

/// Creation report returned by the `.tar.gz` / `.tgz` writer.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarGzCreateReport {
    /// Entries written to the archive.
    pub written_entries: usize,
    /// Sum of uncompressed file bytes written.
    pub written_bytes: u64,
    /// Compression level used.
    pub level: i32,
    /// Non-fatal creation warnings.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarGzExtractReport {
    pub written_entries: usize,
    pub skipped_entries: usize,
    pub written_bytes: u64,
    pub warnings: Vec<String>,
}

/// Error returned by the `.tar.gz` / `.tgz` creator.
#[derive(Debug)]
pub enum TarGzError {
    /// Archive planning failed.
    Plan(PlanError),
    /// Gzip compression level is outside the supported 0-9 range.
    InvalidLevel {
        level: i32,
    },
    /// Filesystem or stream I/O failed.
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Safety(ExtractionSafetyError),
    MissingLinkTarget {
        archive_path: String,
    },
    /// The job was cancelled.
    Cancelled,
}

impl fmt::Display for TarGzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(err) => write!(f, "planning failed: {err}"),
            Self::InvalidLevel { level } => write!(f, "invalid gzip compression level {level}: expected 0-9"),
            Self::Io { path, source } => {
                write!(f, "I/O failed for {}: {source}", path.display())
            }
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::MissingLinkTarget { archive_path } => write!(f, "tar link entry has no target: {archive_path}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for TarGzError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(err) => Some(err),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Cancelled | Self::InvalidLevel { .. } | Self::MissingLinkTarget { .. } => None,
        }
    }
}

impl From<PlanError> for TarGzError {
    fn from(value: PlanError) -> Self {
        Self::Plan(value)
    }
}

impl From<JobCancelled> for TarGzError {
    fn from(_value: JobCancelled) -> Self {
        Self::Cancelled
    }
}

impl From<ExtractionSafetyError> for TarGzError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Creates a `.tar.gz` / `.tgz` archive from a source path.
///
/// # Errors
///
/// Returns [`TarGzError`] when planning fails, files cannot be read, or writing fails.
pub fn create_tar_gz_from_path(source: impl AsRef<Path>, destination: impl AsRef<Path>, options: &TarGzCreateOptions) -> Result<TarGzCreateReport, TarGzError> {
    let manifest = plan_archive(source, &PlanOptions::default())?;
    create_tar_gz_from_manifest(&manifest, destination, options)
}

/// Creates a `.tar.gz` / `.tgz` archive from a manifest.
///
/// # Errors
///
/// Returns [`TarGzError`] when source files cannot be read, tar writing fails,
/// or gzip compression fails.
pub fn create_tar_gz_from_manifest(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TarGzCreateOptions,
) -> Result<TarGzCreateReport, TarGzError> {
    create_tar_gz_from_manifest_inner(manifest, destination, options, None)
}

/// Creates a `.tar.gz` / `.tgz` archive from a manifest while emitting job events.
///
/// # Errors
///
/// Returns [`TarGzError`] when source files cannot be read, tar writing fails,
/// gzip compression fails, or cancellation is requested.
pub fn create_tar_gz_from_manifest_with_context(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TarGzCreateOptions,
    context: &mut JobContext<'_>,
) -> Result<TarGzCreateReport, TarGzError> {
    create_tar_gz_from_manifest_inner(manifest, destination, options, Some(context))
}

fn create_tar_gz_from_manifest_inner(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TarGzCreateOptions,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<TarGzCreateReport, TarGzError> {
    let destination = destination.as_ref();
    // flate2's level is a u32 with an internal 0-9 contract; a negative i32
    // bit-cast would silently produce a huge level, so reject out-of-range
    // values up front (the CLI validates at parse time too).
    if !(0..=9).contains(&options.level) {
        return Err(TarGzError::InvalidLevel { level: options.level });
    }
    let mut output = crate::atomic_file::AtomicOutputFile::create(destination).map_err(|source| TarGzError::Io { path: destination.to_path_buf(), source })?;
    let file = output.file_mut().map_err(|source| TarGzError::Io { path: destination.to_path_buf(), source })?;

    let encoder = GzEncoder::new(file, Compression::new(options.level.cast_unsigned()));
    let mut builder = Builder::new(encoder);
    builder.follow_symlinks(false);
    let mut report = TarGzCreateReport { written_entries: 0, written_bytes: 0, level: options.level, warnings: Vec::new() };

    for entry in &manifest.entries {
        append_manifest_entry(&mut builder, entry, options.preserve_metadata, &mut report, context.as_deref_mut())?;
    }

    let encoder = builder.into_inner().map_err(|source| TarGzError::Io { path: destination.to_path_buf(), source })?;
    encoder.finish().map_err(|source| TarGzError::Io { path: destination.to_path_buf(), source })?;
    output.commit_with_file_replace(options.replace_existing).map_err(|source| TarGzError::Io { path: destination.to_path_buf(), source })?;

    Ok(report)
}

/// Extracts a `.tar.gz` archive through the native Rust `flate2` and `tar`
/// readers and the shared extraction safety policy.
pub fn extract_tar_gz(archive_path: impl AsRef<Path>, destination: impl AsRef<Path>, policy: ExtractionPolicy) -> Result<TarGzExtractReport, TarGzError> {
    extract_tar_gz_inner(archive_path, destination, policy, None, None)
}

pub fn extract_tar_gz_with_context(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    context: &mut JobContext<'_>,
) -> Result<TarGzExtractReport, TarGzError> {
    extract_tar_gz_inner(archive_path, destination, policy, Some(context), None)
}

pub fn extract_tar_gz_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: &mut dyn OverwriteResolver,
) -> Result<TarGzExtractReport, TarGzError> {
    extract_tar_gz_inner(archive_path, destination, policy, None, Some(resolver))
}

#[allow(clippy::too_many_lines)]
fn extract_tar_gz_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    mut context: Option<&mut JobContext<'_>>,
    resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<TarGzExtractReport, TarGzError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let root = crate::safety::prepare_destination_root(destination).map_err(|source| TarGzError::Io { path: destination.to_path_buf(), source })?;
    let file = File::open(archive_path).map_err(|source| TarGzError::Io { path: archive_path.to_path_buf(), source })?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&root, policy, resolver);
    let mut report = TarGzExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() };
    let mut buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];
    let mut deferred_directories = Vec::new();
    let mut deferred_hardlinks = Vec::new();
    for item in archive.entries().map_err(|source| TarGzError::Io { path: archive_path.to_path_buf(), source })? {
        let mut entry = item.map_err(|source| TarGzError::Io { path: archive_path.to_path_buf(), source })?;
        let name = entry.path().map_err(|source| TarGzError::Io { path: archive_path.to_path_buf(), source })?.to_string_lossy().into_owned();
        let kind = tar_gz_entry_kind(&mut entry, &name)?;
        let size = entry.header().size().unwrap_or(0);
        let safety_entry = ExtractionEntry { archive_path: name.clone(), kind, uncompressed_size: Some(size), compressed_size: None };
        crate::extract_loop::process_extraction_entry(&mut report, context.as_deref_mut(), &mut planner, &safety_entry, &mut |action, report, context| {
            match action {
                crate::extract_loop::EntryAction::Skip => Ok::<u64, TarGzError>(0),
                crate::extract_loop::EntryAction::Write(decision) => {
                    if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
                        crate::extract_loop::skip_entry(report, context, crate::safety::unsupported_symlink_warning(&safety_entry.archive_path));
                        return Ok(0);
                    }
                    let metadata = tar_gz_entry_metadata(&mut entry, &safety_entry.archive_path)?;
                    if decision.replace_existing && !matches!(safety_entry.kind, ExtractionEntryKind::File) {
                        crate::safety::remove_destination_for_replace(decision.destination_path)
                            .map_err(|source| TarGzError::Io { path: decision.destination_path.to_path_buf(), source })?;
                    }
                    match &safety_entry.kind {
                        ExtractionEntryKind::Directory => {
                            fs::create_dir_all(decision.destination_path)
                                .map_err(|source| TarGzError::Io { path: decision.destination_path.to_path_buf(), source })?;
                            deferred_directories.push((decision.destination_path.to_path_buf(), metadata));
                            report.written_entries += 1;
                            Ok(0)
                        }
                        ExtractionEntryKind::File => {
                            let copied = crate::extract_loop::copy_file_entry(
                                decision.destination_path,
                                decision.replace_existing,
                                Some(&safety_entry.archive_path),
                                context,
                                &mut buffer,
                                |buf| entry.read(buf).map_err(|source| TarGzError::Io { path: decision.destination_path.to_path_buf(), source }),
                                |source, path| TarGzError::Io { path: path.to_path_buf(), source },
                            )?;
                            apply_tar_gz_metadata(decision.destination_path, metadata)?;
                            report.written_entries += 1;
                            report.written_bytes += copied;
                            Ok(copied)
                        }
                        ExtractionEntryKind::Symlink { target } => {
                            crate::extract_materialize::write_symlink(target, decision.destination_path)
                                .map_err(|source| TarGzError::Io { path: decision.destination_path.to_path_buf(), source })?;
                            apply_tar_gz_symlink_mtime(decision.destination_path, metadata.mtime)?;
                            report.written_entries += 1;
                            Ok(0)
                        }
                        ExtractionEntryKind::Hardlink { .. } => {
                            let source =
                                decision.link_target_path.ok_or_else(|| TarGzError::MissingLinkTarget { archive_path: safety_entry.archive_path.clone() })?;
                            deferred_hardlinks
                                .push(DeferredHardlink { source_path: source.to_path_buf(), destination_path: decision.destination_path.to_path_buf() });
                            Ok(0)
                        }
                        ExtractionEntryKind::Device | ExtractionEntryKind::Special => Err(TarGzError::Io {
                            path: decision.destination_path.to_path_buf(),
                            source: io::Error::new(io::ErrorKind::Unsupported, "special tar entry reached materialization after safety planning"),
                        }),
                    }
                }
            }
        })?;
    }
    crate::extract_materialize::materialize_deferred_hardlinks(&deferred_hardlinks)
        .map_err(|source| TarGzError::Io { path: deferred_hardlinks.first().map_or_else(PathBuf::new, |link| link.destination_path.clone()), source })?;
    for (path, metadata) in deferred_directories {
        apply_tar_gz_metadata(&path, metadata)?;
    }
    report.written_entries += deferred_hardlinks.len();
    Ok(report)
}

#[derive(Debug, Clone, Copy)]
struct TarGzEntryMetadata {
    mode: Option<u32>,
    mtime: Option<crate::tar_metadata::TarTimestamp>,
}

fn tar_gz_entry_metadata<R: Read>(entry: &mut tar::Entry<'_, R>, archive_path: &str) -> Result<TarGzEntryMetadata, TarGzError> {
    let mut metadata = TarGzEntryMetadata {
        mode: entry.header().mode().ok(),
        mtime: entry
            .header()
            .mtime()
            .ok()
            .and_then(|seconds| i64::try_from(seconds).ok())
            .map(|seconds| crate::tar_metadata::TarTimestamp { seconds, nanoseconds: 0 }),
    };
    if let Some(extensions) = entry.pax_extensions().map_err(|source| TarGzError::Io { path: PathBuf::from(archive_path), source })? {
        for extension in extensions {
            let extension = extension.map_err(|source| TarGzError::Io { path: PathBuf::from(archive_path), source })?;
            if extension.key_bytes() == b"mtime" {
                metadata.mtime = Some(crate::tar_metadata::parse_pax_mtime(extension.value_bytes()).ok_or_else(|| TarGzError::Io {
                    path: PathBuf::from(archive_path),
                    source: io::Error::new(io::ErrorKind::InvalidData, "invalid PAX modification time"),
                })?);
            }
        }
    }
    Ok(metadata)
}

fn apply_tar_gz_metadata(path: &Path, metadata: TarGzEntryMetadata) -> Result<(), TarGzError> {
    crate::extract_materialize::apply_metadata(
        path,
        metadata.mode,
        metadata.mtime.map(|mtime| filetime::FileTime::from_unix_time(mtime.seconds, mtime.nanoseconds)),
    )
    .map_err(|source| TarGzError::Io { path: path.to_path_buf(), source })
}

fn apply_tar_gz_symlink_mtime(path: &Path, mtime: Option<crate::tar_metadata::TarTimestamp>) -> Result<(), TarGzError> {
    crate::extract_materialize::apply_symlink_mtime(path, mtime.map(|mtime| filetime::FileTime::from_unix_time(mtime.seconds, mtime.nanoseconds)))
        .map_err(|source| TarGzError::Io { path: path.to_path_buf(), source })
}

fn tar_gz_entry_kind<R: Read>(entry: &mut tar::Entry<'_, R>, name: &str) -> Result<ExtractionEntryKind, TarGzError> {
    let entry_type = entry.header().entry_type();
    if entry_type.is_dir() {
        return Ok(ExtractionEntryKind::Directory);
    }
    if entry_type.is_symlink() {
        let target = entry
            .link_name()
            .map_err(|source| TarGzError::Io { path: PathBuf::from(name), source })?
            .ok_or_else(|| TarGzError::MissingLinkTarget { archive_path: name.to_owned() })?;
        return Ok(ExtractionEntryKind::Symlink { target: target.into_owned() });
    }
    if entry_type.is_hard_link() {
        let target = entry
            .link_name()
            .map_err(|source| TarGzError::Io { path: PathBuf::from(name), source })?
            .ok_or_else(|| TarGzError::MissingLinkTarget { archive_path: name.to_owned() })?;
        return Ok(ExtractionEntryKind::Hardlink { target: target.into_owned() });
    }
    if entry_type.is_file() { Ok(ExtractionEntryKind::File) } else { Ok(ExtractionEntryKind::Special) }
}

fn append_manifest_entry<W: io::Write>(
    builder: &mut Builder<W>,
    entry: &ManifestEntry,
    preserve_metadata: bool,
    report: &mut TarGzCreateReport,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<(), TarGzError> {
    if let Some(context) = context.as_deref_mut() {
        context.check_cancelled()?;
        context.entry_started(&entry.archive_path, Some(entry.size));
        context.check_cancelled()?;
    }

    append_manifest_mtime(builder, entry, preserve_metadata)?;

    let processed = match entry.file_type {
        ManifestFileType::Directory => {
            if preserve_metadata {
                builder.append_dir(&entry.archive_path, &entry.source_path).map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })?;
            } else {
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o755);
                header.set_mtime(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, &entry.archive_path, io::empty())
                    .map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })?;
            }
            report.written_entries += 1;
            0
        }
        ManifestFileType::File => {
            if preserve_metadata {
                builder
                    .append_path_with_name(&entry.source_path, &entry.archive_path)
                    .map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })?;
            } else {
                let mut source = File::open(&entry.source_path).map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })?;
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Regular);
                header.set_size(entry.size);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, &entry.archive_path, &mut source)
                    .map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })?;
            }
            report.written_entries += 1;
            report.written_bytes += entry.size;
            if let Some(context) = context.as_deref_mut() {
                context.bytes_processed(Some(&entry.archive_path), entry.size);
            }
            entry.size
        }
        ManifestFileType::Symlink => {
            let Some(target) = &entry.symlink_target else {
                let warning = format!("skipped symlink {}: missing target", entry.archive_path);
                report.warnings.push(warning.clone());
                if let Some(context) = context.as_deref_mut() {
                    context.warning(warning);
                    context.entry_finished(&entry.archive_path, 0);
                }
                return Ok(());
            };
            append_symlink(builder, entry, target, preserve_metadata)?;
            report.written_entries += 1;
            0
        }
        ManifestFileType::Other => {
            let warning = format!("skipped special file {}: tar.gz backend only writes files, directories, and symlinks", entry.archive_path);
            report.warnings.push(warning.clone());
            if let Some(context) = context.as_deref_mut() {
                context.warning(warning);
            }
            0
        }
    };

    if let Some(context) = context {
        context.entry_finished(&entry.archive_path, processed);
    }

    Ok(())
}

fn append_manifest_mtime<W: io::Write>(builder: &mut Builder<W>, entry: &ManifestEntry, preserve_metadata: bool) -> Result<(), TarGzError> {
    if !preserve_metadata || entry.file_type == ManifestFileType::Other {
        return Ok(());
    }
    crate::tar_metadata::append_pax_mtime(builder, entry.modified).map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })
}

fn append_symlink<W: io::Write>(builder: &mut Builder<W>, entry: &ManifestEntry, target: &Path, preserve_metadata: bool) -> Result<(), TarGzError> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Symlink);
    header.set_size(0);
    if preserve_metadata && let Some(mode) = entry.permissions.unix_mode {
        header.set_mode(mode & 0o7777);
    }
    if preserve_metadata && let Some(modified) = entry.modified.and_then(crate::tar_metadata::system_time_to_unix_seconds) {
        header.set_mtime(modified);
    }
    if !preserve_metadata {
        header.set_mode(0o777);
        header.set_mtime(0);
    }
    builder.append_link(&mut header, &entry.archive_path, target).map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })
}

#[cfg(test)]
mod tests {
    use super::{TarGzCreateOptions, create_tar_gz_from_path, extract_tar_gz};
    use crate::safety::ExtractionPolicy;
    use crate::test_support::TestDir;
    use std::fs::{self, File};
    use std::time::SystemTime;

    #[test]
    fn creates_and_extracts_tar_gz() {
        let temp = TestDir::new("creates_and_extracts_tar_gz");
        temp.write_file("project/src/main.rs", b"fn main() {}\n");
        temp.create_dir("project/empty");
        temp.write_file("project/hello cafe.txt", b"unicode");
        let archive = temp.path("archive.tar.gz");

        let create_report = create_tar_gz_from_path(temp.path("project"), &archive, &TarGzCreateOptions::default()).unwrap();

        let extract_report = extract_tar_gz(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        assert_eq!(create_report.level, 6);
        assert_eq!(create_report.written_entries, 5);
        assert_eq!(extract_report.written_entries, 5);
        assert_eq!(fs::read_to_string(temp.path("out/project/src/main.rs")).unwrap(), "fn main() {}\n");
    }

    #[test]
    fn respects_preserve_metadata_true() {
        let temp = TestDir::new("respects_preserve_metadata_true");
        let file_path = temp.path("project/file.txt");
        temp.write_file("project/file.txt", b"content");

        // Set a specific mod time
        let mtime = SystemTime::UNIX_EPOCH + std::time::Duration::new(12_345_678, 345_678_901);
        filetime::set_file_mtime(&file_path, filetime::FileTime::from_system_time(mtime)).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let archive = temp.path("archive.tar.gz");

        create_tar_gz_from_path(temp.path("project"), &archive, &TarGzCreateOptions { preserve_metadata: true, ..TarGzCreateOptions::default() }).unwrap();

        // Inspect the headers directly
        let file = File::open(&archive).unwrap();
        let decoder = flate2::read::GzDecoder::new(file);
        let mut tar_archive = tar::Archive::new(decoder);
        let entries = tar_archive.entries().unwrap();

        let mut found_file = false;
        for entry_res in entries {
            let entry = entry_res.unwrap();
            let path = entry.path().unwrap();
            if path.ends_with("file.txt") {
                found_file = true;
                let header = entry.header();
                assert_eq!(header.mtime().unwrap(), 12_345_678);
                #[cfg(unix)]
                {
                    assert_eq!(header.mode().unwrap() & 0o777, 0o755);
                }
            }
        }
        assert!(found_file);

        extract_tar_gz(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::metadata(temp.path("out/project/file.txt")).unwrap();
            assert_eq!(metadata.mtime(), 12_345_678);
            assert_eq!(metadata.mtime_nsec(), 345_678_901);
        }
    }

    #[test]
    fn respects_preserve_metadata_false() {
        let temp = TestDir::new("respects_preserve_metadata_false");
        let file_path = temp.path("project/file.txt");
        temp.write_file("project/file.txt", b"content");

        // Set a specific mod time
        let mtime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12_345_678);
        filetime::set_file_mtime(&file_path, filetime::FileTime::from_system_time(mtime)).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let archive = temp.path("archive.tar.gz");

        create_tar_gz_from_path(temp.path("project"), &archive, &TarGzCreateOptions { preserve_metadata: false, ..TarGzCreateOptions::default() }).unwrap();

        // Inspect the headers directly
        let file = File::open(&archive).unwrap();
        let decoder = flate2::read::GzDecoder::new(file);
        let mut tar_archive = tar::Archive::new(decoder);
        let entries = tar_archive.entries().unwrap();

        let mut found_file = false;
        for entry_res in entries {
            let entry = entry_res.unwrap();
            let path = entry.path().unwrap();
            if path.ends_with("file.txt") {
                found_file = true;
                let header = entry.header();
                // mtime is cleared to 0 (unix epoch)
                assert_eq!(header.mtime().unwrap(), 0);
                // mode defaults to 0o644 for files
                assert_eq!(header.mode().unwrap() & 0o777, 0o644);
            }
        }
        assert!(found_file);
    }

    #[test]
    fn respects_custom_compression_level() {
        let temp = TestDir::new("respects_custom_compression_level");
        temp.write_file("project/file.txt", b"content");
        let archive = temp.path("archive.tar.gz");

        let report = create_tar_gz_from_path(temp.path("project"), &archive, &TarGzCreateOptions { level: 3, ..TarGzCreateOptions::default() }).unwrap();

        assert_eq!(report.level, 3);
    }
}
