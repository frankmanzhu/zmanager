//! Libarchive compatibility listing adapter for explicitly allow-listed residual formats (ARC-107).

use std::time::{SystemTime, UNIX_EPOCH};

use crate::archive_browser::BrowserEntryKind;
use crate::engine::format::FormatId;
use crate::engine::registry::{AdapterDescriptor, ReadAdapterFactory};
use crate::engine::source::SourceAccess;
use crate::engine::types::{
    ArchiveError, ArchiveListing, ArchiveOperation, DetectedArchive, EngineEntry, EntryId, ErrorKind, ExtractOptions, ExtractReport, OpenOptions,
    SessionDisposition, TestOptions, TestReport,
};
use crate::libarchive_backend::{self, LibarchiveEntryKind};

fn system_time_string(time: SystemTime) -> Option<String> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    Some(duration.as_secs().to_string())
}

/// Allow-list of formats accepted by the libarchive listing compatibility adapter.
pub const LIBARCHIVE_ALLOW_LIST: &[FormatId] = &[
    FormatId::UNKNOWN,
    FormatId::TAR,
    FormatId::TAR_BZ2,
    FormatId::TAR_XZ,
    FormatId::TAR_LZMA,
    FormatId::TAR_LZ,
    FormatId::TAR_LZO,
    FormatId::TAR_COMPRESS,
    FormatId::TAR_LZ4,
    FormatId::TAR_LRZ,
    FormatId::ISO,
    FormatId::CAB,
    FormatId::CPIO,
    FormatId::RPM,
    FormatId::XAR,
    FormatId::LHA,
    FormatId::AR,
    FormatId::WARC,
    FormatId::MTREE,
    FormatId::DEB,
];

/// Libarchive listing compatibility adapter factory.
#[derive(Debug)]
pub struct LibarchiveListAdapter {
    format: FormatId,
}

impl LibarchiveListAdapter {
    /// Creates a libarchive listing compatibility adapter for an allow-listed format.
    ///
    /// # Errors
    ///
    /// Returns `ArchiveError` if `format` is unknown or not on the explicit allow-list.
    pub fn new(format: FormatId) -> Result<Self, ArchiveError> {
        if !LIBARCHIVE_ALLOW_LIST.contains(&format) {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, format!("Format '{format}' is not on the libarchive compatibility allow-list")));
        }
        Ok(Self { format })
    }

    /// Returns the target format for this adapter instance.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.format
    }
}

impl ReadAdapterFactory for LibarchiveListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        // Dynamic descriptor matching self.format
        Box::leak(Box::new(AdapterDescriptor {
            name: "libarchive_compatibility_lister",
            format: self.format,
            operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract],
            required_source_access: SourceAccess::Seekable,
            supports_encryption: true,
        }))
    }

    fn list(&self, archive: &DetectedArchive, options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        if !LIBARCHIVE_ALLOW_LIST.contains(&archive.format) {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, format!("Format '{}' is rejected prior to libarchive probing", archive.format)));
        }

        let primary_path = archive.source.primary_path();
        let listing = libarchive_backend::list_archive_with_password(primary_path, options.password.as_deref())
            .map_err(|err| ArchiveError::usable(ErrorKind::InvalidFormat, err.to_string()).with_path(primary_path))?;

        let entries = listing
            .entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: EntryId(u64::try_from(index).unwrap_or(0)),
                path: entry.path,
                kind: match entry.kind {
                    LibarchiveEntryKind::File => BrowserEntryKind::File,
                    LibarchiveEntryKind::Directory => BrowserEntryKind::Directory,
                    LibarchiveEntryKind::Symlink => BrowserEntryKind::Symlink,
                    LibarchiveEntryKind::Hardlink => BrowserEntryKind::Hardlink,
                    LibarchiveEntryKind::Special | LibarchiveEntryKind::Device => BrowserEntryKind::Special,
                },
                size: u64::try_from(entry.size).ok(),
                compressed_size: None,
                modified: entry.modified.and_then(system_time_string),
                mode: (entry.mode != 0).then_some(entry.mode & 0o7777),
                encrypted: Some(entry.data_encrypted || entry.metadata_encrypted),
                method: None,
                crc: None,
                comment: None,
                link_target: entry.link_target,
                created: None,
                accessed: None,
                solid: None,
                attributes: None,
                uid: entry.uid,
                gid: entry.gid,
                owner: entry.owner,
                group: entry.group,
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn test(&self, archive: &DetectedArchive, open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        if !LIBARCHIVE_ALLOW_LIST.contains(&archive.format) {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, format!("Format '{}' is rejected prior to libarchive probing", archive.format)));
        }
        let path = archive.source.primary_path();
        let report =
            libarchive_backend::test_archive_with_password_filter(path, open_options.password.as_deref(), |entry_path| test_options.selects(entry_path))
                .map_err(|error| {
                    let kind = match error {
                        libarchive_backend::LibarchiveError::Io { .. } => ErrorKind::Io,
                        libarchive_backend::LibarchiveError::Cancelled => ErrorKind::Cancelled,
                        _ => ErrorKind::CorruptData,
                    };
                    let disposition = if kind == ErrorKind::CorruptData { SessionDisposition::Unusable } else { SessionDisposition::Usable };
                    ArchiveError { kind, message: error.to_string(), disposition, path: Some(path.to_path_buf()) }
                })?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.tested_entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.tested_bytes,
            warnings: Vec::new(),
        })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        if !LIBARCHIVE_ALLOW_LIST.contains(&archive.format) {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, format!("Format '{}' is rejected prior to libarchive probing", archive.format)));
        }
        let path = archive.source.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            libarchive_backend::extract_archive_with_overwrite_resolver_and_password(
                path,
                &options.destination,
                options.policy.clone(),
                open_options.password.as_deref(),
                resolver,
            )
        } else {
            libarchive_backend::extract_archive_with_password(path, &options.destination, options.policy.clone(), open_options.password.as_deref())
        }
        .map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }
}
