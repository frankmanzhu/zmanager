//! Native ZIP listing adapter for single and supported split ZIP archives (ARC-106).

use zip::ZipArchive;

use crate::archive_browser::BrowserEntryKind;
use crate::engine::format::FormatId;
use crate::engine::registry::{AdapterDescriptor, ReadAdapterFactory};
use crate::engine::source::SourceAccess;
use crate::engine::types::{
    ArchiveError, ArchiveListing, ArchiveOperation, DetectedArchive, EngineEntry, EntryId, ErrorKind, ExtractOptions, ExtractReport, OpenOptions,
    SessionDisposition, TestOptions, TestReport,
};
use crate::zip_backend::ZipBackendError;
use crate::zip_split::open_zip_reader;

static ZIP_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_zip_lister",
    format: FormatId::ZIP,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: true,
};

static SPLIT_ZIP_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_split_zip_lister",
    format: FormatId::SPLIT_ZIP,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract],
    required_source_access: SourceAccess::MultiVolumeSet,
    supports_encryption: true,
};

/// Native ZIP read adapter factory.
#[derive(Debug, Default)]
pub struct ZipListAdapter {
    format: FormatId,
}

impl ZipListAdapter {
    /// Creates a native ZIP list adapter factory for standard single-volume ZIP.
    #[must_use]
    pub const fn single_volume() -> Self {
        Self { format: FormatId::ZIP }
    }

    /// Creates a native ZIP list adapter factory for split-volume ZIP.
    #[must_use]
    pub const fn split_volume() -> Self {
        Self { format: FormatId::SPLIT_ZIP }
    }
}

impl ReadAdapterFactory for ZipListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        if self.format == FormatId::SPLIT_ZIP { &SPLIT_ZIP_LIST_DESCRIPTOR } else { &ZIP_LIST_DESCRIPTOR }
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();

        let reader = match open_zip_reader(primary_path) {
            Ok(reader) => reader,
            Err(ZipBackendError::UnsupportedSplitZip { reason }) => {
                return Err(
                    ArchiveError::usable(ErrorKind::UnsupportedOperation, format!("ZIP64 split archive is not supported: {reason}")).with_path(primary_path)
                );
            }
            Err(err) => {
                return Err(ArchiveError::usable(ErrorKind::InvalidFormat, err.to_string()).with_path(primary_path));
            }
        };

        let mut zip_archive = ZipArchive::new(reader)
            .map_err(|err| ArchiveError::usable(ErrorKind::InvalidFormat, format!("Failed to parse ZIP central directory: {err}")).with_path(primary_path))?;

        let len = zip_archive.len();
        let mut entries = Vec::with_capacity(len);

        for index in 0..len {
            let file = zip_archive.by_index_raw(index).map_err(|err| {
                ArchiveError::unusable(ErrorKind::CorruptData, format!("Failed to read ZIP entry header #{index}: {err}")).with_path(primary_path)
            })?;

            let kind = if file.is_dir() {
                BrowserEntryKind::Directory
            } else if file.is_symlink() {
                BrowserEntryKind::Symlink
            } else {
                BrowserEntryKind::File
            };

            let comment = file.comment();
            let comment_opt = (!comment.is_empty()).then(|| comment.to_owned());

            entries.push(EngineEntry {
                id: EntryId(u64::try_from(index).unwrap_or(0)),
                path: file.name().to_owned(),
                kind,
                size: Some(file.size()),
                compressed_size: Some(file.compressed_size()),
                modified: file.last_modified().map(|m| m.to_string()),
                mode: file.unix_mode(),
                encrypted: Some(file.encrypted()),
                method: Some(file.compression().to_string()),
                crc: Some(file.crc32()),
                comment: comment_opt,
                link_target: None,
                ..EngineEntry::default()
            });
        }

        Ok(ArchiveListing { entries })
    }

    fn test(&self, archive: &DetectedArchive, open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        if test_options.is_cancelled() {
            return Err(ArchiveError::usable(ErrorKind::Cancelled, "ZIP test was cancelled").with_path(path));
        }
        let report = crate::zip_backend::test_zip_with_password_filter(path, open_options.password.as_deref(), |entry_path| test_options.selects(entry_path))
            .map_err(|error| {
            let kind = match error {
                ZipBackendError::PasswordRequired => ErrorKind::PasswordRequired,
                ZipBackendError::InvalidPassword => ErrorKind::WrongPassword,
                ZipBackendError::Cancelled => ErrorKind::Cancelled,
                ZipBackendError::Io { .. } => ErrorKind::Io,
                ZipBackendError::UnsupportedSplitZip { .. } => ErrorKind::InvalidFormat,
                _ => ErrorKind::CorruptData,
            };
            let disposition = if matches!(kind, ErrorKind::CorruptData) {
                crate::engine::types::SessionDisposition::Unusable
            } else {
                crate::engine::types::SessionDisposition::Usable
            };
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
        let path = archive.source.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            crate::zip_backend::extract_zip_with_overwrite_resolver_and_password(
                path,
                &options.destination,
                options.policy.clone(),
                open_options.password.as_deref(),
                resolver,
            )
        } else {
            crate::zip_backend::extract_zip_with_password(path, &options.destination, options.policy.clone(), open_options.password.as_deref())
        }
        .map_err(|error| {
            let kind = match error {
                ZipBackendError::PasswordRequired => ErrorKind::PasswordRequired,
                ZipBackendError::InvalidPassword => ErrorKind::WrongPassword,
                ZipBackendError::Cancelled => ErrorKind::Cancelled,
                ZipBackendError::Safety(ref source) => crate::engine::adapters::safety_error_kind(source),
                ZipBackendError::Io { .. } => ErrorKind::Io,
                ZipBackendError::UnsupportedSplitZip { .. } => ErrorKind::UnsupportedOperation,
                _ => ErrorKind::CorruptData,
            };
            ArchiveError {
                kind,
                message: error.to_string(),
                disposition: if matches!(kind, ErrorKind::CorruptData) { SessionDisposition::Unusable } else { SessionDisposition::Usable },
                path: Some(path.to_path_buf()),
            }
        })?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }
}
