//! Native listing adapters for 7z, TAR.ZST, TZAP, RAR, `RawStreams`, Apple Archive, DMG, PKG, MSI, `VirtualDisks` (ARC-200).

use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{Read, Write as _};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::apple_archive_backend;
use crate::apple_dmg_backend;
use crate::apple_pkg_backend;
use crate::archive_browser::BrowserEntryKind;
use crate::engine::format::FormatId;
use crate::engine::registry::{AdapterDescriptor, ReadAdapterFactory};
use crate::engine::source::SourceAccess;
use crate::engine::types::{
    ArchiveError, ArchiveListing, ArchiveOperation, CopyReport, DetectedArchive, EngineEntry, EntryId, ErrorKind, ExtractOptions, ExtractReport, OpenOptions,
    SelectedExtractOptions, SessionDisposition, TestOptions, TestReport,
};
use crate::msi_backend;
use crate::rar_backend;
use crate::raw_stream_backend;
use crate::sevenz_backend;
use crate::tzap_backend;
use crate::virtual_disk_backend;

// --- TAR.GZ and plain TAR ---
static TAR_GZ_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_gz_adapter",
    format: FormatId::TAR_GZ,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static TAR_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_adapter",
    format: FormatId::TAR,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native TAR.GZ listing and extraction adapter.
#[derive(Debug, Default)]
pub struct TarGzListAdapter;

impl ReadAdapterFactory for TarGzListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &TAR_GZ_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let decoder = GzDecoder::new(file);
        let entries = crate::tar_backend::list(decoder, path).map_err(|error| tar_error(path, &error))?;
        Ok(ArchiveListing { entries: map_tar_entries(entries, "gzip") })
    }

    fn test(&self, archive: &DetectedArchive, _open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let decoder = GzDecoder::new(file);
        let report = crate::tar_backend::test(decoder, path, |entry_path| test_options.selects(entry_path), || test_options.is_cancelled())
            .map_err(|error| tar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let decoder = GzDecoder::new(file);
        let report = crate::tar_backend::extract(
            decoder,
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            None,
            options.cancellation.as_ref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn selected_extract<'a>(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        options: &'a mut SelectedExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let decoder = GzDecoder::new(file);
        let report = crate::tar_backend::extract(
            decoder,
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            Some(usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?),
            options.cancellation.as_ref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let decoder = GzDecoder::new(file);
        let written_bytes = crate::tar_backend::copy(
            decoder,
            path,
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            writer,
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

/// Native plain TAR adapter factory.
#[derive(Debug, Default)]
pub struct TarListAdapter;

impl ReadAdapterFactory for TarListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &TAR_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let entries = crate::tar_backend::list(file, path).map_err(|error| tar_error(path, &error))?;
        Ok(ArchiveListing { entries: map_tar_entries(entries, "tar") })
    }

    fn test(&self, archive: &DetectedArchive, _open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let report = crate::tar_backend::test(file, path, |entry_path| test_options.selects(entry_path), || test_options.is_cancelled())
            .map_err(|error| tar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let report = crate::tar_backend::extract(
            file,
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            None,
            options.cancellation.as_ref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn selected_extract<'a>(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        options: &'a mut SelectedExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let report = crate::tar_backend::extract(
            file,
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            Some(usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?),
            options.cancellation.as_ref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let written_bytes = crate::tar_backend::copy(
            file,
            path,
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            writer,
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn map_tar_entries(entries: Vec<crate::tar_backend::TarEntry>, method: &str) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: EntryId(u64::try_from(entry.index).unwrap_or(0)),
            path: entry.path,
            kind: entry.kind,
            size: entry.size,
            compressed_size: None,
            modified: entry.modified,
            mode: entry.mode,
            encrypted: Some(false),
            method: Some(method.to_owned()),
            link_target: entry.link_target,
            ..EngineEntry::default()
        })
        .collect()
}

fn tar_error(path: &std::path::Path, error: &crate::tar_backend::TarError) -> ArchiveError {
    let kind = match error {
        crate::tar_backend::TarError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::tar_backend::TarError::Cancelled => ErrorKind::Cancelled,
        crate::tar_backend::TarError::Io { .. } => ErrorKind::Io,
        crate::tar_backend::TarError::MissingLinkTarget { .. } => ErrorKind::CorruptData,
    };
    ArchiveError {
        kind,
        message: error.to_string(),
        disposition: if kind == ErrorKind::CorruptData { SessionDisposition::Unusable } else { SessionDisposition::Usable },
        path: Some(path.to_path_buf()),
    }
}

static AR_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_ar_adapter",
    format: FormatId::AR,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static CPIO_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_cpio_adapter",
    format: FormatId::CPIO,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static DEB_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_deb_adapter",
    format: FormatId::DEB,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static RPM_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_rpm_adapter",
    format: FormatId::RPM,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static CAB_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_cab_adapter",
    format: FormatId::CAB,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native Debian package adapter composing AR with the registered payload engines.
#[derive(Debug, Default)]
pub struct DebListAdapter;

impl ReadAdapterFactory for DebListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &DEB_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.source.primary_path();
        let entries = crate::ar_backend::list(path).map_err(|error| ar_error(path, &error))?;
        Ok(ArchiveListing { entries: map_ar_entries(entries) })
    }

    fn test(&self, archive: &DetectedArchive, _open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = crate::ar_backend::test(path, test_options).map_err(|error| ar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            crate::deb_backend::extract_deb_nested_with_overwrite_resolver(path, &options.destination, &options.policy, resolver)
        } else {
            crate::deb_backend::extract_deb_nested(path, &options.destination, &options.policy)
        }
        .map_err(|error| deb_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let written_bytes = crate::ar_backend::copy(
            path,
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            writer,
        )
        .map_err(|error| ar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn deb_error(path: &std::path::Path, error: &crate::deb_backend::DebError) -> ArchiveError {
    let kind = match error {
        crate::deb_backend::DebError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::deb_backend::DebError::Engine(source) => source.kind,
        crate::deb_backend::DebError::Ar(source) => match source {
            crate::ar_backend::ArError::Safety(safety) => crate::engine::adapters::safety_error_kind(safety),
            crate::ar_backend::ArError::Cancelled => ErrorKind::Cancelled,
            crate::ar_backend::ArError::Io { .. } => ErrorKind::Io,
            crate::ar_backend::ArError::Invalid { .. } => ErrorKind::CorruptData,
        },
        crate::deb_backend::DebError::Tar(source) => match source {
            crate::tar_backend::TarError::Safety(safety) => crate::engine::adapters::safety_error_kind(safety),
            crate::tar_backend::TarError::Cancelled => ErrorKind::Cancelled,
            crate::tar_backend::TarError::Io { .. } => ErrorKind::Io,
            crate::tar_backend::TarError::MissingLinkTarget { .. } => ErrorKind::CorruptData,
        },
        crate::deb_backend::DebError::RawStream(source) => match source {
            crate::raw_stream_backend::RawStreamError::Safety(safety) => crate::engine::adapters::safety_error_kind(safety),
            crate::raw_stream_backend::RawStreamError::Io { .. } | crate::raw_stream_backend::RawStreamError::ExternalToolUnavailable { .. } => ErrorKind::Io,
            crate::raw_stream_backend::RawStreamError::MissingOutputName { .. } | crate::raw_stream_backend::RawStreamError::ExternalToolFailed { .. } => {
                ErrorKind::CorruptData
            }
        },
        crate::deb_backend::DebError::Io { .. } => ErrorKind::Io,
        crate::deb_backend::DebError::MissingMember { .. } => ErrorKind::CorruptData,
    };
    ArchiveError {
        kind,
        message: error.to_string(),
        disposition: if kind == ErrorKind::CorruptData { SessionDisposition::Unusable } else { SessionDisposition::Usable },
        path: Some(path.to_path_buf()),
    }
}

/// Native RPM container adapter composing the bounded RPM reader with CPIO.
#[derive(Debug, Default)]
pub struct RpmListAdapter;

impl ReadAdapterFactory for RpmListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &RPM_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.source.primary_path();
        let entries = crate::rpm_backend::list(path).map_err(|error| rpm_error(path, &error))?;
        Ok(ArchiveListing { entries: map_cpio_entries(entries) })
    }

    fn test(&self, archive: &DetectedArchive, _open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = crate::rpm_backend::test(path, test_options).map_err(|error| rpm_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = crate::rpm_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            options.cancellation.as_ref(),
        )
        .map_err(|error| rpm_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let written_bytes = crate::rpm_backend::copy(
            path,
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            writer,
        )
        .map_err(|error| rpm_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn rpm_error(path: &std::path::Path, error: &crate::rpm_backend::RpmError) -> ArchiveError {
    let kind = match error {
        crate::rpm_backend::RpmError::Io { .. } => ErrorKind::Io,
        crate::rpm_backend::RpmError::Invalid { .. } => ErrorKind::CorruptData,
        crate::rpm_backend::RpmError::Cpio(source) => match source {
            crate::cpio_backend::CpioError::Safety(safety) => crate::engine::adapters::safety_error_kind(safety),
            crate::cpio_backend::CpioError::Cancelled => ErrorKind::Cancelled,
            crate::cpio_backend::CpioError::Io { .. } => ErrorKind::Io,
            crate::cpio_backend::CpioError::Invalid { .. } => ErrorKind::CorruptData,
        },
        crate::rpm_backend::RpmError::RawStream(source) => match source {
            crate::raw_stream_backend::RawStreamError::Safety(safety) => crate::engine::adapters::safety_error_kind(safety),
            crate::raw_stream_backend::RawStreamError::Io { .. } | crate::raw_stream_backend::RawStreamError::ExternalToolUnavailable { .. } => ErrorKind::Io,
            crate::raw_stream_backend::RawStreamError::MissingOutputName { .. } | crate::raw_stream_backend::RawStreamError::ExternalToolFailed { .. } => {
                ErrorKind::CorruptData
            }
        },
    };
    ArchiveError {
        kind,
        message: error.to_string(),
        disposition: if kind == ErrorKind::CorruptData { SessionDisposition::Unusable } else { SessionDisposition::Usable },
        path: Some(path.to_path_buf()),
    }
}

/// Native single-cabinet adapter backed by the maintained CAB reader.
#[derive(Debug, Default)]
pub struct CabListAdapter;

impl ReadAdapterFactory for CabListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &CAB_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.source.primary_path();
        let entries = crate::cab_backend::list(path).map_err(|error| cab_error(path, &error))?;
        Ok(ArchiveListing { entries: map_cab_entries(entries) })
    }

    fn test(&self, archive: &DetectedArchive, _open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = crate::cab_backend::test(path, test_options).map_err(|error| cab_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = crate::cab_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            options.cancellation.as_ref(),
        )
        .map_err(|error| cab_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let written_bytes = crate::cab_backend::copy(
            path,
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            writer,
        )
        .map_err(|error| cab_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn map_cab_entries(entries: Vec<crate::cab_backend::CabEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: EntryId(u64::try_from(entry.index).unwrap_or(0)),
            path: entry.path,
            kind: BrowserEntryKind::File,
            size: Some(entry.size),
            compressed_size: None,
            modified: entry.modified,
            mode: Some(entry.mode),
            encrypted: Some(false),
            method: Some("cab".to_owned()),
            ..EngineEntry::default()
        })
        .collect()
}

fn cab_error(path: &std::path::Path, error: &crate::cab_backend::CabError) -> ArchiveError {
    let kind = match error {
        crate::cab_backend::CabError::Io { .. } => ErrorKind::Io,
        crate::cab_backend::CabError::Invalid { .. } => ErrorKind::CorruptData,
        crate::cab_backend::CabError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::cab_backend::CabError::Cancelled => ErrorKind::Cancelled,
    };
    ArchiveError {
        kind,
        message: error.to_string(),
        disposition: if kind == ErrorKind::CorruptData { SessionDisposition::Unusable } else { SessionDisposition::Usable },
        path: Some(path.to_path_buf()),
    }
}

/// Native CPIO reader adapter.
#[derive(Debug, Default)]
pub struct CpioListAdapter;

impl ReadAdapterFactory for CpioListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &CPIO_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.source.primary_path();
        let (_temporary, source) = cpio_source(path)?;
        let entries = crate::cpio_backend::list(&source).map_err(|error| cpio_error(path, &error))?;
        Ok(ArchiveListing { entries: map_cpio_entries(entries) })
    }

    fn test(&self, archive: &DetectedArchive, _open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let (_temporary, source) = cpio_source(path)?;
        let report = crate::cpio_backend::test(&source, test_options).map_err(|error| cpio_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let (_temporary, source) = cpio_source(path)?;
        let report = crate::cpio_backend::extract(
            &source,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            None,
            options.cancellation.as_ref(),
        )
        .map_err(|error| cpio_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn selected_extract<'a>(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        options: &'a mut SelectedExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let (_temporary, source) = cpio_source(path)?;
        let report = crate::cpio_backend::extract(
            &source,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            Some(usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?),
            options.cancellation.as_ref(),
        )
        .map_err(|error| cpio_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let (_temporary, source) = cpio_source(path)?;
        let written_bytes = crate::cpio_backend::copy(
            &source,
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            writer,
        )
        .map_err(|error| cpio_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn cpio_source(path: &std::path::Path) -> Result<(Option<crate::temp_names::TemporaryDirectory>, std::path::PathBuf), ArchiveError> {
    let Some(format) = cpio_compression(path) else {
        return Ok((None, path.to_path_buf()));
    };
    let temporary =
        crate::temp_names::TemporaryDirectory::new("cpio-decode").map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
    let decoded_path = temporary.path().join("payload.cpio");
    let mut decoder =
        raw_stream_backend::open_decoder(path, format).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?;
    let mut output = File::create(&decoded_path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
    std::io::copy(&mut decoder, &mut output).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
    output.flush().map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
    Ok((Some(temporary), decoded_path))
}

fn cpio_compression(path: &std::path::Path) -> Option<raw_stream_backend::RawStreamFormat> {
    let name = path.file_name()?.to_str()?;
    if crate::strings::ends_with_ignore_ascii_case(name, ".cpgz") || crate::strings::ends_with_ignore_ascii_case(name, ".cpio.gz") {
        Some(raw_stream_backend::RawStreamFormat::Gzip)
    } else if crate::strings::ends_with_ignore_ascii_case(name, ".cpio.bz2") {
        Some(raw_stream_backend::RawStreamFormat::Bzip2)
    } else if crate::strings::ends_with_ignore_ascii_case(name, ".cpio.xz") {
        Some(raw_stream_backend::RawStreamFormat::Xz)
    } else if crate::strings::ends_with_ignore_ascii_case(name, ".cpio.lzma") {
        Some(raw_stream_backend::RawStreamFormat::Lzma)
    } else if crate::strings::ends_with_ignore_ascii_case(name, ".cpio.zst") {
        Some(raw_stream_backend::RawStreamFormat::Zstd)
    } else {
        None
    }
}

fn map_cpio_entries(entries: Vec<crate::cpio_backend::CpioEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: EntryId(u64::try_from(entry.index).unwrap_or(0)),
            path: entry.path,
            kind: entry.kind,
            size: Some(entry.size),
            mode: Some(entry.mode),
            modified: entry.modified,
            method: Some("cpio".to_owned()),
            link_target: entry.link_target,
            ..EngineEntry::default()
        })
        .collect()
}

fn cpio_error(path: &std::path::Path, error: &crate::cpio_backend::CpioError) -> ArchiveError {
    let kind = match error {
        crate::cpio_backend::CpioError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::cpio_backend::CpioError::Cancelled => ErrorKind::Cancelled,
        crate::cpio_backend::CpioError::Io { .. } => ErrorKind::Io,
        crate::cpio_backend::CpioError::Invalid { .. } => ErrorKind::CorruptData,
    };
    ArchiveError {
        kind,
        message: error.to_string(),
        disposition: if kind == ErrorKind::CorruptData { SessionDisposition::Unusable } else { SessionDisposition::Usable },
        path: Some(path.to_path_buf()),
    }
}

/// Native AR reader adapter.
#[derive(Debug, Default)]
pub struct ArListAdapter;

impl ReadAdapterFactory for ArListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &AR_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.source.primary_path();
        let entries = crate::ar_backend::list(path).map_err(|error| ar_error(path, &error))?;
        Ok(ArchiveListing { entries: map_ar_entries(entries) })
    }

    fn test(&self, archive: &DetectedArchive, _open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = crate::ar_backend::test(path, test_options).map_err(|error| ar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = crate::ar_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            None,
            options.cancellation.as_ref(),
        )
        .map_err(|error| ar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn selected_extract<'a>(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        options: &'a mut SelectedExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = crate::ar_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            Some(usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?),
            options.cancellation.as_ref(),
        )
        .map_err(|error| ar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let written_bytes = crate::ar_backend::copy(
            path,
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            writer,
        )
        .map_err(|error| ar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn map_ar_entries(entries: Vec<crate::ar_backend::ArEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: EntryId(u64::try_from(entry.index).unwrap_or(0)),
            path: entry.path,
            kind: BrowserEntryKind::File,
            size: Some(entry.size),
            compressed_size: Some(entry.size),
            method: Some("ar".to_owned()),
            ..EngineEntry::default()
        })
        .collect()
}

fn ar_error(path: &std::path::Path, error: &crate::ar_backend::ArError) -> ArchiveError {
    let kind = match error {
        crate::ar_backend::ArError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::ar_backend::ArError::Cancelled => ErrorKind::Cancelled,
        crate::ar_backend::ArError::Io { .. } => ErrorKind::Io,
        crate::ar_backend::ArError::Invalid { .. } => ErrorKind::CorruptData,
    };
    ArchiveError {
        kind,
        message: error.to_string(),
        disposition: if kind == ErrorKind::CorruptData { SessionDisposition::Unusable } else { SessionDisposition::Usable },
        path: Some(path.to_path_buf()),
    }
}

static TAR_BZ2_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_bz2_adapter",
    format: FormatId::TAR_BZ2,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static TAR_XZ_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_xz_adapter",
    format: FormatId::TAR_XZ,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static TAR_LZMA_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_lzma_adapter",
    format: FormatId::TAR_LZMA,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native filtered-TAR adapter backed by the shared TAR reader.
#[derive(Debug, Clone, Copy)]
pub struct FilteredTarAdapter {
    format: FormatId,
    decoder: raw_stream_backend::RawStreamFormat,
    method: &'static str,
}

impl FilteredTarAdapter {
    /// Creates a filtered TAR adapter for one canonical format.
    #[must_use]
    pub const fn new(format: FormatId, decoder: raw_stream_backend::RawStreamFormat, method: &'static str) -> Self {
        Self { format, decoder, method }
    }

    fn open_reader(&self, path: &std::path::Path) -> Result<Box<dyn Read>, ArchiveError> {
        raw_stream_backend::open_decoder(path, self.decoder).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))
    }
}

impl ReadAdapterFactory for FilteredTarAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        match self.format {
            FormatId::TAR_BZ2 => &TAR_BZ2_DESCRIPTOR,
            FormatId::TAR_XZ => &TAR_XZ_DESCRIPTOR,
            FormatId::TAR_LZMA => &TAR_LZMA_DESCRIPTOR,
            _ => unreachable!("filtered TAR adapter format must be TAR.BZ2, TAR.XZ, or TAR.LZMA"),
        }
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.source.primary_path();
        let reader = self.open_reader(path)?;
        let entries = crate::tar_backend::list(reader, path).map_err(|error| tar_error(path, &error))?;
        Ok(ArchiveListing { entries: map_tar_entries(entries, self.method) })
    }

    fn test(&self, archive: &DetectedArchive, _open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let reader = self.open_reader(path)?;
        let report = crate::tar_backend::test(reader, path, |entry_path| test_options.selects(entry_path), || test_options.is_cancelled())
            .map_err(|error| tar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let reader = self.open_reader(path)?;
        let report = crate::tar_backend::extract(
            reader,
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            None,
            options.cancellation.as_ref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn selected_extract<'a>(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        options: &'a mut SelectedExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let reader = self.open_reader(path)?;
        let report = crate::tar_backend::extract(
            reader,
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            Some(usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?),
            options.cancellation.as_ref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let reader = self.open_reader(path)?;
        let written_bytes = crate::tar_backend::copy(
            reader,
            path,
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            writer,
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn system_time_string(time: SystemTime) -> Option<String> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    Some(duration.as_secs().to_string())
}

fn tzap_timestamp_string(seconds: i64, nanoseconds: u32) -> Option<String> {
    if seconds == 0 && nanoseconds == 0 {
        return None;
    }
    if nanoseconds == 0 {
        return Some(seconds.to_string());
    }
    let fraction = format!("{nanoseconds:09}");
    Some(format!("{seconds}.{}", fraction.trim_end_matches('0')))
}

fn sevenz_archive_error(error: sevenz_backend::SevenZError, path: &std::path::Path) -> ArchiveError {
    match error {
        sevenz_backend::SevenZError::PasswordRequired => {
            ArchiveError::usable(ErrorKind::PasswordRequired, "password required to decrypt 7z data").with_path(path)
        }
        sevenz_backend::SevenZError::InvalidPassword => ArchiveError::usable(ErrorKind::WrongPassword, "provided 7z password is incorrect").with_path(path),
        sevenz_backend::SevenZError::Io { path, source } => ArchiveError::usable(ErrorKind::Io, source.to_string()).with_path(path),
        sevenz_backend::SevenZError::Safety(source) => {
            let kind = crate::engine::adapters::safety_error_kind(&source);
            ArchiveError::usable(kind, source.to_string()).with_path(path)
        }
        sevenz_backend::SevenZError::Cancelled => ArchiveError::usable(ErrorKind::Cancelled, "7z operation was cancelled").with_path(path),
        sevenz_backend::SevenZError::VolumeSizeTooSmall { size, minimum } => {
            ArchiveError::usable(ErrorKind::UnsupportedOperation, format!("7z volume size {size} bytes is smaller than the minimum {minimum} bytes"))
                .with_path(path)
        }
        sevenz_backend::SevenZError::Plan(source) => ArchiveError::usable(ErrorKind::InvalidFormat, source.to_string()).with_path(path),
        sevenz_backend::SevenZError::SevenZ(source) => ArchiveError::usable(ErrorKind::InvalidFormat, source.to_string()).with_path(path),
    }
}

// --- 7z ---
static SEVEN_Z_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_7z_lister",
    format: FormatId::SEVEN_Z,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: true,
};

/// Native 7z listing adapter factory.
#[derive(Debug, Default)]
pub struct SevenZListAdapter;

impl ReadAdapterFactory for SevenZListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &SEVEN_Z_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let listing = sevenz_backend::list_7z(primary_path, options.password.as_deref()).map_err(|err| sevenz_archive_error(err, primary_path))?;

        let entries = listing
            .entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: EntryId(u64::try_from(index).unwrap_or(0)),
                path: entry.name,
                kind: match entry.kind {
                    sevenz_backend::SevenZEntryKind::File => BrowserEntryKind::File,
                    sevenz_backend::SevenZEntryKind::Directory => BrowserEntryKind::Directory,
                    sevenz_backend::SevenZEntryKind::AntiItem => BrowserEntryKind::Special,
                },
                size: Some(entry.size),
                compressed_size: (entry.compressed_size > 0).then_some(entry.compressed_size),
                modified: entry.modified.and_then(system_time_string),
                mode: entry.mode,
                encrypted: None,
                method: None,
                crc: entry.crc,
                comment: None,
                link_target: None,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn test(&self, archive: &DetectedArchive, open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = sevenz_backend::test_7z_with_password_filter(path, open_options.password.as_deref(), |entry_path| test_options.selects(entry_path))
            .map_err(|error| sevenz_archive_error(error, path))?;
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
            sevenz_backend::extract_7z_with_overwrite_resolver(path, &options.destination, open_options.password.as_deref(), options.policy.clone(), resolver)
        } else {
            sevenz_backend::extract_7z(path, &options.destination, open_options.password.as_deref(), options.policy.clone())
        }
        .map_err(|error| {
            let kind = match error {
                sevenz_backend::SevenZError::PasswordRequired => ErrorKind::PasswordRequired,
                sevenz_backend::SevenZError::InvalidPassword => ErrorKind::WrongPassword,
                sevenz_backend::SevenZError::Io { .. } => ErrorKind::Io,
                sevenz_backend::SevenZError::Safety(ref source) => crate::engine::adapters::safety_error_kind(source),
                sevenz_backend::SevenZError::Cancelled => ErrorKind::Cancelled,
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

    fn selected_extract<'a>(
        &self,
        archive: &DetectedArchive,
        open_options: &OpenOptions,
        entry_id: EntryId,
        options: &'a mut SelectedExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = sevenz_backend::extract_7z_entry_by_index(
            path,
            &options.destination,
            open_options.password.as_deref(),
            options.policy.clone(),
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            options.overwrite_resolver.as_deref_mut(),
        )
        .map_err(|error| sevenz_archive_error(error, path))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let written_bytes = sevenz_backend::copy_7z_entry_by_index(
            path,
            open_options.password.as_deref(),
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            writer,
        )
        .map_err(|error| sevenz_archive_error(error, path))?;
        Ok(CopyReport { written_bytes })
    }
}

// --- TAR.ZST ---
static TAR_ZST_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_zst_lister",
    format: FormatId::TAR_ZST,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native TAR.ZST listing adapter factory.
#[derive(Debug, Default)]
pub struct TarZstListAdapter;

impl ReadAdapterFactory for TarZstListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &TAR_ZST_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let decoder =
            zstd::stream::read::Decoder::new(file).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?;
        let entries = crate::tar_backend::list(decoder, path).map_err(|error| tar_error(path, &error))?;
        Ok(ArchiveListing { entries: map_tar_entries(entries, "zstd") })
    }

    fn test(&self, archive: &DetectedArchive, _open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let decoder =
            zstd::stream::read::Decoder::new(file).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?;
        let report = crate::tar_backend::test(decoder, path, |entry_path| test_options.selects(entry_path), || test_options.is_cancelled())
            .map_err(|error| tar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let decoder =
            zstd::stream::read::Decoder::new(file).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?;
        let report = crate::tar_backend::extract(
            decoder,
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            None,
            options.cancellation.as_ref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn selected_extract<'a>(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        options: &'a mut SelectedExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let decoder =
            zstd::stream::read::Decoder::new(file).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?;
        let report = crate::tar_backend::extract(
            decoder,
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            Some(usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?),
            options.cancellation.as_ref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let file = File::open(path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
        let decoder =
            zstd::stream::read::Decoder::new(file).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?;
        let written_bytes = crate::tar_backend::copy(
            decoder,
            path,
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            writer,
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

// --- TZAP ---
static TZAP_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tzap_lister",
    format: FormatId::TZAP,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: true,
};

/// Native TZAP listing adapter factory.
#[derive(Debug, Default)]
pub struct TzapListAdapter;

impl ReadAdapterFactory for TzapListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &TZAP_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let listing = match options.recipient_key_path() {
            Some(recipient_key) => tzap_backend::list_tzap_index_with_recipient_key(primary_path, recipient_key),
            None => tzap_backend::list_tzap_index_with_optional_password(primary_path, options.password.as_deref()),
        }
        .map_err(|err| ArchiveError::usable(ErrorKind::InvalidFormat, err.to_string()).with_path(primary_path))?;

        let encrypted = listing.encrypted;
        let method = if encrypted {
            match listing.kdf_algo {
                tzap_core::format::KdfAlgo::Argon2id => "Zstd (Argon2id)",
                tzap_core::format::KdfAlgo::RecipientWrap => "Zstd (Recipient)",
                _ => "Zstd (Encrypted)",
            }
        } else {
            "Zstd"
        };
        let entries = listing
            .entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: EntryId(u64::try_from(index).unwrap_or(0)),
                path: entry.path,
                kind: match entry.kind {
                    tzap_backend::TzapEntryKind::File => BrowserEntryKind::File,
                    tzap_backend::TzapEntryKind::Directory => BrowserEntryKind::Directory,
                    tzap_backend::TzapEntryKind::Symlink => BrowserEntryKind::Symlink,
                    tzap_backend::TzapEntryKind::Hardlink => BrowserEntryKind::Hardlink,
                    tzap_backend::TzapEntryKind::CharacterDevice | tzap_backend::TzapEntryKind::BlockDevice | tzap_backend::TzapEntryKind::Fifo => {
                        BrowserEntryKind::Special
                    }
                },
                size: Some(entry.size),
                compressed_size: (entry.compressed_size != 0).then_some(entry.compressed_size),
                modified: tzap_timestamp_string(entry.mtime, entry.mtime_nanoseconds),
                mode: Some(entry.mode),
                encrypted: Some(encrypted),
                method: Some(method.to_owned()),
                crc: None,
                comment: None,
                link_target: entry.link_target,
                created: entry.created.and_then(|(seconds, nanoseconds)| tzap_timestamp_string(seconds, nanoseconds)),
                accessed: entry.accessed.and_then(|(seconds, nanoseconds)| tzap_timestamp_string(seconds, nanoseconds)),
                solid: Some(true),
                attributes: entry.attributes.map(|value| format!("{value:#010X}")),
                uid: entry.uid.and_then(|value| u32::try_from(value).ok()),
                gid: entry.gid.and_then(|value| u32::try_from(value).ok()),
                owner: entry.uname,
                group: entry.gname,
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn test(&self, archive: &DetectedArchive, open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let trust = test_options.tzap_x509_trust.as_ref();
        let recipient_key = test_options.recipient_key.as_deref().or(open_options.recipient_key_path());
        let report = if let Some(recipient_key) = recipient_key {
            tzap_backend::test_tzap_with_recipient_key_filter_and_x509_trust(path, recipient_key, |entry_path| test_options.selects(entry_path), trust)
        } else {
            tzap_backend::test_tzap_with_optional_password_filter_and_x509_trust(
                path,
                open_options.password.as_deref(),
                |entry_path| test_options.selects(entry_path),
                trust,
            )
        }
        .map_err(|error| {
            let kind = match error {
                tzap_backend::TzapError::PasswordRequired | tzap_backend::TzapError::RecipientKeyRequired => ErrorKind::PasswordRequired,
                tzap_backend::TzapError::Cancelled => ErrorKind::Cancelled,
                tzap_backend::TzapError::Io { .. } => ErrorKind::Io,
                _ => ErrorKind::CorruptData,
            };
            let disposition = if kind == ErrorKind::CorruptData { SessionDisposition::Unusable } else { SessionDisposition::Usable };
            ArchiveError { kind, message: error.to_string(), disposition, path: Some(path.to_path_buf()) }
        })?;
        let mut warnings = Vec::new();
        if let Some(root_auth) = report.x509_root_auth {
            warnings.push(format!("TZAP root-auth verified for {}", root_auth.subject));
            warnings.extend(root_auth.diagnostics);
        }
        Ok(TestReport {
            tested_entries: u64::try_from(report.tested_entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.tested_bytes,
            warnings,
        })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let key = if let Some(recipient_key_bytes) = options.recipient_key_bytes.as_deref() {
            tzap_backend::TzapExtractKeySource::RecipientKeyBytes(recipient_key_bytes)
        } else if let Some(recipient_key) = options.recipient_key.as_deref() {
            tzap_backend::TzapExtractKeySource::RecipientKeyPath(recipient_key)
        } else if let Some(password) = options.tzap_password.as_deref() {
            tzap_backend::TzapExtractKeySource::Password(password)
        } else {
            tzap_backend::TzapExtractKeySource::None
        };
        let report = tzap_backend::extract_tzap(
            tzap_backend::TzapExtractRequest {
                key,
                policy: options.policy.clone(),
                restore_options: options.tzap_restore_options.unwrap_or_default(),
                overwrite_resolver: options.overwrite_resolver.as_deref_mut(),
                context: None,
                fast: false,
            },
            path,
            &options.destination,
        )
        .map_err(|error| {
            let kind = match error {
                tzap_backend::TzapError::PasswordRequired | tzap_backend::TzapError::RecipientKeyRequired => ErrorKind::PasswordRequired,
                tzap_backend::TzapError::Cancelled => ErrorKind::Cancelled,
                tzap_backend::TzapError::Io { .. } => ErrorKind::Io,
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

    fn selected_extract<'a>(
        &self,
        archive: &DetectedArchive,
        open_options: &OpenOptions,
        entry_id: EntryId,
        options: &'a mut SelectedExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let entries = match open_options.recipient_key_path() {
            Some(recipient_key) => tzap_backend::list_tzap_index_with_recipient_key(path, recipient_key),
            None => tzap_backend::list_tzap_index_with_optional_password(path, open_options.password.as_deref()),
        }
        .map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?
        .entries;
        let index = usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?;
        let entry =
            entries.get(index).ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "retained TZAP entry ID is not present in this archive"))?;
        let destination_path = options.destination.join(entry.path.replace('\\', "/").trim_matches('/'));
        if matches!(entry.kind, tzap_backend::TzapEntryKind::Directory) {
            std::fs::create_dir_all(&destination_path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
            return Ok(ExtractReport { written_entries: 1, ..ExtractReport::default() });
        }
        if !matches!(entry.kind, tzap_backend::TzapEntryKind::File) {
            return Ok(ExtractReport {
                skipped_entries: 1,
                warnings: vec![format!("skipped unsupported TZAP entry {}", entry.path)],
                ..ExtractReport::default()
            });
        }
        let key = open_options.recipient_key_path().map_or_else(
            || tzap_backend::TzapExtractKeySource::Password(open_options.password.as_deref().unwrap_or("")),
            tzap_backend::TzapExtractKeySource::RecipientKeyPath,
        );
        let report = tzap_backend::extract_tzap_file_to_destination(
            path,
            key,
            &entry.path,
            &destination_path,
            options.policy.overwrite == crate::safety::OverwritePolicy::Replace,
            options.tzap_restore_options.unwrap_or_default(),
        )
        .map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        let Some(report) = report else {
            return Ok(ExtractReport { skipped_entries: 1, ..ExtractReport::default() });
        };
        Ok(ExtractReport { written_entries: 1, written_bytes: report.written_bytes, warnings: report.metadata_diagnostics, ..ExtractReport::default() })
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let entries = match open_options.recipient_key_path() {
            Some(recipient_key) => tzap_backend::list_tzap_index_with_recipient_key(path, recipient_key),
            None => tzap_backend::list_tzap_index_with_optional_password(path, open_options.password.as_deref()),
        }
        .map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?
        .entries;
        let index = usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?;
        let entry =
            entries.get(index).ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "retained TZAP entry ID is not present in this archive"))?;
        let key = open_options.recipient_key_path().map_or_else(
            || tzap_backend::TzapExtractKeySource::Password(open_options.password.as_deref().unwrap_or("")),
            tzap_backend::TzapExtractKeySource::RecipientKeyPath,
        );
        let report =
            tzap_backend::copy_tzap_file_to_writer(path, key, &entry.path, writer).map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        Ok(CopyReport { written_bytes: report.written_bytes })
    }
}

// --- RAR ---
static RAR_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_rar_lister",
    format: FormatId::RAR,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: true,
};

/// Exclusive Native RAR listing adapter factory (ARC-208).
#[derive(Debug, Default)]
pub struct RarListAdapter;

impl ReadAdapterFactory for RarListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &RAR_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let listing = rar_backend::list_rar_with_password(primary_path, options.password.as_deref()).map_err(|err| {
            let msg = err.to_string();
            let lower = msg.to_lowercase();
            if lower.contains("password") {
                // The existing RAR bridge intentionally reports both a missing
                // and a rejected password as invalid_password; preserve that
                // compatibility while keeping the distinction for formats
                // whose backends expose it.
                ArchiveError::usable(ErrorKind::WrongPassword, msg)
            } else {
                ArchiveError::usable(ErrorKind::InvalidFormat, msg)
            }
            .with_path(primary_path)
        })?;

        let entries = listing
            .entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: EntryId(u64::try_from(index).unwrap_or(0)),
                path: entry.path,
                kind: match entry.kind {
                    rar_backend::RarListEntryKind::File => BrowserEntryKind::File,
                    rar_backend::RarListEntryKind::FileCopy => BrowserEntryKind::FileCopy,
                    rar_backend::RarListEntryKind::Directory => BrowserEntryKind::Directory,
                    rar_backend::RarListEntryKind::Symlink => BrowserEntryKind::Symlink,
                    rar_backend::RarListEntryKind::Hardlink => BrowserEntryKind::Hardlink,
                    rar_backend::RarListEntryKind::Special => BrowserEntryKind::Special,
                },
                size: Some(entry.size),
                compressed_size: None,
                modified: None,
                mode: None,
                encrypted: Some(entry.encrypted),
                method: None,
                crc: None,
                comment: None,
                link_target: entry.link_target,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn test(&self, archive: &DetectedArchive, open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = rar_backend::test_rar_with_password_filter(path, open_options.password.as_deref(), |entry_path| test_options.selects(entry_path))
            .map_err(|error| {
                let message = error.to_string();
                let kind = if message.to_lowercase().contains("password") {
                    ErrorKind::WrongPassword
                } else if matches!(error, rar_backend::RarBackendError::Io { .. }) {
                    ErrorKind::Io
                } else {
                    ErrorKind::CorruptData
                };
                let disposition = if kind == ErrorKind::CorruptData { SessionDisposition::Unusable } else { SessionDisposition::Usable };
                ArchiveError { kind, message, disposition, path: Some(path.to_path_buf()) }
            })?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.tested_entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.tested_bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            rar_backend::extract_rar_with_overwrite_resolver_and_password(
                path,
                &options.destination,
                options.policy.clone(),
                open_options.password.as_deref(),
                resolver,
            )
        } else {
            rar_backend::extract_rar_with_password(path, &options.destination, options.policy.clone(), open_options.password.as_deref())
        }
        .map_err(|error| {
            let message = error.to_string();
            let lower = message.to_lowercase();
            let kind = if lower.contains("password") {
                ErrorKind::WrongPassword
            } else if matches!(error, rar_backend::RarBackendError::Io { .. }) {
                ErrorKind::Io
            } else {
                ErrorKind::CorruptData
            };
            ArchiveError {
                kind,
                message,
                disposition: if matches!(kind, ErrorKind::CorruptData) { SessionDisposition::Unusable } else { SessionDisposition::Usable },
                path: Some(path.to_path_buf()),
            }
        })?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn selected_extract<'a>(
        &self,
        archive: &DetectedArchive,
        open_options: &OpenOptions,
        entry_id: EntryId,
        options: &'a mut SelectedExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = rar_backend::extract_rar_entry_by_index(
            path,
            &options.destination,
            options.policy.clone(),
            open_options.password.as_deref(),
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            options.overwrite_resolver.as_deref_mut(),
        )
        .map_err(|error| {
            let message = error.to_string();
            let kind = if message.to_lowercase().contains("password") {
                ErrorKind::WrongPassword
            } else if matches!(error, rar_backend::RarBackendError::Io { .. }) {
                ErrorKind::Io
            } else {
                ErrorKind::CorruptData
            };
            ArchiveError {
                kind,
                message,
                disposition: if kind == ErrorKind::CorruptData { SessionDisposition::Unusable } else { SessionDisposition::Usable },
                path: Some(path.to_path_buf()),
            }
        })?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let written_bytes = rar_backend::copy_rar_entry_by_index(
            path,
            open_options.password.as_deref(),
            usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?,
            writer,
        )
        .map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        Ok(CopyReport { written_bytes })
    }
}

// --- Raw Streams ---
static RAW_STREAM_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_raw_stream_lister",
    format: FormatId::RAW_STREAM,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native Raw Stream listing adapter factory.
#[derive(Debug, Default)]
pub struct RawStreamListAdapter;

impl ReadAdapterFactory for RawStreamListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &RAW_STREAM_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let format = raw_stream_backend::detect_raw_stream_format(primary_path)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Not a recognized raw compression stream").with_path(primary_path))?;

        let payload_name = raw_stream_backend::output_name_for_raw_stream(primary_path, format)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Could not determine raw stream output name").with_path(primary_path))?;

        let metadata = std::fs::metadata(primary_path).map_err(|err| ArchiveError::usable(ErrorKind::Io, err.to_string()).with_path(primary_path))?;

        let entry = EngineEntry {
            id: EntryId(0),
            path: payload_name,
            kind: BrowserEntryKind::File,
            size: None,
            compressed_size: Some(metadata.len()),
            modified: metadata.modified().ok().and_then(system_time_string),
            mode: None,
            encrypted: Some(false),
            method: Some(format.name().to_owned()),
            crc: None,
            comment: None,
            link_target: None,
            ..EngineEntry::default()
        };

        Ok(ArchiveListing { entries: vec![entry] })
    }

    fn test(&self, archive: &DetectedArchive, _open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let format = raw_stream_backend::detect_raw_stream_format(path)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Not a recognized raw compression stream").with_path(path))?;
        let payload_name = raw_stream_backend::output_name_for_raw_stream(path, format)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Could not determine raw stream output name").with_path(path))?;
        if !test_options.selects(&payload_name) {
            return Ok(TestReport { tested_entries: 0, skipped_entries: 1, tested_bytes: 0, warnings: Vec::new() });
        }
        let tested_bytes = raw_stream_backend::test_raw_stream(path, format).map_err(|error| ArchiveError {
            kind: ErrorKind::CorruptData,
            message: error.to_string(),
            disposition: SessionDisposition::Unusable,
            path: Some(path.to_path_buf()),
        })?;
        Ok(TestReport { tested_entries: 1, skipped_entries: 0, tested_bytes, warnings: Vec::new() })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let format = raw_stream_backend::detect_raw_stream_format(path)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Not a recognized raw compression stream").with_path(path))?;
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            raw_stream_backend::extract_raw_stream_with_overwrite_resolver(path, format, &options.destination, options.policy.clone(), resolver)
        } else {
            raw_stream_backend::extract_raw_stream(path, format, &options.destination, options.policy.clone())
        }
        .map_err(|error| {
            let kind = match error {
                raw_stream_backend::RawStreamError::Safety(ref source) => crate::engine::adapters::safety_error_kind(source),
                raw_stream_backend::RawStreamError::Io { .. } => ErrorKind::Io,
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

    fn selected_extract<'a>(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        options: &'a mut SelectedExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        if entry_id != EntryId(0) {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "raw stream contains only entry #0"));
        }
        let path = archive.source.primary_path();
        let format = raw_stream_backend::detect_raw_stream_format(path)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Not a recognized raw compression stream").with_path(path))?;
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            raw_stream_backend::extract_raw_stream_with_overwrite_resolver(path, format, &options.destination, options.policy.clone(), resolver)
        } else {
            raw_stream_backend::extract_raw_stream(path, format, &options.destination, options.policy.clone())
        }
        .map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        _open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        if entry_id != EntryId(0) {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "raw stream contains only entry #0"));
        }
        let path = archive.source.primary_path();
        let format = raw_stream_backend::detect_raw_stream_format(path)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Not a recognized raw compression stream").with_path(path))?;
        let written_bytes =
            raw_stream_backend::copy_raw_stream_to_writer(path, format, writer).map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        Ok(CopyReport { written_bytes })
    }
}

// --- Apple Archive ---
static APPLE_ARCHIVE_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_apple_archive_lister",
    format: FormatId::APPLE_ARCHIVE,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: true,
};

/// Native Apple Archive listing adapter factory.
#[derive(Debug, Default)]
pub struct AppleArchiveListAdapter;

impl ReadAdapterFactory for AppleArchiveListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &APPLE_ARCHIVE_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let listing = apple_archive_backend::list_apple_archive(primary_path, options.password.as_deref())
            .map_err(|err| ArchiveError::usable(ErrorKind::InvalidFormat, err.to_string()).with_path(primary_path))?;

        let entries = listing
            .entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: EntryId(u64::try_from(index).unwrap_or(0)),
                path: entry.path,
                kind: match entry.kind {
                    apple_archive_backend::AppleArchiveEntryKind::File => BrowserEntryKind::File,
                    apple_archive_backend::AppleArchiveEntryKind::Directory => BrowserEntryKind::Directory,
                    apple_archive_backend::AppleArchiveEntryKind::Symlink => BrowserEntryKind::Symlink,
                    apple_archive_backend::AppleArchiveEntryKind::Device | apple_archive_backend::AppleArchiveEntryKind::Special => BrowserEntryKind::Special,
                },
                size: entry.size,
                compressed_size: None,
                modified: entry.modified.and_then(system_time_string),
                mode: entry.mode,
                encrypted: Some(false),
                method: None,
                crc: entry.crc,
                comment: None,
                link_target: entry.link_target,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn test(&self, archive: &DetectedArchive, open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = apple_archive_backend::test_apple_archive_filter(path, |entry_path| test_options.selects(entry_path), open_options.password.as_deref())
            .map_err(|error| {
                let kind = match error {
                    apple_archive_backend::AppleArchiveError::Unsupported => ErrorKind::UnsupportedOperation,
                    apple_archive_backend::AppleArchiveError::Cancelled => ErrorKind::Cancelled,
                    apple_archive_backend::AppleArchiveError::Io { .. } => ErrorKind::Io,
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
        let path = archive.source.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            apple_archive_backend::extract_apple_archive_with_overwrite_resolver(
                path,
                &options.destination,
                options.policy.clone(),
                resolver,
                open_options.password.as_deref(),
            )
        } else {
            apple_archive_backend::extract_apple_archive(path, &options.destination, options.policy.clone(), open_options.password.as_deref())
        }
        .map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn selected_extract<'a>(
        &self,
        archive: &DetectedArchive,
        open_options: &OpenOptions,
        entry_id: EntryId,
        options: &'a mut SelectedExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let entries = apple_archive_backend::list_apple_archive(path, open_options.password.as_deref())
            .map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        let index = usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?;
        let entry =
            entries.entries.get(index).ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "retained Apple Archive entry ID is not present"))?;
        let report = apple_archive_backend::extract_apple_archive_entry(
            path,
            &entry.path,
            &options.destination,
            options.policy.clone(),
            open_options.password.as_deref(),
        )
        .map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn copy_to_writer(
        &self,
        archive: &DetectedArchive,
        open_options: &OpenOptions,
        entry_id: EntryId,
        writer: &mut dyn std::io::Write,
    ) -> Result<CopyReport, ArchiveError> {
        let path = archive.source.primary_path();
        let index = usize::try_from(entry_id.0).map_err(|_| ArchiveError::usable(ErrorKind::InvalidFormat, "entry ID does not fit the native index"))?;
        let mut current = 0_usize;
        let report = apple_archive_backend::copy_apple_archive_files_to_writer(
            path,
            |entry_path| {
                let selected = current == index;
                current = current.saturating_add(1);
                selected && !entry_path.is_empty()
            },
            writer,
            open_options.password.as_deref(),
        )
        .map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        Ok(CopyReport { written_bytes: report.written_bytes })
    }
}

// --- DMG ---
static DMG_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_dmg_lister",
    format: FormatId::DMG,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native DMG listing adapter factory.
#[derive(Debug, Default)]
pub struct DmgListAdapter;

impl ReadAdapterFactory for DmgListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &DMG_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let raw_entries =
            apple_dmg_backend::list_dmg(primary_path).map_err(|err| ArchiveError::usable(ErrorKind::InvalidFormat, err.to_string()).with_path(primary_path))?;

        let entries = raw_entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: EntryId(u64::try_from(index).unwrap_or(0)),
                path: entry.path,
                kind: BrowserEntryKind::File,
                size: Some(entry.size),
                compressed_size: None,
                modified: None,
                mode: None,
                encrypted: Some(false),
                method: None,
                crc: None,
                comment: None,
                link_target: None,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            apple_dmg_backend::extract_dmg_with_overwrite_resolver(path, &options.destination, options.policy.clone(), resolver)
        } else {
            apple_dmg_backend::extract_dmg(path, &options.destination, options.policy.clone())
        }
        .map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }
}

// --- PKG ---
static PKG_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_pkg_lister",
    format: FormatId::PKG,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native PKG listing adapter factory.
#[derive(Debug, Default)]
pub struct PkgListAdapter;

impl ReadAdapterFactory for PkgListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &PKG_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let raw_entries =
            apple_pkg_backend::list_pkg(primary_path).map_err(|err| ArchiveError::usable(ErrorKind::InvalidFormat, err.to_string()).with_path(primary_path))?;

        let entries = raw_entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: EntryId(u64::try_from(index).unwrap_or(0)),
                path: entry.path,
                kind: BrowserEntryKind::File,
                size: Some(entry.size),
                compressed_size: None,
                modified: None,
                mode: None,
                encrypted: Some(false),
                method: None,
                crc: None,
                comment: None,
                link_target: None,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            apple_pkg_backend::extract_pkg_with_overwrite_resolver(path, &options.destination, options.policy.clone(), resolver)
        } else {
            apple_pkg_backend::extract_pkg(path, &options.destination, options.policy.clone())
        }
        .map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }
}

// --- MSI ---
static MSI_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_msi_lister",
    format: FormatId::MSI,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native MSI listing adapter factory.
#[derive(Debug, Default)]
pub struct MsiListAdapter;

impl ReadAdapterFactory for MsiListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &MSI_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let raw_entries =
            msi_backend::list_msi(primary_path).map_err(|err| ArchiveError::usable(ErrorKind::InvalidFormat, err.to_string()).with_path(primary_path))?;

        let entries = raw_entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: EntryId(u64::try_from(index).unwrap_or(0)),
                path: entry.path,
                kind: BrowserEntryKind::File,
                size: Some(entry.size),
                compressed_size: None,
                modified: None,
                mode: None,
                encrypted: Some(false),
                method: None,
                crc: None,
                comment: None,
                link_target: None,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            msi_backend::extract_msi_with_overwrite_resolver(path, &options.destination, options.policy.clone(), resolver)
        } else {
            msi_backend::extract_msi(path, &options.destination, options.policy.clone())
        }
        .map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }
}

// --- Virtual Disks (VHD, VMDK, UDF) ---
/// Native Virtual Disk listing adapter factory.
#[derive(Debug)]
pub struct VirtualDiskListAdapter {
    format: FormatId,
}

impl VirtualDiskListAdapter {
    /// Creates a virtual disk listing adapter for VHD, VMDK, or UDF.
    #[must_use]
    pub const fn new(format: FormatId) -> Self {
        Self { format }
    }
}

impl ReadAdapterFactory for VirtualDiskListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        Box::leak(Box::new(AdapterDescriptor {
            name: "native_virtual_disk_lister",
            format: self.format,
            operations: &[ArchiveOperation::List, ArchiveOperation::Extract],
            required_source_access: SourceAccess::Seekable,
            supports_encryption: false,
        }))
    }

    fn list(&self, archive: &DetectedArchive, _options: &OpenOptions) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let raw_entries = match self.format {
            FormatId::VHD => virtual_disk_backend::list_vhd(primary_path).map_err(|err| err.to_string()),
            FormatId::VMDK => virtual_disk_backend::list_vmdk(primary_path).map_err(|err| err.to_string()),
            FormatId::UDF => virtual_disk_backend::list_udf(primary_path).map_err(|err| err.to_string()),
            _ => Err(format!("Unsupported virtual disk format '{}'", self.format)),
        }
        .map_err(|err| ArchiveError::usable(ErrorKind::InvalidFormat, err).with_path(primary_path))?;

        let entries = raw_entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: EntryId(u64::try_from(index).unwrap_or(0)),
                path: entry.path,
                kind: BrowserEntryKind::File,
                size: Some(entry.size),
                compressed_size: None,
                modified: None,
                mode: None,
                encrypted: Some(false),
                method: None,
                crc: None,
                comment: None,
                link_target: None,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn extract<'a>(&self, archive: &DetectedArchive, _open_options: &OpenOptions, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.source.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            match self.format {
                FormatId::VHD => virtual_disk_backend::extract_vhd_with_overwrite_resolver(path, &options.destination, options.policy.clone(), resolver),
                FormatId::VMDK => virtual_disk_backend::extract_vmdk_with_overwrite_resolver(path, &options.destination, options.policy.clone(), resolver),
                FormatId::UDF => virtual_disk_backend::extract_udf_with_overwrite_resolver(path, &options.destination, options.policy.clone(), resolver),
                _ => return Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, format!("Unsupported virtual disk format '{}'", self.format))),
            }
        } else {
            virtual_disk_backend::extract_virtual_disk(path, &options.destination, options.policy.clone())
        }
        .map_err(|error| crate::engine::adapters::extract_error(path, error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }
}
