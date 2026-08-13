//! Native one-shot archive creation adapters (ARC-600/ARC-601).

use crate::engine::format::FormatId;
use crate::engine::registry::{AdapterDescriptor, CreateAdapterFactory};
use crate::engine::types::{ArchiveError, ArchiveOperation, CreateOptions, CreateReport, CreateRequest, ErrorKind};
use crate::jobs::JobContext;

fn creation_error(path: &std::path::Path, error: impl std::fmt::Display) -> ArchiveError {
    let message = error.to_string();
    let lower = message.to_lowercase();
    let kind = if lower.contains("cancel") {
        ErrorKind::Cancelled
    } else if lower.contains("unsupported") {
        ErrorKind::UnsupportedOperation
    } else if lower.contains("permission") || lower.contains("i/o") || lower.contains("io failed") {
        ErrorKind::Io
    } else {
        ErrorKind::InvalidFormat
    };
    ArchiveError::usable(kind, message).with_path(path)
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Native ZIP and split-ZIP writer.
#[derive(Debug, Default)]
pub struct ZipCreateAdapter;

impl CreateAdapterFactory for ZipCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_zip_creator",
            format: FormatId::ZIP,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: true,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::Zip(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "ZIP creator received non-ZIP options"));
        };
        let report = crate::zip_backend::create_zip_from_manifest_with_context(&request.manifest, &request.destination, options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::ZIP,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: Some(report.encrypted),
            solid: None,
            volume_size: report.volume_size,
            volume_count: count(report.volume_count),
            warnings: report.warnings,
        })
    }
}

/// Native standard split-ZIP writer.
#[derive(Debug, Default)]
pub struct SplitZipCreateAdapter;

impl CreateAdapterFactory for SplitZipCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_split_zip_creator",
            format: FormatId::SPLIT_ZIP,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: true,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::Zip(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "split ZIP creator received non-ZIP options"));
        };
        if options.volume_size.is_none() {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "split ZIP creation requires a volume size"));
        }
        let report = crate::zip_backend::create_zip_from_manifest_with_context(&request.manifest, &request.destination, options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::SPLIT_ZIP,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: Some(report.encrypted),
            solid: None,
            volume_size: report.volume_size,
            volume_count: count(report.volume_count),
            warnings: report.warnings,
        })
    }
}

/// Native 7z writer.
#[derive(Debug, Default)]
pub struct SevenZCreateAdapter;

impl CreateAdapterFactory for SevenZCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_7z_creator",
            format: FormatId::SEVEN_Z,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: true,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::SevenZ(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "7z creator received non-7z options"));
        };
        let report = crate::sevenz_backend::create_7z_from_manifest_with_context(&request.manifest, &request.destination, options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::SEVEN_Z,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: Some(report.encrypted),
            solid: Some(report.solid),
            volume_size: report.volume_size,
            volume_count: count(report.volume_count),
            warnings: report.warnings,
        })
    }
}

/// Native TAR.ZST writer.
#[derive(Debug, Default)]
pub struct TarZstdCreateAdapter;

impl CreateAdapterFactory for TarZstdCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_tar_zstd_creator",
            format: FormatId::TAR_ZST,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: false,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::TarZstd(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "TAR.ZST creator received non-TAR.ZST options"));
        };
        let report = crate::tar_zst_backend::create_tar_zst_from_manifest_with_context(&request.manifest, &request.destination, options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::TAR_ZST,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: None,
            solid: None,
            volume_size: None,
            volume_count: 1,
            warnings: report.warnings,
        })
    }
}

/// Native TAR.GZ writer.
#[derive(Debug, Default)]
pub struct TarGzCreateAdapter;

impl CreateAdapterFactory for TarGzCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_tar_gz_creator",
            format: FormatId::TAR_GZ,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: false,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::TarGz(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "TAR.GZ creator received non-TAR.GZ options"));
        };
        let report = crate::tar_gz_backend::create_tar_gz_from_manifest_with_context(&request.manifest, &request.destination, options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::TAR_GZ,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: None,
            solid: None,
            volume_size: None,
            volume_count: 1,
            warnings: report.warnings,
        })
    }
}

/// Native TZAP writer.
#[derive(Debug, Default)]
pub struct TzapCreateAdapter;

impl CreateAdapterFactory for TzapCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_tzap_creator",
            format: FormatId::TZAP,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: true,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::Tzap(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "TZAP creator received non-TZAP options"));
        };
        let report = crate::tzap_backend::create_tzap_from_manifest_with_context(&request.manifest, &request.destination, options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        let encrypted = !matches!(&options.key_source, crate::tzap_backend::TzapKeySource::NoPassword);
        Ok(CreateReport {
            format: FormatId::TZAP,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: Some(encrypted),
            solid: None,
            volume_size: report.volume_size,
            volume_count: count(report.volume_count),
            warnings: report.warnings,
        })
    }
}

/// Native Apple Archive writer.
#[derive(Debug, Default)]
pub struct AppleArchiveCreateAdapter;

impl CreateAdapterFactory for AppleArchiveCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_apple_archive_creator",
            format: FormatId::APPLE_ARCHIVE,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: true,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::AppleArchive(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "Apple Archive creator received non-Apple Archive options"));
        };
        let report = crate::apple_archive_backend::create_apple_archive_from_manifest_with_context(&request.manifest, &request.destination, options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::APPLE_ARCHIVE,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: Some(options.password.is_some()),
            solid: None,
            volume_size: None,
            volume_count: 1,
            warnings: report.warnings,
        })
    }
}
