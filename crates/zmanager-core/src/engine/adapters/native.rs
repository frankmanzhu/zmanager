//! Native listing adapters for 7z, TAR.ZST, TZAP, RAR, `RawStreams`, Apple Archive, DMG, PKG, MSI, `VirtualDisks` (ARC-200).

use std::fs::File;
use std::time::{SystemTime, UNIX_EPOCH};
use tar::Archive as TarArchive;

use crate::apple_archive_backend;
use crate::apple_dmg_backend;
use crate::apple_pkg_backend;
use crate::archive_browser::BrowserEntryKind;
use crate::engine::format::FormatId;
use crate::engine::registry::{AdapterDescriptor, ReadAdapterFactory};
use crate::engine::source::SourceAccess;
use crate::engine::types::{
    ArchiveError, ArchiveListing, ArchiveOperation, DetectedArchive, EngineEntry, EntryId, ErrorKind, OpenOptions, SessionDisposition, TestOptions, TestReport,
};
use crate::msi_backend;
use crate::rar_backend;
use crate::raw_stream_backend;
use crate::sevenz_backend;
use crate::tzap_backend;
use crate::virtual_disk_backend;

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
        sevenz_backend::SevenZError::Safety(source) => ArchiveError::unusable(ErrorKind::SafetyViolation, source.to_string()).with_path(path),
        sevenz_backend::SevenZError::Cancelled => ArchiveError::usable(ErrorKind::UnsupportedOperation, "7z listing was cancelled").with_path(path),
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
    operations: &[ArchiveOperation::List, ArchiveOperation::Test],
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
}

// --- TAR.ZST ---
static TAR_ZST_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_zst_lister",
    format: FormatId::TAR_ZST,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test],
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
        let primary_path = archive.source.primary_path();
        let file = File::open(primary_path).map_err(|err| ArchiveError::usable(ErrorKind::Io, err.to_string()).with_path(primary_path))?;
        let decoder =
            zstd::stream::read::Decoder::new(file).map_err(|err| ArchiveError::usable(ErrorKind::InvalidFormat, err.to_string()).with_path(primary_path))?;
        let mut tar_archive = TarArchive::new(decoder);

        let mut entries = Vec::new();
        let raw_entries = tar_archive.entries().map_err(|err| ArchiveError::usable(ErrorKind::InvalidFormat, err.to_string()).with_path(primary_path))?;

        for (index, entry) in raw_entries.enumerate() {
            let entry = entry.map_err(|err| ArchiveError::unusable(ErrorKind::CorruptData, err.to_string()).with_path(primary_path))?;
            let path = entry
                .path()
                .map_err(|err| ArchiveError::unusable(ErrorKind::CorruptData, err.to_string()).with_path(primary_path))?
                .to_string_lossy()
                .into_owned();

            let header = entry.header();
            let kind = if header.entry_type().is_dir() {
                BrowserEntryKind::Directory
            } else if header.entry_type().is_symlink() {
                BrowserEntryKind::Symlink
            } else if header.entry_type().is_hard_link() {
                BrowserEntryKind::Hardlink
            } else {
                BrowserEntryKind::File
            };

            entries.push(EngineEntry {
                id: EntryId(u64::try_from(index).unwrap_or(0)),
                path,
                kind,
                size: header.size().ok(),
                compressed_size: None,
                modified: header.mtime().ok().map(|m| m.to_string()),
                mode: header.mode().ok(),
                encrypted: Some(false),
                method: Some("zstd".to_owned()),
                crc: None,
                comment: None,
                link_target: entry.link_name().ok().flatten().map(|p| p.to_string_lossy().into_owned()),
                ..EngineEntry::default()
            });
        }

        Ok(ArchiveListing { entries })
    }

    fn test(&self, archive: &DetectedArchive, _open_options: &OpenOptions, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.source.primary_path();
        let mut sink = std::io::sink();
        let report = crate::tar_zst_backend::copy_tar_zst_files_to_writer(path, |entry_path| test_options.selects(entry_path), &mut sink).map_err(|error| {
            let kind = match error {
                crate::tar_zst_backend::TarZstdError::Io { .. } => ErrorKind::Io,
                crate::tar_zst_backend::TarZstdError::Cancelled => ErrorKind::Cancelled,
                _ => ErrorKind::CorruptData,
            };
            let disposition = if kind == ErrorKind::CorruptData { SessionDisposition::Unusable } else { SessionDisposition::Usable };
            ArchiveError { kind, message: error.to_string(), disposition, path: Some(path.to_path_buf()) }
        })?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.written_entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.written_bytes,
            warnings: report.warnings,
        })
    }
}

// --- TZAP ---
static TZAP_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tzap_lister",
    format: FormatId::TZAP,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test],
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
}

// --- RAR ---
static RAR_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_rar_lister",
    format: FormatId::RAR,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test],
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
}

// --- Raw Streams ---
static RAW_STREAM_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_raw_stream_lister",
    format: FormatId::RAW_STREAM,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test],
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
}

// --- Apple Archive ---
static APPLE_ARCHIVE_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_apple_archive_lister",
    format: FormatId::APPLE_ARCHIVE,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test],
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
}

// --- DMG ---
static DMG_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_dmg_lister",
    format: FormatId::DMG,
    operations: &[ArchiveOperation::List],
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
}

// --- PKG ---
static PKG_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_pkg_lister",
    format: FormatId::PKG,
    operations: &[ArchiveOperation::List],
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
}

// --- MSI ---
static MSI_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_msi_lister",
    format: FormatId::MSI,
    operations: &[ArchiveOperation::List],
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
            operations: &[ArchiveOperation::List],
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
}
