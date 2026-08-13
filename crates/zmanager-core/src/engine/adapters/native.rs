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
use crate::engine::types::{ArchiveError, ArchiveListing, ArchiveOperation, DetectedArchive, EngineEntry, EntryId, ErrorKind};
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

// --- 7z ---
static SEVEN_Z_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_7z_lister",
    format: FormatId::SEVEN_Z,
    operations: &[ArchiveOperation::List],
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

    fn list(&self, archive: &DetectedArchive, password: Option<&str>) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let listing = sevenz_backend::list_7z(primary_path, password)
            .map_err(|err| ArchiveError::usable(ErrorKind::InvalidFormat, err.to_string()).with_path(primary_path))?;

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
            })
            .collect();

        Ok(ArchiveListing { entries })
    }
}

// --- TAR.ZST ---
static TAR_ZST_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_zst_lister",
    format: FormatId::TAR_ZST,
    operations: &[ArchiveOperation::List],
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

    fn list(&self, archive: &DetectedArchive, _password: Option<&str>) -> Result<ArchiveListing, ArchiveError> {
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
            });
        }

        Ok(ArchiveListing { entries })
    }
}

// --- TZAP ---
static TZAP_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tzap_lister",
    format: FormatId::TZAP,
    operations: &[ArchiveOperation::List],
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

    fn list(&self, archive: &DetectedArchive, password: Option<&str>) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let listing = tzap_backend::list_tzap_index_with_optional_password(primary_path, password)
            .map_err(|err| ArchiveError::usable(ErrorKind::InvalidFormat, err.to_string()).with_path(primary_path))?;

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
                modified: Some(entry.mtime.to_string()),
                mode: Some(entry.mode),
                encrypted: Some(true),
                method: None,
                crc: None,
                comment: None,
                link_target: entry.link_target,
            })
            .collect();

        Ok(ArchiveListing { entries })
    }
}

// --- RAR ---
static RAR_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_rar_lister",
    format: FormatId::RAR,
    operations: &[ArchiveOperation::List],
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

    fn list(&self, archive: &DetectedArchive, password: Option<&str>) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let listing = rar_backend::list_rar_with_password(primary_path, password).map_err(|err| {
            let msg = err.to_string();
            let lower = msg.to_lowercase();
            if lower.contains("password") {
                if password.is_some() { ArchiveError::usable(ErrorKind::WrongPassword, msg) } else { ArchiveError::usable(ErrorKind::PasswordRequired, msg) }
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
            })
            .collect();

        Ok(ArchiveListing { entries })
    }
}

// --- Raw Streams ---
static RAW_STREAM_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_raw_stream_lister",
    format: FormatId::RAW_STREAM,
    operations: &[ArchiveOperation::List],
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

    fn list(&self, archive: &DetectedArchive, _password: Option<&str>) -> Result<ArchiveListing, ArchiveError> {
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
        };

        Ok(ArchiveListing { entries: vec![entry] })
    }
}

// --- Apple Archive ---
static APPLE_ARCHIVE_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_apple_archive_lister",
    format: FormatId::APPLE_ARCHIVE,
    operations: &[ArchiveOperation::List],
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

    fn list(&self, archive: &DetectedArchive, password: Option<&str>) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.source.primary_path();
        let listing = apple_archive_backend::list_apple_archive(primary_path, password)
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
            })
            .collect();

        Ok(ArchiveListing { entries })
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

    fn list(&self, archive: &DetectedArchive, _password: Option<&str>) -> Result<ArchiveListing, ArchiveError> {
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

    fn list(&self, archive: &DetectedArchive, _password: Option<&str>) -> Result<ArchiveListing, ArchiveError> {
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

    fn list(&self, archive: &DetectedArchive, _password: Option<&str>) -> Result<ArchiveListing, ArchiveError> {
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

    fn list(&self, archive: &DetectedArchive, _password: Option<&str>) -> Result<ArchiveListing, ArchiveError> {
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
            })
            .collect();

        Ok(ArchiveListing { entries })
    }
}
