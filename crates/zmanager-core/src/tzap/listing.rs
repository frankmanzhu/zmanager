//! TZAP archive listing: full listings decoded from member groups and fast
//! listings built from authenticated index metadata.

use super::TzapError;
use crate::tzap::metadata::metadata_diagnostic_labels;
use crate::tzap::open::{open_tzap_archive, open_tzap_archive_with_recipient_key};
use std::path::Path;
use tzap_core::format::KdfAlgo;
use tzap_core::reader::{ArchiveEntry, ArchiveIndexEntry};
use tzap_core::{OpenedArchive, TarEntryKind};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapListing {
    /// Listed entries.
    pub entries: Vec<TzapEntry>,
    /// Whether the archive is encrypted.
    pub encrypted: bool,
}

/// Fast `.tzap` listing built from authenticated index metadata.
///
/// This intentionally omits portable metadata that requires decoding every tar
/// member group. It is suitable for responsive browsing and exact-path lookup.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapIndexListing {
    /// Indexed entries.
    pub entries: Vec<TzapIndexEntry>,
    /// Whether the archive is encrypted.
    pub encrypted: bool,
    /// The key derivation algorithm used, if any.
    pub kdf_algo: tzap_core::format::KdfAlgo,
}

/// One `.tzap` entry described by authenticated index metadata.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapIndexEntry {
    /// Archive path.
    pub path: String,
    /// Entry kind. Ambiguous zero-byte leaves are decoded individually.
    pub kind: TzapEntryKind,
    /// Uncompressed file bytes.
    pub size: u64,
    /// Estimated compressed member-group bytes, derived from the whole-archive
    /// compression ratio rather than measured per entry.
    pub compressed_size: u64,
    /// Portable mode bits.
    pub mode: u32,
    /// Modification time as signed Unix seconds.
    pub mtime: i64,
    /// Nanosecond component of the modification time.
    pub mtime_nanoseconds: u32,
    /// Link target path.
    pub link_target: Option<String>,
    /// Creation time when present.
    pub created: Option<(i64, u32)>,
    /// Access time when present.
    pub accessed: Option<(i64, u32)>,
    /// BSD/macOS file flags.
    pub attributes: Option<u32>,
    /// User identifier.
    pub uid: Option<u64>,
    /// Group identifier.
    pub gid: Option<u64>,
    /// Owner name.
    pub uname: Option<String>,
    /// Group name.
    pub gname: Option<String>,
}

/// One `.tzap` archive entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapEntry {
    /// Archive path.
    pub path: String,
    /// Entry kind.
    pub kind: TzapEntryKind,
    /// Uncompressed file bytes.
    pub size: u64,
    /// Portable mode bits.
    pub mode: u32,
    /// Modification time as signed Unix seconds.
    pub mtime: i64,
    /// Nanosecond component of the modification time.
    pub mtime_nanoseconds: u32,
    /// Authenticated metadata diagnostics reported by `tzap`.
    pub metadata_diagnostics: Vec<String>,
    /// Link target path.
    pub link_target: Option<String>,
    /// Creation time when present.
    pub created: Option<(i64, u32)>,
    /// Access time when present.
    pub accessed: Option<(i64, u32)>,
    /// BSD/macOS file flags.
    pub attributes: Option<u32>,
    /// User identifier.
    pub uid: Option<u32>,
    /// Group identifier.
    pub gid: Option<u32>,
    /// Owner name.
    pub owner: Option<String>,
    /// Group name.
    pub group: Option<String>,
}

/// Public entry kind for `.tzap` listings.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TzapEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Hard link.
    Hardlink,
    /// POSIX character device.
    CharacterDevice,
    /// POSIX block device.
    BlockDevice,
    /// POSIX FIFO.
    Fifo,
}

/// Lists `.tzap` archive entries with a passphrase.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or listed.
pub fn list_tzap_with_password(archive: impl AsRef<Path>, password: &str) -> Result<TzapListing, TzapError> {
    list_tzap_with_optional_password(archive, Some(password))
}

/// Lists `.tzap` archive entries with an optional passphrase.
///
/// When `password` is [`None`], unencrypted archives are opened without a key,
/// and legacy no-secret raw-key archives are opened with tzap's all-zero key.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or listed.
pub fn list_tzap_with_optional_password(archive: impl AsRef<Path>, password: Option<&str>) -> Result<TzapListing, TzapError> {
    let archive_path = archive.as_ref();
    let opened = open_tzap_archive(archive_path, password)?;
    let encrypted = password.is_some() || opened.crypto_header.kdf_algo != KdfAlgo::None;
    list_opened_tzap_archive(&opened, encrypted)
}

/// Lists `.tzap` archive entries from authenticated index metadata.
///
/// Unlike [`list_tzap_with_optional_password`], this does not decode every
/// payload member group to obtain display-only metadata. Directory paths with
/// descendants are identified from the index; only ambiguous zero-byte leaves
/// are decoded to distinguish empty files, empty directories, and links.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or indexed.
pub fn list_tzap_index_with_optional_password(archive: impl AsRef<Path>, password: Option<&str>) -> Result<TzapIndexListing, TzapError> {
    let archive_path = archive.as_ref();
    let opened = open_tzap_archive(archive_path, password)?;
    let encrypted = password.is_some() || opened.crypto_header.kdf_algo != KdfAlgo::None;
    let indexed = opened.list_index_entries()?;
    Ok(map_index_entries(indexed, opened.observed_archive_bytes(), encrypted, opened.crypto_header.kdf_algo))
}

/// Lists only the immediate children of the requested directory.
pub fn list_tzap_directory_with_optional_password(archive: impl AsRef<Path>, dir_path: &str, password: Option<&str>) -> Result<TzapIndexListing, TzapError> {
    let archive_path = archive.as_ref();
    let opened = open_tzap_archive(archive_path, password)?;
    let encrypted = password.is_some() || opened.crypto_header.kdf_algo != KdfAlgo::None;
    let indexed = opened.list_directory_contents(dir_path)?;
    Ok(map_index_entries(indexed, opened.observed_archive_bytes(), encrypted, opened.crypto_header.kdf_algo))
}

/// Lists recipient-wrapped `.tzap` archive entries with a private key.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or listed.
pub fn list_tzap_with_recipient_key(archive: impl AsRef<Path>, recipient_private_key: impl AsRef<Path>) -> Result<TzapListing, TzapError> {
    let opened = open_tzap_archive_with_recipient_key(archive, recipient_private_key)?;
    list_opened_tzap_archive(&opened, true)
}

pub fn list_tzap_index_with_recipient_key(archive: impl AsRef<Path>, recipient_private_key: impl AsRef<Path>) -> Result<TzapIndexListing, TzapError> {
    let opened = open_tzap_archive_with_recipient_key(archive, recipient_private_key)?;
    let indexed = opened.list_index_entries()?;
    Ok(map_index_entries(indexed, opened.observed_archive_bytes(), true, opened.crypto_header.kdf_algo))
}

/// Maps authenticated index entries into a [`TzapIndexListing`].
///
/// Per-entry `compressed_size` is estimated from the whole-archive compression
/// ratio rather than measured per member group, matching the index listing's
/// promise of avoiding payload decoding.
fn map_index_entries(indexed: Vec<ArchiveIndexEntry>, observed_archive_bytes: u64, encrypted: bool, kdf_algo: KdfAlgo) -> TzapIndexListing {
    let total_uncompressed_size: u64 = indexed.iter().map(|entry| entry.file_data_size).sum();

    let mut entries = Vec::with_capacity(indexed.len());
    for entry in indexed {
        let kind = match entry.kind {
            tzap_core::tar_model::TarEntryKind::Directory => TzapEntryKind::Directory,
            tzap_core::tar_model::TarEntryKind::Symlink => TzapEntryKind::Symlink,
            tzap_core::tar_model::TarEntryKind::Hardlink => TzapEntryKind::Hardlink,
            tzap_core::tar_model::TarEntryKind::CharacterDevice => TzapEntryKind::CharacterDevice,
            tzap_core::tar_model::TarEntryKind::BlockDevice => TzapEntryKind::BlockDevice,
            tzap_core::tar_model::TarEntryKind::Fifo => TzapEntryKind::Fifo,
            tzap_core::tar_model::TarEntryKind::Regular => TzapEntryKind::File,
        };
        entries.push(TzapIndexEntry {
            path: entry.path,
            kind,
            size: entry.file_data_size,
            compressed_size: if entry.file_data_size > 0 {
                // Ratio-based estimate; u128 keeps the multiplication exact
                // (an entry larger than `total_uncompressed_size` would
                // overflow u64). `entry.file_data_size > 0` implies the total
                // is non-zero, so this division never divides by zero.
                u64::try_from(u128::from(entry.file_data_size) * u128::from(observed_archive_bytes) / u128::from(total_uncompressed_size)).unwrap_or(u64::MAX)
            } else {
                0
            },
            mode: entry.mode,
            mtime: entry.mtime.seconds,
            mtime_nanoseconds: entry.mtime.nanoseconds,
            link_target: entry.link_target,
            created: entry.created.map(|t| (t.seconds, t.nanoseconds)),
            accessed: entry.accessed.map(|t| (t.seconds, t.nanoseconds)),
            attributes: entry.attributes,
            uid: entry.uid,
            gid: entry.gid,
            uname: entry.uname,
            gname: entry.gname,
        });
    }
    TzapIndexListing { entries, encrypted, kdf_algo }
}

fn list_opened_tzap_archive(opened: &OpenedArchive, encrypted: bool) -> Result<TzapListing, TzapError> {
    let entries = opened.list_files()?.into_iter().map(tzap_entry_from_archive_entry).collect();
    Ok(TzapListing { entries, encrypted })
}

fn tzap_entry_from_archive_entry(entry: ArchiveEntry) -> TzapEntry {
    TzapEntry {
        path: entry.path,
        kind: tzap_entry_kind_from_member_kind(entry.kind),
        size: entry.file_data_size,
        mode: entry.mode,
        mtime: entry.mtime.seconds,
        mtime_nanoseconds: entry.mtime.nanoseconds,
        metadata_diagnostics: metadata_diagnostic_labels(&entry.diagnostics),
        link_target: entry.link_target,
        created: entry.created.map(|t| (t.seconds, t.nanoseconds)),
        accessed: entry.accessed.map(|t| (t.seconds, t.nanoseconds)),
        attributes: entry.attributes,
        uid: entry.uid.and_then(|u| u32::try_from(u).ok()),
        gid: entry.gid.and_then(|g| u32::try_from(g).ok()),
        owner: entry.uname,
        group: entry.gname,
    }
}

fn tzap_entry_kind_from_member_kind(kind: TarEntryKind) -> TzapEntryKind {
    match kind {
        TarEntryKind::Regular => TzapEntryKind::File,
        TarEntryKind::Directory => TzapEntryKind::Directory,
        TarEntryKind::Symlink => TzapEntryKind::Symlink,
        TarEntryKind::Hardlink => TzapEntryKind::Hardlink,
        TarEntryKind::CharacterDevice => TzapEntryKind::CharacterDevice,
        TarEntryKind::BlockDevice => TzapEntryKind::BlockDevice,
        TarEntryKind::Fifo => TzapEntryKind::Fifo,
    }
}
