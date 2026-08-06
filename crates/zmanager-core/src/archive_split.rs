//! Shared split-archive destination handling for the ZIP and 7z backends.
//!
//! Both backends split output into numbered volumes and guard their
//! destinations with the same existence/replace checks. These helpers were
//! previously copied into each backend with a different error type; the
//! `io::Result`-based versions here keep the checks in one place and each
//! backend maps errors into its own error enum.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use filetime::FileTime;

/// Number of volumes needed for `archive_size` bytes at `volume_size` each.
#[must_use]
pub(crate) fn split_volume_count(archive_size: u64, volume_size: u64) -> Option<usize> {
    let count = archive_size.max(1).div_ceil(volume_size);
    usize::try_from(count).ok()
}

/// Deduplicated paths from two volume-path lists, preserving order.
#[must_use]
pub(crate) fn unique_paths<'a>(left: &'a [PathBuf], right: &'a [PathBuf]) -> Vec<&'a Path> {
    let mut seen = BTreeSet::new();
    left.iter()
        .chain(right.iter())
        .filter_map(|path| if seen.insert(path.clone()) { Some(path.as_path()) } else { None })
        .collect()
}

/// Returns an error when `path` exists and must not be replaced.
///
/// Directories are always refused (a split writer must never replace a
/// directory with a volume file); an existing file is accepted only when
/// `replace_existing` is set; a missing destination is fine.
pub(crate) fn ensure_file_destination_available(path: &Path, replace_existing: bool) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Err(io::Error::new(io::ErrorKind::IsADirectory, format!("cannot replace directory {}", path.display())))
        }
        Ok(_) if !replace_existing => {
            Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("destination already exists: {}", path.display())))
        }
        Ok(_) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source),
    }
}

/// Removes every existing volume destination before an overwrite write.
pub(crate) fn remove_split_destinations_for_replace(
    destination: &Path,
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> io::Result<()> {
    if !replace_existing {
        return Ok(());
    }
    for path in existing_volume_paths {
        remove_file_destination_for_replace(path)?;
    }
    remove_file_destination_for_replace(destination)
}

/// Removes one existing volume file, refusing to remove a directory.
///
/// Deliberately stricter than `safety::remove_destination_for_replace`,
/// which replaces directories: a split writer must never mistake a directory
/// for a volume it is about to create.
pub(crate) fn remove_file_destination_for_replace(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Err(io::Error::new(io::ErrorKind::IsADirectory, format!("cannot replace directory {}", path.display())))
        }
        Ok(_) => fs::remove_file(path),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source),
    }
}

/// Applies portable metadata (Unix mode and modification time) to a written
/// volume file.
///
/// `mode_mask` is passed explicitly because the backends disagree on whether
/// to restore the setuid/setgid/sticky bits (`0o777` vs `0o7777`) — see
/// CR-034 in the implementation-docs tracker; unify once the extraction
/// posture for privileged bits is decided.
pub(crate) fn apply_split_metadata(
    path: &Path,
    unix_mode: Option<u32>,
    modified_time: Option<FileTime>,
    mode_mask: u32,
) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(mode) = unix_mode {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode & mode_mask))?;
    }

    #[cfg(not(unix))]
    if let Some(mode) = unix_mode
        && mode & 0o222 == 0
        && let Ok(metadata) = fs::metadata(path)
    {
        let mut perms = metadata.permissions();
        perms.set_readonly(true);
        fs::set_permissions(path, perms)?;
    }

    if let Some(mtime) = modified_time {
        filetime::set_file_mtime(path, mtime)?;
    }
    Ok(())
}
