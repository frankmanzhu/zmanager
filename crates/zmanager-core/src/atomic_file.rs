use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const TEMP_PREFIX: &str = ".zmanager";
const TEMP_SUFFIX: &str = ".tmp";
const MAX_TEMP_ATTEMPTS: u32 = 100;

pub(crate) struct AtomicOutputFile {
    final_path: PathBuf,
    temp_path: PathBuf,
    file: Option<File>,
    committed: bool,
}

impl AtomicOutputFile {
    pub(crate) fn create(final_path: &Path) -> io::Result<Self> {
        if let Some(parent) = final_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = final_path.file_name().and_then(|name| name.to_str()).unwrap_or("archive");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());

        for attempt in 0..MAX_TEMP_ATTEMPTS {
            let temp_path =
                parent.join(format!("{TEMP_PREFIX}-{file_name}-{}-{now}-{attempt}{TEMP_SUFFIX}", std::process::id()));
            match OpenOptions::new().write(true).create_new(true).open(&temp_path) {
                Ok(file) => {
                    return Ok(Self {
                        final_path: final_path.to_path_buf(),
                        temp_path,
                        file: Some(file),
                        committed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("could not allocate temporary output path for {}", final_path.display()),
        ))
    }

    pub(crate) fn file_mut(&mut self) -> io::Result<&mut File> {
        self.file.as_mut().ok_or_else(|| {
            io::Error::other(format!("temporary output already finalized for {}", self.final_path.display()))
        })
    }

    pub(crate) fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    pub(crate) fn close(&mut self) {
        drop(self.file.take());
    }

    pub(crate) fn commit_with_replace(mut self, replace_existing: bool) -> io::Result<()> {
        self.commit_inner(replace_existing)
    }

    pub(crate) fn commit_with_file_replace(mut self, replace_existing: bool) -> io::Result<()> {
        drop(self.file.take());
        if replace_existing {
            remove_file_destination_for_replace(&self.final_path)?;
            fs::rename(&self.temp_path, &self.final_path)?;
        } else {
            fs::hard_link(&self.temp_path, &self.final_path)?;
            let _ = fs::remove_file(&self.temp_path);
        }
        self.committed = true;
        Ok(())
    }

    /// Commits by renaming over the destination without first removing it:
    /// POSIX `rename` replaces atomically, and Windows uses
    /// `MoveFileExW REPLACE_EXISTING`. Unlike [`Self::commit_with_replace`]
    /// there is no window where the final path is absent, so a crash at any
    /// point leaves either the old or the new file — never neither. Used by
    /// writers whose final file must never disappear (identity catalog).
    pub(crate) fn commit_with_atomic_replace(mut self) -> io::Result<()> {
        drop(self.file.take());
        #[cfg(unix)]
        fs::rename(&self.temp_path, &self.final_path)?;
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
            };

            let from: Vec<u16> = self.temp_path.as_os_str().encode_wide().chain(Some(0)).collect();
            let to: Vec<u16> = self.final_path.as_os_str().encode_wide().chain(Some(0)).collect();
            let result =
                unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
            if result == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        self.committed = true;
        Ok(())
    }

    fn commit_inner(&mut self, replace_existing: bool) -> io::Result<()> {
        drop(self.file.take());
        if replace_existing {
            crate::safety::remove_destination_for_replace(&self.final_path)?;
            fs::rename(&self.temp_path, &self.final_path)?;
        } else {
            fs::hard_link(&self.temp_path, &self.final_path)?;
            let _ = fs::remove_file(&self.temp_path);
        }
        self.committed = true;
        Ok(())
    }
}

pub(crate) struct TemporaryFile {
    path: PathBuf,
    file: File,
}

impl TemporaryFile {
    pub(crate) fn create(label: &str) -> io::Result<Self> {
        let parent = std::env::temp_dir();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());

        for attempt in 0..MAX_TEMP_ATTEMPTS {
            let path =
                parent.join(format!("{TEMP_PREFIX}-{label}-{}-{now}-{attempt}{TEMP_SUFFIX}", std::process::id()));
            match OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
                Ok(file) => return Ok(Self { path, file }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("could not allocate temporary file for {label}")))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Writes secret bytes to `path` atomically: content goes to a temporary
/// sibling file, is synced, and is renamed into place, so a crash at any
/// point leaves either the previous file or the complete new file — never a
/// truncated mix. On Unix the file is created with owner-only permissions
/// (0o600).
///
/// The temporary file is allocated with `create_new` plus a retry loop, so
/// two concurrent writers can never clobber each other's temporary file.
pub(crate) fn write_atomic_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("secret");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());

    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let temporary = parent.join(format!("{file_name}.tmp-{}-{now}-{attempt}", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let write_result: io::Result<()> = (|| {
            let mut file = options.open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            #[cfg(unix)]
            {
                let mut permissions = file.metadata()?.permissions();
                permissions.set_mode(0o600);
                fs::set_permissions(&temporary, permissions)?;
            }
            drop(file);
            replace_file_over_existing(&temporary, path)?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary);
            if error.kind() == io::ErrorKind::AlreadyExists {
                // `create_new` raced with another writer of the same unique
                // name; try the next candidate name.
                continue;
            }
            return Err(error);
        }
        #[cfg(unix)]
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("could not allocate temporary secret file for {}", path.display()),
    ))
}

#[cfg(not(windows))]
fn replace_file_over_existing(temporary: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temporary, path)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn replace_file_over_existing(temporary: &Path, path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let from: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // MoveFileExW with REPLACE_EXISTING is the Windows equivalent of an
    // atomic rename-over-existing-file. WRITE_THROUGH ensures the rename is
    // flushed before the call returns.
    let result = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn remove_file_destination_for_replace(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::IsADirectory,
            format!("cannot replace directory {}", path.display()),
        ));
    }

    fs::remove_file(path)
}

impl Drop for AtomicOutputFile {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.file.take());
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AtomicOutputFile;
    use crate::test_support::TestDir;
    use std::fs;
    use std::io::Write as _;

    #[test]
    fn commit_without_replace_moves_temp_file_to_final_path() {
        let temp = TestDir::new("atomic_commit");
        let final_path = temp.path("archive.zip");
        let mut output = AtomicOutputFile::create(&final_path).unwrap();

        output.file_mut().unwrap().write_all(b"archive").unwrap();
        output.commit_with_file_replace(false).unwrap();

        assert_eq!(fs::read(&final_path).unwrap(), b"archive");
    }

    #[test]
    fn drop_removes_uncommitted_temp_file() {
        let temp = TestDir::new("atomic_drop");
        let final_path = temp.path("archive.zip");

        {
            let mut output = AtomicOutputFile::create(&final_path).unwrap();
            output.file_mut().unwrap().write_all(b"partial").unwrap();
        }

        assert!(!final_path.exists());
        assert_eq!(fs::read_dir(temp.path(".")).unwrap().count(), 0);
    }

    #[test]
    fn commit_without_replace_refuses_existing_final_path() {
        let temp = TestDir::new("atomic_existing");
        let final_path = temp.path("archive.zip");
        fs::write(&final_path, b"old").unwrap();
        let mut output = AtomicOutputFile::create(&final_path).unwrap();
        output.file_mut().unwrap().write_all(b"new").unwrap();

        let error = output.commit_with_file_replace(false).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&final_path).unwrap(), b"old");
    }

    #[test]
    fn commit_with_file_replace_replaces_existing_file() {
        let temp = TestDir::new("atomic_replace_file");
        let final_path = temp.path("archive.zip");
        fs::write(&final_path, b"old").unwrap();
        let mut output = AtomicOutputFile::create(&final_path).unwrap();
        output.file_mut().unwrap().write_all(b"new").unwrap();

        output.commit_with_file_replace(true).unwrap();

        assert_eq!(fs::read(&final_path).unwrap(), b"new");
    }

    #[test]
    fn commit_with_file_replace_refuses_existing_directory() {
        let temp = TestDir::new("atomic_replace_directory");
        let final_path = temp.path("archive.zip");
        fs::create_dir(&final_path).unwrap();
        let mut output = AtomicOutputFile::create(&final_path).unwrap();
        output.file_mut().unwrap().write_all(b"new").unwrap();

        let error = output.commit_with_file_replace(true).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::IsADirectory);
        assert!(final_path.is_dir());
    }
}
