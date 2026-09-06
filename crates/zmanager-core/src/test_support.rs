//! Shared test-support utilities for the core crate.
//!
//! Only compiled when the crate is built for testing. Consolidated from the
//! near-identical `TestDir` copies that used to live in individual test
//! modules; keep shared test scaffolding here instead of re-introducing
//! per-module copies.
#![cfg(test)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEST_DIR_ID: AtomicU64 = AtomicU64::new(0);

/// A uniquely named temporary directory that removes itself on drop.
pub struct TestDir {
    root: PathBuf,
}

impl TestDir {
    /// Creates a fresh, uniquely named directory under the system temp dir.
    pub fn new(label: &str) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let id = NEXT_TEST_DIR_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("zmanager-{label}-{}-{now}-{id}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    /// Returns the test directory root itself.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolves a path relative to the test directory root.
    pub fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.root.join(relative)
    }

    /// Creates a directory (and any missing parents) under the test root.
    pub fn create_dir(&self, relative: impl AsRef<Path>) {
        fs::create_dir_all(self.path(relative)).unwrap();
    }

    /// Writes a file under the test root, creating missing parent directories.
    pub fn write_file(&self, relative: impl AsRef<Path>, contents: &[u8]) {
        let path = self.path(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Creates `project/script.sh` with mode 0o755 and the reference mtime,
/// returning the file path and the mtime used. Shared by the backend
/// metadata round-trip tests (CR-135).
pub fn script_fixture_with_metadata(temp: &TestDir) -> (std::path::PathBuf, filetime::FileTime) {
    temp.write_file("project/script.sh", b"echo hello");
    let path = temp.path("project/script.sh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mtime = filetime::FileTime::from_unix_time(1_500_000_000, 0);
    filetime::set_file_mtime(&path, mtime).unwrap();
    (path, mtime)
}

/// Shared X.509 test-certificate factory (CR-125). Moved to
/// [`crate::x509_fixture`] (always compiled, not `#[cfg(test)]`-gated) so it
/// can also be exposed to sibling crates via
/// [`crate::backend_test_support::x509_factory`]; re-exported here under its
/// old path so existing `use crate::test_support::x509_factory::*;` call
/// sites keep working unchanged.
pub(crate) use crate::x509_fixture as x509_factory;

/// Deterministic xorshift byte stream for reproducible fixture payloads.
pub(crate) fn deterministic_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678_9abc_def0_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

/// Builds a ZIP fixture through the shared manifest/create path.
pub(crate) fn create_zip_fixture(
    source: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    options: &crate::zip_backend::ZipCreateOptions,
) -> Result<crate::zip_backend::ZipCreateReport, crate::zip_backend::ZipBackendError> {
    let manifest = crate::manifest::plan_archive(source, &crate::manifest::PlanOptions::default())?;
    crate::zip_backend::create_zip_from_manifest(&manifest, destination, options)
}
