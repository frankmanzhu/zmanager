//! Shared helpers for the core crate's integration tests.
//!
//! `tests/common/mod.rs` is not compiled as its own test binary; each
//! integration test that needs these helpers declares `mod common;`.

#![allow(dead_code)]

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
