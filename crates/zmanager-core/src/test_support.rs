//! Shared test-support utilities for the core crate.
//!
//! Only compiled when the crate is built for testing. Consolidated from the
//! near-identical `TestDir` copies that used to live in individual test
//! modules; keep shared test scaffolding here instead of re-introducing
//! per-module copies.
#![cfg(test)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// A uniquely named temporary directory that removes itself on drop.
pub struct TestDir {
    root: PathBuf,
}

impl TestDir {
    /// Creates a fresh, uniquely named directory under the system temp dir.
    pub fn new(label: &str) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = std::env::temp_dir().join(format!("zmanager-{label}-{}-{now}", std::process::id()));
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
