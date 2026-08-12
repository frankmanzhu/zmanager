//! Shared helpers for the CLI's integration tests.
//!
//! `tests/common/mod.rs` is not compiled as its own test binary; each
//! integration test that needs these helpers declares `mod common;`.

#![allow(dead_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{SystemTime, UNIX_EPOCH};

/// A uniquely named temporary directory that removes itself on drop.
pub struct TestDir {
    root: PathBuf,
}

impl TestDir {
    /// Creates a fresh, uniquely named directory under the system temp dir.
    pub fn new(label: &str) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = env::temp_dir().join(format!("zmanager-{label}-{}-{now}", std::process::id()));
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
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Absolute path to the built `zm` binary (set by cargo for integration tests).
pub fn zm_path() -> PathBuf {
    if let Ok(path) = env::var("CARGO_BIN_EXE_zm") {
        return PathBuf::from(path);
    }
    let mut path = env::current_exe().unwrap();
    while path.file_name().is_some_and(|name| name != "target") {
        path.pop();
    }
    path.push("debug");
    path.push(if cfg!(windows) { "zm.exe" } else { "zm" });
    path
}

/// Asserts that a command invocation succeeded, dumping stdout/stderr on failure.
pub fn assert_success(label: &str, output: &Output) {
    assert!(output.status.success(), "{label} failed\nstdout:\n{}\nstderr:\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

/// Asserts that a command invocation failed, dumping stdout/stderr on success.
pub fn assert_failure(label: &str, output: &Output) {
    assert!(!output.status.success(), "{label} unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

/// Removes ANSI escape sequences from a string.
pub fn strip_ansi(input: &str) -> String {
    let mut stripped = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            let _ = chars.next();
            for code in chars.by_ref() {
                if ('@'..='~').contains(&code) {
                    break;
                }
            }
        } else {
            stripped.push(ch);
        }
    }
    stripped
}

/// Searches `PATH` for an executable with the given name.
pub fn find_on_path(binary: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).map(|dir| dir.join(binary)).find(|candidate| candidate.is_file())
}

/// Asserts that a file is only readable/writable by its owner (mode 0600).
#[cfg(unix)]
pub fn assert_owner_only_file(path: PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

/// No-op on platforms without Unix permission bits.
#[cfg(not(unix))]
pub fn assert_owner_only_file(_path: PathBuf) {}
