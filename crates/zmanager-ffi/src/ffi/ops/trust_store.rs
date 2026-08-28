//! LocalSend trust-store persistence (Track 12c of zmanager-mobile's docs/
//! mobile-code-health-remediation-plan.md). Stores only user-approved
//! LocalSend device fingerprints, never addresses or secrets. The caller
//! supplies `root`, an app-owned directory it already controls; this module
//! owns the file name, JSON shape, and atomic-write discipline within it.

use std::fs;
use std::path::{Path, PathBuf};

use crate::ffi::error::{ERROR_IO_ERROR, bridge_error};
use crate::ffi::types::{BridgeSeverity, ZmanagerGuiError};

const FILE_NAME: &str = "trusted-fingerprints.json";

fn file_path(root: &str) -> PathBuf {
    Path::new(root).join(FILE_NAME)
}

fn io_error(error: std::io::Error) -> ZmanagerGuiError {
    bridge_error(ERROR_IO_ERROR, error.to_string(), None, BridgeSeverity::Error, false)
}

fn read_fingerprints(root: &str) -> Result<Vec<String>, ZmanagerGuiError> {
    let path = file_path(root);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&path).map_err(io_error)?;
    Ok(serde_json::from_str(&text).unwrap_or_default())
}

fn write_fingerprints(root: &str, mut fingerprints: Vec<String>) -> Result<(), ZmanagerGuiError> {
    fingerprints.sort();
    fingerprints.dedup();
    fs::create_dir_all(root).map_err(io_error)?;
    let path = file_path(root);
    let text = serde_json::to_string_pretty(&fingerprints).unwrap_or_else(|_| "[]".to_string());
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, text).map_err(io_error)?;
    fs::rename(&tmp, &path).map_err(io_error)?;
    Ok(())
}

#[allow(non_snake_case)]
pub fn trustIsTrusted(root: String, fingerprint: String) -> Result<bool, ZmanagerGuiError> {
    Ok(read_fingerprints(&root)?.iter().any(|existing| existing == &fingerprint))
}

#[allow(non_snake_case)]
pub fn trustRemember(root: String, fingerprint: String) -> Result<(), ZmanagerGuiError> {
    let mut fingerprints = read_fingerprints(&root)?;
    if !fingerprints.contains(&fingerprint) {
        fingerprints.push(fingerprint);
    }
    write_fingerprints(&root, fingerprints)
}

#[allow(non_snake_case)]
pub fn trustForget(root: String, fingerprint: String) -> Result<(), ZmanagerGuiError> {
    let mut fingerprints = read_fingerprints(&root)?;
    fingerprints.retain(|existing| existing != &fingerprint);
    write_fingerprints(&root, fingerprints)
}

#[allow(non_snake_case)]
pub fn trustFingerprints(root: String) -> Result<Vec<String>, ZmanagerGuiError> {
    let mut fingerprints = read_fingerprints(&root)?;
    fingerprints.sort();
    Ok(fingerprints)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("zmanager-ffi-trust-store-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn unknown_fingerprint_is_not_trusted_and_directory_need_not_exist_yet() {
        let root = temp_root("unknown");
        assert!(!trustIsTrusted(root.clone(), "abc123".to_string()).unwrap());
        assert!(trustFingerprints(root).unwrap().is_empty());
    }

    #[test]
    fn remember_then_is_trusted_then_forget_round_trips() {
        let root = temp_root("roundtrip");
        assert!(!trustIsTrusted(root.clone(), "fp-1".to_string()).unwrap());

        trustRemember(root.clone(), "fp-1".to_string()).unwrap();
        assert!(trustIsTrusted(root.clone(), "fp-1".to_string()).unwrap());
        assert_eq!(trustFingerprints(root.clone()).unwrap(), vec!["fp-1".to_string()]);

        trustForget(root.clone(), "fp-1".to_string()).unwrap();
        assert!(!trustIsTrusted(root.clone(), "fp-1".to_string()).unwrap());
        assert!(trustFingerprints(root).unwrap().is_empty());
    }

    #[test]
    fn remembering_twice_does_not_duplicate() {
        let root = temp_root("dedup");
        trustRemember(root.clone(), "fp-1".to_string()).unwrap();
        trustRemember(root.clone(), "fp-1".to_string()).unwrap();
        assert_eq!(trustFingerprints(root).unwrap(), vec!["fp-1".to_string()]);
    }

    #[test]
    fn fingerprints_are_returned_sorted() {
        let root = temp_root("sorted");
        trustRemember(root.clone(), "zzz".to_string()).unwrap();
        trustRemember(root.clone(), "aaa".to_string()).unwrap();
        trustRemember(root.clone(), "mmm".to_string()).unwrap();
        assert_eq!(trustFingerprints(root).unwrap(), vec!["aaa".to_string(), "mmm".to_string(), "zzz".to_string()]);
    }

    #[test]
    fn forgetting_an_unknown_fingerprint_is_a_no_op() {
        let root = temp_root("forget-unknown");
        trustRemember(root.clone(), "fp-1".to_string()).unwrap();
        trustForget(root.clone(), "does-not-exist".to_string()).unwrap();
        assert_eq!(trustFingerprints(root).unwrap(), vec!["fp-1".to_string()]);
    }
}
