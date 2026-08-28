//! Recovery-record persistence (Track 12c of zmanager-mobile's docs/
//! mobile-code-health-remediation-plan.md). A failed destination commit's
//! staged output is kept for a limited retention window so the user can
//! recover it. The caller supplies `root` (where record JSON files live)
//! and, per record, an already-validated `staging_root`; this module owns
//! ID generation, the JSON shape, sort order, and the retention window.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ffi::error::{ERROR_IO_ERROR, ERROR_NOT_FOUND, bridge_error};
use crate::ffi::types::{BridgeSeverity, RecoveryRecord, RecoverySaveRequest, ZmanagerGuiError};

/// A record older than this, at the time `recoveryRecords` is called, is
/// deleted before the call returns. Matches the two independent
/// per-platform 7-day windows this store replaces.
const RETENTION_MILLIS: u64 = 7 * 24 * 60 * 60 * 1000;

static NEXT_RECORD_INDEX: AtomicU64 = AtomicU64::new(0);

fn io_error(error: std::io::Error) -> ZmanagerGuiError {
    bridge_error(ERROR_IO_ERROR, error.to_string(), None, BridgeSeverity::Error, false)
}

fn not_found(id: &str) -> ZmanagerGuiError {
    bridge_error(ERROR_NOT_FOUND, format!("Recovery record '{id}' was not found."), None, BridgeSeverity::Warning, false)
}

fn generate_id() -> String {
    let index = NEXT_RECORD_INDEX.fetch_add(1, Ordering::Relaxed);
    format!("recovery-{}-{}", std::process::id(), index)
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_millis() as u64).unwrap_or(0)
}

fn record_path(root: &str, id: &str) -> PathBuf {
    Path::new(root).join(format!("{id}.json"))
}

fn read_record(path: &Path) -> Option<RecoveryRecord> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_record(root: &str, record: &RecoveryRecord) -> Result<(), ZmanagerGuiError> {
    fs::create_dir_all(root).map_err(io_error)?;
    let path = record_path(root, &record.id);
    let text = serde_json::to_string_pretty(record).map_err(|error| bridge_error(ERROR_IO_ERROR, error.to_string(), None, BridgeSeverity::Error, false))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, text).map_err(io_error)?;
    fs::rename(&tmp, &path).map_err(io_error)?;
    Ok(())
}

/// Removes the record's staged output. Staging roots are always created one
/// level below a per-record directory that holds nothing else
/// (`.../extractions/<id>/staging`), so removing that per-record directory
/// — rather than just the staging root itself — leaves no empty directory
/// behind either.
fn remove_staging(staging_root: &str) {
    let staging_root = Path::new(staging_root);
    let target = staging_root.parent().unwrap_or(staging_root);
    let _ = fs::remove_dir_all(target);
}

fn list_record_files(root: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("json"))
        .collect()
}

#[allow(non_snake_case)]
pub fn recoverySave(request: RecoverySaveRequest) -> Result<RecoveryRecord, ZmanagerGuiError> {
    let record = RecoveryRecord {
        id: generate_id(),
        archive_path: request.archive_path,
        archive_display_name: request.archive_display_name,
        selected_paths: request.selected_paths,
        staging_root: request.staging_root,
        destination_label: request.destination_label,
        message: request.message,
        created_at_millis: now_millis(),
    };
    write_record(&request.root, &record)?;
    Ok(record)
}

#[allow(non_snake_case)]
pub fn recoveryRecords(root: String, now_millis: u64) -> Result<Vec<RecoveryRecord>, ZmanagerGuiError> {
    let mut records: Vec<RecoveryRecord> = Vec::new();
    for path in list_record_files(&root) {
        let Some(record) = read_record(&path) else { continue };
        if now_millis.saturating_sub(record.created_at_millis) > RETENTION_MILLIS {
            remove_staging(&record.staging_root);
            let _ = fs::remove_file(&path);
            continue;
        }
        records.push(record);
    }
    records.sort_by_key(|record| std::cmp::Reverse(record.created_at_millis));
    Ok(records)
}

#[allow(non_snake_case)]
pub fn recoveryDiscard(root: String, id: String) -> Result<(), ZmanagerGuiError> {
    let path = record_path(&root, &id);
    if let Some(record) = read_record(&path) {
        remove_staging(&record.staging_root);
    }
    let _ = fs::remove_file(&path);
    Ok(())
}

#[allow(non_snake_case)]
pub fn recoveryFiles(root: String, id: String) -> Result<Vec<String>, ZmanagerGuiError> {
    let path = record_path(&root, &id);
    let record = read_record(&path).ok_or_else(|| not_found(&id))?;
    let mut files = Vec::new();
    collect_files(Path::new(&record.staging_root), &mut files);
    Ok(files)
}

fn collect_files(dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|entry| entry.ok()) {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else { continue };
        if file_type.is_dir() {
            collect_files(&path, out);
        } else if file_type.is_file() {
            out.push(path.to_string_lossy().into_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("zmanager-ffi-recovery-store-test-{name}-{}-{}", std::process::id(), generate_id()));
        let _ = fs::remove_dir_all(&dir);
        dir.to_string_lossy().into_owned()
    }

    fn stage_files(staging_root: &Path, relative_paths: &[&str]) {
        for relative in relative_paths {
            let file = staging_root.join(relative);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(&file, "content").unwrap();
        }
    }

    fn save_request(root: &str, staging_root: &str) -> RecoverySaveRequest {
        RecoverySaveRequest {
            root: root.to_string(),
            archive_path: "/cache/archive.zip".to_string(),
            archive_display_name: "archive.zip".to_string(),
            selected_paths: vec!["docs/readme.txt".to_string()],
            staging_root: staging_root.to_string(),
            destination_label: "Selected folder".to_string(),
            message: "Provider failed".to_string(),
        }
    }

    #[test]
    fn save_then_list_returns_the_record() {
        let root = temp_root("save-list");
        let staging = Path::new(&root).join("extractions/rec-1/staging");
        stage_files(&staging, &["docs/readme.txt"]);

        let record = recoverySave(save_request(&root, staging.to_str().unwrap())).unwrap();
        assert_eq!(record.archive_display_name, "archive.zip");

        let records = recoveryRecords(root, record.created_at_millis).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, record.id);
    }

    #[test]
    fn records_are_sorted_newest_first() {
        let root = temp_root("sort-order");
        let staging_a = Path::new(&root).join("extractions/a/staging");
        let staging_b = Path::new(&root).join("extractions/b/staging");
        stage_files(&staging_a, &["a.txt"]);
        stage_files(&staging_b, &["b.txt"]);

        let first = recoverySave(save_request(&root, staging_a.to_str().unwrap())).unwrap();
        let mut second = recoverySave(save_request(&root, staging_b.to_str().unwrap())).unwrap();
        // Force a distinct, later timestamp: both saves can land in the
        // same millisecond on a fast machine, and sort order is undefined
        // (not wrong) for equal timestamps.
        second.created_at_millis = first.created_at_millis + 1;
        write_record(&root, &second).unwrap();

        let records = recoveryRecords(root, second.created_at_millis).unwrap();
        assert_eq!(records[0].id, second.id);
        assert_eq!(records[1].id, first.id);
    }

    #[test]
    fn expired_records_are_dropped_and_their_staging_removed() {
        let root = temp_root("expiry");
        let staging = Path::new(&root).join("extractions/rec-1/staging");
        stage_files(&staging, &["docs/readme.txt"]);
        let record = recoverySave(save_request(&root, staging.to_str().unwrap())).unwrap();

        let just_under = recoveryRecords(root.clone(), record.created_at_millis + RETENTION_MILLIS).unwrap();
        assert_eq!(just_under.len(), 1, "exactly at the boundary must still be retained");
        assert!(staging.exists());

        let just_over = recoveryRecords(root, record.created_at_millis + RETENTION_MILLIS + 1).unwrap();
        assert!(just_over.is_empty());
        assert!(!staging.exists());
        assert!(!staging.parent().unwrap().exists());
    }

    #[test]
    fn discard_removes_the_record_and_its_staged_output() {
        let root = temp_root("discard");
        let staging = Path::new(&root).join("extractions/rec-1/staging");
        stage_files(&staging, &["docs/readme.txt"]);
        let record = recoverySave(save_request(&root, staging.to_str().unwrap())).unwrap();

        recoveryDiscard(root.clone(), record.id.clone()).unwrap();

        assert!(!staging.exists());
        assert!(recoveryRecords(root, record.created_at_millis).unwrap().is_empty());
    }

    #[test]
    fn discarding_an_unknown_id_is_a_no_op() {
        let root = temp_root("discard-unknown");
        recoveryDiscard(root, "does-not-exist".to_string()).unwrap();
    }

    #[test]
    fn files_lists_every_regular_file_under_the_staging_root() {
        let root = temp_root("files");
        let staging = Path::new(&root).join("extractions/rec-1/staging");
        stage_files(&staging, &["docs/readme.txt", "docs/nested/notes.txt"]);
        let record = recoverySave(save_request(&root, staging.to_str().unwrap())).unwrap();

        let mut files = recoveryFiles(root, record.id).unwrap();
        files.sort();
        assert_eq!(files.len(), 2);
        assert!(files[0].ends_with("nested/notes.txt"));
        assert!(files[1].ends_with("readme.txt"));
    }

    #[test]
    fn files_for_an_unknown_id_returns_not_found() {
        let root = temp_root("files-unknown");
        let error = recoveryFiles(root, "does-not-exist".to_string()).unwrap_err();
        match error {
            ZmanagerGuiError::Bridge { code, .. } => assert_eq!(code, ERROR_NOT_FOUND),
        }
    }
}
