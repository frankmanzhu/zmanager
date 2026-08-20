//! Native WARC reader.
//!
//! Each WARC record is exposed as one regular-file entry.  A record with a
//! `WARC-Target-URI` uses its normalized target path; records without one use
//! a stable `records/` path.  The materialized bytes are the WARC record body
//! exactly as stored, including HTTP framing for response records.

use crate::engine::types::TestOptions;
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use std::fmt;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::{Path, PathBuf};

const RECORDS_DIRECTORY: &str = "records";

/// One normalized WARC record entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WarcEntry {
    /// Retained record-order entry ID.
    pub index: usize,
    /// Stable normalized materialization path.
    pub path: String,
    /// WARC record body length.
    pub size: u64,
    /// WARC record type, retained for diagnostics and method display.
    pub record_type: String,
}

/// Native WARC operation report.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct WarcReport {
    /// Records written or verified.
    pub entries: usize,
    /// Records skipped by selection or policy.
    pub skipped_entries: usize,
    /// Record-body bytes written or verified.
    pub bytes: u64,
    /// Non-fatal diagnostics.
    pub warnings: Vec<String>,
}

/// Native WARC operation error.
#[derive(Debug)]
pub enum WarcError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// The WARC stream or record is malformed.
    Invalid { path: PathBuf, message: String },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// The caller cancelled the operation.
    Cancelled,
}

impl fmt::Display for WarcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Invalid { path, message } => write!(f, "invalid WARC {}: {message}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected WARC entry: {source}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for WarcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Invalid { .. } | Self::Cancelled => None,
        }
    }
}

impl From<ExtractionSafetyError> for WarcError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Lists WARC records without buffering their bodies.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<WarcEntry>, WarcError> {
    let path = path.as_ref();
    let mut reader = open(path)?;
    let mut stream = reader.stream_records();
    let mut entries = Vec::new();
    let mut used_paths = Vec::new();
    while let Some(record) = stream.next_item() {
        let record = record.map_err(|source| warc_error(path, source))?;
        let index = entries.len();
        let record_type = record.warc_type().to_string();
        let path_name = record_path(&record, index, &record_type, &mut used_paths)?;
        entries.push(WarcEntry { index, path: path_name, size: record.content_length(), record_type });
    }
    Ok(entries)
}

/// Verifies WARC headers and streams selected record bodies to a sink.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<WarcReport, WarcError> {
    let path = path.as_ref();
    let mut reader = open(path)?;
    let mut stream = reader.stream_records();
    let mut report = WarcReport::default();
    let mut used_paths = Vec::new();
    while let Some(record) = stream.next_item() {
        if options.is_cancelled() {
            return Err(WarcError::Cancelled);
        }
        let mut record = record.map_err(|source| warc_error(path, source))?;
        let index = report.entries.saturating_add(report.skipped_entries);
        let record_type = record.warc_type().to_string();
        let entry_path = record_path(&record, index, &record_type, &mut used_paths)?;
        if !options.selects(&entry_path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        let expected = record.content_length();
        let bytes = io::copy(&mut record, &mut io::sink()).map_err(|source| io_error(path, source))?;
        if bytes != expected {
            return Err(invalid(path, format!("record {index} decoded to {bytes} bytes, expected {expected}")));
        }
        report.entries = report.entries.saturating_add(1);
        report.bytes = report.bytes.saturating_add(bytes);
    }
    Ok(report)
}

/// Extracts WARC record bodies through the shared safety planner.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<WarcReport, WarcError> {
    let path = path.as_ref();
    let destination = destination.as_ref();
    let root = crate::safety::prepare_destination_root(destination).map_err(|source| io_error(destination, source))?;
    let mut reader = open(path)?;
    let mut stream = reader.stream_records();
    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&root, policy, resolver);
    let mut report = WarcReport::default();
    let mut used_paths = Vec::new();
    while let Some(record) = stream.next_item() {
        if cancellation.is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(WarcError::Cancelled);
        }
        let mut record = record.map_err(|source| warc_error(path, source))?;
        let index = report.entries.saturating_add(report.skipped_entries);
        let record_type = record.warc_type().to_string();
        let entry_path = record_path(&record, index, &record_type, &mut used_paths)?;
        let expected = record.content_length();
        let decision = planner.validate_entry(&ExtractionEntry {
            archive_path: entry_path.clone(),
            kind: ExtractionEntryKind::File,
            uncompressed_size: Some(expected),
            compressed_size: Some(expected),
        })?;
        let ExtractionDecision::Write { destination_path, replace_existing, .. } = decision else {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        };
        let mut output = crate::atomic_file::AtomicOutputFile::create(&destination_path).map_err(|source| io_error(&destination_path, source))?;
        let bytes = io::copy(&mut record, output.file_mut().map_err(|source| io_error(&destination_path, source))?)
            .map_err(|source| io_error(&destination_path, source))?;
        if bytes != expected {
            return Err(invalid(path, format!("record {index} decoded to {bytes} bytes, expected {expected}")));
        }
        output.commit_with_replace(replace_existing).map_err(|source| io_error(&destination_path, source))?;
        report.entries = report.entries.saturating_add(1);
        report.bytes = report.bytes.saturating_add(bytes);
    }
    Ok(report)
}

/// Copies one retained WARC record body to a caller-owned writer.
pub fn copy(path: impl AsRef<Path>, entry_index: usize, writer: &mut dyn io::Write) -> Result<u64, WarcError> {
    let path = path.as_ref();
    let mut reader = open(path)?;
    let mut stream = reader.stream_records();
    let mut used_paths = Vec::new();
    for index in 0..=entry_index {
        let Some(record) = stream.next_item() else {
            return Err(invalid(path, "retained WARC entry ID is not present"));
        };
        let mut record = record.map_err(|source| warc_error(path, source))?;
        let record_type = record.warc_type().to_string();
        let _entry_path = record_path(&record, index, &record_type, &mut used_paths)?;
        if index == entry_index {
            let expected = record.content_length();
            let bytes = io::copy(&mut record, writer).map_err(|source| io_error(path, source))?;
            if bytes != expected {
                return Err(invalid(path, format!("record {index} decoded to {bytes} bytes, expected {expected}")));
            }
            return Ok(bytes);
        }
    }
    Err(invalid(path, "retained WARC entry ID is not present"))
}

/// Copies one retained WARC record by path and duplicate occurrence.
pub fn copy_by_path_occurrence(path: impl AsRef<Path>, selected_path: &str, selected_occurrence: usize, writer: &mut dyn io::Write) -> Result<u64, WarcError> {
    let path = path.as_ref();
    let mut occurrence = 0_usize;
    let entry_index = list(path)?
        .into_iter()
        .find_map(|entry| {
            if entry.path != selected_path {
                return None;
            }
            let matches = occurrence == selected_occurrence;
            occurrence = occurrence.saturating_add(1);
            matches.then_some(entry.index)
        })
        .ok_or_else(|| invalid(path, "retained WARC entry is not present"))?;
    copy(path, entry_index, writer)
}

fn record_path<T: io::Read>(
    record: &warc::Record<warc::StreamingBody<'_, T>>,
    index: usize,
    record_type: &str,
    used: &mut Vec<String>,
) -> Result<String, WarcError> {
    let candidate = record
        .header(warc::WarcHeader::TargetURI)
        .and_then(|target| target_path(&target))
        .unwrap_or_else(|| format!("{RECORDS_DIRECTORY}/{index:08}-{record_type}"));
    let mut path = candidate.clone();
    if used.iter().any(|existing| existing == &path) {
        path = format!("{candidate}~{index}");
    }
    if used.iter().any(|existing| existing == &path) {
        return Err(invalid(Path::new("<WARC>"), format!("duplicate materialized path {path}")));
    }
    used.push(path.clone());
    Ok(path)
}

fn target_path(target: &str) -> Option<String> {
    let target = target.trim().trim_start_matches('<').trim_end_matches('>');
    let raw = if let Some(file_path) = target.strip_prefix("file://") {
        file_path.trim_start_matches('/').to_owned()
    } else if let Some((scheme, rest)) = target.split_once("://") {
        let _ = scheme;
        rest.to_owned()
    } else {
        target.to_owned()
    };
    crate::safety::normalize_archive_path(raw.trim_start_matches('/')).ok()
}

fn warc_error(path: &Path, error: warc::Error) -> WarcError {
    match error {
        warc::Error::ReadData(source) => io_error(path, source),
        other => invalid(path, other),
    }
}

fn open(path: &Path) -> Result<warc::WarcReader<BufReader<File>>, WarcError> {
    let file = File::open(path).map_err(|source| io_error(path, source))?;
    Ok(warc::WarcReader::new(BufReader::new(file)))
}

fn invalid(path: &Path, error: impl fmt::Display) -> WarcError {
    WarcError::Invalid { path: path.to_path_buf(), message: error.to_string() }
}

fn io_error(path: &Path, source: io::Error) -> WarcError {
    WarcError::Io { path: path.to_path_buf(), source }
}

#[cfg(test)]
#[allow(clippy::all, clippy::pedantic)]
mod tests {
    use super::*;
    use crate::safety::ExtractionPolicy;
    use crate::test_support::TestDir;
    use std::fs;

    fn build_warc(records: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut warc = Vec::new();
        for (i, &(record_type, target_uri, body)) in records.iter().enumerate() {
            warc.extend_from_slice(b"WARC/1.0\r\n");
            warc.extend_from_slice(format!("WARC-Type: {record_type}\r\n").as_bytes());
            warc.extend_from_slice(format!("WARC-Record-ID: <urn:uuid:00000000-0000-0000-0000-{i:012}>\r\n").as_bytes());
            warc.extend_from_slice(b"WARC-Date: 2026-01-01T12:00:00Z\r\n");
            if let Some(uri) = target_uri {
                warc.extend_from_slice(format!("WARC-Target-URI: {uri}\r\n").as_bytes());
            }
            warc.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
            warc.extend_from_slice(b"\r\n");
            warc.extend_from_slice(body);
            warc.extend_from_slice(b"\r\n\r\n");
        }
        warc
    }

    #[test]
    fn test_warc_list_test_extract_and_copy() {
        let temp = TestDir::new("warc-backend-test");
        let archive_path = temp.path("sample.warc");

        let warc_bytes =
            build_warc(&[("warcinfo", None, b"software: test\n"), ("response", Some("http://example.com/page.html"), b"<html><body>Hello</body></html>")]);
        fs::write(&archive_path, warc_bytes).unwrap();

        // 1. List
        let entries = list(&archive_path).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].path.starts_with("records/00000000-warcinfo"));
        assert_eq!(entries[0].size, 15);
        assert_eq!(entries[1].path, "example.com/page.html");
        assert_eq!(entries[1].size, 31);

        // 2. Test
        let test_report = test(&archive_path, &TestOptions::default()).unwrap();
        assert_eq!(test_report.entries, 2);
        assert_eq!(test_report.bytes, 15 + 31);

        // Test with selection
        let sel_opts = TestOptions { selected_paths: vec!["example.com/page.html".to_string()], ..TestOptions::default() };
        let sel_report = test(&archive_path, &sel_opts).unwrap();
        assert_eq!(sel_report.entries, 1);
        assert_eq!(sel_report.skipped_entries, 1);

        // 3. Extract
        let dest = temp.path("out");
        let extract_report = extract(&archive_path, &dest, ExtractionPolicy::default(), None, None).unwrap();
        assert_eq!(extract_report.entries, 2);
        assert_eq!(fs::read(dest.join("example.com/page.html")).unwrap(), b"<html><body>Hello</body></html>");

        // 4. Copy by index
        let mut copied = Vec::new();
        let bytes_copied = copy(&archive_path, 1, &mut copied).unwrap();
        assert_eq!(bytes_copied, 31);
        assert_eq!(copied, b"<html><body>Hello</body></html>");

        // 5. Copy by path occurrence
        let mut copied_occ = Vec::new();
        let bytes_occ = copy_by_path_occurrence(&archive_path, "example.com/page.html", 0, &mut copied_occ).unwrap();
        assert_eq!(bytes_occ, 31);
        assert_eq!(copied_occ, b"<html><body>Hello</body></html>");
    }

    #[test]
    fn test_warc_error_handling() {
        let temp = TestDir::new("warc-backend-errors");
        let non_existent = temp.path("missing.warc");
        assert!(list(&non_existent).is_err());
        assert!(test(&non_existent, &TestOptions::default()).is_err());
        assert!(extract(&non_existent, temp.path("out"), ExtractionPolicy::default(), None, None).is_err());
        assert!(copy(&non_existent, 0, &mut Vec::new()).is_err());

        // Corrupt file
        let corrupt = temp.path("corrupt.warc");
        fs::write(&corrupt, b"WARC/1.0\r\nWARC-Type: invalid\r\n\r\n").unwrap();
        // listing or test handles bad data
        let _ = list(&corrupt);

        // Error types & Display coverage
        let inv_err = WarcError::Invalid { path: PathBuf::from("a.warc"), message: "corrupt".to_string() };
        assert!(inv_err.to_string().contains("invalid WARC"));
        assert!(std::error::Error::source(&inv_err).is_none());

        let io_err = WarcError::Io { path: PathBuf::from("b.warc"), source: io::Error::new(io::ErrorKind::NotFound, "err") };
        assert!(io_err.to_string().contains("I/O failed"));
        assert!(std::error::Error::source(&io_err).is_some());

        let cancelled = WarcError::Cancelled;
        assert_eq!(cancelled.to_string(), "job cancelled");

        let safety = WarcError::Safety(ExtractionSafetyError::EmptyPath);
        assert!(safety.to_string().contains("extraction safety"));
        assert!(std::error::Error::source(&safety).is_some());
    }
}
