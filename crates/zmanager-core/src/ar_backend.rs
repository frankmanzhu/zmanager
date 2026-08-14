//! Bounded native System V/GNU/BSD AR reader for package/container adapters.

use crate::engine::types::TestOptions;
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, OverwriteResolver};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const AR_MAGIC: &[u8] = b"!<arch>\n";
const AR_MEMBER_MAGIC: &[u8] = b"`\n";

/// One native AR member.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArEntry {
    /// Archive-order index.
    pub index: usize,
    /// Resolved member name.
    pub path: String,
    /// Member payload size.
    pub size: u64,
    /// Payload offset in the archive file.
    pub data_offset: u64,
    /// Member modification time in seconds since the Unix epoch.
    pub modified: u64,
    /// Portable Unix mode bits from the AR header.
    pub mode: u32,
}

/// Normalized AR operation report.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ArReport {
    /// Members written or verified.
    pub entries: usize,
    /// Members skipped by selection.
    pub skipped_entries: usize,
    /// Payload bytes written or verified.
    pub bytes: u64,
    /// Non-fatal diagnostics.
    pub warnings: Vec<String>,
}

/// Error returned by native AR operations.
#[derive(Debug)]
pub enum ArError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// The AR structure is malformed.
    Invalid { path: PathBuf, message: String },
    /// Extraction safety rejected a member.
    Safety(ExtractionSafetyError),
    /// The caller cancelled the operation.
    Cancelled,
}

impl fmt::Display for ArError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Invalid { path, message } => write!(f, "invalid AR archive {}: {message}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected member: {source}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for ArError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Invalid { .. } | Self::Cancelled => None,
        }
    }
}

impl From<ExtractionSafetyError> for ArError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Lists regular AR members, excluding symbol and string-table metadata members.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<ArEntry>, ArError> {
    parse(path.as_ref())
}

/// Verifies selected or all AR member payloads.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<ArReport, ArError> {
    let path = path.as_ref();
    let entries = parse(path)?;
    let mut file = open(path)?;
    let mut report = ArReport::default();
    for entry in entries {
        if options.is_cancelled() {
            return Err(ArError::Cancelled);
        }
        if !options.selects(&entry.path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        file.seek(SeekFrom::Start(entry.data_offset)).map_err(|source| io_error(path, source))?;
        let copied = io::copy(&mut (&mut file).take(entry.size), &mut io::sink()).map_err(|source| io_error(path, source))?;
        report.entries = report.entries.saturating_add(1);
        report.bytes = report.bytes.saturating_add(copied);
    }
    Ok(report)
}

/// Extracts all AR members using the shared safety planner, or one retained member by index.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    selected_index: Option<usize>,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<ArReport, ArError> {
    let path = path.as_ref();
    let destination = destination.as_ref();
    let root = crate::safety::prepare_destination_root(destination).map_err(|source| io_error(destination, source))?;
    let entries = parse(path)?;
    let mut file = open(path)?;
    let mut planner = crate::safety::ExtractionSafetyPlanner::with_overwrite_resolver(&root, policy, resolver);
    let mut report = ArReport::default();
    for entry in entries {
        if cancellation.is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(ArError::Cancelled);
        }
        if selected_index.is_some_and(|selected| selected != entry.index) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        let safety_entry = ExtractionEntry {
            archive_path: entry.path.clone(),
            kind: ExtractionEntryKind::File,
            uncompressed_size: Some(entry.size),
            compressed_size: Some(entry.size),
        };
        let decision = planner.validate_entry(&safety_entry)?;
        let crate::safety::ExtractionDecision::Write { destination_path, replace_existing, .. } = decision else {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        };
        file.seek(SeekFrom::Start(entry.data_offset)).map_err(|source| io_error(path, source))?;
        let mut output = crate::atomic_file::AtomicOutputFile::create(&destination_path).map_err(|source| io_error(&destination_path, source))?;
        let copied = io::copy(&mut (&mut file).take(entry.size), output.file_mut().map_err(|source| io_error(&destination_path, source))?)
            .map_err(|source| io_error(&destination_path, source))?;
        output.commit_with_replace(replace_existing).map_err(|source| io_error(&destination_path, source))?;
        report.entries = report.entries.saturating_add(1);
        report.bytes = report.bytes.saturating_add(copied);
    }
    Ok(report)
}

/// Extracts one retained member by its path and duplicate occurrence in the
/// session listing.
pub fn extract_by_path_occurrence(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    selected_path: &str,
    selected_occurrence: usize,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<ArReport, ArError> {
    let path = path.as_ref();
    let selected_index = find_path_occurrence(path, selected_path, selected_occurrence)?;
    extract(path, destination, policy, resolver, Some(selected_index), cancellation)
}

/// Copies one retained AR member to a caller-owned writer.
pub fn copy(path: impl AsRef<Path>, entry_index: usize, writer: &mut dyn Write) -> Result<u64, ArError> {
    let path = path.as_ref();
    let entry = parse(path)?
        .into_iter()
        .find(|entry| entry.index == entry_index)
        .ok_or_else(|| ArError::Io { path: path.to_path_buf(), source: io::Error::new(io::ErrorKind::NotFound, "retained AR entry ID is not present") })?;
    let mut file = open(path)?;
    file.seek(SeekFrom::Start(entry.data_offset)).map_err(|source| io_error(path, source))?;
    io::copy(&mut (&mut file).take(entry.size), writer).map_err(|source| io_error(path, source))
}

/// Copies one retained member by path and duplicate occurrence.
pub fn copy_by_path_occurrence(path: impl AsRef<Path>, selected_path: &str, selected_occurrence: usize, writer: &mut dyn Write) -> Result<u64, ArError> {
    let path = path.as_ref();
    let selected_index = find_path_occurrence(path, selected_path, selected_occurrence)?;
    copy(path, selected_index, writer)
}

fn find_path_occurrence(path: &Path, selected_path: &str, selected_occurrence: usize) -> Result<usize, ArError> {
    let mut occurrence = 0_usize;
    parse(path)?
        .into_iter()
        .find_map(|entry| {
            if entry.path != selected_path {
                return None;
            }
            let matches = occurrence == selected_occurrence;
            occurrence = occurrence.saturating_add(1);
            matches.then_some(entry.index)
        })
        .ok_or_else(|| ArError::Io { path: path.to_path_buf(), source: io::Error::new(io::ErrorKind::NotFound, "retained AR entry is not present") })
}

#[derive(Debug)]
struct RawEntry {
    token: String,
    bsd_name: Option<String>,
    size: u64,
    data_offset: u64,
    modified: u64,
    mode: u32,
}

fn parse(path: &Path) -> Result<Vec<ArEntry>, ArError> {
    let mut file = open(path)?;
    let mut magic = [0_u8; AR_MAGIC.len()];
    file.read_exact(&mut magic).map_err(|source| io_error(path, source))?;
    if magic != AR_MAGIC {
        return Err(ArError::Invalid { path: path.to_path_buf(), message: "missing !<arch> header".to_owned() });
    }
    let mut raw_entries = Vec::new();
    let mut string_table = Vec::new();
    loop {
        let mut header = [0_u8; 60];
        match file.read_exact(&mut header) {
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(source) => return Err(io_error(path, source)),
        }
        if &header[58..60] != AR_MEMBER_MAGIC {
            return Err(ArError::Invalid { path: path.to_path_buf(), message: "member header has invalid trailer".to_owned() });
        }
        let token = field(&header[0..16]);
        let modified = parse_number(path, &header[16..28])?;
        let mode = parse_octal(path, &header[40..48])?;
        let size = parse_number(path, &header[48..58])?;
        let data_offset = file.stream_position().map_err(|source| io_error(path, source))?;
        let mut bsd_name = None;
        let payload_size = if let Some(length) = token.strip_prefix("#1/") {
            let name_length =
                length.parse::<u64>().map_err(|_| ArError::Invalid { path: path.to_path_buf(), message: "invalid BSD extended name length".to_owned() })?;
            if name_length > size {
                return Err(ArError::Invalid { path: path.to_path_buf(), message: "BSD extended name exceeds member size".to_owned() });
            }
            let mut name = vec![
                0_u8;
                usize::try_from(name_length)
                    .map_err(|_| ArError::Invalid { path: path.to_path_buf(), message: "BSD name is too long".to_owned() })?
            ];
            file.read_exact(&mut name).map_err(|source| io_error(path, source))?;
            bsd_name = Some(String::from_utf8_lossy(&name).trim_end_matches('\0').to_owned());
            size - name_length
        } else if token == "//" {
            string_table = vec![
                0_u8;
                usize::try_from(size)
                    .map_err(|_| ArError::Invalid { path: path.to_path_buf(), message: "AR string table is too large".to_owned() })?
            ];
            file.read_exact(&mut string_table).map_err(|source| io_error(path, source))?;
            0
        } else {
            size
        };
        let payload_offset = if bsd_name.is_some() { data_offset + size - payload_size } else { data_offset };
        if token != "//" {
            skip(&mut file, payload_size, path)?;
        }
        if size % 2 == 1 {
            skip(&mut file, 1, path)?;
        }
        if token != "//" && !token.starts_with('/') && !token.starts_with("__.SYMDEF") {
            raw_entries.push(RawEntry { token, bsd_name, size: payload_size, data_offset: payload_offset, modified, mode });
        }
    }
    raw_entries
        .into_iter()
        .enumerate()
        .map(|(index, raw)| {
            let path_name = raw.bsd_name.unwrap_or_else(|| resolve_gnu_name(&raw.token, &string_table));
            let path_name = path_name.trim_end_matches('/').to_owned();
            if path_name.is_empty() {
                return Err(ArError::Invalid { path: path.to_path_buf(), message: "AR member has an empty name".to_owned() });
            }
            Ok(ArEntry { index, path: path_name, size: raw.size, data_offset: raw.data_offset, modified: raw.modified, mode: raw.mode })
        })
        .collect()
}

fn resolve_gnu_name(token: &str, string_table: &[u8]) -> String {
    let Some(offset) = token.strip_prefix('/').and_then(|value| value.parse::<usize>().ok()) else {
        return token.to_owned();
    };
    let Some(rest) = string_table.get(offset..) else {
        return token.to_owned();
    };
    let end = rest.iter().position(|byte| *byte == b'\n').unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).trim_end_matches('/').to_owned()
}

fn field(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

fn parse_number(path: &Path, bytes: &[u8]) -> Result<u64, ArError> {
    field(bytes).parse::<u64>().map_err(|_| ArError::Invalid { path: path.to_path_buf(), message: "AR numeric header field is invalid".to_owned() })
}

fn parse_octal(path: &Path, bytes: &[u8]) -> Result<u32, ArError> {
    let value = field(bytes);
    let value = value.trim_start_matches('0');
    u32::from_str_radix(if value.is_empty() { "0" } else { value }, 8)
        .map_err(|_| ArError::Invalid { path: path.to_path_buf(), message: "AR octal header field is invalid".to_owned() })
}

fn skip(file: &mut File, bytes: u64, path: &Path) -> Result<(), ArError> {
    file.seek(SeekFrom::Current(i64::try_from(bytes).map_err(|_| ArError::Invalid { path: path.to_path_buf(), message: "AR member is too large".to_owned() })?))
        .map(|_| ())
        .map_err(|source| io_error(path, source))
}

fn open(path: &Path) -> Result<File, ArError> {
    File::open(path).map_err(|source| io_error(path, source))
}

fn io_error(path: &Path, source: io::Error) -> ArError {
    ArError::Io { path: path.to_path_buf(), source }
}
