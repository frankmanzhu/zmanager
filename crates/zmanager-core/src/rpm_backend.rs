//! Bounded native RPM container reader composing an RPM header with CPIO.

use crate::cpio_backend;
use crate::engine::types::TestOptions;
use crate::safety::{ExtractionPolicy, OverwriteResolver};
use crate::temp_names::{TempDirAllocError, TemporaryDirectory};
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

const RPM_LEAD_SIZE: u64 = 96;
const RPM_LEAD_SIZE_BYTES: usize = 96;
const RPM_LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];
const RPM_HEADER_MAGIC: [u8; 4] = [0x8e, 0xad, 0xe8, 0x01];
const PAYLOAD_COMPRESSOR_TAG: u32 = 1125;
const MAX_HEADER_INDEXES: u32 = 1_000_000;
const MAX_HEADER_DATA_BYTES: u32 = 64 * 1024 * 1024;

/// Native RPM payload description.
#[derive(Debug, Clone, Eq, PartialEq)]
struct RpmPayload {
    offset: u64,
    size: u64,
    suffix: &'static str,
}

/// Error returned by native RPM operations.
#[derive(Debug)]
pub enum RpmError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// The RPM framing or header is malformed.
    Invalid { path: PathBuf, message: String },
    /// The embedded CPIO payload failed.
    Cpio(cpio_backend::CpioError),
    /// The embedded payload compression stream failed.
    RawStream(crate::raw_stream_backend::RawStreamError),
}

impl fmt::Display for RpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Invalid { path, message } => write!(f, "invalid RPM {}: {message}", path.display()),
            Self::Cpio(source) => write!(f, "RPM CPIO payload failed: {source}"),
            Self::RawStream(source) => write!(f, "RPM payload decoder failed: {source}"),
        }
    }
}

impl std::error::Error for RpmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Cpio(source) => Some(source),
            Self::RawStream(source) => Some(source),
            Self::Invalid { .. } => None,
        }
    }
}

impl From<cpio_backend::CpioError> for RpmError {
    fn from(source: cpio_backend::CpioError) -> Self {
        Self::Cpio(source)
    }
}

impl From<crate::raw_stream_backend::RawStreamError> for RpmError {
    fn from(source: crate::raw_stream_backend::RawStreamError) -> Self {
        Self::RawStream(source)
    }
}

impl From<TempDirAllocError> for RpmError {
    fn from(error: TempDirAllocError) -> Self {
        Self::Io { path: error.path, source: error.source }
    }
}

/// Lists entries from the RPM's embedded CPIO payload.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<cpio_backend::CpioEntry>, RpmError> {
    let (_temporary, payload) = materialize_payload(path.as_ref())?;
    cpio_backend::list(payload).map_err(RpmError::from)
}

/// Verifies entries and checksums in the RPM's embedded CPIO payload.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<cpio_backend::CpioReport, RpmError> {
    let (_temporary, payload) = materialize_payload(path.as_ref())?;
    cpio_backend::test(payload, options).map_err(RpmError::from)
}

/// Extracts the RPM's embedded CPIO payload using the shared safety policy.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<cpio_backend::CpioReport, RpmError> {
    let (_temporary, payload) = materialize_payload(path.as_ref())?;
    cpio_backend::extract(payload, destination, policy, resolver, None, cancellation).map_err(RpmError::from)
}

/// Copies one retained CPIO payload entry to a caller-owned writer.
pub fn copy(path: impl AsRef<Path>, entry_index: usize, writer: &mut dyn io::Write) -> Result<u64, RpmError> {
    let (_temporary, payload) = materialize_payload(path.as_ref())?;
    cpio_backend::copy(payload, entry_index, writer).map_err(RpmError::from)
}

/// Copies one retained CPIO payload entry by path and duplicate occurrence.
pub fn copy_by_path_occurrence(path: impl AsRef<Path>, selected_path: &str, selected_occurrence: usize, writer: &mut dyn io::Write) -> Result<u64, RpmError> {
    let (_temporary, payload) = materialize_payload(path.as_ref())?;
    cpio_backend::copy_by_path_occurrence(&payload, selected_path, selected_occurrence, writer).map_err(RpmError::from)
}

fn materialize_payload(path: &Path) -> Result<(TemporaryDirectory, PathBuf), RpmError> {
    let payload = parse_payload(path)?;
    let temporary = TemporaryDirectory::new("zmanager-rpm")?;
    let payload_path = temporary.path().join(format!("payload.cpio{}", payload.suffix));
    let mut input = File::open(path).map_err(|source| RpmError::Io { path: path.to_path_buf(), source })?;
    input.seek(SeekFrom::Start(payload.offset)).map_err(|source| RpmError::Io { path: path.to_path_buf(), source })?;
    let mut limited = input.take(payload.size);
    let mut output = File::create(&payload_path).map_err(|source| RpmError::Io { path: payload_path.clone(), source })?;
    io::copy(&mut limited, &mut output).map_err(|source| RpmError::Io { path: payload_path.clone(), source })?;
    if limited.limit() != 0 {
        return Err(RpmError::Invalid { path: path.to_path_buf(), message: "RPM payload is truncated".to_owned() });
    }
    output.flush().map_err(|source| RpmError::Io { path: payload_path.clone(), source })?;
    if payload.suffix.is_empty() {
        return Ok((temporary, payload_path));
    }
    let format = match payload.suffix {
        ".gz" => crate::raw_stream_backend::RawStreamFormat::Gzip,
        ".bz2" => crate::raw_stream_backend::RawStreamFormat::Bzip2,
        ".xz" => crate::raw_stream_backend::RawStreamFormat::Xz,
        ".lzma" => crate::raw_stream_backend::RawStreamFormat::Lzma,
        ".zst" => crate::raw_stream_backend::RawStreamFormat::Zstd,
        _ => return Err(invalid(path, "RPM payload compression suffix has no decoder")),
    };
    let mut decoder = crate::raw_stream_backend::open_decoder(&payload_path, format)?;
    let decoded_path = temporary.path().join("payload.cpio");
    let mut decoded_output = File::create(&decoded_path).map_err(|source| RpmError::Io { path: decoded_path.clone(), source })?;
    io::copy(&mut decoder, &mut decoded_output).map_err(|source| RpmError::Io { path: decoded_path.clone(), source })?;
    decoded_output.flush().map_err(|source| RpmError::Io { path: decoded_path.clone(), source })?;
    Ok((temporary, decoded_path))
}

fn parse_payload(path: &Path) -> Result<RpmPayload, RpmError> {
    let mut file = File::open(path).map_err(|source| RpmError::Io { path: path.to_path_buf(), source })?;
    let file_size = file.metadata().map_err(|source| RpmError::Io { path: path.to_path_buf(), source })?.len();
    if file_size < RPM_LEAD_SIZE {
        return Err(invalid(path, "RPM lead is truncated"));
    }
    let mut lead = [0_u8; RPM_LEAD_SIZE_BYTES];
    file.read_exact(&mut lead).map_err(|source| io_error(path, source))?;
    if lead[..4] != RPM_LEAD_MAGIC {
        return Err(invalid(path, "RPM lead magic is invalid"));
    }

    let signature = read_header(&mut file, path)?;
    let aligned = align_eight(signature.end)?;
    if aligned > signature.end {
        file.seek(SeekFrom::Start(aligned)).map_err(|source| io_error(path, source))?;
    }
    let main = read_header(&mut file, path)?;
    let payload_offset = main.end;
    if payload_offset > file_size {
        return Err(invalid(path, "RPM main header extends past end of file"));
    }
    let compressor = main.string_value(PAYLOAD_COMPRESSOR_TAG).unwrap_or_default();
    let suffix = payload_suffix(&compressor, path)?;
    Ok(RpmPayload { offset: payload_offset, size: file_size - payload_offset, suffix })
}

fn payload_suffix<'a>(compressor: &str, path: &Path) -> Result<&'a str, RpmError> {
    match compressor.trim().to_ascii_lowercase().as_str() {
        "" | "none" => Ok(""),
        "gzip" | "gz" => Ok(".gz"),
        "bzip2" | "bzip" | "bz2" => Ok(".bz2"),
        "xz" => Ok(".xz"),
        "lzma" => Ok(".lzma"),
        "zstd" | "zstandard" => Ok(".zst"),
        other => Err(invalid(path, &format!("unsupported RPM payload compressor {other}"))),
    }
}

#[derive(Debug)]
struct Header {
    end: u64,
    indexes: Vec<Index>,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct Index {
    tag: u32,
    kind: u32,
    offset: u32,
    count: u32,
}

impl Header {
    fn string_value(&self, tag: u32) -> Option<String> {
        let index = self.indexes.iter().find(|index| index.tag == tag && matches!(index.kind, 6 | 9))?;
        if index.count == 0 {
            return None;
        }
        let start = usize::try_from(index.offset).ok()?;
        let bytes = self.data.get(start..)?;
        let bytes = if index.kind == 6 {
            bytes
        } else {
            let count = usize::try_from(index.count).ok()?;
            bytes.get(..count.min(bytes.len()))?
        };
        let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
        String::from_utf8(bytes[..end].to_vec()).ok()
    }
}

fn read_header(file: &mut File, path: &Path) -> Result<Header, RpmError> {
    let mut fixed = [0_u8; 16];
    file.read_exact(&mut fixed).map_err(|source| io_error(path, source))?;
    if fixed[..4] != RPM_HEADER_MAGIC {
        return Err(invalid(path, "RPM header magic is invalid"));
    }
    let count = u32::from_be_bytes(fixed[8..12].try_into().unwrap());
    let data_size = u32::from_be_bytes(fixed[12..16].try_into().unwrap());
    if count > MAX_HEADER_INDEXES || data_size > MAX_HEADER_DATA_BYTES {
        return Err(invalid(path, "RPM header exceeds bounded index or data limits"));
    }
    let index_bytes = usize::try_from(count).unwrap().checked_mul(16).ok_or_else(|| invalid(path, "RPM header index size overflows"))?;
    let mut raw_indexes = vec![0_u8; index_bytes];
    file.read_exact(&mut raw_indexes).map_err(|source| io_error(path, source))?;
    let mut indexes = Vec::with_capacity(usize::try_from(count).unwrap());
    for chunk in raw_indexes.chunks_exact(16) {
        indexes.push(Index {
            tag: u32::from_be_bytes(chunk[0..4].try_into().unwrap()),
            kind: u32::from_be_bytes(chunk[4..8].try_into().unwrap()),
            offset: u32::from_be_bytes(chunk[8..12].try_into().unwrap()),
            count: u32::from_be_bytes(chunk[12..16].try_into().unwrap()),
        });
    }
    let mut data = vec![0_u8; usize::try_from(data_size).unwrap()];
    file.read_exact(&mut data).map_err(|source| io_error(path, source))?;
    let end = file.stream_position().map_err(|source| io_error(path, source))?;
    Ok(Header { end, indexes, data })
}

fn align_eight(value: u64) -> Result<u64, RpmError> {
    value.checked_add(7).map(|aligned| aligned & !7).ok_or_else(|| invalid(Path::new("<RPM>"), "RPM header alignment overflows"))
}

fn invalid(path: &Path, message: &str) -> RpmError {
    RpmError::Invalid { path: path.to_path_buf(), message: message.to_owned() }
}

fn io_error(path: &Path, source: io::Error) -> RpmError {
    RpmError::Io { path: path.to_path_buf(), source }
}
