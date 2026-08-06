//! Split-volume machinery for the 7z backend.
//!
//! `sevenz_rust2` writes a single seekable archive; splitting it into
//! numbered `.7z.001`/`.7z.002`/... volumes is done byte-wise after the
//! archive is finished. Reading a split set requires discovering all parts
//! from any part's path and exposing them as one contiguous
//! [`Read`] + [`Seek`] stream.

use crate::sevenz_backend::SevenZError;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) const MIN_VOLUME_SIZE_BYTES: u64 = 1_048_576;
const SEVENZ_VOLUME_EXTENSION_WIDTH: usize = 3;

pub(crate) fn split_7z_temp_archive(
    archive_path: &Path,
    destination: &Path,
    volume_size: u64,
    replace_existing: bool,
) -> Result<usize, SevenZError> {
    let archive_size = fs::metadata(archive_path)
        .map_err(|source| SevenZError::Io { path: archive_path.to_path_buf(), source })?
        .len();
    let volume_count = crate::archive_split::split_volume_count(archive_size, volume_size)
        .ok_or_else(|| io_error(destination, io::ErrorKind::InvalidInput, "too many 7z volumes"))?;
    let volume_paths = sevenz_volume_paths(destination, volume_count)?;

    let existing_volume_paths = existing_7z_volume_paths(destination)?;
    ensure_split_destinations_available(destination, &volume_paths, &existing_volume_paths, replace_existing)?;

    let archive_file =
        File::open(archive_path).map_err(|source| SevenZError::Io { path: archive_path.to_path_buf(), source })?;
    let mut archive = BufReader::new(archive_file);
    let mut volume_outputs = Vec::with_capacity(volume_paths.len());

    for (index, volume_path) in volume_paths.iter().enumerate() {
        let mut output = crate::atomic_file::AtomicOutputFile::create(volume_path)
            .map_err(|source| SevenZError::Io { path: volume_path.clone(), source })?;
        let offset = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(volume_size))
            .ok_or_else(|| io_error(volume_path, io::ErrorKind::InvalidInput, "7z volume offset overflow"))?;
        let bytes_to_copy = archive_size.saturating_sub(offset).min(volume_size);
        let output_file = output.file_mut().map_err(|source| SevenZError::Io { path: volume_path.clone(), source })?;
        copy_exact_volume_bytes(&mut archive, output_file, bytes_to_copy, volume_path)?;
        output.close();
        volume_outputs.push(output);
    }

    let created_volume_count = volume_paths.len();
    remove_split_destinations_for_replace(destination, &existing_volume_paths, replace_existing)?;
    for (output, volume_path) in volume_outputs.into_iter().zip(volume_paths) {
        output
            .commit_with_file_replace(replace_existing)
            .map_err(|source| SevenZError::Io { path: volume_path, source })?;
    }

    Ok(created_volume_count)
}

fn sevenz_volume_paths(destination: &Path, count: usize) -> Result<Vec<PathBuf>, SevenZError> {
    let mut paths = Vec::with_capacity(count);
    for index in 1..=count {
        let index = u64::try_from(index)
            .map_err(|_| io_error(destination, io::ErrorKind::InvalidInput, "too many 7z volumes"))?;
        paths.push(sevenz_volume_path(destination, index));
    }
    Ok(paths)
}

fn sevenz_volume_path(destination: &Path, one_based_index: u64) -> PathBuf {
    let mut path = destination.as_os_str().to_os_string();
    path.push(format!(".{one_based_index:0SEVENZ_VOLUME_EXTENSION_WIDTH$}"));
    PathBuf::from(path)
}

fn ensure_split_destinations_available(
    destination: &Path,
    volume_paths: &[PathBuf],
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> Result<(), SevenZError> {
    ensure_file_destination_available(destination, replace_existing)?;
    for path in crate::archive_split::unique_paths(volume_paths, existing_volume_paths) {
        ensure_file_destination_available(path, replace_existing)?;
    }
    Ok(())
}

fn ensure_file_destination_available(path: &Path, replace_existing: bool) -> Result<(), SevenZError> {
    crate::archive_split::ensure_file_destination_available(path, replace_existing)
        .map_err(|source| SevenZError::Io { path: path.to_path_buf(), source })
}

fn remove_split_destinations_for_replace(
    destination: &Path,
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> Result<(), SevenZError> {
    crate::archive_split::remove_split_destinations_for_replace(destination, existing_volume_paths, replace_existing)
        .map_err(|source| SevenZError::Io { path: destination.to_path_buf(), source })
}

fn existing_7z_volume_paths(destination: &Path) -> Result<Vec<PathBuf>, SevenZError> {
    let Some(destination_name) = destination.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };
    let directory = destination.parent().unwrap_or_else(|| Path::new("."));
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(SevenZError::Io { path: directory.to_path_buf(), source });
        }
    };
    let mut paths = BTreeMap::new();

    for entry in entries.flatten() {
        let candidate_name = entry.file_name();
        let Some(candidate_name) = candidate_name.to_str() else {
            continue;
        };
        if let Some((base_name, part)) = parse_7z_volume_file_name(candidate_name)
            && base_name == destination_name
        {
            paths.insert(part, entry.path());
        }
    }

    Ok(paths.into_values().collect())
}

pub(crate) fn parse_7z_volume_file_name(name: &str) -> Option<(&str, u32)> {
    let (base, number) = name.rsplit_once('.')?;
    if number.len() != SEVENZ_VOLUME_EXTENSION_WIDTH || !number.chars().all(|value| value.is_ascii_digit()) {
        return None;
    }
    let part = number.parse().ok()?;
    (part > 0).then_some((base, part))
}

pub(crate) fn has_7z_extension(value: &str) -> bool {
    Path::new(value).extension().is_some_and(|extension| extension.eq_ignore_ascii_case("7z"))
}

pub(crate) fn discover_7z_read_volume_paths(path: &Path) -> Result<Vec<PathBuf>, SevenZError> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(vec![path.to_path_buf()]);
    };
    let lower_name = file_name.to_ascii_lowercase();
    let volume_base = if let Some((base, _)) = parse_7z_volume_file_name(&lower_name) {
        if !has_7z_extension(base) {
            return Ok(vec![path.to_path_buf()]);
        }
        base.to_owned()
    } else if has_7z_extension(&lower_name) {
        lower_name
    } else {
        return Ok(vec![path.to_path_buf()]);
    };
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(vec![path.to_path_buf()]);
        }
        Err(source) => {
            return Err(SevenZError::Io { path: directory.to_path_buf(), source });
        }
    };

    let mut parts = BTreeMap::new();
    for entry in entries.flatten() {
        let candidate_name = entry.file_name();
        let Some(candidate_name) = candidate_name.to_str() else {
            continue;
        };
        let candidate_lower = candidate_name.to_ascii_lowercase();
        if let Some((candidate_base, part)) = parse_7z_volume_file_name(&candidate_lower)
            && candidate_base == volume_base
        {
            parts.insert(part, entry.path());
        }
    }

    if parts.is_empty() {
        return Ok(vec![path.to_path_buf()]);
    }
    let max_part = *parts.keys().last().unwrap_or(&0);
    for expected in 1..=max_part {
        if !parts.contains_key(&expected) {
            return Err(io_error(path, io::ErrorKind::NotFound, format!("missing 7z volume part {expected:03}")));
        }
    }
    Ok(parts.into_values().collect())
}

pub(crate) struct MultiVolumeReader {
    parts: Vec<MultiVolumePart>,
    total_len: u64,
    position: u64,
}

struct MultiVolumePart {
    path: PathBuf,
    file: File,
    start: u64,
    len: u64,
}

impl MultiVolumeReader {
    pub(crate) fn open(paths: Vec<PathBuf>) -> Result<Self, SevenZError> {
        let mut parts = Vec::with_capacity(paths.len());
        let mut total_len = 0u64;
        for path in paths {
            let file = File::open(&path).map_err(|source| SevenZError::Io { path: path.clone(), source })?;
            let len = file.metadata().map_err(|source| SevenZError::Io { path: path.clone(), source })?.len();
            parts.push(MultiVolumePart { path, file, start: total_len, len });
            total_len = total_len.checked_add(len).ok_or_else(|| {
                io_error(Path::new("archive.7z.001"), io::ErrorKind::InvalidInput, "7z volume set is too large")
            })?;
        }
        Ok(Self { parts, total_len, position: 0 })
    }

    fn current_part_index(&self) -> Option<usize> {
        self.parts
            .iter()
            .position(|part| self.position >= part.start && self.position < part.start.saturating_add(part.len))
    }
}

impl Read for MultiVolumeReader {
    fn read(&mut self, mut buffer: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.total_len || buffer.is_empty() {
            return Ok(0);
        }

        let mut copied = 0usize;
        while !buffer.is_empty() && self.position < self.total_len {
            let Some(index) = self.current_part_index() else {
                break;
            };
            let part = &mut self.parts[index];
            let offset = self.position.saturating_sub(part.start);
            let remaining_in_part =
                usize::try_from(part.len.saturating_sub(offset)).unwrap_or(usize::MAX).min(buffer.len());
            part.file.seek(SeekFrom::Start(offset))?;
            let read = part.file.read(&mut buffer[..remaining_in_part])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("unexpected EOF in {}", part.path.display()),
                ));
            }
            self.position = self
                .position
                .checked_add(u64::try_from(read).unwrap_or(0))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "7z volume position overflow"))?;
            copied += read;
            buffer = &mut buffer[read..];
        }
        Ok(copied)
    }
}

impl Seek for MultiVolumeReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let target = match position {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::End(offset) => i128::from(self.total_len) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        if target < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "cannot seek before start of 7z volume set"));
        }
        self.position = u64::try_from(target)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "7z volume seek target overflow"))?;
        Ok(self.position)
    }
}

fn copy_exact_volume_bytes<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    bytes_to_copy: u64,
    volume_path: &Path,
) -> Result<(), SevenZError> {
    let mut limited = reader.take(bytes_to_copy);
    let copied =
        io::copy(&mut limited, writer).map_err(|source| SevenZError::Io { path: volume_path.to_path_buf(), source })?;
    if copied != bytes_to_copy {
        return Err(io_error(
            volume_path,
            io::ErrorKind::UnexpectedEof,
            "7z temp archive ended before volume was filled",
        ));
    }
    Ok(())
}

fn io_error(path: &Path, kind: io::ErrorKind, message: impl Into<String>) -> SevenZError {
    SevenZError::Io { path: path.to_path_buf(), source: io::Error::new(kind, message.into()) }
}

#[cfg(test)]
mod tests {
    use super::MIN_VOLUME_SIZE_BYTES;
    use crate::safety::ExtractionPolicy;
    use crate::secrets::SecretString;
    use crate::sevenz_backend::{SevenZCreateOptions, SevenZError, create_7z_from_path, extract_7z, list_7z};
    use crate::test_support::TestDir;
    use std::fs;

    #[test]
    fn creates_split_7z_volumes() {
        let temp = TestDir::new("creates_split_7z_volumes");
        let payload = deterministic_bytes(3 * 1024 * 1024);
        temp.write_file("payload/blob.bin", &payload);
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                volume_size: Some(MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert_eq!(report.volume_size, Some(MIN_VOLUME_SIZE_BYTES));
        assert!(report.volume_count >= 2);
        assert!(!archive.exists());
        assert_eq!(fs::metadata(temp.path("payload.7z.001")).unwrap().len(), MIN_VOLUME_SIZE_BYTES);

        let mut joined = Vec::new();
        for index in 1..=report.volume_count {
            let part = temp.path(format!("payload.7z.{index:03}"));
            let part_bytes = fs::read(part).unwrap();
            assert!(u64::try_from(part_bytes.len()).unwrap() <= MIN_VOLUME_SIZE_BYTES);
            joined.extend(part_bytes);
        }
        temp.write_file("joined.7z", &joined);

        let listing = list_7z(temp.path("joined.7z"), None).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.name == "payload/blob.bin"));
        let extract_report =
            extract_7z(temp.path("joined.7z"), temp.path("out"), None, ExtractionPolicy::default()).unwrap();

        assert_eq!(extract_report.written_bytes, payload.len() as u64);
        assert_eq!(fs::read(temp.path("out/payload/blob.bin")).unwrap(), payload);
    }

    #[test]
    fn passworded_split_7z_volumes_read_from_first_part() {
        let temp = TestDir::new("passworded_split_7z_volumes_read_from_first_part");
        let payload = deterministic_bytes(3 * 1024 * 1024);
        temp.write_file("payload/blob.bin", &payload);
        let archive = temp.path("payload.7z");
        let first_volume = temp.path("payload.7z.001");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                password: Some(SecretString::from("correct horse")),
                encrypt_file_names: true,
                volume_size: Some(MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert!(report.encrypted);
        assert!(report.volume_count >= 2);
        assert!(matches!(list_7z(&first_volume, None), Err(SevenZError::PasswordRequired)));

        let listing = list_7z(&first_volume, Some("correct horse")).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.name == "payload/blob.bin"));
        let extract_report =
            extract_7z(&first_volume, temp.path("out"), Some("correct horse"), ExtractionPolicy::default()).unwrap();

        assert_eq!(extract_report.written_bytes, payload.len() as u64);
        assert_eq!(fs::read(temp.path("out/payload/blob.bin")).unwrap(), payload);
    }

    #[test]
    fn single_volume_split_7z_reads_from_base_path() {
        let temp = TestDir::new("single_volume_split_7z_reads_from_base_path");
        temp.write_file("payload/file.txt", b"small payload");
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                volume_size: Some(MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert_eq!(report.volume_count, 1);
        assert!(!archive.exists());
        assert!(temp.path("payload.7z.001").exists());

        let listing = list_7z(&archive, None).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.name == "payload/file.txt"));
    }

    #[test]
    fn split_7z_refuses_existing_volume_without_replace() {
        let temp = TestDir::new("split_7z_refuses_existing_volume_without_replace");
        temp.write_file("payload/blob.bin", &deterministic_bytes(2 * 1024 * 1024));
        temp.write_file("payload.7z.001", b"old");
        let archive = temp.path("payload.7z");

        let error = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                volume_size: Some(MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("destination already exists"));
        assert_eq!(fs::read(temp.path("payload.7z.001")).unwrap(), b"old");
    }

    #[test]
    fn split_7z_replace_removes_stale_old_volumes() {
        let temp = TestDir::new("split_7z_replace_removes_stale_old_volumes");
        temp.write_file("payload/blob.bin", &deterministic_bytes(2 * 1024 * 1024));
        let archive = temp.path("payload.7z");

        create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                volume_size: Some(MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();
        assert!(temp.path("payload.7z.002").exists());

        temp.write_file("payload/blob.bin", b"small");
        create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                replace_existing: true,
                volume_size: Some(MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert!(temp.path("payload.7z.001").exists());
        assert!(!temp.path("payload.7z.002").exists());
    }

    fn deterministic_bytes(len: usize) -> Vec<u8> {
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
}
