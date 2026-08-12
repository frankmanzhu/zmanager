//! Multi-volume and split-archive discovery for the libarchive backend.
//!
//! libarchive itself only reads a single file, so split and multi-part
//! archive sets — standard split ZIP (`.z01`/.../`.zip`), numbered 7z/zip
//! stream volumes (`.7z.001`/...), and RAR parts (`.partNN` and old-style
//! `.rNN`) — must be discovered and ordered before libarchive sees them.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const NUMBERED_VOLUME_EXTENSION_WIDTH: usize = 3;
const NUMBERED_VOLUME_ARCHIVE_SUFFIXES: &[&str] = &[".7z", ".zip"];

/// Returns true when `path` belongs to a standard split ZIP set.
#[must_use]
pub(crate) fn is_split_zip_path(path: &Path) -> bool {
    discover_split_zip_paths(path).is_some_and(|paths| paths.len() > 1)
}

pub(crate) fn discover_multi_volume_paths(path: &Path) -> Vec<PathBuf> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return vec![path.to_path_buf()];
    };
    let lower_name = file_name.to_ascii_lowercase();
    let directory = path.parent().unwrap_or_else(|| Path::new("."));

    if let Some(parts) = discover_split_zip_paths(path) {
        return parts;
    }

    if let Some(parts) = discover_numbered_archive_volume_paths(directory, &lower_name) {
        return parts;
    }

    if let Some((base, _)) = parse_part_rar_name(&lower_name)
        && let Ok(entries) = fs::read_dir(directory)
    {
        let mut parts = BTreeMap::new();
        for entry in entries.flatten() {
            let candidate_name = entry.file_name();
            let Some(candidate_name) = candidate_name.to_str() else {
                continue;
            };
            let candidate_lower = candidate_name.to_ascii_lowercase();
            if let Some((candidate_base, part)) = parse_part_rar_name(&candidate_lower)
                && candidate_base == base
            {
                parts.insert(part, entry.path());
            }
        }
        if parts.len() > 1 {
            return parts.into_values().collect();
        }
    }

    if let Some((base, first_path)) = old_style_rar_base(path, &lower_name)
        && let Ok(entries) = fs::read_dir(directory)
    {
        let mut numbered_parts = BTreeMap::new();
        for entry in entries.flatten() {
            let candidate_name = entry.file_name();
            let Some(candidate_name) = candidate_name.to_str() else {
                continue;
            };
            let candidate_lower = candidate_name.to_ascii_lowercase();
            if let Some(part) = parse_old_rar_part_name(&candidate_lower, base) {
                numbered_parts.insert(part, entry.path());
            }
        }
        if !numbered_parts.is_empty() {
            let mut parts = Vec::with_capacity(numbered_parts.len() + 1);
            parts.push(first_path);
            parts.extend(numbered_parts.into_values());
            return parts;
        }
    }

    vec![path.to_path_buf()]
}

fn discover_split_zip_paths(path: &Path) -> Option<Vec<PathBuf>> {
    let file_name = path.file_name()?.to_str()?;
    let lower_name = file_name.to_ascii_lowercase();
    let (base, _) = parse_split_zip_volume_name(&lower_name)?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let entries = fs::read_dir(directory).ok()?;
    let mut sidecars = BTreeMap::new();
    let mut final_zip = None;

    for entry in entries.flatten() {
        let candidate_name = entry.file_name();
        let Some(candidate_name) = candidate_name.to_str() else {
            continue;
        };
        let candidate_lower = candidate_name.to_ascii_lowercase();
        let Some((candidate_base, part)) = parse_split_zip_volume_name(&candidate_lower) else {
            continue;
        };
        if candidate_base != base {
            continue;
        }
        match part {
            SplitZipPart::Sidecar(index) => {
                sidecars.insert(index, entry.path());
            }
            SplitZipPart::Final => {
                final_zip = Some(entry.path());
            }
        }
    }

    let final_zip = final_zip?;
    let max_sidecar = *sidecars.keys().last()?;
    for expected in 1..=max_sidecar {
        sidecars.get(&expected)?;
    }

    let mut parts = sidecars.into_values().collect::<Vec<_>>();
    parts.push(final_zip);
    Some(parts)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SplitZipPart {
    Sidecar(u32),
    Final,
}

fn parse_split_zip_volume_name(name: &str) -> Option<(&str, SplitZipPart)> {
    let (base, extension) = name.rsplit_once('.')?;
    if extension == "zip" {
        return Some((base, SplitZipPart::Final));
    }
    let number = extension.strip_prefix('z')?;
    if number.len() < 2 || !number.chars().all(|value| value.is_ascii_digit()) {
        return None;
    }
    let index = number.parse().ok()?;
    (index > 0).then_some((base, SplitZipPart::Sidecar(index)))
}

#[cfg(test)]
fn parse_numbered_7z_volume_name(name: &str) -> Option<(&str, u32)> {
    let (base, part) = parse_numbered_archive_volume_name(name)?;
    has_7z_extension(base).then_some((base, part))
}

fn discover_numbered_archive_volume_paths(directory: &Path, lower_name: &str) -> Option<Vec<PathBuf>> {
    let (base, _) = parse_numbered_archive_volume_name(lower_name)?;
    let entries = fs::read_dir(directory).ok()?;
    let mut parts = BTreeMap::new();
    for entry in entries.flatten() {
        let candidate_name = entry.file_name();
        let Some(candidate_name) = candidate_name.to_str() else {
            continue;
        };
        let candidate_lower = candidate_name.to_ascii_lowercase();
        if let Some((candidate_base, part)) = parse_numbered_archive_volume_name(&candidate_lower)
            && candidate_base == base
        {
            parts.insert(part, entry.path());
        }
    }
    (parts.len() > 1).then(|| parts.into_values().collect())
}

fn parse_numbered_archive_volume_name(name: &str) -> Option<(&str, u32)> {
    let (base, number) = name.rsplit_once('.')?;
    if !NUMBERED_VOLUME_ARCHIVE_SUFFIXES.iter().any(|suffix| base.ends_with(suffix)) || number.len() != NUMBERED_VOLUME_EXTENSION_WIDTH || !number.chars().all(|value| value.is_ascii_digit()) {
        return None;
    }
    let part = number.parse().ok()?;
    (part > 0).then_some((base, part))
}

#[cfg(test)]
fn has_7z_extension(value: &str) -> bool {
    Path::new(value).extension().is_some_and(|extension| extension.eq_ignore_ascii_case("7z"))
}

fn parse_part_rar_name(name: &str) -> Option<(&str, u32)> {
    let stem = name.strip_suffix(".rar")?;
    let marker = stem.rfind(".part")?;
    let base = &stem[..marker];
    let number = &stem[marker + ".part".len()..];
    if base.is_empty() || number.is_empty() || !number.chars().all(|value| value.is_ascii_digit()) {
        return None;
    }
    Some((base, number.parse().ok()?))
}

fn old_style_rar_base<'a>(path: &Path, lower_name: &'a str) -> Option<(&'a str, PathBuf)> {
    if let Some(base) = lower_name.strip_suffix(".rar")
        && !base.is_empty()
    {
        return Some((base, path.to_path_buf()));
    }

    None
}

fn parse_old_rar_part_name(name: &str, base: &str) -> Option<u32> {
    let suffix = name.strip_prefix(base)?.strip_prefix(".r")?;
    if suffix.len() != 2 || !suffix.chars().all(|value| value.is_ascii_digit()) {
        return None;
    }
    suffix.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{discover_multi_volume_paths, is_split_zip_path, parse_numbered_7z_volume_name, parse_numbered_archive_volume_name};
    use crate::libarchive_backend::{extract_archive, list_archive};
    use crate::safety::ExtractionPolicy;
    use crate::sevenz_backend::{SevenZCreateOptions, create_7z_from_path};
    use crate::test_support::TestDir;
    use std::fs;
    use std::path::{Path, PathBuf};

    #[test]
    fn lists_and_extracts_numbered_7z_volumes() {
        let temp = TestDir::new("lists_and_extracts_numbered_7z_volumes");
        let payload = deterministic_bytes(3 * 1024 * 1024);
        temp.write_file("payload/blob.bin", &payload);
        let archive = temp.path("payload.7z");

        create_7z_from_path(temp.path("payload"), &archive, &SevenZCreateOptions { solid: false, level: Some(1), volume_size: Some(1_048_576), ..SevenZCreateOptions::default() }).unwrap();

        let listing = list_archive(temp.path("payload.7z.001")).unwrap();
        let report = extract_archive(temp.path("payload.7z.001"), temp.path("out"), ExtractionPolicy::default()).unwrap();

        assert!(listing.entries.iter().any(|entry| entry.path == "payload/blob.bin"));
        assert_eq!(report.written_bytes, payload.len() as u64);
        assert_eq!(fs::read(temp.path("out/payload/blob.bin")).unwrap(), payload);
    }

    #[test]
    fn discovers_numbered_7z_volumes_from_any_part() {
        let temp = TestDir::new("discovers_numbered_7z_volumes_from_any_part");
        temp.write_file("payload.7z.001", b"a");
        temp.write_file("payload.7z.002", b"b");
        temp.write_file("payload.7z.003", b"c");

        let from_first = discover_multi_volume_paths(&temp.path("payload.7z.001"));
        let from_middle = discover_multi_volume_paths(&temp.path("payload.7z.002"));

        assert_eq!(relative_names(temp.root(), &from_first), vec!["payload.7z.001", "payload.7z.002", "payload.7z.003"]);
        assert_eq!(from_middle, from_first);
    }

    #[test]
    fn discovers_numbered_zip_stream_volumes_from_any_part() {
        let temp = TestDir::new("discovers_numbered_zip_stream_volumes_from_any_part");
        temp.write_file("payload.zip.001", b"a");
        temp.write_file("payload.zip.002", b"b");
        temp.write_file("payload.zip.003", b"c");

        let from_first = discover_multi_volume_paths(&temp.path("payload.zip.001"));
        let from_middle = discover_multi_volume_paths(&temp.path("payload.zip.002"));

        assert_eq!(relative_names(temp.root(), &from_first), vec!["payload.zip.001", "payload.zip.002", "payload.zip.003"]);
        assert_eq!(from_middle, from_first);
    }

    #[test]
    fn discovers_standard_split_zip_volumes_from_final_or_sidecar() {
        let temp = TestDir::new("discovers_standard_split_zip_volumes_from_final_or_sidecar");
        temp.write_file("payload.z01", b"a");
        temp.write_file("payload.z02", b"b");
        temp.write_file("payload.zip", b"c");

        let from_final = discover_multi_volume_paths(&temp.path("payload.zip"));
        let from_sidecar = discover_multi_volume_paths(&temp.path("payload.z01"));

        assert_eq!(relative_names(temp.root(), &from_final), vec!["payload.z01", "payload.z02", "payload.zip"]);
        assert_eq!(from_sidecar, from_final);
        assert!(is_split_zip_path(&temp.path("payload.zip")));
    }

    #[test]
    fn parses_only_numbered_7z_volume_names() {
        assert_eq!(parse_numbered_7z_volume_name("payload.7z.001"), Some(("payload.7z", 1)));
        assert_eq!(parse_numbered_7z_volume_name("payload.7z.000"), None);
        assert_eq!(parse_numbered_7z_volume_name("payload.zip.001"), None);
        assert_eq!(parse_numbered_7z_volume_name("payload.7z.01"), None);
        assert_eq!(parse_numbered_archive_volume_name("payload.zip.001"), Some(("payload.zip", 1)));
    }

    fn relative_names(root: &Path, paths: &[PathBuf]) -> Vec<String> {
        paths.iter().map(|path| path.strip_prefix(root).unwrap().to_string_lossy().into_owned()).collect()
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
