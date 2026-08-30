//! Cross-check committed fixtures against the external tools that authored or
//! commonly consume them. The fixture files keep this coverage deterministic;
//! the external tools are only test oracles and are never runtime dependencies.

#![cfg(unix)]

mod common;

use common::{TestDir, assert_success, assert_trees_match, collect_tree_entries, find_on_path, is_apple_double, zm_path};

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Clone, Copy)]
enum ExternalArchiveTool {
    SevenZip,
    Unzip,
    Tar,
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn compress_program_for(archive: &Path) -> Option<&'static str> {
    let name = archive.file_name().and_then(|n| n.to_str())?;
    if name.ends_with(".lz4") {
        Some("lz4")
    } else if name.ends_with(".lz") {
        Some("lzip")
    } else if name.ends_with(".lzo") {
        Some("lzop")
    } else if name.ends_with(".zst") {
        Some("zstd")
    } else if name.ends_with(".tar.Z") || name.ends_with(".taz") {
        if find_on_path("uncompress").is_some() {
            Some("uncompress")
        } else if find_on_path("ncompress").is_some() {
            Some("ncompress")
        } else {
            Some("compress")
        }
    } else {
        None
    }
}

impl ExternalArchiveTool {
    fn binary(self) -> Option<PathBuf> {
        match self {
            Self::SevenZip => find_on_path("7zz").or_else(|| find_on_path("7z")),
            Self::Unzip => find_on_path("unzip"),
            Self::Tar => find_on_path("bsdtar").or_else(|| find_on_path("tar")),
        }
    }

    #[allow(clippy::collapsible_if)]
    fn list(self, binary: &Path, archive: &Path) -> Output {
        match self {
            Self::SevenZip => Command::new(binary).args(["l", "-ba"]).arg(archive).output().unwrap(),
            Self::Unzip => Command::new(binary).args(["-Z1"]).arg(archive).output().unwrap(),
            Self::Tar => {
                let mut cmd = Command::new(binary);
                let binary_name = binary.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if binary_name == "tar" {
                    if let Some(program) = compress_program_for(archive) {
                        cmd.arg(format!("--use-compress-program={program}"));
                    }
                }
                cmd.arg("-tf").arg(archive).output().unwrap()
            }
        }
    }

    #[allow(clippy::collapsible_if)]
    fn extract(self, binary: &Path, archive: &Path, destination: &Path) -> Output {
        match self {
            Self::SevenZip => Command::new(binary).arg("x").arg("-y").arg(format!("-o{}", destination.display())).arg(archive).output().unwrap(),
            Self::Unzip => Command::new(binary).args(["-q", "-o"]).arg(archive).arg("-d").arg(destination).output().unwrap(),
            Self::Tar => {
                let mut cmd = Command::new(binary);
                let binary_name = binary.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if binary_name == "tar" {
                    if let Some(program) = compress_program_for(archive) {
                        cmd.arg(format!("--use-compress-program={program}"));
                    }
                }
                cmd.arg("-xf").arg(archive).arg("-C").arg(destination).output().unwrap()
            }
        }
    }
}

#[derive(Clone, Copy)]
struct FixtureCase {
    filename: &'static str,
    tool: ExternalArchiveTool,
}

impl FixtureCase {
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn is_supported(self, binary: &Path) -> bool {
        let name = binary.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "tar" {
            if self.filename.ends_with(".cpio") {
                return false;
            }
            if self.filename.ends_with(".lz") && find_on_path("lzip").is_none() {
                return false;
            }
            if self.filename.ends_with(".lzo") && find_on_path("lzop").is_none() {
                return false;
            }
            if (self.filename.ends_with(".tar.Z") || self.filename.ends_with(".taz"))
                && find_on_path("uncompress").is_none()
                && find_on_path("ncompress").is_none()
                && find_on_path("compress").is_none()
            {
                return false;
            }
            if self.filename.ends_with(".lz4") && find_on_path("lz4").is_none() {
                return false;
            }
            if self.filename.ends_with(".zst") && find_on_path("zstd").is_none() {
                return false;
            }
            if (self.filename.ends_with(".xz") || self.filename.ends_with(".lzma")) && find_on_path("xz").is_none() && find_on_path("lzma").is_none() {
                return false;
            }
            if (self.filename.ends_with(".bz2") || self.filename.ends_with(".tbz") || self.filename.ends_with(".tbz2")) && find_on_path("bzip2").is_none() {
                return false;
            }
            if (self.filename.ends_with(".gz") || self.filename.ends_with(".tgz")) && find_on_path("gzip").is_none() {
                return false;
            }
        }
        true
    }
}

#[test]
fn external_tools_list_and_extract_committed_fixtures() {
    let cases = [
        FixtureCase { filename: "basic.zip", tool: ExternalArchiveTool::Unzip },
        FixtureCase { filename: "basic.7z", tool: ExternalArchiveTool::SevenZip },
        FixtureCase { filename: "basic.tar", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.gz", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.bz2", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.xz", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.lzma", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.lz", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.lzo", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.Z", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.lz4", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.zst", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.cpio", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.cab", tool: ExternalArchiveTool::SevenZip },
        // Ubuntu 22.04 ships 7-Zip 21.07, which cannot read the RAR5 stream
        // emitted by the supported RAR creator. The native fixture test still
        // validates this archive through the bundled UnRAR backend.
        FixtureCase { filename: "basic.lha", tool: ExternalArchiveTool::SevenZip },
    ];

    let archives = repo_root().join("fixtures/archives");
    for case in cases {
        let Some(binary) = case.tool.binary() else {
            eprintln!("skipping external fixture {}: required tool is not installed", case.filename);
            continue;
        };
        if !case.is_supported(&binary) {
            eprintln!("skipping external fixture {}: required helper tool for {} is not installed", case.filename, binary.display());
            continue;
        }
        validate_fixture(case, &binary, &archives.join(case.filename));
    }
}

fn validate_fixture(case: FixtureCase, binary: &Path, archive: &Path) {
    assert!(archive.is_file(), "missing committed fixture: {}", archive.display());
    assert!(fs::metadata(archive).unwrap().len() <= 64 * 1024, "external compatibility fixture grew beyond the small-fixture budget: {}", archive.display());

    let list = case.tool.list(binary, archive);
    assert_success(&format!("{} lists {}", binary.display(), case.filename), &list);

    let external = TestDir::new("external-fixture");
    let external_out = external.path("out");
    fs::create_dir_all(&external_out).unwrap();
    let extract = case.tool.extract(binary, archive, &external_out);
    assert_success(&format!("{} extracts {}", binary.display(), case.filename), &extract);
    assert!(external_out.is_dir(), "external extraction did not create {}", external_out.display());

    let external_entries = collect_tree_entries(&external_out);
    assert!(!external_entries.is_empty(), "external extraction of {} produced no entries", case.filename);
    assert_external_listing_contains_all_entries(case.tool, case.filename, &list, &external_out, &external_entries);

    let zm_list = Command::new(zm_path()).arg("list").arg(archive).arg("--json").output().unwrap();
    assert_success(&format!("zm lists {}", case.filename), &zm_list);
    assert_zm_listing_matches_tree(case.tool, case.filename, &zm_list.stdout, &external_out, &external_entries);

    let zm = TestDir::new("external-fixture-zm");
    let zm_out = zm.path("out");
    let zm_extract = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(&zm_out).output().unwrap();
    assert_success(&format!("zm extracts {}", case.filename), &zm_extract);
    assert_trees_match(&format!("external and zm trees for {}", case.filename), &external_out, &zm_out);
}

/// Decodes the `\NNN` octal escapes bsdtar writes for non-ASCII bytes in its
/// listing output.
///
/// This runs before the backslash-to-slash normalization in
/// [`assert_external_listing_contains_all_entries`], which would otherwise
/// destroy the escape markers. Decoding keeps the oracle strict for Unicode
/// names instead of skipping them: GNU tar on Linux prints the bytes
/// literally, so without this the same assertion passes on CI and fails on a
/// macOS developer machine.
fn decode_tar_octal_escapes(raw: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        let is_octal_escape = raw[index] == b'\\' && index + 3 < raw.len() && raw[index + 1..index + 4].iter().all(|byte| (b'0'..=b'7').contains(byte));
        if is_octal_escape {
            let value = raw[index + 1..index + 4].iter().fold(0u16, |accumulator, byte| accumulator * 8 + u16::from(byte - b'0'));
            if let Ok(byte) = u8::try_from(value) {
                decoded.push(byte);
                index += 4;
                continue;
            }
        }
        decoded.push(raw[index]);
        index += 1;
    }
    decoded
}

fn assert_external_listing_contains_all_entries(tool: ExternalArchiveTool, filename: &str, output: &Output, root: &Path, entries: &[PathBuf]) {
    let raw = match tool {
        ExternalArchiveTool::Tar => decode_tar_octal_escapes(&output.stdout),
        _ => output.stdout.clone(),
    };
    let listing = String::from_utf8_lossy(&raw).replace('\\', "/");
    assert!(!listing.trim().is_empty(), "external listing for {filename} was empty");
    for entry in entries {
        // Some 7-Zip codecs (notably CAB and LHA) synthesize parent
        // directories during extraction without emitting directory records.
        if matches!(tool, ExternalArchiveTool::SevenZip) && fs::symlink_metadata(root.join(entry)).is_ok_and(|metadata| metadata.is_dir()) {
            continue;
        }
        let normalized = entry.to_string_lossy().replace('\\', "/");
        // Info-ZIP on macOS emits non-ASCII names in the current locale even
        // when the archive carries the Unicode path extra field. Extraction
        // below still verifies the exact name and bytes; keep the listing
        // assertion strict for every name the oracle can represent as UTF-8.
        if matches!(tool, ExternalArchiveTool::Unzip) && !normalized.is_ascii() {
            continue;
        }
        assert!(listing.contains(&normalized), "external listing for {filename} missed {normalized}\nstdout:\n{listing}");
    }
}

fn assert_zm_listing_matches_tree(tool: ExternalArchiveTool, filename: &str, stdout: &[u8], root: &Path, external_entries: &[PathBuf]) {
    let listing: Value = serde_json::from_slice(stdout)
        .unwrap_or_else(|error| panic!("invalid JSON listing for {filename}: {error}\nstdout:\n{}", String::from_utf8_lossy(stdout)));
    let actual = listing["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("JSON listing for {filename} has no entries array: {listing}"))
        .iter()
        .filter(|entry| !(matches!(tool, ExternalArchiveTool::SevenZip) && entry["kind"] == "directory"))
        .filter_map(|entry| entry["name"].as_str())
        .filter(|name| !is_apple_double(Path::new(name)))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let expected = external_entries
        .iter()
        .filter(|entry| !(matches!(tool, ExternalArchiveTool::SevenZip) && fs::symlink_metadata(root.join(entry)).is_ok_and(|metadata| metadata.is_dir())))
        .map(|entry| entry.to_string_lossy().replace('\\', "/"))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "zm JSON listing differs from external extraction for {filename}");
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}
