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

impl ExternalArchiveTool {
    fn binary(self) -> Option<PathBuf> {
        match self {
            Self::SevenZip => find_on_path("7zz").or_else(|| find_on_path("7z")),
            Self::Unzip => find_on_path("unzip"),
            Self::Tar => find_on_path("bsdtar").or_else(|| find_on_path("tar")),
        }
    }

    fn list(self, binary: &Path, archive: &Path) -> Output {
        match self {
            Self::SevenZip => Command::new(binary).args(["l", "-ba"]).arg(archive).output().unwrap(),
            Self::Unzip => Command::new(binary).args(["-Z1"]).arg(archive).output().unwrap(),
            Self::Tar => Command::new(binary).arg("-tf").arg(archive).output().unwrap(),
        }
    }

    fn extract(self, binary: &Path, archive: &Path, destination: &Path) -> Output {
        match self {
            Self::SevenZip => Command::new(binary).arg("x").arg("-y").arg(format!("-o{}", destination.display())).arg(archive).output().unwrap(),
            Self::Unzip => Command::new(binary).args(["-q", "-o"]).arg(archive).arg("-d").arg(destination).output().unwrap(),
            Self::Tar => Command::new(binary).arg("-xf").arg(archive).arg("-C").arg(destination).output().unwrap(),
        }
    }
}

struct FixtureCase {
    filename: &'static str,
    tool: ExternalArchiveTool,
}

#[test]
fn external_tools_list_and_extract_committed_fixtures() {
    let cases = [
        FixtureCase { filename: "basic.zip", tool: ExternalArchiveTool::Unzip },
        FixtureCase { filename: "basic.7z", tool: ExternalArchiveTool::SevenZip },
        FixtureCase { filename: "basic.tar", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.gz", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.xz", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.zst", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.cpio", tool: ExternalArchiveTool::Tar },
    ];

    let archives = repo_root().join("fixtures/archives");
    for case in cases {
        let Some(binary) = case.tool.binary() else {
            eprintln!("skipping external fixture {}: required tool is not installed", case.filename);
            continue;
        };
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
    assert_external_listing_contains_all_entries(case.filename, &list, &external_entries);

    let zm_list = Command::new(zm_path()).arg("list").arg(archive).arg("--json").output().unwrap();
    assert_success(&format!("zm lists {}", case.filename), &zm_list);
    assert_zm_listing_matches_tree(case.filename, &zm_list.stdout, &external_entries);

    let zm = TestDir::new("external-fixture-zm");
    let zm_out = zm.path("out");
    let zm_extract = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(&zm_out).output().unwrap();
    assert_success(&format!("zm extracts {}", case.filename), &zm_extract);
    assert_trees_match(&format!("external and zm trees for {}", case.filename), &external_out, &zm_out);
}

fn assert_external_listing_contains_all_entries(filename: &str, output: &Output, entries: &[PathBuf]) {
    let listing = String::from_utf8_lossy(&output.stdout).replace('\\', "/");
    for entry in entries {
        let normalized = entry.to_string_lossy().replace('\\', "/");
        assert!(listing.contains(&normalized), "external listing for {filename} missed {normalized}\nstdout:\n{listing}");
    }
}

fn assert_zm_listing_matches_tree(filename: &str, stdout: &[u8], external_entries: &[PathBuf]) {
    let listing: Value = serde_json::from_slice(stdout)
        .unwrap_or_else(|error| panic!("invalid JSON listing for {filename}: {error}\nstdout:\n{}", String::from_utf8_lossy(stdout)));
    let actual = listing["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("JSON listing for {filename} has no entries array: {listing}"))
        .iter()
        .filter_map(|entry| entry["name"].as_str())
        .filter(|name| !is_apple_double(Path::new(name)))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let expected = external_entries.iter().map(|entry| entry.to_string_lossy().replace('\\', "/")).collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "zm JSON listing differs from external extraction for {filename}");
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}
