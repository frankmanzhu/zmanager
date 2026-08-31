//! Integration suite for the forensic, virtualisation, and logical container
//! formats: VHDX, QCOW2, EWF, AD1, DAR, AFF4, and `RawDisk`.
//!
//! Every fixture lives in `fixtures/archives` (minted by
//! `scripts/generate-forensic-fixtures.sh`), so the suite needs no external
//! checkout and no external tooling. The disk-image fixtures all wrap the same
//! sector image, so [`CANONICAL_PAYLOAD`] is the expected tree for all of them:
//! a format whose container decode drifts fails as a payload mismatch rather
//! than as a format-specific assertion.

mod common;

use common::TestDir;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use zmanager_core::archive_browser::BrowserEntryKind;
use zmanager_core::archive_format::{ArchiveFormatKind, detect_archive_format};
use zmanager_core::backend_test_support::virtual_disk_backend::{
    copy_logical_container_by_path_occurrence, extract_ad1_with_overwrite_resolver, extract_aff4_with_overwrite_resolver, extract_dar_with_overwrite_resolver,
    extract_ewf_with_overwrite_resolver, extract_logical_container, extract_qcow2_with_overwrite_resolver, extract_raw_disk_with_overwrite_resolver,
    extract_vhdx_with_overwrite_resolver, list_ad1, list_aff4, list_dar, list_ewf, list_qcow2, list_raw_disk, list_vhdx, test_logical_container,
    test_virtual_disk,
};
use zmanager_core::engine::{ArchiveSource, ExtractOptions, FormatId, OpenOptions, TestOptions, create_default_engine};
use zmanager_core::safety::{ExtractionPolicy, OverwriteConflict, OverwriteDecision, OverwriteResolver};

/// The file tree every disk-image fixture decodes to, as `path -> contents`.
const CANONICAL_PAYLOAD: &[(&str, &[u8])] = &[
    ("payload/README.txt", b"ZManager fixture payload\n"),
    ("payload/nested/file.txt", b"nested fixture file\n"),
    ("payload/dir with spaces/file with spaces.txt", b"spaces in path\n"),
    ("payload/unicode/\u{3053}\u{3093}\u{306b}\u{3061}\u{306f}.txt", b"unicode path fixture\n"),
];

struct AlwaysReplace;

impl OverwriteResolver for AlwaysReplace {
    fn decide(&mut self, _conflict: &OverwriteConflict) -> OverwriteDecision {
        OverwriteDecision::Replace
    }
}

fn fixture(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name);
    assert!(path.is_file(), "missing fixture: {}", path.display());
    path
}

/// Every regular file under `root`, keyed by its path relative to `root`.
fn tree_of(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display())) {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let key = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                walk(&entry.path(), &key, out);
            } else if file_type.is_file() {
                out.insert(key, std::fs::read(entry.path()).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    if root.is_dir() {
        walk(root, "", &mut out);
    }
    out
}

/// Every directory (including empty ones) below `root`, relative to `root`.
/// `tree_of` above only collects regular files, so a backend that silently
/// drops an empty directory during extraction passes `tree_of` unnoticed;
/// this is the check that catches it.
fn dirs_of(root: &Path) -> BTreeSet<String> {
    fn walk(dir: &Path, prefix: &str, out: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display())) {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let key = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
            if entry.file_type().unwrap().is_dir() {
                out.insert(key.clone());
                walk(&entry.path(), &key, out);
            }
        }
    }
    let mut out = BTreeSet::new();
    if root.is_dir() {
        walk(root, "", &mut out);
    }
    out
}

/// Asserts every file under `destination` really lives inside it once symlinks
/// and `..` are resolved. A sanitized name may still *contain* `..` as literal
/// characters (`../escape.txt` becomes `.._escape.txt`), which is safe; what
/// must never happen is a write that resolves outside the root.
fn assert_nothing_escaped(destination: &Path, label: &str) {
    if !destination.exists() {
        return;
    }
    let root = destination.canonicalize().unwrap_or_else(|e| panic!("{label}: canonicalize destination: {e}"));
    for relative in tree_of(destination).keys() {
        let resolved = destination.join(relative).canonicalize().unwrap_or_else(|e| panic!("{label}: canonicalize {relative}: {e}"));
        assert!(resolved.starts_with(&root), "{label}: {relative} resolved to {} outside {}", resolved.display(), root.display());
    }
}

fn expected_payload() -> BTreeMap<String, Vec<u8>> {
    CANONICAL_PAYLOAD.iter().map(|(path, contents)| ((*path).to_owned(), (*contents).to_vec())).collect()
}

/// Drives one disk-image format through the whole engine surface -- detect,
/// open, list, test, extract, copy -- and holds it to the canonical payload.
fn assert_disk_image_lifecycle(fixture_name: &str, expected_kind: ArchiveFormatKind, expected_format: FormatId) {
    let path = fixture(fixture_name);
    assert_eq!(detect_archive_format(&path), expected_kind, "{fixture_name}");

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&path), OpenOptions::default()).unwrap_or_else(|e| panic!("open {fixture_name}: {e}"));
    assert_eq!(handle.detected().format, expected_format, "{fixture_name}");

    let listing = handle.list().unwrap_or_else(|e| panic!("list {fixture_name}: {e}"));
    for (expected_path, expected_bytes) in CANONICAL_PAYLOAD {
        let entry = listing
            .entries
            .iter()
            .find(|entry| entry.path == *expected_path)
            .unwrap_or_else(|| panic!("{fixture_name}: {expected_path} missing from {:?}", listing.entries.iter().map(|e| &e.path).collect::<Vec<_>>()));
        assert_eq!(entry.kind, BrowserEntryKind::File, "{fixture_name}: {expected_path}");
        assert_eq!(entry.size, Some(expected_bytes.len() as u64), "{fixture_name}: {expected_path}");
    }

    let report = handle.test(&TestOptions::default()).unwrap_or_else(|e| panic!("test {fixture_name}: {e}"));
    assert!(report.tested_entries > 0, "{fixture_name} tested no entries");
    assert!(report.tested_bytes > 0, "{fixture_name} tested no bytes");

    let temp = TestDir::new(&format!("forensic-{expected_format}"));
    let out = temp.path("out");
    let mut options = ExtractOptions { destination: out.clone(), ..Default::default() };
    let extract_report = handle.extract(&mut options).unwrap_or_else(|e| panic!("extract {fixture_name}: {e}"));
    assert_eq!(usize::try_from(extract_report.written_entries).unwrap(), CANONICAL_PAYLOAD.len(), "{fixture_name}");
    assert_eq!(tree_of(&out), expected_payload(), "{fixture_name} extracted a different tree");
    // `tree_of` only sees files: the empty directory is checked separately so
    // a backend that silently drops it does not pass unnoticed.
    assert!(dirs_of(&out).contains("payload/nested/empty-dir"), "{fixture_name} dropped the empty directory");

    // copy_entry must agree byte-for-byte with what extraction wrote.
    for (expected_path, expected_bytes) in CANONICAL_PAYLOAD {
        let entry = listing.entries.iter().find(|entry| entry.path == *expected_path).unwrap();
        let mut copied = Vec::new();
        let copy_report = handle.copy_entry(entry.id, &mut copied).unwrap_or_else(|e| panic!("copy {fixture_name} {expected_path}: {e}"));
        assert_eq!(copied, *expected_bytes, "{fixture_name}: {expected_path}");
        assert_eq!(copy_report.written_bytes, expected_bytes.len() as u64, "{fixture_name}: {expected_path}");
    }

    // Extract one: selecting a single file must write only that file, not
    // the whole tree -- distinct from `copy_entry` above, which reads bytes
    // without ever writing a destination directory.
    let one_temp = TestDir::new(&format!("forensic-{expected_format}-one"));
    let out_one = one_temp.path("out");
    let one_policy = ExtractionPolicy { include_patterns: vec!["payload/README.txt".to_owned()], ..ExtractionPolicy::default() };
    let mut one_options = ExtractOptions { destination: out_one.clone(), policy: one_policy, ..Default::default() };
    handle.extract(&mut one_options).unwrap_or_else(|e| panic!("single-file extract {fixture_name}: {e}"));
    assert_eq!(std::fs::read(out_one.join("payload/README.txt")).unwrap(), b"ZManager fixture payload\n", "{fixture_name}");
    assert!(!out_one.join("payload/nested").exists(), "{fixture_name} single-file selection pulled entries outside it");

    // Selecting a subfolder must pull every entry beneath it and nothing
    // outside it -- the "extract subfolder" leg of the validation matrix,
    // which plain full/single-entry extraction above does not cover.
    let sub_temp = TestDir::new(&format!("forensic-{expected_format}-subfolder"));
    let sub_out = sub_temp.path("out");
    let sub_policy = ExtractionPolicy { include_patterns: vec!["payload/nested".to_owned()], ..ExtractionPolicy::default() };
    let mut sub_options = ExtractOptions { destination: sub_out.clone(), policy: sub_policy, ..Default::default() };
    handle.extract(&mut sub_options).unwrap_or_else(|e| panic!("subfolder extract {fixture_name}: {e}"));
    assert_eq!(std::fs::read(sub_out.join("payload/nested/file.txt")).unwrap(), b"nested fixture file\n", "{fixture_name}");
    assert!(dirs_of(&sub_out).contains("payload/nested/empty-dir"), "{fixture_name} subfolder extraction dropped the empty directory");
    assert!(!sub_out.join("payload/README.txt").exists(), "{fixture_name} subfolder extraction pulled entries outside the subfolder");
}

#[test]
fn engine_vhdx_lifecycle_matches_the_canonical_payload() {
    assert_disk_image_lifecycle("basic.vhdx", ArchiveFormatKind::Vhdx, FormatId::VHDX);
}

#[test]
fn engine_qcow2_lifecycle_matches_the_canonical_payload() {
    assert_disk_image_lifecycle("basic.qcow2", ArchiveFormatKind::Qcow2, FormatId::QCOW2);
    // The legacy `.qcow` extension resolves to the same backend.
    assert_disk_image_lifecycle("basic.qcow", ArchiveFormatKind::Qcow2, FormatId::QCOW2);
}

#[test]
fn engine_ewf_lifecycle_matches_the_canonical_payload() {
    // EWF v1 (EnCase 5/6) and v2 (EnCase 7 `Ex01`) are different on-disk
    // layouts behind one `FormatId`, so both segment-file versions are driven.
    assert_disk_image_lifecycle("basic.e01", ArchiveFormatKind::Ewf, FormatId::EWF);
    assert_disk_image_lifecycle("basic.ex01", ArchiveFormatKind::Ewf, FormatId::EWF);
}

#[test]
fn engine_raw_disk_lifecycle_matches_the_canonical_payload_for_every_extension() {
    // `.raw`, `.dd`, `.dsk` and `.img` are the same bytes under four names:
    // the point is that each advertised extension routes to a working backend.
    for name in ["basic.raw", "basic.dd", "basic.dsk", "basic.img"] {
        assert_disk_image_lifecycle(name, ArchiveFormatKind::RawDisk, FormatId::RAW_DISK);
    }
}

#[test]
fn engine_physical_aff4_lifecycle_matches_the_canonical_payload() {
    // A physical AFF4 (`aff4:ImageStream`) resolves through the sector-stream
    // decoder, a different leg from the logical container below.
    assert_disk_image_lifecycle("basic.aff4", ArchiveFormatKind::Aff4, FormatId::AFF4);
}

#[test]
fn engine_ad1_lifecycle_lists_tests_extracts_and_copies() {
    let path = fixture("basic.ad1");
    assert_eq!(detect_archive_format(&path), ArchiveFormatKind::Ad1);

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&path), OpenOptions::default()).expect("open ad1");
    assert_eq!(handle.detected().format, FormatId::AD1);

    let listing = handle.list().expect("list ad1");
    for (expected_path, expected_bytes) in CANONICAL_PAYLOAD {
        let entry = listing
            .entries
            .iter()
            .find(|entry| entry.path == *expected_path)
            .unwrap_or_else(|| panic!("{expected_path} missing: {:?}", listing.entries.iter().map(|e| &e.path).collect::<Vec<_>>()));
        assert_eq!(entry.size, Some(expected_bytes.len() as u64), "{expected_path}");
    }
    // AD1 has no symlink concept (see `ad1-core`'s `vfs.rs` doc comment), so
    // the empty directory is the one structural, non-file element it carries;
    // assert it is actually surfaced in the listing, not just tolerated.
    let empty_dir = listing.entries.iter().find(|entry| entry.path == "payload/nested/empty-dir").expect("payload/nested/empty-dir missing from AD1 listing");
    assert_eq!(empty_dir.kind, BrowserEntryKind::Directory);

    let report = handle.test(&TestOptions::default()).expect("test ad1");
    assert!(report.tested_entries > 0);

    let temp = TestDir::new("forensic-ad1");
    let out = temp.path("out");
    let mut options = ExtractOptions { destination: out.clone(), ..Default::default() };
    handle.extract(&mut options).expect("extract ad1");
    assert_eq!(tree_of(&out), expected_payload());
    assert!(dirs_of(&out).contains("payload/nested/empty-dir"), "AD1 extraction dropped the empty directory");

    for (expected_path, expected_bytes) in CANONICAL_PAYLOAD {
        let entry = listing.entries.iter().find(|entry| entry.path == *expected_path).unwrap();
        let mut copied = Vec::new();
        handle.copy_entry(entry.id, &mut copied).expect("copy ad1 entry");
        assert_eq!(copied, *expected_bytes, "{expected_path}");
    }

    // Extract one: selecting a single file must write only that file.
    let out_one = temp.path("out-one");
    let one_policy = ExtractionPolicy { include_patterns: vec!["payload/README.txt".to_owned()], ..ExtractionPolicy::default() };
    let mut one_options = ExtractOptions { destination: out_one.clone(), policy: one_policy, ..Default::default() };
    handle.extract(&mut one_options).expect("single-file extract ad1");
    assert_eq!(std::fs::read(out_one.join("payload/README.txt")).unwrap(), b"ZManager fixture payload\n");
    assert!(!out_one.join("payload/nested").exists());

    // Extract subfolder: selecting `payload/nested` must pull the file and
    // the empty directory beneath it, and nothing outside it.
    let sub_out = temp.path("out-subdir");
    let sub_policy = ExtractionPolicy { include_patterns: vec!["payload/nested".to_owned()], ..ExtractionPolicy::default() };
    let mut sub_options = ExtractOptions { destination: sub_out.clone(), policy: sub_policy, ..Default::default() };
    handle.extract(&mut sub_options).expect("subfolder extract ad1");
    assert_eq!(std::fs::read(sub_out.join("payload/nested/file.txt")).unwrap(), b"nested fixture file\n");
    assert!(dirs_of(&sub_out).contains("payload/nested/empty-dir"));
    assert!(!sub_out.join("payload/README.txt").exists());

    // Direct backend entry points, not just the engine adapter.
    assert!(!list_ad1(&path).expect("list_ad1").is_empty());
    let direct = temp.path("direct");
    let mut resolver = AlwaysReplace;
    extract_ad1_with_overwrite_resolver(&path, &direct, ExtractionPolicy::default(), &mut resolver).expect("extract_ad1 direct");
    assert_eq!(tree_of(&direct), expected_payload());
}

#[test]
fn engine_dar_lifecycle_lists_tests_extracts_and_copies() {
    let path = fixture("basic.dar");
    assert_eq!(detect_archive_format(&path), ArchiveFormatKind::Dar);

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&path), OpenOptions::default()).expect("open dar");
    assert_eq!(handle.detected().format, FormatId::DAR);

    let listing = handle.list().expect("list dar");
    let hello = listing.entries.iter().find(|entry| entry.path.ends_with("hello.txt")).expect("hello.txt in dar");

    let report = handle.test(&TestOptions::default()).expect("test dar");
    assert!(report.tested_entries > 0);

    let temp = TestDir::new("forensic-dar");
    let out = temp.path("out");
    let mut options = ExtractOptions { destination: out.clone(), ..Default::default() };
    handle.extract(&mut options).expect("extract dar");
    let extracted = tree_of(&out);
    assert_eq!(extracted.get("hello.txt").map(Vec::as_slice), Some(&b"hello from dar\n"[..]));
    assert_eq!(extracted.get("sub/deep.txt").map(Vec::as_slice), Some(&b"deep\n"[..]));

    let mut copied = Vec::new();
    let copy_report = handle.copy_entry(hello.id, &mut copied).expect("copy dar entry");
    assert_eq!(copied, b"hello from dar\n");
    assert_eq!(copy_report.written_bytes, copied.len() as u64);

    // Extract one: selecting a single file must write only that file.
    let out_one = temp.path("out-one");
    let one_policy = ExtractionPolicy { include_patterns: vec!["hello.txt".to_owned()], ..ExtractionPolicy::default() };
    let mut one_options = ExtractOptions { destination: out_one.clone(), policy: one_policy, ..Default::default() };
    handle.extract(&mut one_options).expect("single-file extract dar");
    assert_eq!(std::fs::read(out_one.join("hello.txt")).unwrap(), b"hello from dar\n");
    assert!(!out_one.join("sub").exists(), "single-file selection pulled the sub/ subtree too");

    // Extract subfolder: selecting `sub` must pull deep.txt and nothing else.
    let out_sub = temp.path("out-sub");
    let sub_policy = ExtractionPolicy { include_patterns: vec!["sub".to_owned()], ..ExtractionPolicy::default() };
    let mut sub_options = ExtractOptions { destination: out_sub.clone(), policy: sub_policy, ..Default::default() };
    handle.extract(&mut sub_options).expect("subfolder extract dar");
    assert_eq!(std::fs::read(out_sub.join("sub/deep.txt")).unwrap(), b"deep\n");
    assert!(!out_sub.join("hello.txt").exists());

    assert!(!list_dar(&path).expect("list_dar").is_empty());
    let direct = temp.path("direct");
    let mut resolver = AlwaysReplace;
    extract_dar_with_overwrite_resolver(&path, &direct, ExtractionPolicy::default(), &mut resolver).expect("extract_dar direct");
    assert_eq!(tree_of(&direct), extracted);
}

#[test]
fn engine_logical_aff4_lifecycle_lists_tests_extracts_and_copies() {
    let path = fixture("basic-logical.aff4");
    assert_eq!(detect_archive_format(&path), ArchiveFormatKind::Aff4);

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&path), OpenOptions::default()).expect("open logical aff4");
    assert_eq!(handle.detected().format, FormatId::AFF4);

    // AFF4-L (`aff4:FileImage`) carries the whole canonical payload tree, not
    // just README.txt: multi-file, nested, spaces-in-name, and Unicode all
    // exercise the same flat-file-list-to-tree derivation `open_aff4_logical`
    // does (it has no directory nodes -- see its doc comment -- so unlike
    // AD1/the disk images, there is no empty directory to assert here: AFF4-L
    // has nothing to carry it in).
    let listing = handle.list().expect("list logical aff4");
    for (expected_path, expected_bytes) in CANONICAL_PAYLOAD {
        let entry = listing
            .entries
            .iter()
            .find(|entry| entry.path == *expected_path)
            .unwrap_or_else(|| panic!("{expected_path} missing: {:?}", listing.entries.iter().map(|e| &e.path).collect::<Vec<_>>()));
        assert_eq!(entry.size, Some(expected_bytes.len() as u64), "{expected_path}");
    }
    let readme = listing.entries.iter().find(|entry| entry.path == "payload/README.txt").unwrap();

    let report = handle.test(&TestOptions::default()).expect("test logical aff4");
    assert!(report.tested_entries > 0);

    let temp = TestDir::new("forensic-aff4-logical");
    let out = temp.path("out");
    let mut options = ExtractOptions { destination: out.clone(), ..Default::default() };
    handle.extract(&mut options).expect("extract logical aff4");
    assert_eq!(tree_of(&out), expected_payload(), "logical aff4 extracted a different tree");

    for (expected_path, expected_bytes) in CANONICAL_PAYLOAD {
        let entry = listing.entries.iter().find(|entry| entry.path == *expected_path).unwrap();
        let mut copied = Vec::new();
        handle.copy_entry(entry.id, &mut copied).unwrap_or_else(|e| panic!("copy logical aff4 {expected_path}: {e}"));
        assert_eq!(copied, *expected_bytes, "{expected_path}");
    }
    // The original single-file assertion, kept as a direct sanity check on
    // the specific entry every earlier version of this test exercised.
    let mut copied = Vec::new();
    handle.copy_entry(readme.id, &mut copied).expect("copy logical aff4 entry");
    assert_eq!(copied, b"ZManager fixture payload\n");

    // Extract one: selecting a single file must write only that file.
    let out_one = temp.path("out-one");
    let one_policy = ExtractionPolicy { include_patterns: vec!["payload/README.txt".to_owned()], ..ExtractionPolicy::default() };
    let mut one_options = ExtractOptions { destination: out_one.clone(), policy: one_policy, ..Default::default() };
    handle.extract(&mut one_options).expect("single-file extract logical aff4");
    assert_eq!(std::fs::read(out_one.join("payload/README.txt")).unwrap(), b"ZManager fixture payload\n");
    assert!(!out_one.join("payload/nested").exists());

    // Extract subfolder: selecting `payload/nested` must pull only the file
    // beneath it (AFF4-L's flat file list has no empty-dir to assert here).
    let sub_out = temp.path("out-subdir");
    let sub_policy = ExtractionPolicy { include_patterns: vec!["payload/nested".to_owned()], ..ExtractionPolicy::default() };
    let mut sub_options = ExtractOptions { destination: sub_out.clone(), policy: sub_policy, ..Default::default() };
    handle.extract(&mut sub_options).expect("subfolder extract logical aff4");
    assert_eq!(std::fs::read(sub_out.join("payload/nested/file.txt")).unwrap(), b"nested fixture file\n");
    assert!(!sub_out.join("payload/README.txt").exists());

    assert!(!list_aff4(&path).expect("list_aff4").is_empty());
    let direct = temp.path("direct");
    let mut resolver = AlwaysReplace;
    extract_aff4_with_overwrite_resolver(&path, &direct, ExtractionPolicy::default(), &mut resolver).expect("extract_aff4 direct");
    assert_eq!(tree_of(&direct), tree_of(&out));
}

#[test]
fn direct_disk_backend_entry_points_agree_with_the_engine() {
    // The `list_*` / `extract_*_with_overwrite_resolver` pairs are the public
    // API the FFI and desktop callers use, so they are exercised on their own
    // rather than only through the engine adapter above.
    let temp = TestDir::new("forensic-direct");

    // The listing and extraction entry points are generic over `AsRef<Path>`,
    // so they cannot share one function-pointer type; drive each pair directly.
    macro_rules! assert_direct_pair {
        ($name:literal, $list:path, $extract:path) => {{
            let path = fixture($name);
            assert!(!$list(&path).unwrap_or_else(|e| panic!("list {}: {e}", $name)).is_empty(), $name);
            let out = temp.path(concat!("out-", $name));
            let mut resolver = AlwaysReplace;
            let report = $extract(&path, &out, ExtractionPolicy::default(), &mut resolver).unwrap_or_else(|e| panic!("extract {}: {e}", $name));
            assert_eq!(usize::try_from(report.written_entries).unwrap(), CANONICAL_PAYLOAD.len(), $name);
            assert_eq!(tree_of(&out), expected_payload(), $name);
        }};
    }

    assert_direct_pair!("basic.vhdx", list_vhdx, extract_vhdx_with_overwrite_resolver);
    assert_direct_pair!("basic.qcow2", list_qcow2, extract_qcow2_with_overwrite_resolver);
    assert_direct_pair!("basic.e01", list_ewf, extract_ewf_with_overwrite_resolver);
    assert_direct_pair!("basic.raw", list_raw_disk, extract_raw_disk_with_overwrite_resolver);
}

#[test]
fn test_and_extract_routes_reject_the_wrong_container_class() {
    // A logical container is not a disk image: routing one through the disk
    // entry points must fail loudly rather than silently mounting it, and the
    // reverse direction must keep working (a disk image is a valid input to the
    // permissive logical route).
    let logical = fixture("basic.ad1");
    let error = test_virtual_disk(&logical, &TestOptions::default()).expect_err("AD1 must not pass as a disk image");
    assert!(format!("{error}").contains("not a disk image"), "unexpected error: {error}");

    let disk = fixture("basic.raw");
    test_logical_container(&disk, &TestOptions::default()).expect("the logical route accepts a disk image");
}

#[test]
fn plain_archives_are_rejected_by_both_container_routes() {
    // `basic.zip` resolves to the engine's loose-archive fallback. Neither the
    // disk nor the logical route owns that, so both must decline instead of
    // listing the archive's members as if it were a container.
    let temp = TestDir::new("forensic-plain-archive");
    let zip = std::fs::read(fixture("basic.zip")).unwrap();
    for name in ["masquerade.aff4", "masquerade.ad1", "masquerade.raw", "masquerade.vhdx"] {
        temp.write_file(name, &zip);
        let path = temp.path(name);
        let error = list_aff4(&path).expect_err(&format!("{name} must not list as a logical container"));
        assert!(format!("{error}").contains("not a disk image"), "{name}: {error}");
        let error = list_raw_disk(&path).expect_err(&format!("{name} must not list as a disk image"));
        assert!(format!("{error}").contains("not a disk image"), "{name}: {error}");
    }
}

#[test]
fn logical_container_copy_selects_the_requested_path_occurrence() {
    // `copy_*_by_path_occurrence` is the selector the engine uses for retained
    // entries. Occurrence 0 must resolve, and an out-of-range occurrence must
    // report "not present" rather than silently returning a neighbouring entry.
    let path = fixture("basic.ad1");
    let mut copied = Vec::new();
    let written = copy_logical_container_by_path_occurrence(&path, "payload/README.txt", 0, &mut copied).expect("occurrence 0");
    assert_eq!(copied, b"ZManager fixture payload\n");
    assert_eq!(written, copied.len() as u64);

    let mut ignored = Vec::new();
    let error = copy_logical_container_by_path_occurrence(&path, "payload/README.txt", 1, &mut ignored).expect_err("occurrence 1 does not exist");
    assert!(format!("{error}").contains("not present"), "unexpected error: {error}");
    assert!(ignored.is_empty());

    let mut ignored = Vec::new();
    let error = copy_logical_container_by_path_occurrence(&path, "payload/nope.txt", 0, &mut ignored).expect_err("unknown path");
    assert!(format!("{error}").contains("not present"), "unexpected error: {error}");
}

#[test]
fn logical_container_extraction_cannot_escape_the_destination() {
    // AD1, DAR and AFF4 are the first containers routed through this backend
    // whose member paths are attacker-controlled strings rather than names read
    // out of a mounted filesystem, so traversal containment is asserted here
    // directly. Whatever the container layer normalises away, nothing may be
    // written outside the destination root.
    let temp = TestDir::new("forensic-traversal");
    let guard = temp.path("guard");
    std::fs::create_dir_all(&guard).unwrap();

    let hostile_names = ["../escape.txt", "../../escape.txt", "a/../../escape.txt", "/abs/escape.txt", "..\\escape.txt"];
    for (index, name) in hostile_names.iter().enumerate() {
        let bytes = aff4::testutil::test_aff4_logical(name, b"pwned\n", "00000000000000000000000000000000");
        let container = format!("hostile-{index}.aff4");
        temp.write_file(&container, &bytes);
        let destination = guard.join(format!("out-{index}"));

        // Either verdict is acceptable -- a hard error, or a report that wrote
        // only paths under the destination. What is not acceptable is a write
        // that lands outside it.
        let _ = extract_logical_container(temp.path(&container), &destination, ExtractionPolicy::default());

        assert!(!guard.join("escape.txt").exists(), "{name}: escaped one level");
        assert!(!temp.path("escape.txt").exists(), "{name}: escaped two levels");
        assert!(!Path::new("/abs/escape.txt").exists(), "{name}: escaped to an absolute path");
        assert_nothing_escaped(&destination, name);
    }
}

#[test]
fn hostile_ad1_member_names_cannot_escape_the_destination() {
    // The AD1 reader is a separate implementation from the AFF4 one above and
    // mounts its own VFS, so it gets its own containment check.
    let built = ad1::testfix::build(ad1::testfix::Node::Dir(
        "root",
        vec![
            ad1::testfix::Node::File("../escape.txt", b"pwned\n".to_vec()),
            ad1::testfix::Node::Dir("..", vec![ad1::testfix::Node::File("escape.txt", b"pwned\n".to_vec())]),
            ad1::testfix::Node::File("safe.txt", b"safe\n".to_vec()),
        ],
    ));
    let temp = TestDir::new("forensic-ad1-traversal");
    let guard = temp.path("guard");
    std::fs::create_dir_all(&guard).unwrap();
    temp.write_file("hostile.ad1", &built.bytes);

    let destination = guard.join("out");
    let _ = extract_logical_container(temp.path("hostile.ad1"), &destination, ExtractionPolicy::default());

    assert!(!guard.join("escape.txt").exists(), "AD1 traversal escaped one level");
    assert!(!temp.path("escape.txt").exists(), "AD1 traversal escaped two levels");
    assert_nothing_escaped(&destination, "hostile ad1");

    // The hostile names are neutralised, not silently dropped along with the
    // rest of the container: the benign sibling still extracts.
    let extracted = tree_of(&destination);
    assert_eq!(extracted.get("root/safe.txt").map(Vec::as_slice), Some(&b"safe\n"[..]), "extracted: {:?}", extracted.keys().collect::<Vec<_>>());
}

#[test]
fn truncated_forensic_containers_fail_closed() {
    // A header-only prefix of each format must be rejected, never listed as an
    // empty-but-valid container.
    let temp = TestDir::new("forensic-truncated");
    for name in ["basic.vhdx", "basic.qcow2", "basic.e01", "basic.ex01", "basic.ad1", "basic.dar", "basic.aff4", "basic.raw"] {
        let bytes = std::fs::read(fixture(name)).unwrap();
        let truncated = &bytes[..bytes.len().min(64)];
        temp.write_file(name, truncated);
        let path = temp.path(name);
        assert!(list_raw_disk(&path).is_err() && list_aff4(&path).is_err(), "{name}: a 64-byte prefix must not list");
        assert!(test_logical_container(&path, &TestOptions::default()).is_err(), "{name}: a 64-byte prefix must not verify");
    }
}
