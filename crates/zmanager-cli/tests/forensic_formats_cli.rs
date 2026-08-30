//! CLI coverage for the forensic / virtual-disk formats.
//!
//! `fixture_cli.rs` already sweeps list/test/extract over every manifest row,
//! so this file covers what that sweep cannot: the format label each fixture
//! reports in `--json`, single-entry `--to-stdout` selection, and the failure
//! wording for inputs the backends must refuse.
//!
//! All fixtures come from `fixtures/archives`, minted by
//! `scripts/generate-forensic-fixtures.sh`; no external checkout is required.

mod common;

use common::*;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// `(fixture, format slug reported in --json)` for every advertised extension
/// of the seven forensic formats.
const FORENSIC_FIXTURES: &[(&str, &str)] = &[
    ("basic.raw", "raw-disk"),
    ("basic.dd", "raw-disk"),
    ("basic.dsk", "raw-disk"),
    ("basic.img", "raw-disk"),
    ("basic.vhdx", "vhdx"),
    ("basic.qcow2", "qcow2"),
    ("basic.qcow", "qcow2"),
    ("basic.e01", "ewf"),
    ("basic.ex01", "ewf"),
    ("basic.aff4", "aff4"),
    ("basic-logical.aff4", "aff4"),
    ("basic.ad1", "ad1"),
    ("basic.dar", "dar"),
];

/// The disk-image fixtures all wrap the same sector image.
const DISK_IMAGE_FIXTURES: &[&str] =
    &["basic.raw", "basic.dd", "basic.dsk", "basic.img", "basic.vhdx", "basic.qcow2", "basic.qcow", "basic.e01", "basic.ex01", "basic.aff4"];

const README_PATH: &str = "payload/README.txt";
const README_BYTES: &[u8] = b"ZManager fixture payload\n";

fn fixture(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name);
    assert!(path.is_file(), "missing fixture: {}", path.display());
    path
}

#[test]
fn zm_reports_the_right_format_for_every_forensic_fixture() {
    let temp = TestDir::new("forensic_cli_format");
    for (name, expected_format) in FORENSIC_FIXTURES {
        let out = temp.path(format!("out-{name}"));
        let output = Command::new(zm_path()).arg("extract").arg(fixture(name)).arg("-C").arg(&out).arg("--json").output().unwrap();
        assert_success(&format!("zm extract --json {name}"), &output);
        let json = String::from_utf8_lossy(&output.stdout);
        assert!(json.contains("\"operation\":\"extract\""), "{name}: {json}");
        assert!(json.contains(&format!("\"format\":\"{expected_format}\"")), "{name} should report format {expected_format}, got: {json}");
    }
}

#[test]
fn zm_lists_the_canonical_payload_from_every_disk_image_fixture() {
    for name in DISK_IMAGE_FIXTURES {
        let output = Command::new(zm_path()).arg("list").arg(fixture(name)).output().unwrap();
        assert_success(&format!("zm list {name}"), &output);
        let listing = String::from_utf8_lossy(&output.stdout);
        for expected in [README_PATH, "payload/nested/file.txt", "payload/dir with spaces/file with spaces.txt"] {
            assert!(listing.contains(expected), "{name} listing is missing {expected}:\n{listing}");
        }
    }
}

#[test]
fn zm_extract_to_stdout_selects_one_entry_from_every_disk_image_fixture() {
    for name in DISK_IMAGE_FIXTURES {
        let output = Command::new(zm_path()).arg("extract").arg(fixture(name)).arg("--to-stdout").arg("--include").arg(README_PATH).output().unwrap();
        assert_success(&format!("zm extract --to-stdout {name}"), &output);
        assert_eq!(output.stdout, README_BYTES, "{name} streamed the wrong bytes");
    }
}

#[test]
fn zm_extract_to_stdout_selects_one_entry_from_the_logical_containers() {
    for (name, entry, expected) in
        [("basic.ad1", README_PATH, README_BYTES), ("basic-logical.aff4", README_PATH, README_BYTES), ("basic.dar", "hello.txt", &b"hello from dar\n"[..])]
    {
        let output = Command::new(zm_path()).arg("extract").arg(fixture(name)).arg("--to-stdout").arg("--include").arg(entry).output().unwrap();
        assert_success(&format!("zm extract --to-stdout {name}"), &output);
        assert_eq!(output.stdout, expected, "{name} streamed the wrong bytes");
    }
}

#[test]
fn zm_extracts_identical_trees_from_every_disk_image_fixture() {
    let temp = TestDir::new("forensic_cli_tree");
    let reference = temp.path("reference");
    let output = Command::new(zm_path()).arg("extract").arg(fixture("basic.vdi")).arg("-C").arg(&reference).output().unwrap();
    assert_success("zm extract basic.vdi", &output);
    let expected = collect_tree_entries(&reference);
    assert!(!expected.is_empty(), "the reference extraction produced nothing");

    for name in DISK_IMAGE_FIXTURES {
        let out = temp.path(format!("tree-{name}"));
        let output = Command::new(zm_path()).arg("extract").arg(fixture(name)).arg("-C").arg(&out).output().unwrap();
        assert_success(&format!("zm extract {name}"), &output);
        assert_eq!(collect_tree_entries(&out), expected, "{name} extracted a different tree than basic.vdi");
        assert_eq!(fs::read(out.join(README_PATH)).unwrap(), README_BYTES, "{name}");
    }
}

#[test]
fn zm_rejects_forensic_extensions_whose_payload_is_not_a_container() {
    // A file that merely carries the extension must fail with a diagnostic,
    // not be reported as an empty-but-valid container.
    let temp = TestDir::new("forensic_cli_reject");
    for name in ["junk.raw", "junk.dd", "junk.dsk", "junk.img", "junk.vhdx", "junk.qcow2", "junk.e01", "junk.ad1", "junk.dar", "junk.aff4"] {
        fs::write(temp.path(name), vec![0x5a_u8; 4096]).unwrap();
        let output = Command::new(zm_path()).arg("list").arg(temp.path(name)).output().unwrap();
        assert!(!output.status.success(), "{name} must not list successfully:\n{}", String::from_utf8_lossy(&output.stdout));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.trim().is_empty(), "{name} failed without a diagnostic");
    }
}

#[test]
fn zm_does_not_claim_the_unsupported_ewf_variants() {
    // `.s01` (SMART) and `.l01`/`.lx01` (EnCase logical evidence) are not
    // advertised: the EWF reader resolves a segment set by the `.e01`/`.ex01`
    // extension alone and cannot open them. They must fail with a diagnostic
    // instead of half-working, whether or not the bytes carry EWF magic.
    let temp = TestDir::new("forensic_cli_ewf_variants");
    let evidence = fs::read(fixture("basic.e01")).unwrap();

    for name in ["evidence.s01", "evidence.l01", "evidence.lx01"] {
        // Bytes that are not any known container: nothing may claim them.
        fs::write(temp.path(name), vec![0x5a_u8; 4096]).unwrap();
        let output = Command::new(zm_path()).arg("list").arg(temp.path(name)).output().unwrap();
        assert!(!output.status.success(), "{name} must not list");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Unsupported or unrecognized archive format"), "{name} should report an unrecognized format, got:\n{stderr}");

        // Real EWF bytes under the unsupported extension: content detection
        // still recognizes the magic, but the reader cannot open a segment set
        // by this name, so the command must fail loudly rather than list an
        // empty image.
        fs::write(temp.path(name), &evidence).unwrap();
        let output = Command::new(zm_path()).arg("list").arg(temp.path(name)).output().unwrap();
        assert!(!output.status.success(), "{name} carrying EWF magic must still not list:\n{}", String::from_utf8_lossy(&output.stdout));
        assert!(output.stdout.is_empty(), "{name} must not emit a listing");
        assert!(!String::from_utf8_lossy(&output.stderr).trim().is_empty(), "{name} failed without a diagnostic");
    }

    // The two supported extensions are unaffected.
    for name in ["basic.e01", "basic.ex01"] {
        let output = Command::new(zm_path()).arg("list").arg(fixture(name)).output().unwrap();
        assert_success(&format!("zm list {name}"), &output);
    }
}

#[test]
fn zm_test_verifies_every_forensic_fixture() {
    for (name, _) in FORENSIC_FIXTURES {
        let output = Command::new(zm_path()).arg("test").arg(fixture(name)).output().unwrap();
        assert_success(&format!("zm test {name}"), &output);
    }
}
