use std::fs;
use std::path::{Path, PathBuf};

use zmanager_wim::{WimArchive, WimEntryKind, WimError};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name)
}

#[test]
fn reads_uncompressed_wim_entries_and_verifies_streams() {
    let mut archive = WimArchive::open(fixture("basic-none.wim")).unwrap();
    let entries = archive.entries().unwrap();
    let readme = entries.iter().find(|entry| entry.path == "README.txt").unwrap();
    assert_eq!(readme.kind, WimEntryKind::File);
    assert_eq!(archive.read_entry_data(readme).unwrap().as_deref(), Some(b"ZManager fixture payload\n".as_slice()));
    assert!(archive.verify().unwrap() > 0);
}

#[test]
fn reads_xpress_and_lzx_wim_resources() {
    for name in ["basic-XPRESS.wim", "basic-LZX.wim"] {
        let mut archive = WimArchive::open(fixture(name)).unwrap();
        let entries = archive.entries().unwrap();
        let file = entries.iter().find(|entry| entry.path == "nested/file.txt").unwrap();
        assert_eq!(archive.read_entry_data(file).unwrap().as_deref(), Some(b"nested fixture file\n".as_slice()), "{name}");
        assert!(archive.verify().unwrap() > 0, "{name}");
    }
}

#[test]
fn resolves_split_wim_parts() {
    let mut archive = WimArchive::open(fixture("split.swm")).unwrap();
    let entries = archive.entries().unwrap();
    let readme = entries.iter().find(|entry| entry.path == "README.txt").unwrap();
    assert_eq!(archive.read_entry_data(readme).unwrap().as_deref(), Some(b"ZManager fixture payload\n".as_slice()));
    archive.verify().unwrap();
}

#[test]
fn rejects_lzms_and_malformed_wims() {
    let empty = fixture("basic-none.wim");
    let mut bytes = fs::read(&empty).unwrap();
    bytes[16..20].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
    let path = std::env::temp_dir().join(format!("zmanager-wim-lzms-{}-{}.wim", std::process::id(), std::thread::current().name().unwrap_or("test")));
    fs::write(&path, bytes).unwrap();
    let error = WimArchive::open(&path).unwrap_err();
    fs::remove_file(&path).unwrap();
    assert!(matches!(error, WimError::Unsupported { .. }));
    assert!(error.to_string().contains("LZMS"));
}

/// LZX long matches, maximum-length runs, and large-offset repeats.
///
/// `basic-LZX.wim` is a few hundred bytes, so it only ever exercises short
/// matches near the window start. This fixture is ~1.1 MiB of deliberately
/// repetitive data captured by `wimlib-imagex --compress=LZX`: 3000-byte
/// single-byte runs (maximum-length matches), a 64 KiB block repeated eight
/// times (long matches at high position slots, which is what drives the
/// aligned-offset block type), and repeated prose (dense literal/match
/// interleaving).
///
/// The oracle is the SHA-1 wimlib wrote into the WIM at capture time, hashed
/// over each file's *uncompressed* bytes before it compressed them (see
/// `WimArchive::verify`). Our decoder never contributes to that value, so a
/// match means our LZX output equals wimlib's input, not that we agree with
/// ourselves. Sizes are asserted from the metadata first so a regenerated
/// fixture with different content fails loudly rather than silently verifying
/// some other payload.
#[test]
fn decodes_lzx_long_matches_identically_to_wimlib() {
    let mut archive = WimArchive::open(fixture("lzx-longmatch.wim")).unwrap();
    let entries = archive.entries().unwrap();

    let expected = [("runs.bin", 360_000_u64), ("repeated-block.bin", 524_288), ("prose.txt", 270_000)];
    for (path, expected_len) in expected {
        let entry = entries.iter().find(|entry| entry.path == path).unwrap_or_else(|| panic!("{path} missing"));
        assert_eq!(entry.size, expected_len, "{path}");
    }

    // `verify` is the single decompression pass: it decodes every stream once,
    // checks the decoded length against the metadata, and compares the SHA-1.
    let verified = archive.verify().unwrap();
    assert_eq!(verified, expected.iter().map(|(_, len)| len).sum::<u64>(), "every LZX stream must decode and match its recorded SHA-1");
}
