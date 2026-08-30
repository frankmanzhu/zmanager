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
