//! Mints the AD1 and AFF4 fixtures in `fixtures/archives`.
//!
//! AD1 (FTK Imager) and AFF4 have no writer on the usual fixture toolchain, so
//! the two reader crates' own test builders are driven here instead. Running
//! this is how those fixtures are regenerated:
//!
//! ```text
//! cargo run -p zmanager-core --example make_forensic_fixtures
//! ```
//!
//! The AD1 tree and the physical AFF4's backing image both carry the same
//! `payload/` tree as every other disk-image fixture, so a single expected
//! listing covers the whole forensic family.

use std::path::{Path, PathBuf};

/// The canonical fixture payload, byte-for-byte identical to the tree inside
/// `basic.vdi` / `basic.raw` / `basic.vhdx` / `basic.qcow2` / `basic.e01`.
fn payload_tree() -> ad1::testfix::Node {
    ad1::testfix::Node::Dir(
        "payload",
        vec![
            ad1::testfix::Node::File("README.txt", b"ZManager fixture payload\n".to_vec()),
            ad1::testfix::Node::Dir("nested", vec![ad1::testfix::Node::File("file.txt", b"nested fixture file\n".to_vec())]),
            ad1::testfix::Node::Dir("dir with spaces", vec![ad1::testfix::Node::File("file with spaces.txt", b"spaces in path\n".to_vec())]),
            ad1::testfix::Node::Dir("unicode", vec![ad1::testfix::Node::File("こんにちは.txt", b"unicode path fixture\n".to_vec())]),
        ],
    )
}

fn archives_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives")
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
}

fn main() {
    let dir = archives_dir();
    assert!(dir.is_dir(), "fixtures directory is missing: {}", dir.display());

    write(&dir.join("basic.ad1"), &ad1::testfix::build(payload_tree()).bytes);

    // The *physical* AFF4 fixture (`basic.aff4`) is minted by
    // `scripts/make_aff4_fixture.py` instead: `aff4-core`'s bundled
    // `testutil::test_aff4` truncates its input to one 512-byte chunk, which
    // cannot hold a disk image.

    // Logical AFF4 (`aff4:FileImage`): a captured file tree rather than a disk,
    // which the engine routes through `open_aff4_logical` instead of the
    // sector-stream resolver. Both legs need a fixture.
    let logical = b"ZManager fixture payload\n";
    write(&dir.join("basic-logical.aff4"), &aff4::testutil::test_aff4_logical("payload/README.txt", logical, "00000000000000000000000000000000"));
}
