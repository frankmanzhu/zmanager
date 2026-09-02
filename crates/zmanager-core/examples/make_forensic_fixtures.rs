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
//! The AD1 tree and the logical AFF4 both carry the same `payload/` tree as
//! every other disk-image fixture (including an empty directory), so a single
//! expected listing covers the whole forensic family.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

/// The canonical fixture payload, byte-for-byte identical to the tree inside
/// `basic.vdi` / `basic.raw` / `basic.vhdx` / `basic.qcow2` / `basic.e01`.
///
/// Carries an empty directory alongside the files: AD1 has no symlink concept
/// (its `Node` builder has no `Symlink` variant — see `ad1-core`'s
/// `vfs.rs` doc comment), so an empty dir is the one structural element left
/// to distinguish "AD1 entries" from "AD1 file list".
fn payload_tree() -> ad1::testfix::Node {
    ad1::testfix::Node::Dir(
        "payload",
        vec![
            ad1::testfix::Node::File("README.txt", b"ZManager fixture payload\n".to_vec()),
            ad1::testfix::Node::Dir(
                "nested",
                vec![ad1::testfix::Node::File("file.txt", b"nested fixture file\n".to_vec()), ad1::testfix::Node::Dir("empty-dir", vec![])],
            ),
            ad1::testfix::Node::Dir("dir with spaces", vec![ad1::testfix::Node::File("file with spaces.txt", b"spaces in path\n".to_vec())]),
            ad1::testfix::Node::Dir("unicode", vec![ad1::testfix::Node::File("こんにちは.txt", b"unicode path fixture\n".to_vec())]),
        ],
    )
}

/// The same four files carried by [`payload_tree`], as `(segment path,
/// content)` pairs for the AFF4-Logical builder below. AFF4-L records a flat
/// file list (see `open_aff4_logical`'s doc comment: "no directory nodes; the
/// tree is derived from the `/`-separated original file names"), so there is
/// no separate empty-dir entry to carry -- the tree is rebuilt from these
/// paths alone.
fn logical_payload_files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("payload/README.txt", b"ZManager fixture payload\n".to_vec()),
        ("payload/nested/file.txt", b"nested fixture file\n".to_vec()),
        ("payload/dir with spaces/file with spaces.txt", b"spaces in path\n".to_vec()),
        ("payload/unicode/こんにちは.txt", b"unicode path fixture\n".to_vec()),
    ]
}

fn archives_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives")
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
}

/// Builds a multi-file AFF4-Logical (AFF4-L) container: one `aff4:FileImage`
/// RDF node and one stored ZIP segment per entry, following the same turtle
/// shape as `aff4-core`'s own single-entry `testutil::test_aff4_logical` (see
/// its doc comment: "mirroring pyaff4's `dream.aff4` shape"), just repeated
/// once per file instead of hard-coded to exactly one. This is data
/// construction against the documented wire shape, not a reimplementation of
/// `aff4::LogicalContainer`'s parser.
fn build_aff4_logical(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let vol = "aff4://zmanager-fixture-logical-volume";
    let mut turtle = String::from(
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
         @prefix aff4: <http://aff4.org/Schema#> .\n\
         @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n",
    );
    for (segment, content) in entries {
        let _ = writeln!(
            turtle,
            "<{vol}/{segment}> rdf:type aff4:FileImage , aff4:Image , aff4:zip_segment ; \
             aff4:originalFileName \"./{segment}\"^^xsd:string ; \
             aff4:size {} ; \
             aff4:lastWritten \"2018-09-17T13:42:20+10:00\"^^xsd:datetime ; \
             aff4:hash \"00000000000000000000000000000000\"^^aff4:MD5 ; \
             aff4:stored <{vol}> .",
            content.len()
        );
    }

    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut zw = ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    zw.start_file("information.turtle", opts).expect("start turtle");
    zw.write_all(turtle.as_bytes()).expect("write turtle");
    for (segment, content) in entries {
        zw.start_file(*segment, opts).unwrap_or_else(|e| panic!("start segment {segment}: {e}"));
        zw.write_all(content).unwrap_or_else(|e| panic!("write segment {segment}: {e}"));
    }
    zw.start_file("version.txt", opts).expect("start version");
    zw.write_all(b"major=1\nminor=1\ntool=zmanager-fixture\n").expect("write version");
    zw.finish().expect("finish zip").into_inner()
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
    // sector-stream resolver. Carries the whole canonical payload (minus the
    // empty dir, which AFF4-L's flat file list has no way to represent) so
    // this leg gets the same multi-file/nested/unicode coverage as every
    // other forensic format instead of a single-file smoke test.
    let files = logical_payload_files();
    let entries: Vec<(&str, &[u8])> = files.iter().map(|(path, bytes)| (*path, bytes.as_slice())).collect();
    write(&dir.join("basic-logical.aff4"), &build_aff4_logical(&entries));
}
