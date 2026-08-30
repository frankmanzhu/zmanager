//! Cross-format adversarial contracts for archive readers.
//!
//! Backend unit tests tend to prove that a well-formed fixture can make a
//! round trip.  This suite instead exercises malformed state transitions at
//! the public engine seam, where a parser must fail closed without creating
//! output or reporting a damaged archive as healthy.

mod common;

use common::TestDir;
use flate2::Compression;
use flate2::write::{GzEncoder, ZlibEncoder};
use std::io::Write;
use std::path::Path;
use zmanager_core::archive_format::{ArchiveFormatKind, detect_archive_format};
use zmanager_core::engine::{ArchiveSource, ExtractOptions, OpenOptions, TestOptions};

struct CorruptCase {
    name: &'static str,
    expected_format: ArchiveFormatKind,
    bytes: &'static [u8],
}

#[test]
fn truncated_container_matrix_fails_integrity_and_extraction_closed() {
    let cases = [
        CorruptCase { name: "truncated.zip", expected_format: ArchiveFormatKind::Zip, bytes: b"PK\x03\x04\x14\0" },
        CorruptCase { name: "truncated.z01", expected_format: ArchiveFormatKind::SplitZip, bytes: b"PK\x03\x04\x14\0" },
        CorruptCase { name: "truncated.7z", expected_format: ArchiveFormatKind::SevenZ, bytes: b"7z\xbc\xaf'\x1c\0\0" },
        CorruptCase { name: "truncated.rar", expected_format: ArchiveFormatKind::Rar, bytes: b"Rar!\x1a\x07\x01\0" },
        CorruptCase { name: "truncated.tar", expected_format: ArchiveFormatKind::Tar, bytes: b"not a complete tar header" },
        CorruptCase { name: "truncated.tar.gz", expected_format: ArchiveFormatKind::TarGz, bytes: b"\x1f\x8b\x08\0" },
        CorruptCase { name: "truncated.tar.zst", expected_format: ArchiveFormatKind::TarZst, bytes: b"\x28\xb5\x2f\xfd" },
        CorruptCase { name: "truncated.tar.bz2", expected_format: ArchiveFormatKind::TarBz2, bytes: b"BZh9" },
        CorruptCase { name: "truncated.tar.xz", expected_format: ArchiveFormatKind::TarXz, bytes: b"\xfd7zXZ\0" },
        CorruptCase { name: "truncated.tar.lzma", expected_format: ArchiveFormatKind::TarLzma, bytes: b"\x5d\0\0\x80\0" },
        CorruptCase { name: "truncated.tar.lz", expected_format: ArchiveFormatKind::TarLz, bytes: b"LZIP\x01" },
        CorruptCase { name: "truncated.tar.lzo", expected_format: ArchiveFormatKind::TarLzo, bytes: b"\x89LZO\0\r\n\x1a\n" },
        CorruptCase { name: "truncated.tar.Z", expected_format: ArchiveFormatKind::TarCompress, bytes: b"\x1f\x9d" },
        CorruptCase { name: "truncated.tar.lz4", expected_format: ArchiveFormatKind::TarLz4, bytes: b"\x04\x22\x4d\x18" },
        CorruptCase { name: "truncated.tar.uu", expected_format: ArchiveFormatKind::TarUu, bytes: b"begin 644 payload.tar\n#bad\n" },
        CorruptCase { name: "truncated.cab", expected_format: ArchiveFormatKind::Cab, bytes: b"MSCF\0\0\0\0" },
        CorruptCase { name: "truncated.cpio", expected_format: ArchiveFormatKind::Cpio, bytes: b"07070100000000" },
        CorruptCase { name: "truncated.rpm", expected_format: ArchiveFormatKind::Rpm, bytes: b"\xed\xab\xee\xdb\x03\0" },
        CorruptCase { name: "truncated.xar", expected_format: ArchiveFormatKind::Xar, bytes: b"xar!\0\x1c\0\x01" },
        CorruptCase { name: "truncated.pkg", expected_format: ArchiveFormatKind::Pkg, bytes: b"xar!\0\x1c\0\x01" },
        CorruptCase { name: "truncated.dmg", expected_format: ArchiveFormatKind::Dmg, bytes: b"koly" },
        CorruptCase { name: "truncated.lha", expected_format: ArchiveFormatKind::Lha, bytes: b"\x16\0-lh5-" },
        CorruptCase { name: "truncated.ar", expected_format: ArchiveFormatKind::Ar, bytes: b"!<arch>\nshort" },
        CorruptCase {
            name: "truncated.warc",
            expected_format: ArchiveFormatKind::Warc,
            bytes: b"WARC/1.1\r\nWARC-Type: response\r\nContent-Length: 9\r\n\r\nshort",
        },
        CorruptCase { name: "truncated.deb", expected_format: ArchiveFormatKind::Deb, bytes: b"!<arch>\n" },
        CorruptCase { name: "truncated.mtree", expected_format: ArchiveFormatKind::Mtree, bytes: b"#mtree\n/set type=bogus\n" },
        CorruptCase { name: "truncated.aar", expected_format: ArchiveFormatKind::AppleArchive, bytes: b"AA01" },
        CorruptCase { name: "truncated.msi", expected_format: ArchiveFormatKind::Msi, bytes: b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" },
        CorruptCase { name: "truncated.vhd", expected_format: ArchiveFormatKind::Vhd, bytes: b"conectix" },
        CorruptCase { name: "truncated.vmdk", expected_format: ArchiveFormatKind::Vmdk, bytes: b"KDMV" },
        CorruptCase { name: "truncated.udf", expected_format: ArchiveFormatKind::Udf, bytes: b"NSR02" },
        CorruptCase { name: "truncated.iso", expected_format: ArchiveFormatKind::Iso, bytes: b"CD001" },
        CorruptCase { name: "truncated.tzap", expected_format: ArchiveFormatKind::Tzap, bytes: b"TZAP" },
        CorruptCase { name: "truncated.gz", expected_format: ArchiveFormatKind::RawStream, bytes: b"\x1f\x8b\x08\0" },
        CorruptCase { name: "truncated.squashfs", expected_format: ArchiveFormatKind::Squashfs, bytes: b"hsqs\0\0\0\0" },
        CorruptCase { name: "truncated.appimage", expected_format: ArchiveFormatKind::AppImage, bytes: b"\x7fELF\x02\x01\x01\0\x41\x49\x02" },
        CorruptCase { name: "truncated.wim", expected_format: ArchiveFormatKind::Wim, bytes: b"MSWIM\0\0\0" },
        CorruptCase { name: "truncated.vdi", expected_format: ArchiveFormatKind::Vdi, bytes: &[0; 100] },
        CorruptCase { name: "truncated.isz", expected_format: ArchiveFormatKind::Isz, bytes: b"IsZ!" },
        CorruptCase { name: "truncated.nrg", expected_format: ArchiveFormatKind::Nrg, bytes: b"NERO\0\0\0\0" },
        CorruptCase { name: "truncated.mdf", expected_format: ArchiveFormatKind::Mdf, bytes: b"MDF\0" },
        CorruptCase { name: "truncated.cdi", expected_format: ArchiveFormatKind::Cdi, bytes: b"CDI\0" },
        CorruptCase { name: "truncated.ccd", expected_format: ArchiveFormatKind::Ccd, bytes: b"[CloneCD]\r\n" },
        CorruptCase { name: "truncated.cue", expected_format: ArchiveFormatKind::Cue, bytes: b"FILE \"missing.bin\" BINARY\r\n" },
        CorruptCase { name: "truncated.vhdx", expected_format: ArchiveFormatKind::Vhdx, bytes: b"vhdxfile" },
        CorruptCase { name: "truncated.qcow2", expected_format: ArchiveFormatKind::Qcow2, bytes: &[0x51, 0x46, 0x49, 0xfb] },
        CorruptCase { name: "truncated.qcow", expected_format: ArchiveFormatKind::Qcow2, bytes: &[0x51, 0x46, 0x49, 0xfb] },
        CorruptCase { name: "truncated.e01", expected_format: ArchiveFormatKind::Ewf, bytes: b"EVF\x09\x0d\x0a\xff\x00" },
        CorruptCase { name: "truncated.ex01", expected_format: ArchiveFormatKind::Ewf, bytes: b"EVF2\x0d\x0a\x81\x00" },
        CorruptCase { name: "truncated.ad1", expected_format: ArchiveFormatKind::Ad1, bytes: b"ADSEGMENTEDFILE\0" },
        CorruptCase { name: "truncated.dar", expected_format: ArchiveFormatKind::Dar, bytes: b"DAR\0" },
        CorruptCase { name: "truncated.aff4", expected_format: ArchiveFormatKind::Aff4, bytes: b"PK\x03\x04" },
        CorruptCase { name: "truncated.raw", expected_format: ArchiveFormatKind::RawDisk, bytes: b"raw sector dump" },
        CorruptCase { name: "truncated.dd", expected_format: ArchiveFormatKind::RawDisk, bytes: b"raw sector dump" },
        CorruptCase { name: "truncated.dsk", expected_format: ArchiveFormatKind::RawDisk, bytes: b"raw sector dump" },
        CorruptCase { name: "truncated.img", expected_format: ArchiveFormatKind::RawDisk, bytes: b"raw sector dump" },
    ];
    let temp = TestDir::new("truncated-container-matrix");
    let mut failures = Vec::new();

    for case in cases {
        temp.write_file(case.name, case.bytes);
        let archive = temp.path(case.name);
        assert_eq!(detect_archive_format(&archive), case.expected_format, "{} routed to the wrong backend", case.name);

        if !engine_test_rejects(&archive) {
            failures.push(format!("{} was reported healthy", case.name));
        }

        let destination = temp.path(format!("out-{}", case.name));
        if !engine_extract_rejects(&archive, &destination) {
            failures.push(format!("{} extracted successfully", case.name));
        }
        if !directory_is_empty_or_absent(&destination) {
            failures.push(format!("{} left materialized output behind", case.name));
        }
    }

    assert!(failures.is_empty(), "cross-format fail-closed violations:\n{}", failures.join("\n"));
}

#[test]
fn rar_signatures_without_a_complete_first_block_are_rejected() {
    let temp = TestDir::new("rar-first-block-truncation");
    for (version, signature) in [("rar4", b"Rar!\x1a\x07\x00".as_slice()), ("rar5", b"Rar!\x1a\x07\x01\x00".as_slice())] {
        for extra_bytes in 0..7 {
            let mut bytes = signature.to_vec();
            bytes.resize(signature.len() + extra_bytes, 0);
            let name = format!("{version}-{extra_bytes}.rar");
            temp.write_file(&name, &bytes);
            let archive = temp.path(&name);
            assert!(engine_test_rejects(&archive), "{name} was reported healthy");
            assert!(engine_extract_rejects(&archive, &temp.path(format!("out-{name}"))), "{name} extracted successfully");
        }
    }
}

#[test]
fn ar_rejects_partial_headers_and_out_of_bounds_member_extents() {
    let temp = TestDir::new("ar-extent-corruption");
    let cases = [
        ("partial-header.ar", b"!<arch>\npartial".to_vec()),
        ("missing-payload.ar", build_ar(&[("payload", 8, b"")])),
        ("partial-payload.ar", build_ar(&[("payload", 8, b"short")])),
        ("missing-padding.ar", build_ar_without_padding("payload", b"x")),
        ("invalid-padding.ar", build_ar_with_padding("payload", b"x", 0)),
    ];

    for (name, bytes) in cases {
        temp.write_file(name, &bytes);
        let archive = temp.path(name);
        assert!(engine_test_rejects(&archive), "{name} was reported healthy");
        assert!(engine_extract_rejects(&archive, &temp.path(format!("out-{name}"))), "{name} extracted successfully");
    }
}

#[test]
fn deb_rejects_missing_or_ambiguous_payload_roles() {
    let temp = TestDir::new("deb-layout-corruption");
    let cases = [
        ("empty.deb", build_ar(&[])),
        ("missing-binary.deb", build_ar(&[("control.tar.gz", 0, b""), ("data.tar.zst", 0, b"")])),
        ("wrong-major-version.deb", build_ar(&[("debian-binary", 4, b"3.0\n"), ("control.tar.gz", 0, b""), ("data.tar.zst", 0, b"")])),
        ("missing-control.deb", build_ar(&[("debian-binary", 4, b"2.0\n"), ("data.tar.zst", 0, b"")])),
        ("missing-data.deb", build_ar(&[("debian-binary", 4, b"2.0\n"), ("control.tar.gz", 0, b"")])),
        (
            "duplicate-control.deb",
            build_ar(&[("debian-binary", 4, b"2.0\n"), ("control.tar.gz", 0, b""), ("control.tar.xz", 0, b""), ("data.tar.zst", 0, b"")]),
        ),
        ("duplicate-data.deb", build_ar(&[("debian-binary", 4, b"2.0\n"), ("control.tar.gz", 0, b""), ("data.tar.zst", 0, b""), ("data.tar.xz", 0, b"")])),
        ("wrong-order.deb", build_ar(&[("debian-binary", 4, b"2.0\n"), ("data.tar.zst", 0, b""), ("control.tar.gz", 0, b"")])),
        ("corrupt-control-payload.deb", build_ar(&[("debian-binary", 4, b"2.0\n"), ("control.tar.gz", 4, b"\x1f\x8b\x08\0"), ("data.tar", 1024, &[0; 1024])])),
    ];

    for (name, bytes) in cases {
        temp.write_file(name, &bytes);
        let archive = temp.path(name);
        assert!(engine_test_rejects(&archive), "{name} was reported healthy");
        assert!(engine_extract_rejects(&archive, &temp.path(format!("out-{name}"))), "{name} extracted successfully");
    }
}

#[test]
fn tar_requires_explicit_end_of_archive_records() {
    let temp = TestDir::new("tar-missing-end-records");
    let raw = build_tar_without_end_records("payload.txt", &vec![b'x'; 16 * 1024]);
    let zero_tailed = build_tar_without_end_records("zero-payload.bin", &vec![0; 16 * 1024]);
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    gzip.write_all(&raw).unwrap();
    let cases = [
        ("missing-end.tar", ArchiveFormatKind::Tar, raw),
        ("zero-tailed-missing-end.tar", ArchiveFormatKind::Tar, zero_tailed),
        ("missing-end.tar.gz", ArchiveFormatKind::TarGz, gzip.finish().unwrap()),
    ];

    for (name, expected_format, bytes) in cases {
        temp.write_file(name, &bytes);
        let archive = temp.path(name);
        assert_eq!(detect_archive_format(&archive), expected_format);
        assert!(engine_test_rejects(&archive), "{name} was reported healthy");
        let destination = temp.path(format!("out-{name}"));
        assert!(engine_extract_rejects(&archive, &destination), "{name} extracted successfully");
        assert!(directory_is_empty_or_absent(&destination), "{name} left materialized output behind");
    }
}

#[test]
fn squashfs_and_wim_malformed_inputs_are_rejected() {
    let temp = TestDir::new("squashfs-wim-malformed");

    // SquashFS with invalid compression ID
    let mut sqfs_bad = vec![0_u8; 1024];
    sqfs_bad[0..4].copy_from_slice(b"hsqs");
    sqfs_bad[20..22].copy_from_slice(&0x9999_u16.to_le_bytes()); // invalid compressor
    temp.write_file("bad-compressor.squashfs", &sqfs_bad);
    assert!(engine_test_rejects(&temp.path("bad-compressor.squashfs")));
    assert!(engine_extract_rejects(&temp.path("bad-compressor.squashfs"), &temp.path("out-sqfs")));

    // WIM with corrupt size fields
    let mut wim_bad = vec![0_u8; 512];
    wim_bad[0..8].copy_from_slice(b"MSWIM\0\0\0");
    wim_bad[8..12].copy_from_slice(&208_u32.to_le_bytes()); // header size
    wim_bad[12..16].copy_from_slice(&0x0001_0d00_u32.to_le_bytes()); // version
    wim_bad[16..20].copy_from_slice(&0x0002_0000_u32.to_le_bytes()); // XPRESS flag
    temp.write_file("bad-header.wim", &wim_bad);
    assert!(engine_test_rejects(&temp.path("bad-header.wim")));
    assert!(engine_extract_rejects(&temp.path("bad-header.wim"), &temp.path("out-wim")));
}

#[test]
fn structured_path_attacks_cannot_materialize_outside_the_destination() {
    let temp = TestDir::new("structured-path-attacks");
    let cases = [
        ("traversal.ar", build_ar(&[("../escape", 5, b"owned")]), true),
        ("traversal.cpio", build_newc("../escape", b"owned"), true),
        (
            "traversal.warc",
            b"WARC/1.1\r\nWARC-Type: response\r\nWARC-Target-URI: file:///../../escape\r\nContent-Length: 5\r\n\r\nowned\r\n\r\n".to_vec(),
            false,
        ),
        ("traversal.xar", build_xar(br#"<xar><toc><file id="1"><type>file</type><name>../escape</name></file></toc></xar>"#, &[]), true),
    ];

    for (name, bytes, must_reject) in cases {
        temp.write_file(name, &bytes);
        let destination = temp.path(format!("out-{name}"));
        let rejected = engine_extract_rejects(&temp.path(name), &destination);
        assert!(!must_reject || rejected, "{name} extracted successfully");
        if rejected {
            assert!(directory_is_empty_or_absent(&destination), "{name} left materialized output behind after rejection");
        }
        assert!(!temp.path("escape").exists(), "{name} escaped the destination");
    }
}

fn engine_test_rejects(path: &Path) -> bool {
    let engine = zmanager_core::engine::create_default_engine().expect("default engine should initialize");
    let source = ArchiveSource::from_path_autodetect(path);
    let Ok(mut handle) = engine.open(source, OpenOptions::default()) else {
        return true;
    };
    handle.test(&TestOptions::default()).is_err()
}

fn engine_extract_rejects(path: &Path, destination: &Path) -> bool {
    let engine = zmanager_core::engine::create_default_engine().expect("default engine should initialize");
    let source = ArchiveSource::from_path_autodetect(path);
    let Ok(mut handle) = engine.open(source, OpenOptions::default()) else {
        return true;
    };
    let mut options = ExtractOptions { destination: destination.to_path_buf(), ..ExtractOptions::default() };
    handle.extract(&mut options).is_err()
}

fn directory_is_empty_or_absent(path: &Path) -> bool {
    !path.exists() || std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
}

fn build_ar(entries: &[(&str, usize, &[u8])]) -> Vec<u8> {
    let mut archive = b"!<arch>\n".to_vec();
    for &(name, declared_size, payload) in entries {
        archive.extend_from_slice(&ar_header(name, declared_size));
        archive.extend_from_slice(payload);
        if declared_size % 2 == 1 && payload.len() == declared_size {
            archive.push(b'\n');
        }
    }
    archive
}

fn build_ar_without_padding(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut archive = b"!<arch>\n".to_vec();
    archive.extend_from_slice(&ar_header(name, payload.len()));
    archive.extend_from_slice(payload);
    archive
}

fn build_ar_with_padding(name: &str, payload: &[u8], padding: u8) -> Vec<u8> {
    let mut archive = build_ar_without_padding(name, payload);
    archive.push(padding);
    archive
}

fn ar_header(name: &str, size: usize) -> [u8; 60] {
    let mut header = [b' '; 60];
    write_field(&mut header[0..16], name.as_bytes());
    write_field(&mut header[16..28], b"0");
    write_field(&mut header[28..34], b"0");
    write_field(&mut header[34..40], b"0");
    write_field(&mut header[40..48], b"100644");
    write_field(&mut header[48..58], size.to_string().as_bytes());
    header[58..60].copy_from_slice(b"`\n");
    header
}

fn write_field(destination: &mut [u8], value: &[u8]) {
    destination[..value.len()].copy_from_slice(value);
}

fn build_newc(name: &str, payload: &[u8]) -> Vec<u8> {
    let name_bytes = format!("{name}\0");
    let fields = [1_u32, 0o100_644, 0, 0, 1, 0, u32::try_from(payload.len()).unwrap(), 0, 0, 0, 0, u32::try_from(name_bytes.len()).unwrap(), 0];
    let mut archive = b"070701".to_vec();
    for field in fields {
        archive.extend_from_slice(format!("{field:08x}").as_bytes());
    }
    archive.extend_from_slice(name_bytes.as_bytes());
    pad_to(&mut archive, 4);
    archive.extend_from_slice(payload);
    pad_to(&mut archive, 4);

    let trailer_name = b"TRAILER!!!\0";
    archive.extend_from_slice(b"070701");
    for field in [0_u32, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, u32::try_from(trailer_name.len()).unwrap(), 0] {
        archive.extend_from_slice(format!("{field:08x}").as_bytes());
    }
    archive.extend_from_slice(trailer_name);
    pad_to(&mut archive, 4);
    archive
}

fn pad_to(bytes: &mut Vec<u8>, alignment: usize) {
    let padding = (alignment - bytes.len() % alignment) % alignment;
    bytes.resize(bytes.len() + padding, 0);
}

fn build_tar_without_end_records(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut complete = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut complete);
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(payload.len()).unwrap());
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, payload).unwrap();
        builder.finish().unwrap();
    }
    assert!(complete.len() >= 1024);
    complete.truncate(complete.len() - 1024);
    complete
}

fn build_xar(toc_xml: &[u8], heap: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(toc_xml).unwrap();
    let compressed_toc = encoder.finish().unwrap();
    let mut archive = Vec::new();
    archive.extend_from_slice(&0x7861_7221_u32.to_be_bytes());
    archive.extend_from_slice(&28_u16.to_be_bytes());
    archive.extend_from_slice(&1_u16.to_be_bytes());
    archive.extend_from_slice(&u64::try_from(compressed_toc.len()).unwrap().to_be_bytes());
    archive.extend_from_slice(&u64::try_from(toc_xml.len()).unwrap().to_be_bytes());
    archive.extend_from_slice(&0_u32.to_be_bytes());
    archive.extend_from_slice(&compressed_toc);
    archive.extend_from_slice(heap);
    archive
}
