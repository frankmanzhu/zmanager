//! Core archive engine adapter conformance test suite (ARC-109, ARC-110).

mod common;

use common::TestDir;
use std::fs::{self, File};
use std::io::Write as _;

use zmanager_core::archive_browser::BrowserEntryKind;
use zmanager_core::engine::{
    ArchiveEngineBuilder, ArchiveError, ArchiveOperation, ArchivePlugin, ArchiveSource, FormatId, OpenOptions, SourceAccess, create_default_engine,
    is_split_zip_archive_path,
};

#[test]
fn default_engine_registers_every_phase_two_native_listing_adapter() {
    let engine = create_default_engine().unwrap();
    let expected = [
        (FormatId::SEVEN_Z, SourceAccess::Seekable),
        (FormatId::TAR_ZST, SourceAccess::Seekable),
        (FormatId::TZAP, SourceAccess::Seekable),
        (FormatId::RAR, SourceAccess::Seekable),
        (FormatId::RAW_STREAM, SourceAccess::Seekable),
        (FormatId::APPLE_ARCHIVE, SourceAccess::Seekable),
        (FormatId::DMG, SourceAccess::Seekable),
        (FormatId::PKG, SourceAccess::Seekable),
        (FormatId::MSI, SourceAccess::Seekable),
        (FormatId::VHD, SourceAccess::Seekable),
        (FormatId::VMDK, SourceAccess::Seekable),
        (FormatId::UDF, SourceAccess::Seekable),
    ];

    for (format, source_access) in expected {
        let capabilities = engine.registry().capabilities_for_format(format).unwrap_or_else(|| panic!("missing capabilities for {format}"));
        assert!(capabilities.operations.contains(&ArchiveOperation::List), "{format} must claim listing");
        assert_eq!(capabilities.source_access, source_access, "{format} advertised the wrong source access");
    }
    assert!(!zmanager_core::engine::adapters::libarchive::LIBARCHIVE_ALLOW_LIST.contains(&FormatId::RAR));
}

#[test]
fn capability_snapshot_reports_registration_and_platform_state() {
    let engine = create_default_engine().unwrap();
    let snapshot = engine.capability_snapshot();

    let zip = snapshot.iter().find(|capability| capability.format == FormatId::ZIP).expect("ZIP capability should be present");
    assert!(zip.recognized);
    assert!(zip.platform_available);
    assert!(zip.unavailable_reason.is_none());
    assert!(zip.operations.contains(&ArchiveOperation::List));
    assert_eq!(zip.source_access, Some(SourceAccess::Seekable));
    assert!(zip.encryption_supported);

    let apple_archive = snapshot.iter().find(|capability| capability.format == FormatId::APPLE_ARCHIVE).expect("Apple Archive capability should be present");
    assert!(apple_archive.recognized);
    assert!(apple_archive.platform_available);
}

#[test]
fn engine_lists_native_zip_fixture() {
    let temp = TestDir::new("engine-conformance-zip");
    let zip_path = temp.path("test.zip");

    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("hello.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"Hello world!").unwrap();
    zip.finish().unwrap();

    let engine = create_default_engine().unwrap();
    let source = ArchiveSource::from_path_autodetect(&zip_path);
    let mut handle = engine.open(source, OpenOptions::default()).unwrap();

    assert_eq!(handle.detected().format, FormatId::ZIP);
    let listing = handle.list().unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "hello.txt");
    assert_eq!(listing.entries[0].kind, BrowserEntryKind::File);
    assert_eq!(listing.entries[0].size, Some(12));

    handle.close().unwrap();
}

#[test]
fn engine_rejects_ambiguous_registrations_at_build_time() {
    struct DummyPlugin;
    impl ArchivePlugin for DummyPlugin {
        fn name(&self) -> &'static str {
            "dummy_duplicate"
        }
        fn register(&self, builder: &mut ArchiveEngineBuilder) -> Result<(), ArchiveError> {
            let factory = std::sync::Arc::new(zmanager_core::engine::adapters::zip::ZipListAdapter::single_volume());
            builder.register_read_adapter(factory.clone())?;
            builder.register_read_adapter(factory)
        }
    }

    let result = zmanager_core::engine::build_engine_with_plugins(&[&DummyPlugin]);
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.message.contains("Ambiguous registration"));
}

#[test]
fn engine_handles_split_zip_sidecar_detection_without_libarchive() {
    let temp = TestDir::new("engine-conformance-split-zip");
    let z01 = temp.path("split_test.z01");
    let zip = temp.path("split_test.zip");

    fs::write(&z01, b"sidecar data").unwrap();
    fs::write(&zip, b"zip data").unwrap();

    assert!(is_split_zip_archive_path(&zip));
    assert!(is_split_zip_archive_path(&z01));

    let source = ArchiveSource::from_path_autodetect(&zip);
    match source {
        ArchiveSource::VolumeSet(volumes) => {
            assert_eq!(volumes.len(), 2);
            assert_eq!(volumes[0], z01);
            assert_eq!(volumes[1], zip);
        }
        ArchiveSource::Path(_) => panic!("Expected VolumeSet for split ZIP"),
    }
}

#[test]
fn engine_unusable_session_prevents_subsequent_operations() {
    let temp = TestDir::new("engine-conformance-corrupt");
    let corrupt_zip = temp.path("corrupt.zip");
    fs::write(&corrupt_zip, b"this is not a valid zip archive").unwrap();

    let engine = create_default_engine().unwrap();
    let source = ArchiveSource::Path(corrupt_zip);
    let mut handle = engine.open(source, OpenOptions::default()).unwrap();

    let res = handle.list();
    assert!(res.is_err());

    // Second call should report session unusable
    let res2 = handle.list();
    assert!(res2.is_err());
}
