//! Core archive engine adapter conformance test suite (ARC-109, ARC-110).

mod common;

use common::TestDir;
use std::fs::{self, File};
use std::io::Write as _;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use zmanager_core::archive_browser::BrowserEntryKind;
use zmanager_core::engine::{
    ArchiveEngineBuilder, ArchiveError, ArchiveOperation, ArchivePlugin, ArchiveSource, ExtractOptions, FormatId, OpenOptions, SourceAccess,
    create_default_engine, is_split_zip_archive_path,
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
        assert!(capabilities.operations.contains(&ArchiveOperation::Extract), "{format} must claim full extraction");
        assert_eq!(capabilities.source_access, source_access, "{format} advertised the wrong source access");
    }
    assert!(!zmanager_core::engine::adapters::libarchive::LIBARCHIVE_ALLOW_LIST.contains(&FormatId::RAR));
    for format in
        [FormatId::ZIP, FormatId::SPLIT_ZIP, FormatId::SEVEN_Z, FormatId::TAR_ZST, FormatId::TZAP, FormatId::RAR, FormatId::RAW_STREAM, FormatId::APPLE_ARCHIVE]
    {
        let capabilities = engine.registry().capabilities_for_format(format).unwrap_or_else(|| panic!("missing capabilities for {format}"));
        assert!(capabilities.operations.contains(&ArchiveOperation::Test), "{format} must claim data testing");
    }
    for format in [
        FormatId::ZIP,
        FormatId::SPLIT_ZIP,
        FormatId::SEVEN_Z,
        FormatId::TAR_ZST,
        FormatId::TAR_GZ,
        FormatId::TZAP,
        FormatId::RAR,
        FormatId::RAW_STREAM,
        FormatId::APPLE_ARCHIVE,
    ] {
        let capabilities = engine.registry().capabilities_for_format(format).unwrap_or_else(|| panic!("missing capabilities for {format}"));
        assert!(capabilities.operations.contains(&ArchiveOperation::Extract), "{format} must claim full extraction");
    }
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
    assert!(zip.operations.contains(&ArchiveOperation::Test));
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
fn engine_tests_native_zip_payload_and_honors_selection() {
    let temp = TestDir::new("engine-conformance-test-zip");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("selected.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"payload").unwrap();
    zip.start_file("skipped.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"other").unwrap();
    zip.finish().unwrap();

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let report = handle.test(&zmanager_core::engine::TestOptions { selected_paths: vec!["selected.txt".to_owned()], ..Default::default() }).unwrap();
    assert_eq!(report.tested_entries, 1);
    assert_eq!(report.skipped_entries, 1);
    assert_eq!(report.tested_bytes, 7);
}

#[test]
fn engine_extracts_native_zip_with_normalized_report() {
    let temp = TestDir::new("engine-conformance-extract-zip");
    let zip_path = temp.path("test.zip");
    let destination = temp.path("out");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("hello.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"Hello world!").unwrap();
    zip.finish().unwrap();

    let mut handle = create_default_engine().unwrap().open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let mut options = ExtractOptions { destination: destination.clone(), ..Default::default() };
    let report = handle.extract(&mut options).unwrap();
    assert_eq!(report.written_entries, 1);
    assert_eq!(report.written_bytes, 12);
    assert_eq!(fs::read(destination.join("hello.txt")).unwrap(), b"Hello world!");
}

#[test]
fn engine_extracts_and_copies_zip_entries_by_retained_id() {
    let temp = TestDir::new("engine-conformance-selected-zip");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("first.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"first").unwrap();
    zip.start_file("second.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"second").unwrap();
    zip.finish().unwrap();

    let mut handle = create_default_engine().unwrap().open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let second_id = listing.entries[1].id;
    let mut selected = zmanager_core::engine::SelectedExtractOptions { destination: temp.path("out"), ..Default::default() };
    let report = handle.extract_selected(second_id, &mut selected).unwrap();
    assert_eq!(report.written_entries, 1);
    assert_eq!(fs::read(temp.path("out/second.txt")).unwrap(), b"second");

    let mut copied = Vec::new();
    let copy_report = handle.copy_entry(listing.entries[0].id, &mut copied).unwrap();
    assert_eq!(copy_report.written_bytes, 5);
    assert_eq!(copied, b"first");
}

#[test]
fn engine_extract_cancellation_is_reported_before_adapter_work() {
    let temp = TestDir::new("engine-conformance-extract-cancelled");
    let zip_path = temp.path("test.zip");
    fs::write(&zip_path, b"not used").unwrap();
    let cancellation = zmanager_core::jobs::CancellationToken::new();
    cancellation.cancel();
    let mut handle = create_default_engine().unwrap().open(ArchiveSource::Path(zip_path), OpenOptions::default()).unwrap();
    let mut options = ExtractOptions { destination: temp.path("out"), cancellation: Some(cancellation), ..Default::default() };
    let error = handle.extract(&mut options).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::Cancelled);
}

#[test]
fn engine_extract_enforces_entry_count_budget() {
    let temp = TestDir::new("engine-conformance-extract-entry-budget");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for name in ["first.txt", "second.txt"] {
        zip.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(b"payload").unwrap();
    }
    zip.finish().unwrap();

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let mut options = ExtractOptions {
        destination: temp.path("out"),
        policy: zmanager_core::safety::ExtractionPolicy {
            limits: zmanager_core::safety::ExtractionLimits { max_entries: Some(1), ..zmanager_core::safety::ExtractionLimits::default() },
            ..zmanager_core::safety::ExtractionPolicy::default()
        },
        ..Default::default()
    };
    let error = handle.extract(&mut options).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::ResourceLimitExceeded);
}

#[test]
fn engine_extract_rejects_traversal_before_writing_outside_destination() {
    let temp = TestDir::new("engine-conformance-extract-traversal");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("../outside.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"must not escape").unwrap();
    zip.finish().unwrap();

    let destination = temp.path("out");
    let outside = temp.path("outside.txt");
    let mut handle = create_default_engine().unwrap().open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let mut options = ExtractOptions { destination, ..Default::default() };
    let error = handle.extract(&mut options).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::SafetyViolation);
    assert!(!outside.exists());
}

#[test]
fn engine_test_cancellation_is_reported_before_adapter_work() {
    let temp = TestDir::new("engine-conformance-test-cancelled");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("payload.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"payload").unwrap();
    zip.finish().unwrap();

    let cancellation = Arc::new(AtomicBool::new(true));
    let mut handle = create_default_engine().unwrap().open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let error = handle.test(&zmanager_core::engine::TestOptions { cancellation: Some(Arc::clone(&cancellation)), ..Default::default() }).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::Cancelled);
    assert!(cancellation.load(Ordering::Relaxed));
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

#[test]
fn engine_test_corruption_invalidates_the_session() {
    let temp = TestDir::new("engine-conformance-test-corrupt");
    let corrupt_zip = temp.path("corrupt.zip");
    fs::write(&corrupt_zip, b"this is not a valid zip archive").unwrap();

    let mut handle = create_default_engine().unwrap().open(ArchiveSource::Path(corrupt_zip), OpenOptions::default()).unwrap();
    let error = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::CorruptData);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Unusable);
    assert!(handle.test(&zmanager_core::engine::TestOptions::default()).is_err());
}
