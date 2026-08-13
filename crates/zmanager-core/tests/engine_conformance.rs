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
    ArchiveEngineBuilder, ArchiveError, ArchiveOperation, ArchivePlugin, ArchivePluginRole, ArchiveSource, CreateOptions, CreateRequest, ExtractOptions,
    FormatId, OpenOptions, SourceAccess, create_default_engine, is_split_zip_archive_path,
};

struct NoopSink;

impl zmanager_core::jobs::JobEventSink for NoopSink {
    fn emit(&mut self, _event: zmanager_core::jobs::JobEvent) {}
}

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
    #[cfg(feature = "libarchive-fallback")]
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
    assert!(zip.operations.contains(&ArchiveOperation::Create));
    assert_eq!(zip.role, Some(ArchivePluginRole::Both));
    assert_eq!(zip.source_access, Some(SourceAccess::Seekable));
    assert!(zip.encryption_supported);

    let apple_archive = snapshot.iter().find(|capability| capability.format == FormatId::APPLE_ARCHIVE).expect("Apple Archive capability should be present");
    assert!(apple_archive.recognized);
    assert!(apple_archive.platform_available);

    let package = snapshot.iter().find(|capability| capability.format == FormatId::PKG).expect("PKG capability should be present");
    assert_eq!(package.role, Some(ArchivePluginRole::Extraction));
}

#[test]
fn engine_creates_zip_through_one_shot_contract_and_commits_before_returning() {
    let temp = TestDir::new("engine-conformance-create-zip");
    let source = temp.path("source.txt");
    let archive = temp.path("created.zip");
    fs::write(&source, b"created through engine").unwrap();
    let manifest = zmanager_core::manifest::plan_archive(&source, &zmanager_core::manifest::PlanOptions::default()).unwrap();
    let request = CreateRequest::new(manifest, &archive, CreateOptions::Zip(zmanager_core::zip_backend::ZipCreateOptions::default()));
    let engine = create_default_engine().unwrap();
    let token = zmanager_core::jobs::CancellationToken::new();
    let mut sink = NoopSink;
    let mut context = zmanager_core::jobs::JobContext::new(&token, &mut sink);

    let report = engine.create(&request, &mut context).unwrap();
    assert_eq!(report.format, FormatId::ZIP);
    assert_eq!(report.written_entries, 1);
    assert_eq!(report.written_bytes, b"created through engine".len() as u64);
    assert!(archive.is_file());
    assert!(!temp.path("created.zip.tmp").exists());

    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    assert_eq!(handle.list().unwrap().entries.len(), 1);
    handle.close().unwrap();
}

fn create_engine_fixture(
    engine: &zmanager_core::engine::ArchiveEngine,
    source: &std::path::Path,
    destination: &std::path::Path,
    options: CreateOptions,
) -> zmanager_core::engine::CreateReport {
    let manifest = zmanager_core::manifest::plan_archive(source, &zmanager_core::manifest::PlanOptions::default()).unwrap();
    let request = CreateRequest::new(manifest, destination, options);
    let token = zmanager_core::jobs::CancellationToken::new();
    let mut sink = NoopSink;
    let mut context = zmanager_core::jobs::JobContext::new(&token, &mut sink);
    engine.create(&request, &mut context).unwrap()
}

#[test]
fn engine_creation_adapters_round_trip_portable_formats() {
    let temp = TestDir::new("engine-conformance-create-matrix");
    let source = temp.path("project");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"portable create matrix").unwrap();
    let engine = create_default_engine().unwrap();

    let cases = [
        ("created.tar.gz", CreateOptions::TarGz(zmanager_core::tar_gz_backend::TarGzCreateOptions::default())),
        ("created.tar.zst", CreateOptions::TarZstd(zmanager_core::tar_zst_backend::TarZstdCreateOptions::default())),
        ("created.7z", CreateOptions::SevenZ(zmanager_core::sevenz_backend::SevenZCreateOptions { encrypt_file_names: false, ..Default::default() })),
        (
            "created.tzap",
            CreateOptions::Tzap(zmanager_core::tzap_backend::TzapCreateOptions {
                key_source: zmanager_core::tzap_backend::TzapKeySource::NoPassword,
                level: 1,
                preserve_metadata: true,
                replace_existing: false,
                volume_size: None,
                recovery_percentage: 0,
                volume_loss_tolerance: 0,
                x509_signing: None,
            }),
        ),
    ];

    for (name, options) in cases {
        let archive = temp.path(name);
        let report = create_engine_fixture(&engine, &source, &archive, options);
        assert_eq!(report.written_entries, 2, "{name} should include the project directory and file");
        assert!(archive.is_file(), "{name} should be committed before create returns");
        let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
        let listing = handle.list().unwrap();
        assert!(listing.entries.iter().any(|entry| entry.path == "project/file.txt"), "{name} should reopen through the engine");
        let destination = temp.path(format!("out-{name}"));
        let mut extract = ExtractOptions { destination, ..Default::default() };
        assert_eq!(handle.extract(&mut extract).unwrap().written_bytes, b"portable create matrix".len() as u64);
    }
}

#[test]
fn native_tar_family_uses_shared_reader_for_all_read_operations() {
    let temp = TestDir::new("engine-conformance-shared-tar");
    let source = temp.path("payload.txt");
    fs::write(&source, b"shared tar payload").unwrap();

    let plain_tar = temp.path("payload.tar");
    let file = File::create(&plain_tar).unwrap();
    let mut builder = tar::Builder::new(file);
    builder.append_path_with_name(&source, "payload.txt").unwrap();
    builder.finish().unwrap();

    let gzip_tar = temp.path("payload.tar.gz");
    zmanager_core::tar_gz_backend::create_tar_gz_from_path(&source, &gzip_tar, &zmanager_core::tar_gz_backend::TarGzCreateOptions::default()).unwrap();

    let bzip_tar = temp.path("payload.tar.bz2");
    let file = File::create(&bzip_tar).unwrap();
    let encoder = bzip2::write::BzEncoder::new(file, bzip2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    builder.append_path_with_name(&source, "payload.txt").unwrap();
    builder.into_inner().unwrap().finish().unwrap();

    let mut archives = vec![plain_tar, gzip_tar, bzip_tar];
    for (tool, suffix) in [("xz", "xz"), ("lzma", "lzma")] {
        let Ok(output) = std::process::Command::new(tool).arg("-c").arg(archives[0].as_path()).output() else {
            continue;
        };
        if output.status.success() {
            let archive = temp.path(format!("payload.tar.{suffix}"));
            fs::write(&archive, output.stdout).unwrap();
            archives.push(archive);
        }
    }

    let engine = create_default_engine().unwrap();
    for (index, archive) in archives.iter().enumerate() {
        let mut handle = engine.open(ArchiveSource::from_path_autodetect(archive), OpenOptions::default()).unwrap();
        let listing = handle.list().unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].path, "payload.txt");
        let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
        assert_eq!(test.tested_entries, 1);
        assert_eq!(test.tested_bytes, b"shared tar payload".len() as u64);
        let mut copied = Vec::new();
        let copy = handle.copy_entry(listing.entries[0].id, &mut copied).unwrap();
        assert_eq!(copy.written_bytes, b"shared tar payload".len() as u64);
        assert_eq!(copied, b"shared tar payload");
        handle.close().unwrap();

        let destination = temp.path(format!("out-{index}"));
        let mut handle = engine.open(ArchiveSource::from_path_autodetect(archive), OpenOptions::default()).unwrap();
        let mut options = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
        let report = handle.extract(&mut options).unwrap();
        assert_eq!(report.written_entries, 1);
        assert_eq!(fs::read(destination.join("payload.txt")).unwrap(), b"shared tar payload");
        handle.close().unwrap();
    }
}

#[test]
fn native_cpio_adapter_uses_bounded_operations_for_fixture() {
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.cpio");
    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    assert!(!listing.entries.is_empty());
    assert!(listing.entries.iter().any(|entry| entry.path.ends_with("README.txt")));

    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert_eq!(test.tested_entries, listing.entries.len() as u64);
    assert!(test.tested_bytes > 0);

    let file_entry = listing
        .entries
        .iter()
        .find(|entry| entry.kind == BrowserEntryKind::File && entry.size == Some(12))
        .unwrap_or_else(|| listing.entries.iter().find(|entry| entry.kind == BrowserEntryKind::File).expect("fixture should contain a regular file"));
    let mut copied = Vec::new();
    let copy = handle.copy_entry(file_entry.id, &mut copied).unwrap();
    assert_eq!(copy.written_bytes, copied.len() as u64);
    assert!(!copied.is_empty());

    let destination = TestDir::new("engine-conformance-cpio");
    let mut options = ExtractOptions { destination: destination.path("out"), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert!(report.written_entries > 0);
    assert!(destination.path("out").join("payload/README.txt").is_file());
    handle.close().unwrap();
}

#[test]
fn native_deb_adapter_composes_ar_and_shared_payload_readers() {
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.deb");
    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    assert_eq!(listing.entries.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>(), ["debian-binary", "control.tar.gz", "data.tar.xz"]);

    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert_eq!(test.tested_entries, 3);
    assert!(test.tested_bytes > 0);

    let destination = TestDir::new("engine-conformance-deb");
    let mut options = ExtractOptions { destination: destination.path("out"), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert!(report.written_entries > 0);
    assert_eq!(fs::read(destination.path("out/data/usr/share/zmanager-fixture/README.txt")).unwrap(), b"ZManager fixture payload\n");
    handle.close().unwrap();
}

#[test]
fn native_rpm_adapter_composes_header_and_cpio_when_rpmbuild_available() {
    let Some(rpmbuild) = std::env::var("PATH")
        .ok()
        .and_then(|path| path.split(':').map(std::path::PathBuf::from).map(|directory| directory.join("rpmbuild")).find(|candidate| candidate.is_file()))
    else {
        return;
    };
    let temp = TestDir::new("engine-conformance-rpm");
    let topdir = temp.path("rpmbuild");
    for directory in ["BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"] {
        fs::create_dir_all(topdir.join(directory)).unwrap();
    }
    let spec = topdir.join("SPECS/zmanager-engine.spec");
    fs::write(
        &spec,
        "Name: zmanager-engine\nVersion: 1.0\nRelease: 1\nSummary: ZManager engine fixture\nLicense: Apache-2.0\nBuildArch: noarch\n\n%description\nZManager engine fixture\n\n%install\nmkdir -p %{buildroot}/usr/share/zmanager-engine\nprintf 'rpm engine payload\\n' > %{buildroot}/usr/share/zmanager-engine/file.txt\n\n%files\n/usr/share/zmanager-engine/file.txt\n",
    )
    .unwrap();
    let build = std::process::Command::new(rpmbuild)
        .arg("--define")
        .arg(format!("_topdir {}", topdir.display()))
        .arg("--define")
        .arg("_build_id_links none")
        .arg("-bb")
        .arg(&spec)
        .output()
        .unwrap();
    assert!(build.status.success(), "rpmbuild failed: {}", String::from_utf8_lossy(&build.stderr));
    let archive = topdir.join("RPMS/noarch/zmanager-engine-1.0-1.noarch.rpm");

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let file_entry =
        listing.entries.iter().find(|entry| entry.path.ends_with("usr/share/zmanager-engine/file.txt")).expect("RPM payload file should be listed");
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert!(test.tested_entries > 0);
    let mut copied = Vec::new();
    let copy = handle.copy_entry(file_entry.id, &mut copied).unwrap();
    assert_eq!(copy.written_bytes, copied.len() as u64);
    assert_eq!(copied, b"rpm engine payload\n");

    let destination = temp.path("out");
    let mut options = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert!(report.written_entries > 0);
    assert_eq!(fs::read(destination.join("usr/share/zmanager-engine/file.txt")).unwrap(), b"rpm engine payload\n");
    handle.close().unwrap();
}

#[test]
fn native_cab_adapter_composes_shared_safety_and_atomic_output() {
    let temp = TestDir::new("engine-conformance-cab");
    let archive = temp.path("payload.cab");
    let mut builder = cab::CabinetBuilder::new();
    let folder = builder.add_folder(cab::CompressionType::MsZip);
    folder.add_file("project/file.txt");
    let mut writer = builder.build(File::create(&archive).unwrap()).unwrap();
    writer.next_file().unwrap().unwrap().write_all(b"cab engine payload\n").unwrap();
    writer.finish().unwrap();

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    assert_eq!(listing.entries[0].path, "project/file.txt");
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert_eq!(test.tested_entries, 1);
    let mut copied = Vec::new();
    handle.copy_entry(listing.entries[0].id, &mut copied).unwrap();
    assert_eq!(copied, b"cab engine payload\n");
    let destination = temp.path("out");
    let mut options = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
    assert_eq!(handle.extract(&mut options).unwrap().written_entries, 1);
    assert_eq!(fs::read(destination.join("project/file.txt")).unwrap(), b"cab engine payload\n");
    handle.close().unwrap();
}

#[test]
fn engine_creation_cancellation_does_not_commit_output() {
    let temp = TestDir::new("engine-conformance-create-cancel");
    let source = temp.path("source.txt");
    let archive = temp.path("cancelled.tar.zst");
    fs::write(&source, b"cancelled create").unwrap();
    let manifest = zmanager_core::manifest::plan_archive(&source, &zmanager_core::manifest::PlanOptions::default()).unwrap();
    let request = CreateRequest::new(manifest, &archive, CreateOptions::TarZstd(zmanager_core::tar_zst_backend::TarZstdCreateOptions::default()));
    let engine = create_default_engine().unwrap();
    let token = zmanager_core::jobs::CancellationToken::new();
    token.cancel();
    let mut sink = NoopSink;
    let mut context = zmanager_core::jobs::JobContext::new(&token, &mut sink);
    let error = engine.create(&request, &mut context).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::Cancelled);
    assert!(!archive.exists());
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
