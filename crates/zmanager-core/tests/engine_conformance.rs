//! Core archive engine adapter conformance test suite (ARC-109, ARC-110).

mod common;

use common::TestDir;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use zmanager_core::archive_browser::BrowserEntryKind;
use zmanager_core::engine::{
    AdapterDescriptor, ArchiveEngineBuilder, ArchiveError, ArchiveListing, ArchiveOperation, ArchivePlugin, ArchivePluginRole, ArchiveSource, CreateOptions,
    CreateRequest, CredentialRequirement, EngineEntry, ExtractOptions, FormatId, NavigationMode, OpenLimits, OpenOptions, ReadAdapterFactory,
    ReadAdapterSession, SevenZCreateOptions, SourceAccess, TarGzCreateOptions, TarZstdCreateOptions, TzapCreateOptions, TzapKeySource, ZipCreateOptions,
    create_default_engine, is_split_zip_archive_path,
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
        (FormatId::ISO, SourceAccess::Seekable),
        (FormatId::TAR_LZ, SourceAccess::Seekable),
        (FormatId::TAR_LZO, SourceAccess::Seekable),
        (FormatId::TAR_COMPRESS, SourceAccess::Seekable),
        (FormatId::TAR_LZ4, SourceAccess::Seekable),
        (FormatId::TAR_LRZ, SourceAccess::Seekable),
        (FormatId::LHA, SourceAccess::Seekable),
        (FormatId::WARC, SourceAccess::Seekable),
    ];

    for (format, source_access) in expected {
        let capabilities = engine.registry().capabilities_for_format(format).unwrap_or_else(|| panic!("missing capabilities for {format}"));
        assert!(capabilities.operations.contains(&ArchiveOperation::List), "{format} must claim listing");
        assert!(capabilities.operations.contains(&ArchiveOperation::Extract), "{format} must claim full extraction");
        assert_eq!(capabilities.source_access, source_access, "{format} advertised the wrong source access");
    }
    let mtree = engine.registry().capabilities_for_format(FormatId::MTREE).expect("missing MTREE capabilities");
    assert!(mtree.operations.contains(&ArchiveOperation::List));
    assert!(mtree.operations.contains(&ArchiveOperation::Test));
    assert!(!mtree.operations.contains(&ArchiveOperation::Extract));
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
        FormatId::ISO,
        FormatId::TAR_LZ,
        FormatId::TAR_LZO,
        FormatId::TAR_COMPRESS,
        FormatId::TAR_LZ4,
        FormatId::TAR_LRZ,
    ] {
        let capabilities = engine.registry().capabilities_for_format(format).unwrap_or_else(|| panic!("missing capabilities for {format}"));
        assert!(capabilities.operations.contains(&ArchiveOperation::Extract), "{format} must claim full extraction");
    }

    let zip = engine.registry().capabilities_for_format(FormatId::ZIP).unwrap();
    assert_eq!(zip.navigation, NavigationMode::RandomAccess);
    for format in [FormatId::TAR_GZ, FormatId::TAR_ZST, FormatId::SEVEN_Z, FormatId::TZAP, FormatId::RAR, FormatId::RAW_STREAM] {
        let capabilities = engine.registry().capabilities_for_format(format).unwrap_or_else(|| panic!("missing capabilities for {format}"));
        assert_eq!(capabilities.navigation, NavigationMode::SequentialScan, "{format} must advertise its cursor-scan navigation");
    }
    assert_eq!(zip.credential_requirement, CredentialRequirement::Password);
    let tzap = engine.registry().capabilities_for_format(FormatId::TZAP).unwrap();
    assert_eq!(tzap.credential_requirement, CredentialRequirement::PasswordOrRecipientKey);
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
    let request = CreateRequest::new(manifest, &archive, CreateOptions::Zip(ZipCreateOptions::default()));
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
        ("created.tar.gz", CreateOptions::TarGz(TarGzCreateOptions::default())),
        ("created.tar.zst", CreateOptions::TarZstd(TarZstdCreateOptions::default())),
        ("created.7z", CreateOptions::SevenZ(SevenZCreateOptions { encrypt_file_names: false, ..Default::default() })),
        (
            "created.tzap",
            CreateOptions::Tzap(TzapCreateOptions {
                key_source: TzapKeySource::NoPassword,
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
    zmanager_core::backend_test_support::tar_gz_backend::create_tar_gz_from_path(
        &source,
        &gzip_tar,
        &zmanager_core::backend_test_support::tar_gz_backend::TarGzCreateOptions::default(),
    )
    .unwrap();

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
fn native_xar_adapter_uses_standalone_reader_when_xar_available() {
    let Some(xar) = std::env::var("PATH")
        .ok()
        .and_then(|path| path.split(':').map(std::path::PathBuf::from).map(|directory| directory.join("xar")).find(|candidate| candidate.is_file()))
    else {
        return;
    };
    let temp = TestDir::new("engine-conformance-xar");
    let source = temp.path("project");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"xar engine payload\n").unwrap();
    let archive = temp.path("payload.xar");
    let create = std::process::Command::new(xar).current_dir(temp.root()).arg("-cf").arg(&archive).arg("project").output().unwrap();
    assert!(create.status.success(), "xar failed: {}", String::from_utf8_lossy(&create.stderr));

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let file_entry = listing.entries.iter().find(|entry| entry.path.ends_with("project/file.txt")).expect("XAR file should be listed");
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert!(test.tested_entries > 0);
    let mut copied = Vec::new();
    let copy = handle.copy_entry(file_entry.id, &mut copied).unwrap();
    assert_eq!(copy.written_bytes, copied.len() as u64);
    assert_eq!(copied, b"xar engine payload\n");
    let destination = temp.path("out");
    let mut options = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert!(report.written_entries > 0);
    assert_eq!(fs::read(destination.join("project/file.txt")).unwrap(), b"xar engine payload\n");
    handle.close().unwrap();
}

#[test]
fn native_lha_adapter_uses_delharc_when_lha_available() {
    let Some(lha) = std::env::var("PATH")
        .ok()
        .and_then(|path| path.split(':').map(std::path::PathBuf::from).map(|directory| directory.join("lha")).find(|candidate| candidate.is_file()))
    else {
        return;
    };
    let temp = TestDir::new("engine-conformance-lha");
    let source = temp.path("project");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"lha engine payload\n").unwrap();
    let archive = temp.path("payload.lzh");
    let create = std::process::Command::new(lha).current_dir(temp.root()).arg("a").arg(&archive).arg("project").output().unwrap();
    assert!(create.status.success(), "lha failed: {}", String::from_utf8_lossy(&create.stderr));

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let file_entry = listing.entries.iter().find(|entry| entry.path.ends_with("project/file.txt")).expect("LHA file should be listed");
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert!(test.tested_entries > 0);
    let mut copied = Vec::new();
    let copy = handle.copy_entry(file_entry.id, &mut copied).unwrap();
    assert_eq!(copy.written_bytes, copied.len() as u64);
    assert_eq!(copied, b"lha engine payload\n");
    let destination = temp.path("out");
    let mut options = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert!(report.written_entries > 0);
    assert_eq!(fs::read(destination.join("project/file.txt")).unwrap(), b"lha engine payload\n");
    handle.close().unwrap();
}

#[test]
fn native_warc_adapter_materializes_record_bodies_when_bsdtar_available() {
    let Some(bsdtar) = std::env::var("PATH")
        .ok()
        .and_then(|path| path.split(':').map(std::path::PathBuf::from).map(|directory| directory.join("bsdtar")).find(|candidate| candidate.is_file()))
    else {
        return;
    };
    let temp = TestDir::new("engine-conformance-warc");
    let source = temp.path("project");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"warc engine payload\n").unwrap();
    let archive = temp.path("payload.warc");
    let create = std::process::Command::new(bsdtar)
        .current_dir(temp.root())
        .arg("--format")
        .arg("warc")
        .arg("-cf")
        .arg(&archive)
        .arg("project/file.txt")
        .output()
        .unwrap();
    assert!(create.status.success(), "bsdtar failed: {}", String::from_utf8_lossy(&create.stderr));

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let file_entry = listing.entries.iter().find(|entry| entry.path == "project/file.txt").expect("WARC target URI should become the entry path");
    assert!(listing.entries.iter().any(|entry| entry.path.starts_with("records/")), "WARC info record should retain a stable record path");
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert_eq!(test.tested_entries, listing.entries.len() as u64);
    let mut copied = Vec::new();
    let copy = handle.copy_entry(file_entry.id, &mut copied).unwrap();
    assert_eq!(copy.written_bytes, copied.len() as u64);
    assert_eq!(copied, b"warc engine payload\n");
    let destination = temp.path("out");
    let mut options = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert_eq!(report.written_entries, listing.entries.len() as u64);
    assert_eq!(fs::read(destination.join("project/file.txt")).unwrap(), b"warc engine payload\n");
    handle.close().unwrap();
}

#[test]
fn native_mtree_adapter_lists_and_verifies_manifest_metadata_without_materializing_payloads() {
    let Some(bsdtar) = std::env::var("PATH")
        .ok()
        .and_then(|path| path.split(':').map(std::path::PathBuf::from).map(|directory| directory.join("bsdtar")).find(|candidate| candidate.is_file()))
    else {
        return;
    };
    let temp = TestDir::new("engine-conformance-mtree");
    let source = temp.path("project");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"mtree engine payload\n").unwrap();
    let archive = temp.path("payload.mtree");
    let create =
        std::process::Command::new(bsdtar).current_dir(temp.root()).arg("--format").arg("mtree").arg("-cf").arg(&archive).arg("project").output().unwrap();
    assert!(create.status.success(), "bsdtar failed: {}", String::from_utf8_lossy(&create.stderr));

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    assert!(listing.entries.iter().any(|entry| entry.path == "project/file.txt"));
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert_eq!(test.tested_entries, listing.entries.len() as u64);
    assert_eq!(test.tested_bytes, b"mtree engine payload\n".len() as u64);
    let mut options = ExtractOptions { destination: temp.path("out"), ..ExtractOptions::default() };
    let error = handle.extract(&mut options).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::UnsupportedOperation);
    handle.close().unwrap();
}

#[test]
fn native_mtree_adapter_rejects_unsupported_unset_directives_without_panicking() {
    let temp = TestDir::new("engine-conformance-mtree-unset");
    let archive = temp.path("unsupported.mtree");
    fs::write(&archive, b"/set type=file\n/unset type\n./file.txt size=1\n").unwrap();
    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let error = handle.list().unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::CorruptData);
    assert_eq!(error.disposition, zmanager_core::engine::SessionDisposition::Unusable);
}

#[test]
fn native_iso_adapter_uses_forensic_vfs_for_list_test_copy_and_extract() {
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.iso");
    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let file_entry = listing.entries.iter().find(|entry| entry.path == "README.TXT").expect("ISO fixture file should be listed");
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert_eq!(test.tested_entries, listing.entries.len() as u64);
    assert!(test.tested_bytes > 0);
    let mut copied = Vec::new();
    let copy = handle.copy_entry(file_entry.id, &mut copied).unwrap();
    assert_eq!(copy.written_bytes, copied.len() as u64);
    assert_eq!(copied, b"ZManager fixture payload\n");
    let destination = TestDir::new("engine-conformance-iso");
    let mut options = ExtractOptions { destination: destination.path("out"), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert!(report.written_entries > 0);
    assert_eq!(fs::read(destination.path("out/README.TXT")).unwrap(), b"ZManager fixture payload\n");
    handle.close().unwrap();
}

#[test]
fn native_iso_adapter_marks_corrupt_images_terminal() {
    let source = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.iso");
    let bytes = fs::read(&source).unwrap();
    let temp = TestDir::new("engine-conformance-corrupt-iso");
    let archive = temp.path("corrupt.iso");
    fs::write(&archive, &bytes[..24 * 2048]).unwrap();

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let error = handle.list().unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::CorruptData);
    assert_eq!(error.disposition, zmanager_core::engine::SessionDisposition::Unusable);
    let second = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap_err();
    assert_eq!(second.kind, zmanager_core::engine::ErrorKind::CorruptData);
}

#[test]
fn engine_creation_cancellation_does_not_commit_output() {
    let temp = TestDir::new("engine-conformance-create-cancel");
    let source = temp.path("source.txt");
    let archive = temp.path("cancelled.tar.zst");
    fs::write(&source, b"cancelled create").unwrap();
    let manifest = zmanager_core::manifest::plan_archive(&source, &zmanager_core::manifest::PlanOptions::default()).unwrap();
    let request = CreateRequest::new(manifest, &archive, CreateOptions::TarZstd(TarZstdCreateOptions::default()));
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
fn engine_rejects_unknown_input_during_open() {
    let temp = TestDir::new("engine-conformance-unknown-open");
    let path = temp.path("payload.unknown");
    fs::write(&path, b"not an archive format").unwrap();

    let error = create_default_engine().unwrap().open(ArchiveSource::Path(path), OpenOptions::default()).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::InvalidFormat);
}

#[test]
fn engine_rejects_source_changes_before_using_retained_entry_id() {
    let temp = TestDir::new("engine-conformance-source-change");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("payload.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"original").unwrap();
    zip.finish().unwrap();

    let mut handle = create_default_engine().unwrap().open(ArchiveSource::Path(zip_path.clone()), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    fs::write(&zip_path, b"replacement archive with different bytes").unwrap();

    let error = handle.copy_entry(listing.entries[0].id, &mut Vec::new()).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::SourceChanged);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Unusable);
}

#[test]
fn engine_entry_ids_are_scoped_to_the_handle_that_listed_them() {
    let temp = TestDir::new("engine-conformance-entry-id-scope");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("payload.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"payload").unwrap();
    zip.finish().unwrap();

    let engine = create_default_engine().unwrap();
    let mut first = engine.open(ArchiveSource::Path(zip_path.clone()), OpenOptions::default()).unwrap();
    let mut second = engine.open(ArchiveSource::Path(zip_path), OpenOptions::default()).unwrap();
    let first_id = first.list().unwrap().entries[0].id;
    second.list().unwrap();

    let error = second.copy_entry(first_id, &mut Vec::new()).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::InvalidFormat);
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
    static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "duplicate-registration-test-adapter",
        format: FormatId::ZIP,
        operations: &[ArchiveOperation::List],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };

    struct DuplicateFactory;

    impl ReadAdapterFactory for DuplicateFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &DESCRIPTOR
        }

        fn open(self: Arc<Self>, _archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "test factory is not opened"))
        }
    }

    struct DummyPlugin;
    impl ArchivePlugin for DummyPlugin {
        fn name(&self) -> &'static str {
            "dummy_duplicate"
        }
        fn register(&self, builder: &mut ArchiveEngineBuilder) -> Result<(), ArchiveError> {
            let factory = std::sync::Arc::new(DuplicateFactory);
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
fn engine_rejects_disjoint_factories_for_one_format() {
    static LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "disjoint-factory-test-adapter",
        format: FormatId::ZIP,
        operations: &[ArchiveOperation::List],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };
    static TEST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "disjoint-factory-test-adapter",
        format: FormatId::ZIP,
        operations: &[ArchiveOperation::Test],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };

    struct ListOnlyFactory;
    impl ReadAdapterFactory for ListOnlyFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &LIST_DESCRIPTOR
        }

        fn open(self: Arc<Self>, _archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "test factory is not opened"))
        }
    }

    struct TestOnlyFactory;
    impl ReadAdapterFactory for TestOnlyFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &TEST_DESCRIPTOR
        }

        fn open(self: Arc<Self>, _archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "test factory is not opened"))
        }
    }

    static DUPLICATE_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "duplicate-operation-test-adapter",
        format: FormatId::TAR,
        operations: &[ArchiveOperation::List, ArchiveOperation::List],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };
    struct DuplicateOperationFactory;
    impl ReadAdapterFactory for DuplicateOperationFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &DUPLICATE_DESCRIPTOR
        }

        fn open(self: Arc<Self>, _archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "test factory is not opened"))
        }
    }

    let mut builder = ArchiveEngineBuilder::new();
    builder.register_read_adapter(Arc::new(ListOnlyFactory)).unwrap();
    let error = builder.register_read_adapter(Arc::new(TestOnlyFactory)).unwrap_err();
    assert!(error.message.contains("one factory instance"));

    let mut duplicate_builder = ArchiveEngineBuilder::new();
    let error = duplicate_builder.register_read_adapter(Arc::new(DuplicateOperationFactory)).unwrap_err();
    assert!(error.message.contains("more than once"));
}

#[test]
fn engine_handles_split_zip_sidecar_detection_without_compatibility_fallback() {
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
fn engine_rejects_explicit_volume_sets_for_single_file_adapters() {
    let temp = TestDir::new("engine-conformance-source-access");
    let source = temp.path("archive.zip");
    fs::write(&source, b"not a split archive").unwrap();

    let error = create_default_engine().unwrap().open(ArchiveSource::VolumeSet(vec![source]), OpenOptions::default()).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::UnsupportedOperation);
    assert!(error.message.contains("MultiVolumeSet"));
    assert!(error.message.contains("Seekable"));
}

#[test]
fn engine_enforces_configured_source_size_limit_before_adapter_open() {
    let temp = TestDir::new("engine-conformance-source-limit");
    let archive = temp.path("archive.zip");
    fs::write(&archive, b"not a zip archive").unwrap();

    let error = create_default_engine()
        .unwrap()
        .open(ArchiveSource::Path(archive), OpenOptions { limits: OpenLimits { max_source_bytes: Some(1) }, ..Default::default() })
        .unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::ResourceLimitExceeded);
}

#[test]
fn engine_rejects_tzap_sibling_mutation_after_open() {
    let temp = TestDir::new("engine-conformance-tzap-source-integrity");
    let source = temp.path("payload.bin");
    let mut state = 0x1234_5678_9abc_def0_u64;
    let payload: Vec<u8> = (0..(3 * 1024 * 1024))
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect();
    fs::write(&source, payload).unwrap();

    let engine = create_default_engine().unwrap();
    let archive = temp.path("split.tzap");
    let report = create_engine_fixture(
        &engine,
        &source,
        &archive,
        CreateOptions::Tzap(TzapCreateOptions {
            key_source: TzapKeySource::NoPassword,
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: Some(1024 * 1024),
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: None,
        }),
    );
    assert!(report.volume_count > 1, "fixture must contain format-owned sibling volumes");

    // A split TZAP archive has numbered volume files and no base `.tzap` file.
    // Opening the requested base path must still use the same format-owned
    // volume discovery path as opening one of its physical volumes.
    let limited = engine
        .open(ArchiveSource::from_path_autodetect(&archive), OpenOptions { limits: OpenLimits { max_source_bytes: Some(1) }, ..Default::default() })
        .unwrap_err();
    assert_eq!(limited.kind, zmanager_core::engine::ErrorKind::ResourceLimitExceeded);

    let mut base_handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    assert!(!base_handle.list().unwrap().entries.is_empty());

    let first_volume = temp.path("split.vol000.tzap");
    let second_volume = temp.path("split.vol001.tzap");
    assert!(first_volume.is_file());
    assert!(second_volume.is_file());

    let logical_source = ArchiveSource::from_path_autodetect(&archive);
    let plan_fingerprint = engine.capture_source_fingerprint(&logical_source).unwrap();

    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&second_volume), OpenOptions::default()).unwrap();
    let mut mutated = fs::read(&first_volume).unwrap();
    mutated.push(0);
    fs::write(&first_volume, mutated).unwrap();
    assert_ne!(engine.capture_source_fingerprint(&logical_source).unwrap(), plan_fingerprint);

    let error = handle.list().unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::SourceChanged);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Unusable);

    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&second_volume), OpenOptions::default()).unwrap();
    fs::write(temp.path("split.vol999.tzap"), b"unexpected volume").unwrap();
    let error = handle.list().unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::SourceChanged);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Unusable);
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

#[test]
fn engine_opens_one_read_session_and_reuses_the_listing_snapshot() {
    static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "counting-read-adapter",
        format: FormatId::ZIP,
        operations: &[ArchiveOperation::List],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };

    struct CountingFactory {
        opens: Arc<std::sync::atomic::AtomicUsize>,
    }

    struct CountingSession {
        lists: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ReadAdapterFactory for CountingFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &DESCRIPTOR
        }

        fn open(self: Arc<Self>, _archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            self.opens.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(CountingSession { lists: Arc::new(std::sync::atomic::AtomicUsize::new(0)) }))
        }
    }

    impl ReadAdapterSession for CountingSession {
        fn list(&mut self) -> Result<ArchiveListing, ArchiveError> {
            self.lists.fetch_add(1, Ordering::Relaxed);
            Ok(ArchiveListing { entries: vec![EngineEntry { path: "payload.txt".to_owned(), ..EngineEntry::default() }] })
        }

        fn test(&mut self, _options: &zmanager_core::engine::TestOptions) -> Result<zmanager_core::engine::TestReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn extract<'a>(&mut self, _options: &'a mut ExtractOptions<'a>) -> Result<zmanager_core::engine::ExtractReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn selected_extract<'a>(
            &mut self,
            _entry_id: zmanager_core::engine::EntryId,
            _options: &'a mut zmanager_core::engine::SelectedExtractOptions<'a>,
        ) -> Result<zmanager_core::engine::ExtractReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn copy_to_writer(
            &mut self,
            _entry_id: zmanager_core::engine::EntryId,
            _writer: &mut dyn std::io::Write,
        ) -> Result<zmanager_core::engine::CopyReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }
    }

    let temp = TestDir::new("engine-conformance-session-reuse");
    let source = temp.path("source.zip");
    fs::write(&source, b"placeholder").unwrap();
    let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut builder = ArchiveEngineBuilder::new();
    builder.register_read_adapter(Arc::new(CountingFactory { opens: Arc::clone(&opens) })).unwrap();
    let engine = zmanager_core::engine::ArchiveEngine::new(builder.build());
    let mut handle = engine.open(ArchiveSource::Path(source), OpenOptions::default()).unwrap();

    assert_eq!(handle.list().unwrap().entries[0].path, "payload.txt");
    assert_eq!(handle.list().unwrap().entries[0].path, "payload.txt");
    assert_eq!(opens.load(Ordering::Relaxed), 1);
}

#[test]
fn engine_rejects_source_mutation_detected_after_an_operation() {
    static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "mutating-read-adapter",
        format: FormatId::ZIP,
        operations: &[ArchiveOperation::List],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };

    struct MutatingFactory;
    struct MutatingSession {
        source: PathBuf,
    }

    impl ReadAdapterSession for MutatingSession {
        fn list(&mut self) -> Result<ArchiveListing, ArchiveError> {
            fs::write(&self.source, b"replacement archive written during listing").unwrap();
            Ok(ArchiveListing { entries: vec![EngineEntry { path: "payload.txt".to_owned(), ..EngineEntry::default() }] })
        }

        fn test(&mut self, _options: &zmanager_core::engine::TestOptions) -> Result<zmanager_core::engine::TestReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn extract<'a>(&mut self, _options: &'a mut ExtractOptions<'a>) -> Result<zmanager_core::engine::ExtractReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn selected_extract<'a>(
            &mut self,
            _entry_id: zmanager_core::engine::EntryId,
            _options: &'a mut zmanager_core::engine::SelectedExtractOptions<'a>,
        ) -> Result<zmanager_core::engine::ExtractReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn copy_to_writer(
            &mut self,
            _entry_id: zmanager_core::engine::EntryId,
            _writer: &mut dyn std::io::Write,
        ) -> Result<zmanager_core::engine::CopyReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }
    }

    impl ReadAdapterFactory for MutatingFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &DESCRIPTOR
        }

        fn open(self: Arc<Self>, archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            Ok(Box::new(MutatingSession { source: archive.source.primary_path().to_path_buf() }))
        }
    }

    let temp = TestDir::new("engine-conformance-post-operation-source-change");
    let source = temp.path("source.zip");
    fs::write(&source, b"original archive bytes").unwrap();
    let mut builder = ArchiveEngineBuilder::new();
    builder.register_read_adapter(Arc::new(MutatingFactory)).unwrap();
    let engine = zmanager_core::engine::ArchiveEngine::new(builder.build());
    let mut handle = engine.open(ArchiveSource::Path(source), OpenOptions::default()).unwrap();

    let error = handle.list().unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::SourceChanged);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Unusable);
}

#[test]
fn engine_rejects_unclaimed_operations_at_the_registry_seam_after_open() {
    static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "list-only-read-adapter",
        format: FormatId::ZIP,
        operations: &[ArchiveOperation::List],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };

    struct ListOnlyFactory;
    struct ListOnlySession;

    impl ReadAdapterSession for ListOnlySession {
        fn list(&mut self) -> Result<ArchiveListing, ArchiveError> {
            Ok(ArchiveListing { entries: vec![EngineEntry { path: "payload.txt".to_owned(), ..EngineEntry::default() }] })
        }

        fn test(&mut self, _options: &zmanager_core::engine::TestOptions) -> Result<zmanager_core::engine::TestReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn extract<'a>(&mut self, _options: &'a mut ExtractOptions<'a>) -> Result<zmanager_core::engine::ExtractReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn selected_extract<'a>(
            &mut self,
            _entry_id: zmanager_core::engine::EntryId,
            _options: &'a mut zmanager_core::engine::SelectedExtractOptions<'a>,
        ) -> Result<zmanager_core::engine::ExtractReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn copy_to_writer(
            &mut self,
            _entry_id: zmanager_core::engine::EntryId,
            _writer: &mut dyn std::io::Write,
        ) -> Result<zmanager_core::engine::CopyReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }
    }

    impl ReadAdapterFactory for ListOnlyFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &DESCRIPTOR
        }

        fn open(self: Arc<Self>, _archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            Ok(Box::new(ListOnlySession))
        }
    }

    let temp = TestDir::new("engine-conformance-unclaimed-operation");
    let source = temp.path("source.zip");
    fs::write(&source, b"placeholder").unwrap();
    let mut builder = ArchiveEngineBuilder::new();
    builder.register_read_adapter(Arc::new(ListOnlyFactory)).unwrap();
    let engine = zmanager_core::engine::ArchiveEngine::new(builder.build());
    let mut handle = engine.open(ArchiveSource::Path(source), OpenOptions::default()).unwrap();

    handle.list().unwrap();
    let error = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::UnsupportedOperation);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Usable);
}
