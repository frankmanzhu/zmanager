use super::error::{ERROR_DAMAGED_ARCHIVE, ERROR_INVALID_PASSWORD, ERROR_INVALID_REQUEST, ERROR_NOT_FOUND, ERROR_PASSWORD_REQUIRED, WARNING_LAUNCH_GATED_FORMAT};
use super::ops::jobs::MobileJobRegistry;
use super::util::{classify_archive_path, password_ref, sanitize_password};
use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zmanager_core::jobs::{CancellationToken, JobEvent as CoreJobEvent, JobKind as CoreJobKind};
use zmanager_core::manifest::{PlanOptions, plan_archive, plan_archives};
use zmanager_core::sevenz_backend::{SevenZCreateOptions, create_7z_from_manifest};
use zmanager_core::zip_backend::{ZipCreateOptions, create_zip_from_manifest};

use tzap_core::format::FormatError;
use tzap_core::{MasterKey, RegularFile, RootAuthWriterConfig, WriterOptions, write_archive_with_root_auth};
use tzap_plugin_signing::x509_chain::X509RootAuthSigner;

static JOB_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn healthcheck_reports_real_core() {
    let result = healthcheck();

    assert_eq!(result.engine, "zmanager-core");
    assert!(result.ready);
    assert_eq!(result.status, "ready");
    assert!(result.summary.contains("zmanager-core"));
}

#[test]
fn classify_archive_path_supports_launch_extensions() {
    let cases = [
        ("ARCHIVE.ZIP", ArchiveFormat::Zip),
        ("archive.z01", ArchiveFormat::SplitZip),
        ("archive.part01.rar", ArchiveFormat::MultipartRar),
        ("archive.r02", ArchiveFormat::MultipartRar),
        ("archive.7z", ArchiveFormat::SevenZ),
        ("archive.tar", ArchiveFormat::Tar),
        ("archive.tar.gz", ArchiveFormat::TarGz),
        ("archive.tbz2", ArchiveFormat::TarBz2),
        ("archive.txz", ArchiveFormat::TarXz),
        ("archive.tar.zst", ArchiveFormat::TarZst),
        ("archive.gz", ArchiveFormat::Gzip),
        ("archive.bz2", ArchiveFormat::Bzip2),
        ("archive.xz", ArchiveFormat::Xz),
        ("archive.zst", ArchiveFormat::Zstd),
        ("archive.tzap", ArchiveFormat::Tzap),
        ("archive.aar", ArchiveFormat::AppleArchive),
        ("archive.xip", ArchiveFormat::Xip),
    ];

    for (path, expected) in cases {
        assert_eq!(classify_archive_path(Path::new(path)).0, expected, "{path}");
    }
}

#[test]
fn classify_archive_path_identifies_the_final_volume_of_a_split_zip() {
    let temp = TestDir::new("classify-split-zip");
    temp.write_file("archive.z01", b"first volume");
    temp.write_file("archive.zip", b"final volume");

    assert_eq!(classify_archive_path(&temp.path("archive.zip")).0, ArchiveFormat::SplitZip);
}

#[test]
fn classify_archive_path_identifies_the_first_volume_of_a_split_7z() {
    assert_eq!(classify_archive_path(Path::new("archive.7z.001")).0, ArchiveFormat::SevenZ);
}

#[test]
fn detect_archive_rejects_platform_uri_objects() {
    let error = detectArchive(DetectArchiveRequest { archive_path: "content://downloads/archive.zip".to_string() }).unwrap_err();

    assert_bridge_error_code(error, ERROR_INVALID_REQUEST);
}

#[test]
fn detect_archive_classifies_existing_app_controlled_file() {
    let temp = TestDir::new("detect-existing-file");
    temp.write_file("ARCHIVE.ZIP", b"not parsed during detection");

    let result = detectArchive(DetectArchiveRequest { archive_path: temp.path("ARCHIVE.ZIP").to_string_lossy().to_string() }).expect("detection should classify an existing app-controlled path");

    assert_eq!(result.format, ArchiveFormat::Zip);
    assert_eq!(result.format_label, "ZIP");
    assert!(result.exists);
    assert!(result.is_file);
    assert!(result.can_list);
    assert!(result.can_extract);
    assert!(result.can_create);
}

#[test]
fn detect_archive_returns_normalized_launch_gated_warning() {
    let temp = TestDir::new("detect-launch-gated-warning");
    temp.write_file("archive.xip", b"not parsed during detection");

    let result = detectArchive(DetectArchiveRequest { archive_path: temp.path("archive.xip").to_string_lossy().to_string() }).expect("detection should classify launch-gated app-controlled path");

    assert_eq!(result.format, ArchiveFormat::Xip);
    assert!(!result.can_list);
    assert!(!result.can_extract);
    assert!(!result.can_create);
    assert_eq!(result.warnings.len(), 1);
    let warning = &result.warnings[0];
    assert_eq!(warning.code, WARNING_LAUNCH_GATED_FORMAT);
    assert!(matches!(warning.severity, BridgeSeverity::Warning));
    assert!(!warning.retryable);
}

#[test]
fn list_archive_rejects_missing_path() {
    let error = listArchive(ListArchiveRequest { archive_path: "/definitely/missing/archive.zip".to_string(), password: None }).unwrap_err();

    assert_bridge_error_code(error, ERROR_NOT_FOUND);
}

#[test]
fn list_archive_reads_real_zip_through_core() {
    let temp = TestDir::new("list-archive-real-zip");
    temp.create_dir("project");
    temp.write_file("project/readme.txt", b"hello mobile bridge\n");
    let archive = temp.path("archive.zip");
    let manifest = plan_archive(temp.path("project"), &PlanOptions::default()).expect("fixture manifest should be planned");
    create_zip_from_manifest(&manifest, &archive, &ZipCreateOptions::default()).expect("fixture zip should be created through zmanager-core");

    let result = listArchive(ListArchiveRequest { archive_path: archive.to_string_lossy().to_string(), password: None }).expect("core-backed listing should succeed");

    assert_eq!(result.format, ArchiveFormat::Zip);
    assert!(result.entry_count >= 1);
    assert!(result.entries.iter().any(|entry| entry.path.ends_with("readme.txt")));
    assert!(result.total_size.is_some());
}

#[test]
fn plan_extract_starts_for_a_real_7z_archive() {
    let temp = TestDir::new("plan-extract-real-7z");
    temp.write_file("readme.txt", b"hello mobile bridge\n");
    temp.write_file("manifest.json", b"{}\n");
    let archive = temp.path("archive.7z");
    let destination = temp.path("staging");
    let manifest = plan_archives([temp.path("readme.txt"), temp.path("manifest.json")], &PlanOptions::default()).expect("fixture manifest should be planned");
    create_7z_from_manifest(&manifest, &archive, &SevenZCreateOptions::default()).expect("fixture archive should be created through zmanager-core");

    let plan = planExtract(PlanExtractRequest {
        archive_path: archive.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: None,
        selected_paths: Vec::new(),
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Replace,
    })
    .expect("7z plan should be created");

    assert!(plan.can_start, "7z plan should be startable: {plan:?}");
    assert_eq!(plan.blocked_entries, 0);
    assert!(!plan.plan_token.is_empty());
    assert!(plan.entries.iter().all(|entry| entry.replace_existing), "replace staging plans must use rename-based commits even for new files: {plan:?}");
}

#[test]
fn bridge_lists_tests_plans_and_extracts_passworded_split_7z() {
    let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
    let temp = TestDir::new("bridge-passworded-split-7z");
    let password = " split 7z password ";
    let payload = deterministic_bytes(2_300_000);
    temp.write_file("project/blob.bin", &payload);
    temp.write_file("project/notes/readme.txt", b"bridge coverage\n");
    temp.create_dir("project/empty");
    let archive = temp.path("project.7z");
    let destination = temp.path("out");
    let manifest = plan_archive(temp.path("project"), &PlanOptions::default()).expect("fixture manifest should be planned");

    let created = create_7z_from_manifest(
        &manifest,
        &archive,
        &SevenZCreateOptions { password: Some(password.into()), encrypt_file_names: true, volume_size: Some(1_048_576), ..SevenZCreateOptions::default() },
    )
    .expect("passworded split 7z fixture should be created");
    assert!(created.encrypted);
    assert!(created.volume_count >= 2);
    let first_volume = temp.path("project.7z.001");

    let missing_password = listArchive(ListArchiveRequest { archive_path: first_volume.to_string_lossy().to_string(), password: None }).expect_err("encrypted header listing must require a password");
    assert_bridge_error_code(missing_password, ERROR_PASSWORD_REQUIRED);

    let wrong_password = listArchive(ListArchiveRequest { archive_path: first_volume.to_string_lossy().to_string(), password: Some("wrong password".to_string()) })
        .expect_err("an incorrect password must not list the archive");
    assert_bridge_error_code(wrong_password, ERROR_INVALID_PASSWORD);

    let listing = listArchive(ListArchiveRequest { archive_path: first_volume.to_string_lossy().to_string(), password: Some(password.to_string()) })
        .expect("the exact password should list every split 7z entry");
    assert_eq!(listing.format, ArchiveFormat::SevenZ);
    assert_eq!(listing.entries.iter().filter(|entry| entry.path == "project/blob.bin").count(), 1);
    assert!(listing.entries.iter().any(|entry| entry.path == "project/empty"));

    let verified = testArchive(TestArchiveRequest { archive_path: first_volume.to_string_lossy().to_string(), password: Some(password.to_string()), selected_paths: Vec::new() })
        .expect("the split archive should verify through the mobile bridge");
    assert!(verified.verified);
    assert!(verified.tested_entries >= 2);

    let plan = planExtract(PlanExtractRequest {
        archive_path: first_volume.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: Some(password.to_string()),
        selected_paths: Vec::new(),
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Replace,
    })
    .expect("the split archive should produce an approved replacement plan");
    assert!(plan.can_start, "split 7z plan should be startable: {plan:?}");
    assert_eq!(plan.blocked_entries, 0);

    let started = startExtract(StartExtractRequest {
        archive_path: first_volume.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: Some(password.to_string()),
        selected_paths: Vec::new(),
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Replace,
        plan_token: plan.plan_token,
    })
    .expect("the approved split 7z plan should start");
    assert_eq!(started.kind, MobileJobKind::SevenZExtract);

    let terminal = wait_for_terminal_job(&started.job_id);
    assert_eq!(terminal.status, MobileJobStatus::Completed);
    assert!(terminal.terminal_summary.as_ref().is_some_and(|summary| summary.written_bytes == (payload.len() + b"bridge coverage\n".len()) as u64));
    assert!(!format!("{terminal:?}").contains(password), "bridge diagnostics must not retain archive passwords");
    assert_eq!(fs::read(destination.join("project/blob.bin")).unwrap(), payload);
    assert_eq!(fs::read_to_string(destination.join("project/notes/readme.txt")).unwrap(), "bridge coverage\n");
    assert!(destination.join("project/empty").is_dir());
}

#[test]
fn bridge_lists_plans_and_extracts_passworded_multipart_rar() {
    let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
    let password = "zmanager-rar-fixture-password";
    let archive = checked_in_rar_fixture("rar5-passworded-multipart.part1.rar");
    let temp = TestDir::new("bridge-passworded-multipart-rar");
    let destination = temp.path("out");

    let missing_password =
        listArchive(ListArchiveRequest { archive_path: archive.to_string_lossy().to_string(), password: None }).expect_err("passworded multipart RAR must not list without a password");
    assert_bridge_error_code(missing_password, ERROR_INVALID_PASSWORD);

    let wrong_password = listArchive(ListArchiveRequest { archive_path: archive.to_string_lossy().to_string(), password: Some("wrong password".to_string()) })
        .expect_err("passworded multipart RAR must reject a wrong password");
    assert_bridge_error_code(wrong_password, ERROR_INVALID_PASSWORD);

    let listing =
        listArchive(ListArchiveRequest { archive_path: archive.to_string_lossy().to_string(), password: Some(password.to_string()) }).expect("the exact password should list the multipart RAR");
    assert_eq!(listing.format, ArchiveFormat::MultipartRar);
    assert_eq!(listing.entries.iter().filter(|entry| entry.path == "rar-fixture/data/stream.bin").count(), 1);
    assert!(listing.entries.iter().any(|entry| entry.path == "rar-fixture/docs/readme.txt"));

    let plan = planExtract(PlanExtractRequest {
        archive_path: archive.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: Some(password.to_string()),
        selected_paths: Vec::new(),
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Replace,
    })
    .expect("the multipart RAR should produce an approved extraction plan");
    assert!(plan.can_start, "multipart RAR plan should be startable: {plan:?}");
    assert_eq!(plan.blocked_entries, 0);

    let started = startExtract(StartExtractRequest {
        archive_path: archive.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: Some(password.to_string()),
        selected_paths: Vec::new(),
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Replace,
        plan_token: plan.plan_token,
    })
    .expect("the approved multipart RAR plan should start");
    assert_eq!(started.kind, MobileJobKind::RarExtract);

    let terminal = wait_for_terminal_job(&started.job_id);
    assert_eq!(terminal.status, MobileJobStatus::Completed);
    assert_eq!(terminal.terminal_summary.as_ref().map(|summary| summary.written_bytes), Some(196_608 + 22 + 23));
    assert!(!format!("{terminal:?}").contains(password), "bridge diagnostics must not retain archive passwords");
    assert_eq!(fs::read(destination.join("rar-fixture/data/stream.bin")).unwrap(), vec![0; 196_608]);
    assert_eq!(fs::read_to_string(destination.join("rar-fixture/docs/readme.txt")).unwrap(), "RAR multipart fixture\n");
}

#[test]
fn test_archive_reads_real_zip_through_core() {
    let fixture = create_test_zip("test-archive-real-zip");

    let result =
        testArchive(TestArchiveRequest { archive_path: fixture.archive.to_string_lossy().to_string(), password: None, selected_paths: Vec::new() }).expect("core-backed archive test should succeed");

    assert_eq!(result.format, ArchiveFormat::Zip);
    assert!(result.verified);
    assert!(result.tested_entries >= 1);
    assert_eq!(result.total_entries, result.tested_entries + result.skipped_entries);
    assert!(result.tested_bytes > 0);
}

#[test]
fn test_archive_honors_selected_entry_filter() {
    let fixture = create_test_zip("test-archive-selected-filter");

    let result = testArchive(TestArchiveRequest { archive_path: fixture.archive.to_string_lossy().to_string(), password: None, selected_paths: vec!["missing.txt".to_string()] })
        .expect("skipping all entries is still a successful filtered test");

    assert_eq!(result.tested_entries, 0);
    assert!(result.skipped_entries >= 1);
    assert_eq!(result.total_entries, result.skipped_entries);
    assert_eq!(result.tested_bytes, 0);
}

#[test]
fn test_archive_reports_corrupt_zip_as_damaged_archive() {
    let temp = TestDir::new("test-archive-corrupt-zip");
    temp.write_file("broken.zip", b"this is not a zip archive");

    let error = testArchive(TestArchiveRequest { archive_path: temp.path("broken.zip").to_string_lossy().to_string(), password: None, selected_paths: Vec::new() }).unwrap_err();

    assert_bridge_error_code(error, ERROR_DAMAGED_ARCHIVE);
}

#[test]
fn password_helpers_preserve_boundary_whitespace() {
    let password = Some(" secret ".to_string());

    assert_eq!(password_ref(&password), Some(" secret "));
    assert_eq!(sanitize_password(password), Some(" secret ".to_string()));
}

#[test]
fn materialize_preview_extracts_one_entry_to_cleanup_root() {
    let fixture = create_test_zip("materialize-preview-real-zip");
    let entry_path = readme_entry_path(&fixture.archive);

    let result = materializePreview(MaterializePreviewRequest { archive_path: fixture.archive.to_string_lossy().to_string(), entry_path: entry_path.clone(), password: None, strip_components: 0 })
        .expect("preview should materialize through zmanager-core");

    let cleanup_root = PathBuf::from(&result.cleanup_root);
    let preview_path = PathBuf::from(&result.preview_path);
    let canonical_cleanup_root = fs::canonicalize(&cleanup_root).expect("cleanup root should exist");
    let canonical_preview_path = fs::canonicalize(&preview_path).expect("preview path should exist");
    assert_eq!(result.entry_path, entry_path);
    assert!(canonical_preview_path.starts_with(&canonical_cleanup_root));
    assert_eq!(fs::read_to_string(&preview_path).expect("preview file should be readable"), "hello mobile bridge\n");
    assert!(result.written_bytes > 0);

    fs::remove_dir_all(cleanup_root).expect("preview cleanup root should be removable");
}

#[test]
fn materialize_preview_rejects_empty_entry_path() {
    let fixture = create_test_zip("materialize-preview-empty-entry");

    let error =
        materializePreview(MaterializePreviewRequest { archive_path: fixture.archive.to_string_lossy().to_string(), entry_path: String::new(), password: None, strip_components: 0 }).unwrap_err();

    assert_bridge_error_code(error, ERROR_INVALID_REQUEST);
}

#[test]
fn plan_extract_returns_write_plan_without_creating_destination() {
    let fixture = create_test_zip("plan-extract-real-zip");
    let destination = fixture.temp.path("out");

    let result = planExtract(PlanExtractRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: None,
        selected_paths: Vec::new(),
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Refuse,
    })
    .expect("planning should succeed without extracting");

    assert!(!destination.exists());
    assert!(result.can_start);
    assert!(result.writable_entries >= 1);
    assert_eq!(result.blocked_entries, 0);
    assert!(result.estimated_bytes.is_some());
    assert!(
        result
            .entries
            .iter()
            .any(|entry| { matches!(entry.status, ExtractionPlanEntryStatus::Write) && entry.destination_path.as_deref().is_some_and(|path| Path::new(path).starts_with(&destination)) })
    );
}

#[test]
fn plan_extract_surfaces_destination_collision_as_blocked_entry() {
    let fixture = create_test_zip("plan-extract-collision");
    let entry_path = readme_entry_path(&fixture.archive);
    let destination = fixture.temp.path("out");
    let colliding_path = destination.join(&entry_path);
    fs::create_dir_all(colliding_path.parent().expect("colliding path should have a parent")).expect("collision parent should be created");
    fs::write(&colliding_path, b"existing").expect("collision file should be written");

    let result = planExtract(PlanExtractRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: None,
        selected_paths: vec![entry_path.clone()],
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Refuse,
    })
    .expect("planning should return a blocked collision row");

    assert_eq!(result.total_entries, 1);
    assert_eq!(result.writable_entries, 0);
    assert_eq!(result.blocked_entries, 1);
    assert!(!result.can_start);
    let blocked = result.entries.first().expect("blocked entry should exist");
    assert_eq!(blocked.archive_path, entry_path);
    assert!(matches!(blocked.status, ExtractionPlanEntryStatus::Block));
    assert!(blocked.reason.as_deref().is_some_and(|reason| reason.contains("would overwrite")));
}

#[test]
fn plan_create_returns_manifest_without_writing_archive() {
    let temp = TestDir::new("plan-create-zip");
    temp.create_dir("project");
    temp.write_file("project/readme.txt", b"hello mobile bridge\n");
    let destination = temp.path("archive.zip");

    let result = planCreate(PlanCreateRequest {
        source_paths: vec![temp.path("project").to_string_lossy().to_string()],
        destination_archive_path: destination.to_string_lossy().to_string(),
        format: CreateArchiveFormat::Zip,
        password: None,
        preserve_metadata: true,
        replace_existing: false,
        clean_source: false,
        verify_after_create: false,
    })
    .expect("create planning should succeed");

    assert!(!destination.exists());
    assert_eq!(result.format, CreateArchiveFormat::Zip);
    assert_eq!(result.format_label, "ZIP");
    assert!(result.can_start);
    assert!(!result.encrypted);
    assert!(result.verify_supported);
    assert!(result.total_entries >= 1);
    assert!(result.total_bytes > 0);
    assert!(result.entries.iter().any(|entry| { entry.archive_path.ends_with("readme.txt") && matches!(entry.kind, ArchiveEntryKind::File) }));
}

#[test]
fn plan_create_blocks_existing_output_without_replace() {
    let temp = TestDir::new("plan-create-collision");
    temp.create_dir("project");
    temp.write_file("project/readme.txt", b"hello mobile bridge\n");
    let destination = temp.path("archive.zip");
    fs::write(&destination, b"existing").expect("existing destination should be written");

    let result = planCreate(PlanCreateRequest {
        source_paths: vec![temp.path("project").to_string_lossy().to_string()],
        destination_archive_path: destination.to_string_lossy().to_string(),
        format: CreateArchiveFormat::Zip,
        password: None,
        preserve_metadata: true,
        replace_existing: false,
        clean_source: false,
        verify_after_create: false,
    })
    .expect("create planning should surface output collision");

    assert!(result.output_exists);
    assert!(!result.can_start);
    assert!(result.warnings.iter().any(|warning| warning.message.contains("already exists")));
}

#[test]
fn start_extract_job_extracts_zip_and_reports_terminal_summary() {
    let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
    let fixture = create_test_zip("start-extract-real-zip");
    let entry_path = readme_entry_path(&fixture.archive);
    let destination = fixture.temp.path("out");

    let started = startExtract(StartExtractRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: None,
        selected_paths: Vec::new(),
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Refuse,
        plan_token: approved_refuse_plan_token(&fixture.archive, &destination, None, Vec::new()),
    })
    .expect("extract job should start");

    assert_eq!(started.kind, MobileJobKind::ZipExtract);
    assert_eq!(started.status, MobileJobStatus::Queued);

    let terminal = wait_for_terminal_job(&started.job_id);
    assert_eq!(terminal.status, MobileJobStatus::Completed);
    assert!(terminal.is_terminal);
    assert!(terminal.events.iter().any(|event| { matches!(event.event_type, MobileJobEventKind::Started) && event.job_kind == Some(MobileJobKind::ZipExtract) }));
    assert!(terminal.events.iter().any(|event| matches!(event.event_type, MobileJobEventKind::Completed)));
    let summary = terminal.terminal_summary.expect("completed job should include a terminal summary");
    assert!(summary.written_entries >= 1);
    assert!(summary.written_bytes > 0);
    assert_eq!(fs::read_to_string(destination.join(entry_path)).expect("extracted file should be readable"), "hello mobile bridge\n");
}

#[test]
fn start_extract_rejects_a_plan_token_when_the_reviewed_request_changed() {
    let fixture = create_test_zip("start-extract-plan-token");
    let destination = fixture.temp.path("out");
    let plan_token = approved_refuse_plan_token(&fixture.archive, &destination, None, Vec::new());

    let error = startExtract(StartExtractRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: None,
        selected_paths: vec![readme_entry_path(&fixture.archive)],
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Refuse,
        plan_token,
    })
    .expect_err("a changed selection must require a new extraction plan");

    assert_bridge_error_code(error, ERROR_INVALID_REQUEST);
    assert!(!destination.exists(), "rejected plan tokens must not write output");
}

#[test]
fn start_create_job_creates_zip_and_reports_terminal_summary() {
    let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
    let temp = TestDir::new("start-create-zip");
    temp.create_dir("project");
    temp.write_file("project/readme.txt", b"hello mobile bridge\n");
    let destination = temp.path("archive.zip");

    let started = startCreate(StartCreateRequest {
        source_paths: vec![temp.path("project").to_string_lossy().to_string()],
        destination_archive_path: destination.to_string_lossy().to_string(),
        format: CreateArchiveFormat::Zip,
        password: None,
        preserve_metadata: true,
        replace_existing: false,
        clean_source: false,
        verify_after_create: false,
        excluded_paths: vec![],
        level: 0,
        encrypt_file_names: false,
        volume_size: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        tzap_signing_certificate: None,
        tzap_signing_private_key: None,
        tzap_signing_chain: vec![],
        tzap_identity: None,
        tzap_identity_password: None,
    })
    .expect("create job should start");

    assert_eq!(started.kind, MobileJobKind::ZipCreate);
    let terminal = wait_for_terminal_summary(&started.job_id, |summary| summary.encrypted == Some(false));
    assert_eq!(terminal.status, MobileJobStatus::Completed);
    assert!(destination.exists());
    let summary = terminal.terminal_summary.expect("create job should include a terminal summary");
    assert!(summary.written_entries >= 1);
    assert!(summary.written_bytes > 0);
    assert_eq!(summary.encrypted, Some(false));
    assert_eq!(summary.verified, None);
    assert_eq!(summary.output_paths, vec![destination.to_string_lossy().to_string()]);

    let listing = listArchive(ListArchiveRequest { archive_path: destination.to_string_lossy().to_string(), password: None }).expect("created zip should list through the bridge");
    assert!(listing.entries.iter().any(|entry| entry.path.ends_with("readme.txt")));
}

#[test]
fn start_create_job_honors_clean_source_for_zip() {
    let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
    let temp = TestDir::new("start-create-clean-source-zip");
    temp.create_dir("project/src");
    temp.create_dir("project/target");
    temp.write_file("project/src/main.txt", b"keep me\n");
    temp.write_file("project/target/build.bin", b"exclude me\n");
    let destination = temp.path("archive.zip");

    let started = startCreate(StartCreateRequest {
        source_paths: vec![temp.path("project").to_string_lossy().to_string()],
        destination_archive_path: destination.to_string_lossy().to_string(),
        format: CreateArchiveFormat::Zip,
        password: None,
        preserve_metadata: true,
        replace_existing: false,
        clean_source: true,
        verify_after_create: false,
        excluded_paths: vec![],
        level: 0,
        encrypt_file_names: false,
        volume_size: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        tzap_signing_certificate: None,
        tzap_signing_private_key: None,
        tzap_signing_chain: vec![],
        tzap_identity: None,
        tzap_identity_password: None,
    })
    .expect("clean source create job should start");

    let terminal = wait_for_terminal_job(&started.job_id);
    assert_eq!(terminal.status, MobileJobStatus::Completed);

    let listing = listArchive(ListArchiveRequest { archive_path: destination.to_string_lossy().to_string(), password: None }).expect("created clean-source zip should list");
    assert!(listing.entries.iter().any(|entry| entry.path.ends_with("src/main.txt")));
    assert!(!listing.entries.iter().any(|entry| entry.path.contains("/target/")));
}

#[test]
fn start_create_job_preserves_encrypted_zip_password_whitespace() {
    let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
    let temp = TestDir::new("start-create-encrypted-zip");
    temp.create_dir("project");
    temp.write_file("project/readme.txt", b"hello mobile bridge\n");
    let destination = temp.path("archive.zip");
    let password = " secret ";

    let started = startCreate(StartCreateRequest {
        source_paths: vec![temp.path("project").to_string_lossy().to_string()],
        destination_archive_path: destination.to_string_lossy().to_string(),
        format: CreateArchiveFormat::Zip,
        password: Some(password.to_string()),
        preserve_metadata: true,
        replace_existing: false,
        clean_source: false,
        verify_after_create: true,
        excluded_paths: vec![],
        level: 0,
        encrypt_file_names: false,
        volume_size: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        tzap_signing_certificate: None,
        tzap_signing_private_key: None,
        tzap_signing_chain: vec![],
        tzap_identity: None,
        tzap_identity_password: None,
    })
    .expect("encrypted create job should start");

    let terminal = wait_for_terminal_summary(&started.job_id, |summary| summary.verified == Some(true));
    assert_eq!(terminal.status, MobileJobStatus::Completed);
    assert!(!format!("{terminal:?}").contains(password), "job events and summaries must not expose passwords");
    assert_eq!(terminal.terminal_summary.as_ref().and_then(|summary| summary.encrypted), Some(true));
    assert_eq!(terminal.terminal_summary.as_ref().and_then(|summary| summary.verified), Some(true));

    let verified = testArchive(TestArchiveRequest { archive_path: destination.to_string_lossy().to_string(), password: Some(password.to_string()), selected_paths: Vec::new() })
        .expect("created encrypted zip should verify with the exact password");
    assert!(verified.verified);
    assert!(verified.tested_entries >= 1);
}

#[test]
fn start_extract_job_honors_selected_paths() {
    let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
    let fixture = create_test_zip("start-extract-selected-zip");
    let entry_path = readme_entry_path(&fixture.archive);
    let destination = fixture.temp.path("out");

    let started = startExtract(StartExtractRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: None,
        selected_paths: vec![entry_path.clone()],
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Refuse,
        plan_token: approved_refuse_plan_token(&fixture.archive, &destination, None, vec![entry_path.clone()]),
    })
    .expect("selected extract job should start");

    let terminal = wait_for_terminal_job(&started.job_id);
    assert_eq!(terminal.status, MobileJobStatus::Completed);
    assert!(terminal.events.iter().any(|event| { matches!(event.event_type, MobileJobEventKind::EntryStarted) && event.path.as_deref() == Some(entry_path.as_str()) }));
    assert_eq!(fs::read_to_string(destination.join(entry_path)).expect("selected file should be extracted"), "hello mobile bridge\n");
}

#[test]
fn clear_sensitive_state_removes_retained_terminal_jobs() {
    let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
    let fixture = create_test_zip("clear-sensitive-terminal-job");
    let destination = fixture.temp.path("out");

    let started = startExtract(StartExtractRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: Some(" secret ".to_string()),
        selected_paths: Vec::new(),
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Refuse,
        plan_token: approved_refuse_plan_token(&fixture.archive, &destination, Some(" secret "), Vec::new()),
    })
    .expect("sensitive extract job should start");
    let terminal = wait_for_terminal_job(&started.job_id);
    assert!(terminal.is_terminal);

    let result = clearSensitiveState();
    assert!(result.cleared_terminal_jobs >= 1);
    assert_eq!(result.cancel_requested_jobs, 0);

    let error = pollJobEvents(PollJobEventsRequest { job_id: started.job_id, cursor: 0 }).unwrap_err();
    assert_bridge_error_code(error, ERROR_NOT_FOUND);
}

#[test]
fn clear_sensitive_state_cancels_and_removes_active_sensitive_jobs() {
    let registry = MobileJobRegistry::default();
    let sensitive_token = CancellationToken::new();
    let regular_token = CancellationToken::new();
    let sensitive_job = registry.create_job(MobileJobKind::ZipExtract, sensitive_token.clone(), true);
    let regular_job = registry.create_job(MobileJobKind::ZipCreate, regular_token.clone(), false);

    let result = registry.clear_sensitive_state();

    assert_eq!(result.cleared_terminal_jobs, 0);
    assert_eq!(result.cancel_requested_jobs, 1);
    assert_eq!(result.retained_active_jobs, 1);
    assert!(sensitive_token.is_cancelled());
    assert!(!regular_token.is_cancelled());

    let sensitive_error = registry.poll_events(PollJobEventsRequest { job_id: sensitive_job.job_id, cursor: 0 }).unwrap_err();
    assert_bridge_error_code(sensitive_error, ERROR_NOT_FOUND);

    let regular_result = registry.poll_events(PollJobEventsRequest { job_id: regular_job.job_id, cursor: 0 }).expect("non-sensitive active job should stay pollable");
    assert_eq!(regular_result.status, MobileJobStatus::Queued);
}

#[test]
fn poll_job_events_uses_sequence_cursor() {
    let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
    let fixture = create_test_zip("poll-job-cursor");
    let destination = fixture.temp.path("out");

    let started = startExtract(StartExtractRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: None,
        selected_paths: Vec::new(),
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Refuse,
        plan_token: approved_refuse_plan_token(&fixture.archive, &destination, None, Vec::new()),
    })
    .expect("extract job should start");

    let terminal = wait_for_terminal_job(&started.job_id);
    assert!(!terminal.events.is_empty());
    let repeated = pollJobEvents(PollJobEventsRequest { job_id: started.job_id, cursor: terminal.next_cursor }).expect("polling from the latest cursor should succeed");

    assert!(repeated.events.is_empty());
    assert_eq!(repeated.next_cursor, terminal.next_cursor);
    assert!(repeated.is_terminal);
}

#[test]
fn cancel_job_rejects_unknown_job_id() {
    let error = cancelJob(CancelJobRequest { job_id: "missing-job".to_string() }).unwrap_err();

    assert_bridge_error_code(error, ERROR_NOT_FOUND);
}

#[test]
fn tzap_service_endpoints_return_validation_error_instead_of_continuing() {
    let temp = TestDir::new("tzap-service-validation");

    // Regression: the validation failure used to be passed to the core
    // service as the archive path, which then reported its own secondary
    // error. The caller must see the validation message instead.
    let result = tzapPublicMetadataSummary(temp.path("missing.tzap").to_string_lossy().to_string());
    assert!(result.contains("archivePath does not exist"), "expected the validation error envelope, got: {result}");
    assert!(result.starts_with("{\"ok\":false"));

    let display = tzapPublicMetadataDisplaySummary(temp.path("missing.tzap").to_string_lossy().to_string());
    assert!(display.contains("archivePath does not exist"), "expected the validation error envelope, got: {display}");
    assert!(display.starts_with("{\"ok\":false"));
}

#[test]
fn tzap_public_metadata_display_summary_reports_unsigned_archive() {
    use zmanager_core::jobs::JobContext;
    use zmanager_core::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PermissionSnapshot};
    use zmanager_core::tzap_backend::{TzapCreateOptions, TzapKeySource, create_tzap_from_manifest_with_context};

    let temp = TestDir::new("tzap-display-summary");
    let source = temp.path("payload.txt");
    let archive = temp.path("unsigned.tzap");
    fs::write(&source, b"display payload").unwrap();

    let manifest = ArchiveManifest {
        root: temp.path("."),
        entries: vec![ManifestEntry {
            archive_path: "payload.txt".to_owned(),
            source_path: source,
            file_type: ManifestFileType::File,
            size: b"display payload".len() as u64,
            modified: None,
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
            symlink_target: None,
        }],
        total_bytes: b"display payload".len() as u64,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    };
    let options = TzapCreateOptions {
        key_source: TzapKeySource::NoPassword,
        level: 1,
        preserve_metadata: true,
        replace_existing: false,
        volume_size: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: None,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let result = tzapPublicMetadataDisplaySummary(archive.to_string_lossy().to_string());
    assert!(result.contains("\"ok\":true"), "got: {result}");
    assert!(result.contains("\"status\":\"unsigned\""), "got: {result}");
    assert!(result.contains("\"key_derivation\":\"none\""), "got: {result}");
}

// X.509 fixtures for the signed display-summary tests: a self-signed RSA-2048
// leaf with the `digitalSignature` key usage and a 100-year validity, so the
// fixtures stay usable without regeneration. To regenerate:
//
//   openssl req -x509 -newkey rsa:2048 -keyout ffi_signer.key -out ffi_signer.pem \
//     -days 36500 -nodes -subj "/CN=ZManager FFI Test Signer" \
//     -addext "keyUsage=critical,digitalSignature"
const TEST_LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDOTCCAiGgAwIBAgIUKpN56sqVOMaPXsi55AM0RNv2od8wDQYJKoZIhvcNAQEL
BQAwIzEhMB8GA1UEAwwYWk1hbmFnZXIgRkZJIFRlc3QgU2lnbmVyMCAXDTI2MDgw
ODEyNTMzNloYDzIxMjYwNzE1MTI1MzM2WjAjMSEwHwYDVQQDDBhaTWFuYWdlciBG
RkkgVGVzdCBTaWduZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
Dlev5I2sPsnEIx5QlgRH/F6UnLSPTqMxvNZUz9r95DiHB5K3Rec/vWDgR7OuZ3Kn
oeoYBpKWI9aSiMJKtSndFPfBPr8LOCkfcXW5oYp+Ru5VGOsHrDGzphM7Gp80PRGs
qYPLiH4Vdr9jT6NTqLQu+RmhmB/odV23SUhhYfsMpbqAxOr6H+pTr0BImbtaUmZN
2nwLsdU0vn63KifJXyZ3cnLVZ+H/Mc/gPo0icET1pRRMzYE2jTFMvEEjTWfS/rkb
vudLqMJMi0ouRSo6yvfw7jRpGTmrO+K8TLxX1duzpbFBkDgsO+ZOwwpQhlnbX5Eq
mLdS3oa29tAbKkB3iTpBAgMBAAGjYzBhMB0GA1UdDgQWBBRCSGa9lfCggdmisR/N
REo9GuZnDjAfBgNVHSMEGDAWgBRCSGa9lfCggdmisR/NREo9GuZnDjAPBgNVHRMB
Af8EBTADAQH/MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAdYKi
/AMDB1opwH7MoaFVPAgs32Q3fddYX9qVq91orG61EuXk1bdl+ByGKT0A07I1YsfF
yS1IWF/IMcvCy9/vOlOWEfN95szohp1qS3+wZEu6+rmjTBIys7ExzSMx1iZknuoy
3X+eRiY66pNtRWod0ffm86SW3O+UGoDHsffJwtRQs5swnFGKVeaP70BOgsu4riG3
5VzgF/6RF7Qv29U27W36u0NNCoe4nRahWZhGI6iE+ZtJA0U9FhYr8Mdr17iN1lUO
M1+kurEbOjjg6QKMUdlrlhj8k4FM5uHoHRpnS2Qlwx89VntwsWkjQq33OwJ9LJ9G
ZZxolvHTPjCTdshjwQ==
-----END CERTIFICATE-----";
const TEST_LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7Dlev5I2sPsnE
Ix5QlgRH/F6UnLSPTqMxvNZUz9r95DiHB5K3Rec/vWDgR7OuZ3KnoeoYBpKWI9aS
iMJKtSndFPfBPr8LOCkfcXW5oYp+Ru5VGOsHrDGzphM7Gp80PRGsqYPLiH4Vdr9j
T6NTqLQu+RmhmB/odV23SUhhYfsMpbqAxOr6H+pTr0BImbtaUmZN2nwLsdU0vn63
KifJXyZ3cnLVZ+H/Mc/gPo0icET1pRRMzYE2jTFMvEEjTWfS/rkbvudLqMJMi0ou
RSo6yvfw7jRpGTmrO+K8TLxX1duzpbFBkDgsO+ZOwwpQhlnbX5EqmLdS3oa29tAb
KkB3iTpBAgMBAAECggEAF6DnrbXSuZPS295NyYMxtkAoWGB1JHccAT/n2R3KfXDT
PSdVPqZrYC9Vae9UwK6bmpZG4lMOOD39sFPrKxG4YI9x/mylKE8nTqv/4XuI6Yuf
NounwLfdLWLIohoqSyh9r5BYMCElQCPYaDyalopEfHyF4tY7DZupw2nT5U1Br6aW
N7K1Idef3KlolvGx7GJ0LVHzx1rVcm6WwLq3QxaTkFRGS6wKDm9EZYRgMyDHQfAs
E35Hllcxbgw6taGSPa9OCFF4jp5ym3+nOpPl3yuAZTa1B0qPo84Rhr/gFpls9Moe
72HuYSi3/ll4zNpU2tF/hS+f44QY3z+NBxReGzibuQKBgQDr/eJjpeqJGZaXAvQY
0O8CGWBUMe1jsgl1WICE6ET1AQaRi5RXBgcuB23lvR+cazm17Fy2E+zd+r3Jyn4z
v/M2fWgatO9w1mooZwZBQFA/Uyy4tTzrei421w/gzCvUFPKDolSwnVQkXA+7ccou
NUCjWkjEToQFITryrLyCHhfXrQKBgQDK6lODRsOq+Hfl0yTfp4rdA7jpbBAWnkY7
aNpXSv1CdTxgsdunOQN1F4T6OWOSVLkUM58ZUlErILZoEzUZqGdoeApMYJOle3Cw
5oVa9dRN8GVHAk+HR86AAVWxtPZJDB7I81VD5RYDsHKsY1im/36Etu9jb1llevDn
2TnlBDYPZQKBgGcB1JVmUG8zahXURjOmzwx9gxx9Bn9jsNk1njNlJuRCZFmXMVKi
4PNobsG+wVOHQhN0bitTmypxTfIMnvV7rW91YcF2hKUeEgw8m/BTYDOj3HtrMIIg
PJfXW6jltaPG2Ow4KPtGUPnl7UAGNRfiSqqCuAxnsRyEGrTeTRIGjKWpAoGBAJxX
pZbtLA+MN90lLTEBxxV5K7z13QOAWX6m0CwYBEBzUdzyzNnwLMDIKVYeZ6C0lJGD
IJ+C9DU1lDVmLzCgt2QfsVedxcTn8jDqvG8UH8sZYP8wQZRq+ClaXet5EZXAt+t+
yQBx/t9C0WgPd5vcGWAqDxJfFdMBwaHxlhDliL2dAoGBAI5T5py8nbfR6Ma88p7i
jVNycLtmEw9Zf4El3KhVrKJkmC7cbDoJ4D5Q9Mv8qHmcXeG+RfAIGpe8XUtYZCYH
XzuI4HQvxWLbhYYyE57ijUfokL0DQHo08feGLtPki+AdJZ5pqIzVoQebz88KFpoS
VfwBjNLu/eSndu5yGiwpZ+3g
-----END PRIVATE KEY-----";

/// Writes a stripe-N archive whose volumes carry an X.509 `RootAuth` footer
/// produced by the fixture signer.
fn write_x509_signed_archive(stripe_width: u32) -> tzap_core::writer::WrittenArchive {
    let signer = X509RootAuthSigner::from_pem_or_der(TEST_LEAF_CERT_PEM.as_bytes(), TEST_LEAF_KEY_PEM.as_bytes(), Vec::new(), 1_700_000_000).unwrap();
    write_archive_with_root_auth(
        &[RegularFile::new("payload.txt", b"signed payload")],
        &MasterKey::from_raw_key(&[7u8; 32]).unwrap(),
        WriterOptions { stripe_width, volume_loss_tolerance: 0, ..WriterOptions::default() },
        signer.root_auth_writer_config().unwrap(),
        |request| signer.authenticator_value_for_request(request).map_err(|_| FormatError::InvalidArchive("X.509 RootAuth signer failed")),
    )
    .unwrap()
}

#[test]
fn tzap_public_metadata_display_summary_reports_signed_x509_footer() {
    let temp = TestDir::new("tzap-display-signed");
    let archive = temp.path("signed.tzap");
    fs::write(&archive, write_x509_signed_archive(1).bytes).unwrap();

    let result = tzapPublicMetadataDisplaySummary(archive.to_string_lossy().to_string());
    assert!(result.contains("\"ok\":true"), "got: {result}");
    assert!(result.contains("\"status\":\"signed\""), "got: {result}");
    assert!(result.contains("\"verification_scope\":\"footer-only\""), "got: {result}");
    assert!(result.contains("\"content_verified\":false"), "got: {result}");
    assert!(result.contains("\"status\":\"root_auth_signer_inspected\""), "got: {result}");
    assert!(result.contains("\"subject\":\"CN=ZManager FFI Test Signer\""), "got: {result}");
    assert!(result.contains("\"signature_verified\":true"), "got: {result}");
    assert!(result.contains("\"trust_validated\":false"), "got: {result}");
}

#[test]
fn tzap_public_metadata_display_summary_reports_not_authentic_for_tampered_signature() {
    let temp = TestDir::new("tzap-display-not-authentic");
    let archive = temp.path("tampered.tzap");
    let signer = X509RootAuthSigner::from_pem_or_der(TEST_LEAF_CERT_PEM.as_bytes(), TEST_LEAF_KEY_PEM.as_bytes(), Vec::new(), 1_700_000_000).unwrap();
    // A real signature with one flipped byte in the signature region: the
    // footer parses but the signature no longer verifies.
    let written = write_archive_with_root_auth(
        &[RegularFile::new("payload.txt", b"tampered payload")],
        &MasterKey::from_raw_key(&[7u8; 32]).unwrap(),
        WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() },
        signer.root_auth_writer_config().unwrap(),
        |request| {
            let mut value = signer.authenticator_value_for_request(request).map_err(|_| FormatError::InvalidArchive("X.509 RootAuth signer failed"))?;
            let last = value.len() - 1;
            value[last] ^= 0x01;
            Ok(value)
        },
    )
    .unwrap();
    fs::write(&archive, written.bytes).unwrap();

    let result = tzapPublicMetadataDisplaySummary(archive.to_string_lossy().to_string());
    assert!(result.contains("\"ok\":true"), "got: {result}");
    assert!(result.contains("\"status\":\"not_authentic\""), "got: {result}");
    assert!(result.contains("\"message\":\"X.509 RootAuth signature failed\""), "got: {result}");
}

#[test]
fn tzap_public_metadata_display_summary_reports_unavailable_for_non_x509_footer() {
    let temp = TestDir::new("tzap-display-non-x509");
    let archive = temp.path("signed.tzap");
    let written = write_archive_with_root_auth(
        &[RegularFile::new("plain.txt", b"generic signing profile")],
        &MasterKey::from_raw_key(&[7u8; 32]).unwrap(),
        WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() },
        RootAuthWriterConfig { authenticator_id: 0x7777, signer_identity_type: 1, signer_identity: b"test signer", authenticator_value_length: 32 },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();
    fs::write(&archive, written.bytes).unwrap();

    let result = tzapPublicMetadataDisplaySummary(archive.to_string_lossy().to_string());
    assert!(result.contains("\"ok\":true"), "got: {result}");
    assert!(result.contains("\"status\":\"unavailable\""), "got: {result}");
    assert!(result.contains("non-X.509 root-auth profile"), "got: {result}");
}

#[test]
fn tzap_public_metadata_display_summary_accepts_multi_volume_base_path() {
    let temp = TestDir::new("tzap-display-multi-volume");
    let written = write_x509_signed_archive(4);
    for (index, volume) in written.volumes.iter().enumerate() {
        fs::write(temp.path(&format!("sample.vol{index:03}.tzap")), volume).unwrap();
    }

    // The volume set exists only under numbered sibling names; the
    // non-existent base path must still resolve to the set and verify every
    // volume's footer.
    let result = tzapPublicMetadataDisplaySummary(temp.path("sample.tzap").to_string_lossy().to_string());
    assert!(result.contains("\"ok\":true"), "got: {result}");
    assert!(result.contains("\"status\":\"signed\""), "got: {result}");
    assert!(result.contains("\"expected_volume_count\":4"), "got: {result}");
    assert!(result.contains("\"present_volume_count\":4"), "got: {result}");
    assert!(result.contains("\"subject\":\"CN=ZManager FFI Test Signer\""), "got: {result}");
}

#[test]
fn phase_progress_surfaces_as_bytes_without_spurious_started_events() {
    use zmanager_core::jobs::JobPhase;

    let registry = MobileJobRegistry::default();
    let job = registry.create_job(MobileJobKind::TzapCreate, CancellationToken::new(), false);

    registry.emit_core_event(&job.job_id, CoreJobEvent::Started { kind: CoreJobKind::TzapCreate, total_bytes: Some(100) });
    registry.emit_core_event(&job.job_id, CoreJobEvent::PhaseStarted { phase: JobPhase::EmittingPayload, total_bytes: Some(50) });
    registry.emit_core_event(
        &job.job_id,
        CoreJobEvent::PhaseBytesProcessed {
            phase: JobPhase::EmittingPayload,
            path: Some("payload.bin".to_string()),
            recent_paths: Vec::new(),
            recent_path_identities: Vec::new(),
            bytes: 10,
            total_bytes_processed: 10,
            total_bytes: Some(50),
            recent_paths_truncated: false,
        },
    );
    registry.emit_core_event(
        &job.job_id,
        CoreJobEvent::PhaseBytesProcessed {
            phase: JobPhase::EmittingPayload,
            path: Some("payload.bin".to_string()),
            recent_paths: Vec::new(),
            recent_path_identities: Vec::new(),
            bytes: 20,
            total_bytes_processed: 30,
            total_bytes: Some(50),
            recent_paths_truncated: false,
        },
    );

    let polled = registry.poll_events(PollJobEventsRequest { job_id: job.job_id, cursor: 0 }).unwrap();
    let kinds = polled.events.iter().map(|event| event.event_type).collect::<Vec<_>>();
    // Phase transitions must not emit spurious job-Started events; their
    // byte progress surfaces as regular byte-progress events with the
    // totals intact.
    assert_eq!(kinds, vec![MobileJobEventKind::Started, MobileJobEventKind::BytesProcessed, MobileJobEventKind::BytesProcessed]);
    assert_eq!(polled.events[1].bytes, Some(10));
    assert_eq!(polled.events[1].total_bytes_processed, Some(10));
    assert_eq!(polled.events[2].bytes, Some(20));
    assert_eq!(polled.events[2].total_bytes_processed, Some(30));
}

#[test]
fn job_registry_recovers_after_mutex_poisoning() {
    let registry = MobileJobRegistry::default();

    // Poison the registry's mutex by panicking while holding the lock.
    let _ = std::panic::catch_unwind(|| {
        let mut inner = registry.inner.lock().expect("test lock");
        inner.next_job_index = inner.next_job_index.saturating_add(1);
        panic!("intentional panic while holding the job registry lock");
    });

    // A poisoned mutex must not permanently disable the job registry.
    let result = registry.create_job(MobileJobKind::ZipCreate, CancellationToken::new(), false);
    assert!(result.job_id.starts_with("job-"));
    assert_eq!(result.status, MobileJobStatus::Queued);
}

fn assert_bridge_error_code(error: ZmanagerGuiError, expected: &str) {
    match error {
        ZmanagerGuiError::Bridge { code, .. } => assert_eq!(code, expected),
    }
}

fn approved_refuse_plan_token(archive: &Path, destination: &Path, password: Option<&str>, selected_paths: Vec<String>) -> String {
    let plan = planExtract(PlanExtractRequest {
        archive_path: archive.to_string_lossy().to_string(),
        destination_root: destination.to_string_lossy().to_string(),
        password: password.map(ToOwned::to_owned),
        selected_paths,
        strip_components: 0,
        collision_policy: ExtractionCollisionPolicy::Refuse,
    })
    .expect("extraction plan should be approved for the test fixture");

    assert!(plan.can_start, "test fixture plan should be startable");
    assert!(!plan.plan_token.is_empty(), "startable plan should have an opaque token");
    plan.plan_token
}

fn wait_for_terminal_job(job_id: &str) -> PollJobEventsResult {
    for _ in 0..100 {
        let poll = pollJobEvents(PollJobEventsRequest { job_id: job_id.to_string(), cursor: 0 }).expect("job should remain pollable");

        if poll.is_terminal {
            return poll;
        }

        std::thread::sleep(Duration::from_millis(20));
    }

    panic!("job did not finish within the test timeout");
}

fn wait_for_terminal_summary(job_id: &str, predicate: impl Fn(&JobTerminalSummary) -> bool) -> PollJobEventsResult {
    for _ in 0..100 {
        let poll = pollJobEvents(PollJobEventsRequest { job_id: job_id.to_string(), cursor: 0 }).expect("job should remain pollable");

        if poll.is_terminal && poll.terminal_summary.as_ref().is_some_and(&predicate) {
            return poll;
        }

        std::thread::sleep(Duration::from_millis(20));
    }

    panic!("job terminal summary did not settle within the test timeout");
}

fn readme_entry_path(archive: &Path) -> String {
    listArchive(ListArchiveRequest { archive_path: archive.to_string_lossy().to_string(), password: None })
        .expect("fixture archive should list")
        .entries
        .into_iter()
        .find(|entry| entry.path.ends_with("readme.txt"))
        .expect("fixture archive should contain readme.txt")
        .path
}

fn deterministic_bytes(length: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_u32;
    let mut bytes = Vec::with_capacity(length);
    for _ in 0..length {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        bytes.push((state >> 24) as u8);
    }
    bytes
}

fn checked_in_rar_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name)
}

fn create_test_zip(name: &str) -> TestArchiveFixture {
    let temp = TestDir::new(name);
    temp.create_dir("project");
    temp.write_file("project/readme.txt", b"hello mobile bridge\n");
    let archive = temp.path("archive.zip");
    let manifest = plan_archive(temp.path("project"), &PlanOptions::default()).expect("fixture manifest should be planned");
    create_zip_from_manifest(&manifest, &archive, &ZipCreateOptions::default()).expect("fixture zip should be created through zmanager-core");
    TestArchiveFixture { temp, archive }
}

struct TestArchiveFixture {
    temp: TestDir,
    archive: PathBuf,
}

struct TestDir {
    root: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = std::env::temp_dir().join(format!("zmanager-mobile-{name}-{}-{now}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("test temp root should be created");
        Self { root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn create_dir(&self, relative: &str) {
        fs::create_dir_all(self.path(relative)).expect("test directory should be created");
    }

    fn write_file(&self, relative: &str, contents: &[u8]) {
        let path = self.path(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("test parent should be created");
        }
        fs::write(path, contents).expect("test file should be written");
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
