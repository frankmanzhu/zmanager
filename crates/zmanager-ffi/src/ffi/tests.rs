use super::error::{ERROR_DAMAGED_ARCHIVE, ERROR_INVALID_REQUEST, ERROR_NOT_FOUND, WARNING_LAUNCH_GATED_FORMAT};
use super::ops::jobs::MobileJobRegistry;
use super::util::{classify_archive_path, password_ref, sanitize_password};
use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zmanager_core::jobs::{CancellationToken, JobEvent as CoreJobEvent, JobKind as CoreJobKind};
use zmanager_core::manifest::{PlanOptions, plan_archive};
use zmanager_core::zip_backend::{ZipCreateOptions, create_zip_from_manifest};

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
fn detect_archive_rejects_platform_uri_objects() {
    let error = detectArchive(DetectArchiveRequest { archive_path: "content://downloads/archive.zip".to_string() })
        .unwrap_err();

    assert_bridge_error_code(error, ERROR_INVALID_REQUEST);
}

#[test]
fn detect_archive_classifies_existing_app_controlled_file() {
    let temp = TestDir::new("detect-existing-file");
    temp.write_file("ARCHIVE.ZIP", b"not parsed during detection");

    let result =
        detectArchive(DetectArchiveRequest { archive_path: temp.path("ARCHIVE.ZIP").to_string_lossy().to_string() })
            .expect("detection should classify an existing app-controlled path");

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

    let result =
        detectArchive(DetectArchiveRequest { archive_path: temp.path("archive.xip").to_string_lossy().to_string() })
            .expect("detection should classify launch-gated app-controlled path");

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
    let error =
        listArchive(ListArchiveRequest { archive_path: "/definitely/missing/archive.zip".to_string(), password: None })
            .unwrap_err();

    assert_bridge_error_code(error, ERROR_NOT_FOUND);
}

#[test]
fn list_archive_reads_real_zip_through_core() {
    let temp = TestDir::new("list-archive-real-zip");
    temp.create_dir("project");
    temp.write_file("project/readme.txt", b"hello mobile bridge\n");
    let archive = temp.path("archive.zip");
    let manifest =
        plan_archive(temp.path("project"), &PlanOptions::default()).expect("fixture manifest should be planned");
    create_zip_from_manifest(&manifest, &archive, &ZipCreateOptions::default())
        .expect("fixture zip should be created through zmanager-core");

    let result =
        listArchive(ListArchiveRequest { archive_path: archive.to_string_lossy().to_string(), password: None })
            .expect("core-backed listing should succeed");

    assert_eq!(result.format, ArchiveFormat::Zip);
    assert!(result.entry_count >= 1);
    assert!(result.entries.iter().any(|entry| entry.path.ends_with("readme.txt")));
    assert!(result.total_size.is_some());
}

#[test]
fn test_archive_reads_real_zip_through_core() {
    let fixture = create_test_zip("test-archive-real-zip");

    let result = testArchive(TestArchiveRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        password: None,
        selected_paths: Vec::new(),
    })
    .expect("core-backed archive test should succeed");

    assert_eq!(result.format, ArchiveFormat::Zip);
    assert!(result.verified);
    assert!(result.tested_entries >= 1);
    assert_eq!(result.total_entries, result.tested_entries + result.skipped_entries);
    assert!(result.tested_bytes > 0);
}

#[test]
fn test_archive_honors_selected_entry_filter() {
    let fixture = create_test_zip("test-archive-selected-filter");

    let result = testArchive(TestArchiveRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        password: None,
        selected_paths: vec!["missing.txt".to_string()],
    })
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

    let error = testArchive(TestArchiveRequest {
        archive_path: temp.path("broken.zip").to_string_lossy().to_string(),
        password: None,
        selected_paths: Vec::new(),
    })
    .unwrap_err();

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

    let result = materializePreview(MaterializePreviewRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        entry_path: entry_path.clone(),
        password: None,
        strip_components: 0,
    })
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

    let error = materializePreview(MaterializePreviewRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        entry_path: String::new(),
        password: None,
        strip_components: 0,
    })
    .unwrap_err();

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
    assert!(result.entries.iter().any(|entry| {
        matches!(entry.status, ExtractionPlanEntryStatus::Write)
            && entry.destination_path.as_deref().is_some_and(|path| Path::new(path).starts_with(&destination))
    }));
}

#[test]
fn plan_extract_surfaces_destination_collision_as_blocked_entry() {
    let fixture = create_test_zip("plan-extract-collision");
    let entry_path = readme_entry_path(&fixture.archive);
    let destination = fixture.temp.path("out");
    let colliding_path = destination.join(&entry_path);
    fs::create_dir_all(colliding_path.parent().expect("colliding path should have a parent"))
        .expect("collision parent should be created");
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
    assert!(
        result.entries.iter().any(|entry| {
            entry.archive_path.ends_with("readme.txt") && matches!(entry.kind, ArchiveEntryKind::File)
        })
    );
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
    })
    .expect("extract job should start");

    assert_eq!(started.kind, MobileJobKind::ZipExtract);
    assert_eq!(started.status, MobileJobStatus::Queued);

    let terminal = wait_for_terminal_job(&started.job_id);
    assert_eq!(terminal.status, MobileJobStatus::Completed);
    assert!(terminal.is_terminal);
    assert!(terminal.events.iter().any(|event| {
        matches!(event.event_type, MobileJobEventKind::Started) && event.job_kind == Some(MobileJobKind::ZipExtract)
    }));
    assert!(terminal.events.iter().any(|event| matches!(event.event_type, MobileJobEventKind::Completed)));
    let summary = terminal.terminal_summary.expect("completed job should include a terminal summary");
    assert!(summary.written_entries >= 1);
    assert!(summary.written_bytes > 0);
    assert_eq!(
        fs::read_to_string(destination.join(entry_path)).expect("extracted file should be readable"),
        "hello mobile bridge\n"
    );
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

    let listing =
        listArchive(ListArchiveRequest { archive_path: destination.to_string_lossy().to_string(), password: None })
            .expect("created zip should list through the bridge");
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

    let listing =
        listArchive(ListArchiveRequest { archive_path: destination.to_string_lossy().to_string(), password: None })
            .expect("created clean-source zip should list");
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

    let verified = testArchive(TestArchiveRequest {
        archive_path: destination.to_string_lossy().to_string(),
        password: Some(password.to_string()),
        selected_paths: Vec::new(),
    })
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
    })
    .expect("selected extract job should start");

    let terminal = wait_for_terminal_job(&started.job_id);
    assert_eq!(terminal.status, MobileJobStatus::Completed);
    assert!(terminal.events.iter().any(|event| {
        matches!(event.event_type, MobileJobEventKind::EntryStarted)
            && event.path.as_deref() == Some(entry_path.as_str())
    }));
    assert_eq!(
        fs::read_to_string(destination.join(entry_path)).expect("selected file should be extracted"),
        "hello mobile bridge\n"
    );
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

    let sensitive_error =
        registry.poll_events(PollJobEventsRequest { job_id: sensitive_job.job_id, cursor: 0 }).unwrap_err();
    assert_bridge_error_code(sensitive_error, ERROR_NOT_FOUND);

    let regular_result = registry
        .poll_events(PollJobEventsRequest { job_id: regular_job.job_id, cursor: 0 })
        .expect("non-sensitive active job should stay pollable");
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
    })
    .expect("extract job should start");

    let terminal = wait_for_terminal_job(&started.job_id);
    assert!(!terminal.events.is_empty());
    let repeated = pollJobEvents(PollJobEventsRequest { job_id: started.job_id, cursor: terminal.next_cursor })
        .expect("polling from the latest cursor should succeed");

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
}

#[test]
fn phase_progress_surfaces_as_bytes_without_spurious_started_events() {
    use zmanager_core::jobs::JobPhase;

    let registry = MobileJobRegistry::default();
    let job = registry.create_job(MobileJobKind::TzapCreate, CancellationToken::new(), false);

    registry
        .emit_core_event(&job.job_id, CoreJobEvent::Started { kind: CoreJobKind::TzapCreate, total_bytes: Some(100) });
    registry.emit_core_event(
        &job.job_id,
        CoreJobEvent::PhaseStarted { phase: JobPhase::EmittingPayload, total_bytes: Some(50) },
    );
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
    assert_eq!(
        kinds,
        vec![MobileJobEventKind::Started, MobileJobEventKind::BytesProcessed, MobileJobEventKind::BytesProcessed]
    );
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

fn wait_for_terminal_job(job_id: &str) -> PollJobEventsResult {
    for _ in 0..100 {
        let poll = pollJobEvents(PollJobEventsRequest { job_id: job_id.to_string(), cursor: 0 })
            .expect("job should remain pollable");

        if poll.is_terminal {
            return poll;
        }

        std::thread::sleep(Duration::from_millis(20));
    }

    panic!("job did not finish within the test timeout");
}

fn wait_for_terminal_summary(job_id: &str, predicate: impl Fn(&JobTerminalSummary) -> bool) -> PollJobEventsResult {
    for _ in 0..100 {
        let poll = pollJobEvents(PollJobEventsRequest { job_id: job_id.to_string(), cursor: 0 })
            .expect("job should remain pollable");

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

fn create_test_zip(name: &str) -> TestArchiveFixture {
    let temp = TestDir::new(name);
    temp.create_dir("project");
    temp.write_file("project/readme.txt", b"hello mobile bridge\n");
    let archive = temp.path("archive.zip");
    let manifest =
        plan_archive(temp.path("project"), &PlanOptions::default()).expect("fixture manifest should be planned");
    create_zip_from_manifest(&manifest, &archive, &ZipCreateOptions::default())
        .expect("fixture zip should be created through zmanager-core");
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
