//! Archive healthcheck/detect/list/test/materialize/plan ops and the
//! job-spawning entry points.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::UNIX_EPOCH;

use sha2::{Digest as _, Sha256};

use zmanager_core::apple_archive_backend;
use zmanager_core::archive_browser::{self, BrowserExtractOptions, BrowserListOptions};
use zmanager_core::engine::{ArchiveOperation, ArchiveSource, OpenOptions, create_default_engine};
use zmanager_core::jobs::CancellationToken;
use zmanager_core::libarchive_backend;
use zmanager_core::manifest;
use zmanager_core::raw_stream_backend;
use zmanager_core::safety::{ExtractionPolicy, ExtractionSafetyPlanner};
use zmanager_core::sevenz_backend;
use zmanager_core::tzap_backend;
use zmanager_core::zip_backend;

use crate::ffi::error::map_apple_archive_error;
use crate::ffi::error::{
    ERROR_INVALID_REQUEST, ERROR_OPERATION_FAILED, ERROR_UNSUPPORTED_FORMAT, WARNING_LAUNCH_GATED_FORMAT, bridge_error, bridge_error_from_mobile,
    bridge_warning, bridge_warning_with_code, hint, map_7z_error, map_archive_browser_error, map_libarchive_error, map_plan_error, map_raw_stream_error,
    map_tzap_error, map_zip_error,
};
use crate::ffi::ops::jobs::{
    CreateJobInput, ExtractJobInput, PlanEntryOutcome, RegistryJobEventSink, TestArchiveReport, create_plan_options, create_verify_supported, job_registry,
    map_collision_policy, map_manifest_file_type, mobile_create_job_kind, mobile_extract_job_kind, plan_browser_entry, run_create_job, run_extract_job,
};
use crate::ffi::session::session_registry;
use crate::ffi::types::{
    ArchiveEntry, ArchiveEntryKind, ArchiveFormat, BridgeError, BridgeSeverity, CancelJobRequest, CancelJobResult, ClearSensitiveStateResult, CreatePlanEntry,
    DetectArchiveRequest, DetectArchiveResult, ExtractionCollisionPolicy, ExtractionPlanEntryStatus, FormatDescriptor, HealthcheckResult, ListArchiveRequest,
    ListArchiveResult, ListFormatsResult, MaterializePreviewRequest, MaterializePreviewResult, PlanCreateRequest, PlanCreateResult, PlanExtractRequest,
    PlanExtractResult, PollJobEventsRequest, PollJobEventsResult, StartCreateRequest, StartExtractRequest, StartJobResult, TestArchiveRequest,
    TestArchiveResult, ZmanagerGuiError, usize_to_u64,
};
use crate::ffi::util::{
    classify_archive_path, create_format_label, ensure_destination_archive_path, ensure_destination_root_path, ensure_existing_file_path,
    ensure_existing_source_paths, ensure_non_empty_entry_path, format_capabilities, format_capabilities_for_kind, format_label, kind_label,
    map_browser_entry_kind, password_ref, sanitize_password, usize_from_u64,
};

const MAX_RETAINED_EXTRACTION_PLANS: usize = 64;

static EXTRACTION_PLAN_REGISTRY: OnceLock<Mutex<ExtractionPlanRegistry>> = OnceLock::new();

#[derive(Default)]
struct ExtractionPlanRegistry {
    next_plan_index: u64,
    plans: HashMap<String, ExtractionPlanBinding>,
    insertion_order: VecDeque<String>,
}

struct ExtractionPlanBinding {
    archive_path: String,
    destination_root: String,
    archive_size: u64,
    archive_modified_nanos: Option<u128>,
    password_digest: [u8; 32],
    selected_paths: Vec<String>,
    strip_components: u64,
    collision_policy: ExtractionCollisionPolicy,
}

impl ExtractionPlanBinding {
    fn from_request(
        archive_path: String,
        destination_root: String,
        password: Option<&str>,
        selected_paths: Vec<String>,
        strip_components: u64,
        collision_policy: ExtractionCollisionPolicy,
    ) -> Result<Self, ZmanagerGuiError> {
        let metadata = std::fs::metadata(&archive_path).map_err(|_| {
            bridge_error(
                ERROR_INVALID_REQUEST,
                "Unable to read the archive while preparing extraction.",
                hint("Reopen the archive and review the extraction plan again."),
                BridgeSeverity::Warning,
                true,
            )
        })?;
        let archive_modified_nanos = metadata.modified().ok().and_then(|modified| modified.duration_since(UNIX_EPOCH).ok()).map(|duration| duration.as_nanos());

        Ok(Self {
            archive_path,
            destination_root,
            archive_size: metadata.len(),
            archive_modified_nanos,
            password_digest: extraction_password_digest(password),
            selected_paths,
            strip_components,
            collision_policy,
        })
    }

    fn matches(&self, other: &Self) -> bool {
        self.archive_path == other.archive_path
            && self.destination_root == other.destination_root
            && self.archive_size == other.archive_size
            && self.archive_modified_nanos == other.archive_modified_nanos
            && self.password_digest == other.password_digest
            && self.selected_paths == other.selected_paths
            && self.strip_components == other.strip_components
            && self.collision_policy == other.collision_policy
    }
}

fn extraction_plan_registry() -> &'static Mutex<ExtractionPlanRegistry> {
    EXTRACTION_PLAN_REGISTRY.get_or_init(|| Mutex::new(ExtractionPlanRegistry::default()))
}

fn register_extraction_plan(binding: ExtractionPlanBinding) -> String {
    let mut registry = extraction_plan_registry().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    registry.next_plan_index = registry.next_plan_index.saturating_add(1);
    let token = format!("plan-{}-{}", std::process::id(), registry.next_plan_index);

    while registry.plans.len() >= MAX_RETAINED_EXTRACTION_PLANS {
        let Some(oldest_token) = registry.insertion_order.pop_front() else {
            break;
        };
        registry.plans.remove(&oldest_token);
    }

    registry.insertion_order.push_back(token.clone());
    registry.plans.insert(token.clone(), binding);
    token
}

fn consume_extraction_plan(token: &str, candidate: ExtractionPlanBinding) -> Result<(), ZmanagerGuiError> {
    let mut registry = extraction_plan_registry().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(expected) = registry.plans.remove(token) else {
        return Err(invalid_extraction_plan_error());
    };
    registry.insertion_order.retain(|registered_token| registered_token != token);

    if expected.matches(&candidate) { Ok(()) } else { Err(invalid_extraction_plan_error()) }
}

fn extraction_password_digest(password: Option<&str>) -> [u8; 32] {
    let mut digest = Sha256::new();
    match password {
        Some(value) => {
            digest.update(b"zmanager-extraction-plan-password-present\0");
            digest.update(value.as_bytes());
        }
        None => digest.update(b"zmanager-extraction-plan-password-absent\0"),
    }
    digest.finalize().into()
}

fn invalid_extraction_plan_error() -> ZmanagerGuiError {
    bridge_error(
        ERROR_INVALID_REQUEST,
        "The extraction plan is no longer valid.",
        hint("Review the extraction plan again before starting."),
        BridgeSeverity::Warning,
        true,
    )
}

pub fn healthcheck() -> HealthcheckResult {
    let report = zmanager_core::healthcheck();
    HealthcheckResult {
        status: if report.ready { "ready" } else { "not-ready" }.to_string(),
        engine: report.engine.to_string(),
        version: report.version.to_string(),
        ready: report.ready,
        summary: report.summary(),
    }
}

/// Enumerates the full compile-time format capability registry so consumers
/// can present or verify format support without duplicating extension lists
/// or platform predicates.
#[allow(non_snake_case)]
pub fn listFormats() -> ListFormatsResult {
    let engine_snapshot = create_default_engine().ok().map(|engine| engine.capability_snapshot()).unwrap_or_default();
    let formats = zmanager_core::archive_format::FORMAT_CAPABILITIES
        .iter()
        .map(|capability| {
            let (can_list, can_extract, can_create) = format_capabilities_for_kind(capability.kind);
            let engine_capability = zmanager_core::engine::FormatId::from_archive_format_kind(capability.kind)
                .and_then(|format| engine_snapshot.iter().find(|snapshot| snapshot.format == format));
            let recognized = !matches!(capability.kind, zmanager_core::archive_format::ArchiveFormatKind::Unknown);
            let platform_available = engine_capability.is_some_and(|snapshot| snapshot.platform_available);
            let unavailable_reason = engine_capability.and_then(|snapshot| snapshot.unavailable_reason.clone());
            let source_access = engine_capability.and_then(|snapshot| snapshot.source_access.map(source_access_label));
            let encryption_supported = engine_capability.is_some_and(|snapshot| snapshot.encryption_supported);
            FormatDescriptor {
                kind: format!("{:?}", capability.kind),
                label: kind_label(capability.kind).to_string(),
                extensions: capability.extensions.iter().map(|suffix| suffix.to_string()).collect(),
                can_list: engine_capability.is_some_and(|snapshot| snapshot.operations.contains(&ArchiveOperation::List)) && can_list,
                can_extract,
                can_create,
                recognized,
                platform_available,
                unavailable_reason,
                source_access,
                encryption_supported,
            }
        })
        .collect();
    ListFormatsResult { formats }
}

fn source_access_label(source_access: zmanager_core::engine::SourceAccess) -> String {
    match source_access {
        zmanager_core::engine::SourceAccess::Seekable => "seekable",
        zmanager_core::engine::SourceAccess::SequentialOnly => "sequential_only",
        zmanager_core::engine::SourceAccess::MultiVolumeSet => "multi_volume_set",
    }
    .to_owned()
}

#[allow(non_snake_case)]
pub fn detectArchive(request: DetectArchiveRequest) -> Result<DetectArchiveResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let path = Path::new(&archive_path);
    let (format, mut warnings) = classify_archive_path(path);
    let (can_list, can_extract, can_create) = format_capabilities(format);

    if matches!(format, ArchiveFormat::Xip) {
        warnings
            .push(bridge_warning_with_code(WARNING_LAUNCH_GATED_FORMAT, "This launch-scope format must be handled by zmanager-core before mobile exposes it."));
    }

    Ok(DetectArchiveResult {
        archive_path,
        format,
        format_label: format_label(format).to_string(),
        exists: true,
        is_file: true,
        can_list,
        can_extract,
        can_create,
        warnings,
    })
}

#[allow(non_snake_case)]
pub fn listArchive(request: ListArchiveRequest) -> Result<ListArchiveResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let password = password_ref(&request.password);
    let path = Path::new(&archive_path);
    let (format, _warnings) = classify_archive_path(path);

    let listing = {
        let mut sessions = session_registry().lock().unwrap_or_else(|error| error.into_inner());
        let session_id = sessions
            .open_session(ArchiveSource::from_path_autodetect(path), OpenOptions { password: password.map(ToOwned::to_owned), recipient_key: None })
            .map_err(crate::ffi::error::map_archive_engine_error)?;
        let listing = sessions.list_session(&session_id).map_err(crate::ffi::error::map_archive_engine_error)?;
        sessions.close_session(&session_id).map_err(crate::ffi::error::map_archive_engine_error)?;
        listing
    };

    let mut total_size = 0u64;
    let mut has_size = false;
    let mut entries = Vec::with_capacity(listing.entries.len());

    for entry in listing.entries {
        if let Some(size) = entry.size {
            total_size = total_size.saturating_add(size);
            has_size = true;
        }

        let kind = map_browser_entry_kind(entry.kind);
        entries.push(ArchiveEntry {
            path: entry.path,
            kind,
            is_dir: matches!(kind, ArchiveEntryKind::Directory),
            size: entry.size,
            compressed_size: entry.compressed_size,
            modified_at: entry.modified,
        });
    }

    Ok(ListArchiveResult {
        archive_path,
        format,
        format_label: format_label(format).to_string(),
        entry_count: entries.len() as u64,
        total_size: has_size.then_some(total_size),
        entries,
        warnings: Vec::new(),
    })
}

fn maybe_test_apple_archive(format: ArchiveFormat, path: &Path, selected_paths: &[String]) -> Option<Result<TestArchiveReport, ZmanagerGuiError>> {
    if !matches!(format, ArchiveFormat::AppleArchive) {
        return None;
    }
    Some(
        apple_archive_backend::test_apple_archive_filter(path, |entry_path| selected_path_matches(selected_paths, entry_path), None)
            .map_err(map_apple_archive_error)
            .map(TestArchiveReport::from_apple_archive),
    )
}

#[allow(non_snake_case)]
pub fn testArchive(request: TestArchiveRequest) -> Result<TestArchiveResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let password = password_ref(&request.password);
    let selected_paths = sanitize_selected_paths(request.selected_paths);
    let path = Path::new(&archive_path);
    let (format, _warnings) = classify_archive_path(path);

    let report = if matches!(format, ArchiveFormat::Zip) {
        let selected_paths = selected_paths.as_slice();
        TestArchiveReport::from_zip(
            zip_backend::test_zip_with_password_filter(path, password, |entry_path| selected_path_matches(selected_paths, entry_path))
                .map_err(map_zip_error)?,
        )
    } else if matches!(format, ArchiveFormat::Tzap) {
        let selected_paths = selected_paths.as_slice();
        TestArchiveReport::from_tzap(
            tzap_backend::test_tzap_with_optional_password_filter_and_x509_trust(
                path,
                password,
                |entry_path| selected_path_matches(selected_paths, entry_path),
                None,
            )
            .map_err(map_tzap_error)?,
        )
    } else if matches!(format, ArchiveFormat::SevenZ) {
        let selected_paths = selected_paths.as_slice();
        TestArchiveReport::from_7z(
            sevenz_backend::test_7z_with_password_filter(path, password, |entry_path| selected_path_matches(selected_paths, entry_path))
                .map_err(map_7z_error)?,
        )
    } else if let Some(report) = maybe_test_apple_archive(format, path, &selected_paths) {
        report?
    } else if let Some(raw_format) = raw_stream_backend::detect_raw_stream_format(path) {
        test_raw_stream(path, raw_format, &selected_paths)?
    } else {
        let selected_paths = selected_paths.as_slice();
        TestArchiveReport::from_libarchive(
            libarchive_backend::test_archive_with_password_filter(path, password, |entry_path| selected_path_matches(selected_paths, entry_path))
                .map_err(map_libarchive_error)?,
        )
    };

    Ok(TestArchiveResult {
        archive_path,
        format,
        format_label: format_label(format).to_string(),
        verified: true,
        tested_entries: report.tested_entries,
        skipped_entries: report.skipped_entries,
        total_entries: report.total_entries(),
        tested_bytes: report.tested_bytes,
        warnings: report.warnings,
    })
}

#[allow(non_snake_case)]
pub fn materializePreview(request: MaterializePreviewRequest) -> Result<MaterializePreviewResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let entry_path = ensure_non_empty_entry_path(request.entry_path)?;
    let strip_components = usize_from_u64(request.strip_components, "stripComponents")?;
    let password = password_ref(&request.password);

    let options = BrowserExtractOptions { password, strip_components, ..BrowserExtractOptions::default() };

    let report = archive_browser::preview_entry_with_options(Path::new(&archive_path), &entry_path, options).map_err(map_archive_browser_error)?;

    Ok(MaterializePreviewResult {
        archive_path,
        entry_path,
        cleanup_root: report.cleanup_root.to_string_lossy().to_string(),
        preview_path: report.preview_path.to_string_lossy().to_string(),
        written_bytes: report.written_bytes,
        warnings: Vec::new(),
    })
}

#[allow(non_snake_case)]
pub fn planExtract(request: PlanExtractRequest) -> Result<PlanExtractResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let destination_root = ensure_destination_root_path(request.destination_root)?;
    let strip_components = usize_from_u64(request.strip_components, "stripComponents")?;
    let password = password_ref(&request.password);
    let selected_paths = sanitize_selected_paths(request.selected_paths);
    let plan_binding = ExtractionPlanBinding::from_request(
        archive_path.clone(),
        destination_root.clone(),
        password,
        selected_paths.clone(),
        request.strip_components,
        request.collision_policy,
    )?;
    let path = Path::new(&archive_path);
    let (format, _warnings) = classify_archive_path(path);
    let listing = archive_browser::list_entries_with_options(path, BrowserListOptions { password, recipient_key: None }).map_err(map_archive_browser_error)?;

    let policy = ExtractionPolicy { overwrite: map_collision_policy(request.collision_policy), strip_components, ..ExtractionPolicy::default() };
    let mut planner = ExtractionSafetyPlanner::new(PathBuf::from(&destination_root), policy);
    let mut entries = Vec::new();
    let mut estimated_bytes = 0u64;
    let mut has_estimated_bytes = false;
    let mut warnings = Vec::new();

    for entry in listing.entries {
        if !selected_path_matches(&selected_paths, &entry.path) {
            continue;
        }

        match plan_browser_entry(&mut planner, entry) {
            PlanEntryOutcome::Entry(plan_entry) => {
                if matches!(plan_entry.status, ExtractionPlanEntryStatus::Write)
                    && matches!(plan_entry.kind, ArchiveEntryKind::File)
                    && let Some(size) = plan_entry.size
                {
                    estimated_bytes = estimated_bytes.saturating_add(size);
                    has_estimated_bytes = true;
                }
                entries.push(plan_entry);
            }
            PlanEntryOutcome::EntryWithWarning { plan_entry, warning } => {
                warnings.push(warning);
                entries.push(plan_entry);
            }
        }
    }

    let total_entries = usize_to_u64(entries.len());
    let writable_entries = usize_to_u64(entries.iter().filter(|entry| matches!(entry.status, ExtractionPlanEntryStatus::Write)).count());
    let skipped_entries = usize_to_u64(entries.iter().filter(|entry| matches!(entry.status, ExtractionPlanEntryStatus::Skip)).count());
    let blocked_entries = usize_to_u64(entries.iter().filter(|entry| matches!(entry.status, ExtractionPlanEntryStatus::Block)).count());

    let can_start = writable_entries > 0 && blocked_entries == 0;
    let plan_token = if can_start { register_extraction_plan(plan_binding) } else { String::new() };

    Ok(PlanExtractResult {
        archive_path,
        destination_root,
        format,
        format_label: format_label(format).to_string(),
        entries,
        total_entries,
        writable_entries,
        skipped_entries,
        blocked_entries,
        estimated_bytes: has_estimated_bytes.then_some(estimated_bytes),
        can_start,
        warnings,
        plan_token,
    })
}

#[allow(non_snake_case)]
pub fn planCreate(request: PlanCreateRequest) -> Result<PlanCreateResult, ZmanagerGuiError> {
    let source_paths = ensure_existing_source_paths(request.source_paths)?;
    let destination_archive_path = ensure_destination_archive_path(request.destination_archive_path)?;
    let destination_path = Path::new(&destination_archive_path);
    let output_exists = destination_path.exists();
    let plan_options = create_plan_options(request.clean_source, &[]);
    let source_path_bufs = source_paths.iter().map(PathBuf::from).collect::<Vec<_>>();
    let manifest = manifest::plan_archives(&source_path_bufs, &plan_options).map_err(map_plan_error)?;
    let mut warnings =
        manifest.warnings.iter().map(|warning| bridge_warning(format!("{}: {}", warning.source_path.display(), warning.message))).collect::<Vec<_>>();

    if output_exists && !request.replace_existing {
        warnings.push(bridge_warning("Destination archive already exists and replaceExisting is false."));
    }

    let entries = manifest
        .entries
        .iter()
        .map(|entry| CreatePlanEntry {
            archive_path: entry.archive_path.clone(),
            source_path: entry.source_path.to_string_lossy().to_string(),
            kind: map_manifest_file_type(entry.file_type),
            size: entry.size,
        })
        .collect::<Vec<_>>();
    let total_entries = usize_to_u64(entries.len());
    let encrypted = password_ref(&request.password).is_some();

    Ok(PlanCreateResult {
        source_paths,
        destination_archive_path,
        format: request.format,
        format_label: create_format_label(request.format).to_string(),
        entries,
        total_entries,
        total_bytes: manifest.total_bytes,
        excluded_entries: usize_to_u64(manifest.excluded_count()),
        excluded_bytes: manifest.excluded_bytes,
        output_exists,
        replace_existing: request.replace_existing,
        encrypted,
        preserve_metadata: request.preserve_metadata,
        clean_source: request.clean_source,
        verify_after_create: request.verify_after_create,
        verify_supported: create_verify_supported(request.format),
        can_start: total_entries > 0 && (!output_exists || request.replace_existing),
        warnings,
    })
}

#[allow(non_snake_case)]
pub fn startCreate(request: StartCreateRequest) -> Result<StartJobResult, ZmanagerGuiError> {
    let source_paths = ensure_existing_source_paths(request.source_paths)?;
    let destination_archive_path = ensure_destination_archive_path(request.destination_archive_path)?;
    if Path::new(&destination_archive_path).exists() && !request.replace_existing {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            "Destination archive already exists.",
            hint("Choose a different output name or enable replaceExisting."),
            BridgeSeverity::Warning,
            false,
        ));
    }

    let password = sanitize_password(request.password);
    let contains_sensitive_input = password.is_some();
    let token = CancellationToken::new();
    let kind = mobile_create_job_kind(request.format);
    let registry = job_registry();
    let result = registry.create_job(kind, token.clone(), contains_sensitive_input);
    let job_id = result.job_id.clone();
    let input = CreateJobInput {
        source_paths: source_paths.iter().map(PathBuf::from).collect(),
        destination_archive_path,
        format: request.format,
        password,
        preserve_metadata: request.preserve_metadata,
        replace_existing: request.replace_existing,
        clean_source: request.clean_source,
        verify_after_create: request.verify_after_create,
        excluded_paths: request.excluded_paths,
        level: request.level,
        encrypt_file_names: request.encrypt_file_names,
        volume_size: request.volume_size,
        recovery_percentage: request.recovery_percentage,
        volume_loss_tolerance: request.volume_loss_tolerance,
        tzap_signing_certificate: request.tzap_signing_certificate,
        tzap_signing_private_key: request.tzap_signing_private_key,
        tzap_signing_chain: request.tzap_signing_chain,
        tzap_identity: request.tzap_identity,
        tzap_identity_password: request.tzap_identity_password,
    };
    let worker_registry = Arc::clone(&registry);

    thread::spawn(move || {
        let worker_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut sink = RegistryJobEventSink { registry: Arc::clone(&worker_registry), job_id: job_id.clone() };
            run_create_job(input, &token, &mut sink)
        }));

        match worker_result {
            Ok(Ok(summary)) => worker_registry.set_terminal_summary(&job_id, summary),
            Ok(Err(error)) => {
                worker_registry.finish_with_error(&job_id, create_worker_error(error));
            }
            Err(_) => {
                worker_registry.finish_with_error(
                    &job_id,
                    BridgeError {
                        code: ERROR_OPERATION_FAILED.to_string(),
                        message: "Create worker failed unexpectedly.".to_string(),
                        recovery_hint: hint("Retry the operation and report this if it repeats."),
                        severity: BridgeSeverity::Error,
                        retryable: true,
                    },
                );
            }
        }
    });

    Ok(result)
}

fn extraction_worker_error(error: ZmanagerGuiError) -> BridgeError {
    let error = bridge_error_from_mobile(error);
    if matches!(error.code.as_str(), "io_error" | "not_found" | ERROR_OPERATION_FAILED) {
        BridgeError {
            code: error.code,
            message: "Unable to write the staged extraction.".to_string(),
            recovery_hint: hint("Check available storage and retry the extraction."),
            severity: error.severity,
            retryable: true,
        }
    } else {
        error
    }
}

fn create_worker_error(error: ZmanagerGuiError) -> BridgeError {
    bridge_error_from_mobile(error)
}

#[allow(non_snake_case)]
pub fn startExtract(request: StartExtractRequest) -> Result<StartJobResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let destination_root = ensure_destination_root_path(request.destination_root)?;
    let strip_components = usize_from_u64(request.strip_components, "stripComponents")?;
    let selected_paths = sanitize_selected_paths(request.selected_paths);
    let password = sanitize_password(request.password);
    let plan_binding = ExtractionPlanBinding::from_request(
        archive_path.clone(),
        destination_root.clone(),
        password.as_deref(),
        selected_paths.clone(),
        request.strip_components,
        request.collision_policy,
    )?;
    consume_extraction_plan(&request.plan_token, plan_binding)?;
    let path = Path::new(&archive_path);
    let (format, _warnings) = classify_archive_path(path);
    let (_, can_extract, _) = format_capabilities(format);

    if !can_extract {
        return Err(bridge_error(
            ERROR_UNSUPPORTED_FORMAT,
            format!("{} extraction is not exposed by zmanager-core for mobile yet.", format_label(format)),
            None,
            BridgeSeverity::Warning,
            false,
        ));
    }

    let token = CancellationToken::new();
    let kind = mobile_extract_job_kind(path, format);
    let registry = job_registry();
    let result = registry.create_job(kind, token.clone(), password.is_some());
    let job_id = result.job_id.clone();
    let input =
        ExtractJobInput { archive_path, destination_root, password, selected_paths, strip_components, collision_policy: request.collision_policy, format };
    let worker_registry = Arc::clone(&registry);

    thread::spawn(move || {
        let worker_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut sink = RegistryJobEventSink { registry: Arc::clone(&worker_registry), job_id: job_id.clone() };
            run_extract_job(input, &token, &mut sink)
        }));

        match worker_result {
            Ok(Ok(summary)) => worker_registry.set_terminal_summary(&job_id, summary),
            Ok(Err(error)) => {
                worker_registry.finish_with_error(&job_id, extraction_worker_error(error));
            }
            Err(_) => {
                worker_registry.finish_with_error(
                    &job_id,
                    BridgeError {
                        code: ERROR_OPERATION_FAILED.to_string(),
                        message: "Extraction worker failed unexpectedly.".to_string(),
                        recovery_hint: hint("Retry the operation and report this if it repeats."),
                        severity: BridgeSeverity::Error,
                        retryable: true,
                    },
                );
            }
        }
    });

    Ok(result)
}

#[allow(non_snake_case)]
pub fn pollJobEvents(request: PollJobEventsRequest) -> Result<PollJobEventsResult, ZmanagerGuiError> {
    job_registry().poll_events(request)
}

#[allow(non_snake_case)]
pub fn cancelJob(request: CancelJobRequest) -> Result<CancelJobResult, ZmanagerGuiError> {
    job_registry().cancel_job(request)
}

#[allow(non_snake_case)]
pub fn clearSensitiveState() -> ClearSensitiveStateResult {
    job_registry().clear_sensitive_state()
}

pub(crate) fn sanitize_selected_paths(selected_paths: Vec<String>) -> Vec<String> {
    selected_paths.into_iter().map(|value| value.trim().to_string()).filter(|value| !value.is_empty()).collect()
}

pub(crate) fn selected_path_matches(selected_paths: &[String], entry_path: &str) -> bool {
    selected_paths.is_empty() || selected_paths.iter().any(|value| value == entry_path)
}

fn test_raw_stream(path: &Path, format: raw_stream_backend::RawStreamFormat, selected_paths: &[String]) -> Result<TestArchiveReport, ZmanagerGuiError> {
    let synthetic_entry =
        raw_stream_backend::output_name_for_raw_stream(path, format).unwrap_or_else(|| format_label(classify_archive_path(path).0).to_string());

    if !selected_path_matches(selected_paths, &synthetic_entry) {
        return Ok(TestArchiveReport { tested_entries: 0, skipped_entries: 1, tested_bytes: 0, warnings: Vec::new() });
    }

    let tested_bytes = raw_stream_backend::test_raw_stream(path, format).map_err(map_raw_stream_error)?;

    Ok(TestArchiveReport { tested_entries: 1, skipped_entries: 0, tested_bytes, warnings: Vec::new() })
}
