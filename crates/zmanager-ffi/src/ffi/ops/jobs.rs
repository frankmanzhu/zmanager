//! Background job registry and the create/extract job runners.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use zmanager_core::archive_browser::{self, BrowserEntry, BrowserEntryKind, BrowserExtractOptions};
use zmanager_core::engine::{
    ArchiveSource, OpenOptions, SevenZCreateOptions, TarZstdCreateOptions, TzapCreateOptions, TzapKeySource, TzapX509SigningOptions, ZipCreateOptions,
    create_default_engine,
};
use zmanager_core::jobs::{self, CancellationToken, JobEvent as CoreJobEvent, JobKind as CoreJobKind};
use zmanager_core::manifest::{ManifestFileType, PlanOptions};
use zmanager_core::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwritePolicy,
};
use zmanager_core::secrets::SecretString;

use crate::ffi::error::{
    ERROR_CANCELLED, ERROR_NOT_FOUND, bridge_error, bridge_error_from_mobile, bridge_warning, cancelled_bridge_error, hint, map_archive_browser_error,
    map_archive_engine_error,
};
use crate::ffi::event::{cancelled_event, completed_event_from_summary, failed_event, mobile_event_from_core_event};
use crate::ffi::ops::archive::{selected_path_matches, testArchive};
use crate::ffi::types::{
    ArchiveEntryKind, ArchiveFormat, BridgeError, BridgeSeverity, CancelJobRequest, CancelJobResult, ClearSensitiveStateResult, CreateArchiveFormat,
    ExtractionCollisionPolicy, ExtractionPlanEntry, ExtractionPlanEntryStatus, JobTerminalSummary, MobileJobEvent, MobileJobEventKind, MobileJobKind,
    MobileJobStatus, PollJobEventsRequest, PollJobEventsResult, StartJobResult, TestArchiveRequest, ZmanagerGuiError, usize_to_u64,
};
use crate::ffi::util::map_browser_entry_kind;

pub(crate) const MAX_EVENTS_PER_JOB: usize = 512;

static JOB_REGISTRY: OnceLock<Arc<MobileJobRegistry>> = OnceLock::new();

#[derive(Default)]
pub(crate) struct MobileJobRegistry {
    pub(crate) inner: Mutex<MobileJobRegistryInner>,
}

#[derive(Default)]
pub(crate) struct MobileJobRegistryInner {
    pub(crate) next_job_index: u64,
    pub(crate) jobs: HashMap<String, MobileJobRecord>,
}

pub(crate) struct MobileJobRecord {
    kind: MobileJobKind,
    status: MobileJobStatus,
    events: VecDeque<MobileJobEvent>,
    next_sequence: u64,
    token: CancellationToken,
    terminal_summary: Option<JobTerminalSummary>,
    contains_sensitive_input: bool,
}

pub(crate) struct RegistryJobEventSink {
    pub(crate) registry: Arc<MobileJobRegistry>,
    pub(crate) job_id: String,
}

impl jobs::JobEventSink for RegistryJobEventSink {
    fn emit(&mut self, event: CoreJobEvent) {
        self.registry.emit_core_event(&self.job_id, event);
    }
}

impl MobileJobRegistry {
    /// Returns the registry state, recovering from a poisoned mutex. The
    /// inner state is a plain job map whose records are individually
    /// consistent, so recovering is safe; a panic while holding the lock
    /// must not permanently disable the job registry.
    fn lock_inner(&self) -> std::sync::MutexGuard<'_, MobileJobRegistryInner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn create_job(&self, kind: MobileJobKind, token: CancellationToken, contains_sensitive_input: bool) -> StartJobResult {
        let mut inner = self.lock_inner();
        inner.next_job_index = inner.next_job_index.saturating_add(1);
        let job_id = format!("job-{}-{}", std::process::id(), inner.next_job_index);
        inner.jobs.insert(
            job_id.clone(),
            MobileJobRecord {
                kind,
                status: MobileJobStatus::Queued,
                events: VecDeque::new(),
                next_sequence: 1,
                token,
                terminal_summary: None,
                contains_sensitive_input,
            },
        );

        StartJobResult { job_id, kind, status: MobileJobStatus::Queued }
    }

    pub(crate) fn poll_events(&self, request: PollJobEventsRequest) -> Result<PollJobEventsResult, ZmanagerGuiError> {
        let inner = self.lock_inner();
        let record = inner.jobs.get(&request.job_id).ok_or_else(|| {
            bridge_error(ERROR_NOT_FOUND, "Job not found.", hint("The job may have been created in a previous app process."), BridgeSeverity::Warning, false)
        })?;

        let events: Vec<MobileJobEvent> = record.events.iter().filter(|event| event.sequence > request.cursor).cloned().collect();
        let next_cursor = events.last().map(|event| event.sequence).unwrap_or(request.cursor);
        let min_retained_sequence = record.events.front().map(|event| event.sequence).unwrap_or(record.next_sequence);

        Ok(PollJobEventsResult {
            job_id: request.job_id,
            kind: record.kind,
            status: record.status,
            events,
            next_cursor,
            min_retained_sequence,
            is_terminal: record.status.is_terminal(),
            terminal_summary: record.terminal_summary.clone(),
        })
    }

    pub(crate) fn cancel_job(&self, request: CancelJobRequest) -> Result<CancelJobResult, ZmanagerGuiError> {
        let inner = self.lock_inner();
        let record = inner.jobs.get(&request.job_id).ok_or_else(|| {
            bridge_error(ERROR_NOT_FOUND, "Job not found.", hint("The job may have been created in a previous app process."), BridgeSeverity::Warning, false)
        })?;

        let cancel_requested = !record.status.is_terminal();
        if cancel_requested {
            record.token.cancel();
        }

        Ok(CancelJobResult { job_id: request.job_id, status: record.status, cancel_requested })
    }

    pub(crate) fn clear_sensitive_state(&self) -> ClearSensitiveStateResult {
        let mut inner = self.lock_inner();
        let mut cleared_terminal_jobs = 0u64;
        let mut cancel_requested_jobs = 0u64;
        let mut retained_active_jobs = 0u64;

        inner.jobs.retain(|_, record| {
            if record.status.is_terminal() {
                cleared_terminal_jobs = cleared_terminal_jobs.saturating_add(1);
                return false;
            }

            if record.contains_sensitive_input {
                record.token.cancel();
                cancel_requested_jobs = cancel_requested_jobs.saturating_add(1);
                return false;
            } else {
                retained_active_jobs = retained_active_jobs.saturating_add(1);
            }

            true
        });

        ClearSensitiveStateResult { cleared_terminal_jobs, cancel_requested_jobs, retained_active_jobs }
    }

    pub(crate) fn emit_core_event(&self, job_id: &str, event: CoreJobEvent) {
        let mut inner = self.lock_inner();
        let Some(record) = inner.jobs.get_mut(job_id) else {
            return;
        };
        let Some(event) = mobile_event_from_core_event(event) else {
            return;
        };
        Self::append_event(record, event);
    }

    pub(crate) fn set_terminal_summary(&self, job_id: &str, summary: JobTerminalSummary) {
        let mut inner = self.lock_inner();
        let Some(record) = inner.jobs.get_mut(job_id) else {
            return;
        };
        record.terminal_summary = Some(summary.clone());
        if !record.status.is_terminal() {
            Self::append_event(record, completed_event_from_summary(&summary));
        }
    }

    pub(crate) fn finish_with_error(&self, job_id: &str, error: BridgeError) {
        let mut inner = self.lock_inner();
        let Some(record) = inner.jobs.get_mut(job_id) else {
            return;
        };

        if matches!(record.status, MobileJobStatus::Cancelled) {
            return;
        }

        if matches!(record.events.back().map(|event| event.event_type), Some(MobileJobEventKind::Failed)) {
            if let Some(event) = record.events.back_mut() {
                event.message = Some(error.message.clone());
                event.error = Some(error);
            }
            return;
        }

        if error.code == ERROR_CANCELLED {
            if !record.status.is_terminal() {
                Self::append_event(record, cancelled_event(error.message));
            }
        } else if !record.status.is_terminal() {
            Self::append_event(record, failed_event(error));
        }
    }

    fn append_event(record: &mut MobileJobRecord, mut event: MobileJobEvent) {
        if record.status.is_terminal() && matches!(event.event_type, MobileJobEventKind::Completed | MobileJobEventKind::Failed | MobileJobEventKind::Cancelled)
        {
            return;
        }

        match event.event_type {
            MobileJobEventKind::Started => {
                if !record.status.is_terminal() {
                    record.status = MobileJobStatus::Running;
                }
            }
            MobileJobEventKind::Completed => {
                record.status = MobileJobStatus::Completed;
                if record.terminal_summary.is_none() {
                    record.terminal_summary = Some(JobTerminalSummary {
                        written_entries: event.entries.unwrap_or(0),
                        skipped_entries: None,
                        written_bytes: event.bytes.unwrap_or(0),
                        encrypted: None,
                        volume_size: None,
                        volume_count: None,
                        output_paths: Vec::new(),
                        verified: None,
                        verified_entries: None,
                        verified_bytes: None,
                        warnings: Vec::new(),
                    });
                }
            }
            MobileJobEventKind::Failed => record.status = MobileJobStatus::Failed,
            MobileJobEventKind::Cancelled => record.status = MobileJobStatus::Cancelled,
            MobileJobEventKind::EntryStarted | MobileJobEventKind::BytesProcessed | MobileJobEventKind::EntryFinished | MobileJobEventKind::Warning => {}
        }

        event.sequence = record.next_sequence;
        record.next_sequence = record.next_sequence.saturating_add(1);
        record.events.push_back(event);
        while record.events.len() > MAX_EVENTS_PER_JOB {
            record.events.pop_front();
        }
    }
}

pub(crate) struct ExtractJobInput {
    pub(crate) archive_path: String,
    pub(crate) destination_root: String,
    pub(crate) password: Option<String>,
    pub(crate) selected_paths: Vec<String>,
    pub(crate) strip_components: usize,
    pub(crate) collision_policy: ExtractionCollisionPolicy,
    pub(crate) format: ArchiveFormat,
}

pub(crate) struct CreateJobInput {
    pub(crate) source_paths: Vec<PathBuf>,
    pub(crate) destination_archive_path: String,
    pub(crate) format: CreateArchiveFormat,
    pub(crate) password: Option<String>,
    pub(crate) preserve_metadata: bool,
    pub(crate) replace_existing: bool,
    pub(crate) clean_source: bool,
    pub(crate) verify_after_create: bool,
    pub(crate) excluded_paths: Vec<String>,
    pub(crate) level: u32,
    pub(crate) encrypt_file_names: bool,
    pub(crate) volume_size: Option<u64>,
    pub(crate) recovery_percentage: u8,
    pub(crate) volume_loss_tolerance: u8,
    pub(crate) tzap_signing_certificate: Option<String>,
    pub(crate) tzap_signing_private_key: Option<String>,
    pub(crate) tzap_signing_chain: Vec<String>,
    pub(crate) tzap_identity: Option<String>,
    pub(crate) tzap_identity_password: Option<String>,
}

pub(crate) fn job_registry() -> Arc<MobileJobRegistry> {
    JOB_REGISTRY.get_or_init(|| Arc::new(MobileJobRegistry::default())).clone()
}

pub(crate) fn run_create_job(
    input: CreateJobInput,
    token: &CancellationToken,
    sink: &mut dyn jobs::JobEventSink,
) -> Result<JobTerminalSummary, ZmanagerGuiError> {
    let destination = Path::new(&input.destination_archive_path);
    let plan_options = create_plan_options(input.clean_source, &input.excluded_paths);
    let verify_after_create = input.verify_after_create;
    let verify_password = verify_after_create.then(|| input.password.clone()).flatten();
    let level = input.level;
    let volume_size = input.volume_size;
    let encrypt_file_names = input.encrypt_file_names;
    let recovery_percentage = input.recovery_percentage;
    let volume_loss_tolerance = input.volume_loss_tolerance;
    let x509_signing = tzap_signing_options(&input);
    let mut summary = match input.format {
        CreateArchiveFormat::Zip => {
            let options = ZipCreateOptions {
                preserve_metadata: input.preserve_metadata,
                replace_existing: input.replace_existing,
                password: input.password.map(SecretString::from),
                level: (level > 0).then_some(i64::from(level)),
                volume_size,
                ..ZipCreateOptions::default()
            };
            let report = jobs::run_engine_create_job_from_sources(
                &input.source_paths,
                destination,
                &zmanager_core::engine::CreateOptions::Zip(options),
                &plan_options,
                token,
                sink,
            )
            .map_err(map_archive_engine_error)?;
            JobTerminalSummary::from(ArchiveJobReport::from(report).with_output_path(destination))
        }
        CreateArchiveFormat::SevenZ => {
            let options = SevenZCreateOptions {
                preserve_metadata: input.preserve_metadata,
                replace_existing: input.replace_existing,
                password: input.password.map(SecretString::from),
                level: (level > 0).then_some(level),
                encrypt_file_names,
                volume_size,
                ..SevenZCreateOptions::default()
            };
            let report = jobs::run_engine_create_job_from_sources(
                &input.source_paths,
                destination,
                &zmanager_core::engine::CreateOptions::SevenZ(options),
                &plan_options,
                token,
                sink,
            )
            .map_err(map_archive_engine_error)?;
            JobTerminalSummary::from(ArchiveJobReport::from(report).with_output_path(destination))
        }
        CreateArchiveFormat::TarZst => {
            let options = TarZstdCreateOptions {
                preserve_metadata: input.preserve_metadata,
                replace_existing: input.replace_existing,
                level: i32::try_from(level).unwrap_or(0),
                ..TarZstdCreateOptions::default()
            };
            let report = jobs::run_engine_create_job_from_sources(
                &input.source_paths,
                destination,
                &zmanager_core::engine::CreateOptions::TarZstd(options),
                &plan_options,
                token,
                sink,
            )
            .map_err(map_archive_engine_error)?;
            JobTerminalSummary::from(ArchiveJobReport::from(report).with_output_path(destination))
        }
        CreateArchiveFormat::Tzap => {
            let options = TzapCreateOptions {
                key_source: input.password.map(|password| TzapKeySource::Passphrase(SecretString::from(password))).unwrap_or(TzapKeySource::NoPassword),
                level: i32::try_from(level).unwrap_or(0),
                preserve_metadata: input.preserve_metadata,
                replace_existing: input.replace_existing,
                volume_size,
                recovery_percentage,
                volume_loss_tolerance,
                x509_signing,
            };
            let report = jobs::run_engine_create_job_from_sources(
                &input.source_paths,
                destination,
                &zmanager_core::engine::CreateOptions::Tzap(options),
                &plan_options,
                token,
                sink,
            )
            .map_err(map_archive_engine_error)?;
            JobTerminalSummary::from(ArchiveJobReport::from(report).with_output_path(destination))
        }
    };

    if verify_after_create {
        apply_create_verification(&mut summary, destination, verify_password, sink);
    }

    Ok(summary)
}

pub(crate) fn run_extract_job(
    input: ExtractJobInput,
    token: &CancellationToken,
    sink: &mut dyn jobs::JobEventSink,
) -> Result<JobTerminalSummary, ZmanagerGuiError> {
    if input.selected_paths.is_empty() { run_full_extract_job(input, token, sink) } else { run_selected_extract_job(input, token, sink) }
}

fn run_full_extract_job(input: ExtractJobInput, token: &CancellationToken, sink: &mut dyn jobs::JobEventSink) -> Result<JobTerminalSummary, ZmanagerGuiError> {
    let archive_path = Path::new(&input.archive_path);
    let destination_root = Path::new(&input.destination_root);
    let policy = extraction_policy_for_request(input.collision_policy, input.strip_components);
    if token.is_cancelled() {
        sink.emit(CoreJobEvent::Cancelled { message: "job cancelled".to_owned() });
        return Err(cancelled_bridge_error("Extraction job was cancelled."));
    }
    sink.emit(CoreJobEvent::Started { kind: core_extract_job_kind(archive_path, input.format), total_bytes: None });
    let mut options =
        zmanager_core::engine::ExtractOptions { destination: destination_root.to_path_buf(), policy, cancellation: Some(token.clone()), ..Default::default() };
    let result = zmanager_core::engine::extract_with_default_engine(
        zmanager_core::engine::ArchiveSource::from_path_autodetect(archive_path),
        zmanager_core::engine::OpenOptions { password: input.password, recipient_key: None, ..Default::default() },
        &mut options,
    );
    match result {
        Ok(report) => {
            sink.emit(CoreJobEvent::Completed { entries: usize::try_from(report.written_entries).unwrap_or(usize::MAX), bytes: report.written_bytes });
            Ok(JobTerminalSummary {
                written_entries: report.written_entries,
                skipped_entries: Some(report.skipped_entries),
                written_bytes: report.written_bytes,
                encrypted: None,
                volume_size: None,
                volume_count: None,
                output_paths: Vec::new(),
                verified: None,
                verified_entries: None,
                verified_bytes: None,
                warnings: report.warnings.into_iter().map(bridge_warning).collect(),
            })
        }
        Err(error) => {
            if error.kind == zmanager_core::engine::ErrorKind::Cancelled {
                sink.emit(CoreJobEvent::Cancelled { message: error.message.clone() });
            } else {
                sink.emit(CoreJobEvent::Failed { message: error.message.clone() });
            }
            Err(map_archive_engine_error(error))
        }
    }
}

fn run_selected_extract_job(
    input: ExtractJobInput,
    token: &CancellationToken,
    sink: &mut dyn jobs::JobEventSink,
) -> Result<JobTerminalSummary, ZmanagerGuiError> {
    let archive_path = Path::new(&input.archive_path);
    let destination_root = Path::new(&input.destination_root);
    let password = input.password.as_deref();
    let engine = create_default_engine().map_err(map_archive_engine_error)?;
    let mut handle = engine
        .open(
            ArchiveSource::from_path_autodetect(archive_path),
            OpenOptions { password: password.map(ToOwned::to_owned), recipient_key: None, ..Default::default() },
        )
        .map_err(map_archive_engine_error)?;
    let listing = handle.list().map_err(map_archive_engine_error)?;
    let entries: Vec<_> = listing.entries.into_iter().filter(|entry| selected_path_matches(&input.selected_paths, &entry.path)).collect();

    if entries.is_empty() {
        return Err(bridge_error(
            ERROR_NOT_FOUND,
            "No selected archive entries were found.",
            hint("Refresh the archive listing and select entries that still exist."),
            BridgeSeverity::Warning,
            false,
        ));
    }

    let total_bytes = entries.iter().fold((false, 0_u64), |(has_size, total), entry| match entry.size {
        Some(size) => (true, total.saturating_add(size)),
        None => (has_size, total),
    });
    sink.emit(CoreJobEvent::Started { kind: core_extract_job_kind(archive_path, input.format), total_bytes: total_bytes.0.then_some(total_bytes.1) });

    let selected_entry_paths: Vec<String> = entries.iter().map(|entry| entry.path.clone()).collect();
    let mut written_entries = 0usize;
    let mut written_bytes = 0u64;
    let options = BrowserExtractOptions {
        password,
        overwrite: map_collision_policy(input.collision_policy),
        strip_components: input.strip_components,
        ..Default::default()
    };

    let extracted = archive_browser::extract_selected_entries_from_engine_handle(&mut handle, &selected_entry_paths, destination_root, options)
        .map_err(map_archive_browser_error)?;

    for (entry_path, report) in extracted {
        if token.is_cancelled() {
            sink.emit(CoreJobEvent::Cancelled { message: "job cancelled".to_string() });
            return Err(cancelled_bridge_error("Extraction job was cancelled."));
        }

        let entry_size = entries.iter().find(|entry| entry.path == entry_path).and_then(|entry| entry.size);
        sink.emit(CoreJobEvent::EntryStarted { path: entry_path.clone(), bytes: entry_size });
        written_entries = written_entries.saturating_add(1);
        written_bytes = written_bytes.saturating_add(report.written_bytes);
        sink.emit(CoreJobEvent::EntryFinished { path: entry_path, bytes: report.written_bytes });
    }

    sink.emit(CoreJobEvent::Completed { entries: written_entries, bytes: written_bytes });

    Ok(JobTerminalSummary {
        written_entries: usize_to_u64(written_entries),
        skipped_entries: Some(0),
        written_bytes,
        encrypted: None,
        volume_size: None,
        volume_count: None,
        output_paths: Vec::new(),
        verified: None,
        verified_entries: None,
        verified_bytes: None,
        warnings: Vec::new(),
    })
}

struct ArchiveJobReport {
    written_entries: usize,
    skipped_entries: usize,
    written_bytes: u64,
    encrypted: Option<bool>,
    volume_size: Option<u64>,
    volume_count: Option<usize>,
    output_paths: Vec<String>,
    warnings: Vec<String>,
}

impl ArchiveJobReport {
    fn with_output_path(mut self, path: &Path) -> Self {
        self.output_paths.push(path.to_string_lossy().to_string());
        self
    }
}

impl From<zmanager_core::engine::CreateReport> for ArchiveJobReport {
    fn from(report: zmanager_core::engine::CreateReport) -> Self {
        Self {
            written_entries: usize::try_from(report.written_entries).unwrap_or(usize::MAX),
            skipped_entries: 0,
            written_bytes: report.written_bytes,
            encrypted: report.encrypted,
            volume_size: report.volume_size,
            volume_count: Some(usize::try_from(report.volume_count).unwrap_or(usize::MAX)),
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<ArchiveJobReport> for JobTerminalSummary {
    fn from(report: ArchiveJobReport) -> Self {
        Self {
            written_entries: usize_to_u64(report.written_entries),
            skipped_entries: Some(usize_to_u64(report.skipped_entries)),
            written_bytes: report.written_bytes,
            encrypted: report.encrypted,
            volume_size: report.volume_size,
            volume_count: report.volume_count.map(usize_to_u64),
            output_paths: report.output_paths,
            verified: None,
            verified_entries: None,
            verified_bytes: None,
            warnings: report.warnings.into_iter().map(bridge_warning).collect(),
        }
    }
}

pub(crate) struct TestArchiveReport {
    pub(crate) tested_entries: u64,
    pub(crate) skipped_entries: u64,
    pub(crate) tested_bytes: u64,
    pub(crate) warnings: Vec<BridgeError>,
}

impl TestArchiveReport {
    pub(crate) fn from_engine(report: zmanager_core::engine::TestReport) -> Self {
        Self {
            tested_entries: report.tested_entries,
            skipped_entries: report.skipped_entries,
            tested_bytes: report.tested_bytes,
            warnings: report.warnings.into_iter().map(bridge_warning).collect(),
        }
    }

    pub(crate) fn total_entries(&self) -> u64 {
        self.tested_entries.saturating_add(self.skipped_entries)
    }
}

pub(crate) enum PlanEntryOutcome {
    Entry(ExtractionPlanEntry),
    EntryWithWarning { plan_entry: ExtractionPlanEntry, warning: BridgeError },
}

pub(crate) fn plan_browser_entry(planner: &mut ExtractionSafetyPlanner<'_>, entry: BrowserEntry) -> PlanEntryOutcome {
    let kind = map_browser_entry_kind(entry.kind);

    let extraction_kind = match entry.kind {
        BrowserEntryKind::File | BrowserEntryKind::FileCopy => ExtractionEntryKind::File,
        BrowserEntryKind::Directory => ExtractionEntryKind::Directory,
        BrowserEntryKind::Symlink | BrowserEntryKind::Hardlink => {
            let reason = "Link target metadata is required before mobile can safely plan this entry.";
            let archive_path = entry.path.clone();
            return PlanEntryOutcome::EntryWithWarning {
                plan_entry: blocked_plan_entry(entry, kind, reason),
                warning: bridge_warning(format!("Blocked {} until zmanager-core exposes link target metadata for mobile planning.", archive_path)),
            };
        }
        BrowserEntryKind::Special => {
            return PlanEntryOutcome::Entry(blocked_plan_entry(entry, kind, "Special files are blocked by the mobile extraction policy."));
        }
    };

    let safety_entry =
        ExtractionEntry { archive_path: entry.path.clone(), kind: extraction_kind, uncompressed_size: entry.size, compressed_size: entry.compressed_size };

    match planner.validate_entry(&safety_entry) {
        Ok(ExtractionDecision::Write { normalized_archive_path, destination_path, replace_existing, .. }) => PlanEntryOutcome::Entry(ExtractionPlanEntry {
            archive_path: entry.path,
            normalized_path: Some(normalized_archive_path),
            destination_path: Some(destination_path.to_string_lossy().to_string()),
            kind,
            status: ExtractionPlanEntryStatus::Write,
            reason: None,
            size: entry.size,
            compressed_size: entry.compressed_size,
            replace_existing,
        }),
        Ok(ExtractionDecision::Skip { normalized_archive_path, reason }) => PlanEntryOutcome::Entry(ExtractionPlanEntry {
            archive_path: entry.path,
            normalized_path: Some(normalized_archive_path),
            destination_path: None,
            kind,
            status: ExtractionPlanEntryStatus::Skip,
            reason: Some(reason),
            size: entry.size,
            compressed_size: entry.compressed_size,
            replace_existing: false,
        }),
        Err(error) => PlanEntryOutcome::Entry(blocked_plan_entry_from_safety_error(entry, kind, error)),
    }
}

fn blocked_plan_entry(entry: BrowserEntry, kind: ArchiveEntryKind, reason: impl Into<String>) -> ExtractionPlanEntry {
    ExtractionPlanEntry {
        archive_path: entry.path,
        normalized_path: None,
        destination_path: None,
        kind,
        status: ExtractionPlanEntryStatus::Block,
        reason: Some(reason.into()),
        size: entry.size,
        compressed_size: entry.compressed_size,
        replace_existing: false,
    }
}

fn blocked_plan_entry_from_safety_error(entry: BrowserEntry, kind: ArchiveEntryKind, error: ExtractionSafetyError) -> ExtractionPlanEntry {
    let destination_path = safety_error_destination_path(&error);
    ExtractionPlanEntry {
        archive_path: entry.path,
        normalized_path: None,
        destination_path: destination_path.map(|path| path.to_string_lossy().to_string()),
        kind,
        status: ExtractionPlanEntryStatus::Block,
        reason: Some(error.to_string()),
        size: entry.size,
        compressed_size: entry.compressed_size,
        replace_existing: false,
    }
}

fn safety_error_destination_path(error: &ExtractionSafetyError) -> Option<PathBuf> {
    match error {
        ExtractionSafetyError::DestinationEscape { destination_path, .. }
        | ExtractionSafetyError::DestinationExists { destination_path, .. }
        | ExtractionSafetyError::OverwritePromptUnavailable { destination_path, .. }
        | ExtractionSafetyError::OverwriteAborted { destination_path, .. }
        | ExtractionSafetyError::DestinationProbe { destination_path, .. }
        | ExtractionSafetyError::RenameDestinationExhausted { destination_path, .. } => Some(destination_path.clone()),
        ExtractionSafetyError::EmptyPath
        | ExtractionSafetyError::NulByte { .. }
        | ExtractionSafetyError::AbsolutePath { .. }
        | ExtractionSafetyError::WindowsPrefix { .. }
        | ExtractionSafetyError::ParentTraversal { .. }
        | ExtractionSafetyError::NameCollision { .. }
        | ExtractionSafetyError::UnsafeFileType { .. }
        | ExtractionSafetyError::LinkTargetEscapes { .. }
        | ExtractionSafetyError::ExpandedSizeLimitExceeded { .. }
        | ExtractionSafetyError::ExpansionRatioLimitExceeded { .. }
        | ExtractionSafetyError::EntryCountLimitExceeded { .. }
        | ExtractionSafetyError::PathTooLong { .. }
        | ExtractionSafetyError::WindowsReservedName { .. } => None,
    }
}

pub(crate) fn map_collision_policy(policy: ExtractionCollisionPolicy) -> OverwritePolicy {
    match policy {
        ExtractionCollisionPolicy::Refuse => OverwritePolicy::Refuse,
        ExtractionCollisionPolicy::Replace => OverwritePolicy::Replace,
        ExtractionCollisionPolicy::Rename => OverwritePolicy::Rename,
    }
}

fn extraction_policy_for_request(collision_policy: ExtractionCollisionPolicy, strip_components: usize) -> ExtractionPolicy {
    ExtractionPolicy { overwrite: map_collision_policy(collision_policy), strip_components, ..ExtractionPolicy::default() }
}

pub(crate) fn create_plan_options(clean_source: bool, excluded_paths: &[String]) -> PlanOptions {
    let mut options = if clean_source { PlanOptions::clean_source() } else { PlanOptions::default() };
    let excluded: Vec<String> = excluded_paths.iter().filter(|path| !path.trim().is_empty()).cloned().collect();
    if !excluded.is_empty() {
        options.exclude_archive_paths = excluded;
    }
    options
}

fn tzap_signing_options(input: &CreateJobInput) -> Option<TzapX509SigningOptions> {
    if let Some(identity) = input.tzap_identity.as_deref().filter(|path| !path.is_empty()) {
        return Some(TzapX509SigningOptions::Pkcs12 {
            identity: PathBuf::from(identity),
            password: SecretString::from(input.tzap_identity_password.clone().unwrap_or_default()),
        });
    }

    match (input.tzap_signing_certificate.as_deref().filter(|path| !path.is_empty()), input.tzap_signing_private_key.as_deref().filter(|path| !path.is_empty()))
    {
        (Some(certificate), Some(private_key)) => Some(TzapX509SigningOptions::CertificateAndKey {
            signing_certificate: PathBuf::from(certificate),
            signing_private_key: PathBuf::from(private_key),
            signing_chain: input.tzap_signing_chain.iter().filter(|path| !path.is_empty()).map(PathBuf::from).collect(),
        }),
        _ => None,
    }
}

/// Whether the format supports verify-after-create through the generic test
/// path. All current formats do; a format without a test path must return
/// false here instead of silently offering verification.
pub(crate) fn create_verify_supported(format: CreateArchiveFormat) -> bool {
    matches!(format, CreateArchiveFormat::Zip | CreateArchiveFormat::SevenZ | CreateArchiveFormat::TarZst | CreateArchiveFormat::Tzap)
}

fn apply_create_verification(summary: &mut JobTerminalSummary, destination: &Path, password: Option<String>, sink: &mut dyn jobs::JobEventSink) {
    match testArchive(TestArchiveRequest { archive_path: destination.to_string_lossy().to_string(), password, selected_paths: Vec::new() }) {
        Ok(report) => {
            summary.verified = Some(true);
            summary.verified_entries = Some(report.tested_entries);
            summary.verified_bytes = Some(report.tested_bytes);
            summary.warnings.extend(report.warnings);
        }
        Err(error) => {
            let error = bridge_error_from_mobile(error);
            summary.verified = Some(false);
            summary.warnings.push(error.clone());
            sink.emit(CoreJobEvent::Warning { message: format!("Created archive verification failed: {}", error.message) });
        }
    }
}

pub(crate) fn mobile_create_job_kind(format: CreateArchiveFormat) -> MobileJobKind {
    match format {
        CreateArchiveFormat::Zip => MobileJobKind::ZipCreate,
        CreateArchiveFormat::SevenZ => MobileJobKind::SevenZCreate,
        CreateArchiveFormat::TarZst => MobileJobKind::TarZstdCreate,
        CreateArchiveFormat::Tzap => MobileJobKind::TzapCreate,
    }
}

pub(crate) fn map_manifest_file_type(file_type: ManifestFileType) -> ArchiveEntryKind {
    match file_type {
        ManifestFileType::File => ArchiveEntryKind::File,
        ManifestFileType::Directory => ArchiveEntryKind::Directory,
        ManifestFileType::Symlink => ArchiveEntryKind::Symlink,
        ManifestFileType::Other => ArchiveEntryKind::Special,
    }
}

pub(crate) fn mobile_extract_job_kind(path: &Path, format: ArchiveFormat) -> MobileJobKind {
    mobile_job_kind_from_core(core_extract_job_kind(path, format))
}

fn core_extract_job_kind(path: &Path, format: ArchiveFormat) -> CoreJobKind {
    // The engine identity owns the format→job-kind label mapping; the bridge
    // only translates its display enum into the engine kind first.
    let kind = if matches!(format, ArchiveFormat::Other) {
        // Unknown at the bridge level: fall back to core path detection so
        // raw-stream files keep their progress kind.
        zmanager_core::archive_format::detect_archive_format(path)
    } else {
        crate::ffi::util::kind_for_format(format)
    };
    zmanager_core::engine::FormatId::from_archive_format_kind(kind).map_or(CoreJobKind::ArchiveExtract, zmanager_core::engine::FormatId::extract_job_kind)
}

pub(crate) fn mobile_job_kind_from_core(kind: CoreJobKind) -> MobileJobKind {
    match kind {
        CoreJobKind::ZipCreate => MobileJobKind::ZipCreate,
        CoreJobKind::ZipExtract => MobileJobKind::ZipExtract,
        CoreJobKind::SevenZCreate => MobileJobKind::SevenZCreate,
        CoreJobKind::SevenZExtract => MobileJobKind::SevenZExtract,
        CoreJobKind::RarExtract => MobileJobKind::RarExtract,
        CoreJobKind::TarZstdCreate => MobileJobKind::TarZstdCreate,
        CoreJobKind::TarZstdExtract => MobileJobKind::TarZstdExtract,
        CoreJobKind::TzapCreate => MobileJobKind::TzapCreate,
        CoreJobKind::TzapExtract => MobileJobKind::TzapExtract,
        CoreJobKind::AppleArchiveCreate => MobileJobKind::AppleArchiveCreate,
        CoreJobKind::AppleArchiveExtract => MobileJobKind::AppleArchiveExtract,
        CoreJobKind::ArchiveExtract => MobileJobKind::ArchiveExtract,
        CoreJobKind::RawStreamExtract => MobileJobKind::RawStreamExtract,
        CoreJobKind::TarGzCreate => MobileJobKind::TarGzCreate,
    }
}
