use super::{CancellationToken, JobContext, JobEvent, JobEventSink, JobKind};
use crate::apple_archive_backend::{self, AppleArchiveError};
use crate::engine::{CreateOptions, CreateReport, CreateRequest, FormatId, create_default_engine};
use crate::manifest::{PlanOptions, plan_archives};
use crate::safety::ExtractionPolicy;
use crate::sevenz_backend::{SevenZCreateOptions, SevenZCreateReport};
use crate::tar_zst_backend::{self, TarZstdCreateOptions, TarZstdError, TarZstdExtractReport};
use crate::tzap_backend::{self, TzapCreateOptions, TzapCreateReport, TzapError};
use crate::zip_backend::{self, ZipBackendError, ZipCreateOptions, ZipCreateReport};
use crate::{
    libarchive_backend,
    libarchive_backend::LibarchiveError,
    rar_backend,
    rar_backend::RarBackendError,
    raw_stream_backend,
    raw_stream_backend::{RawStreamError, RawStreamFormat},
    sevenz_backend,
    sevenz_backend::SevenZError,
};
use std::path::{Path, PathBuf};

/// Runs one normalized engine creation job for multiple source roots.
pub fn run_engine_create_job_from_sources(
    sources: &[PathBuf],
    destination: impl AsRef<Path>,
    options: &CreateOptions,
    plan_options: &PlanOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<CreateReport, crate::engine::ArchiveError> {
    let manifest = match plan_archives(sources, plan_options) {
        Ok(manifest) => manifest,
        Err(error) => {
            let error = crate::engine::ArchiveError::usable(crate::engine::ErrorKind::InvalidFormat, error.to_string());
            sink.emit(JobEvent::Failed { message: error.to_string() });
            return Err(error);
        }
    };
    let format = options.format();
    let kind = match format {
        FormatId::ZIP | FormatId::SPLIT_ZIP => JobKind::ZipCreate,
        FormatId::SEVEN_Z => JobKind::SevenZCreate,
        FormatId::TAR_ZST => JobKind::TarZstdCreate,
        FormatId::TAR_GZ => JobKind::TarGzCreate,
        FormatId::TZAP => JobKind::TzapCreate,
        FormatId::APPLE_ARCHIVE => JobKind::AppleArchiveCreate,
        _ => JobKind::ArchiveExtract,
    };
    sink.emit(JobEvent::Started { kind, total_bytes: Some(manifest.total_bytes) });
    let mut context = JobContext::new_with_progress_total(token, sink, Some(manifest.total_bytes));
    let request = CreateRequest::new(manifest, destination.as_ref().to_path_buf(), options.clone());
    let result = create_default_engine().and_then(|engine| engine.create(&request, &mut context));
    context.flush_progress();
    match result {
        Ok(report) => {
            for warning in &report.warnings {
                sink.emit(JobEvent::Warning { message: warning.clone() });
            }
            sink.emit(JobEvent::Completed { entries: usize::try_from(report.written_entries).unwrap_or(usize::MAX), bytes: report.written_bytes });
            Ok(report)
        }
        Err(error) => {
            if error.kind == crate::engine::ErrorKind::Cancelled {
                sink.emit(JobEvent::Cancelled { message: error.message.clone() });
            } else {
                sink.emit(JobEvent::Failed { message: error.to_string() });
            }
            Err(error)
        }
    }
}

/// Runs a ZIP create job for multiple source roots with explicit planning
/// options and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave a partial destination archive.
/// Atomic cleanup is deferred to hardening work.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when planning, ZIP creation, filesystem I/O, or
/// cancellation fails.
pub fn run_zip_create_job_from_sources_with_plan_options(
    sources: &[PathBuf],
    destination: impl AsRef<Path>,
    options: &ZipCreateOptions,
    plan_options: &PlanOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<ZipCreateReport, ZipBackendError> {
    let manifest = match plan_archives(sources, plan_options) {
        Ok(manifest) => manifest,
        Err(error) => {
            let error = ZipBackendError::Plan(error);
            sink.emit(JobEvent::Started { kind: JobKind::ZipCreate, total_bytes: None });
            sink.emit(JobEvent::Failed { message: error.to_string() });
            return Err(error);
        }
    };
    sink.emit(JobEvent::Started { kind: JobKind::ZipCreate, total_bytes: Some(manifest.total_bytes) });
    let mut context = JobContext::new_with_progress_total(token, sink, Some(manifest.total_bytes));
    let result = zip_backend::create_zip_from_manifest_with_context(&manifest, destination, options, &mut context);
    context.flush_progress();
    finish_zip_create_result(result, sink)
}

/// Runs a ZIP extract job and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave already-extracted files in the
/// destination directory.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when ZIP reading, extraction safety,
/// filesystem I/O, or cancellation fails.
/// Runs a ZIP extract job with an optional password and explicit extraction
/// policy while emitting lifecycle/progress events.
///
/// Partial output state: cancellation can leave already-extracted files in the
/// destination directory.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when ZIP reading, password validation,
/// extraction safety, filesystem I/O, or cancellation fails.
pub fn run_zip_extract_job_with_password_and_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<zip_backend::ZipExtractReport, ZipBackendError> {
    sink.emit(JobEvent::Started { kind: JobKind::ZipExtract, total_bytes: None });
    let mut context = JobContext::new(token, sink);
    let result = zip_backend::extract_zip_with_context_and_password(archive_path, destination, policy, password, &mut context);
    context.flush_progress();
    finish_zip_extract_result(result, sink)
}

/// Runs a TAR.ZST create job for multiple source roots with explicit planning
/// options and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave a partial destination archive.
///
/// # Errors
///
/// Returns [`TarZstdError`] when planning, TAR.ZST creation, filesystem I/O, or
/// cancellation fails.
pub fn run_tar_zst_create_job_from_sources_with_plan_options(
    sources: &[PathBuf],
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
    plan_options: &PlanOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<tar_zst_backend::TarZstdCreateReport, TarZstdError> {
    let manifest = match plan_archives(sources, plan_options) {
        Ok(manifest) => manifest,
        Err(error) => {
            let error = TarZstdError::Plan(error);
            sink.emit(JobEvent::Started { kind: JobKind::TarZstdCreate, total_bytes: None });
            sink.emit(JobEvent::Failed { message: error.to_string() });
            return Err(error);
        }
    };
    sink.emit(JobEvent::Started { kind: JobKind::TarZstdCreate, total_bytes: Some(manifest.total_bytes) });
    let mut context = JobContext::new_with_progress_total(token, sink, Some(manifest.total_bytes));
    let result = tar_zst_backend::create_tar_zst_from_manifest_with_context(&manifest, destination, options, &mut context);
    context.flush_progress();
    finish_tar_zst_create_result(result, sink)
}

/// Runs a TAR.GZ create job for multiple source roots with explicit planning
/// options and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave a partial destination archive.
///
/// # Errors
///
/// Returns [`TarGzError`] when planning, TAR.GZ creation, filesystem I/O, or
/// cancellation fails.
/// Runs a 7z create job for multiple source roots with explicit planning
/// options and emits lifecycle events.
///
/// Partial output state: cancellation during 7z encoding is backend-limited.
///
/// # Errors
///
/// Returns [`SevenZError`] when planning, filesystem reads, or 7z writing fails.
pub fn run_7z_create_job_from_sources_with_plan_options(
    sources: &[PathBuf],
    destination: impl AsRef<Path>,
    options: &SevenZCreateOptions,
    plan_options: &PlanOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<SevenZCreateReport, SevenZError> {
    let manifest = match plan_archives(sources, plan_options) {
        Ok(manifest) => manifest,
        Err(error) => {
            let error = SevenZError::Plan(error);
            sink.emit(JobEvent::Started { kind: JobKind::SevenZCreate, total_bytes: None });
            sink.emit(JobEvent::Failed { message: error.to_string() });
            return Err(error);
        }
    };
    sink.emit(JobEvent::Started { kind: JobKind::SevenZCreate, total_bytes: Some(manifest.total_bytes) });
    let mut context = JobContext::new_with_progress_total(token, sink, Some(manifest.total_bytes));
    let result = sevenz_backend::create_7z_from_manifest_with_context(&manifest, destination, options, &mut context);
    context.flush_progress();
    finish_7z_create_result(result, sink)
}

/// Emits the terminal lifecycle events for one backend result and returns it.
///
/// `emit_warnings:` re-emits the report's warnings before completion for
/// extract backends. `cancelled:` names the error type's `Cancelled` variant,
/// adding the dedicated cancelled arm. (Error types whose `Cancelled` variant
/// carries a payload — `TarGzError` — keep a hand-written helper.)
macro_rules! finish_result {
    ($name:ident, $report:ty, $error:path, emit_warnings: $emit_warnings:expr, cancelled: $cancelled:path) => {
        fn $name(result: Result<$report, $error>, sink: &mut dyn JobEventSink) -> Result<$report, $error> {
            match result {
                Ok(report) => {
                    if $emit_warnings {
                        for warning in &report.warnings {
                            sink.emit(JobEvent::Warning { message: warning.clone() });
                        }
                    }
                    sink.emit(JobEvent::Completed { entries: report.written_entries, bytes: report.written_bytes });
                    Ok(report)
                }
                Err($cancelled) => {
                    sink.emit(JobEvent::Cancelled { message: "job cancelled".to_owned() });
                    Err($cancelled)
                }
                Err(error) => {
                    sink.emit(JobEvent::Failed { message: error.to_string() });
                    Err(error)
                }
            }
        }
    };
}

/// Same as [`finish_result!`] for error types without a `Cancelled` variant
/// (RAR and raw-stream backends).
macro_rules! finish_result_no_cancelled {
    ($name:ident, $report:ty, $error:path, emit_warnings: $emit_warnings:expr) => {
        fn $name(result: Result<$report, $error>, sink: &mut dyn JobEventSink) -> Result<$report, $error> {
            match result {
                Ok(report) => {
                    if $emit_warnings {
                        for warning in &report.warnings {
                            sink.emit(JobEvent::Warning { message: warning.clone() });
                        }
                    }
                    sink.emit(JobEvent::Completed { entries: report.written_entries, bytes: report.written_bytes });
                    Ok(report)
                }
                Err(error) => {
                    sink.emit(JobEvent::Failed { message: error.to_string() });
                    Err(error)
                }
            }
        }
    };
}

finish_result!(finish_7z_create_result, SevenZCreateReport, SevenZError, emit_warnings: false, cancelled: SevenZError::Cancelled);

/// Runs a TZAP create job for multiple source roots with explicit planning
/// options and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave a partial destination archive.
///
/// # Errors
///
/// Returns [`TzapError`] when planning, TZAP creation, filesystem I/O,
/// password key derivation, or cancellation fails.
pub fn run_tzap_create_job_from_sources_with_plan_options(
    sources: &[PathBuf],
    destination: impl AsRef<Path>,
    options: &TzapCreateOptions,
    plan_options: &PlanOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<TzapCreateReport, TzapError> {
    let manifest = match plan_archives(sources, plan_options) {
        Ok(manifest) => manifest,
        Err(error) => {
            let error = TzapError::Plan(error);
            sink.emit(JobEvent::Started { kind: JobKind::TzapCreate, total_bytes: None });
            sink.emit(JobEvent::Failed { message: error.to_string() });
            return Err(error);
        }
    };
    sink.emit(JobEvent::Started { kind: JobKind::TzapCreate, total_bytes: Some(manifest.total_bytes) });
    let mut context = JobContext::new_with_progress_total(token, sink, Some(manifest.total_bytes));
    let result = tzap_backend::create_tzap_from_manifest_with_context(&manifest, destination, options, &mut context);
    context.flush_progress();
    finish_tzap_create_result(result, sink)
}

/// Runs a TAR.ZST extract job with an explicit extraction policy while emitting
/// lifecycle/progress events.
///
/// Partial output state: cancellation can leave already-extracted files in the
/// destination directory.
///
/// # Errors
///
/// Returns [`TarZstdError`] when TAR.ZST reading, extraction safety,
/// filesystem I/O, or cancellation fails.
pub fn run_tar_zst_extract_job_with_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<TarZstdExtractReport, TarZstdError> {
    let total_bytes = tar_zst_backend::estimate_tar_zst_uncompressed_size(&archive_path).ok();
    sink.emit(JobEvent::Started { kind: JobKind::TarZstdExtract, total_bytes });
    let mut context = JobContext::new_with_progress_total(token, sink, total_bytes);
    let result = tar_zst_backend::extract_tar_zst_with_context(archive_path, destination, policy, &mut context);
    context.flush_progress();
    finish_tar_zst_extract_result(result, sink)
}

/// Runs an `AppleArchive` extract job with an explicit extraction policy while
/// emitting lifecycle/progress events.
///
/// Partial output state: cancellation can leave already-extracted files in the
/// destination directory.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when `AppleArchive` reading, extraction safety,
/// filesystem I/O, or cancellation fails.
pub fn run_apple_archive_extract_job_with_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<apple_archive_backend::AppleArchiveExtractReport, AppleArchiveError> {
    sink.emit(JobEvent::Started { kind: JobKind::AppleArchiveExtract, total_bytes: None });
    let mut context = JobContext::new(token, sink);
    let result = apple_archive_backend::extract_apple_archive_with_context(
        archive_path,
        destination,
        policy,
        None, // password handled via native AppleArchive prompt if needed
        &mut context,
    );
    context.flush_progress();
    finish_apple_archive_extract_result(result, sink)
}

/// Runs a 7z extract job with an optional password and explicit extraction
/// policy while emitting lifecycle events.
///
/// Partial output state: cancellation is checked before extraction starts, but
/// 7z extraction itself is synchronous in this v1 adapter.
///
/// # Errors
///
/// Returns [`SevenZError`] when 7z reading, password validation, extraction
/// safety, or filesystem I/O fails.
pub fn run_7z_extract_job_with_password_and_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<sevenz_backend::SevenZExtractReport, SevenZError> {
    if let Some(source) = pre_start_cancelled(token, sink) {
        return Err(SevenZError::Io { path: archive_path.as_ref().to_path_buf(), source });
    }

    sink.emit(JobEvent::Started { kind: JobKind::SevenZExtract, total_bytes: None });

    let mut context = JobContext::new(token, sink);
    let result = sevenz_backend::extract_7z_with_context(archive_path, destination, password, policy, &mut context);
    context.flush_progress();
    finish_7z_extract_result(result, sink)
}

/// Runs a RAR extract job with an optional password and explicit extraction
/// policy while emitting lifecycle events.
///
/// Partial output state: cancellation is checked before extraction starts, but
/// RAR extraction itself is synchronous in this v1 adapter.
///
/// # Errors
///
/// Returns [`RarBackendError`] when bundled `UnRAR` reading, password validation,
/// extraction safety, or filesystem I/O fails.
pub fn run_rar_extract_job_with_password_and_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<rar_backend::RarExtractReport, RarBackendError> {
    if let Some(source) = pre_start_cancelled(token, sink) {
        return Err(RarBackendError::Io { path: archive_path.as_ref().to_path_buf(), source });
    }

    let listing = match rar_backend::list_rar_with_password(&archive_path, password) {
        Ok(listing) => listing,
        Err(error) => {
            // The listing is what determines the extraction entry set; a
            // listing failure (bad password, corrupt archive) must surface
            // instead of silently falling back to a full extraction.
            sink.emit(JobEvent::Started { kind: JobKind::RarExtract, total_bytes: None });
            sink.emit(JobEvent::Failed { message: error.to_string() });
            return Err(error);
        }
    };
    let total_bytes: Option<u64> = Some(listing.entries.iter().map(|entry| entry.size).sum());
    sink.emit(JobEvent::Started { kind: JobKind::RarExtract, total_bytes });

    let entries = listing.entries.into_iter().map(rar_backend::RarListEntry::into_unrar_entry).collect::<Vec<_>>();
    let mut context = JobContext::new_with_progress_total(token, sink, total_bytes);
    let result = rar_backend::extract_rar_entries_with_password_and_context(archive_path, destination, policy, password, entries, &mut context);
    context.flush_progress();
    finish_rar_extract_result(result, sink)
}

/// Runs a broad libarchive extract job with an optional password and explicit
/// extraction policy while emitting coarse lifecycle events.
///
/// Partial output state: cancellation is checked before extraction starts, but
/// libarchive extraction itself is synchronous in this v1 adapter.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when libarchive reading, password validation,
/// extraction safety, or filesystem I/O fails.
pub fn run_libarchive_extract_job_with_password_and_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<libarchive_backend::LibarchiveExtractReport, LibarchiveError> {
    if let Some(source) = pre_start_cancelled(token, sink) {
        return Err(LibarchiveError::Io { path: archive_path.as_ref().to_path_buf(), source });
    }

    sink.emit(JobEvent::Started { kind: JobKind::ArchiveExtract, total_bytes: None });

    let mut context = JobContext::new(token, sink);
    let result = libarchive_backend::extract_archive_with_password_and_context(archive_path, destination, policy, password, &mut context);
    context.flush_progress();
    finish_libarchive_extract_result(result, sink)
}

/// Runs a raw single-file stream extract job with an explicit extraction policy
/// while emitting coarse lifecycle events.
///
/// Partial output state: cancellation is checked before extraction starts, but
/// raw stream extraction itself is synchronous in this v1 adapter.
///
/// # Errors
///
/// Returns [`RawStreamError`] when stream decoding, extraction safety, or
/// filesystem I/O fails.
pub fn run_raw_stream_extract_job_with_policy(
    archive_path: impl AsRef<Path>,
    format: RawStreamFormat,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<raw_stream_backend::RawStreamExtractReport, RawStreamError> {
    let archive_path = archive_path.as_ref();
    let estimated_total_bytes = raw_stream_backend::estimate_raw_stream_uncompressed_size(archive_path, format);
    let source_size = archive_path.metadata().ok().map(|metadata| metadata.len());
    let track_source_progress =
        estimated_total_bytes.is_none() && raw_stream_backend::can_track_source_progress(format) && source_size.is_some_and(|size| size > 0);
    let total_bytes = if estimated_total_bytes.is_some() {
        estimated_total_bytes
    } else if track_source_progress {
        source_size
    } else {
        None
    };
    if let Some(source) = pre_start_cancelled(token, sink) {
        return Err(RawStreamError::Io { path: archive_path.to_path_buf(), source });
    }
    sink.emit(JobEvent::Started { kind: JobKind::RawStreamExtract, total_bytes });

    let mut context = JobContext::new_with_progress_total(token, sink, total_bytes);
    let progress_path = archive_path.to_string_lossy().into_owned();
    let result = raw_stream_backend::extract_raw_stream_with_progress(
        archive_path,
        format,
        destination,
        policy,
        Some(&mut |bytes| context.bytes_processed(Some(&progress_path), bytes)),
        track_source_progress,
    );
    context.flush_progress();
    finish_raw_stream_extract_result(result, sink)
}

/// Runs a TZAP extract job with a required password and explicit extraction
/// policy while emitting lifecycle/progress events.
///
/// Partial output state: cancellation can leave already-extracted files in the
/// destination directory.
///
/// # Errors
///
/// Returns [`TzapError`] when the password is missing, TZAP reading,
/// extraction safety, filesystem I/O, or cancellation fails.
pub fn run_tzap_extract_job_with_password_and_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<tzap_backend::TzapExtractReport, TzapError> {
    run_tzap_extract_job_with_password_and_policy_and_restore_options(
        archive_path,
        destination,
        password,
        policy,
        tzap_backend::TzapRestoreOptions::default(),
        token,
        sink,
    )
}

/// Runs a TZAP extract job with explicit archive safety and metadata restoration policies.
///
/// # Errors
///
/// Returns [`TzapError`] when TZAP reading, extraction safety, requested
/// metadata restoration, filesystem I/O, or cancellation fails.
pub fn run_tzap_extract_job_with_password_and_policy_and_restore_options(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    restore_options: tzap_backend::TzapRestoreOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<tzap_backend::TzapExtractReport, TzapError> {
    if pre_start_cancelled(token, sink).is_some() {
        return Err(TzapError::Cancelled);
    }
    sink.emit(JobEvent::Started { kind: JobKind::TzapExtract, total_bytes: None });

    let mut context = JobContext::new(token, sink);
    let key = match password {
        Some(password) => tzap_backend::TzapExtractKeySource::Password(password),
        None => tzap_backend::TzapExtractKeySource::None,
    };
    let result = tzap_backend::extract_tzap(
        tzap_backend::TzapExtractRequest { key, policy, restore_options, overwrite_resolver: None, context: Some(&mut context), fast: true },
        archive_path,
        destination,
    );
    context.flush_progress();
    finish_tzap_extract_result(result, sink)
}

/// Standardized pre-start cancellation check (CR-088): emits `Cancelled`
/// before the job reports `Started` and returns the error to return, or
/// `None` to proceed. All `run_*_job` entry points use this so event
/// consumers see one protocol regardless of backend.
fn pre_start_cancelled(token: &CancellationToken, sink: &mut dyn JobEventSink) -> Option<std::io::Error> {
    if token.is_cancelled() {
        sink.emit(JobEvent::Cancelled { message: "job cancelled".to_owned() });
        Some(std::io::Error::new(std::io::ErrorKind::Interrupted, "job cancelled"))
    } else {
        None
    }
}

finish_result!(finish_zip_create_result, ZipCreateReport, ZipBackendError, emit_warnings: false, cancelled: ZipBackendError::Cancelled);

finish_result!(finish_tzap_create_result, TzapCreateReport, TzapError, emit_warnings: false, cancelled: TzapError::Cancelled);

finish_result!(finish_tzap_extract_result, tzap_backend::TzapExtractReport, TzapError, emit_warnings: false, cancelled: TzapError::Cancelled);

finish_result!(finish_apple_archive_extract_result, apple_archive_backend::AppleArchiveExtractReport, AppleArchiveError, emit_warnings: true, cancelled: AppleArchiveError::Cancelled);

finish_result!(finish_zip_extract_result, zip_backend::ZipExtractReport, ZipBackendError, emit_warnings: false, cancelled: ZipBackendError::Cancelled);

finish_result!(finish_tar_zst_create_result, tar_zst_backend::TarZstdCreateReport, TarZstdError, emit_warnings: false, cancelled: TarZstdError::Cancelled);

finish_result!(finish_tar_zst_extract_result, TarZstdExtractReport, TarZstdError, emit_warnings: false, cancelled: TarZstdError::Cancelled);

finish_result!(finish_7z_extract_result, sevenz_backend::SevenZExtractReport, SevenZError, emit_warnings: true, cancelled: SevenZError::Cancelled);

finish_result_no_cancelled!(finish_rar_extract_result, rar_backend::RarExtractReport, RarBackendError, emit_warnings: true);

finish_result_no_cancelled!(finish_libarchive_extract_result, libarchive_backend::LibarchiveExtractReport, LibarchiveError, emit_warnings: true);

finish_result_no_cancelled!(finish_raw_stream_extract_result, raw_stream_backend::RawStreamExtractReport, RawStreamError, emit_warnings: true);
