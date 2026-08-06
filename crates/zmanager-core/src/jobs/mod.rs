//! Job model: event types, progress projection, cancellation, and the
//! per-backend job adapters.
//!
//! Split by concern (CR-139): the event/progress model lives here,
//! [`progress`] owns the coalescing machinery, [`cancellation`] owns the
//! token, and [`adapters`] owns the `run_*_job` wrappers around the archive
//! backends. This module re-exports their public items so the crate's API
//! surface is unchanged.

mod adapters;
mod cancellation;
mod progress;
#[cfg(test)]
mod tests;

pub use adapters::{
    run_7z_create_job_from_sources_with_plan_options, run_7z_extract_job_with_password_and_policy,
    run_apple_archive_extract_job_with_policy, run_libarchive_extract_job_with_password_and_policy,
    run_rar_extract_job_with_password_and_policy, run_raw_stream_extract_job_with_policy,
    run_tar_zst_create_job_from_sources_with_plan_options, run_tar_zst_extract_job_with_policy,
    run_tzap_create_job_from_sources_with_plan_options, run_tzap_extract_job_with_password_and_policy,
    run_tzap_extract_job_with_password_and_policy_and_restore_options,
    run_zip_create_job_from_sources_with_plan_options, run_zip_extract_job_with_password_and_policy,
};
pub use cancellation::{CancellationToken, JobCancelled};
pub use progress::{
    JobEventSink, JobProgressState, PROGRESS_PATH_DISPLAY_BYTES_LIMIT, PROGRESS_RECENT_PATH_BYTES_LIMIT,
    PROGRESS_RECENT_PATH_LIMIT,
};
#[cfg(test)]
pub(crate) use progress::{PROGRESS_ENTRY_STEP, PROGRESS_MIN_BYTE_STEP};
pub(crate) use progress::{ProgressBatch, ProgressCoalescer};

use self::progress::path_identity;
use std::collections::BTreeMap;

/// Bounded identity of an exact producer path whose display copy may be truncated.
pub type ProgressPathIdentity = [u8; 32];

/// Long-running job kind.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum JobKind {
    /// ZIP creation.
    ZipCreate,
    /// ZIP extraction.
    ZipExtract,
    /// 7z creation.
    SevenZCreate,
    /// 7z extraction.
    SevenZExtract,
    /// RAR extraction.
    RarExtract,
    /// TAR.ZST creation.
    TarZstdCreate,
    /// TAR.GZ creation.
    TarGzCreate,
    /// TAR.ZST extraction.
    TarZstdExtract,
    /// TZAP creation.
    TzapCreate,
    /// TZAP extraction.
    TzapExtract,
    /// `AppleArchive` creation.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    AppleArchiveCreate,
    /// `AppleArchive` extraction.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    AppleArchiveExtract,
    /// Broad libarchive-backed extraction.
    ArchiveExtract,
    /// Raw single-file stream extraction.
    RawStreamExtract,
}

/// One observable phase of an archive job.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum JobPhase {
    /// Read and compress source payloads to determine the archive layout.
    PlanningPayload,
    /// Build indexes and metadata after the payload layout is known.
    PlanningMetadata,
    /// Read, compress, protect, and write payload blocks.
    EmittingPayload,
    /// Protect and write indexes, recovery metadata, footers, and trailers.
    EmittingMetadata,
    /// Publish temporary output files at their final paths.
    CommittingOutput,
}

/// Progress and lifecycle event emitted by archive jobs.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum JobEvent {
    /// Job started.
    Started {
        /// Job kind.
        kind: JobKind,
        /// Planned source bytes when known.
        total_bytes: Option<u64>,
    },
    /// An archive entry started processing.
    EntryStarted {
        /// Archive path.
        path: String,
        /// Entry bytes when known.
        bytes: Option<u64>,
    },
    /// Bytes were processed for an entry.
    BytesProcessed {
        /// Archive path when associated with a specific entry.
        path: Option<String>,
        /// Most recently active archive paths, capped by the producer.
        recent_paths: Vec<String>,
        /// Bounded identities of the exact producer paths corresponding to `recent_paths`.
        recent_path_identities: Vec<ProgressPathIdentity>,
        /// Incremental bytes processed by this event.
        bytes: u64,
        /// Total bytes processed so far by this job context.
        total_bytes_processed: u64,
        /// Incremental completed entries represented by this aggregate.
        entries: u64,
        /// Total completed entries so far in the job.
        total_entries_processed: u64,
        /// Whether any display path was truncated to satisfy the UTF-8 storage bound.
        recent_paths_truncated: bool,
    },
    /// A job entered a new observable phase.
    PhaseStarted {
        /// Newly active phase.
        phase: JobPhase,
        /// Total source bytes for this phase when known.
        total_bytes: Option<u64>,
    },
    /// Source bytes were processed within one observable phase.
    PhaseBytesProcessed {
        /// Active phase.
        phase: JobPhase,
        /// Archive path when associated with a specific entry.
        path: Option<String>,
        /// Most recently active archive paths, capped by the producer.
        recent_paths: Vec<String>,
        /// Bounded identities of the exact producer paths corresponding to `recent_paths`.
        recent_path_identities: Vec<ProgressPathIdentity>,
        /// Incremental bytes processed by this event.
        bytes: u64,
        /// Total bytes processed so far within this phase.
        total_bytes_processed: u64,
        /// Total source bytes for this phase when known.
        total_bytes: Option<u64>,
        /// Whether any display path was truncated to satisfy the UTF-8 storage bound.
        recent_paths_truncated: bool,
    },
    /// An archive entry finished processing.
    EntryFinished {
        /// Archive path.
        path: String,
        /// Entry bytes processed.
        bytes: u64,
    },
    /// Non-fatal warning.
    Warning {
        /// Warning message.
        message: String,
    },
    /// Job completed successfully.
    Completed {
        /// Entries written or extracted.
        entries: usize,
        /// Bytes written or extracted.
        bytes: u64,
    },
    /// Job failed.
    Failed {
        /// Failure message.
        message: String,
    },
    /// Job was cancelled cooperatively.
    Cancelled {
        /// Cancellation message.
        message: String,
    },
}

/// Terminal outcome of a core archive execution.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum JobOutcome {
    /// The operation committed successfully.
    Completed,
    /// The operation failed.
    Failed,
    /// The operation observed cooperative cancellation before success.
    Cancelled,
}

pub struct JobContext<'a> {
    token: &'a CancellationToken,
    sink: &'a mut dyn JobEventSink,
    total_bytes_processed: u64,
    total_entries_processed: u64,
    progress: ProgressCoalescer,
    phase_bytes_processed: BTreeMap<JobPhase, u64>,
}

impl<'a> JobContext<'a> {
    /// Creates a context backed by a cancellation token and event sink.
    pub fn new(token: &'a CancellationToken, sink: &'a mut dyn JobEventSink) -> Self {
        Self::new_with_progress_total(token, sink, None)
    }

    /// Creates a context with a known logical byte total for progress batching.
    pub fn new_with_progress_total(
        token: &'a CancellationToken,
        sink: &'a mut dyn JobEventSink,
        total_bytes: Option<u64>,
    ) -> Self {
        Self {
            token,
            sink,
            total_bytes_processed: 0,
            total_entries_processed: 0,
            progress: ProgressCoalescer::new(total_bytes),
            phase_bytes_processed: BTreeMap::new(),
        }
    }

    /// Emits an event.
    pub fn emit(&mut self, event: JobEvent) {
        self.sink.emit(event);
    }

    /// Emits an entry-started event carrying the entry's known byte size.
    ///
    /// Backends pass real sizes where they know them (for example the TZAP
    /// modules), so the event carries them rather than discarding them.
    pub fn entry_started(&mut self, path: impl Into<String>, bytes: Option<u64>) {
        let path = path.into();
        self.emit(JobEvent::EntryStarted { path: path.clone(), bytes });
        // Entry accounting and recent-path tracking happen in `entry_finished`;
        // a `record_activity(0, 0)` here would be a no-op by the coalescer's
        // early return on zero bytes and entries.
    }

    /// Emits an entry-finished event carrying the processed byte count and
    /// accounts one completed entry, matching the backends' own emit paths.
    pub fn entry_finished(&mut self, path: impl Into<String>, bytes: u64) {
        self.total_entries_processed = self.total_entries_processed.saturating_add(1);
        let path = path.into();
        self.emit(JobEvent::EntryFinished { path: path.clone(), bytes });
        if let Some(batch) = self.progress.record_activity(Some(&path), 0, 1) {
            self.emit_bytes_processed_batch(batch);
        }
    }

    /// Emits a warning event.
    pub fn warning(&mut self, message: impl Into<String>) {
        self.emit(JobEvent::Warning { message: message.into() });
    }

    /// Emits a bytes-processed event and updates cumulative progress.
    pub fn bytes_processed(&mut self, path: Option<&str>, bytes: u64) {
        self.total_bytes_processed = self.total_bytes_processed.saturating_add(bytes);
        if let Some(batch) = self.progress.record(path, bytes) {
            self.emit_bytes_processed_batch(batch);
        }
    }

    /// Flushes pending format-neutral byte progress.
    pub fn flush_progress(&mut self) {
        if let Some(batch) = self.progress.flush() {
            self.emit_bytes_processed_batch(batch);
        }
    }

    fn emit_bytes_processed_batch(&mut self, batch: ProgressBatch) {
        self.emit(JobEvent::BytesProcessed {
            path: batch.path,
            recent_paths: batch.recent_paths,
            recent_path_identities: batch.recent_path_identities,
            bytes: batch.bytes,
            total_bytes_processed: self.total_bytes_processed,
            entries: batch.entries,
            total_entries_processed: self.total_entries_processed,
            recent_paths_truncated: batch.recent_paths_truncated,
        });
    }

    /// Emits a phase-started event and resets that phase's byte counter.
    pub fn phase_started(&mut self, phase: JobPhase, total_bytes: Option<u64>) {
        self.flush_progress();
        self.phase_bytes_processed.insert(phase, 0);
        self.emit(JobEvent::PhaseStarted { phase, total_bytes });
    }

    /// Emits phase-scoped byte progress with a capped recent-path activity list.
    pub fn phase_bytes_processed_with_recent_paths(
        &mut self,
        phase: JobPhase,
        path: Option<&str>,
        recent_paths: Vec<String>,
        bytes: u64,
        total_bytes: Option<u64>,
        recent_paths_truncated: bool,
    ) {
        let recent_path_identities = recent_paths.iter().map(|path| path_identity(path)).collect();
        self.phase_bytes_processed_with_path_identities(
            phase,
            path,
            recent_paths,
            recent_path_identities,
            bytes,
            total_bytes,
            recent_paths_truncated,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn phase_bytes_processed_with_path_identities(
        &mut self,
        phase: JobPhase,
        path: Option<&str>,
        recent_paths: Vec<String>,
        recent_path_identities: Vec<ProgressPathIdentity>,
        bytes: u64,
        total_bytes: Option<u64>,
        recent_paths_truncated: bool,
    ) {
        let total_bytes_processed = {
            let processed = self.phase_bytes_processed.entry(phase).or_default();
            *processed = processed.saturating_add(bytes);
            *processed
        };
        self.emit(JobEvent::PhaseBytesProcessed {
            phase,
            path: path.map(ToOwned::to_owned),
            recent_paths,
            recent_path_identities,
            bytes,
            total_bytes_processed,
            total_bytes,
            recent_paths_truncated,
        });
    }

    /// Returns an error if cancellation was requested.
    ///
    /// # Errors
    ///
    /// Returns [`JobCancelled`] when the shared token has been cancelled.
    pub fn check_cancelled(&self) -> Result<(), JobCancelled> {
        if self.token.is_cancelled() { Err(JobCancelled) } else { Ok(()) }
    }

    /// Returns a clone of the cancellation token for reader adapters that
    /// cannot hold a borrow of the full job context.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.token.clone()
    }
}
