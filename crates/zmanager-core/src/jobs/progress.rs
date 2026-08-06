//! Progress projection and coalescing machinery (CR-139).
//!
//! [`JobProgressState`] is the runtime-neutral projection exposed to
//! consumers; [`ProgressCoalescer`] batches byte/entry events so sinks are
//! not flooded. The model types these operate on live in
//! [`crate::jobs`].

use crate::jobs::{JobEvent, JobOutcome, JobPhase, ProgressPathIdentity};
use sha2::{Digest as _, Sha256};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Runtime-neutral projection of the latest raw progress facts.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct JobProgressState {
    pub processed_bytes: u64,
    pub total_bytes: Option<u64>,
    pub processed_entries: u64,
    pub total_entries: Option<u64>,
    pub current_path: Option<String>,
    pub recent_paths: Vec<String>,
    pub active_phase: Option<JobPhase>,
    pub phase_processed_bytes: u64,
    pub phase_total_bytes: Option<u64>,
    pub warning_count: u64,
    pub outcome: Option<JobOutcome>,
    recent_path_identities: Vec<ProgressPathIdentity>,
}

impl JobProgressState {
    /// Applies one semantic event. The first terminal outcome is immutable.
    pub fn apply(&mut self, event: &JobEvent) {
        if self.outcome.is_some() {
            return;
        }
        match event {
            JobEvent::Started { total_bytes, .. } => self.total_bytes = *total_bytes,
            JobEvent::EntryStarted { path, .. } => self.record_path(path),
            JobEvent::BytesProcessed {
                path,
                recent_paths,
                recent_path_identities,
                total_bytes_processed,
                total_entries_processed,
                ..
            } => {
                self.processed_bytes = self.processed_bytes.max(*total_bytes_processed);
                self.processed_entries = self.processed_entries.max(*total_entries_processed);
                self.record_paths(path.as_deref(), recent_paths, recent_path_identities);
            }
            JobEvent::PhaseStarted { phase, total_bytes } => {
                self.active_phase = Some(*phase);
                self.phase_processed_bytes = 0;
                self.phase_total_bytes = *total_bytes;
            }
            JobEvent::PhaseBytesProcessed {
                phase,
                path,
                recent_paths,
                recent_path_identities,
                total_bytes_processed,
                total_bytes,
                ..
            } => {
                if self.active_phase != Some(*phase) {
                    self.active_phase = Some(*phase);
                    self.phase_processed_bytes = 0;
                }
                self.phase_processed_bytes = self.phase_processed_bytes.max(*total_bytes_processed);
                self.phase_total_bytes = *total_bytes;
                self.record_paths(path.as_deref(), recent_paths, recent_path_identities);
            }
            JobEvent::EntryFinished { path, .. } => {
                self.processed_entries = self.processed_entries.saturating_add(1);
                self.record_path(path);
            }
            JobEvent::Warning { .. } => self.warning_count = self.warning_count.saturating_add(1),
            JobEvent::Completed { entries, bytes } => {
                self.processed_entries = self.processed_entries.max(*entries as u64);
                self.processed_bytes = self.processed_bytes.max(*bytes);
                self.outcome = Some(JobOutcome::Completed);
            }
            JobEvent::Failed { .. } => self.outcome = Some(JobOutcome::Failed),
            JobEvent::Cancelled { .. } => self.outcome = Some(JobOutcome::Cancelled),
        }
    }

    fn record_paths(&mut self, current: Option<&str>, recent: &[String], identities: &[ProgressPathIdentity]) {
        for (index, path) in recent.iter().enumerate() {
            self.record_path_with_identity(path, identities.get(index).copied().unwrap_or_else(|| path_identity(path)));
        }
        if let Some(path) = current {
            let identity = recent
                .iter()
                .rposition(|candidate| candidate == path)
                .and_then(|index| identities.get(index))
                .copied()
                .unwrap_or_else(|| path_identity(path));
            self.record_path_with_identity(path, identity);
        }
    }

    fn record_path(&mut self, path: &str) {
        self.record_path_with_identity(path, path_identity(path));
    }

    fn record_path_with_identity(&mut self, path: &str, identity: ProgressPathIdentity) {
        let path = truncate_utf8(path, PROGRESS_PATH_DISPLAY_BYTES_LIMIT);
        if let Some(index) = self.recent_path_identities.iter().position(|candidate| *candidate == identity) {
            self.recent_paths.remove(index);
            self.recent_path_identities.remove(index);
        }
        self.recent_paths.push(path.clone());
        self.recent_path_identities.push(identity);
        if self.recent_paths.len() > PROGRESS_RECENT_PATH_LIMIT {
            self.recent_paths.remove(0);
            self.recent_path_identities.remove(0);
        }
        while self.recent_paths.iter().map(String::len).sum::<usize>() > PROGRESS_RECENT_PATH_BYTES_LIMIT {
            self.recent_paths.remove(0);
            self.recent_path_identities.remove(0);
        }
        self.current_path = Some(path);
    }
}

/// Consumer of job events.
pub trait JobEventSink {
    /// Receives one event.
    fn emit(&mut self, event: JobEvent);
}

impl<F> JobEventSink for F
where
    F: FnMut(JobEvent),
{
    fn emit(&mut self, event: JobEvent) {
        self(event);
    }
}

pub(crate) const PROGRESS_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const PROGRESS_MIN_BYTE_STEP: u64 = 4 * 1024 * 1024;
pub const PROGRESS_RECENT_PATH_LIMIT: usize = 10;
pub const PROGRESS_RECENT_PATH_BYTES_LIMIT: usize = 4 * 1024;
pub const PROGRESS_PATH_DISPLAY_BYTES_LIMIT: usize = PROGRESS_RECENT_PATH_BYTES_LIMIT / PROGRESS_RECENT_PATH_LIMIT;
pub(crate) const PROGRESS_ENTRY_STEP: u64 = 128;

pub(crate) struct ProgressBatch {
    pub(crate) path: Option<String>,
    pub(crate) recent_paths: Vec<String>,
    pub(crate) recent_path_identities: Vec<ProgressPathIdentity>,
    pub(crate) bytes: u64,
    pub(crate) entries: u64,
    pub(crate) recent_paths_truncated: bool,
}

pub(crate) struct ProgressCoalescer {
    total_bytes: Option<u64>,
    pending_bytes: u64,
    pending_entries: u64,
    latest_path: Option<String>,
    recent_paths: VecDeque<(ProgressPathIdentity, String)>,
    last_emitted: Instant,
    emitted_once: bool,
    recent_paths_truncated: bool,
}

impl ProgressCoalescer {
    pub(crate) fn new(total_bytes: Option<u64>) -> Self {
        Self::new_at(total_bytes, Instant::now())
    }

    pub(crate) fn new_at(total_bytes: Option<u64>, now: Instant) -> Self {
        Self {
            total_bytes,
            pending_bytes: 0,
            pending_entries: 0,
            latest_path: None,
            recent_paths: VecDeque::new(),
            last_emitted: now,
            emitted_once: false,
            recent_paths_truncated: false,
        }
    }

    pub(crate) fn reset(&mut self, total_bytes: Option<u64>) {
        self.reset_at(total_bytes, Instant::now());
    }

    pub(crate) fn reset_at(&mut self, total_bytes: Option<u64>, now: Instant) {
        self.total_bytes = total_bytes;
        self.pending_bytes = 0;
        self.pending_entries = 0;
        self.latest_path = None;
        self.recent_paths.clear();
        self.last_emitted = now;
        self.emitted_once = false;
        self.recent_paths_truncated = false;
    }

    pub(crate) fn record(&mut self, path: Option<&str>, bytes: u64) -> Option<ProgressBatch> {
        self.record_activity(path, bytes, 0)
    }

    pub(crate) fn record_activity(&mut self, path: Option<&str>, bytes: u64, entries: u64) -> Option<ProgressBatch> {
        self.record_activity_at(path, bytes, entries, Instant::now())
    }

    pub(crate) fn record_activity_at(
        &mut self,
        path: Option<&str>,
        bytes: u64,
        entries: u64,
        now: Instant,
    ) -> Option<ProgressBatch> {
        if bytes == 0 && entries == 0 {
            return None;
        }
        self.pending_bytes = self.pending_bytes.saturating_add(bytes);
        self.pending_entries = self.pending_entries.saturating_add(entries);
        if let Some(path) = path {
            self.recent_paths_truncated |= path.len() > PROGRESS_PATH_DISPLAY_BYTES_LIMIT;
            let identity = path_identity(path);
            let display_path = truncate_utf8(path, PROGRESS_PATH_DISPLAY_BYTES_LIMIT);
            if self.latest_path.as_deref() != Some(display_path.as_str()) {
                self.latest_path = Some(display_path.clone());
            }
            if self.recent_paths.back().is_none_or(|(recent_identity, _)| *recent_identity != identity) {
                if let Some(position) =
                    self.recent_paths.iter().position(|(recent_identity, _)| *recent_identity == identity)
                {
                    self.recent_paths.remove(position);
                }
                self.recent_paths.push_back((identity, display_path));
                if self.recent_paths.len() > PROGRESS_RECENT_PATH_LIMIT {
                    self.recent_paths.pop_front();
                }
                while self.recent_paths.iter().map(|(_, path)| path.len()).sum::<usize>()
                    > PROGRESS_RECENT_PATH_BYTES_LIMIT
                {
                    self.recent_paths.pop_front();
                    self.recent_paths_truncated = true;
                }
            }
        }

        let one_percent = self.total_bytes.unwrap_or_default().div_ceil(100);
        let byte_step = PROGRESS_MIN_BYTE_STEP.max(one_percent);
        if !self.emitted_once
            || self.pending_bytes >= byte_step
            || self.pending_entries >= PROGRESS_ENTRY_STEP
            || now.saturating_duration_since(self.last_emitted) >= PROGRESS_INTERVAL
        {
            self.flush_at(now)
        } else {
            None
        }
    }

    pub(crate) fn flush(&mut self) -> Option<ProgressBatch> {
        self.flush_at(Instant::now())
    }

    fn flush_at(&mut self, now: Instant) -> Option<ProgressBatch> {
        if self.pending_bytes == 0 && self.pending_entries == 0 {
            return None;
        }
        self.emitted_once = true;
        self.last_emitted = now;
        Some(ProgressBatch {
            path: self.latest_path.take(),
            recent_path_identities: self.recent_paths.iter().map(|(identity, _)| *identity).collect(),
            recent_paths: self.recent_paths.drain(..).map(|(_, path)| path).collect(),
            bytes: std::mem::take(&mut self.pending_bytes),
            entries: std::mem::take(&mut self.pending_entries),
            recent_paths_truncated: std::mem::take(&mut self.recent_paths_truncated),
        })
    }
}

fn truncate_utf8(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

pub(crate) fn path_identity(path: &str) -> ProgressPathIdentity {
    Sha256::digest(path.as_bytes()).into()
}
