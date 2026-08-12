//! Mapping of core job events to the mobile event model.

use zmanager_core::jobs::JobEvent as CoreJobEvent;

use crate::ffi::error::{ERROR_CANCELLED, ERROR_OPERATION_FAILED, bridge_warning};
use crate::ffi::ops::jobs::mobile_job_kind_from_core;
use crate::ffi::types::{BridgeError, BridgeSeverity, JobTerminalSummary, MobileJobEvent, MobileJobEventKind, usize_to_u64};

pub(crate) fn mobile_event_from_core_event(event: CoreJobEvent) -> Option<MobileJobEvent> {
    match event {
        CoreJobEvent::Started { kind, total_bytes } => Some(MobileJobEvent {
            sequence: 0,
            event_type: MobileJobEventKind::Started,
            job_kind: Some(mobile_job_kind_from_core(kind)),
            path: None,
            bytes: None,
            total_bytes,
            total_bytes_processed: None,
            entries: None,
            total_entries: None,
            message: None,
            error: None,
        }),
        CoreJobEvent::EntryStarted { path, bytes } => Some(MobileJobEvent {
            sequence: 0,
            event_type: MobileJobEventKind::EntryStarted,
            job_kind: None,
            path: Some(path),
            bytes,
            total_bytes: None,
            total_bytes_processed: None,
            entries: None,
            total_entries: None,
            message: None,
            error: None,
        }),
        CoreJobEvent::BytesProcessed { path, bytes, total_bytes_processed, .. } => Some(MobileJobEvent {
            sequence: 0,
            event_type: MobileJobEventKind::BytesProcessed,
            job_kind: None,
            path,
            bytes: Some(bytes),
            total_bytes: None,
            total_bytes_processed: Some(total_bytes_processed),
            entries: None,
            total_entries: None,
            message: None,
            error: None,
        }),
        CoreJobEvent::EntryFinished { path, bytes } => Some(MobileJobEvent {
            sequence: 0,
            event_type: MobileJobEventKind::EntryFinished,
            job_kind: None,
            path: Some(path),
            bytes: Some(bytes),
            total_bytes: None,
            total_bytes_processed: None,
            entries: None,
            total_entries: None,
            message: None,
            error: None,
        }),
        CoreJobEvent::Warning { message } => {
            let error = bridge_warning(message.clone());
            Some(MobileJobEvent {
                sequence: 0,
                event_type: MobileJobEventKind::Warning,
                job_kind: None,
                path: None,
                bytes: None,
                total_bytes: None,
                total_bytes_processed: None,
                entries: None,
                total_entries: None,
                message: Some(message),
                error: Some(error),
            })
        }
        CoreJobEvent::Completed { entries, bytes } => Some(MobileJobEvent {
            sequence: 0,
            event_type: MobileJobEventKind::Completed,
            job_kind: None,
            path: None,
            bytes: Some(bytes),
            total_bytes: None,
            total_bytes_processed: None,
            entries: Some(usize_to_u64(entries)),
            total_entries: None,
            message: None,
            error: None,
        }),
        CoreJobEvent::Failed { message } => {
            let error = BridgeError { code: ERROR_OPERATION_FAILED.to_string(), message: message.clone(), recovery_hint: None, severity: BridgeSeverity::Error, retryable: false };
            Some(MobileJobEvent {
                sequence: 0,
                event_type: MobileJobEventKind::Failed,
                job_kind: None,
                path: None,
                bytes: None,
                total_bytes: None,
                total_bytes_processed: None,
                entries: None,
                total_entries: None,
                message: Some(message),
                error: Some(error),
            })
        }
        CoreJobEvent::Cancelled { message } => Some(cancelled_event(message)),
        // TZAP jobs emit phase lifecycle events. The mobile event model has
        // no phase concept yet, so phase transitions are not surfaced (the
        // real job Started event already set the running status) and phase
        // byte progress is folded into the plain byte-progress stream with
        // all totals preserved. Add dedicated phase event kinds when the
        // mobile UI adopts them.
        CoreJobEvent::PhaseStarted { .. } => None,
        CoreJobEvent::PhaseBytesProcessed { path, bytes, total_bytes_processed, .. } => Some(MobileJobEvent {
            sequence: 0,
            event_type: MobileJobEventKind::BytesProcessed,
            job_kind: None,
            path,
            bytes: Some(bytes),
            total_bytes: None,
            total_bytes_processed: Some(total_bytes_processed),
            entries: None,
            total_entries: None,
            message: None,
            error: None,
        }),
    }
}

pub(crate) fn completed_event_from_summary(summary: &JobTerminalSummary) -> MobileJobEvent {
    MobileJobEvent {
        sequence: 0,
        event_type: MobileJobEventKind::Completed,
        job_kind: None,
        path: None,
        bytes: Some(summary.written_bytes),
        total_bytes: None,
        total_bytes_processed: None,
        entries: Some(summary.written_entries),
        total_entries: None,
        message: None,
        error: None,
    }
}

pub(crate) fn failed_event(error: BridgeError) -> MobileJobEvent {
    MobileJobEvent {
        sequence: 0,
        event_type: MobileJobEventKind::Failed,
        job_kind: None,
        path: None,
        bytes: None,
        total_bytes: None,
        total_bytes_processed: None,
        entries: None,
        total_entries: None,
        message: Some(error.message.clone()),
        error: Some(error),
    }
}

pub(crate) fn cancelled_event(message: String) -> MobileJobEvent {
    MobileJobEvent {
        sequence: 0,
        event_type: MobileJobEventKind::Cancelled,
        job_kind: None,
        path: None,
        bytes: None,
        total_bytes: None,
        total_bytes_processed: None,
        entries: None,
        total_entries: None,
        message: Some(message),
        error: Some(BridgeError { code: ERROR_CANCELLED.to_string(), message: "Job was cancelled.".to_string(), recovery_hint: None, severity: BridgeSeverity::Info, retryable: true }),
    }
}
