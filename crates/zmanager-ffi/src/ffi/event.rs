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
            let error = BridgeError {
                code: ERROR_OPERATION_FAILED.to_string(),
                message: message.clone(),
                recovery_hint: None,
                severity: BridgeSeverity::Error,
                retryable: false,
            };
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
        error: Some(BridgeError {
            code: ERROR_CANCELLED.to_string(),
            message: "Job was cancelled.".to_string(),
            recovery_hint: None,
            severity: BridgeSeverity::Info,
            retryable: true,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zmanager_core::jobs::JobKind as CoreJobKind;

    #[test]
    fn test_mobile_events_from_core_events() {
        // Started
        let started = mobile_event_from_core_event(CoreJobEvent::Started { kind: CoreJobKind::ArchiveExtract, total_bytes: Some(1024) }).unwrap();
        assert_eq!(started.event_type, MobileJobEventKind::Started);
        assert_eq!(started.total_bytes, Some(1024));

        // EntryStarted
        let entry_start = mobile_event_from_core_event(CoreJobEvent::EntryStarted { path: "file.txt".to_string(), bytes: Some(100) }).unwrap();
        assert_eq!(entry_start.event_type, MobileJobEventKind::EntryStarted);
        assert_eq!(entry_start.path, Some("file.txt".to_string()));

        // BytesProcessed
        let bytes_proc = mobile_event_from_core_event(CoreJobEvent::BytesProcessed {
            path: Some("file.txt".to_string()),
            recent_paths: vec!["file.txt".to_string()],
            recent_path_identities: vec![],
            bytes: 50,
            total_bytes_processed: 50,
            entries: 1,
            total_entries_processed: 1,
            recent_paths_truncated: false,
        })
        .unwrap();
        assert_eq!(bytes_proc.event_type, MobileJobEventKind::BytesProcessed);
        assert_eq!(bytes_proc.bytes, Some(50));

        // EntryFinished
        let entry_fin = mobile_event_from_core_event(CoreJobEvent::EntryFinished { path: "file.txt".to_string(), bytes: 100 }).unwrap();
        assert_eq!(entry_fin.event_type, MobileJobEventKind::EntryFinished);

        // Warning
        let warning = mobile_event_from_core_event(CoreJobEvent::Warning { message: "warning msg".to_string() }).unwrap();
        assert_eq!(warning.event_type, MobileJobEventKind::Warning);

        // Completed
        let completed = mobile_event_from_core_event(CoreJobEvent::Completed { entries: 5, bytes: 500 }).unwrap();
        assert_eq!(completed.event_type, MobileJobEventKind::Completed);
        assert_eq!(completed.entries, Some(5));

        // Failed
        let failed = mobile_event_from_core_event(CoreJobEvent::Failed { message: "failure msg".to_string() }).unwrap();
        assert_eq!(failed.event_type, MobileJobEventKind::Failed);

        // Cancelled
        let cancelled = mobile_event_from_core_event(CoreJobEvent::Cancelled { message: "user cancel".to_string() }).unwrap();
        assert_eq!(cancelled.event_type, MobileJobEventKind::Cancelled);
    }
}
