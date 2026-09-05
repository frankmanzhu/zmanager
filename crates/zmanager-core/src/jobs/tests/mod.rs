use super::{CancellationToken, JobEvent, JobKind, JobOutcome, JobPhase, JobProgressState, PROGRESS_ENTRY_STEP, ProgressCoalescer};
use crate::engine::CreateOptions;
use crate::manifest::PlanOptions;
use crate::test_support::TestDir;
use std::time::{Duration, Instant};

#[test]
fn progress_projection_is_monotonic_bounded_and_terminal_is_immutable() {
    let mut state = JobProgressState::default();
    state.apply(&JobEvent::Started { kind: JobKind::ZipCreate, total_bytes: Some(10) });
    for index in 0..20 {
        state.apply(&JobEvent::BytesProcessed {
            path: Some(format!("file-{index}")),
            recent_paths: vec![],
            recent_path_identities: vec![],
            bytes: 1,
            total_bytes_processed: index + 1,
            entries: 0,
            total_entries_processed: 0,
            recent_paths_truncated: false,
        });
    }
    state.apply(&JobEvent::Completed { entries: 20, bytes: 20 });
    let terminal = state.clone();
    state.apply(&JobEvent::Failed { message: "late".into() });
    assert_eq!(state, terminal);
    assert_eq!(state.outcome, Some(JobOutcome::Completed));
    assert_eq!(state.processed_bytes, 20);
    assert_eq!(state.recent_paths.len(), super::PROGRESS_RECENT_PATH_LIMIT);
    assert_eq!(state.current_path.as_deref(), Some("file-19"));
}

#[test]
fn progress_projection_resets_only_phase_local_facts() {
    let mut state = JobProgressState::default();
    state.apply(&JobEvent::BytesProcessed {
        path: None,
        recent_paths: vec![],
        recent_path_identities: vec![],
        bytes: 5,
        total_bytes_processed: 5,
        entries: 0,
        total_entries_processed: 0,
        recent_paths_truncated: false,
    });
    state.apply(&JobEvent::PhaseStarted { phase: JobPhase::PlanningPayload, total_bytes: Some(8) });
    state.apply(&JobEvent::PhaseBytesProcessed {
        phase: JobPhase::PlanningPayload,
        path: None,
        recent_paths: vec![],
        recent_path_identities: vec![],
        bytes: 4,
        total_bytes_processed: 4,
        total_bytes: Some(8),
        recent_paths_truncated: false,
    });
    state.apply(&JobEvent::PhaseStarted { phase: JobPhase::EmittingPayload, total_bytes: Some(8) });
    assert_eq!(state.processed_bytes, 5);
    assert_eq!(state.phase_processed_bytes, 0);
}

#[test]
fn engine_create_job_emits_lifecycle_events() {
    let temp = TestDir::new("engine_create_job_emits_lifecycle_events");
    temp.write_file("project/file.txt", b"hello");
    let mut events = Vec::new();

    let report = super::adapters::run_engine_create_job_from_sources(
        &[temp.path("project")],
        temp.path("archive.zip"),
        &CreateOptions::Zip(crate::engine::ZipCreateOptions::default()),
        &PlanOptions::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    assert_eq!(report.written_bytes, 5);
    assert!(matches!(events.first(), Some(JobEvent::Started { kind: JobKind::ZipCreate, .. })));
    assert!(matches!(events.last(), Some(JobEvent::Completed { entries: 2, bytes: 5 })));
}

#[test]
fn engine_tzap_create_accepts_unicode_entry_names() {
    let temp = TestDir::new("engine_tzap_create_unicode_entry");
    temp.write_file("金庸-神雕侠侣txt精校版.txt", b"unicode filename");
    let mut events = Vec::new();

    let report = super::adapters::run_engine_create_job_from_sources(
        &[temp.path("金庸-神雕侠侣txt精校版.txt")],
        temp.path("unicode.tzap"),
        &CreateOptions::Tzap(crate::engine::TzapCreateOptions {
            key_source: crate::engine::TzapKeySource::NoPassword,
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: None,
            volume_count: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: None,
            emit_bootstrap_sidecar: false,
        }),
        &PlanOptions::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    assert_eq!(report.written_entries, 1);
    assert!(events.iter().any(|event| matches!(event, JobEvent::Completed { .. })));
}

#[test]
fn progress_coalescer_flushes_entry_and_time_thresholds_without_sleeping() {
    let start = Instant::now();
    let mut entries = ProgressCoalescer::new_at(None, start);
    assert!(entries.record_activity_at(Some("first"), 0, 1, start).is_some());
    for index in 0..(PROGRESS_ENTRY_STEP - 1) {
        assert!(entries.record_activity_at(Some("tiny"), 0, 1, start + Duration::from_millis(index)).is_none());
    }
    let batch = entries.record_activity_at(Some("tiny"), 0, 1, start + Duration::from_millis(PROGRESS_ENTRY_STEP - 1)).expect("entry threshold flush");
    assert_eq!(batch.entries, PROGRESS_ENTRY_STEP);
}
