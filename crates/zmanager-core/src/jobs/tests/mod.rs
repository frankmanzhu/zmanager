use super::{
    CancellationToken, JobEvent, JobOutcome, JobPhase, JobProgressState, PROGRESS_MIN_BYTE_STEP, ProgressCoalescer,
    run_7z_create_job_from_sources_with_plan_options, run_7z_extract_job_with_password_and_policy, run_raw_stream_extract_job_with_policy,
    run_tar_zst_create_job_from_sources_with_plan_options, run_tzap_create_job_from_sources_with_plan_options, run_tzap_extract_job_with_password_and_policy,
    run_zip_create_job_from_sources_with_plan_options, run_zip_extract_job_with_password_and_policy,
};
use crate::test_support::TestDir;

#[test]
fn progress_projection_is_monotonic_bounded_and_terminal_is_immutable() {
    let mut state = JobProgressState::default();
    state.apply(&JobEvent::Started { kind: super::JobKind::ZipCreate, total_bytes: Some(10) });
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
use crate::archive_browser::list_entries;
use crate::manifest::PlanOptions;
use crate::raw_stream_backend::RawStreamFormat;
use crate::safety::ExtractionPolicy;
use crate::sevenz_backend::{SevenZCreateOptions, SevenZError};
use crate::tar_zst_backend::TarZstdCreateOptions;
use crate::tzap_backend::{TzapCreateOptions, TzapKeySource};
use crate::zip_backend::{ZipBackendError, ZipCreateOptions, list_zip};
use bzip2::Compression;
use bzip2::write::BzEncoder;
use std::fs;
use std::io::Write as _;
use std::time::{Duration, Instant};

#[test]
fn progress_coalescer_flushes_entry_and_time_thresholds_without_sleeping() {
    let start = Instant::now();
    let mut entries = ProgressCoalescer::new_at(None, start);
    assert!(entries.record_activity_at(Some("first"), 0, 1, start).is_some());
    for index in 0..127 {
        assert!(entries.record_activity_at(Some("tiny"), 0, 1, start + Duration::from_millis(index)).is_none());
    }
    let batch = entries.record_activity_at(Some("tiny"), 0, 1, start + Duration::from_millis(127)).expect("128 entries flush");
    assert_eq!(batch.entries, super::PROGRESS_ENTRY_STEP);

    let mut timed = ProgressCoalescer::new_at(None, start);
    assert!(timed.record_activity_at(Some("first"), 1, 0, start).is_some());
    assert!(timed.record_activity_at(Some("pending"), 1, 0, start + Duration::from_millis(999)).is_none());
    assert!(timed.record_activity_at(Some("pending"), 1, 0, start + Duration::from_secs(1)).is_some());
}

#[test]
fn progress_paths_are_utf8_safe_and_storage_bounded() {
    let mut progress = ProgressCoalescer::new(None);
    let long = "界".repeat(super::PROGRESS_RECENT_PATH_BYTES_LIMIT);
    let batch = progress.record(Some(&long), 1).expect("first activity flushes");
    assert!(batch.recent_paths_truncated);
    assert!(batch.path.as_ref().unwrap().len() <= super::PROGRESS_RECENT_PATH_BYTES_LIMIT);
    assert!(batch.path.as_ref().unwrap().is_char_boundary(batch.path.as_ref().unwrap().len()));
}

#[test]
fn progress_paths_deduplicate_by_exact_source_before_display_truncation() {
    let mut progress = ProgressCoalescer::new_at(None, Instant::now());
    let common = "x".repeat(super::PROGRESS_RECENT_PATH_BYTES_LIMIT);
    let first = format!("{common}-first");
    let second = format!("{common}-second");
    let _ = progress.record(Some("warmup"), 1).expect("first activity flushes");
    assert!(progress.record(Some(&first), 1).is_none());
    let batch = progress.flush().expect("pending activity flushes");
    assert_eq!(batch.recent_paths.len(), 1);
    assert!(progress.record(Some(&first), 1).is_none());
    assert!(progress.record(Some(&second), 1).is_none());
    let batch = progress.flush().expect("distinct long paths flush");
    assert_eq!(batch.recent_paths.len(), 2);
    assert_ne!(batch.recent_path_identities[0], batch.recent_path_identities[1]);
    assert!(batch.recent_paths_truncated);

    let mut projection = JobProgressState::default();
    projection.apply(&JobEvent::BytesProcessed {
        path: batch.path,
        recent_paths: batch.recent_paths,
        recent_path_identities: batch.recent_path_identities,
        bytes: batch.bytes,
        total_bytes_processed: 3,
        entries: 0,
        total_entries_processed: 0,
        recent_paths_truncated: true,
    });
    assert_eq!(projection.recent_paths.len(), 2);
}

#[test]
fn job_context_preserves_truncation_and_flushes_before_phase_start() {
    let token = CancellationToken::new();
    let mut events = Vec::new();
    {
        let mut sink = |event| events.push(event);
        let mut context = super::JobContext::new(&token, &mut sink);
        context.bytes_processed(Some(&"界".repeat(super::PROGRESS_RECENT_PATH_BYTES_LIMIT)), 1);
        context.bytes_processed(Some("pending"), 1);
        context.phase_started(JobPhase::PlanningPayload, Some(2));
    }
    assert!(matches!(events.first(), Some(JobEvent::BytesProcessed { recent_paths_truncated: true, .. })));
    let pending = events
        .iter()
        .position(|event| matches!(event, JobEvent::BytesProcessed { path: Some(path), .. } if path == "pending"))
        .expect("pending logical progress flushed");
    let phase = events.iter().position(|event| matches!(event, JobEvent::PhaseStarted { .. })).expect("phase started");
    assert!(pending < phase);
}

#[test]
fn progress_coalescer_uses_one_percent_floor_and_caps_recent_paths() {
    let four_gib = 4 * 1024 * 1024 * 1024u64;
    let one_percent = four_gib.div_ceil(100);
    let mut progress = ProgressCoalescer::new(Some(four_gib));

    let first = progress.record(Some("file-00"), 1).unwrap();
    assert_eq!(first.path.as_deref(), Some("file-00"));
    assert_eq!(first.recent_paths, ["file-00"]);
    assert!(one_percent > PROGRESS_MIN_BYTE_STEP);
    assert!(progress.record(Some("file-01"), one_percent - 1).is_none());
    let one_percent_batch = progress.record(Some("file-02"), 1).unwrap();
    assert_eq!(one_percent_batch.bytes, one_percent);

    for index in 0..12 {
        assert!(progress.record(Some(&format!("recent-{index:02}")), 1).is_none());
    }
    let recent = progress.flush().unwrap();
    assert_eq!(recent.recent_paths.len(), 10);
    assert_eq!(recent.recent_paths.first().map(String::as_str), Some("recent-02"));
    assert_eq!(recent.recent_paths.last().map(String::as_str), Some("recent-11"));
    assert_eq!(recent.path.as_deref(), Some("recent-11"));
}

#[test]
fn zip_create_job_emits_ordered_events() {
    let temp = TestDir::new("zip_create_job_emits_ordered_events");
    temp.write_file("project/file.txt", b"hello");
    let mut events = Vec::new();

    run_zip_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        temp.path("archive.zip"),
        &ZipCreateOptions::default(),
        &PlanOptions::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    assert!(matches!(events.first(), Some(JobEvent::Started { kind: super::JobKind::ZipCreate, .. })));
    assert!(events.iter().any(|event| matches!(
        event,
        JobEvent::BytesProcessed {
            path: Some(path),
            recent_paths,
            bytes: 5,
            ..
        } if path == "project/file.txt"
            && recent_paths == &["project/file.txt".to_owned()]
    )));
    assert!(matches!(events.last(), Some(JobEvent::Completed { entries: 2, bytes: 5 })));
}

#[test]
fn zip_extract_job_emits_failure_event() {
    let temp = TestDir::new("zip_extract_job_emits_failure_event");
    let mut events = Vec::new();

    let result = run_zip_extract_job_with_password_and_policy(
        temp.path("missing.zip"),
        temp.path("out"),
        None,
        ExtractionPolicy::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    );

    assert!(result.is_err());
    assert!(matches!(events.first(), Some(JobEvent::Started { .. })));
    assert!(matches!(events.last(), Some(JobEvent::Failed { .. })));
}

#[test]
fn zip_extract_job_starts_without_progress_only_listing() {
    let temp = TestDir::new("zip_extract_without_progress_listing");
    temp.write_file("project/file.txt", b"hello");
    run_zip_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        temp.path("archive.zip"),
        &ZipCreateOptions::default(),
        &PlanOptions::default(),
        &CancellationToken::new(),
        &mut |_| {},
    )
    .unwrap();
    let mut events = Vec::new();

    run_zip_extract_job_with_password_and_policy(
        temp.path("archive.zip"),
        temp.path("out"),
        None,
        ExtractionPolicy::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    assert_extract_started_with_unknown_total(&events, super::JobKind::ZipExtract);
}

#[test]
fn sevenz_extract_job_starts_without_progress_only_listing() {
    let temp = TestDir::new("sevenz_extract_without_progress_listing");
    temp.write_file("project/file.txt", b"hello");
    run_7z_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        temp.path("archive.7z"),
        &SevenZCreateOptions::default(),
        &crate::manifest::PlanOptions::default(),
        &CancellationToken::new(),
        &mut |_| {},
    )
    .unwrap();
    let mut events = Vec::new();

    run_7z_extract_job_with_password_and_policy(
        temp.path("archive.7z"),
        temp.path("out"),
        None,
        ExtractionPolicy::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    assert_extract_started_with_unknown_total(&events, super::JobKind::SevenZExtract);
}

#[test]
fn raw_stream_extract_job_emits_progress_events() {
    let temp = TestDir::new("raw_stream_extract_job_emits_progress_events");
    let archive_path = temp.path("payload.txt.zst");
    {
        let file = fs::File::create(&archive_path).unwrap();
        let mut encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
        encoder.write_all(b"hello world").unwrap();
        encoder.finish().unwrap();
    }
    let mut events = Vec::new();

    run_raw_stream_extract_job_with_policy(
        &archive_path,
        RawStreamFormat::Zstd,
        temp.path("out"),
        ExtractionPolicy::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    assert!(matches!(events.first(), Some(JobEvent::Started { kind: super::JobKind::RawStreamExtract, total_bytes: Some(_) })));
    assert!(events.iter().any(|event| matches!(event, JobEvent::BytesProcessed { .. })));
}

#[test]
fn raw_stream_extract_progress_tracks_compressed_bytes_for_bz2() {
    let temp = TestDir::new("raw_stream_extract_progress_tracks_compressed_bytes_for_bz2");
    let archive_path = temp.path("payload.txt.bz2");
    {
        let file = fs::File::create(&archive_path).unwrap();
        let mut encoder = BzEncoder::new(file, Compression::best());
        let payload = vec![b'a'; 1_024 * 1_024 * 4];
        encoder.write_all(&payload).unwrap();
        encoder.finish().unwrap();
    }
    let source_size = fs::metadata(&archive_path).unwrap().len();
    let mut events = Vec::new();

    run_raw_stream_extract_job_with_policy(
        &archive_path,
        RawStreamFormat::Bzip2,
        temp.path("out"),
        ExtractionPolicy::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    let last_progress = events
        .iter()
        .rev()
        .find_map(|event| if let JobEvent::BytesProcessed { total_bytes_processed, .. } = event { Some(*total_bytes_processed) } else { None });
    let Some(last_processed_bytes) = last_progress else {
        panic!("expected at least one progress event");
    };

    assert_eq!(events.first(), Some(&JobEvent::Started { kind: super::JobKind::RawStreamExtract, total_bytes: Some(source_size) }));
    assert!(last_processed_bytes <= source_size);
}

#[test]
fn tzap_create_job_emits_phase_progress_through_output_commit() {
    let temp = TestDir::new("tzap_create_job_emits_progress_before_completion_for_large_file");
    let payload = large_tzap_progress_payload();
    temp.write_file("project/payload.bin", &payload);
    let mut events = Vec::new();

    run_tzap_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        temp.path("archive.tzap"),
        &test_tzap_create_options(),
        &crate::manifest::PlanOptions::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    let phases = events
        .iter()
        .filter_map(|event| match event {
            JobEvent::PhaseStarted { phase, .. } => Some(*phase),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        phases,
        vec![JobPhase::PlanningPayload, JobPhase::PlanningMetadata, JobPhase::EmittingPayload, JobPhase::EmittingMetadata, JobPhase::CommittingOutput,]
    );
    for phase in [JobPhase::PlanningPayload, JobPhase::EmittingPayload] {
        let phase_progress = events
            .iter()
            .filter_map(|event| match event {
                JobEvent::PhaseBytesProcessed { phase: event_phase, total_bytes_processed, .. } if *event_phase == phase => Some(*total_bytes_processed),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(phase_progress.len() <= 2);
        let final_phase_total = phase_progress.last().copied();
        assert_eq!(final_phase_total, Some(payload.len() as u64));
    }
    assert!(matches!(events.last(), Some(JobEvent::Completed { .. })));
}

#[test]
fn tzap_create_job_emits_entry_finished_during_multi_file_progress() {
    let temp = TestDir::new("tzap_create_job_emits_entry_finished_during_multi_file_progress");
    let payload = large_tzap_progress_payload();
    temp.write_file("project/one.bin", &payload);
    temp.write_file("project/two.bin", &payload);
    let mut events = Vec::new();

    run_tzap_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        temp.path("archive.tzap"),
        &test_tzap_create_options(),
        &crate::manifest::PlanOptions::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    let first_finished_index = events
        .iter()
        .position(|event| matches!(event, JobEvent::BytesProcessed { total_entries_processed, .. } if *total_entries_processed > 0))
        .expect("expected at least one aggregate with a finished entry");

    assert!(
        events.iter().skip(first_finished_index + 1).any(|event| matches!(event, JobEvent::BytesProcessed { .. })),
        "expected later byte progress after the first finished entry"
    );
    assert!(events.iter().all(|event| !matches!(event, JobEvent::PhaseBytesProcessed { path: None, .. })));
}

#[test]
fn tzap_create_job_can_be_cancelled_during_payload_planning() {
    assert_tzap_create_cancels_at(TzapCreateCancellationPoint::PlanningPayload);
}

#[test]
fn tzap_create_job_can_be_cancelled_during_payload_emission() {
    assert_tzap_create_cancels_at(TzapCreateCancellationPoint::EmittingPayload);
}

#[test]
fn tzap_create_job_honours_cancellation_before_output_commit() {
    assert_tzap_create_cancels_at(TzapCreateCancellationPoint::CommittingOutput);
}

#[derive(Clone, Copy)]
enum TzapCreateCancellationPoint {
    PlanningPayload,
    EmittingPayload,
    CommittingOutput,
}

impl TzapCreateCancellationPoint {
    fn matches(self, event: &JobEvent) -> bool {
        match self {
            Self::PlanningPayload => {
                matches!(event, JobEvent::PhaseBytesProcessed { phase: JobPhase::PlanningPayload, .. })
            }
            Self::EmittingPayload => matches!(event, JobEvent::BytesProcessed { .. }),
            Self::CommittingOutput => {
                matches!(event, JobEvent::PhaseStarted { phase: JobPhase::CommittingOutput, .. })
            }
        }
    }

    const fn test_name(self) -> &'static str {
        match self {
            Self::PlanningPayload => "tzap_cancel_during_payload_planning",
            Self::EmittingPayload => "tzap_cancel_during_payload_emission",
            Self::CommittingOutput => "tzap_cancel_before_output_commit",
        }
    }
}

fn assert_tzap_create_cancels_at(cancellation_point: TzapCreateCancellationPoint) {
    let temp = TestDir::new(cancellation_point.test_name());
    temp.write_file("project/payload.bin", &large_tzap_progress_payload());
    let destination = temp.path("archive.tzap");
    let token = CancellationToken::new();
    let token_for_sink = token.clone();
    let mut events = Vec::new();

    let result = run_tzap_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        &destination,
        &test_tzap_create_options(),
        &crate::manifest::PlanOptions::default(),
        &token,
        &mut |event| {
            if cancellation_point.matches(&event) {
                token_for_sink.cancel();
            }
            events.push(event);
        },
    );

    assert!(matches!(result, Err(crate::tzap_backend::TzapError::Cancelled)));
    assert!(events.iter().any(|event| matches!(event, JobEvent::Cancelled { .. })));
    assert!(!events.iter().any(|event| matches!(event, JobEvent::Completed { .. })));
    assert!(!destination.exists());
}

#[test]
fn tzap_phase_progress_caps_recent_paths_at_ten() {
    let temp = TestDir::new("tzap_phase_progress_caps_recent_paths_at_ten");
    for index in 0..12 {
        temp.write_file(format!("project/file-{index:02}.txt"), b"payload");
    }
    let mut events = Vec::new();

    run_tzap_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        temp.path("archive.tzap"),
        &test_tzap_create_options(),
        &crate::manifest::PlanOptions::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    let phase_progress = events
        .iter()
        .filter_map(|event| match event {
            JobEvent::PhaseBytesProcessed { path, recent_paths, .. } => Some((path, recent_paths)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(!phase_progress.is_empty());
    for (path, recent_paths) in phase_progress {
        assert!(!recent_paths.is_empty());
        assert!(recent_paths.len() <= 10);
        assert_eq!(path.as_ref(), recent_paths.last());
    }
}

#[test]
fn sevenz_create_job_emits_progress_before_completion_for_large_file() {
    let temp = TestDir::new("sevenz_create_job_emits_progress_before_completion_for_large_file");
    let payload = large_tzap_progress_payload();
    temp.write_file("project/payload.bin", &payload);
    let mut events = Vec::new();

    run_7z_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        temp.path("archive.7z"),
        &SevenZCreateOptions { level: Some(1), ..SevenZCreateOptions::default() },
        &crate::manifest::PlanOptions::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    assert_monotonic_progress_reaches_total_before_completion(&events, payload.len() as u64);
}

#[test]
fn sevenz_create_job_can_be_cancelled_during_file_progress() {
    let temp = TestDir::new("sevenz_create_job_can_be_cancelled_during_file_progress");
    let payload = large_tzap_progress_payload();
    temp.write_file("project/payload.bin", &payload);
    let token = CancellationToken::new();
    let token_for_sink = token.clone();
    let mut events = Vec::new();

    let result = run_7z_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        temp.path("archive.7z"),
        &SevenZCreateOptions { level: Some(1), ..SevenZCreateOptions::default() },
        &crate::manifest::PlanOptions::default(),
        &token,
        &mut |event| {
            if matches!(event, JobEvent::BytesProcessed { .. }) {
                token_for_sink.cancel();
            }
            events.push(event);
        },
    );

    assert!(matches!(result, Err(SevenZError::Cancelled)));
    assert!(events.iter().any(|event| matches!(event, JobEvent::Cancelled { .. })));
    assert!(!events.iter().any(|event| matches!(event, JobEvent::Completed { .. })));
}

#[test]
fn tzap_extract_job_emits_progress_before_completion_for_large_file() {
    let temp = TestDir::new("tzap_extract_job_emits_progress_before_completion_for_large_file");
    let payload = large_tzap_progress_payload();
    temp.write_file("project/payload.bin", &payload);

    run_tzap_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        temp.path("archive.tzap"),
        &test_tzap_create_options(),
        &crate::manifest::PlanOptions::default(),
        &CancellationToken::new(),
        &mut |_| {},
    )
    .unwrap();

    let mut events = Vec::new();
    run_tzap_extract_job_with_password_and_policy(
        temp.path("archive.tzap"),
        temp.path("out"),
        None,
        ExtractionPolicy::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    assert_extract_started_with_unknown_total(&events, super::JobKind::TzapExtract);
    assert_monotonic_progress_reaches_total_before_completion(&events, payload.len() as u64);
    assert!(events.iter().all(|event| match event {
        JobEvent::BytesProcessed { path, recent_paths, .. } => path.is_some() && !recent_paths.is_empty(),
        _ => true,
    }));
    assert_eq!(fs::read(temp.path("out/project/payload.bin")).unwrap(), payload);
}

#[test]
fn zip_create_job_can_be_cancelled() {
    let temp = TestDir::new("zip_create_job_can_be_cancelled");
    temp.write_file("project/file.txt", b"hello");
    let token = CancellationToken::new();
    let token_for_sink = token.clone();
    let mut events = Vec::new();

    let result = run_zip_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        temp.path("archive.zip"),
        &ZipCreateOptions::default(),
        &PlanOptions::default(),
        &token,
        &mut |event| {
            if matches!(event, JobEvent::BytesProcessed { .. }) {
                token_for_sink.cancel();
            }
            events.push(event);
        },
    );

    assert!(matches!(result, Err(ZipBackendError::Cancelled)));
    assert!(events.iter().any(|event| matches!(event, JobEvent::Cancelled { .. })));
    assert!(!events.iter().any(|event| matches!(event, JobEvent::Completed { .. })));
}

#[test]
fn zip_create_job_accepts_multiple_source_roots() {
    let temp = TestDir::new("zip_create_job_accepts_multiple_source_roots");
    temp.write_file("a.txt", b"a");
    temp.write_file("folder/b.txt", b"bb");
    let archive = temp.path("selection.zip");
    let mut events = Vec::new();

    let report = run_zip_create_job_from_sources_with_plan_options(
        &[temp.path("a.txt"), temp.path("folder")],
        &archive,
        &ZipCreateOptions::default(),
        &PlanOptions::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    assert_eq!(report.written_entries, 3);
    assert_eq!(report.written_bytes, 3);
    assert!(matches!(events.first(), Some(JobEvent::Started { kind: super::JobKind::ZipCreate, total_bytes: Some(3) })));

    let listing = list_zip(&archive).unwrap();
    let names = listing.entries.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>();
    assert_eq!(names, vec!["a.txt", "folder/", "folder/b.txt"]);
}

#[test]
fn tar_zst_create_job_emits_entry_and_byte_events() {
    let temp = TestDir::new("tar_zst_create_job_emits_entry_and_byte_events");
    temp.write_file("project/file.txt", b"hello");
    let mut events = Vec::new();

    run_tar_zst_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        temp.path("archive.tar.zst"),
        &TarZstdCreateOptions { level: 1, threads: Some(1), preserve_metadata: true, replace_existing: false },
        &PlanOptions::default(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    assert!(matches!(events.first(), Some(JobEvent::Started { kind: super::JobKind::TarZstdCreate, .. })));
    assert!(events.iter().any(|event| matches!(event, JobEvent::BytesProcessed { bytes: 5, .. })));
    assert!(matches!(events.last(), Some(JobEvent::Completed { entries: 2, bytes: 5 })));
}

#[test]
fn clean_source_tar_zst_job_uses_clean_manifest_profile() {
    let temp = TestDir::new("clean_source_tar_zst_job_uses_clean_manifest_profile");
    temp.write_file("project/src/main.rs", b"fn main() {}\n");
    temp.write_file("project/node_modules/pkg/index.js", b"drop");
    let mut events = Vec::new();

    let report = run_tar_zst_create_job_from_sources_with_plan_options(
        &[temp.path("project")],
        temp.path("project.clean.tar.zst"),
        &TarZstdCreateOptions { level: 1, threads: Some(1), preserve_metadata: true, replace_existing: false },
        &PlanOptions::clean_source(),
        &CancellationToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();

    assert_eq!(report.written_entries, 3);
    let paths = events
        .iter()
        .filter_map(|event| match event {
            JobEvent::BytesProcessed { path, .. } => path.as_deref(),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(paths.contains(&"project/src/main.rs"));
    assert!(!paths.iter().any(|path| path.contains("node_modules")));
}

#[test]
fn clean_source_tar_zst_job_accepts_multiple_source_roots() {
    let temp = TestDir::new("clean_source_tar_zst_job_accepts_multiple_source_roots");
    temp.write_file("a.txt", b"a");
    temp.write_file("folder/b.txt", b"bb");
    temp.write_file("folder/node_modules/pkg/index.js", b"drop");
    let archive = temp.path("selection.clean.tar.zst");

    let report = run_tar_zst_create_job_from_sources_with_plan_options(
        &[temp.path("a.txt"), temp.path("folder")],
        &archive,
        &TarZstdCreateOptions { level: 1, threads: Some(1), preserve_metadata: true, replace_existing: false },
        &PlanOptions::clean_source(),
        &CancellationToken::new(),
        &mut |_| {},
    )
    .unwrap();

    assert_eq!(report.written_entries, 3);
    assert_eq!(report.written_bytes, 3);

    let listing = list_entries(&archive).unwrap();
    let paths = listing.entries.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>();
    assert_eq!(paths, vec!["a.txt", "folder", "folder/b.txt"]);
}

fn large_tzap_progress_payload() -> Vec<u8> {
    (0..(512 * 1024)).map(|index| u8::try_from(index % 251).expect("modulo result fits in u8")).collect()
}

fn test_tzap_create_options() -> TzapCreateOptions {
    TzapCreateOptions {
        key_source: TzapKeySource::NoPassword,
        level: 1,
        preserve_metadata: true,
        replace_existing: false,
        volume_size: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: None,
    }
}

fn assert_monotonic_progress_reaches_total_before_completion(events: &[JobEvent], expected_total: u64) {
    let progress_totals = progress_totals_before_completion(events);

    assert!(!progress_totals.is_empty());
    assert!(progress_totals.iter().all(|total| *total <= expected_total));
    assert!(progress_totals.windows(2).all(|window| window[0] <= window[1]));
    assert_eq!(progress_totals.last(), Some(&expected_total));
}

fn assert_extract_started_with_unknown_total(events: &[JobEvent], kind: super::JobKind) {
    assert!(matches!(
        events.first(),
        Some(JobEvent::Started {
            kind: event_kind,
            total_bytes: None,
        }) if *event_kind == kind
    ));
}

fn progress_totals_before_completion(events: &[JobEvent]) -> Vec<u64> {
    let completed_index = events.iter().position(|event| matches!(event, JobEvent::Completed { .. })).expect("expected completed event");
    events[..completed_index]
        .iter()
        .filter_map(|event| match event {
            JobEvent::BytesProcessed { total_bytes_processed, .. } => Some(*total_bytes_processed),
            _ => None,
        })
        .collect()
}
