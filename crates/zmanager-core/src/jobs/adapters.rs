use super::{CancellationToken, JobContext, JobEvent, JobEventSink, JobKind};
use crate::engine::{CreateOptions, CreateReport, CreateRequest, FormatId, create_default_engine};
use crate::manifest::{PlanOptions, plan_archives};
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
    let kind = match options.format() {
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
