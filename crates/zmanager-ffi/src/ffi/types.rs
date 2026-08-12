//! Public DTOs exposed across the FFI surface.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BridgeSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeError {
    pub code: String,
    pub message: String,
    pub recovery_hint: Option<String>,
    pub severity: BridgeSeverity,
    pub retryable: bool,
}

#[derive(Debug, Error)]
pub enum ZmanagerGuiError {
    #[error("{user_message}")]
    Bridge { code: String, user_message: String, recovery_hint: Option<String>, severity: BridgeSeverity, retryable: bool },
}

impl From<BridgeError> for ZmanagerGuiError {
    fn from(error: BridgeError) -> Self {
        Self::Bridge { code: error.code, user_message: error.message, recovery_hint: error.recovery_hint, severity: error.severity, retryable: error.retryable }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthcheckResult {
    pub status: String,
    pub engine: String,
    pub version: String,
    pub ready: bool,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveFormat {
    Zip,
    SplitZip,
    Rar,
    MultipartRar,
    SevenZ,
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    TarZst,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Tzap,
    AppleArchive,
    Xip,
    RawStream,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectArchiveRequest {
    pub archive_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectArchiveResult {
    pub archive_path: String,
    pub format: ArchiveFormat,
    pub format_label: String,
    pub exists: bool,
    pub is_file: bool,
    pub can_list: bool,
    pub can_extract: bool,
    pub can_create: bool,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ArchiveEntryKind {
    File,
    Directory,
    Symlink,
    Hardlink,
    Special,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub path: String,
    pub kind: ArchiveEntryKind,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub modified_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListArchiveRequest {
    pub archive_path: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListArchiveResult {
    pub archive_path: String,
    pub format: ArchiveFormat,
    pub format_label: String,
    pub entries: Vec<ArchiveEntry>,
    pub entry_count: u64,
    pub total_size: Option<u64>,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestArchiveRequest {
    pub archive_path: String,
    pub password: Option<String>,
    pub selected_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestArchiveResult {
    pub archive_path: String,
    pub format: ArchiveFormat,
    pub format_label: String,
    pub verified: bool,
    pub tested_entries: u64,
    pub skipped_entries: u64,
    pub total_entries: u64,
    pub tested_bytes: u64,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializePreviewRequest {
    pub archive_path: String,
    pub entry_path: String,
    pub password: Option<String>,
    pub strip_components: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializePreviewResult {
    pub archive_path: String,
    pub entry_path: String,
    pub cleanup_root: String,
    pub preview_path: String,
    pub written_bytes: u64,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtractionCollisionPolicy {
    Refuse,
    Replace,
    Rename,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExtractionPlanEntryStatus {
    Write,
    Skip,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanExtractRequest {
    pub archive_path: String,
    pub destination_root: String,
    pub password: Option<String>,
    pub selected_paths: Vec<String>,
    pub strip_components: u64,
    pub collision_policy: ExtractionCollisionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionPlanEntry {
    pub archive_path: String,
    pub normalized_path: Option<String>,
    pub destination_path: Option<String>,
    pub kind: ArchiveEntryKind,
    pub status: ExtractionPlanEntryStatus,
    pub reason: Option<String>,
    pub size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub replace_existing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanExtractResult {
    pub archive_path: String,
    pub destination_root: String,
    pub format: ArchiveFormat,
    pub format_label: String,
    pub entries: Vec<ExtractionPlanEntry>,
    pub total_entries: u64,
    pub writable_entries: u64,
    pub skipped_entries: u64,
    pub blocked_entries: u64,
    pub estimated_bytes: Option<u64>,
    pub can_start: bool,
    pub warnings: Vec<BridgeError>,
    pub plan_token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreateArchiveFormat {
    Zip,
    SevenZ,
    TarZst,
    Tzap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanCreateRequest {
    pub source_paths: Vec<String>,
    pub destination_archive_path: String,
    pub format: CreateArchiveFormat,
    pub password: Option<String>,
    pub preserve_metadata: bool,
    pub replace_existing: bool,
    pub clean_source: bool,
    pub verify_after_create: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePlanEntry {
    pub archive_path: String,
    pub source_path: String,
    pub kind: ArchiveEntryKind,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanCreateResult {
    pub source_paths: Vec<String>,
    pub destination_archive_path: String,
    pub format: CreateArchiveFormat,
    pub format_label: String,
    pub entries: Vec<CreatePlanEntry>,
    pub total_entries: u64,
    pub total_bytes: u64,
    pub excluded_entries: u64,
    pub excluded_bytes: u64,
    pub output_exists: bool,
    pub replace_existing: bool,
    pub encrypted: bool,
    pub preserve_metadata: bool,
    pub clean_source: bool,
    pub verify_after_create: bool,
    pub verify_supported: bool,
    pub can_start: bool,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartCreateRequest {
    pub source_paths: Vec<String>,
    pub destination_archive_path: String,
    pub format: CreateArchiveFormat,
    pub password: Option<String>,
    pub preserve_metadata: bool,
    pub replace_existing: bool,
    pub clean_source: bool,
    pub verify_after_create: bool,
    pub excluded_paths: Vec<String>,
    pub level: u32,
    pub encrypt_file_names: bool,
    pub volume_size: Option<u64>,
    pub recovery_percentage: u8,
    pub volume_loss_tolerance: u8,
    pub tzap_signing_certificate: Option<String>,
    pub tzap_signing_private_key: Option<String>,
    pub tzap_signing_chain: Vec<String>,
    pub tzap_identity: Option<String>,
    pub tzap_identity_password: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileJobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl MobileJobStatus {
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileJobKind {
    ZipCreate,
    ZipExtract,
    SevenZCreate,
    SevenZExtract,
    RarExtract,
    TarZstdCreate,
    TarZstdExtract,
    TzapCreate,
    TzapExtract,
    AppleArchiveCreate,
    AppleArchiveExtract,
    ArchiveExtract,
    RawStreamExtract,
    TestArchive,
    TarGzCreate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileJobEventKind {
    Started,
    EntryStarted,
    BytesProcessed,
    EntryFinished,
    Warning,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileJobEvent {
    pub sequence: u64,
    pub event_type: MobileJobEventKind,
    pub job_kind: Option<MobileJobKind>,
    pub path: Option<String>,
    pub bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub total_bytes_processed: Option<u64>,
    pub entries: Option<u64>,
    pub total_entries: Option<u64>,
    pub message: Option<String>,
    pub error: Option<BridgeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobTerminalSummary {
    pub written_entries: u64,
    pub skipped_entries: Option<u64>,
    pub written_bytes: u64,
    pub encrypted: Option<bool>,
    pub volume_size: Option<u64>,
    pub volume_count: Option<u64>,
    pub output_paths: Vec<String>,
    pub verified: Option<bool>,
    pub verified_entries: Option<u64>,
    pub verified_bytes: Option<u64>,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartExtractRequest {
    pub archive_path: String,
    pub destination_root: String,
    pub password: Option<String>,
    pub selected_paths: Vec<String>,
    pub strip_components: u64,
    pub collision_policy: ExtractionCollisionPolicy,
    pub plan_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartJobResult {
    pub job_id: String,
    pub kind: MobileJobKind,
    pub status: MobileJobStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollJobEventsRequest {
    pub job_id: String,
    pub cursor: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollJobEventsResult {
    pub job_id: String,
    pub kind: MobileJobKind,
    pub status: MobileJobStatus,
    pub events: Vec<MobileJobEvent>,
    pub next_cursor: u64,
    pub min_retained_sequence: u64,
    pub is_terminal: bool,
    pub terminal_summary: Option<JobTerminalSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelJobRequest {
    pub job_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelJobResult {
    pub job_id: String,
    pub status: MobileJobStatus,
    pub cancel_requested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearSensitiveStateResult {
    pub cleared_terminal_jobs: u64,
    pub cancel_requested_jobs: u64,
    pub retained_active_jobs: u64,
}

pub(crate) fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
