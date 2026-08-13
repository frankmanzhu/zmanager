//! Internal organization of the zmanager FFI bridge.
//!
//! The public FFI surface (types + functions declared in `zmanager_ffi.udl`)
//! is re-exported from this module so that the crate root stays a thin
//! facade. All helpers here are crate-internal (`pub(crate)`) and never
//! reach the exported surface.

mod error;
mod event;
mod ops;
pub mod session;
mod types;
mod util;

#[cfg(test)]
mod tests;

pub use ops::archive::{
    cancelJob, clearSensitiveState, detectArchive, healthcheck, listArchive, listFormats, materializePreview, planCreate, planExtract, pollJobEvents,
    startCreate, startExtract, testArchive,
};
pub use ops::tzap::{
    createTzapSelfSignedIdentity, inspectTzapX509PublicNoKeySigner, inspectTzapX509Signer, tzap_auth_account_url_json, tzap_auth_callback_json,
    tzap_auth_forget_json, tzap_auth_login_json, tzap_auth_status_json, tzap_cert_enroll_json, tzap_cert_renew_json, tzap_cert_revoke_json,
    tzap_certificate_inventory_json, tzap_contact_export_json, tzap_contact_import_json, tzap_contact_list_json, tzap_contact_remove_json,
    tzap_device_retire_json, tzap_document_sign_json, tzap_document_verify_json, tzap_recipient_key_generate_json, tzap_recipient_key_remove_json,
    tzap_share_create_json, tzapPublicMetadataDisplaySummary, tzapPublicMetadataSummary, verifyTzapX509, verifyTzapX509PublicNoKey,
};
pub use types::{
    ArchiveEntry, ArchiveEntryKind, ArchiveFormat, BridgeError, BridgeSeverity, CancelJobRequest, CancelJobResult, ClearSensitiveStateResult,
    CreateArchiveFormat, CreatePlanEntry, DetectArchiveRequest, DetectArchiveResult, ExtractionCollisionPolicy, ExtractionPlanEntry, ExtractionPlanEntryStatus,
    FormatDescriptor, HealthcheckResult, JobTerminalSummary, ListArchiveRequest, ListArchiveResult, ListFormatsResult, MaterializePreviewRequest,
    MaterializePreviewResult, MobileJobEvent, MobileJobEventKind, MobileJobKind, MobileJobStatus, PlanCreateRequest, PlanCreateResult, PlanExtractRequest,
    PlanExtractResult, PollJobEventsRequest, PollJobEventsResult, StartCreateRequest, StartExtractRequest, StartJobResult, TestArchiveRequest,
    TestArchiveResult, ZmanagerGuiError,
};
