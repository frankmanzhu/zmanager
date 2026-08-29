//! Internal organization of the zmanager FFI bridge.
//!
//! The public FFI surface (types + functions declared in `zmanager_ffi.udl`)
//! is re-exported from this module so that the crate root stays a thin
//! facade. All helpers here are crate-internal (`pub(crate)`) and never
//! reach the exported surface.

mod error;
mod ops;
mod types;
mod util;

#[cfg(test)]
mod tests;

pub use ops::archive::{detectArchive, healthcheck, listArchive, listFormats, materializePreview, testArchive};
pub use ops::localsend::{
    localsendCancelSend, localsendDiscover, localsendPollEvents, localsendRespondToTransfer, localsendSendFile, localsendStartReceiver, localsendStopReceiver,
};
pub use ops::tzap::{
    createTzapSelfSignedIdentity, inspectTzapX509PublicNoKeySigner, inspectTzapX509Signer, tzap_auth_account_url_json, tzap_auth_forget_json,
    tzap_cert_renew_json, tzap_cert_revoke_json, tzap_contact_export_json, tzap_contact_import_json, tzap_contact_list_json, tzap_contact_remove_json,
    tzap_device_retire_json, tzap_recipient_key_generate_json, tzap_recipient_key_remove_json, tzap_share_create_json, tzapAuthCallback, tzapAuthLogin,
    tzapAuthStatus, tzapCertEnroll, tzapCertificateInventory, tzapDocumentSign, tzapDocumentVerify, tzapPublicMetadataDisplaySummary,
    tzapPublicMetadataSummary, verifyTzapX509, verifyTzapX509PublicNoKey,
};
pub use types::{
    ArchiveEntry, ArchiveEntryKind, ArchiveFormat, BridgeError, BridgeSeverity, CancelSendRequest, DetectArchiveRequest, DetectArchiveResult, DeviceInfoDto,
    DiscoverRequest, FormatDescriptor, HealthcheckResult, ListArchiveRequest, ListArchiveResult, ListFormatsResult, MaterializePreviewRequest,
    MaterializePreviewResult, PollEventsResult, QueuedEvent, RespondToTransferRequest, SendFileRequest, SendFileResult, StartReceiverRequest,
    TestArchiveRequest, TestArchiveResult, TransferDecisionKind, TransferFile, TzapAuthCallbackRequest, TzapAuthLoginRequest, TzapAuthLoginResult,
    TzapAuthStatusRequest, TzapAuthStatusResult, TzapCertEnrollRequest, TzapCertificateInventoryRequest, TzapCertificateInventoryResult, TzapDocumentPayload,
    TzapDocumentSignRequest, TzapDocumentSignResult, TzapDocumentVerifyRequest, TzapDocumentVerifyResult, ZmanagerGuiError,
};
