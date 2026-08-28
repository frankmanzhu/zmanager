//! Stable FFI stubs for builds without the hosted TZAP profile.

use crate::ffi::error::{ERROR_UNSUPPORTED_FORMAT, bridge_error};
use crate::ffi::types::{
    BridgeSeverity, TzapAuthCallbackRequest, TzapAuthLoginRequest, TzapAuthLoginResult, TzapAuthStatusRequest, TzapAuthStatusResult, TzapCertEnrollRequest,
    TzapCertificateInventoryRequest, TzapCertificateInventoryResult, TzapDocumentSignRequest, TzapDocumentSignResult, TzapDocumentVerifyRequest,
    TzapDocumentVerifyResult, ZmanagerGuiError,
};

fn unavailable(operation: &str) -> String {
    format!(r#"{{"ok":false,"error":"tzap-online feature not enabled in this build","operation":"{operation}"}}"#)
}

fn unavailable_error(operation: &str) -> ZmanagerGuiError {
    bridge_error(ERROR_UNSUPPORTED_FORMAT, format!("The {operation} feature is not enabled in this build."), None, BridgeSeverity::Warning, false)
}

macro_rules! unavailable_json_endpoint {
    ($name:ident, $operation:literal) => {
        pub fn $name(_request_json: String) -> String {
            unavailable($operation)
        }
    };
}

#[allow(non_snake_case)]
pub fn tzapPublicMetadataSummary(_archive_path: String) -> String {
    unavailable("tzapPublicMetadataSummary")
}

#[allow(non_snake_case)]
pub fn tzapPublicMetadataDisplaySummary(_archive_path: String) -> String {
    unavailable("tzapPublicMetadataDisplaySummary")
}

#[allow(non_snake_case)]
pub fn verifyTzapX509(_archive_path: String, _password: Option<String>, _trusted_ca_certs: Vec<String>, _trusted_system_roots: bool) -> String {
    unavailable("verifyTzapX509")
}

#[allow(non_snake_case)]
pub fn verifyTzapX509PublicNoKey(_archive_path: String, _trusted_ca_certs: Vec<String>, _trusted_system_roots: bool) -> String {
    unavailable("verifyTzapX509PublicNoKey")
}

#[allow(non_snake_case)]
pub fn inspectTzapX509Signer(_archive_path: String, _password: Option<String>) -> String {
    unavailable("inspectTzapX509Signer")
}

#[allow(non_snake_case)]
pub fn inspectTzapX509PublicNoKeySigner(_archive_path: String) -> String {
    unavailable("inspectTzapX509PublicNoKeySigner")
}

#[allow(non_snake_case)]
pub fn createTzapSelfSignedIdentity(_identity_path: String, _public_certificate_path: String, _common_name: String, _password: String) -> String {
    unavailable("createTzapSelfSignedIdentity")
}

#[allow(non_snake_case)]
pub fn tzapAuthLogin(_request: TzapAuthLoginRequest) -> Result<TzapAuthLoginResult, ZmanagerGuiError> {
    Err(unavailable_error("tzapAuthLogin"))
}

#[allow(non_snake_case)]
pub fn tzapAuthCallback(_request: TzapAuthCallbackRequest) -> Result<(), ZmanagerGuiError> {
    Err(unavailable_error("tzapAuthCallback"))
}

#[allow(non_snake_case)]
pub fn tzapAuthStatus(_request: TzapAuthStatusRequest) -> Result<TzapAuthStatusResult, ZmanagerGuiError> {
    Err(unavailable_error("tzapAuthStatus"))
}

unavailable_json_endpoint!(tzap_auth_forget_json, "tzap_auth_forget_json");
unavailable_json_endpoint!(tzap_auth_account_url_json, "tzap_auth_account_url_json");

#[allow(non_snake_case)]
pub fn tzapCertificateInventory(_request: TzapCertificateInventoryRequest) -> Result<TzapCertificateInventoryResult, ZmanagerGuiError> {
    Err(unavailable_error("tzapCertificateInventory"))
}

#[allow(non_snake_case)]
pub fn tzapCertEnroll(_request: TzapCertEnrollRequest) -> Result<(), ZmanagerGuiError> {
    Err(unavailable_error("tzapCertEnroll"))
}

unavailable_json_endpoint!(tzap_cert_renew_json, "tzap_cert_renew_json");
unavailable_json_endpoint!(tzap_cert_revoke_json, "tzap_cert_revoke_json");
unavailable_json_endpoint!(tzap_device_retire_json, "tzap_device_retire_json");

#[allow(non_snake_case)]
pub fn tzapDocumentSign(_request: TzapDocumentSignRequest) -> Result<TzapDocumentSignResult, ZmanagerGuiError> {
    Err(unavailable_error("tzapDocumentSign"))
}

/// Unlike the rest of this module, document verification stays available:
/// it is a local/offline cryptographic check (see `tzap_offline.rs`) that
/// needs no hosted transport or account state, so the reduced FFI profile
/// keeps it working rather than stubbing it out.
#[allow(non_snake_case)]
pub fn tzapDocumentVerify(request: TzapDocumentVerifyRequest) -> Result<TzapDocumentVerifyResult, ZmanagerGuiError> {
    let envelope: serde_json::Value =
        serde_json::from_str(&request.envelope_json).map_err(|error| unavailable_verify_error(format!("invalid signed envelope: {error}")))?;
    let request_json = serde_json::json!({
        "envelope": envelope,
        "custom_trust_root_cert_paths": request.custom_trust_root_cert_paths,
        "verifier_time_unix_seconds": request.verifier_time_unix_seconds,
    })
    .to_string();
    let response_json = super::tzap_offline::tzap_document_verify_json(request_json);
    let response: serde_json::Value =
        serde_json::from_str(&response_json).map_err(|error| unavailable_verify_error(format!("invalid response JSON: {error}")))?;
    if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let message = response.get("error").and_then(serde_json::Value::as_str).unwrap_or("The identity operation failed.").to_owned();
        return Err(unavailable_verify_error(message));
    }
    let state = response
        .get("state")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| unavailable_verify_error("response missing field: state".to_owned()))?
        .to_owned();
    Ok(TzapDocumentVerifyResult { state })
}

fn unavailable_verify_error(message: String) -> ZmanagerGuiError {
    bridge_error(ERROR_UNSUPPORTED_FORMAT, message, None, BridgeSeverity::Warning, false)
}

unavailable_json_endpoint!(tzap_recipient_key_generate_json, "tzap_recipient_key_generate_json");
unavailable_json_endpoint!(tzap_recipient_key_remove_json, "tzap_recipient_key_remove_json");
unavailable_json_endpoint!(tzap_contact_export_json, "tzap_contact_export_json");
unavailable_json_endpoint!(tzap_contact_import_json, "tzap_contact_import_json");
unavailable_json_endpoint!(tzap_contact_list_json, "tzap_contact_list_json");
unavailable_json_endpoint!(tzap_contact_remove_json, "tzap_contact_remove_json");
unavailable_json_endpoint!(tzap_share_create_json, "tzap_share_create_json");
