//! TZAP service JSON passthrough endpoints.

use crate::ffi::error::{existing_archive_path_or_tzap_error, map_tzap_error};
#[cfg(test)]
use crate::ffi::types::TzapDocumentPayload;
use crate::ffi::types::{
    TzapAuthCallbackRequest, TzapAuthLoginRequest, TzapAuthLoginResult, TzapAuthStatusRequest, TzapAuthStatusResult, TzapCertEnrollRequest,
    TzapCertificateInventoryRequest, TzapCertificateInventoryResult, TzapDocumentSignRequest, TzapDocumentSignResult, TzapDocumentVerifyRequest,
    TzapDocumentVerifyResult, ZmanagerGuiError,
};
use crate::ffi::util::password_ref;

/// Calls one of `zmanager_tzap_hosted::tzap_service`'s JSON-passthrough
/// functions with `request`, parses its `{"ok": ...}` envelope, and returns
/// the parsed response on success. That crate's own contract stays a loose
/// `serde_json::Value` underneath (defaulted optional fields, not a fixed
/// struct); this is the one place in this crate that still speaks it, so
/// every typed tzap wrapper below can build a small, exact request object
/// and extract only the fields it needs from the response.
fn tzap_call(request: serde_json::Value, raw_fn: impl FnOnce(String) -> String) -> Result<serde_json::Value, ZmanagerGuiError> {
    let response_json = raw_fn(request.to_string());
    let response: serde_json::Value = serde_json::from_str(&response_json).map_err(|error| map_tzap_error(format!("invalid response JSON: {error}")))?;
    if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let message = response
            .get("message")
            .or_else(|| response.get("error"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("The identity operation failed.")
            .to_owned();
        return Err(map_tzap_error(message));
    }
    Ok(response)
}

fn tzap_response_field(response: &serde_json::Value, field: &str) -> Result<serde_json::Value, ZmanagerGuiError> {
    response.get(field).cloned().ok_or_else(|| map_tzap_error(format!("response missing field: {field}")))
}

fn tzap_response_string(response: &serde_json::Value, field: &str) -> Result<String, ZmanagerGuiError> {
    tzap_response_field(response, field)?.as_str().map(str::to_owned).ok_or_else(|| map_tzap_error(format!("response field is not a string: {field}")))
}

#[allow(non_snake_case)]
pub fn tzapPublicMetadataSummary(archive_path: String) -> String {
    let archive_path = match existing_archive_path_or_tzap_error(archive_path) {
        Ok(path) => path,
        Err(envelope) => return envelope,
    };
    zmanager_tzap_hosted::tzap_service::tzap_public_metadata_summary(&archive_path)
}

/// Bounded display summary: header/trailer metadata plus a footer-only
/// signature status. Never reads archive contents, so it is safe for
/// QuickLook/Spotlight-style surfaces regardless of archive size.
#[allow(non_snake_case)]
pub fn tzapPublicMetadataDisplaySummary(archive_path: String) -> String {
    let archive_path = match existing_archive_path_or_tzap_error(archive_path) {
        Ok(path) => path,
        Err(envelope) => return envelope,
    };
    zmanager_tzap_hosted::tzap_service::tzap_public_metadata_display_summary(&archive_path)
}

#[allow(non_snake_case)]
pub fn verifyTzapX509(archive_path: String, password: Option<String>, trusted_ca_certs: Vec<String>, trusted_system_roots: bool) -> String {
    let archive_path = match existing_archive_path_or_tzap_error(archive_path) {
        Ok(path) => path,
        Err(envelope) => return envelope,
    };
    zmanager_tzap_hosted::tzap_service::verify_tzap_x509(&archive_path, password_ref(&password), &trusted_ca_certs, trusted_system_roots)
}

#[allow(non_snake_case)]
pub fn verifyTzapX509PublicNoKey(archive_path: String, trusted_ca_certs: Vec<String>, trusted_system_roots: bool) -> String {
    let archive_path = match existing_archive_path_or_tzap_error(archive_path) {
        Ok(path) => path,
        Err(envelope) => return envelope,
    };
    zmanager_tzap_hosted::tzap_service::verify_tzap_x509_public_no_key(&archive_path, &trusted_ca_certs, trusted_system_roots)
}

#[allow(non_snake_case)]
pub fn inspectTzapX509Signer(archive_path: String, password: Option<String>) -> String {
    let archive_path = match existing_archive_path_or_tzap_error(archive_path) {
        Ok(path) => path,
        Err(envelope) => return envelope,
    };
    zmanager_tzap_hosted::tzap_service::inspect_tzap_x509_signer(&archive_path, password_ref(&password))
}

#[allow(non_snake_case)]
pub fn inspectTzapX509PublicNoKeySigner(archive_path: String) -> String {
    let archive_path = match existing_archive_path_or_tzap_error(archive_path) {
        Ok(path) => path,
        Err(envelope) => return envelope,
    };
    zmanager_tzap_hosted::tzap_service::inspect_tzap_x509_public_no_key_signer(&archive_path)
}

#[allow(non_snake_case)]
pub fn createTzapSelfSignedIdentity(identity_path: String, public_certificate_path: String, common_name: String, password: String) -> String {
    zmanager_tzap_hosted::tzap_service::create_tzap_self_signed_identity(&identity_path, Some(&public_certificate_path), &common_name, &password)
}

#[allow(non_snake_case)]
pub fn tzapAuthLogin(request: TzapAuthLoginRequest) -> Result<TzapAuthLoginResult, ZmanagerGuiError> {
    let response = tzap_call(
        serde_json::json!({
            "state_dir": request.state_dir,
            "account_key": request.account_key,
            "client_id": request.client_id,
            "redirect_uri": request.redirect_uri,
            "auth_base_url": request.auth_base_url,
            "account_base_url": request.account_base_url,
        }),
        |request_json| zmanager_tzap_hosted::tzap_service::tzap_auth_login_json(&request_json),
    )?;
    Ok(TzapAuthLoginResult { launch_url: tzap_response_string(&response, "launch_url")? })
}

#[allow(non_snake_case)]
pub fn tzapAuthCallback(request: TzapAuthCallbackRequest) -> Result<(), ZmanagerGuiError> {
    tzap_call(
        serde_json::json!({
            "state_dir": request.state_dir,
            "account_key": request.account_key,
            "client_id": request.client_id,
            "redirect_uri": request.redirect_uri,
            "auth_base_url": request.auth_base_url,
            "callback_url": request.callback_url,
            "state": request.state,
            "handoff_code": request.handoff_code,
        }),
        |request_json| zmanager_tzap_hosted::tzap_service::tzap_auth_callback_json(&request_json),
    )?;
    Ok(())
}

#[allow(non_snake_case)]
pub fn tzapAuthStatus(request: TzapAuthStatusRequest) -> Result<TzapAuthStatusResult, ZmanagerGuiError> {
    let response = tzap_call(
        serde_json::json!({
            "state_dir": request.state_dir,
            "account_key": request.account_key,
        }),
        |request_json| zmanager_tzap_hosted::tzap_service::tzap_auth_status_json(&request_json),
    )?;
    Ok(TzapAuthStatusResult { authenticated: response.get("authenticated").and_then(serde_json::Value::as_bool).unwrap_or(false) })
}

pub fn tzap_auth_forget_json(_request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_auth_forget_json(&_request_json)
}

pub fn tzap_auth_account_url_json(_request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_auth_account_url_json(&_request_json)
}

#[allow(non_snake_case)]
pub fn tzapCertificateInventory(request: TzapCertificateInventoryRequest) -> Result<TzapCertificateInventoryResult, ZmanagerGuiError> {
    let response = tzap_call(
        serde_json::json!({
            "state_dir": request.state_dir,
            "account_key": request.account_key,
        }),
        |request_json| zmanager_tzap_hosted::tzap_service::tzap_certificate_inventory_json(&request_json),
    )?;
    let certificate_ids = tzap_response_field(&response, "inventory")?
        .get("certificates")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|certificate| certificate.get("certificate_id").and_then(serde_json::Value::as_str).map(str::to_owned))
        .collect();
    Ok(TzapCertificateInventoryResult { certificate_ids })
}

#[allow(non_snake_case)]
pub fn tzapCertEnroll(request: TzapCertEnrollRequest) -> Result<(), ZmanagerGuiError> {
    tzap_call(
        serde_json::json!({
            "state_dir": request.state_dir,
            "account_key": request.account_key,
            "service_base_url": request.service_base_url,
            "custom_trust_root_cert_paths": request.custom_trust_root_cert_paths,
            "requested_validity_seconds": request.requested_validity_seconds,
        }),
        |request_json| zmanager_tzap_hosted::tzap_service::tzap_cert_enroll_json(&request_json),
    )?;
    Ok(())
}

pub fn tzap_cert_renew_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_cert_renew_json(&request_json)
}

pub fn tzap_cert_revoke_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_cert_revoke_json(&request_json)
}

pub fn tzap_device_retire_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_device_retire_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapDocumentSign(request: TzapDocumentSignRequest) -> Result<TzapDocumentSignResult, ZmanagerGuiError> {
    let response = tzap_call(
        serde_json::json!({
            "state_dir": request.state_dir,
            "account_key": request.account_key,
            "certificate_id": request.certificate_id,
            "payload": {
                "tzap_payload_version": request.payload.tzap_payload_version,
                "title": request.payload.title,
                "body": request.payload.body,
            },
        }),
        |request_json| zmanager_tzap_hosted::tzap_service::tzap_document_sign_json(&request_json),
    )?;
    let envelope = tzap_response_field(&response, "envelope")?;
    let envelope_json = serde_json::to_string(&envelope).map_err(|error| map_tzap_error(format!("failed to serialize signed envelope: {error}")))?;
    Ok(TzapDocumentSignResult { envelope_json })
}

#[allow(non_snake_case)]
pub fn tzapDocumentVerify(request: TzapDocumentVerifyRequest) -> Result<TzapDocumentVerifyResult, ZmanagerGuiError> {
    let envelope: serde_json::Value =
        serde_json::from_str(&request.envelope_json).map_err(|error| map_tzap_error(format!("invalid signed envelope: {error}")))?;
    let response = tzap_call(
        serde_json::json!({
            "envelope": envelope,
            "custom_trust_root_cert_paths": request.custom_trust_root_cert_paths,
            "verifier_time_unix_seconds": request.verifier_time_unix_seconds,
        }),
        |request_json| zmanager_tzap_hosted::tzap_service::tzap_document_verify_json(&request_json),
    )?;
    Ok(TzapDocumentVerifyResult { state: tzap_response_string(&response, "state")? })
}

pub fn tzap_recipient_key_generate_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_recipient_key_generate_json(&request_json)
}

pub fn tzap_recipient_key_remove_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_recipient_key_remove_json(&request_json)
}

pub fn tzap_contact_export_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_contact_export_json(&request_json)
}

pub fn tzap_contact_import_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_contact_import_json(&request_json)
}

pub fn tzap_contact_list_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_contact_list_json(&request_json)
}

pub fn tzap_contact_remove_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_contact_remove_json(&request_json)
}

pub fn tzap_share_create_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_share_create_json(&request_json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tzap_ffi_missing_paths() {
        let missing = "non_existent_archive_12345.tzap".to_string();
        let summary = tzapPublicMetadataSummary(missing.clone());
        assert!(summary.contains("\"ok\":false"));

        let display_summary = tzapPublicMetadataDisplaySummary(missing.clone());
        assert!(display_summary.contains("\"ok\":false"));

        let verify = verifyTzapX509(missing.clone(), None, vec![], false);
        assert!(verify.contains("\"ok\":false"));

        let verify_pub = verifyTzapX509PublicNoKey(missing.clone(), vec![], false);
        assert!(verify_pub.contains("\"ok\":false"));

        let inspect = inspectTzapX509Signer(missing.clone(), None);
        assert!(inspect.contains("\"ok\":false"));

        let inspect_pub = inspectTzapX509PublicNoKeySigner(missing);
        assert!(inspect_pub.contains("\"ok\":false"));
    }

    #[test]
    fn test_tzap_ffi_json_endpoints() {
        let empty_req = "{}".to_string();
        assert!(!tzap_auth_forget_json(empty_req.clone()).is_empty());
        assert!(!tzap_auth_account_url_json(empty_req.clone()).is_empty());
        assert!(!tzap_cert_renew_json(empty_req.clone()).is_empty());
        assert!(!tzap_cert_revoke_json(empty_req.clone()).is_empty());
        assert!(!tzap_device_retire_json(empty_req.clone()).is_empty());
        assert!(!tzap_recipient_key_generate_json(empty_req.clone()).is_empty());
        assert!(!tzap_recipient_key_remove_json(empty_req.clone()).is_empty());
        assert!(!tzap_contact_export_json(empty_req.clone()).is_empty());
        assert!(!tzap_contact_import_json(empty_req.clone()).is_empty());
        assert!(!tzap_contact_list_json(empty_req.clone()).is_empty());
        assert!(!tzap_contact_remove_json(empty_req.clone()).is_empty());
        assert!(!tzap_share_create_json(empty_req).is_empty());
    }

    #[test]
    fn test_tzap_ffi_typed_endpoints() {
        let temp_dir = std::env::temp_dir().join(format!("zmanager-ffi-tzap-test-{}", std::process::id()));
        let state_dir = temp_dir.to_string_lossy().into_owned();

        let status = tzapAuthStatus(TzapAuthStatusRequest { state_dir: state_dir.clone(), account_key: "test".to_owned() });
        assert!(matches!(status, Ok(TzapAuthStatusResult { authenticated: false })));

        let inventory = tzapCertificateInventory(TzapCertificateInventoryRequest { state_dir: state_dir.clone(), account_key: "test".to_owned() });
        assert!(matches!(inventory, Ok(TzapCertificateInventoryResult { ref certificate_ids }) if certificate_ids.is_empty()));

        let enroll = tzapCertEnroll(TzapCertEnrollRequest {
            state_dir: state_dir.clone(),
            account_key: "test".to_owned(),
            service_base_url: String::new(),
            custom_trust_root_cert_paths: vec![],
            requested_validity_seconds: 0,
        });
        assert!(enroll.is_err());

        let sign = tzapDocumentSign(TzapDocumentSignRequest {
            state_dir: state_dir.clone(),
            account_key: "test".to_owned(),
            certificate_id: "missing".to_owned(),
            payload: TzapDocumentPayload { tzap_payload_version: 1, title: "t".to_owned(), body: "b".to_owned() },
        });
        assert!(sign.is_err());

        let verify = tzapDocumentVerify(TzapDocumentVerifyRequest {
            envelope_json: "{}".to_owned(),
            custom_trust_root_cert_paths: vec![],
            verifier_time_unix_seconds: 0,
        });
        assert!(verify.is_err());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
