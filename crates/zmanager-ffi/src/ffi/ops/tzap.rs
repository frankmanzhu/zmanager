//! TZAP service JSON passthrough endpoints.

use crate::ffi::error::existing_archive_path_or_tzap_error;
use crate::ffi::util::password_ref;

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

pub fn tzap_auth_login_json(_request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_auth_login_json(&_request_json)
}

pub fn tzap_auth_callback_json(_request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_auth_callback_json(&_request_json)
}

pub fn tzap_auth_status_json(_request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_auth_status_json(&_request_json)
}

pub fn tzap_auth_forget_json(_request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_auth_forget_json(&_request_json)
}

pub fn tzap_auth_account_url_json(_request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_auth_account_url_json(&_request_json)
}

pub fn tzap_certificate_inventory_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_certificate_inventory_json(&request_json)
}

pub fn tzap_cert_enroll_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_cert_enroll_json(&request_json)
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

pub fn tzap_document_sign_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_document_sign_json(&request_json)
}

pub fn tzap_document_verify_json(request_json: String) -> String {
    zmanager_tzap_hosted::tzap_service::tzap_document_verify_json(&request_json)
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
        assert!(!tzap_auth_status_json(empty_req.clone()).is_empty());
        assert!(!tzap_auth_forget_json(empty_req.clone()).is_empty());
        assert!(!tzap_auth_account_url_json(empty_req.clone()).is_empty());
        assert!(!tzap_certificate_inventory_json(empty_req.clone()).is_empty());
        assert!(!tzap_cert_enroll_json(empty_req.clone()).is_empty());
        assert!(!tzap_cert_renew_json(empty_req.clone()).is_empty());
        assert!(!tzap_cert_revoke_json(empty_req.clone()).is_empty());
        assert!(!tzap_device_retire_json(empty_req.clone()).is_empty());
        assert!(!tzap_document_sign_json(empty_req.clone()).is_empty());
        assert!(!tzap_document_verify_json(empty_req.clone()).is_empty());
        assert!(!tzap_recipient_key_generate_json(empty_req.clone()).is_empty());
        assert!(!tzap_recipient_key_remove_json(empty_req.clone()).is_empty());
        assert!(!tzap_contact_export_json(empty_req.clone()).is_empty());
        assert!(!tzap_contact_import_json(empty_req.clone()).is_empty());
        assert!(!tzap_contact_list_json(empty_req.clone()).is_empty());
        assert!(!tzap_contact_remove_json(empty_req.clone()).is_empty());
        assert!(!tzap_share_create_json(empty_req).is_empty());
    }
}
