#![allow(non_snake_case)]
//! Offline-build stubs for the TZAP service endpoints.
//!
//! Compiled when the `auth` feature is off: the UniFFI contract keeps
//! every method (the generated scaffolding references them all), but the
//! operations report that the feature is not enabled in this build.

fn unavailable(operation: &str) -> String {
    format!(r#"{{"ok":false,"error":"auth feature not enabled in this build","operation":"{operation}"}}"#)
}

pub fn tzapPublicMetadataSummary(_archive_path: String) -> String {
    unavailable("tzapPublicMetadataSummary")
}

pub fn tzapPublicMetadataDisplaySummary(_archive_path: String) -> String {
    unavailable("tzapPublicMetadataDisplaySummary")
}

pub fn verifyTzapX509(_archive_path: String, _password: Option<String>, _trusted_ca_certs: Vec<String>, _trusted_system_roots: bool) -> String {
    unavailable("verifyTzapX509")
}

pub fn verifyTzapX509PublicNoKey(_archive_path: String, _trusted_ca_certs: Vec<String>, _trusted_system_roots: bool) -> String {
    unavailable("verifyTzapX509PublicNoKey")
}

pub fn inspectTzapX509Signer(_archive_path: String, _password: Option<String>) -> String {
    unavailable("inspectTzapX509Signer")
}

pub fn inspectTzapX509PublicNoKeySigner(_archive_path: String) -> String {
    unavailable("inspectTzapX509PublicNoKeySigner")
}

pub fn createTzapSelfSignedIdentity(_identity_path: String, _public_certificate_path: String, _common_name: String, _password: String) -> String {
    unavailable("createTzapSelfSignedIdentity")
}

pub fn tzap_auth_login_json(_request_json: String) -> String {
    unavailable("tzap_auth_login_json")
}

pub fn tzap_auth_callback_json(_request_json: String) -> String {
    unavailable("tzap_auth_callback_json")
}

pub fn tzap_auth_status_json(_request_json: String) -> String {
    unavailable("tzap_auth_status_json")
}

pub fn tzap_auth_forget_json(_request_json: String) -> String {
    unavailable("tzap_auth_forget_json")
}

pub fn tzap_auth_account_url_json(_request_json: String) -> String {
    unavailable("tzap_auth_account_url_json")
}

pub fn tzap_certificate_inventory_json(_request_json: String) -> String {
    unavailable("tzap_certificate_inventory_json")
}

pub fn tzap_cert_enroll_json(_request_json: String) -> String {
    unavailable("tzap_cert_enroll_json")
}

pub fn tzap_cert_renew_json(_request_json: String) -> String {
    unavailable("tzap_cert_renew_json")
}

pub fn tzap_cert_revoke_json(_request_json: String) -> String {
    unavailable("tzap_cert_revoke_json")
}

pub fn tzap_device_retire_json(_request_json: String) -> String {
    unavailable("tzap_device_retire_json")
}

pub fn tzap_document_sign_json(_request_json: String) -> String {
    unavailable("tzap_document_sign_json")
}

pub fn tzap_document_verify_json(_request_json: String) -> String {
    unavailable("tzap_document_verify_json")
}

pub fn tzap_recipient_key_generate_json(_request_json: String) -> String {
    unavailable("tzap_recipient_key_generate_json")
}

pub fn tzap_recipient_key_remove_json(_request_json: String) -> String {
    unavailable("tzap_recipient_key_remove_json")
}

pub fn tzap_contact_export_json(_request_json: String) -> String {
    unavailable("tzap_contact_export_json")
}

pub fn tzap_contact_import_json(_request_json: String) -> String {
    unavailable("tzap_contact_import_json")
}

pub fn tzap_contact_list_json(_request_json: String) -> String {
    unavailable("tzap_contact_list_json")
}

pub fn tzap_contact_remove_json(_request_json: String) -> String {
    unavailable("tzap_contact_remove_json")
}

pub fn tzap_share_create_json(_request_json: String) -> String {
    unavailable("tzap_share_create_json")
}
