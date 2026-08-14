//! Stable FFI stubs for builds without the hosted TZAP profile.

fn unavailable(operation: &str) -> String {
    format!(r#"{{"ok":false,"error":"tzap-online feature not enabled in this build","operation":"{operation}"}}"#)
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

unavailable_json_endpoint!(tzap_auth_login_json, "tzap_auth_login_json");
unavailable_json_endpoint!(tzap_auth_callback_json, "tzap_auth_callback_json");
unavailable_json_endpoint!(tzap_auth_status_json, "tzap_auth_status_json");
unavailable_json_endpoint!(tzap_auth_forget_json, "tzap_auth_forget_json");
unavailable_json_endpoint!(tzap_auth_account_url_json, "tzap_auth_account_url_json");
unavailable_json_endpoint!(tzap_certificate_inventory_json, "tzap_certificate_inventory_json");
unavailable_json_endpoint!(tzap_cert_enroll_json, "tzap_cert_enroll_json");
unavailable_json_endpoint!(tzap_cert_renew_json, "tzap_cert_renew_json");
unavailable_json_endpoint!(tzap_cert_revoke_json, "tzap_cert_revoke_json");
unavailable_json_endpoint!(tzap_device_retire_json, "tzap_device_retire_json");
unavailable_json_endpoint!(tzap_document_sign_json, "tzap_document_sign_json");
pub fn tzap_document_verify_json(request_json: String) -> String {
    super::tzap_offline::tzap_document_verify_json(request_json)
}
unavailable_json_endpoint!(tzap_recipient_key_generate_json, "tzap_recipient_key_generate_json");
unavailable_json_endpoint!(tzap_recipient_key_remove_json, "tzap_recipient_key_remove_json");
unavailable_json_endpoint!(tzap_contact_export_json, "tzap_contact_export_json");
unavailable_json_endpoint!(tzap_contact_import_json, "tzap_contact_import_json");
unavailable_json_endpoint!(tzap_contact_list_json, "tzap_contact_list_json");
unavailable_json_endpoint!(tzap_contact_remove_json, "tzap_contact_remove_json");
unavailable_json_endpoint!(tzap_share_create_json, "tzap_share_create_json");
