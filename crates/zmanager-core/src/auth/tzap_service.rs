//! TZAP service endpoints in the JSON wire format consumed by shell UIs.
//!
//! This module is ported from the legacy `zmanager_ffi_*` C-ABI facade.
//! Each endpoint parses a JSON request, orchestrates `zmanager-core`, and
//! returns a JSON response envelope. The wire contracts are the same as the
//! legacy facade; the FFI crate declares them as `UniFFI` functions.

use std::fs;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509, X509NameBuilder};
use serde_json::{Value, json};

use crate::trust;
use crate::tzap_service_auth::{
    AUTH_PENDING_FILE, TzapFfiSessionStore, current_unix_seconds, default_tzap_state_dir, load_pending_auth, parse_auth_environment, save_pending_auth,
    session_summary_json, session_summary_json_at,
};

use crate::auth_client::TzapSessionStore;
use crate::jobs::{CancellationToken, JobEvent};
use crate::local_identity_store::{
    FileTzapLocalIdentityStore, TzapContactRecord, TzapEnrolledCertificateRecord, TzapLocalCertificateState, TzapLocalIdentityInventory,
    TzapLocalIdentityStore, TzapRecipientEncryptionKeyRecord,
};
use crate::manifest::PlanOptions;
use crate::secrets::SecretString;
use crate::tzap_backend::{TzapCreateOptions, TzapKeySource, TzapPublicSignatureStatus, TzapX509TrustOptions};
use crate::x509_format::{hex_lower, x509_name_to_string};

const TZAP_DEFAULT_COMPRESSION_LEVEL: i32 = 3;
const TZAP_DEFAULT_RECOVERY_PERCENTAGE: u8 = 5;
const TZAP_SINGLE_VOLUME_LOSS_TOLERANCE: u8 = 0;
const SELF_SIGNED_IDENTITY_RSA_BITS: u32 = 3072;
const SELF_SIGNED_IDENTITY_VALID_DAYS: u32 = 3_650;
const SELF_SIGNED_IDENTITY_SERIAL_BITS: i32 = 159;
const DEFAULT_TZAP_CLIENT_ID: &str = "zmanager-cli";
const DEFAULT_TZAP_REDIRECT_URI: &str = "zmanager://auth/callback";
const DEFAULT_TZAP_PROVIDER_ID: &str = "hosted";
const DEFAULT_TZAP_ACCOUNT_KEY: &str = "default";
const OP_CERT_ENROLL: &str = "cert_enroll";
const OP_CERT_RENEW: &str = "cert_renew";
const OP_CERT_REVOKE: &str = "cert_revoke";
const OP_DEVICE_RETIRE: &str = "device_retire";
const MISSING_TZAP_SESSION: &str = "no local TZAP session";
const DEV_ONLY_SELF_SIGNED_IDENTITY_KIND: &str = "dev_only_self_signed_x509_identity";

struct TzapFfiContext {
    state_dir: PathBuf,
    account_key: String,
}

impl TzapFfiContext {
    fn from_request(request: &Value) -> Result<Self, String> {
        Ok(Self {
            state_dir: request_path(request, "state_dir")?.unwrap_or_else(default_tzap_state_dir),
            account_key: request_string(request, "account_key")?.unwrap_or_else(|| DEFAULT_TZAP_ACCOUNT_KEY.to_owned()),
        })
    }
}

fn with_json_request(request_json: &str, operation: impl FnOnce(Value) -> Result<Value, String>) -> String {
    match parse_json_request(request_json).and_then(operation) {
        Ok(response) => response.to_string(),
        Err(message) => ffi_error_json(&message),
    }
}

fn parse_json_request(request_json: &str) -> Result<Value, String> {
    if request_json.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(request_json).map_err(|error| format!("invalid request JSON: {error}"))
}

pub(crate) fn request_string(request: &Value, field: &'static str) -> Result<Option<String>, String> {
    match request.get(field) {
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        None | Some(Value::Null | Value::String(_)) => Ok(None),
        _ => Err(format!("missing or invalid field: {field}")),
    }
}

pub(crate) fn required_request_string(request: &Value, field: &'static str) -> Result<String, String> {
    request_string(request, field)?.ok_or_else(|| format!("missing or invalid field: {field}"))
}

fn request_path(request: &Value, field: &'static str) -> Result<Option<PathBuf>, String> {
    Ok(request_string(request, field)?.map(PathBuf::from))
}

fn required_request_path(request: &Value, field: &'static str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(required_request_string(request, field)?))
}

pub(crate) fn request_u64(request: &Value, field: &'static str) -> Result<Option<u64>, String> {
    match request.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().ok_or_else(|| format!("missing or invalid field: {field}")).map(Some),
    }
}

fn request_i64(request: &Value, field: &'static str) -> Result<Option<i64>, String> {
    match request.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().ok_or_else(|| format!("missing or invalid field: {field}")).map(Some),
    }
}

fn request_string_array(request: &Value, field: &'static str) -> Result<Vec<String>, String> {
    match request.get(field) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| value.as_str().filter(|value| !value.is_empty()).map(str::to_owned).ok_or_else(|| format!("missing or invalid field: {field}")))
            .collect(),
        _ => Err(format!("missing or invalid field: {field}")),
    }
}

fn required_request_path_array(request: &Value, field: &'static str) -> Result<Vec<PathBuf>, String> {
    let paths = request_string_array(request, field)?.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    if paths.is_empty() { Err(format!("missing or invalid field: {field}")) } else { Ok(paths) }
}

fn run_local_tzap_service<F>(request_json: &str, action: F) -> String
where
    F: FnOnce(
        &mut FileTzapLocalIdentityStore,
        &crate::auth_client::TzapSessionRecord,
        &crate::local_tzap_service::TzapLocalServiceOptions,
        &Value,
    ) -> Result<Value, String>,
{
    match parse_json_request(request_json).and_then(|request| {
        let context = TzapFfiContext::from_request(&request)?;
        let session_store = TzapFfiSessionStore::new(&context.state_dir);
        let Some(session) = session_store.load_session(&context.account_key) else {
            return Err(MISSING_TZAP_SESSION.to_owned());
        };
        let mut identity_store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let options = crate::local_tzap_service::TzapLocalServiceOptions {
            account_key: context.account_key,
            now_unix_seconds: request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds),
        };
        action(&mut identity_store, &session, &options, &request)
    }) {
        Ok(value) => value.to_string(),
        // Single error envelope for every tzap service endpoint; consumers
        // parse `ok`/`message` only. The legacy `operation`/`error` shape
        // was dropped when the local endpoints were unified with the
        // JSON-request endpoints.
        Err(message) => ffi_error_json(&message),
    }
}

fn inventory_summary_json(inventory: &TzapLocalIdentityInventory) -> Value {
    json!({
        "device_signing_key_count": inventory.device_signing_keys.len(),
        "recipient_encryption_keys": inventory
            .recipient_encryption_keys
            .iter()
            .map(recipient_key_summary_json)
            .collect::<Vec<_>>(),
        "certificates": inventory
            .enrolled_certificates
            .iter()
            .map(certificate_summary_json)
            .collect::<Vec<_>>(),
        "contacts": inventory
            .contacts
            .iter()
            .map(contact_summary_json)
            .collect::<Vec<_>>(),
        "emergency_blocklist": {
            "blocked_root_sha256": inventory.emergency_blocklist.blocked_root_sha256,
            "blocked_issuer_sha256": inventory.emergency_blocklist.blocked_issuer_sha256,
            "updated_at_unix_seconds": inventory.emergency_blocklist.updated_at_unix_seconds,
        },
    })
}

fn certificate_summary_json(certificate: &TzapEnrolledCertificateRecord) -> Value {
    json!({
        "certificate_id": certificate.certificate_id,
        "certificate_sha256": certificate.certificate_sha256,
        "issuer_certificate_sha256": certificate.issuer_certificate_sha256,
        "issuer_key_identifier": certificate.issuer_key_identifier,
        "serial_number": certificate.serial_number,
        "not_before_unix_seconds": certificate.not_before_unix_seconds,
        "not_after_unix_seconds": certificate.not_after_unix_seconds,
        "sign_device_id": certificate.sign_device_id,
        "signing_key_id": certificate.signing_key_id,
        "state": certificate.state.as_str(),
        "active": certificate.state == TzapLocalCertificateState::Active,
        "public_metadata": {
            "version": certificate.public_metadata.version,
            "public_signer_id": certificate.public_metadata.public_signer_id,
            "public_org_id": certificate.public_metadata.public_org_id,
            "public_device_id": certificate.public_metadata.public_device_id,
            "assurance_level": certificate.public_metadata.assurance_level.as_str(),
            "policy_oid": certificate.public_metadata.policy_oid,
        },
    })
}

fn recipient_key_summary_json(record: &TzapRecipientEncryptionKeyRecord) -> Value {
    json!({
        "key_id": record.key_id,
        "algorithm": record.algorithm,
        "public_key_fingerprint": record.public_key_fingerprint,
        "public_key_der": URL_SAFE_NO_PAD.encode(&record.public_key_der),
        "created_at_unix_seconds": record.created_at_unix_seconds,
        "label": record.label,
    })
}

fn contact_summary_json(contact: &TzapContactRecord) -> Value {
    json!({
        "contact_id": contact.contact_id,
        "display_name": contact.display_name,
        "signing_certificate_sha256": contact.signing_certificate_sha256,
        "recipient_public_key_fingerprint": contact.recipient_public_key_fingerprint,
        "trust_anchor_type": contact.trust_anchor_type.as_str(),
        "verification_state": contact.verification_state.as_str(),
        "missing_status_caveat": contact.missing_status_caveat,
        "accepted_at_unix_seconds": contact.accepted_at_unix_seconds,
    })
}

fn document_verification_result_json(result: &crate::document_verification::TzapDocumentVerificationResult) -> Value {
    json!({
        "ok": result.state != trust::TzapVerificationState::Invalid,
        "state": result.state.as_str(),
        "trust_anchor_type": result.trust_anchor_type.as_str(),
        "reason": result.reason,
        "root_certificate_sha256": result.root_certificate_sha256,
        "public_metadata": result.public_metadata.as_ref().map(|metadata| {
            json!({
                "version": metadata.version,
                "public_signer_id": metadata.public_signer_id,
                "public_org_id": metadata.public_org_id,
                "public_device_id": metadata.public_device_id,
                "assurance_level": metadata.assurance_level.as_str(),
                "policy_oid": metadata.policy_oid,
            })
        }),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn retirement_completion_label(completion: crate::certificate_lifecycle::TzapRetirementCompletion) -> &'static str {
    match completion {
        crate::certificate_lifecycle::TzapRetirementCompletion::Complete => "complete",
        crate::certificate_lifecycle::TzapRetirementCompletion::Incomplete => "incomplete",
    }
}

fn create_self_signed_tzap_identity(
    identity_path: &Path,
    public_certificate_path: Option<&Path>,
    common_name: &str,
    password: &SecretString,
) -> Result<Value, String> {
    let key = PKey::from_rsa(Rsa::generate(SELF_SIGNED_IDENTITY_RSA_BITS).map_err(|source| format!("could not generate signing key: {source}"))?)
        .map_err(|source| format!("could not prepare signing key: {source}"))?;
    let certificate = create_self_signed_certificate(common_name, &key)?;
    let identity = Pkcs12::builder()
        .name(common_name)
        .pkey(&key)
        .cert(&certificate)
        .build2(password.expose_secret())
        .map_err(|source| format!("could not create PKCS#12 identity: {source}"))?;

    write_output_file(identity_path, &identity.to_der().map_err(|source| format!("could not encode PKCS#12 identity: {source}"))?)?;
    if let Some(path) = public_certificate_path {
        write_output_file(path, &certificate.to_pem().map_err(|source| format!("could not encode public certificate: {source}"))?)?;
    }

    x509_certificate_summary_json(&certificate)
}

fn create_self_signed_certificate(common_name: &str, key: &PKey<Private>) -> Result<X509, String> {
    let mut name = X509NameBuilder::new().map_err(|source| format!("could not create certificate name: {source}"))?;
    name.append_entry_by_text("CN", common_name).map_err(|source| format!("could not set certificate name: {source}"))?;
    let name = name.build();

    let mut builder = X509::builder().map_err(|source| format!("could not create certificate: {source}"))?;
    builder.set_version(2).map_err(|source| format!("could not set certificate version: {source}"))?;
    let serial = random_certificate_serial()?;
    builder.set_serial_number(&serial).map_err(|source| format!("could not set certificate serial number: {source}"))?;
    builder.set_subject_name(&name).map_err(|source| format!("could not set certificate subject: {source}"))?;
    builder.set_issuer_name(&name).map_err(|source| format!("could not set certificate issuer: {source}"))?;
    builder.set_pubkey(key).map_err(|source| format!("could not set certificate public key: {source}"))?;
    let not_before = Asn1Time::days_from_now(0).map_err(|source| format!("could not set certificate start date: {source}"))?;
    builder.set_not_before(&not_before).map_err(|source| format!("could not set certificate start date: {source}"))?;
    let not_after = Asn1Time::days_from_now(SELF_SIGNED_IDENTITY_VALID_DAYS).map_err(|source| format!("could not set certificate expiry: {source}"))?;
    builder.set_not_after(&not_after).map_err(|source| format!("could not set certificate expiry: {source}"))?;
    builder
        .append_extension(BasicConstraints::new().critical().ca().build().map_err(|source| format!("could not set certificate constraints: {source}"))?)
        .map_err(|source| format!("could not set certificate constraints: {source}"))?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_cert_sign()
                .crl_sign()
                .build()
                .map_err(|source| format!("could not set certificate key usage: {source}"))?,
        )
        .map_err(|source| format!("could not set certificate key usage: {source}"))?;
    builder.sign(key, MessageDigest::sha256()).map_err(|source| format!("could not sign certificate: {source}"))?;

    Ok(builder.build())
}

fn random_certificate_serial() -> Result<Asn1Integer, String> {
    let mut serial = BigNum::new().map_err(|source| format!("could not create serial number: {source}"))?;
    serial.rand(SELF_SIGNED_IDENTITY_SERIAL_BITS, MsbOption::MAYBE_ZERO, false).map_err(|source| format!("could not create serial number: {source}"))?;
    serial.to_asn1_integer().map_err(|source| format!("could not encode serial number: {source}"))
}

fn x509_certificate_summary_json(certificate: &X509) -> Result<Value, String> {
    let fingerprint = certificate.digest(MessageDigest::sha256()).map_err(|source| format!("could not fingerprint certificate: {source}"))?;
    let serial_number = certificate
        .serial_number()
        .to_bn()
        .map_err(|source| format!("could not read certificate serial number: {source}"))?
        .to_hex_str()
        .map_err(|source| format!("could not encode certificate serial number: {source}"))?
        .to_string();

    Ok(json!({
        "subject": x509_name_to_string(certificate.subject_name()),
        "issuer": x509_name_to_string(certificate.issuer_name()),
        "serial_number": serial_number,
        "certificate_sha256": hex_lower(fingerprint.as_ref()),
        "not_before": certificate.not_before().to_string(),
        "not_after": certificate.not_after().to_string(),
    }))
}

fn write_output_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|source| format!("could not create {}: {source}", parent.display()))?;
    }

    fs::write(path, bytes).map_err(|source| format!("could not write {}: {source}", path.display()))
}

pub fn create_tzap_self_signed_identity(identity_path: &str, public_certificate_path: Option<&str>, common_name: &str, password: &str) -> String {
    let identity_path = PathBuf::from(identity_path);
    let public_certificate_path = public_certificate_path.map(PathBuf::from);

    match create_self_signed_tzap_identity(&identity_path, public_certificate_path.as_deref(), common_name, &SecretString::from(password)) {
        Ok(certificate) => json!({
            "ok": true,
            "identity_kind": DEV_ONLY_SELF_SIGNED_IDENTITY_KIND,
            "official_tzap_signing_identity": false,
            "identity_path": identity_path.display().to_string(),
            "public_certificate_path": public_certificate_path
                .as_ref()
                .map(|path| path.display().to_string()),
            "certificate": certificate,
        })
        .to_string(),
        Err(message) => ffi_error_json(&message),
    }
}

fn tzap_public_metadata_json(summary: &crate::tzap_backend::TzapPublicMetadataSummary) -> Value {
    let volumes = summary
        .volumes
        .iter()
        .map(|volume| {
            json!({
                "index": volume.index,
                "path": volume.path.display().to_string(),
                "size": volume.size,
            })
        })
        .collect::<Vec<_>>();
    let format = &summary.format;

    json!({
        "requested_path": summary.requested_path.display().to_string(),
        "expected_volume_count": summary.expected_volume_count,
        "present_volume_count": summary.present_volume_count,
        "missing_volume_indices": &summary.missing_volume_indices,
        "total_size": summary.total_size,
        "expected_volume_size": summary.expected_volume_size,
        "volumes": volumes,
        "format": {
            "format_version": format.format_version,
            "volume_format_revision": format.volume_format_revision,
            "archive_uuid": hex_lower(&format.archive_uuid),
            "session_id": hex_lower(&format.session_id),
            "compression_algorithm": format.compression_algorithm,
            "encryption_algorithm": format.encryption_algorithm,
            "recovery_algorithm": format.recovery_algorithm,
            "key_derivation": format.key_derivation,
            "password_required": format.password_required,
            "bit_rot_buffer_percentage": format.bit_rot_buffer_percentage,
            "volume_loss_tolerance": format.volume_loss_tolerance,
            "data_shard_count": format.data_shard_count,
            "parity_shard_count": format.parity_shard_count,
            "index_data_shard_count": format.index_data_shard_count,
            "index_parity_shard_count": format.index_parity_shard_count,
            "index_root_data_shard_count": format.index_root_data_shard_count,
            "index_root_parity_shard_count": format.index_root_parity_shard_count,
            "block_size": format.block_size,
            "chunk_size": format.chunk_size,
            "envelope_target_size": format.envelope_target_size,
            "has_dictionary": format.has_dictionary,
        },
    })
}
fn tzap_x509_root_auth_json(report: &crate::tzap_backend::TzapX509VerificationReport) -> Value {
    let status = report.diagnostics.first().map_or("root_auth_content_verified", String::as_str);
    json!({
        "status": status,
        "diagnostics": &report.diagnostics,
        "authenticator": "x509",
        "archive_root": hex_lower(&report.archive_root),
        "authenticator_id": report.authenticator_id,
        "signer_identity_type": report.signer_identity_type,
        "total_data_block_count": report.total_data_block_count,
        "signature_verified": true,
        "trust_validated": true,
        "subject": report.subject,
        "issuer": report.issuer,
        "serial_number": report.serial_number_hex,
        "certificate_sha256": hex_lower(&report.certificate_sha256),
        "signed_at_unix_seconds": report.signed_at_unix_seconds,
        "verified_chain_subjects": report.verified_chain_subjects,
        "trust_anchor_subject": report.trust_anchor_subject,
    })
}
fn tzap_x509_signer_inspection_json(report: &crate::tzap_backend::TzapX509SignerInspection) -> Value {
    let status = report.diagnostics.first().map_or("root_auth_signer_inspected", String::as_str);
    json!({
        "status": status,
        "diagnostics": &report.diagnostics,
        "authenticator": "x509",
        "archive_root": hex_lower(&report.archive_root),
        "authenticator_id": report.authenticator_id,
        "signer_identity_type": report.signer_identity_type,
        "total_data_block_count": report.total_data_block_count,
        "signature_verified": true,
        "trust_validated": false,
        "subject": report.subject,
        "issuer": report.issuer,
        "serial_number": report.serial_number_hex,
        "certificate_sha256": hex_lower(&report.certificate_sha256),
        "signed_at_unix_seconds": report.signed_at_unix_seconds,
        "verified_chain_subjects": [],
        "trust_anchor_subject": Value::Null,
    })
}
fn ffi_error_json(message: &str) -> String {
    json!({
        "ok": false,
        "message": message,
    })
    .to_string()
}
/// Verifies the X.509 `RootAuth` signer of a `.tzap` archive with an optional
/// password and explicit trust sources, returning a JSON response envelope.
#[must_use]
pub fn verify_tzap_x509(archive_path: &str, password: Option<&str>, trusted_ca_certs: &[String], trusted_system_roots: bool) -> String {
    let trust = tzap_x509_trust_options(trusted_ca_certs, trusted_system_roots);
    if !trust.has_trust_source() {
        return ffi_error_json("X.509 verification requires trusted roots");
    }
    match crate::tzap_backend::test_tzap_with_optional_password_filter_and_x509_trust(PathBuf::from(archive_path), password, |_| true, Some(&trust)) {
        Ok(report) => match report.x509_root_auth.as_ref() {
            Some(root_auth) => json!({
                "ok": true,
                "entries": report.entries,
                "tested_entries": report.tested_entries,
                "skipped_entries": report.skipped_entries,
                "tested_bytes": report.tested_bytes,
                "root_auth": tzap_x509_root_auth_json(root_auth),
            })
            .to_string(),
            None => ffi_error_json("missing X.509 RootAuth verification report"),
        },
        Err(error) => ffi_error_json(&error.to_string()),
    }
}

/// Verifies the X.509 `RootAuth` signer of a `.tzap` archive without the
/// archive key, using explicit trust sources.
#[must_use]
pub fn verify_tzap_x509_public_no_key(archive_path: &str, trusted_ca_certs: &[String], trusted_system_roots: bool) -> String {
    let trust = tzap_x509_trust_options(trusted_ca_certs, trusted_system_roots);
    if !trust.has_trust_source() {
        return ffi_error_json("X.509 verification requires trusted roots");
    }
    match crate::tzap_backend::verify_tzap_x509_public_no_key(PathBuf::from(archive_path), &trust) {
        Ok(root_auth) => json!({
            "ok": true,
            "verification_mode": "public-no-key",
            "root_auth": tzap_x509_root_auth_json(&root_auth),
            "public_diagnostics": &root_auth.diagnostics,
        })
        .to_string(),
        Err(error) => ffi_error_json(&error.to_string()),
    }
}

/// Inspects the X.509 `RootAuth` signer of a `.tzap` archive with an optional
/// password, returning a JSON response envelope.
#[must_use]
pub fn inspect_tzap_x509_signer(archive_path: &str, password: Option<&str>) -> String {
    match crate::tzap_backend::inspect_tzap_x509_signer(PathBuf::from(archive_path), password) {
        Ok(report) => json!({
            "ok": true,
            "inspection_mode": "full",
            "root_auth": tzap_x509_signer_inspection_json(&report),
        })
        .to_string(),
        Err(error) => ffi_error_json(&error.to_string()),
    }
}

/// Inspects the X.509 `RootAuth` signer of a `.tzap` archive without the
/// archive key, returning a JSON response envelope.
#[must_use]
pub fn inspect_tzap_x509_public_no_key_signer(archive_path: &str) -> String {
    match crate::tzap_backend::inspect_tzap_x509_public_no_key_signer(PathBuf::from(archive_path)) {
        Ok(report) => json!({
            "ok": true,
            "inspection_mode": "public-no-key",
            "root_auth": tzap_x509_signer_inspection_json(&report),
        })
        .to_string(),
        Err(error) => ffi_error_json(&error.to_string()),
    }
}

/// Returns the public metadata summary for a `.tzap` archive as a JSON string.
///
/// The response envelope is `{ok, metadata, signature}` where `signature`
/// carries the X.509 `RootAuth` status when the archive is signed.
#[must_use]
pub fn tzap_public_metadata_summary(archive_path: &str) -> String {
    let archive_path = PathBuf::from(archive_path);
    match crate::tzap_backend::summarize_tzap_public_metadata(&archive_path) {
        Ok(summary) => {
            let signature = match crate::tzap_backend::verify_tzap_x509_public_no_key(
                &archive_path,
                &TzapX509TrustOptions { trusted_ca_certificates: Vec::new(), trusted_system_roots: true, include_official_tzap_root: true },
            ) {
                Ok(root_auth) => json!({
                    "status": "verified",
                    "verification_mode": "public-no-key",
                    "root_auth": tzap_x509_root_auth_json(&root_auth),
                }),
                Err(error) => match crate::tzap_backend::inspect_tzap_x509_public_no_key_signer(&archive_path) {
                    Ok(root_auth) => json!({
                        "status": "unverified",
                        "verification_mode": "public-no-key-inspection",
                        "message": format!(
                            "Signer certificate inspected, but trust was not verified: {error}"
                        ),
                        "root_auth": tzap_x509_signer_inspection_json(&root_auth),
                    }),
                    Err(_) => json!({
                        "status": "unverified",
                        "message": error.to_string(),
                    }),
                },
            };
            json!({
                "ok": true,
                "metadata": tzap_public_metadata_json(&summary),
                "signature": signature,
            })
            .to_string()
        }
        Err(error) => ffi_error_json(&error.to_string()),
    }
}

/// Returns a bounded display summary for a `.tzap` archive as a JSON string.
///
/// The response envelope is `{ok, metadata, signature}` — the same envelope as
/// [`tzap_public_metadata_summary`] — but `signature` carries a different,
/// footer-derived vocabulary: `status` is `signed`, `unsigned`,
/// `not_authentic`, or `unavailable` (a `signed` payload embeds the signer
/// inspection without trust validation; `verified`/`unverified` from
/// [`tzap_public_metadata_summary`] do not appear here). Footer inspection is
/// assertion 1 only (the embedded certificate's key really signed the footer);
/// archive contents are never read, so a `signed` payload is explicitly marked
/// `verification_scope: "footer-only"` and `content_verified: false` — the
/// summary is bounded regardless of archive size. Content integrity and
/// trust-chain validation remain the explicit `verify_tzap_x509_public_no_key`
/// surface.
#[must_use]
pub fn tzap_public_metadata_display_summary(archive_path: &str) -> String {
    let archive_path = PathBuf::from(archive_path);
    match crate::tzap_backend::summarize_tzap_public_display(&archive_path) {
        Ok(summary) => {
            let signature = match &summary.signature {
                TzapPublicSignatureStatus::Signed { signer } => json!({
                    "status": "signed",
                    "verification_scope": "footer-only",
                    "content_verified": false,
                    "root_auth": tzap_x509_signer_inspection_json(signer),
                }),
                TzapPublicSignatureStatus::Unsigned => json!({
                    "status": "unsigned",
                }),
                TzapPublicSignatureStatus::NotAuthentic { reason } => json!({
                    "status": "not_authentic",
                    "message": reason,
                }),
                TzapPublicSignatureStatus::Unavailable { reason } => json!({
                    "status": "unavailable",
                    "message": reason,
                }),
            };
            json!({
                "ok": true,
                "metadata": tzap_public_metadata_json(&summary.metadata),
                "signature": signature,
            })
            .to_string()
        }
        Err(error) => ffi_error_json(&error.to_string()),
    }
}

fn tzap_x509_trust_options(trusted_ca_certs: &[String], trusted_system_roots: bool) -> TzapX509TrustOptions {
    TzapX509TrustOptions {
        trusted_ca_certificates: trusted_ca_certs.iter().map(PathBuf::from).collect(),
        trusted_system_roots,
        include_official_tzap_root: false,
    }
}

/// Builds the custom trust root inputs from the request (CR-113: the service
/// adopted the CLI's `--custom-trust-root-cert` behavior — PEM/DER files are
/// loaded and fingerprinted alongside the explicit SHA-256 pins).
fn custom_trust_roots_from_request(request: &Value) -> Result<(Vec<String>, Vec<Vec<u8>>), String> {
    let mut custom_trust_root_sha256 = request_string_array(request, "custom_trust_root_sha256")?;
    let custom_root_cert_paths = request_string_array(request, "custom_trust_root_cert_paths")?.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    let custom_trust_root_certificates_der = trust::load_custom_root_certificate_files(&custom_root_cert_paths, &mut custom_trust_root_sha256)?;
    Ok((custom_trust_root_sha256, custom_trust_root_certificates_der))
}

#[must_use]
pub fn tzap_auth_login_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let environment = request
            .get("environment")
            .and_then(Value::as_str)
            .map(parse_auth_environment)
            .transpose()?
            .unwrap_or(crate::auth_client::TzapHostedAuthEnvironment::Prod);
        let client_id = request_string(&request, "client_id")?.unwrap_or_else(|| DEFAULT_TZAP_CLIENT_ID.into());
        let redirect_uri = request_string(&request, "redirect_uri")?.unwrap_or_else(|| DEFAULT_TZAP_REDIRECT_URI.into());
        let provider_id = request_string(&request, "provider_id")?.unwrap_or_else(|| DEFAULT_TZAP_PROVIDER_ID.into());
        let now_unix_seconds = request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds);

        let mut tracker = crate::auth_client::TzapOAuthStateTracker::new();
        let pending = tracker.begin(provider_id, redirect_uri.clone(), now_unix_seconds);

        let mut config = crate::auth_client::TzapHostedAuthLaunchConfig::for_environment(environment, client_id, redirect_uri);
        if let Some(auth_base_url) = request_string(&request, "auth_base_url")? {
            config.hosted_auth_base_url = auth_base_url;
        }
        if let Some(account_base_url) = request_string(&request, "account_base_url")? {
            config.hosted_account_base_url = account_base_url;
        }
        config.selected_org_id = request_string(&request, "org_id")?;
        // Persist the login metadata too (CR-113): the callback's
        // handoff-code exchange needs `client_id`/`auth_base_url` without
        // the caller repeating the login options.
        save_pending_auth(&context.state_dir, &pending, &config).map_err(|error| error.to_string())?;
        let launch_url = config.launch_url(&pending).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "status": "pending",
            "launch_url": launch_url,
            "state": pending.state,
            "expires_at_unix_seconds": pending
                .created_at_unix_seconds
                .saturating_add(crate::auth_client::AUTH_HANDOFF_LIFETIME_SECONDS),
        }))
    })
}

#[must_use]
pub fn tzap_auth_callback_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let pending = load_pending_auth(&context.state_dir)?;
        let state = required_request_string(&request, "state")?;
        let redirect_uri = request_string(&request, "redirect_uri")?.unwrap_or_else(|| DEFAULT_TZAP_REDIRECT_URI.into());
        let relay_body = required_request_string(&request, "relay_body")?.into_bytes();
        let callback = crate::auth_client::TzapHostedAuthCallback {
            state,
            redirect_uri,
            pkce_verifier: pending.pkce.verifier.clone(),
            callback_url: request_string(&request, "callback_url")?,
            relay_body,
        };
        let mut tracker = crate::auth_client::TzapOAuthStateTracker::new();
        tracker.insert_pending(pending).map_err(|error| error.to_string())?;
        let mut session_store = TzapFfiSessionStore::new(&context.state_dir);
        let session = crate::auth_client::complete_hosted_auth_handoff(
            &mut tracker,
            &mut session_store,
            &context.account_key,
            &callback,
            request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds),
        )
        .map_err(|error| error.to_string())?;
        let _ = fs::remove_file(context.state_dir.join(AUTH_PENDING_FILE));
        Ok(json!({
            "ok": true,
            "authenticated": true,
            "session": session_summary_json(&session),
        }))
    })
}

#[must_use]
pub fn tzap_auth_status_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let store = TzapFfiSessionStore::new(&context.state_dir);
        let now = request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds);
        Ok(match store.load_session(&context.account_key) {
            Some(session) => json!({
                "ok": true,
                "authenticated": true,
                "session": session_summary_json_at(&session, now),
            }),
            None => json!({
                "ok": true,
                "authenticated": false,
            }),
        })
    })
}

#[must_use]
pub fn tzap_auth_forget_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let mut store = TzapFfiSessionStore::new(&context.state_dir);
        store.clear_session(&context.account_key).map_err(|error| error.to_string())?;
        let _ = fs::remove_file(context.state_dir.join(AUTH_PENDING_FILE));
        Ok(json!({
            "ok": true,
            "forgotten": true,
        }))
    })
}

#[must_use]
pub fn tzap_auth_account_url_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let environment = request
            .get("environment")
            .and_then(Value::as_str)
            .map(parse_auth_environment)
            .transpose()?
            .unwrap_or(crate::auth_client::TzapHostedAuthEnvironment::Prod);
        let client_id = request_string(&request, "client_id")?.unwrap_or_else(|| DEFAULT_TZAP_CLIENT_ID.into());
        let redirect_uri = request_string(&request, "redirect_uri")?.unwrap_or_else(|| DEFAULT_TZAP_REDIRECT_URI.into());
        let mut config = crate::auth_client::TzapHostedAuthLaunchConfig::for_environment(environment, client_id, redirect_uri);
        if let Some(account_base_url) = request_string(&request, "account_base_url")? {
            config.hosted_account_base_url = account_base_url;
        }
        config.selected_org_id = request_string(&request, "org_id")?;
        Ok(json!({
            "ok": true,
            "account_url": config.account_url(),
        }))
    })
}

#[must_use]
pub fn tzap_certificate_inventory_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let inventory = store.load_inventory(&context.account_key).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "inventory": inventory_summary_json(&inventory),
        }))
    })
}

#[must_use]
pub fn tzap_cert_enroll_json(request_json: &str) -> String {
    run_local_tzap_service(request_json, |store, session, options, _| {
        crate::local_tzap_service::enroll_local_certificate(store, session, options)
            .map(|certificate| {
                json!({
                    "ok": true,
                    "operation": OP_CERT_ENROLL,
                    "certificate": certificate_summary_json(&certificate),
                })
            })
            .map_err(|error| error.to_string())
    })
}

#[must_use]
pub fn tzap_cert_renew_json(request_json: &str) -> String {
    run_local_tzap_service(request_json, |store, session, options, request| {
        let certificate_id = required_request_string(request, "certificate_id")?;
        crate::local_tzap_service::renew_local_certificate(store, session, options, &certificate_id)
            .map(|certificate| {
                json!({
                    "ok": true,
                    "operation": OP_CERT_RENEW,
                    "certificate": certificate_summary_json(&certificate),
                })
            })
            .map_err(|error| error.to_string())
    })
}

#[must_use]
pub fn tzap_cert_revoke_json(request_json: &str) -> String {
    run_local_tzap_service(request_json, |store, session, options, request| {
        let certificate_id = required_request_string(request, "certificate_id")?;
        crate::local_tzap_service::revoke_local_certificate(store, session, options, &certificate_id)
            .map(|completion| {
                json!({
                    "ok": true,
                    "operation": OP_CERT_REVOKE,
                    "completion": retirement_completion_label(completion),
                })
            })
            .map_err(|error| error.to_string())
    })
}

#[must_use]
pub fn tzap_device_retire_json(request_json: &str) -> String {
    run_local_tzap_service(request_json, |store, session, options, _| {
        crate::local_tzap_service::retire_local_device(store, session, options)
            .map(|report| {
                json!({
                    "ok": true,
                    "operation": OP_DEVICE_RETIRE,
                    "completion": retirement_completion_label(report.completion),
                    "attempted_sign_device_ids": report.attempted_sign_device_ids,
                })
            })
            .map_err(|error| error.to_string())
    })
}

#[must_use]
pub fn tzap_document_sign_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let certificate_id = required_request_string(&request, "certificate_id")?;
        let payload = request.get("payload").cloned().ok_or_else(|| "missing or invalid field: payload".to_owned())?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let mut signing_request = crate::document_signing::TzapDocumentSigningRequest::new(
            context.account_key,
            certificate_id,
            request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds),
        );
        signing_request.claimed_signing_time = request_string(&request, "claimed_signing_time")?;
        let envelope = crate::document_signing::sign_tzap_document_payload(&store, &signing_request, payload).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "envelope": envelope,
        }))
    })
}

#[must_use]
pub fn tzap_document_verify_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let envelope = request.get("envelope").ok_or_else(|| "missing or invalid field: envelope".to_owned())?;
        let bytes = serde_json::to_vec(envelope).map_err(|error| error.to_string())?;
        let (custom_trust_root_sha256, custom_trust_root_certificates_der) = custom_trust_roots_from_request(&request)?;
        let options = crate::document_verification::TzapOfflineVerificationOptions {
            verifier_time_unix_seconds: request_i64(&request, "verifier_time_unix_seconds")?
                .unwrap_or_else(|| i64::try_from(current_unix_seconds()).unwrap_or(i64::MAX)),
            official_root_pins: &trust::OFFICIAL_TZAP_ROOT_PINS,
            official_root_certificates_der: Vec::new(),
            custom_trust_root_sha256,
            custom_trust_root_certificates_der,
            certificate_profile_options: trust::TzapCertificateProfileOptions::default(),
        };
        let result = crate::document_verification::verify_tzap_document_envelope_offline_json(&bytes, &options);
        if request_string(&request, "mode")?.as_deref().unwrap_or("offline") == "offline" || result.state == trust::TzapVerificationState::Invalid {
            return Ok(document_verification_result_json(&result));
        }
        if request_string(&request, "mode")?.as_deref() != Some("valid_now") {
            return Err("document verify mode must be offline or valid_now".to_owned());
        }
        let envelope = crate::document_envelope::parse_tzap_document_envelope_json(&bytes).map_err(|error| error.to_string())?;
        let status_value = request.get("status_response").ok_or_else(|| "missing or invalid field: status_response".to_owned())?;
        let status = crate::status_client::TzapStatusResponse::from_json_value(status_value).map_err(|error| error.to_string())?;
        let result = crate::status_client::verify_tzap_document_envelope_valid_now(&envelope, &options, &status);
        Ok(document_verification_result_json(&result))
    })
}

#[must_use]
pub fn tzap_recipient_key_generate_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let material = crate::device_identity::generate_recipient_encryption_key().map_err(|error| error.to_string())?;
        let record = TzapRecipientEncryptionKeyRecord {
            key_id: material.public_key_fingerprint.clone(),
            algorithm: material.algorithm.to_owned(),
            public_key_fingerprint: material.public_key_fingerprint,
            public_key_der: material.public_key_spki_der,
            private_key_der: material.private_key_der,
            created_at_unix_seconds: request_u64(&request, "created_at_unix_seconds")?.unwrap_or_else(current_unix_seconds),
            label: request_string(&request, "label")?,
        };
        let mut store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let mut inventory = store.load_inventory(&context.account_key).map_err(|error| error.to_string())?;
        inventory.recipient_encryption_keys.retain(|existing| existing.key_id != record.key_id);
        inventory.recipient_encryption_keys.push(record.clone());
        store.save_inventory(&context.account_key, inventory).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "recipient_key": recipient_key_summary_json(&record),
        }))
    })
}

#[must_use]
pub fn tzap_recipient_key_remove_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let key_id = required_request_string(&request, "key_id")?;
        let mut store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let mut inventory = store.load_inventory(&context.account_key).map_err(|error| error.to_string())?;
        let before = inventory.recipient_encryption_keys.len();
        inventory.recipient_encryption_keys.retain(|record| record.key_id != key_id);
        let removed = before != inventory.recipient_encryption_keys.len();
        store.save_inventory(&context.account_key, inventory).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "removed": removed,
        }))
    })
}

#[must_use]
pub fn tzap_contact_export_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let export_request = crate::contact_card::TzapContactCardExportRequest {
            account_key: context.account_key,
            recipient_key_id: required_request_string(&request, "recipient_key_id")?,
            certificate_id: required_request_string(&request, "certificate_id")?,
            display_name: required_request_string(&request, "display_name")?,
            device_label: request_string(&request, "device_label")?.unwrap_or_else(|| "ZManager".to_owned()),
            created_at_unix_seconds: request_u64(&request, "created_at_unix_seconds")?.unwrap_or_else(current_unix_seconds),
            expires_at_unix_seconds: request_u64(&request, "expires_at_unix_seconds")?,
        };
        let card = crate::contact_card::export_tzap_contact_card(&store, &export_request).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "contact_card": card,
        }))
    })
}

#[must_use]
pub fn tzap_contact_import_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let card = request.get("contact_card").cloned().ok_or_else(|| "missing or invalid field: contact_card".to_owned())?;
        let (custom_trust_root_sha256, custom_trust_root_certificates_der) = custom_trust_roots_from_request(&request)?;
        let options = crate::contact_card::TzapContactCardImportOptions {
            verifier_time_unix_seconds: request_i64(&request, "verifier_time_unix_seconds")?
                .unwrap_or_else(|| i64::try_from(current_unix_seconds()).unwrap_or(i64::MAX)),
            official_root_pins: &trust::OFFICIAL_TZAP_ROOT_PINS,
            official_root_certificates_der: Vec::new(),
            custom_trust_root_sha256,
            custom_trust_root_certificates_der,
            certificate_profile_options: trust::TzapCertificateProfileOptions::default(),
        };
        let mut store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let accepted_at = request
            .get("accept")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            .then_some(request_u64(&request, "accepted_at_unix_seconds")?.unwrap_or_else(current_unix_seconds));
        let contact =
            crate::contact_card::import_tzap_contact_card(&mut store, &context.account_key, &card, &options, accepted_at).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "contact": contact_summary_json(&contact),
        }))
    })
}

#[must_use]
pub fn tzap_contact_list_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let inventory = store.load_inventory(&context.account_key).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "contacts": inventory
                .contacts
                .iter()
                .map(contact_summary_json)
                .collect::<Vec<_>>(),
        }))
    })
}

#[must_use]
pub fn tzap_contact_remove_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let contact_id = required_request_string(&request, "contact_id")?;
        let mut store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let mut inventory = store.load_inventory(&context.account_key).map_err(|error| error.to_string())?;
        let before = inventory.contacts.len();
        inventory.contacts.retain(|contact| contact.contact_id != contact_id);
        let removed = before != inventory.contacts.len();
        store.save_inventory(&context.account_key, inventory).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "removed": removed,
        }))
    })
}

#[must_use]
pub fn tzap_share_create_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let destination = required_request_path(&request, "destination")?;
        let sources = required_request_path_array(&request, "sources")?;
        let contact_ids = request_string_array(&request, "contact_ids")?;
        let now_unix_seconds = request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds);
        let certificate_id = request_string(&request, "certificate_id")?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        // CR-113: the share endpoint adopts the CLI's engine — resolve the
        // X.509 signing material from the local inventory (when a
        // `certificate_id` is requested) and create through the manifest
        // path with progress, instead of the job path without signing.
        let x509_signing = match certificate_id.as_deref() {
            Some(certificate_id) => Some(
                crate::tzap_backend::tzap_x509_signing_options_from_inventory(&store, &context.account_key, certificate_id, now_unix_seconds)
                    .map_err(|error| error.clone())?,
            ),
            None => None,
        };
        let recipients = crate::contact_card::accepted_contact_recipients(&store, &context.account_key, &contact_ids, now_unix_seconds)
            .map_err(|error| error.to_string())?;
        let recipient_status_caveats = recipients.iter().filter(|recipient| recipient.missing_status_caveat).count();
        let recipient_public_keys = recipients.into_iter().map(|recipient| recipient.recipient_public_key_der).collect();
        let options = TzapCreateOptions {
            key_source: TzapKeySource::RecipientPublicKeys(recipient_public_keys),
            level: TZAP_DEFAULT_COMPRESSION_LEVEL,
            preserve_metadata: true,
            replace_existing: request.get("replace_existing").and_then(Value::as_bool).unwrap_or(false),
            volume_size: None,
            recovery_percentage: TZAP_DEFAULT_RECOVERY_PERCENTAGE,
            volume_loss_tolerance: TZAP_SINGLE_VOLUME_LOSS_TOLERANCE,
            x509_signing,
        };
        let manifest = crate::manifest::plan_archives(&sources, &PlanOptions::default()).map_err(|error| error.to_string())?;
        let token = CancellationToken::new();
        let mut event_sink = |_event: JobEvent| {};
        let mut job_context = crate::jobs::JobContext::new_with_progress_total(&token, &mut event_sink, Some(manifest.total_bytes));
        let report = crate::tzap_backend::create_tzap_from_manifest_with_context(&manifest, &destination, &options, &mut job_context)
            .map_err(|error| error.to_string())?;
        job_context.flush_progress();
        let mut response = json!({
            "ok": true,
            "archive": destination.display().to_string(),
            "format": "tzap",
            "entries": report.written_entries,
            "bytes": report.written_bytes,
            "recipients": contact_ids.len(),
            "recipient_status_caveats": recipient_status_caveats,
            "volume_count": report.volume_count,
        });
        if let Some(certificate_id) = certificate_id {
            response["signed"] = json!(true);
            response["certificate_id"] = json!(certificate_id);
        }
        Ok(response)
    })
}
