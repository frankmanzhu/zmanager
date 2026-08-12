//! Public TZAP trust distribution, status, bulk-status, and CRL client helpers.

use crate::auth_client::{TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpResponse, TzapAuthHttpTransport};
pub use crate::crl::validate_crl_der_against_manifest;
use crate::crl::{crl_download_to_der, optional_unix_or_rfc3339, parse_crl_manifest};
use crate::document_verification::{TzapDocumentVerificationResult, TzapOfflineVerificationOptions, verify_tzap_document_envelope_offline};
use crate::http_client::{require_success, send_json_request};
use crate::json_util::{json_object, required_string};
use crate::trust::{self, TzapCertificateStatus, TzapTrustAnchorType, TzapVerificationState};
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::fmt;

pub const STATUS_FRESHNESS_SKEW_SECONDS: i64 = 5 * 60;
pub const MAX_POSITIVE_STATUS_WINDOW_SECONDS: i64 = 24 * 60 * 60;
pub const MIN_BULK_LOOKUPS: usize = 1;
pub const MAX_BULK_LOOKUPS: usize = 100;

#[derive(Debug)]
pub enum TzapStatusClientError {
    Auth(TzapAuthError),
    InvalidJson(serde_json::Error),
    InvalidField { field: &'static str },
    InvalidBulkLookup { reason: &'static str },
    HttpStatus { status_code: u16 },
    CrlValidation { reason: String },
}

impl fmt::Display for TzapStatusClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(error) => write!(f, "status client auth failed: {error}"),
            Self::InvalidJson(error) => write!(f, "status JSON is invalid: {error}"),
            Self::InvalidField { field } => write!(f, "status field is invalid: {field}"),
            Self::InvalidBulkLookup { reason } => {
                write!(f, "bulk status lookup is invalid: {reason}")
            }
            Self::HttpStatus { status_code } => {
                write!(f, "status HTTP request failed with status {status_code}")
            }
            Self::CrlValidation { reason } => write!(f, "CRL validation failed: {reason}"),
        }
    }
}

impl std::error::Error for TzapStatusClientError {}

impl From<TzapAuthError> for TzapStatusClientError {
    fn from(error: TzapAuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<serde_json::Error> for TzapStatusClientError {
    fn from(error: serde_json::Error) -> Self {
        Self::InvalidJson(error)
    }
}

pub struct TzapStatusClient<'a, T> {
    sign_base_url: String,
    transport: &'a T,
}

impl<'a, T: TzapAuthHttpTransport> TzapStatusClient<'a, T> {
    #[must_use]
    pub fn new(sign_base_url: impl Into<String>, transport: &'a T) -> Self {
        Self { sign_base_url: sign_base_url.into(), transport }
    }

    pub fn status_by_fingerprint(&self, certificate_sha256: &str) -> Result<TzapStatusResponse, TzapStatusClientError> {
        let path = trust::status_certificate_by_fingerprint_path(certificate_sha256).map_err(|_| TzapStatusClientError::InvalidField { field: "certificate_sha256" })?;
        let bytes = self.get_bytes(&path)?;
        TzapStatusResponse::from_json_bytes(&bytes)
    }

    pub fn bulk_status(&self, lookups: &[TzapBulkStatusLookup]) -> Result<Vec<TzapBulkStatusItem>, TzapStatusClientError> {
        validate_bulk_lookups(lookups)?;
        let body = json!({
            "lookups": lookups.iter().map(TzapBulkStatusLookup::to_json).collect::<Vec<_>>(),
        });
        let response = self.send_json(TzapAuthHttpMethod::Post, trust::STATUS_BULK_PATH, Some(body))?;
        parse_bulk_status_response(&response.body, lookups)
    }

    pub fn crl_manifest(&self) -> Result<Vec<TzapCrlManifestEntry>, TzapStatusClientError> {
        let bytes = self.get_bytes(trust::STATUS_CRL_MANIFEST_PATH)?;
        parse_crl_manifest(&bytes)
    }

    pub fn crl_der(&self, issuer_sha256: &str) -> Result<Vec<u8>, TzapStatusClientError> {
        let path = trust::status_crl_pem_path(issuer_sha256).map_err(|_| TzapStatusClientError::InvalidField { field: "issuer_sha256" })?;
        crl_download_to_der(&self.get_bytes(&path)?)
    }

    fn get_bytes(&self, path: &str) -> Result<Vec<u8>, TzapStatusClientError> {
        Ok(self.send_json(TzapAuthHttpMethod::Get, path, None)?.body)
    }

    fn send_json(&self, method: TzapAuthHttpMethod, path: &str, body: Option<Value>) -> Result<TzapAuthHttpResponse, TzapStatusClientError> {
        let response = send_json_request(self.transport, method, &self.sign_base_url, path, None, body)?;
        require_success(response, |status_code, _| TzapStatusClientError::HttpStatus { status_code })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapBulkStatusLookupForm {
    CertificateFingerprint { certificate_sha256: String },
    IssuerSerial { issuer_certificate_sha256: String, serial_number: String },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapBulkStatusLookup {
    pub lookup_id: String,
    pub form: TzapBulkStatusLookupForm,
}

impl TzapBulkStatusLookup {
    #[must_use]
    pub fn by_fingerprint(lookup_id: impl Into<String>, certificate_sha256: impl Into<String>) -> Self {
        Self { lookup_id: lookup_id.into(), form: TzapBulkStatusLookupForm::CertificateFingerprint { certificate_sha256: certificate_sha256.into() } }
    }

    #[must_use]
    pub fn by_issuer_serial(lookup_id: impl Into<String>, issuer_certificate_sha256: impl Into<String>, serial_number: impl Into<String>) -> Self {
        Self { lookup_id: lookup_id.into(), form: TzapBulkStatusLookupForm::IssuerSerial { issuer_certificate_sha256: issuer_certificate_sha256.into(), serial_number: serial_number.into() } }
    }

    fn to_json(&self) -> Value {
        match &self.form {
            TzapBulkStatusLookupForm::CertificateFingerprint { certificate_sha256 } => json!({
                "lookup_id": self.lookup_id,
                "certificate_sha256": certificate_sha256,
            }),
            TzapBulkStatusLookupForm::IssuerSerial { issuer_certificate_sha256, serial_number } => json!({
                "lookup_id": self.lookup_id,
                "issuer_certificate_sha256": issuer_certificate_sha256,
                "serial_number": serial_number,
            }),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapStatusResponse {
    pub status: TzapCertificateStatus,
    pub certificate_sha256: Option<String>,
    pub issuer_certificate_sha256: Option<String>,
    pub issuer_key_identifier: Option<String>,
    pub serial_number: Option<String>,
    pub not_before_unix_seconds: Option<i64>,
    pub not_after_unix_seconds: Option<i64>,
    pub this_update_unix_seconds: Option<i64>,
    pub next_update_unix_seconds: Option<i64>,
    pub revoked_at_unix_seconds: Option<i64>,
    pub revocation_reason: Option<String>,
    pub query: TzapStatusQueryEcho,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapDocumentStatusTarget {
    pub certificate_sha256: String,
    pub issuer_certificate_sha256: String,
    pub issuer_key_identifier: String,
    pub serial_number: String,
}

impl TzapDocumentStatusTarget {
    #[must_use]
    pub fn from_envelope(envelope: &crate::document_envelope::TzapDocumentEnvelope) -> Self {
        Self {
            certificate_sha256: envelope.signed_payload.leaf_certificate_sha256.clone(),
            issuer_certificate_sha256: envelope.signed_payload.issuer_certificate_sha256.clone(),
            issuer_key_identifier: envelope.signed_payload.issuer_key_identifier.clone(),
            serial_number: envelope.signed_payload.certificate_serial_number.clone(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TzapStatusQueryEcho {
    pub certificate_sha256: Option<String>,
    pub issuer_certificate_sha256: Option<String>,
    pub serial_number: Option<String>,
}

impl TzapStatusResponse {
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, TzapStatusClientError> {
        let value: Value = serde_json::from_slice(bytes)?;
        Self::from_json_value(&value)
    }

    pub fn from_json_value(value: &Value) -> Result<Self, TzapStatusClientError> {
        let object = json_object::<TzapStatusClientError>(value, "object")?;
        let status = required_string::<TzapStatusClientError>(object, "status")?.parse::<TzapCertificateStatus>().map_err(|()| TzapStatusClientError::InvalidField { field: "status" })?;
        let query = parse_query_echo(object)?;
        let response = Self {
            status,
            certificate_sha256: optional_string(object, "certificate_sha256")?,
            issuer_certificate_sha256: optional_string(object, "issuer_certificate_sha256")?,
            issuer_key_identifier: optional_string(object, "issuer_key_identifier")?,
            serial_number: optional_string(object, "serial_number")?,
            not_before_unix_seconds: optional_unix_or_rfc3339(object, "not_before_unix_seconds", "not_before", "not_before_unix_seconds")?,
            not_after_unix_seconds: optional_unix_or_rfc3339(object, "not_after_unix_seconds", "not_after", "not_after_unix_seconds")?,
            this_update_unix_seconds: optional_unix_or_rfc3339(object, "this_update_unix_seconds", "this_update", "this_update_unix_seconds")?,
            next_update_unix_seconds: optional_unix_or_rfc3339(object, "next_update_unix_seconds", "next_update", "next_update_unix_seconds")?,
            revoked_at_unix_seconds: optional_unix_or_rfc3339(object, "revoked_at_unix_seconds", "revoked_at", "revoked_at_unix_seconds")?,
            revocation_reason: optional_string(object, "revocation_reason")?,
            query,
        };
        response.validate_shape()?;
        Ok(response)
    }

    #[must_use]
    pub fn is_fresh_valid_for_valid_now(&self, verifier_time_unix_seconds: i64) -> bool {
        if self.status != TzapCertificateStatus::Valid {
            return false;
        }
        let Some(this_update) = self.this_update_unix_seconds else {
            return false;
        };
        let Some(next_update) = self.next_update_unix_seconds else {
            return false;
        };
        this_update <= verifier_time_unix_seconds + STATUS_FRESHNESS_SKEW_SECONDS
            && next_update > verifier_time_unix_seconds - STATUS_FRESHNESS_SKEW_SECONDS
            && next_update > this_update
            && next_update - this_update <= MAX_POSITIVE_STATUS_WINDOW_SECONDS
    }

    fn validate_shape(&self) -> Result<(), TzapStatusClientError> {
        match self.status {
            TzapCertificateStatus::Valid
            | TzapCertificateStatus::Revoked
            | TzapCertificateStatus::Expired
            | TzapCertificateStatus::NotYetValid
            | TzapCertificateStatus::Suspended
            | TzapCertificateStatus::IssuerSuspended
            | TzapCertificateStatus::IssuerRevoked => {
                require_some(self.certificate_sha256.as_ref(), "certificate_sha256")?;
                require_some(self.issuer_certificate_sha256.as_ref(), "issuer_certificate_sha256")?;
                require_some(self.issuer_key_identifier.as_ref(), "issuer_key_identifier")?;
                require_some(self.serial_number.as_ref(), "serial_number")?;
                require_some(self.not_before_unix_seconds.as_ref(), "not_before_unix_seconds")?;
                require_some(self.not_after_unix_seconds.as_ref(), "not_after_unix_seconds")?;
                require_some(self.this_update_unix_seconds.as_ref(), "this_update_unix_seconds")?;
                require_some(self.next_update_unix_seconds.as_ref(), "next_update_unix_seconds")?;
                if self.status == TzapCertificateStatus::Revoked {
                    require_some(self.revoked_at_unix_seconds.as_ref(), "revoked_at_unix_seconds")?;
                    require_some(self.revocation_reason.as_ref(), "revocation_reason")?;
                }
            }
            TzapCertificateStatus::UnknownCertificate | TzapCertificateStatus::UnknownIssuer | TzapCertificateStatus::MalformedLookup | TzapCertificateStatus::UnsupportedLookupForm => {
                require_some(self.this_update_unix_seconds.as_ref(), "this_update_unix_seconds")?;
                require_some(self.next_update_unix_seconds.as_ref(), "next_update_unix_seconds")?;
                if self.certificate_sha256.is_some() || self.issuer_certificate_sha256.is_some() || self.issuer_key_identifier.is_some() || self.serial_number.is_some() {
                    return Err(TzapStatusClientError::InvalidField { field: "unknown_leaf_fields" });
                }
                if self.query.certificate_sha256.is_none() && self.query.issuer_certificate_sha256.is_none() {
                    return Err(TzapStatusClientError::InvalidField { field: "query" });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapBulkStatusItem {
    pub lookup_id: String,
    pub response: TzapStatusResponse,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCrlManifestEntry {
    pub crl_scope: String,
    pub crl_url: String,
    pub issuer_certificate_sha256: String,
    pub crl_sha256: String,
    pub crl_number: String,
    pub this_update_unix_seconds: i64,
    pub next_update_unix_seconds: i64,
}

#[must_use]
pub fn online_verification_result_from_status(
    offline: TzapDocumentVerificationResult,
    expected: &TzapDocumentStatusTarget,
    status: &TzapStatusResponse,
    verifier_time_unix_seconds: i64,
) -> TzapDocumentVerificationResult {
    // Report the actual failing stage instead of always blaming the online
    // status: the offline state may itself have failed, the status may be
    // for a different document, or the status may be stale or non-valid.
    if offline.state != TzapVerificationState::CryptographicallyIntactOffline || offline.trust_anchor_type == TzapTrustAnchorType::Untrusted {
        return TzapDocumentVerificationResult {
            state: TzapVerificationState::Invalid,
            reason: Some(offline.reason.clone().unwrap_or_else(|| "offline verification did not establish a valid state".to_owned())),
            ..offline
        };
    }
    if !status_matches_document(expected, status) {
        return TzapDocumentVerificationResult { state: TzapVerificationState::Invalid, reason: Some("online status does not match the document".to_owned()), ..offline };
    }
    if !status.is_fresh_valid_for_valid_now(verifier_time_unix_seconds) {
        return TzapDocumentVerificationResult { state: TzapVerificationState::Invalid, reason: Some(format!("online status is {}", status.status.as_str())), ..offline };
    }
    TzapDocumentVerificationResult { state: TzapVerificationState::ValidNow, reason: None, ..offline }
}

fn status_matches_document(expected: &TzapDocumentStatusTarget, status: &TzapStatusResponse) -> bool {
    let leaf_fields_match = status.certificate_sha256.as_deref() == Some(expected.certificate_sha256.as_str())
        && status.issuer_certificate_sha256.as_deref() == Some(expected.issuer_certificate_sha256.as_str())
        && status.issuer_key_identifier.as_deref() == Some(expected.issuer_key_identifier.as_str())
        && status.serial_number.as_deref() == Some(expected.serial_number.as_str());
    let query_matches = if status.query.certificate_sha256.is_none() && status.query.issuer_certificate_sha256.is_none() && status.query.serial_number.is_none() {
        true
    } else {
        status.query.certificate_sha256.as_deref() == Some(expected.certificate_sha256.as_str())
            || (status.query.issuer_certificate_sha256.as_deref() == Some(expected.issuer_certificate_sha256.as_str())
                && status.query.serial_number.as_deref() == Some(expected.serial_number.as_str()))
    };
    leaf_fields_match && query_matches
}

#[must_use]
pub fn verify_tzap_document_envelope_valid_now(
    envelope: &crate::document_envelope::TzapDocumentEnvelope,
    offline_options: &TzapOfflineVerificationOptions<'_>,
    status: &TzapStatusResponse,
) -> TzapDocumentVerificationResult {
    let offline = verify_tzap_document_envelope_offline(envelope, offline_options);
    let expected = TzapDocumentStatusTarget::from_envelope(envelope);
    online_verification_result_from_status(offline, &expected, status, offline_options.verifier_time_unix_seconds)
}

fn validate_bulk_lookups(lookups: &[TzapBulkStatusLookup]) -> Result<(), TzapStatusClientError> {
    if !(MIN_BULK_LOOKUPS..=MAX_BULK_LOOKUPS).contains(&lookups.len()) {
        return Err(TzapStatusClientError::InvalidBulkLookup { reason: "lookup count must be 1-100" });
    }
    let mut ids = HashSet::new();
    for lookup in lookups {
        if !is_printable_ascii(&lookup.lookup_id) || !ids.insert(lookup.lookup_id.as_str()) {
            return Err(TzapStatusClientError::InvalidBulkLookup { reason: "lookup_id must be unique printable ASCII" });
        }
        match &lookup.form {
            TzapBulkStatusLookupForm::CertificateFingerprint { certificate_sha256 } => {
                trust::parse_certificate_sha256(certificate_sha256).map_err(|_| TzapStatusClientError::InvalidBulkLookup { reason: "certificate_sha256 is invalid" })?;
            }
            TzapBulkStatusLookupForm::IssuerSerial { issuer_certificate_sha256, serial_number } => {
                trust::parse_issuer_sha256(issuer_certificate_sha256).map_err(|_| TzapStatusClientError::InvalidBulkLookup { reason: "issuer_certificate_sha256 is invalid" })?;
                trust::parse_serial_hex(serial_number).map_err(|_| TzapStatusClientError::InvalidBulkLookup { reason: "serial_number is invalid" })?;
            }
        }
    }
    Ok(())
}

fn parse_bulk_status_response(bytes: &[u8], lookups: &[TzapBulkStatusLookup]) -> Result<Vec<TzapBulkStatusItem>, TzapStatusClientError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let root_object = json_object::<TzapStatusClientError>(&value, "object")?;
    let results = root_object.get("results").and_then(Value::as_array).ok_or(TzapStatusClientError::InvalidField { field: "results" })?;
    if results.len() != lookups.len() {
        return Err(TzapStatusClientError::InvalidField { field: "results" });
    }
    results
        .iter()
        .zip(lookups)
        .map(|(item, lookup)| {
            let item_object = json_object::<TzapStatusClientError>(item, "object")?;
            let lookup_id = required_string::<TzapStatusClientError>(item_object, "lookup_id")?;
            if lookup_id != lookup.lookup_id {
                return Err(TzapStatusClientError::InvalidField { field: "lookup_id" });
            }
            let response_value = item_object.get("status_response").ok_or(TzapStatusClientError::InvalidField { field: "status_response" })?;
            Ok(TzapBulkStatusItem { lookup_id: lookup_id.clone(), response: TzapStatusResponse::from_json_value(response_value)? })
        })
        .collect()
}

fn parse_query_echo(response_object: &Map<String, Value>) -> Result<TzapStatusQueryEcho, TzapStatusClientError> {
    let Some(value) = response_object.get("query") else {
        return Ok(TzapStatusQueryEcho::default());
    };
    let query = json_object::<TzapStatusClientError>(value, "object")?;
    Ok(TzapStatusQueryEcho {
        certificate_sha256: optional_string(query, "certificate_sha256")?,
        issuer_certificate_sha256: optional_string(query, "issuer_certificate_sha256")?,
        serial_number: optional_string(query, "serial_number")?,
    })
}

fn optional_string(object: &Map<String, Value>, field: &'static str) -> Result<Option<String>, TzapStatusClientError> {
    object.get(field).map(|value| value.as_str().filter(|value| !value.is_empty()).map(str::to_owned).ok_or(TzapStatusClientError::InvalidField { field })).transpose()
}

pub(crate) fn optional_i64(object: &Map<String, Value>, field: &'static str) -> Result<Option<i64>, TzapStatusClientError> {
    object.get(field).map(|value| value.as_i64().ok_or(TzapStatusClientError::InvalidField { field })).transpose()
}

fn require_some<T>(value: Option<&T>, field: &'static str) -> Result<(), TzapStatusClientError> {
    if value.is_some() { Ok(()) } else { Err(TzapStatusClientError::InvalidField { field }) }
}

fn is_printable_ascii(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

// See `crate::trust::sha256_identifier` (CR-124).
#[cfg(test)]
mod tests {
    use super::{TzapBulkStatusLookup, TzapDocumentStatusTarget, TzapStatusClient, TzapStatusResponse, online_verification_result_from_status, validate_bulk_lookups};
    use crate::auth_client::{TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpRequest, TzapAuthHttpResponse, TzapAuthHttpTransport};
    use crate::document_verification::TzapDocumentVerificationResult;
    use crate::trust::{self, TzapCertificateStatus, TzapTrustAnchorType, TzapVerificationState};
    use serde_json::json;
    use std::cell::RefCell;

    #[test]
    fn status_client_uses_percent_encoded_paths_and_parses_fresh_valid_status() {
        let certificate_sha256 = trust::format_certificate_sha256(&[0x0a; 32]);
        let transport = FakeStatusTransport::new(vec![json_response(&valid_status(&certificate_sha256))]);
        let client = TzapStatusClient::new("https://sign.example/", &transport);

        let status = client.status_by_fingerprint(&certificate_sha256).unwrap();

        assert_eq!(status.status, TzapCertificateStatus::Valid);
        assert!(status.is_fresh_valid_for_valid_now(1_000));
        assert!(transport.requests()[0].url.contains("sha256%3A"));
    }

    #[test]
    fn status_response_accepts_server_iso_timestamps() {
        let certificate_sha256 = trust::format_certificate_sha256(&[0x0a; 32]);
        let mut value = valid_status(&certificate_sha256);
        value.as_object_mut().unwrap().remove("not_before_unix_seconds");
        value.as_object_mut().unwrap().remove("not_after_unix_seconds");
        value.as_object_mut().unwrap().remove("this_update_unix_seconds");
        value.as_object_mut().unwrap().remove("next_update_unix_seconds");
        value["not_before"] = json!("1970-01-01T00:01:40Z");
        value["not_after"] = json!("1970-01-01T00:33:20Z");
        value["this_update"] = json!("1970-01-01T00:15:00Z");
        value["next_update"] = json!("1970-01-01T00:25:00Z");

        let status = TzapStatusResponse::from_json_value(&value).unwrap();

        assert_eq!(status.not_before_unix_seconds, Some(100));
        assert_eq!(status.not_after_unix_seconds, Some(2_000));
        assert_eq!(status.this_update_unix_seconds, Some(900));
        assert_eq!(status.next_update_unix_seconds, Some(1_500));
        assert!(status.is_fresh_valid_for_valid_now(1_000));
    }

    #[test]
    fn status_shapes_reject_stale_unknown_suspended_and_malformed_for_valid_now() {
        let certificate_sha256 = trust::format_certificate_sha256(&[0x0b; 32]);
        let mut stale = valid_status(&certificate_sha256);
        stale["next_update_unix_seconds"] = json!(600);
        assert!(!TzapStatusResponse::from_json_value(&stale).unwrap().is_fresh_valid_for_valid_now(1_000));

        for status in ["suspended", "issuer_revoked", "revoked", "expired", "not_yet_valid"] {
            let mut value = valid_status(&certificate_sha256);
            value["status"] = json!(status);
            if status == "revoked" {
                value["revoked_at_unix_seconds"] = json!(900);
                value["revocation_reason"] = json!("key_compromise");
            }
            assert!(!TzapStatusResponse::from_json_value(&value).unwrap().is_fresh_valid_for_valid_now(1_000));
        }

        let unknown = json!({
            "status": "unknown_certificate",
            "query": {"certificate_sha256": certificate_sha256},
            "this_update_unix_seconds": 900,
            "next_update_unix_seconds": 1_800
        });
        assert_eq!(TzapStatusResponse::from_json_value(&unknown).unwrap().status, TzapCertificateStatus::UnknownCertificate);
        let mut underspecified_unknown = unknown.clone();
        underspecified_unknown.as_object_mut().unwrap().remove("next_update_unix_seconds");
        assert!(TzapStatusResponse::from_json_value(&underspecified_unknown).is_err());

        let malformed = json!({
            "status": "malformed_lookup",
            "query": {"issuer_certificate_sha256": trust::format_issuer_sha256(&[0x0c; 32]), "serial_number": "01"},
            "this_update_unix_seconds": 900,
            "next_update_unix_seconds": 1_800
        });
        assert_eq!(TzapStatusResponse::from_json_value(&malformed).unwrap().status, TzapCertificateStatus::MalformedLookup);

        for status in ["unknown_issuer", "unsupported_lookup_form"] {
            let value = json!({
                "status": status,
                "query": {
                    "issuer_certificate_sha256": trust::format_issuer_sha256(&[0x0c; 32]),
                    "serial_number": "01",
                },
                "this_update_unix_seconds": 900,
                "next_update_unix_seconds": 1_800
            });
            assert!(!TzapStatusResponse::from_json_value(&value).unwrap().is_fresh_valid_for_valid_now(1_000));
        }
    }

    #[test]
    fn bulk_status_validates_lookup_ids_forms_and_preserves_response_order() {
        let certificate_sha256 = trust::format_certificate_sha256(&[0x0d; 32]);
        let duplicate_target = TzapBulkStatusLookup::by_fingerprint("a", &certificate_sha256);
        let second = TzapBulkStatusLookup::by_fingerprint("b", &certificate_sha256);
        validate_bulk_lookups(&[duplicate_target.clone(), second.clone()]).unwrap();
        assert!(validate_bulk_lookups(&[duplicate_target.clone(), duplicate_target]).is_err());
        assert!(validate_bulk_lookups(&[TzapBulkStatusLookup::by_fingerprint("\n", certificate_sha256.clone())]).is_err());

        let response = json!({
            "results": [
                {"lookup_id": "a", "status_response": valid_status(&certificate_sha256)},
                {"lookup_id": "b", "status_response": valid_status(&certificate_sha256)}
            ]
        });
        let transport = FakeStatusTransport::new(vec![json_response(&response)]);
        let client = TzapStatusClient::new("https://sign.example", &transport);
        let results = client.bulk_status(&[second_lookup("a", &certificate_sha256), second_lookup("b", &certificate_sha256)]).unwrap();

        assert_eq!(results[0].lookup_id, "a");
        assert_eq!(results[1].lookup_id, "b");
        assert_eq!(transport.requests()[0].method, TzapAuthHttpMethod::Post);
    }

    #[test]
    fn online_status_mapping_returns_valid_now_only_for_fresh_valid_status() {
        let offline = TzapDocumentVerificationResult {
            state: TzapVerificationState::CryptographicallyIntactOffline,
            trust_anchor_type: TzapTrustAnchorType::OfficialTzap,
            reason: Some("offline verification has no fresh status proof".to_owned()),
            root_certificate_sha256: None,
            public_metadata: None,
        };
        let certificate_sha256 = trust::format_certificate_sha256(&[0x0e; 32]);
        let expected = TzapDocumentStatusTarget {
            certificate_sha256: certificate_sha256.clone(),
            issuer_certificate_sha256: trust::format_issuer_sha256(&[0x02; 32]),
            issuer_key_identifier: "AQIDBA".to_owned(),
            serial_number: "01".to_owned(),
        };
        let valid = TzapStatusResponse::from_json_value(&valid_status(&certificate_sha256)).unwrap();
        let valid_now = online_verification_result_from_status(offline.clone(), &expected, &valid, 1_000);
        assert_eq!(valid_now.state, TzapVerificationState::ValidNow);
        assert_eq!(valid_now.reason, None);
        let mismatched = TzapStatusResponse::from_json_value(&valid_status(&trust::format_certificate_sha256(&[0x55; 32]))).unwrap();
        assert_eq!(online_verification_result_from_status(offline.clone(), &expected, &mismatched, 1_000).state, TzapVerificationState::Invalid);

        let mut suspended = valid_status(&certificate_sha256);
        suspended["status"] = json!("suspended");
        let suspended = TzapStatusResponse::from_json_value(&suspended).unwrap();
        assert_eq!(online_verification_result_from_status(offline, &expected, &suspended, 1_000).state, TzapVerificationState::Invalid);
    }

    #[test]
    fn crl_manifest_parses_and_rejects_bad_fields() {
        let issuer_sha256 = trust::format_issuer_sha256(&[0x0f; 32]);
        let manifest = json!({
            "crls": [{
                "crl_scope": trust::TZAP_CRL_SCOPE_ALL_CERTIFICATES_ISSUED_BY_CA,
                "crl_url": trust::status_crl_pem_path(&issuer_sha256).unwrap(),
                "issuer_certificate_sha256": issuer_sha256,
                "crl_number": "01",
                "crl_sha256": trust::format_certificate_sha256(&[0x10; 32]),
                "this_update_unix_seconds": 900,
                "next_update_unix_seconds": 1_200
            }]
        });
        let entries = super::parse_crl_manifest(serde_json::to_string(&manifest).unwrap().as_bytes()).unwrap();
        assert_eq!(entries[0].crl_scope, trust::TZAP_CRL_SCOPE_ALL_CERTIFICATES_ISSUED_BY_CA);

        let iso_manifest = json!({
            "crls": [{
                "crl_scope": trust::TZAP_CRL_SCOPE_ALL_CERTIFICATES_ISSUED_BY_CA,
                "crl_url": trust::status_crl_pem_path(&issuer_sha256).unwrap(),
                "issuer_certificate_sha256": issuer_sha256,
                "crl_number": "01",
                "crl_sha256": trust::format_certificate_sha256(&[0x10; 32]),
                "this_update": "1970-01-01T00:15:00Z",
                "next_update": "1970-01-01T00:20:00Z"
            }]
        });
        let iso_entries = super::parse_crl_manifest(serde_json::to_string(&iso_manifest).unwrap().as_bytes()).unwrap();
        assert_eq!(iso_entries[0].this_update_unix_seconds, 900);
        assert_eq!(iso_entries[0].next_update_unix_seconds, 1_200);

        let mut bad = manifest;
        bad["crls"][0]["next_update_unix_seconds"] = json!(800);
        assert!(super::parse_crl_manifest(serde_json::to_string(&bad).unwrap().as_bytes()).is_err());

        let mut bad_scope = bad.clone();
        bad_scope["crls"][0]["next_update_unix_seconds"] = json!(1_200);
        bad_scope["crls"][0]["crl_scope"] = json!("issuer");
        assert!(super::parse_crl_manifest(serde_json::to_string(&bad_scope).unwrap().as_bytes()).is_err());
    }

    #[test]
    fn crl_download_decodes_pem_endpoint_to_der() {
        let issuer_sha256 = trust::format_issuer_sha256(&[0x11; 32]);
        let transport = FakeStatusTransport::new(vec![TzapAuthHttpResponse { status_code: 200, body: TEST_CRL_PEM.as_bytes().to_vec() }]);
        let client = TzapStatusClient::new("https://sign.example/", &transport);

        let crl_der = client.crl_der(&issuer_sha256).unwrap();

        assert!(openssl::x509::X509Crl::from_der(&crl_der).is_ok());
        assert!(transport.requests()[0].url.ends_with(&format!("/v1/status/crls/{}/pem", trust::percent_encode_path_param(&issuer_sha256))));
    }

    fn valid_status(certificate_sha256: &str) -> serde_json::Value {
        json!({
            "status": "valid",
            "certificate_sha256": certificate_sha256,
            "issuer_certificate_sha256": trust::format_issuer_sha256(&[0x02; 32]),
            "issuer_key_identifier": "AQIDBA",
            "serial_number": "01",
            "not_before_unix_seconds": 100,
            "not_after_unix_seconds": 2_000,
            "this_update_unix_seconds": 900,
            "next_update_unix_seconds": 1_500,
        })
    }

    fn second_lookup(id: &str, certificate_sha256: &str) -> TzapBulkStatusLookup {
        TzapBulkStatusLookup::by_fingerprint(id, certificate_sha256)
    }

    fn json_response(body: &serde_json::Value) -> TzapAuthHttpResponse {
        TzapAuthHttpResponse { status_code: 200, body: serde_json::to_vec(body).unwrap() }
    }

    const TEST_CRL_PEM: &str = "-----BEGIN X509 CRL-----\nMIIBajBUAgEBMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBlRlc3RDQRcNMjYw\nNjI2MDQwOTQ1WhcNMjYwNjI3MDQwOTQ1WqAPMA0wCwYDVR0UBAQCAhAAMA0GCSqG\nSIb3DQEBCwUAA4IBAQBvjtd1d23B5m454FBHAuBiy7Q+BnXBDEK5txSMSe30g9Zt\nm+1/WhHsqMp1biNSyQhVQYwLsJoWimzqcgR4CygJyFaVM3gT1QpN4yFxxs6tmEyi\nAgDD+ngO6GtY+ouzRpsnsrd5g9PTPbchGjjDjbwjCwcqcWY6n7cxMwJc0OBxj6BU\nYaz++TmBFD9a7p3HOL2SJWfSaT4JACRofsmGfiSQa6xBum91/NbVYDtDly8sp8si\n1d4lPYtpBr3r+PKMKEilx+vHOo0kUIOcKQkJx85revQeZhQXRJfPphMn+iJkp8QQ\n6lNu5AzDf/eH7pjDm8htQOlZil25T3BXhEMzc/ts\n-----END X509 CRL-----\n";

    struct FakeStatusTransport {
        responses: RefCell<Vec<TzapAuthHttpResponse>>,
        requests: RefCell<Vec<TzapAuthHttpRequest>>,
    }

    impl FakeStatusTransport {
        fn new(responses: Vec<TzapAuthHttpResponse>) -> Self {
            Self { responses: RefCell::new(responses.into_iter().rev().collect()), requests: RefCell::new(Vec::new()) }
        }

        fn requests(&self) -> Vec<TzapAuthHttpRequest> {
            self.requests.borrow().clone()
        }
    }

    impl TzapAuthHttpTransport for FakeStatusTransport {
        fn send(&self, request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> {
            self.requests.borrow_mut().push(request.clone());
            self.responses.borrow_mut().pop().ok_or(TzapAuthError::HttpStatus { status_code: 599 })
        }
    }
}
