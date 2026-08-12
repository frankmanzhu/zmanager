//! CRL validation and manifest parsing (CR-141).
//!
//! Extracted from the status client; the client re-exports
//! [`validate_crl_der_against_manifest`] to keep its public API.

use crate::json_util::{json_object, required_string};
use crate::status_client::{TzapCrlManifestEntry, TzapStatusClientError};
use openssl::x509::{X509, X509Crl};
use serde_json::{Map, Value};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use x509_parser::prelude::FromDer as _;
use x509_parser::revocation_list::CertificateRevocationList;

pub fn validate_crl_der_against_manifest(entry: &TzapCrlManifestEntry, crl_der: &[u8], issuer_certificate_der: &[u8]) -> Result<(), TzapStatusClientError> {
    if crate::trust::sha256_identifier(crl_der) != entry.crl_sha256 {
        return Err(TzapStatusClientError::CrlValidation { reason: "DER SHA-256 does not match manifest".to_owned() });
    }
    let crl = X509Crl::from_der(crl_der).map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;
    let parsed_crl = parse_crl_der(crl_der)?;
    validate_crl_manifest_fields(entry, &parsed_crl)?;
    let issuer = X509::from_der(issuer_certificate_der).map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;
    let name_order = crl.issuer_name().try_cmp(issuer.subject_name()).map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;
    if name_order != std::cmp::Ordering::Equal {
        return Err(TzapStatusClientError::CrlValidation { reason: "CRL issuer does not match issuer certificate subject".to_owned() });
    }
    let issuer_key = issuer.public_key().map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;
    if !crl.verify(&issuer_key).map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })? {
        return Err(TzapStatusClientError::CrlValidation { reason: "CRL signature did not verify".to_owned() });
    }
    Ok(())
}

fn parse_crl_der(crl_der: &[u8]) -> Result<CertificateRevocationList<'_>, TzapStatusClientError> {
    let (remaining, crl) = CertificateRevocationList::from_der(crl_der).map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;
    if remaining.is_empty() { Ok(crl) } else { Err(TzapStatusClientError::CrlValidation { reason: "CRL has trailing DER bytes".to_owned() }) }
}

pub(crate) fn crl_download_to_der(bytes: &[u8]) -> Result<Vec<u8>, TzapStatusClientError> {
    if let Ok(crl) = X509Crl::from_pem(bytes) {
        crl.to_der().map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })
    } else {
        X509Crl::from_der(bytes).map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;
        Ok(bytes.to_vec())
    }
}

fn validate_crl_manifest_fields(entry: &TzapCrlManifestEntry, crl: &CertificateRevocationList<'_>) -> Result<(), TzapStatusClientError> {
    let crl_number =
        crl.crl_number().map(canonical_biguint_hex).ok_or_else(|| TzapStatusClientError::CrlValidation { reason: "CRL number is missing".to_owned() })?;
    if crl_number != entry.crl_number {
        return Err(TzapStatusClientError::CrlValidation { reason: "CRL number does not match manifest".to_owned() });
    }
    if crl.last_update().timestamp() != entry.this_update_unix_seconds {
        return Err(TzapStatusClientError::CrlValidation { reason: "CRL thisUpdate does not match manifest".to_owned() });
    }
    let next_update = crl.next_update().ok_or_else(|| TzapStatusClientError::CrlValidation { reason: "CRL nextUpdate is missing".to_owned() })?.timestamp();
    if next_update != entry.next_update_unix_seconds {
        return Err(TzapStatusClientError::CrlValidation { reason: "CRL nextUpdate does not match manifest".to_owned() });
    }
    Ok(())
}

fn canonical_biguint_hex(value: &num_bigint::BigUint) -> String {
    // to_bytes_be yields minimal big-endian bytes (even-length hex), matching
    // the previous to_str_radix(16) + zero-pad behavior.
    crate::hex::hex_upper(&value.to_bytes_be())
}

pub(crate) fn parse_crl_manifest(bytes: &[u8]) -> Result<Vec<TzapCrlManifestEntry>, TzapStatusClientError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let root_object = json_object::<TzapStatusClientError>(&value, "object")?;
    let entries = root_object.get("crls").and_then(Value::as_array).ok_or(TzapStatusClientError::InvalidField { field: "crls" })?;
    entries
        .iter()
        .map(|entry| {
            let entry_object = json_object::<TzapStatusClientError>(entry, "object")?;
            let parsed = TzapCrlManifestEntry {
                crl_scope: required_string::<TzapStatusClientError>(entry_object, "crl_scope")?,
                crl_url: required_string::<TzapStatusClientError>(entry_object, "crl_url")?,
                issuer_certificate_sha256: required_string::<TzapStatusClientError>(entry_object, "issuer_certificate_sha256")?,
                crl_sha256: required_string::<TzapStatusClientError>(entry_object, "crl_sha256")?,
                crl_number: required_string::<TzapStatusClientError>(entry_object, "crl_number")?,
                this_update_unix_seconds: required_unix_or_rfc3339(entry_object, "this_update_unix_seconds", "this_update", "this_update_unix_seconds")?,
                next_update_unix_seconds: required_unix_or_rfc3339(entry_object, "next_update_unix_seconds", "next_update", "next_update_unix_seconds")?,
            };
            if parsed.crl_scope != crate::trust::TZAP_CRL_SCOPE_ALL_CERTIFICATES_ISSUED_BY_CA {
                return Err(TzapStatusClientError::InvalidField { field: "crl_scope" });
            }
            crate::trust::parse_issuer_sha256(&parsed.issuer_certificate_sha256)
                .map_err(|_| TzapStatusClientError::InvalidField { field: "issuer_certificate_sha256" })?;
            let expected_crl_url = crate::trust::status_crl_pem_path(&parsed.issuer_certificate_sha256)
                .map_err(|_| TzapStatusClientError::InvalidField { field: "issuer_certificate_sha256" })?;
            if parsed.crl_url != expected_crl_url {
                return Err(TzapStatusClientError::InvalidField { field: "crl_url" });
            }
            crate::trust::parse_crl_sha256(&parsed.crl_sha256).map_err(|_| TzapStatusClientError::InvalidField { field: "crl_sha256" })?;
            crate::trust::parse_serial_hex(&parsed.crl_number).map_err(|_| TzapStatusClientError::InvalidField { field: "crl_number" })?;
            if parsed.next_update_unix_seconds <= parsed.this_update_unix_seconds {
                return Err(TzapStatusClientError::InvalidField { field: "next_update_unix_seconds" });
            }
            Ok(parsed)
        })
        .collect()
}

pub(crate) fn required_unix_or_rfc3339(
    object: &Map<String, Value>,
    unix_field: &'static str,
    rfc3339_field: &'static str,
    error_field: &'static str,
) -> Result<i64, TzapStatusClientError> {
    optional_unix_or_rfc3339(object, unix_field, rfc3339_field, error_field)?.ok_or(TzapStatusClientError::InvalidField { field: error_field })
}

pub(crate) fn optional_unix_or_rfc3339(
    object: &Map<String, Value>,
    unix_field: &'static str,
    rfc3339_field: &'static str,
    error_field: &'static str,
) -> Result<Option<i64>, TzapStatusClientError> {
    if object.contains_key(unix_field) {
        return crate::status_client::optional_i64(object, unix_field);
    }
    object
        .get(rfc3339_field)
        .map(|value| {
            let text = value.as_str().filter(|value| !value.is_empty()).ok_or(TzapStatusClientError::InvalidField { field: error_field })?;
            OffsetDateTime::parse(text, &Rfc3339).map(OffsetDateTime::unix_timestamp).map_err(|_| TzapStatusClientError::InvalidField { field: error_field })
        })
        .transpose()
}
