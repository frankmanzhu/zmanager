//! CRL validation and manifest parsing (CR-141).
//!
//! Extracted from the status client; the client re-exports
//! [`validate_crl_der_against_manifest`] to keep its public API.

use crate::json_util::{json_object, required_string};
use crate::status_client::{TzapCrlManifestEntry, TzapStatusClientError};
use serde_json::{Map, Value};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use x509_parser::prelude::{FromDer as _, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;

pub fn validate_crl_der_against_manifest(entry: &TzapCrlManifestEntry, crl_der: &[u8], issuer_certificate_der: &[u8]) -> Result<(), TzapStatusClientError> {
    if crate::trust::sha256_identifier(crl_der) != entry.crl_sha256 {
        return Err(TzapStatusClientError::CrlValidation { reason: "DER SHA-256 does not match manifest".to_owned() });
    }
    let parsed_crl = parse_crl_der(crl_der)?;
    validate_crl_manifest_fields(entry, &parsed_crl)?;
    let (remaining, issuer) =
        X509Certificate::from_der(issuer_certificate_der).map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;
    if !remaining.is_empty() {
        return Err(TzapStatusClientError::CrlValidation { reason: "issuer certificate has trailing DER bytes".to_owned() });
    }
    if parsed_crl.tbs_cert_list.issuer != *issuer.subject() {
        return Err(TzapStatusClientError::CrlValidation { reason: "CRL issuer does not match issuer certificate subject".to_owned() });
    }
    verify_crl_signature(&parsed_crl, issuer.tbs_certificate.subject_pki.raw)?;
    Ok(())
}

/// Verifies the CRL signature over its TBS DER with the issuer's SPKI
/// (the `RustCrypto` `x509-verify` replacement for OpenSSL's `X509Crl::verify`).
fn verify_crl_signature(crl: &CertificateRevocationList<'_>, issuer_spki_raw: &[u8]) -> Result<(), TzapStatusClientError> {
    let key_info = x509_cert::spki::SubjectPublicKeyInfoRef::try_from(issuer_spki_raw)
        .map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;
    let key = x509_verify::VerifyingKey::new(key_info).map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;

    let signature_algorithm = crl.signature_algorithm.clone();
    let algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
        oid: x509_cert::spki::ObjectIdentifier::try_from(signature_algorithm.algorithm.as_bytes())
            .map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?,
        parameters: signature_algorithm.parameters.as_ref().and_then(x509_parser_any_to_der_any),
    };
    let signature = x509_verify::Signature::new(&algorithm, crl.signature_value.data.as_ref().to_vec());
    let message = x509_verify::Message::new(crl.tbs_cert_list.as_ref());
    let verify_info = x509_verify::VerifyInfo::new(message, signature);
    key.verify(&verify_info).map_err(|_| TzapStatusClientError::CrlValidation { reason: "CRL signature did not verify".to_owned() })
}

/// Converts an `x509-parser` `Any` parameter value to a `der` crate `Any`.
fn x509_parser_any_to_der_any(any: &x509_parser::asn1_rs::Any<'_>) -> Option<x509_cert::der::asn1::Any> {
    let tag = x509_cert::der::Tag::try_from(u8::try_from(any.tag().0).ok()?).ok()?;
    let any_ref = x509_cert::der::asn1::AnyRef::new(tag, any.data).ok()?;
    x509_cert::der::asn1::Any::encode_from(&any_ref).ok()
}

fn parse_crl_der(crl_der: &[u8]) -> Result<CertificateRevocationList<'_>, TzapStatusClientError> {
    let (remaining, crl) = CertificateRevocationList::from_der(crl_der).map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;
    if remaining.is_empty() { Ok(crl) } else { Err(TzapStatusClientError::CrlValidation { reason: "CRL has trailing DER bytes".to_owned() }) }
}

pub(crate) fn crl_download_to_der(bytes: &[u8]) -> Result<Vec<u8>, TzapStatusClientError> {
    if bytes.windows(b"-----BEGIN".len()).any(|window| window == b"-----BEGIN") {
        for pem in x509_parser::pem::Pem::iter_from_buffer(bytes) {
            let pem = pem.map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;
            if pem.label != "X509 CRL" {
                continue;
            }
            let (remaining, _) =
                CertificateRevocationList::from_der(&pem.contents).map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;
            if !remaining.is_empty() {
                return Err(TzapStatusClientError::CrlValidation { reason: "CRL has trailing DER bytes".to_owned() });
            }
            return Ok(pem.contents);
        }
        Err(TzapStatusClientError::CrlValidation { reason: "CRL PEM file is empty".to_owned() })
    } else {
        let (remaining, _) = CertificateRevocationList::from_der(bytes).map_err(|error| TzapStatusClientError::CrlValidation { reason: error.to_string() })?;
        if !remaining.is_empty() {
            return Err(TzapStatusClientError::CrlValidation { reason: "CRL has trailing DER bytes".to_owned() });
        }
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
