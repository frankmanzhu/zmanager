//! Offline TZAP document-envelope verification.

use crate::document_envelope::{self, TzapDocumentEnvelope};
use crate::p256_signature;
use crate::trust::{self, TzapCertificateProfileOptions, TzapRootPinSet, TzapTrustAnchorType, TzapVerificationState};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::x509::X509;
use std::fmt;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer as _, X509Certificate};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapOfflineVerificationOptions<'a> {
    pub verifier_time_unix_seconds: i64,
    pub official_root_pins: &'a TzapRootPinSet,
    pub official_root_certificates_der: Vec<Vec<u8>>,
    pub custom_trust_root_sha256: Vec<String>,
    pub custom_trust_root_certificates_der: Vec<Vec<u8>>,
    pub certificate_profile_options: TzapCertificateProfileOptions,
}

impl<'a> TzapOfflineVerificationOptions<'a> {
    #[must_use]
    pub fn official(verifier_time_unix_seconds: i64, official_root_pins: &'a TzapRootPinSet) -> Self {
        Self {
            verifier_time_unix_seconds,
            official_root_pins,
            official_root_certificates_der: Vec::new(),
            custom_trust_root_sha256: Vec::new(),
            custom_trust_root_certificates_der: Vec::new(),
            certificate_profile_options: TzapCertificateProfileOptions::default(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapDocumentVerificationResult {
    pub state: TzapVerificationState,
    pub trust_anchor_type: TzapTrustAnchorType,
    pub reason: Option<String>,
    pub root_certificate_sha256: Option<String>,
    pub public_metadata: Option<trust::TzapCertificatePublicMetadata>,
}

impl TzapDocumentVerificationResult {
    #[must_use]
    pub fn is_cryptographically_intact_offline(&self) -> bool {
        self.state == TzapVerificationState::CryptographicallyIntactOffline
    }

    fn invalid(trust_anchor_type: TzapTrustAnchorType, reason: impl Into<String>) -> Self {
        Self { state: TzapVerificationState::Invalid, trust_anchor_type, reason: Some(reason.into()), root_certificate_sha256: None, public_metadata: None }
    }
}

#[derive(Debug)]
enum TzapOfflineVerificationError {
    Envelope(document_envelope::TzapDocumentEnvelopeError),
    CertificateParse(String),
    CertificateReference(&'static str),
    CertificateValidity(&'static str),
    Signature(String),
    Untrusted(String),
}

impl fmt::Display for TzapOfflineVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(error) => write!(f, "{error}"),
            Self::CertificateParse(reason) => write!(f, "certificate parse failed: {reason}"),
            Self::CertificateReference(field) => {
                write!(f, "certificate reference mismatch: {field}")
            }
            Self::CertificateValidity(reason) => write!(f, "certificate validity failed: {reason}"),
            Self::Signature(reason) => write!(f, "document signature failed: {reason}"),
            Self::Untrusted(reason) => write!(f, "certificate chain is untrusted: {reason}"),
        }
    }
}

#[must_use]
pub fn verify_tzap_document_envelope_offline_json(bytes: &[u8], options: &TzapOfflineVerificationOptions<'_>) -> TzapDocumentVerificationResult {
    match document_envelope::parse_tzap_document_envelope_json(bytes) {
        Ok(envelope) => verify_tzap_document_envelope_offline(&envelope, options),
        Err(error) => TzapDocumentVerificationResult::invalid(TzapTrustAnchorType::Untrusted, TzapOfflineVerificationError::Envelope(error).to_string()),
    }
}

#[must_use]
pub fn verify_tzap_document_envelope_offline(envelope: &TzapDocumentEnvelope, options: &TzapOfflineVerificationOptions<'_>) -> TzapDocumentVerificationResult {
    match verify_offline_inner(envelope, options) {
        Ok(result) => result,
        Err(error) => TzapDocumentVerificationResult::invalid(TzapTrustAnchorType::Untrusted, error.to_string()),
    }
}

fn verify_offline_inner(envelope: &TzapDocumentEnvelope, options: &TzapOfflineVerificationOptions<'_>) -> Result<TzapDocumentVerificationResult, TzapOfflineVerificationError> {
    let embedded_chain_der = envelope_chain_der(envelope);
    let leaf = X509::from_der(&envelope.leaf_certificate_der).map_err(|error| TzapOfflineVerificationError::CertificateParse(error.to_string()))?;
    let parsed_leaf = parse_certificate(&envelope.leaf_certificate_der, "leaf")?;
    let parsed_issuer =
        envelope.intermediate_chain_der.first().ok_or(TzapOfflineVerificationError::CertificateReference("intermediate_chain_der")).and_then(|issuer| parse_certificate(issuer, "issuer"))?;

    validate_certificate_references(envelope, &parsed_leaf, &parsed_issuer)?;
    validate_leaf_current_validity(&parsed_leaf, options.verifier_time_unix_seconds)?;
    verify_document_signature(envelope, &leaf)?;
    verify_chain_trust(&embedded_chain_der, options)
}

fn envelope_chain_der(envelope: &TzapDocumentEnvelope) -> Vec<Vec<u8>> {
    let mut chain_der = Vec::with_capacity(1 + envelope.intermediate_chain_der.len());
    chain_der.push(envelope.leaf_certificate_der.clone());
    chain_der.extend(envelope.intermediate_chain_der.clone());
    chain_der
}

fn parse_certificate<'a>(der: &'a [u8], label: &'static str) -> Result<X509Certificate<'a>, TzapOfflineVerificationError> {
    let (remaining, certificate) = X509Certificate::from_der(der).map_err(|error| TzapOfflineVerificationError::CertificateParse(format!("{label}: {error}")))?;
    if remaining.is_empty() { Ok(certificate) } else { Err(TzapOfflineVerificationError::CertificateParse(format!("{label}: trailing DER bytes"))) }
}

fn validate_certificate_references(envelope: &TzapDocumentEnvelope, leaf: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> Result<(), TzapOfflineVerificationError> {
    if crate::trust::sha256_identifier(&envelope.leaf_certificate_der) != envelope.signed_payload.leaf_certificate_sha256 {
        return Err(TzapOfflineVerificationError::CertificateReference("leaf_certificate_sha256"));
    }
    if crate::trust::sha256_identifier(&envelope.intermediate_chain_der[0]) != envelope.signed_payload.issuer_certificate_sha256 {
        return Err(TzapOfflineVerificationError::CertificateReference("issuer_certificate_sha256"));
    }
    if trust::canonical_serial_hex(leaf.raw_serial()).map_err(|_| TzapOfflineVerificationError::CertificateReference("certificate_serial_number"))? != envelope.signed_payload.certificate_serial_number
    {
        return Err(TzapOfflineVerificationError::CertificateReference("certificate_serial_number"));
    }

    let leaf_aki = authority_key_identifier(leaf).ok_or(TzapOfflineVerificationError::CertificateReference("issuer_key_identifier"))?;
    let issuer_ski = subject_key_identifier(issuer).ok_or(TzapOfflineVerificationError::CertificateReference("issuer_key_identifier"))?;
    if leaf_aki != issuer_ski || URL_SAFE_NO_PAD.encode(&leaf_aki) != envelope.signed_payload.issuer_key_identifier {
        return Err(TzapOfflineVerificationError::CertificateReference("issuer_key_identifier"));
    }

    Ok(())
}

fn validate_leaf_current_validity(leaf: &X509Certificate<'_>, verifier_time_unix_seconds: i64) -> Result<(), TzapOfflineVerificationError> {
    let validity = leaf.validity();
    if verifier_time_unix_seconds < validity.not_before.timestamp() {
        return Err(TzapOfflineVerificationError::CertificateValidity("leaf not yet valid"));
    }
    if verifier_time_unix_seconds >= validity.not_after.timestamp() {
        return Err(TzapOfflineVerificationError::CertificateValidity("leaf expired"));
    }
    Ok(())
}

fn verify_document_signature(envelope: &TzapDocumentEnvelope, leaf: &X509) -> Result<(), TzapOfflineVerificationError> {
    let public_key = leaf.public_key().map_err(|error| TzapOfflineVerificationError::Signature(error.to_string()))?;
    let verified = p256_signature::verify_p256_sha256_p1363(&public_key, &envelope.canonical_signed_payload, &envelope.signature)
        .map_err(|error| TzapOfflineVerificationError::Signature(format!("{error:?}")))?;
    if verified { Ok(()) } else { Err(TzapOfflineVerificationError::Signature("signature did not verify".to_owned())) }
}

fn verify_chain_trust(embedded_chain_der: &[Vec<u8>], options: &TzapOfflineVerificationOptions<'_>) -> Result<TzapDocumentVerificationResult, TzapOfflineVerificationError> {
    let mut official_error = None;
    for chain_der in crate::trust::candidate_chains(embedded_chain_der, &options.official_root_certificates_der) {
        match trust::validate_official_tzap_certificate_chain_der(&chain_der, options.official_root_pins, &options.certificate_profile_options) {
            Ok(validation) => {
                return Ok(TzapDocumentVerificationResult {
                    state: TzapVerificationState::CryptographicallyIntactOffline,
                    trust_anchor_type: validation.trust_anchor_type,
                    reason: Some("offline verification has no fresh status proof".to_owned()),
                    root_certificate_sha256: Some(validation.root_certificate_sha256),
                    public_metadata: Some(validation.public_metadata),
                });
            }
            Err(error) => official_error = Some(error),
        }
    }

    let mut custom_error = None;
    for chain_der in crate::trust::candidate_chains(embedded_chain_der, &options.custom_trust_root_certificates_der) {
        let Some(root_sha256) = chain_der.last().map(Vec::as_slice).map(crate::trust::sha256_identifier) else {
            continue;
        };
        if !options.custom_trust_root_sha256.iter().any(|configured| configured == &root_sha256) {
            continue;
        }
        match trust::validate_custom_tzap_certificate_chain_der(&chain_der, &options.certificate_profile_options) {
            Ok(validation) => {
                return Ok(TzapDocumentVerificationResult {
                    state: TzapVerificationState::CryptographicallyIntactOffline,
                    trust_anchor_type: validation.trust_anchor_type,
                    reason: Some("offline verification has no fresh status proof".to_owned()),
                    root_certificate_sha256: Some(validation.root_certificate_sha256),
                    public_metadata: Some(validation.public_metadata),
                });
            }
            Err(error) => custom_error = Some(error),
        }
    }

    let reason =
        custom_error.map(|error| error.to_string()).or_else(|| official_error.map(|error| error.to_string())).unwrap_or_else(|| "root is not pinned official or configured custom trust".to_owned());
    Err(TzapOfflineVerificationError::Untrusted(reason))
}

// See `crate::trust::sha256_identifier` (CR-124).
fn authority_key_identifier(certificate: &X509Certificate<'_>) -> Option<Vec<u8>> {
    certificate.iter_extensions().find_map(|extension| {
        if let ParsedExtension::AuthorityKeyIdentifier(identifier) = extension.parsed_extension() { identifier.key_identifier.as_ref().map(|key_identifier| key_identifier.0.to_vec()) } else { None }
    })
}

fn subject_key_identifier(certificate: &X509Certificate<'_>) -> Option<Vec<u8>> {
    certificate.iter_extensions().find_map(|extension| if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension() { Some(identifier.0.to_vec()) } else { None })
}

#[cfg(test)]
mod tests {
    use super::{TzapOfflineVerificationOptions, verify_tzap_document_envelope_offline, verify_tzap_document_envelope_offline_json};
    use crate::document_envelope::validate_tzap_document_envelope_value;
    use crate::jcs;
    use crate::p256_signature::sign_p256_sha256_p1363;
    use crate::test_support::x509_factory::*;
    use crate::trust::{self, TzapRootPinSet, TzapTrustAnchorType, TzapVerificationState};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::{Value, json};
    use std::time::{SystemTime, UNIX_EPOCH};
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::prelude::{FromDer as _, X509Certificate};

    #[test]
    fn offline_verify_accepts_official_signed_envelope() {
        let fixture = SignedEnvelopeFixture::new(ChainConfig::default());
        let pins = pin_set(&fixture.root_sha256);
        let options = options(&pins, &fixture.root_der);

        let result = verify_tzap_document_envelope_offline(&fixture.parsed_envelope, &options);

        assert_eq!(result.state, TzapVerificationState::CryptographicallyIntactOffline);
        assert_eq!(result.trust_anchor_type, TzapTrustAnchorType::OfficialTzap);
        assert_eq!(result.root_certificate_sha256, Some(fixture.root_sha256));
        assert!(result.is_cryptographically_intact_offline());
    }

    #[test]
    fn offline_verify_accepts_configured_custom_root_without_official_upgrade() {
        let fixture = SignedEnvelopeFixture::new(ChainConfig::default());
        let empty_official_pins = TzapRootPinSet { current: &[], planned_successors: &[] };
        let mut options = TzapOfflineVerificationOptions::official(now_unix_seconds(), &empty_official_pins);
        options.custom_trust_root_certificates_der = vec![fixture.root_der.clone()];
        options.custom_trust_root_sha256 = vec![fixture.root_sha256.clone()];

        let result = verify_tzap_document_envelope_offline(&fixture.parsed_envelope, &options);

        assert_eq!(result.state, TzapVerificationState::CryptographicallyIntactOffline);
        assert_eq!(result.trust_anchor_type, TzapTrustAnchorType::Custom);
    }

    #[test]
    fn offline_verify_rejects_bad_signature_payload_hash_and_unknown_version() {
        let fixture = SignedEnvelopeFixture::new(ChainConfig::default());
        let pins = pin_set(&fixture.root_sha256);
        let options = options(&pins, &fixture.root_der);

        let mut bad_signature = fixture.envelope.clone();
        bad_signature["signature"] = json!(URL_SAFE_NO_PAD.encode([0_u8; 64]));
        let result = verify_tzap_document_envelope_offline_json(serde_json::to_string(&bad_signature).unwrap().as_bytes(), &options);
        assert_eq!(result.state, TzapVerificationState::Invalid);

        let mut bad_hash = fixture.envelope.clone();
        bad_hash["signed_payload"]["payload_hash"] = json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        let result = verify_tzap_document_envelope_offline_json(serde_json::to_string(&bad_hash).unwrap().as_bytes(), &options);
        assert_eq!(result.state, TzapVerificationState::Invalid);

        let mut unknown_version = fixture.envelope;
        unknown_version["document_payload"]["tzap_payload_version"] = json!(2);
        let result = verify_tzap_document_envelope_offline_json(serde_json::to_string(&unknown_version).unwrap().as_bytes(), &options);
        assert_eq!(result.state, TzapVerificationState::Invalid);
    }

    #[test]
    fn offline_verify_rejects_wrong_issuer_bad_policy_and_expired_leaf() {
        let fixture = SignedEnvelopeFixture::new(ChainConfig::default());
        let pins = pin_set(&fixture.root_sha256);
        let verify_options = options(&pins, &fixture.root_der);

        let mut wrong_issuer = fixture.envelope.clone();
        wrong_issuer["signed_payload"]["issuer_certificate_sha256"] = json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        let result = verify_tzap_document_envelope_offline_json(serde_json::to_string(&wrong_issuer).unwrap().as_bytes(), &verify_options);
        assert_eq!(result.state, TzapVerificationState::Invalid);

        let bad_policy = SignedEnvelopeFixture::new(ChainConfig { omit_leaf_policy: true });
        let bad_policy_pins = pin_set(&bad_policy.root_sha256);
        let result = verify_tzap_document_envelope_offline(&bad_policy.parsed_envelope, &options(&bad_policy_pins, &bad_policy.root_der));
        assert_eq!(result.state, TzapVerificationState::Invalid);

        let result = verify_tzap_document_envelope_offline(&fixture.parsed_envelope, &expired_options(&pins, &fixture.root_der));
        assert_eq!(result.state, TzapVerificationState::Invalid);
    }

    #[test]
    fn timestamp_and_status_proof_do_not_upgrade_offline_verify() {
        let mut fixture = SignedEnvelopeFixture::new(ChainConfig::default());
        fixture.envelope["timestamp_token"] = json!("future-token");
        fixture.envelope["status_proof"] = json!({"status": "valid"});
        let parsed = validate_tzap_document_envelope_value(&fixture.envelope).unwrap();
        let pins = pin_set(&fixture.root_sha256);

        let result = verify_tzap_document_envelope_offline(&parsed, &options(&pins, &fixture.root_der));

        assert_eq!(result.state, TzapVerificationState::CryptographicallyIntactOffline);
        assert_ne!(result.state, TzapVerificationState::ValidAtTrustedTime);
        assert_ne!(result.state, TzapVerificationState::ValidNow);
    }

    struct SignedEnvelopeFixture {
        envelope: Value,
        parsed_envelope: crate::document_envelope::TzapDocumentEnvelope,
        root_sha256: String,
        root_der: Vec<u8>,
    }

    impl SignedEnvelopeFixture {
        fn new(config: ChainConfig) -> Self {
            let chain = certificate_fixture(config);
            let payload = json!({
                "tzap_payload_version": 1,
                "title": "Invoice",
            });
            let payload_hash = jcs::canonical_sha256_digest(&payload).unwrap();
            let leaf = X509Certificate::from_der(&chain.chain_der[0]).unwrap().1;
            let issuer = X509Certificate::from_der(&chain.chain_der[1]).unwrap().1;
            let issuer_key_identifier = URL_SAFE_NO_PAD.encode(subject_key_identifier(&issuer).unwrap());
            let signed_payload = json!({
                "envelope_version": 1,
                "domain_separator": trust::TZAP_DOCUMENT_DOMAIN_SEPARATOR,
                "payload_hash_algorithm": trust::TZAP_PAYLOAD_DIGEST_ALGORITHM,
                "payload_hash": payload_hash,
                "signature_algorithm": trust::TZAP_DOCUMENT_SIGNATURE_ALGORITHM,
                "leaf_certificate_sha256": crate::trust::sha256_identifier(&chain.chain_der[0]),
                "issuer_certificate_sha256": crate::trust::sha256_identifier(&chain.chain_der[1]),
                "issuer_key_identifier": issuer_key_identifier,
                "certificate_serial_number": trust::canonical_serial_hex(leaf.raw_serial()).unwrap(),
            });
            let canonical_signed_payload = jcs::canonicalize_json_bytes(&signed_payload).unwrap();
            let signature = sign_p256_sha256_p1363(&chain.leaf_key, &canonical_signed_payload).unwrap();
            let envelope = json!({
                "document_payload": payload,
                "signed_payload": signed_payload,
                "signature": URL_SAFE_NO_PAD.encode(signature),
                "leaf_certificate_der": URL_SAFE_NO_PAD.encode(&chain.chain_der[0]),
                "intermediate_chain_der": chain.chain_der[1..chain.chain_der.len() - 1]
                    .iter()
                    .map(|der| URL_SAFE_NO_PAD.encode(der))
                    .collect::<Vec<_>>(),
            });
            let parsed_envelope = validate_tzap_document_envelope_value(&envelope).unwrap();
            Self { envelope, parsed_envelope, root_sha256: chain.root_sha256, root_der: chain.root_der }
        }
    }

    fn subject_key_identifier(certificate: &X509Certificate<'_>) -> Option<Vec<u8>> {
        certificate.iter_extensions().find_map(|extension| if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension() { Some(identifier.0.to_vec()) } else { None })
    }

    fn pin_set(root_sha256: &str) -> TzapRootPinSet {
        let pin: &'static str = Box::leak(root_sha256.to_owned().into_boxed_str());
        let current: &'static [&'static str] = Box::leak(vec![pin].into_boxed_slice());
        TzapRootPinSet { current, planned_successors: &[] }
    }

    fn options<'a>(pins: &'a TzapRootPinSet, root_der: &[u8]) -> TzapOfflineVerificationOptions<'a> {
        let mut options = TzapOfflineVerificationOptions::official(now_unix_seconds(), pins);
        options.official_root_certificates_der = vec![root_der.to_vec()];
        options
    }

    fn expired_options<'a>(pins: &'a TzapRootPinSet, root_der: &[u8]) -> TzapOfflineVerificationOptions<'a> {
        let mut options = TzapOfflineVerificationOptions::official(4_102_444_800, pins);
        options.official_root_certificates_der = vec![root_der.to_vec()];
        options
    }

    fn now_unix_seconds() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().try_into().unwrap()
    }
}
