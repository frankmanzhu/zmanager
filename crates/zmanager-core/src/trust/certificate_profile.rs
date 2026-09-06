//! TZAP certificate-profile validation (CR-137).
//!
//! Validates certificate chains against the TZAP document-signing profiles:
//! chain ordering and signatures, algorithm requirements, root/intermediate/
//! leaf shape, extended-key-usage restrictions, and the public-metadata
//! extension. Moved out of `trust.rs` with its private OID and path-length
//! constants; the public items are re-exported from [`crate::trust`].

use crate::trust::{
    TZAP_OID_CA_POLICY, TZAP_OID_DOCUMENT_SIGNING_EKU, TZAP_OID_LEAF_POLICY, TZAP_OID_METADATA_EXTENSION, TZAP_OID_ORGANIZATION_POLICY, TzapIdentityAssurance,
    TzapRootPinSet, TzapTrustAnchorType, format_certificate_sha256, is_valid_public_device_id, is_valid_public_org_id, is_valid_public_signer_id,
};
use openssl::asn1::Asn1Object;
use openssl::nid::Nid;
use openssl::x509::X509;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::fmt;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer as _, X509Certificate};

const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ANY_EXTENDED_KEY_USAGE: &str = "2.5.29.37.0";
const OID_EXTENDED_KEY_USAGE_EXTENSION: &str = "2.5.29.37";
const OID_SERVER_AUTH_EKU: &str = "1.3.6.1.5.5.7.3.1";
const OID_CLIENT_AUTH_EKU: &str = "1.3.6.1.5.5.7.3.2";
const OID_CODE_SIGNING_EKU: &str = "1.3.6.1.5.5.7.3.3";
pub(crate) const REQUIRED_ROOT_PATH_LEN: u32 = 2;
#[cfg(test)]
pub(crate) const PLATFORM_PATH_LEN_WITH_ORG_INTERMEDIATE: u32 = 1;
#[cfg(test)]
pub(crate) const PLATFORM_LEAF_ONLY_PATH_LEN: u32 = 0;
pub(crate) const ORG_INTERMEDIATE_PATH_LEN: u32 = 0;
const MIN_TZAP_CHAIN_LEN: usize = 3;
const MAX_TZAP_CHAIN_LEN: usize = 4;
const MAX_TZAP_LEAF_VALIDITY_DAYS: i64 = 1095;
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TzapOfficialRootPinKind {
    Current,
    PlannedSuccessor,
}

impl TzapOfficialRootPinKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::PlannedSuccessor => "planned_successor",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCertificateProfileOptions {
    /// Approved organization-intermediate policy OIDs for managed issuers.
    pub approved_org_intermediate_policy_oids: Vec<String>,
    /// Approved leaf policy OIDs beyond the default TZAP leaf policy.
    pub approved_leaf_policy_oids: Vec<String>,
    /// Optional unix timestamp to validate certificate expiration against.
    pub validation_time_unix_seconds: Option<u64>,
}

impl Default for TzapCertificateProfileOptions {
    fn default() -> Self {
        Self {
            approved_org_intermediate_policy_oids: vec![TZAP_OID_ORGANIZATION_POLICY.to_owned()],
            approved_leaf_policy_oids: vec![TZAP_OID_LEAF_POLICY.to_owned()],
            validation_time_unix_seconds: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCertificatePublicMetadata {
    pub version: u64,
    pub public_signer_id: String,
    pub public_org_id: Option<String>,
    pub public_device_id: String,
    pub assurance_level: TzapIdentityAssurance,
    pub policy_oid: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCertificateProfileValidation {
    pub trust_anchor_type: TzapTrustAnchorType,
    pub official_root_pin_kind: Option<TzapOfficialRootPinKind>,
    pub root_certificate_sha256: String,
    pub public_metadata: TzapCertificatePublicMetadata,
}

#[derive(Debug)]
pub enum TzapCertificateProfileError {
    InvalidChainLength { actual: usize },
    CertificateParse { index: usize, detail: String },
    ChainOrder { child_index: usize },
    SignatureValidation { subject_index: usize, detail: String },
    UnsupportedAlgorithm { index: usize, reason: &'static str },
    RootNotSelfSigned,
    RootNotPinned { fingerprint: String },
    RootProfile { reason: &'static str },
    IntermediateProfile { index: usize, reason: &'static str },
    LeafProfile { reason: &'static str },
    MissingMetadata,
    DuplicateMetadata,
    CriticalMetadata,
    NestedAsn1Metadata,
    MalformedMetadata { reason: &'static str },
    UnknownMetadataField { field: String },
    MetadataPolicyMismatch { policy_oid: String },
    Expired { index: usize },
}

impl fmt::Display for TzapCertificateProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChainLength { actual } => {
                write!(f, "TZAP certificate chain has invalid length {actual}")
            }
            Self::CertificateParse { index, detail } => {
                write!(f, "failed to parse certificate at chain index {index}: {detail}")
            }
            Self::ChainOrder { child_index } => {
                write!(f, "certificate chain is not ordered leaf issuer rootward at index {child_index}")
            }
            Self::SignatureValidation { subject_index, detail } => {
                write!(f, "certificate signature validation failed at chain index {subject_index}: {detail}")
            }
            Self::UnsupportedAlgorithm { index, reason } => {
                write!(f, "certificate at chain index {index} uses unsupported algorithm: {reason}")
            }
            Self::RootNotSelfSigned => write!(f, "TZAP root certificate is not self-signed"),
            Self::RootNotPinned { fingerprint } => {
                write!(f, "TZAP root fingerprint is not pinned: {fingerprint}")
            }
            Self::RootProfile { reason } => write!(f, "TZAP root profile rejected: {reason}"),
            Self::IntermediateProfile { index, reason } => {
                write!(f, "TZAP intermediate profile rejected at index {index}: {reason}")
            }
            Self::LeafProfile { reason } => write!(f, "TZAP leaf profile rejected: {reason}"),
            Self::MissingMetadata => write!(f, "TZAP metadata extension is missing"),
            Self::DuplicateMetadata => write!(f, "TZAP metadata extension appears more than once"),
            Self::CriticalMetadata => write!(f, "TZAP metadata extension must be non-critical"),
            Self::NestedAsn1Metadata => {
                write!(f, "TZAP metadata extension contains a nested ASN.1 wrapper")
            }
            Self::MalformedMetadata { reason } => {
                write!(f, "TZAP metadata extension is malformed: {reason}")
            }
            Self::UnknownMetadataField { field } => {
                write!(f, "TZAP metadata extension has unknown v1 field {field}")
            }
            Self::MetadataPolicyMismatch { policy_oid } => {
                write!(f, "TZAP certificate metadata policy OID does not match extension ({policy_oid})")
            }
            Self::Expired { index } => {
                write!(f, "certificate at chain index {index} is expired or not yet valid at validation time")
            }
        }
    }
}

impl std::error::Error for TzapCertificateProfileError {}

/// Validates an official TZAP document-signing chain against pinned root
/// fingerprints and the MVP certificate profiles.
pub fn validate_official_tzap_certificate_chain_der(
    chain_der: &[Vec<u8>],
    root_pins: &TzapRootPinSet,
    options: &TzapCertificateProfileOptions,
) -> Result<TzapCertificateProfileValidation, TzapCertificateProfileError> {
    validate_tzap_certificate_chain_der(chain_der, Some(root_pins), TzapTrustAnchorType::OfficialTzap, options)
}

/// Validates a custom trust chain against TZAP document-signing profiles without
/// upgrading it to official TZAP trust.
pub fn validate_custom_tzap_certificate_chain_der(
    chain_der: &[Vec<u8>],
    options: &TzapCertificateProfileOptions,
) -> Result<TzapCertificateProfileValidation, TzapCertificateProfileError> {
    validate_tzap_certificate_chain_der(chain_der, None, TzapTrustAnchorType::Custom, options)
}

/// Returns the certificate chain entries that belong in public TZAP envelopes.
///
/// Local inventory keeps the full issuer chain rootward so enrollment, renewal,
/// and profile validation can operate without another root lookup. MVP document
/// envelopes and contact cards omit the pinned root certificate; verifiers are
/// expected to use their configured root store to reconstruct the full chain.
#[must_use]
pub fn public_intermediate_chain_der(chain_der: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let Some((last, rest)) = chain_der.split_last() else {
        return Vec::new();
    };
    if is_self_issued_certificate_der(last) { rest.to_vec() } else { chain_der.to_vec() }
}

fn is_self_issued_certificate_der(der: &[u8]) -> bool {
    X509Certificate::from_der(der).is_ok_and(|(remaining, certificate)| remaining.is_empty() && certificate.issuer() == certificate.subject())
}

fn validate_tzap_certificate_chain_der(
    chain_der: &[Vec<u8>],
    official_root_pins: Option<&TzapRootPinSet>,
    trust_anchor_type: TzapTrustAnchorType,
    options: &TzapCertificateProfileOptions,
) -> Result<TzapCertificateProfileValidation, TzapCertificateProfileError> {
    if !(MIN_TZAP_CHAIN_LEN..=MAX_TZAP_CHAIN_LEN).contains(&chain_der.len()) {
        return Err(TzapCertificateProfileError::InvalidChainLength { actual: chain_der.len() });
    }

    let parsed = parse_x509_chain(chain_der)?;
    let openssl = parse_openssl_chain(chain_der)?;
    validate_chain_order_and_signatures(&parsed, &openssl)?;
    validate_chain_algorithms(&parsed, &openssl)?;

    let root_index = parsed.len() - 1;
    let mut root_digest = [0_u8; 32];
    root_digest.copy_from_slice(&Sha256::digest(&chain_der[root_index]));
    let root_fingerprint = format_certificate_sha256(&root_digest);
    let official_root_pin_kind = match official_root_pins {
        Some(pins) => official_root_pin_kind(pins, &root_fingerprint)?,
        None => None,
    };

    validate_root_certificate(&parsed[root_index], root_index, options)?;
    validate_intermediates(&parsed, options)?;
    require_leaf_aki_matches_issuer(&parsed)?;
    let public_metadata = validate_leaf_certificate(&parsed[0], 0, options)?;

    Ok(TzapCertificateProfileValidation { trust_anchor_type, official_root_pin_kind, root_certificate_sha256: root_fingerprint, public_metadata })
}

fn parse_x509_chain(chain_der: &[Vec<u8>]) -> Result<Vec<X509Certificate<'_>>, TzapCertificateProfileError> {
    chain_der
        .iter()
        .enumerate()
        .map(|(index, der)| {
            X509Certificate::from_der(der).map_err(|error| TzapCertificateProfileError::CertificateParse { index, detail: error.to_string() }).and_then(
                |(remaining, certificate)| {
                    if remaining.is_empty() {
                        Ok(certificate)
                    } else {
                        Err(TzapCertificateProfileError::CertificateParse { index, detail: "trailing DER bytes".to_owned() })
                    }
                },
            )
        })
        .collect()
}

fn parse_openssl_chain(chain_der: &[Vec<u8>]) -> Result<Vec<X509>, TzapCertificateProfileError> {
    chain_der
        .iter()
        .enumerate()
        .map(|(index, der)| X509::from_der(der).map_err(|source| TzapCertificateProfileError::CertificateParse { index, detail: source.to_string() }))
        .collect()
}

fn validate_chain_order_and_signatures(parsed: &[X509Certificate<'_>], openssl: &[X509]) -> Result<(), TzapCertificateProfileError> {
    for (index, pair) in parsed.windows(2).enumerate() {
        if pair[0].issuer() != pair[1].subject() {
            return Err(TzapCertificateProfileError::ChainOrder { child_index: index });
        }
    }

    let root = parsed.last().expect("chain length checked");
    if root.issuer() != root.subject() {
        return Err(TzapCertificateProfileError::RootNotSelfSigned);
    }

    for (index, pair) in openssl.windows(2).enumerate() {
        let issuer_key =
            pair[1].public_key().map_err(|source| TzapCertificateProfileError::SignatureValidation { subject_index: index, detail: source.to_string() })?;
        let verified = pair[0]
            .verify(&issuer_key)
            .map_err(|source| TzapCertificateProfileError::SignatureValidation { subject_index: index, detail: source.to_string() })?;
        if !verified {
            return Err(TzapCertificateProfileError::SignatureValidation {
                subject_index: index,
                detail: "issuer public key did not verify certificate signature".to_owned(),
            });
        }
    }

    let root_index = openssl.len() - 1;
    let root_key = openssl[root_index]
        .public_key()
        .map_err(|source| TzapCertificateProfileError::SignatureValidation { subject_index: root_index, detail: source.to_string() })?;
    if !openssl[root_index]
        .verify(&root_key)
        .map_err(|source| TzapCertificateProfileError::SignatureValidation { subject_index: root_index, detail: source.to_string() })?
    {
        return Err(TzapCertificateProfileError::RootNotSelfSigned);
    }

    Ok(())
}

fn validate_chain_algorithms(parsed: &[X509Certificate<'_>], openssl: &[X509]) -> Result<(), TzapCertificateProfileError> {
    for (index, certificate) in parsed.iter().enumerate() {
        if certificate.signature_algorithm.oid().to_id_string() != OID_ECDSA_WITH_SHA256
            || certificate.tbs_certificate.signature.oid().to_id_string() != OID_ECDSA_WITH_SHA256
        {
            return Err(TzapCertificateProfileError::UnsupportedAlgorithm { index, reason: "certificate signature must be ECDSA P-256 with SHA-256" });
        }

        let key = openssl[index].public_key().map_err(|source| TzapCertificateProfileError::UnsupportedAlgorithm {
            index,
            reason: if source.errors().is_empty() { "certificate public key is unreadable" } else { "certificate public key is unsupported" },
        })?;
        let ec_key =
            key.ec_key().map_err(|_| TzapCertificateProfileError::UnsupportedAlgorithm { index, reason: "certificate public key must be ECDSA P-256" })?;
        if ec_key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Err(TzapCertificateProfileError::UnsupportedAlgorithm { index, reason: "certificate public key must use prime256v1" });
        }
    }

    Ok(())
}

pub(crate) fn official_root_pin_kind(pins: &TzapRootPinSet, fingerprint: &str) -> Result<Option<TzapOfficialRootPinKind>, TzapCertificateProfileError> {
    if pins.is_current_root(fingerprint) {
        Ok(Some(TzapOfficialRootPinKind::Current))
    } else if pins.is_planned_successor(fingerprint) {
        Ok(Some(TzapOfficialRootPinKind::PlannedSuccessor))
    } else {
        Err(TzapCertificateProfileError::RootNotPinned { fingerprint: fingerprint.to_owned() })
    }
}

fn validate_root_certificate(
    certificate: &X509Certificate<'_>,
    index: usize,
    options: &TzapCertificateProfileOptions,
) -> Result<(), TzapCertificateProfileError> {
    if let Some(time) = options.validation_time_unix_seconds
        && !is_valid_at(certificate, time)
    {
        return Err(TzapCertificateProfileError::Expired { index });
    }
    let basic_constraints = certificate
        .basic_constraints()
        .map_err(|_| TzapCertificateProfileError::RootProfile { reason: "basic constraints are invalid or duplicated" })?
        .ok_or(TzapCertificateProfileError::RootProfile { reason: "missing critical basic constraints" })?;
    if !basic_constraints.critical || !basic_constraints.value.ca || basic_constraints.value.path_len_constraint != Some(REQUIRED_ROOT_PATH_LEN) {
        return Err(TzapCertificateProfileError::RootProfile { reason: "root must be a critical CA with pathLenConstraint 2" });
    }

    require_ca_key_usage(certificate, CertificateRole::Root, None)?;
    if subject_key_identifier(certificate).is_none() {
        return Err(TzapCertificateProfileError::RootProfile { reason: "missing subject key identifier" });
    }
    reject_forbidden_extended_key_usage(certificate, CertificateRole::Root, None)?;

    Ok(())
}

fn validate_intermediates(chain: &[X509Certificate<'_>], options: &TzapCertificateProfileOptions) -> Result<(), TzapCertificateProfileError> {
    let root_index = chain.len() - 1;
    for (index, certificate) in chain.iter().enumerate().take(root_index).skip(1) {
        if let Some(time) = options.validation_time_unix_seconds
            && !is_valid_at(certificate, time)
        {
            return Err(TzapCertificateProfileError::Expired { index });
        }
        let has_org_intermediate = chain.len() == MAX_TZAP_CHAIN_LEN;
        let role = if has_org_intermediate && index == 1 { CertificateRole::OrganizationIntermediate } else { CertificateRole::PlatformIntermediate };

        let basic_constraints = certificate
            .basic_constraints()
            .map_err(|_| TzapCertificateProfileError::IntermediateProfile { index, reason: "basic constraints are invalid or duplicated" })?
            .ok_or(TzapCertificateProfileError::IntermediateProfile { index, reason: "missing critical basic constraints" })?;
        // pathLenConstraint is a ceiling on how many more CAs may follow, not a
        // per-chain exact count: RFC 5280 ss4.2.1.9 lets a stricter value pass
        // any chain with fewer subordinate CAs than the ceiling allows. A
        // single platform issuer legitimately signs both organization
        // intermediates (needs pathlen >= 1) and leaf certificates directly
        // (needs pathlen >= 0) with the *same* certificate, so requiring an
        // exact match per scenario rejected valid leaf-only chains issued by
        // an org-capable platform issuer. The organization intermediate role
        // keeps an exact match: it must never be allowed to sign further
        // sub-CAs, so a looser-than-zero pathlen is a real profile violation,
        // not just an unused allowance.
        let remaining_cas_below = u32::try_from(index - 1).unwrap_or(u32::MAX);
        let path_len_ok = match role {
            CertificateRole::PlatformIntermediate => basic_constraints.value.path_len_constraint.is_some_and(|actual| actual >= remaining_cas_below),
            CertificateRole::OrganizationIntermediate => basic_constraints.value.path_len_constraint == Some(ORG_INTERMEDIATE_PATH_LEN),
            CertificateRole::Root => unreachable!(),
        };
        if !basic_constraints.critical || !basic_constraints.value.ca || !path_len_ok {
            return Err(TzapCertificateProfileError::IntermediateProfile { index, reason: "intermediate must be a critical CA with a sufficient path length" });
        }

        require_ca_key_usage(certificate, role, Some(index))?;
        reject_forbidden_extended_key_usage(certificate, role, Some(index))?;
        require_aki_ski_pair(chain, index)?;
        if !certificate_has_policy(certificate, TZAP_OID_CA_POLICY) {
            return Err(TzapCertificateProfileError::IntermediateProfile { index, reason: "missing TZAP CA policy OID" });
        }
        if matches!(role, CertificateRole::OrganizationIntermediate) && !has_any_policy(certificate, &options.approved_org_intermediate_policy_oids) {
            return Err(TzapCertificateProfileError::IntermediateProfile {
                index,
                reason: "organization intermediate lacks an approved organization policy OID",
            });
        }
        if certificate.iter_extensions().all(|extension| extension.oid.to_id_string() != "2.5.29.31") {
            return Err(TzapCertificateProfileError::IntermediateProfile {
                index,
                reason: "missing CRL distribution point or TZAP status distribution extension",
            });
        }
    }

    Ok(())
}

fn validate_leaf_certificate(
    certificate: &X509Certificate<'_>,
    index: usize,
    options: &TzapCertificateProfileOptions,
) -> Result<TzapCertificatePublicMetadata, TzapCertificateProfileError> {
    if let Some(time) = options.validation_time_unix_seconds
        && !is_valid_at(certificate, time)
    {
        return Err(TzapCertificateProfileError::Expired { index });
    }
    let basic_constraints = certificate
        .basic_constraints()
        .map_err(|_| TzapCertificateProfileError::LeafProfile { reason: "basic constraints are invalid or duplicated" })?
        .ok_or(TzapCertificateProfileError::LeafProfile { reason: "missing critical basic constraints" })?;
    if !basic_constraints.critical || basic_constraints.value.ca {
        return Err(TzapCertificateProfileError::LeafProfile { reason: "leaf must have critical CA:FALSE basic constraints" });
    }
    let validity = certificate.validity();
    let Some(validity_duration) = validity.not_after - validity.not_before else {
        return Err(TzapCertificateProfileError::LeafProfile { reason: "leaf validity interval is invalid" });
    };
    if validity_duration.whole_days() > MAX_TZAP_LEAF_VALIDITY_DAYS {
        return Err(TzapCertificateProfileError::LeafProfile { reason: "leaf validity exceeds the TZAP MVP maximum" });
    }

    let key_usage = certificate
        .key_usage()
        .map_err(|_| TzapCertificateProfileError::LeafProfile { reason: "key usage is invalid or duplicated" })?
        .ok_or(TzapCertificateProfileError::LeafProfile { reason: "missing critical key usage" })?;
    if !key_usage.critical || key_usage.value.flags != 1 {
        return Err(TzapCertificateProfileError::LeafProfile { reason: "leaf key usage must be exactly digitalSignature" });
    }

    let eku_oids =
        extended_key_usage_oids(certificate).ok_or(TzapCertificateProfileError::LeafProfile { reason: "missing document-signing extended key usage" })?;
    let document_signing_oid =
        oid_value_bytes(TZAP_OID_DOCUMENT_SIGNING_EKU).ok_or(TzapCertificateProfileError::LeafProfile { reason: "document-signing OID is not numeric" })?;
    if eku_oids.as_slice() != [document_signing_oid.as_slice()] {
        return Err(TzapCertificateProfileError::LeafProfile { reason: "extended key usage must be exactly TZAP document signing" });
    }

    if let Some(san) = certificate
        .subject_alternative_name()
        .map_err(|_| TzapCertificateProfileError::LeafProfile { reason: "subject alternative name is invalid or duplicated" })?
        && san.value.general_names.iter().any(|name| matches!(name, GeneralName::DNSName(_) | GeneralName::IPAddress(_)))
    {
        return Err(TzapCertificateProfileError::LeafProfile { reason: "MVP leaves must not contain DNS or IP subject alternative names" });
    }

    if !has_any_policy(certificate, &options.approved_leaf_policy_oids) {
        return Err(TzapCertificateProfileError::LeafProfile { reason: "missing approved TZAP leaf policy OID" });
    }

    if authority_key_identifier(certificate).is_none() {
        return Err(TzapCertificateProfileError::LeafProfile { reason: "missing authority key identifier" });
    }

    let metadata = parse_public_metadata_extension(certificate)?;
    if !certificate_has_policy(certificate, &metadata.policy_oid) {
        return Err(TzapCertificateProfileError::MetadataPolicyMismatch { policy_oid: metadata.policy_oid });
    }

    Ok(metadata)
}

fn require_ca_key_usage(certificate: &X509Certificate<'_>, role: CertificateRole, index: Option<usize>) -> Result<(), TzapCertificateProfileError> {
    let key_usage = certificate
        .key_usage()
        .map_err(|_| role.profile_error("key usage is invalid or duplicated", index))?
        .ok_or_else(|| role.profile_error("missing critical key usage", index))?;
    if !key_usage.critical || !key_usage.value.key_cert_sign() || !key_usage.value.crl_sign() || key_usage.value.flags != ((1 << 5) | (1 << 6)) {
        return Err(role.profile_error("CA key usage must be exactly keyCertSign and cRLSign", index));
    }
    Ok(())
}

fn reject_forbidden_extended_key_usage(
    certificate: &X509Certificate<'_>,
    role: CertificateRole,
    index: Option<usize>,
) -> Result<(), TzapCertificateProfileError> {
    if let Some(eku) = certificate.extended_key_usage().map_err(|_| role.profile_error("extended key usage is invalid or duplicated", index))? {
        if eku.value.any || eku.value.server_auth || eku.value.client_auth || eku.value.code_signing {
            return Err(role.profile_error("certificate authorizes forbidden extended key usage", index));
        }
        let other_oids = eku.value.other.iter().map(x509_parser::asn1_rs::Oid::to_id_string).collect::<Vec<_>>();
        if other_oids.iter().any(|oid| oid == OID_ANY_EXTENDED_KEY_USAGE) {
            return Err(role.profile_error("certificate authorizes anyExtendedKeyUsage", index));
        }
    }
    if let Some(oids) = extended_key_usage_oids(certificate) {
        let forbidden = [OID_ANY_EXTENDED_KEY_USAGE, OID_SERVER_AUTH_EKU, OID_CLIENT_AUTH_EKU, OID_CODE_SIGNING_EKU]
            .into_iter()
            .filter_map(oid_value_bytes)
            .collect::<Vec<_>>();
        if oids.iter().any(|oid| forbidden.iter().any(|forbidden| forbidden == oid)) {
            return Err(role.profile_error("certificate authorizes forbidden extended key usage", index));
        }
    }
    Ok(())
}

fn require_aki_ski_pair(parsed: &[X509Certificate<'_>], index: usize) -> Result<(), TzapCertificateProfileError> {
    let child_aki = authority_key_identifier(&parsed[index])
        .ok_or(TzapCertificateProfileError::IntermediateProfile { index, reason: "missing authority key identifier" })?;
    let issuer_ski = subject_key_identifier(&parsed[index + 1])
        .ok_or(TzapCertificateProfileError::IntermediateProfile { index, reason: "issuer is missing subject key identifier" })?;
    let own_ski =
        subject_key_identifier(&parsed[index]).ok_or(TzapCertificateProfileError::IntermediateProfile { index, reason: "missing subject key identifier" })?;
    if child_aki != issuer_ski {
        return Err(TzapCertificateProfileError::IntermediateProfile {
            index,
            reason: "authority key identifier does not match issuer subject key identifier",
        });
    }
    if index > 1 {
        let issued_child_aki = authority_key_identifier(&parsed[index - 1])
            .ok_or(TzapCertificateProfileError::IntermediateProfile { index, reason: "issued child is missing authority key identifier" })?;
        if own_ski != issued_child_aki {
            return Err(TzapCertificateProfileError::IntermediateProfile {
                index,
                reason: "subject key identifier does not match child authority key identifier",
            });
        }
    }
    Ok(())
}

fn require_leaf_aki_matches_issuer(parsed: &[X509Certificate<'_>]) -> Result<(), TzapCertificateProfileError> {
    let leaf_aki = authority_key_identifier(&parsed[0]).ok_or(TzapCertificateProfileError::LeafProfile { reason: "missing authority key identifier" })?;
    let issuer_ski =
        subject_key_identifier(&parsed[1]).ok_or(TzapCertificateProfileError::LeafProfile { reason: "issuer is missing subject key identifier" })?;
    if leaf_aki != issuer_ski {
        return Err(TzapCertificateProfileError::LeafProfile { reason: "authority key identifier does not match issuer subject key identifier" });
    }
    Ok(())
}

fn parse_public_metadata_extension(certificate: &X509Certificate<'_>) -> Result<TzapCertificatePublicMetadata, TzapCertificateProfileError> {
    let mut matches = certificate.iter_extensions().filter(|extension| extension_oid_matches(extension, TZAP_OID_METADATA_EXTENSION));
    let extension = matches.next().ok_or(TzapCertificateProfileError::MissingMetadata)?;
    if matches.next().is_some() {
        return Err(TzapCertificateProfileError::DuplicateMetadata);
    }
    if extension.critical {
        return Err(TzapCertificateProfileError::CriticalMetadata);
    }
    if looks_like_nested_asn1(extension.value) {
        return Err(TzapCertificateProfileError::NestedAsn1Metadata);
    }

    let raw = std::str::from_utf8(extension.value).map_err(|_| TzapCertificateProfileError::MalformedMetadata { reason: "metadata is not UTF-8" })?;
    let value: Value = serde_json::from_str(raw).map_err(|_| TzapCertificateProfileError::MalformedMetadata { reason: "metadata is not JSON" })?;
    let canonical = serde_json_canonicalizer::to_string(&value)
        .map_err(|_| TzapCertificateProfileError::MalformedMetadata { reason: "metadata is not JCS canonicalizable" })?;
    if canonical.as_bytes() != extension.value {
        return Err(TzapCertificateProfileError::MalformedMetadata { reason: "metadata is not JCS canonical JSON" });
    }

    parse_public_metadata_value(&value)
}

fn parse_public_metadata_value(value: &Value) -> Result<TzapCertificatePublicMetadata, TzapCertificateProfileError> {
    let object = value.as_object().ok_or(TzapCertificateProfileError::MalformedMetadata { reason: "metadata is not a JSON object" })?;
    validate_metadata_fields(object)?;

    let version = required_u64(object, "version")?;
    if version != 1 {
        return Err(TzapCertificateProfileError::MalformedMetadata { reason: "unsupported metadata version" });
    }
    let public_signer_id = required_string(object, "public_signer_id")?;
    if !is_valid_public_signer_id(public_signer_id) {
        return Err(TzapCertificateProfileError::MalformedMetadata { reason: "invalid public_signer_id" });
    }
    let public_org_id = optional_string(object, "public_org_id")?;
    if let Some(value) = public_org_id
        && !is_valid_public_org_id(value)
    {
        return Err(TzapCertificateProfileError::MalformedMetadata { reason: "invalid public_org_id" });
    }
    let public_device_id = required_string(object, "public_device_id")?;
    if !is_valid_public_device_id(public_device_id) {
        return Err(TzapCertificateProfileError::MalformedMetadata { reason: "invalid public_device_id" });
    }
    let assurance_level = required_string(object, "assurance_level")?;
    let assurance_level =
        TzapIdentityAssurance::parse(assurance_level).ok_or(TzapCertificateProfileError::MalformedMetadata { reason: "invalid assurance_level" })?;
    let policy_oid = required_string(object, "policy_oid")?;
    if !is_numeric_dotted_oid(policy_oid) {
        return Err(TzapCertificateProfileError::MalformedMetadata { reason: "invalid policy_oid" });
    }

    Ok(TzapCertificatePublicMetadata {
        version,
        public_signer_id: public_signer_id.to_owned(),
        public_org_id: public_org_id.map(ToOwned::to_owned),
        public_device_id: public_device_id.to_owned(),
        assurance_level,
        policy_oid: policy_oid.to_owned(),
    })
}

fn validate_metadata_fields(object: &Map<String, Value>) -> Result<(), TzapCertificateProfileError> {
    const ALLOWED_FIELDS: &[&str] = &["assurance_level", "policy_oid", "public_device_id", "public_org_id", "public_signer_id", "version"];
    for field in object.keys() {
        if !ALLOWED_FIELDS.contains(&field.as_str()) {
            return Err(TzapCertificateProfileError::UnknownMetadataField { field: field.clone() });
        }
    }
    Ok(())
}

fn required_u64(object: &Map<String, Value>, field: &'static str) -> Result<u64, TzapCertificateProfileError> {
    object.get(field).and_then(Value::as_u64).ok_or(TzapCertificateProfileError::MalformedMetadata { reason: field })
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &'static str) -> Result<&'a str, TzapCertificateProfileError> {
    object.get(field).and_then(Value::as_str).ok_or(TzapCertificateProfileError::MalformedMetadata { reason: field })
}

fn optional_string<'a>(object: &'a Map<String, Value>, field: &'static str) -> Result<Option<&'a str>, TzapCertificateProfileError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(TzapCertificateProfileError::MalformedMetadata { reason: field }),
    }
}

fn looks_like_nested_asn1(value: &[u8]) -> bool {
    matches!(value.first(), Some(0x04 | 0x0c | 0x13 | 0x16 | 0x30))
}

fn is_numeric_dotted_oid(value: &str) -> bool {
    if value.is_empty() || value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return false;
    }
    value.split('.').all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn certificate_has_policy(certificate: &X509Certificate<'_>, oid: &str) -> bool {
    let Ok(target_oid) = Asn1Object::from_str(oid) else {
        return false;
    };
    let target_oid = target_oid.as_slice();
    certificate.iter_extensions().filter(|extension| extension.oid.to_id_string() == "2.5.29.32").any(|extension| {
        certificate_policies_contains_oid(extension.value, target_oid)
            || matches!(
                extension.parsed_extension(),
                ParsedExtension::CertificatePolicies(policies)
                    if policies.iter().any(|policy| policy.policy_id.to_id_string() == oid)
            )
    })
}

fn certificate_policies_contains_oid(mut input: &[u8], target_oid: &[u8]) -> bool {
    let Some(policies_content) = der_take_constructed(&mut input, 0x30) else {
        return false;
    };
    if !input.is_empty() {
        return false;
    }

    let mut policies = policies_content;
    while !policies.is_empty() {
        let Some(mut policy_info) = der_take_constructed(&mut policies, 0x30) else {
            return false;
        };
        let Some(policy_oid) = der_take_primitive(&mut policy_info, 0x06) else {
            return false;
        };
        if policy_oid == target_oid {
            return true;
        }
    }
    false
}

fn der_take_constructed<'a>(input: &mut &'a [u8], expected_tag: u8) -> Option<&'a [u8]> {
    der_take_primitive(input, expected_tag)
}

fn der_take_primitive<'a>(input: &mut &'a [u8], expected_tag: u8) -> Option<&'a [u8]> {
    let tag = *input.first()?;
    if tag != expected_tag {
        return None;
    }
    *input = &input[1..];
    let length = der_take_length(input)?;
    if input.len() < length {
        return None;
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Some(value)
}

fn der_take_length(input: &mut &[u8]) -> Option<usize> {
    let first = *input.first()?;
    *input = &input[1..];
    if first & 0x80 == 0 {
        return Some(usize::from(first));
    }
    let byte_count = usize::from(first & 0x7f);
    if byte_count == 0 || byte_count > 4 || input.len() < byte_count {
        return None;
    }
    let mut length = 0usize;
    for byte in &input[..byte_count] {
        length = (length << 8) | usize::from(*byte);
    }
    *input = &input[byte_count..];
    Some(length)
}

fn has_any_policy(certificate: &X509Certificate<'_>, oids: &[String]) -> bool {
    oids.iter().any(|oid| certificate_has_policy(certificate, oid))
}

fn extended_key_usage_oids(certificate: &X509Certificate<'_>) -> Option<Vec<Vec<u8>>> {
    let mut matching = certificate.iter_extensions().filter(|extension| extension.oid.to_id_string() == OID_EXTENDED_KEY_USAGE_EXTENSION);
    let extension = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    der_sequence_of_oids(extension.value)
}

fn der_sequence_of_oids(mut input: &[u8]) -> Option<Vec<Vec<u8>>> {
    let sequence = der_take_constructed(&mut input, 0x30)?;
    if !input.is_empty() {
        return None;
    }
    let mut values = Vec::new();
    let mut sequence_input = sequence;
    while !sequence_input.is_empty() {
        values.push(der_take_primitive(&mut sequence_input, 0x06)?.to_vec());
    }
    Some(values)
}

fn oid_value_bytes(oid: &str) -> Option<Vec<u8>> {
    Asn1Object::from_str(oid).ok().map(|oid| oid.as_slice().to_vec())
}

fn extension_oid_matches(extension: &x509_parser::extensions::X509Extension<'_>, oid: &str) -> bool {
    oid_value_bytes(oid).is_some_and(|target| extension.oid.as_bytes() == target.as_slice()) || extension.oid.to_id_string() == oid
}

pub(crate) fn authority_key_identifier(certificate: &X509Certificate<'_>) -> Option<Vec<u8>> {
    certificate.iter_extensions().find_map(|extension| {
        if let ParsedExtension::AuthorityKeyIdentifier(aki) = extension.parsed_extension() {
            aki.key_identifier.as_ref().map(|identifier| identifier.0.to_vec())
        } else {
            None
        }
    })
}

pub(crate) fn subject_key_identifier(certificate: &X509Certificate<'_>) -> Option<Vec<u8>> {
    certificate.iter_extensions().find_map(|extension| {
        if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension() { Some(identifier.0.to_vec()) } else { None }
    })
}

#[derive(Copy, Clone)]
enum CertificateRole {
    Root,
    PlatformIntermediate,
    OrganizationIntermediate,
}

impl CertificateRole {
    fn profile_error(self, reason: &'static str, index: Option<usize>) -> TzapCertificateProfileError {
        match self {
            Self::Root => TzapCertificateProfileError::RootProfile { reason },
            Self::PlatformIntermediate | Self::OrganizationIntermediate => {
                TzapCertificateProfileError::IntermediateProfile { index: index.unwrap_or(0), reason }
            }
        }
    }
}

#[allow(clippy::cast_possible_wrap)]
fn is_valid_at(certificate: &X509Certificate<'_>, unix_seconds: u64) -> bool {
    let validity = certificate.validity();
    validity.not_before.timestamp() <= (unix_seconds as i64) && (unix_seconds as i64) <= validity.not_after.timestamp()
}
