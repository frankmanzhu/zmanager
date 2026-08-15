//! Local (offline) TZAP certificate service.
//!
//! Issues, renews, and revokes certificates from a deterministic local CA
//! rooted at a fixed key, without any hosted server. The CLI uses this path
//! for `cert enroll/renew/revoke` and device retire whenever no
//! `--service-base-url` is configured; `tzap_service` exposes the same
//! operations as JSON endpoints. The deterministic outputs also let the
//! obligation-harness integration tests assert on stable fixtures.

use crate::auth_client::{SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError, TzapSessionRecord};
use crate::certificate_lifecycle::TzapRetirementCompletion;
use crate::device_identity::{TzapDeviceCsrOptions, generate_device_signing_key_and_csr};
use crate::local_identity_store::{
    TzapDeviceSigningKeyRecord, TzapEnrolledCertificateRecord, TzapLocalCertificateState, TzapLocalIdentityInventory, TzapLocalIdentityStore,
    TzapLocalIdentityStoreError, TzapSignDeviceRouting,
};
use crate::trust::{self, TzapCertificatePublicMetadata};
use crate::x509_build::{self, RawCertificateSpec};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ecdsa::elliptic_curve::Generate as _;
use pkcs8::EncodePublicKey;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::fmt;
use x509_cert::der::Encode as _;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer as _, X509Certificate};

const LOCAL_ROOT_CN: &str = "ZManager Local TZAP Root";
const LOCAL_PLATFORM_CN: &str = "ZManager Local TZAP Platform";
const LOCAL_SIGNER_CN: &str = "ZManager Local TZAP Signer";
const LOCAL_SIGNER_ID: &str = "psign_0123456789ABCDEFGH";
const LOCAL_DEVICE_ID: &str = "pdev_0123456789ABCDEFGH";
const LOCAL_CERTIFICATE_ID_PREFIX: &str = "local-cert-";
const LOCAL_RENEWED_CERTIFICATE_ID_PREFIX: &str = "local-renewed-cert-";
const LOCAL_SIGN_DEVICE_ID_PREFIX: &str = "local-sign-device-";
const LOCAL_VALIDITY_SECONDS: u64 = 90 * 24 * 60 * 60;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapLocalServiceOptions {
    pub account_key: String,
    pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapLocalRetirementReport {
    pub completion: TzapRetirementCompletion,
    pub attempted_sign_device_ids: Vec<String>,
}

#[derive(Debug)]
pub enum TzapLocalServiceError {
    Auth(TzapAuthError),
    Store(TzapLocalIdentityStoreError),
    Crypto(String),
    CertificateNotFound,
    SessionExpired,
}

impl fmt::Display for TzapLocalServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(error) => write!(f, "local TZAP auth failed: {error}"),
            Self::Store(error) => write!(f, "local TZAP store update failed: {error}"),
            Self::Crypto(reason) => write!(f, "local TZAP certificate generation failed: {reason}"),
            Self::CertificateNotFound => write!(f, "certificate was not found locally"),
            Self::SessionExpired => write!(f, "session expired"),
        }
    }
}

impl std::error::Error for TzapLocalServiceError {}

impl From<TzapAuthError> for TzapLocalServiceError {
    fn from(error: TzapAuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<TzapLocalIdentityStoreError> for TzapLocalServiceError {
    fn from(error: TzapLocalIdentityStoreError) -> Self {
        Self::Store(error)
    }
}

pub fn enroll_local_certificate(
    store: &mut impl TzapLocalIdentityStore,
    session: &TzapSessionRecord,
    options: &TzapLocalServiceOptions,
) -> Result<TzapEnrolledCertificateRecord, TzapLocalServiceError> {
    require_active_sign_session(session, options.now_unix_seconds)?;
    let mut inventory = store.load_inventory(&options.account_key)?;
    let signing_key = ensure_device_signing_key(&mut inventory, options.now_unix_seconds)?;
    let record = issue_local_certificate(
        &signing_key,
        local_certificate_id(LOCAL_CERTIFICATE_ID_PREFIX, inventory.enrolled_certificates.len() + 1),
        options.now_unix_seconds,
    )?;
    inventory.enrolled_certificates.retain(|existing| existing.certificate_sha256 != record.certificate_sha256);
    inventory.enrolled_certificates.push(record.clone());
    store.save_inventory(&options.account_key, inventory)?;
    Ok(record)
}

pub fn renew_local_certificate(
    store: &mut impl TzapLocalIdentityStore,
    session: &TzapSessionRecord,
    options: &TzapLocalServiceOptions,
    certificate_id: &str,
) -> Result<TzapEnrolledCertificateRecord, TzapLocalServiceError> {
    require_active_sign_session(session, options.now_unix_seconds)?;
    let mut inventory = store.load_inventory(&options.account_key)?;
    let previous = inventory
        .enrolled_certificates
        .iter()
        .find(|record| record.certificate_id == certificate_id)
        .cloned()
        .ok_or(TzapLocalServiceError::CertificateNotFound)?;
    if !matches!(previous.state, TzapLocalCertificateState::Active) {
        return Err(TzapLocalServiceError::CertificateNotFound);
    }
    let signing_key = inventory
        .device_signing_keys
        .iter()
        .find(|record| record.key_id == previous.signing_key_id)
        .cloned()
        .ok_or(TzapLocalServiceError::CertificateNotFound)?;
    let record = issue_local_certificate(
        &signing_key,
        local_certificate_id(LOCAL_RENEWED_CERTIFICATE_ID_PREFIX, inventory.enrolled_certificates.len() + 1),
        options.now_unix_seconds,
    )?;
    inventory.enrolled_certificates.push(record.clone());
    store.save_inventory(&options.account_key, inventory)?;
    Ok(record)
}

pub fn revoke_local_certificate(
    store: &mut impl TzapLocalIdentityStore,
    session: &TzapSessionRecord,
    options: &TzapLocalServiceOptions,
    certificate_id: &str,
) -> Result<TzapRetirementCompletion, TzapLocalServiceError> {
    require_active_sign_session(session, options.now_unix_seconds)?;
    let mut inventory = store.load_inventory(&options.account_key)?;
    let mut found = false;
    for certificate in &mut inventory.enrolled_certificates {
        if certificate.certificate_id == certificate_id {
            certificate.state = TzapLocalCertificateState::Revoked;
            found = true;
        }
    }
    if !found {
        return Err(TzapLocalServiceError::CertificateNotFound);
    }
    store.save_inventory(&options.account_key, inventory)?;
    Ok(TzapRetirementCompletion::Complete)
}

pub fn retire_local_device(
    store: &mut impl TzapLocalIdentityStore,
    session: &TzapSessionRecord,
    options: &TzapLocalServiceOptions,
) -> Result<TzapLocalRetirementReport, TzapLocalServiceError> {
    require_active_sign_session(session, options.now_unix_seconds)?;
    let mut inventory = store.load_inventory(&options.account_key)?;
    let mut attempted = Vec::new();
    for certificate in &mut inventory.enrolled_certificates {
        if certificate.state == TzapLocalCertificateState::Active && matches!(certificate.sign_device_routing, TzapSignDeviceRouting::Personal) {
            attempted.push(certificate.sign_device_id.clone());
            certificate.state = TzapLocalCertificateState::Revoked;
        }
    }
    store.save_inventory(&options.account_key, inventory)?;
    Ok(TzapLocalRetirementReport { completion: TzapRetirementCompletion::Complete, attempted_sign_device_ids: attempted })
}

fn require_active_sign_session(session: &TzapSessionRecord, now_unix_seconds: u64) -> Result<(), TzapLocalServiceError> {
    session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
    if session.is_expired_at(now_unix_seconds) {
        return Err(TzapLocalServiceError::SessionExpired);
    }
    Ok(())
}

fn ensure_device_signing_key(inventory: &mut TzapLocalIdentityInventory, now_unix_seconds: u64) -> Result<TzapDeviceSigningKeyRecord, TzapLocalServiceError> {
    if let Some(record) = inventory.device_signing_keys.first() {
        return Ok(record.clone());
    }
    let material = generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).map_err(|error| TzapLocalServiceError::Crypto(error.to_string()))?;
    let record = TzapDeviceSigningKeyRecord {
        key_id: material.public_key_fingerprint.clone(),
        public_key_fingerprint: material.public_key_fingerprint,
        private_key_der: material.private_key_der,
        created_at_unix_seconds: now_unix_seconds,
        label: Some("Local TZAP signing key".to_owned()),
    };
    inventory.device_signing_keys.push(record.clone());
    Ok(record)
}

fn issue_local_certificate(
    signing_key: &TzapDeviceSigningKeyRecord,
    certificate_id: String,
    now_unix_seconds: u64,
) -> Result<TzapEnrolledCertificateRecord, TzapLocalServiceError> {
    let leaf_key = crate::p256_signature::parse_p256_private_key_der(signing_key.private_key_der.expose_secret())
        .map_err(|error| TzapLocalServiceError::Crypto(format!("{error:?}")))?;
    let chain = certificate_chain_for_leaf_key(&leaf_key, now_unix_seconds)?;
    Ok(TzapEnrolledCertificateRecord {
        certificate_id,
        certificate_sha256: chain.leaf_sha256,
        issuer_certificate_sha256: chain.platform_sha256,
        issuer_key_identifier: chain.issuer_key_identifier,
        serial_number: chain.serial_number,
        leaf_certificate_der: chain.leaf_der,
        intermediate_chain_der: vec![chain.platform_der, chain.root_der],
        not_before_unix_seconds: now_unix_seconds,
        not_after_unix_seconds: now_unix_seconds.saturating_add(LOCAL_VALIDITY_SECONDS),
        public_metadata: public_metadata(),
        sign_device_id: local_sign_device_id(&signing_key.public_key_fingerprint),
        sign_device_routing: TzapSignDeviceRouting::Personal,
        signing_key_id: signing_key.key_id.clone(),
        state: TzapLocalCertificateState::Active,
    })
}

#[derive(Debug)]
struct IssuedChain {
    leaf_der: Vec<u8>,
    platform_der: Vec<u8>,
    root_der: Vec<u8>,
    leaf_sha256: String,
    platform_sha256: String,
    issuer_key_identifier: String,
    serial_number: String,
}

fn certificate_chain_for_leaf_key(leaf_key: &p256::SecretKey, now_unix_seconds: u64) -> Result<IssuedChain, TzapLocalServiceError> {
    let root_key = p256_private_key();
    let platform_key = p256_private_key();
    let root_der = root_certificate(&root_key, now_unix_seconds)?;
    let platform_der = intermediate_certificate(&platform_key, &root_key, now_unix_seconds)?;
    let leaf_der = leaf_certificate(leaf_key, &platform_key, now_unix_seconds)?;
    let platform_parsed = parse_certificate(&platform_der, "platform")?;
    let leaf_parsed = parse_certificate(&leaf_der, "leaf")?;
    Ok(IssuedChain {
        issuer_key_identifier: URL_SAFE_NO_PAD
            .encode(subject_key_identifier(&platform_parsed).ok_or_else(|| TzapLocalServiceError::Crypto("platform certificate missing SKI".to_owned()))?),
        serial_number: trust::canonical_serial_hex(leaf_parsed.raw_serial()).map_err(|_| TzapLocalServiceError::Crypto("invalid serial".to_owned()))?,
        leaf_sha256: crate::trust::sha256_identifier(&leaf_der),
        platform_sha256: crate::trust::sha256_identifier(&platform_der),
        leaf_der,
        platform_der,
        root_der,
    })
}

fn key_spki_der(key: &p256::SecretKey) -> Result<Vec<u8>, TzapLocalServiceError> {
    key.public_key().to_public_key_der().map(|document| document.as_bytes().to_vec()).map_err(|error| TzapLocalServiceError::Crypto(error.to_string()))
}

fn not_before_unix(now_unix_seconds: u64) -> i64 {
    i64::try_from(now_unix_seconds).unwrap_or(i64::MAX)
}

fn not_after_unix(now_unix_seconds: u64) -> i64 {
    i64::try_from(now_unix_seconds.saturating_add(LOCAL_VALIDITY_SECONDS)).unwrap_or(i64::MAX)
}

fn root_certificate(key: &p256::SecretKey, now_unix_seconds: u64) -> Result<Vec<u8>, TzapLocalServiceError> {
    let subject_spki_der = key_spki_der(key)?;
    let extensions = vec![basic_constraints_extension(true, Some(2)), ca_key_usage_extension(), ski_extension(&subject_spki_der)?];
    local_certificate(LOCAL_ROOT_CN, LOCAL_ROOT_CN, key, &subject_spki_der, &extensions, now_unix_seconds)
}

fn intermediate_certificate(key: &p256::SecretKey, root_key: &p256::SecretKey, now_unix_seconds: u64) -> Result<Vec<u8>, TzapLocalServiceError> {
    let subject_spki_der = key_spki_der(key)?;
    let root_spki_der = key_spki_der(root_key)?;
    let extensions = vec![
        basic_constraints_extension(true, Some(0)),
        ca_key_usage_extension(),
        ski_extension(&subject_spki_der)?,
        aki_extension(&root_spki_der)?,
        raw_extension_der("2.5.29.32", false, &certificate_policies_der(&[trust::TZAP_OID_CA_POLICY])?)?,
        raw_extension_der("2.5.29.31", false, &[0x30, 0x00])?,
    ];
    local_certificate(LOCAL_PLATFORM_CN, LOCAL_ROOT_CN, root_key, &subject_spki_der, &extensions, now_unix_seconds)
}

fn leaf_certificate(key: &p256::SecretKey, platform_key: &p256::SecretKey, now_unix_seconds: u64) -> Result<Vec<u8>, TzapLocalServiceError> {
    let subject_spki_der = key_spki_der(key)?;
    let platform_spki_der = key_spki_der(platform_key)?;
    let eku_oid = der_oid(trust::TZAP_OID_DOCUMENT_SIGNING_EKU)?;
    let extensions = vec![
        basic_constraints_extension(false, None),
        leaf_key_usage_extension(),
        raw_extension_der("2.5.29.37", false, &der_sequence(&eku_oid))?,
        aki_extension(&platform_spki_der)?,
        raw_extension_der("2.5.29.32", false, &certificate_policies_der(&[trust::TZAP_OID_LEAF_POLICY])?)?,
        raw_extension_der(trust::TZAP_OID_METADATA_EXTENSION, false, &metadata_extension_bytes()?)?,
    ];
    local_certificate(LOCAL_SIGNER_CN, LOCAL_PLATFORM_CN, platform_key, &subject_spki_der, &extensions, now_unix_seconds)
}

/// Assembles one local-chain certificate from raw extension DER elements.
fn local_certificate(
    subject_cn: &str,
    issuer_cn: &str,
    issuer_key: &p256::SecretKey,
    subject_spki_der: &[u8],
    extensions: &[Vec<u8>],
    now_unix_seconds: u64,
) -> Result<Vec<u8>, TzapLocalServiceError> {
    let issuer_der = x509_build::common_name_name(issuer_cn)
        .map_err(TzapLocalServiceError::Crypto)?
        .to_der()
        .map_err(|error| TzapLocalServiceError::Crypto(error.to_string()))?;
    let spec = RawCertificateSpec {
        subject_cn,
        issuer_der,
        subject_spki_der: subject_spki_der.to_vec(),
        serial: serial_number(now_unix_seconds),
        not_before_unix: not_before_unix(now_unix_seconds),
        not_after_unix: not_after_unix(now_unix_seconds),
        extensions: extensions.to_vec(),
    };
    x509_build::assemble_ecdsa_certificate_raw(&spec, issuer_key).map_err(TzapLocalServiceError::Crypto)
}

fn basic_constraints_extension(ca: bool, path_len: Option<u8>) -> Vec<u8> {
    // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
    let mut elements = Vec::new();
    elements.extend(der_wrap(0x01, &[if ca { 0xff } else { 0x00 }]));
    if let Some(path_len) = path_len {
        elements.extend(der_wrap(0x02, &[path_len]));
    }
    raw_extension_elements("2.5.29.19", true, &der_sequence(&elements))
}

fn ca_key_usage_extension() -> Vec<u8> {
    // KeyUsage ::= BIT STRING — keyCertSign(5) + cRLSign(6) => 0x06 with one unused trailing bit
    raw_extension_elements("2.5.29.15", true, &der_wrap(0x03, &[0x01, 0x06]))
}

fn leaf_key_usage_extension() -> Vec<u8> {
    // digitalSignature(0) => bit 0x80
    raw_extension_elements("2.5.29.15", true, &der_wrap(0x03, &[0x07, 0x80]))
}

fn ski_extension(spki_der: &[u8]) -> Result<Vec<u8>, TzapLocalServiceError> {
    let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::try_from(spki_der).map_err(|error| TzapLocalServiceError::Crypto(error.to_string()))?;
    let digest = Sha256::digest(spki.subject_public_key.raw_bytes());
    Ok(raw_extension_elements("2.5.29.14", false, &der_wrap(0x04, digest.as_slice())))
}

fn aki_extension(issuer_spki_der: &[u8]) -> Result<Vec<u8>, TzapLocalServiceError> {
    let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::try_from(issuer_spki_der).map_err(|error| TzapLocalServiceError::Crypto(error.to_string()))?;
    let digest = Sha256::digest(spki.subject_public_key.raw_bytes());
    // AuthorityKeyIdentifier ::= SEQUENCE { [0] IMPLICIT OCTET STRING }
    Ok(raw_extension_elements("2.5.29.35", false, &der_sequence(&der_wrap(0x80, digest.as_slice()))))
}

/// A complete DER extension SEQUENCE element.
fn raw_extension_elements(oid: &str, critical: bool, contents: &[u8]) -> Vec<u8> {
    x509_build::raw_extension_der(&der_oid(oid).expect("constant OID is valid"), critical, contents)
}

fn raw_extension_der(oid: &str, critical: bool, contents: &[u8]) -> Result<Vec<u8>, TzapLocalServiceError> {
    Ok(x509_build::raw_extension_der(&der_oid(oid)?, critical, contents))
}

fn p256_private_key() -> p256::SecretKey {
    p256::SecretKey::generate_from_rng(&mut zmanager_core::os_rng::OsRng)
}

fn serial_number(now_unix_seconds: u64) -> u64 {
    (now_unix_seconds % u64::from(u32::MAX - 1)) + 1
}

fn certificate_policies_der(policies: &[&str]) -> Result<Vec<u8>, TzapLocalServiceError> {
    let policy_infos =
        policies.iter().map(|policy| der_oid(policy).map(|oid| der_sequence(&oid))).collect::<Result<Vec<_>, _>>()?.into_iter().flatten().collect::<Vec<_>>();
    Ok(der_sequence(&policy_infos))
}

fn der_oid(oid: &str) -> Result<Vec<u8>, TzapLocalServiceError> {
    Ok(der_wrap(0x06, crate::x509_build::oid_der_bytes(oid).ok_or_else(|| TzapLocalServiceError::Crypto("invalid OID".to_owned()))?.as_slice()))
}

fn der_sequence(contents: &[u8]) -> Vec<u8> {
    der_wrap(0x30, contents)
}

fn der_wrap(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(contents.len()));
    out.extend(contents);
    out
}

#[allow(clippy::cast_possible_truncation)]
fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn metadata_extension_bytes() -> Result<Vec<u8>, TzapLocalServiceError> {
    crate::jcs::canonicalize_json_bytes(&json!({
        "version": 1,
        "public_signer_id": LOCAL_SIGNER_ID,
        "public_org_id": Value::Null,
        "public_device_id": LOCAL_DEVICE_ID,
        "assurance_level": "oauth_verified_email",
        "policy_oid": trust::TZAP_OID_LEAF_POLICY,
    }))
    .map_err(|error| TzapLocalServiceError::Crypto(format!("{error:?}")))
}

fn public_metadata() -> TzapCertificatePublicMetadata {
    TzapCertificatePublicMetadata {
        version: 1,
        public_signer_id: LOCAL_SIGNER_ID.to_owned(),
        public_org_id: None,
        public_device_id: LOCAL_DEVICE_ID.to_owned(),
        assurance_level: trust::TzapIdentityAssurance::OauthVerifiedEmail,
        policy_oid: trust::TZAP_OID_LEAF_POLICY.to_owned(),
    }
}

fn subject_key_identifier(certificate: &X509Certificate<'_>) -> Option<Vec<u8>> {
    certificate.iter_extensions().find_map(|extension| {
        if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension() { Some(identifier.0.to_vec()) } else { None }
    })
}

fn parse_certificate<'a>(der: &'a [u8], label: &'static str) -> Result<X509Certificate<'a>, TzapLocalServiceError> {
    let (remaining, certificate) = X509Certificate::from_der(der).map_err(|error| TzapLocalServiceError::Crypto(format!("{label}: {error}")))?;
    if remaining.is_empty() { Ok(certificate) } else { Err(TzapLocalServiceError::Crypto(format!("{label}: trailing DER bytes"))) }
}

// See `crate::trust::sha256_identifier` (CR-124).
fn local_certificate_id(prefix: &str, index: usize) -> String {
    format!("{prefix}{index}")
}

fn local_sign_device_id(public_key_fingerprint: &str) -> String {
    let suffix = public_key_fingerprint.strip_prefix("sha256:").unwrap_or(public_key_fingerprint).chars().take(16).collect::<String>();
    format!("{LOCAL_SIGN_DEVICE_ID_PREFIX}{suffix}")
}
