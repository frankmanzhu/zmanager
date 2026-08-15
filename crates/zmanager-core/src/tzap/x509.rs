//! TZAP X.509 `RootAuth` support: signer loading, recipient private-key
//! lookup, verification report mapping, public no-key verification, signer
//! inspection, and raw authenticator parsing.

use super::TzapError;
use crate::os_rng::OsRng;
use crate::p256_signature::parse_p256_private_key_der;
use crate::secrets::{SecretBytes, SecretString};
use crate::tzap::open::{open_tzap_archive, open_tzap_archive_with_recipient_key, read_tzap_input_volume_bytes};
use crate::tzap::write::TzapCreateOptions;
use crate::x509_format::x509_name_to_string;
use base64::Engine as _;
use ecdsa::elliptic_curve::Generate as _;
use ecdsa::signature::SignatureEncoding as _;
use ecdsa::signature::hazmat::RandomizedPrehashSigner;
use openssl::pkcs12::Pkcs12;
use p256::ecdsa::SigningKey;
use pkcs8::EncodePublicKey;
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tzap_core::WriterOptions;
use tzap_core::format::{FORMAT_VERSION, FormatError, VOLUME_FORMAT_REV};
use tzap_core::reader::{PublicNoKeyDiagnostic, RecipientWrapRecordContext, RootAuthDiagnostic};
use tzap_core::wire::RecipientRecordV1;
use tzap_core::wire::RootAuthFooterV1;
use tzap_core::{MasterKey, OpenedArchive, TarEntryKind, public_no_key_verify_volumes_with};
use tzap_plugin_keywrap::{
    ArchiveIdentity as KeyWrapArchiveIdentity, KeyWrapOutcome, KeyWrapSuite, PrivateKeyLookup, RecipientRecordInput, RecipientRecordMetadata,
    dispatch_key_wrap_record, wrap_master_key_for_recipient,
};
use tzap_plugin_signing::x509_chain::{
    X509_AUTHENTICATOR_ID, X509RootAuthReport, X509RootAuthSigner, X509SigningKey, certificate_der_from_pem_or_der, certificates_der_from_pem_or_der,
    verify_root_auth_footer, verify_root_auth_signature,
};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::certificate::Version;
use x509_cert::der::DateTime as DerDateTime;
use x509_cert::der::Encode as _;
use x509_cert::der::asn1::{BitString, ObjectIdentifier, OctetString, UtcTime, Utf8StringRef};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier};
use x509_cert::name::{Name, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate};
use x509_parser::prelude::FromDer as _;

// The official root literals live in `trust::` (pinned there too), so the
// pin set and the embedded certificates cannot drift.
const OID_COMMON_NAME: &str = "2.5.4.3";
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const SYNTHETIC_RECIPIENT_CN: &str = "ZManager Contact Recipient";

const OFFICIAL_TZAP_ROOT_CERT_SHA256: &str = crate::trust::TZAP_PRODUCTION_ROOT_SHA256;
const OFFICIAL_TZAP_ROOT_CERT_PEM: &[u8] = include_bytes!("../trust/tzap-production-root-ca-2026.pem");
const OFFICIAL_TZAP_STAGING_ROOT_PEM: &[u8] = include_bytes!("../trust/tzap-staging-root-ca-2026.pem");

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapX509SigningOptions {
    /// PKCS#12 signing identity containing the leaf certificate, private key,
    /// and optional intermediate certificates.
    Pkcs12 {
        /// PKCS#12 identity file path.
        identity: PathBuf,
        /// PKCS#12 import password.
        password: SecretString,
    },
    /// Advanced PEM/DER signing inputs.
    CertificateAndKey {
        /// PEM or DER leaf signing certificate. PEM bundles may include
        /// intermediate certificates after the leaf certificate.
        signing_certificate: PathBuf,
        /// PEM or DER private key matching the leaf signing certificate.
        signing_private_key: PathBuf,
        /// Optional PEM or DER intermediate certificates.
        signing_chain: Vec<PathBuf>,
    },
    /// Validated in-memory signing material resolved from a secure store.
    InMemory {
        /// Leaf signing certificate in PEM or DER form.
        signing_certificate: Vec<u8>,
        /// Matching private key. This value is redacted and zeroized on drop.
        signing_private_key: SecretBytes,
        /// Optional intermediate certificates in PEM or DER form.
        signing_chain: Vec<Vec<u8>>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TzapX509TrustOptions {
    /// PEM or DER trusted CA certificates.
    pub trusted_ca_certificates: Vec<PathBuf>,
    /// Allow OpenSSL's default system trust roots.
    pub trusted_system_roots: bool,
    /// Include `ZManager`'s embedded official TZAP root certificate.
    pub include_official_tzap_root: bool,
}

impl TzapX509TrustOptions {
    /// Returns whether verification has any trust source to use.
    #[must_use]
    pub fn has_trust_source(&self) -> bool {
        self.include_official_tzap_root || !self.trusted_ca_certificates.is_empty() || self.trusted_system_roots
    }
}

/// Resolves the in-memory X.509 signing material for a locally enrolled
/// certificate (CR-113: moved from the CLI so the tzap JSON service's share
/// endpoint uses the same battle-tested resolution rules).
pub fn tzap_x509_signing_options_from_inventory(
    store: &impl crate::local_identity_store::TzapLocalIdentityStore,
    account_key: &str,
    certificate_id: &str,
    now_unix_seconds: u64,
) -> Result<TzapX509SigningOptions, String> {
    use crate::local_identity_store::TzapLocalCertificateState;
    use crate::trust::TzapCertificateStatus;

    let inventory = store.load_inventory(account_key).map_err(|error| error.to_string())?;
    let certificate = inventory
        .enrolled_certificates
        .iter()
        .find(|record| record.certificate_id == certificate_id)
        .ok_or_else(|| format!("certificate not found: {certificate_id}"))?;
    if certificate.state != TzapLocalCertificateState::Active {
        return Err(format!("certificate is not active: {}", certificate.state.as_str()));
    }
    if now_unix_seconds < certificate.not_before_unix_seconds {
        return Err("certificate is not yet valid".to_owned());
    }
    if now_unix_seconds >= certificate.not_after_unix_seconds {
        return Err("certificate is expired".to_owned());
    }
    if inventory.emergency_blocklist.blocked_issuer_sha256.contains(&certificate.issuer_certificate_sha256) {
        return Err("certificate issuer is locally blocked".to_owned());
    }
    if inventory
        .certificate_status_cache
        .iter()
        .any(|status| status.certificate_sha256 == certificate.certificate_sha256 && status.status != TzapCertificateStatus::Valid)
    {
        return Err("certificate status blocks signing".to_owned());
    }
    let signing_key = inventory
        .device_signing_keys
        .iter()
        .find(|key| key.key_id == certificate.signing_key_id)
        .ok_or_else(|| "certificate signing key is missing".to_owned())?;
    Ok(TzapX509SigningOptions::InMemory {
        signing_certificate: certificate.leaf_certificate_der.clone(),
        signing_private_key: signing_key.private_key_der.clone(),
        signing_chain: certificate.intermediate_chain_der.clone(),
    })
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapX509VerificationReport {
    /// Verified archive root commitment.
    pub archive_root: [u8; 32],
    /// `RootAuth` authenticator identifier.
    pub authenticator_id: u16,
    /// `RootAuth` signer identity type.
    pub signer_identity_type: u16,
    /// Number of data blocks covered by the `RootAuth` footer.
    pub total_data_block_count: u64,
    /// Signer-claimed signing time as Unix seconds.
    pub signed_at_unix_seconds: i64,
    /// Leaf certificate subject.
    pub subject: String,
    /// Leaf certificate issuer.
    pub issuer: String,
    /// Leaf certificate serial number.
    pub serial_number_hex: String,
    /// SHA-256 fingerprint of the leaf certificate.
    pub certificate_sha256: [u8; 32],
    /// Subjects in the verified chain.
    pub verified_chain_subjects: Vec<String>,
    /// Trust anchor subject, when OpenSSL reported one.
    pub trust_anchor_subject: Option<String>,
    /// Root-auth verification diagnostics reported by `tzap`.
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapX509SignerInspection {
    /// Verified archive root commitment.
    pub archive_root: [u8; 32],
    /// `RootAuth` authenticator identifier.
    pub authenticator_id: u16,
    /// `RootAuth` signer identity type.
    pub signer_identity_type: u16,
    /// Number of data blocks covered by the `RootAuth` footer.
    pub total_data_block_count: u64,
    /// Signer-claimed signing time as Unix seconds.
    pub signed_at_unix_seconds: i64,
    /// Leaf certificate subject.
    pub subject: String,
    /// Leaf certificate issuer.
    pub issuer: String,
    /// Leaf certificate serial number.
    pub serial_number_hex: String,
    /// SHA-256 fingerprint of the leaf certificate.
    pub certificate_sha256: [u8; 32],
    /// Root-auth inspection diagnostics reported by `tzap`.
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapTestReport {
    /// Number of entries in the archive.
    pub entries: usize,
    /// Number of entries selected by the filter.
    pub tested_entries: usize,
    /// Number of entries skipped by the filter.
    pub skipped_entries: usize,
    /// Total selected regular-file bytes.
    pub tested_bytes: u64,
    /// Verified X.509 `RootAuth` details when trust options were supplied.
    pub x509_root_auth: Option<TzapX509VerificationReport>,
}

pub(crate) fn load_x509_signer(options: &TzapX509SigningOptions) -> Result<X509RootAuthSigner, TzapError> {
    match options {
        TzapX509SigningOptions::Pkcs12 { identity, password } => load_x509_signer_from_pkcs12(identity, password),
        TzapX509SigningOptions::CertificateAndKey { signing_certificate, signing_private_key, signing_chain } => {
            load_x509_signer_from_certificate_files(signing_certificate, signing_private_key, signing_chain)
        }
        TzapX509SigningOptions::InMemory { signing_certificate, signing_private_key, signing_chain } => {
            X509RootAuthSigner::from_pem_or_der(signing_certificate, signing_private_key.expose_secret(), signing_chain.clone(), current_unix_seconds_i64()?)
                .map_err(|source| TzapError::X509RootAuth(source.to_string()))
        }
    }
}

fn load_x509_signer_from_certificate_files(
    signing_certificate: &Path,
    signing_private_key: &Path,
    signing_chain: &[PathBuf],
) -> Result<X509RootAuthSigner, TzapError> {
    let certificate = read_x509_input_file(signing_certificate)?;
    let mut certificate_der = certificates_der_from_pem_or_der(&certificate).map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let leaf_certificate_der = certificate_der.remove(0);
    let private_key = read_x509_input_file(signing_private_key)?;
    let mut chain_der = certificate_der;
    chain_der.extend(load_x509_certificate_files(signing_chain)?);
    X509RootAuthSigner::from_pem_or_der(&leaf_certificate_der, &private_key, chain_der, current_unix_seconds_i64()?)
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))
}

/// PKCS#12 identity import — the one allow-listed OpenSSL surface left in
/// this module. The RustCrypto `pkcs12` crate is a pre-release container
/// skeleton with no PBE decryption yet, so PKCS#12 parsing stays on vendored
/// OpenSSL per the §6 gap decision recorded in
/// `implementation-docs/adr/2026-08-15-chain-verification-backend.md`
/// (and the plan's "PKCS12 leniency" note). Everything else in this file is
/// RustCrypto.
fn load_x509_signer_from_pkcs12(identity: &Path, password: &SecretString) -> Result<X509RootAuthSigner, TzapError> {
    let identity_bytes = read_x509_input_file(identity)?;
    let pkcs12 = Pkcs12::from_der(&identity_bytes).map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let parsed = pkcs12.parse2(password.expose_secret()).map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let certificate = parsed.cert.ok_or_else(|| TzapError::X509RootAuth("PKCS#12 identity has no certificate".to_owned()))?;
    let private_key = parsed.pkey.ok_or_else(|| TzapError::X509RootAuth("PKCS#12 identity has no private key".to_owned()))?;
    let chain_der = parsed
        .ca
        .map(|chain| {
            chain.iter().map(|certificate| certificate.to_der().map_err(|source| TzapError::X509RootAuth(source.to_string()))).collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    let signing_key = X509SigningKey::from_der(&private_key.private_key_to_der().map_err(|source| TzapError::X509RootAuth(source.to_string()))?)
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    X509RootAuthSigner::new(
        certificate.to_der().map_err(|source| TzapError::X509RootAuth(source.to_string()))?,
        signing_key,
        chain_der,
        current_unix_seconds_i64()?,
    )
    .map_err(|source| TzapError::X509RootAuth(source.to_string()))
}

pub(crate) fn load_x509_certificate_files(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>, TzapError> {
    let mut certificates = Vec::new();
    for path in paths {
        let bytes = read_x509_input_file(path)?;
        let mut parsed = certificates_der_from_pem_or_der(&bytes).map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
        certificates.append(&mut parsed);
    }
    Ok(certificates)
}

fn read_x509_input_file(path: &Path) -> Result<Vec<u8>, TzapError> {
    fs::read(path).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })
}

pub(crate) fn load_x509_trusted_roots(trust: &TzapX509TrustOptions) -> Result<Vec<Vec<u8>>, TzapError> {
    let mut certificates = Vec::new();
    if trust.include_official_tzap_root {
        certificates.push(
            certificate_der_from_pem_or_der(OFFICIAL_TZAP_ROOT_CERT_PEM).map_err(|source| {
                TzapError::X509RootAuth(format!("failed to parse embedded TZAP root certificate {OFFICIAL_TZAP_ROOT_CERT_SHA256}: {source}"))
            })?,
        );
        // Staging is trusted by default alongside production (see
        // `trust::OFFICIAL_TZAP_ROOT_PINS`).
        certificates.push(certificate_der_from_pem_or_der(OFFICIAL_TZAP_STAGING_ROOT_PEM).map_err(|source| {
            TzapError::X509RootAuth(format!("failed to parse embedded TZAP staging root certificate {}: {source}", crate::trust::TZAP_STAGING_ROOT_SHA256))
        })?);
    }
    certificates.extend(load_x509_certificate_files(&trust.trusted_ca_certificates)?);
    Ok(certificates)
}

pub(crate) fn validate_recipient_wrap_create_options(options: &TzapCreateOptions) -> Result<(), TzapError> {
    if options.volume_size.is_some() || options.volume_loss_tolerance != 0 {
        return Err(TzapError::Format(FormatError::WriterUnsupported(
            "recipient certificate encryption is currently supported only for single-volume TZAP create",
        )));
    }
    Ok(())
}

pub(crate) fn build_recipient_wrap_record_from_certificate_path(
    recipient_certificate_path: &Path,
    master_key: &MasterKey,
    options: &mut WriterOptions,
) -> Result<RecipientRecordV1, TzapError> {
    let recipient_certificate = load_single_x509_certificate_file("recipient certificate", recipient_certificate_path)?;
    let archive_identity = recipient_wrap_archive_identity_for_writer(options);
    build_recipient_wrap_record_from_certificate_der(&recipient_certificate, master_key, &archive_identity)
}

pub(crate) fn build_recipient_wrap_record_from_certificate_der(
    recipient_certificate: &[u8],
    master_key: &MasterKey,
    archive_identity: &KeyWrapArchiveIdentity,
) -> Result<RecipientRecordV1, TzapError> {
    let master_key_bytes = master_key.0;
    for suite in [KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305, KeyWrapSuite::P256HkdfSha256Aes256Gcm] {
        match wrap_master_key_for_recipient(archive_identity.clone(), recipient_certificate, &master_key_bytes, suite) {
            Ok(record) => return Ok(record),
            Err(KeyWrapOutcome::InvalidRecord | KeyWrapOutcome::UnsupportedSuite) => {}
            Err(outcome) => return Err(key_wrap_outcome_error(&outcome)),
        }
    }
    Err(TzapError::Format(FormatError::WriterUnsupported("recipient certificate is not supported by keywrap-v1 suites")))
}

/// Wraps a raw recipient SPKI in a throwaway self-signed certificate so the
/// keywrap plugin's cert-only API can consume it.
///
/// The recipient identity recorded in the archive is therefore this synthetic
/// certificate, not the recipient's real one. See the design note
/// `adr/2026-08-06-synthetic-recipient-certificate.md` in the private
/// implementation-docs repo; revisit when the plugin accepts raw SPKI.
pub(crate) fn synthetic_recipient_certificate_der(public_key_spki_der: &[u8]) -> Result<Vec<u8>, TzapError> {
    let wrap = |detail: String| TzapError::KeyWrap(format!("recipient certificate failed: {detail}"));
    let subject_public_key_info =
        SubjectPublicKeyInfoOwned::try_from(public_key_spki_der).map_err(|source| wrap(format!("recipient public key is invalid: {source}")))?;

    // Throwaway P-256 issuer key: the certificate is self-issued but not
    // self-signed with the recipient's (unknown) private key.
    let issuer_key = p256::SecretKey::generate_from_rng(&mut OsRng);

    let subject = synthetic_recipient_name().map_err(|source| wrap(format!("recipient certificate name failed: {source}")))?;
    let not_before = utc_time_from_now(0).map_err(|source| wrap(format!("recipient certificate time failed: {source}")))?;
    let not_after = utc_time_from_now(365).map_err(|source| wrap(format!("recipient certificate time failed: {source}")))?;

    let basic_constraints = Extension {
        extn_id: ObjectIdentifier::new_unwrap("2.5.29.19"),
        critical: true,
        extn_value: OctetString::new(BasicConstraints { ca: false, path_len_constraint: None }.to_der().map_err(|source| wrap(source.to_string()))?)
            .map_err(|source| wrap(source.to_string()))?,
    };
    let key_usage = Extension {
        extn_id: ObjectIdentifier::new_unwrap("2.5.29.15"),
        critical: true,
        extn_value: OctetString::new(KeyUsage(KeyUsages::KeyAgreement.into()).to_der().map_err(|source| wrap(source.to_string()))?)
            .map_err(|source| wrap(source.to_string()))?,
    };
    // OpenSSL's default SKI derivation is SHA-1 over the public-key BIT STRING;
    // SHA-256 over the same content is used here (the identifier is not
    // referenced by anything in the keywrap protocol).
    let ski_bytes = Sha256::digest(subject_public_key_info.subject_public_key.raw_bytes());
    let subject_key_identifier = Extension {
        extn_id: ObjectIdentifier::new_unwrap("2.5.29.14"),
        critical: false,
        extn_value: OctetString::new(
            SubjectKeyIdentifier(OctetString::new(ski_bytes.as_slice()).map_err(|source| wrap(source.to_string()))?)
                .to_der()
                .map_err(|source| wrap(source.to_string()))?,
        )
        .map_err(|source| wrap(source.to_string()))?,
    };

    let signature_algorithm = AlgorithmIdentifierOwned { oid: ObjectIdentifier::new_unwrap(OID_ECDSA_WITH_SHA256), parameters: None };
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::from(1u64),
        signature: signature_algorithm.clone(),
        issuer: subject.clone(),
        validity: Validity { not_before: Time::UtcTime(not_before), not_after: Time::UtcTime(not_after) },
        subject,
        subject_public_key_info,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![basic_constraints, key_usage, subject_key_identifier]),
    };
    let tbs_der = tbs.to_der().map_err(|source| wrap(format!("recipient certificate DER failed: {source}")))?;
    let signing_key = SigningKey::from(issuer_key);
    let fixed: ecdsa::Signature<p256::NistP256> = signing_key
        .sign_prehash_with_rng(&mut OsRng, &Sha256::digest(&tbs_der))
        .map_err(|source| wrap(format!("recipient certificate signing failed: {source}")))?;
    let signature = ecdsa::der::Signature::<p256::NistP256>::from(fixed.normalize_s());
    let certificate = Certificate {
        tbs_certificate: tbs,
        signature_algorithm,
        signature: BitString::from_bytes(&signature.to_vec()).map_err(|source| wrap(format!("recipient certificate DER failed: {source}")))?,
    };
    certificate.to_der().map_err(|source| wrap(format!("recipient certificate DER failed: {source}")))
}

fn synthetic_recipient_name() -> Result<Name, String> {
    let mut rdn = RelativeDistinguishedName::default();
    rdn.0
        .insert(AttributeTypeAndValue {
            oid: ObjectIdentifier::new_unwrap(OID_COMMON_NAME),
            value: x509_cert::der::asn1::Any::encode_from(&Utf8StringRef::new(SYNTHETIC_RECIPIENT_CN).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?,
        })
        .map_err(|error| error.to_string())?;
    let mut name = Name::default();
    name.0.push(rdn);
    Ok(name)
}

fn utc_time_from_now(days: i64) -> Result<UtcTime, String> {
    let time = time::OffsetDateTime::now_utc() + time::Duration::days(days);
    let datetime = DerDateTime::new(
        u16::try_from(time.year()).map_err(|_| "certificate year out of range".to_owned())?,
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
    )
    .map_err(|error| error.to_string())?;
    UtcTime::from_date_time(datetime).map_err(|error| error.to_string())
}

pub(crate) fn load_single_x509_certificate_file(label: &'static str, path: &Path) -> Result<Vec<u8>, TzapError> {
    let bytes = read_x509_input_file(path)?;
    let certificates =
        certificates_der_from_pem_or_der(&bytes).map_err(|source| TzapError::KeyWrap(format!("failed to parse {label} {}: {source}", path.display())))?;
    match certificates.as_slice() {
        [certificate] => Ok(certificate.clone()),
        [] | [_, _, ..] => Err(TzapError::KeyWrap(format!("{label} must contain exactly one X.509 certificate"))),
    }
}

pub(crate) fn recipient_wrap_archive_identity_for_writer(options: &mut WriterOptions) -> KeyWrapArchiveIdentity {
    let archive_uuid = *options.archive_uuid.get_or_insert_with(random_16_bytes);
    let session_id = *options.session_id.get_or_insert_with(random_16_bytes);
    KeyWrapArchiveIdentity { archive_uuid, session_id, format_version: FORMAT_VERSION, volume_format_rev: VOLUME_FORMAT_REV }
}

fn random_16_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

fn key_wrap_outcome_error(outcome: &KeyWrapOutcome) -> TzapError {
    match outcome {
        KeyWrapOutcome::UnsupportedProfileId => TzapError::Format(FormatError::ReaderUnsupported("unsupported keywrap recipient profile")),
        KeyWrapOutcome::UnsupportedArchiveIdentity => TzapError::Format(FormatError::ReaderUnsupported("unsupported keywrap archive identity")),
        KeyWrapOutcome::UnsupportedRecipientIdentity => TzapError::Format(FormatError::ReaderUnsupported("unsupported keywrap recipient identity")),
        KeyWrapOutcome::UnsupportedSuite => TzapError::Format(FormatError::ReaderUnsupported("unsupported keywrap recipient suite")),
        KeyWrapOutcome::CertificatePolicyRejected => TzapError::Format(FormatError::ReaderUnsupported("recipient certificate policy rejected")),
        KeyWrapOutcome::InvalidRecord => TzapError::Format(FormatError::InvalidArchive("invalid keywrap recipient record")),
        KeyWrapOutcome::NoMatchingPrivateKey => TzapError::KeyWrap("no matching recipient private key for archive".to_owned()),
        KeyWrapOutcome::UnwrappedCandidateMasterKey { .. } => {
            TzapError::Format(FormatError::WriterInvariant("keywrap success outcome cannot be converted to error"))
        }
    }
}

#[derive(Debug)]
pub(crate) struct TzapRecipientPrivateKeyLookup {
    private_key_bytes: Vec<u8>,
    private_key_spki_der: Option<Vec<u8>>,
}

impl PrivateKeyLookup for TzapRecipientPrivateKeyLookup {
    fn lookup_private_key(
        &self,
        _archive_identity: &KeyWrapArchiveIdentity,
        _metadata: &RecipientRecordMetadata,
        recipient_identity_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        if let Some(private_key_spki_der) = self.private_key_spki_der.as_ref() {
            let (remaining, certificate) = x509_parser::parse_x509_certificate(recipient_identity_bytes).ok()?;
            if !remaining.is_empty() {
                return None;
            }
            let certificate_spki_der = certificate.tbs_certificate.subject_pki.raw;
            if certificate_spki_der != *private_key_spki_der {
                return None;
            }
        }
        Some(self.private_key_bytes.clone())
    }
}

pub(crate) fn load_recipient_private_key_lookup(path: &Path) -> Result<TzapRecipientPrivateKeyLookup, TzapError> {
    let bytes = fs::read(path).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })?;
    load_recipient_private_key_lookup_from_bytes(&bytes, &path.display().to_string())
}

pub(crate) fn load_recipient_private_key_lookup_from_bytes(bytes: &[u8], description: &str) -> Result<TzapRecipientPrivateKeyLookup, TzapError> {
    if bytes.len() == 32 {
        return Ok(TzapRecipientPrivateKeyLookup { private_key_bytes: bytes.to_vec(), private_key_spki_der: None });
    }
    let key_der = if bytes.starts_with(b"-----BEGIN") {
        pem_payload_der(bytes).ok_or_else(|| TzapError::KeyWrap(format!("failed to parse recipient private key {description}: invalid PEM")))?
    } else {
        bytes.to_vec()
    };
    match parse_p256_private_key_der(&key_der) {
        Ok(private_key) => {
            let private_key_bytes = private_key
                .to_sec1_der()
                .map_err(|source| TzapError::KeyWrap(format!("failed to normalize recipient private key {description}: {source}")))?
                .to_vec();
            let private_key_spki_der = private_key.public_key().to_public_key_der().ok().map(|document| document.as_bytes().to_vec());
            Ok(TzapRecipientPrivateKeyLookup { private_key_bytes, private_key_spki_der })
        }
        Err(_) => {
            // Non-P-256 keys (e.g. X25519 PKCS#8) pass through raw: the keywrap
            // plugin parses them itself; SPKI pre-matching is disabled for these.
            Ok(TzapRecipientPrivateKeyLookup { private_key_bytes: key_der, private_key_spki_der: None })
        }
    }
}

/// Decodes the first PEM block of the input to its DER payload.
fn pem_payload_der(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut rest = bytes;
    while let Some(start) = rest.windows(b"-----BEGIN".len()).position(|window| window == b"-----BEGIN") {
        let block = &rest[start..];
        let end = block.windows(b"-----END".len()).position(|window| window == b"-----END")?;
        let body_start = block[..end].iter().position(|byte| *byte == b'\n').map_or(0, |position| position + 1);
        let body = &block[body_start..end];
        let encoded: Vec<u8> = body.iter().copied().filter(|byte| !byte.is_ascii_whitespace()).collect();
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&encoded) {
            return Some(decoded);
        }
        rest = &block[end + b"-----END".len()..];
    }
    None
}

#[derive(Debug, Default)]
pub(crate) struct RecipientWrapOpenStats {
    records_seen: usize,
    no_matching_private_key: usize,
    invalid_record_or_unwrap: usize,
    unsupported_record: usize,
    candidate_count: usize,
}

pub(crate) fn recipient_wrap_candidates_for_record(
    context: &RecipientWrapRecordContext<'_>,
    lookup: &TzapRecipientPrivateKeyLookup,
    stats: &mut RecipientWrapOpenStats,
) -> Vec<[u8; 32]> {
    stats.records_seen += 1;
    let input = RecipientRecordInput {
        archive_identity: KeyWrapArchiveIdentity {
            archive_uuid: context.archive_identity.archive_uuid,
            session_id: context.archive_identity.session_id,
            format_version: context.archive_identity.format_version,
            volume_format_rev: context.archive_identity.volume_format_rev,
        },
        metadata: RecipientRecordMetadata {
            profile_id: context.record.profile_id,
            recipient_identity_type: context.record.recipient_identity_type,
            recipient_identity_digest: context.record.recipient_identity_digest,
        },
        recipient_identity_bytes: context.record.recipient_identity_bytes.clone(),
        profile_payload_bytes: context.record.profile_payload_bytes.clone(),
    };
    match dispatch_key_wrap_record(input, lookup) {
        KeyWrapOutcome::UnwrappedCandidateMasterKey { master_key, .. } => {
            stats.candidate_count += 1;
            vec![master_key]
        }
        KeyWrapOutcome::NoMatchingPrivateKey => {
            stats.no_matching_private_key += 1;
            Vec::new()
        }
        KeyWrapOutcome::InvalidRecord | KeyWrapOutcome::CertificatePolicyRejected => {
            stats.invalid_record_or_unwrap += 1;
            Vec::new()
        }
        KeyWrapOutcome::UnsupportedProfileId
        | KeyWrapOutcome::UnsupportedArchiveIdentity
        | KeyWrapOutcome::UnsupportedRecipientIdentity
        | KeyWrapOutcome::UnsupportedSuite => {
            stats.unsupported_record += 1;
            Vec::new()
        }
    }
}

pub(crate) fn recipient_wrap_open_error(source: FormatError, stats: &RecipientWrapOpenStats) -> TzapError {
    if !matches!(source, FormatError::KeyMaterialMismatch) {
        return TzapError::Format(source);
    }
    if stats.candidate_count > 0 {
        return TzapError::KeyWrap(format!("{source}: recipient private key unwrapped a candidate, but archive header HMAC did not verify"));
    }
    if stats.records_seen == 0 {
        return TzapError::KeyWrap(format!("{source}: recipient-wrap archive has no recipient records"));
    }
    if stats.no_matching_private_key > 0 && stats.invalid_record_or_unwrap == 0 {
        return TzapError::KeyWrap(format!("{source}: no matching recipient private key for archive"));
    }
    TzapError::KeyWrap(format!("{source}: recipient private key did not match any recipient record or failed recipient unwrap"))
}

fn current_unix_seconds_i64() -> Result<i64, TzapError> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|source| TzapError::X509RootAuth(source.to_string()))?.as_secs();
    i64::try_from(seconds).map_err(|_| TzapError::X509RootAuth("current Unix time exceeds i64".to_owned()))
}

fn verify_opened_x509_root_auth(opened: &OpenedArchive, trust: &TzapX509TrustOptions) -> Result<TzapX509VerificationReport, TzapError> {
    let trusted_roots_der = load_x509_trusted_roots(trust)?;
    let mut report = None;
    let mut x509_error = None;
    let verification = opened
        .verify_root_auth_with(|footer, archive_root| {
            match verify_root_auth_footer(footer, archive_root, &trusted_roots_der, trust.trusted_system_roots, trust.include_official_tzap_root) {
                Ok(value) => {
                    report = Some(value);
                    Ok(true)
                }
                Err(error) => {
                    x509_error = Some(error.to_string());
                    Ok(false)
                }
            }
        })
        .map_err(|source| if let Some(detail) = x509_error { TzapError::X509RootAuth(format!("{source}: {detail}")) } else { TzapError::Format(source) })?;
    let report = report.ok_or(TzapError::Format(FormatError::InvalidArchive("missing X.509 RootAuth verification report")))?;

    Ok(x509_report_from_verification(
        verification.archive_root,
        verification.authenticator_id,
        verification.signer_identity_type,
        verification.total_data_block_count,
        report,
        &verification.diagnostics,
        root_auth_diagnostic_labels,
    ))
}

/// Maps a successful X.509 `RootAuth` verification and its tzap-plugin report
/// into the public [`TzapX509VerificationReport`], rendering diagnostics with
/// the verification flavor's label function.
fn x509_report_from_verification<Diagnostics>(
    archive_root: [u8; 32],
    authenticator_id: u16,
    signer_identity_type: u16,
    total_data_block_count: u64,
    report: X509RootAuthReport,
    diagnostics: &[Diagnostics],
    diagnostics_labels: fn(&[Diagnostics]) -> Vec<String>,
) -> TzapX509VerificationReport {
    TzapX509VerificationReport {
        archive_root,
        authenticator_id,
        signer_identity_type,
        total_data_block_count,
        signed_at_unix_seconds: report.signed_at_unix_seconds,
        subject: report.subject,
        issuer: report.issuer,
        serial_number_hex: report.serial_number_hex,
        certificate_sha256: report.certificate_sha256,
        verified_chain_subjects: report.verified_chain_subjects,
        trust_anchor_subject: report.trust_anchor_subject,
        diagnostics: diagnostics_labels(diagnostics),
    }
}

fn root_auth_diagnostic_labels(diagnostics: &[RootAuthDiagnostic]) -> Vec<String> {
    diagnostics.iter().map(|diagnostic| diagnostic.label().to_owned()).collect()
}

fn public_no_key_diagnostic_labels(diagnostics: &[PublicNoKeyDiagnostic]) -> Vec<String> {
    diagnostics.iter().map(|diagnostic| diagnostic.label().to_owned()).collect()
}

/// Tests `.tzap` archive readability and integrity with a filter.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or verified.
pub fn test_tzap_with_password_filter(archive: impl AsRef<Path>, password: &str, selector: impl Fn(&str) -> bool) -> Result<TzapTestReport, TzapError> {
    test_tzap_with_optional_password_filter_and_x509_trust(archive, Some(password), selector, None)
}

/// Tests `.tzap` archive readability and integrity with optional X.509 `RootAuth` verification.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, verified, or when
/// requested X.509 `RootAuth` verification fails.
pub fn test_tzap_with_password_filter_and_x509_trust(
    archive: impl AsRef<Path>,
    password: &str,
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    test_tzap_with_optional_password_filter_and_x509_trust(archive, Some(password), selector, x509_trust)
}

/// Tests `.tzap` archive readability and integrity with an optional passphrase.
///
/// When `password` is [`None`], unencrypted archives are opened without a key,
/// and legacy no-secret raw-key archives are opened with tzap's all-zero key.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, verified, or when
/// requested X.509 `RootAuth` verification fails.
pub fn test_tzap_with_optional_password_filter_and_x509_trust(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    test_opened_tzap_archive(&opened, selector, x509_trust)
}

/// Tests recipient-wrapped `.tzap` readability and integrity with a private key.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, verified, or when
/// requested X.509 `RootAuth` verification fails.
pub fn test_tzap_with_recipient_key_filter_and_x509_trust(
    archive: impl AsRef<Path>,
    recipient_private_key: impl AsRef<Path>,
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    let opened = open_tzap_archive_with_recipient_key(archive, recipient_private_key)?;
    test_opened_tzap_archive(&opened, selector, x509_trust)
}

fn test_opened_tzap_archive(
    opened: &OpenedArchive,
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    opened.verify()?;
    let x509_root_auth = match x509_trust.filter(|trust| trust.has_trust_source()) {
        Some(trust) if should_verify_opened_x509_root_auth(opened, trust) => Some(verify_opened_x509_root_auth(opened, trust)?),
        _ => None,
    };
    let entries = opened.list_files()?;
    let mut tested_entries = 0usize;
    let mut tested_bytes = 0u64;
    for entry in &entries {
        if selector(&entry.path) {
            tested_entries += 1;
            if entry.kind == TarEntryKind::Regular {
                tested_bytes = tested_bytes.saturating_add(entry.file_data_size);
            }
        }
    }
    Ok(TzapTestReport { entries: entries.len(), tested_entries, skipped_entries: entries.len().saturating_sub(tested_entries), tested_bytes, x509_root_auth })
}

fn should_verify_opened_x509_root_auth(opened: &OpenedArchive, trust: &TzapX509TrustOptions) -> bool {
    let explicit_trust = !trust.trusted_ca_certificates.is_empty() || trust.trusted_system_roots;
    let has_x509_root_auth = opened.root_auth_footer.as_ref().is_some_and(|footer| footer.authenticator_id == X509_AUTHENTICATOR_ID);
    explicit_trust || has_x509_root_auth
}

/// Verifies a TZAP X.509 `RootAuth` without the archive key.
///
/// This checks the public data-block commitment and X.509 authenticator, but it
/// does not decrypt entries or prove that recovery/parity material is complete.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive volumes cannot be read, the public
/// commitment does not verify, or X.509 trust validation fails.
pub fn verify_tzap_x509_public_no_key(archive: impl AsRef<Path>, trust: &TzapX509TrustOptions) -> Result<TzapX509VerificationReport, TzapError> {
    if !trust.has_trust_source() {
        return Err(TzapError::X509RootAuth("X.509 verification requires trusted roots".to_owned()));
    }

    let archive_path = archive.as_ref();
    let volume_bytes = read_tzap_input_volume_bytes(archive_path)?;
    let volume_refs = volume_bytes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let trusted_roots_der = load_x509_trusted_roots(trust)?;
    let mut report = None;
    let mut x509_error = None;
    let verification = public_no_key_verify_volumes_with(&volume_refs, |footer, archive_root| {
        if footer.authenticator_id != X509_AUTHENTICATOR_ID {
            return Err(FormatError::ReaderUnsupported("X.509 trust can only verify X.509 RootAuth"));
        }
        match verify_root_auth_footer(footer, archive_root, &trusted_roots_der, trust.trusted_system_roots, trust.include_official_tzap_root) {
            Ok(value) => {
                report = Some(value);
                Ok(true)
            }
            Err(error) => {
                x509_error = Some(error.to_string());
                Ok(false)
            }
        }
    })
    .map_err(|source| if let Some(detail) = x509_error { TzapError::X509RootAuth(format!("{source}: {detail}")) } else { TzapError::Format(source) })?;
    let report = report.ok_or(TzapError::Format(FormatError::InvalidArchive("missing X.509 public no-key verification report")))?;

    Ok(x509_report_from_verification(
        verification.archive_root,
        verification.authenticator_id,
        verification.signer_identity_type,
        verification.total_data_block_count,
        report,
        &verification.diagnostics,
        public_no_key_diagnostic_labels,
    ))
}

/// Inspects a TZAP X.509 `RootAuth` signer without validating trust roots.
///
/// This verifies archive content, `RootAuth` commitments, and the `RootAuth`
/// signature made by the embedded leaf certificate. It intentionally does not
/// validate that certificate against a trusted root.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, the `RootAuth`
/// signature does not match the embedded certificate, or the archive is not
/// signed with the X.509 `RootAuth` profile.
pub fn inspect_tzap_x509_signer(archive: impl AsRef<Path>, password: Option<&str>) -> Result<TzapX509SignerInspection, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    inspect_opened_x509_signer(&opened)
}

/// Inspects a TZAP X.509 `RootAuth` signer without the archive key or trust roots.
///
/// This checks the public data-block commitment and the `RootAuth` signature, but
/// does not decrypt entries, prove recovery/parity material is complete, or
/// validate the certificate chain against a trusted root.
///
/// # Errors
///
/// Returns [`TzapError`] when public no-key inspection cannot read the volume
/// set, the `RootAuth` signature does not match the embedded certificate, or the
/// archive is not signed with the X.509 `RootAuth` profile.
pub fn inspect_tzap_x509_public_no_key_signer(archive: impl AsRef<Path>) -> Result<TzapX509SignerInspection, TzapError> {
    let archive_path = archive.as_ref();
    let volume_bytes = read_tzap_input_volume_bytes(archive_path)?;
    let volume_refs = volume_bytes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let mut inspection = None;
    let mut x509_error = None;
    let verification = public_no_key_verify_volumes_with(&volume_refs, |footer, archive_root| match inspect_x509_root_auth_footer(footer, archive_root) {
        Ok(value) => {
            inspection = Some(value);
            Ok(true)
        }
        Err(error) => {
            x509_error = Some(error.to_string());
            Ok(false)
        }
    })
    .map_err(|source| if let Some(detail) = x509_error { TzapError::X509RootAuth(format!("{source}: {detail}")) } else { TzapError::Format(source) })?;
    let mut inspection = inspection.ok_or(TzapError::Format(FormatError::InvalidArchive("missing X.509 public no-key signer inspection report")))?;
    inspection.diagnostics = public_no_key_diagnostic_labels(&verification.diagnostics);
    Ok(inspection)
}

fn inspect_opened_x509_signer(opened: &OpenedArchive) -> Result<TzapX509SignerInspection, TzapError> {
    let mut inspection = None;
    let mut x509_error = None;
    let verification = opened
        .verify_root_auth_with(|footer, archive_root| match inspect_x509_root_auth_footer(footer, archive_root) {
            Ok(value) => {
                inspection = Some(value);
                Ok(true)
            }
            Err(error) => {
                x509_error = Some(error.to_string());
                Ok(false)
            }
        })
        .map_err(|source| if let Some(detail) = x509_error { TzapError::X509RootAuth(format!("{source}: {detail}")) } else { TzapError::Format(source) })?;
    let mut inspection = inspection.ok_or(TzapError::Format(FormatError::InvalidArchive("missing X.509 signer inspection report")))?;
    inspection.diagnostics = root_auth_diagnostic_labels(&verification.diagnostics);
    Ok(inspection)
}

pub(crate) fn inspect_x509_root_auth_footer(footer: &RootAuthFooterV1, archive_root: &[u8; 32]) -> Result<TzapX509SignerInspection, TzapError> {
    // All crypto is delegated to the plugin's trust-less assertion-1 check
    // (scheme-aware: RSA-PKCS1 / ECDSA / RSA-PSS). This wrapper only adds the
    // display fields derived from the embedded leaf certificate.
    let report = verify_root_auth_signature(footer, archive_root).map_err(|error| TzapError::X509RootAuth(error.to_string()))?;
    let (remaining, leaf_certificate) = x509_parser::certificate::X509Certificate::from_der(&footer.signer_identity_bytes)
        .map_err(|source| TzapError::X509RootAuth(format!("invalid X.509 signer identity: {source}")))?;
    if !remaining.is_empty() {
        return Err(TzapError::X509RootAuth("invalid X.509 signer identity: trailing DER bytes".to_owned()));
    }
    Ok(TzapX509SignerInspection {
        archive_root: *archive_root,
        authenticator_id: footer.authenticator_id,
        signer_identity_type: footer.signer_identity_type,
        total_data_block_count: footer.total_data_block_count,
        signed_at_unix_seconds: report.signed_at_unix_seconds,
        subject: x509_name_to_string(leaf_certificate.subject()),
        issuer: x509_name_to_string(leaf_certificate.issuer()),
        serial_number_hex: leaf_certificate.serial.to_str_radix(16),
        certificate_sha256: report.certificate_sha256,
        diagnostics: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::{TzapX509TrustOptions, load_x509_trusted_roots};
    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer as _;

    #[test]
    fn x509_trust_options_can_include_embedded_official_root() {
        let trust = TzapX509TrustOptions { trusted_ca_certificates: Vec::new(), trusted_system_roots: false, include_official_tzap_root: true };

        let roots = load_x509_trusted_roots(&trust).unwrap();

        assert_eq!(roots.len(), 2);
        assert_eq!(crate::trust::certificate_sha256_identifier_for_der(&roots[0]), crate::trust::TZAP_PRODUCTION_ROOT_SHA256);
        assert_eq!(crate::trust::certificate_sha256_identifier_for_der(&roots[1]), crate::trust::TZAP_STAGING_ROOT_SHA256);
        let root = X509Certificate::from_der(&roots[0]).unwrap().1;
        assert_eq!(crate::x509_format::x509_name_to_string(root.subject()), "CN=TZAP Production Root CA 2026, O=TZAP, C=AU");
        let staging = X509Certificate::from_der(&roots[1]).unwrap().1;
        assert_eq!(crate::x509_format::x509_name_to_string(staging.subject()), "CN=TZAP Staging Root CA 2026, O=TZAP, C=AU");
    }
}
