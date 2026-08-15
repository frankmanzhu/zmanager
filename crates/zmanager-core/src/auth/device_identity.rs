//! Local TZAP device-signing key generation and CSR helpers.

use crate::os_rng::OsRng;
use crate::p256_signature::parse_p256_private_key_der;
use crate::secrets::SecretBytes;
use crate::trust;
use ecdsa::elliptic_curve::Generate as _;
use ecdsa::signature::SignatureEncoding as _;
use ecdsa::signature::hazmat::RandomizedPrehashSigner;
use p256::SecretKey;
use p256::ecdsa::SigningKey;
use pkcs8::EncodePublicKey;
use sha2::{Digest as _, Sha256};
use std::fmt;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::der::asn1::{Any, BitString, ObjectIdentifier, Utf8StringRef};
use x509_cert::der::{Decode as _, Encode as _};
use x509_cert::name::{Name, RelativeDistinguishedName};
use x509_cert::request::{CertReq, CertReqInfo, Version};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const OID_COMMON_NAME: &str = "2.5.4.3";
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";

pub const DEVICE_CSR_COMMON_NAME: &str = "TZAP Device Signing Key";
pub const RECIPIENT_ENCRYPTION_KEY_ALGORITHM: &str = "P-256-SPKI";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapDeviceCsrOptions {
    pub common_name: String,
}

impl Default for TzapDeviceCsrOptions {
    fn default() -> Self {
        Self { common_name: DEVICE_CSR_COMMON_NAME.to_owned() }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapDeviceSigningKeyMaterial {
    pub private_key_der: SecretBytes,
    pub public_key_spki_der: Vec<u8>,
    pub public_key_fingerprint: String,
    pub csr_der: Vec<u8>,
    pub csr_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapRecipientEncryptionKeyMaterial {
    pub algorithm: &'static str,
    pub private_key_der: SecretBytes,
    pub public_key_spki_der: Vec<u8>,
    pub public_key_fingerprint: String,
}

#[derive(Debug)]
pub enum TzapDeviceIdentityError {
    EmptyCommonName,
    RecipientKeyReusesSigningKey,
    Crypto(String),
}

impl fmt::Display for TzapDeviceIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommonName => write!(f, "device CSR common name is empty"),
            Self::RecipientKeyReusesSigningKey => {
                write!(f, "recipient encryption key reuses signing key material")
            }
            Self::Crypto(reason) => write!(f, "device identity crypto operation failed: {reason}"),
        }
    }
}

impl std::error::Error for TzapDeviceIdentityError {}

pub fn generate_device_signing_key_and_csr(options: &TzapDeviceCsrOptions) -> Result<TzapDeviceSigningKeyMaterial, TzapDeviceIdentityError> {
    if options.common_name.is_empty() {
        return Err(TzapDeviceIdentityError::EmptyCommonName);
    }

    let private_key = generate_p256_private_key();
    let public_key_spki_der =
        private_key.public_key().to_public_key_der().map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))?.as_bytes().to_vec();
    let public_key_fingerprint = spki_fingerprint(&public_key_spki_der);
    let csr_der = build_device_csr(&private_key, options)?;
    let csr_sha256 = csr_fingerprint(&csr_der);

    Ok(TzapDeviceSigningKeyMaterial {
        private_key_der: SecretBytes::from(private_key.to_sec1_der().map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))?.to_vec()),
        public_key_spki_der,
        public_key_fingerprint,
        csr_der,
        csr_sha256,
    })
}

/// Rebuilds a device CSR from an existing private key.
///
/// Hosted organization enrollment uses this after an administrator approves
/// the pending device key, so the retry presents the same device identity.
pub fn generate_device_csr_from_private_key(private_key_der: &SecretBytes, options: &TzapDeviceCsrOptions) -> Result<Vec<u8>, TzapDeviceIdentityError> {
    if options.common_name.is_empty() {
        return Err(TzapDeviceIdentityError::EmptyCommonName);
    }
    let private_key = parse_p256_private_key_der(private_key_der.expose_secret()).map_err(|error| TzapDeviceIdentityError::Crypto(format!("{error:?}")))?;
    build_device_csr(&private_key, options)
}

pub fn generate_recipient_encryption_key() -> Result<TzapRecipientEncryptionKeyMaterial, TzapDeviceIdentityError> {
    let private_key = generate_p256_private_key();
    let public_key_spki_der =
        private_key.public_key().to_public_key_der().map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))?.as_bytes().to_vec();
    let public_key_fingerprint = spki_fingerprint(&public_key_spki_der);

    Ok(TzapRecipientEncryptionKeyMaterial {
        algorithm: RECIPIENT_ENCRYPTION_KEY_ALGORITHM,
        private_key_der: SecretBytes::from(private_key.to_sec1_der().map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))?.to_vec()),
        public_key_spki_der,
        public_key_fingerprint,
    })
}

pub fn ensure_recipient_key_is_distinct_from_signing_key(
    signing_public_key_fingerprint: &str,
    recipient_public_key_fingerprint: &str,
) -> Result<(), TzapDeviceIdentityError> {
    if signing_public_key_fingerprint == recipient_public_key_fingerprint { Err(TzapDeviceIdentityError::RecipientKeyReusesSigningKey) } else { Ok(()) }
}

fn generate_p256_private_key() -> SecretKey {
    SecretKey::generate_from_rng(&mut OsRng)
}

fn build_device_csr(private_key: &SecretKey, options: &TzapDeviceCsrOptions) -> Result<Vec<u8>, TzapDeviceIdentityError> {
    let spki_der = private_key.public_key().to_public_key_der().map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))?;
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))?;

    let mut rdn = RelativeDistinguishedName::default();
    let common_name = AttributeTypeAndValue {
        oid: ObjectIdentifier::new_unwrap(OID_COMMON_NAME),
        value: Any::encode_from(&Utf8StringRef::new(&options.common_name).map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))?)
            .map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))?,
    };
    rdn.0.insert(common_name).map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))?;
    let mut subject = Name::default();
    subject.0.push(rdn);

    let info = CertReqInfo { version: Version::V1, subject, public_key: spki, attributes: Default::default() };
    let info_der = info.to_der().map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))?;

    // ECDSA P-256 with SHA-256 over the DER-encoded CertificationRequestInfo
    // (RFC 2986), the OpenSSL `X509ReqBuilder::sign(sha256)` equivalent.
    let signing_key = SigningKey::from(private_key.clone());
    let fixed: ecdsa::Signature<p256::NistP256> =
        signing_key.sign_prehash_with_rng(&mut OsRng, &Sha256::digest(&info_der)).map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))?;
    let signature_der = ecdsa::der::Signature::<p256::NistP256>::from(fixed.normalize_s());

    let csr = CertReq {
        info,
        algorithm: AlgorithmIdentifierOwned { oid: ObjectIdentifier::new_unwrap(OID_ECDSA_WITH_SHA256), parameters: None },
        signature: BitString::from_bytes(&signature_der.to_vec()).map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))?,
    };
    csr.to_der().map_err(|error| TzapDeviceIdentityError::Crypto(error.to_string()))
}

fn spki_fingerprint(spki_der: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(spki_der).into();
    trust::format_certificate_sha256(&digest)
}

#[must_use]
pub fn csr_fingerprint(csr_der: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(csr_der).into();
    trust::format_csr_sha256(&digest)
}

#[cfg(test)]
mod tests {
    use super::{
        DEVICE_CSR_COMMON_NAME, RECIPIENT_ENCRYPTION_KEY_ALGORITHM, TzapDeviceCsrOptions, TzapDeviceIdentityError,
        ensure_recipient_key_is_distinct_from_signing_key, generate_device_csr_from_private_key, generate_device_signing_key_and_csr,
        generate_recipient_encryption_key,
    };
    use crate::trust;
    use openssl::nid::Nid;
    use openssl::x509::X509Req;
    use sha2::{Digest as _, Sha256};

    #[test]
    fn device_signing_key_generation_returns_p256_key_and_csr() {
        let material = generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();

        assert!(!material.private_key_der.is_empty());
        assert!(!material.public_key_spki_der.is_empty());
        assert!(trust::parse_spki_sha256(&material.public_key_fingerprint).is_ok());
        assert!(trust::parse_csr_sha256(&material.csr_sha256).is_ok());
        assert_eq!(format!("{:?}", material.private_key_der), "SecretBytes([redacted])");

        assert!(crate::p256_signature::parse_p256_private_key_der(material.private_key_der.expose_secret()).is_ok());

        let csr = X509Req::from_der(&material.csr_der).unwrap();
        assert!(csr.verify(csr.public_key().unwrap().as_ref()).unwrap());
        let subject = csr.subject_name();
        let common_name = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
        assert_eq!(common_name.data().to_string().unwrap(), DEVICE_CSR_COMMON_NAME);

        let csr_digest: [u8; 32] = Sha256::digest(&material.csr_der).into();
        assert_eq!(material.csr_sha256, trust::format_csr_sha256(&csr_digest));
    }

    #[test]
    fn device_csr_options_reject_empty_common_name() {
        assert!(matches!(
            generate_device_signing_key_and_csr(&TzapDeviceCsrOptions { common_name: String::new() }),
            Err(TzapDeviceIdentityError::EmptyCommonName)
        ));
    }

    #[test]
    fn existing_device_key_can_rebuild_a_valid_csr() {
        let material = generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();

        let rebuilt = generate_device_csr_from_private_key(&material.private_key_der, &TzapDeviceCsrOptions::default()).unwrap();
        let csr = X509Req::from_der(&rebuilt).unwrap();

        assert!(csr.verify(csr.public_key().unwrap().as_ref()).unwrap());
        assert_eq!(csr.public_key().unwrap().public_key_to_der().unwrap(), material.public_key_spki_der);
    }

    #[test]
    fn recipient_encryption_key_generation_is_separate_from_signing_keys() {
        let signing_key = generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
        let recipient_key = generate_recipient_encryption_key().unwrap();

        assert_eq!(recipient_key.algorithm, RECIPIENT_ENCRYPTION_KEY_ALGORITHM);
        assert!(!recipient_key.private_key_der.is_empty());
        assert!(!recipient_key.public_key_spki_der.is_empty());
        assert!(trust::parse_spki_sha256(&recipient_key.public_key_fingerprint).is_ok());
        ensure_recipient_key_is_distinct_from_signing_key(&signing_key.public_key_fingerprint, &recipient_key.public_key_fingerprint).unwrap();

        assert!(crate::p256_signature::parse_p256_private_key_der(recipient_key.private_key_der.expose_secret()).is_ok());
    }

    #[test]
    fn recipient_key_distinctness_rejects_reused_signing_fingerprint() {
        let fingerprint = trust::format_certificate_sha256(&[0x42; 32]);

        assert!(matches!(
            ensure_recipient_key_is_distinct_from_signing_key(&fingerprint, &fingerprint),
            Err(TzapDeviceIdentityError::RecipientKeyReusesSigningKey)
        ));
    }
}
