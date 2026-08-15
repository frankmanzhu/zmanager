//! ECDSA P-256 SHA-256 primitive helpers.
//!
//! The public signing and verification helpers accept canonical payload bytes,
//! not precomputed digests. They perform SHA-256 internally so callers do not
//! need to choose between raw and prehashed APIs.

use ecdsa::elliptic_curve::scalar::IsHigh as _;
use ecdsa::signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};
use p256::SecretKey;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use pkcs8::{DecodePrivateKey, DecodePublicKey};
use sha2::{Digest, Sha256};
use x509_parser::prelude::FromDer as _;

use crate::os_rng::OsRng;

/// Fixed-width signature length for P-1363 `(r || s)` on P-256.
pub const P256_P1363_SIGNATURE_LENGTH: usize = 64;

/// Errors returned by the P-256 helpers.
#[derive(Debug)]
pub enum P256SignatureError {
    /// Signature input is not exactly 64 bytes.
    InvalidSignatureLength { actual: usize },
    /// Signature rejected because `s` is not canonical low-S.
    NonCanonicalLowS,
    /// The `RustCrypto` stack rejected an operation.
    Crypto(String),
}

/// Signs `payload` bytes with SHA-256 + P-256 and returns fixed-width P-1363 bytes.
///
/// The SHA-256 hashing step is intentionally inside this helper to avoid callers
/// accidentally hashing payloads twice. Nonces are provider-RNG backed
/// (randomized signing, not RFC 6979), matching the pre-migration OpenSSL
/// behavior; `s` is normalized to canonical low-S.
pub fn sign_p256_sha256_p1363(private_key: &SecretKey, payload: &[u8]) -> Result<[u8; P256_P1363_SIGNATURE_LENGTH], P256SignatureError> {
    let signing_key = SigningKey::from(private_key.clone());
    let digest = sha256_digest(payload);
    let signature: ecdsa::Signature<p256::NistP256> =
        signing_key.sign_prehash_with_rng(&mut OsRng, &digest).map_err(|error| P256SignatureError::Crypto(error.to_string()))?;
    Ok(encode_p256_p1363_signature(&signature.normalize_s()))
}

/// Verifies a SHA-256 + P-256 P-1363 signature.
///
/// The SHA-256 hashing step is intentionally inside this helper to avoid callers
/// accidentally hashing payloads twice.
pub fn verify_p256_sha256_p1363(public_key: &VerifyingKey, payload: &[u8], signature: &[u8]) -> Result<bool, P256SignatureError> {
    let signature = decode_p256_p1363_signature(signature)?;

    if signature.s().is_high().into() {
        return Err(P256SignatureError::NonCanonicalLowS);
    }

    let digest = sha256_digest(payload);
    Ok(public_key.verify_prehash(&digest, &signature).is_ok())
}

/// Encodes an ECDSA P-256 signature as fixed-width P-1363 `r || s` bytes.
#[must_use]
pub fn encode_p256_p1363_signature(signature: &Signature) -> [u8; P256_P1363_SIGNATURE_LENGTH] {
    let bytes = signature.to_bytes();
    let mut out = [0_u8; P256_P1363_SIGNATURE_LENGTH];
    out.copy_from_slice(&bytes);
    out
}

/// Decodes fixed-width P-1363 `r || s` bytes into an ECDSA P-256 signature.
///
/// This enforces the fixed-width encoding and rejects scalars outside the
/// curve order. Verification helpers perform canonical low-S policy checks
/// before asking the verifying key to verify.
pub fn decode_p256_p1363_signature(signature: &[u8]) -> Result<Signature, P256SignatureError> {
    if signature.len() != P256_P1363_SIGNATURE_LENGTH {
        return Err(P256SignatureError::InvalidSignatureLength { actual: signature.len() });
    }

    Signature::from_slice(signature).map_err(|error| P256SignatureError::Crypto(error.to_string()))
}

fn sha256_digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

/// Parses a stored device signing key into a P-256 secret key.
///
/// Identity-store records hold OpenSSL `private_key_to_der()` output, which is
/// SEC1 for EC keys; PKCS#8 is also accepted for converted or future records.
pub fn parse_p256_private_key_der(der: &[u8]) -> Result<SecretKey, P256SignatureError> {
    SecretKey::from_pkcs8_der(der).or_else(|_| SecretKey::from_sec1_der(der)).map_err(|error| P256SignatureError::Crypto(error.to_string()))
}

/// Parses a `SubjectPublicKeyInfo` DER blob into a P-256 verifying key.
pub fn parse_p256_public_key_spki_der(spki_der: &[u8]) -> Result<VerifyingKey, P256SignatureError> {
    let public_key = p256::PublicKey::from_public_key_der(spki_der).map_err(|error| P256SignatureError::Crypto(error.to_string()))?;
    Ok(public_key.into())
}

/// Extracts the P-256 verifying key from a DER X.509 certificate.
///
/// The SPKI algorithm must be `id-ecPublicKey` with the P-256 namedCurve;
/// `DecodePublicKey` enforces both, matching the pre-migration OpenSSL
/// `ec_key()`/`curve_name() == prime256v1` checks.
pub fn parse_p256_public_key_cert_der(cert_der: &[u8]) -> Result<VerifyingKey, P256SignatureError> {
    let (remaining, certificate) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|error| P256SignatureError::Crypto(format!("certificate parse failed: {error}")))?;
    if !remaining.is_empty() {
        return Err(P256SignatureError::Crypto("certificate DER has trailing bytes".to_owned()));
    }
    let public_key =
        p256::PublicKey::from_public_key_der(certificate.tbs_certificate.subject_pki.raw).map_err(|error| P256SignatureError::Crypto(error.to_string()))?;
    Ok(public_key.into())
}

#[cfg(test)]
mod tests {
    use super::verify_p256_sha256_p1363;
    use super::{P256_P1363_SIGNATURE_LENGTH, P256SignatureError, decode_p256_p1363_signature, encode_p256_p1363_signature, sign_p256_sha256_p1363};
    use ecdsa::elliptic_curve::Generate as _;
    use p256::SecretKey;
    use p256::ecdsa::VerifyingKey;
    use sha2::{Digest, Sha256};

    fn test_keys() -> (SecretKey, VerifyingKey) {
        let private = SecretKey::generate_from_rng(&mut crate::os_rng::OsRng);
        let public = private.public_key().into();
        (private, public)
    }

    #[test]
    fn p256_signature_is_64_bytes_and_rejects_wrong_key_or_tamper() {
        let (private, public) = test_keys();
        let payload = b"deterministic payload";

        let signature = sign_p256_sha256_p1363(&private, payload).unwrap();
        assert_eq!(signature.len(), P256_P1363_SIGNATURE_LENGTH);

        assert!(verify_p256_sha256_p1363(&public, payload, &signature).unwrap());
        assert!(!verify_p256_sha256_p1363(&public, &Sha256::digest(payload), &signature).unwrap());

        let tampered_payload = b"tampered payload";
        assert!(!verify_p256_sha256_p1363(&public, tampered_payload, &signature).unwrap());

        let (_other_private, other_public) = test_keys();
        assert!(!verify_p256_sha256_p1363(&other_public, payload, &signature).unwrap());
    }

    #[test]
    fn p256_p1363_decode_requires_fixed_width() {
        let (private, _public) = test_keys();
        let signature = sign_p256_sha256_p1363(&private, b"p1363 payload").unwrap();
        let decoded = decode_p256_p1363_signature(&signature).unwrap();

        assert_eq!(encode_p256_p1363_signature(&decoded), signature);
        assert!(matches!(
            decode_p256_p1363_signature(&signature[..P256_P1363_SIGNATURE_LENGTH - 1]),
            Err(P256SignatureError::InvalidSignatureLength { actual })
                if actual == P256_P1363_SIGNATURE_LENGTH - 1
        ));
    }

    #[test]
    fn p256_signature_nonces_are_csprng_non_deterministic() {
        let (private, _public) = test_keys();
        let payload = b"nonce check payload";

        let first = sign_p256_sha256_p1363(&private, payload).unwrap();
        let second = sign_p256_sha256_p1363(&private, payload).unwrap();

        // Signing is randomized (provider-RNG backed, no RFC 6979 selection),
        // so two signatures must differ — the pre-migration OpenSSL behavior.
        assert_ne!(first, second);
    }

    #[test]
    fn p256_verification_rejects_high_s_signature() {
        let (private, public) = test_keys();
        let payload = b"high-s check payload";

        let signature = sign_p256_sha256_p1363(&private, payload).unwrap();
        let decoded = decode_p256_p1363_signature(&signature).unwrap();

        // Invert s: order - s is necessarily high for a low-S input.
        let mut high_signature = signature;
        let high_s = -decoded.s();
        high_signature[P256_P1363_SIGNATURE_LENGTH / 2..].copy_from_slice(&high_s.to_bytes());

        let result = verify_p256_sha256_p1363(&public, payload, &high_signature);
        assert!(matches!(result, Err(P256SignatureError::NonCanonicalLowS)));
    }
}
