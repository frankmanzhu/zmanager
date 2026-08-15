//! `RustCrypto` X.509 certificate assembly shared by the hosted services
//! (OR-300 self-signed identities, OR-302 local signer chains).
//!
//! Certificates are assembled with `x509-cert` types and signed with the
//! `RustCrypto` stack (ECDSA P-256 SHA-256, or RSA PKCS#1v1.5 SHA-256); the
//! OpenSSL surface in this crate is limited to PKCS#12 container export per
//! the ADR 2026-08-15 gap decision.

use ecdsa::signature::SignatureEncoding as _;
use ecdsa::signature::hazmat::RandomizedPrehashSigner;
use p256::ecdsa::SigningKey;
use rsa::pkcs1v15;
use sha2::{Digest, Sha256};
use signature::DigestSigner as _;
use signature::SignatureEncoding as _;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::der::DateTime as DerDateTime;
use x509_cert::der::Encode as _;
use x509_cert::der::asn1::{Any, BitString, GeneralizedTime, ObjectIdentifier, OctetString, UtcTime, Utf8StringRef};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::name::{Name, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};

const OID_COMMON_NAME: &str = "2.5.4.3";
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";

/// Inputs for one certificate in an assembled chain.
pub(crate) struct CertificateSpec<'a> {
    pub(crate) subject_cn: &'a str,
    /// The issuer's subject name (the subject name itself for roots).
    pub(crate) issuer: Name,
    /// Subject public key SPKI DER.
    pub(crate) subject_spki_der: Vec<u8>,
    pub(crate) serial: u64,
    pub(crate) not_before_unix: i64,
    pub(crate) not_after_unix: i64,
    pub(crate) extensions: Vec<Extension>,
}

/// Builds a CN-only distinguished name.
pub(crate) fn common_name_name(common_name: &str) -> Result<Name, String> {
    let mut rdn = RelativeDistinguishedName::default();
    rdn.0
        .insert(AttributeTypeAndValue {
            oid: ObjectIdentifier::new_unwrap(OID_COMMON_NAME),
            value: Any::encode_from(&Utf8StringRef::new(common_name).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?,
        })
        .map_err(|error| error.to_string())?;
    let mut name = Name::default();
    name.0.push(rdn);
    Ok(name)
}

/// Subject key identifier extension: SHA-256 over the SPKI BIT STRING content
/// (the OpenSSL x509v3-context derivation is SHA-1; this chain is internally
/// consistent either way, and nothing external pins the identifier bytes).
pub(crate) fn subject_key_identifier_extension(spki_der: &[u8]) -> Result<Extension, String> {
    let spki = SubjectPublicKeyInfoOwned::try_from(spki_der).map_err(|error| error.to_string())?;
    let digest = Sha256::digest(spki.subject_public_key.raw_bytes());
    Ok(Extension {
        extn_id: ObjectIdentifier::new_unwrap("2.5.29.14"),
        critical: false,
        extn_value: OctetString::new(
            SubjectKeyIdentifier(OctetString::new(digest.as_slice()).map_err(|error| error.to_string())?).to_der().map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?,
    })
}

/// Assembles and signs a certificate with an RSA issuer key (PKCS#1v1.5 SHA-256).
pub(crate) fn assemble_rsa_certificate(spec: &CertificateSpec<'_>, issuer_key: &rsa::RsaPrivateKey) -> Result<Vec<u8>, String> {
    let signature_algorithm = AlgorithmIdentifierOwned { oid: ObjectIdentifier::new_unwrap(OID_SHA256_WITH_RSA), parameters: None };
    let tbs = build_tbs(spec, &signature_algorithm)?;
    let tbs_der = tbs.to_der().map_err(|error| error.to_string())?;
    let signing_key = pkcs1v15::SigningKey::<Sha256>::new(issuer_key.clone());
    let signature: rsa::pkcs1v15::Signature = signing_key.sign_digest(Sha256::new_with_prefix(&tbs_der));
    assemble_certificate(tbs, signature_algorithm, signature.to_vec())
}

fn build_tbs(spec: &CertificateSpec<'_>, signature_algorithm: &AlgorithmIdentifierOwned) -> Result<TbsCertificate, String> {
    let subject_public_key_info = SubjectPublicKeyInfoOwned::try_from(spec.subject_spki_der.as_slice()).map_err(|error| error.to_string())?;
    Ok(TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::from(spec.serial),
        signature: signature_algorithm.clone(),
        issuer: spec.issuer.clone(),
        validity: Validity { not_before: time_from_unix(spec.not_before_unix)?, not_after: time_from_unix(spec.not_after_unix)? },
        subject: common_name_name(spec.subject_cn)?,
        subject_public_key_info,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(spec.extensions.clone()),
    })
}

fn assemble_certificate(tbs: TbsCertificate, signature_algorithm: AlgorithmIdentifierOwned, signature: Vec<u8>) -> Result<Vec<u8>, String> {
    let certificate =
        Certificate { tbs_certificate: tbs, signature_algorithm, signature: BitString::from_bytes(&signature).map_err(|error| error.to_string())? };
    certificate.to_der().map_err(|error| error.to_string())
}

/// DER-encodes a `BasicConstraints` extension value.
pub(crate) fn basic_constraints_der(ca: bool, path_len: Option<u8>) -> Result<Vec<u8>, String> {
    x509_cert::ext::pkix::BasicConstraints { ca, path_len_constraint: path_len }.to_der().map_err(|error| error.to_string())
}

/// Builds an extension from raw DER contents and a numeric dotted OID.
pub(crate) fn raw_der_extension(oid: &str, critical: bool, contents: &[u8]) -> Result<Extension, String> {
    Ok(Extension {
        extn_id: ObjectIdentifier::try_from(oid_der_bytes(oid).ok_or("invalid OID")?.as_slice()).map_err(|error| error.to_string())?,
        critical,
        extn_value: OctetString::new(contents).map_err(|error| error.to_string())?,
    })
}

/// Inputs for a certificate assembled from raw DER extension bytes.
///
/// The local TZAP chain needs policy/metadata OIDs whose arcs exceed u32
/// (const-oid's limit), so those certificates are assembled with a raw TBS
/// encoder instead of `x509-cert`'s typed extensions.
pub(crate) struct RawCertificateSpec<'a> {
    pub(crate) subject_cn: &'a str,
    /// Issuer name bytes (a DER-encoded `RDNSequence`).
    pub(crate) issuer_der: Vec<u8>,
    /// Subject public key SPKI DER.
    pub(crate) subject_spki_der: Vec<u8>,
    pub(crate) serial: u64,
    pub(crate) not_before_unix: i64,
    pub(crate) not_after_unix: i64,
    /// Raw DER-encoded extensions (complete SEQUENCE elements).
    pub(crate) extensions: Vec<Vec<u8>>,
}

/// Encodes a raw extension SEQUENCE element from a complete OID element
/// (tag + length + arcs), an optional critical flag, and the extension value
/// OCTET STRING.
pub(crate) fn raw_extension_der(oid_element: &[u8], critical: bool, contents: &[u8]) -> Vec<u8> {
    let mut elements = oid_element.to_vec();
    if critical {
        elements.extend(der_wrap_raw(0x01, &[0xff]));
    }
    elements.extend(der_wrap_raw(0x04, contents));
    der_wrap_raw(0x30, &elements)
}

/// Assembles and signs a certificate with raw extensions and an ECDSA P-256
/// issuer key. This is the raw-DER sibling of [`assemble_ecdsa_certificate`].
pub(crate) fn assemble_ecdsa_certificate_raw(spec: &RawCertificateSpec<'_>, issuer_key: &p256::SecretKey) -> Result<Vec<u8>, String> {
    let sig_alg = der_wrap_raw(0x30, &der_wrap_raw(0x06, &oid_der_bytes(OID_ECDSA_WITH_SHA256).ok_or("invalid OID")?));

    let mut tbs_elements = Vec::new();
    // [0] EXPLICIT version (v3 = INTEGER 2)
    tbs_elements.extend(der_wrap_raw(0xa0, &der_wrap_raw(0x02, &minimal_integer_bytes(spec.serial))));
    tbs_elements.extend(der_wrap_raw(0x02, &minimal_integer_bytes(spec.serial)));
    tbs_elements.extend(sig_alg.clone());
    tbs_elements.extend(spec.issuer_der.clone());
    // Validity ::= SEQUENCE { notBefore Time, notAfter Time } — the Time
    // CHOICE (UTCTime/GeneralizedTime) is encoded directly, not wrapped.
    tbs_elements.extend(der_wrap_raw(0x30, &[utc_or_generalized_time_der(spec.not_before_unix)?, utc_or_generalized_time_der(spec.not_after_unix)?].concat()));
    tbs_elements.extend(common_name_name(spec.subject_cn)?.to_der().map_err(|error| error.to_string())?);
    tbs_elements.extend(spec.subject_spki_der.clone());
    if !spec.extensions.is_empty() {
        let extensions = der_wrap_raw(0x30, &spec.extensions.concat());
        tbs_elements.extend(der_wrap_raw(0xa3, &extensions));
    }
    let tbs_der = der_wrap_raw(0x30, &tbs_elements);

    let signing_key = SigningKey::from(issuer_key.clone());
    let fixed: ecdsa::Signature<p256::NistP256> =
        signing_key.sign_prehash_with_rng(&mut zmanager_core::os_rng::OsRng, &Sha256::digest(&tbs_der)).map_err(|error| error.to_string())?;
    let signature = ecdsa::der::Signature::<p256::NistP256>::from(fixed.normalize_s()).to_vec();

    let mut certificate_elements = tbs_der;
    certificate_elements.extend(sig_alg);
    certificate_elements.extend(der_wrap_raw(0x03, &[&[0u8][..], signature.as_slice()].concat()));
    Ok(der_wrap_raw(0x30, &certificate_elements))
}

/// Minimal big-endian INTEGER content with a leading zero when the high bit
/// is set (DER positive-integer encoding).
fn minimal_integer_bytes(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first_nonzero = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len() - 1);
    let trimmed = &bytes[first_nonzero..];
    if trimmed[0] & 0x80 != 0 {
        let mut out = Vec::with_capacity(trimmed.len() + 1);
        out.push(0);
        out.extend(trimmed);
        out
    } else {
        trimmed.to_vec()
    }
}

#[allow(clippy::cast_possible_truncation)] // month/day/hour/minute/second are bounded by construction
fn utc_or_generalized_time_der(seconds: i64) -> Result<Vec<u8>, String> {
    let time = time::OffsetDateTime::from_unix_timestamp(seconds).map_err(|error| error.to_string())?;
    if time.year() >= 2050 {
        Ok(der_wrap_raw(
            0x18,
            format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", time.year(), u8::from(time.month()), time.day(), time.hour(), time.minute(), time.second()).as_bytes(),
        ))
    } else {
        Ok(der_wrap_raw(
            0x17,
            format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", time.year() % 100, u8::from(time.month()), time.day(), time.hour(), time.minute(), time.second())
                .as_bytes(),
        ))
    }
}

fn der_wrap_raw(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len_raw(contents.len()));
    out.extend(contents);
    out
}

#[allow(clippy::cast_possible_truncation)] // 0x80 | byte-count is 0x81..=0x84 by construction
fn der_len_raw(length: usize) -> Vec<u8> {
    if length < 128 {
        vec![length as u8]
    } else {
        let bytes = length.to_be_bytes();
        let first_nonzero = bytes.iter().position(|byte| *byte != 0).unwrap_or(0);
        let mut out = vec![0x80 | (bytes.len() - first_nonzero) as u8];
        out.extend(&bytes[first_nonzero..]);
        out
    }
}

/// Encodes a Unix timestamp as `UTCTime` (or `GeneralizedTime` past 2049),
/// matching OpenSSL's `ASN1_TIME` normalization boundary.
pub(crate) fn time_from_unix(seconds: i64) -> Result<Time, String> {
    let time = time::OffsetDateTime::from_unix_timestamp(seconds).map_err(|error| error.to_string())?;
    let datetime = DerDateTime::new(
        u16::try_from(time.year()).map_err(|_| "certificate year out of range".to_owned())?,
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
    )
    .map_err(|error| error.to_string())?;
    if time.year() >= 2050 {
        Ok(Time::GeneralTime(GeneralizedTime::from_date_time(datetime)))
    } else {
        UtcTime::from_date_time(datetime).map(Time::UtcTime).map_err(|error| error.to_string())
    }
}

/// DER-encodes a numeric dotted OID (arcs beyond `u64` are supported via
/// decimal long division — TZAP's UUID-derived policy OIDs need it).
pub(crate) fn oid_der_bytes(oid: &str) -> Option<Vec<u8>> {
    let mut arcs = oid.split('.');
    let first = arcs.next()?.parse::<u64>().ok()?;
    let second = arcs.next()?.parse::<u64>().ok()?;
    let mut out = Vec::new();
    push_base128(&mut out, first.checked_mul(40)?.checked_add(second)?);
    for arc in arcs {
        if arc.is_empty() {
            return None;
        }
        encode_big_base128(&mut out, arc.as_bytes());
    }
    Some(out)
}

fn push_base128(out: &mut Vec<u8>, value: u64) {
    let mut buffer = [0u8; 10];
    let mut index = 0;
    let mut remaining = value;
    loop {
        buffer[index] = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining == 0 {
            break;
        }
        index += 1;
    }
    while index > 0 {
        out.push(buffer[index] | 0x80);
        index -= 1;
    }
    out.push(buffer[0]);
}

fn encode_big_base128(out: &mut Vec<u8>, decimal: &[u8]) {
    let mut digits: Vec<u8> = decimal.iter().map(|digit| *digit - b'0').collect();
    let mut groups: Vec<u8> = Vec::new();
    loop {
        let mut remainder = 0u16;
        let mut next: Vec<u8> = Vec::with_capacity(digits.len());
        let mut started = false;
        for digit in &digits {
            let value = remainder * 10 + u16::from(*digit);
            let quotient = value / 128;
            remainder = value % 128;
            if started || quotient != 0 {
                started = true;
                next.push(quotient as u8);
            }
        }
        groups.push(remainder as u8);
        if next.is_empty() {
            break;
        }
        digits = next;
    }
    for (index, group) in groups.iter().enumerate().rev() {
        if index == 0 {
            out.push(*group);
        } else {
            out.push(*group | 0x80);
        }
    }
}

/// Encodes DER bytes as a PEM block with 64-column base64 lines.
pub(crate) fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    use std::fmt::Write as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 64 + 64);
    let _ = writeln!(out, "-----BEGIN {label}-----");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 output is ASCII"));
        out.push('\n');
    }
    let _ = writeln!(out, "-----END {label}-----");
    out
}
