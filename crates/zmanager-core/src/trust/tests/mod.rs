use super::{
    OFFICIAL_TZAP_ROOT_PINS, TZAP_OID_CA_POLICY, TZAP_OID_DOCUMENT_SIGNING_EKU, TZAP_OID_LEAF_POLICY, TZAP_OID_METADATA_EXTENSION, TzapCertificateProfileError,
    TzapCertificateProfileOptions, TzapCertificateStatus, TzapIdentityAssurance, TzapOfficialRootPinKind, TzapRootPinSet, TzapTrustAnchorType,
    TzapVerificationState, canonical_serial_hex, format_certificate_sha256, format_csr_sha256, format_issuer_sha256, is_valid_base64url_no_padding,
    is_valid_issuer_key_identifier, is_valid_public_device_id, is_valid_public_org_id, is_valid_public_signer_id, is_valid_serial_hex,
    is_valid_sha256_identifier, parse_certificate_sha256, parse_crl_sha256, parse_csr_sha256, parse_issuer_sha256, parse_serial_hex, parse_sha256_identifier,
    parse_spki_sha256, percent_encode_path_param, status_certificate_by_fingerprint_path, validate_base64url_no_padding,
    validate_custom_tzap_certificate_chain_der, validate_official_tzap_certificate_chain_der,
};
use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier};
use openssl::x509::{X509, X509Extension, X509NameBuilder, X509Ref};
use serde_json::{Value, json};
use sha2::Digest as _;

const SHA256_BYTES: [u8; 32] = [
    0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xca, 0xdb, 0xec, 0xfd, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9,
    0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
];
const SHA256_IDENT: &str = "sha256:0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f";

#[test]
fn canonical_sha256_formatters_match() {
    assert_eq!(format_certificate_sha256(&SHA256_BYTES), SHA256_IDENT);
    assert_eq!(format_issuer_sha256(&SHA256_BYTES), SHA256_IDENT);
    assert_eq!(format_csr_sha256(&SHA256_BYTES), SHA256_IDENT);
}

#[test]
fn canonical_sha256_parsers_match() {
    assert_eq!(parse_certificate_sha256(SHA256_IDENT).unwrap(), SHA256_BYTES);
    assert_eq!(parse_issuer_sha256(SHA256_IDENT).unwrap(), SHA256_BYTES);
    assert_eq!(parse_crl_sha256(SHA256_IDENT).unwrap(), SHA256_BYTES);
    assert_eq!(parse_csr_sha256(SHA256_IDENT).unwrap(), SHA256_BYTES);
    assert_eq!(parse_spki_sha256(SHA256_IDENT).unwrap(), SHA256_BYTES);
}

#[test]
fn sha256_identifier_validation_rejects_malformed_values() {
    assert!(is_valid_sha256_identifier(SHA256_IDENT));
    assert!(parse_sha256_identifier(SHA256_IDENT).is_ok());

    let invalid_hex_character = format!("sha256:Z{}", "0".repeat(63));
    assert!(matches!(super::parse_sha256_identifier(&invalid_hex_character), Err(super::TrustIdentifierError::InvalidCharacter)));
    assert!(matches!(
        super::parse_sha256_identifier("SHA256:0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f00"),
        Err(super::TrustIdentifierError::InvalidPrefix)
    ));
    assert!(matches!(
        super::parse_sha256_identifier("sha256:0A1B2C3D4E5F6A7B8C9DAEBFCADBECFD102132435465768798A9BACBDCEDFE0F"),
        Err(super::TrustIdentifierError::MixedCase)
    ));
    assert!(super::parse_sha256_identifier(SHA256_IDENT).is_ok());
    assert!(super::parse_sha256_identifier("0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f00").is_err());
    assert!(super::parse_sha256_identifier("c2hhMjU2OmFiYw").is_err());
}

#[test]
fn serial_helper_validates_canonical_hex() {
    assert_eq!(canonical_serial_hex(&[0x00, 0x01, 0x0a, 0x00]).unwrap(), "010A00");
    assert_eq!(canonical_serial_hex(&[0x0a]).unwrap(), "0A");
    assert!(canonical_serial_hex(&[]).is_err());
    assert!(canonical_serial_hex(&[0x00, 0x00]).is_err());
    assert!(is_valid_serial_hex("01ABCDEF"));
    assert!(!is_valid_serial_hex("1aB2"));
    assert!(!is_valid_serial_hex("01ABC"));
    assert!(!is_valid_serial_hex("000000"));
    assert!(!is_valid_serial_hex("0001"));

    assert!(parse_serial_hex("ABCD").is_ok());
    assert!(matches!(parse_serial_hex("abcd"), Err(super::TrustIdentifierError::MixedCase)));
}

#[test]
fn base64url_validation_enforces_no_padding() {
    assert!(is_valid_base64url_no_padding("SGVsbG9fV29ybGQ"));
    assert!(is_valid_issuer_key_identifier("SGVsbG9fV29ybGQ"));
    assert!(validate_base64url_no_padding("SGVsbG9fV29ybGQ").is_ok());
    assert!(validate_base64url_no_padding("SGVsbG9fV29ybGQ=").is_err());
    assert!(validate_base64url_no_padding("SGVsbG8+").is_err());
    assert!(validate_base64url_no_padding("A").is_err());
    assert!(validate_base64url_no_padding("").is_err());
}

#[test]
fn percent_encodes_sha256_path_parameter() {
    let encoded = percent_encode_path_param(SHA256_IDENT);
    assert_eq!(encoded, "sha256%3A0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f");
}

#[test]
fn fingerprint_path_builder_validates_and_percent_encodes() {
    let fingerprint = status_certificate_by_fingerprint_path(SHA256_IDENT).unwrap();
    assert_eq!(fingerprint, "/v1/status/certificates/by-fingerprint/sha256%3A0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f");
}

#[test]
fn public_identifier_rules() {
    assert!(is_valid_public_signer_id("psign_AbCdEfGhIjKlMnOpqR1_"));
    assert!(!is_valid_public_signer_id("sign_AbCdEfGhIjKlMnOpqR1_"));
    assert!(!is_valid_public_signer_id("psign_short"));

    assert!(is_valid_public_org_id("porg_AbCdEfGhIjKlMnOpqR1-2_3"));
    assert!(is_valid_public_device_id("pdev_AbCdEfGhIjKlMnOpqR1_2-"));
    assert!(!is_valid_public_device_id("pdev_Only-15chars___"));
}

#[test]
fn enum_roundtrip_helpers_work() {
    assert_eq!("oauth_verified_email".parse::<TzapIdentityAssurance>().ok(), Some(TzapIdentityAssurance::OauthVerifiedEmail));
    assert_eq!("valid".parse::<TzapCertificateStatus>().ok(), Some(TzapCertificateStatus::Valid));
    assert_eq!("unsupported_lookup_form".parse::<TzapCertificateStatus>().ok(), Some(TzapCertificateStatus::UnsupportedLookupForm));
    assert_eq!(TzapVerificationState::Invalid.as_str(), "invalid");
    assert_eq!(TzapTrustAnchorType::OfficialTzap.as_str(), "official_tzap");
}

#[test]
fn root_pin_set_helpers() {
    let pins = TzapRootPinSet {
        current: &["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        planned_successors: &["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
    };
    assert!(pins.is_current_root("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(pins.is_planned_successor("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    assert!(!pins.is_official_root("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    assert!(!pins.is_official_root("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

    assert_eq!(OFFICIAL_TZAP_ROOT_PINS.current, &[super::TZAP_PRODUCTION_ROOT_SHA256, super::TZAP_STAGING_ROOT_SHA256]);
    assert!(OFFICIAL_TZAP_ROOT_PINS.planned_successors.is_empty());
}

#[test]
fn certificate_profile_accepts_valid_official_chain_and_metadata() {
    let fixture = certificate_fixture(ChainConfig::default());
    let pins = current_pin_set(&fixture.root_pin);

    let validation = validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default()).unwrap();

    assert_eq!(validation.trust_anchor_type, TzapTrustAnchorType::OfficialTzap);
    assert_eq!(validation.official_root_pin_kind, Some(TzapOfficialRootPinKind::Current));
    assert_eq!(validation.root_certificate_sha256, fixture.root_pin);
    assert_eq!(validation.public_metadata.public_signer_id, "psign_0123456789ABCDEFGH");
    assert_eq!(validation.public_metadata.assurance_level, TzapIdentityAssurance::OauthVerifiedEmail);
}

#[test]
fn certificate_profile_reports_planned_successor_root_pin() {
    let fixture = certificate_fixture(ChainConfig::default());
    let pins = planned_successor_pin_set(&fixture.root_pin);

    let validation = validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default()).unwrap();

    assert_eq!(validation.official_root_pin_kind, Some(TzapOfficialRootPinKind::PlannedSuccessor));
}

#[test]
fn certificate_profile_custom_trust_is_distinguishable_from_official_trust() {
    let fixture = certificate_fixture(ChainConfig::default());

    let validation = validate_custom_tzap_certificate_chain_der(&fixture.chain_der, &TzapCertificateProfileOptions::default()).unwrap();

    assert_eq!(validation.trust_anchor_type, TzapTrustAnchorType::Custom);
    assert_eq!(validation.official_root_pin_kind, None);
}

#[test]
fn certificate_profile_unpinned_or_system_root_trust_never_becomes_official() {
    let fixture = certificate_fixture(ChainConfig::default());
    let pins = TzapRootPinSet { current: &[], planned_successors: &[] };

    assert!(matches!(
        validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default(),),
        Err(TzapCertificateProfileError::RootNotPinned { .. })
    ));
}

#[test]
fn certificate_profile_rejects_missing_metadata() {
    let fixture = certificate_fixture(ChainConfig { metadata: MetadataMode::Missing, ..ChainConfig::default() });
    let pins = current_pin_set(&fixture.root_pin);

    assert!(matches!(
        validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default(),),
        Err(TzapCertificateProfileError::MissingMetadata)
    ));
}

#[test]
fn certificate_profile_rejects_nested_asn1_metadata() {
    let fixture = certificate_fixture(ChainConfig { metadata: MetadataMode::NestedOctetString, ..ChainConfig::default() });
    let pins = current_pin_set(&fixture.root_pin);

    assert!(matches!(
        validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default(),),
        Err(TzapCertificateProfileError::NestedAsn1Metadata)
    ));
}

#[test]
fn certificate_profile_rejects_unknown_metadata_field() {
    let fixture = certificate_fixture(ChainConfig { metadata: MetadataMode::UnknownField, ..ChainConfig::default() });
    let pins = current_pin_set(&fixture.root_pin);

    assert!(matches!(
        validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default(),),
        Err(TzapCertificateProfileError::UnknownMetadataField { .. })
    ));
}

#[test]
fn certificate_profile_rejects_invalid_public_ids_and_assurance_values() {
    for metadata in [MetadataMode::InvalidSignerId, MetadataMode::InvalidOrgId, MetadataMode::InvalidDeviceId, MetadataMode::InvalidAssurance] {
        let fixture = certificate_fixture(ChainConfig { metadata, ..ChainConfig::default() });
        let pins = current_pin_set(&fixture.root_pin);

        assert!(matches!(
            validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default(),),
            Err(TzapCertificateProfileError::MalformedMetadata { .. })
        ));
    }
}

#[test]
fn certificate_profile_rejects_symbolic_and_mismatched_metadata_policy_oids() {
    for metadata in [MetadataMode::SymbolicPolicyOid, MetadataMode::MismatchedPolicyOid] {
        let fixture = certificate_fixture(ChainConfig { metadata, ..ChainConfig::default() });
        let pins = current_pin_set(&fixture.root_pin);

        assert!(validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default(),).is_err());
    }
}

#[test]
fn certificate_profile_rejects_root_profile_errors() {
    for config in
        [ChainConfig { root_path_len: 1, ..ChainConfig::default() }, ChainConfig { root_key_usage_extra_digital_signature: true, ..ChainConfig::default() }]
    {
        let fixture = certificate_fixture(config);
        let pins = current_pin_set(&fixture.root_pin);

        assert!(matches!(
            validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default(),),
            Err(TzapCertificateProfileError::RootProfile { .. })
        ));
    }
}

#[test]
fn certificate_profile_rejects_intermediate_path_and_policy_errors() {
    for config in [ChainConfig { platform_path_len: 1, ..ChainConfig::default() }, ChainConfig { omit_platform_ca_policy: true, ..ChainConfig::default() }] {
        let fixture = certificate_fixture(config);
        let pins = current_pin_set(&fixture.root_pin);

        assert!(matches!(
            validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default(),),
            Err(TzapCertificateProfileError::IntermediateProfile { .. })
        ));
    }
}

#[test]
fn certificate_profile_rejects_org_intermediate_without_approved_policy() {
    let fixture = certificate_fixture(ChainConfig { include_org_intermediate: true, omit_org_policy: true, ..ChainConfig::default() });
    let pins = current_pin_set(&fixture.root_pin);
    let mut options = TzapCertificateProfileOptions::default();
    options.approved_org_intermediate_policy_oids.push(TEST_ORG_POLICY_OID.to_owned());

    assert!(matches!(
        validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &options),
        Err(TzapCertificateProfileError::IntermediateProfile { .. })
    ));
}

#[test]
fn certificate_profile_accepts_org_intermediate_with_approved_policy() {
    let fixture = certificate_fixture(ChainConfig { include_org_intermediate: true, ..ChainConfig::default() });
    let pins = current_pin_set(&fixture.root_pin);
    let mut options = TzapCertificateProfileOptions::default();
    options.approved_org_intermediate_policy_oids.push(TEST_ORG_POLICY_OID.to_owned());

    let validation = validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &options).unwrap();

    assert_eq!(validation.trust_anchor_type, TzapTrustAnchorType::OfficialTzap);
}

#[test]
fn certificate_profile_rejects_leaf_eku_for_tls_client_code_and_anyeku() {
    for leaf_eku in [LeafEkuMode::ServerAuth, LeafEkuMode::ClientAuth, LeafEkuMode::CodeSigning, LeafEkuMode::AnyExtendedKeyUsage] {
        let fixture = certificate_fixture(ChainConfig { leaf_eku, ..ChainConfig::default() });
        let pins = current_pin_set(&fixture.root_pin);

        assert!(matches!(
            validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default(),),
            Err(TzapCertificateProfileError::LeafProfile { .. })
        ));
    }
}

#[test]
fn certificate_profile_rejects_leaf_key_usage_and_san_profile_errors() {
    for config in [
        ChainConfig { leaf_key_usage_extra_key_encipherment: true, ..ChainConfig::default() },
        ChainConfig { leaf_validity_days: 181, ..ChainConfig::default() },
        ChainConfig { leaf_san: Some(LeafSanMode::Dns), ..ChainConfig::default() },
        ChainConfig { leaf_san: Some(LeafSanMode::Ip), ..ChainConfig::default() },
    ] {
        let fixture = certificate_fixture(config);
        let pins = current_pin_set(&fixture.root_pin);

        assert!(matches!(
            validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default(),),
            Err(TzapCertificateProfileError::LeafProfile { .. })
        ));
    }
}

#[test]
fn certificate_profile_rejects_aki_ski_mismatch_and_chain_order() {
    let fixture = certificate_fixture(ChainConfig { leaf_aki_from_root: true, ..ChainConfig::default() });
    let pins = current_pin_set(&fixture.root_pin);
    assert!(matches!(
        validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &TzapCertificateProfileOptions::default(),),
        Err(TzapCertificateProfileError::LeafProfile { .. })
    ));

    let mut reordered = certificate_fixture(ChainConfig::default());
    reordered.chain_der.swap(1, 2);
    let pins = current_pin_set(&reordered.root_pin);
    assert!(matches!(
        validate_official_tzap_certificate_chain_der(&reordered.chain_der, &pins, &TzapCertificateProfileOptions::default(),),
        Err(TzapCertificateProfileError::ChainOrder { .. } | TzapCertificateProfileError::RootNotSelfSigned)
    ));
}

#[test]
fn certificate_profile_rejects_expired_certificates() {
    let fixture = certificate_fixture(ChainConfig::default());
    let pins = current_pin_set(&fixture.root_pin);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    let mut options = TzapCertificateProfileOptions { validation_time_unix_seconds: Some(now), ..Default::default() };

    // Valid currently
    assert!(validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &options).is_ok());

    // Expired root/chain (1 day in the past, not yet valid)
    options.validation_time_unix_seconds = Some(now - 86400);
    assert!(matches!(validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &options), Err(TzapCertificateProfileError::Expired { .. })));

    // Expired leaf/chain (100 days in the future, past expiration)
    options.validation_time_unix_seconds = Some(now + 100 * 86400);
    assert!(matches!(validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &options), Err(TzapCertificateProfileError::Expired { .. })));
}

const TEST_ORG_POLICY_OID: &str = "2.25.123456789012345678901234567890123456";
const TEST_OTHER_POLICY_OID: &str = "2.25.999999999999999999999999999999999999";

struct CertificateFixture {
    chain_der: Vec<Vec<u8>>,
    root_pin: String,
}

#[derive(Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
struct ChainConfig {
    include_org_intermediate: bool,
    root_path_len: u32,
    root_key_usage_extra_digital_signature: bool,
    platform_path_len: u32,
    omit_platform_ca_policy: bool,
    omit_org_policy: bool,
    leaf_eku: LeafEkuMode,
    leaf_key_usage_extra_key_encipherment: bool,
    leaf_validity_days: u32,
    leaf_san: Option<LeafSanMode>,
    leaf_aki_from_root: bool,
    metadata: MetadataMode,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            include_org_intermediate: false,
            root_path_len: super::REQUIRED_ROOT_PATH_LEN,
            root_key_usage_extra_digital_signature: false,
            platform_path_len: super::PLATFORM_LEAF_ONLY_PATH_LEN,
            omit_platform_ca_policy: false,
            omit_org_policy: false,
            leaf_eku: LeafEkuMode::DocumentSigning,
            leaf_key_usage_extra_key_encipherment: false,
            leaf_validity_days: 90,
            leaf_san: None,
            leaf_aki_from_root: false,
            metadata: MetadataMode::Valid,
        }
    }
}

#[derive(Clone, Copy)]
enum LeafEkuMode {
    DocumentSigning,
    ServerAuth,
    ClientAuth,
    CodeSigning,
    AnyExtendedKeyUsage,
}

#[derive(Clone, Copy)]
enum LeafSanMode {
    Dns,
    Ip,
}

#[derive(Clone, Copy)]
enum MetadataMode {
    Valid,
    Missing,
    NestedOctetString,
    UnknownField,
    InvalidSignerId,
    InvalidOrgId,
    InvalidDeviceId,
    InvalidAssurance,
    SymbolicPolicyOid,
    MismatchedPolicyOid,
}

fn certificate_fixture(config: ChainConfig) -> CertificateFixture {
    let root_key = p256_private_key();
    let platform_key = p256_private_key();
    let leaf_key = p256_private_key();
    let root = root_certificate(&root_key, config);
    let platform = intermediate_certificate(
        "TZAP Platform Intermediate",
        &platform_key,
        root.as_ref(),
        root_key.as_ref(),
        root.as_ref(),
        if config.include_org_intermediate { super::PLATFORM_PATH_LEN_WITH_ORG_INTERMEDIATE } else { config.platform_path_len },
        if config.omit_platform_ca_policy { &[] } else { &[TZAP_OID_CA_POLICY] },
    );

    let (issuer_cert, issuer_key, org_der) = if config.include_org_intermediate {
        let org_key = p256_private_key();
        let mut policies = vec![TZAP_OID_CA_POLICY];
        if !config.omit_org_policy {
            policies.push(TEST_ORG_POLICY_OID);
        }
        let org = intermediate_certificate(
            "TZAP Organization Intermediate",
            &org_key,
            platform.as_ref(),
            platform_key.as_ref(),
            platform.as_ref(),
            super::ORG_INTERMEDIATE_PATH_LEN,
            &policies,
        );
        let org_der = org.to_der().unwrap();
        (org, org_key, Some(org_der))
    } else {
        (platform.clone(), platform_key, None)
    };

    let aki_source = if config.leaf_aki_from_root { root.as_ref() } else { issuer_cert.as_ref() };
    let leaf = leaf_certificate(&leaf_key, issuer_cert.as_ref(), issuer_key.as_ref(), aki_source, config);

    let root_der = root.to_der().unwrap();
    let mut root_digest = [0_u8; 32];
    root_digest.copy_from_slice(&sha2::Sha256::digest(&root_der));

    let mut chain_der = vec![leaf.to_der().unwrap()];
    if let Some(org_der) = org_der {
        chain_der.push(org_der);
    }
    chain_der.push(platform.to_der().unwrap());
    chain_der.push(root_der);

    CertificateFixture { chain_der, root_pin: format_certificate_sha256(&root_digest) }
}

fn root_certificate(key: &PKeyRef<Private>, config: ChainConfig) -> X509 {
    let mut builder = base_certificate_builder("TZAP Test Root", key, None);
    builder.append_extension(BasicConstraints::new().critical().ca().pathlen(config.root_path_len).build().unwrap()).unwrap();
    let mut key_usage = KeyUsage::new();
    key_usage.critical().key_cert_sign().crl_sign();
    if config.root_key_usage_extra_digital_signature {
        key_usage.digital_signature();
    }
    builder.append_extension(key_usage.build().unwrap()).unwrap();
    append_subject_key_identifier(&mut builder, None);
    builder.sign(key, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn intermediate_certificate(
    common_name: &str,
    key: &PKeyRef<Private>,
    issuer_cert: &X509Ref,
    issuer_key: &PKeyRef<Private>,
    aki_source: &X509Ref,
    path_len: u32,
    policies: &[&str],
) -> X509 {
    let mut builder = base_certificate_builder(common_name, key, Some(issuer_cert));
    builder.append_extension(BasicConstraints::new().critical().ca().pathlen(path_len).build().unwrap()).unwrap();
    builder.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().unwrap()).unwrap();
    append_subject_key_identifier(&mut builder, None);
    append_authority_key_identifier(&mut builder, aki_source);
    if !policies.is_empty() {
        append_der_extension(&mut builder, "2.5.29.32", false, &certificate_policies_der(policies));
    }
    append_der_extension(&mut builder, "2.5.29.31", false, &[0x30, 0x00]);
    builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn leaf_certificate(key: &PKeyRef<Private>, issuer_cert: &X509Ref, issuer_key: &PKeyRef<Private>, aki_source: &X509Ref, config: ChainConfig) -> X509 {
    let mut builder = base_certificate_builder("TZAP Test Signer", key, Some(issuer_cert));
    builder.set_not_after(&Asn1Time::days_from_now(config.leaf_validity_days).unwrap()).unwrap();
    builder.append_extension(BasicConstraints::new().critical().build().unwrap()).unwrap();
    let mut key_usage = KeyUsage::new();
    key_usage.critical().digital_signature();
    if config.leaf_key_usage_extra_key_encipherment {
        key_usage.key_encipherment();
    }
    builder.append_extension(key_usage.build().unwrap()).unwrap();
    builder.append_extension(leaf_eku(config.leaf_eku)).unwrap();
    if let Some(san) = config.leaf_san {
        append_leaf_san(&mut builder, san);
    }
    append_authority_key_identifier(&mut builder, aki_source);
    append_der_extension(&mut builder, "2.5.29.32", false, &certificate_policies_der(&[TZAP_OID_LEAF_POLICY]));
    if !matches!(config.metadata, MetadataMode::Missing) {
        append_der_extension(&mut builder, TZAP_OID_METADATA_EXTENSION, false, &metadata_extension_bytes(config.metadata));
    }
    builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn base_certificate_builder(common_name: &str, key: &PKeyRef<Private>, issuer: Option<&X509Ref>) -> openssl::x509::X509Builder {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&serial_number()).unwrap();
    builder.set_subject_name(&name).unwrap();
    if let Some(issuer) = issuer {
        builder.set_issuer_name(issuer.subject_name()).unwrap();
    } else {
        builder.set_issuer_name(&name).unwrap();
    }
    builder.set_pubkey(key).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(90).unwrap()).unwrap();
    builder
}

fn p256_private_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn serial_number() -> openssl::asn1::Asn1Integer {
    BigNum::from_u32(42).unwrap().to_asn1_integer().unwrap()
}

fn append_subject_key_identifier(builder: &mut openssl::x509::X509Builder, issuer: Option<&X509Ref>) {
    let extension = {
        let context = builder.x509v3_context(issuer, None);
        SubjectKeyIdentifier::new().build(&context).unwrap()
    };
    builder.append_extension(extension).unwrap();
}

fn append_authority_key_identifier(builder: &mut openssl::x509::X509Builder, issuer: &X509Ref) {
    let extension = {
        let context = builder.x509v3_context(Some(issuer), None);
        AuthorityKeyIdentifier::new().keyid(true).build(&context).unwrap()
    };
    builder.append_extension(extension).unwrap();
}

fn append_leaf_san(builder: &mut openssl::x509::X509Builder, mode: LeafSanMode) {
    let extension = {
        let context = builder.x509v3_context(None, None);
        let mut san = SubjectAlternativeName::new();
        match mode {
            LeafSanMode::Dns => {
                san.dns("example.test");
            }
            LeafSanMode::Ip => {
                san.ip("127.0.0.1");
            }
        }
        san.build(&context).unwrap()
    };
    builder.append_extension(extension).unwrap();
}

fn leaf_eku(mode: LeafEkuMode) -> X509Extension {
    let mut eku = ExtendedKeyUsage::new();
    match mode {
        LeafEkuMode::DocumentSigning => {
            eku.other(TZAP_OID_DOCUMENT_SIGNING_EKU);
        }
        LeafEkuMode::ServerAuth => {
            eku.server_auth();
        }
        LeafEkuMode::ClientAuth => {
            eku.client_auth();
        }
        LeafEkuMode::CodeSigning => {
            eku.code_signing();
        }
        LeafEkuMode::AnyExtendedKeyUsage => {
            eku.other("2.5.29.37.0");
        }
    }
    eku.build().unwrap()
}

fn append_der_extension(builder: &mut openssl::x509::X509Builder, oid: &str, critical: bool, contents: &[u8]) {
    let oid = Asn1Object::from_str(oid).unwrap();
    let contents = Asn1OctetString::new_from_bytes(contents).unwrap();
    builder.append_extension(X509Extension::new_from_der(&oid, critical, &contents).unwrap()).unwrap();
}

fn certificate_policies_der(policies: &[&str]) -> Vec<u8> {
    let policy_infos = policies.iter().flat_map(|policy| der_sequence(&der_oid(policy))).collect::<Vec<_>>();
    der_sequence(&policy_infos)
}

fn der_oid(oid: &str) -> Vec<u8> {
    der_wrap(0x06, Asn1Object::from_str(oid).unwrap().as_slice())
}

fn der_sequence(contents: &[u8]) -> Vec<u8> {
    der_wrap(0x30, contents)
}

fn der_octet_string(contents: &[u8]) -> Vec<u8> {
    der_wrap(0x04, contents)
}

fn der_wrap(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(contents.len()));
    out.extend(contents);
    out
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![u8::try_from(len).unwrap()]
    } else if len <= 0xff {
        vec![0x81, u8::try_from(len).unwrap()]
    } else {
        vec![0x82, u8::try_from(len >> 8).unwrap(), u8::try_from(len & 0xff).unwrap()]
    }
}

fn metadata_extension_bytes(mode: MetadataMode) -> Vec<u8> {
    let mut value = json!({
        "version": 1,
        "public_signer_id": "psign_0123456789ABCDEFGH",
        "public_org_id": "porg_0123456789ABCDEFGH",
        "public_device_id": "pdev_0123456789ABCDEFGH",
        "assurance_level": "oauth_verified_email",
        "policy_oid": TZAP_OID_LEAF_POLICY,
    });

    match mode {
        MetadataMode::Valid => {}
        MetadataMode::Missing => unreachable!(),
        MetadataMode::NestedOctetString => {
            return der_octet_string(&metadata_extension_bytes(MetadataMode::Valid));
        }
        MetadataMode::UnknownField => {
            value["unexpected"] = Value::Bool(true);
        }
        MetadataMode::InvalidSignerId => {
            value["public_signer_id"] = Value::String("user_123".to_owned());
        }
        MetadataMode::InvalidOrgId => {
            value["public_org_id"] = Value::String("org_123".to_owned());
        }
        MetadataMode::InvalidDeviceId => {
            value["public_device_id"] = Value::String("device_123".to_owned());
        }
        MetadataMode::InvalidAssurance => {
            value["assurance_level"] = Value::String("verified-ish".to_owned());
        }
        MetadataMode::SymbolicPolicyOid => {
            value["policy_oid"] = Value::String("TBD".to_owned());
        }
        MetadataMode::MismatchedPolicyOid => {
            value["policy_oid"] = Value::String(TEST_OTHER_POLICY_OID.to_owned());
        }
    }

    serde_json_canonicalizer::to_vec(&value).unwrap()
}

fn current_pin_set(root_pin: &str) -> TzapRootPinSet {
    let pin: &'static str = Box::leak(root_pin.to_owned().into_boxed_str());
    let current: &'static [&'static str] = Box::leak(vec![pin].into_boxed_slice());
    TzapRootPinSet { current, planned_successors: &[] }
}

fn planned_successor_pin_set(root_pin: &str) -> TzapRootPinSet {
    let pin: &'static str = Box::leak(root_pin.to_owned().into_boxed_str());
    let planned_successors: &'static [&'static str] = Box::leak(vec![pin].into_boxed_slice());
    TzapRootPinSet { current: &[], planned_successors }
}
