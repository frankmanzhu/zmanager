//! Shared display formatting for X.509 metadata.

use x509_parser::x509::X509Name;

#[must_use]
pub fn x509_name_to_string(name: &X509Name<'_>) -> String {
    let mut parts = Vec::new();
    for attribute in name.iter_attributes() {
        let key = oid_short_name(attribute.attr_type().to_id_string().as_str()).unwrap_or("OID");
        let value = attribute_string_value(attribute).unwrap_or_else(|| hex_lower(attribute.as_slice()));
        parts.push(format!("{key}={value}"));
    }
    parts.join(", ")
}

/// Decodes an attribute value the way OpenSSL's `ASN1_STRING_to_UTF8` does for
/// the common string types: the four `x509-parser` supports natively, plus
/// BMPString (UTF-16BE) and TeletexString (Latin-1).
fn attribute_string_value(attribute: &x509_parser::x509::AttributeTypeAndValue<'_>) -> Option<String> {
    if let Ok(value) = attribute.as_str() {
        return Some(value.to_owned());
    }
    let any = attribute.attr_value();
    match any.tag() {
        x509_parser::asn1_rs::Tag::BmpString => decode_bmp_string(any.data),
        x509_parser::asn1_rs::Tag::TeletexString => Some(String::from_utf8_lossy(any.data).into_owned()),
        _ => None,
    }
}

/// Decodes a BMPString (big-endian UTF-16 code units).
fn decode_bmp_string(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        units.push(u16::from_be_bytes([pair[0], pair[1]]));
    }
    String::from_utf16(&units).ok()
}

/// Short names for the common DN attribute OIDs, matching the OpenSSL NID
/// short names the pre-migration formatter produced. Unknown OIDs fall back
/// to `OID`, as before.
fn oid_short_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "STREET",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.13" => "description",
        "2.5.4.15" => "businessCategory",
        "2.5.4.17" => "postalCode",
        "2.5.4.42" => "GN",
        "2.5.4.43" => "initials",
        "2.5.4.44" => "generationQualifier",
        "2.5.4.46" => "dnQualifier",
        "2.5.4.65" => "pseudonym",
        "2.5.4.97" => "organizationIdentifier",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "1.2.840.113549.1.9.2" => "unstructuredName",
        "1.3.6.1.4.1.311.60.2.1.1" => "jurisdictionLocalityName",
        "1.3.6.1.4.1.311.60.2.1.2" => "jurisdictionStateOrProvinceName",
        "1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionCountryName",
        _ => return None,
    })
}

#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    crate::hex::hex_lower(bytes)
}
