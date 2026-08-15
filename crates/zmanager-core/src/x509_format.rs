//! Shared display formatting for X.509 metadata.

use x509_parser::x509::X509Name;

#[must_use]
pub fn x509_name_to_string(name: &X509Name<'_>) -> String {
    let mut parts = Vec::new();
    for attribute in name.iter_attributes() {
        let key = oid_short_name(attribute.attr_type().to_id_string().as_str()).unwrap_or("OID");
        let value = attribute.as_str().map_or_else(|_| hex_lower(attribute.as_slice()), str::to_owned);
        parts.push(format!("{key}={value}"));
    }
    parts.join(", ")
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
        "2.5.4.42" => "GN",
        "2.5.4.43" => "initials",
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
