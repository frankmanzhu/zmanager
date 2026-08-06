//! Shared display formatting for X.509 metadata.

use openssl::x509::X509NameRef;

#[must_use]
pub fn x509_name_to_string(name: &X509NameRef) -> String {
    let mut parts = Vec::new();
    for entry in name.entries() {
        let key = entry.object().nid().short_name().unwrap_or("OID");
        let value = entry.data().to_string().unwrap_or_else(|_| hex_lower(entry.data().as_slice()));
        parts.push(format!("{key}={value}"));
    }
    parts.join(", ")
}

#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    crate::hex::hex_lower(bytes)
}
