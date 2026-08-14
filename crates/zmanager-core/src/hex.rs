//! Shared hex encoding tables and helpers.
//!
//! Historically each module shipped its own nibble tables and loops
//! (`trust`, `x509_format`); this is the
//! single implementation so the schemes cannot drift.

pub(crate) const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
pub(crate) const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Lower-case hex encoding.
#[must_use]
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        output.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    output
}

/// Upper-case hex encoding.
#[must_use]
pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
        output.push(char::from(HEX_UPPER[usize::from(byte & 0x0f)]));
    }
    output
}
