pub(crate) const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
        output.push(char::from(HEX_UPPER[usize::from(byte & 0x0f)]));
    }
    output
}
