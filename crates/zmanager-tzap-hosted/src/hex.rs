pub(crate) const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
        output.push(char::from(HEX_UPPER[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_upper() {
        assert_eq!(hex_upper(&[]), "");
        assert_eq!(hex_upper(&[0x00, 0x0f, 0x10, 0xab, 0xff]), "000F10ABFF");
    }
}
