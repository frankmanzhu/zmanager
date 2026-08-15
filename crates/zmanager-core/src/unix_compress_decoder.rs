//! Native Unix `compress` (`.Z`) stream decoder.
//!
//! Ported from libarchive's internal LZW decompressor in
//! `archive_read_support_filter_compress.c`:
//!
//! ```text
//! Copyright (c) 2003-2007 Tim Kientzle
//! BSD-2-Clause.
//!
//! Derived from the BSD compress source code:
//! Copyright (c) 1985, 1986, 1992, 1993 The Regents of the University of
//! California. All rights reserved.
//! ```
//!
//! libarchive implements the whole decompressor in-process ("LZW
//! decompression is pretty simple"); this module is a direct translation of
//! that implementation and replaces the previous external `uncompress`
//! process invocation.

use std::io::{self, Read};

/// Output chunk size, matching libarchive's `out_block_size`.
const OUT_BLOCK_SIZE: usize = 64 * 1024;

/// Dictionary size: codes 0..65535.
const DICTIONARY_SIZE: usize = 65536;

/// Worst-case expansion scratch space, matching libarchive's 65300-byte
/// stack (the longest dictionary entry is 65536 - 256 bytes).
const STACK_CAPACITY: usize = 65300;

/// Streaming decoder for Unix compress (`.Z`) data.
pub struct UnixCompressReader<R> {
    inner: R,
    end_of_stream: bool,

    // Input bit state.
    bit_buffer: u32,
    bits_avail: u32,
    bytes_in_section: u64,

    // Decompression status.
    maxcode: i32,
    maxcode_bits: u32,
    section_end_code: i32,
    bits: u32,
    oldcode: i32,
    finbyte: u8,
    free_ent: i32,
    use_reset_code: bool,

    // Dictionary.
    suffix: Vec<u8>,
    prefix: Vec<u16>,

    // Scratch area for expanding dictionary entries; entries are pushed in
    // reverse order and popped from the top.
    stack: Vec<u8>,
    stack_len: usize,

    // Decoded bytes not yet handed out.
    out: Vec<u8>,
    out_len: usize,
    out_pos: usize,
}

impl<R: Read> UnixCompressReader<R> {
    /// Validates the compress header (magic, reserved bits, and code-width
    /// parameters) and initializes the decompressor.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidData` error for a missing magic or invalid
    /// compression parameters.
    pub fn new(inner: R) -> io::Result<Self> {
        let mut reader = Self {
            inner,
            end_of_stream: false,
            bit_buffer: 0,
            bits_avail: 0,
            bytes_in_section: 0,
            maxcode: 0,
            maxcode_bits: 0,
            section_end_code: 0,
            bits: 0,
            oldcode: -1,
            finbyte: 0,
            free_ent: 0,
            use_reset_code: false,
            suffix: vec![0_u8; DICTIONARY_SIZE],
            prefix: vec![0_u16; DICTIONARY_SIZE],
            stack: Vec::with_capacity(STACK_CAPACITY),
            stack_len: 0,
            out: Vec::with_capacity(OUT_BLOCK_SIZE),
            out_len: 0,
            out_pos: 0,
        };

        let first = reader.getbits(8).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated compress stream"))?;
        let second = reader.getbits(8).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated compress stream"))?;
        if first != 0x1f || second != 0x9d {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not a compress stream"));
        }

        let parameters = reader.getbits(8).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated compress stream"))?;
        if parameters & 0x20 != 0 || parameters & 0x40 != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid compress stream parameters"));
        }
        reader.maxcode_bits = u32::try_from(parameters & 0x1f).unwrap_or(16);
        if reader.maxcode_bits > 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid compressed data"));
        }
        reader.maxcode = 1_i32 << reader.maxcode_bits;
        reader.use_reset_code = parameters & 0x80 != 0;

        // Initialize the decompressor.
        reader.free_ent = 256;
        if reader.use_reset_code {
            reader.free_ent += 1;
        }
        reader.bits = 9;
        reader.section_end_code = (1_i32 << reader.bits) - 1;
        for code in (0..=255).rev() {
            reader.prefix[code] = 0;
            reader.suffix[code] = u8::try_from(code).unwrap_or(0);
        }
        reader.next_code()?;

        Ok(reader)
    }

    /// Returns the next `n` bits from the stream, or `None` at end of data.
    fn getbits(&mut self, n: u32) -> Option<i32> {
        const MASK: [i32; 17] = [0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff, 0xfff, 0x1fff, 0x3fff, 0x7fff, 0xffff];

        while self.bits_avail < n {
            let mut byte = [0_u8; 1];
            match self.inner.read(&mut byte) {
                Ok(0) => return None,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return None,
            }
            self.bit_buffer |= u32::from(byte[0]) << self.bits_avail;
            self.bits_avail += 8;
            self.bytes_in_section += 1;
        }

        let code = self.bit_buffer;
        self.bit_buffer >>= n;
        self.bits_avail -= n;

        // The mask caps the value at `n` bits (at most 16, the widest
        // compress code), so the u32-to-i32 conversion cannot wrap.
        #[allow(clippy::cast_possible_wrap)]
        Some(code as i32 & MASK[usize::try_from(n).unwrap_or(0)])
    }

    /// Processes the next code, pushing its expansion onto the stack.
    ///
    /// Returns `Ok(false)` at clean end of stream.
    fn next_code(&mut self) -> io::Result<bool> {
        loop {
            let Some(mut code) = self.getbits(self.bits) else {
                return Ok(false);
            };
            let newcode = code;

            // Reset code: reset the dictionary and skip the byte-alignment
            // junk the original compress implementation inserts.
            if code == 256 && self.use_reset_code {
                let mut skip_bytes = self.bits - u32::try_from(self.bytes_in_section % u64::from(self.bits)).unwrap_or(0);
                skip_bytes %= self.bits;
                self.bits_avail = 0; // Discard the rest of this byte.
                while skip_bytes > 0 {
                    if self.getbits(8).is_none() {
                        return Ok(false);
                    }
                    skip_bytes -= 1;
                }
                self.bytes_in_section = 0;
                self.bits = 9;
                self.section_end_code = (1_i32 << self.bits) - 1;
                self.free_ent = 257;
                self.oldcode = -1;
                continue;
            }

            if code > self.free_ent || (code == self.free_ent && self.oldcode < 0) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid compressed data"));
            }

            // Special case for KwKwK strings.
            if code >= self.free_ent {
                self.push_stack(self.finbyte)?;
                code = self.oldcode;
            }

            // Expand the code into output characters in reverse order.
            while code >= 256 {
                self.push_stack(self.suffix[usize::try_from(code).unwrap_or(0)])?;
                code = i32::from(self.prefix[usize::try_from(code).unwrap_or(0)]);
            }
            self.finbyte = u8::try_from(code).unwrap_or(0);
            self.push_stack(self.finbyte)?;

            // Generate the new dictionary entry.
            let mut code = self.free_ent;
            if code < self.maxcode && self.oldcode >= 0 {
                self.prefix[usize::try_from(code).unwrap_or(0)] = u16::try_from(self.oldcode).unwrap_or(0);
                self.suffix[usize::try_from(code).unwrap_or(0)] = self.finbyte;
                code += 1;
                self.free_ent = code;
            }
            if self.free_ent > self.section_end_code {
                self.bits += 1;
                self.bytes_in_section = 0;
                self.section_end_code = if self.bits == self.maxcode_bits { self.maxcode } else { (1_i32 << self.bits) - 1 };
            }

            self.oldcode = newcode;
            return Ok(true);
        }
    }

    /// Pushes one byte onto the expansion stack.
    fn push_stack(&mut self, byte: u8) -> io::Result<()> {
        if self.stack_len >= STACK_CAPACITY {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "compress stream dictionary entry too long"));
        }
        if self.stack_len == self.stack.len() {
            self.stack.push(byte);
        } else {
            self.stack[self.stack_len] = byte;
        }
        self.stack_len += 1;
        Ok(())
    }

    /// Fills `self.out` with the next chunk of decoded bytes.
    fn fill_out_block(&mut self) -> io::Result<()> {
        self.out.clear();
        self.out_len = 0;
        while self.out_len < OUT_BLOCK_SIZE && !self.end_of_stream {
            if self.stack_len > 0 {
                self.stack_len -= 1;
                self.out.push(self.stack[self.stack_len]);
                self.out_len += 1;
            } else if !self.next_code()? {
                self.end_of_stream = true;
            }
        }
        self.out_pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for UnixCompressReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.out_pos < self.out_len {
                let remaining = &self.out[self.out_pos..self.out_len];
                let take = remaining.len().min(buffer.len());
                buffer[..take].copy_from_slice(&remaining[..take]);
                self.out_pos += take;
                return Ok(take);
            }
            if self.end_of_stream {
                return Ok(0);
            }
            self.fill_out_block()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UnixCompressReader;
    use std::io::Read as _;

    /// `compress` of the single byte `A` without reset codes
    /// (params `0x10` = `maxcode_bits` 16, no block mode): literal 65, then
    /// end of data.
    const SINGLE_A_COMPRESS: &[u8] = &[0x1f, 0x9d, 0x10, 0x41, 0x00];

    /// Same payload in block mode (`0x90`): clear code, the byte-alignment
    /// junk the original compress implementation inserts after each reset,
    /// literal 65, then end of data. The junk count follows libarchive's
    /// section accounting, which includes the three header bytes: 9 bits -
    /// (3 header + 2 clear-code bytes) = 4 junk bytes.
    const SINGLE_A_COMPRESS_BLOCK_MODE: &[u8] = &[0x1f, 0x9d, 0x90, 0x00, 0x01, 0x55, 0x55, 0x55, 0x55, 0x41, 0x00];

    #[test]
    fn decodes_single_byte_stream() {
        let mut reader = UnixCompressReader::new(SINGLE_A_COMPRESS).unwrap();
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, b"A");
    }

    #[test]
    fn decodes_block_mode_stream_with_reset_codes() {
        let mut reader = UnixCompressReader::new(SINGLE_A_COMPRESS_BLOCK_MODE).unwrap();
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, b"A");
    }

    #[test]
    fn rejects_bad_magic() {
        let error = UnixCompressReader::new(b"\x1f\x9c\x90".as_slice()).err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_reserved_parameter_bits() {
        let error = UnixCompressReader::new(&[0x1f, 0x9d, 0x90 | 0x20][..]).err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_code_widths_above_sixteen() {
        // 0x9f: maxcode_bits = 31 with no reserved bits.
        let error = UnixCompressReader::new(&[0x1f, 0x9d, 0x9f][..]).err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
