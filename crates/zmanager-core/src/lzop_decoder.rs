//! Native LZOP (`.lzo`) stream decoder.
//!
//! The lzop container framing (header layout, block framing, checksum rules,
//! and multipart re-header handling) is ported from libarchive's
//! `archive_read_support_filter_lzop.c`:
//!
//! ```text
//! Copyright (c) 2003-2007 Tim Kientzle
//! Copyright (c) 2012 Michihiro NAKAJIMA
//! BSD-2-Clause.
//! ```
//!
//! Raw LZO1X block decompression is delegated to the Apache-2.0 `lzo` crate
//! (<https://github.com/SecurityRonin/lzo>), a pure-Rust, bounds-checked
//! decoder for blocks produced by `lzo1x_1`, `lzo1x_1_15`, and `lzo1x_999`
//! (the liblzo2 / lzop family). This replaces the previous external `lzop`
//! process invocation.

use std::io::{self, Read};

/// lzop container magic (`\x89LZO\0\r\n\x1a\n`).
const LZOP_HEADER_MAGIC: [u8; 9] = [0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a];

/// Header flag: stored uncompressed-data checksum is ADLER32 (else CRC32).
const FLAG_ADLER32_UNCOMPRESSED: u32 = 0x0001;
/// Header flag: stored compressed-data checksum is ADLER32 (else CRC32).
const FLAG_ADLER32_COMPRESSED: u32 = 0x0002;
/// Header flag: an extra field follows the header checksum.
const FLAG_EXTRA_FIELD: u32 = 0x0040;
/// Header flag: a filter name field is present.
const FLAG_FILTER: u32 = 0x0800;
/// Header flag: stored uncompressed-data checksum is CRC32.
const FLAG_CRC32_UNCOMPRESSED: u32 = 0x0100;
/// Header flag: stored compressed-data checksum is CRC32.
const FLAG_CRC32_COMPRESSED: u32 = 0x0200;
/// Header flag: the header checksum is CRC32 (else ADLER32).
const FLAG_CRC32_HEADER: u32 = 0x1000;

/// Largest accepted block size, matching libarchive's guard against
/// allocation bombs in hostile input.
const MAX_BLOCK_SIZE: usize = 64 * 1024 * 1024;

/// Streaming decoder for lzop-compressed data.
///
/// The lzop stream is read from the wrapped reader: one 9-byte magic, one
/// header, then a sequence of blocks. A block whose uncompressed size is
/// zero ends the stream; for multipart lzop files another magic + header
/// may follow, otherwise EOF.
pub struct LzopReader<R> {
    inner: R,
    /// Flags from the most recent header; they govern block checksums.
    flags: u32,
    /// Decoded bytes of the current block not yet handed out.
    out: Vec<u8>,
    out_pos: usize,
    finished: bool,
}

impl<R: Read> LzopReader<R> {
    /// Reads and validates the lzop header, or fails when the stream does
    /// not begin with the lzop magic.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidData` error for a missing magic, unsupported
    /// method/level, or a corrupted header checksum.
    pub fn new(inner: R) -> io::Result<Self> {
        let mut reader = Self { inner, flags: 0, out: Vec::new(), out_pos: 0, finished: false };
        reader.consume_header()?;
        Ok(reader)
    }

    /// Parses one lzop header (magic through the optional extra field).
    fn consume_header(&mut self) -> io::Result<()> {
        let mut magic = [0_u8; 9];
        self.read_exact_or_eof(&mut magic)?;
        if magic != LZOP_HEADER_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not an lzop stream"));
        }
        self.flags = self.parse_header_after_magic()?;
        Ok(())
    }

    /// Parses the header fields that follow the magic and returns the
    /// header flags.
    fn parse_header_after_magic(&mut self) -> io::Result<u32> {
        // Every byte after the magic up to and including the filename is
        // checksummed; accumulate it while parsing.
        let mut header = Vec::new();

        let mut byte = [0_u8; 1];
        let mut short = [0_u8; 2];
        let mut word = [0_u8; 4];

        // version (2) + library version (2).
        self.read_exact_or_eof(&mut short)?;
        header.extend_from_slice(&short);
        let version = u16::from_be_bytes(short);
        self.read_exact_or_eof(&mut short)?;
        header.extend_from_slice(&short);

        if version >= 0x0940 {
            self.read_exact_or_eof(&mut short)?;
            header.extend_from_slice(&short);
            let required_version = u16::from_be_bytes(short);
            if required_version < 0x0900 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "lzop stream requires an unsupported version"));
            }
        }

        self.read_exact_or_eof(&mut byte)?;
        header.extend_from_slice(&byte);
        let method = byte[0];
        if !(1..=3).contains(&method) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "lzop stream uses an unsupported compression method"));
        }

        if version >= 0x0940 {
            self.read_exact_or_eof(&mut byte)?;
            header.extend_from_slice(&byte);
            if byte[0] > 9 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "lzop stream uses an invalid compression level"));
            }
        }

        self.read_exact_or_eof(&mut word)?;
        header.extend_from_slice(&word);
        let flags = u32::from_be_bytes(word);
        if flags & FLAG_FILTER != 0 {
            self.read_exact_or_eof(&mut word)?; // Skip filter name.
            header.extend_from_slice(&word);
        }
        self.read_exact_or_eof(&mut word)?; // Skip mode.
        header.extend_from_slice(&word);
        if version >= 0x0940 {
            let mut mtime = [0_u8; 8];
            self.read_exact_or_eof(&mut mtime)?;
            header.extend_from_slice(&mtime);
        } else {
            self.read_exact_or_eof(&mut word)?;
            header.extend_from_slice(&word);
        }
        self.read_exact_or_eof(&mut byte)?;
        header.extend_from_slice(&byte);
        let mut filename = vec![0_u8; usize::from(byte[0])];
        self.read_exact_or_eof(&mut filename)?;
        header.extend_from_slice(&filename);

        self.read_exact_or_eof(&mut word)?;
        let stored_checksum = u32::from_be_bytes(word);
        let computed_checksum = if flags & FLAG_CRC32_HEADER != 0 { crc32(&header) } else { adler32(&header) };
        if stored_checksum != computed_checksum {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupted lzop header"));
        }

        if flags & FLAG_EXTRA_FIELD != 0 {
            self.read_exact_or_eof(&mut word)?;
            let extra_len = u32::from_be_bytes(word);
            let extra_len = usize::try_from(extra_len).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "oversized lzop extra field"))?;
            let mut extra = vec![0_u8; extra_len];
            self.read_exact_or_eof(&mut extra)?;
        }

        Ok(flags)
    }

    /// Reads exactly `buffer.len()` bytes or fails cleanly at EOF.
    fn read_exact_or_eof(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        self.inner.read_exact(buffer).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof { io::Error::new(io::ErrorKind::InvalidData, "truncated lzop stream") } else { error }
        })
    }

    /// Decodes the next block into `self.out`.
    ///
    /// Returns `Ok(false)` at end of stream.
    fn next_block(&mut self) -> io::Result<bool> {
        let mut size = [0_u8; 4];
        self.read_exact_or_eof(&mut size)?;
        let uncompressed_size = u32::from_be_bytes(size);
        if uncompressed_size == 0 {
            // Multipart lzop: another header may follow; anything else ends
            // the stream.
            let mut magic = [0_u8; 9];
            let mut read = 0;
            while read < magic.len() {
                match self.inner.read(&mut magic[read..]) {
                    Ok(0) => return Ok(false),
                    Ok(count) => read += count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            if magic != LZOP_HEADER_MAGIC {
                return Ok(false);
            }
            self.flags = self.parse_header_after_magic()?;
            return self.next_block();
        }

        let uncompressed_size = usize::try_from(uncompressed_size).unwrap_or(usize::MAX);
        if uncompressed_size > MAX_BLOCK_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "lzop block exceeds the 64 MiB limit"));
        }

        self.read_exact_or_eof(&mut size)?;
        let compressed_size = usize::try_from(u32::from_be_bytes(size)).unwrap_or(usize::MAX);
        if compressed_size > uncompressed_size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupted lzop block"));
        }

        let flags = self.flags;
        let mut checksum_bytes = [0_u8; 4];
        let uncompressed_checksum = if flags & (FLAG_CRC32_UNCOMPRESSED | FLAG_ADLER32_UNCOMPRESSED) != 0 {
            self.read_exact_or_eof(&mut checksum_bytes)?;
            Some(u32::from_be_bytes(checksum_bytes))
        } else {
            None
        };
        let compressed_checksum = if flags & (FLAG_CRC32_COMPRESSED | FLAG_ADLER32_COMPRESSED) != 0 && compressed_size < uncompressed_size {
            self.read_exact_or_eof(&mut checksum_bytes)?;
            Some(u32::from_be_bytes(checksum_bytes))
        } else {
            None
        };

        let mut data = vec![0_u8; compressed_size];
        self.read_exact_or_eof(&mut data)?;

        if let Some(checksum) = compressed_checksum {
            let computed = if flags & FLAG_CRC32_COMPRESSED != 0 { crc32(&data) } else { adler32(&data) };
            if computed != checksum {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupted lzop block"));
            }
        }

        // A block stored uncompressed needs no LZO pass.
        let decoded = if compressed_size == uncompressed_size {
            data
        } else {
            lzo::decompress(&data, uncompressed_size)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("lzop block decompression failed: {error}")))?
        };
        if decoded.len() != uncompressed_size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "lzop block decompressed to an unexpected size"));
        }

        if let Some(checksum) = uncompressed_checksum {
            let computed = if flags & FLAG_CRC32_UNCOMPRESSED != 0 { crc32(&decoded) } else { adler32(&decoded) };
            if computed != checksum {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupted lzop block"));
            }
        }

        self.out = decoded;
        self.out_pos = 0;
        Ok(true)
    }
}

impl<R: Read> Read for LzopReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.out_pos < self.out.len() {
                let remaining = &self.out[self.out_pos..];
                let take = remaining.len().min(buffer.len());
                buffer[..take].copy_from_slice(&remaining[..take]);
                self.out_pos += take;
                return Ok(take);
            }
            if self.finished {
                return Ok(0);
            }
            if !self.next_block()? {
                self.finished = true;
            }
        }
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

fn adler32(data: &[u8]) -> u32 {
    adler2::adler32_slice(data)
}

#[cfg(test)]
mod tests {
    use super::LzopReader;
    use std::io::Read as _;

    /// Builds a minimal valid lzop stream with one stored (uncompressed)
    /// block and no optional checksums, exercising header parsing, checksum
    /// verification, stored-block passthrough, and EOF handling.
    fn stored_lzop_stream(payload: &[u8]) -> Vec<u8> {
        let mut stream = Vec::new();
        stream.extend_from_slice(&[0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a]);

        let mut header = Vec::new();
        header.extend_from_slice(&0x1030_u16.to_be_bytes()); // version
        header.extend_from_slice(&0x2080_u16.to_be_bytes()); // library version
        header.extend_from_slice(&0x0940_u16.to_be_bytes()); // required version
        header.push(1); // method lzo1x-1
        header.push(5); // level
        header.extend_from_slice(&0_u32.to_be_bytes()); // flags
        header.extend_from_slice(&0_u32.to_be_bytes()); // mode
        header.extend_from_slice(&0_u64.to_be_bytes()); // mtime
        header.push(0); // empty filename
        stream.extend_from_slice(&header);
        stream.extend_from_slice(&adler2::adler32_slice(&header).to_be_bytes());

        stream.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes()); // uncompressed size
        stream.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes()); // compressed size
        stream.extend_from_slice(payload);
        stream.extend_from_slice(&0_u32.to_be_bytes()); // end of stream
        stream
    }

    #[test]
    fn decodes_stored_block_stream() {
        let payload = b"lzop stored block payload";
        let stream = stored_lzop_stream(payload);
        let mut reader = LzopReader::new(stream.as_slice()).unwrap();
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rejects_bad_magic() {
        let error = LzopReader::new(b"not lzop at all".as_slice()).err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_corrupted_header_checksum() {
        let mut stream = stored_lzop_stream(b"payload");
        // Flip a byte inside the version field, outside the magic.
        stream[10] ^= 0xff;
        let error = LzopReader::new(stream.as_slice()).err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("corrupted lzop header"), "{error}");
    }

    #[test]
    fn rejects_oversized_block_declaration() {
        let mut stream = stored_lzop_stream(b"payload");
        // The block-size fields start right after the header checksum: 9
        // magic + 25 header + 4 checksum.
        let block_size_offset = 9 + 25 + 4;
        stream[block_size_offset..block_size_offset + 4].copy_from_slice(&(70 * 1024 * 1024_u32).to_be_bytes());
        let mut reader = LzopReader::new(stream.as_slice()).unwrap();
        let mut decoded = Vec::new();
        let error = reader.read_to_end(&mut decoded).err().unwrap();
        assert!(error.to_string().contains("64 MiB"), "{error}");
    }
}
