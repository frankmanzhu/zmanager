//! Native uuencode / base64 text filter decoder (`.uu`, `.b64`).
//!
//! Ported from libarchive's `archive_read_support_filter_uu.c`:
//!
//! ```text
//! Copyright (c) 2009-2011 Michihiro NAKAJIMA
//! BSD-2-Clause.
//! ```
//!
//! The filter reads a text stream of `begin <mode> <name>` / `begin-base64
//! <mode> <name>` header lines followed by uuencoded or base64 body lines,
//! and emits the decoded bytes. Multi-part streams (several `begin` sections
//! in one file) are decoded in sequence; anything after the final `end` /
//! `====` line is ignored.

use std::io::{self, Read};

/// Maximum bytes scanned while searching for a `begin` line, matching
/// libarchive's `UUENCODE_BID_MAX_READ`. The port applies the cap
/// cumulatively across refills, where libarchive only caps within one
/// buffer refill; the cumulative cap closes a slow-scan gap on hostile
/// input.
const MAX_SCAN: usize = 128 * 1024;
/// Maximum accepted line length, matching libarchive.
const MAX_LINE: usize = 128 * 1024;
/// Decoded output chunk size, matching libarchive's `OUT_BUFF_SIZE`.
const OUT_BUFF_SIZE: usize = 64 * 1024;

/// Decoder state machine, mirroring libarchive's `ST_*` states.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum State {
    /// Searching for the next `begin` / `begin-base64` header line.
    FindHead,
    /// Decoding uuencoded body lines.
    ReadUu,
    /// Expecting the `end ` line after a zero-count uuencode line.
    UuEnd,
    /// Decoding base64 body lines.
    ReadBase64,
    /// Data appeared after the payload; everything remaining is ignored.
    Ignore,
}

/// Streaming decoder for uuencode / base64 text streams.
pub struct UuDecoder<R> {
    inner: R,
    state: State,
    /// Raw input buffered from `inner`; `pos` marks consumed bytes.
    input: Vec<u8>,
    pos: usize,
    /// Bytes scanned in `FindHead` since the last header (cumulative cap).
    scanned: usize,
    /// Cumulative decoded bytes (drives the ignore-and-fail semantics).
    total: u64,
    /// Decoded bytes not yet handed out.
    out: Vec<u8>,
    out_pos: usize,
    finished: bool,
}

impl<R: Read> UuDecoder<R> {
    /// Wraps a reader. Header validation happens lazily on the first read:
    /// a stream without a `begin` line fails with `InvalidData`.
    #[must_use]
    pub fn new(inner: R) -> Self {
        Self { inner, state: State::FindHead, input: Vec::new(), pos: 0, scanned: 0, total: 0, out: Vec::new(), out_pos: 0, finished: false }
    }

    /// Decodes the next chunk of output into `self.out`.
    fn fill(&mut self) -> io::Result<()> {
        self.out.clear();
        self.out_pos = 0;
        let mut produced = 0_usize;

        loop {
            // Compact already-consumed input.
            if self.pos > 0 {
                self.input.drain(..self.pos);
                self.pos = 0;
            }
            if self.state == State::Ignore {
                self.input.clear();
                return Ok(());
            }

            // Locate the next line end, validating characters as we go.
            let mut content_end = None;
            let mut nl_size = 0_usize;
            let mut idx = self.pos;
            while idx < self.input.len() {
                match self.input[idx] {
                    b'\n' => {
                        nl_size = 1;
                        content_end = Some(idx);
                        break;
                    }
                    b'\r' => {
                        nl_size = if idx + 1 < self.input.len() && self.input[idx + 1] == b'\n' { 2 } else { 1 };
                        content_end = Some(idx);
                        break;
                    }
                    byte if (0x20..=0x7e).contains(&byte) => idx += 1,
                    _ => {
                        // Non-ascii or control character.
                        if self.state == State::FindHead && (self.total > 0 || produced > 0) {
                            self.state = State::Ignore;
                            self.input.clear();
                            return Ok(());
                        }
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient uuencode data"));
                    }
                }
            }

            let Some(content_end) = content_end else {
                // No complete line yet: cap the pending line, then read more.
                if self.input.len() - self.pos > MAX_LINE {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid uuencode line length"));
                }
                let mut chunk = vec![0_u8; 32 * 1024];
                match self.inner.read(&mut chunk) {
                    Ok(0) => {
                        // End of stream. A clean EOF with nothing pending
                        // finishes normally.
                        if self.pos == self.input.len() {
                            self.finished = true;
                            return Ok(());
                        }
                        // End of stream with a partial (unterminated) line.
                        let partial = self.input[self.pos..].to_vec();
                        if self.state == State::UuEnd {
                            self.process_line(&partial, &mut produced)?;
                        } else if produced == 0 {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "missing uuencode format data"));
                        } else {
                            // Trailing partial line after decoded data is
                            // dropped (libarchive errors on a later call;
                            // the port ends cleanly instead).
                        }
                        self.finished = true;
                        return Ok(());
                    }
                    Ok(count) => self.input.extend_from_slice(&chunk[..count]),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
                continue;
            };

            let content = self.input[self.pos..content_end].to_vec();
            let line_len = content.len() + nl_size;

            // The output cap runs before decoding a body line; a line that
            // cannot fit with the current output ends this refill.
            if matches!(self.state, State::ReadUu | State::ReadBase64) && self.out.len() + line_len * 2 > OUT_BUFF_SIZE {
                if self.out.is_empty() {
                    self.finished = true;
                }
                return Ok(());
            }

            self.pos = content_end + nl_size;
            self.process_line(&content, &mut produced)?;
        }
    }

    /// Runs one complete line through the state machine, appending decoded
    /// bytes to `self.out`.
    fn process_line(&mut self, line: &[u8], produced: &mut usize) -> io::Result<()> {
        match self.state {
            State::FindHead => self.find_header(line),
            State::ReadUu => self.decode_uu_line(line, produced),
            State::UuEnd => self.expect_end_line(line),
            State::ReadBase64 => self.decode_base64_line(line, produced),
            State::Ignore => unreachable!("ignore state is handled by the refill loop"),
        }
    }

    /// Searches for the next `begin` / `begin-base64` header line.
    fn find_header(&mut self, line: &[u8]) -> io::Result<()> {
        self.scanned += line.len() + 1;
        if self.scanned > MAX_SCAN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid uuencode format data"));
        }
        let offset = if line.len() >= 11 && line.starts_with(b"begin ") {
            Some(6_usize)
        } else if line.len() >= 18 && line.starts_with(b"begin-base64 ") {
            Some(13_usize)
        } else {
            None
        };
        let Some(offset) = offset else {
            return Ok(());
        };
        let valid_mode = line
            .get(offset..offset + 4)
            .is_some_and(|mode| (b'0'..=b'7').contains(&mode[0]) && (b'0'..=b'7').contains(&mode[1]) && (b'0'..=b'7').contains(&mode[2]) && mode[3] == b' ');
        if valid_mode {
            self.state = if offset == 6 { State::ReadUu } else { State::ReadBase64 };
            self.scanned = 0;
        }
        Ok(())
    }

    /// Decodes one uuencoded body line.
    fn decode_uu_line(&mut self, line: &[u8], produced: &mut usize) -> io::Result<()> {
        let Some(&first) = line.first() else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient uuencode data"));
        };
        if !is_uu_char(first) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient uuencode data"));
        }
        let mut count = usize::from(uu_decode(first));
        let body = line.len() - 1;
        if count > body {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient uuencode data"));
        }
        if count == 0 {
            self.state = State::UuEnd;
            return Ok(());
        }
        let mut cursor = 1_usize;
        while count > 0 {
            // libarchive reads past the body into the newline byte, whose
            // lookup fails the character check; the port uses bounds-checked
            // access with the same failure.
            let (Some(&first_char), Some(&second_char)) = (line.get(cursor), line.get(cursor + 1)) else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient uuencode data"));
            };
            if !is_uu_char(first_char) || !is_uu_char(second_char) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient uuencode data"));
            }
            let mut value = u32::from(uu_decode(first_char)) << 18;
            value |= u32::from(uu_decode(second_char)) << 12;
            self.out.push(u8::try_from(value >> 16).unwrap_or(0));
            *produced += 1;
            count -= 1;
            cursor += 2;
            if count > 0 {
                let Some(&next_char) = line.get(cursor) else {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient uuencode data"));
                };
                if !is_uu_char(next_char) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient uuencode data"));
                }
                value |= u32::from(uu_decode(next_char)) << 6;
                self.out.push(u8::try_from((value >> 8) & 0xff).unwrap_or(0));
                *produced += 1;
                count -= 1;
                cursor += 1;
            }
            if count > 0 {
                let Some(&next_char) = line.get(cursor) else {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient uuencode data"));
                };
                if !is_uu_char(next_char) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient uuencode data"));
                }
                value |= u32::from(uu_decode(next_char));
                self.out.push(u8::try_from(value & 0xff).unwrap_or(0));
                *produced += 1;
                count -= 1;
                cursor += 1;
            }
        }
        Ok(())
    }

    /// Expects the uuencode end line: exactly the three bytes `end`
    /// (libarchive's check is `memcmp(b, "end ", 3)`).
    fn expect_end_line(&mut self, line: &[u8]) -> io::Result<()> {
        if line == b"end" {
            self.state = State::FindHead;
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient uuencode data"))
        }
    }

    /// Decodes one base64 body line.
    fn decode_base64_line(&mut self, line: &[u8], produced: &mut usize) -> io::Result<()> {
        let mut remaining = line.len();
        if remaining >= 3 && line.starts_with(b"===") {
            self.state = State::FindHead;
            return Ok(());
        }
        let mut cursor = 0_usize;
        while remaining > 0 {
            let (Some(&first_char), Some(&second_char)) = (line.get(cursor), line.get(cursor + 1)) else {
                break;
            };
            if !is_base64_char(first_char) || !is_base64_char(second_char) {
                break;
            }
            let mut value = u32::from(base64_value(first_char)) << 18;
            value |= u32::from(base64_value(second_char)) << 12;
            self.out.push(u8::try_from(value >> 16).unwrap_or(0));
            *produced += 1;
            remaining -= 2;
            cursor += 2;

            if remaining > 0 {
                let Some(&next_char) = line.get(cursor) else {
                    break;
                };
                if next_char == b'=' || !is_base64_char(next_char) {
                    break;
                }
                value |= u32::from(base64_value(next_char)) << 6;
                self.out.push(u8::try_from((value >> 8) & 0xff).unwrap_or(0));
                *produced += 1;
                remaining -= 1;
                cursor += 1;
            }
            if remaining > 0 {
                let Some(&next_char) = line.get(cursor) else {
                    break;
                };
                if next_char == b'=' || !is_base64_char(next_char) {
                    break;
                }
                value |= u32::from(base64_value(next_char));
                self.out.push(u8::try_from(value & 0xff).unwrap_or(0));
                *produced += 1;
                remaining -= 1;
                cursor += 1;
            }
        }
        if remaining > 0 && line.get(cursor).is_some_and(|&byte| byte != b'=') {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "insufficient uuencode data"));
        }
        Ok(())
    }
}

impl<R: Read> Read for UuDecoder<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.out_pos < self.out.len() {
                let remaining = &self.out[self.out_pos..];
                let take = remaining.len().min(buffer.len());
                buffer[..take].copy_from_slice(&remaining[..take]);
                self.out_pos += take;
                self.total += take as u64;
                return Ok(take);
            }
            if self.finished {
                return Ok(0);
            }
            self.fill()?;
        }
    }
}

/// uuencode alphabet check: characters `0x20..=0x60` (libarchive's `uuchar`
/// table; `0x60` backtick is the traditional zero-padding character).
const fn is_uu_char(byte: u8) -> bool {
    byte >= 0x20 && byte <= 0x60
}

/// `UUDECODE(c) = ((c) - 0x20) & 0x3f`.
const fn uu_decode(byte: u8) -> u8 {
    (byte.wrapping_sub(0x20)) & 0x3f
}

/// Base64 alphabet check: `A-Za-z0-9+/=` (libarchive's `base64` table).
const fn is_base64_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'='
}

/// Base64 sextet value (libarchive's `base64num` table).
const fn base64_value(byte: u8) -> u8 {
    match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::UuDecoder;
    use std::io::Read as _;

    /// Minimal uuencode writer for test fixtures.
    fn uuencode(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"begin 644 payload\n");
        for chunk in data.chunks(45) {
            out.push(u8::try_from(chunk.len()).unwrap_or(0) + 0x20);
            for triple in chunk.chunks(3) {
                let first = triple.first().copied().unwrap_or(0);
                let second = triple.get(1).copied().unwrap_or(0);
                let third = triple.get(2).copied().unwrap_or(0);
                let value = u32::from(first) << 16 | u32::from(second) << 8 | u32::from(third);
                for shift in [18_u32, 12, 6, 0] {
                    out.push(u8::try_from((value >> shift) & 0x3f).unwrap_or(0) + 0x20);
                }
            }
            out.push(b'\n');
        }
        out.push(b' ');
        out.push(b'\n');
        out.extend_from_slice(b"end\n");
        out
    }

    /// Base64 writer producing the `begin-base64` + `====` framing.
    fn base64_stream(data: &[u8]) -> Vec<u8> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut body = Vec::new();
        for chunk in data.chunks(3) {
            let first = chunk.first().copied().unwrap_or(0);
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);
            let value = u32::from(first) << 16 | u32::from(second) << 8 | u32::from(third);
            body.push(ALPHABET[usize::try_from((value >> 18) & 0x3f).unwrap_or(0)]);
            body.push(ALPHABET[usize::try_from((value >> 12) & 0x3f).unwrap_or(0)]);
            body.push(if chunk.len() > 1 { ALPHABET[usize::try_from((value >> 6) & 0x3f).unwrap_or(0)] } else { b'=' });
            body.push(if chunk.len() > 2 { ALPHABET[usize::try_from(value & 0x3f).unwrap_or(0)] } else { b'=' });
        }
        let mut out = Vec::new();
        out.extend_from_slice(b"begin-base64 644 payload\n");
        for line in body.chunks(76) {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
        out.extend_from_slice(b"====\n");
        out
    }

    fn decode_all(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut decoder = UuDecoder::new(data);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)?;
        Ok(output)
    }

    #[test]
    fn decodes_uuencoded_stream() {
        let payloads: [&[u8]; 4] =
            [b"hello", b"a", b"", b"the quick brown fox jumps over the lazy dog, repeatedly, until the payload exceeds forty-five bytes"];
        for payload in payloads {
            assert_eq!(decode_all(&uuencode(payload)).unwrap(), payload);
        }
    }

    #[test]
    fn decodes_base64_stream() {
        let payloads: [&[u8]; 5] = [b"hello", b"a", b"ab", b"", b"base64 payload with more than three bytes"];
        for payload in payloads {
            assert_eq!(decode_all(&base64_stream(payload)).unwrap(), payload);
        }
    }

    #[test]
    fn decodes_multipart_stream_and_ignores_trailing_garbage() {
        let mut stream = uuencode(b"first");
        stream.extend_from_slice(&base64_stream(b"second"));
        stream.extend_from_slice(b"trailing junk after the payload\n");
        assert_eq!(decode_all(&stream).unwrap(), b"firstsecond");
    }

    #[test]
    fn rejects_binary_junk_before_header() {
        let error = decode_all(b"\xff\xfe garbage\n").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_truncated_stream_without_output() {
        // A `begin` header followed by an unfinished body line and EOF.
        let error = decode_all(b"begin 644 payload\nM12").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
