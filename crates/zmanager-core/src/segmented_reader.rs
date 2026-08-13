//! Generic ordered-volume byte source for formats whose parts are raw stream
//! segments. Format-specific framing and validation remain in the owning
//! adapter; this module only provides a checked logical `Read + Seek` view.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

/// A logical byte stream backed by ordered files.
///
/// The reader never concatenates the parts into memory or a temporary file.
/// Callers must discover and validate the format-specific volume set before
/// constructing this source.
pub(crate) struct SegmentedReader {
    parts: Vec<Segment>,
    total_len: u64,
    position: u64,
}

struct Segment {
    path: PathBuf,
    file: File,
    start: u64,
    len: u64,
    file_position: u64,
}

impl SegmentedReader {
    /// Opens an already ordered, non-empty volume set.
    pub(crate) fn open(paths: Vec<PathBuf>) -> io::Result<Self> {
        if paths.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "segmented source has no parts"));
        }

        let mut parts = Vec::with_capacity(paths.len());
        let mut total_len = 0_u64;
        for path in paths {
            let file = File::open(&path)?;
            let len = file.metadata()?.len();
            if len == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("segmented source part is empty: {}", path.display())));
            }
            let start = total_len;
            total_len = total_len.checked_add(len).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "segmented source length overflow"))?;
            parts.push(Segment { path, file, start, len, file_position: 0 });
        }

        Ok(Self { parts, total_len, position: 0 })
    }

    pub(crate) fn total_len(&self) -> u64 {
        self.total_len
    }

    pub(crate) fn part_layout(&self) -> Vec<(u64, u64)> {
        self.parts.iter().map(|part| (part.start, part.len)).collect()
    }

    fn current_part_index(&self) -> Option<usize> {
        let index = self.parts.partition_point(|part| part.start <= self.position).checked_sub(1)?;
        let part = self.parts.get(index)?;
        (self.position < part.start.saturating_add(part.len)).then_some(index)
    }
}

impl Read for SegmentedReader {
    fn read(&mut self, mut buffer: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.total_len || buffer.is_empty() {
            return Ok(0);
        }

        let mut copied = 0usize;
        while !buffer.is_empty() && self.position < self.total_len {
            let Some(index) = self.current_part_index() else {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "segmented source has a gap"));
            };
            let part = &mut self.parts[index];
            let offset = self.position.saturating_sub(part.start);
            let remaining = usize::try_from(part.len.saturating_sub(offset)).unwrap_or(usize::MAX).min(buffer.len());
            if part.file_position != offset {
                part.file.seek(SeekFrom::Start(offset))?;
                part.file_position = offset;
            }
            let read = part.file.read(&mut buffer[..remaining])?;
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("unexpected EOF in {}", part.path.display())));
            }
            self.position = self
                .position
                .checked_add(u64::try_from(read).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "segmented read size overflow"))?)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "segmented position overflow"))?;
            part.file_position = part
                .file_position
                .checked_add(u64::try_from(read).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "segmented read size overflow"))?)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "segmented part position overflow"))?;
            copied += read;
            buffer = &mut buffer[read..];
        }
        Ok(copied)
    }
}

impl Seek for SegmentedReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let target = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(offset) => i128::from(self.total_len) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        if !(0..=i128::from(self.total_len)).contains(&target) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "segmented seek outside source"));
        }
        self.position = u64::try_from(target).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "segmented seek overflow"))?;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::SegmentedReader;
    use crate::test_support::TestDir;
    use std::io::{Read, Seek, SeekFrom};

    #[test]
    fn reads_and_reseeks_across_ordered_parts() {
        let temp = TestDir::new("segmented_reader");
        temp.write_file("one", b"abc");
        temp.write_file("two", b"defg");
        let mut reader = SegmentedReader::open(vec![temp.path("one"), temp.path("two")]).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcdefg");
        reader.seek(SeekFrom::Start(2)).unwrap();
        let mut suffix = [0_u8; 3];
        reader.read_exact(&mut suffix).unwrap();
        assert_eq!(&suffix, b"cde");
    }
}
