#!/usr/bin/env python3
"""Mint the physical AFF4 fixture (`aff4:ImageStream`) from a raw disk image.

`aff4-core`'s bundled `testutil::test_aff4` truncates its input to a single
512-byte chunk, so it cannot carry a whole disk image. This writes the same
AFF4 Standard v1.0 layout with as many chunks as the image needs, so the
physical-AFF4 fixture decodes to the identical `payload/` tree every other
disk-image fixture exposes.

Layout (an AFF4 container is a Zip):

    information.turtle          RDF metadata describing the ImageStream
    <base>/00000000             bevy: `chunks_in_segment` chunks, concatenated
    <base>/00000000.index       12 bytes per chunk: u64 offset, u32 length

Chunks are stored uncompressed (`aff4:NullCompressor`) and the *Zip* entry is
Deflated instead, so a mostly-zero image collapses to a few KiB while the index
stays a trivial fixed stride.

Usage:
    python3 scripts/make_aff4_fixture.py <raw-image> <out.aff4>
"""

from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path

CHUNK_SIZE = 32768
CHUNKS_IN_SEGMENT = 64
STREAM_ARN = "aff4://zmanager-fixture-image-stream"
ZIP_BASE = "zmanager-fixture-image-stream"
# Fixed Zip entry timestamp: the mint must be byte-reproducible.
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

TURTLE = """@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix aff4: <http://aff4.org/Schema#> .
<{arn}> rdf:type aff4:ImageStream ; aff4:size {size} ; aff4:chunkSize {chunk} ; \
aff4:chunksInSegment {per_segment} ; aff4:compressionMethod aff4:NullCompressor .
"""


def build(image: bytes) -> bytes:
    # Whole chunks only: the trailing partial chunk is zero-padded and the
    # declared stream size is grown to match, exactly as an imager would.
    chunk_count = (len(image) + CHUNK_SIZE - 1) // CHUNK_SIZE
    padded = image.ljust(chunk_count * CHUNK_SIZE, b"\x00")

    # A fixed entry timestamp keeps the mint byte-reproducible, so the manifest
    # checksum only moves when the payload actually changes.
    def entry(name: str) -> zipfile.ZipInfo:
        info = zipfile.ZipInfo(name, date_time=FIXED_TIMESTAMP)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        return info

    buffer = _ZipBuffer()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr(
            entry("information.turtle"),
            TURTLE.format(arn=STREAM_ARN, size=len(padded), chunk=CHUNK_SIZE, per_segment=CHUNKS_IN_SEGMENT),
        )
        for segment, start in enumerate(range(0, chunk_count, CHUNKS_IN_SEGMENT)):
            stop = min(start + CHUNKS_IN_SEGMENT, chunk_count)
            bevy = padded[start * CHUNK_SIZE : stop * CHUNK_SIZE]
            index = b"".join(
                struct.pack("<QI", (chunk - start) * CHUNK_SIZE, CHUNK_SIZE) for chunk in range(start, stop)
            )
            zf.writestr(entry(f"{ZIP_BASE}/{segment:08d}"), bevy)
            zf.writestr(entry(f"{ZIP_BASE}/{segment:08d}.index"), index)
    return buffer.getvalue()


class _ZipBuffer:
    """Minimal seekable in-memory sink for `zipfile.ZipFile`."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._pos = 0

    def write(self, data: bytes) -> int:
        end = self._pos + len(data)
        if end > len(self._buf):
            self._buf.extend(b"\x00" * (end - len(self._buf)))
        self._buf[self._pos : end] = data
        self._pos = end
        return len(data)

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = 0) -> int:
        base = {0: 0, 1: self._pos, 2: len(self._buf)}[whence]
        self._pos = base + offset
        return self._pos

    def flush(self) -> None:
        return None

    def seekable(self) -> bool:
        return True

    def getvalue(self) -> bytes:
        return bytes(self._buf)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    image = Path(argv[1]).read_bytes()
    payload = build(image)
    Path(argv[2]).write_bytes(payload)
    print(f"wrote {argv[2]} ({len(payload)} bytes) from {len(image)} raw bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
