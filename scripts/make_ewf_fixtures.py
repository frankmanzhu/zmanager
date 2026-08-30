#!/usr/bin/env python3
"""Mint the EWF (Expert Witness Format) fixtures from a raw disk image.

`ewfacquire` is not available on every machine that regenerates fixtures, and
vendoring a third-party `.E01` would drag ~2 MB of high-entropy NTFS into the
repository. Both segment files are therefore written here directly, wrapping the
same raw image the `.raw`/`.vhdx`/`.qcow2` fixtures use, so every disk-image
fixture in `fixtures/archives` decodes to one identical payload tree.

The layouts follow the two format versions the `ewf` crate's reader parses:

  * EWF v1 (`.e01`, `EVF\\x09\\x0d\\x0a\\xff\\x00`) -- 13-byte file header, then a
    chain of 76-byte section descriptors: `volume`, `table`, `sectors`, `done`.
    Table entries are `u32`, bit 31 marking a zlib-compressed chunk and the low
    31 bits holding the chunk's offset from the table's `base_offset`.

  * EWF v2 (`.ex01`, `EVF2\\x0d\\x0a\\x81\\x00`) -- 32-byte file header, then
    sections written as DATA-then-DESCRIPTOR (64-byte descriptors, each pointing
    back at the previous one): `device_info`, `sector_data`, `sector_table`,
    `done`. Table entries are 16 bytes: absolute offset, size, flags.

Usage:
    python3 scripts/make_ewf_fixtures.py <raw-image> <out.e01> <out.ex01>
"""

from __future__ import annotations

import sys
import zlib
from pathlib import Path

BYTES_PER_SECTOR = 512
SECTORS_PER_CHUNK = 64
CHUNK_SIZE = BYTES_PER_SECTOR * SECTORS_PER_CHUNK  # 32 KiB

EVF1_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
EVF2_SIGNATURE = b"EVF2\x0d\x0a\x81\x00"

V1_FILE_HEADER_SIZE = 13
V1_SECTION_DESCRIPTOR_SIZE = 76
V1_VOLUME_DATA_SIZE = 94
V1_TABLE_HEADER_SIZE = 24

V2_FILE_HEADER_SIZE = 32
V2_SECTION_DESCRIPTOR_SIZE = 64
V2_TABLE_HEADER_SIZE = 32
V2_TABLE_ENTRY_SIZE = 16
V2_CHUNK_FLAG_COMPRESSED = 0x0000_0001


def chunks_of(image: bytes) -> list[bytes]:
    """Split `image` into whole 32 KiB chunks, zero-padding the final one."""
    out = []
    for start in range(0, len(image), CHUNK_SIZE):
        chunk = image[start : start + CHUNK_SIZE]
        out.append(chunk.ljust(CHUNK_SIZE, b"\x00"))
    return out


def build_evf1(image: bytes) -> bytes:
    compressed = [zlib.compress(chunk, 9) for chunk in chunks_of(image)]
    count = len(compressed)
    sector_count = (count * CHUNK_SIZE) // BYTES_PER_SECTOR

    # Lay the file out first: every descriptor stores the absolute offset of the
    # next one, so the offsets have to be known before any bytes are emitted.
    volume_desc_off = V1_FILE_HEADER_SIZE
    volume_data_off = volume_desc_off + V1_SECTION_DESCRIPTOR_SIZE
    table_desc_off = volume_data_off + V1_VOLUME_DATA_SIZE
    table_header_off = table_desc_off + V1_SECTION_DESCRIPTOR_SIZE
    table_entries_off = table_header_off + V1_TABLE_HEADER_SIZE
    sectors_desc_off = table_entries_off + 4 * count
    sectors_data_off = sectors_desc_off + V1_SECTION_DESCRIPTOR_SIZE
    done_desc_off = sectors_data_off + sum(len(c) for c in compressed)

    def descriptor(name: bytes, next_offset: int, section_size: int) -> bytes:
        desc = bytearray(V1_SECTION_DESCRIPTOR_SIZE)
        desc[0 : len(name)] = name
        desc[16:24] = next_offset.to_bytes(8, "little")
        desc[24:32] = section_size.to_bytes(8, "little")
        return bytes(desc)  # checksum at [72..76] is left zero; the reader ignores it

    out = bytearray()
    out += EVF1_SIGNATURE
    out += bytes([0x01])  # fields_start
    out += (1).to_bytes(2, "little")  # segment number
    out += (0).to_bytes(2, "little")  # fields_end
    assert len(out) == V1_FILE_HEADER_SIZE

    out += descriptor(b"volume", table_desc_off, V1_SECTION_DESCRIPTOR_SIZE + V1_VOLUME_DATA_SIZE)
    volume = bytearray(V1_VOLUME_DATA_SIZE)
    volume[0:4] = (1).to_bytes(4, "little")  # media_type = fixed disk
    volume[4:8] = count.to_bytes(4, "little")
    volume[8:12] = SECTORS_PER_CHUNK.to_bytes(4, "little")
    volume[12:16] = BYTES_PER_SECTOR.to_bytes(4, "little")
    volume[16:24] = sector_count.to_bytes(8, "little")
    out += bytes(volume)

    table_size = V1_SECTION_DESCRIPTOR_SIZE + V1_TABLE_HEADER_SIZE + 4 * count
    out += descriptor(b"table", sectors_desc_off, table_size)
    table_header = bytearray(V1_TABLE_HEADER_SIZE)
    table_header[0:4] = count.to_bytes(4, "little")
    table_header[8:16] = sectors_data_off.to_bytes(8, "little")
    out += bytes(table_header)

    relative = 0
    for payload in compressed:
        assert relative < 0x8000_0000, "chunk offset overflows the 31-bit table entry"
        out += (0x8000_0000 | relative).to_bytes(4, "little")
        relative += len(payload)

    out += descriptor(b"sectors", done_desc_off, V1_SECTION_DESCRIPTOR_SIZE + relative)
    for payload in compressed:
        out += payload

    out += descriptor(b"done", 0, V1_SECTION_DESCRIPTOR_SIZE)
    assert len(out) == done_desc_off + V1_SECTION_DESCRIPTOR_SIZE
    return bytes(out)


def build_evf2(image: bytes) -> bytes:
    compressed = [zlib.compress(chunk, 9) for chunk in chunks_of(image)]
    count = len(compressed)
    total_sectors = (count * CHUNK_SIZE) // BYTES_PER_SECTOR

    device_info = (
        f"2\nmain\nb\tsc\tts\n{BYTES_PER_SECTOR}\t{SECTORS_PER_CHUNK}\t{total_sectors}\n\n"
    ).encode("utf-16-le")

    device_info_data_off = V2_FILE_HEADER_SIZE
    device_info_desc_off = device_info_data_off + len(device_info)
    sectors_data_off = device_info_desc_off + V2_SECTION_DESCRIPTOR_SIZE
    sectors_desc_off = sectors_data_off + sum(len(c) for c in compressed)
    table_data_off = sectors_desc_off + V2_SECTION_DESCRIPTOR_SIZE
    table_data_size = V2_TABLE_HEADER_SIZE + V2_TABLE_ENTRY_SIZE * count
    table_desc_off = table_data_off + table_data_size

    def descriptor(section_type: int, data_size: int, previous_offset: int) -> bytes:
        desc = bytearray(V2_SECTION_DESCRIPTOR_SIZE)
        desc[0:4] = section_type.to_bytes(4, "little")
        desc[8:16] = previous_offset.to_bytes(8, "little")
        desc[16:24] = data_size.to_bytes(8, "little")
        desc[24:28] = V2_SECTION_DESCRIPTOR_SIZE.to_bytes(4, "little")
        return bytes(desc)

    out = bytearray()
    out += EVF2_SIGNATURE
    out += bytes([2, 1])  # major, minor version
    out += (1).to_bytes(2, "little")  # compression method = zlib
    out += (1).to_bytes(4, "little")  # segment number
    out += bytes(16)  # set identifier
    assert len(out) == V2_FILE_HEADER_SIZE

    out += device_info
    out += descriptor(0x01, len(device_info), 0)

    offset = sectors_data_off
    entries = bytearray()
    for payload in compressed:
        out += payload
        entry = bytearray(V2_TABLE_ENTRY_SIZE)
        entry[0:8] = offset.to_bytes(8, "little")
        entry[8:12] = len(payload).to_bytes(4, "little")
        entry[12:16] = V2_CHUNK_FLAG_COMPRESSED.to_bytes(4, "little")
        entries += entry
        offset += len(payload)
    out += descriptor(0x03, sum(len(c) for c in compressed), device_info_desc_off)

    table_header = bytearray(V2_TABLE_HEADER_SIZE)
    table_header[0:8] = (0).to_bytes(8, "little")  # first_chunk
    table_header[8:12] = count.to_bytes(4, "little")  # entry_count
    out += bytes(table_header)
    out += bytes(entries)
    out += descriptor(0x04, table_data_size, sectors_desc_off)

    out += descriptor(0x0F, 0, table_desc_off)
    return bytes(out)


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    raw = Path(argv[1]).read_bytes()
    Path(argv[2]).write_bytes(build_evf1(raw))
    Path(argv[3]).write_bytes(build_evf2(raw))
    print(f"wrote {argv[2]} and {argv[3]} from {len(raw)} raw bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
