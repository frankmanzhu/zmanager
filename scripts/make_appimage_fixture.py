#!/usr/bin/env python3
"""Build a type-2 AppImage fixture from a SquashFS payload.

A type-2 AppImage is an ELF runtime with the SquashFS image appended directly
after the section-header table, so the payload offset is
``e_shoff + e_shentsize * e_shnum``. This writes the smallest ELF with that
shape, with a decoy ``hsqs`` sequence planted inside the runtime region so a
reader that scans for the magic instead of computing the offset is caught.
"""

import struct
import sys

SECTION_ENTRY_SIZE = 64
SECTION_COUNT = 3
SECTION_HEADER_OFFSET = 4096


def main(payload_path: str, output_path: str) -> None:
    with open(payload_path, "rb") as handle:
        payload = handle.read()

    payload_offset = SECTION_HEADER_OFFSET + SECTION_ENTRY_SIZE * SECTION_COUNT
    elf = bytearray(payload_offset)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2  # ELFCLASS64
    elf[5] = 1  # ELFDATA2LSB
    elf[6] = 1  # EV_CURRENT
    elf[8:11] = bytes([0x41, 0x49, 0x02])  # "AI\x02": type-2 AppImage marker
    struct.pack_into("<Q", elf, 0x28, SECTION_HEADER_OFFSET)  # e_shoff
    struct.pack_into("<H", elf, 0x3A, SECTION_ENTRY_SIZE)  # e_shentsize
    struct.pack_into("<H", elf, 0x3C, SECTION_COUNT)  # e_shnum
    elf[2048:2052] = b"hsqs"  # decoy ahead of the real payload

    with open(output_path, "wb") as handle:
        handle.write(bytes(elf))
        handle.write(payload)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} <payload.squashfs> <out.AppImage>")
    main(sys.argv[1], sys.argv[2])
