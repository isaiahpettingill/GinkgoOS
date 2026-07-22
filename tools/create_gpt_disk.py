#!/usr/bin/env python3
"""Create a sparse GPT disk image with one empty filesystem partition."""

import argparse
import binascii
import os
import struct
import uuid

SECTOR_SIZE = 512
ENTRY_COUNT = 128
ENTRY_SIZE = 128
ENTRY_SECTORS = ENTRY_COUNT * ENTRY_SIZE // SECTOR_SIZE
PARTITION_START = 2048
LINUX_FILESYSTEM = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
DISK_GUID = uuid.UUID("67db1850-3e9d-4d70-9528-58acdf755133")
PARTITION_GUID = uuid.UUID("afea2d75-6340-48f2-b128-428c5b0601f7")


def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def gpt_header(current: int, backup: int, entries_lba: int, first_usable: int,
               last_usable: int, entries_crc: int) -> bytes:
    header = bytearray(SECTOR_SIZE)
    struct.pack_into("<8sIIIIQQQQ16sQIII", header, 0, b"EFI PART", 0x00010000,
                     92, 0, 0, current, backup, first_usable, last_usable,
                     DISK_GUID.bytes_le, entries_lba, ENTRY_COUNT, ENTRY_SIZE,
                     entries_crc)
    struct.pack_into("<I", header, 16, crc32(header[:92]))
    return bytes(header)


def create(path: str, size_mb: int) -> None:
    if os.path.exists(path):
        return
    sectors = size_mb * 1024 * 1024 // SECTOR_SIZE
    if sectors <= PARTITION_START + ENTRY_SECTORS + 1:
        raise ValueError("disk image is too small for the GPT layout")

    last_lba = sectors - 1
    backup_entries_lba = last_lba - ENTRY_SECTORS
    first_usable = PARTITION_START
    last_usable = backup_entries_lba - 1

    entries = bytearray(ENTRY_COUNT * ENTRY_SIZE)
    name = "GinkgoOS RedoxFS".encode("utf-16-le")
    struct.pack_into("<16s16sQQQ", entries, 0, LINUX_FILESYSTEM.bytes_le,
                     PARTITION_GUID.bytes_le, first_usable, last_usable, 0)
    entries[56:56 + len(name)] = name
    entries_crc = crc32(entries)

    protective_mbr = bytearray(SECTOR_SIZE)
    protective_count = min(last_lba, 0xFFFFFFFF)
    struct.pack_into("<B3sB3sII", protective_mbr, 446, 0, b"\0\x02\0", 0xEE,
                     b"\xff\xff\xff", 1, protective_count)
    protective_mbr[510:512] = b"\x55\xaa"

    primary = gpt_header(1, last_lba, 2, first_usable, last_usable, entries_crc)
    backup = gpt_header(last_lba, 1, backup_entries_lba, first_usable,
                        last_usable, entries_crc)

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "xb") as image:
        image.truncate(sectors * SECTOR_SIZE)
        image.seek(0)
        image.write(protective_mbr)
        image.write(primary)
        image.write(entries)
        image.seek(backup_entries_lba * SECTOR_SIZE)
        image.write(entries)
        image.write(backup)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--size-mb", type=int, default=16)
    args = parser.parse_args()
    create(args.path, args.size_mb)


if __name__ == "__main__":
    main()
