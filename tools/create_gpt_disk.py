#!/usr/bin/env python3
"""Create a sparse GPT disk image with one empty filesystem partition."""

import argparse
import binascii
import os
import shutil
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
               last_usable: int, entries_crc: int,
               disk_guid: uuid.UUID = DISK_GUID) -> bytes:
    header = bytearray(SECTOR_SIZE)
    struct.pack_into("<8sIIIIQQQQ16sQIII", header, 0, b"EFI PART", 0x00010000,
                     92, 0, 0, current, backup, first_usable, last_usable,
                     disk_guid.bytes_le, entries_lba, ENTRY_COUNT, ENTRY_SIZE,
                     entries_crc)
    struct.pack_into("<I", header, 16, crc32(header[:92]))
    return bytes(header)


def validate_primary_gpt(image) -> tuple[bytearray, bytearray, tuple]:
    image.seek(SECTOR_SIZE)
    header = bytearray(image.read(SECTOR_SIZE))
    if len(header) != SECTOR_SIZE:
        raise ValueError("existing disk has a truncated GPT header")
    fields = struct.unpack_from("<8sIIIIQQQQ16sQIII", header)
    (signature, revision, header_size, header_crc, reserved, current_lba,
     backup_lba, first_usable, last_usable, disk_guid_bytes, entries_lba,
     entry_count, entry_size, entries_crc) = fields
    if (signature != b"EFI PART" or revision != 0x00010000 or reserved != 0
            or current_lba != 1 or entries_lba != 2
            or entry_count != ENTRY_COUNT or entry_size != ENTRY_SIZE
            or header_size < 92 or header_size > SECTOR_SIZE):
        raise ValueError("existing disk does not use the supported GPT layout")
    checked_header = bytearray(header)
    struct.pack_into("<I", checked_header, 16, 0)
    if crc32(checked_header[:header_size]) != header_crc:
        raise ValueError("existing disk has an invalid primary GPT checksum")
    image.seek(entries_lba * SECTOR_SIZE)
    entries = bytearray(image.read(entry_count * entry_size))
    if len(entries) != entry_count * entry_size or crc32(entries) != entries_crc:
        raise ValueError("existing disk has an invalid GPT entry checksum")
    if any(entries[ENTRY_SIZE:]):
        raise ValueError("existing disk has more than one partition")
    return header, entries, fields


def grow(path: str, size_mb: int) -> bool:
    requested_bytes = size_mb * 1024 * 1024
    old_bytes = os.path.getsize(path)
    if old_bytes >= requested_bytes:
        return False
    if old_bytes % SECTOR_SIZE != 0 or requested_bytes % SECTOR_SIZE != 0:
        raise ValueError("disk image size is not sector aligned")

    temporary = f"{path}.grow-{os.getpid()}"
    if os.path.exists(temporary):
        os.remove(temporary)
    shutil.copy2(path, temporary)
    try:
        raw_image = False
        with open(temporary, "r+b") as image:
            signature = image.read(8)
            if signature == b"RedoxFS\0":
                raw_image = True
                image.truncate(requested_bytes)
            else:
                _, entries, fields = validate_primary_gpt(image)
                old_sectors = old_bytes // SECTOR_SIZE
                new_sectors = requested_bytes // SECTOR_SIZE
                old_last_lba = old_sectors - 1
                new_last_lba = new_sectors - 1
                old_backup_lba = fields[6]
                first_usable = fields[7]
                old_last_usable = fields[8]
                disk_guid = uuid.UUID(bytes_le=fields[9])
                partition_first, partition_last = struct.unpack_from("<QQ", entries, 32)
                if (old_backup_lba != old_last_lba or partition_first != first_usable
                        or partition_last != old_last_usable):
                    raise ValueError("existing partition does not fill the supported GPT disk")

                backup_entries_lba = new_last_lba - ENTRY_SECTORS
                last_usable = backup_entries_lba - 1
                struct.pack_into("<Q", entries, 40, last_usable)
                entries_crc = crc32(entries)

                image.seek(0)
                protective_mbr = bytearray(image.read(SECTOR_SIZE))
                if protective_mbr[510:512] != b"\x55\xaa":
                    raise ValueError("existing disk has an invalid protective MBR")
                struct.pack_into("<I", protective_mbr, 458, min(new_last_lba, 0xFFFFFFFF))
                primary = gpt_header(1, new_last_lba, 2, first_usable,
                                     last_usable, entries_crc, disk_guid)
                backup = gpt_header(new_last_lba, 1, backup_entries_lba,
                                    first_usable, last_usable, entries_crc, disk_guid)

                image.truncate(requested_bytes)
                image.seek(0)
                image.write(protective_mbr)
                image.write(primary)
                image.write(entries)
                image.seek((old_backup_lba - ENTRY_SECTORS) * SECTOR_SIZE)
                image.write(b"\0" * ((ENTRY_SECTORS + 1) * SECTOR_SIZE))
                image.seek(backup_entries_lba * SECTOR_SIZE)
                image.write(entries)
                image.write(backup)
            image.flush()
            os.fsync(image.fileno())
        os.replace(temporary, path)
        if raw_image:
            print(f"expanded raw RedoxFS image {path} from "
                  f"{old_bytes // (1024 * 1024)} MiB to {size_mb} MiB; "
                  "RedoxFS will grow on next boot")
            return True
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)
    print(f"expanded {path} from {old_bytes // (1024 * 1024)} MiB "
          f"to {size_mb} MiB; RedoxFS will grow on next boot")
    return True


def create(path: str, size_mb: int) -> None:
    if os.path.exists(path):
        grow(path, size_mb)
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
