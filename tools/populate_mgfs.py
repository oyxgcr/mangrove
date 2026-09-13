#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
import math
import hashlib
import os
import re
import secrets
import struct
import sys

from image_payloads import (DATA_MANIFEST, DATA_RECORD_IDS,
                            HARDWARE_RECORD_ID, PITH_RECORD_ID,
                            PAYLOAD_MANIFEST, SYSTEM_FILES)

B = 4096
CRC_POLY = 0x42F0E1EBA9EA3693
MAGIC = b"MGFSv1\0\0"
VFS_UID_SYSTEM = 0
PERMISSION_OWNER_READ = 1 << 0
PERMISSION_OWNER_WRITE = 1 << 1
PERMISSION_OTHER_READ = 1 << 2
PERMISSION_OTHER_WRITE = 1 << 3
SYSTEM_PERMISSIONS = PERMISSION_OWNER_READ | PERMISSION_OWNER_WRITE | PERMISSION_OTHER_READ
# /temp is system-owned, but ordinary users need to be able to create their
# own temporary files there.  File objects still receive the creating user's
# ownership and normal permissions.
TEMP_PERMISSIONS = SYSTEM_PERMISSIONS | PERMISSION_OTHER_WRITE
USER_PERMISSIONS = PERMISSION_OWNER_READ | PERMISSION_OWNER_WRITE
RECORD_INLINE_DATA = 1
RECORD_OWNER_SHIFT = 1
RECORD_PERMISSIONS_SHIFT = 33
RECORD_CHILD_MUTATION_SHIFT = 41
RECORD_CHILD_MUTATION_OWNER_RESTRICTED = 1

def w64(buf, off, value):
    struct.pack_into("<Q", buf, off, value)

def crc64(data):
    crc = 0
    for byte in data:
        crc ^= byte << 56
        for _ in range(8):
            crc = ((crc << 1) ^ CRC_POLY) & ((1 << 64) - 1) if crc & (1 << 63) else (crc << 1) & ((1 << 64) - 1)
    return crc

def checksum(buf, offset, length):
    w64(buf, offset, 0)
    w64(buf, offset, crc64(buf[:length]))

def extent(record, offset, logical, physical, count, flags=1):
    for value in (logical, physical, count, flags):
        w64(record, offset, value)
        offset += 8

def make_record(record_id, record_type, size=0, extents=(), owner_uid=VFS_UID_SYSTEM,
                permissions=SYSTEM_PERMISSIONS, child_mutation_policy=0):
    record = bytearray(192)
    child_policy = (RECORD_CHILD_MUTATION_OWNER_RESTRICTED <<
                    RECORD_CHILD_MUTATION_SHIFT
                    if record_type == 2 and child_mutation_policy else 0)
    w64(record, 0, record_type)
    w64(record, 8, ((owner_uid << RECORD_OWNER_SHIFT) |
                    (permissions << RECORD_PERMISSIONS_SHIFT) |
                    child_policy))
    w64(record, 16, record_id)
    w64(record, 24, 1)
    w64(record, 32, size)
    w64(record, 40, len(extents))
    w64(record, 48, min(2, len(extents)))
    for index, item in enumerate(extents[:2]):
        extent(record, 64 + index * 32, *item)
    if len(extents) > 2:
        w64(record, 56, extents[2][1])
    checksum(record, 184, 192)
    return record

def record_payload_matches(image, table_start, record_id, payload):
    """Return whether a regular-file Record contains exactly payload."""
    slot = record_id - 1
    record_offset = (table_start + slot // 21) * B + 24 + (slot % 21) * 192
    if record_offset + 192 > len(image):
        return False
    record = image[record_offset:record_offset + 192]
    if struct.unpack_from("<Q", record, 0)[0] != 1:
        return False
    if struct.unpack_from("<Q", record, 32)[0] != len(payload):
        return False
    extent_count = struct.unpack_from("<Q", record, 40)[0]
    direct_count = min(2, extent_count)
    copied = bytearray()
    for index in range(direct_count):
        extent_offset = 64 + index * 32
        physical = struct.unpack_from("<Q", record, extent_offset + 8)[0]
        blocks = struct.unpack_from("<Q", record, extent_offset + 16)[0]
        if not blocks or physical * B + blocks * B > len(image):
            return False
        copied.extend(image[physical * B:physical * B + blocks * B])
    return bytes(copied[:len(payload)]) == payload

def directory_entry(record_id, name):
    encoded = name.encode("utf-8")
    size = (32 + len(encoded) + 7) & ~7
    entry = bytearray(size)
    w64(entry, 0, record_id)
    w64(entry, 8, len(encoded))
    w64(entry, 16, 1)
    entry[32:32 + len(encoded)] = encoded
    checksum(entry, 24, size)
    return entry

HELP_SOURCE_DIR = "share/help"
HELP_FILES = (
    "clear", "cp", "fetch", "identity", "locate", "ls", "mkdir", "mv",
    "netinfo", "netcfg", "ping", "plant", "power", "reboot", "type",
    "resolve", "rm", "rmdir", "say", "shutdown", "sprout", "uptime",
    "user", "version", "where", "lspci", "lsusb", "lsdsk", "crew", "mem",
    "time", "tmon", "logv", "mount", "unmount", "eject", "diskutil", "date",
    "info", "history",
)
HELP_INDEX_NAME = ".index"


def build_help_index(payloads, directory_size):
    entries = [b"version=1\ndirectory_size=%d\n" % directory_size]
    for name in HELP_FILES:
        fields = {}
        for raw_line in payloads[name].decode("utf-8").splitlines():
            line = raw_line.strip()
            if "=" not in line or line.startswith("//"):
                continue
            key, value = line.split("=", 1)
            if key in ("name", "category", "description"):
                fields[key] = value.strip()
        if set(fields) != {"name", "category", "description"}:
            raise SystemExit("populate_mgfs: invalid help metadata for %s" % name)
        entries.append(("name=%s\ncategory=%s\ndescription=%s\n\n" %
                        (fields["name"], fields["category"],
                         fields["description"])).encode("utf-8"))
    return b"\n".join(entries).rstrip() + b"\n"

NETWORK_RECORD_ID = 30
NETWORK_CONFIG_RECORD_ID = 31
DEVELOPER_HOME_RECORD_ID = 33
STATE_RECORD_ID = 34
ACCOUNTS_RECORD_ID = 35
ACCOUNT_DATABASE_RECORD_ID = 36
SESSION_RECORD_ID = 38
SESSION_CONFIG_RECORD_ID = 39
SHARE_RECORD_ID = 42
HELP_RECORD_ID = 43
HELP_INDEX_RECORD_ID = 44
# Keep the fresh-image help range clear of all fixed service, command, and
# shared-data records. Existing images retain their discovered help record
# IDs during incremental updates.
HELP_FIRST_RECORD_ID = 170
SECURITY_RECORD_ID = 70
SECURITY_CONFIG_RECORD_ID = 71
CONF_RECORD_ID = 5
CORE_RECORD_ID = 4
HOME_RECORD_ID = 7
TEMP_RECORD_ID = 6
VOL_RECORD_ID = 73
DEFAULT_NETWORK_CONFIG = (
    b"// Mangrove network configuration\n"
    b"\n"
    b"mode=dhcp\n"
)
DEFAULT_SESSION_CONFIG = b"autologin=false\n"
DEFAULT_SECURITY_CONFIG = (
    b"// Mangrove administrator authorization policy.\n"
    b"//\n"
    b"// This file controls how already-authorized human administrators approve\n"
    b"// privileged actions. It does not grant privileges and cannot elevate\n"
    b"// regular users.\n"
    b"//\n"
    b"// Available authorization modes:\n"
    b"//   password - require password reauthentication for each privileged action\n"
    b"//   confirm  - show a trusted confirmation prompt for each privileged action\n"
    b"//   scripts  - allow direct admin commands without prompts and reserve one\n"
    b"//              trusted authorization context for supported script executions\n"
    b"//   none     - do not prompt already-authorized administrators\n"
    b"//\n"
    b"// Regular users remain denied for administrator-only actions in every mode.\n"
    b"// Missing or invalid values safely fall back to: confirm\n"
    b"\n"
    b"authorization=confirm\n"
)
PASSWORD_SALT_BYTES = 16
PASSWORD_HASH_BYTES = 32
PASSWORD_ITERATIONS = 120000


def default_password_authentication(password=b"mangrove"):
    salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password, salt,
                                 PASSWORD_ITERATIONS, PASSWORD_HASH_BYTES)
    return ("pbkdf2-sha256", salt.hex(), PASSWORD_ITERATIONS, digest.hex())


def default_account_database():
    algorithm, salt, iterations, digest = default_password_authentication()
    return ("version=2\n"
            "next_uid=1001\n"
            "\n"
            "// Initial development identity\n"
            "account uid=1000 username=developer role=admin "
            "home=/home/developer flags=initial auth=%s salt=%s "
            "iterations=%d hash=%s\n" %
            (algorithm, salt, iterations, digest)).encode("ascii")


DEFAULT_ACCOUNT_DATABASE = default_account_database()


def main():
    expected_argc = 2 + len(PAYLOAD_MANIFEST) + len(DATA_MANIFEST)
    if len(sys.argv) not in (expected_argc, expected_argc + 1):
        names = " ".join("<%s-elf>" % name
                         for _, name, _ in PAYLOAD_MANIFEST)
        names += " " + " ".join("<%s>" % name
                                  for _, name, _ in DATA_MANIFEST)
        raise SystemExit("usage: populate_mgfs.py <image> %s "
                         "[--autologin=<name>]" % names)

    autologin = None
    policy_index = 2 + len(PAYLOAD_MANIFEST) + len(DATA_MANIFEST)
    if len(sys.argv) == expected_argc + 1:
        if not sys.argv[policy_index].startswith("--autologin="):
            raise SystemExit("populate_mgfs: invalid image policy")
        autologin = sys.argv[policy_index][len("--autologin="):]
        if not re.fullmatch(r"[a-z][a-z0-9_-]*", autologin):
            raise SystemExit("populate_mgfs: invalid autologin username")

    image_path = sys.argv[1]
    payloads = {
        record_id: open(path, "rb").read()
        for (record_id, _), path in zip(
            SYSTEM_FILES, sys.argv[3:3 + len(SYSTEM_FILES)])
    }
    payloads[PITH_RECORD_ID] = open(sys.argv[2], "rb").read()
    data_start = 3 + len(SYSTEM_FILES)
    data_payloads = {
        record_id: open(path, "rb").read()
        for (record_id, _payload_name, _installed_name), path in zip(
            DATA_MANIFEST,
            sys.argv[data_start:data_start + len(DATA_MANIFEST)])
    }
    image = bytearray(open(image_path, "rb").read())
    if image[:8] != MAGIC:
        raise SystemExit("populate_mgfs: not an MGFS v1 image")

    total_blocks = struct.unpack_from("<Q", image, 40)[0]
    alloc_start = struct.unpack_from("<Q", image, 104)[0]
    record_bitmap_start = struct.unpack_from("<Q", image, 120)[0]
    table_start = struct.unpack_from("<Q", image, 136)[0]
    data_start = struct.unpack_from("<Q", image, 160)[0]
    record_count = struct.unpack_from("<Q", image, 152)[0]
    if table_start != 3 or data_start <= table_start or total_blocks * B != len(image):
        raise SystemExit("populate_mgfs: unsupported MGFS geometry")
    if max(max(record_id for record_id, _ in SYSTEM_FILES),
           max(DATA_RECORD_IDS), HARDWARE_RECORD_ID) >= record_count:
        raise SystemExit("populate_mgfs: image has insufficient record slots")

    root_directories = (
        (2, "bin"), (3, "boot"), (CONF_RECORD_ID, "conf"),
        (CORE_RECORD_ID, "core"), (HOME_RECORD_ID, "home"),
        (SHARE_RECORD_ID, "share"), (STATE_RECORD_ID, "sys"),
        (TEMP_RECORD_ID, "temp"), (VOL_RECORD_ID, "vol"),
    )
    root_data = b"".join(directory_entry(record_id, name)
                           for record_id, name in root_directories)
    boot_data = directory_entry(PITH_RECORD_ID, "pith.elf")
    bin_data = b"".join(directory_entry(record_id, name)
                         for record_id, name in SYSTEM_FILES
                         if record_id not in (8, 69, 74, 75, 76, 110, 111))
    help_payloads = {
        name: open(os.path.join(HELP_SOURCE_DIR, name), "rb").read()
        for name in HELP_FILES
    }
    help_data = b"".join(
        directory_entry(HELP_FIRST_RECORD_ID + index, name)
        for index, name in enumerate(HELP_FILES))
    help_data = directory_entry(HELP_INDEX_RECORD_ID, HELP_INDEX_NAME) + help_data
    help_index_payload = build_help_index(help_payloads, len(help_data))
    conf_data = directory_entry(NETWORK_RECORD_ID, "network")
    core_data = (directory_entry(8, "sprout") +
                 directory_entry(69, "sessiond") +
                 directory_entry(110, "logind") +
                 directory_entry(111, "logd") +
                 directory_entry(74, "networkd") +
                 directory_entry(75, "deviced") +
                 directory_entry(76, "volumed"))
    state_data = directory_entry(ACCOUNTS_RECORD_ID, "accounts")
    conf_data += directory_entry(SESSION_RECORD_ID, "session")
    conf_data += directory_entry(SECURITY_RECORD_ID, "security")
    session_config = (b"autologin=true\nuser=" + autologin.encode("ascii") +
                      b"\n") if autologin else DEFAULT_SESSION_CONFIG
    session_data = directory_entry(SESSION_CONFIG_RECORD_ID, "config")
    security_data = directory_entry(SECURITY_CONFIG_RECORD_ID, "config")
    network_data = directory_entry(NETWORK_CONFIG_RECORD_ID, "config")
    user_data = directory_entry(DEVELOPER_HOME_RECORD_ID, "developer")
    accounts_data = directory_entry(ACCOUNT_DATABASE_RECORD_ID, "users")
    share_data = (directory_entry(HELP_RECORD_ID, "help") +
                  directory_entry(HARDWARE_RECORD_ID, "hardware"))
    hardware_data = b"".join(
        directory_entry(record_id, installed_name.rsplit("/", 1)[-1])
        for record_id, _payload_name, installed_name in DATA_MANIFEST)
    blocks_needed = 12 + 1 + \
        math.ceil(len(DEFAULT_NETWORK_CONFIG) / B) + \
        math.ceil(len(DEFAULT_ACCOUNT_DATABASE) / B) + \
        math.ceil(len(session_config) / B) + \
        math.ceil(len(DEFAULT_SECURITY_CONFIG) / B) + \
        sum(math.ceil(len(payload) / B) for payload in payloads.values()) + \
        math.ceil(len(help_index_payload) / B) + \
        sum(math.ceil(len(payload) / B) for payload in help_payloads.values()) + \
        math.ceil(len(hardware_data) / B) + \
        sum(math.ceil(len(payload) / B) for payload in data_payloads.values())
    first_block = data_start
    if first_block + blocks_needed >= total_blocks:
        raise SystemExit("populate_mgfs: image has insufficient data blocks")

    def write_block(block, data):
        image[block * B:(block + 1) * B] = data[:B].ljust(B, b"\0")

    write_block(first_block, root_data)
    write_block(first_block + 1, bin_data)
    write_block(first_block + 2, boot_data)
    write_block(first_block + 3, conf_data)
    write_block(first_block + 4, core_data)
    write_block(first_block + 5, state_data)
    write_block(first_block + 6, network_data)
    write_block(first_block + 7, accounts_data)
    write_block(first_block + 8, user_data)
    write_block(first_block + 9, share_data)
    write_block(first_block + 10, help_data)
    write_block(first_block + 11, session_data)
    write_block(first_block + 12, security_data)
    write_block(first_block + 13, hardware_data)

    file_extents = {}
    next_block = first_block + 14
    network_config_blocks = math.ceil(len(DEFAULT_NETWORK_CONFIG) / B)
    for index in range(network_config_blocks):
        write_block(next_block + index,
                    DEFAULT_NETWORK_CONFIG[index * B:(index + 1) * B])
    network_config_start = next_block
    next_block += network_config_blocks
    account_database_blocks = math.ceil(len(DEFAULT_ACCOUNT_DATABASE) / B)
    for index in range(account_database_blocks):
        write_block(next_block + index,
                    DEFAULT_ACCOUNT_DATABASE[index * B:(index + 1) * B])
    account_database_start = next_block
    next_block += account_database_blocks
    session_config_blocks = math.ceil(len(session_config) / B)
    for index in range(session_config_blocks):
        write_block(next_block + index,
                    session_config[index * B:(index + 1) * B])
    session_config_start = next_block
    next_block += session_config_blocks
    security_config_blocks = math.ceil(len(DEFAULT_SECURITY_CONFIG) / B)
    for index in range(security_config_blocks):
        write_block(next_block + index,
                    DEFAULT_SECURITY_CONFIG[index * B:(index + 1) * B])
    security_config_start = next_block
    next_block += security_config_blocks
    kernel_block_count = math.ceil(len(payloads[PITH_RECORD_ID]) / B)
    for index in range(kernel_block_count):
        write_block(next_block + index,
                    payloads[PITH_RECORD_ID][index * B:(index + 1) * B])
    kernel_extents = [(0, next_block, kernel_block_count, 1)]
    next_block += kernel_block_count
    for record_id, _ in SYSTEM_FILES:
        payload = payloads[record_id]
        block_count = math.ceil(len(payload) / B)
        for index in range(block_count):
            write_block(next_block + index, payload[index * B:(index + 1) * B])
        file_extents[record_id] = [(0, next_block, block_count, 1)]
        next_block += block_count
    help_extents = {}
    index_blocks = math.ceil(len(help_index_payload) / B)
    for block_index in range(index_blocks):
        write_block(next_block + block_index,
                    help_index_payload[block_index * B:(block_index + 1) * B])
    help_extents[HELP_INDEX_RECORD_ID] = [(0, next_block, index_blocks, 1)]
    next_block += index_blocks
    for index, name in enumerate(HELP_FILES):
        record_id = HELP_FIRST_RECORD_ID + index
        payload = help_payloads[name]
        block_count = math.ceil(len(payload) / B)
        for block_index in range(block_count):
            write_block(next_block + block_index,
                        payload[block_index * B:(block_index + 1) * B])
        help_extents[record_id] = [(0, next_block, block_count, 1)]
        next_block += block_count

    data_extents = {}
    for record_id, _payload_name, _installed_name in DATA_MANIFEST:
        payload = data_payloads[record_id]
        block_count = math.ceil(len(payload) / B)
        for block_index in range(block_count):
            write_block(next_block + block_index,
                        payload[block_index * B:(block_index + 1) * B])
        data_extents[record_id] = [(0, next_block, block_count, 1)]
        next_block += block_count

    records = [
        make_record(1, 2, len(root_data), [(0, first_block, 1, 2)]),
        make_record(2, 2, len(bin_data), [(0, first_block + 1, 1, 2)]),
        make_record(3, 2, len(boot_data), [(0, first_block + 2, 1, 2)]),
        make_record(4, 2, len(core_data), [(0, first_block + 4, 1, 2)]),
        make_record(5, 2, len(conf_data), [(0, first_block + 3, 1, 2)]),
        make_record(6, 2, permissions=TEMP_PERMISSIONS,
                    child_mutation_policy=1),
        make_record(7, 2, len(user_data), [(0, first_block + 8, 1, 2)]),
        make_record(8, 1, len(payloads[8]), file_extents[8]),
        make_record(PITH_RECORD_ID, 1, len(payloads[PITH_RECORD_ID]), kernel_extents),
    ]
    highest_payload_id = max(max(record_id for record_id, _ in SYSTEM_FILES),
                             max(DATA_RECORD_IDS))
    for record_id in range(10, highest_payload_id + 1):
        if record_id in (NETWORK_RECORD_ID, NETWORK_CONFIG_RECORD_ID,
                         DEVELOPER_HOME_RECORD_ID, ACCOUNTS_RECORD_ID,
                         STATE_RECORD_ID, ACCOUNT_DATABASE_RECORD_ID,
                         SESSION_RECORD_ID, SESSION_CONFIG_RECORD_ID,
                         SHARE_RECORD_ID, HELP_RECORD_ID,
                         HELP_INDEX_RECORD_ID, VOL_RECORD_ID,
                         SECURITY_RECORD_ID, SECURITY_CONFIG_RECORD_ID,
                         HARDWARE_RECORD_ID) or \
                HELP_FIRST_RECORD_ID <= record_id < \
                HELP_FIRST_RECORD_ID + len(HELP_FILES):
            continue
        if record_id in payloads:
            records.append(make_record(record_id, 1, len(payloads[record_id]),
                                       file_extents[record_id]))
        # Record IDs are sparse object identifiers, not physical table slots.
        # Leave unused IDs unallocated instead of manufacturing malformed
        # type-0 records that a validator (and the bootloader reader) must
        # reject.
    records.append(make_record(NETWORK_RECORD_ID, 2, len(network_data),
                               [(0, first_block + 6, 1, 2)]))
    records.append(make_record(NETWORK_CONFIG_RECORD_ID, 1,
                               len(DEFAULT_NETWORK_CONFIG),
                               [(0, network_config_start, network_config_blocks,
                                 1)]))
    records.append(make_record(DEVELOPER_HOME_RECORD_ID, 2,
                               owner_uid=1000,
                               permissions=USER_PERMISSIONS))
    records.append(make_record(STATE_RECORD_ID, 2, len(state_data),
                               [(0, first_block + 5, 1, 2)]))
    records.append(make_record(ACCOUNTS_RECORD_ID, 2, len(accounts_data),
                               [(0, first_block + 7, 1, 2)]))
    records.append(make_record(ACCOUNT_DATABASE_RECORD_ID, 1,
                               len(DEFAULT_ACCOUNT_DATABASE),
                               [(0, account_database_start,
                                 account_database_blocks, 1)]))
    records.append(make_record(SHARE_RECORD_ID, 2, len(share_data),
                               [(0, first_block + 9, 1, 2)]))
    records.append(make_record(HELP_RECORD_ID, 2, len(help_data),
                               [(0, first_block + 10, 1, 2)]))
    records.append(make_record(HELP_INDEX_RECORD_ID, 1,
                               len(help_index_payload),
                               help_extents[HELP_INDEX_RECORD_ID]))
    for index, name in enumerate(HELP_FILES):
        record_id = HELP_FIRST_RECORD_ID + index
        records.append(make_record(record_id, 1, len(help_payloads[name]),
                                   help_extents[record_id]))
    records.append(make_record(VOL_RECORD_ID, 2))
    records.append(make_record(SESSION_RECORD_ID, 2,
                               len(session_data),
                               [(0, first_block + 11, 1, 2)]))
    records.append(make_record(SESSION_CONFIG_RECORD_ID, 1,
                               len(session_config),
                               [(0, session_config_start,
                                 session_config_blocks, 1)]))
    records.append(make_record(SECURITY_RECORD_ID, 2,
                               len(security_data),
                               [(0, first_block + 12, 1, 2)]))
    records.append(make_record(SECURITY_CONFIG_RECORD_ID, 1,
                               len(DEFAULT_SECURITY_CONFIG),
                               [(0, security_config_start,
                               security_config_blocks, 1)]))
    records.append(make_record(HARDWARE_RECORD_ID, 2, len(hardware_data),
                               [(0, first_block + 13, 1, 2)]))
    for record_id, _payload_name, _installed_name in DATA_MANIFEST:
        payload = data_payloads[record_id]
        records.append(make_record(record_id, 1, len(payload),
                                   data_extents[record_id]))

    table_blocks = {}
    for slot, record in enumerate(records):
        block_index = slot // 21
        table = table_blocks.setdefault(
            block_index,
            bytearray(image[(table_start + block_index) * B:
                            (table_start + block_index + 1) * B]))
        table_offset = 24 + (slot % 21) * 192
        table[table_offset:table_offset + 192] = record
    for block_index, table in table_blocks.items():
        checksum(table, 16, B)
        image[(table_start + block_index) * B:
              (table_start + block_index + 1) * B] = table

    record_bitmap = bytearray(image[record_bitmap_start * B:(record_bitmap_start + 1) * B])
    for slot in range(len(records)):
        record_bitmap[24 + slot // 8] |= 1 << (slot % 8)
    checksum(record_bitmap, 16, B)
    image[record_bitmap_start * B:(record_bitmap_start + 1) * B] = record_bitmap

    allocation = bytearray(image[alloc_start * B:(alloc_start + 1) * B])
    for block in range(first_block, next_block):
        relative = block - data_start
        allocation[24 + relative // 8] |= 1 << (relative % 8)
    checksum(allocation, 16, B)
    image[alloc_start * B:(alloc_start + 1) * B] = allocation

    superblock = bytearray(image[:B])
    highest_record_id = max(record_id for record_id, _ in SYSTEM_FILES)
    highest_record_id = max(highest_record_id, SESSION_RECORD_ID,
                            SESSION_CONFIG_RECORD_ID)
    highest_record_id = max(highest_record_id, SHARE_RECORD_ID, HELP_RECORD_ID,
                            HELP_INDEX_RECORD_ID,
                            HELP_FIRST_RECORD_ID + len(HELP_FILES) - 1,
                            VOL_RECORD_ID, SECURITY_RECORD_ID,
                            SECURITY_CONFIG_RECORD_ID, HARDWARE_RECORD_ID,
                            max(DATA_RECORD_IDS))
    w64(superblock, 96, highest_record_id + 1)
    checksum(superblock, 192, 200)
    image[:B] = superblock
    with open(image_path, "wb") as output:
        output.write(image)

if __name__ == "__main__":
    main()
