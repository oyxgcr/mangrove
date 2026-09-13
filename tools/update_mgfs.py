#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Update Mangrove's fixed system payloads without rebuilding user data."""

import math
import os
import re
import struct
import sys

from populate_mgfs import (B, DEFAULT_ACCOUNT_DATABASE,
                           DEFAULT_NETWORK_CONFIG, DEFAULT_SECURITY_CONFIG,
                           DEFAULT_SESSION_CONFIG,
                           default_password_authentication, MAGIC, checksum,
                           crc64,
                           PERMISSION_OWNER_READ, PERMISSION_OWNER_WRITE,
                           PERMISSION_OTHER_READ, PERMISSION_OTHER_WRITE,
                           SYSTEM_PERMISSIONS, TEMP_PERMISSIONS,
                           USER_PERMISSIONS,
                           RECORD_INLINE_DATA, RECORD_OWNER_SHIFT,
                           RECORD_PERMISSIONS_SHIFT,
                           RECORD_CHILD_MUTATION_SHIFT,
                           RECORD_CHILD_MUTATION_OWNER_RESTRICTED,
                           directory_entry, w64)
from populate_mgfs import (HELP_FILES, HELP_INDEX_NAME, build_help_index)
from image_payloads import (BIN_PAYLOAD_NAMES, PAYLOAD_MANIFEST,
                            DATA_MANIFEST, DATA_RECORD_IDS,
                            HARDWARE_RECORD_ID, PAYLOAD_NAMES,
                            PAYLOAD_RECORD_IDS as CANONICAL_PAYLOAD_RECORD_IDS)

EXTENT_LIST_MAGIC = 0x315458455346474D
EXTENTS_PER_LIST_BLOCK = 126
RECORD_BYTES = 192
RECORDS_PER_TABLE_BLOCK = 21
METADATA_CHECKSUM_OFFSET = 16
RECORD_CHECKSUM_OFFSET = 184
SUPER_CHECKSUM_OFFSET = 192
MGFS_FORMAT_MINOR = 2
MGFS_FORMAT_MINOR_LEGACY = 1
VFS_UID_SYSTEM = 0
DEVELOPER_UID = 1000
FIRST_USER_UID = 1001
ACCOUNT_MAX_RECORDS = 64
IDENTITY_USERNAME_CAPACITY = 32
IDENTITY_HOME_CAPACITY = 256
PASSWORD_SALT_BYTES = 16
PASSWORD_HASH_BYTES = 32
PASSWORD_MIN_ITERATIONS = 10000
PASSWORD_MAX_ITERATIONS = 1000000

SYSTEM_RECORDS = {
    8: "sprout",
    69: "sessiond",
    110: "logind",
    111: "logd",
    11: "shoot",
    10: "clear",
    13: "cp",
    14: "say",
    15: "uptime",
    12: "ls",
    16: "locate",
    21: "mv",
    22: "plant",
    23: "read",
    24: "rm",
    25: "version",
    26: "where",
    17: "ping",
    18: "resolve",
    19: "fetch",
    20: "netinfo",
    27: "shutdown",
    28: "reboot",
    29: "power",
    32: "identity",
    37: "user",
    75: "deviced",
    153: "lspci",
    154: "lsusb",
    106: "lsdsk",
    150: "netcfg",
    107: "crew",
    108: "mem",
    151: "time",
    152: "tmon",
    109: "logv",
    159: "mount",
    160: "unmount",
    161: "eject",
    162: "diskutil",
    112: "date",
    163: "info",
}

PITH_RECORD_ID = 9
NETWORKD_RECORD_ID = 74
DEVICED_RECORD_ID = 75
VOLUMED_RECORD_ID = 76
LSPCI_RECORD_ID = 153
LSUSB_RECORD_ID = 154
LOGIND_RECORD_ID = 110
LOGD_RECORD_ID = 111

NETWORK_RECORD_ID = 30
NETWORK_CONFIG_RECORD_ID = 31
DEVELOPER_HOME_RECORD_ID = 33
STATE_RECORD_ID = 34
ACCOUNTS_RECORD_ID = 35
ACCOUNT_DATABASE_RECORD_ID = 36
LEGACY_ACCOUNT_DATABASE_NAME = "users.db"
ACCOUNT_DATABASE_NAME = "users"
SESSION_RECORD_ID = 38
SESSION_CONFIG_RECORD_ID = 39
SECURITY_RECORD_ID = 70
SECURITY_CONFIG_RECORD_ID = 71
SHARE_RECORD_ID = 42
HELP_RECORD_ID = 43
# Keep the fresh-image help range clear of fixed service/config records.
# Incremental updates continue to honor existing help record IDs.
HELP_FIRST_RECORD_ID = 77
HELP_SOURCE_DIR = "share/help"
HELP_NAMES = (HELP_INDEX_NAME,) + HELP_FILES
CONF_RECORD_ID = 5
CORE_RECORD_ID = 4
HOME_RECORD_ID = 7
TEMP_RECORD_ID = 6
VOL_RECORD_ID = 73
RESERVED_SYSTEM_RECORD_IDS = frozenset(SYSTEM_RECORDS) | {
    NETWORK_RECORD_ID, NETWORK_CONFIG_RECORD_ID, DEVELOPER_HOME_RECORD_ID,
    STATE_RECORD_ID, ACCOUNTS_RECORD_ID, ACCOUNT_DATABASE_RECORD_ID,
    CONF_RECORD_ID, CORE_RECORD_ID, HOME_RECORD_ID, TEMP_RECORD_ID,
    VOL_RECORD_ID, PITH_RECORD_ID, SECURITY_RECORD_ID,
    SECURITY_CONFIG_RECORD_ID, NETWORKD_RECORD_ID, DEVICED_RECORD_ID,
    VOLUMED_RECORD_ID,
    LOGD_RECORD_ID,
    HARDWARE_RECORD_ID, *DATA_RECORD_IDS,
}

# This order is the public payload argument order used by make_image.sh.
# Keep it explicit: record IDs are not numerically ordered because the
# directory metadata occupies the intervening records.
# mkdir, rmdir, and the public sprout command retain dynamically discovered
# record IDs on existing images.  Their payload order still comes from the
# shared manifest.
PAYLOAD_RECORD_IDS = tuple(
    None if name in ("mkdir", "rmdir", "sprout") else record_id
    for name, record_id in zip(PAYLOAD_NAMES, CANONICAL_PAYLOAD_RECORD_IDS)
)

NETWORK_NAME = "network"
NETWORK_CONFIG_NAME = "config"


def _account_strip_comment(line):
    quoted = False
    index = 0
    while index + 1 < len(line):
        if line[index] == '"':
            quoted = not quoted
        if not quoted and line[index:index + 2] == "//":
            return line[:index].rstrip()
        index += 1
    return line.rstrip()


def _account_parse_uid(value):
    if not value or not value.isdigit():
        raise RuntimeError("account database has invalid UID")
    uid = int(value, 10)
    if uid > 0xffffffff or uid == VFS_UID_SYSTEM:
        raise RuntimeError("account database has reserved UID")
    return uid


def _account_parse_records(lines, legacy, version):
    records = []
    names = set()
    uids = set()
    initial_count = 0
    username_pattern = re.compile(r"^[a-z][a-z0-9_-]*$")
    for line in lines:
        line = _account_strip_comment(line).strip()
        if not line:
            continue
        tokens = line.split()
        if not tokens or tokens[0] != "account":
            raise RuntimeError("account database has malformed record")
        values = {}
        for token in tokens[1:]:
            if "=" not in token:
                raise RuntimeError("account database has malformed record")
            key, value = token.split("=", 1)
            valid_keys = {"uid", "username", "role", "home", "flags"}
            if version == 2:
                valid_keys |= {"auth", "salt", "iterations", "hash"}
            if key in values or key not in valid_keys or not value:
                raise RuntimeError("account database has malformed record")
            values[key] = value
        required = {"uid", "username", "role", "home", "flags"}
        if version == 2:
            required.add("auth")
        if not required.issubset(values):
            raise RuntimeError("account database has incomplete record")
        uid = _account_parse_uid(values["uid"])
        username = values["username"]
        home = values["home"]
        if len(username) >= IDENTITY_USERNAME_CAPACITY or not username_pattern.fullmatch(username):
            raise RuntimeError("account database has invalid username")
        if values["role"] not in {"regular", "admin"}:
            raise RuntimeError("account database has invalid role")
        expected_home = "/home/" + username
        if legacy and home == "/user/" + username:
            home = expected_home
        if home != expected_home or len(home) >= IDENTITY_HOME_CAPACITY:
            raise RuntimeError("account database has invalid home")
        if legacy:
            flag_tokens = values["flags"].split(",")
            if "disabled" in flag_tokens or any(flag not in {"enabled", "initial"} for flag in flag_tokens):
                raise RuntimeError("account database has unsupported account state")
            flags = "initial" if "initial" in flag_tokens else "none"
        else:
            if values["flags"] not in {"none", "initial"}:
                raise RuntimeError("account database has invalid account flags")
            flags = values["flags"]
        if uid in uids or username in names:
            raise RuntimeError("account database has duplicate account")
        uids.add(uid)
        names.add(username)
        if flags == "initial":
            initial_count += 1
        if version == 1:
            authentication = ("none", "", 0, "")
        elif values["auth"] == "none":
            if any(key in values for key in ("salt", "iterations", "hash")):
                raise RuntimeError("account database has invalid auth metadata")
            authentication = ("none", "", 0, "")
        elif values["auth"] == "pbkdf2-sha256":
            if set(values) != required | {"salt", "iterations", "hash"}:
                raise RuntimeError("account database has incomplete auth metadata")
            salt = values["salt"]
            digest = values["hash"]
            if (len(salt) != PASSWORD_SALT_BYTES * 2 or
                    len(digest) != PASSWORD_HASH_BYTES * 2):
                raise RuntimeError("account database has invalid auth metadata")
            try:
                bytes.fromhex(salt)
                bytes.fromhex(digest)
            except ValueError:
                raise RuntimeError("account database has invalid auth metadata")
            if not values["iterations"].isdigit():
                raise RuntimeError("account database has invalid auth iterations")
            iterations = int(values["iterations"], 10)
            if not PASSWORD_MIN_ITERATIONS <= iterations <= PASSWORD_MAX_ITERATIONS:
                raise RuntimeError("account database has invalid auth iterations")
            authentication = ("pbkdf2-sha256", salt.lower(), iterations,
                              digest.lower())
        else:
            raise RuntimeError("account database has unknown auth algorithm")
        records.append((uid, username, values["role"], home, flags,
                        authentication))
    if not records or initial_count != 1:
        raise RuntimeError("account database must contain one initial account")
    return records


def parse_account_database(payload):
    if len(payload) == 0 or len(payload) > 16384:
        raise RuntimeError("account database has invalid size")
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        raise RuntimeError("account database is not ASCII")
    lines = text.splitlines()
    meaningful = []
    for line in lines:
        stripped = _account_strip_comment(line).strip()
        if stripped:
            meaningful.append(stripped)
    if not meaningful:
        raise RuntimeError("account database is empty")
    first = meaningful[0]
    if first == "MangroveAccounts 1":
        records = _account_parse_records(meaningful[1:], True, 1)
        legacy = True
        next_uid = max(FIRST_USER_UID, max(record[0] for record in records) + 1)
    elif first == "version=1":
        if len(meaningful) < 2 or not meaningful[1].startswith("next_uid="):
            raise RuntimeError("account database has no next_uid")
        next_text = meaningful[1][len("next_uid="):]
        if not next_text.isdigit():
            raise RuntimeError("account database has invalid next_uid")
        next_uid = int(next_text, 10)
        if next_uid < FIRST_USER_UID or next_uid >= 0x100000000:
            raise RuntimeError("account database has invalid next_uid")
        records = _account_parse_records(meaningful[2:], False, 1)
        legacy = False
    elif first == "version=2":
        if len(meaningful) < 2 or not meaningful[1].startswith("next_uid="):
            raise RuntimeError("account database has no next_uid")
        next_text = meaningful[1][len("next_uid="):]
        if not next_text.isdigit():
            raise RuntimeError("account database has invalid next_uid")
        next_uid = int(next_text, 10)
        if next_uid < FIRST_USER_UID or next_uid >= 0x100000000:
            raise RuntimeError("account database has invalid next_uid")
        records = _account_parse_records(meaningful[2:], False, 2)
        legacy = False
    else:
        raise RuntimeError("unsupported account database version")
    if next_uid <= max(record[0] for record in records):
        raise RuntimeError("account database next_uid is not monotonic")
    return records, next_uid, legacy


def serialize_account_database(records, next_uid):
    output = ["version=2", "next_uid=%d" % next_uid, ""]
    for uid, username, role, home, flags, authentication in records:
        algorithm, salt, iterations, digest = authentication
        line = ("account uid=%d username=%s role=%s home=%s flags=%s auth=%s" %
                (uid, username, role, home, flags, algorithm))
        if algorithm == "pbkdf2-sha256":
            line += " salt=%s iterations=%d hash=%s" % (
                salt, iterations, digest)
        output.append(line)
    payload = ("\n".join(output) + "\n").encode("ascii")
    if len(payload) > 16384:
        raise RuntimeError("account database exceeds maximum size")
    return payload


def migrate_account_database(payload):
    records, next_uid, legacy = parse_account_database(payload)
    converted = serialize_account_database(records, next_uid)
    return converted, legacy or converted != payload


def ensure_developer_password(payload):
    """Give a passwordless development identity its one-time live default."""
    records, next_uid, _ = parse_account_database(payload)
    changed = False
    updated = []
    for record in records:
        uid, name, role, home, flags, authentication = record
        if name == "developer" and authentication[0] == "none":
            authentication = default_password_authentication()
            changed = True
        updated.append((uid, name, role, home, flags, authentication))
    return serialize_account_database(updated, next_uid), changed


def u64(buf, offset):
    return struct.unpack_from("<Q", buf, offset)[0]


def record_offset(image, table_start, record_id, record_count):
    for slot in range(record_count):
        table_block = slot // RECORDS_PER_TABLE_BLOCK
        table_slot = slot % RECORDS_PER_TABLE_BLOCK
        offset = (table_start + table_block) * B + 24 + table_slot * RECORD_BYTES
        if u64(image, offset + 16) == record_id:
            return offset
    if 0 < record_id <= record_count:
        slot = record_id - 1
        table_block = slot // RECORDS_PER_TABLE_BLOCK
        table_slot = slot % RECORDS_PER_TABLE_BLOCK
        return (table_start + table_block) * B + 24 + table_slot * RECORD_BYTES
    raise RuntimeError("system Record ID %d is outside the record table" % record_id)


def record_slot_from_offset(offset, table_start):
    relative = offset - table_start * B
    offset_in_block = relative % B
    if relative < 0 or offset_in_block < 24 or \
            (offset_in_block - 24) % RECORD_BYTES:
        raise RuntimeError("invalid MGFS Record table offset")
    table_block = relative // B
    slot_in_block = (offset_in_block - 24) // RECORD_BYTES
    if slot_in_block >= RECORDS_PER_TABLE_BLOCK:
        raise RuntimeError("invalid MGFS Record table slot")
    return table_block * RECORDS_PER_TABLE_BLOCK + slot_in_block


def record_table_offset(layout, slot):
    return (layout["record_table_start"] + slot // RECORDS_PER_TABLE_BLOCK) * B + \
        24 + (slot % RECORDS_PER_TABLE_BLOCK) * RECORD_BYTES


def record_slot_allocated(image, layout, slot):
    offset = layout["record_bitmap_start"] * B + 24 + slot // 8
    return bool(image[offset] & (1 << (slot % 8)))


def set_record_allocated(image, layout, slot, value):
    offset = layout["record_bitmap_start"] * B + 24 + slot // 8
    mask = 1 << (slot % 8)
    if value:
        image[offset] |= mask
    else:
        image[offset] &= ~mask & 0xff


def all_record_ids(image, layout):
    result = set()
    for slot in range(layout["record_count"]):
        offset = record_table_offset(layout, slot)
        record_id = u64(image, offset + 16)
        if record_id:
            result.add(record_id)
    return result


def allocate_record_slots(image, layout, count, excluded_slots=()):
    excluded = set(excluded_slots)
    slots = []
    for slot in range(layout["record_count"]):
        if slot in excluded or record_slot_allocated(image, layout, slot):
            continue
        set_record_allocated(image, layout, slot, True)
        slots.append(slot)
        if len(slots) == count:
            return slots
    raise RuntimeError("MGFS Record table is full while adding network config")


def directory_entries(payload):
    entries = []
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < 32:
            raise RuntimeError("truncated MGFS directory entry")
        name_length = u64(payload, offset + 8)
        entry_size = (32 + name_length + 7) & ~7
        if not name_length or entry_size > len(payload) - offset:
            raise RuntimeError("invalid MGFS directory entry")
        name = bytes(payload[offset + 32:offset + 32 + name_length])
        entries.append((offset, entry_size, u64(payload, offset),
                        u64(payload, offset + 16), name))
        offset += entry_size
    return entries


def directory_find(payload, name):
    wanted = name.encode("utf-8")
    for offset, size, record_id, flags, entry_name in directory_entries(payload):
        if flags == 1 and entry_name == wanted:
            return record_id
    return None


def directory_rename(payload, old_name, new_name):
    """Rename one live directory entry without changing its Record ID."""
    old_bytes = old_name.encode("utf-8")
    new_bytes = new_name.encode("utf-8")
    old_entry = None
    for offset, size, record_id, flags, name in directory_entries(payload):
        if flags != 1:
            continue
        if name == new_bytes:
            raise RuntimeError("directory already contains %s" % new_name)
        if name == old_bytes:
            if old_entry is not None:
                raise RuntimeError("directory contains duplicate %s" % old_name)
            old_entry = (offset, size, record_id)
    if old_entry is None:
        raise RuntimeError("directory has no %s entry" % old_name)
    replacement = directory_entry(old_entry[2], new_name)
    if len(replacement) != old_entry[1]:
        raise RuntimeError("directory entry rename changes its allocated size")
    result = bytearray(payload)
    result[old_entry[0]:old_entry[0] + old_entry[1]] = replacement
    return bytes(result)


def directory_remove(payload, name):
    """Remove one live entry while preserving all other directory bytes."""
    wanted = name.encode("utf-8")
    result = bytearray()
    found = False
    for offset, size, record_id, flags, entry_name in directory_entries(payload):
        if flags == 1 and entry_name == wanted:
            if found:
                raise RuntimeError("directory contains duplicate %s" % name)
            found = True
            continue
        result.extend(payload[offset:offset + size])
    if not found:
        raise RuntimeError("directory has no %s entry" % name)
    return bytes(result)


def extent_values(record, offset):
    return (u64(record, offset), u64(record, offset + 8),
            u64(record, offset + 16), u64(record, offset + 24))


def record_extents(image, record):
    extent_count = u64(record, 40)
    inline_count = u64(record, 48)
    list_block = u64(record, 56)
    extents = []
    list_blocks = []

    for index in range(inline_count):
        extents.append(extent_values(record, 64 + index * 32))

    while list_block:
        if list_block in list_blocks:
            raise RuntimeError("cyclic system extent-list chain")
        list_blocks.append(list_block)
        offset = list_block * B
        if u64(image, offset) != EXTENT_LIST_MAGIC:
            raise RuntimeError("invalid system extent-list block")
        entry_count = u64(image, offset + 24)
        if not entry_count or entry_count > EXTENTS_PER_LIST_BLOCK:
            raise RuntimeError("invalid system extent-list entry count")
        for index in range(entry_count):
            extents.append(extent_values(image, offset + 64 + index * 32))
        list_block = u64(image, offset + 16)

    if len(extents) != extent_count:
        raise RuntimeError("incomplete system extent-list chain")
    return extents, list_blocks


def record_payload(image, record):
    size = u64(record, 32)
    extents, _ = record_extents(image, record)
    payload = bytearray()
    for _, physical, count, flags in extents:
        if flags not in (1, 2):
            raise RuntimeError("invalid system extent")
        for block in range(physical, physical + count):
            offset = block * B
            payload.extend(image[offset:offset + B])
    return bytes(payload[:size])


def record_extent_layout_valid(image, layout, record):
    """Validate the logical ordering used by a Record's extent chain."""
    try:
        extents, list_blocks = record_extents(image, record)
    except (IndexError, RuntimeError, struct.error):
        return False
    expected_logical = 0
    for logical, physical, count, flags in extents:
        if logical != expected_logical or count == 0 or flags not in (1, 2):
            return False
        if physical < layout["data_start"] or \
                physical + count > layout["data_start"] + layout["data_blocks"]:
            return False
        expected_logical += count
    for block in list_blocks:
        if block < layout["data_start"] or \
                block >= layout["data_start"] + layout["data_blocks"]:
            return False
    required_blocks = (u64(record, 32) + B - 1) // B
    return expected_logical >= required_blocks


def record_owner(record):
    return (u64(record, 8) >> RECORD_OWNER_SHIFT) & 0xffffffff


def record_permissions(record):
    return (u64(record, 8) >> RECORD_PERMISSIONS_SHIFT) & 0xf


def record_child_mutation_policy(record):
    return 1 if u64(record, 8) & (1 << RECORD_CHILD_MUTATION_SHIFT) else 0


def bitmap_location(layout, bit):
    bitmap_block = bit // 32576
    byte_offset = bitmap_block * B + 24 + (bit % 32576) // 8
    return layout["allocation_bitmap_start"] * B + byte_offset, 1 << (bit % 8)


def set_allocated(image, layout, physical_block, value):
    data_start = layout["data_start"]
    data_blocks = layout["data_blocks"]
    if physical_block < data_start or physical_block >= data_start + data_blocks:
        raise RuntimeError("system block lies outside the data area")
    offset, mask = bitmap_location(layout, physical_block - data_start)
    if value:
        image[offset] |= mask
    else:
        image[offset] &= ~mask & 0xff


def is_allocated(image, layout, physical_block):
    offset, mask = bitmap_location(layout, physical_block - layout["data_start"])
    return bool(image[offset] & mask)


def allocate_blocks(image, layout, count, reserved):
    blocks = []
    if count == 0:
        return blocks
    for physical in range(layout["data_start"],
                          layout["data_start"] + layout["data_blocks"]):
        if physical in reserved or is_allocated(image, layout, physical):
            continue
        set_allocated(image, layout, physical, True)
        reserved.add(physical)
        blocks.append(physical)
        if len(blocks) == count:
            return blocks
    raise RuntimeError("MGFS data area is full while updating system files")


def make_extents(blocks, flags=1):
    if not blocks:
        return []
    extents = []
    start = previous = blocks[0]
    logical = 0
    for block in blocks[1:]:
        if block == previous + 1:
            previous = block
            continue
        count = previous - start + 1
        extents.append((logical, start, count, flags))
        logical += count
        start = previous = block
    count = previous - start + 1
    extents.append((logical, start, count, flags))
    return extents


def record_flags(owner_uid=VFS_UID_SYSTEM, permissions=SYSTEM_PERMISSIONS,
                 inline_data=False, child_mutation_policy=0):
    return ((RECORD_INLINE_DATA if inline_data else 0) |
            (owner_uid << RECORD_OWNER_SHIFT) |
            (permissions << RECORD_PERMISSIONS_SHIFT) |
            (RECORD_CHILD_MUTATION_OWNER_RESTRICTED << RECORD_CHILD_MUTATION_SHIFT
             if child_mutation_policy else 0))


def write_record(image, offset, record_id, record_type, generation, payload,
                 extents, list_head, owner_uid=VFS_UID_SYSTEM,
                 permissions=SYSTEM_PERMISSIONS, child_mutation_policy=0):
    record = bytearray(RECORD_BYTES)
    w64(record, 0, record_type)
    w64(record, 8, record_flags(owner_uid, permissions,
                               record_type == 1 and not extents,
                               child_mutation_policy if record_type == 2 else 0))
    w64(record, 16, record_id)
    w64(record, 24, generation)
    w64(record, 32, len(payload))
    w64(record, 40, len(extents))
    w64(record, 48, min(2, len(extents)))
    w64(record, 56, list_head)
    for index, extent in enumerate(extents[:2]):
        for value_index, value in enumerate(extent):
            w64(record, 64 + index * 32 + value_index * 8, value)
    checksum(record, RECORD_CHECKSUM_OFFSET, RECORD_BYTES)
    image[offset:offset + RECORD_BYTES] = record


def write_extent_lists(image, record_id, extents, list_blocks):
    remaining = extents[2:]
    for index, physical in enumerate(list_blocks):
        block = bytearray(B)
        w64(block, 0, EXTENT_LIST_MAGIC)
        w64(block, 8, record_id)
        w64(block, 16, list_blocks[index + 1] if index + 1 < len(list_blocks) else 0)
        entries = remaining[index * EXTENTS_PER_LIST_BLOCK:
                           (index + 1) * EXTENTS_PER_LIST_BLOCK]
        w64(block, 24, len(entries))
        for entry_index, extent in enumerate(entries):
            for value_index, value in enumerate(extent):
                w64(block, 64 + entry_index * 32 + value_index * 8, value)
        checksum(block, 32, B)
        offset = physical * B
        image[offset:offset + B] = block


def replace_directory_payload(image, layout, record_id, payload, reserved):
    """Replace a directory payload while retaining its existing entries."""
    offset = record_offset(image, layout["record_table_start"], record_id,
                           layout["record_count"])
    old_record = bytes(image[offset:offset + RECORD_BYTES])
    old_extents, old_list_blocks = record_extents(image, old_record)
    old_data_blocks = []
    for _, physical, count, flags in old_extents:
        if flags != 2:
            raise RuntimeError("directory Record has non-directory extents")
        old_data_blocks.extend(range(physical, physical + count))

    needed = math.ceil(len(payload) / B)
    data_blocks = old_data_blocks[:]
    if len(data_blocks) < needed:
        data_blocks.extend(allocate_blocks(image, layout,
                                            needed - len(data_blocks), reserved))
    selected_blocks = data_blocks[:needed]
    extents = make_extents(selected_blocks, 2)
    list_count = math.ceil(max(0, len(extents) - 2) / EXTENTS_PER_LIST_BLOCK)
    list_blocks = allocate_blocks(image, layout, list_count, reserved)

    for index, block in enumerate(selected_blocks):
        start = index * B
        image[block * B:(block + 1) * B] = payload[start:start + B].ljust(B, b"\0")
    write_extent_lists(image, record_id, extents, list_blocks)
    write_record(image, offset, record_id, 2, u64(old_record, 24) + 1,
                 payload, extents, list_blocks[0] if list_blocks else 0,
                 record_owner(old_record), record_permissions(old_record),
                 record_child_mutation_policy(old_record))

    for block in old_data_blocks[len(selected_blocks):]:
        set_allocated(image, layout, block, False)
    for block in old_list_blocks:
        if block not in list_blocks:
            set_allocated(image, layout, block, False)
    return record_slot_from_offset(offset, layout["record_table_start"]) // \
        RECORDS_PER_TABLE_BLOCK


def replace_file_payload(image, layout, record_id, payload, reserved):
    """Replace a file payload while retaining its ownership and Record ID."""
    offset = record_offset(image, layout["record_table_start"], record_id,
                           layout["record_count"])
    old_record = bytes(image[offset:offset + RECORD_BYTES])
    if u64(old_record, 0) != 1:
        raise RuntimeError("account database is not a file")
    old_extents, old_list_blocks = record_extents(image, old_record)
    old_data_blocks = []
    for _, physical, count, flags in old_extents:
        if flags != 1:
            raise RuntimeError("account database has invalid data extents")
        old_data_blocks.extend(range(physical, physical + count))

    needed = math.ceil(len(payload) / B)
    data_blocks = allocate_blocks(image, layout, needed, reserved)
    extents = make_extents(data_blocks, 1)
    list_count = math.ceil(max(0, len(extents) - 2) / EXTENTS_PER_LIST_BLOCK)
    list_blocks = allocate_blocks(image, layout, list_count, reserved)
    for index, block in enumerate(data_blocks):
        start = index * B
        image[block * B:(block + 1) * B] = payload[start:start + B].ljust(B, b"\0")
    write_extent_lists(image, record_id, extents, list_blocks)
    write_record(image, offset, record_id, 1, u64(old_record, 24) + 1,
                 payload, extents, list_blocks[0] if list_blocks else 0,
                 record_owner(old_record), record_permissions(old_record))

    for block in old_data_blocks:
        set_allocated(image, layout, block, False)
    for block in old_list_blocks:
        set_allocated(image, layout, block, False)
    return record_slot_from_offset(offset, layout["record_table_start"]) // \
        RECORDS_PER_TABLE_BLOCK


def refresh_table_checksum(image, layout, table_index):
    offset = (layout["record_table_start"] + table_index) * B
    block = bytearray(image[offset:offset + B])
    checksum(block, METADATA_CHECKSUM_OFFSET, B)
    image[offset:offset + B] = block


def refresh_record_bitmap_checksum(image, layout):
    for index in range(layout["record_bitmap_blocks"]):
        offset = (layout["record_bitmap_start"] + index) * B
        block = bytearray(image[offset:offset + B])
        checksum(block, METADATA_CHECKSUM_OFFSET, B)
        image[offset:offset + B] = block


def scrub_free_record(image, layout, slot, record):
    """Return whether a stale free Record can be safely discarded.

    The kernel treats the Record bitmap as authoritative and, historically,
    released a slot without clearing its old table bytes.  Such bytes are
    harmless tombstones only when the old Record is structurally valid and
    all of its referenced data/list blocks have already been released.  Do
    not guess when those conditions are not provable: an allocated reference
    may indicate an interrupted deletion and must remain a hard error.
    """
    record_type = u64(record, 0)
    flags = u64(record, 8)
    record_id = u64(record, 16)
    generation = u64(record, 24)
    size = u64(record, 32)
    extent_count = u64(record, 40)
    inline_count = u64(record, 48)
    list_head = u64(record, 56)
    known_flags = RECORD_INLINE_DATA | ((1 << 32) - 1) << RECORD_OWNER_SHIFT | \
        ((1 << 4) - 1) << RECORD_PERMISSIONS_SHIFT | \
        (RECORD_CHILD_MUTATION_OWNER_RESTRICTED <<
         RECORD_CHILD_MUTATION_SHIFT)

    if (record_type not in (1, 2) or record_id == 0 or generation == 0 or
            flags & ~known_flags or
            (record_type == 1 and
             flags & (RECORD_CHILD_MUTATION_OWNER_RESTRICTED <<
                      RECORD_CHILD_MUTATION_SHIFT)) or
            ((flags >> RECORD_PERMISSIONS_SHIFT) & 0xF) == 0):
        raise RuntimeError("free MGFS Record slot %d is malformed" % slot)
    checked = bytearray(record)
    stored_checksum = u64(checked, RECORD_CHECKSUM_OFFSET)
    w64(checked, RECORD_CHECKSUM_OFFSET, 0)
    if stored_checksum != crc64(checked):
        raise RuntimeError("free MGFS Record slot %d has a bad checksum" % slot)

    if flags & RECORD_INLINE_DATA:
        if (record_type != 1 or size > 56 or extent_count != 0 or
                inline_count != 0 or list_head != 0):
            raise RuntimeError("free MGFS Record slot %d is malformed" % slot)
        return True

    if (inline_count > 2 or inline_count > extent_count or
            (extent_count == 0 and list_head != 0) or
            (extent_count <= 2 and list_head != 0) or
            not record_extent_layout_valid(image, layout, record)):
        raise RuntimeError("free MGFS Record slot %d has invalid extents" % slot)
    try:
        extents, list_blocks = record_extents(image, record)
    except (IndexError, RuntimeError, struct.error):
        raise RuntimeError("free MGFS Record slot %d has invalid extents" % slot)
    for _, physical, count, _ in extents:
        if any(is_allocated(image, layout, block)
               for block in range(physical, physical + count)):
            raise RuntimeError(
                "free MGFS Record slot %d retains allocated data" % slot)
    if any(is_allocated(image, layout, block) for block in list_blocks):
        raise RuntimeError(
            "free MGFS Record slot %d retains an allocated extent list" % slot)
    return True


def reconcile_record_bitmap(image, layout):
    """Reconcile Record bitmap state without guessing about live data.

    The kernel uses the Record bitmap as the ownership authority.  A normal
    runtime deletion can therefore leave old Record bytes in a now-free slot;
    scrub those bytes only after proving that the old Record and every block it
    references are detached.  An allocated reference remains a hard error.
    """
    changed = False
    zero_record = b"\0" * RECORD_BYTES
    table_indices = set()
    for slot in range(layout["record_count"]):
        offset = record_table_offset(layout, slot)
        record = bytes(image[offset:offset + RECORD_BYTES])
        allocated = record_slot_allocated(image, layout, slot)
        if allocated and record == zero_record:
            set_record_allocated(image, layout, slot, False)
            changed = True
            continue
        if allocated:
            record_type = u64(record, 0)
            record_id = u64(record, 16)
            if record_type not in (1, 2) or record_id == 0:
                raise RuntimeError(
                    "allocated MGFS Record slot %d is malformed" % slot)
        elif record != zero_record:
            scrub_free_record(image, layout, slot, record)
            image[offset:offset + RECORD_BYTES] = zero_record
            table_indices.add(slot // RECORDS_PER_TABLE_BLOCK)
            changed = True
    if changed:
        refresh_record_bitmap_checksum(image, layout)
        for table_index in table_indices:
            refresh_table_checksum(image, layout, table_index)
    return changed


def ensure_hierarchy_layout(image, layout):
    """Install the canonical root directories and migrate defined root names."""
    root_offset = record_offset(image, layout["record_table_start"], 1,
                                layout["record_count"])
    root_record = bytes(image[root_offset:root_offset + RECORD_BYTES])
    if u64(root_record, 0) != 2:
        raise RuntimeError("root Record is not a directory")
    root_payload = record_payload(image, root_record)
    changed = False
    table_indices = set()
    used_ids = all_record_ids(image, layout)
    next_id = max(2, u64(image, 96), max(used_ids, default=1) + 1)
    reserved_slots = {record_id - 1 for record_id in RESERVED_SYSTEM_RECORD_IDS
                      if 0 < record_id <= layout["record_count"]}
    reserved = set()

    def record_type(record_id, path):
        offset = record_offset(image, layout["record_table_start"], record_id,
                               layout["record_count"])
        record = bytes(image[offset:offset + RECORD_BYTES])
        if u64(record, 0) != 2:
            raise RuntimeError("%s is not a directory" % path)
        return offset

    for old_name, new_name in (("user", "home"), ("state", "sys"),
                               ("mount", "vol")):
        old_id = directory_find(root_payload, old_name)
        new_id = directory_find(root_payload, new_name)
        if old_id is None:
            continue
        record_type(old_id, old_name)
        if new_id is not None and new_id != old_id:
            raise RuntimeError("root contains both %s and %s" %
                               (old_name, new_name))
        root_payload = directory_remove(root_payload, old_name)
        if new_id is None:
            root_payload += directory_entry(old_id, new_name)
        changed = True

    required = ("bin", "boot", "conf", "core", "home", "share", "sys",
                "temp", "vol")
    temp_was_present = directory_find(root_payload, "temp") is not None
    for name in required:
        record_id = directory_find(root_payload, name)
        if record_id is not None:
            record_type(record_id, name)
            continue
        while next_id in used_ids or next_id in RESERVED_SYSTEM_RECORD_IDS:
            next_id += 1
        record_id = next_id
        next_id += 1
        used_ids.add(record_id)
        slot = allocate_record_slots(image, layout, 1, reserved_slots)[0]
        table_indices.add(_create_payload_record(
            image, layout, record_id, slot, 2, b"", 2, reserved))
        root_payload += directory_entry(record_id, name)
        changed = True

    # /temp is the canonical shared temporary-data directory. Existing
    # metadata is preserved; a newly established directory receives the
    # canonical system ownership and shared directory permissions. Its
    # persistent child-mutation policy prevents ordinary users from removing
    # or renaming one another's entries.
    temp_id = directory_find(root_payload, "temp")
    if temp_was_present:
        temp_offset = record_offset(image, layout["record_table_start"],
                                     temp_id, layout["record_count"])
        temp_record = bytes(image[temp_offset:temp_offset + RECORD_BYTES])
        temp_owner = record_owner(temp_record)
        temp_permissions = record_permissions(temp_record)
    else:
        temp_owner = VFS_UID_SYSTEM
        temp_permissions = TEMP_PERMISSIONS
    temp_security_index = rewrite_record_security(
        image, layout, temp_id, temp_owner, temp_permissions, 1)
    if temp_security_index is not None:
        table_indices.add(temp_security_index)
        changed = True

    if root_payload != record_payload(image, root_record):
        table_indices.add(replace_directory_payload(
            image, layout, 1, root_payload, reserved))
        changed = True
    for table_index in table_indices:
        refresh_table_checksum(image, layout, table_index)
    if not changed:
        return False
    refresh_record_bitmap_checksum(image, layout)
    refresh_metadata_checksums(image, layout)
    superblock = bytearray(image[:B])
    w64(superblock, 96, next_id)
    checksum(superblock, SUPER_CHECKSUM_OFFSET, 200)
    image[:B] = superblock
    return True


def ensure_boot_kernel(image, layout, payload):
    """Keep the current Pith payload in the MGFS /boot directory."""
    root_offset = record_offset(image, layout["record_table_start"], 1,
                                layout["record_count"])
    root_record = bytes(image[root_offset:root_offset + RECORD_BYTES])
    root_payload = record_payload(image, root_record)
    boot_id = directory_find(root_payload, "boot")
    if boot_id is None:
        raise RuntimeError("root directory has no boot directory")
    boot_offset = record_offset(image, layout["record_table_start"], boot_id,
                                layout["record_count"])
    boot_record = bytes(image[boot_offset:boot_offset + RECORD_BYTES])
    if u64(boot_record, 0) != 2:
        raise RuntimeError("boot Record is not a directory")
    boot_payload = record_payload(image, boot_record)
    current_id = directory_find(boot_payload, "pith.elf")
    changed = False
    table_indices = set()

    for old_name in ("kernel.elf", "KERNEL.ELF", "rhizome.elf",
                     "RHIZOME.ELF", "pith"):
        old_id = directory_find(boot_payload, old_name)
        if old_id is None or old_id == current_id:
            continue
        boot_payload = directory_remove(boot_payload, old_name)
        release_record(image, layout, old_id)
        changed = True

    used_ids = all_record_ids(image, layout)
    next_id = max(2, u64(image, 96), max(used_ids, default=1) + 1)
    reserved_slots = {record_id - 1 for record_id in RESERVED_SYSTEM_RECORD_IDS
                      if 0 < record_id <= layout["record_count"]}
    if current_id is None:
        if PITH_RECORD_ID not in used_ids:
            current_id = PITH_RECORD_ID
        else:
            while next_id in used_ids or next_id in RESERVED_SYSTEM_RECORD_IDS:
                next_id += 1
            current_id = next_id
            next_id += 1
        slot = allocate_record_slots(image, layout, 1, reserved_slots)[0]
        table_indices.add(_create_payload_record(
            image, layout, current_id, slot, 1, payload, 1, set()))
        boot_payload += directory_entry(current_id, "pith.elf")
        changed = True
    elif _record_type(image, layout, current_id)[0] != 1:
        raise RuntimeError("boot/pith.elf is not a file")

    if boot_payload != record_payload(image, boot_record):
        table_indices.add(replace_directory_payload(
            image, layout, boot_id, boot_payload, set()))
        changed = True
    security_index = rewrite_record_security(
        image, layout, current_id, VFS_UID_SYSTEM, SYSTEM_PERMISSIONS)
    if security_index is not None:
        table_indices.add(security_index)
        changed = True
    for table_index in table_indices:
        refresh_table_checksum(image, layout, table_index)
    if not changed:
        return boot_id, current_id, False
    refresh_record_bitmap_checksum(image, layout)
    refresh_metadata_checksums(image, layout)
    superblock = bytearray(image[:B])
    w64(superblock, 96, next_id)
    checksum(superblock, SUPER_CHECKSUM_OFFSET, 200)
    image[:B] = superblock
    return boot_id, current_id, True


def ensure_network_config(image, layout):
    """Migrate network configuration into administrator-owned /conf."""
    root_offset = record_offset(image, layout["record_table_start"], 1,
                                layout["record_count"])
    root_record = bytes(image[root_offset:root_offset + RECORD_BYTES])
    root_payload = record_payload(image, root_record)
    conf_id = directory_find(root_payload, "conf")
    core_id = directory_find(root_payload, "core")
    if conf_id is None or core_id is None:
        raise RuntimeError("root is missing conf or core directory")

    def get_directory(record_id, path):
        offset = record_offset(image, layout["record_table_start"], record_id,
                               layout["record_count"])
        record = bytes(image[offset:offset + RECORD_BYTES])
        if u64(record, 0) != 2:
            raise RuntimeError("%s is not a directory" % path)
        return record_payload(image, record)

    conf_payload = get_directory(conf_id, "conf")
    core_payload = get_directory(core_id, "core")
    new_network_id = directory_find(conf_payload, NETWORK_NAME)
    old_network_id = directory_find(core_payload, NETWORK_NAME)
    if new_network_id is not None and old_network_id is not None and \
            new_network_id != old_network_id:
        raise RuntimeError("both conf/network and core/network exist")
    network_id = new_network_id if new_network_id is not None else old_network_id
    changed = False
    table_indices = set()
    if old_network_id is not None:
        core_payload = directory_remove(core_payload, NETWORK_NAME)
        changed = True
    if new_network_id is None and network_id is not None:
        conf_payload += directory_entry(network_id, NETWORK_NAME)
        changed = True

    used_ids = all_record_ids(image, layout)
    next_id = max(2, u64(image, 96), max(used_ids, default=1) + 1)
    reserved_slots = {record_id - 1 for record_id in RESERVED_SYSTEM_RECORD_IDS
                      if 0 < record_id <= layout["record_count"]}
    reserved = set()

    if network_id is None:
        while next_id in used_ids or next_id in RESERVED_SYSTEM_RECORD_IDS:
            next_id += 1
        network_id = next_id
        next_id += 1
        used_ids.add(network_id)
        slot = allocate_record_slots(image, layout, 1, reserved_slots)[0]
        table_indices.add(_create_payload_record(
            image, layout, network_id, slot, 2, b"", 2, reserved))
        conf_payload += directory_entry(network_id, NETWORK_NAME)
        changed = True

    network_payload = get_directory(network_id, "conf/network")
    config_id = directory_find(network_payload, NETWORK_CONFIG_NAME)
    if config_id is not None:
        config_offset = record_offset(image, layout["record_table_start"],
                                      config_id, layout["record_count"])
        config_record = bytes(image[config_offset:config_offset + RECORD_BYTES])
        if u64(config_record, 0) != 1:
            raise RuntimeError("conf/network/config is not a file")
    else:
        while next_id in used_ids or next_id in RESERVED_SYSTEM_RECORD_IDS:
            next_id += 1
        config_id = next_id
        next_id += 1
        used_ids.add(config_id)
        slot = allocate_record_slots(image, layout, 1, reserved_slots)[0]
        table_indices.add(_create_payload_record(
            image, layout, config_id, slot, 1, DEFAULT_NETWORK_CONFIG, 1,
            reserved))
        network_payload += directory_entry(config_id, NETWORK_CONFIG_NAME)
        changed = True

    old_network_payload = get_directory(network_id, "conf/network")
    if network_payload != old_network_payload:
        table_indices.add(replace_directory_payload(
            image, layout, network_id, network_payload, reserved))
        changed = True
    old_conf_payload = get_directory(conf_id, "conf")
    if conf_payload != old_conf_payload:
        table_indices.add(replace_directory_payload(
            image, layout, conf_id, conf_payload, reserved))
        changed = True
    old_core_payload = get_directory(core_id, "core")
    if core_payload != old_core_payload:
        table_indices.add(replace_directory_payload(
            image, layout, core_id, core_payload, reserved))
        changed = True
    for table_index in table_indices:
        refresh_table_checksum(image, layout, table_index)
    if not changed:
        return False
    refresh_record_bitmap_checksum(image, layout)
    refresh_metadata_checksums(image, layout)
    superblock = bytearray(image[:B])
    w64(superblock, 96, next_id)
    checksum(superblock, SUPER_CHECKSUM_OFFSET, 200)
    image[:B] = superblock
    return True


def ensure_security_config(image, layout):
    """Install the administrator authorization policy under /conf/security."""
    root_offset = record_offset(image, layout["record_table_start"], 1,
                                layout["record_count"])
    root_record = bytes(image[root_offset:root_offset + RECORD_BYTES])
    root_payload = record_payload(image, root_record)
    conf_id = directory_find(root_payload, "conf")
    if conf_id is None:
        raise RuntimeError("root is missing conf directory")

    def get_directory(record_id, path):
        offset = record_offset(image, layout["record_table_start"], record_id,
                               layout["record_count"])
        record = bytes(image[offset:offset + RECORD_BYTES])
        if u64(record, 0) != 2:
            raise RuntimeError("%s is not a directory" % path)
        return record_payload(image, record)

    conf_payload = get_directory(conf_id, "conf")
    security_id = directory_find(conf_payload, "security")
    if security_id is not None and _record_type(image, layout, security_id)[0] != 2:
        raise RuntimeError("conf/security is not a directory")

    changed = False
    table_indices = set()
    used_ids = all_record_ids(image, layout)
    next_id = max(2, u64(image, 96), max(used_ids, default=1) + 1)
    reserved_slots = {record_id - 1 for record_id in RESERVED_SYSTEM_RECORD_IDS
                      if 0 < record_id <= layout["record_count"]}
    reserved = set()

    def allocate_id():
        nonlocal next_id
        while next_id in used_ids or next_id in RESERVED_SYSTEM_RECORD_IDS:
            next_id += 1
        result = next_id
        used_ids.add(result)
        next_id += 1
        return result

    missing_security = security_id is None
    security_id = security_id if security_id is not None else SECURITY_RECORD_ID
    if missing_security:
        if security_id in used_ids:
            security_id = allocate_id()
        else:
            used_ids.add(security_id)
            next_id = max(next_id, security_id + 1)
        conf_payload += directory_entry(security_id, "security")
        changed = True

    security_payload = (b"" if missing_security else
                        get_directory(security_id, "conf/security"))
    config_id = directory_find(security_payload, "config")
    if config_id is not None:
        if _record_type(image, layout, config_id)[0] != 1:
            raise RuntimeError("conf/security/config is not a file")
    else:
        config_id = SECURITY_CONFIG_RECORD_ID
        if config_id in used_ids:
            config_id = allocate_id()
        else:
            used_ids.add(config_id)
            next_id = max(next_id, config_id + 1)
        slots = allocate_record_slots(image, layout, 1, reserved_slots)
        table_indices.add(_create_payload_record(
            image, layout, config_id, slots[0], 1,
            DEFAULT_SECURITY_CONFIG, 1, reserved))
        security_payload += directory_entry(config_id, "config")
        changed = True

    if missing_security:
        slots = allocate_record_slots(image, layout, 1, reserved_slots)
        table_indices.add(_create_payload_record(
            image, layout, security_id, slots[0], 2, security_payload, 2,
            reserved))
    else:
        old_security_payload = get_directory(security_id, "conf/security")
        if security_payload != old_security_payload:
            table_indices.add(replace_directory_payload(
                image, layout, security_id, security_payload, reserved))
            changed = True

    old_conf_payload = get_directory(conf_id, "conf")
    if conf_payload != old_conf_payload:
        table_indices.add(replace_directory_payload(
            image, layout, conf_id, conf_payload, reserved))
        changed = True

    for record_id in (security_id, config_id):
        security_index = rewrite_record_security(
            image, layout, record_id, VFS_UID_SYSTEM, SYSTEM_PERMISSIONS)
        if security_index is not None:
            table_indices.add(security_index)
            changed = True
    for table_index in table_indices:
        refresh_table_checksum(image, layout, table_index)
    if not changed:
        return False
    refresh_record_bitmap_checksum(image, layout)
    refresh_metadata_checksums(image, layout)
    superblock = bytearray(image[:B])
    w64(superblock, 96, next_id)
    checksum(superblock, SUPER_CHECKSUM_OFFSET, 200)
    image[:B] = superblock
    return True


def migrate_managed_logs(image, layout):
    """Move the old boot-log subtree from /core into managed /sys state."""
    root_offset = record_offset(image, layout["record_table_start"], 1,
                                layout["record_count"])
    root_payload = record_payload(
        image, bytes(image[root_offset:root_offset + RECORD_BYTES]))
    core_id = directory_find(root_payload, "core")
    sys_id = directory_find(root_payload, "sys")
    if core_id is None or sys_id is None:
        raise RuntimeError("root has no core or sys directory")

    def get_directory(record_id, path):
        offset = record_offset(image, layout["record_table_start"], record_id,
                               layout["record_count"])
        record = bytes(image[offset:offset + RECORD_BYTES])
        if u64(record, 0) != 2:
            raise RuntimeError("%s is not a directory" % path)
        return record_payload(image, record)

    core_payload = get_directory(core_id, "core")
    sys_payload = get_directory(sys_id, "sys")
    old_logs_id = directory_find(core_payload, "logs")
    new_logs_id = directory_find(sys_payload, "logs")
    if old_logs_id is not None and new_logs_id is not None and \
            old_logs_id != new_logs_id:
        raise RuntimeError("both core/logs and sys/logs exist")
    if old_logs_id is None:
        return False
    logs_offset = record_offset(image, layout["record_table_start"],
                                old_logs_id, layout["record_count"])
    logs_record = bytes(image[logs_offset:logs_offset + RECORD_BYTES])
    if u64(logs_record, 0) != 2:
        raise RuntimeError("core/logs is not a directory")
    core_payload = directory_remove(core_payload, "logs")
    if new_logs_id is None:
        sys_payload += directory_entry(old_logs_id, "logs")
    table_indices = {
        replace_directory_payload(image, layout, core_id, core_payload, set()),
    }
    if new_logs_id is None:
        table_indices.add(replace_directory_payload(
            image, layout, sys_id, sys_payload, set()))
    for table_index in table_indices:
        refresh_table_checksum(image, layout, table_index)
    refresh_record_bitmap_checksum(image, layout)
    refresh_metadata_checksums(image, layout)
    return True


def _record_type(image, layout, record_id):
    offset = record_offset(image, layout["record_table_start"], record_id,
                           layout["record_count"])
    return u64(image, offset), offset


def _create_payload_record(image, layout, record_id, slot, record_type,
                           payload, extent_flags, reserved, owner_uid=0,
                           permissions=SYSTEM_PERMISSIONS):
    blocks = allocate_blocks(image, layout, math.ceil(len(payload) / B),
                             reserved)
    for index, block in enumerate(blocks):
        start = index * B
        image[block * B:(block + 1) * B] = payload[start:start + B].ljust(B, b"\0")
    extents = make_extents(blocks, extent_flags)
    list_count = math.ceil(max(0, len(extents) - 2) / EXTENTS_PER_LIST_BLOCK)
    list_blocks = allocate_blocks(image, layout, list_count, reserved)
    write_extent_lists(image, record_id, extents, list_blocks)
    write_record(image, record_table_offset(layout, slot), record_id,
                 record_type, 1, payload, extents,
                 list_blocks[0] if list_blocks else 0, owner_uid, permissions)
    return record_table_offset(layout, slot) // B - layout["record_table_start"]


def ensure_help_layout(image, layout):
    """Install /share/help records without disturbing guest-owned records."""
    root_offset = record_offset(image, layout["record_table_start"], 1,
                                layout["record_count"])
    root_record = bytes(image[root_offset:root_offset + RECORD_BYTES])
    if u64(root_record, 0) != 2:
        raise RuntimeError("root Record is not a directory")
    root_payload = record_payload(image, root_record)
    share_id = directory_find(root_payload, "share")
    if share_id is not None and _record_type(image, layout, share_id)[0] != 2:
        raise RuntimeError("root/share is not a directory")

    share_payload = b""
    if share_id is not None:
        share_offset = _record_type(image, layout, share_id)[1]
        share_payload = record_payload(
            image, bytes(image[share_offset:share_offset + RECORD_BYTES]))
    help_id = directory_find(share_payload, "help")
    if help_id is not None and _record_type(image, layout, help_id)[0] != 2:
        raise RuntimeError("share/help is not a directory")

    help_payload = b""
    if help_id is not None:
        help_offset = _record_type(image, layout, help_id)[1]
        help_payload = record_payload(
            image, bytes(image[help_offset:help_offset + RECORD_BYTES]))

    # The public log reader was renamed after release.  Preserve its Record
    # and move only the managed directory entry; user data is untouched.
    renamed = False
    for old_name, new_name in (("logs", "logv"),
                               ("disks", "lsdsk"), ("network", "netinfo")):
        old_id = directory_find(help_payload, old_name)
        new_id = directory_find(help_payload, new_name)
        if old_id is not None and new_id is not None and old_id != new_id:
            raise RuntimeError("share/help contains both %s and %s" %
                               (old_name, new_name))
        if old_id is not None and new_id is None:
            help_payload = directory_rename(help_payload, old_name, new_name)
            renamed = True

    old_names = {"copy", "list", "move", "remove", "task", "tasks", "memory",
                 "lsdev", "devices"}
    removed_ids = []
    for name in old_names:
        old_id = directory_find(help_payload, name)
        if old_id is not None:
            help_payload = directory_remove(help_payload, name)
            removed_ids.append(old_id)
    for old_id in removed_ids:
        release_record(image, layout, old_id)

    source_payloads = {
        name: open(os.path.join(HELP_SOURCE_DIR, name), "rb").read()
        for name in HELP_FILES
    }
    existing = {name: record_id for _, _, record_id, flags, name in
                directory_entries(help_payload) if flags == 1}
    for name in HELP_NAMES:
        record_id = existing.get(name.encode("utf-8"))
        if record_id is not None and _record_type(image, layout, record_id)[0] != 1:
            raise RuntimeError("share/help/%s is not a file" % name)

    missing_share = share_id is None
    missing_help = help_id is None
    missing_files = [name for name in HELP_NAMES
                     if name.encode("utf-8") not in existing]
    final_help_size = len(help_payload)
    for name in missing_files:
        final_help_size += len(directory_entry(0, name))
    source_payloads[HELP_INDEX_NAME] = build_help_index(
        source_payloads, final_help_size)
    missing_count = int(missing_share) + int(missing_help) + len(missing_files)
    used_ids = all_record_ids(image, layout)
    next_id = max(2, u64(image, 96), max(used_ids, default=1) + 1)
    reserved_slots = {record_id - 1 for record_id in
                      (set(SYSTEM_RECORDS) | {
                          NETWORK_RECORD_ID, NETWORK_CONFIG_RECORD_ID,
                          DEVELOPER_HOME_RECORD_ID, STATE_RECORD_ID,
                          ACCOUNTS_RECORD_ID, ACCOUNT_DATABASE_RECORD_ID,
                          SESSION_RECORD_ID, SESSION_CONFIG_RECORD_ID,
                          NETWORKD_RECORD_ID,
                          VOLUMED_RECORD_ID,
                          SECURITY_RECORD_ID, SECURITY_CONFIG_RECORD_ID,
                      }) if 0 < record_id <= layout["record_count"]}
    slots = allocate_record_slots(image, layout, missing_count,
                                   reserved_slots) if missing_count else []
    slot_index = 0
    reserved = set()
    table_indices = set()

    def allocate_id():
        nonlocal next_id
        while next_id in used_ids or next_id in RESERVED_SYSTEM_RECORD_IDS:
            next_id += 1
        result = next_id
        used_ids.add(result)
        next_id += 1
        return result

    def create_directory():
        nonlocal slot_index
        record_id = allocate_id()
        slot = slots[slot_index]
        slot_index += 1
        table_indices.add(_create_payload_record(
            image, layout, record_id, slot, 2, b"", 2, reserved))
        return record_id

    changed = renamed or bool(removed_ids)
    if share_id is None:
        share_id = create_directory()
        root_payload += directory_entry(share_id, "share")
        changed = True
    if help_id is None:
        help_id = create_directory()
        share_payload += directory_entry(help_id, "help")
        changed = True

    for name in missing_files:
        record_id = allocate_id()
        slot = slots[slot_index]
        slot_index += 1
        table_indices.add(_create_payload_record(
            image, layout, record_id, slot, 1, source_payloads[name], 1,
            reserved))
        help_payload += directory_entry(record_id, name)
        existing[name.encode("utf-8")] = record_id
        changed = True

    share_offset = _record_type(image, layout, share_id)[1]
    old_share_payload = record_payload(
        image, bytes(image[share_offset:share_offset + RECORD_BYTES]))
    if share_payload != old_share_payload:
        table_indices.add(replace_directory_payload(
            image, layout, share_id, share_payload, reserved))
        changed = True
    help_offset = _record_type(image, layout, help_id)[1]
    old_help_payload = record_payload(
        image, bytes(image[help_offset:help_offset + RECORD_BYTES]))
    if help_payload != old_help_payload:
        table_indices.add(replace_directory_payload(
            image, layout, help_id, help_payload, reserved))
        changed = True
    if root_payload != record_payload(image, root_record):
        table_indices.add(replace_directory_payload(
            image, layout, 1, root_payload, reserved))
        changed = True

    for name in HELP_NAMES:
        record_id = existing.get(name.encode("utf-8"))
        offset = _record_type(image, layout, record_id)[1]
        record = bytes(image[offset:offset + RECORD_BYTES])
        if record_payload(image, record) != source_payloads[name]:
            table_indices.add(replace_file_payload(
                image, layout, record_id, source_payloads[name], reserved))
            changed = True
        security_index = rewrite_record_security(
            image, layout, record_id, VFS_UID_SYSTEM, SYSTEM_PERMISSIONS)
        if security_index is not None:
            table_indices.add(security_index)
            changed = True

    for record_id in (share_id, help_id):
        security_index = rewrite_record_security(
            image, layout, record_id, VFS_UID_SYSTEM, SYSTEM_PERMISSIONS)
        if security_index is not None:
            table_indices.add(security_index)
            changed = True

    for table_index in table_indices:
        refresh_table_checksum(image, layout, table_index)
    if not changed:
        return False
    refresh_record_bitmap_checksum(image, layout)
    refresh_metadata_checksums(image, layout)
    superblock = bytearray(image[:B])
    w64(superblock, 96, next_id)
    checksum(superblock, SUPER_CHECKSUM_OFFSET, 200)
    image[:B] = superblock
    return True


def ensure_hardware_layout(image, layout, data_payloads):
    """Install /share/hardware ID data without making it a boot dependency."""
    root_offset = record_offset(image, layout["record_table_start"], 1,
                                layout["record_count"])
    root_record = bytes(image[root_offset:root_offset + RECORD_BYTES])
    root_payload = record_payload(image, root_record)
    share_id = directory_find(root_payload, "share")
    if share_id is None or _record_type(image, layout, share_id)[0] != 2:
        raise RuntimeError("root/share is not a directory")
    share_offset = _record_type(image, layout, share_id)[1]
    share_record = bytes(image[share_offset:share_offset + RECORD_BYTES])
    share_payload = record_payload(image, share_record)
    hardware_id = directory_find(share_payload, "hardware")
    if hardware_id is not None and \
            _record_type(image, layout, hardware_id)[0] != 2:
        raise RuntimeError("share/hardware is not a directory")

    hardware_payload = b""
    if hardware_id is not None:
        hardware_offset = _record_type(image, layout, hardware_id)[1]
        hardware_record = bytes(image[hardware_offset:
                                     hardware_offset + RECORD_BYTES])
        hardware_payload = record_payload(image, hardware_record)
    existing = {name: record_id for _, _, record_id, flags, name in
                directory_entries(hardware_payload) if flags == 1}
    for _record_id, payload_name, installed_name in DATA_MANIFEST:
        name = installed_name.rsplit("/", 1)[-1].encode("utf-8")
        record_id = existing.get(name)
        if record_id is not None and _record_type(image, layout, record_id)[0] != 1:
            raise RuntimeError("share/hardware/%s is not a file" %
                               name.decode("utf-8"))

    missing = int(hardware_id is None) + sum(
        1 for _, _, installed_name in DATA_MANIFEST
        if installed_name.rsplit("/", 1)[-1].encode("utf-8") not in existing)
    used_ids = all_record_ids(image, layout)
    next_id = max(2, u64(image, 96), max(used_ids, default=1) + 1)
    slots = allocate_record_slots(image, layout, missing,
                                  {record_id - 1
                                   for record_id in RESERVED_SYSTEM_RECORD_IDS
                                   if 0 < record_id <= layout["record_count"]}) \
        if missing else []
    reserved = set()
    table_indices = set()
    slot_index = 0
    changed = False

    def allocate_id():
        nonlocal next_id
        while next_id in used_ids or next_id in RESERVED_SYSTEM_RECORD_IDS:
            next_id += 1
        result = next_id
        used_ids.add(result)
        next_id += 1
        return result

    if hardware_id is None:
        hardware_id = allocate_id()
        table_indices.add(_create_payload_record(
            image, layout, hardware_id, slots[slot_index], 2, b"", 2,
            reserved))
        slot_index += 1
        share_payload += directory_entry(hardware_id, "hardware")
        changed = True

    for _, payload_name, installed_name in DATA_MANIFEST:
        name = installed_name.rsplit("/", 1)[-1]
        encoded_name = name.encode("utf-8")
        record_id = existing.get(encoded_name)
        payload = data_payloads[payload_name]
        if record_id is None:
            record_id = allocate_id()
            table_indices.add(_create_payload_record(
                image, layout, record_id, slots[slot_index], 1, payload, 1,
                reserved))
            slot_index += 1
            hardware_payload += directory_entry(record_id, name)
            existing[encoded_name] = record_id
            changed = True
        else:
            offset = _record_type(image, layout, record_id)[1]
            record = bytes(image[offset:offset + RECORD_BYTES])
            if record_payload(image, record) != payload:
                table_indices.add(replace_file_payload(
                    image, layout, record_id, payload, reserved))
                changed = True
        security_index = rewrite_record_security(
            image, layout, record_id, VFS_UID_SYSTEM, SYSTEM_PERMISSIONS)
        if security_index is not None:
            table_indices.add(security_index)
            changed = True

    hardware_offset = _record_type(image, layout, hardware_id)[1]
    old_hardware_payload = record_payload(
        image, bytes(image[hardware_offset:hardware_offset + RECORD_BYTES]))
    if hardware_payload != old_hardware_payload:
        table_indices.add(replace_directory_payload(
            image, layout, hardware_id, hardware_payload, reserved))
        changed = True
    if share_payload != record_payload(image, share_record):
        table_indices.add(replace_directory_payload(
            image, layout, share_id, share_payload, reserved))
        changed = True
    for record_id in (hardware_id, share_id):
        security_index = rewrite_record_security(
            image, layout, record_id, VFS_UID_SYSTEM, SYSTEM_PERMISSIONS)
        if security_index is not None:
            table_indices.add(security_index)
            changed = True
    for table_index in table_indices:
        refresh_table_checksum(image, layout, table_index)
    if not changed:
        return False
    refresh_record_bitmap_checksum(image, layout)
    refresh_metadata_checksums(image, layout)
    superblock = bytearray(image[:B])
    w64(superblock, 96, next_id)
    checksum(superblock, SUPER_CHECKSUM_OFFSET, 200)
    image[:B] = superblock
    return True


def migrate_command_names(image, layout):
    """Rename the old public file utilities in /bin without changing Records."""
    bin_offset = record_offset(image, layout["record_table_start"], 2,
                               layout["record_count"])
    bin_record = bytes(image[bin_offset:bin_offset + RECORD_BYTES])
    if u64(bin_record, 0) != 2:
        raise RuntimeError("bin Record is not a directory")
    payload = record_payload(image, bin_record)
    changed = False
    for old_name, new_name in (("copy", "cp"), ("list", "ls"),
                               ("move", "mv"), ("remove", "rm"),
                               ("logs", "logv"),
                               ("disks", "lsdsk"), ("network", "netinfo"),
                               ("tasks", "crew"), ("task", "crew"),
                               ("memory", "mem")):
        old_id = directory_find(payload, old_name)
        new_id = directory_find(payload, new_name)
        if old_id is None:
            continue
        if new_id is not None and new_id != old_id:
            raise RuntimeError("bin contains both %s and %s" %
                               (old_name, new_name))
        payload = directory_remove(payload, old_name)
        payload += directory_entry(old_id, new_name)
        changed = True
    for old_name in ("lsdev", "devices"):
        old_id = directory_find(payload, old_name)
        if old_id is None:
            continue
        payload = directory_remove(payload, old_name)
        release_record(image, layout, old_id)
        changed = True
    if not changed:
        return False
    reserved = set()
    table_index = replace_directory_payload(image, layout, 2, payload, reserved)
    refresh_table_checksum(image, layout, table_index)
    refresh_record_bitmap_checksum(image, layout)
    refresh_metadata_checksums(image, layout)
    return True


def ensure_system_core_program(image, layout, payload, name="sprout",
                               preferred_id=None, allow_public_duplicate=False):
    """Keep one internal executable under the system core namespace."""
    root_offset = record_offset(image, layout["record_table_start"], 1,
                                layout["record_count"])
    root_payload = record_payload(
        image, bytes(image[root_offset:root_offset + RECORD_BYTES]))
    core_id = directory_find(root_payload, "core")
    if core_id is None:
        raise RuntimeError("root directory has no core directory")
    core_offset = record_offset(image, layout["record_table_start"], core_id,
                                layout["record_count"])
    core_record = bytes(image[core_offset:core_offset + RECORD_BYTES])
    if u64(core_record, 0) != 2:
        raise RuntimeError("core Record is not a directory")
    core_payload = record_payload(image, core_record)

    bin_offset = record_offset(image, layout["record_table_start"], 2,
                               layout["record_count"])
    bin_record = bytes(image[bin_offset:bin_offset + RECORD_BYTES])
    if u64(bin_record, 0) != 2:
        raise RuntimeError("bin Record is not a directory")
    bin_payload = record_payload(image, bin_record)
    core_program = directory_find(core_payload, name)
    bin_program = directory_find(bin_payload, name)
    if core_program is not None and bin_program is not None and \
            core_program != bin_program and not allow_public_duplicate:
        raise RuntimeError("both core/%s and bin/%s exist" % (name, name))
    # The public sprout client intentionally shares the basename with the
    # internal supervisor.  On older images, however, /bin/sprout is the
    # former supervisor location and must be migrated into /core.  Only move
    # it when its payload still identifies it as that old internal program;
    # never steal a distinct public client executable.
    old_internal_bin = False
    if core_program is None and bin_program is not None:
        bin_offset = record_offset(image, layout["record_table_start"],
                                   bin_program, layout["record_count"])
        bin_record = bytes(image[bin_offset:bin_offset + RECORD_BYTES])
        old_internal_bin = record_payload(image, bin_record) == payload
    program_id = core_program if core_program is not None else \
        (bin_program if old_internal_bin else None)
    changed = False
    table_indices = set()
    next_id = None
    if old_internal_bin:
        bin_payload = directory_remove(bin_payload, name)
        changed = True
    if core_program is None and program_id is not None:
        core_payload += directory_entry(program_id, name)
        changed = True
    if program_id is None:
        used_ids = all_record_ids(image, layout)
        if preferred_id is not None and preferred_id not in used_ids:
            program_id = preferred_id
            next_id = max(2, u64(image, 96), max(used_ids, default=1) + 1)
        else:
            next_id = max(2, u64(image, 96), max(used_ids, default=1) + 1)
            while next_id in used_ids or next_id in RESERVED_SYSTEM_RECORD_IDS:
                next_id += 1
            program_id = next_id
            next_id += 1
        slots = allocate_record_slots(
            image, layout, 1,
            {record_id - 1 for record_id in RESERVED_SYSTEM_RECORD_IDS
             if 0 < record_id <= layout["record_count"]})
        table_indices.add(_create_payload_record(
            image, layout, program_id, slots[0], 1, payload, 1, set()))
        core_payload += directory_entry(program_id, name)
        changed = True
    if bin_payload != record_payload(image, bin_record):
        table_indices.add(replace_directory_payload(
            image, layout, 2, bin_payload, set()))
        changed = True
    if core_payload != record_payload(image, core_record):
        table_indices.add(replace_directory_payload(
            image, layout, core_id, core_payload, set()))
        changed = True
    security_index = rewrite_record_security(
        image, layout, program_id, VFS_UID_SYSTEM, SYSTEM_PERMISSIONS)
    if security_index is not None:
        table_indices.add(security_index)
        changed = True
    for table_index in table_indices:
        refresh_table_checksum(image, layout, table_index)
    if not changed:
        return core_id, program_id, False
    refresh_record_bitmap_checksum(image, layout)
    refresh_metadata_checksums(image, layout)
    if next_id is not None:
        superblock = bytearray(image[:B])
        w64(superblock, 96, next_id)
        checksum(superblock, SUPER_CHECKSUM_OFFSET, 200)
        image[:B] = superblock
    return core_id, program_id, True


def ensure_system_commands(image, layout, payloads):
    """Ensure every installed command has one file Record in /bin.

    Existing Records are found by their directory names.  Newly introduced
    commands receive ordinary free Record IDs so guest-created Records can
    never be overwritten by a later system update.
    """
    bin_offset = record_offset(image, layout["record_table_start"], 2,
                               layout["record_count"])
    bin_record = bytes(image[bin_offset:bin_offset + RECORD_BYTES])
    if u64(bin_record, 0) != 2:
        raise RuntimeError("bin Record is not a directory")
    bin_payload = record_payload(image, bin_record)
    command_records = {}
    for name in BIN_PAYLOAD_NAMES:
        record_id = directory_find(bin_payload, name)
        if record_id is not None:
            if name in command_records:
                raise RuntimeError("bin contains duplicate %s" % name)
            if _record_type(image, layout, record_id)[0] != 1:
                raise RuntimeError("bin/%s is not a file" % name)
            command_records[name] = record_id

    missing = [name for name in BIN_PAYLOAD_NAMES if name not in command_records]
    used_ids = all_record_ids(image, layout)
    next_id = max(2, u64(image, 96), max(used_ids, default=1) + 1)
    reserved_slots = {record_id - 1 for record_id in
                      (set(SYSTEM_RECORDS) | {
                          NETWORK_RECORD_ID, NETWORK_CONFIG_RECORD_ID,
                          DEVELOPER_HOME_RECORD_ID, STATE_RECORD_ID,
                          ACCOUNTS_RECORD_ID, ACCOUNT_DATABASE_RECORD_ID,
                          SESSION_RECORD_ID, SESSION_CONFIG_RECORD_ID,
                          NETWORKD_RECORD_ID, DEVICED_RECORD_ID,
                          VOLUMED_RECORD_ID,
                      }) if 0 < record_id <= layout["record_count"]}
    slots = allocate_record_slots(image, layout, len(missing),
                                   reserved_slots) if missing else []
    reserved = set()
    table_indices = set()
    changed = False

    def allocate_id():
        nonlocal next_id
        while next_id in used_ids or next_id in SYSTEM_RECORDS:
            next_id += 1
        result = next_id
        used_ids.add(result)
        next_id += 1
        return result

    for index, name in enumerate(missing):
        record_id = allocate_id()
        slot = slots[index]
        table_indices.add(_create_payload_record(
            image, layout, record_id, slot, 1, payloads[name], 1, reserved))
        command_records[name] = record_id
        bin_payload += directory_entry(record_id, name)
        changed = True

    if bin_payload != record_payload(image, bin_record):
        table_indices.add(replace_directory_payload(
            image, layout, 2, bin_payload, reserved))
        changed = True

    for name, record_id in command_records.items():
        security_index = rewrite_record_security(
            image, layout, record_id, VFS_UID_SYSTEM, SYSTEM_PERMISSIONS)
        if security_index is not None:
            table_indices.add(security_index)
            changed = True
    for table_index in table_indices:
        refresh_table_checksum(image, layout, table_index)
    if changed:
        refresh_record_bitmap_checksum(image, layout)
        refresh_metadata_checksums(image, layout)
        superblock = bytearray(image[:B])
        w64(superblock, 96, next_id)
        checksum(superblock, SUPER_CHECKSUM_OFFSET, 200)
        image[:B] = superblock
    return command_records, changed


def ensure_session_config(image, layout, username):
    """Install /conf/session/config and retire the old marker subtree."""
    if username and not re.fullmatch(r"[a-z][a-z0-9_-]*", username):
        raise RuntimeError("invalid autologin username")

    root_offset = record_offset(image, layout["record_table_start"], 1,
                                layout["record_count"])
    root_record = bytes(image[root_offset:root_offset + RECORD_BYTES])
    root_payload = record_payload(image, root_record)

    def get_directory(record_id, path):
        offset = record_offset(image, layout["record_table_start"], record_id,
                               layout["record_count"])
        record = bytes(image[offset:offset + RECORD_BYTES])
        if u64(record, 0) != 2:
            raise RuntimeError("%s is not a directory" % path)
        return record, record_payload(image, record)

    conf_id = directory_find(root_payload, "conf")
    sys_id = directory_find(root_payload, "sys")
    core_id = directory_find(root_payload, "core")
    if conf_id is None or sys_id is None or core_id is None:
        raise RuntimeError("root is missing conf, sys, or core directory")
    conf_record, conf_payload = get_directory(conf_id, "conf")
    sys_record, sys_payload = get_directory(sys_id, "sys")
    core_record, core_payload = get_directory(core_id, "core")

    session_id = directory_find(conf_payload, "session")
    old_ids = []
    for parent_name, parent_payload in (("sys", sys_payload),
                                        ("core", core_payload)):
        old_id = directory_find(parent_payload, "session")
        if old_id is not None:
            old_ids.append((parent_name, old_id))
    old_session_id = old_ids[0][1] if old_ids else None
    if any(old_id != old_session_id for _, old_id in old_ids):
        raise RuntimeError("legacy session markers disagree")

    old_marker_id = None
    old_marker_name = None
    if old_session_id is not None:
        _, old_session_payload = get_directory(old_session_id,
                                                "legacy session")
        entries = list(directory_entries(old_session_payload))
        for _, _, child_id, flags, name in entries:
            if flags != 1 or name != b"autologin":
                raise RuntimeError("legacy session contains unsupported data")
            if old_marker_id is not None:
                raise RuntimeError("legacy session has duplicate markers")
            old_marker_id = child_id
        if old_marker_id is not None:
            marker_offset = record_offset(image, layout["record_table_start"],
                                          old_marker_id, layout["record_count"])
            marker_record = bytes(image[marker_offset:marker_offset + RECORD_BYTES])
            if u64(marker_record, 0) != 1:
                raise RuntimeError("legacy session marker is not a file")
            try:
                old_marker_name = record_payload(image, marker_record).decode(
                    "ascii").strip()
            except UnicodeDecodeError:
                raise RuntimeError("legacy session marker is not ASCII")
            if not re.fullmatch(r"[a-z][a-z0-9_-]*", old_marker_name):
                raise RuntimeError("legacy session marker has invalid user")

    table_indices = set()
    changed = False
    used_ids = all_record_ids(image, layout)
    next_id = max(2, u64(image, 96), max(used_ids, default=1) + 1)
    reserved_slots = {record_id - 1 for record_id in RESERVED_SYSTEM_RECORD_IDS
                      if 0 < record_id <= layout["record_count"]}

    def allocate_id():
        nonlocal next_id
        while next_id in used_ids or next_id in RESERVED_SYSTEM_RECORD_IDS:
            next_id += 1
        result = next_id
        used_ids.add(result)
        next_id += 1
        return result

    config_id = None
    session_payload = b""
    if session_id is not None:
        _, session_payload = get_directory(session_id, "conf/session")
        config_id = directory_find(session_payload, "config")
        if config_id is not None:
            config_offset = record_offset(image, layout["record_table_start"],
                                          config_id, layout["record_count"])
            config_record = bytes(image[config_offset:config_offset + RECORD_BYTES])
            if u64(config_record, 0) != 1:
                raise RuntimeError("conf/session/config is not a file")

    need_session = session_id is None
    need_config = config_id is None and old_marker_id is None
    slots = allocate_record_slots(image, layout,
                                   int(need_session) + int(need_config),
                                   reserved_slots) \
        if need_session or need_config else []
    slot_index = 0
    reserved = set()

    if session_id is None:
        session_id = allocate_id()
        session_slot = slots[slot_index]
        slot_index += 1
        table_indices.add(_create_payload_record(
            image, layout, session_id, session_slot, 2, b"", 2, reserved))
        session_payload = b""
        conf_payload += directory_entry(session_id, "session")
        changed = True

    old_config_payload = None
    if config_id is None:
        if old_marker_id is not None:
            config_id = old_marker_id
            old_config_payload = ("autologin=true\nuser=%s\n" %
                                  (old_marker_name or "")).encode("ascii")
        else:
            config_id = allocate_id()
            old_config_payload = DEFAULT_SESSION_CONFIG if not username else (
                "autologin=true\nuser=%s\n" % username).encode("ascii")
            config_slot = slots[slot_index]
            slot_index += 1
            table_indices.add(_create_payload_record(
                image, layout, config_id, config_slot, 1,
                old_config_payload, 1, reserved))
        if old_marker_id is not None:
            table_indices.add(replace_file_payload(
                image, layout, config_id, old_config_payload, reserved))
            session_payload = directory_remove(session_payload, "autologin")
        session_payload += directory_entry(config_id, "config")
        changed = True
    elif old_marker_id is not None:
        session_payload = directory_remove(session_payload, "autologin")
        table_indices.add(release_record(image, layout, old_marker_id))
        changed = True

    if session_payload != record_payload(image, bytes(image[
            record_offset(image, layout["record_table_start"], session_id,
                          layout["record_count"]):
            record_offset(image, layout["record_table_start"], session_id,
                          layout["record_count"]) + RECORD_BYTES])):
        table_indices.add(replace_directory_payload(
            image, layout, session_id, session_payload, reserved))
        changed = True

    released_sessions = set()
    for parent_name, old_id in old_ids:
        if parent_name == "sys":
            sys_payload = directory_remove(sys_payload, "session")
        else:
            core_payload = directory_remove(core_payload, "session")
        changed = True
        if old_id != session_id and old_id not in released_sessions:
            table_indices.add(release_record(image, layout, old_id))
            released_sessions.add(old_id)

    if conf_payload != record_payload(image, conf_record):
        table_indices.add(replace_directory_payload(
            image, layout, conf_id, conf_payload, reserved))
        changed = True
    if sys_payload != record_payload(image, sys_record):
        table_indices.add(replace_directory_payload(
            image, layout, sys_id, sys_payload, reserved))
        changed = True
    if core_payload != record_payload(image, core_record):
        table_indices.add(replace_directory_payload(
            image, layout, core_id, core_payload, reserved))
        changed = True

    for record_id in (session_id, config_id):
        security_index = rewrite_record_security(
            image, layout, record_id, VFS_UID_SYSTEM, SYSTEM_PERMISSIONS)
        if security_index is not None:
            table_indices.add(security_index)
            changed = True
    for table_index in table_indices:
        refresh_table_checksum(image, layout, table_index)
    if not table_indices and not changed:
        return False
    refresh_record_bitmap_checksum(image, layout)
    refresh_metadata_checksums(image, layout)
    superblock = bytearray(image[:B])
    w64(superblock, 96, next_id)
    checksum(superblock, SUPER_CHECKSUM_OFFSET, 200)
    image[:B] = superblock
    return True


def rewrite_record_security(image, layout, record_id, owner_uid, permissions,
                            child_mutation_policy=None):
    offset = record_offset(image, layout["record_table_start"], record_id,
                           layout["record_count"])
    record = bytearray(image[offset:offset + RECORD_BYTES])
    old_flags = u64(record, 8)
    if child_mutation_policy is None:
        child_mutation_policy = (record_child_mutation_policy(record)
                                 if u64(record, 0) == 2 else 0)
    new_flags = record_flags(owner_uid, permissions,
                             bool(old_flags & RECORD_INLINE_DATA),
                             child_mutation_policy)
    if old_flags == new_flags:
        return None
    w64(record, 8, new_flags)
    checksum(record, RECORD_CHECKSUM_OFFSET, RECORD_BYTES)
    image[offset:offset + RECORD_BYTES] = record
    return record_slot_from_offset(offset, layout["record_table_start"]) // \
        RECORDS_PER_TABLE_BLOCK


def release_record(image, layout, record_id):
    offset = record_offset(image, layout["record_table_start"], record_id,
                           layout["record_count"])
    record = bytes(image[offset:offset + RECORD_BYTES])
    extents, list_blocks = record_extents(image, record)
    for _, physical, count, _ in extents:
        for block in range(physical, physical + count):
            set_allocated(image, layout, block, False)
    for block in list_blocks:
        set_allocated(image, layout, block, False)
    set_record_allocated(image, layout,
                         record_slot_from_offset(offset,
                                                 layout["record_table_start"]),
                         False)
    image[offset:offset + RECORD_BYTES] = b"\0" * RECORD_BYTES
    return record_slot_from_offset(offset, layout["record_table_start"]) // \
        RECORDS_PER_TABLE_BLOCK


def assign_subtree_security(image, layout, record_id, owner_uid, permissions,
                            visited=None):
    if visited is None:
        visited = set()
    if record_id in visited:
        raise RuntimeError("cycle in user directory tree")
    visited.add(record_id)
    offset = record_offset(image, layout["record_table_start"], record_id,
                           layout["record_count"])
    record = bytes(image[offset:offset + RECORD_BYTES])
    table_indices = set()
    changed = rewrite_record_security(image, layout, record_id, owner_uid,
                                      permissions)
    if changed is not None:
        table_indices.add(changed)
    if u64(record, 0) == 2:
        for _, _, child_id, flags, _ in directory_entries(record_payload(image, record)):
            if flags == 1:
                table_indices.update(assign_subtree_security(
                    image, layout, child_id, owner_uid, permissions, visited))
    visited.remove(record_id)
    return table_indices


def ensure_account_layout(image, layout):
    """Migrate account state into /sys and homes into /home."""
    root_offset = record_offset(image, layout["record_table_start"], 1,
                                layout["record_count"])
    root_record = bytes(image[root_offset:root_offset + RECORD_BYTES])
    if u64(root_record, 0) != 2:
        raise RuntimeError("root Record is not a directory")
    root_payload = record_payload(image, root_record)

    def record_type(record_id):
        offset = record_offset(image, layout["record_table_start"], record_id,
                               layout["record_count"])
        return u64(image, offset), offset

    core_id = directory_find(root_payload, "core")
    sys_id = directory_find(root_payload, "sys")
    home_id = directory_find(root_payload, "home")
    if core_id is None or sys_id is None or home_id is None:
        raise RuntimeError("root is missing core, sys, or home directory")
    core_type, core_offset = record_type(core_id)
    sys_type, sys_offset = record_type(sys_id)
    home_type, home_offset = record_type(home_id)
    if core_type != 2 or sys_type != 2 or home_type != 2:
        raise RuntimeError("root hierarchy contains a non-directory")
    core_payload = record_payload(image, bytes(image[core_offset:
                                                   core_offset + RECORD_BYTES]))
    sys_payload = record_payload(image, bytes(image[sys_offset:
                                                  sys_offset + RECORD_BYTES]))
    home_payload = record_payload(image, bytes(image[home_offset:
                                                   home_offset + RECORD_BYTES]))

    core_accounts_id = directory_find(core_payload, "accounts")
    sys_accounts_id = directory_find(sys_payload, "accounts")
    if core_accounts_id is not None and sys_accounts_id is not None and \
            core_accounts_id != sys_accounts_id:
        raise RuntimeError("both core/accounts and sys/accounts exist")
    accounts_id = sys_accounts_id if sys_accounts_id is not None else \
        core_accounts_id
    if accounts_id is not None and record_type(accounts_id)[0] != 2:
        raise RuntimeError("account directory is not a directory")

    changed = False
    table_indices = set()
    if core_accounts_id is not None:
        core_payload = directory_remove(core_payload, "accounts")
        if sys_accounts_id is None:
            sys_payload += directory_entry(core_accounts_id, "accounts")
        changed = True

    developer_id = directory_find(home_payload, "developer")
    if developer_id is not None and record_type(developer_id)[0] != 2:
        raise RuntimeError("home/developer is not a directory")

    accounts_payload = b""
    if accounts_id is not None:
        accounts_payload = record_payload(image, bytes(image[
            record_type(accounts_id)[1]:record_type(accounts_id)[1] + RECORD_BYTES]))
    database_id = directory_find(accounts_payload, ACCOUNT_DATABASE_NAME)
    legacy_database_id = directory_find(accounts_payload,
                                        LEGACY_ACCOUNT_DATABASE_NAME)
    if database_id is not None and legacy_database_id is not None:
        raise RuntimeError("account directory contains both databases")
    if database_id is None:
        database_id = legacy_database_id
    if database_id is not None and record_type(database_id)[0] != 1:
        raise RuntimeError("account database is not a file")

    missing = (developer_id is None, accounts_id is None, database_id is None)
    used_ids = all_record_ids(image, layout)
    next_id = max(2, u64(image, 96), max(used_ids, default=1) + 1)
    reserved_slots = {record_id - 1 for record_id in
                      RESERVED_SYSTEM_RECORD_IDS
                      if 0 < record_id <= layout["record_count"]}
    slots = allocate_record_slots(image, layout, sum(missing), reserved_slots) \
        if any(missing) else []
    slot_index = 0
    reserved = set()

    def allocate_id():
        nonlocal next_id
        while next_id in used_ids or next_id in RESERVED_SYSTEM_RECORD_IDS:
            next_id += 1
        result = next_id
        used_ids.add(result)
        next_id += 1
        return result

    def create_empty_directory(owner_uid=VFS_UID_SYSTEM,
                               permissions=SYSTEM_PERMISSIONS):
        nonlocal slot_index
        record_id = allocate_id()
        offset = record_table_offset(layout, slots[slot_index])
        slot_index += 1
        write_record(image, offset, record_id, 2, 1, b"", [], 0,
                     owner_uid, permissions)
        table_indices.add(record_slot_from_offset(
            offset, layout["record_table_start"]) // RECORDS_PER_TABLE_BLOCK)
        return record_id

    def create_database():
        nonlocal slot_index
        record_id = allocate_id()
        offset = record_table_offset(layout, slots[slot_index])
        slot_index += 1
        blocks = allocate_blocks(
            image, layout, math.ceil(len(DEFAULT_ACCOUNT_DATABASE) / B),
            reserved)
        for index, block in enumerate(blocks):
            start = index * B
            image[block * B:(block + 1) * B] = DEFAULT_ACCOUNT_DATABASE[
                start:start + B].ljust(B, b"\0")
        write_record(image, offset, record_id, 1, 1,
                     DEFAULT_ACCOUNT_DATABASE, make_extents(blocks, 1), 0,
                     VFS_UID_SYSTEM, SYSTEM_PERMISSIONS)
        table_indices.add(record_slot_from_offset(
            offset, layout["record_table_start"]) // RECORDS_PER_TABLE_BLOCK)
        return record_id

    if accounts_id is None:
        accounts_id = create_empty_directory()
        sys_payload += directory_entry(accounts_id, "accounts")
        accounts_payload = b""
        changed = True
    if developer_id is None:
        developer_id = create_empty_directory(DEVELOPER_UID, USER_PERMISSIONS)
        home_payload += directory_entry(developer_id, "developer")
        changed = True
    if database_id is None:
        database_id = create_database()
        accounts_payload += directory_entry(database_id, ACCOUNT_DATABASE_NAME)
        changed = True
    elif legacy_database_id is not None:
        accounts_payload = directory_remove(
            accounts_payload, LEGACY_ACCOUNT_DATABASE_NAME)
        accounts_payload += directory_entry(database_id, ACCOUNT_DATABASE_NAME)
        changed = True

    if developer_id is not None:
        if directory_find(home_payload, "developer") != developer_id:
            raise RuntimeError("home/developer entry was not installed")
        old_home_payload = record_payload(image, bytes(image[
            record_type(home_id)[1]:record_type(home_id)[1] + RECORD_BYTES]))
        if home_payload != old_home_payload:
            table_indices.add(replace_directory_payload(
                image, layout, home_id, home_payload, reserved))
    if accounts_id is not None:
        old_accounts_payload = record_payload(image, bytes(image[
            record_type(accounts_id)[1]:record_type(accounts_id)[1] + RECORD_BYTES]))
        if accounts_payload != old_accounts_payload:
            table_indices.add(replace_directory_payload(
                image, layout, accounts_id, accounts_payload, reserved))
    old_sys_payload = record_payload(image, bytes(image[
        record_type(sys_id)[1]:record_type(sys_id)[1] + RECORD_BYTES]))
    if sys_payload != old_sys_payload:
        table_indices.add(replace_directory_payload(
            image, layout, sys_id, sys_payload, reserved))
    current_core_payload = record_payload(image, bytes(image[
        core_offset:core_offset + RECORD_BYTES]))
    if core_payload != current_core_payload:
        table_indices.add(replace_directory_payload(
            image, layout, core_id, core_payload, reserved))
    old_root_payload = record_payload(image, root_record)
    if root_payload != old_root_payload:
        table_indices.add(replace_directory_payload(
            image, layout, 1, root_payload, reserved))

    if database_id is not None:
        database_offset = record_type(database_id)[1]
        database_record = bytes(image[database_offset:database_offset + RECORD_BYTES])
        database_payload = record_payload(image, database_record)
        migrated_database, database_changed = migrate_account_database(
            database_payload)
        migrated_database, password_changed = ensure_developer_password(
            migrated_database)
        database_changed = database_changed or password_changed
        if database_changed:
            table_indices.add(replace_file_payload(
                image, layout, database_id, migrated_database, reserved))
            changed = True

    if developer_id is not None:
        security_indices = assign_subtree_security(
            image, layout, developer_id, DEVELOPER_UID, USER_PERMISSIONS)
        table_indices.update(security_indices)
        changed = changed or bool(security_indices)
    if table_indices:
        changed = True

    for record_id in (sys_id, accounts_id, database_id):
        security_index = rewrite_record_security(
            image, layout, record_id, VFS_UID_SYSTEM, SYSTEM_PERMISSIONS)
        if security_index is not None:
            table_indices.add(security_index)
            changed = True

    for table_index in table_indices:
        refresh_table_checksum(image, layout, table_index)
    refresh_record_bitmap_checksum(image, layout)
    refresh_metadata_checksums(image, layout)
    superblock = bytearray(image[:B])
    w64(superblock, 96, next_id)
    checksum(superblock, SUPER_CHECKSUM_OFFSET, 200)
    image[:B] = superblock
    return changed


def refresh_metadata_checksums(image, layout):
    for index in range(layout["allocation_bitmap_blocks"]):
        offset = (layout["allocation_bitmap_start"] + index) * B
        block = bytearray(image[offset:offset + B])
        checksum(block, METADATA_CHECKSUM_OFFSET, B)
        image[offset:offset + B] = block


def upgrade_security_metadata(image, layout):
    """Upgrade legacy v1.0 records without interpreting old flag bits."""
    table_indices = set()
    for slot in range(layout["record_count"]):
        if not record_slot_allocated(image, layout, slot):
            continue
        offset = record_table_offset(layout, slot)
        record = bytearray(image[offset:offset + RECORD_BYTES])
        record_type = u64(record, 0)
        if record_type not in (1, 2):
            continue
        old_flags = u64(record, 8)
        w64(record, 8, record_flags(
            VFS_UID_SYSTEM, SYSTEM_PERMISSIONS,
            bool(old_flags & RECORD_INLINE_DATA)))
        checksum(record, RECORD_CHECKSUM_OFFSET, RECORD_BYTES)
        image[offset:offset + RECORD_BYTES] = record
        table_indices.add(slot // RECORDS_PER_TABLE_BLOCK)

    for table_index in table_indices:
        refresh_table_checksum(image, layout, table_index)
    superblock = bytearray(image[:B])
    w64(superblock, 16, MGFS_FORMAT_MINOR)
    checksum(superblock, SUPER_CHECKSUM_OFFSET, 200)
    image[:B] = superblock
    return True


def update(image_path, payload_paths, data_paths, autologin=None):
    image = bytearray(open(image_path, "rb").read())
    if image[:8] != MAGIC:
        raise RuntimeError("not an MGFS v1 image")
    format_minor = u64(image, 16)
    if format_minor not in (0, MGFS_FORMAT_MINOR_LEGACY, MGFS_FORMAT_MINOR):
        raise RuntimeError("unsupported MGFS format minor version")

    total_blocks = u64(image, 40)
    if total_blocks * B != len(image):
        raise RuntimeError("unsupported MGFS geometry")
    layout = {
        "allocation_bitmap_start": u64(image, 104),
        "allocation_bitmap_blocks": u64(image, 112),
        "record_bitmap_start": u64(image, 120),
        "record_bitmap_blocks": u64(image, 128),
        "record_table_start": u64(image, 136),
        "record_table_blocks": u64(image, 144),
        "record_count": u64(image, 152),
        "data_start": u64(image, 160),
        "data_blocks": u64(image, 168),
    }
    if len(payload_paths) != len(PAYLOAD_NAMES):
        raise RuntimeError("wrong number of system payloads")
    payloads = {name: open(path, "rb").read()
                for name, path in zip(PAYLOAD_NAMES, payload_paths)}
    data_payloads = {name: open(path, "rb").read()
                     for (_, name, _), path in zip(DATA_MANIFEST, data_paths)}
    persistent_changed = False
    if format_minor != MGFS_FORMAT_MINOR:
        persistent_changed = True
    if reconcile_record_bitmap(image, layout):
        persistent_changed = True
    if format_minor == 0:
        persistent_changed = upgrade_security_metadata(image, layout)
    if ensure_hierarchy_layout(image, layout):
        persistent_changed = True
    if migrate_managed_logs(image, layout):
        persistent_changed = True
    persistent_changed = ensure_network_config(image, layout) or persistent_changed
    persistent_changed = ensure_security_config(image, layout) or persistent_changed
    if ensure_account_layout(image, layout):
        persistent_changed = True
    if migrate_command_names(image, layout):
        persistent_changed = True
    boot_id, pith_record_id, boot_changed = ensure_boot_kernel(
        image, layout, payloads["pith"])
    if boot_changed:
        persistent_changed = True
    core_id, sprout_record_id, core_changed = ensure_system_core_program(
        image, layout, payloads["sprout_core"], allow_public_duplicate=True)
    core_id, sessiond_record_id, sessiond_changed = ensure_system_core_program(
        image, layout, payloads["sessiond"], "sessiond", 69)
    core_id, logind_record_id, logind_changed = ensure_system_core_program(
        image, layout, payloads["logind"], "logind", LOGIND_RECORD_ID)
    core_id, logd_record_id, logd_changed = ensure_system_core_program(
        image, layout, payloads["logd"], "logd", LOGD_RECORD_ID)
    core_id, networkd_record_id, networkd_changed = ensure_system_core_program(
        image, layout, payloads["networkd"], "networkd", NETWORKD_RECORD_ID)
    core_id, deviced_record_id, deviced_changed = ensure_system_core_program(
        image, layout, payloads["deviced"], "deviced", DEVICED_RECORD_ID)
    core_id, volumed_record_id, volumed_changed = ensure_system_core_program(
        image, layout, payloads["volumed"], "volumed", VOLUMED_RECORD_ID)
    if (core_changed or sessiond_changed or logind_changed or logd_changed or
            networkd_changed or deviced_changed or volumed_changed):
        persistent_changed = True
    if ensure_help_layout(image, layout):
        persistent_changed = True
    if ensure_hardware_layout(image, layout, data_payloads):
        persistent_changed = True
    command_records, commands_changed = ensure_system_commands(
        image, layout, payloads)
    if commands_changed:
        persistent_changed = True
    if ensure_session_config(image, layout, autologin):
        persistent_changed = True
    system_records = {command_records[name]: name for name in BIN_PAYLOAD_NAMES}
    bin_data = b"".join(directory_entry(command_records[name], name)
                         for name in BIN_PAYLOAD_NAMES)
    core_offset = record_offset(image, layout["record_table_start"], core_id,
                                layout["record_count"])
    core_data = record_payload(image, bytes(image[core_offset:
                                                  core_offset + RECORD_BYTES]))
    active_records = [2, boot_id, pith_record_id, core_id,
                      sprout_record_id, sessiond_record_id, logind_record_id,
                      logd_record_id,
                      networkd_record_id, deviced_record_id,
                      volumed_record_id] + \
        list(system_records)
    offsets = {record_id: record_offset(image, layout["record_table_start"],
                                         record_id, layout["record_count"])
               for record_id in active_records}
    if not all(record_extent_layout_valid(
            image, layout, bytes(image[offsets[record_id]:
                                       offsets[record_id] + RECORD_BYTES]))
               for record_id in active_records):
        persistent_changed = True

    if (record_payload(image, bytes(image[offsets[2]:offsets[2] + RECORD_BYTES])) ==
            bin_data and
            record_payload(image, bytes(image[offsets[boot_id]:
                                               offsets[boot_id] + RECORD_BYTES])) ==
                directory_entry(pith_record_id, "pith.elf") and
            record_payload(image, bytes(image[offsets[pith_record_id]:
                                               offsets[pith_record_id] + RECORD_BYTES])) ==
                payloads["pith"] and
            record_payload(image, bytes(image[offsets[core_id]:
                                               offsets[core_id] + RECORD_BYTES])) ==
                core_data and
            record_payload(image, bytes(image[offsets[sprout_record_id]:
                                               offsets[sprout_record_id] + RECORD_BYTES])) ==
                payloads["sprout_core"] and
            record_payload(image, bytes(image[offsets[sessiond_record_id]:
                                               offsets[sessiond_record_id] + RECORD_BYTES])) ==
                payloads["sessiond"] and
            record_payload(image, bytes(image[offsets[logind_record_id]:
                                               offsets[logind_record_id] + RECORD_BYTES])) ==
                payloads["logind"] and
            record_payload(image, bytes(image[offsets[logd_record_id]:
                                               offsets[logd_record_id] + RECORD_BYTES])) ==
                payloads["logd"] and
            record_payload(image, bytes(image[offsets[networkd_record_id]:
                                               offsets[networkd_record_id] + RECORD_BYTES])) ==
                payloads["networkd"] and
            record_payload(image, bytes(image[offsets[deviced_record_id]:
                                               offsets[deviced_record_id] + RECORD_BYTES])) ==
                payloads["deviced"] and
            record_payload(image, bytes(image[offsets[volumed_record_id]:
                                               offsets[volumed_record_id] + RECORD_BYTES])) ==
                payloads["volumed"] and
            all(record_payload(image, bytes(image[offsets[record_id]:
                                                  offsets[record_id] + RECORD_BYTES])) ==
                payloads[system_records[record_id]]
                for record_id in system_records) and
            not persistent_changed):
        return False

    reserved = set()
    old_state = {}
    for record_id, offset in offsets.items():
        record = bytes(image[offset:offset + RECORD_BYTES])
        extents, list_blocks = record_extents(image, record)
        data_blocks = []
        for logical, physical, count, flags in extents:
            if count == 0 or flags not in (1, 2) or \
                    physical < layout["data_start"] or \
                    physical + count > layout["data_start"] + layout["data_blocks"]:
                raise RuntimeError("invalid system extent")
            data_blocks.extend(range(physical, physical + count))
        old_state[record_id] = (u64(record, 24), extents, list_blocks, data_blocks)
        for block in data_blocks + list_blocks:
            set_allocated(image, layout, block, False)

    for record_id, offset in offsets.items():
        if record_id == 2:
            payload = bin_data
            record_type = 2
        elif record_id == boot_id:
            payload = directory_entry(pith_record_id, "pith.elf")
            record_type = 2
        elif record_id == pith_record_id:
            payload = payloads["pith"]
            record_type = 1
        elif record_id == core_id:
            payload = core_data
            record_type = 2
        elif record_id == sprout_record_id:
            payload = payloads["sprout_core"]
            record_type = 1
        elif record_id == sessiond_record_id:
            payload = payloads["sessiond"]
            record_type = 1
        elif record_id == logind_record_id:
            payload = payloads["logind"]
            record_type = 1
        elif record_id == logd_record_id:
            payload = payloads["logd"]
            record_type = 1
        elif record_id == networkd_record_id:
            payload = payloads["networkd"]
            record_type = 1
        elif record_id == deviced_record_id:
            payload = payloads["deviced"]
            record_type = 1
        elif record_id == volumed_record_id:
            payload = payloads["volumed"]
            record_type = 1
        else:
            payload = payloads[system_records[record_id]]
            record_type = 1
        needed = math.ceil(len(payload) / B)
        data_blocks = allocate_blocks(image, layout, needed, reserved)
        extents = make_extents(data_blocks, 2 if record_type == 2 else 1)
        list_count = math.ceil(max(0, len(extents) - 2) / EXTENTS_PER_LIST_BLOCK)
        list_blocks = allocate_blocks(image, layout, list_count, reserved)
        for index, block in enumerate(data_blocks):
            start = index * B
            image[block * B:(block + 1) * B] = payload[start:start + B].ljust(B, b"\0")
        write_extent_lists(image, record_id, extents, list_blocks)
        generation = old_state[record_id][0] + 1
        write_record(image, offset, record_id, record_type,
                     generation, payload, extents,
                     list_blocks[0] if list_blocks else 0)

    table_indices = {
        (offset - layout["record_table_start"] * B) // B
        for offset in offsets.values()
    }
    for index in table_indices:
        offset = (layout["record_table_start"] + index) * B
        block = bytearray(image[offset:offset + B])
        checksum(block, METADATA_CHECKSUM_OFFSET, B)
        image[offset:offset + B] = block

    record_bitmap = bytearray(image[layout["record_bitmap_start"] * B:
                                    (layout["record_bitmap_start"] + 1) * B])
    for record_id in active_records:
        record_offset_value = record_offset(
            image, layout["record_table_start"], record_id,
            layout["record_count"])
        bit = record_slot_from_offset(
            record_offset_value, layout["record_table_start"])
        record_bitmap[24 + bit // 8] |= 1 << (bit % 8)
    checksum(record_bitmap, METADATA_CHECKSUM_OFFSET, B)
    image[layout["record_bitmap_start"] * B:
          (layout["record_bitmap_start"] + 1) * B] = record_bitmap

    refresh_metadata_checksums(image, layout)
    superblock = bytearray(image[:B])
    w64(superblock, 16, MGFS_FORMAT_MINOR)
    w64(superblock, 64, 1)
    checksum(superblock, SUPER_CHECKSUM_OFFSET, 200)
    image[:B] = superblock

    temporary = image_path + ".update-tmp"
    with open(temporary, "wb") as output:
        output.write(image)
    os.replace(temporary, image_path)
    return True


def main():
    expected_argc = 2 + len(PAYLOAD_NAMES) + len(DATA_MANIFEST)
    if len(sys.argv) not in (expected_argc, expected_argc + 1):
        names = " ".join("<%s-elf>" % name
                         for _, name, _ in PAYLOAD_MANIFEST)
        names += " " + " ".join("<%s>" % name
                                  for _, name, _ in DATA_MANIFEST)
        raise SystemExit("usage: update_mgfs.py <image> %s "
                         "[--autologin=<name>]" % names)
    autologin = None
    policy_index = 2 + len(PAYLOAD_NAMES) + len(DATA_MANIFEST)
    if len(sys.argv) == expected_argc + 1:
        if not sys.argv[policy_index].startswith("--autologin="):
            raise SystemExit("update_mgfs: invalid image policy")
        autologin = sys.argv[policy_index][len("--autologin="):]
    try:
        data_index = 2 + len(PAYLOAD_NAMES)
        update(sys.argv[1], sys.argv[2:data_index],
               sys.argv[data_index:data_index + len(DATA_MANIFEST)], autologin)
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit("update_mgfs: %s" % error)


if __name__ == "__main__":
    main()
