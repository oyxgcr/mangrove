#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression test for the MGFS 1.1 to 1.2 metadata migration."""

import pathlib
import struct
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import populate_mgfs  # noqa: E402
import update_mgfs  # noqa: E402


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def image_layout(image):
    return {
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


def record(image, layout, record_id):
    offset = update_mgfs.record_offset(
        image, layout["record_table_start"], record_id,
        layout["record_count"])
    return bytes(image[offset:offset + update_mgfs.RECORD_BYTES])


def snapshot(image, layout, record_id):
    item = record(image, layout, record_id)
    return {
        "type": u64(item, 0),
        "owner": update_mgfs.record_owner(item),
        "permissions": update_mgfs.record_permissions(item),
        "policy": update_mgfs.record_child_mutation_policy(item),
        "payload": update_mgfs.record_payload(image, item),
    }


def create_record(image, layout, record_id, record_type, payload=b"",
                  owner=populate_mgfs.VFS_UID_SYSTEM,
                  permissions=populate_mgfs.SYSTEM_PERMISSIONS, reserved=None):
    if reserved is None:
        reserved = set()
    slot = record_id - 1
    update_mgfs.set_record_allocated(image, layout, slot, True)
    update_mgfs._create_payload_record(
        image, layout, record_id, slot, record_type, payload,
        2 if record_type == 2 else 1, reserved, owner, permissions)


def finalize_metadata(image, layout, minor):
    for index in range(layout["record_table_blocks"]):
        update_mgfs.refresh_table_checksum(image, layout, index)
    update_mgfs.refresh_record_bitmap_checksum(image, layout)
    update_mgfs.refresh_metadata_checksums(image, layout)
    superblock = bytearray(image[:update_mgfs.B])
    update_mgfs.w64(superblock, 16, minor)
    update_mgfs.checksum(superblock, update_mgfs.SUPER_CHECKSUM_OFFSET, 200)
    image[:update_mgfs.B] = superblock


def assert_equal(actual, expected, message):
    if actual != expected:
        raise AssertionError("%s: %r != %r" % (message, actual, expected))


def build_fixture(mkmgfs, image_path, include_temp):
    uuid = ("11111111-2222-3333-4444-555555555555" if include_temp else
            "66666666-7777-8888-9999-aaaaaaaaaaaa")
    subprocess.run([
        str(mkmgfs), "--blocks", "3200", "--uuid", uuid,
        "--format-time-ns", "1", str(image_path),
    ], check=True)
    image = bytearray(image_path.read_bytes())
    layout = image_layout(image)
    reserved = set()
    next_id = 2
    directories = {}
    root_entries = []

    if include_temp:
        directories["temp"] = (1000, 0x3)
    directories.update({"scratch": (1000, 0x3), "notes": (1001, 0x7),
                         "home": (0, 0x7)})
    for name, (owner, permissions) in directories.items():
        record_id = next_id
        next_id += 1
        create_record(image, layout, record_id, 2, owner=owner,
                      permissions=permissions, reserved=reserved)
        directories[name] = (record_id, owner, permissions)
        root_entries.append(populate_mgfs.directory_entry(record_id, name))

    developer_id = next_id
    next_id += 1
    create_record(image, layout, developer_id, 2, owner=1000,
                  permissions=0x3, reserved=reserved)
    directories["developer"] = (developer_id, 1000, 0x3)
    update_mgfs.replace_directory_payload(
        image, layout, directories["home"][0],
        populate_mgfs.directory_entry(developer_id, "developer"), reserved)

    for name, marker_owner in (("scratch", 1000), ("notes", 1001)):
        marker_id = next_id
        next_id += 1
        marker = (name + "-marker\n").encode("ascii")
        create_record(image, layout, marker_id, 1, marker,
                      owner=marker_owner, permissions=0x7, reserved=reserved)
        directories[name + "/marker"] = (marker_id, marker_owner, 0x7)
        update_mgfs.replace_directory_payload(
            image, layout, directories[name][0],
            populate_mgfs.directory_entry(marker_id, "marker"), reserved)

    update_mgfs.replace_directory_payload(
        image, layout, 1, b"".join(root_entries), reserved)
    original = {record_id: snapshot(image, layout, record_id)
                for record_id, _, _ in directories.values()}
    original.update({record_id: snapshot(image, layout, record_id)
                     for key, (record_id, _, _) in directories.items()
                     if "/" in key})
    finalize_metadata(image, layout, update_mgfs.MGFS_FORMAT_MINOR_LEGACY)
    image_path.write_bytes(image)
    return layout, original


def migrate_and_check(image_path, layout, original, mgfsck, include_temp):
    image = bytearray(image_path.read_bytes())
    root_before = update_mgfs.record_payload(image, record(image, layout, 1))
    names_before = {entry[4]: entry[2]
                    for entry in update_mgfs.directory_entries(root_before)}
    if not update_mgfs.ensure_hierarchy_layout(image, layout):
        raise AssertionError("1.1 hierarchy migration made no changes")
    finalize_metadata(image, layout, update_mgfs.MGFS_FORMAT_MINOR)

    root = update_mgfs.record_payload(image, record(image, layout, 1))
    for name, record_id in names_before.items():
        assert_equal(update_mgfs.directory_find(root, name.decode("utf-8")),
                     record_id, "preserved root entry %s" % name.decode())
    temp_id = update_mgfs.directory_find(root, "temp")
    if temp_id is None:
        raise AssertionError("canonical /temp was not established")
    temp = snapshot(image, layout, temp_id)
    assert_equal(temp["policy"], 1, "/temp child-mutation policy")
    if include_temp:
        if temp_id not in original:
            raise AssertionError("existing /temp Record was not retained")
        assert_equal(temp["owner"], original[temp_id]["owner"],
                     "/temp owner preservation")
        assert_equal(temp["permissions"], original[temp_id]["permissions"],
                     "/temp permissions preservation")
    elif temp_id in original:
        raise AssertionError("absent /temp reused a fixture Record")
    else:
        assert_equal(temp["owner"], 0, "new /temp owner")
        assert_equal(temp["permissions"], 0xf, "new /temp permissions")

    for record_id, before in original.items():
        after = snapshot(image, layout, record_id)
        for key in ("type", "owner", "permissions", "payload"):
            assert_equal(after[key], before[key],
                         "Record %d %s" % (record_id, key))
        if record_id != temp_id:
            assert_equal(after["policy"], 0,
                         "Record %d child-mutation policy" % record_id)

    migrated_path = image_path.with_name("migrated.img")
    migrated_path.write_bytes(image)
    subprocess.run([str(mgfsck), str(migrated_path)], check=True,
                   stdout=subprocess.DEVNULL)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: %s <mkmgfs> <mgfsck>" % sys.argv[0])
    mkmgfs = pathlib.Path(sys.argv[1])
    mgfsck = pathlib.Path(sys.argv[2])

    with tempfile.TemporaryDirectory(prefix="mangrove-mgfs-migration-") as name:
        directory = pathlib.Path(name)
        present_path = directory / "legacy-present.img"
        present_layout, present_original = build_fixture(
            mkmgfs, present_path, True)
        migrate_and_check(present_path, present_layout, present_original,
                          mgfsck, True)

        absent_path = directory / "legacy-absent.img"
        absent_layout, absent_original = build_fixture(
            mkmgfs, absent_path, False)
        migrate_and_check(absent_path, absent_layout, absent_original,
                          mgfsck, False)

    print("MGFS 1.1 to 1.2 migration test passed")


if __name__ == "__main__":
    main()
