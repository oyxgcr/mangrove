# SPDX-License-Identifier: GPL-3.0-or-later
"""Canonical ordered payload manifest shared by MGFS image builders."""

# Each entry is (MGFS record ID, payload key, installed directory name).  The
# payload key is distinct from the installed name for the Sprout core service,
# which shares its name with the public /bin/sprout control client.
PAYLOAD_MANIFEST = (
    (9, "pith", "pith.elf"),
    (8, "sprout_core", "sprout"),
    (69, "sessiond", "sessiond"),
    (110, "logind", "logind"),
    (111, "logd", "logd"),
    (74, "networkd", "networkd"),
    (75, "deviced", "deviced"),
    (76, "volumed", "volumed"),
    (153, "lspci", "lspci"),
    (154, "lsusb", "lsusb"),
    (106, "lsdsk", "lsdsk"),
    (107, "crew", "crew"),
    (108, "mem", "mem"),
    (151, "time", "time"),
    (152, "tmon", "tmon"),
    (109, "logv", "logv"),
    (159, "mount", "mount"),
    (160, "unmount", "unmount"),
    (161, "eject", "eject"),
    (162, "diskutil", "diskutil"),
    (11, "shoot", "shoot"),
    (10, "clear", "clear"),
    (13, "cp", "cp"),
    (14, "say", "say"),
    (15, "uptime", "uptime"),
    (12, "ls", "ls"),
    (16, "locate", "locate"),
    (21, "mv", "mv"),
    (22, "plant", "plant"),
    (23, "type", "type"),
    (24, "rm", "rm"),
    (25, "version", "version"),
    (26, "where", "where"),
    (17, "ping", "ping"),
    (18, "resolve", "resolve"),
    (19, "fetch", "fetch"),
    (20, "netinfo", "netinfo"),
    (150, "netcfg", "netcfg"),
    (27, "shutdown", "shutdown"),
    (28, "reboot", "reboot"),
    (29, "power", "power"),
    (32, "identity", "identity"),
    (37, "user", "user"),
    (40, "mkdir", "mkdir"),
    (41, "rmdir", "rmdir"),
    (72, "sprout", "sprout"),
    (112, "date", "date"),
    (163, "info", "info"),
)

# Shared, non-executable image data uses the same canonical argument manifest
# as system binaries, but remains outside /bin and outside kernel payloads.
DATA_MANIFEST = (
    (156, "pci_ids", "share/hardware/pci.ids"),
    (157, "usb_ids", "share/hardware/usb.ids"),
    (158, "hardware_readme", "share/hardware/README.txt"),
)
HARDWARE_RECORD_ID = 155

PITH_RECORD_ID = PAYLOAD_MANIFEST[0][0]
PAYLOAD_NAMES = tuple(payload_name for _, payload_name, _ in PAYLOAD_MANIFEST)
PAYLOAD_RECORD_IDS = tuple(record_id for record_id, _, _ in PAYLOAD_MANIFEST)
SYSTEM_FILES = tuple(
    (record_id, installed_name)
    for record_id, payload_name, installed_name in PAYLOAD_MANIFEST
    if payload_name != "pith"
)
BIN_PAYLOAD_NAMES = tuple(
    payload_name for _, payload_name, _ in PAYLOAD_MANIFEST
    if payload_name not in {
        "pith", "sprout_core", "sessiond", "logind", "logd",
        "networkd", "deviced", "volumed",
    }
)
DATA_PAYLOAD_NAMES = tuple(payload_name for _, payload_name, _ in DATA_MANIFEST)
DATA_RECORD_IDS = tuple(record_id for record_id, _, _ in DATA_MANIFEST)
