# Mangrove system image and runtime layout

Mangrove's bootable development and USB images are complete GPT disks. The
partition names are role markers consumed by both the UEFI loader and kernel;
they are not presentation labels.

## GPT layout

The current image contains 264,225 512-byte sectors (135,283,200 bytes):

| Entry | LBA range | Size | GPT role | Contents |
| --- | --- | --- | --- | --- |
| 1 | 2048–133119 | 64 MiB | `MANGROVE_ESP` | FAT32 EFI System Partition |
| 2 | 133120–264191 | 64 MiB | `MANGROVE_ROOT` | MGFS root filesystem |

The leading space provides GPT metadata and 1 MiB alignment; the disk tail
contains backup GPT metadata. The ESP uses the standard EFI System Partition
type. The root currently uses the generic data type selected by the host GPT
tool, while its `MANGROVE_ROOT` name supplies the Mangrove system role.

The ESP contains `/EFI/BOOT/BOOTX64.EFI`. The kernel is not stored on the ESP;
the loader reads `/boot/pith.elf` from MGFS in `MANGROVE_ROOT`.

## Root filesystem hierarchy

The image population tools create this system-owned structure:

```text
/
├── bin/                 standalone user commands
├── boot/pith.elf        kernel image loaded by UEFI
├── conf/                administrator-managed configuration
│   ├── network/config
│   ├── security/config
│   └── session/config
├── core/                supervised system-service executables
├── home/                per-user persistent directories
├── share/               immutable/read-only shared data
│   ├── hardware/        PCI/USB ID data and provenance note
│   └── help/            command help records and index
├── sys/                 mutable system-owned persistent state
│   ├── accounts/users
│   └── logs/            boot and persistent logging state
├── temp/                shared temporary data
└── vol/                 removable-volume mount namespace
```

`/bin`, `/boot`, `/core`, and `/share` are system payload. `/conf` is persistent
administrator configuration. `/sys` is persistent system state. `/home` is
persistent user data. `/temp` is mutable shared temporary storage. `/vol`
contains runtime mount entries created and removed by volume policy; external
filesystem contents are not baked into MGFS.

The system services are `/core/sprout`, `/core/sessiond`, `/core/logind`,
`/core/logd`, `/core/networkd`, `/core/deviced`, and `/core/volumed`. Other
installed executables live under `/bin`.

## Image variants

The persistent development disk is `.mangrove/MangroveDev.img`, with its MGFS
partition staged separately as `.mangrove/MangroveDevRoot.img` during updates.
Incremental updates preserve guest-owned MGFS records and unrelated files on
the ESP while replacing managed payloads and configuration defaults according
to the update tool's ownership rules.

`build/Mangrove/MangroveUSB.img` is the rebuilt distribution/hardware image.
Its root is freshly generated as `build/Mangrove/MangroveFlash.img` before the
ESP and root partition images are copied into the GPT disk.

## Authoritative code

- `scripts/make_image.sh` and `scripts/update_dev_image.sh`
- `tools/populate_mgfs.py`, `tools/update_mgfs.py`, and
  `tools/copy_partition.py`
- the `flash-image`, `dev-image`, `fresh-image`, and `usb-image` Make targets
- `boot/src/filesystem.c` and kernel GPT role classification
