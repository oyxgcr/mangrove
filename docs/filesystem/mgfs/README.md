# Mangrove File System (MGFS)

MGFS is Mangrove's native writable filesystem. System images place it in the
GPT partition named `MANGROVE_ROOT`; the UEFI loader locates that role
partition and loads `/boot/pith.elf` from its MGFS root. MGFS can also be used
on removable partitions and on unpartitioned whole devices.

The current on-disk format is major version 1, minor version 2. Its magic is
`MGFSv1\0\0`, its filesystem block size is 4096 bytes, and it currently
requires a block device with 512-byte logical sectors. The filesystem uses
UTF-8 names, permanent filesystem-local Record IDs, extent-based file data,
and CRC-64 checksums for metadata.

## Object model

Path lookup follows this chain:

```text
path component -> directory entry -> Record ID -> File Record -> extents
```

A Record ID is immutable and is not reused within a filesystem. Renaming or
moving an object changes directory entries while retaining the same Record ID
and File Record. Paths are the application-facing identity; Record IDs remain
an internal filesystem mechanism.

Files and directories carry a 32-bit owner UID and owner/other read/write
permissions in their File Record flags. Directories additionally carry a
native child-mutation policy. Regular files up to 56 bytes may keep
their contents inline in the File Record. Larger files, directory streams, and
extent-list metadata occupy blocks in the data area.

Names are case-sensitive UTF-8 byte strings. MGFS performs no Unicode
normalization. A name cannot be empty, contain NUL or `/`, equal `.` or `..`,
or exceed 255 bytes. Directories do not store `.` or `..` entries.

## Supported operations

The kernel driver supports mounting, lookup, directory enumeration, file
reads and writes, extension, truncation, file and directory creation, file
deletion, empty-directory deletion, and rename or move within one MGFS
filesystem. The VFS applies owner/other access checks before filesystem
operations.

MGFS has no journal. Metadata mutations set `NEEDS_FSCK` before publishing
changes and restore `CLEAN` only after the operation's required writes
complete. Metadata write ordering is designed to leave incomplete operations
detectable, but compound operations are not power-loss atomic. `mgfsck`
validates checksums, allocation ownership, Record IDs, directory structure,
and reachability; it is not an automatic runtime repair path.

## Format and tools

The exact binary layout, checksums, formatter state, and write ordering are
specified in [format.md](format.md). Volume-label storage and validation are
specified in [labels.md](labels.md).

The host tools are:

- `mkmgfs`, which creates a deterministic filesystem from explicit size,
  UUID, timestamp, and optional label inputs;
- `mgfsck`, which checks an existing MGFS image;
- `populate_mgfs.py` and `update_mgfs.py`, which populate or update Mangrove
  image payloads without redefining the on-disk format.

The runtime formatter in `kernel/src/storage/format.c`, the kernel driver in
`kernel/src/storage/mgfs.c`, and the host tools use the same current layout
constants and invariants.

## Directory creation and mutation policy

Creation defaults are fixed VFS policy, not inherited directory metadata. A
normal file is owned by the creating UID and starts with `rw:r-`; a normal
directory is owned by the creating UID and starts with `rw:r-`. Explicit
trusted creation paths may choose other values, such as system-owned image
objects or an administrator creating on behalf of a regular user. Existing
children are never changed by a parent's policy.

MGFS v1.2 stores one directory-only child-mutation policy bit. `open` permits
any caller who can write the directory to delete or rename an existing child.
`owner-restricted` additionally requires ownership of the child or containing
directory. This is a native mutation rule, not a Unix mode, umask, ACL, or
sticky bit.

The system image gives human home directories private `rw:--` directory
permissions. `/temp` is system-owned with shared `rw:rw` directory
permissions and owner-restricted child mutation; children still use the
normal `rw:r-` file default and retain their creating owner. Existing v1.1
images are upgraded without renaming or merging existing directory names;
an existing `/temp` receives this policy, while other existing directories
retain their names and use open child mutation unless a trusted image policy
sets the bit.
