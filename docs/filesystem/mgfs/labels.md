# MGFS volume labels

MGFS major version 1, minor version 1 and later store an optional label extension after
the fixed 200-byte superblock header. The extension does not change the
original header checksum coverage.

The extension occupies bytes 200 through 287 of superblock block zero:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| 200 | 8 | `MGLABEL1` extension magic |
| 208 | 8 | UTF-8 label length in bytes, at most 63 |
| 216 | 63 | label bytes, without a terminating NUL |
| 279 | 1 | reserved, zero |
| 280 | 8 | CRC-64 of bytes 200 through 287, with this field zero |

An all-zero extension means that the filesystem has no label. The extension
has its own checksum because the original v1 superblock checksum covers only
bytes 0 through 199.  Bytes 288 through 4095 remain reserved and zero.

## Validation

Labels are UTF-8 and at most 63 bytes. An empty label is valid. Non-empty
labels must contain non-whitespace content and cannot begin or end with
Unicode whitespace. Invalid UTF-8, NUL, `/`, controls, bidi or formatting
characters, emoji and pictographic ranges, and decorative symbol ranges are
rejected. ASCII labels are limited to letters, decimal digits, ordinary
space, `_`, `-`, and `.`. The current validator deliberately does not perform
Unicode normalization or use a complete Unicode category database.

The same validation is used by the host formatter and the runtime label path.
`mkmgfs` accepts `--label <label>`. `diskutil` changes labels only on an
unmounted filesystem and verifies the result through the canonical probe
metadata after flushing.

## Presentation

The kernel exposes a valid stored label through the filesystem metadata
callback. `lsdsk` displays that metadata. `volumed` uses a label as an
automount path component only when it is also safe for the VFS path policy;
otherwise it retains the stored label for inspection and falls back to the
current disk or partition name for the mountpoint.
