/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <uefi.h>

#define MGFS_BOOT_BLOCK_BYTES          4096U
#define MGFS_BOOT_RECORD_BYTES         192U
#define MGFS_BOOT_RECORDS_PER_BLOCK    21U
#define MGFS_BOOT_BITMAP_HEADER_BYTES  24U
#define MGFS_BOOT_BITMAP_BITS_PER_BLOCK 32576U
#define MGFS_BOOT_EXTENT_LIST_MAGIC    0x315458455346474DULL
#define MGFS_BOOT_EXTENT_LIST_HEADER_BYTES 64U
#define MGFS_BOOT_EXTENTS_PER_LIST_BLOCK 126U
#define MGFS_BOOT_MAX_PATH             256U
#define MGFS_BOOT_MAX_NAME             255U
#define MGFS_BOOT_INLINE_DATA_BYTES    56U

typedef struct
{
    EFI_BLOCK_IO_PROTOCOL *block_io;
    u32 media_id;
    u64 partition_start;
    u64 partition_blocks;
    u64 total_blocks;
    u64 format_minor;
    u64 root_record_id;
    u64 record_table_start;
    u64 record_table_blocks;
    u64 record_count;
    u64 data_start;
    u64 data_blocks;
    u8 *record_bitmap;
    usize record_bitmap_size;
    u8 table_block[MGFS_BOOT_BLOCK_BYTES];
    u64 table_block_number;
    bool table_block_valid;
} MGFS_BOOT_FS;

typedef struct
{
    MGFS_BOOT_FS *fs;
    u64 record_id;
    u64 size;
    u64 position;
} MGFS_BOOT_FILE;

EFI_STATUS mgfs_boot_init(MGFS_BOOT_FS *fs,
                          EFI_BLOCK_IO_PROTOCOL *block_io,
                          u64 media_id,
                          u64 partition_start,
                          u64 partition_blocks);

EFI_STATUS mgfs_boot_open(MGFS_BOOT_FS *fs,
                          const char *path,
                          MGFS_BOOT_FILE *file);

EFI_STATUS mgfs_boot_read(MGFS_BOOT_FILE *file,
                          void *buffer,
                          usize *buffer_size);

EFI_STATUS mgfs_boot_seek(MGFS_BOOT_FILE *file, u64 position);
