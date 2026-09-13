/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <mgfs.h>
#include <memory.h>

#define MGFS_MAGIC_U64 0x000031765346474DULL
#define MGFS_FORMAT_MAJOR 1ULL
#define MGFS_FORMAT_MINOR 2ULL
#define MGFS_FORMAT_MINOR_LEGACY 1ULL
#define MGFS_HEADER_BYTES 200ULL
#define MGFS_MIN_TOTAL_BLOCKS 64ULL
#define MGFS_BITMAP_BITS_PER_BLOCK 32576ULL
#define MGFS_RECORD_TABLE_KIND 3ULL
#define MGFS_RECORD_BITMAP_KIND 2ULL
#define MGFS_RECORD_FILE 1ULL
#define MGFS_RECORD_DIRECTORY 2ULL
#define MGFS_RECORD_INLINE_DATA 0x1ULL
#define MGFS_RECORD_OWNER_MASK (0xFFFFFFFFULL << 1U)
#define MGFS_RECORD_PERMISSIONS_MASK (0xFULL << 33U)
#define MGFS_RECORD_CHILD_MUTATION_OWNER_RESTRICTED (1ULL << 41U)
#define MGFS_RECORD_FLAGS_KNOWN (MGFS_RECORD_INLINE_DATA | \
                                 MGFS_RECORD_OWNER_MASK | \
                                 MGFS_RECORD_PERMISSIONS_MASK | \
                                 MGFS_RECORD_CHILD_MUTATION_OWNER_RESTRICTED)
#define MGFS_DIRENT_IN_USE 1ULL
#define MGFS_DIRENT_TOMBSTONE 2ULL
#define MGFS_EXTENT_DATA 0x1ULL
#define MGFS_EXTENT_DIRECTORY 0x2ULL
#define MGFS_EXTENT_LIST_HEADER_BYTES 64ULL
#define MGFS_RECORD_CHECKSUM_OFFSET 184U
#define MGFS_METADATA_CHECKSUM_OFFSET 16U
#define MGFS_CRC64_POLYNOMIAL 0x42F0E1EBA9EA3693ULL
#define MGFS_U64_MAX 0xFFFFFFFFFFFFFFFFULL

/* The EFI loader does not provide a stack-probing runtime.  Keep the few
 * block-sized scratch buffers in loader-owned static storage instead of
 * placing them in individual call frames.  Boot-time MGFS access is
 * single-threaded and these buffers have deliberately separate roles so a
 * nested metadata read cannot overwrite its caller's block. */
static u8 MgfsBootSuperblock[MGFS_BOOT_BLOCK_BYTES];
static u8 MgfsBootBlock[MGFS_BOOT_BLOCK_BYTES];
static u8 MgfsBootListBlock[MGFS_BOOT_BLOCK_BYTES];
static u8 MgfsBootFileBlock[MGFS_BOOT_BLOCK_BYTES];

static u64 mgfs_boot_le64(const u8 *data)
{
    u64 value = 0;
    for (u32 i = 0; i < 8U; i++) value |= (u64)data[i] << (i * 8U);
    return value;
}

static void mgfs_boot_zero(void *destination, usize size)
{
    u8 *bytes = (u8 *)destination;
    for (usize i = 0; i < size; i++) bytes[i] = 0;
}

static void mgfs_boot_copy(void *destination, const void *source, usize size)
{
    u8 *out = (u8 *)destination;
    const u8 *in = (const u8 *)source;
    for (usize i = 0; i < size; i++) out[i] = in[i];
}

static bool mgfs_boot_equal(const u8 *left, const u8 *right, usize size)
{
    for (usize i = 0; i < size; i++) {
        if (left[i] != right[i]) return false;
    }
    return true;
}

static u64 mgfs_boot_crc64(const u8 *data, usize length, u32 checksum_offset)
{
    u64 crc = 0;
    for (usize byte = 0; byte < length; byte++) {
        u8 value = (byte >= checksum_offset && byte < checksum_offset + 8U)
            ? 0U : data[byte];
        crc ^= (u64)value << 56U;
        for (u32 bit = 0; bit < 8U; bit++) {
            crc = (crc & (1ULL << 63U))
                ? (crc << 1U) ^ MGFS_CRC64_POLYNOMIAL
                : crc << 1U;
        }
    }
    return crc;
}

static bool mgfs_boot_checksum(const u8 *data, usize length,
                               u32 checksum_offset)
{
    return mgfs_boot_le64(data + checksum_offset) ==
           mgfs_boot_crc64(data, length, checksum_offset);
}

static bool mgfs_boot_add(u64 left, u64 right, u64 *out)
{
    if (left > MGFS_U64_MAX - right) return false;
    *out = left + right;
    return true;
}

static u64 mgfs_boot_ceil_div(u64 value, u64 divisor)
{
    return value / divisor + ((value % divisor) != 0ULL);
}

static bool mgfs_boot_read_block(MGFS_BOOT_FS *fs, u64 block, u8 *buffer)
{
    u64 sector_offset;
    u64 lba;

    if (!fs || !fs->block_io || !fs->block_io->Media || !buffer ||
        fs->block_io->Media->BlockSize != 512U ||
        block >= fs->partition_blocks / 8ULL ||
        block > MGFS_U64_MAX / 8ULL) return false;
    sector_offset = block * 8ULL;
    if (fs->partition_start > MGFS_U64_MAX - sector_offset) return false;
    lba = fs->partition_start + sector_offset;
    if (lba > fs->block_io->Media->LastBlock ||
        fs->block_io->Media->LastBlock - lba < 7ULL) return false;
    return fs->block_io->ReadBlocks(fs->block_io, fs->media_id, lba,
                                    MGFS_BOOT_BLOCK_BYTES, buffer) == EFI_SUCCESS;
}

static bool mgfs_boot_validate_layout(MGFS_BOOT_FS *fs, u64 total_blocks,
                                      const u8 *superblock)
{
    u64 table_blocks = total_blocks / 320ULL;
    u64 record_count;
    u64 record_bitmap_blocks;
    u64 allocation_bitmap_blocks;
    u64 data_start;

    if (table_blocks == 0ULL) table_blocks = 1ULL;
    if (table_blocks > MGFS_U64_MAX / 21ULL) return false;
    record_count = table_blocks * 21ULL;
    record_bitmap_blocks = mgfs_boot_ceil_div(record_count,
                                               MGFS_BITMAP_BITS_PER_BLOCK);
    allocation_bitmap_blocks = mgfs_boot_ceil_div(total_blocks,
                                                   MGFS_BITMAP_BITS_PER_BLOCK);
    if (!mgfs_boot_add(1ULL, allocation_bitmap_blocks, &data_start) ||
        !mgfs_boot_add(data_start, record_bitmap_blocks, &data_start) ||
        !mgfs_boot_add(data_start, table_blocks, &data_start) ||
        data_start >= total_blocks) return false;

    if (mgfs_boot_le64(superblock + 104) != 1ULL ||
        mgfs_boot_le64(superblock + 112) != allocation_bitmap_blocks ||
        mgfs_boot_le64(superblock + 120) != 1ULL + allocation_bitmap_blocks ||
        mgfs_boot_le64(superblock + 128) != record_bitmap_blocks ||
        mgfs_boot_le64(superblock + 136) !=
            1ULL + allocation_bitmap_blocks + record_bitmap_blocks ||
        mgfs_boot_le64(superblock + 144) != table_blocks ||
        mgfs_boot_le64(superblock + 152) != record_count ||
        mgfs_boot_le64(superblock + 160) != data_start ||
        mgfs_boot_le64(superblock + 168) != total_blocks - data_start) return false;

    fs->record_table_start = mgfs_boot_le64(superblock + 136);
    fs->record_table_blocks = table_blocks;
    fs->record_count = record_count;
    fs->data_start = data_start;
    fs->data_blocks = total_blocks - data_start;
    return true;
}

static bool mgfs_boot_record_allocated(const MGFS_BOOT_FS *fs, u64 slot)
{
    if (!fs || slot >= fs->record_count) return false;
    return (fs->record_bitmap[slot / 8ULL] &
            (u8)(1U << (slot % 8ULL))) != 0U;
}

static bool mgfs_boot_validate_record(const MGFS_BOOT_FS *fs,
                                      const u8 *record)
{
    u64 type = mgfs_boot_le64(record);
    u64 flags = mgfs_boot_le64(record + 8);
    u64 id = mgfs_boot_le64(record + 16);
    u64 generation = mgfs_boot_le64(record + 24);
    u64 size = mgfs_boot_le64(record + 32);
    u64 extent_count = mgfs_boot_le64(record + 40);
    u64 inline_count = mgfs_boot_le64(record + 48);
    u64 list = mgfs_boot_le64(record + 56);

    if (!mgfs_boot_checksum(record, MGFS_BOOT_RECORD_BYTES,
                            MGFS_RECORD_CHECKSUM_OFFSET) ||
        id == 0ULL || generation == 0ULL ||
        (type != MGFS_RECORD_FILE && type != MGFS_RECORD_DIRECTORY) ||
        (flags & ~MGFS_RECORD_FLAGS_KNOWN) != 0ULL ||
        (flags & MGFS_RECORD_PERMISSIONS_MASK) == 0ULL ||
        (type == MGFS_RECORD_FILE &&
         (flags & MGFS_RECORD_CHILD_MUTATION_OWNER_RESTRICTED) != 0ULL) ||
        (fs && fs->format_minor == MGFS_FORMAT_MINOR_LEGACY &&
         (flags & MGFS_RECORD_CHILD_MUTATION_OWNER_RESTRICTED) != 0ULL) ||
        inline_count > 2ULL || inline_count > extent_count ||
        (extent_count == 0ULL && list != 0ULL) ||
        (extent_count <= 2ULL && list != 0ULL)) return false;
    if ((flags & MGFS_RECORD_INLINE_DATA) != 0ULL &&
        (type != MGFS_RECORD_FILE || extent_count != 0ULL ||
         inline_count != 0ULL || list != 0ULL || size > MGFS_BOOT_INLINE_DATA_BYTES)) {
        return false;
    }
    return true;
}

static bool mgfs_boot_load_table(MGFS_BOOT_FS *fs, u64 table_number)
{
    u8 *block = fs->table_block;
    if (table_number >= fs->record_table_blocks) return false;
    if (fs->table_block_valid && fs->table_block_number == table_number) {
        return true;
    }
    if (!mgfs_boot_read_block(fs, fs->record_table_start + table_number, block) ||
        mgfs_boot_le64(block) != MGFS_RECORD_TABLE_KIND ||
        mgfs_boot_le64(block + 8) != table_number ||
        !mgfs_boot_checksum(block, MGFS_BOOT_BLOCK_BYTES,
                            MGFS_METADATA_CHECKSUM_OFFSET)) return false;
    fs->table_block_number = table_number;
    fs->table_block_valid = true;
    return true;
}

static bool mgfs_boot_read_record(MGFS_BOOT_FS *fs, u64 record_id,
                                  u8 output[MGFS_BOOT_RECORD_BYTES])
{
    if (!fs || !output || record_id == 0ULL) return false;
    for (u64 table = 0; table < fs->record_table_blocks; table++) {
        if (!mgfs_boot_load_table(fs, table)) return false;
        for (u64 slot_in_table = 0; slot_in_table < 21ULL; slot_in_table++) {
            u64 slot = table * 21ULL + slot_in_table;
            const u8 *record;
            if (slot >= fs->record_count ||
                !mgfs_boot_record_allocated(fs, slot)) continue;
            record = fs->table_block + MGFS_BOOT_BITMAP_HEADER_BYTES +
                     slot_in_table * MGFS_BOOT_RECORD_BYTES;
            if (mgfs_boot_le64(record + 16) == record_id) {
                if (!mgfs_boot_validate_record(fs, record)) return false;
                mgfs_boot_copy(output, record, MGFS_BOOT_RECORD_BYTES);
                return true;
            }
        }
    }
    return false;
}

static bool mgfs_boot_extent_valid(MGFS_BOOT_FS *fs, const u8 *extent,
                                   u64 expected, u64 expected_flags,
                                   u64 *next)
{
    u64 logical = mgfs_boot_le64(extent);
    u64 physical = mgfs_boot_le64(extent + 8);
    u64 count = mgfs_boot_le64(extent + 16);
    u64 flags = mgfs_boot_le64(extent + 24);
    u64 end;

    if (count == 0ULL || logical != expected || flags != expected_flags ||
        !mgfs_boot_add(logical, count, &end) ||
        physical < fs->data_start ||
        physical - fs->data_start >= fs->data_blocks ||
        count > fs->data_blocks - (physical - fs->data_start)) return false;
    *next = end;
    return true;
}

static bool mgfs_boot_read_extent_list(MGFS_BOOT_FS *fs, u64 list,
                                       u64 record_id, u64 expected_flags,
                                       u64 *expected, u64 *count,
                                       u64 total, u64 wanted_block,
                                       u8 wanted[MGFS_BOOT_BLOCK_BYTES],
                                       bool *found, u64 *previous_physical_end)
{
    u8 *block = MgfsBootListBlock;
    u64 list_count = 0;

    while (list != 0ULL) {
        u64 entries;
        u64 next_list;
        if (++list_count > fs->record_count ||
            !mgfs_boot_read_block(fs, list, block) ||
            mgfs_boot_le64(block) != MGFS_BOOT_EXTENT_LIST_MAGIC ||
            mgfs_boot_le64(block + 8) != record_id ||
            !mgfs_boot_checksum(block, MGFS_BOOT_BLOCK_BYTES, 32U)) return false;
        entries = mgfs_boot_le64(block + 24);
        next_list = mgfs_boot_le64(block + 16);
        if (entries == 0ULL || entries > MGFS_BOOT_EXTENTS_PER_LIST_BLOCK ||
            next_list == list ||
            list < fs->data_start || list - fs->data_start >= fs->data_blocks) return false;
        for (u32 i = 40U; i < 64U; i++) if (block[i] != 0U) return false;
        for (u64 i = 0; i < entries; i++) {
            const u8 *extent = block + MGFS_BOOT_EXTENT_LIST_HEADER_BYTES + i * 32ULL;
            u64 logical = mgfs_boot_le64(extent);
            u64 physical = mgfs_boot_le64(extent + 8);
            u64 blocks = mgfs_boot_le64(extent + 16);
            u64 next_expected;
            if (*count >= total ||
                (expected_flags == MGFS_EXTENT_DATA &&
                 *count != 0ULL && physical < *previous_physical_end) ||
                !mgfs_boot_extent_valid(fs, extent, *expected, expected_flags,
                                        &next_expected)) return false;
            if (wanted_block >= logical && wanted_block - logical < blocks) {
                if (!mgfs_boot_read_block(fs,
                        physical + wanted_block - logical, wanted)) return false;
                *found = true;
            }
            *expected = next_expected;
            *previous_physical_end = physical + blocks;
            (*count)++;
        }
        list = next_list;
    }
    return true;
}

static bool mgfs_boot_read_mapped_block(MGFS_BOOT_FS *fs,
                                        const u8 record[MGFS_BOOT_RECORD_BYTES],
                                        u64 logical_block,
                                        u64 expected_flags,
                                        u8 output[MGFS_BOOT_BLOCK_BYTES])
{
    u64 expected = 0;
    u64 count = 0;
    u64 previous_end = 0;
    u64 inline_count = mgfs_boot_le64(record + 48);
    u64 total = mgfs_boot_le64(record + 40);
    u64 list = mgfs_boot_le64(record + 56);
    bool found = false;

    for (u64 i = 0; i < inline_count; i++) {
        const u8 *extent = record + 64ULL + i * 32ULL;
        u64 next_expected;
        u64 physical = mgfs_boot_le64(extent + 8);
        u64 blocks = mgfs_boot_le64(extent + 16);
        if (expected_flags == MGFS_EXTENT_DATA && count != 0ULL &&
            physical < previous_end) return false;
        if (!mgfs_boot_extent_valid(fs, extent, expected, expected_flags,
                                    &next_expected)) return false;
        if (logical_block >= expected && logical_block - expected < blocks) {
            if (!mgfs_boot_read_block(fs, physical + logical_block - expected,
                                      output)) return false;
            found = true;
        }
        expected = next_expected;
        previous_end = physical + blocks;
        count++;
    }
    if (!mgfs_boot_read_extent_list(fs, list, mgfs_boot_le64(record + 16),
                                    expected_flags, &expected, &count, total,
                                    logical_block, output, &found,
                                    &previous_end)) return false;
    return found && count == total;
}

static bool mgfs_boot_read_directory_bytes(MGFS_BOOT_FS *fs,
                                            const u8 record[MGFS_BOOT_RECORD_BYTES],
                                            u64 offset, u64 size, u8 *output)
{
    u8 *block = MgfsBootBlock;
    u64 logical_size = mgfs_boot_le64(record + 32);
    u64 remaining = size;
    if (offset > logical_size || size > logical_size - offset) return false;
    while (remaining > 0ULL) {
        u64 logical_block = offset / MGFS_BOOT_BLOCK_BYTES;
        u64 within = offset % MGFS_BOOT_BLOCK_BYTES;
        u64 chunk = MGFS_BOOT_BLOCK_BYTES - within;
        if (chunk > remaining) chunk = remaining;
        if (!mgfs_boot_read_mapped_block(fs, record, logical_block,
                                         MGFS_EXTENT_DIRECTORY, block)) return false;
        mgfs_boot_copy(output, block + within, (usize)chunk);
        output += chunk;
        offset += chunk;
        remaining -= chunk;
    }
    return true;
}

static bool mgfs_boot_find_child(MGFS_BOOT_FS *fs, u64 parent_id,
                                 const char *name, u64 *child_id,
                                 u64 *child_type, u64 *child_size)
{
    u8 parent[MGFS_BOOT_RECORD_BYTES];
    u8 header[32];
    u8 entry[MGFS_BOOT_MAX_NAME + 40U];
    u64 offset = 0;
    u64 directory_size;
    usize name_length = 0;

    if (!fs || !name || !child_id || !child_type || !child_size ||
        !mgfs_boot_read_record(fs, parent_id, parent) ||
        mgfs_boot_le64(parent) != MGFS_RECORD_DIRECTORY) return false;
    while (name[name_length] != '\0') {
        if (++name_length > MGFS_BOOT_MAX_NAME) return false;
    }
    directory_size = mgfs_boot_le64(parent + 32);
    while (offset < directory_size) {
        u64 entry_name_length;
        u64 aligned;
        if (directory_size - offset < 32ULL ||
            !mgfs_boot_read_directory_bytes(fs, parent, offset, 32ULL, header)) return false;
        entry_name_length = mgfs_boot_le64(header + 8);
        aligned = (32ULL + entry_name_length + 7ULL) & ~7ULL;
        if (entry_name_length == 0ULL || entry_name_length > MGFS_BOOT_MAX_NAME ||
            aligned > sizeof(entry) || aligned > directory_size - offset ||
            !mgfs_boot_read_directory_bytes(fs, parent, offset, aligned, entry)) return false;
        if (!mgfs_boot_checksum(entry, (usize)aligned, 24U)) return false;
        for (u64 i = 32ULL + entry_name_length; i < aligned; i++) {
            if (entry[i] != 0U) return false;
        }
        if (mgfs_boot_le64(entry + 16) != MGFS_DIRENT_IN_USE &&
            mgfs_boot_le64(entry + 16) != MGFS_DIRENT_TOMBSTONE) return false;
        if (mgfs_boot_le64(entry + 16) == MGFS_DIRENT_IN_USE &&
            entry_name_length == (u64)name_length) {
            bool equal = true;
            for (usize i = 0; i < name_length; i++) {
                if (entry[32U + i] != (u8)name[i]) equal = false;
            }
            if (equal) {
                u8 child[MGFS_BOOT_RECORD_BYTES];
                *child_id = mgfs_boot_le64(entry);
                if (!mgfs_boot_read_record(fs, *child_id, child)) return false;
                *child_type = mgfs_boot_le64(child);
                *child_size = mgfs_boot_le64(child + 32);
                return true;
            }
        }
        offset += aligned;
    }
    return false;
}

EFI_STATUS mgfs_boot_init(MGFS_BOOT_FS *fs,
                          EFI_BLOCK_IO_PROTOCOL *block_io,
                          u64 media_id,
                          u64 partition_start,
                          u64 partition_blocks)
{
    u8 *superblock = MgfsBootSuperblock;
    u64 total_blocks;
    u64 bitmap_blocks;
    u64 bitmap_bytes;

    if (!fs || !block_io || !block_io->Media || !block_io->ReadBlocks ||
        block_io->Media->BlockSize != 512U || partition_blocks < 8ULL) {
        return EFI_INVALID_PARAMETER;
    }
    mgfs_boot_zero(fs, sizeof(*fs));
    fs->block_io = block_io;
    fs->media_id = (u32)media_id;
    fs->partition_start = partition_start;
    fs->partition_blocks = partition_blocks;
    if (!mgfs_boot_read_block(fs, 0, superblock) ||
        !mgfs_boot_equal(superblock, (const u8 *)"MGFSv1\0\0", 8U) ||
        mgfs_boot_le64(superblock + 8) != MGFS_FORMAT_MAJOR ||
        (mgfs_boot_le64(superblock + 16) != MGFS_FORMAT_MINOR &&
         mgfs_boot_le64(superblock + 16) != MGFS_FORMAT_MINOR_LEGACY) ||
        mgfs_boot_le64(superblock + 24) != MGFS_HEADER_BYTES ||
         mgfs_boot_le64(superblock + 32) != MGFS_BOOT_BLOCK_BYTES ||
        !mgfs_boot_checksum(superblock, MGFS_HEADER_BYTES, 192U)) return EFI_COMPROMISED_DATA;
    fs->format_minor = mgfs_boot_le64(superblock + 16);
    total_blocks = mgfs_boot_le64(superblock + 40);
    if (total_blocks < MGFS_MIN_TOTAL_BLOCKS || total_blocks > partition_blocks / 8ULL ||
        !mgfs_boot_validate_layout(fs, total_blocks, superblock) ||
        mgfs_boot_le64(superblock + 48) != 0ULL ||
        mgfs_boot_le64(superblock + 56) != 0ULL ||
        mgfs_boot_le64(superblock + 96) < 2ULL) return EFI_COMPROMISED_DATA;
    fs->root_record_id = mgfs_boot_le64(superblock + 88);
    if (fs->root_record_id == 0ULL || fs->root_record_id > fs->record_count) {
        return EFI_COMPROMISED_DATA;
    }
    for (u32 i = MGFS_HEADER_BYTES; i < MGFS_BOOT_BLOCK_BYTES; i++) {
        if (superblock[i] != 0U) return EFI_COMPROMISED_DATA;
    }
    bitmap_blocks = mgfs_boot_ceil_div(fs->record_count,
                                       MGFS_BITMAP_BITS_PER_BLOCK);
    bitmap_bytes = (fs->record_count + 7ULL) / 8ULL;
    fs->record_bitmap_size = (usize)bitmap_bytes;
    if (bitmap_bytes > (u64)(usize)-1 ||
        memory_allocate(EFI_LOADER_DATA, fs->record_bitmap_size,
                        (void **)&fs->record_bitmap) != EFI_SUCCESS) {
        return EFI_OUT_OF_RESOURCES;
    }
    mgfs_boot_zero(fs->record_bitmap, fs->record_bitmap_size);
    for (u64 i = 0; i < bitmap_blocks; i++) {
        if (!mgfs_boot_read_block(fs, fs->record_table_start - bitmap_blocks + i,
                                  MgfsBootBlock) ||
            mgfs_boot_le64(MgfsBootBlock) != MGFS_RECORD_BITMAP_KIND ||
            mgfs_boot_le64(MgfsBootBlock + 8) != i ||
            !mgfs_boot_checksum(MgfsBootBlock, MGFS_BOOT_BLOCK_BYTES,
                                MGFS_METADATA_CHECKSUM_OFFSET)) return EFI_COMPROMISED_DATA;
        u64 first_slot = i * MGFS_BITMAP_BITS_PER_BLOCK;
        u64 slots = fs->record_count - first_slot;
        if (slots > MGFS_BITMAP_BITS_PER_BLOCK) slots = MGFS_BITMAP_BITS_PER_BLOCK;
        for (u64 slot = 0; slot < slots; slot++) {
            if ((MgfsBootBlock[MGFS_BOOT_BITMAP_HEADER_BYTES + slot / 8ULL] &
                 (u8)(1U << (slot % 8ULL))) != 0U) {
                u64 target = first_slot + slot;
                fs->record_bitmap[target / 8ULL] |=
                    (u8)(1U << (target % 8ULL));
            }
        }
    }
    /* Validate every allocated slot and every record-table block before any
     * path lookup.  This also preserves sparse Record ID semantics. */
    for (u64 table = 0; table < fs->record_table_blocks; table++) {
        if (!mgfs_boot_load_table(fs, table)) return EFI_COMPROMISED_DATA;
        for (u64 slot_in_table = 0; slot_in_table < 21ULL; slot_in_table++) {
            u64 slot = table * 21ULL + slot_in_table;
            const u8 *record;
            if (slot >= fs->record_count || !mgfs_boot_record_allocated(fs, slot)) continue;
            record = fs->table_block + MGFS_BOOT_BITMAP_HEADER_BYTES +
                     slot_in_table * MGFS_BOOT_RECORD_BYTES;
            if (!mgfs_boot_validate_record(fs, record)) return EFI_COMPROMISED_DATA;
        }
    }
    {
        u8 root[MGFS_BOOT_RECORD_BYTES];
        if (!mgfs_boot_read_record(fs, fs->root_record_id, root) ||
            mgfs_boot_le64(root) != MGFS_RECORD_DIRECTORY) return EFI_COMPROMISED_DATA;
    }
    return EFI_SUCCESS;
}

EFI_STATUS mgfs_boot_open(MGFS_BOOT_FS *fs, const char *path,
                          MGFS_BOOT_FILE *file)
{
    u64 current;
    u64 type;
    u64 size;
    const char *component;
    char name[MGFS_BOOT_MAX_NAME + 1U];
    usize length;

    if (!fs || !path || !file || path[0] != '/') return EFI_INVALID_PARAMETER;
    current = fs->root_record_id;
    component = path + 1;
    while (*component) {
        const char *end = component;
        while (*end && *end != '/') end++;
        length = (usize)(end - component);
        if (length == 0U || length > MGFS_BOOT_MAX_NAME) return EFI_INVALID_PARAMETER;
        for (usize i = 0; i < length; i++) name[i] = component[i];
        name[length] = '\0';
        if (!mgfs_boot_find_child(fs, current, name, &current, &type, &size)) {
            return EFI_NOT_FOUND;
        }
        if (*end == '/') {
            component = end + 1;
            if (*component == '\0') return EFI_NOT_FOUND;
            if (type != MGFS_RECORD_DIRECTORY) return EFI_NOT_FOUND;
        } else {
            if (type != MGFS_RECORD_FILE) return EFI_NOT_FOUND;
            break;
        }
    }
    if (path[1] == '\0') return EFI_INVALID_PARAMETER;
    file->fs = fs;
    file->record_id = current;
    file->size = size;
    file->position = 0;
    return EFI_SUCCESS;
}

EFI_STATUS mgfs_boot_read(MGFS_BOOT_FILE *file, void *buffer, usize *buffer_size)
{
    u8 record[MGFS_BOOT_RECORD_BYTES];
    u8 *block = MgfsBootFileBlock;
    u64 remaining;
    u64 initial_position;
    usize requested_size;
    u8 *output;

    if (!file || !file->fs || !buffer || !buffer_size ||
        !mgfs_boot_read_record(file->fs, file->record_id, record) ||
        mgfs_boot_le64(record) != MGFS_RECORD_FILE) return EFI_INVALID_PARAMETER;
    requested_size = *buffer_size;
    initial_position = file->position;
    if (file->position >= file->size) {
        *buffer_size = 0;
        return EFI_SUCCESS;
    }
    remaining = file->size - file->position;
    if ((u64)requested_size < remaining) remaining = requested_size;
    output = (u8 *)buffer;
    if ((mgfs_boot_le64(record + 8) & MGFS_RECORD_INLINE_DATA) != 0ULL) {
        mgfs_boot_copy(output + 0, record + 128U + file->position,
                       (usize)remaining);
        file->position += remaining;
        *buffer_size = (usize)remaining;
        return EFI_SUCCESS;
    }
    while (remaining > 0ULL) {
        u64 logical = file->position / MGFS_BOOT_BLOCK_BYTES;
        u64 within = file->position % MGFS_BOOT_BLOCK_BYTES;
        u64 chunk = MGFS_BOOT_BLOCK_BYTES - within;
        if (chunk > remaining) chunk = remaining;
        if (!mgfs_boot_read_mapped_block(file->fs, record, logical,
                                         MGFS_EXTENT_DATA, block)) return EFI_DEVICE_ERROR;
        mgfs_boot_copy(output, block + within, (usize)chunk);
        output += chunk;
        file->position += chunk;
        remaining -= chunk;
    }
    *buffer_size = (usize)(file->position - initial_position);
    return EFI_SUCCESS;
}

EFI_STATUS mgfs_boot_seek(MGFS_BOOT_FILE *file, u64 position)
{
    if (!file || position > file->size) return EFI_INVALID_PARAMETER;
    file->position = position;
    return EFI_SUCCESS;
}
