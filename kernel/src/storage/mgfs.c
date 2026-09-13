/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <storage/mgfs.h>

#include <block.h>
#include <heap.h>
#include <kprint.h>
#include <string.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

#define MGFS_BLOCK_BYTES             4096U
#define MGFS_FORMAT_MAJOR            1ULL
#define MGFS_FORMAT_MINOR            2ULL
#define MGFS_FORMAT_MINOR_LEGACY     1ULL
#define MGFS_HEADER_BYTES            200ULL
#define MGFS_RECORD_BYTES            192U
#define MGFS_RECORDS_PER_TABLE_BLOCK 21ULL
#define MGFS_BITMAP_HEADER_BYTES     24U
#define MGFS_BITMAP_BITS_PER_BLOCK   32576ULL
#define MGFS_MIN_TOTAL_BLOCKS        64ULL
#define MGFS_TABLE_BLOCKS_DIVISOR    320ULL
#define MGFS_SEEN_NAME_BUCKET_COUNT 64U
#define MGFS_DENTRY_CACHE_COUNT      128U

#define MGFS_STATE_KNOWN_MASK        0x3ULL
#define MGFS_STATE_CLEAN             0x1ULL
#define MGFS_STATE_NEEDS_FSCK        0x2ULL

#define MGFS_METADATA_ALLOCATION_BITMAP 1ULL
#define MGFS_METADATA_RECORD_BITMAP     2ULL
#define MGFS_METADATA_RECORD_TABLE      3ULL

#define MGFS_RECORD_FILE              1ULL
#define MGFS_RECORD_DIRECTORY         2ULL
#define MGFS_RECORD_INLINE_DATA       0x1ULL
#define MGFS_RECORD_OWNER_SHIFT       1U
#define MGFS_RECORD_OWNER_MASK        (0xFFFFFFFFULL << MGFS_RECORD_OWNER_SHIFT)
#define MGFS_RECORD_PERMISSIONS_SHIFT 33U
#define MGFS_RECORD_PERMISSIONS_MASK  (0xFULL << MGFS_RECORD_PERMISSIONS_SHIFT)
#define MGFS_RECORD_CHILD_MUTATION_SHIFT 41U
#define MGFS_RECORD_CHILD_MUTATION_OWNER_RESTRICTED \
    (1ULL << MGFS_RECORD_CHILD_MUTATION_SHIFT)
#define MGFS_RECORD_FLAGS_KNOWN       (MGFS_RECORD_INLINE_DATA | \
                                      MGFS_RECORD_OWNER_MASK | \
                                      MGFS_RECORD_PERMISSIONS_MASK | \
                                      MGFS_RECORD_CHILD_MUTATION_OWNER_RESTRICTED)

#define MGFS_EXTENT_DATA              0x1ULL
#define MGFS_EXTENT_DIRECTORY_METADATA 0x2ULL
#define MGFS_EXTENT_LIST_METADATA     0x4ULL
#define MGFS_EXTENT_LIST_MAGIC         0x315458455346474DULL
#define MGFS_EXTENT_LIST_HEADER_BYTES  64ULL
#define MGFS_EXTENTS_PER_LIST_BLOCK    126ULL
#define MGFS_INLINE_DATA_BYTES         56ULL

#define MGFS_DIRENT_IN_USE             1ULL
#define MGFS_DIRENT_TOMBSTONE          2ULL
#define MGFS_SUPER_CHECKSUM_OFFSET    192U
#define MGFS_LABEL_EXTENSION_OFFSET   200U
#define MGFS_LABEL_LENGTH_OFFSET      208U
#define MGFS_LABEL_DATA_OFFSET        216U
#define MGFS_LABEL_CHECKSUM_OFFSET    280U
#define MGFS_LABEL_BYTES              63U
#define MGFS_LABEL_EXTENSION_BYTES    88U
#define MGFS_METADATA_CHECKSUM_OFFSET 16U
#define MGFS_RECORD_CHECKSUM_OFFSET   184U

#define MGFS_CRC64_POLYNOMIAL         0x42F0E1EBA9EA3693ULL
#define MGFS_U64_MAX                  0xFFFFFFFFFFFFFFFFULL

typedef struct {
    u64 allocation_bitmap_start;
    u64 allocation_bitmap_blocks;
    u64 record_bitmap_start;
    u64 record_bitmap_blocks;
    u64 record_table_start;
    u64 record_table_blocks;
    u64 record_count;
    u64 data_start;
    u64 data_blocks;
} mgfs_layout_t;

typedef struct {
    u64 id;
    u64 slot;
} mgfs_record_ref_t;

typedef struct {
    bool valid;
    u64 parent_id;
    u64 target_id;
    u64 age;
    u16 name_length;
    char name[256];
} mgfs_dentry_cache_entry_t;

typedef struct {
    block_device_t *dev;
    u64 format_minor;
    mgfs_layout_t layout;
    u64 total_blocks;
    u64 root_record_id;
    u64 next_record_id;
    u8 *record_bitmap;
    u64 record_bitmap_bytes;
    mgfs_record_ref_t *record_ids;
    u64 record_id_capacity;
    u64 allocated_record_count;
    mgfs_dentry_cache_entry_t dentry_cache[MGFS_DENTRY_CACHE_COUNT];
    u64 dentry_cache_age;
} mgfs_fs_t;

static const vfs_ops_t mgfs_node_ops;
static const vfs_super_ops_t mgfs_super_ops;
static const char *mgfs_error = "no error";
static void mgfs_store_extent(u8 *record, u64 offset, u64 logical,
                              u64 physical, u64 blocks, u64 flags);
static u64 mgfs_read(vfs_node_t *node, u64 offset, u64 size, void *buffer);

static u64 mgfs_get_le64(const u8 *data)
{
    u64 value = 0;
    for (u32 i = 0; i < 8; i++) {
        value |= (u64)data[i] << (i * 8);
    }
    return value;
}

static u64 mgfs_security_flags(u32 owner_uid, u32 permissions,
                               bool inline_data,
                               vfs_child_mutation_policy_t child_mutation_policy)
{
    return (inline_data ? MGFS_RECORD_INLINE_DATA : 0ULL) |
           ((u64)owner_uid << MGFS_RECORD_OWNER_SHIFT) |
           ((u64)(permissions & VFS_PERMISSION_KNOWN) << MGFS_RECORD_PERMISSIONS_SHIFT) |
           (child_mutation_policy == VFS_CHILD_MUTATION_OWNER_RESTRICTED
                ? MGFS_RECORD_CHILD_MUTATION_OWNER_RESTRICTED : 0ULL);
}

static u32 mgfs_record_owner(const u8 record[MGFS_RECORD_BYTES])
{
    return (u32)((mgfs_get_le64(record + 8) & MGFS_RECORD_OWNER_MASK) >>
                 MGFS_RECORD_OWNER_SHIFT);
}

static u32 mgfs_record_permissions(const u8 record[MGFS_RECORD_BYTES])
{
    return (u32)((mgfs_get_le64(record + 8) & MGFS_RECORD_PERMISSIONS_MASK) >>
                 MGFS_RECORD_PERMISSIONS_SHIFT);
}

static vfs_child_mutation_policy_t mgfs_record_child_mutation_policy(
    const u8 record[MGFS_RECORD_BYTES])
{
    return (mgfs_get_le64(record + 8) &
            MGFS_RECORD_CHILD_MUTATION_OWNER_RESTRICTED)
        ? VFS_CHILD_MUTATION_OWNER_RESTRICTED
        : VFS_CHILD_MUTATION_OPEN;
}

static void mgfs_apply_directory_policy(const u8 record[MGFS_RECORD_BYTES],
                                        vfs_node_t *node)
{
    vfs_child_mutation_policy_t child_mutation_policy;

    if (!node || mgfs_get_le64(record) != MGFS_RECORD_DIRECTORY) return;
    child_mutation_policy = mgfs_record_child_mutation_policy(record);
    vfs_node_set_child_mutation_policy(node, child_mutation_policy);
}

static void mgfs_set_error(const char *message)
{
    mgfs_error = message;
}

static bool mgfs_bytes_equal(const u8 *left, const u8 *right, usize length)
{
    for (usize i = 0; i < length; i++) {
        if (left[i] != right[i]) {
            return false;
        }
    }
    return true;
}

static u64 mgfs_name_hash(const char *name, u64 length)
{
    u64 hash = 1469598103934665603ULL;
    for (u64 i = 0; i < length; i++) {
        hash ^= (u8)name[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static u32 mgfs_seen_bucket(const char *name, u64 length)
{
    return (u32)(mgfs_name_hash(name, length) % MGFS_SEEN_NAME_BUCKET_COUNT);
}

static bool mgfs_dentry_cache_lookup(mgfs_fs_t *fs, u64 parent_id,
                                     const char *name, u64 *out_target_id)
{
    u64 length;

    if (!fs || !name || !out_target_id) return false;
    length = strlen(name);
    if (length > 255ULL) return false;
    for (u32 i = 0; i < MGFS_DENTRY_CACHE_COUNT; i++) {
        mgfs_dentry_cache_entry_t *entry = &fs->dentry_cache[i];
        if (entry->valid && entry->parent_id == parent_id &&
            entry->name_length == length &&
            mgfs_bytes_equal((const u8 *)entry->name, (const u8 *)name,
                             (usize)length)) {
            entry->age = ++fs->dentry_cache_age;
            *out_target_id = entry->target_id;
            return true;
        }
    }
    return false;
}

static void mgfs_dentry_cache_insert(mgfs_fs_t *fs, u64 parent_id,
                                     const char *name, u64 target_id)
{
    mgfs_dentry_cache_entry_t *victim;
    u64 length;

    if (!fs || !name) return;
    length = strlen(name);
    if (length == 0ULL || length > 255ULL) return;
    victim = &fs->dentry_cache[0];
    for (u32 i = 0; i < MGFS_DENTRY_CACHE_COUNT; i++) {
        mgfs_dentry_cache_entry_t *entry = &fs->dentry_cache[i];
        if (!entry->valid) {
            victim = entry;
            break;
        }
        if (entry->age < victim->age) victim = entry;
    }
    victim->valid = true;
    victim->parent_id = parent_id;
    victim->target_id = target_id;
    victim->age = ++fs->dentry_cache_age;
    victim->name_length = (u16)length;
    memcpy(victim->name, name, (usize)length + 1ULL);
}

static void mgfs_dentry_cache_invalidate_parent(mgfs_fs_t *fs, u64 parent_id)
{
    if (!fs) return;
    for (u32 i = 0; i < MGFS_DENTRY_CACHE_COUNT; i++) {
        if (fs->dentry_cache[i].valid &&
            fs->dentry_cache[i].parent_id == parent_id) {
            fs->dentry_cache[i].valid = false;
        }
    }
}

const char *mgfs_last_error(void)
{
    return mgfs_error;
}
static u64 mgfs_crc64(const u8 *data, usize length)
{
    u64 crc = 0;

    for (usize byte = 0; byte < length; byte++) {
        crc ^= (u64)data[byte] << 56;
        for (u32 bit = 0; bit < 8; bit++) {
            if (crc & (1ULL << 63)) {
                crc = (crc << 1) ^ MGFS_CRC64_POLYNOMIAL;
            } else {
                crc <<= 1;
            }
        }
    }

    return crc;
}

static bool mgfs_checksum_block(const u8 *block, u32 checksum_offset,
                                usize covered_bytes)
{
    u64 stored = mgfs_get_le64(block + checksum_offset);
    u64 calculated = 0;

    /* Checksum fields are logically zero while calculating.  Reading them
     * as zero avoids a full-block scratch copy on small kernel stacks. */
    for (usize i = 0; i < covered_bytes; i++) {
        u8 value = (i >= checksum_offset && i < checksum_offset + 8U)
            ? 0 : block[i];
        calculated ^= (u64)value << 56;
        for (u32 bit = 0; bit < 8; bit++) {
            calculated = (calculated & 0x8000000000000000ULL)
                ? (calculated << 1) ^ MGFS_CRC64_POLYNOMIAL
                : calculated << 1;
        }
    }

    return calculated == stored;
}

static bool mgfs_label_extension_valid(const u8 *block)
{
    static const u8 magic[8] = { 'M', 'G', 'L', 'A', 'B', 'E', 'L', '1' };
    u64 length;

    if (!block || !mgfs_bytes_equal(block + MGFS_LABEL_EXTENSION_OFFSET,
                                    magic, sizeof(magic))) return false;
    length = mgfs_get_le64(block + MGFS_LABEL_LENGTH_OFFSET);
    if (length > MGFS_LABEL_BYTES) return false;
    for (u64 index = length; index < MGFS_LABEL_BYTES; index++) {
        if (block[MGFS_LABEL_DATA_OFFSET + index] != 0) return false;
    }
    if (block[MGFS_LABEL_DATA_OFFSET + MGFS_LABEL_BYTES] != 0) return false;
    return mgfs_checksum_block(block + MGFS_LABEL_EXTENSION_OFFSET,
                               MGFS_LABEL_CHECKSUM_OFFSET -
                                   MGFS_LABEL_EXTENSION_OFFSET,
                               MGFS_LABEL_EXTENSION_BYTES);
}

static bool mgfs_read_block(block_device_t *dev, u64 block_number, u8 *buffer)
{
    u64 lba;

    if (!dev || !buffer || dev->sector_size != 512U) {
        mgfs_set_error("MGFS requires 512-byte block-device sectors");
        return false;
    }

    if (block_number > (MGFS_U64_MAX / 8ULL)) {
        mgfs_set_error("MGFS block address overflows the sector address");
        return false;
    }

    lba = block_number * 8ULL;
    if (lba > dev->sector_count || dev->sector_count - lba < 8ULL) {
        mgfs_set_error("MGFS block lies outside the block device");
        return false;
    }

    if (!block_read(dev, lba, 8, buffer)) {
        mgfs_set_error("MGFS block read failed");
        return false;
    }

    return true;
}

static bool mgfs_write_block(block_device_t *dev, u64 block_number, const u8 *buffer)
{
    u64 lba;

    if (!dev || !buffer || dev->sector_size != 512U ||
        block_number > MGFS_U64_MAX / 8ULL) {
        mgfs_set_error("invalid MGFS block write");
        return false;
    }
    lba = block_number * 8ULL;
    if (lba > dev->sector_count || dev->sector_count - lba < 8ULL ||
        !block_write(dev, lba, 8, buffer)) {
        mgfs_set_error("MGFS block write failed");
        return false;
    }
    return true;
}

static void mgfs_store_le64(u8 *data, u64 value)
{
    for (u32 i = 0; i < 8; i++) {
        data[i] = (u8)(value >> (i * 8));
    }
}

static bool mgfs_recompute_checksum(u8 *block, u32 offset, usize covered_bytes)
{
    mgfs_store_le64(block + offset, 0ULL);
    mgfs_store_le64(block + offset, mgfs_crc64(block, covered_bytes));
    return true;
}

static u64 mgfs_ceil_div(u64 value, u64 divisor)
{
    return (value / divisor) + ((value % divisor) != 0ULL);
}

static bool mgfs_calculate_layout(u64 total_blocks, mgfs_layout_t *layout)
{
    u64 table_blocks;
    u64 record_count;
    u64 record_bitmap_blocks;
    u64 allocation_bitmap_blocks;
    u64 data_start;

    if (total_blocks < MGFS_MIN_TOTAL_BLOCKS) {
        return false;
    }

    table_blocks = total_blocks / MGFS_TABLE_BLOCKS_DIVISOR;
    if (table_blocks == 0ULL) {
        table_blocks = 1ULL;
    }

    if (table_blocks > MGFS_U64_MAX / MGFS_RECORDS_PER_TABLE_BLOCK) {
        return false;
    }
    record_count = table_blocks * MGFS_RECORDS_PER_TABLE_BLOCK;
    record_bitmap_blocks = mgfs_ceil_div(record_count, MGFS_BITMAP_BITS_PER_BLOCK);
    allocation_bitmap_blocks = mgfs_ceil_div(total_blocks, MGFS_BITMAP_BITS_PER_BLOCK);

    if (allocation_bitmap_blocks > MGFS_U64_MAX - 1ULL ||
        record_bitmap_blocks > MGFS_U64_MAX - 1ULL - allocation_bitmap_blocks ||
        table_blocks > MGFS_U64_MAX - 1ULL - allocation_bitmap_blocks - record_bitmap_blocks) {
        return false;
    }

    data_start = 1ULL + allocation_bitmap_blocks + record_bitmap_blocks + table_blocks;
    if (data_start >= total_blocks) {
        return false;
    }

    layout->allocation_bitmap_start = 1ULL;
    layout->allocation_bitmap_blocks = allocation_bitmap_blocks;
    layout->record_bitmap_start = 1ULL + allocation_bitmap_blocks;
    layout->record_bitmap_blocks = record_bitmap_blocks;
    layout->record_table_start = layout->record_bitmap_start + record_bitmap_blocks;
    layout->record_table_blocks = table_blocks;
    layout->record_count = record_count;
    layout->data_start = data_start;
    layout->data_blocks = total_blocks - data_start;
    return true;
}

static bool mgfs_validate_superblock(
    block_device_t *dev,
    const u8 *block,
    mgfs_fs_t *fs)
{
    static const u8 magic[8] = { 'M', 'G', 'F', 'S', 'v', '1', 0, 0 };
    mgfs_layout_t expected;
    u64 total_blocks;
    u64 state_flags;
    u64 feature_compat;
    u64 feature_incompat;

    if (!mgfs_bytes_equal(block, magic, sizeof(magic))) {
        mgfs_set_error("MGFS magic mismatch");
        return false;
    }

    if (mgfs_get_le64(block + 8) != MGFS_FORMAT_MAJOR ||
        (mgfs_get_le64(block + 16) != MGFS_FORMAT_MINOR &&
         mgfs_get_le64(block + 16) != MGFS_FORMAT_MINOR_LEGACY)) {
        mgfs_set_error("unsupported MGFS version");
        return false;
    }
    fs->format_minor = mgfs_get_le64(block + 16);

    if (mgfs_get_le64(block + 24) != MGFS_HEADER_BYTES ||
        mgfs_get_le64(block + 32) != MGFS_BLOCK_BYTES) {
        mgfs_set_error("invalid MGFS header or block size");
        return false;
    }

    /* Bytes 200..287 are the optional, independently checksummed label
     * extension.  Keeping it outside the original 200-byte checksum makes
     * unlabeled v1.1 images fully compatible while still protecting labels. */
    for (u32 i = MGFS_LABEL_EXTENSION_OFFSET + MGFS_LABEL_EXTENSION_BYTES;
         i < MGFS_BLOCK_BYTES; i++) {
        if (block[i] != 0) {
            mgfs_set_error("nonzero MGFS superblock reserved bytes");
            return false;
        }
    }

    if (!mgfs_checksum_block(block, MGFS_SUPER_CHECKSUM_OFFSET,
                             MGFS_HEADER_BYTES)) {
        mgfs_set_error("MGFS superblock checksum mismatch");
        return false;
    }

    total_blocks = mgfs_get_le64(block + 40);
    /* A GPT partition may end up to seven sectors past an MGFS block
     * boundary.  The formatter deliberately leaves that tail outside the
     * filesystem; require the superblock to describe exactly the complete
     * 4 KiB blocks available in this device extent. */
    if (total_blocks < MGFS_MIN_TOTAL_BLOCKS ||
        total_blocks != dev->sector_count / 8ULL) {
        mgfs_set_error("MGFS total block count does not match the device");
        return false;
    }

    feature_compat = mgfs_get_le64(block + 48);
    feature_incompat = mgfs_get_le64(block + 56);
    if (feature_compat != 0ULL || feature_incompat != 0ULL) {
        mgfs_set_error("unsupported MGFS feature flags");
        return false;
    }

    state_flags = mgfs_get_le64(block + 64);
    if ((state_flags & ~MGFS_STATE_KNOWN_MASK) != 0ULL || state_flags == 0ULL) {
        mgfs_set_error("invalid MGFS state flags");
        return false;
    }

    if (!mgfs_calculate_layout(total_blocks, &expected) ||
        mgfs_get_le64(block + 104) != expected.allocation_bitmap_start ||
        mgfs_get_le64(block + 112) != expected.allocation_bitmap_blocks ||
        mgfs_get_le64(block + 120) != expected.record_bitmap_start ||
        mgfs_get_le64(block + 128) != expected.record_bitmap_blocks ||
        mgfs_get_le64(block + 136) != expected.record_table_start ||
        mgfs_get_le64(block + 144) != expected.record_table_blocks ||
        mgfs_get_le64(block + 152) != expected.record_count ||
        mgfs_get_le64(block + 160) != expected.data_start ||
        mgfs_get_le64(block + 168) != expected.data_blocks) {
        mgfs_set_error("invalid MGFS region layout");
        return false;
    }

    if (mgfs_get_le64(block + 88) != 1ULL || mgfs_get_le64(block + 96) < 2ULL) {
        mgfs_set_error("invalid MGFS root or next Record ID");
        return false;
    }

    fs->total_blocks = total_blocks;
    fs->layout = expected;
    fs->root_record_id = mgfs_get_le64(block + 88);
    fs->next_record_id = mgfs_get_le64(block + 96);
    return true;
}

static bool mgfs_validate_metadata_header(
    u8 *block,
    u64 expected_kind,
    u64 expected_index)
{
    if (mgfs_get_le64(block) != expected_kind ||
        mgfs_get_le64(block + 8) != expected_index) {
        mgfs_set_error("invalid MGFS metadata block header");
        return false;
    }

    if (!mgfs_checksum_block(block, MGFS_METADATA_CHECKSUM_OFFSET,
                             MGFS_BLOCK_BYTES)) {
        mgfs_set_error("MGFS metadata block checksum mismatch");
        return false;
    }

    return true;
}

static bool mgfs_validate_bitmap_region(
    mgfs_fs_t *fs,
    u64 start,
    u64 block_count,
    u64 expected_kind,
    u64 valid_bits,
    bool copy_record_bitmap)
{
    u8 block[MGFS_BLOCK_BYTES];

    for (u64 index = 0; index < block_count; index++) {
        u64 first_bit = index * MGFS_BITMAP_BITS_PER_BLOCK;
        u64 block_valid_bits = 0;

        if (first_bit < valid_bits) {
            u64 remaining = valid_bits - first_bit;
            block_valid_bits = remaining < MGFS_BITMAP_BITS_PER_BLOCK
                ? remaining : MGFS_BITMAP_BITS_PER_BLOCK;
        }

        if (!mgfs_read_block(fs->dev, start + index, block) ||
            !mgfs_validate_metadata_header(block, expected_kind, index)) {
            return false;
        }

        for (u64 bit = block_valid_bits; bit < MGFS_BITMAP_BITS_PER_BLOCK; bit++) {
            if ((block[MGFS_BITMAP_HEADER_BYTES + bit / 8ULL] &
                 (1U << (bit % 8ULL))) == 0U) {
                mgfs_set_error("MGFS bitmap has a free out-of-range bit");
                return false;
            }
        }

        if (copy_record_bitmap) {
            memcpy(fs->record_bitmap + index * MGFS_BLOCK_BYTES,
                   block, MGFS_BLOCK_BYTES);
        }
    }

    return true;
}

static bool mgfs_record_slot_allocated(const mgfs_fs_t *fs, u64 slot)
{
    u64 bitmap_block = slot / MGFS_BITMAP_BITS_PER_BLOCK;
    u64 bit = slot % MGFS_BITMAP_BITS_PER_BLOCK;
    u64 byte_offset = bitmap_block * MGFS_BLOCK_BYTES + MGFS_BITMAP_HEADER_BYTES + bit / 8ULL;
    return (fs->record_bitmap[byte_offset] & (1U << (bit % 8ULL))) != 0U;
}

static bool mgfs_update_superblock(mgfs_fs_t *fs, u64 next_record_id, u64 state_flags)
{
    u8 block[MGFS_BLOCK_BYTES];

    if (!mgfs_read_block(fs->dev, 0, block)) {
        return false;
    }
    mgfs_store_le64(block + 64, state_flags);
    mgfs_store_le64(block + 96, next_record_id);
    mgfs_recompute_checksum(block, MGFS_SUPER_CHECKSUM_OFFSET, MGFS_HEADER_BYTES);
    if (!mgfs_write_block(fs->dev, 0, block)) {
        return false;
    }
    fs->next_record_id = next_record_id;
    return true;
}

static bool mgfs_set_state(mgfs_fs_t *fs, u64 state_flags)
{
    return mgfs_update_superblock(fs, fs->next_record_id, state_flags);
}

static bool mgfs_update_bitmap_bit(
    mgfs_fs_t *fs,
    u64 region_start,
    u64 region_blocks,
    u64 valid_bits,
    u64 bit,
    bool value,
    bool record_bitmap)
{
    u8 block[MGFS_BLOCK_BYTES];
    u64 block_index = bit / MGFS_BITMAP_BITS_PER_BLOCK;
    u64 bit_in_block = bit % MGFS_BITMAP_BITS_PER_BLOCK;
    u64 byte_offset;

    if (bit >= valid_bits || block_index >= region_blocks ||
        !mgfs_read_block(fs->dev, region_start + block_index, block) ||
        !mgfs_validate_metadata_header(block,
            record_bitmap ? MGFS_METADATA_RECORD_BITMAP : MGFS_METADATA_ALLOCATION_BITMAP,
            block_index)) {
        mgfs_set_error("invalid MGFS bitmap allocation request");
        return false;
    }
    byte_offset = MGFS_BITMAP_HEADER_BYTES + bit_in_block / 8ULL;
    if (value) {
        block[byte_offset] |= (u8)(1U << (bit_in_block % 8ULL));
    } else {
        block[byte_offset] &= (u8)~(1U << (bit_in_block % 8ULL));
    }
    mgfs_recompute_checksum(block, MGFS_METADATA_CHECKSUM_OFFSET, MGFS_BLOCK_BYTES);
    if (!mgfs_write_block(fs->dev, region_start + block_index, block)) {
        return false;
    }
    if (record_bitmap) {
        u64 cache_offset = block_index * MGFS_BLOCK_BYTES + byte_offset;
        fs->record_bitmap[cache_offset] = block[byte_offset];
    }
    return true;
}

static bool mgfs_allocate_data_block(mgfs_fs_t *fs, u64 *out_block)
{
    u8 block[MGFS_BLOCK_BYTES];
    for (u64 index = 0; index < fs->layout.data_blocks; index++) {
        u64 bitmap_block = index / MGFS_BITMAP_BITS_PER_BLOCK;
        u64 bit = index % MGFS_BITMAP_BITS_PER_BLOCK;
        u64 byte_offset = MGFS_BITMAP_HEADER_BYTES + bit / 8ULL;
        if (!mgfs_read_block(fs->dev,
                             fs->layout.allocation_bitmap_start + bitmap_block,
                             block) ||
            !mgfs_validate_metadata_header(block, MGFS_METADATA_ALLOCATION_BITMAP,
                                           bitmap_block)) {
            return false;
        }
        if ((block[byte_offset] & (1U << (bit % 8ULL))) == 0U) {
            if (!mgfs_update_bitmap_bit(fs, fs->layout.allocation_bitmap_start,
                                        fs->layout.allocation_bitmap_blocks,
                                        fs->layout.data_blocks, index, true, false)) {
                return false;
            }
            *out_block = fs->layout.data_start + index;
            return true;
        }
    }
    mgfs_set_error("MGFS data area is full");
    return false;
}

static bool mgfs_allocate_record(mgfs_fs_t *fs, u64 *out_slot, u64 *out_id)
{
    for (u64 slot = 0; slot < fs->layout.record_count; slot++) {
        if (!mgfs_record_slot_allocated(fs, slot)) {
            if (fs->next_record_id == 0ULL || fs->next_record_id == MGFS_U64_MAX) {
                mgfs_set_error("MGFS Record ID space is exhausted");
                return false;
            }
            *out_id = fs->next_record_id;
            if (!mgfs_update_bitmap_bit(fs, fs->layout.record_bitmap_start,
                                        fs->layout.record_bitmap_blocks,
                                        fs->layout.record_count, slot, true, true) ||
                !mgfs_update_superblock(fs, fs->next_record_id + 1ULL,
                                        MGFS_STATE_NEEDS_FSCK)) {
                return false;
            }
            *out_slot = slot;
            return true;
        }
    }
    mgfs_set_error("MGFS File Record table is full");
    return false;
}

static bool mgfs_free_data_block(mgfs_fs_t *fs, u64 block_number)
{
    if (block_number < fs->layout.data_start ||
        block_number - fs->layout.data_start >= fs->layout.data_blocks) {
        mgfs_set_error("invalid MGFS data block release");
        return false;
    }
    return mgfs_update_bitmap_bit(fs, fs->layout.allocation_bitmap_start,
                                  fs->layout.allocation_bitmap_blocks,
                                  fs->layout.data_blocks,
                                  block_number - fs->layout.data_start,
                                  false, false);
}

static bool mgfs_free_record_slot(mgfs_fs_t *fs, u64 slot)
{
    if (slot >= fs->layout.record_count ||
        !mgfs_record_slot_allocated(fs, slot)) {
        mgfs_set_error("invalid MGFS Record release");
        return false;
    }
    return mgfs_update_bitmap_bit(fs, fs->layout.record_bitmap_start,
                                  fs->layout.record_bitmap_blocks,
                                  fs->layout.record_count, slot, false, true);
}

static bool mgfs_write_record_slot(
    mgfs_fs_t *fs, u64 slot, const u8 record[MGFS_RECORD_BYTES])
{
    u8 block[MGFS_BLOCK_BYTES];
    u64 table_index = slot / MGFS_RECORDS_PER_TABLE_BLOCK;
    u64 slot_in_block = slot % MGFS_RECORDS_PER_TABLE_BLOCK;

    if (table_index >= fs->layout.record_table_blocks ||
        !mgfs_read_block(fs->dev, fs->layout.record_table_start + table_index, block) ||
        !mgfs_validate_metadata_header(block, MGFS_METADATA_RECORD_TABLE, table_index)) {
        return false;
    }
    memcpy(block + MGFS_BITMAP_HEADER_BYTES + slot_in_block * MGFS_RECORD_BYTES,
           record, MGFS_RECORD_BYTES);
    mgfs_recompute_checksum(block, MGFS_METADATA_CHECKSUM_OFFSET, MGFS_BLOCK_BYTES);
    return mgfs_write_block(fs->dev, fs->layout.record_table_start + table_index, block);
}

static u64 mgfs_hash_id(u64 id)
{
    id ^= id >> 30;
    id *= 0xbf58476d1ce4e5b9ULL;
    id ^= id >> 27;
    id *= 0x94d049bb133111ebULL;
    return id ^ (id >> 31);
}

static bool mgfs_insert_record_id(mgfs_fs_t *fs, u64 id, u64 slot)
{
    u64 mask = fs->record_id_capacity - 1ULL;
    u64 index = mgfs_hash_id(id) & mask;

    for (u64 probe = 0; probe < fs->record_id_capacity; probe++) {
        if (fs->record_ids[index].id == 0ULL) {
            fs->record_ids[index].id = id;
            fs->record_ids[index].slot = slot;
            return true;
        }
        if (fs->record_ids[index].id == id) {
            mgfs_set_error("duplicate MGFS Record ID");
            return false;
        }
        index = (index + 1ULL) & mask;
    }

    mgfs_set_error("MGFS Record ID index is full");
    return false;
}

static bool mgfs_find_record_slot(
    const mgfs_fs_t *fs,
    u64 id,
    u64 *out_slot)
{
    u64 mask;
    u64 index;

    if (!fs || !out_slot || id == 0ULL || fs->record_id_capacity == 0ULL) {
        return false;
    }

    mask = fs->record_id_capacity - 1ULL;
    index = mgfs_hash_id(id) & mask;
    for (u64 probe = 0; probe < fs->record_id_capacity; probe++) {
        if (fs->record_ids[index].id == 0ULL) {
            return false;
        }
        if (fs->record_ids[index].id == id) {
            *out_slot = fs->record_ids[index].slot;
            return true;
        }
        index = (index + 1ULL) & mask;
    }

    return false;
}

static bool mgfs_validate_record(const mgfs_fs_t *fs, const u8 *record)
{
    u64 type = mgfs_get_le64(record);
    u64 flags = mgfs_get_le64(record + 8);
    u64 id = mgfs_get_le64(record + 16);
    u64 generation = mgfs_get_le64(record + 24);
    u64 size = mgfs_get_le64(record + 32);
    u64 extent_count = mgfs_get_le64(record + 40);
    u64 inline_extent_count = mgfs_get_le64(record + 48);
    u64 extent_list_head = mgfs_get_le64(record + 56);

    if (!mgfs_checksum_block(record, MGFS_RECORD_CHECKSUM_OFFSET,
                             MGFS_RECORD_BYTES)) {
        mgfs_set_error("MGFS File Record checksum mismatch");
        return false;
    }

    if (id == 0ULL || generation == 0ULL ||
        (type != MGFS_RECORD_FILE && type != MGFS_RECORD_DIRECTORY) ||
        (flags & ~MGFS_RECORD_FLAGS_KNOWN) != 0ULL ||
        (mgfs_record_permissions(record) & ~VFS_PERMISSION_KNOWN) != 0U ||
        mgfs_record_permissions(record) == 0U ||
        (type == MGFS_RECORD_FILE &&
         (flags & MGFS_RECORD_CHILD_MUTATION_OWNER_RESTRICTED) != 0ULL) ||
        (fs && fs->format_minor == MGFS_FORMAT_MINOR_LEGACY &&
         (flags & MGFS_RECORD_CHILD_MUTATION_OWNER_RESTRICTED) != 0ULL) ||
        inline_extent_count > 2ULL || inline_extent_count > extent_count ||
        (extent_count == 0ULL && extent_list_head != 0ULL) ||
        (extent_count <= 2ULL && extent_list_head != 0ULL)) {
        mgfs_set_error("invalid MGFS File Record fields");
        return false;
    }

    if ((flags & MGFS_RECORD_INLINE_DATA) != 0ULL &&
        (type != MGFS_RECORD_FILE || extent_count != 0ULL ||
        inline_extent_count != 0ULL || extent_list_head != 0ULL || size > MGFS_INLINE_DATA_BYTES)) {
        mgfs_set_error("invalid MGFS inline-data File Record");
        return false;
    }

    return true;
}

static bool mgfs_read_record(
    mgfs_fs_t *fs,
    u64 record_id,
    u8 out_record[MGFS_RECORD_BYTES])
{
    u8 table_block[MGFS_BLOCK_BYTES];
    u64 slot;
    u64 table_index;
    u64 slot_in_block;
    u8 *record;

    if (!mgfs_find_record_slot(fs, record_id, &slot)) {
        mgfs_set_error("MGFS directory entry references a missing Record ID");
        return false;
    }

    table_index = slot / MGFS_RECORDS_PER_TABLE_BLOCK;
    slot_in_block = slot % MGFS_RECORDS_PER_TABLE_BLOCK;
    if (table_index >= fs->layout.record_table_blocks ||
        !mgfs_read_block(fs->dev, fs->layout.record_table_start + table_index, table_block) ||
        !mgfs_validate_metadata_header(table_block, MGFS_METADATA_RECORD_TABLE, table_index)) {
        return false;
    }
    record = table_block + MGFS_BITMAP_HEADER_BYTES + slot_in_block * MGFS_RECORD_BYTES;
    if (!mgfs_validate_record(fs, record) || mgfs_get_le64(record + 16) != record_id) {
        mgfs_set_error("MGFS Record lookup validation failed");
        return false;
    }

    memcpy(out_record, record, MGFS_RECORD_BYTES);
    return true;
}

static bool mgfs_validate_extent(
    mgfs_fs_t *fs,
    const u8 *extent,
    u64 *expected_logical_block,
    u64 *extent_count,
    u64 record_id,
    u64 requested_logical_block,
    u8 requested_block[MGFS_BLOCK_BYTES],
    bool *found_requested_block)
{
    u64 logical_start = mgfs_get_le64(extent);
    u64 physical_start = mgfs_get_le64(extent + 8);
    u64 block_count = mgfs_get_le64(extent + 16);
    u64 flags = mgfs_get_le64(extent + 24);

    if (block_count == 0ULL || flags != MGFS_EXTENT_DIRECTORY_METADATA ||
        logical_start != *expected_logical_block ||
        block_count > MGFS_U64_MAX - logical_start ||
        physical_start < fs->layout.data_start ||
        physical_start - fs->layout.data_start >= fs->layout.data_blocks ||
        block_count > fs->layout.data_blocks - (physical_start - fs->layout.data_start)) {
        mgfs_set_error("invalid MGFS directory extent");
        return false;
    }

    if (requested_logical_block >= logical_start &&
        requested_logical_block - logical_start < block_count) {
        u64 physical_block = physical_start + (requested_logical_block - logical_start);
        if (!mgfs_read_block(fs->dev, physical_block, requested_block)) {
            return false;
        }
        *found_requested_block = true;
    }

    *expected_logical_block += block_count;
    (*extent_count)++;
    if (*extent_count > fs->layout.record_count) {
        mgfs_set_error("MGFS directory extent count is unreasonable");
        return false;
    }

    (void)record_id;
    return true;
}

static bool mgfs_read_directory_block(
    mgfs_fs_t *fs,
    const u8 record[MGFS_RECORD_BYTES],
    u64 logical_block,
    u8 output[MGFS_BLOCK_BYTES])
{
    u8 list_block[MGFS_BLOCK_BYTES];
    u64 expected_logical_block = 0;
    u64 extent_count = 0;
    u64 inline_extent_count = mgfs_get_le64(record + 48);
    u64 total_extent_count = mgfs_get_le64(record + 40);
    u64 list_block_number = mgfs_get_le64(record + 56);
    bool found_requested_block = false;

    for (u64 i = 0; i < inline_extent_count; i++) {
        if (!mgfs_validate_extent(fs,
                                  record + 64 + i * 32,
                                  &expected_logical_block,
                                  &extent_count,
                                  mgfs_get_le64(record + 16),
                                  logical_block,
                                  output,
                                  &found_requested_block)) {
            return false;
        }
    }

    while (list_block_number != 0ULL) {
        u64 next_list_block;
        u64 entry_count;

        if (extent_count >= total_extent_count ||
            !mgfs_read_block(fs->dev, list_block_number, list_block)) {
            mgfs_set_error("invalid MGFS extent-list chain");
            return false;
        }

        if (mgfs_get_le64(list_block) != MGFS_EXTENT_LIST_MAGIC ||
            mgfs_get_le64(list_block + 8) != mgfs_get_le64(record + 16)) {
            mgfs_set_error("invalid MGFS directory extent-list owner");
            return false;
        }

        entry_count = mgfs_get_le64(list_block + 24);
        next_list_block = mgfs_get_le64(list_block + 16);
        if (entry_count == 0ULL || entry_count > MGFS_EXTENTS_PER_LIST_BLOCK) {
            mgfs_set_error("invalid MGFS extent-list entry count");
            return false;
        }

        for (u32 i = 40; i < 64; i++) {
            if (list_block[i] != 0U) {
                mgfs_set_error("nonzero MGFS extent-list reserved bytes");
                return false;
            }
        }

        if (!mgfs_checksum_block(list_block, 32, MGFS_BLOCK_BYTES)) {
            mgfs_set_error("MGFS extent-list checksum mismatch");
            return false;
        }

        if (next_list_block == list_block_number ||
            list_block_number < fs->layout.data_start ||
            list_block_number - fs->layout.data_start >= fs->layout.data_blocks) {
            mgfs_set_error("invalid MGFS extent-list block address");
            return false;
        }

        for (u64 i = 0; i < entry_count; i++) {
            if (!mgfs_validate_extent(fs,
                                      list_block + MGFS_EXTENT_LIST_HEADER_BYTES + i * 32,
                                      &expected_logical_block,
                                      &extent_count,
                                      mgfs_get_le64(record + 16),
                                      logical_block,
                                      output,
                                      &found_requested_block)) {
                return false;
            }
        }

        list_block_number = next_list_block;
    }

    if (extent_count != total_extent_count || !found_requested_block) {
        mgfs_set_error("MGFS directory extent coverage is incomplete");
        return false;
    }

    return true;
}

static bool mgfs_read_directory_bytes(
    mgfs_fs_t *fs,
    const u8 record[MGFS_RECORD_BYTES],
    u64 offset,
    u64 size,
    u8 *output)
{
    u8 block[MGFS_BLOCK_BYTES];
    u64 logical_size = mgfs_get_le64(record + 32);
    u64 remaining = size;

    if (offset > logical_size || size > logical_size - offset) {
        mgfs_set_error("MGFS directory read exceeds its logical size");
        return false;
    }

    while (remaining > 0ULL) {
        u64 logical_block = offset / MGFS_BLOCK_BYTES;
        u64 within_block = offset % MGFS_BLOCK_BYTES;
        u64 chunk = MGFS_BLOCK_BYTES - within_block;
        if (chunk > remaining) {
            chunk = remaining;
        }

        if (!mgfs_read_directory_block(fs, record, logical_block, block)) {
            return false;
        }
        memcpy(output, block + within_block, (usize)chunk);
        output += chunk;
        offset += chunk;
        remaining -= chunk;
    }

    return true;
}

static bool mgfs_validate_file_extent(
    mgfs_fs_t *fs,
    const u8 *extent,
    u64 *expected_logical_block,
    u64 *previous_physical_end,
    u64 *extent_count,
    u64 requested_logical_block,
    u8 requested_block[MGFS_BLOCK_BYTES],
    bool *found_requested_block)
{
    u64 logical_start = mgfs_get_le64(extent);
    u64 physical_start = mgfs_get_le64(extent + 8);
    u64 block_count = mgfs_get_le64(extent + 16);
    u64 flags = mgfs_get_le64(extent + 24);

    if (block_count == 0ULL || flags != MGFS_EXTENT_DATA ||
        logical_start != *expected_logical_block ||
        physical_start < *previous_physical_end ||
        block_count > MGFS_U64_MAX - logical_start ||
        physical_start < fs->layout.data_start ||
        physical_start - fs->layout.data_start >= fs->layout.data_blocks ||
        block_count > fs->layout.data_blocks -
            (physical_start - fs->layout.data_start)) {
        mgfs_set_error("invalid MGFS regular-file extent");
        return false;
    }

    if (requested_logical_block >= logical_start &&
        requested_logical_block - logical_start < block_count) {
        u64 physical_block = physical_start +
            (requested_logical_block - logical_start);
        if (!mgfs_read_block(fs->dev, physical_block, requested_block)) {
#ifdef NETWORK_BOOT_DIAG
            kprint("[MGFS-READ] file-block failed logical=%llu physical=%llu lba=%llu error=%s\n",
                   requested_logical_block, physical_block,
                   physical_block * 8ULL, mgfs_last_error());
#endif
            return false;
        }
        *found_requested_block = true;
    }

    *expected_logical_block += block_count;
    *previous_physical_end = physical_start + block_count;
    (*extent_count)++;
    if (*extent_count > fs->layout.record_count) {
        mgfs_set_error("MGFS regular-file extent count is unreasonable");
        return false;
    }
    return true;
}

static bool mgfs_read_file_block(
    mgfs_fs_t *fs,
    const u8 record[MGFS_RECORD_BYTES],
    u64 logical_block,
    u8 output[MGFS_BLOCK_BYTES])
{
    u8 list_block[MGFS_BLOCK_BYTES];
    u64 expected_logical_block = 0;
    u64 previous_physical_end = 0;
    u64 extent_count = 0;
    u64 inline_extent_count = mgfs_get_le64(record + 48);
    u64 total_extent_count = mgfs_get_le64(record + 40);
    u64 list_block_number = mgfs_get_le64(record + 56);
    u64 logical_size = mgfs_get_le64(record + 32);
    bool found_requested_block = false;

    for (u64 i = 0; i < inline_extent_count; i++) {
        if (!mgfs_validate_file_extent(fs,
                                       record + 64 + i * 32,
                                       &expected_logical_block,
                                       &previous_physical_end,
                                       &extent_count,
                                       logical_block,
                                       output,
                                       &found_requested_block)) {
            return false;
        }
    }

    while (list_block_number != 0ULL) {
        u64 next_list_block;
        u64 entry_count;

        if (extent_count >= total_extent_count ||
            !mgfs_read_block(fs->dev, list_block_number, list_block)) {
            mgfs_set_error("invalid MGFS regular-file extent-list chain");
            return false;
        }
        if (mgfs_get_le64(list_block) != MGFS_EXTENT_LIST_MAGIC ||
            mgfs_get_le64(list_block + 8) != mgfs_get_le64(record + 16)) {
            mgfs_set_error("invalid MGFS regular-file extent-list owner");
            return false;
        }

        entry_count = mgfs_get_le64(list_block + 24);
        next_list_block = mgfs_get_le64(list_block + 16);
        if (entry_count == 0ULL || entry_count > MGFS_EXTENTS_PER_LIST_BLOCK) {
            mgfs_set_error("invalid MGFS regular-file extent-list entry count");
            return false;
        }
        for (u32 i = 40; i < 64; i++) {
            if (list_block[i] != 0U) {
                mgfs_set_error("nonzero MGFS extent-list reserved bytes");
                return false;
            }
        }
        if (!mgfs_checksum_block(list_block, 32, MGFS_BLOCK_BYTES)) {
            mgfs_set_error("MGFS regular-file extent-list checksum mismatch");
            return false;
        }
        if (next_list_block == list_block_number ||
            list_block_number < fs->layout.data_start ||
            list_block_number - fs->layout.data_start >= fs->layout.data_blocks) {
            mgfs_set_error("invalid MGFS regular-file extent-list block address");
            return false;
        }

        for (u64 i = 0; i < entry_count; i++) {
            if (!mgfs_validate_file_extent(fs,
                                           list_block + MGFS_EXTENT_LIST_HEADER_BYTES + i * 32,
                                           &expected_logical_block,
                                           &previous_physical_end,
                                           &extent_count,
                                           logical_block,
                                           output,
                                           &found_requested_block)) {
                return false;
            }
        }
        list_block_number = next_list_block;
    }

    if (extent_count != total_extent_count || !found_requested_block ||
        expected_logical_block < logical_size / MGFS_BLOCK_BYTES +
            (logical_size % MGFS_BLOCK_BYTES != 0ULL)) {
        mgfs_set_error("MGFS regular-file extent coverage is incomplete");
        return false;
    }
    return true;
}

static bool mgfs_validate_regular_file_record(const u8 record[MGFS_RECORD_BYTES])
{
    u64 flags = mgfs_get_le64(record + 8);
    u64 size = mgfs_get_le64(record + 32);
    u64 extent_count = mgfs_get_le64(record + 40);
    u64 inline_extent_count = mgfs_get_le64(record + 48);
    u64 extent_list_head = mgfs_get_le64(record + 56);

    if (mgfs_get_le64(record) != MGFS_RECORD_FILE ||
        !mgfs_validate_record(NULL, record)) {
        mgfs_set_error("MGFS Record is not a valid regular file");
        return false;
    }
    if ((flags & MGFS_RECORD_INLINE_DATA) != 0ULL) {
        if (size > MGFS_INLINE_DATA_BYTES || extent_count != 0ULL ||
            inline_extent_count != 0ULL || extent_list_head != 0ULL) {
            mgfs_set_error("invalid MGFS inline-data state");
            return false;
        }
        for (u64 i = size; i < MGFS_INLINE_DATA_BYTES; i++) {
            if (record[128 + i] != 0U) {
                mgfs_set_error("nonzero MGFS inline-data tail");
                return false;
            }
        }
    } else {
        if (inline_extent_count > 2ULL || extent_count < inline_extent_count ||
            (extent_count <= 2ULL && extent_list_head != 0ULL)) {
            mgfs_set_error("invalid MGFS regular-file extent state");
            return false;
        }
        for (u64 i = 0; i < MGFS_INLINE_DATA_BYTES; i++) {
            if (record[128 + i] != 0U) {
                mgfs_set_error("nonzero MGFS regular-file inline-data area");
                return false;
            }
        }
        if (size != 0ULL && extent_count == 0ULL) {
            mgfs_set_error("MGFS regular file has unmapped data");
            return false;
        }
    }
    return true;
}

typedef struct {
    u64 logical_start;
    u64 physical_start;
    u64 block_count;
    u64 flags;
} mgfs_extent_desc_t;

static bool mgfs_collect_file_extents(
    mgfs_fs_t *fs,
    const u8 record[MGFS_RECORD_BYTES],
    mgfs_extent_desc_t *extents,
    u64 capacity,
    u64 *out_count,
    u64 expected_type)
{
    u64 expected = 0;
    u64 count = 0;
    u64 inline_count = mgfs_get_le64(record + 48);
    u64 total = mgfs_get_le64(record + 40);
    u64 list = mgfs_get_le64(record + 56);

    for (u64 i = 0; i < inline_count; i++) {
        const u8 *e = record + 64 + i * 32;
        u64 blocks = mgfs_get_le64(e + 16);
        if (count >= capacity || mgfs_get_le64(e) != expected || blocks == 0 ||
            mgfs_get_le64(e + 24) != expected_type) {
            mgfs_set_error("invalid MGFS regular-file extents");
            return false;
        }
        extents[count++] = (mgfs_extent_desc_t){
            mgfs_get_le64(e), mgfs_get_le64(e + 8), blocks, mgfs_get_le64(e + 24)};
        expected += blocks;
    }
    while (list != 0ULL) {
        u8 block[MGFS_BLOCK_BYTES];
        u64 entries;
        if (count >= total || !mgfs_read_block(fs->dev, list, block) ||
            mgfs_get_le64(block) != MGFS_EXTENT_LIST_MAGIC ||
            mgfs_get_le64(block + 8) != mgfs_get_le64(record + 16)) {
            mgfs_set_error("invalid MGFS regular-file extent-list chain");
            return false;
        }
        entries = mgfs_get_le64(block + 24);
        if (entries == 0 || entries > MGFS_EXTENTS_PER_LIST_BLOCK) {
            mgfs_set_error("invalid MGFS regular-file extent-list entry count");
            return false;
        }
        if (!mgfs_checksum_block(block, 32, MGFS_BLOCK_BYTES)) {
            mgfs_set_error("MGFS regular-file extent-list checksum mismatch");
            return false;
        }
        for (u64 i = 0; i < entries; i++) {
            const u8 *e = block + MGFS_EXTENT_LIST_HEADER_BYTES + i * 32;
            u64 blocks = mgfs_get_le64(e + 16);
            if (count >= capacity || mgfs_get_le64(e) != expected || blocks == 0 ||
                mgfs_get_le64(e + 24) != expected_type) {
                mgfs_set_error("invalid MGFS regular-file extents");
                return false;
            }
            extents[count++] = (mgfs_extent_desc_t){
                mgfs_get_le64(e), mgfs_get_le64(e + 8), blocks, mgfs_get_le64(e + 24)};
            expected += blocks;
        }
        list = mgfs_get_le64(block + 16);
    }
    if (count != total) {
        mgfs_set_error("MGFS regular-file extent count mismatch");
        return false;
    }
    *out_count = count;
    return true;
}

static bool mgfs_collect_extent_list_blocks(
    mgfs_fs_t *fs,
    const u8 record[MGFS_RECORD_BYTES],
    u64 *blocks,
    u64 capacity,
    u64 *out_count)
{
    u64 list = mgfs_get_le64(record + 56);
    u64 count = 0;
    while (list != 0) {
        u8 block[MGFS_BLOCK_BYTES];
        if (count >= capacity || !mgfs_read_block(fs->dev, list, block) ||
            mgfs_get_le64(block) != MGFS_EXTENT_LIST_MAGIC ||
            mgfs_get_le64(block + 8) != mgfs_get_le64(record + 16)) {
            mgfs_set_error("invalid MGFS extent-list chain");
            return false;
        }
        if (!mgfs_checksum_block(block, 32, MGFS_BLOCK_BYTES)) {
            mgfs_set_error("MGFS extent-list checksum mismatch");
            return false;
        }
        blocks[count++] = list;
        list = mgfs_get_le64(block + 16);
    }
    *out_count = count;
    return true;
}

static bool mgfs_extent_contains_block(
    const mgfs_extent_desc_t *extents, u64 extent_count, u64 physical)
{
    for (u64 i = 0; i < extent_count; i++) {
        if (physical >= extents[i].physical_start &&
            physical - extents[i].physical_start < extents[i].block_count) {
            return true;
        }
    }
    return false;
}

static bool mgfs_reclaim_obsolete_blocks(
    mgfs_fs_t *fs,
    const mgfs_extent_desc_t *old_extents,
    u64 old_extent_count,
    const u64 *old_list_blocks,
    u64 old_list_count,
    const mgfs_extent_desc_t *new_extents,
    u64 new_extent_count,
    u64 new_list_head)
{
    for (u64 i = 0; i < old_extent_count; i++) {
        for (u64 block = 0; block < old_extents[i].block_count; block++) {
            u64 physical = old_extents[i].physical_start + block;
            if (!mgfs_extent_contains_block(new_extents, new_extent_count, physical) &&
                !mgfs_free_data_block(fs, physical)) {
                return false;
            }
        }
    }
    for (u64 i = 0; i < old_list_count; i++) {
        if (old_list_blocks[i] != new_list_head &&
            !mgfs_free_data_block(fs, old_list_blocks[i])) {
            return false;
        }
    }
    return true;
}

static bool mgfs_write_file_data(
    mgfs_fs_t *fs,
    const mgfs_extent_desc_t *extents,
    u64 extent_count,
    u64 old_size,
    u64 offset,
    const u8 *input,
    u64 input_size,
    u64 final_size)
{
    u64 remaining = input_size;
    u64 source_offset = 0;
    u64 position = offset;
    while (remaining > 0) {
        u64 logical = position / MGFS_BLOCK_BYTES;
        u64 within = position % MGFS_BLOCK_BYTES;
        u64 physical = 0;
        u8 block[MGFS_BLOCK_BYTES];
        bool found = false;
        for (u64 i = 0; i < extent_count && !found; i++) {
            if (logical >= extents[i].logical_start &&
                logical - extents[i].logical_start < extents[i].block_count) {
                physical = extents[i].physical_start + logical - extents[i].logical_start;
                found = true;
            }
        }
        if (!found || !mgfs_read_block(fs->dev, physical, block)) {
            mgfs_set_error("MGFS write target block is not mapped");
            return false;
        }
        u64 chunk = MGFS_BLOCK_BYTES - within;
        if (chunk > remaining) chunk = remaining;
        memcpy(block + within, input + source_offset, (usize)chunk);
        if (!mgfs_write_block(fs->dev, physical, block)) return false;
        position += chunk;
        source_offset += chunk;
        remaining -= chunk;
    }
    (void)old_size;
    (void)final_size;
    return true;
}

static bool mgfs_write_extent_list(
    mgfs_fs_t *fs,
    u64 record_id,
    u64 list_block_number,
    const mgfs_extent_desc_t *extents,
    u64 extent_count,
    u64 extent_type)
{
    u8 block[MGFS_BLOCK_BYTES];
    u64 list_count = extent_count > 2 ? extent_count - 2 : 0;
    if (list_count == 0) return true;
    if (list_count > MGFS_EXTENTS_PER_LIST_BLOCK) {
        mgfs_set_error("MGFS extent-list capacity exceeded");
        return false;
    }
    memset(block, 0, sizeof(block));
    mgfs_store_le64(block, MGFS_EXTENT_LIST_MAGIC);
    mgfs_store_le64(block + 8, record_id);
    mgfs_store_le64(block + 24, list_count);
    for (u64 i = 0; i < list_count; i++) {
        mgfs_store_extent(block, MGFS_EXTENT_LIST_HEADER_BYTES + i * 32,
                          extents[i + 2].logical_start,
                          extents[i + 2].physical_start,
                          extents[i + 2].block_count,
                          extent_type);
    }
    mgfs_recompute_checksum(block, 32, MGFS_BLOCK_BYTES);
    return mgfs_write_block(fs->dev, list_block_number, block);
}

static u64 mgfs_write(vfs_node_t *node, u64 offset, u64 size, const void *buffer)
{
    mgfs_fs_t *fs;
    u8 old_record[MGFS_RECORD_BYTES];
    u8 new_record[MGFS_RECORD_BYTES];
    u64 old_size;
    u64 final_size;
    u64 slot;
    u64 extent_capacity;
    u64 extent_count = 0;
    u64 old_extent_count = 0;
    u64 old_list_count = 0;
    u64 new_list_head = 0;
    mgfs_extent_desc_t *extents;
    mgfs_extent_desc_t *old_extents;
    u64 *old_list_blocks;
    const u8 *input = (const u8 *)buffer;

    if (!node || !node->super || !node->super->private_data ||
        node->type != VFS_TYPE_FILE || (size != 0 && !buffer)) {
        mgfs_set_error("invalid MGFS write request");
        return 0;
    }
    fs = (mgfs_fs_t *)node->super->private_data;
    if (!mgfs_read_record(fs, node->inode, old_record) ||
        !mgfs_validate_regular_file_record(old_record)) return 0;
    old_size = mgfs_get_le64(old_record + 32);
    if (offset > old_size || size > MGFS_U64_MAX - offset) {
        mgfs_set_error("MGFS writes may not create sparse files");
        return 0;
    }
    final_size = offset + size;
    if (size == 0) return 0;
    extent_capacity = fs->layout.record_count;
    old_extents = (mgfs_extent_desc_t *)kmalloc((usize)(extent_capacity * sizeof(*old_extents)));
    old_list_blocks = (u64 *)kmalloc((usize)(extent_capacity * sizeof(u64)));
    if (!old_extents || !old_list_blocks) {
        kfree(old_extents); kfree(old_list_blocks);
        mgfs_set_error("MGFS shrink reclamation state unavailable");
        return 0;
    }
    if (!mgfs_collect_file_extents(fs, old_record, old_extents, extent_capacity,
                                   &old_extent_count, MGFS_EXTENT_DATA) ||
        !mgfs_collect_extent_list_blocks(fs, old_record, old_list_blocks,
                                         extent_capacity, &old_list_count)) {
        kfree(old_extents); kfree(old_list_blocks);
        return 0;
    }
    if (!mgfs_set_state(fs, MGFS_STATE_NEEDS_FSCK)) return 0;

    if (final_size <= MGFS_INLINE_DATA_BYTES) {
        memset(new_record, 0, MGFS_RECORD_BYTES);
        mgfs_store_le64(new_record, MGFS_RECORD_FILE);
        mgfs_store_le64(new_record + 8,
                        mgfs_security_flags(mgfs_record_owner(old_record),
                                             mgfs_record_permissions(old_record), true,
                                             VFS_CHILD_MUTATION_OPEN));
        mgfs_store_le64(new_record + 16, mgfs_get_le64(old_record + 16));
        mgfs_store_le64(new_record + 24, mgfs_get_le64(old_record + 24) + 1);
        if (old_size > 0) {
            u64 preserved = old_size < MGFS_INLINE_DATA_BYTES
                ? old_size : MGFS_INLINE_DATA_BYTES;
            if (old_size <= MGFS_INLINE_DATA_BYTES) {
                memcpy(new_record + 128, old_record + 128, (usize)preserved);
            } else if (preserved > 0 && mgfs_read(node, 0, preserved,
                                                  new_record + 128) != preserved) {
                mgfs_set_error("unable to preserve MGFS file data during shrink");
                return 0;
            }
        }
        memcpy(new_record + 128 + offset, input, (usize)size);
        memset(new_record + 128 + final_size, 0,
               (usize)(MGFS_INLINE_DATA_BYTES - final_size));
        mgfs_store_le64(new_record + 32, final_size);
        mgfs_recompute_checksum(new_record, MGFS_RECORD_CHECKSUM_OFFSET,
                                MGFS_RECORD_BYTES);
        if (!mgfs_find_record_slot(fs, node->inode, &slot) ||
            !mgfs_write_record_slot(fs, slot, new_record)) return 0;
        if (!mgfs_reclaim_obsolete_blocks(fs, old_extents, old_extent_count,
                                          old_list_blocks, old_list_count,
                                          NULL, 0, 0) ||
            !mgfs_set_state(fs, MGFS_STATE_CLEAN)) return 0;
        kfree(old_extents); kfree(old_list_blocks);
        node->size = final_size;
        return size;
    }

    extents = (mgfs_extent_desc_t *)kmalloc((usize)(extent_capacity * sizeof(*extents)));
    if (!extents) { kfree(old_extents); kfree(old_list_blocks); mgfs_set_error("MGFS extent allocation state unavailable"); return 0; }
    if (!mgfs_collect_file_extents(fs, old_record, extents, extent_capacity,
                                   &extent_count, MGFS_EXTENT_DATA)) {
        kfree(extents); return 0;
    }
    u64 required_blocks = final_size / MGFS_BLOCK_BYTES +
        (final_size % MGFS_BLOCK_BYTES != 0);
    u64 retained_blocks = required_blocks;
    u64 retained_extent_count = 0;
    for (u64 i = 0; i < extent_count && retained_blocks > 0; i++) {
        u64 keep = extents[i].block_count < retained_blocks
            ? extents[i].block_count : retained_blocks;
        extents[retained_extent_count] = extents[i];
        extents[retained_extent_count].block_count = keep;
        retained_extent_count++;
        retained_blocks -= keep;
    }
    extent_count = retained_extent_count;
    u64 covered_blocks = 0;
    for (u64 i = 0; i < extent_count; i++) covered_blocks += extents[i].block_count;
    while (covered_blocks < required_blocks) {
        u64 physical;
        if (extent_count >= extent_capacity ||
            !mgfs_allocate_data_block(fs, &physical)) { kfree(extents); return 0; }
        if (extent_count > 0 &&
            extents[extent_count - 1].physical_start + extents[extent_count - 1].block_count == physical) {
            extents[extent_count - 1].block_count++;
        } else {
            extents[extent_count++] = (mgfs_extent_desc_t){
                covered_blocks, physical, 1, MGFS_EXTENT_DATA};
        }
        covered_blocks++;
    }
    for (u64 logical = 0; logical < required_blocks; logical++) {
        u64 physical = 0;
        bool found = false;
        for (u64 i = 0; i < extent_count && !found; i++) {
            if (logical >= extents[i].logical_start &&
                logical - extents[i].logical_start < extents[i].block_count) {
                physical = extents[i].physical_start + logical - extents[i].logical_start;
                found = true;
            }
        }
        if (!found) { kfree(extents); mgfs_set_error("MGFS write extent mapping failed"); return 0; }
        u8 block[MGFS_BLOCK_BYTES];
        memset(block, 0, sizeof(block));
        if (logical < old_size / MGFS_BLOCK_BYTES + (old_size % MGFS_BLOCK_BYTES != 0) &&
            !mgfs_read_block(fs->dev, physical, block)) { kfree(extents); return 0; }
        u64 block_start = logical * MGFS_BLOCK_BYTES;
        u64 write_start = offset > block_start ? offset : block_start;
        u64 write_end = offset + size < block_start + MGFS_BLOCK_BYTES
            ? offset + size : block_start + MGFS_BLOCK_BYTES;
        if (write_end > write_start)
            memcpy(block + write_start - block_start,
                   input + write_start - offset, (usize)(write_end - write_start));
        if (!mgfs_write_block(fs->dev, physical, block)) { kfree(extents); return 0; }
    }
    memcpy(new_record, old_record, MGFS_RECORD_BYTES);
    memset(new_record + 64, 0, 64);
    memset(new_record + 128, 0, MGFS_INLINE_DATA_BYTES);
    mgfs_store_le64(new_record + 8,
                    mgfs_security_flags(mgfs_record_owner(old_record),
                                         mgfs_record_permissions(old_record), false,
                                         VFS_CHILD_MUTATION_OPEN));
    mgfs_store_le64(new_record + 32, final_size);
    mgfs_store_le64(new_record + 40, extent_count);
    mgfs_store_le64(new_record + 48, extent_count < 2 ? extent_count : 2);
    mgfs_store_le64(new_record + 56, 0);
    for (u64 i = 0; i < extent_count && i < 2; i++)
        mgfs_store_extent(new_record, 64 + i * 32, extents[i].logical_start,
                          extents[i].physical_start, extents[i].block_count,
                          MGFS_EXTENT_DATA);
    if (extent_count > 2) {
        u64 list_block = mgfs_get_le64(old_record + 56);
        if (list_block == 0 && !mgfs_allocate_data_block(fs, &list_block)) { kfree(extents); return 0; }
        if (!mgfs_write_extent_list(fs, node->inode, list_block, extents,
                                    extent_count, MGFS_EXTENT_DATA)) {
            kfree(extents);
            return 0;
        }
        mgfs_store_le64(new_record + 56, list_block);
        new_list_head = list_block;
    }
    mgfs_store_le64(new_record + 24, mgfs_get_le64(old_record + 24) + 1);
    mgfs_recompute_checksum(new_record, MGFS_RECORD_CHECKSUM_OFFSET, MGFS_RECORD_BYTES);
    if (!mgfs_find_record_slot(fs, node->inode, &slot) ||
        !mgfs_write_record_slot(fs, slot, new_record)) { kfree(extents); return 0; }
    if (!mgfs_reclaim_obsolete_blocks(fs, old_extents, old_extent_count,
                                      old_list_blocks, old_list_count,
                                      extents, extent_count, new_list_head) ||
        !mgfs_set_state(fs, MGFS_STATE_CLEAN)) {
        kfree(extents); kfree(old_extents); kfree(old_list_blocks); return 0;
    }
    kfree(extents);
    kfree(old_extents);
    kfree(old_list_blocks);
    node->size = final_size;
    return size;
}

/* The public filesystem API currently needs explicit replacement semantics
 * for copy.  Keep truncation atomic and limited to an empty regular file. */
static int mgfs_truncate(vfs_node_t *node)
{
    mgfs_fs_t *fs;
    u8 old_record[MGFS_RECORD_BYTES];
    u8 new_record[MGFS_RECORD_BYTES];
    u64 slot;
    u64 capacity;
    u64 extent_count = 0;
    u64 list_count = 0;
    mgfs_extent_desc_t *extents;
    u64 *list_blocks;

    if (!node || !node->super || !node->super->private_data ||
        node->type != VFS_TYPE_FILE) {
        return VFS_ERR_INVALID_PARAM;
    }
    fs = (mgfs_fs_t *)node->super->private_data;
    if (!mgfs_read_record(fs, node->inode, old_record) ||
        !mgfs_validate_regular_file_record(old_record)) {
        return VFS_ERR_IO;
    }
    capacity = fs->layout.record_count;
    extents = (mgfs_extent_desc_t *)kmalloc((usize)(capacity * sizeof(*extents)));
    list_blocks = (u64 *)kmalloc((usize)(capacity * sizeof(*list_blocks)));
    if (!extents || !list_blocks) {
        kfree(extents);
        kfree(list_blocks);
        return VFS_ERR_NO_MEM;
    }
    if (!mgfs_collect_file_extents(fs, old_record, extents, capacity,
                                   &extent_count, MGFS_EXTENT_DATA) ||
        !mgfs_collect_extent_list_blocks(fs, old_record, list_blocks, capacity,
                                         &list_count) ||
        !mgfs_find_record_slot(fs, node->inode, &slot) ||
        !mgfs_set_state(fs, MGFS_STATE_NEEDS_FSCK)) {
        kfree(extents);
        kfree(list_blocks);
        return VFS_ERR_IO;
    }
    memset(new_record, 0, sizeof(new_record));
    mgfs_store_le64(new_record, MGFS_RECORD_FILE);
    mgfs_store_le64(new_record + 8,
                    mgfs_security_flags(mgfs_record_owner(old_record),
                                         mgfs_record_permissions(old_record), true,
                                         VFS_CHILD_MUTATION_OPEN));
    mgfs_store_le64(new_record + 16, node->inode);
    mgfs_store_le64(new_record + 24, mgfs_get_le64(old_record + 24) + 1);
    mgfs_recompute_checksum(new_record, MGFS_RECORD_CHECKSUM_OFFSET,
                            MGFS_RECORD_BYTES);
    if (!mgfs_write_record_slot(fs, slot, new_record) ||
        !mgfs_reclaim_obsolete_blocks(fs, extents, extent_count, list_blocks,
                                      list_count, NULL, 0, 0) ||
        !mgfs_set_state(fs, MGFS_STATE_CLEAN)) {
        kfree(extents);
        kfree(list_blocks);
        return VFS_ERR_IO;
    }
    kfree(extents);
    kfree(list_blocks);
    node->size = 0;
    return VFS_OK;
}

static u64 mgfs_read(vfs_node_t *node, u64 offset, u64 size, void *buffer)
{
    mgfs_fs_t *fs;
    u8 record[MGFS_RECORD_BYTES];
    u64 logical_size;
    u64 remaining;

    if (!node || !node->super || !node->super->private_data ||
        node->type != VFS_TYPE_FILE || (size != 0ULL && !buffer)) {
        mgfs_set_error("invalid MGFS read request");
        return 0;
    }
    fs = (mgfs_fs_t *)node->super->private_data;
    if (!mgfs_read_record(fs, node->inode, record) ||
        !mgfs_validate_regular_file_record(record)) {
        return 0;
    }
    logical_size = mgfs_get_le64(record + 32);
    if (offset >= logical_size || size == 0ULL) {
        return 0;
    }
    if (size > logical_size - offset) {
        size = logical_size - offset;
    }

    if ((mgfs_get_le64(record + 8) & MGFS_RECORD_INLINE_DATA) != 0ULL) {
        memcpy(buffer, record + 128 + offset, (usize)size);
        return size;
    }

    remaining = size;
    while (remaining > 0ULL) {
        u8 block[MGFS_BLOCK_BYTES];
        u64 logical_block = offset / MGFS_BLOCK_BYTES;
        u64 within_block = offset % MGFS_BLOCK_BYTES;
        u64 chunk = MGFS_BLOCK_BYTES - within_block;
        if (chunk > remaining) {
            chunk = remaining;
        }
        if (!mgfs_read_file_block(fs, record, logical_block, block)) {
#ifdef NETWORK_BOOT_DIAG
            kprint("[MGFS-READ] file=%llu offset=%llu logical=%llu error=%s\n",
                   mgfs_get_le64(record + 16), offset, logical_block,
                   mgfs_last_error());
#endif
            return 0;
        }
        memcpy(buffer, block + within_block, (usize)chunk);
        buffer = (u8 *)buffer + chunk;
        offset += chunk;
        remaining -= chunk;
    }
    return size;
}

typedef struct {
    u64 target_record_id;
    u64 name_length;
    u64 flags;
    u64 total_bytes;
    char name[256];
} mgfs_directory_entry_t;

static bool mgfs_valid_utf8_name(const u8 *name, u64 length)
{
    u64 i = 0;

    if (length == 0ULL || length > 255ULL ||
        (length == 1ULL && name[0] == '.') ||
        (length == 2ULL && name[0] == '.' && name[1] == '.')) {
        return false;
    }

    while (i < length) {
        u8 first = name[i++];
        u32 continuation_count = 0;
        u8 second = 0;

        if (first == 0U || first == '/') {
            return false;
        }
        if (first < 0x80U) {
            continue;
        }
        if (first >= 0xC2U && first <= 0xDFU) {
            continuation_count = 1;
        } else if (first >= 0xE0U && first <= 0xEFU) {
            continuation_count = 2;
        } else if (first >= 0xF0U && first <= 0xF4U) {
            continuation_count = 3;
        } else {
            return false;
        }

        if (i + continuation_count > length) {
            return false;
        }
        second = name[i];
        for (u32 j = 0; j < continuation_count; j++) {
            u8 value = name[i + j];
            if (value < 0x80U || value > 0xBFU || value == 0U || value == '/') {
                return false;
            }
        }
        if ((first == 0xE0U && second < 0xA0U) ||
            (first == 0xEDU && second > 0x9FU) ||
            (first == 0xF0U && second < 0x90U) ||
            (first == 0xF4U && second > 0x8FU)) {
            return false;
        }
        i += continuation_count;
    }

    return true;
}

static bool mgfs_read_directory_entry(
    mgfs_fs_t *fs,
    const u8 record[MGFS_RECORD_BYTES],
    u64 offset,
    mgfs_directory_entry_t *entry)
{
    u8 header[32];
    u8 serialized[288];
    u64 aligned_length;
    u64 name_length;

    if (offset > mgfs_get_le64(record + 32) ||
        mgfs_get_le64(record + 32) - offset < 32ULL ||
        !mgfs_read_directory_bytes(fs, record, offset, 32ULL, header)) {
        mgfs_set_error("truncated MGFS directory entry header");
        return false;
    }

    name_length = mgfs_get_le64(header + 8);
    if (name_length == 0ULL || name_length > 255ULL ||
        name_length > MGFS_U64_MAX - 39ULL) {
        mgfs_set_error("invalid MGFS directory entry name length");
        return false;
    }
    aligned_length = (32ULL + name_length + 7ULL) & ~7ULL;
    if (aligned_length > sizeof(serialized) ||
        aligned_length > mgfs_get_le64(record + 32) - offset ||
        !mgfs_read_directory_bytes(fs, record, offset, aligned_length, serialized)) {
        mgfs_set_error("truncated MGFS directory entry");
        return false;
    }

    if (!mgfs_checksum_block(serialized, 24, (usize)aligned_length)) {
        mgfs_set_error("MGFS directory entry checksum mismatch");
        return false;
    }

    for (u64 i = 32ULL + name_length; i < aligned_length; i++) {
        if (serialized[i] != 0U) {
            mgfs_set_error("nonzero MGFS directory entry padding");
            return false;
        }
    }

    if (mgfs_get_le64(serialized) == 0ULL ||
        (mgfs_get_le64(serialized + 16) != MGFS_DIRENT_IN_USE &&
         mgfs_get_le64(serialized + 16) != MGFS_DIRENT_TOMBSTONE) ||
        !mgfs_valid_utf8_name(serialized + 32, name_length)) {
        mgfs_set_error("invalid MGFS directory entry fields or name");
        return false;
    }

    entry->target_record_id = mgfs_get_le64(serialized);
    entry->name_length = name_length;
    entry->flags = mgfs_get_le64(serialized + 16);
    entry->total_bytes = aligned_length;
    memcpy(entry->name, serialized + 32, (usize)name_length);
    entry->name[name_length] = '\0';
    return true;
}

static bool mgfs_find_directory_block(
    mgfs_fs_t *fs,
    const u8 record[MGFS_RECORD_BYTES],
    u64 logical_block,
    u64 *out_physical_block)
{
    u64 expected = 0;
    u64 total = mgfs_get_le64(record + 40);
    u64 count = mgfs_get_le64(record + 48);
    u64 list = mgfs_get_le64(record + 56);
    for (u64 i = 0; i < count; i++) {
        u64 logical = mgfs_get_le64(record + 64 + i * 32);
        u64 physical = mgfs_get_le64(record + 72 + i * 32);
        u64 blocks = mgfs_get_le64(record + 80 + i * 32);
        if (logical != expected || blocks == 0 ||
            physical < fs->layout.data_start ||
            physical - fs->layout.data_start >= fs->layout.data_blocks ||
            blocks > fs->layout.data_blocks - (physical - fs->layout.data_start)) {
            mgfs_set_error("invalid MGFS directory extent");
            return false;
        }
        if (logical_block >= logical && logical_block - logical < blocks) {
            *out_physical_block = physical + logical_block - logical;
            return true;
        }
        expected += blocks;
    }
    while (list != 0ULL) {
        u8 block[MGFS_BLOCK_BYTES];
        u64 entries;
        if (count >= total || !mgfs_read_block(fs->dev, list, block) ||
            mgfs_get_le64(block) != MGFS_EXTENT_LIST_MAGIC ||
            mgfs_get_le64(block + 8) != mgfs_get_le64(record + 16)) {
            mgfs_set_error("invalid MGFS directory extent-list chain");
            return false;
        }
        entries = mgfs_get_le64(block + 24);
        if (entries == 0 || entries > MGFS_EXTENTS_PER_LIST_BLOCK) {
            mgfs_set_error("invalid MGFS extent-list entry count");
            return false;
        }
        for (u64 i = 0; i < entries; i++) {
            const u8 *extent = block + MGFS_EXTENT_LIST_HEADER_BYTES + i * 32;
            u64 logical = mgfs_get_le64(extent);
            u64 physical = mgfs_get_le64(extent + 8);
            u64 blocks = mgfs_get_le64(extent + 16);
            if (logical != expected || blocks == 0 ||
                mgfs_get_le64(extent + 24) != MGFS_EXTENT_DIRECTORY_METADATA ||
                physical < fs->layout.data_start ||
                physical - fs->layout.data_start >= fs->layout.data_blocks ||
                blocks > fs->layout.data_blocks - (physical - fs->layout.data_start)) {
                mgfs_set_error("invalid MGFS directory extent");
                return false;
            }
            if (logical_block >= logical && logical_block - logical < blocks) {
                *out_physical_block = physical + logical_block - logical;
                return true;
            }
            expected += blocks;
            count++;
        }
        list = mgfs_get_le64(block + 16);
    }
    mgfs_set_error("MGFS directory block is not mapped");
    return false;
}

static void mgfs_store_extent(u8 *record, u64 offset, u64 logical,
                              u64 physical, u64 blocks, u64 flags)
{
    mgfs_store_le64(record + offset, logical);
    mgfs_store_le64(record + offset + 8, physical);
    mgfs_store_le64(record + offset + 16, blocks);
    mgfs_store_le64(record + offset + 24, flags);
}

static bool mgfs_append_directory_entry(
    mgfs_fs_t *fs,
    u64 parent_id,
    const u8 *entry,
    u64 entry_bytes,
    u8 out_parent[MGFS_RECORD_BYTES])
{
    u8 parent[MGFS_RECORD_BYTES];
    u64 logical_size;
    u64 new_size;
    u64 old_block_count;
    u64 required_block_count;
    u64 extent_capacity;
    u64 extent_count = 0;
    u64 list_block;
    u64 physical_block;
    u64 slot;
    mgfs_extent_desc_t *extents;
    u8 block[MGFS_BLOCK_BYTES];

    if (!fs || !entry || !out_parent || entry_bytes == 0ULL ||
        entry_bytes > sizeof(block) ||
        !mgfs_read_record(fs, parent_id, parent) ||
        mgfs_get_le64(parent) != MGFS_RECORD_DIRECTORY) {
        mgfs_set_error("MGFS parent is not a directory");
        return false;
    }
    logical_size = mgfs_get_le64(parent + 32);
    if (logical_size > MGFS_U64_MAX - entry_bytes) {
        mgfs_set_error("MGFS directory size overflow");
        return false;
    }
    new_size = logical_size + entry_bytes;
    old_block_count = mgfs_ceil_div(logical_size, MGFS_BLOCK_BYTES);
    required_block_count = mgfs_ceil_div(new_size, MGFS_BLOCK_BYTES);
    extent_capacity = fs->layout.record_count;
    if (extent_capacity > (u64)(usize)-1 / sizeof(*extents)) {
        mgfs_set_error("MGFS directory extent allocation overflow");
        return false;
    }
    extents = (mgfs_extent_desc_t *)kmalloc(
        (usize)(extent_capacity * sizeof(*extents)));
    if (!extents || !mgfs_collect_file_extents(
            fs, parent, extents, extent_capacity, &extent_count,
            MGFS_EXTENT_DIRECTORY_METADATA)) {
        kfree(extents);
        return false;
    }

    if (required_block_count > old_block_count) {
        if (!mgfs_allocate_data_block(fs, &physical_block)) {
            kfree(extents);
            return false;
        }
        if (extent_count > 0ULL &&
            extents[extent_count - 1].physical_start <= MGFS_U64_MAX -
                extents[extent_count - 1].block_count &&
            extents[extent_count - 1].physical_start +
                extents[extent_count - 1].block_count == physical_block) {
            extents[extent_count - 1].block_count++;
        } else {
            if (extent_count >= 2ULL + MGFS_EXTENTS_PER_LIST_BLOCK) {
                (void)mgfs_free_data_block(fs, physical_block);
                mgfs_set_error("MGFS directory extent capacity exceeded");
                kfree(extents);
                return false;
            }
            extents[extent_count++] = (mgfs_extent_desc_t){
                old_block_count, physical_block, 1,
                MGFS_EXTENT_DIRECTORY_METADATA};
        }

        if (logical_size % MGFS_BLOCK_BYTES != 0ULL) {
            u64 previous_physical;
            u64 first_bytes = MGFS_BLOCK_BYTES -
                (logical_size % MGFS_BLOCK_BYTES);
            if (!mgfs_find_directory_block(
                    fs, parent, logical_size / MGFS_BLOCK_BYTES,
                    &previous_physical) ||
                !mgfs_read_block(fs->dev, previous_physical, block)) {
                kfree(extents);
                return false;
            }
            memcpy(block + logical_size % MGFS_BLOCK_BYTES, entry,
                   (usize)first_bytes);
            if (!mgfs_write_block(fs->dev, previous_physical, block)) {
                kfree(extents);
                return false;
            }
            memset(block, 0, sizeof(block));
            memcpy(block, entry + first_bytes,
                   (usize)(entry_bytes - first_bytes));
        } else {
            memset(block, 0, sizeof(block));
            memcpy(block, entry, (usize)entry_bytes);
        }
        if (!mgfs_write_block(fs->dev, physical_block, block)) {
            kfree(extents);
            return false;
        }
    } else {
        if (!mgfs_find_directory_block(fs, parent,
                                       logical_size / MGFS_BLOCK_BYTES,
                                       &physical_block) ||
            !mgfs_read_block(fs->dev, physical_block, block)) {
            kfree(extents);
            return false;
        }
        memcpy(block + logical_size % MGFS_BLOCK_BYTES, entry,
               (usize)entry_bytes);
        if (!mgfs_write_block(fs->dev, physical_block, block)) {
            kfree(extents);
            return false;
        }
    }

    mgfs_store_le64(parent + 32, new_size);
    mgfs_store_le64(parent + 24, mgfs_get_le64(parent + 24) + 1);
    mgfs_store_le64(parent + 40, extent_count);
    mgfs_store_le64(parent + 48, extent_count < 2ULL ? extent_count : 2ULL);
    memset(parent + 64, 0, 64);
    for (u64 i = 0; i < extent_count && i < 2ULL; i++) {
        mgfs_store_extent(parent, 64 + i * 32, extents[i].logical_start,
                          extents[i].physical_start, extents[i].block_count,
                          MGFS_EXTENT_DIRECTORY_METADATA);
    }
    list_block = mgfs_get_le64(parent + 56);
    if (extent_count > 2ULL) {
        if (list_block == 0ULL && !mgfs_allocate_data_block(fs, &list_block)) {
            kfree(extents);
            return false;
        }
        if (!mgfs_write_extent_list(fs, parent_id, list_block, extents,
                                    extent_count,
                                    MGFS_EXTENT_DIRECTORY_METADATA)) {
            kfree(extents);
            return false;
        }
        mgfs_store_le64(parent + 56, list_block);
    } else {
        mgfs_store_le64(parent + 56, 0ULL);
    }
    mgfs_recompute_checksum(parent, MGFS_RECORD_CHECKSUM_OFFSET, MGFS_RECORD_BYTES);
    if (!mgfs_find_record_slot(fs, parent_id, &slot) ||
        !mgfs_write_record_slot(fs, slot, parent)) {
        kfree(extents);
        return false;
    }
    memcpy(out_parent, parent, MGFS_RECORD_BYTES);
    kfree(extents);
    mgfs_dentry_cache_invalidate_parent(fs, parent_id);
    return true;
}

static void mgfs_refresh_directory_node(mgfs_fs_t *fs, vfs_node_t *node)
{
    u8 record[MGFS_RECORD_BYTES];
    if (node && mgfs_read_record(fs, (u64)(uintptr_t)node->fs_data, record) &&
        mgfs_get_le64(record) == MGFS_RECORD_DIRECTORY) {
        node->size = mgfs_get_le64(record + 32);
    }
}

static bool mgfs_touch_directory_record(mgfs_fs_t *fs, u64 record_id)
{
    u8 record[MGFS_RECORD_BYTES];
    u64 slot;
    if (!mgfs_read_record(fs, record_id, record) ||
        mgfs_get_le64(record) != MGFS_RECORD_DIRECTORY ||
        !mgfs_find_record_slot(fs, record_id, &slot)) {
        return false;
    }
    mgfs_store_le64(record + 24, mgfs_get_le64(record + 24) + 1ULL);
    mgfs_recompute_checksum(record, MGFS_RECORD_CHECKSUM_OFFSET, MGFS_RECORD_BYTES);
    return mgfs_write_record_slot(fs, slot, record);
}

typedef struct mgfs_seen_name {
    u64 length;
    char name[256];
    struct mgfs_seen_name *next;
} mgfs_seen_name_t;

static bool mgfs_seen_name_contains(mgfs_seen_name_t *const buckets[],
                                    const char *name, u64 length)
{
    u32 bucket = mgfs_seen_bucket(name, length);
    for (mgfs_seen_name_t *current = buckets[bucket]; current;
         current = current->next) {
        if (current->length == length &&
            mgfs_bytes_equal((const u8 *)current->name,
                             (const u8 *)name, (usize)length)) return true;
    }
    return false;
}

static bool mgfs_seen_name_add(mgfs_seen_name_t *buckets[],
                               const char *name, u64 length)
{
    u32 bucket = mgfs_seen_bucket(name, length);
    mgfs_seen_name_t *new_name;

    if (mgfs_seen_name_contains(buckets, name, length)) return false;
    new_name = (mgfs_seen_name_t *)kmalloc(sizeof(*new_name));
    if (!new_name) return false;
    new_name->length = length;
    memcpy(new_name->name, name, (usize)length + 1ULL);
    new_name->next = buckets[bucket];
    buckets[bucket] = new_name;
    return true;
}

typedef struct {
    mgfs_fs_t *fs;
    u8 directory_record[MGFS_RECORD_BYTES];
    u64 logical_size;
    u64 offset;
    mgfs_seen_name_t *seen[MGFS_SEEN_NAME_BUCKET_COUNT];
} mgfs_directory_cursor_t;

static void mgfs_free_seen_names(mgfs_seen_name_t *buckets[])
{
    for (u32 bucket = 0; bucket < MGFS_SEEN_NAME_BUCKET_COUNT; bucket++) {
        mgfs_seen_name_t *names = buckets[bucket];
        while (names) {
            mgfs_seen_name_t *next = names->next;
            kfree(names);
            names = next;
        }
    }
}

static bool mgfs_scan_directory(
    vfs_node_t *dir,
    const char *wanted_name,
    u32 wanted_index,
    vfs_dirent_t *out_entry,
    u8 out_record[MGFS_RECORD_BYTES])
{
    mgfs_fs_t *fs = (mgfs_fs_t *)dir->super->private_data;
    u8 directory_record[MGFS_RECORD_BYTES];
    mgfs_seen_name_t *seen[MGFS_SEEN_NAME_BUCKET_COUNT] = {0};
    u64 offset = 0;
    u32 visible_index = 0;
    bool found = false;

    bool record_valid = mgfs_read_record(fs, (u64)(uintptr_t)dir->fs_data,
                                         directory_record);
    if (!record_valid ||
        mgfs_get_le64(directory_record) != MGFS_RECORD_DIRECTORY) {
        mgfs_set_error("MGFS directory Record is invalid");
        return false;
    }

    while (offset < mgfs_get_le64(directory_record + 32)) {
        mgfs_directory_entry_t entry;
        u8 child_record[MGFS_RECORD_BYTES];

        if (!mgfs_read_directory_entry(fs, directory_record, offset, &entry)) {
            mgfs_free_seen_names(seen);
            return false;
        }
        offset += entry.total_bytes;

        if (entry.flags == MGFS_DIRENT_TOMBSTONE) {
            continue;
        }

        if (mgfs_seen_name_contains(seen, entry.name, entry.name_length)) {
            mgfs_free_seen_names(seen);
            mgfs_set_error("duplicate in-use MGFS directory name");
            return false;
        }
        if (!mgfs_seen_name_add(seen, entry.name, entry.name_length)) {
            mgfs_free_seen_names(seen);
            mgfs_set_error("unable to allocate MGFS directory name state");
            return false;
        }

        if ((wanted_name && strcmp(entry.name, wanted_name) == 0) ||
            (!wanted_name && visible_index == wanted_index)) {
            if (!mgfs_read_record(fs, entry.target_record_id, child_record)) {
                mgfs_free_seen_names(seen);
                return false;
            }
            if (out_entry) {
                memcpy(out_entry->name, entry.name, (usize)entry.name_length + 1ULL);
                out_entry->inode = entry.target_record_id;
                out_entry->type = mgfs_get_le64(child_record) == MGFS_RECORD_DIRECTORY
                    ? VFS_TYPE_DIRECTORY : VFS_TYPE_FILE;
            }
            if (out_record) {
                memcpy(out_record, child_record, MGFS_RECORD_BYTES);
            }
            found = true;
        }
        visible_index++;
    }

    mgfs_free_seen_names(seen);
    if (offset != mgfs_get_le64(directory_record + 32)) {
        mgfs_set_error("MGFS directory stream has trailing bytes");
        return false;
    }
    return found;
}

static bool mgfs_readdir_open(vfs_node_t *dir, void **out_state)
{
    mgfs_fs_t *fs;
    mgfs_directory_cursor_t *cursor;

    if (!dir || !out_state || dir->type != VFS_TYPE_DIRECTORY ||
        !dir->super || !dir->super->private_data || !dir->fs_data) {
        return false;
    }
    fs = (mgfs_fs_t *)dir->super->private_data;
    cursor = (mgfs_directory_cursor_t *)kmalloc(sizeof(*cursor));
    if (!cursor) {
        mgfs_set_error("unable to allocate MGFS directory cursor");
        return false;
    }
    memset(cursor, 0, sizeof(*cursor));
    cursor->fs = fs;
    if (!mgfs_read_record(fs, (u64)(uintptr_t)dir->fs_data,
                          cursor->directory_record) ||
        mgfs_get_le64(cursor->directory_record) != MGFS_RECORD_DIRECTORY) {
        kfree(cursor);
        mgfs_set_error("MGFS directory Record is invalid");
        return false;
    }
    cursor->logical_size = mgfs_get_le64(cursor->directory_record + 32);
    *out_state = cursor;
    return true;
}

static bool mgfs_readdir_next(void *state, vfs_dirent_t *out_entry)
{
    mgfs_directory_cursor_t *cursor = (mgfs_directory_cursor_t *)state;

    if (!cursor || !out_entry) return false;
    while (cursor->offset < cursor->logical_size) {
        mgfs_directory_entry_t entry;
        u8 child_record[MGFS_RECORD_BYTES];

        if (!mgfs_read_directory_entry(cursor->fs, cursor->directory_record,
                                       cursor->offset, &entry)) {
            return false;
        }
        cursor->offset += entry.total_bytes;
        if (entry.flags == MGFS_DIRENT_TOMBSTONE) continue;

        if (mgfs_seen_name_contains(cursor->seen, entry.name,
                                    entry.name_length)) {
            mgfs_set_error("duplicate in-use MGFS directory name");
            return false;
        }
        if (!mgfs_seen_name_add(cursor->seen, entry.name,
                                entry.name_length)) {
            mgfs_set_error("unable to allocate MGFS directory name state");
            return false;
        }

        if (!mgfs_read_record(cursor->fs, entry.target_record_id,
                              child_record)) return false;
        memcpy(out_entry->name, entry.name,
               (usize)entry.name_length + 1ULL);
        out_entry->inode = entry.target_record_id;
        out_entry->type = mgfs_get_le64(child_record) == MGFS_RECORD_DIRECTORY
            ? VFS_TYPE_DIRECTORY : VFS_TYPE_FILE;
        return true;
    }
    return false;
}

static void mgfs_readdir_close(void *state)
{
    mgfs_directory_cursor_t *cursor = (mgfs_directory_cursor_t *)state;
    if (!cursor) return;
    mgfs_free_seen_names(cursor->seen);
    kfree(cursor);
}

static bool mgfs_locate_directory_entry(
    mgfs_fs_t *fs,
    u64 directory_id,
    const char *name,
    u8 directory_record[MGFS_RECORD_BYTES],
    u64 *out_offset,
    mgfs_directory_entry_t *out_entry,
    u8 out_child[MGFS_RECORD_BYTES])
{
    u64 offset = 0;
    if (!mgfs_read_record(fs, directory_id, directory_record) ||
        mgfs_get_le64(directory_record) != MGFS_RECORD_DIRECTORY) {
        mgfs_set_error("MGFS parent is not a directory");
        return false;
    }
    while (offset < mgfs_get_le64(directory_record + 32)) {
        mgfs_directory_entry_t entry;
        if (!mgfs_read_directory_entry(fs, directory_record, offset, &entry)) return false;
        if (entry.flags == MGFS_DIRENT_IN_USE && strcmp(entry.name, name) == 0) {
            if (out_offset) *out_offset = offset;
            if (out_entry) *out_entry = entry;
            if (out_child && !mgfs_read_record(fs, entry.target_record_id, out_child)) return false;
            return true;
        }
        offset += entry.total_bytes;
    }
    mgfs_set_error("MGFS directory entry not found");
    return false;
}

static bool mgfs_publish_tombstone(
    mgfs_fs_t *fs,
    const u8 directory_record[MGFS_RECORD_BYTES],
    u64 offset,
    u64 entry_bytes)
{
    u64 physical;
    u8 block[MGFS_BLOCK_BYTES];
    u8 *entry;
    if (!mgfs_find_directory_block(fs, directory_record,
                                   offset / MGFS_BLOCK_BYTES, &physical) ||
        !mgfs_read_block(fs->dev, physical, block)) return false;
    entry = block + offset % MGFS_BLOCK_BYTES;
    mgfs_store_le64(entry + 16, MGFS_DIRENT_TOMBSTONE);
    mgfs_recompute_checksum(entry, 24, (usize)entry_bytes);
    return mgfs_write_block(fs->dev, physical, block);
}

/* A directory's logical stream can retain tombstoned entries after unlink.
   Emptiness therefore depends on entry state, not stream length. */
static bool mgfs_directory_has_live_entries(
    mgfs_fs_t *fs,
    const u8 directory_record[MGFS_RECORD_BYTES],
    bool *out_has_live)
{
    u64 offset = 0;
    u64 logical_size = mgfs_get_le64(directory_record + 32);
    bool has_live = false;

    while (offset < logical_size) {
        mgfs_directory_entry_t entry;
        if (!mgfs_read_directory_entry(fs, directory_record, offset, &entry)) {
            return false;
        }
        if (entry.flags == MGFS_DIRENT_IN_USE) {
            has_live = true;
        }
        offset += entry.total_bytes;
    }
    if (offset != logical_size) {
        mgfs_set_error("MGFS directory stream has trailing bytes");
        return false;
    }
    *out_has_live = has_live;
    return true;
}

static int mgfs_delete_entry(vfs_node_t *parent, const char *name, bool directory_only)
{
    mgfs_fs_t *fs;
    u8 parent_record[MGFS_RECORD_BYTES];
    u8 child_record[MGFS_RECORD_BYTES];
    mgfs_directory_entry_t entry;
    u64 offset;
    u64 slot;
    u64 capacity;
    mgfs_extent_desc_t *extents;
    u64 *list_blocks;
    u64 extent_count = 0;
    u64 list_count = 0;
    bool has_live_entries;

    if (!parent || parent->type != VFS_TYPE_DIRECTORY || !name ||
        !parent->super || !parent->super->private_data) {
        mgfs_set_error("invalid MGFS deletion parent");
        return VFS_ERR_INVALID_PARAM;
    }
    fs = (mgfs_fs_t *)parent->super->private_data;
    if (!mgfs_locate_directory_entry(fs, (u64)(uintptr_t)parent->fs_data, name,
                                     parent_record, &offset, &entry, child_record)) {
        return VFS_ERR_NOT_FOUND;
    }
    if (directory_only) {
        if (mgfs_get_le64(child_record) != MGFS_RECORD_DIRECTORY) {
            mgfs_set_error("MGFS rmdir target is not a directory");
            return VFS_ERR_INVALID_PARAM;
        }
        if (!mgfs_directory_has_live_entries(fs, child_record, &has_live_entries)) {
            return VFS_ERR_IO;
        }
        if (has_live_entries) {
            mgfs_set_error("MGFS directory is not empty");
            return VFS_ERR_NOT_EMPTY;
        }
    } else if (mgfs_get_le64(child_record) == MGFS_RECORD_DIRECTORY) {
        mgfs_set_error("MGFS rm target is a directory");
        return VFS_ERR_INVALID_PARAM;
    }

    capacity = fs->layout.record_count;
    extents = (mgfs_extent_desc_t *)kmalloc((usize)(capacity * sizeof(*extents)));
    list_blocks = (u64 *)kmalloc((usize)(capacity * sizeof(u64)));
    if (!extents || !list_blocks) {
        kfree(extents); kfree(list_blocks);
        mgfs_set_error("MGFS deletion state allocation failed");
        return VFS_ERR_NO_MEM;
    }
    if (!mgfs_collect_file_extents(fs, child_record, extents, capacity, &extent_count,
                                   mgfs_get_le64(child_record) == MGFS_RECORD_DIRECTORY
                                       ? MGFS_EXTENT_DIRECTORY_METADATA : MGFS_EXTENT_DATA) ||
        !mgfs_collect_extent_list_blocks(fs, child_record, list_blocks, capacity, &list_count) ||
        !mgfs_find_record_slot(fs, entry.target_record_id, &slot) ||
        !mgfs_set_state(fs, MGFS_STATE_NEEDS_FSCK)) {
        kfree(extents); kfree(list_blocks); return VFS_ERR_IO;
    }

    /* The tombstone is the publication point; the old Record remains valid
       until this write completes. */
    if (!mgfs_publish_tombstone(fs, parent_record, offset, entry.total_bytes)) {
        kfree(extents); kfree(list_blocks); return VFS_ERR_IO;
    }
    mgfs_dentry_cache_invalidate_parent(fs, (u64)(uintptr_t)parent->fs_data);
    if (!mgfs_free_record_slot(fs, slot) ||
        !mgfs_reclaim_obsolete_blocks(fs, extents, extent_count, list_blocks,
                                      list_count, NULL, 0, 0) ||
        !mgfs_set_state(fs, MGFS_STATE_CLEAN)) {
        kfree(extents); kfree(list_blocks); return VFS_ERR_IO;
    }
    kfree(extents); kfree(list_blocks);
    return VFS_OK;
}

static int mgfs_unlink(vfs_node_t *parent, const char *name)
{
    return mgfs_delete_entry(parent, name, false);
}

static bool mgfs_record_in_subtree(mgfs_fs_t *fs, u64 root_id, u64 target_id,
                                   u64 *visited, u64 capacity, u64 *visited_count,
                                   bool *out_found)
{
    u8 record[MGFS_RECORD_BYTES];
    u64 offset;

    if (root_id == target_id) {
        *out_found = true;
        return true;
    }
    for (u64 i = 0; i < *visited_count; i++) {
        if (visited[i] == root_id) return true;
    }
    if (*visited_count >= capacity || !mgfs_read_record(fs, root_id, record)) {
        return false;
    }
    visited[(*visited_count)++] = root_id;
    if (mgfs_get_le64(record) != MGFS_RECORD_DIRECTORY) return true;

    offset = 0;
    while (offset < mgfs_get_le64(record + 32)) {
        mgfs_directory_entry_t entry;
        u8 child[MGFS_RECORD_BYTES];
        if (!mgfs_read_directory_entry(fs, record, offset, &entry)) return false;
        offset += entry.total_bytes;
        if (entry.flags != MGFS_DIRENT_IN_USE) continue;
        if (!mgfs_read_record(fs, entry.target_record_id, child)) return false;
        if (mgfs_get_le64(child) == MGFS_RECORD_DIRECTORY &&
            !mgfs_record_in_subtree(fs, entry.target_record_id, target_id,
                                    visited, capacity, visited_count, out_found)) {
            return false;
        }
        if (*out_found) return true;
    }
    return offset == mgfs_get_le64(record + 32);
}

static int mgfs_rename_entry(vfs_node_t *src_dir, const char *src_name,
                             vfs_node_t *dst_dir, const char *dst_name)
{
    mgfs_fs_t *fs;
    u8 src_record[MGFS_RECORD_BYTES];
    u8 child_record[MGFS_RECORD_BYTES];
    mgfs_directory_entry_t source_entry;
    u64 src_offset;
    u64 src_id;
    u64 dst_id;
    u64 name_length;
    u64 entry_length;
    u8 new_entry[288];
    u8 dst_parent_record[MGFS_RECORD_BYTES];
    u64 *visited;
    u64 visited_count = 0;
    bool found = false;

    if (!src_dir || !dst_dir || !src_name || !dst_name ||
        src_dir->type != VFS_TYPE_DIRECTORY || dst_dir->type != VFS_TYPE_DIRECTORY ||
        !src_dir->super || src_dir->super != dst_dir->super ||
        !src_dir->super->private_data || !src_name[0] || !dst_name[0]) {
        mgfs_set_error("invalid MGFS rename request");
        return VFS_ERR_INVALID_PARAM;
    }
    fs = (mgfs_fs_t *)src_dir->super->private_data;
    src_id = (u64)(uintptr_t)src_dir->fs_data;
    dst_id = (u64)(uintptr_t)dst_dir->fs_data;
    if (!mgfs_valid_utf8_name((const u8 *)dst_name, strlen(dst_name))) {
        mgfs_set_error("invalid MGFS destination name");
        return VFS_ERR_INVALID_PARAM;
    }
    if (!mgfs_locate_directory_entry(fs, src_id, src_name, src_record,
                                     &src_offset, &source_entry, child_record)) {
        return VFS_ERR_NOT_FOUND;
    }
    if (source_entry.target_record_id == fs->root_record_id) {
        mgfs_set_error("MGFS root directory cannot be moved");
        return VFS_ERR_INVALID_PARAM;
    }
    if (src_id == dst_id && strcmp(src_name, dst_name) == 0) return VFS_OK;
    mgfs_set_error("no error");
    if (mgfs_scan_directory(dst_dir, dst_name, 0, NULL, NULL)) {
        mgfs_set_error("MGFS rename destination already exists");
        return VFS_ERR_INVALID_PARAM;
    }
    if (strcmp(mgfs_last_error(), "no error") != 0) return VFS_ERR_BAD_FORMAT;
    if (mgfs_get_le64(child_record) == MGFS_RECORD_DIRECTORY) {
        visited = (u64 *)kmalloc((usize)(fs->layout.record_count * sizeof(u64)));
        if (!visited) return VFS_ERR_NO_MEM;
        if (!mgfs_record_in_subtree(fs, source_entry.target_record_id, dst_id,
                                    visited, fs->layout.record_count,
                                    &visited_count, &found)) {
            kfree(visited);
            return VFS_ERR_IO;
        }
        kfree(visited);
        if (found) {
            mgfs_set_error("MGFS directory move would create a cycle");
            return VFS_ERR_INVALID_PARAM;
        }
    }

    name_length = strlen(dst_name);
    entry_length = (32ULL + name_length + 7ULL) & ~7ULL;
    memset(new_entry, 0, sizeof(new_entry));
    mgfs_store_le64(new_entry, source_entry.target_record_id);
    mgfs_store_le64(new_entry + 8, name_length);
    mgfs_store_le64(new_entry + 16, MGFS_DIRENT_IN_USE);
    memcpy(new_entry + 32, dst_name, (usize)name_length);
    mgfs_recompute_checksum(new_entry, 24, (usize)entry_length);

    if (!mgfs_set_state(fs, MGFS_STATE_NEEDS_FSCK) ||
        !mgfs_append_directory_entry(fs, dst_id, new_entry, entry_length,
                                     dst_parent_record) ||
        !mgfs_publish_tombstone(fs, src_record, src_offset, source_entry.total_bytes) ||
        !mgfs_touch_directory_record(fs, src_id) ||
        !mgfs_set_state(fs, MGFS_STATE_CLEAN)) {
        return VFS_ERR_IO;
    }
    mgfs_refresh_directory_node(fs, dst_dir);
    mgfs_dentry_cache_invalidate_parent(fs, src_id);
    mgfs_dentry_cache_invalidate_parent(fs, dst_id);
    if (src_dir == dst_dir) src_dir->size = dst_dir->size;
    return VFS_OK;
}

static int mgfs_rmdir(vfs_node_t *parent, const char *name)
{
    if (parent && parent->super && parent->super->private_data &&
        (strcmp(name, "/") == 0 || name[0] == '\0')) {
        mgfs_set_error("MGFS root directory cannot be removed");
        return VFS_ERR_INVALID_PARAM;
    }
    return mgfs_delete_entry(parent, name, true);
}

static vfs_node_t *mgfs_finddir(vfs_node_t *dir, const char *name)
{
    mgfs_fs_t *fs;
    u64 parent_id;
    u64 child_id;
    u8 child_record[MGFS_RECORD_BYTES];
    vfs_node_t *node;

    if (!dir || !name || dir->type != VFS_TYPE_DIRECTORY || !dir->super ||
        !dir->super->private_data || !dir->fs_data) {
        return NULL;
    }
    fs = (mgfs_fs_t *)dir->super->private_data;
    parent_id = (u64)(uintptr_t)dir->fs_data;
    if (mgfs_dentry_cache_lookup(fs, parent_id, name, &child_id)) {
        if (child_id == 0ULL ||
            !mgfs_read_record(fs, child_id, child_record)) return NULL;
    } else {
        if (!mgfs_scan_directory(dir, name, 0, NULL, child_record)) {
            return NULL;
        }
        child_id = mgfs_get_le64(child_record + 16);
        mgfs_dentry_cache_insert(fs, parent_id, name, child_id);
    }

    node = (vfs_node_t *)kmalloc(sizeof(vfs_node_t));
    if (!node) {
        mgfs_set_error("unable to allocate MGFS child node");
        return NULL;
    }
    memset(node, 0, sizeof(*node));
    node->inode = mgfs_get_le64(child_record + 16);
    node->type = mgfs_get_le64(child_record) == MGFS_RECORD_DIRECTORY
        ? VFS_TYPE_DIRECTORY : VFS_TYPE_FILE;
    node->size = mgfs_get_le64(child_record + 32);
    node->owner_uid = mgfs_record_owner(child_record);
    node->permissions = mgfs_record_permissions(child_record);
    mgfs_apply_directory_policy(child_record, node);
    node->ref_count = 1;
    node->super = dir->super;
    node->fs_data = (void *)(uintptr_t)node->inode;
    node->ops = &mgfs_node_ops;
    vfs_node_register(node);
    return node;
}

static bool mgfs_readdir(vfs_node_t *dir, u32 index, vfs_dirent_t *out_entry)
{
    if (!dir || !out_entry || dir->type != VFS_TYPE_DIRECTORY ||
        !dir->super || !dir->super->private_data || !dir->fs_data) {
        return false;
    }
    return mgfs_scan_directory(dir, NULL, index, out_entry, NULL);
}

static int mgfs_create_node(
    vfs_node_t *dir,
    const char *name,
    u64 record_type,
    bool explicit_security,
    u32 explicit_owner_uid,
    u32 explicit_permissions,
    vfs_node_t **out_node)
{
    mgfs_fs_t *fs;
    u64 parent_id;
    u64 slot;
    u64 record_id;
    u8 record[MGFS_RECORD_BYTES];
    u8 parent[MGFS_RECORD_BYTES];
    u8 entry[288];
    u64 name_length;
    u64 entry_length;
    u32 owner_uid;
    u32 permissions;

    if (!dir || !name || !out_node || dir->type != VFS_TYPE_DIRECTORY ||
        !dir->super || !dir->super->private_data) {
        mgfs_set_error("invalid MGFS create parent");
        return VFS_ERR_INVALID_PARAM;
    }
    name_length = strlen(name);
    if (!mgfs_valid_utf8_name((const u8 *)name, name_length)) {
        mgfs_set_error("invalid MGFS name");
        return VFS_ERR_INVALID_PARAM;
    }
    fs = (mgfs_fs_t *)dir->super->private_data;
    parent_id = (u64)(uintptr_t)dir->fs_data;
    if (explicit_security) {
        owner_uid = explicit_owner_uid;
        if ((explicit_permissions & ~VFS_PERMISSION_KNOWN) != 0U ||
            !explicit_permissions) {
            mgfs_set_error("invalid explicit MGFS security metadata");
            return VFS_ERR_INVALID_PARAM;
        }
        permissions = explicit_permissions;
    } else if (!vfs_current_uid(&owner_uid)) {
        mgfs_set_error("unable to determine creating process identity");
        return VFS_ERR_ACCESS_DENIED;
    } else {
        permissions = record_type == MGFS_RECORD_DIRECTORY
            ? VFS_DEFAULT_DIRECTORY_PERMISSIONS
            : VFS_DEFAULT_FILE_PERMISSIONS;
    }
    mgfs_set_error("no error");
    if (mgfs_scan_directory(dir, name, 0, NULL, NULL)) {
        mgfs_set_error("MGFS directory name already exists");
        return VFS_ERR_INVALID_PARAM;
    }
    if (strcmp(mgfs_last_error(), "no error") != 0) {
        return VFS_ERR_BAD_FORMAT;
    }
    if (!mgfs_set_state(fs, MGFS_STATE_NEEDS_FSCK) ||
        !mgfs_allocate_record(fs, &slot, &record_id)) {
        return VFS_ERR_IO;
    }

    memset(record, 0, sizeof(record));
    mgfs_store_le64(record, record_type);
    mgfs_store_le64(record + 8,
                    mgfs_security_flags(owner_uid, permissions, false,
                                         VFS_CHILD_MUTATION_OPEN));
    mgfs_store_le64(record + 16, record_id);
    mgfs_store_le64(record + 24, 1ULL);
    mgfs_recompute_checksum(record, MGFS_RECORD_CHECKSUM_OFFSET, MGFS_RECORD_BYTES);
    if (!mgfs_write_record_slot(fs, slot, record) ||
        !mgfs_insert_record_id(fs, record_id, slot)) return VFS_ERR_IO;

    memset(entry, 0, sizeof(entry));
    mgfs_store_le64(entry, record_id);
    mgfs_store_le64(entry + 8, name_length);
    mgfs_store_le64(entry + 16, MGFS_DIRENT_IN_USE);
    memcpy(entry + 32, name, (usize)name_length);
    entry_length = (32ULL + name_length + 7ULL) & ~7ULL;
    mgfs_recompute_checksum(entry, 24, (usize)entry_length);
    if (!mgfs_append_directory_entry(fs, parent_id, entry, entry_length, parent) ||
        !mgfs_set_state(fs, MGFS_STATE_CLEAN)) {
        return VFS_ERR_IO;
    }
    *out_node = (vfs_node_t *)kmalloc(sizeof(vfs_node_t));
    if (!*out_node) return VFS_ERR_NO_MEM;
    memset(*out_node, 0, sizeof(vfs_node_t));
    (*out_node)->inode = record_id;
    (*out_node)->type = record_type == MGFS_RECORD_DIRECTORY
        ? VFS_TYPE_DIRECTORY : VFS_TYPE_FILE;
    (*out_node)->ref_count = 1;
    (*out_node)->owner_uid = owner_uid;
    (*out_node)->permissions = permissions;
    vfs_node_set_child_mutation_policy(*out_node, VFS_CHILD_MUTATION_OPEN);
    (*out_node)->super = dir->super;
    (*out_node)->fs_data = (void *)(uintptr_t)record_id;
    (*out_node)->ops = &mgfs_node_ops;
    vfs_node_register(*out_node);
    return VFS_OK;
}

static int mgfs_create(vfs_node_t *dir, const char *name, vfs_node_t **out_node)
{
    return mgfs_create_node(dir, name, MGFS_RECORD_FILE, false, 0, 0,
                            out_node);
}

static int mgfs_mkdir(vfs_node_t *dir, const char *name, vfs_node_t **out_node)
{
    return mgfs_create_node(dir, name, MGFS_RECORD_DIRECTORY, false, 0, 0,
                            out_node);
}

static int mgfs_create_owned(vfs_node_t *dir, const char *name, u32 owner_uid,
                             u32 permissions, vfs_node_t **out_node)
{
    return mgfs_create_node(dir, name, MGFS_RECORD_FILE, true, owner_uid,
                            permissions, out_node);
}

static int mgfs_mkdir_owned(vfs_node_t *dir, const char *name, u32 owner_uid,
                            u32 permissions, vfs_node_t **out_node)
{
    return mgfs_create_node(dir, name, MGFS_RECORD_DIRECTORY, true,
                            owner_uid, permissions, out_node);
}

static bool mgfs_scan_records(mgfs_fs_t *fs)
{
    u8 block[MGFS_BLOCK_BYTES];
    u64 allocated = 0;
    u64 capacity = 16ULL;

    for (u64 slot = 0; slot < fs->layout.record_count; slot++) {
        if (mgfs_record_slot_allocated(fs, slot)) {
            allocated++;
        }
    }

    while (capacity < (allocated > MGFS_U64_MAX / 2ULL ? MGFS_U64_MAX : allocated * 2ULL)) {
        if (capacity > MGFS_U64_MAX / 2ULL) {
            mgfs_set_error("MGFS Record ID index size overflow");
            return false;
        }
        capacity <<= 1;
    }

    if (capacity > (u64)(usize)-1 / sizeof(mgfs_record_ref_t)) {
        mgfs_set_error("MGFS Record ID index allocation overflow");
        return false;
    }

    fs->record_ids = (mgfs_record_ref_t *)kmalloc((usize)(capacity * sizeof(mgfs_record_ref_t)));
    if (!fs->record_ids) {
        mgfs_set_error("unable to allocate MGFS Record ID index");
        return false;
    }
    memset(fs->record_ids, 0, (usize)(capacity * sizeof(mgfs_record_ref_t)));
    fs->record_id_capacity = capacity;
    fs->allocated_record_count = allocated;

    u64 root_slot = MGFS_U64_MAX;
    for (u64 table_index = 0; table_index < fs->layout.record_table_blocks; table_index++) {
        if (!mgfs_read_block(fs->dev, fs->layout.record_table_start + table_index, block) ||
            !mgfs_validate_metadata_header(block, MGFS_METADATA_RECORD_TABLE, table_index)) {
            return false;
        }

        for (u64 slot_in_block = 0; slot_in_block < MGFS_RECORDS_PER_TABLE_BLOCK; slot_in_block++) {
            u64 slot = table_index * MGFS_RECORDS_PER_TABLE_BLOCK + slot_in_block;
            u8 *record;

            if (slot >= fs->layout.record_count || !mgfs_record_slot_allocated(fs, slot)) {
                continue;
            }

            record = block + MGFS_BITMAP_HEADER_BYTES + slot_in_block * MGFS_RECORD_BYTES;
            if (!mgfs_validate_record(fs, record)) {
                return false;
            }
            if (!mgfs_insert_record_id(fs, mgfs_get_le64(record + 16), slot)) {
                return false;
            }

            if (mgfs_get_le64(record + 16) == fs->root_record_id) {
                if (root_slot != MGFS_U64_MAX || mgfs_get_le64(record) != MGFS_RECORD_DIRECTORY) {
                    mgfs_set_error("invalid MGFS root Record");
                    return false;
                }
                root_slot = slot;
            }
        }
    }

    if (root_slot == MGFS_U64_MAX) {
        mgfs_set_error("MGFS root Record was not found");
        return false;
    }

    if (root_slot != 0ULL) {
        mgfs_set_error("MGFS root Record is not in table slot zero");
        return false;
    }

    return true;
}

static bool mgfs_probe(block_device_t *dev)
{
    u8 block[MGFS_BLOCK_BYTES];
    mgfs_fs_t *fs;
    bool valid;

    if (!dev || dev->sector_size != 512U || dev->sector_count < 8ULL ||
        !mgfs_read_block(dev, 0, block)) {
        return false;
    }

    /* Probe results feed the authoritative volume snapshot.  A magic-only
     * answer would advertise a truncated or structurally invalid MGFS image
     * as mountable even though mgfs_mount() would reject it.  Keep probe and
     * mount eligibility coherent by applying the same bounded superblock
     * validation here.  mgfs_fs_t contains directory-cache state and must
     * stay off the small kernel stack. */
    fs = (mgfs_fs_t *)kmalloc(sizeof(*fs));
    if (!fs) return false;
    valid = mgfs_validate_superblock(dev, block, fs);
    kfree(fs);
    return valid;
}

static bool mgfs_read_label(block_device_t *dev, char *out, usize capacity)
{
    u8 block[MGFS_BLOCK_BYTES];
    u64 length;

    if (!out || capacity < 2U) return false;
    out[0] = '\0';
    if (!dev || !mgfs_read_block(dev, 0, block) ||
        !mgfs_label_extension_valid(block)) return false;
    length = mgfs_get_le64(block + MGFS_LABEL_LENGTH_OFFSET);
    if (!length || length >= capacity) return false;
    memcpy(out, block + MGFS_LABEL_DATA_OFFSET, (usize)length);
    out[length] = '\0';
    return true;
}

static int mgfs_mount(vfs_fs_type_t *fs_type, block_device_t *dev,
                      vfs_super_t **out_sb, bool read_only)
{
    u8 superblock[MGFS_BLOCK_BYTES];
    vfs_super_t *sb;
    vfs_node_t *root;
    mgfs_fs_t *fs;

    (void)fs_type;
    (void)read_only;
    mgfs_set_error("no error");

    if (!dev || !out_sb || dev->sector_size != 512U) {
        mgfs_set_error("invalid MGFS mount device");
        return VFS_ERR_INVALID_PARAM;
    }

    fs = (mgfs_fs_t *)kmalloc(sizeof(mgfs_fs_t));
    if (!fs) {
        mgfs_set_error("unable to allocate MGFS state");
        return VFS_ERR_NO_MEM;
    }
    memset(fs, 0, sizeof(*fs));
    fs->dev = dev;

    if (!mgfs_read_block(dev, 0, superblock) ||
        !mgfs_validate_superblock(dev, superblock, fs)) {
        kfree(fs);
        return VFS_ERR_BAD_FORMAT;
    }

    if (fs->layout.record_bitmap_blocks > (u64)(usize)-1 / MGFS_BLOCK_BYTES) {
        mgfs_set_error("MGFS Record bitmap allocation overflow");
        kfree(fs);
        return VFS_ERR_BAD_FORMAT;
    }
    fs->record_bitmap_bytes = fs->layout.record_bitmap_blocks * MGFS_BLOCK_BYTES;
    fs->record_bitmap = (u8 *)kmalloc((usize)fs->record_bitmap_bytes);
    if (!fs->record_bitmap) {
        mgfs_set_error("unable to allocate MGFS Record bitmap");
        kfree(fs);
        return VFS_ERR_NO_MEM;
    }

    if (!mgfs_validate_bitmap_region(fs,
                                     fs->layout.allocation_bitmap_start,
                                     fs->layout.allocation_bitmap_blocks,
                                     MGFS_METADATA_ALLOCATION_BITMAP,
                                     fs->layout.data_blocks, false) ||
        !mgfs_validate_bitmap_region(fs,
                                     fs->layout.record_bitmap_start,
                                     fs->layout.record_bitmap_blocks,
                                     MGFS_METADATA_RECORD_BITMAP,
                                     fs->layout.record_count, true) ||
        !mgfs_scan_records(fs)) {
        kfree(fs->record_bitmap);
        kfree(fs->record_ids);
        kfree(fs);
        return VFS_ERR_BAD_FORMAT;
    }

    sb = (vfs_super_t *)kmalloc(sizeof(vfs_super_t));
    root = (vfs_node_t *)kmalloc(sizeof(vfs_node_t));
    if (!sb || !root) {
        kfree(sb);
        kfree(root);
        kfree(fs->record_bitmap);
        kfree(fs->record_ids);
        kfree(fs);
        mgfs_set_error("unable to allocate MGFS VFS objects");
        return VFS_ERR_NO_MEM;
    }

    memset(sb, 0, sizeof(*sb));
    memset(root, 0, sizeof(*root));
    root->inode = fs->root_record_id;
    root->type = VFS_TYPE_DIRECTORY;
    {
        u8 root_record[MGFS_RECORD_BYTES];
        if (!mgfs_read_record(fs, fs->root_record_id, root_record)) {
            kfree(sb);
            kfree(root);
            kfree(fs->record_bitmap);
            kfree(fs->record_ids);
            kfree(fs);
            return VFS_ERR_BAD_FORMAT;
        }
        root->owner_uid = mgfs_record_owner(root_record);
        root->permissions = mgfs_record_permissions(root_record);
        root->size = mgfs_get_le64(root_record + 32);
        mgfs_apply_directory_policy(root_record, root);
    }
    root->ref_count = 1;
    root->super = sb;
    root->fs_data = (void *)(uintptr_t)fs->root_record_id;
    root->ops = &mgfs_node_ops;

    sb->fs_type = fs_type;
    sb->dev = dev;
    sb->root_node = root;
    sb->private_data = fs;
    sb->ops = &mgfs_super_ops;
    *out_sb = sb;
    return VFS_OK;
}

static int mgfs_unmount(vfs_super_t *sb)
{
    mgfs_fs_t *fs;

    if (!sb) {
        return VFS_ERR_INVALID_PARAM;
    }

    fs = (mgfs_fs_t *)sb->private_data;
    if (fs) {
        kfree(fs->record_bitmap);
        kfree(fs->record_ids);
        kfree(fs);
        sb->private_data = NULL;
    }
    return VFS_OK;
}

static const vfs_ops_t mgfs_node_ops = {
    .read = mgfs_read,
    .write = mgfs_write,
    .finddir = mgfs_finddir,
    .readdir = mgfs_readdir,
    .readdir_open = mgfs_readdir_open,
    .readdir_next = mgfs_readdir_next,
    .readdir_close = mgfs_readdir_close,
    .create = mgfs_create,
    .mkdir = mgfs_mkdir,
    .create_owned = mgfs_create_owned,
    .mkdir_owned = mgfs_mkdir_owned,
    .unlink = mgfs_unlink,
    .rmdir = mgfs_rmdir,
    .rename = mgfs_rename_entry,
    .truncate = mgfs_truncate,
};

static const vfs_super_ops_t mgfs_super_ops = {
    .unmount = mgfs_unmount,
    .sync = NULL,
};

static vfs_fs_type_t mgfs_fs_type = {
    .name = "mgfs",
    .probe = mgfs_probe,
    .label = mgfs_read_label,
    .mount = mgfs_mount,
    .next = NULL,
};

int mgfs_init(void)
{
    return vfs_register_fs(&mgfs_fs_type);
}
