/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <storage/format.h>

#include <heap.h>
#include <string.h>
#include <vfs.h>
#include <storage/fat32.h>
#include <storage/exfat.h>

#define FORMAT_SECTOR_BYTES 512U

#define FAT32_RESERVED_SECTORS 32U
#define FAT32_FAT_COUNT        2U
#define FAT32_MIN_CLUSTERS     65525ULL
#define FAT32_MAX_CLUSTERS     0x0ffffff5ULL
/* Legacy BPB geometry is not used for addressing on modern media, but
 * non-zero conventional values are required by common interoperable tools. */
#define FAT32_BPB_SECTORS_PER_TRACK 63U
#define FAT32_BPB_HEADS             255U

#define MGFS_BLOCK_BYTES             4096U
#define MGFS_BLOCK_SECTORS           8ULL
#define MGFS_FORMAT_MAJOR            1ULL
#define MGFS_FORMAT_MINOR            2ULL
#define MGFS_HEADER_BYTES            200ULL
#define MGFS_RECORD_BYTES            192ULL
#define MGFS_RECORDS_PER_TABLE_BLOCK 21ULL
#define MGFS_BITMAP_HEADER_BYTES     24ULL
#define MGFS_BITMAP_BITS_PER_BLOCK   32576ULL
#define MGFS_MIN_TOTAL_BLOCKS        64ULL
#define MGFS_TABLE_BLOCKS_DIVISOR    320ULL
#define MGFS_ROOT_RECORD_ID          1ULL
#define MGFS_NEXT_RECORD_ID          2ULL
#define MGFS_INITIAL_GENERATION      1ULL
#define MGFS_STATE_CLEAN             1ULL
#define MGFS_METADATA_ALLOCATION_BITMAP 1ULL
#define MGFS_METADATA_RECORD_BITMAP     2ULL
#define MGFS_METADATA_RECORD_TABLE      3ULL
#define MGFS_RECORD_DIRECTORY            2ULL
#define MGFS_CRC64_POLYNOMIAL         0x42F0E1EBA9EA3693ULL

#define MGFS_LABEL_EXTENSION_OFFSET   200U
#define MGFS_LABEL_LENGTH_OFFSET      208U
#define MGFS_LABEL_DATA_OFFSET        216U
#define MGFS_LABEL_CHECKSUM_OFFSET    280U
#define MGFS_LABEL_BYTES              63U
#define MGFS_LABEL_EXTENSION_BYTES    88U

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
} mgfs_format_layout_t;

static bool storage_operation_in_progress;

bool storage_mutation_begin(void)
{
    if (storage_operation_in_progress) return false;
    storage_operation_in_progress = true;
    return true;
}

void storage_mutation_end(void)
{
    storage_operation_in_progress = false;
}

bool storage_mutation_busy(void)
{
    return storage_operation_in_progress;
}

/* Formatting is the one kernel path that intentionally issues a sequence of
 * raw metadata writes.  Keep the extent check immediately below the
 * filesystem-specific code so a layout-calculation bug cannot escape through
 * the generic block callback into a neighbouring partition. */
static bool format_write(block_device_t *device, u64 lba, u32 sector_count,
                         const void *buffer)
{
    if (!device || !buffer || !sector_count || !block_device_is_live(device) ||
        lba > device->sector_count ||
        (u64)sector_count > device->sector_count - lba) return false;
    return block_write(device, lba, sector_count, buffer);
}

static bool format_read(block_device_t *device, u64 lba, u32 sector_count,
                        void *buffer)
{
    if (!device || !buffer || !sector_count || !block_device_is_live(device) ||
        lba > device->sector_count ||
        (u64)sector_count > device->sector_count - lba) return false;
    return block_read(device, lba, sector_count, buffer);
}

static bool format_block_write(block_device_t *device, u64 block_number,
                               const void *buffer)
{
    if (block_number > ~(u64)0 / MGFS_BLOCK_SECTORS) return false;
    return format_write(device, block_number * MGFS_BLOCK_SECTORS, 8U,
                        buffer);
}

static void store_le16(u8 *data, u16 value)
{
    data[0] = (u8)value;
    data[1] = (u8)(value >> 8);
}

static void store_le32(u8 *data, u32 value)
{
    for (u32 index = 0; index < 4U; index++)
        data[index] = (u8)(value >> (index * 8U));
}

static void store_le64(u8 *data, u64 value)
{
    for (u32 index = 0; index < 8U; index++)
        data[index] = (u8)(value >> (index * 8U));
}

static u64 crc64(const u8 *data, usize length, u32 zero_offset)
{
    u64 crc = 0;

    for (usize index = 0; index < length; index++) {
        u8 value = (zero_offset != ~(u32)0U && index >= zero_offset &&
                    index - zero_offset < 8U)
            ? 0U : data[index];
        crc ^= (u64)value << 56U;
        for (u32 bit = 0; bit < 8U; bit++)
            crc = (crc & 0x8000000000000000ULL)
                ? (crc << 1U) ^ MGFS_CRC64_POLYNOMIAL
                : crc << 1U;
    }
    return crc;
}

static bool write_zero_sectors(block_device_t *device, u64 lba, u64 count)
{
    u8 zero[MGFS_BLOCK_BYTES];

    memset(zero, 0, sizeof(zero));
    while (count) {
        u32 batch = count > 8ULL ? 8U : (u32)count;
        if (!format_write(device, lba, batch, zero)) return false;
        if (lba > ~(u64)0 - batch) return false;
        lba += batch;
        count -= batch;
    }
    return true;
}

static bool calculate_mgfs_layout(u64 total_blocks,
                                  mgfs_format_layout_t *layout)
{
    u64 table_blocks;
    u64 record_count;
    u64 record_bitmap_blocks;
    u64 allocation_bitmap_blocks;
    u64 data_start;

    if (!layout || total_blocks < MGFS_MIN_TOTAL_BLOCKS) return false;
    table_blocks = total_blocks / MGFS_TABLE_BLOCKS_DIVISOR;
    if (!table_blocks) table_blocks = 1ULL;
    if (table_blocks > ~(u64)0 / MGFS_RECORDS_PER_TABLE_BLOCK) return false;
    record_count = table_blocks * MGFS_RECORDS_PER_TABLE_BLOCK;
    if (record_count > ~(u64)0 - (MGFS_BITMAP_BITS_PER_BLOCK - 1ULL) ||
        total_blocks > ~(u64)0 - (MGFS_BITMAP_BITS_PER_BLOCK - 1ULL))
        return false;
    record_bitmap_blocks = (record_count + MGFS_BITMAP_BITS_PER_BLOCK - 1ULL) /
                           MGFS_BITMAP_BITS_PER_BLOCK;
    allocation_bitmap_blocks = (total_blocks + MGFS_BITMAP_BITS_PER_BLOCK - 1ULL) /
                               MGFS_BITMAP_BITS_PER_BLOCK;
    if (allocation_bitmap_blocks > ~(u64)0 - 1ULL ||
        record_bitmap_blocks > ~(u64)0 - 1ULL - allocation_bitmap_blocks ||
        table_blocks > ~(u64)0 - 1ULL - allocation_bitmap_blocks -
                         record_bitmap_blocks) return false;
    data_start = 1ULL + allocation_bitmap_blocks + record_bitmap_blocks +
                 table_blocks;
    if (data_start >= total_blocks) return false;
    layout->allocation_bitmap_start = 1ULL;
    layout->allocation_bitmap_blocks = allocation_bitmap_blocks;
    layout->record_bitmap_start = 1ULL + allocation_bitmap_blocks;
    layout->record_bitmap_blocks = record_bitmap_blocks;
    layout->record_table_start = layout->record_bitmap_start +
                                 record_bitmap_blocks;
    layout->record_table_blocks = table_blocks;
    layout->record_count = record_count;
    layout->data_start = data_start;
    layout->data_blocks = total_blocks - data_start;
    return true;
}

static bool format_mgfs(block_device_t *device)
{
    mgfs_format_layout_t layout;
    u8 block[MGFS_BLOCK_BYTES];
    u64 total_blocks;
    u32 root_owner;
    u32 root_permissions;
    u64 root_flags;

    if (!device || device->sector_size != FORMAT_SECTOR_BYTES) return false;
    /* A runtime-created removable MGFS volume belongs to the authenticated
     * formatting process.  Reusing the image-builder's system-owned root
     * would make a freshly formatted removable volume read-only to its
     * normal user despite a successful format. */
    if (!vfs_current_uid(&root_owner)) return false;
    root_permissions = root_owner == VFS_UID_SYSTEM
        ? VFS_DEFAULT_SYSTEM_PERMISSIONS : VFS_DEFAULT_DIRECTORY_PERMISSIONS;
    root_flags = ((u64)root_owner << 1U) |
                 ((u64)root_permissions << 33U);
    /* GPT's final usable LBA is not necessarily 4 KiB aligned.  MGFS owns
     * complete 4 KiB blocks, so retain at most seven harmless trailing
     * sectors inside the selected extent rather than rejecting an otherwise
     * valid partition or ever writing past its boundary. */
    total_blocks = device->sector_count / MGFS_BLOCK_SECTORS;
    if (!calculate_mgfs_layout(total_blocks, &layout)) return false;

    for (u64 index = 0; index < layout.allocation_bitmap_blocks; index++) {
        u64 first_bit = index * MGFS_BITMAP_BITS_PER_BLOCK;
        u64 valid_bits = first_bit < layout.data_blocks
            ? layout.data_blocks - first_bit : 0ULL;
        if (valid_bits > MGFS_BITMAP_BITS_PER_BLOCK)
            valid_bits = MGFS_BITMAP_BITS_PER_BLOCK;
        memset(block, 0, sizeof(block));
        store_le64(block, MGFS_METADATA_ALLOCATION_BITMAP);
        store_le64(block + 8, index);
        memset(block + MGFS_BITMAP_HEADER_BYTES, 0xff,
               sizeof(block) - MGFS_BITMAP_HEADER_BYTES);
        for (u64 bit = 0; bit < valid_bits; bit++)
            block[MGFS_BITMAP_HEADER_BYTES + bit / 8ULL] &=
                (u8)~(1U << (bit % 8ULL));
        store_le64(block + 16, crc64(block, sizeof(block), 16U));
        if (layout.allocation_bitmap_start > ~(u64)0 - index ||
            !format_block_write(device, layout.allocation_bitmap_start + index,
                                block)) return false;
    }

    for (u64 index = 0; index < layout.record_bitmap_blocks; index++) {
        u64 first_bit = index * MGFS_BITMAP_BITS_PER_BLOCK;
        u64 valid_bits = first_bit < layout.record_count
            ? layout.record_count - first_bit : 0ULL;
        if (valid_bits > MGFS_BITMAP_BITS_PER_BLOCK)
            valid_bits = MGFS_BITMAP_BITS_PER_BLOCK;
        memset(block, 0, sizeof(block));
        store_le64(block, MGFS_METADATA_RECORD_BITMAP);
        store_le64(block + 8, index);
        memset(block + MGFS_BITMAP_HEADER_BYTES, 0xff,
               sizeof(block) - MGFS_BITMAP_HEADER_BYTES);
        for (u64 bit = 0; bit < valid_bits; bit++)
            block[MGFS_BITMAP_HEADER_BYTES + bit / 8ULL] &=
                (u8)~(1U << (bit % 8ULL));
        if (!index) block[MGFS_BITMAP_HEADER_BYTES] |= 1U;
        store_le64(block + 16, crc64(block, sizeof(block), 16U));
        if (layout.record_bitmap_start > ~(u64)0 - index ||
            !format_block_write(device, layout.record_bitmap_start + index,
                                block)) return false;
    }

    for (u64 index = 0; index < layout.record_table_blocks; index++) {
        memset(block, 0, sizeof(block));
        store_le64(block, MGFS_METADATA_RECORD_TABLE);
        store_le64(block + 8, index);
        if (!index) {
            u8 *root = block + MGFS_BITMAP_HEADER_BYTES;
            store_le64(root, MGFS_RECORD_DIRECTORY);
            store_le64(root + 8, root_flags);
            store_le64(root + 16, MGFS_ROOT_RECORD_ID);
            store_le64(root + 24, MGFS_INITIAL_GENERATION);
            store_le64(root + 184, crc64(root, MGFS_RECORD_BYTES, 184U));
        }
        store_le64(block + 16, crc64(block, sizeof(block), 16U));
        if (layout.record_table_start > ~(u64)0 - index ||
            !format_block_write(device, layout.record_table_start + index,
                                block)) return false;
    }

    memset(block, 0, sizeof(block));
    {
        static const u8 magic[8] = {'M','G','F','S','v','1',0,0};
        memcpy(block, magic, sizeof(magic));
        store_le64(block + 8, MGFS_FORMAT_MAJOR);
        store_le64(block + 16, MGFS_FORMAT_MINOR);
        store_le64(block + 24, MGFS_HEADER_BYTES);
        store_le64(block + 32, MGFS_BLOCK_BYTES);
        store_le64(block + 40, total_blocks);
        store_le64(block + 64, MGFS_STATE_CLEAN);
        store_le64(block + 88, MGFS_ROOT_RECORD_ID);
        store_le64(block + 96, MGFS_NEXT_RECORD_ID);
        store_le64(block + 104, layout.allocation_bitmap_start);
        store_le64(block + 112, layout.allocation_bitmap_blocks);
        store_le64(block + 120, layout.record_bitmap_start);
        store_le64(block + 128, layout.record_bitmap_blocks);
        store_le64(block + 136, layout.record_table_start);
        store_le64(block + 144, layout.record_table_blocks);
        store_le64(block + 152, layout.record_count);
        store_le64(block + 160, layout.data_start);
        store_le64(block + 168, layout.data_blocks);
        /* An empty label is represented by an all-zero optional extension. */
        store_le64(block + 192, crc64(block, MGFS_HEADER_BYTES, 192U));
    }
    if (!format_block_write(device, 0, block)) return false;
    if (layout.data_start > ~(u64)0 / MGFS_BLOCK_SECTORS) return false;
    return write_zero_sectors(device, layout.data_start * MGFS_BLOCK_SECTORS,
                              8ULL);
}

static u32 fat32_fat_size(u32 total_sectors, u32 sectors_per_cluster,
                          u64 *out_clusters)
{
    u64 fat_size = 1ULL;
    u64 clusters = 0;

    /* The integer equation can oscillate by one sector on small volumes:
     * calculating a smaller FAT exposes another cluster, which in turn
     * needs the larger FAT again.  Grow until the current FAT can hold all
     * entries for the geometry it creates; never select the smaller side. */
    for (u32 iteration = 0; iteration < 64U; iteration++) {
        u64 overhead = FAT32_RESERVED_SECTORS +
                       (u64)FAT32_FAT_COUNT * fat_size;
        u64 data_sectors;
        u64 next_size;
        if (overhead >= total_sectors) return 0;
        data_sectors = total_sectors - overhead;
        clusters = data_sectors / sectors_per_cluster;
        next_size = ((clusters + 2ULL) * 4ULL + FORMAT_SECTOR_BYTES - 1ULL) /
                    FORMAT_SECTOR_BYTES;
        if (next_size <= fat_size) {
            if (!clusters || clusters < FAT32_MIN_CLUSTERS ||
                clusters > FAT32_MAX_CLUSTERS || fat_size > 0xffffffffULL)
                return 0;
            if (out_clusters) *out_clusters = clusters;
            return (u32)fat_size;
        }
        fat_size = next_size;
    }
    return 0;
}

static bool format_fat32(block_device_t *device)
{
    u32 total_sectors;
    u32 sectors_per_cluster = 1U;
    u32 fat_size;
    u64 clusters = 0;
    u64 data_start;
    u8 sector[FORMAT_SECTOR_BYTES];
    u8 fsinfo[FORMAT_SECTOR_BYTES];

    if (!device || device->sector_size != FORMAT_SECTOR_BYTES ||
        device->sector_count > 0xffffffffULL || device->sector_count < 2ULL)
        return false;
    total_sectors = (u32)device->sector_count;
    for (;;) {
        fat_size = fat32_fat_size(total_sectors, sectors_per_cluster,
                                  &clusters);
        if (fat_size || sectors_per_cluster >= 64U) break;
        sectors_per_cluster <<= 1U;
    }
    if (!fat_size) return false;
    data_start = FAT32_RESERVED_SECTORS +
                 (u64)FAT32_FAT_COUNT * fat_size;
    if (data_start >= device->sector_count ||
        clusters > 0xffffffffULL || data_start + sectors_per_cluster >=
        device->sector_count) return false;

    memset(sector, 0, sizeof(sector));
    sector[0] = 0xeb; sector[1] = 0x58; sector[2] = 0x90;
    memcpy(sector + 3, "MANGROVE", 8);
    store_le16(sector + 11, FORMAT_SECTOR_BYTES);
    sector[13] = (u8)sectors_per_cluster;
    store_le16(sector + 14, FAT32_RESERVED_SECTORS);
    sector[16] = FAT32_FAT_COUNT;
    sector[21] = 0xf8;
    store_le16(sector + 24, FAT32_BPB_SECTORS_PER_TRACK);
    store_le16(sector + 26, FAT32_BPB_HEADS);
    store_le32(sector + 32, total_sectors);
    store_le32(sector + 36, fat_size);
    store_le32(sector + 44, 2U);
    store_le16(sector + 48, 1U);
    store_le16(sector + 50, 6U);
    sector[64] = 0x80;
    sector[66] = 0x29;
    store_le32(sector + 67, (u32)device->id);
    memcpy(sector + 71, "NO NAME    ", 11U);
    memcpy(sector + 82, "FAT32   ", 8U);
    sector[510] = 0x55; sector[511] = 0xaa;
    if (!format_write(device, 0, 1U, sector) ||
        !format_write(device, 6, 1U, sector)) return false;

    memset(fsinfo, 0, sizeof(fsinfo));
    store_le32(fsinfo, 0x41615252U);
    store_le32(fsinfo + 484, 0x61417272U);
    store_le32(fsinfo + 488, (u32)(clusters - 1ULL));
    store_le32(fsinfo + 492, 3U);
    store_le32(fsinfo + 508, 0xaa550000U);
    if (!format_write(device, 1, 1U, fsinfo) ||
        !format_write(device, 7, 1U, fsinfo)) return false;

    if (!write_zero_sectors(device, FAT32_RESERVED_SECTORS,
                            (u64)FAT32_FAT_COUNT * fat_size)) return false;
    memset(sector, 0, sizeof(sector));
    store_le32(sector, 0x0ffffff8U);
    store_le32(sector + 4, 0xffffffffU);
    store_le32(sector + 8, 0x0fffffffU);
    if (!format_write(device, FAT32_RESERVED_SECTORS, 1U, sector) ||
        !format_write(device, FAT32_RESERVED_SECTORS + fat_size, 1U, sector))
        return false;
    return write_zero_sectors(device, data_start, sectors_per_cluster);
}

static bool utf8_mgfs_label_valid(const char *label)
{
    usize length;
    usize offset = 0;
    u32 first = 0;
    u32 last = 0;
    bool content = false;

    if (!label || (length = strlen(label)) > MGFS_LABEL_BYTES) return false;
    if (!length) return true;
    while (offset < length) {
        u8 lead = (u8)label[offset++];
        u32 codepoint;
        u32 minimum;
        u32 count;
        if (lead < 0x80U) { codepoint = lead; minimum = 0; count = 1; }
        else if (lead >= 0xc2U && lead <= 0xdfU) {
            codepoint = lead & 0x1fU; minimum = 0x80U; count = 2;
        } else if (lead >= 0xe0U && lead <= 0xefU) {
            codepoint = lead & 0x0fU; minimum = 0x800U; count = 3;
        } else if (lead >= 0xf0U && lead <= 0xf4U) {
            codepoint = lead & 7U; minimum = 0x10000U; count = 4;
        } else return false;
        if (offset + count - 1U > length) return false;
        for (u32 index = 1U; index < count; index++) {
            u8 value = (u8)label[offset++];
            if ((value & 0xc0U) != 0x80U) return false;
            codepoint = (codepoint << 6U) | (value & 0x3fU);
        }
        if (codepoint < minimum || codepoint > 0x10ffffU ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU)) return false;
        if (codepoint < 0x20U || (codepoint >= 0x7fU && codepoint <= 0x9fU) ||
            (codepoint >= 0x1f000U && codepoint <= 0x1ffffU) ||
            (codepoint >= 0x2000U && codepoint <= 0x2fffU) ||
            (codepoint >= 0xfe00U && codepoint <= 0xfeffU) ||
            (codepoint >= 0xe0000U && codepoint <= 0xe0fffU) ||
            (codepoint >= 0x202aU && codepoint <= 0x202eU) ||
            (codepoint >= 0x2066U && codepoint <= 0x2069U)) return false;
        if (!first) first = codepoint;
        last = codepoint;
        if (codepoint != 0x20U && codepoint != 0xa0U &&
            !(codepoint >= 0x2000U && codepoint <= 0x200aU) &&
            codepoint != 0x2028U && codepoint != 0x2029U &&
            codepoint != 0x202fU && codepoint != 0x205fU &&
            codepoint != 0x3000U)
            content = true;
    }
    return content && first != 0x20U && first != 0xa0U &&
           !(first >= 0x2000U && first <= 0x200aU) &&
           first != 0x2028U && first != 0x2029U && first != 0x202fU &&
           first != 0x205fU && first != 0x3000U && last != 0x20U &&
           last != 0xa0U && !(last >= 0x2000U && last <= 0x200aU) &&
           last != 0x2028U && last != 0x2029U && last != 0x202fU &&
           last != 0x205fU && last != 0x3000U;
}

static bool format_label_mgfs(block_device_t *device, const char *label)
{
    u8 block[MGFS_BLOCK_BYTES];
    usize length;
    static const u8 magic[8] = {'M','G','L','A','B','E','L','1'};

    if (!utf8_mgfs_label_valid(label) || !format_read(device, 0, 8U, block))
        return false;
    memset(block + MGFS_LABEL_EXTENSION_OFFSET, 0,
           MGFS_LABEL_EXTENSION_BYTES);
    length = strlen(label);
    if (length) {
        memcpy(block + MGFS_LABEL_EXTENSION_OFFSET, magic, sizeof(magic));
        store_le64(block + MGFS_LABEL_LENGTH_OFFSET, length);
        memcpy(block + MGFS_LABEL_DATA_OFFSET, label, length);
        store_le64(block + MGFS_LABEL_CHECKSUM_OFFSET,
                   crc64(block + MGFS_LABEL_EXTENSION_OFFSET,
                         MGFS_LABEL_EXTENSION_BYTES, 80U));
    }
    return format_block_write(device, 0, block);
}

int storage_format_filesystem(block_device_t *device, const char *filesystem)
{
    bool result;
    int preflight;
    const char *probed;

    if (!device || !filesystem) return VFS_ERR_INVALID_PARAM;
    if (strcmp(filesystem, "fat32") != 0 && strcmp(filesystem, "mgfs") != 0 &&
        strcmp(filesystem, "exfat") != 0)
        return VFS_ERR_UNSUPPORTED;
    if (!block_device_is_live(device)) return VFS_ERR_DEVICE_GONE;
    if (device->read_only) return VFS_ERR_ACCESS_DENIED;
    preflight = vfs_format_preflight(device);
    if (preflight != VFS_OK) return preflight;
    if (!storage_mutation_begin()) return VFS_ERR_BUSY;
    result = strcmp(filesystem, "fat32") == 0
        ? format_fat32(device) : strcmp(filesystem, "mgfs") == 0
        ? format_mgfs(device) : exfat_format_device(device);
    if (result && block_device_is_live(device)) {
        result = block_flush(device);
        if (result && block_device_is_live(device)) {
            probed = vfs_probe_filesystem(device);
            result = probed && strcmp(probed, filesystem) == 0;
        }
    }
    storage_mutation_end();
    return result ? VFS_OK :
           (!block_device_is_live(device) ? VFS_ERR_DEVICE_GONE : VFS_ERR_IO);
}

int storage_set_filesystem_label(block_device_t *device,
                                 const char *filesystem,
                                 const char *label)
{
    bool result;
    int preflight;
    const char *probed;

    if (!device || !filesystem || !label) return VFS_ERR_INVALID_PARAM;
    if (strcmp(filesystem, "fat32") != 0 && strcmp(filesystem, "mgfs") != 0 &&
        strcmp(filesystem, "exfat") != 0)
        return VFS_ERR_UNSUPPORTED;
    if (!block_device_is_live(device)) return VFS_ERR_DEVICE_GONE;
    if (device->read_only) return VFS_ERR_ACCESS_DENIED;
    preflight = vfs_format_preflight(device);
    if (preflight != VFS_OK) return preflight;
    probed = vfs_probe_filesystem(device);
    if (!probed || strcmp(probed, filesystem) != 0)
        return VFS_ERR_BAD_FORMAT;
    if ((strcmp(filesystem, "fat32") == 0 && !fat32_label_valid(label)) ||
        (strcmp(filesystem, "mgfs") == 0 && !utf8_mgfs_label_valid(label)))
        return VFS_ERR_INVALID_PARAM;
    if (!storage_mutation_begin()) return VFS_ERR_BUSY;
    result = strcmp(filesystem, "fat32") == 0
        ? fat32_set_label(device, label)
        : strcmp(filesystem, "mgfs") == 0
        ? format_label_mgfs(device, label)
        : exfat_set_label(device, label);
    if (result) result = block_flush(device);
    if (result && block_device_is_live(device)) {
        char readback[64];
        probed = vfs_probe_filesystem(device);
        result = probed && strcmp(probed, filesystem) == 0;
        if (result && label[0]) {
            memset(readback, 0, sizeof(readback));
            result = vfs_filesystem_label(device, filesystem, readback,
                                          sizeof(readback)) &&
                     strcmp(readback, label) == 0;
        }
    }
    storage_mutation_end();
    return result ? VFS_OK :
           (!block_device_is_live(device) ? VFS_ERR_DEVICE_GONE : VFS_ERR_IO);
}
