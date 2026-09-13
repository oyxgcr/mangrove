/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define MGFS_BLOCK_BYTES                 UINT64_C(4096)
#define MGFS_FORMAT_MAJOR                UINT64_C(1)
#define MGFS_FORMAT_MINOR                UINT64_C(2)
#define MGFS_HEADER_BYTES                UINT64_C(200)
#define MGFS_RECORD_BYTES                UINT64_C(192)
#define MGFS_RECORDS_PER_TABLE_BLOCK     UINT64_C(21)
#define MGFS_BITMAP_HEADER_BYTES         UINT64_C(24)
#define MGFS_BITMAP_BITS_PER_BLOCK       UINT64_C(32576)
#define MGFS_MIN_TOTAL_BLOCKS            UINT64_C(64)
#define MGFS_TABLE_BLOCKS_DIVISOR        UINT64_C(320)
#define MGFS_UUID_BYTES                  16U
#define MGFS_ROOT_RECORD_ID              UINT64_C(1)
#define MGFS_NEXT_RECORD_ID              UINT64_C(2)
#define MGFS_INITIAL_GENERATION          UINT64_C(1)

#define MGFS_STATE_CLEAN                 UINT64_C(0x0000000000000001)

#define MGFS_METADATA_ALLOCATION_BITMAP  UINT64_C(1)
#define MGFS_METADATA_RECORD_BITMAP      UINT64_C(2)
#define MGFS_METADATA_RECORD_TABLE       UINT64_C(3)

#define MGFS_RECORD_DIRECTORY            UINT64_C(2)
#define MGFS_ROOT_RECORD_FLAGS           (UINT64_C(7) << 33)

#define MGFS_CRC64_POLYNOMIAL            UINT64_C(0x42F0E1EBA9EA3693)

#define SUPER_MAGIC_OFFSET               0U
#define SUPER_FORMAT_MAJOR_OFFSET        8U
#define SUPER_FORMAT_MINOR_OFFSET        16U
#define SUPER_HEADER_BYTES_OFFSET        24U
#define SUPER_BLOCK_BYTES_OFFSET         32U
#define SUPER_TOTAL_BLOCKS_OFFSET        40U
#define SUPER_FEATURE_COMPAT_OFFSET      48U
#define SUPER_FEATURE_INCOMPAT_OFFSET    56U
#define SUPER_STATE_FLAGS_OFFSET         64U
#define SUPER_UUID_OFFSET                72U
#define SUPER_ROOT_RECORD_ID_OFFSET      88U
#define SUPER_NEXT_RECORD_ID_OFFSET      96U
#define SUPER_ALLOC_BITMAP_START_OFFSET  104U
#define SUPER_ALLOC_BITMAP_COUNT_OFFSET  112U
#define SUPER_RECORD_BITMAP_START_OFFSET 120U
#define SUPER_RECORD_BITMAP_COUNT_OFFSET 128U
#define SUPER_RECORD_TABLE_START_OFFSET  136U
#define SUPER_RECORD_TABLE_COUNT_OFFSET  144U
#define SUPER_RECORD_COUNT_OFFSET        152U
#define SUPER_DATA_START_OFFSET          160U
#define SUPER_DATA_COUNT_OFFSET          168U
#define SUPER_FORMAT_TIME_OFFSET         176U
#define SUPER_LAST_MOUNT_TIME_OFFSET     184U
#define SUPER_CHECKSUM_OFFSET            192U
#define SUPER_LABEL_EXTENSION_OFFSET     200U
#define SUPER_LABEL_LENGTH_OFFSET        208U
#define SUPER_LABEL_DATA_OFFSET          216U
#define SUPER_LABEL_CHECKSUM_OFFSET      280U
#define SUPER_LABEL_BYTES                63U
#define SUPER_LABEL_EXTENSION_BYTES      88U

#define METADATA_KIND_OFFSET             0U
#define METADATA_REGION_INDEX_OFFSET     8U
#define METADATA_CHECKSUM_OFFSET         16U

#define RECORD_TYPE_OFFSET               0U
#define RECORD_ID_OFFSET                 16U
#define RECORD_GENERATION_OFFSET         24U
#define RECORD_CHECKSUM_OFFSET           184U

typedef struct {
    uint64_t allocation_bitmap_start;
    uint64_t allocation_bitmap_blocks;
    uint64_t record_bitmap_start;
    uint64_t record_bitmap_blocks;
    uint64_t record_table_start;
    uint64_t record_table_blocks;
    uint64_t record_count;
    uint64_t data_start;
    uint64_t data_blocks;
} mgfs_layout_t;

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s --blocks <total_blocks> --uuid <canonical-uuid> "
            "--format-time-ns <u64> <image-path> [--label <label>]\n",
            program);
}

static bool label_codepoint_allowed(uint32_t codepoint)
{
    if (codepoint < 0x20U || (codepoint >= 0x7fU && codepoint <= 0x9fU))
        return false;
    if (codepoint < 0x80U) {
        return (codepoint >= 'A' && codepoint <= 'Z') ||
               (codepoint >= 'a' && codepoint <= 'z') ||
               (codepoint >= '0' && codepoint <= '9') ||
               codepoint == ' ' || codepoint == '_' || codepoint == '-' ||
               codepoint == '.';
    }
    /* Keep filesystem labels human-readable and path-safe without placing a
     * Unicode category database in the kernel or image.  Letter/digit scripts
     * remain accepted; symbols, emoji, bidi and formatting ranges do not. */
    if ((codepoint >= 0xa0U && codepoint <= 0xbfU) ||
        (codepoint >= 0x2000U && codepoint <= 0x2fffU) ||
        (codepoint >= 0x1f000U && codepoint <= 0x1ffffU) ||
        (codepoint >= 0xfe00U && codepoint <= 0xfeffU) ||
        (codepoint >= 0xe0000U && codepoint <= 0xe0fffU) ||
        (codepoint >= 0x202aU && codepoint <= 0x202eU) ||
        (codepoint >= 0x2066U && codepoint <= 0x2069U)) return false;
    return true;
}

static bool label_whitespace(uint32_t codepoint)
{
    return codepoint == 0x20U || codepoint == 0xa0U ||
           (codepoint >= 0x2000U && codepoint <= 0x200aU) ||
           codepoint == 0x2028U || codepoint == 0x2029U ||
           codepoint == 0x202fU || codepoint == 0x205fU ||
           codepoint == 0x3000U;
}

static bool valid_label(const char *label)
{
    size_t length;
    size_t offset = 0;
    uint32_t first = 0;
    uint32_t last = 0;
    bool content = false;

    if (!label || (length = strlen(label)) > SUPER_LABEL_BYTES) return false;
    if (!length) return true;
    while (offset < length) {
        uint8_t lead = (uint8_t)label[offset++];
        uint32_t codepoint;
        uint32_t minimum;
        unsigned count;

        if (lead < 0x80U) {
            codepoint = lead;
            count = 1U;
            minimum = 0;
        } else if (lead >= 0xc2U && lead <= 0xdfU) {
            codepoint = lead & 0x1fU;
            count = 2U;
            minimum = 0x80U;
        } else if (lead >= 0xe0U && lead <= 0xefU) {
            codepoint = lead & 0x0fU;
            count = 3U;
            minimum = 0x800U;
        } else if (lead >= 0xf0U && lead <= 0xf4U) {
            codepoint = lead & 0x07U;
            count = 4U;
            minimum = 0x10000U;
        } else {
            return false;
        }
        if (offset + count - 1U > length) return false;
        for (unsigned index = 1U; index < count; index++) {
            uint8_t continuation = (uint8_t)label[offset++];
            if ((continuation & 0xc0U) != 0x80U) return false;
            codepoint = (codepoint << 6) | (continuation & 0x3fU);
        }
        if (codepoint < minimum || codepoint > 0x10ffffU ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU) ||
            !label_codepoint_allowed(codepoint)) return false;
        if (!first) first = codepoint;
        last = codepoint;
        if (!label_whitespace(codepoint)) content = true;
    }
    return content && !label_whitespace(first) && !label_whitespace(last);
}

static bool parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    if (!text || text[0] == '-' || text[0] == '\0') {
        return false;
    }

    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        return false;
    }

    *value = (uint64_t)parsed;
    return true;
}

static int hex_value(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    return -1;
}

static bool parse_uuid(const char *text, uint8_t uuid[MGFS_UUID_BYTES])
{
    static const unsigned int hyphen_offsets[] = { 8U, 13U, 18U, 23U };
    unsigned int source = 0;
    unsigned int destination = 0;

    if (!text || strlen(text) != 36U) {
        return false;
    }

    for (source = 0; source < 36U; source++) {
        bool hyphen = false;
        for (unsigned int i = 0; i < 4U; i++) {
            if (source == hyphen_offsets[i]) {
                hyphen = true;
                break;
            }
        }

        if (hyphen) {
            if (text[source] != '-') {
                return false;
            }
            continue;
        }

        if (hex_value(text[source]) < 0) {
            return false;
        }
    }

    for (source = 0; source < 36U;) {
        int high;
        int low;

        if (text[source] == '-') {
            source++;
            continue;
        }

        high = hex_value(text[source++]);
        low = hex_value(text[source++]);
        uuid[destination++] = (uint8_t)((high << 4) | low);
    }

    return destination == MGFS_UUID_BYTES;
}

static void put_le64(uint8_t *destination, uint64_t value)
{
    for (unsigned int i = 0; i < 8U; i++) {
        destination[i] = (uint8_t)(value >> (i * 8U));
    }
}

static uint64_t crc64_ecma182(const uint8_t *data, size_t length)
{
    uint64_t crc = 0;

    for (size_t byte = 0; byte < length; byte++) {
        crc ^= (uint64_t)data[byte] << 56U;
        for (unsigned int bit = 0; bit < 8U; bit++) {
            crc = (crc & (UINT64_C(1) << 63U))
                ? (crc << 1U) ^ MGFS_CRC64_POLYNOMIAL
                : (crc << 1U);
        }
    }

    return crc;
}

static uint64_t ceil_div_u64(uint64_t dividend, uint64_t divisor)
{
    return (dividend / divisor) + ((dividend % divisor) != 0U);
}

static bool calculate_layout(uint64_t total_blocks, mgfs_layout_t *layout)
{
    uint64_t table_blocks;
    uint64_t record_count;
    uint64_t record_bitmap_blocks;
    uint64_t allocation_bitmap_blocks;
    uint64_t metadata_blocks;

    if (total_blocks < MGFS_MIN_TOTAL_BLOCKS) {
        return false;
    }

    table_blocks = total_blocks / MGFS_TABLE_BLOCKS_DIVISOR;
    if (table_blocks == 0U) {
        table_blocks = 1U;
    }
    if (table_blocks > UINT64_MAX / MGFS_RECORDS_PER_TABLE_BLOCK) {
        return false;
    }

    record_count = table_blocks * MGFS_RECORDS_PER_TABLE_BLOCK;
    record_bitmap_blocks = ceil_div_u64(record_count, MGFS_BITMAP_BITS_PER_BLOCK);
    allocation_bitmap_blocks = ceil_div_u64(total_blocks, MGFS_BITMAP_BITS_PER_BLOCK);

    if (allocation_bitmap_blocks > UINT64_MAX - 1U ||
        record_bitmap_blocks > UINT64_MAX - 1U - allocation_bitmap_blocks ||
        table_blocks > UINT64_MAX - 1U - allocation_bitmap_blocks - record_bitmap_blocks) {
        return false;
    }

    metadata_blocks = 1U + allocation_bitmap_blocks + record_bitmap_blocks + table_blocks;
    if (metadata_blocks >= total_blocks) {
        return false;
    }

    layout->allocation_bitmap_start = 1U;
    layout->allocation_bitmap_blocks = allocation_bitmap_blocks;
    layout->record_bitmap_start = layout->allocation_bitmap_start + allocation_bitmap_blocks;
    layout->record_bitmap_blocks = record_bitmap_blocks;
    layout->record_table_start = layout->record_bitmap_start + record_bitmap_blocks;
    layout->record_table_blocks = table_blocks;
    layout->record_count = record_count;
    layout->data_start = layout->record_table_start + table_blocks;
    layout->data_blocks = total_blocks - layout->data_start;
    return true;
}

static bool write_exact_block(int fd, uint64_t block_number, const uint8_t block[MGFS_BLOCK_BYTES])
{
    uint64_t byte_offset = block_number * MGFS_BLOCK_BYTES;
    size_t completed = 0;

    if (byte_offset > (uint64_t)INT64_MAX) {
        return false;
    }

    while (completed < (size_t)MGFS_BLOCK_BYTES) {
        ssize_t written = pwrite(fd, block + completed,
                                 (size_t)MGFS_BLOCK_BYTES - completed,
                                 (off_t)(byte_offset + completed));
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (written == 0) {
            return false;
        }
        completed += (size_t)written;
    }

    return true;
}

static void finalize_metadata_checksum(uint8_t block[MGFS_BLOCK_BYTES])
{
    put_le64(block + METADATA_CHECKSUM_OFFSET, 0U);
    put_le64(block + METADATA_CHECKSUM_OFFSET, crc64_ecma182(block, (size_t)MGFS_BLOCK_BYTES));
}

static void initialize_bitmap_block(
    uint8_t block[MGFS_BLOCK_BYTES],
    uint64_t kind,
    uint64_t region_index,
    uint64_t valid_bits,
    bool reserve_first_bit)
{
    memset(block, 0, (size_t)MGFS_BLOCK_BYTES);
    put_le64(block + METADATA_KIND_OFFSET, kind);
    put_le64(block + METADATA_REGION_INDEX_OFFSET, region_index);

    memset(block + MGFS_BITMAP_HEADER_BYTES, 0xff,
           (size_t)(MGFS_BLOCK_BYTES - MGFS_BITMAP_HEADER_BYTES));
    for (uint64_t bit = 0; bit < valid_bits; bit++) {
        size_t byte_index = (size_t)(MGFS_BITMAP_HEADER_BYTES + (bit / 8U));
        block[byte_index] &= (uint8_t)~(UINT8_C(1) << (bit % 8U));
    }

    if (reserve_first_bit) {
        block[MGFS_BITMAP_HEADER_BYTES] |= UINT8_C(1);
    }

    finalize_metadata_checksum(block);
}

static bool write_bitmaps(int fd, const mgfs_layout_t *layout)
{
    uint8_t block[MGFS_BLOCK_BYTES];

    for (uint64_t index = 0; index < layout->allocation_bitmap_blocks; index++) {
        uint64_t first_bit = index * MGFS_BITMAP_BITS_PER_BLOCK;
        uint64_t valid_bits = 0;

        if (first_bit < layout->data_blocks) {
            uint64_t remaining = layout->data_blocks - first_bit;
            valid_bits = remaining < MGFS_BITMAP_BITS_PER_BLOCK
                ? remaining : MGFS_BITMAP_BITS_PER_BLOCK;
        }

        initialize_bitmap_block(block, MGFS_METADATA_ALLOCATION_BITMAP, index, valid_bits, false);
        if (!write_exact_block(fd, layout->allocation_bitmap_start + index, block)) {
            return false;
        }
    }

    for (uint64_t index = 0; index < layout->record_bitmap_blocks; index++) {
        uint64_t first_bit = index * MGFS_BITMAP_BITS_PER_BLOCK;
        uint64_t valid_bits = 0;

        if (first_bit < layout->record_count) {
            uint64_t remaining = layout->record_count - first_bit;
            valid_bits = remaining < MGFS_BITMAP_BITS_PER_BLOCK
                ? remaining : MGFS_BITMAP_BITS_PER_BLOCK;
        }

        initialize_bitmap_block(block, MGFS_METADATA_RECORD_BITMAP, index, valid_bits, index == 0U);
        if (!write_exact_block(fd, layout->record_bitmap_start + index, block)) {
            return false;
        }
    }

    return true;
}

static bool write_record_table(int fd, const mgfs_layout_t *layout)
{
    uint8_t block[MGFS_BLOCK_BYTES];

    for (uint64_t index = 0; index < layout->record_table_blocks; index++) {
        memset(block, 0, (size_t)MGFS_BLOCK_BYTES);
        put_le64(block + METADATA_KIND_OFFSET, MGFS_METADATA_RECORD_TABLE);
        put_le64(block + METADATA_REGION_INDEX_OFFSET, index);

        if (index == 0U) {
            uint8_t *root_record = block + MGFS_BITMAP_HEADER_BYTES;

            put_le64(root_record + RECORD_TYPE_OFFSET, MGFS_RECORD_DIRECTORY);
            put_le64(root_record + 8U, MGFS_ROOT_RECORD_FLAGS);
            put_le64(root_record + RECORD_ID_OFFSET, MGFS_ROOT_RECORD_ID);
            put_le64(root_record + RECORD_GENERATION_OFFSET, MGFS_INITIAL_GENERATION);
            put_le64(root_record + RECORD_CHECKSUM_OFFSET, 0U);
            put_le64(root_record + RECORD_CHECKSUM_OFFSET,
                     crc64_ecma182(root_record, (size_t)MGFS_RECORD_BYTES));
        }

        finalize_metadata_checksum(block);
        if (!write_exact_block(fd, layout->record_table_start + index, block)) {
            return false;
        }
    }

    return true;
}

static bool write_superblock(
    int fd,
    uint64_t total_blocks,
    const uint8_t uuid[MGFS_UUID_BYTES],
    uint64_t format_time_ns,
    const mgfs_layout_t *layout,
    const char *label)
{
    uint8_t block[MGFS_BLOCK_BYTES];
    static const uint8_t magic[8] = { 'M', 'G', 'F', 'S', 'v', '1', 0, 0 };

    memset(block, 0, (size_t)MGFS_BLOCK_BYTES);
    memcpy(block + SUPER_MAGIC_OFFSET, magic, sizeof(magic));
    put_le64(block + SUPER_FORMAT_MAJOR_OFFSET, MGFS_FORMAT_MAJOR);
    put_le64(block + SUPER_FORMAT_MINOR_OFFSET, MGFS_FORMAT_MINOR);
    put_le64(block + SUPER_HEADER_BYTES_OFFSET, MGFS_HEADER_BYTES);
    put_le64(block + SUPER_BLOCK_BYTES_OFFSET, MGFS_BLOCK_BYTES);
    put_le64(block + SUPER_TOTAL_BLOCKS_OFFSET, total_blocks);
    put_le64(block + SUPER_FEATURE_COMPAT_OFFSET, 0U);
    put_le64(block + SUPER_FEATURE_INCOMPAT_OFFSET, 0U);
    put_le64(block + SUPER_STATE_FLAGS_OFFSET, MGFS_STATE_CLEAN);
    memcpy(block + SUPER_UUID_OFFSET, uuid, MGFS_UUID_BYTES);
    put_le64(block + SUPER_ROOT_RECORD_ID_OFFSET, MGFS_ROOT_RECORD_ID);
    put_le64(block + SUPER_NEXT_RECORD_ID_OFFSET, MGFS_NEXT_RECORD_ID);
    put_le64(block + SUPER_ALLOC_BITMAP_START_OFFSET, layout->allocation_bitmap_start);
    put_le64(block + SUPER_ALLOC_BITMAP_COUNT_OFFSET, layout->allocation_bitmap_blocks);
    put_le64(block + SUPER_RECORD_BITMAP_START_OFFSET, layout->record_bitmap_start);
    put_le64(block + SUPER_RECORD_BITMAP_COUNT_OFFSET, layout->record_bitmap_blocks);
    put_le64(block + SUPER_RECORD_TABLE_START_OFFSET, layout->record_table_start);
    put_le64(block + SUPER_RECORD_TABLE_COUNT_OFFSET, layout->record_table_blocks);
    put_le64(block + SUPER_RECORD_COUNT_OFFSET, layout->record_count);
    put_le64(block + SUPER_DATA_START_OFFSET, layout->data_start);
    put_le64(block + SUPER_DATA_COUNT_OFFSET, layout->data_blocks);
    put_le64(block + SUPER_FORMAT_TIME_OFFSET, format_time_ns);
    put_le64(block + SUPER_LAST_MOUNT_TIME_OFFSET, 0U);
    if (label && label[0]) {
        static const uint8_t label_magic[8] = {
            'M', 'G', 'L', 'A', 'B', 'E', 'L', '1'
        };
        size_t label_length = strlen(label);
        memcpy(block + SUPER_LABEL_EXTENSION_OFFSET,
               label_magic, sizeof(label_magic));
        put_le64(block + SUPER_LABEL_LENGTH_OFFSET, label_length);
        memcpy(block + SUPER_LABEL_DATA_OFFSET, label, label_length);
        put_le64(block + SUPER_LABEL_CHECKSUM_OFFSET, 0U);
        put_le64(block + SUPER_LABEL_CHECKSUM_OFFSET,
                 crc64_ecma182(block + SUPER_LABEL_EXTENSION_OFFSET,
                               SUPER_LABEL_EXTENSION_BYTES));
    }
    put_le64(block + SUPER_CHECKSUM_OFFSET, 0U);
    put_le64(block + SUPER_CHECKSUM_OFFSET,
             crc64_ecma182(block, (size_t)MGFS_HEADER_BYTES));

    return write_exact_block(fd, 0U, block);
}

int main(int argc, char **argv)
{
    uint64_t total_blocks;
    uint64_t format_time_ns;
    uint64_t image_bytes;
    uint8_t uuid[MGFS_UUID_BYTES];
    mgfs_layout_t layout;
    int fd;
    int result = EXIT_FAILURE;
    const char *label = "";

    if ((argc != 8 && argc != 10) || strcmp(argv[1], "--blocks") != 0 ||
        strcmp(argv[3], "--uuid") != 0 ||
        strcmp(argv[5], "--format-time-ns") != 0 ||
        (argc == 10 && strcmp(argv[8], "--label") != 0)) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (argc == 10) label = argv[9];

    if (!parse_u64(argv[2], &total_blocks) ||
        !parse_uuid(argv[4], uuid) ||
        !parse_u64(argv[6], &format_time_ns) ||
        !valid_label(label) ||
        !calculate_layout(total_blocks, &layout) ||
        total_blocks > (uint64_t)INT64_MAX / MGFS_BLOCK_BYTES) {
        fprintf(stderr, "mkmgfs: invalid format parameters\n");
        return EXIT_FAILURE;
    }

    image_bytes = total_blocks * MGFS_BLOCK_BYTES;
    fd = open(argv[7], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("mkmgfs: open");
        return EXIT_FAILURE;
    }

    if (ftruncate(fd, (off_t)image_bytes) != 0) {
        perror("mkmgfs: resize");
        goto out;
    }

    if (!write_bitmaps(fd, &layout) ||
        !write_record_table(fd, &layout) ||
        !write_superblock(fd, total_blocks, uuid, format_time_ns, &layout,
                          label)) {
        perror("mkmgfs: write");
        goto out;
    }

    if (fsync(fd) != 0) {
        perror("mkmgfs: sync");
        goto out;
    }

    result = EXIT_SUCCESS;

out:
    if (close(fd) != 0 && result == EXIT_SUCCESS) {
        perror("mkmgfs: close");
        result = EXIT_FAILURE;
    }
    return result;
}
