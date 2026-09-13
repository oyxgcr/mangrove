/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <mangrove.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/help.h"
#include "../common/path.h"

#define LS_COLUMN_GAP 2U
#define LS_INITIAL_CAPACITY MG_DIRECTORY_BATCH_MAX
#define LS_PATH_CAPACITY 512U
#define LS_TREE_PREFIX_CAPACITY 128U
#define LS_MAX_TREE_DEPTH 16U
#define LS_MAX_TREE_ENTRIES 4096U
#define LS_OWNER_CAPACITY (MG_IDENTITY_USERNAME_CAPACITY + 12U)
#define LS_SIZE_CAPACITY 32U

typedef struct {
    mg_directory_entry_t entry;
    mg_path_info_t info;
    char owner[LS_OWNER_CAPACITY];
    char permissions[6];
    char size[LS_SIZE_CAPACITY];
    char tree_prefix[LS_TREE_PREFIX_CAPACITY];
    usize display_width;
    bool has_info;
} ls_entry_t;

typedef struct {
    bool long_listing;
    bool tree;
    usize tree_depth;
    const char *path;
} ls_options_t;

static bool needs_directory_suffix(const ls_entry_t *entry,
                                   bool styled_output)
{
    return entry && !styled_output &&
           entry->entry.type == MG_PATH_TYPE_DIRECTORY &&
           strcmp(entry->entry.name, "/") != 0;
}

static usize entry_display_width(const ls_entry_t *entry, bool styled_output)
{
    usize width;

    if (!entry) return 0;
    width = strlen(entry->entry.name);
    if (needs_directory_suffix(entry, styled_output)) width++;
    return width;
}

static bool copy_string(char *destination, usize capacity,
                        const char *source)
{
    usize length;

    if (!destination || !source || capacity == 0U) return false;
    length = strlen(source);
    if (length >= capacity) return false;
    memcpy(destination, source, length + 1U);
    return true;
}

static bool join_path(const char *base, const char *name,
                      char *output, usize capacity)
{
    usize base_length;
    usize name_length;
    bool root;

    if (!base || !name || !output || capacity == 0U) return false;
    base_length = strlen(base);
    name_length = strlen(name);
    root = base_length == 1U && base[0] == '/';
    if (root) {
        if (name_length + 2U > capacity) return false;
        output[0] = '/';
        memcpy(output + 1, name, name_length + 1U);
        return true;
    }
    if (base_length == 0U || base_length + 1U > (usize)-1 - name_length ||
        base_length + name_length + 2U > capacity) return false;
    memcpy(output, base, base_length);
    output[base_length] = '/';
    memcpy(output + base_length + 1U, name, name_length + 1U);
    return true;
}

static bool append_entry(ls_entry_t **entries, usize *count,
                         usize *capacity, const ls_entry_t *entry)
{
    usize required;

    if (!entries || !count || !capacity || !entry) return false;
    if (*count == LS_MAX_TREE_ENTRIES || *count == (usize)-1) return false;
    required = *count + 1U;
    if (required > *capacity) {
        usize new_capacity = *capacity ? *capacity : LS_INITIAL_CAPACITY;
        ls_entry_t *replacement;

        while (new_capacity < required) {
            if (new_capacity > (usize)-1 / 2U) {
                new_capacity = required;
                break;
            }
            new_capacity *= 2U;
        }
        if (new_capacity > (usize)-1 / sizeof(**entries)) return false;
        replacement = (ls_entry_t *)realloc(
            *entries, new_capacity * sizeof(**entries));
        if (!replacement) return false;
        *entries = replacement;
        *capacity = new_capacity;
    }
    (*entries)[*count] = *entry;
    *count = required;
    return true;
}

static usize layout_rows(usize count, usize columns)
{
    return count / columns + (count % columns != 0U);
}

static usize layout_used_columns(usize count, usize columns)
{
    usize rows = layout_rows(count, columns);

    return count / rows + (count % rows != 0U);
}

static usize layout_column_width(const ls_entry_t *entries, usize count,
                                 usize columns, usize column)
{
    usize rows = layout_rows(count, columns);
    usize width = 0;

    for (usize row = 0; row < rows; row++) {
        usize index = column * rows + row;

        if (index >= count) continue;
        if (entries[index].display_width > width)
            width = entries[index].display_width;
    }
    return width;
}

static bool layout_fits(const ls_entry_t *entries, usize count,
                        usize columns, usize terminal_width)
{
    usize total = 0;
    usize used_columns = layout_used_columns(count, columns);

    for (usize column = 0; column < used_columns; column++) {
        usize width = layout_column_width(entries, count, columns, column);

        if (column && total > (usize)-1 - LS_COLUMN_GAP) return false;
        if (column) total += LS_COLUMN_GAP;
        if (total > (usize)-1 - width) return false;
        total += width;
        if (total > terminal_width) return false;
    }
    return true;
}

static usize choose_columns(const ls_entry_t *entries, usize count,
                            usize terminal_width)
{
    usize maximum;
    usize columns;

    if (!entries || !count || !terminal_width) return 1U;
    maximum = count;
    if (terminal_width <= (usize)-1 - LS_COLUMN_GAP) {
        usize width_limited =
            (terminal_width + LS_COLUMN_GAP) / (1U + LS_COLUMN_GAP);

        if (width_limited < maximum) maximum = width_limited;
    }
    if (!maximum) maximum = 1U;
    columns = maximum;
    for (;;) {
        if (layout_fits(entries, count, columns, terminal_width))
            return layout_used_columns(count, columns);
        if (columns == 1U) return 1U;
        columns--;
    }
}

static bool write_spaces(usize count)
{
    static const char spaces[] =
        "                                ";

    while (count) {
        usize chunk = count < sizeof(spaces) - 1U ? count :
                      sizeof(spaces) - 1U;

        if (console_write(spaces, chunk) != (mg_result_t)chunk) return false;
        count -= chunk;
    }
    return true;
}

static bool write_string(const char *text)
{
    usize length;

    if (!text) return false;
    length = strlen(text);
    return console_write(text, length) == (mg_result_t)length;
}

static bool write_name(const ls_entry_t *entry, bool styled_output)
{
    char display[sizeof(entry->entry.name) + 2U];
    usize length;
    mg_result_t result;

    if (!entry) return false;
    length = strlen(entry->entry.name);
    memcpy(display, entry->entry.name, length);
    if (needs_directory_suffix(entry, styled_output))
        display[length++] = '/';
    result = styled_output
        ? terminal_write_semantic(
              display, length,
              entry->entry.type == MG_PATH_TYPE_DIRECTORY
                  ? MG_TERMINAL_STYLE_DIRECTORY : MG_TERMINAL_STYLE_DEFAULT)
        : console_write(display, length);
    return result == (mg_result_t)length;
}

static bool write_aligned_field(const char *text, usize width,
                                bool right_aligned)
{
    usize length;

    if (!text) return false;
    length = strlen(text);
    if (length > width) return false;
    if (right_aligned && !write_spaces(width - length)) return false;
    if (!write_string(text)) return false;
    if (!right_aligned && !write_spaces(width - length)) return false;
    return true;
}

static bool fill_owner(const mg_path_info_t *info,
                       const mg_account_info_t *accounts, usize account_count,
                       char *output, usize capacity)
{
    if (!info || !output || capacity == 0U) return false;
    if (info->owner_uid == MG_UID_SYSTEM)
        return copy_string(output, capacity, "system");
    for (usize index = 0; index < account_count; index++) {
        if (accounts[index].uid == info->owner_uid)
            return copy_string(output, capacity, accounts[index].username);
    }
    return snprintf(output, capacity, "%u", info->owner_uid) >= 0 &&
           strlen(output) < capacity;
}

static bool fill_metadata(ls_entry_t *entry, const char *path,
                          const mg_account_info_t *accounts,
                          usize account_count)
{
    mg_result_t result;
    u32 permissions;

    if (!entry || !path) return false;
    result = path_info(path, &entry->info);
    if (result_is_error(result)) return false;
    entry->has_info = true;
    entry->entry.type = entry->info.type;
    permissions = entry->info.permissions & MG_PERMISSION_KNOWN;
    entry->permissions[0] = (permissions & MG_PERMISSION_OWNER_READ) ? 'r' : '-';
    entry->permissions[1] = (permissions & MG_PERMISSION_OWNER_WRITE) ? 'w' : '-';
    entry->permissions[2] = ':';
    entry->permissions[3] = (permissions & MG_PERMISSION_OTHER_READ) ? 'r' : '-';
    entry->permissions[4] = (permissions & MG_PERMISSION_OTHER_WRITE) ? 'w' : '-';
    entry->permissions[5] = '\0';
    if (!fill_owner(&entry->info, accounts, account_count,
                    entry->owner, sizeof(entry->owner))) return false;
    if (entry->info.type == MG_PATH_TYPE_DIRECTORY) {
        if (!copy_string(entry->size, sizeof(entry->size), "-")) return false;
    } else {
        if (snprintf(entry->size, sizeof(entry->size), "%llu",
                     entry->info.size) < 0 ||
            strlen(entry->size) >= sizeof(entry->size)) return false;
    }
    return true;
}

static bool load_accounts(mg_account_info_t *accounts, usize *count)
{
    mg_result_t result;

    if (!accounts || !count) return false;
    *count = 0;
    result = account_list(accounts, MG_ACCOUNT_MAX_RECORDS, count);
    return !result_is_error(result);
}

static mg_result_t collect_directory(const char *path, bool need_info,
                                     bool styled_output,
                                     const mg_account_info_t *accounts,
                                     usize account_count,
                                     ls_entry_t **entries, usize *count,
                                     usize *capacity)
{
    mg_handle_t directory;
    mg_directory_entry_t *batch;
    mg_result_t result;

    if (!path || !entries || !count || !capacity) return MG_ERR_BAD_ARGUMENT;
    result = directory_open(path);
    if (result_is_error(result)) return result;
    directory = (mg_handle_t)result;
    batch = (mg_directory_entry_t *)malloc(
        MG_DIRECTORY_BATCH_MAX * sizeof(*batch));
    if (!batch) {
        (void)handle_close(directory);
        return MG_ERR_NO_MEMORY;
    }
    for (;;) {
        usize batch_count = 0;

        result = directory_read_batch(directory, batch,
                                      MG_DIRECTORY_BATCH_MAX, &batch_count);
        if (result == MG_ERR_END_OF_FILE) break;
        if (result_is_error(result)) {
            (void)handle_close(directory);
            free(batch);
            return result;
        }
        for (usize index = 0; index < batch_count; index++) {
            char child_path[LS_PATH_CAPACITY];
            ls_entry_t entry = {0};

            entry.entry = batch[index];
            if (!join_path(path, entry.entry.name, child_path,
                           sizeof(child_path)) ||
                (need_info && !fill_metadata(&entry, child_path, accounts,
                                              account_count))) {
                (void)handle_close(directory);
                free(batch);
                return MG_ERR_IO;
            }
            entry.display_width = entry_display_width(&entry, styled_output);
            if (!append_entry(entries, count, capacity, &entry)) {
                (void)handle_close(directory);
                free(batch);
                return MG_ERR_NO_MEMORY;
            }
        }
    }
    (void)handle_close(directory);
    free(batch);
    return MG_OK;
}

static bool render_columns(const ls_entry_t *entries, usize count,
                           usize terminal_width, bool styled_output)
{
    usize columns;
    usize rows;
    usize *widths;
    bool success = true;

    if (!count) return true;
    columns = choose_columns(entries, count, terminal_width);
    rows = layout_rows(count, columns);
    if (columns > (usize)-1 / sizeof(*widths)) return false;
    widths = (usize *)calloc(columns, sizeof(*widths));
    if (!widths) return false;
    for (usize column = 0; column < columns; column++)
        widths[column] = layout_column_width(entries, count, columns, column);

    if (console_begin_transaction() != MG_OK) {
        free(widths);
        return false;
    }
    for (usize row = 0; row < rows && success; row++) {
        usize last_column = 0;
        bool have_entry = false;

        for (usize column = 0; column < columns; column++) {
            if (column * rows + row < count) {
                last_column = column;
                have_entry = true;
            }
        }
        if (!have_entry) continue;
        for (usize column = 0; column <= last_column; column++) {
            usize index = column * rows + row;

            if (index >= count) continue;
            if (!write_name(&entries[index], styled_output)) {
                success = false;
                break;
            }
            if (column != last_column &&
                !write_spaces(widths[column] - entries[index].display_width +
                              LS_COLUMN_GAP)) {
                success = false;
                break;
            }
        }
        if (success && console_write("\n", 1U) != 1) success = false;
    }
    if (console_end_transaction() != MG_OK) success = false;
    free(widths);
    return success;
}

static bool render_long(const ls_entry_t *entries, usize count,
                        bool styled_output)
{
    usize owner_width = 0;
    usize size_width = 0;
    bool success = true;

    for (usize index = 0; index < count; index++) {
        usize owner_length = strlen(entries[index].owner);
        usize size_length = strlen(entries[index].size);

        if (owner_length > owner_width) owner_width = owner_length;
        if (size_length > size_width) size_width = size_length;
    }
    if (console_begin_transaction() != MG_OK) return false;
    for (usize index = 0; index < count && success; index++) {
        const ls_entry_t *entry = &entries[index];
        char type = entry->entry.type == MG_PATH_TYPE_DIRECTORY ? 'd' :
                    entry->entry.type == MG_PATH_TYPE_FILE ? 'f' : '?';

        if (console_write(&type, 1U) != 1 || !write_spaces(1U) ||
            !write_string(entry->permissions) || !write_spaces(1U) ||
            !write_aligned_field(entry->owner, owner_width, false) ||
            !write_spaces(1U) ||
            !write_aligned_field(entry->size, size_width, true) ||
            !write_spaces(1U) || !write_string(entry->tree_prefix) ||
            !write_name(entry, styled_output) || console_write("\n", 1U) != 1)
            success = false;
    }
    if (console_end_transaction() != MG_OK) success = false;
    return success;
}

static bool render_tree(const ls_entry_t *entries, usize count,
                        bool styled_output)
{
    bool success = true;

    if (console_begin_transaction() != MG_OK) return false;
    for (usize index = 0; index < count && success; index++) {
        if (!write_string(entries[index].tree_prefix) ||
            !write_name(&entries[index], styled_output) ||
            console_write("\n", 1U) != 1) success = false;
    }
    if (console_end_transaction() != MG_OK) success = false;
    return success;
}

static bool append_tree_row(ls_entry_t **rows, usize *row_count,
                            usize *row_capacity, const ls_entry_t *source,
                            const char *prefix)
{
    ls_entry_t row;

    if (!source || !prefix) return false;
    row = *source;
    if (!copy_string(row.tree_prefix, sizeof(row.tree_prefix), prefix))
        return false;
    return append_entry(rows, row_count, row_capacity, &row);
}

static mg_result_t collect_tree(const char *path, usize remaining_depth,
                                const char *indent, bool need_info,
                                bool styled_output,
                                const mg_account_info_t *accounts,
                                usize account_count, ls_entry_t **rows,
                                usize *row_count, usize *row_capacity)
{
    ls_entry_t *children = NULL;
    usize child_count = 0;
    usize child_capacity = 0;
    mg_result_t result;

    if (remaining_depth == 0U) return MG_OK;
    result = collect_directory(path, need_info, styled_output, accounts,
                               account_count, &children, &child_count,
                               &child_capacity);
    if (result_is_error(result)) {
        free(children);
        return result;
    }
    for (usize index = 0; index < child_count; index++) {
        char prefix[LS_TREE_PREFIX_CAPACITY];
        char child_indent[LS_TREE_PREFIX_CAPACITY];
        char child_path[LS_PATH_CAPACITY];
        usize indent_length = strlen(indent);
        usize branch_length;
        usize continuation_length;
        bool last = index + 1U == child_count;
        const char *branch = last ? "└── " : "├── ";
        const char *continuation = last ? "    " : "│   ";

        branch_length = strlen(branch);
        continuation_length = strlen(continuation);
        if (indent_length + branch_length >= sizeof(prefix) ||
            indent_length + continuation_length >= sizeof(child_indent)) {
            free(children);
            return MG_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(prefix, indent, indent_length);
        memcpy(prefix + indent_length, branch, branch_length + 1U);
        memcpy(child_indent, indent, indent_length);
        memcpy(child_indent + indent_length, continuation,
               continuation_length + 1U);
        if (!append_tree_row(rows, row_count, row_capacity,
                             &children[index], prefix)) {
            free(children);
            return MG_ERR_NO_MEMORY;
        }
        if (remaining_depth > 1U &&
            children[index].entry.type == MG_PATH_TYPE_DIRECTORY) {
            if (!join_path(path, children[index].entry.name, child_path,
                           sizeof(child_path))) {
                free(children);
                return MG_ERR_BUFFER_TOO_SMALL;
            }
            result = collect_tree(child_path, remaining_depth - 1U,
                                  child_indent, need_info, styled_output,
                                  accounts, account_count, rows, row_count,
                                  row_capacity);
            if (result == MG_ERR_ACCESS_DENIED) {
                /* The child remains visible, but its contents are not. */
                continue;
            }
            if (result_is_error(result)) {
                free(children);
                return result;
            }
        }
    }
    free(children);
    return MG_OK;
}

static bool parse_depth(const char *text, usize *depth)
{
    usize value = 0;

    if (!text || !*text || !depth) return false;
    for (const char *cursor = text; *cursor; cursor++) {
        usize digit;

        if (*cursor < '0' || *cursor > '9') return false;
        digit = (usize)(*cursor - '0');
        if (value > ((usize)-1 - digit) / 10U) return false;
        value = value * 10U + digit;
        if (value > LS_MAX_TREE_DEPTH) return false;
    }
    if (value == 0U) return false;
    *depth = value;
    return true;
}

static bool parse_options(int argc, char **argv, ls_options_t *options,
                          const char **bad_option)
{
    bool path_seen = false;

    if (!options || !bad_option) return false;
    options->long_listing = false;
    options->tree = false;
    options->tree_depth = 0;
    options->path = ".";
    *bad_option = NULL;
    for (int index = 1; index < argc; index++) {
        const char *argument = argv[index];

        if (!argument || argument[0] != '-' || argument[1] == '\0') {
            if (path_seen) {
                *bad_option = argument;
                return false;
            }
            options->path = argument;
            path_seen = true;
            continue;
        }
        if (!strcmp(argument, "--long")) {
            options->long_listing = true;
            continue;
        }
        if (!strcmp(argument, "--tree")) {
            if (index + 1 >= argc ||
                !parse_depth(argv[++index], &options->tree_depth)) {
                *bad_option = index < argc ? argv[index] : argument;
                return false;
            }
            options->tree = true;
            continue;
        }
        if (argument[1] == '-') {
            *bad_option = argument;
            return false;
        }
        for (usize option_index = 1; argument[option_index]; option_index++) {
            char option = argument[option_index];

            if (option == 'l') {
                options->long_listing = true;
                continue;
            }
            if (option == 't') {
                if (argument[option_index + 1] != '\0' || index + 1 >= argc ||
                    !parse_depth(argv[++index], &options->tree_depth)) {
                    *bad_option = index < argc ? argv[index] : argument;
                    return false;
                }
                options->tree = true;
                break;
            }
            *bad_option = argument;
            return false;
        }
    }
    return true;
}

static bool make_target_entry(const char *path, const mg_path_info_t *info,
                              const mg_account_info_t *accounts,
                              usize account_count, ls_entry_t *entry)
{
    const char *name = path;

    if (!path || !info || !entry) return false;
    memset(entry, 0, sizeof(*entry));
    for (const char *cursor = path; *cursor; cursor++)
        if (*cursor == '/' && cursor[1]) name = cursor + 1;
    if (name == path && path[0] == '/') name = "/";
    if (!copy_string(entry->entry.name, sizeof(entry->entry.name), name))
        return false;
    entry->entry.type = info->type;
    entry->entry.identifier = info->identifier;
    return fill_metadata(entry, path, accounts, account_count);
}

int main(int argc, char **argv)
{
    char path[LS_PATH_CAPACITY];
    const char *bad_option;
    mg_path_info_t target_info;
    mg_account_info_t *accounts = NULL;
    usize account_count = 0;
    ls_options_t options;
    ls_entry_t *entries = NULL;
    usize entry_count = 0;
    usize entry_capacity = 0;
    usize terminal_width = 1U;
    mg_terminal_size_t terminal_size = {0};
    mg_terminal_capabilities_t terminal_capabilities = {0};
    bool styled_output;
    mg_result_t result;

    if (command_help_requested(argc, argv))
        return command_print_help(argv[0]);
    if (!parse_options(argc, argv, &options, &bad_option)) {
        command_usage_error(argv[0],
                            "ls [-l|--long] [-t|--tree DEPTH] [path]",
                            bad_option);
        return 1;
    }
    styled_output = terminal_get_capabilities(&terminal_capabilities) == MG_OK &&
        (terminal_capabilities.capabilities & MG_TERMINAL_CAP_STYLED_OUTPUT) != 0;
    if (!command_resolve_path(options.path, path, sizeof(path))) {
        printf("Could not list \"%s\": invalid path.\n", options.path);
        return 1;
    }
    result = path_info(path, &target_info);
    if (result_is_error(result)) {
        printf("Could not list \"%s\": %s.\n", options.path,
               error_string(result));
        return 1;
    }
    if (options.long_listing) {
        accounts = (mg_account_info_t *)malloc(
            MG_ACCOUNT_MAX_RECORDS * sizeof(*accounts));
        if (accounts && !load_accounts(accounts, &account_count))
            account_count = 0;
    }
    if (target_info.type == MG_PATH_TYPE_FILE) {
        ls_entry_t target;

        if (!make_target_entry(path, &target_info, accounts, account_count,
                               &target)) {
            printf("Could not list \"%s\": metadata unavailable.\n",
                   options.path);
            free(accounts);
            return 1;
        }
        target.display_width = entry_display_width(&target, styled_output);
        if (!append_entry(&entries, &entry_count, &entry_capacity, &target)) {
            free(entries);
            free(accounts);
            return 1;
        }
    } else if (target_info.type == MG_PATH_TYPE_DIRECTORY) {
        if (options.tree) {
            ls_entry_t root;

            if (!make_target_entry(path, &target_info, accounts, account_count,
                                   &root) ||
                !append_tree_row(&entries, &entry_count, &entry_capacity,
                                 &root, "")) {
                printf("Could not list \"%s\": metadata unavailable.\n",
                       options.path);
                free(entries);
                free(accounts);
                return 1;
            }
            result = collect_tree(path, options.tree_depth, "",
                                  options.long_listing, styled_output,
                                  accounts, account_count, &entries,
                                  &entry_count, &entry_capacity);
            if (result_is_error(result)) {
                printf("Could not list \"%s\": %s.\n", options.path,
                       error_string(result));
                free(entries);
                free(accounts);
                return 1;
            }
        } else {
            result = collect_directory(path, options.long_listing,
                                       styled_output, accounts, account_count,
                                       &entries, &entry_count, &entry_capacity);
            if (result_is_error(result)) {
                printf("Could not list \"%s\": %s.\n", options.path,
                       error_string(result));
                free(entries);
                free(accounts);
                return 1;
            }
        }
    } else {
        printf("Could not list \"%s\": unsupported file type.\n",
               options.path);
        free(accounts);
        return 1;
    }

    if (!options.long_listing && !options.tree &&
        terminal_get_size(&terminal_size) == MG_OK && terminal_size.columns)
        terminal_width = terminal_size.columns;
    if (options.long_listing)
        result = render_long(entries, entry_count, styled_output) ? MG_OK :
                 MG_ERR_IO;
    else if (options.tree)
        result = render_tree(entries, entry_count, styled_output) ? MG_OK :
                 MG_ERR_IO;
    else
        result = render_columns(entries, entry_count, terminal_width,
                                styled_output) ? MG_OK : MG_ERR_IO;
    free(entries);
    free(accounts);
    if (result != MG_OK) {
        printf("Could not write directory listing.\n");
        return 1;
    }
    return 0;
}
