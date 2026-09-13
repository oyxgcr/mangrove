/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <mangrove.h>
#include <stdio.h>
#include "../common/help.h"
#include "../common/path.h"

int main(int argc, char **argv)
{
    char path[256];
    char buffer[512];
    mg_handle_t file;
    mg_result_t result;

    if (command_help_requested(argc, argv))
        return command_print_help(argv[0]);
    if (argc != 2) {
        command_usage_error(argv[0], "type <file>",
                            argc > 1 && argv[1][0] == '-' ? argv[1] : NULL);
        return 1;
    }
    if (!command_resolve_path(argv[1], path, sizeof(path))) {
        printf("Could not read \"%s\": invalid path.\n", argv[1]);
        return 1;
    }
    result = file_open(path, MG_OPEN_READ);
    if (result_is_error(result)) {
        printf("Could not read \"%s\": %s.\n", argv[1], error_string(result));
        return 1;
    }
    file = (mg_handle_t)result;
    if (console_begin_transaction() != MG_OK) {
        (void)handle_close(file);
        printf("Could not read \"%s\": console unavailable.\n", argv[1]);
        return 1;
    }
    for (;;) {
        result = object_read(file, buffer, sizeof(buffer) - 1);
        if (result == MG_ERR_END_OF_FILE || result == 0) break;
        if (result_is_error(result)) {
            (void)console_end_transaction();
            printf("\nRead error: %s.\n", error_string(result));
            (void)handle_close(file);
            return 1;
        }
        buffer[result] = '\0';
        if (printf("%s", buffer) < 0) {
            (void)console_end_transaction();
            (void)handle_close(file);
            return 1;
        }
    }
    if (console_end_transaction() != MG_OK) {
        (void)handle_close(file);
        return 1;
    }
    (void)handle_close(file);
    return 0;
}
