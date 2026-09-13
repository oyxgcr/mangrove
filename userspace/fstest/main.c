/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <mangrove.h>
#include <stdio.h>
#include <string.h>

static int fail(const char *step)
{
    printf("fstest failed at step: %s\n", step);
    return 43;
}

int main(void)
{
    char cwd[256];
    usize cwd_size = 0;
    mg_path_info_t info;
    mg_directory_entry_t entry;
    mg_handle_t directory;
    mg_handle_t file;
    mg_result_t result;
    bool saw_hello = false;
    const char payload[] = "filesystem validation\n";

    if (process_getcwd(cwd, sizeof(cwd), &cwd_size) < 0 ||
        strcmp(cwd, "/") != 0 || cwd_size != 2) return fail("getcwd_root");

    if (path_info("/bin", &info) < 0 ||
        info.type != MG_PATH_TYPE_DIRECTORY) return fail("pathinfo_bin");

    result = directory_open("/bin");
    if (result < 0) return fail("diropen_bin");
    directory = (mg_handle_t)result;
    while (directory_read(directory, &entry) == MG_OK) {
        if (strcmp(entry.name, "hello") == 0 &&
            entry.type == MG_PATH_TYPE_FILE) saw_hello = true;
    }
    if (!saw_hello) return fail("read_bin_hello");
    if (handle_close(directory) < 0) return fail("close_bin_dir");

    result = file_create("/temp/fstest-persist");
    if (result != MG_OK && result != MG_ERR_ALREADY_EXISTS) return fail("create_temp_persist");
    if (path_info("/temp/fstest-persist", &info) != MG_OK ||
        info.type != MG_PATH_TYPE_FILE) return fail("info_temp_persist");

    if (directory_create("/temp/fstest-source") != MG_OK) return fail("mkdir_temp_source");
    if (directory_create("/temp/fstest-destination") != MG_OK) return fail("mkdir_temp_dest");
    if (path_info("/temp/fstest-source", &info) != MG_OK ||
        info.permissions != 0x7U) return fail("mkdir_default_permissions");
    if (directory_create("/temp/fstest-source") != MG_ERR_ALREADY_EXISTS) return fail("mkdir_temp_source_exists");

    result = directory_open("/temp/fstest-source");
    if (result < 0) return fail("diropen_temp_source");
    if (directory_read((mg_handle_t)result, &entry) != MG_ERR_END_OF_FILE) return fail("dirread_empty_source");
    if (handle_close((mg_handle_t)result) != MG_OK) return fail("dirclose_temp_source");

    if (process_chdir("/temp/fstest-source") != MG_OK) return fail("chdir_temp_source");
    if (file_create("./fstest-file") != MG_OK) return fail("create_relative_file");
    if (file_create("fstest-file") != MG_ERR_ALREADY_EXISTS) return fail("create_file_exists");

    result = file_open("fstest-file", MG_OPEN_WRITE);
    if (result < 0) return fail("open_file_write");
    file = (mg_handle_t)result;

    if (object_write_all(file, payload, sizeof(payload) - 1) != (mg_result_t)(sizeof(payload) - 1)) return fail("write_payload");
    if (file_truncate(file) != MG_OK) return fail("truncate_file");
    if (handle_close(file) != MG_OK) return fail("close_file");

    if (process_chdir("..") != MG_OK) return fail("chdir_up");
    if (path_move("fstest-source/fstest-file", "fstest-destination/renamed") != MG_OK) return fail("move_file");
    if (path_info("./fstest-destination/renamed", &info) != MG_OK) return fail("info_renamed");
    if (info.type != MG_PATH_TYPE_FILE || info.size != 0) return fail("verify_renamed_info");

    if (path_remove("fstest-destination") != MG_ERR_NOT_EMPTY) return fail("rmdir_not_empty");
    if (path_remove("fstest-destination/renamed") != MG_OK) return fail("rm_renamed");
    if (path_remove("fstest-source") != MG_OK) return fail("rm_source");
    if (path_remove("fstest-destination") != MG_OK) return fail("rm_dest");

    if (process_chdir("/") != MG_OK) return fail("chdir_root");
    if (path_remove("/") != MG_ERR_BAD_ARGUMENT) return fail("rm_root_bad_arg");

    puts("filesystem API validation passed");
    return 0;
}
