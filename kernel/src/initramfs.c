/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <initramfs.h>
#include <heap.h>
#include <string.h>

#ifndef NULL
#define NULL ((void*)0)
#endif

typedef struct initramfs_entry {
    char name[256];
    vfs_node_type_t type;
    u64 size;
    const u8 *data;
    struct initramfs_entry *children;
    struct initramfs_entry *next;
} initramfs_entry_t;

typedef struct {
    initramfs_entry_t *root_entry;
} initramfs_fs_t;

static const vfs_ops_t initramfs_node_ops;
static const vfs_super_ops_t initramfs_super_ops;

static u64 initramfs_read(vfs_node_t *node, u64 offset, u64 size, void *buffer) {
    if (!node || !buffer || !node->fs_data) {
        return 0;
    }

    initramfs_entry_t *entry = (initramfs_entry_t *)node->fs_data;
    if (entry->type != VFS_TYPE_FILE || !entry->data) {
        return 0;
    }

    if (offset >= entry->size) {
        return 0;
    }

    u64 avail = entry->size - offset;
    if (size > avail) {
        size = avail;
    }

    memcpy(buffer, entry->data + offset, size);
    return size;
}

static vfs_node_t *initramfs_finddir(vfs_node_t *dir, const char *name) {
    if (!dir || !name || dir->type != VFS_TYPE_DIRECTORY || !dir->fs_data) {
        return NULL;
    }

    initramfs_entry_t *parent = (initramfs_entry_t *)dir->fs_data;
    initramfs_entry_t *child = parent->children;

    while (child) {
        if (strcmp(child->name, name) == 0) {
            vfs_node_t *node = (vfs_node_t *)kmalloc(sizeof(vfs_node_t));
            if (!node) {
                return NULL;
            }
            node->inode = (u64)child;
            node->type = child->type;
            node->size = child->size;
            vfs_node_set_security(node, VFS_UID_SYSTEM,
                                  VFS_DEFAULT_SYSTEM_PERMISSIONS);
            node->child_mutation_policy = VFS_CHILD_MUTATION_OPEN;
            node->ref_count = 1;
            node->super = dir->super;
            node->fs_data = child;
            node->ops = &initramfs_node_ops;
            vfs_node_register(node);
            return node;
        }
        child = child->next;
    }

    return NULL;
}

static bool initramfs_readdir(vfs_node_t *dir, u32 index, vfs_dirent_t *out_entry) {
    if (!dir || !out_entry || dir->type != VFS_TYPE_DIRECTORY || !dir->fs_data) {
        return false;
    }

    initramfs_entry_t *parent = (initramfs_entry_t *)dir->fs_data;
    initramfs_entry_t *child = parent->children;
    u32 curr = 0;

    while (child) {
        if (curr == index) {
            strncpy(out_entry->name, child->name, sizeof(out_entry->name) - 1);
            out_entry->name[sizeof(out_entry->name) - 1] = '\0';
            out_entry->inode = (u64)child;
            out_entry->type = child->type;
            return true;
        }
        curr++;
        child = child->next;
    }

    return false;
}

static const vfs_ops_t initramfs_node_ops = {
    .read = initramfs_read,
    .write = NULL,
    .finddir = initramfs_finddir,
    .readdir = initramfs_readdir,
    .readdir_open = NULL,
    .readdir_next = NULL,
    .readdir_close = NULL,
};

static int initramfs_unmount(vfs_super_t *sb) {
    if (!sb) return VFS_ERR_INVALID_PARAM;
    return VFS_OK;
}

static const vfs_super_ops_t initramfs_super_ops = {
    .unmount = initramfs_unmount,
    .sync = NULL,
};

static bool initramfs_probe(block_device_t *dev) {
    (void)dev;
    return true; // RAM filesystem recognizes RAM mounts
}

static const char test_welcome[] = "Welcome to Pith! The VFS and Initramfs are operational.\n";
static const char test_config[]  = "os=MangroveOS\nversion=0.1.1\narch=x86_64\n";

static int initramfs_mount(vfs_fs_type_t *fs_type, block_device_t *dev,
                           vfs_super_t **out_sb, bool read_only) {
    (void)dev;
    (void)read_only;
    if (!fs_type || !out_sb) {
        return VFS_ERR_INVALID_PARAM;
    }

    vfs_super_t *sb = (vfs_super_t *)kmalloc(sizeof(vfs_super_t));
    if (!sb) {
        return VFS_ERR_NO_MEM;
    }

    initramfs_fs_t *fs = (initramfs_fs_t *)kmalloc(sizeof(initramfs_fs_t));
    if (!fs) {
        return VFS_ERR_NO_MEM;
    }

    /* Build initial in-memory test entries */
    initramfs_entry_t *root_entry = (initramfs_entry_t *)kmalloc(sizeof(initramfs_entry_t));
    initramfs_entry_t *file_welcome = (initramfs_entry_t *)kmalloc(sizeof(initramfs_entry_t));
    initramfs_entry_t *file_config  = (initramfs_entry_t *)kmalloc(sizeof(initramfs_entry_t));

    if (!root_entry || !file_welcome || !file_config) {
        return VFS_ERR_NO_MEM;
    }

    /* Root directory */
    strcpy(root_entry->name, "");
    root_entry->type = VFS_TYPE_DIRECTORY;
    root_entry->size = 0;
    root_entry->data = NULL;
    root_entry->children = file_welcome;
    root_entry->next = NULL;

    /* /welcome.txt */
    strcpy(file_welcome->name, "welcome.txt");
    file_welcome->type = VFS_TYPE_FILE;
    file_welcome->size = sizeof(test_welcome) - 1;
    file_welcome->data = (const u8 *)test_welcome;
    file_welcome->children = NULL;
    file_welcome->next = file_config;

    /* /config.txt */
    strcpy(file_config->name, "config.txt");
    file_config->type = VFS_TYPE_FILE;
    file_config->size = sizeof(test_config) - 1;
    file_config->data = (const u8 *)test_config;
    file_config->children = NULL;
    file_config->next = NULL;

    fs->root_entry = root_entry;

    /* Create root vfs_node_t */
    vfs_node_t *root_node = (vfs_node_t *)kmalloc(sizeof(vfs_node_t));
    if (!root_node) {
        return VFS_ERR_NO_MEM;
    }

    root_node->inode = (u64)root_entry;
    root_node->type = VFS_TYPE_DIRECTORY;
    root_node->size = 0;
    vfs_node_set_security(root_node, VFS_UID_SYSTEM,
                          VFS_DEFAULT_SYSTEM_PERMISSIONS);
    root_node->child_mutation_policy = VFS_CHILD_MUTATION_OPEN;
    root_node->ref_count = 1;
    root_node->super = sb;
    root_node->fs_data = root_entry;
    root_node->ops = &initramfs_node_ops;

    sb->fs_type = fs_type;
    sb->dev = NULL;
    sb->root_node = root_node;
    sb->private_data = fs;
    sb->ops = &initramfs_super_ops;

    *out_sb = sb;
    return VFS_OK;
}

static vfs_fs_type_t initramfs_fs_type = {
    .name = "initramfs",
    .probe = initramfs_probe,
    .mount = initramfs_mount,
    .next = NULL,
};

int initramfs_init(void) {
    return vfs_register_fs(&initramfs_fs_type);
}
