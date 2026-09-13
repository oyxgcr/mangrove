/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <types.h>
#include <block.h>
#include <mutex.h>
#include <identity.h>

#define VFS_OK                    0
#define VFS_ERR_INVALID_PARAM   (-1)
#define VFS_ERR_NOT_FOUND       (-2)
#define VFS_ERR_IO              (-3)
#define VFS_ERR_NO_MEM          (-4)
#define VFS_ERR_BAD_FORMAT      (-5)
#define VFS_ERR_UNSUPPORTED     (-6)
#define VFS_ERR_NOT_EMPTY       (-7)
#define VFS_ERR_ACCESS_DENIED   (-8)
#define VFS_ERR_NOT_DIRECTORY   (-9)
#define VFS_ERR_BUSY           (-10)
#define VFS_ERR_DEVICE_GONE   (-11)
#define VFS_ERR_NO_SPACE       (-12)

#define VFS_ERR_ALREADY_EXISTS (-13)

#define VFS_UID_SYSTEM          0U

#define VFS_PERMISSION_OWNER_READ   (1U << 0)
#define VFS_PERMISSION_OWNER_WRITE  (1U << 1)
#define VFS_PERMISSION_OTHER_READ   (1U << 2)
#define VFS_PERMISSION_OTHER_WRITE  (1U << 3)
#define VFS_PERMISSION_KNOWN        (VFS_PERMISSION_OWNER_READ | \
                                     VFS_PERMISSION_OWNER_WRITE | \
                                     VFS_PERMISSION_OTHER_READ | \
                                     VFS_PERMISSION_OTHER_WRITE)

/* Access requests use operation bits; stored permissions use owner/other
 * bits above. */
#define VFS_ACCESS_READ          (1U << 0)
#define VFS_ACCESS_WRITE         (1U << 1)
#define VFS_ACCESS_READ_WRITE    (VFS_ACCESS_READ | VFS_ACCESS_WRITE)

#define VFS_DEFAULT_SYSTEM_PERMISSIONS \
    (VFS_PERMISSION_OWNER_READ | VFS_PERMISSION_OWNER_WRITE | \
     VFS_PERMISSION_OTHER_READ)
#define VFS_DEFAULT_USER_PERMISSIONS \
    (VFS_PERMISSION_OWNER_READ | VFS_PERMISSION_OWNER_WRITE)

/* Creation defaults are independent of the permissions on the containing
 * directory.  The legacy names above remain for explicit system/user paths. */
#define VFS_DEFAULT_FILE_PERMISSIONS VFS_DEFAULT_SYSTEM_PERMISSIONS
#define VFS_DEFAULT_DIRECTORY_PERMISSIONS VFS_DEFAULT_SYSTEM_PERMISSIONS

typedef enum {
    VFS_CHILD_MUTATION_OPEN = 0,
    VFS_CHILD_MUTATION_OWNER_RESTRICTED,
} vfs_child_mutation_policy_t;

#define VFS_OPEN_READ            0x0001U
#define VFS_OPEN_WRITE           0x0002U
#define VFS_OPEN_RDWR            (VFS_OPEN_READ | VFS_OPEN_WRITE)

#define VFS_SEEK_SET             0
#define VFS_SEEK_CUR             1
#define VFS_SEEK_END             2

#define VFS_MAX_MOUNTS 32
#define VFS_DIRECTORY_BATCH_MAX 32U
#define VFS_MOUNT_PATH_MAX 256U

typedef enum {
    VFS_TYPE_UNKNOWN = 0,
    VFS_TYPE_FILE,
    VFS_TYPE_DIRECTORY,
} vfs_node_type_t;

typedef struct {
    char name[256];
    u64 inode;
    vfs_node_type_t type;
} vfs_dirent_t;

typedef struct vfs_node vfs_node_t;
typedef struct vfs_super vfs_super_t;
typedef struct vfs_fs_type vfs_fs_type_t;
typedef struct vfs_file_handle vfs_file_handle_t;

typedef enum {
    VFS_MOUNT_ROLE_ROOT = 0,
    VFS_MOUNT_ROLE_BOOT,
    VFS_MOUNT_ROLE_VOLUME,
} vfs_mount_role_t;

typedef enum {
    VFS_SUPER_ACTIVE = 0,
    VFS_SUPER_DETACHING,
    VFS_SUPER_DEAD,
} vfs_super_state_t;

/* Authorization carried by one kernel-side file handle.  These scopes are
 * deliberately not process credentials or persistent object metadata. */
typedef enum {
    VFS_AUTH_NONE = 0,
    VFS_AUTH_CONFIGURATION_WRITE,
    VFS_AUTH_REGULAR_USER_DATA,
} vfs_authorization_scope_t;

/* Node Operations Table */
typedef struct {
    u64 (*read)(vfs_node_t *node, u64 offset, u64 size, void *buffer);
    u64 (*write)(vfs_node_t *node, u64 offset, u64 size, const void *buffer);
    vfs_node_t *(*finddir)(vfs_node_t *dir, const char *name);
    bool (*readdir)(vfs_node_t *dir, u32 index, vfs_dirent_t *out_entry);
    /* Optional per-open sequential enumeration. */
    bool (*readdir_open)(vfs_node_t *dir, void **out_state);
    bool (*readdir_next)(void *state, vfs_dirent_t *out_entry);
    void (*readdir_close)(void *state);
    int (*create)(vfs_node_t *dir, const char *name, vfs_node_t **out_node);
    int (*mkdir)(vfs_node_t *dir, const char *name, vfs_node_t **out_node);
    /* Trusted kernel creation path with explicit security metadata. */
    int (*create_owned)(vfs_node_t *dir, const char *name, u32 owner_uid,
                        u32 permissions, vfs_node_t **out_node);
    int (*mkdir_owned)(vfs_node_t *dir, const char *name, u32 owner_uid,
                       u32 permissions, vfs_node_t **out_node);
    int (*unlink)(vfs_node_t *dir, const char *name);
    int (*rmdir)(vfs_node_t *dir, const char *name);
    int (*rename)(vfs_node_t *src_dir, const char *src_name,
                  vfs_node_t *dst_dir, const char *dst_name);
    int (*truncate)(vfs_node_t *node);
} vfs_ops_t;

/* Superblock Operations Table */
typedef struct {
    int (*unmount)(vfs_super_t *sb);
    int (*sync)(vfs_super_t *sb);
} vfs_super_ops_t;

/* Filesystem Instance (Superblock) */
struct vfs_super {
    vfs_fs_type_t *fs_type;       // Pointer to driver plugin
    block_device_t *dev;          // Associated block device (or NULL for RAM)
    vfs_node_t *root_node;        // Root directory node of this instance
    void *private_data;           // Driver-private superblock state
    const vfs_super_ops_t *ops;   // Instance operations
    u64 device_id;                // Immutable backing block-device identity
    u32 reference_count;          // Open file/directory objects
    vfs_super_state_t state;
    vfs_node_t *nodes;            // Nodes retained for safe dead-state retargeting
    /* Serializes complete filesystem operations that may sleep in block I/O. */
    mutex_t operation_lock;
    bool dispose_pending;
};

/* Filesystem Driver Registration Plugin (Static Kernel Lifetime) */
struct vfs_fs_type {
    const char *name;             // Driver plugin name, e.g. "fat32"
    bool (*probe)(block_device_t *dev);
    /* Optional bounded metadata read used by inspection/policy services. */
    bool (*label)(block_device_t *dev, char *out, usize capacity);
    int (*mount)(vfs_fs_type_t *fs_type, block_device_t *dev,
                 vfs_super_t **out_sb, bool read_only);
    vfs_fs_type_t *next;
};

/* Inode / Metadata Node */
struct vfs_node {
    u64 inode;
    vfs_node_type_t type;
    u64 size;
    u32 owner_uid;
    u32 permissions;
    /* Meaningful only for directories. */
    vfs_child_mutation_policy_t child_mutation_policy;
    u32 ref_count;
    vfs_super_t *super;           // Owning superblock instance
    void *fs_data;                // Driver-private node state
    const vfs_ops_t *ops;
    vfs_node_t *next_in_super;    // Kernel lifetime list for teardown retargeting
};

/* Kernel-side open instance; this is not a process file descriptor. */
struct vfs_file_handle {
    vfs_node_t *node;
    vfs_super_t *super;
    u64 offset;
    u32 flags;
    u32 valid;
    /* A single open instance may be shared by duplicated kernel objects. */
    mutex_t offset_lock;
    /* Narrow, kernel-created authorization bound to this exact node. */
    u32 authorized_access;
    vfs_authorization_scope_t authorization_scope;
    u32 authorization_owner_uid;
};

/* Node-based Mount Entry */
typedef struct {
    vfs_super_t *sb;             // Mounted filesystem instance
    vfs_node_t *covered_node;    // Directory node covered by this mount (NULL for root "/")
    vfs_super_t *covered_super;  // Stable identity of covered_node's filesystem
    u64 covered_inode;           // Stable identity of covered_node within that FS
    vfs_super_t *parent_super;   // Parent directory identity for virtual mounts
    u64 parent_inode;
    block_device_t *dev;
    u64 dev_id;                   // Immutable backing device identity
    vfs_mount_role_t role;
    bool read_only;
    char mount_point[VFS_MOUNT_PATH_MAX];
    char name[VFS_MOUNT_PATH_MAX];
    bool active;                 // Slot active flag
} vfs_mount_t;

/* VFS Initialization & Mount Management API */
void vfs_init(void);
int vfs_register_fs(vfs_fs_type_t *fs_type);
vfs_fs_type_t *vfs_find_fs(const char *name);
/* Probe only the currently supported on-disk filesystem drivers.  This is a
 * read-only kernel helper; it never mounts or changes a device. */
const char *vfs_probe_filesystem(block_device_t *dev);
bool vfs_filesystem_label(block_device_t *dev, const char *fs_name,
                          char *out, usize capacity);

int vfs_mount_root(const char *fs_name, block_device_t *dev);
int vfs_mount_node(vfs_node_t *target_node, const char *fs_name, block_device_t *dev);
/* Mount at an existing directory or at a runtime-only child mount point.
 * The latter is used for /vol/<name> without persisting fake MGFS entries. */
int vfs_mount_path(vfs_node_t *parent, const char *name,
                   const char *mount_point, const char *fs_name,
                   block_device_t *dev, vfs_mount_role_t role,
                   bool read_only);
int vfs_unmount_sb(vfs_super_t *sb);
int vfs_unmount_device(block_device_t *device);
int vfs_unmount_device_preflight(block_device_t *device);
int vfs_unmount_devices(block_device_t *devices[], u32 count);
int vfs_unmount_devices_preflight(block_device_t *devices[], u32 count);
/* Formatting is permitted only when no live mount or VFS reference can
 * still issue filesystem I/O against the exact device instance. */
int vfs_format_preflight(block_device_t *device);
/* Mandatory device-loss notification; unlike unmount, it cannot fail or
 * wait for user references because the hardware is already gone. */
void vfs_device_removed(block_device_t *device);
bool vfs_super_is_live(const vfs_super_t *sb);
bool vfs_node_is_live(const vfs_node_t *node);
bool vfs_super_retain(vfs_super_t *sb);
void vfs_super_release(vfs_super_t *sb);
void vfs_node_register(vfs_node_t *node);
/* Pin a node's live superblock before calling a filesystem operation. */
bool vfs_node_retain_super(vfs_node_t *node, vfs_super_t **out_super);
/* The caller must hold a superblock reference while using these helpers. */
bool vfs_super_operation_lock(vfs_super_t *sb);
void vfs_super_operation_unlock(vfs_super_t *sb);

vfs_node_t *vfs_get_root_node(void);
vfs_mount_t *vfs_find_mount_for_node(vfs_node_t *node);
bool vfs_mount_point_for_device(block_device_t *device, char *out_path,
                                usize capacity, vfs_mount_role_t *out_role);
/* A directory with a runtime child mount must use VFS enumeration so the
 * synthetic child is visible alongside its persistent entries. */
bool vfs_directory_has_mount_children(vfs_node_t *dir);

/* Mount-Aware Path Resolution API */
int vfs_lookup(const char *path, vfs_node_t **out_node);
int vfs_resolve_path(const char *cwd, const char *input_path, char *out_buf, usize out_size);
int vfs_open(const char *path, u32 flags, vfs_file_handle_t **out_handle);
int vfs_open_node(vfs_node_t *node, u32 flags, vfs_file_handle_t **out_handle);
int vfs_open_node_authorized(vfs_node_t *node, u32 flags,
                             vfs_file_handle_t **out_handle);
int vfs_open_node_user_authorized(vfs_node_t *node, u32 flags,
                                  vfs_file_handle_t **out_handle);
int vfs_truncate_handle(vfs_file_handle_t *handle);
int vfs_close(vfs_file_handle_t *handle);
u64 vfs_file_read(vfs_file_handle_t *handle, u64 size, void *buffer);
u64 vfs_file_write(vfs_file_handle_t *handle, u64 size, const void *buffer);
int vfs_seek(vfs_file_handle_t *handle, i64 offset, int whence, u64 *out_offset);

/* Authorization is centralized here so all filesystem implementations and
 * userspace entry points apply the same owner/other policy. */
bool vfs_check_access(const vfs_node_t *node, u32 permission);
bool vfs_current_uid(u32 *out_uid);
void vfs_node_set_security(vfs_node_t *node, u32 owner_uid, u32 permissions);
void vfs_node_set_child_mutation_policy(
    vfs_node_t *node, vfs_child_mutation_policy_t child_mutation_policy);
bool vfs_directory_child_mutation_allowed(const vfs_node_t *dir,
                                          const vfs_node_t *child);
/* True only for a human administrator acting on a live regular-user-owned
 * object with persistent MGFS security metadata. */
bool vfs_administrator_override_allowed(
    const vfs_node_t *node, const process_credentials_t *credentials);

/* Core Node-level VFS Operations */
int vfs_create(vfs_node_t *dir, const char *name, vfs_node_t **out_node);
int vfs_mkdir(vfs_node_t *dir, const char *name, vfs_node_t **out_node);
int vfs_unlink(vfs_node_t *dir, const char *name);
int vfs_rmdir(vfs_node_t *dir, const char *name);
int vfs_rename(vfs_node_t *src_dir, const char *src_name,
               vfs_node_t *dst_dir, const char *dst_name);
int vfs_truncate(vfs_node_t *node);
u64 vfs_read(vfs_node_t *node, u64 offset, u64 size, void *buffer);
u64 vfs_write(vfs_node_t *node, u64 offset, u64 size, const void *buffer);
vfs_node_t *vfs_finddir(vfs_node_t *dir, const char *name);
bool vfs_readdir(vfs_node_t *dir, u32 index, vfs_dirent_t *out_entry);

/* Kernel-internal operations for managed system state.  These deliberately
 * bypass the current process credentials and are not exposed through libc. */
int vfs_lookup_trusted(const char *path, vfs_node_t **out_node);
int vfs_open_trusted(const char *path, u32 flags,
                     vfs_file_handle_t **out_handle);
u64 vfs_file_read_trusted(vfs_file_handle_t *handle, u64 size, void *buffer);
u64 vfs_file_write_trusted(vfs_file_handle_t *handle, u64 size,
                           const void *buffer);
int vfs_close_trusted(vfs_file_handle_t *handle);
int vfs_truncate_trusted(vfs_node_t *node);
int vfs_create_owned(vfs_node_t *dir, const char *name, u32 owner_uid,
                     u32 permissions, vfs_node_t **out_node);
int vfs_mkdir_owned(vfs_node_t *dir, const char *name, u32 owner_uid,
                    u32 permissions, vfs_node_t **out_node);
int vfs_unlink_trusted(vfs_node_t *dir, const char *name);
int vfs_rmdir_trusted(vfs_node_t *dir, const char *name);
int vfs_rename_trusted(vfs_node_t *src_dir, const char *src_name,
                       vfs_node_t *dst_dir, const char *dst_name);
/* Name-based mutation with an already-resolved stable object identity. */
int vfs_unlink_expected(vfs_node_t *dir, const char *name,
                        vfs_super_t *expected_super, u64 expected_inode);
/* Used only after a separate, object-bound administrator authorization has
 * been validated by the syscall layer. */
int vfs_unlink_expected_authorized(vfs_node_t *dir, const char *name,
                                   vfs_super_t *expected_super,
                                   u64 expected_inode);
int vfs_rmdir_expected(vfs_node_t *dir, const char *name,
                       vfs_super_t *expected_super, u64 expected_inode);
int vfs_rmdir_expected_authorized(vfs_node_t *dir, const char *name,
                                  vfs_super_t *expected_super,
                                  u64 expected_inode);
int vfs_rename_expected(vfs_node_t *src_dir, const char *src_name,
                        vfs_super_t *expected_super, u64 expected_inode,
                        vfs_node_t *dst_dir, const char *dst_name);
int vfs_rename_expected_authorized(
    vfs_node_t *src_dir, const char *src_name,
    vfs_super_t *expected_super, u64 expected_inode,
    vfs_node_t *dst_dir, const char *dst_name);
vfs_node_t *vfs_finddir_trusted(vfs_node_t *dir, const char *name);
bool vfs_readdir_trusted(vfs_node_t *dir, u32 index, vfs_dirent_t *out_entry);
