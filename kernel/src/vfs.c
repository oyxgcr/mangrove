/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <vfs.h>
#include <heap.h>
#include <string.h>
#include <kprint.h>
#include <process.h>

#ifndef NULL
#define NULL ((void*)0)
#endif

static vfs_fs_type_t *fs_type_list = NULL;
static vfs_mount_t mount_table[VFS_MAX_MOUNTS];
static vfs_super_t dead_super;
static spinlock_t vfs_metadata_lock;
static mutex_t vfs_mount_lock;

static vfs_mount_t *vfs_find_mount_child(vfs_node_t *parent,
                                         const char *name);
static vfs_mount_t *vfs_find_mount_child_locked(vfs_node_t *parent,
                                                const char *name);
static vfs_mount_t *vfs_find_mount_for_node_locked(vfs_node_t *node);

static void vfs_retarget_nodes_locked(vfs_super_t *sb)
{
    vfs_node_t *node;

    if (!sb) return;
    node = sb->nodes;
    while (node) {
        vfs_node_t *next = node->next_in_super;
        __atomic_store_n(&node->super, &dead_super, __ATOMIC_RELEASE);
        node->next_in_super = NULL;
        node = next;
    }
    sb->nodes = NULL;
}

static bool vfs_super_is_live_locked(const vfs_super_t *sb)
{
    return sb && sb != &dead_super &&
           sb->state == VFS_SUPER_ACTIVE &&
           (!sb->dev || block_device_id_is_live(sb->device_id));
}

static bool vfs_super_mark_dispose_locked(vfs_super_t *sb)
{
    if (!sb || sb == &dead_super || sb->reference_count ||
        sb->state == VFS_SUPER_ACTIVE || sb->dispose_pending) return false;
    sb->dispose_pending = true;
    sb->state = VFS_SUPER_DEAD;
    /* Nodes returned by lookup are intentionally long-lived in the current
     * VFS.  Retarget them before releasing driver-private state so a stale
     * node can only observe the inert dead-super sentinel. */
    vfs_retarget_nodes_locked(sb);
    return true;
}

static void vfs_super_destroy(vfs_super_t *sb)
{
    if (!sb || sb == &dead_super) return;
    if (sb->ops && sb->ops->unmount)
        (void)sb->ops->unmount(sb);
    kfree(sb);
}

static void vfs_dispose_unpublished(vfs_super_t *sb)
{
    u64 flags;

    if (!sb || sb == &dead_super) return;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    sb->state = VFS_SUPER_DEAD;
    sb->dispose_pending = true;
    vfs_retarget_nodes_locked(sb);
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    vfs_super_destroy(sb);
}

static void vfs_super_dispose(vfs_super_t *sb)
{
    bool dispose;
    u64 flags;

    if (!sb || sb == &dead_super) return;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    dispose = vfs_super_mark_dispose_locked(sb);
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    if (dispose) vfs_super_destroy(sb);
}

bool vfs_super_is_live(const vfs_super_t *sb)
{
    vfs_super_state_t state;

    if (!sb || sb == &dead_super) return false;
    state = __atomic_load_n(&sb->state, __ATOMIC_ACQUIRE);
    if (state != VFS_SUPER_ACTIVE) return false;
    if (sb->dev && !block_device_id_is_live(sb->device_id)) return false;
    return true;
}

bool vfs_node_is_live(const vfs_node_t *node)
{
    vfs_super_t *sb;

    if (!node) return false;
    sb = __atomic_load_n(&node->super, __ATOMIC_ACQUIRE);
    return vfs_super_is_live(sb);
}

bool vfs_super_retain(vfs_super_t *sb)
{
    u64 flags;
    bool retained = false;

    if (!sb || sb == &dead_super) return false;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    if (vfs_super_is_live_locked(sb) &&
        sb->reference_count != ~(u32)0) {
        sb->reference_count++;
        retained = true;
    }
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return retained;
}

void vfs_super_release(vfs_super_t *sb)
{
    bool dispose = false;
    u64 flags;

    if (!sb || sb == &dead_super) return;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    if (sb->reference_count) {
        sb->reference_count--;
        if (!sb->reference_count)
            dispose = vfs_super_mark_dispose_locked(sb);
    }
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    if (dispose) vfs_super_destroy(sb);
}

void vfs_node_register(vfs_node_t *node)
{
    vfs_super_t *sb;

    if (!node) return;
    sb = __atomic_load_n(&node->super, __ATOMIC_ACQUIRE);
    if (!sb) return;
    u64 flags = spin_lock_irqsave(&vfs_metadata_lock);
    node->next_in_super = sb->nodes;
    sb->nodes = node;
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
}

bool vfs_node_retain_super(vfs_node_t *node, vfs_super_t **out_super)
{
    vfs_super_t *sb;
    u64 flags;
    bool retained = false;

    if (!node || !out_super) return false;
    *out_super = NULL;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    sb = __atomic_load_n(&node->super, __ATOMIC_ACQUIRE);
    if (vfs_super_is_live_locked(sb) &&
        sb->reference_count != ~(u32)0) {
        sb->reference_count++;
        *out_super = sb;
        retained = true;
    }
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return retained;
}

bool vfs_super_operation_lock(vfs_super_t *sb)
{
    return sb && vfs_super_is_live(sb) && mutex_lock(&sb->operation_lock);
}

void vfs_super_operation_unlock(vfs_super_t *sb)
{
    if (sb) (void)mutex_unlock(&sb->operation_lock);
}

static bool vfs_node_operation_begin(vfs_node_t *node, vfs_super_t **out_sb)
{
    vfs_super_t *sb;

    if (!vfs_node_retain_super(node, &sb)) return false;
    if (!mutex_lock(&sb->operation_lock)) {
        vfs_super_release(sb);
        return false;
    }
    if (out_sb) *out_sb = sb;
    return true;
}

static void vfs_node_operation_end(vfs_super_t *sb)
{
    if (!sb) return;
    (void)mutex_unlock(&sb->operation_lock);
    vfs_super_release(sb);
}

static bool vfs_node_on_read_only_mount(const vfs_node_t *node)
{
    u64 flags;
    bool read_only = false;

    if (!node) return false;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    vfs_super_t *node_super = __atomic_load_n(&node->super,
                                               __ATOMIC_ACQUIRE);
    for (u32 i = 0; i < VFS_MAX_MOUNTS; i++) {
        if (mount_table[i].active && mount_table[i].sb == node_super &&
            mount_table[i].read_only) {
            read_only = true;
            break;
        }
    }
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return read_only;
}

#define VFS_FILE_HANDLE_VALID 0x56465348U

static bool vfs_context_uid(u32 *out_uid, bool *out_kernel)
{
    process_t *process;
    process_credentials_t credentials;

    if (!out_uid || !out_kernel) return false;
    process = process_current();
    if (!process) {
        *out_uid = VFS_UID_SYSTEM;
        *out_kernel = true;
        return true;
    }
    if (!process_get_credentials(process, &credentials) ||
        !identity_credentials_valid(&credentials)) {
        return false;
    }
    *out_uid = credentials.uid;
    *out_kernel = false;
    return true;
}

bool vfs_current_uid(u32 *out_uid)
{
    bool kernel_context;
    return vfs_context_uid(out_uid, &kernel_context);
}

bool vfs_check_access(const vfs_node_t *node, u32 permission)
{
    u32 uid;
    bool kernel_context;
    u32 available;

    if (!node || (permission & ~VFS_ACCESS_READ_WRITE) != 0U ||
        permission == 0U || !vfs_context_uid(&uid, &kernel_context)) {
        return false;
    }
    if (kernel_context) return true;
    available = 0U;
    if (uid == node->owner_uid) {
        if ((node->permissions & VFS_PERMISSION_OWNER_READ) != 0U) {
            available |= VFS_ACCESS_READ;
        }
        if ((node->permissions & VFS_PERMISSION_OWNER_WRITE) != 0U) {
            available |= VFS_ACCESS_WRITE;
        }
    } else {
        if ((node->permissions & VFS_PERMISSION_OTHER_READ) != 0U) {
            available |= VFS_ACCESS_READ;
        }
        if ((node->permissions & VFS_PERMISSION_OTHER_WRITE) != 0U) {
            available |= VFS_ACCESS_WRITE;
        }
    }
    return (available & permission) == permission;
}

static bool vfs_node_has_persistent_security(const vfs_node_t *node)
{
    return node && node->super && node->super->fs_type &&
           node->super->fs_type->name &&
           strcmp(node->super->fs_type->name, "mgfs") == 0;
}

bool vfs_administrator_override_allowed(
    const vfs_node_t *node, const process_credentials_t *credentials)
{
    user_identity_t owner;

    if (!node || !credentials || !vfs_node_is_live(node) ||
        !vfs_node_has_persistent_security(node) ||
        !identity_credentials_is_admin(credentials) ||
        node->owner_uid == VFS_UID_SYSTEM ||
        node->owner_uid == credentials->uid ||
        !identity_registry_lookup_uid(node->owner_uid, &owner)) return false;
    return owner.role == MG_IDENTITY_ROLE_REGULAR;
}

void vfs_node_set_security(vfs_node_t *node, u32 owner_uid, u32 permissions)
{
    if (!node) return;
    node->owner_uid = owner_uid;
    node->permissions = permissions & VFS_PERMISSION_KNOWN;
}

void vfs_node_set_child_mutation_policy(
    vfs_node_t *node, vfs_child_mutation_policy_t child_mutation_policy)
{
    if (!node) return;
    if (node->type != VFS_TYPE_DIRECTORY ||
        child_mutation_policy > VFS_CHILD_MUTATION_OWNER_RESTRICTED) {
        node->child_mutation_policy = VFS_CHILD_MUTATION_OPEN;
        return;
    }
    node->child_mutation_policy = child_mutation_policy;
}

bool vfs_directory_child_mutation_allowed(const vfs_node_t *dir,
                                          const vfs_node_t *child)
{
    u32 uid;

    if (!dir || dir->type != VFS_TYPE_DIRECTORY) return false;
    if (dir->child_mutation_policy == VFS_CHILD_MUTATION_OPEN) return true;
    if (dir->child_mutation_policy != VFS_CHILD_MUTATION_OWNER_RESTRICTED ||
        !child || !vfs_current_uid(&uid)) return false;
    return uid == dir->owner_uid || uid == child->owner_uid;
}

void vfs_init(void) {
    fs_type_list = NULL;
    spinlock_init(&vfs_metadata_lock);
    mutex_init(&vfs_mount_lock);
    memset(&dead_super, 0, sizeof(dead_super));
    dead_super.state = VFS_SUPER_DEAD;
    for (u32 i = 0; i < VFS_MAX_MOUNTS; i++) {
        memset(&mount_table[i], 0, sizeof(mount_table[i]));
    }
}

int vfs_register_fs(vfs_fs_type_t *fs_type) {
    u64 flags;

    if (!fs_type || !fs_type->name) {
        return VFS_ERR_INVALID_PARAM;
    }

    flags = spin_lock_irqsave(&vfs_metadata_lock);
    for (vfs_fs_type_t *curr = fs_type_list; curr; curr = curr->next) {
        if (strcmp(curr->name, fs_type->name) == 0) {
            spin_unlock_irqrestore(&vfs_metadata_lock, flags);
            return VFS_ERR_INVALID_PARAM;
        }
    }
    fs_type->next = fs_type_list;
    fs_type_list = fs_type;
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return VFS_OK;
}

vfs_fs_type_t *vfs_find_fs(const char *name) {
    u64 flags;
    vfs_fs_type_t *result = NULL;

    if (!name) {
        return NULL;
    }

    flags = spin_lock_irqsave(&vfs_metadata_lock);
    vfs_fs_type_t *curr = fs_type_list;
    while (curr) {
        if (strcmp(curr->name, name) == 0) {
            result = curr;
            break;
        }
        curr = curr->next;
    }
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return result;
}

const char *vfs_probe_filesystem(block_device_t *dev)
{
    static const char *supported[] = { "mgfs", "fat32", "exfat" };

    if (!dev || !block_device_is_live(dev)) return NULL;
    for (usize index = 0; index < sizeof(supported) / sizeof(supported[0]);
         index++) {
        vfs_fs_type_t *type = vfs_find_fs(supported[index]);
        if (type && type->probe && type->probe(dev) && type->name)
            return type->name;
    }
    return NULL;
}

bool vfs_filesystem_label(block_device_t *dev, const char *fs_name,
                          char *out, usize capacity)
{
    vfs_fs_type_t *type;

    if (!out || capacity < 2U) return false;
    out[0] = '\0';
    if (!dev || !fs_name || !block_device_is_live(dev)) return false;
    type = vfs_find_fs(fs_name);
    if (!type || !type->label) return false;
    return type->label(dev, out, capacity) && out[0] != '\0';
}

int vfs_mount_root(const char *fs_name, block_device_t *dev) {
    u64 flags;
    int result;
    bool mount_busy;

    if (!fs_name) return VFS_ERR_INVALID_PARAM;
    if (!mutex_lock(&vfs_mount_lock)) return VFS_ERR_IO;

    flags = spin_lock_irqsave(&vfs_metadata_lock);
    if (mount_table[0].active) {
        spin_unlock_irqrestore(&vfs_metadata_lock, flags);
        (void)mutex_unlock(&vfs_mount_lock);
        return VFS_ERR_INVALID_PARAM;
    }
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    if (dev && !block_device_is_live(dev)) {
        (void)mutex_unlock(&vfs_mount_lock);
        return VFS_ERR_DEVICE_GONE;
    }

    vfs_fs_type_t *fs_type = vfs_find_fs(fs_name);
    if (!fs_type || !fs_type->mount) {
        (void)mutex_unlock(&vfs_mount_lock);
        return VFS_ERR_NOT_FOUND;
    }

    vfs_super_t *sb = NULL;
    int res = fs_type->mount(fs_type, dev, &sb, false);
    if (res != VFS_OK || !sb || !sb->root_node) {
        result = (res != VFS_OK) ? res : VFS_ERR_BAD_FORMAT;
        (void)mutex_unlock(&vfs_mount_lock);
        return result;
    }

    sb->device_id = dev ? dev->id : 0ULL;
    sb->reference_count = 0;
    sb->state = VFS_SUPER_ACTIVE;
    sb->nodes = NULL;
    mutex_init(&sb->operation_lock);
    sb->dispose_pending = false;
    vfs_node_register(sb->root_node);

    flags = spin_lock_irqsave(&vfs_metadata_lock);
    mount_busy = mount_table[0].active;
    if (mount_busy || (dev && !block_device_id_is_live(dev->id))) {
        spin_unlock_irqrestore(&vfs_metadata_lock, flags);
        vfs_dispose_unpublished(sb);
        (void)mutex_unlock(&vfs_mount_lock);
        return mount_busy ? VFS_ERR_INVALID_PARAM : VFS_ERR_DEVICE_GONE;
    }
    mount_table[0].sb = sb;
    mount_table[0].covered_node = NULL;
    mount_table[0].covered_super = NULL;
    mount_table[0].covered_inode = 0;
    mount_table[0].parent_super = NULL;
    mount_table[0].parent_inode = 0;
    mount_table[0].dev = dev;
    mount_table[0].dev_id = dev ? dev->id : 0ULL;
    mount_table[0].role = VFS_MOUNT_ROLE_ROOT;
    mount_table[0].read_only = false;
    strcpy(mount_table[0].mount_point, "/");
    mount_table[0].name[0] = '\0';
    mount_table[0].active = true;
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);

    (void)mutex_unlock(&vfs_mount_lock);
    return VFS_OK;
}

static int vfs_mount_slot_locked(void) {
    int slot = -1;
    for (u32 i = 1; i < VFS_MAX_MOUNTS; i++) {
        if (!mount_table[i].active) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        return VFS_ERR_NO_MEM;
    }
    return slot;
}

static int vfs_mount_instance(vfs_node_t *parent, const char *name,
                              vfs_node_t *target_node,
                              const char *mount_point, const char *fs_name,
                              block_device_t *dev, vfs_mount_role_t role,
                              bool read_only) {
    int slot;
    vfs_fs_type_t *fs_type;
    vfs_super_t *sb = NULL;
    int res;

    if (!fs_name || !mount_point || mount_point[0] != '/' ||
        strlen(mount_point) >= VFS_MOUNT_PATH_MAX ||
        (parent && (!name || !*name || strlen(name) >= VFS_MOUNT_PATH_MAX)) ||
        (!parent && !target_node)) {
        return VFS_ERR_INVALID_PARAM;
    }
    if (dev && !block_device_is_live(dev)) return VFS_ERR_DEVICE_GONE;
    if (target_node && target_node->type != VFS_TYPE_DIRECTORY) {
        return VFS_ERR_NOT_DIRECTORY;
    }

    fs_type = vfs_find_fs(fs_name);
    if (!fs_type || !fs_type->mount) return VFS_ERR_NOT_FOUND;

    res = fs_type->mount(fs_type, dev, &sb, read_only);
    if (res != VFS_OK || !sb || !sb->root_node) {
        if (res != VFS_OK) return res;
        return VFS_ERR_BAD_FORMAT;
    }

    sb->device_id = dev ? dev->id : 0ULL;
    sb->reference_count = 0;
    sb->state = VFS_SUPER_ACTIVE;
    sb->nodes = NULL;
    mutex_init(&sb->operation_lock);
    sb->dispose_pending = false;
    vfs_node_register(sb->root_node);

    {
        u64 flags = spin_lock_irqsave(&vfs_metadata_lock);

        if ((dev && !block_device_id_is_live(dev->id)) ||
            (target_node && !vfs_super_is_live_locked(target_node->super)) ||
            (parent && !vfs_super_is_live_locked(parent->super))) {
            spin_unlock_irqrestore(&vfs_metadata_lock, flags);
            vfs_dispose_unpublished(sb);
            return VFS_ERR_DEVICE_GONE;
        }
        slot = vfs_mount_slot_locked();
        if (slot < 0) {
            spin_unlock_irqrestore(&vfs_metadata_lock, flags);
            vfs_dispose_unpublished(sb);
            return slot;
        }
        if ((parent && vfs_find_mount_child_locked(parent, name)) ||
            (target_node && vfs_find_mount_for_node_locked(target_node))) {
            spin_unlock_irqrestore(&vfs_metadata_lock, flags);
            vfs_dispose_unpublished(sb);
            return VFS_ERR_INVALID_PARAM;
        }

    memset(&mount_table[slot], 0, sizeof(mount_table[slot]));
    mount_table[slot].sb = sb;
    mount_table[slot].covered_node = target_node;
    if (target_node) {
        mount_table[slot].covered_super = target_node->super;
        mount_table[slot].covered_inode = target_node->inode;
    }
    if (parent) {
        mount_table[slot].parent_super = parent->super;
        mount_table[slot].parent_inode = parent->inode;
        strncpy(mount_table[slot].name, name,
                sizeof(mount_table[slot].name) - 1U);
    }
    mount_table[slot].dev = dev;
    mount_table[slot].dev_id = dev ? dev->id : 0ULL;
    mount_table[slot].role = role;
    mount_table[slot].read_only = read_only;
    strncpy(mount_table[slot].mount_point, mount_point,
            sizeof(mount_table[slot].mount_point) - 1U);
    mount_table[slot].active = true;
    KERNEL_BOOT_DEBUG_LOG(
        "[VFS] mount slot=%u role=%u path=%s fs=%s dev=%llu parent=%llu "
        "covered=%llu virtual=%u\n",
        (u32)slot, (u32)role, mount_table[slot].mount_point, fs_name,
        dev ? dev->id : 0ULL,
        parent ? parent->inode : 0ULL,
        target_node ? target_node->inode : 0ULL,
        target_node ? 0U : 1U);
        spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    }
    return VFS_OK;
}

int vfs_mount_node(vfs_node_t *target_node, const char *fs_name, block_device_t *dev) {
    int result;

    if (!mutex_lock(&vfs_mount_lock)) return VFS_ERR_IO;
    if (!vfs_node_is_live(target_node) ||
        target_node->type != VFS_TYPE_DIRECTORY || !fs_name) {
        (void)mutex_unlock(&vfs_mount_lock);
        return VFS_ERR_INVALID_PARAM;
    }

    if (vfs_find_mount_for_node(target_node) != NULL) {
        (void)mutex_unlock(&vfs_mount_lock);
        return VFS_ERR_INVALID_PARAM;
    }

    result = vfs_mount_instance(NULL, NULL, target_node, "/", fs_name,
                                dev, VFS_MOUNT_ROLE_VOLUME, false);
    (void)mutex_unlock(&vfs_mount_lock);
    return result;
}

int vfs_mount_path(vfs_node_t *parent, const char *name,
                   const char *mount_point, const char *fs_name,
                   block_device_t *dev, vfs_mount_role_t role,
                   bool read_only) {
    vfs_node_t *target_node;
    int result;

    if (!mutex_lock(&vfs_mount_lock)) return VFS_ERR_IO;
    if (!vfs_node_is_live(parent) ||
        parent->type != VFS_TYPE_DIRECTORY || !name || !*name ||
        !mount_point || mount_point[0] != '/' || !fs_name) {
        (void)mutex_unlock(&vfs_mount_lock);
        return VFS_ERR_INVALID_PARAM;
    }
    if (vfs_find_mount_child(parent, name) != NULL) {
        (void)mutex_unlock(&vfs_mount_lock);
        return VFS_ERR_INVALID_PARAM;
    }

    target_node = vfs_finddir_trusted(parent, name);
    if (target_node && target_node->type != VFS_TYPE_DIRECTORY) {
        (void)mutex_unlock(&vfs_mount_lock);
        return VFS_ERR_NOT_DIRECTORY;
    }

    result = vfs_mount_instance(parent, name, target_node, mount_point,
                                fs_name, dev, role, read_only);
    (void)mutex_unlock(&vfs_mount_lock);
    return result;
}

static void vfs_mount_detach(vfs_mount_t *mount)
{
    if (!mount) return;
    mount->sb = NULL;
    mount->covered_node = NULL;
    mount->covered_super = NULL;
    mount->parent_super = NULL;
    mount->parent_inode = 0;
    mount->dev = NULL;
    mount->dev_id = 0;
    mount->mount_point[0] = '\0';
    mount->name[0] = '\0';
    mount->active = false;
}

static int vfs_unmount_preflight_super_locked(vfs_super_t *sb)
{
    if (!sb) return VFS_ERR_INVALID_PARAM;
    if (sb->state != VFS_SUPER_ACTIVE) return VFS_ERR_DEVICE_GONE;
    if (sb->reference_count) return VFS_ERR_BUSY;
    for (u32 i = 0; i < VFS_MAX_MOUNTS; i++) {
        if (mount_table[i].active && mount_table[i].sb == sb &&
            process_any_cwd_under_path(mount_table[i].mount_point))
            return VFS_ERR_BUSY;
    }
    return VFS_OK;
}

static vfs_super_t *vfs_mounted_super_for_device_locked(block_device_t *device)
{
    if (!device) return NULL;
    for (u32 i = 0; i < VFS_MAX_MOUNTS; i++) {
        if (mount_table[i].active && mount_table[i].dev_id == device->id)
            return mount_table[i].sb;
    }
    return NULL;
}

int vfs_unmount_device_preflight(block_device_t *device)
{
    vfs_super_t *sb;
    u64 flags;

    if (!device) return VFS_ERR_INVALID_PARAM;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    sb = vfs_mounted_super_for_device_locked(device);
    int result = sb ? vfs_unmount_preflight_super_locked(sb) :
        VFS_ERR_NOT_FOUND;
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return result;
}

int vfs_format_preflight(block_device_t *device)
{
    u64 flags;
    bool mounted;

    if (!device || !block_device_is_live(device)) return VFS_ERR_DEVICE_GONE;
    /* A mounted superblock is the authoritative indication that filesystem
     * objects may still issue I/O.  Formatting deliberately does not
     * unmount or invalidate it on the caller's behalf. */
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    mounted = vfs_mounted_super_for_device_locked(device) != NULL;
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    if (mounted) return VFS_ERR_BUSY;
    return VFS_OK;
}

int vfs_unmount_devices_preflight(block_device_t *devices[], u32 count)
{
    vfs_super_t *supers[VFS_MAX_MOUNTS];
    u32 super_count = 0;
    u64 flags;

    if (!devices || count == 0 || count > VFS_MAX_MOUNTS)
        return VFS_ERR_INVALID_PARAM;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    for (u32 index = 0; index < count; index++) {
        vfs_super_t *sb = vfs_mounted_super_for_device_locked(devices[index]);
        bool duplicate = false;
        if (!sb) continue;
        for (u32 prior = 0; prior < super_count; prior++)
            if (supers[prior] == sb) duplicate = true;
        if (duplicate) continue;
        if (super_count >= VFS_MAX_MOUNTS) {
            spin_unlock_irqrestore(&vfs_metadata_lock, flags);
            return VFS_ERR_NO_MEM;
        }
        supers[super_count++] = sb;
    }
    if (!super_count) {
        spin_unlock_irqrestore(&vfs_metadata_lock, flags);
        return VFS_ERR_NOT_FOUND;
    }
    for (u32 index = 0; index < super_count; index++) {
        int result = vfs_unmount_preflight_super_locked(supers[index]);
        if (result != VFS_OK) {
            spin_unlock_irqrestore(&vfs_metadata_lock, flags);
            return result;
        }
    }
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return VFS_OK;
}

int vfs_unmount_devices(block_device_t *devices[], u32 count)
{
    vfs_super_t *supers[VFS_MAX_MOUNTS];
    u32 super_count = 0;
    int result;
    u64 flags;

    if (!devices || count == 0 || count > VFS_MAX_MOUNTS)
        return VFS_ERR_INVALID_PARAM;
    if (!mutex_lock(&vfs_mount_lock)) return VFS_ERR_IO;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    for (u32 index = 0; index < count; index++) {
        vfs_super_t *sb = vfs_mounted_super_for_device_locked(devices[index]);
        bool duplicate = false;
        if (!sb) continue;
        for (u32 prior = 0; prior < super_count; prior++)
            if (supers[prior] == sb) duplicate = true;
        if (duplicate) continue;
        if (super_count >= VFS_MAX_MOUNTS) {
            spin_unlock_irqrestore(&vfs_metadata_lock, flags);
            (void)mutex_unlock(&vfs_mount_lock);
            return VFS_ERR_NO_MEM;
        }
        supers[super_count++] = sb;
    }
    if (!super_count) {
        spin_unlock_irqrestore(&vfs_metadata_lock, flags);
        (void)mutex_unlock(&vfs_mount_lock);
        return VFS_ERR_NOT_FOUND;
    }

    /* Preflight every child before changing any mount state.  This makes a
     * busy child fail an eject without partially detaching an earlier child. */
    for (u32 index = 0; index < super_count; index++) {
        result = vfs_unmount_preflight_super_locked(supers[index]);
        if (result != VFS_OK) {
            spin_unlock_irqrestore(&vfs_metadata_lock, flags);
            (void)mutex_unlock(&vfs_mount_lock);
            return result;
        }
    }
    for (u32 index = 0; index < super_count; index++) {
        if (supers[index]->reference_count == ~(u32)0) {
            spin_unlock_irqrestore(&vfs_metadata_lock, flags);
            (void)mutex_unlock(&vfs_mount_lock);
            return VFS_ERR_NO_MEM;
        }
        /* The mount itself is an implicit lifetime reference while sync and
         * teardown run outside the metadata spinlock. */
        supers[index]->reference_count++;
        supers[index]->state = VFS_SUPER_DETACHING;
    }
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    for (u32 index = 0; index < super_count; index++) {
        if (!supers[index]->ops || !supers[index]->ops->sync) continue;
        if (!mutex_lock(&supers[index]->operation_lock)) {
            result = VFS_ERR_IO;
        } else {
            result = supers[index]->ops->sync(supers[index]);
            (void)mutex_unlock(&supers[index]->operation_lock);
        }
        if (result != VFS_OK) {
            flags = spin_lock_irqsave(&vfs_metadata_lock);
            for (u32 restore = 0; restore < super_count; restore++)
                if (supers[restore]->state == VFS_SUPER_DETACHING)
                    supers[restore]->state = VFS_SUPER_ACTIVE;
            spin_unlock_irqrestore(&vfs_metadata_lock, flags);
            for (u32 release = 0; release < super_count; release++)
                vfs_super_release(supers[release]);
            (void)mutex_unlock(&vfs_mount_lock);
            return result;
        }
    }
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    for (u32 index = 0; index < VFS_MAX_MOUNTS; index++) {
        vfs_mount_t *mount = &mount_table[index];
        bool selected = false;
        if (!mount->active) continue;
        for (u32 super = 0; super < super_count; super++)
            if (mount->sb == supers[super]) selected = true;
        if (selected) vfs_mount_detach(mount);
    }
    for (u32 index = 0; index < super_count; index++) {
        supers[index]->state = VFS_SUPER_DEAD;
        vfs_retarget_nodes_locked(supers[index]);
    }
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    for (u32 index = 0; index < super_count; index++)
        vfs_super_release(supers[index]);
    (void)mutex_unlock(&vfs_mount_lock);
    return VFS_OK;
}

int vfs_unmount_sb(vfs_super_t *sb)
{
    block_device_t *device = NULL;
    u64 flags;

    if (!sb) return VFS_ERR_INVALID_PARAM;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    for (u32 i = 0; i < VFS_MAX_MOUNTS; i++)
        if (mount_table[i].active && mount_table[i].sb == sb)
            device = mount_table[i].dev;
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    if (!device) return VFS_ERR_NOT_FOUND;
    return vfs_unmount_device(device);
}

int vfs_unmount_device(block_device_t *device)
{
    block_device_t *devices[1];

    if (!device) return VFS_ERR_INVALID_PARAM;
    devices[0] = device;
    return vfs_unmount_devices(devices, 1);
}

void vfs_device_removed(block_device_t *device)
{
    vfs_super_t *dead_supers[VFS_MAX_MOUNTS];
    u32 dead_count = 0;
    u64 flags;

    if (!device) return;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    for (u32 i = 0; i < VFS_MAX_MOUNTS; i++) {
        vfs_mount_t *mount = &mount_table[i];
        vfs_super_t *sb;
        if (!mount->active || mount->dev_id != device->id) continue;
        sb = mount->sb;
        if (!sb) {
            vfs_mount_detach(mount);
            continue;
        }
        /* Physical loss is not a clean unmount: no flush is attempted and
         * dirty data is considered lost.  Detach the namespace immediately,
         * retaining the superblock while open objects unwind. */
        sb->state = VFS_SUPER_DEAD;
        vfs_mount_detach(mount);
        if (dead_count < VFS_MAX_MOUNTS)
            dead_supers[dead_count++] = sb;
    }
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    for (u32 i = 0; i < dead_count; i++)
        vfs_super_dispose(dead_supers[i]);
}

vfs_node_t *vfs_get_root_node(void) {
    vfs_node_t *root = NULL;
    u64 flags = spin_lock_irqsave(&vfs_metadata_lock);
    if (mount_table[0].active && mount_table[0].sb &&
        vfs_super_is_live_locked(mount_table[0].sb))
        root = mount_table[0].sb->root_node;
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return root;
}

static vfs_mount_t *vfs_find_mount_for_node_locked(vfs_node_t *node) {
    if (!node) {
        return NULL;
    }

    for (u32 i = 0; i < VFS_MAX_MOUNTS; i++) {
        if (mount_table[i].active && mount_table[i].covered_node &&
            ((mount_table[i].covered_node == node) ||
             (mount_table[i].covered_super == node->super &&
              mount_table[i].covered_inode == node->inode))) {
            return &mount_table[i];
        }
    }

    return NULL;
}

vfs_mount_t *vfs_find_mount_for_node(vfs_node_t *node) {
    vfs_mount_t *mount;
    u64 flags;

    flags = spin_lock_irqsave(&vfs_metadata_lock);
    mount = vfs_find_mount_for_node_locked(node);
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return mount;
}

bool vfs_mount_point_for_device(block_device_t *device, char *out_path,
                                usize capacity, vfs_mount_role_t *out_role)
{
    u64 flags;
    bool found = false;

    if (!device || !out_path || capacity < 2U) return false;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    for (u32 index = 0; index < VFS_MAX_MOUNTS; index++) {
        if (!mount_table[index].active || mount_table[index].dev_id != device->id)
            continue;
        strncpy(out_path, mount_table[index].mount_point, capacity - 1U);
        out_path[capacity - 1U] = '\0';
        if (out_role) *out_role = mount_table[index].role;
        found = true;
        break;
    }
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return found;
}

static bool vfs_mount_parent_matches(const vfs_mount_t *mount,
                                     const vfs_node_t *parent)
{
    return mount && mount->active && parent && mount->parent_super == parent->super &&
           mount->parent_inode == parent->inode;
}

bool vfs_directory_has_mount_children(vfs_node_t *dir)
{
    bool found = false;
    u64 flags;

    if (!dir || dir->type != VFS_TYPE_DIRECTORY) return false;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    for (u32 i = 1; i < VFS_MAX_MOUNTS; i++) {
        if (vfs_mount_parent_matches(&mount_table[i], dir)) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return found;
}

static vfs_mount_t *vfs_find_mount_child_locked(vfs_node_t *parent,
                                                const char *name)
{
    if (!parent || !name) return NULL;
    for (u32 i = 1; i < VFS_MAX_MOUNTS; i++) {
        if (vfs_mount_parent_matches(&mount_table[i], parent) &&
            strcmp(mount_table[i].name, name) == 0) {
            return &mount_table[i];
        }
    }
    return NULL;
}

static vfs_mount_t *vfs_find_mount_child(vfs_node_t *parent, const char *name)
{
    vfs_mount_t *mount;
    u64 flags;

    flags = spin_lock_irqsave(&vfs_metadata_lock);
    mount = vfs_find_mount_child_locked(parent, name);
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return mount;
}

static vfs_node_t *vfs_resolve_mount(vfs_node_t *node) {
    vfs_node_t *resolved = node;
    u64 flags;

    if (!vfs_node_is_live(node)) return NULL;
    flags = spin_lock_irqsave(&vfs_metadata_lock);
    vfs_mount_t *m = vfs_find_mount_for_node_locked(node);
    if (m && m->active && m->sb && m->sb->root_node)
        resolved = m->sb->root_node;
    spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    return resolved;
}

static vfs_node_t *vfs_finddir_internal(vfs_node_t *dir, const char *name,
                                        bool enforce) {
    vfs_node_t *mounted_root = NULL;
    vfs_super_t *sb;

    if (!dir || !name || dir->type != VFS_TYPE_DIRECTORY || !dir->ops ||
        !dir->ops->finddir || !vfs_node_is_live(dir) || (enforce &&
        !vfs_check_access(dir, VFS_ACCESS_READ))) {
        return NULL;
    }
    if (!vfs_node_operation_begin(dir, &sb)) return NULL;
    {
        u64 flags = spin_lock_irqsave(&vfs_metadata_lock);
        vfs_mount_t *mount = vfs_find_mount_child_locked(dir, name);
        if (mount && mount->sb && mount->sb->root_node)
            mounted_root = mount->sb->root_node;
        spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    }
    if (!mounted_root)
        mounted_root = dir->ops->finddir(dir, name);
    vfs_node_operation_end(sb);
    return mounted_root;
}

/* Find a child while the caller owns the containing superblock operation
 * mutex.  This is used to bind name-based mutations to the object that was
 * authorized before a possible path replacement. */
static vfs_node_t *vfs_finddir_locked(vfs_node_t *dir, const char *name)
{
    vfs_node_t *mounted_root = NULL;

    if (!dir || !name || dir->type != VFS_TYPE_DIRECTORY || !dir->ops ||
        !dir->ops->finddir) return NULL;
    {
        u64 flags = spin_lock_irqsave(&vfs_metadata_lock);
        vfs_mount_t *mount = vfs_find_mount_child_locked(dir, name);
        if (mount && mount->sb && mount->sb->root_node)
            mounted_root = mount->sb->root_node;
        spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    }
    if (!mounted_root)
        mounted_root = dir->ops->finddir(dir, name);
    return mounted_root;
}

static int vfs_lookup_internal(const char *path, vfs_node_t **out_node,
                               bool enforce) {
    if (!path || path[0] != '/' || !out_node) {
        return VFS_ERR_INVALID_PARAM;
    }

    vfs_node_t *curr = vfs_get_root_node();
    if (!curr) {
        return VFS_ERR_NOT_FOUND;
    }

    const char *ptr = path;

    while (*ptr) {
        while (*ptr == '/') {
            ptr++;
        }

        if (*ptr == '\0') {
            break;
        }

        char component[256];
        u32 len = 0;
        while (*ptr && *ptr != '/') {
            if (len >= sizeof(component) - 1) {
                return VFS_ERR_INVALID_PARAM;
            }
            component[len++] = *ptr;
            ptr++;
        }
        component[len] = '\0';

        curr = vfs_resolve_mount(curr);
        if (!curr) return VFS_ERR_DEVICE_GONE;

        if (curr->type != VFS_TYPE_DIRECTORY) {
            return VFS_ERR_NOT_FOUND;
        }
        if (enforce && !vfs_check_access(curr, VFS_ACCESS_READ)) {
            return VFS_ERR_ACCESS_DENIED;
        }

        vfs_node_t *next = vfs_finddir_internal(curr, component, enforce);
        if (!next) {
            return VFS_ERR_NOT_FOUND;
        }

        curr = vfs_resolve_mount(next);
        if (!curr) return VFS_ERR_DEVICE_GONE;
    }

    /* Looking up a protected object is itself a read operation.  This keeps
       private files and directories from being discoverable by pathname. */
    if (!vfs_node_is_live(curr)) return VFS_ERR_DEVICE_GONE;
    if (enforce && !vfs_check_access(curr, VFS_ACCESS_READ)) {
        return VFS_ERR_ACCESS_DENIED;
    }

    *out_node = curr;
    return VFS_OK;
}

int vfs_lookup(const char *path, vfs_node_t **out_node) {
    return vfs_lookup_internal(path, out_node, true);
}

int vfs_lookup_trusted(const char *path, vfs_node_t **out_node) {
    return vfs_lookup_internal(path, out_node, false);
}

static int vfs_open_node_internal(vfs_node_t *node, u32 flags,
                                  vfs_file_handle_t **out_handle,
                                  u32 authorized_access,
                                  vfs_authorization_scope_t authorization_scope,
                                  u32 authorization_owner_uid,
                                  bool enforce_access) {
    vfs_file_handle_t *handle;
    vfs_super_t *super = NULL;

    if (!node || !out_handle ||
        (flags != VFS_OPEN_READ && flags != VFS_OPEN_WRITE && flags != VFS_OPEN_RDWR)) {
        return VFS_ERR_INVALID_PARAM;
    }

    *out_handle = NULL;
    if (!vfs_node_retain_super(node, &super)) return VFS_ERR_DEVICE_GONE;
    if ((flags & VFS_OPEN_WRITE) && vfs_node_on_read_only_mount(node)) {
        vfs_super_release(super);
        return VFS_ERR_ACCESS_DENIED;
    }
    if (enforce_access && (((flags & VFS_OPEN_READ) &&
         !(authorized_access & VFS_ACCESS_READ) &&
         !vfs_check_access(node, VFS_ACCESS_READ)) ||
        ((flags & VFS_OPEN_WRITE) &&
         !(authorized_access & VFS_ACCESS_WRITE) &&
         !vfs_check_access(node, VFS_ACCESS_WRITE)))) {
        vfs_super_release(super);
        return VFS_ERR_ACCESS_DENIED;
    }

    handle = (vfs_file_handle_t *)kmalloc(sizeof(*handle));
    if (!handle) {
        vfs_super_release(super);
        return VFS_ERR_NO_MEM;
    }

    handle->node = node;
    handle->super = super;
    handle->offset = 0;
    handle->flags = flags;
    handle->valid = VFS_FILE_HANDLE_VALID;
    mutex_init(&handle->offset_lock);
    handle->authorized_access = authorized_access & VFS_ACCESS_READ_WRITE;
    handle->authorization_scope = authorization_scope;
    handle->authorization_owner_uid = authorization_owner_uid;
    *out_handle = handle;
    return VFS_OK;
}

int vfs_open_node(vfs_node_t *node, u32 flags,
                  vfs_file_handle_t **out_handle) {
    return vfs_open_node_internal(node, flags, out_handle, 0U,
                                  VFS_AUTH_NONE, 0U, true);
}

int vfs_open_node_authorized(vfs_node_t *node, u32 flags,
                             vfs_file_handle_t **out_handle) {
    return vfs_open_node_internal(node, flags, out_handle, VFS_ACCESS_WRITE,
                                  VFS_AUTH_CONFIGURATION_WRITE, 0U, true);
}

int vfs_open_node_user_authorized(vfs_node_t *node, u32 flags,
                                  vfs_file_handle_t **out_handle) {
    process_credentials_t credentials;

    if (!process_get_credentials(process_current(), &credentials) ||
        !vfs_administrator_override_allowed(node, &credentials))
        return VFS_ERR_ACCESS_DENIED;
    return vfs_open_node_internal(node, flags, out_handle,
                                  VFS_ACCESS_READ_WRITE,
                                  VFS_AUTH_REGULAR_USER_DATA,
                                  node->owner_uid, true);
}

int vfs_open(const char *path, u32 flags, vfs_file_handle_t **out_handle) {
    vfs_node_t *node = NULL;
    int result;

    if (!path || path[0] == '\0' || path[0] != '/' || !out_handle) {
        return VFS_ERR_INVALID_PARAM;
    }
    result = vfs_lookup(path, &node);
    if (result != VFS_OK) return result;
    return vfs_open_node(node, flags, out_handle);
}

int vfs_open_trusted(const char *path, u32 flags,
                     vfs_file_handle_t **out_handle) {
    vfs_node_t *node = NULL;

    if (!path || path[0] != '/' || !out_handle ||
        (flags != VFS_OPEN_READ && flags != VFS_OPEN_WRITE &&
         flags != VFS_OPEN_RDWR)) {
        return VFS_ERR_INVALID_PARAM;
    }
    *out_handle = NULL;
    if (vfs_lookup_trusted(path, &node) != VFS_OK || !node) {
        return VFS_ERR_NOT_FOUND;
    }
    return vfs_open_node_internal(node, flags, out_handle, 0U,
                                  VFS_AUTH_NONE, 0U, false);
}

int vfs_close(vfs_file_handle_t *handle) {
    vfs_super_t *super;

    if (!handle || !mutex_lock(&handle->offset_lock)) {
        return VFS_ERR_INVALID_PARAM;
    }
    if (handle->valid != VFS_FILE_HANDLE_VALID || !handle->node) {
        (void)mutex_unlock(&handle->offset_lock);
        return VFS_ERR_INVALID_PARAM;
    }

    super = handle->super;
    handle->valid = 0;
    handle->node = NULL;
    handle->super = NULL;
    (void)mutex_unlock(&handle->offset_lock);
    vfs_super_release(super);
    kfree(handle);
    return VFS_OK;
}

static bool vfs_handle_valid(const vfs_file_handle_t *handle) {
    return handle && handle->valid == VFS_FILE_HANDLE_VALID && handle->node &&
           vfs_super_is_live(handle->super);
}

static bool vfs_handle_authorized(const vfs_file_handle_t *handle,
                                  u32 permission)
{
    process_credentials_t credentials;

    if (!handle || !(handle->authorized_access & permission)) return false;
    if (handle->authorization_scope == VFS_AUTH_CONFIGURATION_WRITE)
        return permission == VFS_ACCESS_WRITE;
    if (handle->authorization_scope != VFS_AUTH_REGULAR_USER_DATA ||
        !process_get_credentials(process_current(), &credentials) ||
        handle->node->owner_uid != handle->authorization_owner_uid) {
        return false;
    }
    return vfs_administrator_override_allowed(handle->node, &credentials);
}

u64 vfs_file_read(vfs_file_handle_t *handle, u64 size, void *buffer) {
    u64 transferred;

    if (!handle || !mutex_lock(&handle->offset_lock) ||
        !vfs_handle_valid(handle) || !(handle->flags & VFS_OPEN_READ) ||
        (size != 0 && !buffer) || !handle->node->ops || !handle->node->ops->read) {
        if (handle) (void)mutex_unlock(&handle->offset_lock);
        return 0;
    }
    if (!vfs_handle_authorized(handle, VFS_ACCESS_READ) &&
        !vfs_check_access(handle->node, VFS_ACCESS_READ)) {
        (void)mutex_unlock(&handle->offset_lock);
        return 0;
    }
    if (size == 0) {
        (void)mutex_unlock(&handle->offset_lock);
        return 0;
    }

    if (!vfs_super_operation_lock(handle->super)) {
        (void)mutex_unlock(&handle->offset_lock);
        return 0;
    }
    transferred = handle->node->ops->read(handle->node, handle->offset, size,
                                           buffer);
    vfs_super_operation_unlock(handle->super);
    if (transferred <= (u64)-1 - handle->offset) {
        handle->offset += transferred;
    }
    (void)mutex_unlock(&handle->offset_lock);
    return transferred;
}

u64 vfs_file_read_trusted(vfs_file_handle_t *handle, u64 size, void *buffer) {
    u64 transferred;

    if (!handle || !mutex_lock(&handle->offset_lock) ||
        !vfs_handle_valid(handle) || !(handle->flags & VFS_OPEN_READ) ||
        (size != 0 && !buffer) || !handle->node->ops ||
        !handle->node->ops->read || size == 0) {
        if (handle) (void)mutex_unlock(&handle->offset_lock);
        return 0;
    }
    if (!vfs_super_operation_lock(handle->super)) {
        (void)mutex_unlock(&handle->offset_lock);
        return 0;
    }
    transferred = handle->node->ops->read(handle->node, handle->offset, size,
                                          buffer);
    vfs_super_operation_unlock(handle->super);
    if (transferred <= (u64)-1 - handle->offset) handle->offset += transferred;
    (void)mutex_unlock(&handle->offset_lock);
    return transferred;
}

u64 vfs_file_write(vfs_file_handle_t *handle, u64 size, const void *buffer) {
    u64 transferred;

    if (!handle || !mutex_lock(&handle->offset_lock) ||
        !vfs_handle_valid(handle) || !(handle->flags & VFS_OPEN_WRITE) ||
        (size != 0 && !buffer) || !handle->node->ops || !handle->node->ops->write) {
        if (handle) (void)mutex_unlock(&handle->offset_lock);
        return 0;
    }
    if ((!vfs_handle_authorized(handle, VFS_ACCESS_WRITE) &&
         !vfs_check_access(handle->node, VFS_ACCESS_WRITE)) ||
        vfs_node_on_read_only_mount(handle->node)) {
        (void)mutex_unlock(&handle->offset_lock);
        return 0;
    }
    if (size == 0) {
        (void)mutex_unlock(&handle->offset_lock);
        return 0;
    }

    if (!vfs_super_operation_lock(handle->super)) {
        (void)mutex_unlock(&handle->offset_lock);
        return 0;
    }
    transferred = handle->node->ops->write(handle->node, handle->offset, size,
                                            buffer);
    vfs_super_operation_unlock(handle->super);
    if (transferred <= (u64)-1 - handle->offset) {
        handle->offset += transferred;
    }
    (void)mutex_unlock(&handle->offset_lock);
    return transferred;
}

u64 vfs_file_write_trusted(vfs_file_handle_t *handle, u64 size,
                           const void *buffer) {
    u64 transferred;

    if (!handle || !mutex_lock(&handle->offset_lock) ||
        !vfs_handle_valid(handle) || !(handle->flags & VFS_OPEN_WRITE) ||
        (size != 0 && !buffer) || !handle->node->ops ||
        !handle->node->ops->write || size == 0) {
        if (handle) (void)mutex_unlock(&handle->offset_lock);
        return 0;
    }
    if (!vfs_super_operation_lock(handle->super)) {
        (void)mutex_unlock(&handle->offset_lock);
        return 0;
    }
    transferred = handle->node->ops->write(handle->node, handle->offset, size,
                                           buffer);
    vfs_super_operation_unlock(handle->super);
    if (transferred <= (u64)-1 - handle->offset) handle->offset += transferred;
    (void)mutex_unlock(&handle->offset_lock);
    return transferred;
}

int vfs_close_trusted(vfs_file_handle_t *handle)
{
    return vfs_close(handle);
}

int vfs_seek(vfs_file_handle_t *handle, i64 offset, int whence, u64 *out_offset) {
    u64 base, target, magnitude;

    if (!handle || !mutex_lock(&handle->offset_lock))
        return VFS_ERR_INVALID_PARAM;
    if (handle->valid != VFS_FILE_HANDLE_VALID || !handle->node ||
        !handle->super) {
        (void)mutex_unlock(&handle->offset_lock);
        return VFS_ERR_INVALID_PARAM;
    }
    if (!vfs_super_is_live(handle->super)) {
        (void)mutex_unlock(&handle->offset_lock);
        return VFS_ERR_DEVICE_GONE;
    }
    if ((whence != VFS_SEEK_SET && whence != VFS_SEEK_CUR &&
         whence != VFS_SEEK_END)) {
        (void)mutex_unlock(&handle->offset_lock);
        return VFS_ERR_INVALID_PARAM;
    }

    if (whence == VFS_SEEK_SET) {
        if (offset < 0) {
            (void)mutex_unlock(&handle->offset_lock);
            return VFS_ERR_INVALID_PARAM;
        }
        target = (u64)offset;
    } else {
        if (whence == VFS_SEEK_END &&
            !vfs_super_operation_lock(handle->super)) {
            (void)mutex_unlock(&handle->offset_lock);
            return VFS_ERR_DEVICE_GONE;
        }
        base = (whence == VFS_SEEK_CUR) ? handle->offset : handle->node->size;
        if (whence == VFS_SEEK_END)
            vfs_super_operation_unlock(handle->super);
        if (offset >= 0) {
            if (base > (u64)-1 - (u64)offset) {
                (void)mutex_unlock(&handle->offset_lock);
                return VFS_ERR_INVALID_PARAM;
            }
            target = base + (u64)offset;
        } else {
            magnitude = (u64)(-(offset + 1)) + 1;
            if (magnitude > base) {
                (void)mutex_unlock(&handle->offset_lock);
                return VFS_ERR_INVALID_PARAM;
            }
            target = base - magnitude;
        }
    }

    handle->offset = target;
    if (out_offset) *out_offset = target;
    (void)mutex_unlock(&handle->offset_lock);
    return VFS_OK;
}

int vfs_resolve_path(const char *cwd, const char *input_path, char *out_buf, usize out_size) {
    const char *base;
    usize input_len;
    usize base_len;
    usize raw_len;
    usize required;
    usize written;

    if (!input_path || !out_buf || out_size == 0) {
        return VFS_ERR_INVALID_PARAM;
    }

    char raw[512];
    if (input_path[0] == '/') {
        input_len = strlen(input_path);
        if (input_len >= sizeof(raw)) return VFS_ERR_INVALID_PARAM;
        memcpy(raw, input_path, input_len + 1);
    } else {
        base = (cwd && cwd[0]) ? cwd : "/";
        base_len = strlen(base);
        input_len = strlen(input_path);
        raw_len = base_len + input_len;
        if (base_len && base[base_len - 1] != '/') raw_len++;
        if (raw_len >= sizeof(raw)) return VFS_ERR_INVALID_PARAM;
        memcpy(raw, base, base_len);
        written = base_len;
        if (written && raw[written - 1] != '/') raw[written++] = '/';
        memcpy(raw + written, input_path, input_len + 1);
    }

    char *stack[32];
    int top = 0;

    char *ptr = raw;
    while (*ptr) {
        while (*ptr == '/') ptr++;
        if (*ptr == '\0') break;

        char *comp = ptr;
        while (*ptr && *ptr != '/') ptr++;
        if (*ptr) {
            *ptr++ = '\0';
        }

        if (strcmp(comp, ".") == 0) {
            continue;
        }
        if (strcmp(comp, "..") == 0) {
            if (top > 0) {
                top--;
            }
            continue;
        }

        if (strlen(comp) >= 256 || top == 32) return VFS_ERR_INVALID_PARAM;
        stack[top++] = comp;
    }

    required = 1;
    for (int i = 0; i < top; i++) {
        usize component_length = strlen(stack[i]);
        if (component_length > ~(usize)0 - required - (i ? 1 : 0)) {
            return VFS_ERR_INVALID_PARAM;
        }
        required += component_length + (i ? 1 : 0);
    }
    if (required >= out_size) return VFS_ERR_INVALID_PARAM;

    out_buf[0] = '/';
    written = 1;
    for (int i = 0; i < top; i++) {
        usize component_length = strlen(stack[i]);
        if (i) out_buf[written++] = '/';
        memcpy(out_buf + written, stack[i], component_length);
        written += component_length;
    }
    out_buf[written] = '\0';

    return VFS_OK;
}

int vfs_create(vfs_node_t *dir, const char *name, vfs_node_t **out_node) {
    vfs_super_t *sb;
    int result;

    if (!vfs_node_is_live(dir) || !name ||
        dir->type != VFS_TYPE_DIRECTORY || !out_node || !dir->ops ||
        !dir->ops->create) {
        return VFS_ERR_INVALID_PARAM;
    }
    if (vfs_node_on_read_only_mount(dir) ||
        !vfs_check_access(dir, VFS_ACCESS_WRITE)) {
        return VFS_ERR_ACCESS_DENIED;
    }
    if (!vfs_node_operation_begin(dir, &sb)) return VFS_ERR_DEVICE_GONE;
    result = dir->ops->create(dir, name, out_node);
    vfs_node_operation_end(sb);
    return result;
}

int vfs_create_owned(vfs_node_t *dir, const char *name, u32 owner_uid,
                     u32 permissions, vfs_node_t **out_node) {
    vfs_super_t *sb;
    int result;

    if (!vfs_node_is_live(dir) || !name ||
        dir->type != VFS_TYPE_DIRECTORY || !out_node ||
        !dir->ops || !dir->ops->create_owned ||
        (permissions & ~VFS_PERMISSION_KNOWN) != 0U || !permissions) {
        return VFS_ERR_INVALID_PARAM;
    }
    if (vfs_node_on_read_only_mount(dir)) return VFS_ERR_ACCESS_DENIED;
    if (!vfs_node_operation_begin(dir, &sb)) return VFS_ERR_DEVICE_GONE;
    result = dir->ops->create_owned(dir, name, owner_uid, permissions,
                                    out_node);
    vfs_node_operation_end(sb);
    return result;
}

int vfs_mkdir(vfs_node_t *dir, const char *name, vfs_node_t **out_node) {
    vfs_super_t *sb;
    int result;

    if (!vfs_node_is_live(dir) || !name ||
        dir->type != VFS_TYPE_DIRECTORY || !out_node || !dir->ops ||
        !dir->ops->mkdir) {
        return VFS_ERR_INVALID_PARAM;
    }
    if (vfs_node_on_read_only_mount(dir) ||
        !vfs_check_access(dir, VFS_ACCESS_WRITE)) {
        return VFS_ERR_ACCESS_DENIED;
    }
    if (!vfs_node_operation_begin(dir, &sb)) return VFS_ERR_DEVICE_GONE;
    result = dir->ops->mkdir(dir, name, out_node);
    vfs_node_operation_end(sb);
    return result;
}

int vfs_mkdir_owned(vfs_node_t *dir, const char *name, u32 owner_uid,
                    u32 permissions, vfs_node_t **out_node) {
    vfs_super_t *sb;
    int result;

    if (!vfs_node_is_live(dir) || !name ||
        dir->type != VFS_TYPE_DIRECTORY || !out_node ||
        !dir->ops || !dir->ops->mkdir_owned ||
        (permissions & ~VFS_PERMISSION_KNOWN) != 0U || !permissions) {
        return VFS_ERR_INVALID_PARAM;
    }
    if (vfs_node_on_read_only_mount(dir)) return VFS_ERR_ACCESS_DENIED;
    if (!vfs_node_operation_begin(dir, &sb)) return VFS_ERR_DEVICE_GONE;
    result = dir->ops->mkdir_owned(dir, name, owner_uid, permissions,
                                    out_node);
    vfs_node_operation_end(sb);
    return result;
}

int vfs_unlink(vfs_node_t *dir, const char *name) {
    vfs_super_t *sb;
    vfs_node_t *child;
    int result;

    if (!vfs_node_is_live(dir) || !name ||
        dir->type != VFS_TYPE_DIRECTORY || !dir->ops ||
        !dir->ops->unlink) {
        return VFS_ERR_INVALID_PARAM;
    }
    if (vfs_node_on_read_only_mount(dir) ||
        !vfs_check_access(dir, VFS_ACCESS_WRITE)) {
        return VFS_ERR_ACCESS_DENIED;
    }
    if (!vfs_node_operation_begin(dir, &sb)) return VFS_ERR_DEVICE_GONE;
    child = vfs_finddir_locked(dir, name);
    result = child && !vfs_directory_child_mutation_allowed(dir, child)
        ? VFS_ERR_ACCESS_DENIED : dir->ops->unlink(dir, name);
    vfs_node_operation_end(sb);
    return result;
}

int vfs_unlink_trusted(vfs_node_t *dir, const char *name) {
    vfs_super_t *sb;
    int result;

    if (!vfs_node_is_live(dir) || !name ||
        dir->type != VFS_TYPE_DIRECTORY || !dir->ops ||
        !dir->ops->unlink) return VFS_ERR_INVALID_PARAM;
    if (!vfs_node_operation_begin(dir, &sb)) return VFS_ERR_DEVICE_GONE;
    result = dir->ops->unlink(dir, name);
    vfs_node_operation_end(sb);
    return result;
}

int vfs_rmdir(vfs_node_t *dir, const char *name) {
    vfs_super_t *sb;
    vfs_node_t *child;
    int result;

    if (!vfs_node_is_live(dir) || !name ||
        dir->type != VFS_TYPE_DIRECTORY || !dir->ops ||
        !dir->ops->rmdir) {
        return VFS_ERR_INVALID_PARAM;
    }
    if (vfs_node_on_read_only_mount(dir) ||
        !vfs_check_access(dir, VFS_ACCESS_WRITE)) {
        return VFS_ERR_ACCESS_DENIED;
    }
    if (!vfs_node_operation_begin(dir, &sb)) return VFS_ERR_DEVICE_GONE;
    child = vfs_finddir_locked(dir, name);
    result = child && !vfs_directory_child_mutation_allowed(dir, child)
        ? VFS_ERR_ACCESS_DENIED : dir->ops->rmdir(dir, name);
    vfs_node_operation_end(sb);
    return result;
}

int vfs_rmdir_trusted(vfs_node_t *dir, const char *name) {
    vfs_super_t *sb;
    int result;

    if (!vfs_node_is_live(dir) || !name ||
        dir->type != VFS_TYPE_DIRECTORY || !dir->ops ||
        !dir->ops->rmdir) return VFS_ERR_INVALID_PARAM;
    if (!vfs_node_operation_begin(dir, &sb)) return VFS_ERR_DEVICE_GONE;
    result = dir->ops->rmdir(dir, name);
    vfs_node_operation_end(sb);
    return result;
}

int vfs_rename(vfs_node_t *src_dir, const char *src_name,
               vfs_node_t *dst_dir, const char *dst_name) {
    vfs_super_t *sb;
    vfs_node_t *source;
    int result;

    if (!vfs_node_is_live(src_dir) || !src_name ||
        !vfs_node_is_live(dst_dir) || !dst_name ||
        src_dir->type != VFS_TYPE_DIRECTORY ||
        dst_dir->type != VFS_TYPE_DIRECTORY ||
        !src_dir->ops || !src_dir->ops->rename) {
        return VFS_ERR_INVALID_PARAM;
    }
    if (vfs_node_on_read_only_mount(src_dir) ||
        vfs_node_on_read_only_mount(dst_dir) ||
        !vfs_check_access(src_dir, VFS_ACCESS_WRITE) ||
        !vfs_check_access(dst_dir, VFS_ACCESS_WRITE)) {
        return VFS_ERR_ACCESS_DENIED;
    }
    if (src_dir->super != dst_dir->super) return VFS_ERR_UNSUPPORTED;
    if (!vfs_node_operation_begin(src_dir, &sb)) return VFS_ERR_DEVICE_GONE;
    source = vfs_finddir_locked(src_dir, src_name);
    result = source && !vfs_directory_child_mutation_allowed(src_dir, source)
        ? VFS_ERR_ACCESS_DENIED
        : src_dir->ops->rename(src_dir, src_name, dst_dir, dst_name);
    vfs_node_operation_end(sb);
    return result;
}

static bool vfs_node_identity_matches(const vfs_node_t *node,
                                      vfs_super_t *expected_super,
                                      u64 expected_inode)
{
    return node && expected_super && node->super == expected_super &&
           node->inode == expected_inode;
}

static int vfs_unlink_expected_internal(
    vfs_node_t *dir, const char *name, vfs_super_t *expected_super,
    u64 expected_inode, bool authorized)
{
    vfs_super_t *sb;
    vfs_node_t *actual;
    int result;

    if (!vfs_node_is_live(dir) || !name || !*name ||
        dir->type != VFS_TYPE_DIRECTORY || !dir->ops ||
        !dir->ops->unlink || expected_super != dir->super) {
        return VFS_ERR_INVALID_PARAM;
    }
    if (vfs_node_on_read_only_mount(dir)) return VFS_ERR_ACCESS_DENIED;
    if (!vfs_node_operation_begin(dir, &sb)) return VFS_ERR_DEVICE_GONE;
    actual = vfs_finddir_locked(dir, name);
    if (!vfs_node_identity_matches(actual, expected_super, expected_inode) ||
        actual->type != VFS_TYPE_FILE ||
        (!authorized && !vfs_directory_child_mutation_allowed(dir, actual))) {
        result = VFS_ERR_ACCESS_DENIED;
    } else {
        result = dir->ops->unlink(dir, name);
    }
    vfs_node_operation_end(sb);
    return result;
}

int vfs_unlink_expected(vfs_node_t *dir, const char *name,
                        vfs_super_t *expected_super, u64 expected_inode)
{
    return vfs_unlink_expected_internal(dir, name, expected_super,
                                        expected_inode, false);
}

int vfs_unlink_expected_authorized(vfs_node_t *dir, const char *name,
                                   vfs_super_t *expected_super,
                                   u64 expected_inode)
{
    return vfs_unlink_expected_internal(dir, name, expected_super,
                                        expected_inode, true);
}

static int vfs_rmdir_expected_internal(
    vfs_node_t *dir, const char *name, vfs_super_t *expected_super,
    u64 expected_inode, bool authorized)
{
    vfs_super_t *sb;
    vfs_node_t *actual;
    int result;

    if (!vfs_node_is_live(dir) || !name || !*name ||
        dir->type != VFS_TYPE_DIRECTORY || !dir->ops ||
        !dir->ops->rmdir || expected_super != dir->super) {
        return VFS_ERR_INVALID_PARAM;
    }
    if (vfs_node_on_read_only_mount(dir)) return VFS_ERR_ACCESS_DENIED;
    if (!vfs_node_operation_begin(dir, &sb)) return VFS_ERR_DEVICE_GONE;
    actual = vfs_finddir_locked(dir, name);
    if (!vfs_node_identity_matches(actual, expected_super, expected_inode) ||
        actual->type != VFS_TYPE_DIRECTORY ||
        (!authorized && !vfs_directory_child_mutation_allowed(dir, actual))) {
        result = VFS_ERR_ACCESS_DENIED;
    } else {
        result = dir->ops->rmdir(dir, name);
    }
    vfs_node_operation_end(sb);
    return result;
}

int vfs_rmdir_expected(vfs_node_t *dir, const char *name,
                       vfs_super_t *expected_super, u64 expected_inode)
{
    return vfs_rmdir_expected_internal(dir, name, expected_super,
                                       expected_inode, false);
}

int vfs_rmdir_expected_authorized(vfs_node_t *dir, const char *name,
                                  vfs_super_t *expected_super,
                                  u64 expected_inode)
{
    return vfs_rmdir_expected_internal(dir, name, expected_super,
                                       expected_inode, true);
}

static int vfs_rename_expected_internal(
    vfs_node_t *src_dir, const char *src_name,
    vfs_super_t *expected_super, u64 expected_inode,
    vfs_node_t *dst_dir, const char *dst_name, bool authorized)
{
    vfs_super_t *sb;
    vfs_node_t *actual_source;
    int result;

    if (!vfs_node_is_live(src_dir) || !src_name || !*src_name ||
        !vfs_node_is_live(dst_dir) || !dst_name || !*dst_name ||
        src_dir->type != VFS_TYPE_DIRECTORY ||
        dst_dir->type != VFS_TYPE_DIRECTORY || !src_dir->ops ||
        !src_dir->ops->rename || expected_super != src_dir->super ||
        src_dir->super != dst_dir->super) {
        return VFS_ERR_INVALID_PARAM;
    }
    if (vfs_node_on_read_only_mount(src_dir) ||
        vfs_node_on_read_only_mount(dst_dir)) {
        return VFS_ERR_ACCESS_DENIED;
    }
    if (!vfs_node_operation_begin(src_dir, &sb)) return VFS_ERR_DEVICE_GONE;
    actual_source = vfs_finddir_locked(src_dir, src_name);
    if (!vfs_node_identity_matches(actual_source, expected_super,
                                   expected_inode) ||
        (!authorized && !vfs_directory_child_mutation_allowed(src_dir,
                                                               actual_source))) {
        result = VFS_ERR_ACCESS_DENIED;
    } else if (vfs_finddir_locked(dst_dir, dst_name)) {
        result = VFS_ERR_ALREADY_EXISTS;
    } else {
        result = src_dir->ops->rename(src_dir, src_name, dst_dir, dst_name);
    }
    vfs_node_operation_end(sb);
    return result;
}

int vfs_rename_expected(vfs_node_t *src_dir, const char *src_name,
                        vfs_super_t *expected_super, u64 expected_inode,
                        vfs_node_t *dst_dir, const char *dst_name)
{
    return vfs_rename_expected_internal(src_dir, src_name, expected_super,
                                        expected_inode, dst_dir, dst_name,
                                        false);
}

int vfs_rename_expected_authorized(
    vfs_node_t *src_dir, const char *src_name,
    vfs_super_t *expected_super, u64 expected_inode,
    vfs_node_t *dst_dir, const char *dst_name)
{
    return vfs_rename_expected_internal(src_dir, src_name, expected_super,
                                        expected_inode, dst_dir, dst_name,
                                        true);
}

int vfs_rename_trusted(vfs_node_t *src_dir, const char *src_name,
                       vfs_node_t *dst_dir, const char *dst_name) {
    vfs_super_t *sb;
    int result;

    if (!vfs_node_is_live(src_dir) || !src_name ||
        !vfs_node_is_live(dst_dir) || !dst_name ||
        src_dir->type != VFS_TYPE_DIRECTORY ||
        dst_dir->type != VFS_TYPE_DIRECTORY || !src_dir->ops ||
        !src_dir->ops->rename) return VFS_ERR_INVALID_PARAM;
    if (src_dir->super != dst_dir->super) return VFS_ERR_UNSUPPORTED;
    if (!vfs_node_operation_begin(src_dir, &sb)) return VFS_ERR_DEVICE_GONE;
    result = src_dir->ops->rename(src_dir, src_name, dst_dir, dst_name);
    vfs_node_operation_end(sb);
    return result;
}

int vfs_truncate_handle(vfs_file_handle_t *handle) {
    vfs_node_t *node;
    int result;

    if (!handle || !mutex_lock(&handle->offset_lock))
        return VFS_ERR_INVALID_PARAM;
    if (handle->valid != VFS_FILE_HANDLE_VALID || !handle->node ||
        !handle->super) {
        (void)mutex_unlock(&handle->offset_lock);
        return VFS_ERR_INVALID_PARAM;
    }
    if (!vfs_super_is_live(handle->super)) {
        (void)mutex_unlock(&handle->offset_lock);
        return VFS_ERR_DEVICE_GONE;
    }
    if (!(handle->flags & VFS_OPEN_WRITE)) {
        (void)mutex_unlock(&handle->offset_lock);
        return VFS_ERR_INVALID_PARAM;
    }
    node = handle->node;
    if (node->type != VFS_TYPE_FILE) {
        (void)mutex_unlock(&handle->offset_lock);
        return VFS_ERR_INVALID_PARAM;
    }
    if (!node->ops || !node->ops->truncate) {
        (void)mutex_unlock(&handle->offset_lock);
        return VFS_ERR_UNSUPPORTED;
    }
    if (vfs_node_on_read_only_mount(node) ||
        (!vfs_handle_authorized(handle, VFS_ACCESS_WRITE) &&
         !vfs_check_access(node, VFS_ACCESS_WRITE))) {
        (void)mutex_unlock(&handle->offset_lock);
        return VFS_ERR_ACCESS_DENIED;
    }
    if (!vfs_super_operation_lock(handle->super)) {
        (void)mutex_unlock(&handle->offset_lock);
        return VFS_ERR_DEVICE_GONE;
    }
    result = node->ops->truncate(node);
    vfs_super_operation_unlock(handle->super);
    (void)mutex_unlock(&handle->offset_lock);
    return result;
}

int vfs_truncate(vfs_node_t *node) {
    vfs_super_t *sb;
    int result;

    if (!node || node->type != VFS_TYPE_FILE || !node->ops ||
        !node->ops->truncate) return VFS_ERR_INVALID_PARAM;
    if (vfs_node_on_read_only_mount(node) ||
        !vfs_check_access(node, VFS_ACCESS_WRITE))
        return VFS_ERR_ACCESS_DENIED;
    if (!vfs_node_operation_begin(node, &sb)) return VFS_ERR_DEVICE_GONE;
    result = node->ops->truncate(node);
    vfs_node_operation_end(sb);
    return result;
}

int vfs_truncate_trusted(vfs_node_t *node) {
    vfs_super_t *sb;
    int result;

    if (!vfs_node_is_live(node) || node->type != VFS_TYPE_FILE || !node->ops ||
        !node->ops->truncate) return VFS_ERR_INVALID_PARAM;
    if (!vfs_node_operation_begin(node, &sb)) return VFS_ERR_DEVICE_GONE;
    result = node->ops->truncate(node);
    vfs_node_operation_end(sb);
    return result;
}

u64 vfs_read(vfs_node_t *node, u64 offset, u64 size, void *buffer) {
    vfs_super_t *sb;
    u64 result;

    if (!vfs_node_is_live(node) || !buffer || !node->ops || !node->ops->read) {
        return 0;
    }
    if (!vfs_check_access(node, VFS_ACCESS_READ)) return 0;
    if (!vfs_node_operation_begin(node, &sb)) return 0;
    result = node->ops->read(node, offset, size, buffer);
    vfs_node_operation_end(sb);
    return result;
}

u64 vfs_write(vfs_node_t *node, u64 offset, u64 size, const void *buffer) {
    vfs_super_t *sb;
    u64 result;

    if (!vfs_node_is_live(node) || !buffer || !node->ops || !node->ops->write) {
        return 0;
    }
    if (vfs_node_on_read_only_mount(node) ||
        !vfs_check_access(node, VFS_ACCESS_WRITE)) return 0;
    if (!vfs_node_operation_begin(node, &sb)) return 0;
    result = node->ops->write(node, offset, size, buffer);
    vfs_node_operation_end(sb);
    return result;
}

vfs_node_t *vfs_finddir(vfs_node_t *dir, const char *name) {
    return vfs_finddir_internal(dir, name, true);
}

vfs_node_t *vfs_finddir_trusted(vfs_node_t *dir, const char *name) {
    return vfs_finddir_internal(dir, name, false);
}

typedef struct {
    char name[VFS_MOUNT_PATH_MAX];
    u64 inode;
} vfs_mount_dirent_snapshot_t;

static bool vfs_readdir_internal(vfs_node_t *dir, u32 index,
                                 vfs_dirent_t *out_entry, bool enforce) {
    u32 base_count;
    u32 mount_index;
    u32 mount_count = 0;
    bool result = false;
    vfs_super_t *sb = NULL;
    vfs_mount_dirent_snapshot_t *mounts = NULL;

    if (!vfs_node_is_live(dir) || !out_entry ||
        dir->type != VFS_TYPE_DIRECTORY || !dir->ops ||
        !dir->ops->readdir) return false;
    if (enforce && !vfs_check_access(dir, VFS_ACCESS_READ)) return false;
    if (!vfs_node_operation_begin(dir, &sb)) return false;

    if (dir->ops->readdir(dir, index, out_entry)) {
        result = true;
        goto done;
    }
    base_count = 0;
    while (dir->ops->readdir(dir, base_count, out_entry)) base_count++;
    if (index < base_count) goto done;

    mounts = (vfs_mount_dirent_snapshot_t *)kmalloc(
        sizeof(*mounts) * VFS_MAX_MOUNTS);
    if (!mounts) goto done;

    /* Snapshot mount names while holding only VFS metadata state.  Filesystem
     * callbacks below may sleep and must never run under this spinlock. */
    {
        u64 flags = spin_lock_irqsave(&vfs_metadata_lock);
        for (u32 i = 1; i < VFS_MAX_MOUNTS; i++) {
            vfs_mount_t *mount = &mount_table[i];
            if (!vfs_mount_parent_matches(mount, dir)) continue;
            strncpy(mounts[mount_count].name, mount->name,
                    sizeof(mounts[mount_count].name) - 1U);
            mounts[mount_count].name[
                sizeof(mounts[mount_count].name) - 1U] = '\0';
            mounts[mount_count].inode = mount->sb && mount->sb->root_node
                ? mount->sb->root_node->inode : 0;
            mount_count++;
        }
        spin_unlock_irqrestore(&vfs_metadata_lock, flags);
    }

    mount_index = 0;
    for (u32 i = 0; i < mount_count; i++) {
        bool already_present = false;
        for (u32 base_index = 0; base_index < base_count; base_index++) {
            vfs_dirent_t base_entry;
            if (!dir->ops->readdir(dir, base_index, &base_entry)) break;
            if (strcmp(base_entry.name, mounts[i].name) == 0) {
                already_present = true;
                break;
            }
        }
        if (already_present) continue;
        if (mount_index == index - base_count) {
            strncpy(out_entry->name, mounts[i].name,
                    sizeof(out_entry->name) - 1U);
            out_entry->name[sizeof(out_entry->name) - 1U] = '\0';
            out_entry->inode = mounts[i].inode;
            out_entry->type = VFS_TYPE_DIRECTORY;
            result = true;
            break;
        }
        mount_index++;
    }

done:
    if (mounts) kfree(mounts);
    vfs_node_operation_end(sb);
    return result;
}

bool vfs_readdir(vfs_node_t *dir, u32 index, vfs_dirent_t *out_entry) {
    return vfs_readdir_internal(dir, index, out_entry, true);
}

bool vfs_readdir_trusted(vfs_node_t *dir, u32 index, vfs_dirent_t *out_entry) {
    return vfs_readdir_internal(dir, index, out_entry, false);
}
