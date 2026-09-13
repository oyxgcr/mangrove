/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <syscall.h>
#include <msr.h>
#include <cpu.h>
#include <scheduler.h>
#include <process.h>
#include <heap.h>
#include <pmm.h>
#include <vmm.h>
#include <terminal.h>
#include <mangrove_errors.h>
#include <mg/filesystem.h>
#include <mg/net.h>
#include <mg/network_service.h>
#include <mg/power.h>
#include <mg/service.h>
#include <mg/session_service.h>
#include <mg/device_service.h>
#include <mg/volume_service.h>
#include <mg/storage.h>
#include <mg/terminal.h>
#include <mg/identity.h>
#include <net/user.h>
#include <string.h>
#include <kprint.h>
#include <timer.h>
#include <timekeeping.h>
#include <platform_power.h>
#include <identity.h>
#include <pass.h>
#include <session.h>
#include <ipc.h>
#include <service.h>
#include <device.h>
#include <inspection.h>
#include <storage/gpt.h>
#include <storage/format.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

#define MSR_EFER  0xC0000080U
#define MSR_STAR  0xC0000081U
#define MSR_LSTAR 0xC0000082U
#define MSR_FMASK 0xC0000084U
#define EFER_SCE  (1ULL << 0)

typedef struct syscall_frame {
    u64 r15, r14, r13, r12, r10, r9, r8;
    u64 rbp, rdi, rsi, rdx, rbx, rax;
    u64 rcx, r11;
} syscall_frame_t;

extern void syscall_entry(void);
static void syscall_fail(syscall_frame_t *frame, i64 error);

void syscall_init_cpu(void)
{
    u64 efer = rdmsr(MSR_EFER);

    /* STAR selects kernel CS=0x08 and SYSRET user CS=0x3B/data SS=0x33. */
    wrmsr(MSR_STAR, (0x2BULL << 48) | (0x08ULL << 32));
    wrmsr(MSR_LSTAR, (u64)(uintptr_t)&syscall_entry);
    /* Mask IF, TF and DF while executing the entry path. */
    wrmsr(MSR_FMASK, (1ULL << 9) | (1ULL << 8) | (1ULL << 10));
    wrmsr(MSR_EFER, efer | EFER_SCE);
}

static bool syscall_user_buffer_valid(const void *buffer, u64 length)
{
    uintptr_t start = (uintptr_t)buffer;
    if (length == 0) return true;
    return vmm_user_range_valid((const void *)start, (usize)length);
}

static bool syscall_copy_path(const char *user_path, char *path, usize size)
{
    usize i;
    if (!user_path || !path || size < 2) return false;
    for (i = 0; i < size; i++) {
        if (!vmm_user_range_valid(user_path + i, 1)) return false;
        path[i] = user_path[i];
        if (path[i] == '\0') return i != 0;
    }
    return false;
}

static bool syscall_copy_bounded_text(const char *user_text, char *text,
                                      usize size, bool allow_empty)
{
    usize i;
    if (!user_text || !text || size == 0) return false;
    for (i = 0; i < size; i++) {
        if (!vmm_user_range_valid(user_text + i, 1)) return false;
        text[i] = user_text[i];
        if (!text[i]) return allow_empty || i != 0;
    }
    return false;
}

static bool syscall_copy_text(const char *user_text, char *text, usize size)
{
    return syscall_copy_bounded_text(user_text, text, size, false);
}

static bool syscall_copy_argument(const char *user_text, char *text,
                                  usize size)
{
    return syscall_copy_bounded_text(user_text, text, size, true);
}

static bool syscall_is_editable_configuration(const char *path)
{
    /* The canonical path is produced by process_resolve_path(), so this
     * boundary is deliberately component-based rather than a substring
     * match (for example, /configuration must not qualify). */
    return path && path[0] == '/' && path[1] == 'c' && path[2] == 'o' &&
           path[3] == 'n' && path[4] == 'f' && path[5] == '/' &&
           path[6] != '\0';
}

static i64 syscall_network_open(process_t *process, kernel_object_t *object)
{
    process_handle_t handle;
    if (!object) return MG_ERR_NO_MEMORY;
    if (!process_handle_install(process, object, OBJECT_RIGHT_READ | OBJECT_RIGHT_WRITE,
                                &handle)) {
        object_release(object);
        return MG_ERR_NO_MEMORY;
    }
    object_release(object);
    return (i64)handle;
}

static bool syscall_is_network_service(const process_t *process)
{
    return process && process->system_service &&
           process->service_id == MG_SERVICE_NETWORKD &&
           process->credentials_initialized &&
           identity_credentials_has_privilege(
               &process->credentials, IDENTITY_PRIVILEGE_MANAGE_NETWORK);
}

static bool syscall_is_logind(const process_t *process)
{
    return process && process->system_service &&
           process->service_id == MG_SERVICE_LOGIND &&
           process->credentials_initialized &&
           identity_credentials_has_privilege(
               &process->credentials, IDENTITY_PRIVILEGE_MANAGE_SESSIONS);
}

static bool syscall_is_volumed(const process_t *process)
{
    return process && process->system_service &&
           process->service_id == MG_SERVICE_VOLUMED &&
           process->credentials_initialized &&
           identity_credentials_has_privilege(
               &process->credentials, IDENTITY_PRIVILEGE_MANAGE_DEVICES) &&
           identity_credentials_has_privilege(
               &process->credentials, IDENTITY_PRIVILEGE_MANAGE_STORAGE);
}

static bool syscall_is_diskutil(const process_t *process)
{
    return process && !process->system_service &&
           process->credentials_initialized &&
           !strcmp(process->name, "diskutil") &&
           identity_credentials_has_privilege(
               &process->credentials, IDENTITY_PRIVILEGE_MANAGE_STORAGE);
}

static bool syscall_fixed_text_valid(const char *text, usize capacity,
                                     bool allow_empty)
{
    if (!text || !capacity) return false;
    for (usize index = 0; index < capacity; index++) {
        if (text[index] == '\0') return allow_empty || index != 0U;
    }
    return false;
}

static bool syscall_volume_path_valid(const char *path, char *name,
                                      usize name_capacity)
{
    const char prefix[] = "/vol/";
    usize prefix_length = sizeof(prefix) - 1U;
    usize length;

    if (!path || !name || name_capacity < 2U ||
        !syscall_fixed_text_valid(path, MG_VOLUME_MOUNT_MAX, false))
        return false;
    length = strlen(path);
    if (length <= prefix_length || strncmp(path, prefix, prefix_length) != 0)
        return false;
    if (strlen(path + prefix_length) >= name_capacity ||
        !strcmp(path + prefix_length, ".") ||
        !strcmp(path + prefix_length, "..")) return false;
    for (const char *part = path + prefix_length; *part; part++)
        if (*part == '/') return false;
    memcpy(name, path + prefix_length, strlen(path + prefix_length) + 1U);
    return true;
}

static bool syscall_volume_device_allowed(block_device_t *device,
                                          u64 expected_parent_id)
{
    gpt_partition_info_t partition;
    u64 parent_id;

    if (!device || !block_device_is_live(device)) return false;
    if (device->type == BLOCK_DEVICE_USB) {
        if (expected_parent_id != 0ULL) return false;
        for (u32 index = 0; index < block_device_count(); index++) {
            block_device_t *child = block_get_device(index);
            if (!child || child->type != BLOCK_DEVICE_PARTITION) continue;
            if (!gpt_get_partition_info(child, &partition) ||
                !gpt_partition_parent_matches(&partition, device)) continue;
            if (!strcmp(partition.name, GPT_MANGROVE_ROOT_NAME) ||
                !strcmp(partition.name, GPT_MANGROVE_BOOT_NAME)) return false;
        }
        return true;
    }
    if (device->type != BLOCK_DEVICE_PARTITION ||
        !gpt_get_partition_info(device, &partition) || !partition.parent ||
        !block_device_is_live(partition.parent) ||
        partition.parent->type != BLOCK_DEVICE_USB)
        return false;
    parent_id = BLOCK_DEVICE_ID_BASE | (partition.parent->id + 1ULL);
    if (expected_parent_id != parent_id) return false;
    if (!strcmp(partition.name, GPT_MANGROVE_ROOT_NAME) ||
        !strcmp(partition.name, GPT_MANGROVE_BOOT_NAME)) return false;
    return true;
}

static u32 syscall_volume_collect_children(block_device_t *parent,
                                           block_device_t *devices[],
                                           u32 capacity)
{
    u32 count = 0;

    if (!parent || !devices || capacity == 0U) return 0;
    for (u32 index = 0; index < block_device_count(); index++) {
        block_device_t *device = block_get_device(index);
        gpt_partition_info_t partition;
        if (!device || !block_device_is_live(device)) continue;
        if (device != parent) {
            if (device->type != BLOCK_DEVICE_PARTITION ||
                !gpt_get_partition_info(device, &partition) ||
                !gpt_partition_parent_matches(&partition, parent)) continue;
        }
        if (count >= capacity) break;
        devices[count++] = device;
    }
    return count;
}

static bool syscall_storage_device_matches(block_device_t *device,
                                           u64 expected_parent_id)
{
    gpt_partition_info_t partition;

    if (!device || !block_device_is_live(device)) return false;
    if (device->type != BLOCK_DEVICE_PARTITION)
        return expected_parent_id == 0ULL;
    if (!gpt_get_partition_info(device, &partition) || !partition.parent ||
        !block_device_is_live(partition.parent)) return false;
    return expected_parent_id ==
           (BLOCK_DEVICE_ID_BASE | (partition.parent->id + 1ULL));
}

static bool syscall_storage_system_managed(block_device_t *device)
{
    gpt_partition_info_t partition;

    if (!device) return true;
    if (device->type == BLOCK_DEVICE_PARTITION) {
        if (!gpt_get_partition_info(device, &partition)) return false;
        if (!strcmp(partition.name, GPT_MANGROVE_ROOT_NAME) ||
            !strcmp(partition.name, GPT_MANGROVE_BOOT_NAME)) return true;
        device = partition.parent;
    }
    if (!device) return true;
    for (u32 index = 0; index < block_device_count(); index++) {
        block_device_t *child = block_get_device(index);
        if (!child || child->type != BLOCK_DEVICE_PARTITION ||
            !gpt_get_partition_info(child, &partition) ||
            !gpt_partition_parent_matches(&partition, device)) continue;
        if (!strcmp(partition.name, GPT_MANGROVE_ROOT_NAME) ||
            !strcmp(partition.name, GPT_MANGROVE_BOOT_NAME)) return true;
    }
    return false;
}

static i64 syscall_authorize_volume_request(process_t *process,
                                            process_handle_t request_handle,
                                            u32 operation)
{
    const char *description;

    if (!syscall_is_volumed(process)) return MG_ERR_PRIVILEGE_REQUIRED;
    switch (operation) {
        case MG_VOLUME_OP_MOUNT:
            description = "Mount a removable volume.";
            break;
        case MG_VOLUME_OP_UNMOUNT:
            description = "Unmount a removable volume.";
            break;
        case MG_VOLUME_OP_EJECT:
            description = "Eject removable media.";
            break;
        default:
            return MG_ERR_BAD_ARGUMENT;
    }
    return pass_authorize_request(process, request_handle,
                                  IDENTITY_PRIVILEGE_MANAGE_STORAGE,
                                  description);
}

static void syscall_copy_identity(const user_identity_t *source,
                                  mg_identity_t *destination)
{
    memset(destination, 0, sizeof(*destination));
    destination->uid = source->uid;
    destination->role = source->role;
    strncpy(destination->username, source->username,
            sizeof(destination->username) - 1U);
    strncpy(destination->home, source->home,
            sizeof(destination->home) - 1U);
}

static i64 syscall_authorize_network_request(process_t *process,
                                             process_handle_t request_handle,
                                             u32 operation)
{
    const char *description;

    if (!syscall_is_network_service(process))
        return MG_ERR_PRIVILEGE_REQUIRED;
    switch (operation) {
        case MG_NETWORK_OP_SET_AUTOMATIC:
            description = "Configure the network automatically.";
            break;
        case MG_NETWORK_OP_SET_MANUAL:
            description = "Configure the network manually.";
            break;
        case MG_NETWORK_OP_ENABLE:
            description = "Enable the network interface.";
            break;
        case MG_NETWORK_OP_DISABLE:
            description = "Disable the network interface.";
            break;
        case MG_NETWORK_OP_RENEW:
            description = "Renew the DHCP lease.";
            break;
        case MG_NETWORK_OP_RELOAD:
            description = "Reload the network configuration.";
            break;
        default:
            return MG_ERR_BAD_ARGUMENT;
    }
    return pass_authorize_request(
        process, request_handle, IDENTITY_PRIVILEGE_MANAGE_NETWORK,
        description);
}

static void syscall_network(process_t *process, syscall_frame_t *frame)
{
    mg_net_request_t request;
    kernel_object_t *object;
    i64 result;

    if (!process || !frame || !frame->rdi ||
        !syscall_user_buffer_valid((const void *)(uintptr_t)frame->rdi,
                                   sizeof(request))) {
        syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
        return;
    }
    memcpy(&request, (const void *)(uintptr_t)frame->rdi, sizeof(request));
    switch (request.operation) {
        case MG_NET_OP_INFO:
            if (!request.result || request.result_capacity < sizeof(mg_net_info_t) ||
                !syscall_user_buffer_valid(request.result, sizeof(mg_net_info_t))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT); return;
            }
            frame->rax = (u64)net_user_info((mg_net_info_t *)request.result); return;
        case MG_NET_OP_RESOLVE_A: {
            char hostname[256];
            if (!request.buffer || !request.result || request.result_capacity < sizeof(mg_ipv4_addr_t) ||
                !syscall_copy_text((const char *)request.buffer, hostname, sizeof(hostname)) ||
                !syscall_user_buffer_valid(request.result, sizeof(mg_ipv4_addr_t))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT); return;
            }
            frame->rax = (u64)net_user_resolve_a(hostname, (mg_ipv4_addr_t *)request.result,
                                                 request.timeout_ms);
            return;
        }
        case MG_NET_OP_INTERFACES:
            if (request.result && request.result_capacity &&
                !syscall_user_buffer_valid(request.result, request.result_capacity)) { syscall_fail(frame, MG_ERR_BAD_ARGUMENT); return; }
            frame->rax = (u64)net_user_interfaces((mg_net_interface_info_t *)request.result, request.result_capacity); return;
        case MG_NET_OP_ROUTES:
            if (request.result && request.result_capacity &&
                !syscall_user_buffer_valid(request.result, request.result_capacity)) { syscall_fail(frame, MG_ERR_BAD_ARGUMENT); return; }
            frame->rax = (u64)net_user_routes((mg_net_route_info_t *)request.result, request.result_capacity); return;
        case MG_NET_OP_NEIGHBORS:
            if (request.result && request.result_capacity &&
                !syscall_user_buffer_valid(request.result, request.result_capacity)) { syscall_fail(frame, MG_ERR_BAD_ARGUMENT); return; }
            frame->rax = (u64)net_user_neighbors((mg_net_neighbor_info_t *)request.result, request.result_capacity); return;
        case MG_NET_OP_CONNECTIONS:
            if (request.result && request.result_capacity &&
                !syscall_user_buffer_valid(request.result, request.result_capacity)) { syscall_fail(frame, MG_ERR_BAD_ARGUMENT); return; }
            frame->rax = (u64)net_user_connections((mg_net_connection_info_t *)request.result, request.result_capacity); return;
        case MG_NET_OP_RENEW:
            if (!syscall_is_network_service(process)) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            if (request.flags > 1U) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            frame->rax = (u64)net_user_dhcp_renew(
                request.timeout_ms, request.flags != 0U); return;
        case MG_NET_OP_SET_MANUAL: {
            mg_net_manual_config_t configuration;
            if (!syscall_is_network_service(process)) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            if (!request.buffer || request.buffer_length < sizeof(configuration) ||
                !syscall_user_buffer_valid(request.buffer, sizeof(configuration))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT); return;
            }
            memcpy(&configuration, request.buffer, sizeof(configuration));
            frame->rax = (u64)net_user_set_manual(&configuration); return;
        }
        case MG_NET_OP_SET_AUTOMATIC: {
            if (!syscall_is_network_service(process)) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            frame->rax = (u64)net_user_set_automatic(request.timeout_ms); return;
        }
        case MG_NET_OP_RELOAD: {
            if (!syscall_is_network_service(process)) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            frame->rax = (u64)net_user_reload(); return;
        }
        case MG_NET_OP_SERVICE_SET_ENABLED:
            if (!syscall_is_network_service(process)) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            if (request.flags > 1U) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            frame->rax = (u64)net_user_set_enabled(request.flags != 0U);
            return;
        case MG_NET_OP_SERVICE_CLEAR:
            if (!syscall_is_network_service(process)) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            frame->rax = (u64)net_user_clear_runtime();
            return;
        case MG_NET_OP_ICMP_OPEN:
            object = net_user_icmp_create();
            frame->rax = (u64)(object ? syscall_network_open(process, object) : MG_ERR_BUSY);
            return;
        case MG_NET_OP_DATAGRAM_OPEN:
            object = net_user_datagram_create(request.endpoint.port, &result);
            frame->rax = (u64)(object ? syscall_network_open(process, object) : result);
            return;
        case MG_NET_OP_STREAM_CONNECT:
            object = net_user_stream_connect(&request.endpoint, request.timeout_ms, &result);
            frame->rax = (u64)(object ? syscall_network_open(process, object) : result);
            return;
        case MG_NET_OP_ICMP_ECHO:
            object = process_handle_lookup(process, request.handle, OBJECT_TYPE_NETWORK_ICMP,
                                           OBJECT_RIGHT_WRITE);
            if (!object || !request.result || request.result_capacity < sizeof(mg_icmp_echo_result_t) ||
                (!request.buffer && request.buffer_length) ||
                !syscall_user_buffer_valid(request.result, sizeof(mg_icmp_echo_result_t)) ||
                !syscall_user_buffer_valid(request.buffer, request.buffer_length)) {
                syscall_fail(frame, !object ? MG_ERR_INVALID_HANDLE : MG_ERR_BAD_ARGUMENT); return;
            }
            frame->rax = (u64)net_user_icmp_echo(object, &request.endpoint.address,
                                                  request.buffer, request.buffer_length,
                                                  request.timeout_ms,
                                                  (mg_icmp_echo_result_t *)request.result);
            return;
        case MG_NET_OP_DATAGRAM_SEND:
            object = process_handle_lookup(process, request.handle, OBJECT_TYPE_NETWORK_DATAGRAM,
                                           OBJECT_RIGHT_WRITE);
            if (!object || (!request.buffer && request.buffer_length) ||
                !syscall_user_buffer_valid(request.buffer, request.buffer_length)) {
                syscall_fail(frame, !object ? MG_ERR_INVALID_HANDLE : MG_ERR_BAD_ARGUMENT); return;
            }
            frame->rax = (u64)net_user_datagram_send(object, &request.endpoint,
                                                      request.buffer, request.buffer_length,
                                                      request.timeout_ms); return;
        case MG_NET_OP_DATAGRAM_RECEIVE:
            object = process_handle_lookup(process, request.handle, OBJECT_TYPE_NETWORK_DATAGRAM,
                                           OBJECT_RIGHT_READ);
            if (!object || !request.buffer || !request.result ||
                request.result_capacity < sizeof(mg_datagram_result_t) ||
                !syscall_user_buffer_valid(request.buffer, request.buffer_length) ||
                !syscall_user_buffer_valid(request.result, sizeof(mg_datagram_result_t))) {
                syscall_fail(frame, !object ? MG_ERR_INVALID_HANDLE : MG_ERR_BAD_ARGUMENT); return;
            }
            frame->rax = (u64)net_user_datagram_receive(object, (void *)request.buffer,
                                                         request.buffer_length, request.timeout_ms,
                                                         (mg_datagram_result_t *)request.result); return;
        case MG_NET_OP_STREAM_SEND:
            object = process_handle_lookup(process, request.handle, OBJECT_TYPE_NETWORK_STREAM,
                                           OBJECT_RIGHT_WRITE);
            if (!object || (!request.buffer && request.buffer_length) ||
                !syscall_user_buffer_valid(request.buffer, request.buffer_length)) {
                syscall_fail(frame, !object ? MG_ERR_INVALID_HANDLE : MG_ERR_BAD_ARGUMENT); return;
            }
            frame->rax = (u64)net_user_stream_send(object, request.buffer,
                                                    request.buffer_length, request.timeout_ms); return;
        case MG_NET_OP_STREAM_RECEIVE:
            object = process_handle_lookup(process, request.handle, OBJECT_TYPE_NETWORK_STREAM,
                                           OBJECT_RIGHT_READ);
            if (!object || !request.buffer || !request.buffer_length ||
                !syscall_user_buffer_valid(request.buffer, request.buffer_length)) {
                syscall_fail(frame, !object ? MG_ERR_INVALID_HANDLE : MG_ERR_BAD_ARGUMENT); return;
            }
            frame->rax = (u64)net_user_stream_receive(object, (void *)request.buffer,
                                                       request.buffer_length, request.timeout_ms); return;
        case MG_NET_OP_STREAM_CLOSE:
            object = process_handle_lookup(process, request.handle, OBJECT_TYPE_NETWORK_STREAM,
                                           OBJECT_RIGHT_WRITE);
            if (!object) { syscall_fail(frame, MG_ERR_INVALID_HANDLE); return; }
            result = net_user_stream_close(object);
            if (result == MG_OK) (void)process_handle_close(process, request.handle);
            frame->rax = (u64)result; return;
        case MG_NET_OP_ICMP_CLOSE:
            object = process_handle_lookup(process, request.handle, OBJECT_TYPE_NETWORK_ICMP,
                                           OBJECT_RIGHT_WRITE);
            if (!object) { syscall_fail(frame, MG_ERR_INVALID_HANDLE); return; }
            frame->rax = process_handle_close(process, request.handle) ? MG_OK : MG_ERR_INVALID_HANDLE;
            return;
        case MG_NET_OP_DATAGRAM_CLOSE:
            object = process_handle_lookup(process, request.handle, OBJECT_TYPE_NETWORK_DATAGRAM,
                                           OBJECT_RIGHT_WRITE);
            if (!object) { syscall_fail(frame, MG_ERR_INVALID_HANDLE); return; }
            frame->rax = process_handle_close(process, request.handle) ? MG_OK : MG_ERR_INVALID_HANDLE;
            return;
        default:
            syscall_fail(frame, MG_ERR_UNSUPPORTED); return;
    }
}

static void syscall_fail(syscall_frame_t *frame, i64 error)
{
    frame->rax = (u64)error;
}

static i64 syscall_vfs_error(int result)
{
    switch (result) {
        case VFS_OK: return MG_OK;
        case VFS_ERR_NOT_FOUND: return MG_ERR_NOT_FOUND;
        case VFS_ERR_NO_MEM: return MG_ERR_NO_MEMORY;
        case VFS_ERR_UNSUPPORTED: return MG_ERR_UNSUPPORTED;
        case VFS_ERR_NOT_EMPTY: return MG_ERR_NOT_EMPTY;
        case VFS_ERR_IO: return MG_ERR_IO;
        case VFS_ERR_BAD_FORMAT: return MG_ERR_IO;
        case VFS_ERR_ACCESS_DENIED: return MG_ERR_ACCESS_DENIED;
        case VFS_ERR_NOT_DIRECTORY: return MG_ERR_NOT_DIRECTORY;
        case VFS_ERR_BUSY: return MG_ERR_BUSY;
        case VFS_ERR_DEVICE_GONE: return MG_ERR_DEVICE_GONE;
        case VFS_ERR_NO_SPACE: return MG_ERR_IO;
        case VFS_ERR_ALREADY_EXISTS: return MG_ERR_ALREADY_EXISTS;
        default: return MG_ERR_BAD_ARGUMENT;
    }
}

static bool syscall_resolve_path(process_t *process, const char *user_path,
                                 char *resolved, usize resolved_size)
{
    char path[256];

    return syscall_copy_path(user_path, path, sizeof(path)) &&
           process_resolve_path(process, path, resolved, resolved_size);
}

static bool syscall_resolve_parent(process_t *process, const char *user_path,
                                   char *parent, usize parent_size,
                                   char *name, usize name_size)
{
    char path[256];

    return syscall_copy_path(user_path, path, sizeof(path)) &&
           process_split_path(process, path, parent, parent_size,
                              name, name_size);
}

static i64 syscall_create_path(process_t *process, const char *user_path,
                               bool directory)
{
    char parent_path[512];
    char name[256];
    vfs_node_t *parent = NULL;
    vfs_node_t *created = NULL;
    int result;
    int lookup_result;

    if (!syscall_resolve_parent(process, user_path, parent_path,
                                sizeof(parent_path), name, sizeof(name))) {
        return MG_ERR_BAD_ARGUMENT;
    }
    lookup_result = vfs_lookup(parent_path, &parent);
    if (lookup_result != VFS_OK || !parent) {
        return syscall_vfs_error(lookup_result);
    }
    if (parent->type != VFS_TYPE_DIRECTORY) return MG_ERR_NOT_DIRECTORY;
    if (!vfs_check_access(parent, VFS_ACCESS_WRITE)) {
        return MG_ERR_ACCESS_DENIED;
    }
    if (vfs_finddir(parent, name)) return MG_ERR_ALREADY_EXISTS;
    result = directory ? vfs_mkdir(parent, name, &created) :
                         vfs_create(parent, name, &created);
    return syscall_vfs_error(result);
}

static bool syscall_admin_credentials(process_t *process,
                                      process_credentials_t *credentials)
{
    return process && process == process_current() && credentials &&
           process_get_credentials(process, credentials) &&
           identity_credentials_is_admin(credentials);
}

static bool syscall_admin_can_traverse(const vfs_node_t *node,
                                       const process_credentials_t *credentials)
{
    return node && credentials && vfs_node_is_live(node) &&
           (vfs_check_access(node, VFS_ACCESS_READ) ||
            vfs_administrator_override_allowed(node, credentials));
}

static bool syscall_admin_lookup_path(const char *path,
                                      const process_credentials_t *credentials,
                                      vfs_node_t **out_node)
{
    vfs_node_t *current;
    char prefix[512];
    const char *cursor;
    usize prefix_length = 1;

    if (!path || path[0] != '/' || !credentials || !out_node) return false;
    current = vfs_get_root_node();
    if (!current || !vfs_node_is_live(current)) return false;
    prefix[0] = '/';
    prefix[1] = '\0';
    cursor = path + 1;
    while (*cursor) {
        const char *component = cursor;
        usize component_length;
        vfs_node_t *next = NULL;

        while (*cursor && *cursor != '/') cursor++;
        component_length = (usize)(cursor - component);
        if (component_length == 0) {
            while (*cursor == '/') cursor++;
            continue;
        }
        if (!syscall_admin_can_traverse(current, credentials) ||
            component_length >= 256U ||
            prefix_length > sizeof(prefix) - component_length - 1U) {
            return false;
        }
        if (prefix_length > 1U) prefix[prefix_length++] = '/';
        memcpy(prefix + prefix_length, component, component_length);
        prefix_length += component_length;
        prefix[prefix_length] = '\0';
        if (vfs_lookup_trusted(prefix, &next) != VFS_OK || !next) return false;
        current = next;
        while (*cursor == '/') cursor++;
    }
    *out_node = current;
    return true;
}

static bool syscall_admin_same_node(const vfs_node_t *left,
                                    const vfs_node_t *right)
{
    return left && right && left->super == right->super &&
           left->inode == right->inode;
}

static int syscall_admin_authorize(process_t *process,
                                   const char *description,
                                   process_credentials_t *credentials)
{
    int result;

    if (!syscall_admin_credentials(process, credentials))
        return MG_ERR_PRIVILEGE_REQUIRED;
    result = pass_authorize_current(IDENTITY_PRIVILEGE_MANAGE_USER_DATA,
                                    description);
    if (result != MG_OK) return result;
    if (!syscall_admin_credentials(process, credentials))
        return MG_ERR_ACCESS_DENIED;
    return MG_OK;
}

static bool syscall_admin_parent_allowed(
    vfs_node_t *parent, const process_credentials_t *credentials)
{
    return parent && parent->type == VFS_TYPE_DIRECTORY && credentials &&
           (vfs_check_access(parent, VFS_ACCESS_WRITE) ||
            vfs_administrator_override_allowed(parent, credentials));
}

static bool syscall_admin_user_parent_allowed(
    vfs_node_t *parent, const process_credentials_t *credentials)
{
    return parent && parent->type == VFS_TYPE_DIRECTORY && credentials &&
           vfs_administrator_override_allowed(parent, credentials);
}

static int syscall_admin_create_path(process_t *process, const char *user_path,
                                     bool directory)
{
    char parent_path[512];
    char name[256];
    vfs_node_t *parent = NULL;
    vfs_node_t *revalidated_parent = NULL;
    vfs_node_t *created = NULL;
    process_credentials_t credentials;
    int result;

    if (!syscall_resolve_parent(process, user_path, parent_path,
                                sizeof(parent_path), name, sizeof(name))) {
        return MG_ERR_BAD_ARGUMENT;
    }
    if (!syscall_admin_credentials(process, &credentials) ||
        !syscall_admin_lookup_path(parent_path, &credentials, &parent) ||
        !syscall_admin_user_parent_allowed(parent, &credentials)) {
        return MG_ERR_ACCESS_DENIED;
    }
    if (vfs_finddir_trusted(parent, name)) return MG_ERR_ALREADY_EXISTS;
    result = syscall_admin_authorize(
        process, directory ? "Create a directory in regular-user data."
                           : "Create a file in regular-user data.",
        &credentials);
    if (result != MG_OK) return result;
    if (!syscall_admin_lookup_path(parent_path, &credentials,
                                   &revalidated_parent) ||
        !syscall_admin_same_node(parent, revalidated_parent) ||
        !syscall_admin_user_parent_allowed(revalidated_parent, &credentials)) {
        return MG_ERR_ACCESS_DENIED;
    }
    if (vfs_finddir_trusted(revalidated_parent, name))
        return MG_ERR_ALREADY_EXISTS;
    result = directory
        ? vfs_mkdir_owned(revalidated_parent, name,
                          revalidated_parent->owner_uid,
                          VFS_DEFAULT_DIRECTORY_PERMISSIONS, &created)
        : vfs_create_owned(revalidated_parent, name,
                           revalidated_parent->owner_uid,
                           VFS_DEFAULT_FILE_PERMISSIONS, &created);
    return syscall_vfs_error(result);
}

static int syscall_admin_open(process_t *process, const char *user_path,
                              u32 flags)
{
    char resolved[512];
    char parent_path[512];
    char name[256];
    vfs_node_t *parent = NULL;
    vfs_node_t *revalidated_parent = NULL;
    vfs_node_t *node = NULL;
    vfs_node_t *revalidated_node = NULL;
    process_credentials_t credentials;
    process_handle_t handle;
    kernel_object_t *object;
    u64 inode;
    vfs_super_t *super;
    int result;
    u32 rights = 0;

    if (flags != VFS_OPEN_READ && flags != VFS_OPEN_WRITE &&
        flags != VFS_OPEN_RDWR) return MG_ERR_BAD_ARGUMENT;
    if (!syscall_resolve_path(process, user_path, resolved, sizeof(resolved)) ||
        !process_split_path(process, resolved, parent_path,
                            sizeof(parent_path), name, sizeof(name)) ||
        !syscall_admin_credentials(process, &credentials) ||
        !syscall_admin_lookup_path(parent_path, &credentials, &parent) ||
        !syscall_admin_parent_allowed(parent, &credentials)) {
        return MG_ERR_ACCESS_DENIED;
    }
    node = vfs_finddir_trusted(parent, name);
    if (!node) return MG_ERR_NOT_FOUND;
    if (node->type != VFS_TYPE_FILE ||
        !vfs_administrator_override_allowed(node, &credentials)) {
        return node->type != VFS_TYPE_FILE ? MG_ERR_NOT_FOUND
                                           : MG_ERR_ACCESS_DENIED;
    }
    super = node->super;
    inode = node->inode;
    result = syscall_admin_authorize(
        process, "Open regular-user data with administrator access.",
        &credentials);
    if (result != MG_OK) return result;
    if (!syscall_admin_lookup_path(parent_path, &credentials,
                                   &revalidated_parent) ||
        !syscall_admin_same_node(parent, revalidated_parent) ||
        !syscall_admin_parent_allowed(revalidated_parent, &credentials)) {
        return MG_ERR_ACCESS_DENIED;
    }
    revalidated_node = vfs_finddir_trusted(revalidated_parent, name);
    if (!syscall_admin_same_node(node, revalidated_node) ||
        revalidated_node->super != super || revalidated_node->inode != inode ||
        !vfs_administrator_override_allowed(revalidated_node, &credentials)) {
        return MG_ERR_ACCESS_DENIED;
    }
    object = object_file_create_node_user_authorized(revalidated_node, flags);
    if (!object) return MG_ERR_IO;
    if (flags & VFS_OPEN_READ) rights |= OBJECT_RIGHT_READ;
    if (flags & VFS_OPEN_WRITE) rights |= OBJECT_RIGHT_WRITE;
    if (!process_handle_install(process, object, rights, &handle)) {
        object_release(object);
        return MG_ERR_NO_MEMORY;
    }
    object_release(object);
    return (int)handle;
}

static int syscall_admin_remove(process_t *process, const char *user_path)
{
    char parent_path[512];
    char name[256];
    vfs_node_t *parent = NULL;
    vfs_node_t *revalidated_parent = NULL;
    vfs_node_t *node = NULL;
    vfs_node_t *revalidated_node = NULL;
    process_credentials_t credentials;
    vfs_super_t *super;
    u64 inode;
    vfs_node_type_t type;
    int result;

    if (!syscall_resolve_parent(process, user_path, parent_path,
                                sizeof(parent_path), name, sizeof(name)) ||
        !syscall_admin_credentials(process, &credentials) ||
        !syscall_admin_lookup_path(parent_path, &credentials, &parent) ||
        !syscall_admin_parent_allowed(parent, &credentials)) {
        return MG_ERR_ACCESS_DENIED;
    }
    node = vfs_finddir_trusted(parent, name);
    if (!node) return MG_ERR_NOT_FOUND;
    if (node->super != parent->super ||
        !vfs_administrator_override_allowed(node, &credentials)) {
        return MG_ERR_ACCESS_DENIED;
    }
    super = node->super;
    inode = node->inode;
    type = node->type;
    result = syscall_admin_authorize(
        process, "Remove regular-user data.", &credentials);
    if (result != MG_OK) return result;
    if (!syscall_admin_lookup_path(parent_path, &credentials,
                                   &revalidated_parent) ||
        !syscall_admin_same_node(parent, revalidated_parent) ||
        !syscall_admin_parent_allowed(revalidated_parent, &credentials)) {
        return MG_ERR_ACCESS_DENIED;
    }
    revalidated_node = vfs_finddir_trusted(revalidated_parent, name);
    if (!syscall_admin_same_node(node, revalidated_node) ||
        revalidated_node->super != super || revalidated_node->inode != inode ||
        revalidated_node->type != type ||
        !vfs_administrator_override_allowed(revalidated_node, &credentials)) {
        return MG_ERR_ACCESS_DENIED;
    }
    result = type == VFS_TYPE_DIRECTORY
        ? vfs_rmdir_expected_authorized(revalidated_parent, name, super, inode)
        : vfs_unlink_expected_authorized(revalidated_parent, name, super, inode);
    return syscall_vfs_error(result);
}

static int syscall_admin_move(process_t *process, const char *source,
                              const char *destination)
{
    char source_parent_path[512], destination_parent_path[512];
    char source_name[256], destination_name[256];
    vfs_node_t *source_parent = NULL, *destination_parent = NULL;
    vfs_node_t *revalidated_source_parent = NULL;
    vfs_node_t *revalidated_destination_parent = NULL;
    vfs_node_t *source_node = NULL, *revalidated_source = NULL;
    process_credentials_t credentials;
    vfs_super_t *super;
    u64 inode;
    int result;

    if (!syscall_resolve_parent(process, source, source_parent_path,
                                sizeof(source_parent_path), source_name,
                                sizeof(source_name)) ||
        !syscall_resolve_parent(process, destination, destination_parent_path,
                                sizeof(destination_parent_path),
                                destination_name, sizeof(destination_name)) ||
        !syscall_admin_credentials(process, &credentials) ||
        !syscall_admin_lookup_path(source_parent_path, &credentials,
                                   &source_parent) ||
        !syscall_admin_lookup_path(destination_parent_path, &credentials,
                                   &destination_parent) ||
        !syscall_admin_parent_allowed(source_parent, &credentials) ||
        !syscall_admin_parent_allowed(destination_parent, &credentials)) {
        return MG_ERR_ACCESS_DENIED;
    }
    if (source_parent->super != destination_parent->super)
        return MG_ERR_UNSUPPORTED;
    source_node = vfs_finddir_trusted(source_parent, source_name);
    if (!source_node) return MG_ERR_NOT_FOUND;
    if (source_node->super != source_parent->super ||
        !vfs_administrator_override_allowed(source_node, &credentials)) {
        return MG_ERR_ACCESS_DENIED;
    }
    if (vfs_finddir_trusted(destination_parent, destination_name))
        return MG_ERR_ALREADY_EXISTS;
    super = source_node->super;
    inode = source_node->inode;
    result = syscall_admin_authorize(
        process, "Move regular-user data.", &credentials);
    if (result != MG_OK) return result;
    if (!syscall_admin_lookup_path(source_parent_path, &credentials,
                                   &revalidated_source_parent) ||
        !syscall_admin_lookup_path(destination_parent_path, &credentials,
                                   &revalidated_destination_parent) ||
        !syscall_admin_same_node(source_parent, revalidated_source_parent) ||
        !syscall_admin_same_node(destination_parent,
                                 revalidated_destination_parent) ||
        !syscall_admin_parent_allowed(revalidated_source_parent,
                                      &credentials) ||
        !syscall_admin_parent_allowed(revalidated_destination_parent,
                                      &credentials)) {
        return MG_ERR_ACCESS_DENIED;
    }
    revalidated_source = vfs_finddir_trusted(revalidated_source_parent,
                                             source_name);
    if (!syscall_admin_same_node(source_node, revalidated_source) ||
        revalidated_source->super != super ||
        revalidated_source->inode != inode ||
        !vfs_administrator_override_allowed(revalidated_source,
                                            &credentials) ||
        vfs_finddir_trusted(revalidated_destination_parent, destination_name)) {
        return MG_ERR_ACCESS_DENIED;
    }
    result = vfs_rename_expected_authorized(
        revalidated_source_parent, source_name, super, inode,
        revalidated_destination_parent, destination_name);
    return syscall_vfs_error(result);
}

void syscall_dispatch(void *raw_frame)
{
    syscall_frame_t *frame = (syscall_frame_t *)raw_frame;

    if (!frame) return;

    switch (frame->rax) {
        case SYSCALL_OPEN: {
            char path[256];
            char resolved[512];
            vfs_node_t *node = NULL;
            int lookup_result;
            u32 flags = (u32)frame->rsi;
            u32 rights;
            bool authorized_configuration_write;
            process_handle_t handle;
            kernel_object_t *object;
            if (!syscall_copy_path((const char *)(uintptr_t)frame->rdi,
                                   path, sizeof(path))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            if (!process_resolve_path(process_current(), path,
                                      resolved, sizeof(resolved))) {
                syscall_fail(frame, MG_ERR_NOT_FOUND);
                return;
            }
            if (flags != VFS_OPEN_READ && flags != VFS_OPEN_WRITE &&
                flags != VFS_OPEN_RDWR) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            lookup_result = vfs_lookup(resolved, &node);
            if (lookup_result != VFS_OK || !node) {
                syscall_fail(frame, syscall_vfs_error(lookup_result));
                return;
            }
            if (node->type != VFS_TYPE_FILE) {
                syscall_fail(frame, MG_ERR_NOT_FOUND);
                return;
            }
            authorized_configuration_write =
                (flags & VFS_OPEN_WRITE) != 0U &&
                syscall_is_editable_configuration(resolved);
            if (((flags & VFS_OPEN_READ) &&
                 !vfs_check_access(node, VFS_ACCESS_READ)) ||
                ((flags & VFS_OPEN_WRITE) && !authorized_configuration_write &&
                 !vfs_check_access(node, VFS_ACCESS_WRITE))) {
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            if (authorized_configuration_write) {
                int authorization_result = pass_authorize_current(
                    IDENTITY_PRIVILEGE_MANAGE_CONFIGURATION,
                    "Modify administrator configuration.");
                if (authorization_result != MG_OK) {
                    syscall_fail(frame, authorization_result);
                    return;
                }
            }
            object = authorized_configuration_write
                ? object_file_create_node_authorized(node, flags)
                : object_file_create_node(node, flags);
            if (!object) {
                syscall_fail(frame, MG_ERR_IO);
                return;
            }
            rights = 0;
            if (flags & VFS_OPEN_READ) rights |= OBJECT_RIGHT_READ;
            if (flags & VFS_OPEN_WRITE) rights |= OBJECT_RIGHT_WRITE;
            if (!process_handle_install(process_current(), object, rights,
                                        &handle)) {
                object_release(object);
                syscall_fail(frame, MG_ERR_NO_MEMORY);
                return;
            }
            object_release(object);
            frame->rax = handle;
            return;
        }
        case SYSCALL_READ:
        case SYSCALL_WRITE: {
            process_handle_t handle = (process_handle_t)frame->rdi;
            void *buffer = (void *)(uintptr_t)frame->rsi;
            u64 length = frame->rdx;
            kernel_object_t *object = process_handle_lookup(
                process_current(), handle, OBJECT_TYPE_INVALID,
                frame->rax == SYSCALL_READ ? OBJECT_RIGHT_READ : OBJECT_RIGHT_WRITE);
            i64 result;
            if (!object) {
                syscall_fail(frame, MG_ERR_INVALID_HANDLE);
                return;
            }
            if (!syscall_user_buffer_valid(buffer, length)) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = frame->rax == SYSCALL_READ
                ? object_read(object, buffer, length)
                : object_write(object, buffer, length);
            frame->rax = result < 0
                ? (result == MG_ERR_DEVICE_GONE
                    ? (u64)MG_ERR_DEVICE_GONE : (u64)MG_ERR_UNSUPPORTED)
                : (u64)result;
            return;
        }
        case SYSCALL_CLOSE:
            frame->rax = process_handle_close(
                             process_current(),
                             (process_handle_t)frame->rdi)
                ? (u64)MG_OK : (u64)MG_ERR_INVALID_HANDLE;
            return;
        case SYSCALL_SPAWN: {
            char cmdline[256];
            process_handle_t handle;
            if (!syscall_copy_text((const char *)(uintptr_t)frame->rdi,
                                   cmdline, sizeof(cmdline))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            /* The spawn argument is a command line, not a filesystem path.
             * Resolving the complete string would normalize slashes inside
             * arguments (for example, "http://" became "http:/").
             * process_spawn() parses the copied command line and resolves
             * only argv[0] against the parent's working directory. */
            bool spawned = process_spawn(process_current(), cmdline, &handle);
            if (!spawned) {
                syscall_fail(frame, MG_ERR_INVALID_EXEC);
                return;
            }
            frame->rax = handle;
            return;
        }
        case SYSCALL_SPAWN_ARGV: {
            const char *argv[16];
            char argument_storage[256];
            const uintptr_t *user_argv =
                (const uintptr_t *)(uintptr_t)frame->rdi;
            u64 requested_argc = frame->rsi;
            usize used = 0;
            process_handle_t handle;

            if (!user_argv || requested_argc == 0 || requested_argc > 16U ||
                !syscall_user_buffer_valid(
                    user_argv, (usize)requested_argc * sizeof(*user_argv))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            for (u32 index = 0; index < (u32)requested_argc; index++) {
                uintptr_t user_argument;
                usize length;

                memcpy(&user_argument, user_argv + index,
                       sizeof(user_argument));
                if (!user_argument || used >= sizeof(argument_storage) ||
                    !syscall_copy_argument(
                        (const char *)user_argument,
                        argument_storage + used,
                        sizeof(argument_storage) - used)) {
                    syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                    return;
                }
                argv[index] = argument_storage + used;
                length = strlen(argv[index]) + 1U;
                used += length;
            }
            if (!process_spawn_argv(process_current(), argv,
                                    (u32)requested_argc, &handle)) {
                syscall_fail(frame, MG_ERR_INVALID_EXEC);
                return;
            }
            frame->rax = handle;
            return;
        }
        case SYSCALL_SPAWN_WITH_OUTPUT: {
            char cmdline[256];
            process_handle_t handle;
            if (!syscall_copy_text((const char *)(uintptr_t)frame->rdi,
                                   cmdline, sizeof(cmdline))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            if (!process_spawn_with_output(
                    process_current(), cmdline,
                    (process_handle_t)frame->rsi, &handle)) {
                syscall_fail(frame, MG_ERR_INVALID_EXEC);
                return;
            }
            frame->rax = handle;
            return;
        }
        case SYSCALL_REDIRECT_OUTPUT: {
            process_handle_t saved;
            process_handle_t *user_saved =
                (process_handle_t *)(uintptr_t)frame->rsi;
            if (!user_saved || !syscall_user_buffer_valid(user_saved,
                                                          sizeof(*user_saved)) ||
                !process_redirect_output(process_current(),
                                         (process_handle_t)frame->rdi,
                                         &saved)) {
                syscall_fail(frame, MG_ERR_INVALID_HANDLE);
                return;
            }
            *user_saved = saved;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_RESTORE_OUTPUT:
            frame->rax = process_restore_output(
                process_current(), (process_handle_t)frame->rdi)
                ? (u64)MG_OK : (u64)MG_ERR_INVALID_HANDLE;
            return;
        case SYSCALL_WAIT: {
            process_handle_t handle = (process_handle_t)frame->rdi;
            i32 status;
            i32 *user_status = (i32 *)(uintptr_t)frame->rsi;
            if (!syscall_user_buffer_valid(user_status, sizeof(*user_status))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            if (!process_wait(process_current(), handle, &status)) {
                syscall_fail(frame, MG_ERR_INVALID_HANDLE);
                return;
            }
            *user_status = status;
            frame->rax = 0;
            return;
        }
        case SYSCALL_CHDIR: {
            char path[256];
            int result;
            if (!syscall_copy_path((const char *)(uintptr_t)frame->rdi,
                                   path, sizeof(path))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = process_chdir_result(process_current(), path);
            if (result != VFS_OK) {
                syscall_fail(frame, syscall_vfs_error(result));
                return;
            }
            frame->rax = 0;
            return;
        }
        case SYSCALL_MEMORY_MAP: {
            uintptr_t address;
            uintptr_t *user_address = (uintptr_t *)(uintptr_t)frame->rsi;
            i64 result;

            if (!syscall_user_buffer_valid(user_address,
                                           sizeof(*user_address))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = process_memory_map(process_current(), (usize)frame->rdi,
                                        &address);
            if (result < 0) {
                syscall_fail(frame, result);
                return;
            }
            *user_address = address;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_MEMORY_UNMAP:
            frame->rax = (u64)process_memory_unmap(
                process_current(), (uintptr_t)frame->rdi);
            return;
        case SYSCALL_GETCWD: {
            process_t *process = process_current();
            char *buffer = (char *)(uintptr_t)frame->rdi;
            usize capacity = (usize)frame->rsi;
            usize *user_size = (usize *)(uintptr_t)frame->rdx;
            usize required;

            if (!process || !buffer || capacity == 0 || !user_size ||
                !syscall_user_buffer_valid(buffer, capacity) ||
                !syscall_user_buffer_valid(user_size, sizeof(*user_size))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            required = strlen(process->cwd) + 1;
            *user_size = required;
            if (capacity < required) {
                syscall_fail(frame, MG_ERR_BUFFER_TOO_SMALL);
                return;
            }
            memcpy(buffer, process->cwd, required);
            frame->rax = required - 1;
            return;
        }
        case SYSCALL_PATH_INFO: {
            char resolved[512];
            vfs_node_t *node = NULL;
            mg_path_info_t *info = (mg_path_info_t *)(uintptr_t)frame->rsi;
            int lookup_result;

            if (!info || !syscall_user_buffer_valid(info, sizeof(*info))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            if (!syscall_resolve_path(process_current(),
                                      (const char *)(uintptr_t)frame->rdi,
                                      resolved, sizeof(resolved))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            lookup_result = vfs_lookup(resolved, &node);
            if (lookup_result != VFS_OK || !node) {
                syscall_fail(frame, syscall_vfs_error(lookup_result));
                return;
            }
            info->type = node->type == VFS_TYPE_DIRECTORY
                ? MG_PATH_TYPE_DIRECTORY : MG_PATH_TYPE_FILE;
            info->permissions = node->permissions;
            info->size = node->size;
            info->identifier = node->inode;
            info->owner_uid = node->owner_uid;
            info->reserved = 0;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_DIRECTORY_OPEN: {
            char resolved[512];
            vfs_node_t *node = NULL;
            int lookup_result;
            process_handle_t handle;
            kernel_object_t *object;

            if (!syscall_resolve_path(process_current(),
                                      (const char *)(uintptr_t)frame->rdi,
                                      resolved, sizeof(resolved))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            lookup_result = vfs_lookup(resolved, &node);
            if (lookup_result != VFS_OK || !node) {
                syscall_fail(frame, syscall_vfs_error(lookup_result));
                return;
            }
            if (node->type != VFS_TYPE_DIRECTORY) {
                syscall_fail(frame, MG_ERR_NOT_DIRECTORY);
                return;
            }
            if (!vfs_check_access(node, VFS_ACCESS_READ)) {
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            object = object_directory_create_node(node);
            if (!object) {
                syscall_fail(frame, MG_ERR_IO);
                return;
            }
            if (!process_handle_install(process_current(), object,
                                        OBJECT_RIGHT_READ, &handle)) {
                object_release(object);
                syscall_fail(frame, MG_ERR_NO_MEMORY);
                return;
            }
            object_release(object);
            frame->rax = handle;
            return;
        }
        case SYSCALL_DIRECTORY_READ: {
            mg_directory_entry_t *user_entry =
                (mg_directory_entry_t *)(uintptr_t)frame->rsi;
            kernel_object_t *object;
            vfs_dirent_t entry;
            i64 result;

            if (!user_entry ||
                !syscall_user_buffer_valid(user_entry, sizeof(*user_entry))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            object = process_handle_lookup(process_current(),
                                           (process_handle_t)frame->rdi,
                                           OBJECT_TYPE_DIRECTORY,
                                           OBJECT_RIGHT_READ);
            if (!object) {
                syscall_fail(frame, MG_ERR_INVALID_HANDLE);
                return;
            }
            result = object_directory_read(object, &entry);
            if (result < 0) {
                syscall_fail(frame, result == MG_ERR_DEVICE_GONE
                    ? MG_ERR_DEVICE_GONE : MG_ERR_UNSUPPORTED);
                return;
            }
            if (result == 0) {
                syscall_fail(frame, MG_ERR_END_OF_FILE);
                return;
            }
            memcpy(user_entry->name, entry.name, sizeof(user_entry->name));
            user_entry->type = entry.type == VFS_TYPE_DIRECTORY
                ? MG_PATH_TYPE_DIRECTORY : MG_PATH_TYPE_FILE;
            user_entry->reserved = 0;
            user_entry->identifier = entry.inode;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_DIRECTORY_READ_BATCH: {
            mg_directory_entry_t *user_entries =
                (mg_directory_entry_t *)(uintptr_t)frame->rsi;
            kernel_object_t *object;
            vfs_dirent_t *entries;
            u64 capacity = frame->rdx;
            i64 result;

            if (!user_entries || capacity == 0 ||
                capacity > VFS_DIRECTORY_BATCH_MAX ||
                !syscall_user_buffer_valid(user_entries,
                    (usize)capacity * sizeof(*user_entries))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            object = process_handle_lookup(process_current(),
                                           (process_handle_t)frame->rdi,
                                           OBJECT_TYPE_DIRECTORY,
                                           OBJECT_RIGHT_READ);
            if (!object) {
                syscall_fail(frame, MG_ERR_INVALID_HANDLE);
                return;
            }
            entries = (vfs_dirent_t *)kmalloc(
                (usize)capacity * sizeof(*entries));
            if (!entries) {
                syscall_fail(frame, MG_ERR_NO_MEMORY);
                return;
            }
            result = object_directory_read_batch(object, entries,
                                                 (u32)capacity);
            if (result < 0) {
                kfree(entries);
                syscall_fail(frame, result == MG_ERR_DEVICE_GONE
                    ? MG_ERR_DEVICE_GONE : MG_ERR_UNSUPPORTED);
                return;
            }
            for (i64 i = 0; i < result; i++) {
                memcpy(user_entries[i].name, entries[i].name,
                       sizeof(user_entries[i].name));
                user_entries[i].type = entries[i].type == VFS_TYPE_DIRECTORY
                    ? MG_PATH_TYPE_DIRECTORY : MG_PATH_TYPE_FILE;
                user_entries[i].reserved = 0;
                user_entries[i].identifier = entries[i].inode;
            }
            kfree(entries);
            if (result == 0) {
                syscall_fail(frame, MG_ERR_END_OF_FILE);
                return;
            }
            frame->rax = (u64)result;
            return;
        }
        case SYSCALL_FILE_CREATE:
            frame->rax = (u64)syscall_create_path(
                process_current(), (const char *)(uintptr_t)frame->rdi, false);
            return;
        case SYSCALL_DIRECTORY_CREATE:
            frame->rax = (u64)syscall_create_path(
                process_current(), (const char *)(uintptr_t)frame->rdi, true);
            return;
        case SYSCALL_PATH_MOVE: {
            char source_parent_path[512], destination_parent_path[512];
            char source_name[256], destination_name[256];
            vfs_node_t *source_parent = NULL, *destination_parent = NULL;
            vfs_node_t *source_node;
            vfs_super_t *source_super;
            u64 source_inode;
            int result;

            if (!syscall_resolve_parent(process_current(),
                                        (const char *)(uintptr_t)frame->rdi,
                                        source_parent_path,
                                        sizeof(source_parent_path), source_name,
                                        sizeof(source_name)) ||
                !syscall_resolve_parent(process_current(),
                                        (const char *)(uintptr_t)frame->rsi,
                                        destination_parent_path,
                                        sizeof(destination_parent_path),
                                        destination_name,
                                        sizeof(destination_name))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            int source_lookup = vfs_lookup(source_parent_path, &source_parent);
            int destination_lookup = vfs_lookup(destination_parent_path,
                                                &destination_parent);
            if (source_lookup != VFS_OK ||
                !source_parent || destination_lookup != VFS_OK ||
                !destination_parent) {
                syscall_fail(frame, syscall_vfs_error(source_lookup != VFS_OK
                    ? source_lookup : destination_lookup));
                return;
            }
            if (source_parent->type != VFS_TYPE_DIRECTORY ||
                destination_parent->type != VFS_TYPE_DIRECTORY) {
                syscall_fail(frame, MG_ERR_NOT_DIRECTORY);
                return;
            }
            if (!vfs_check_access(source_parent, VFS_ACCESS_WRITE) ||
                !vfs_check_access(destination_parent, VFS_ACCESS_WRITE)) {
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            source_node = vfs_finddir(source_parent, source_name);
            if (!source_node) {
                syscall_fail(frame, MG_ERR_NOT_FOUND);
                return;
            }
            if (vfs_finddir(destination_parent, destination_name)) {
                syscall_fail(frame, MG_ERR_ALREADY_EXISTS);
                return;
            }
            if (source_parent->super != destination_parent->super) {
                syscall_fail(frame, MG_ERR_UNSUPPORTED);
                return;
            }
            source_super = source_node->super;
            source_inode = source_node->inode;
            result = vfs_rename_expected(source_parent, source_name,
                                         source_super, source_inode,
                                         destination_parent, destination_name);
            frame->rax = (u64)syscall_vfs_error(result);
            return;
        }
        case SYSCALL_PATH_REMOVE: {
            char parent_path[512], name[256];
            vfs_node_t *parent = NULL, *node;
            int result;
            int lookup_result;

            if (!syscall_resolve_parent(process_current(),
                                        (const char *)(uintptr_t)frame->rdi,
                                        parent_path, sizeof(parent_path), name,
                                        sizeof(name))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            lookup_result = vfs_lookup(parent_path, &parent);
            if (lookup_result != VFS_OK || !parent ||
                parent->type != VFS_TYPE_DIRECTORY) {
                syscall_fail(frame, lookup_result != VFS_OK
                    ? syscall_vfs_error(lookup_result) : MG_ERR_NOT_DIRECTORY);
                return;
            }
            if (!vfs_check_access(parent, VFS_ACCESS_WRITE)) {
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            node = vfs_finddir(parent, name);
            if (!node) {
                syscall_fail(frame, MG_ERR_NOT_FOUND);
                return;
            }
            result = node->type == VFS_TYPE_DIRECTORY
                ? vfs_rmdir_expected(parent, name, node->super, node->inode)
                : vfs_unlink_expected(parent, name, node->super, node->inode);
            frame->rax = (u64)syscall_vfs_error(result);
            return;
        }
        case SYSCALL_FILESYSTEM_ADMIN: {
            mg_filesystem_admin_request_t request;
            mg_filesystem_admin_request_t *user_request =
                (mg_filesystem_admin_request_t *)(uintptr_t)frame->rdi;

            if (!user_request || !syscall_user_buffer_valid(user_request,
                                                              sizeof(request))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            switch (request.operation) {
                case MG_FILESYSTEM_ADMIN_OPEN:
                    if (!request.source || request.destination ||
                        (request.flags != VFS_OPEN_READ &&
                         request.flags != VFS_OPEN_WRITE &&
                         request.flags != VFS_OPEN_RDWR)) {
                        syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                        return;
                    }
                    frame->rax = (u64)syscall_admin_open(
                        process_current(), request.source, request.flags);
                    return;
                case MG_FILESYSTEM_ADMIN_CREATE_FILE:
                case MG_FILESYSTEM_ADMIN_CREATE_DIRECTORY:
                    if (!request.source || request.destination || request.flags) {
                        syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                        return;
                    }
                    frame->rax = (u64)syscall_admin_create_path(
                        process_current(), request.source,
                        request.operation == MG_FILESYSTEM_ADMIN_CREATE_DIRECTORY);
                    return;
                case MG_FILESYSTEM_ADMIN_MOVE:
                    if (!request.source || !request.destination || request.flags) {
                        syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                        return;
                    }
                    frame->rax = (u64)syscall_admin_move(
                        process_current(), request.source,
                        request.destination);
                    return;
                case MG_FILESYSTEM_ADMIN_REMOVE:
                    if (!request.source || request.destination || request.flags) {
                        syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                        return;
                    }
                    frame->rax = (u64)syscall_admin_remove(
                        process_current(), request.source);
                    return;
                default:
                    syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                    return;
            }
        }
        case SYSCALL_FILE_TRUNCATE: {
            kernel_object_t *object = process_handle_lookup(
                process_current(), (process_handle_t)frame->rdi,
                OBJECT_TYPE_FILE, OBJECT_RIGHT_WRITE);
            if (!object) {
                syscall_fail(frame, MG_ERR_INVALID_HANDLE);
                return;
            }
            frame->rax = (u64)syscall_vfs_error(object_file_truncate(object));
            return;
        }
        case SYSCALL_FILE_SEEK: {
            kernel_object_t *object = process_handle_lookup(
                process_current(), (process_handle_t)frame->rdi,
                OBJECT_TYPE_FILE, 0);
            if (!object || frame->rdx > MG_SEEK_END) {
                syscall_fail(frame, !object ? MG_ERR_INVALID_HANDLE :
                             MG_ERR_BAD_ARGUMENT);
                return;
            }
            frame->rax = (u64)syscall_vfs_error(object_file_seek(
                object, (i64)frame->rsi, (u32)frame->rdx));
            return;
        }
        case SYSCALL_CONSOLE_TRANSACTION: {
            u64 op = frame->rdi;
            process_t *process = process_current();
            if (op > 1U) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            if (!process || (op == 1U
                    ? !terminal_begin_batch_for_process(process->pid)
                    : !terminal_end_batch_for_process(process->pid))) {
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_CONSOLE_INPUT_MODE:
            if (frame->rdi > 1U || !process_current()) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            if (!terminal_process_controls(process_current()->pid)) {
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            if (frame->rdi)
                terminal_cursor_disable();
            else
                terminal_cursor_enable();
            frame->rax = MG_OK;
            return;
        case SYSCALL_TERMINAL_CONTROL: {
            process_t *process = process_current();
            u32 operation = (u32)frame->rdi;
            i64 result = MG_OK;

            if (!process || operation < MG_TERMINAL_OP_ALTERNATE_ENTER ||
                operation > MG_TERMINAL_OP_OVERLAY_CLEAR) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }

            switch (operation) {
                case MG_TERMINAL_OP_ALTERNATE_ENTER:
                    if (frame->rsi || frame->rdx ||
                        !terminal_alternate_enter_process(process->pid))
                        result = MG_ERR_BUSY;
                    break;
                case MG_TERMINAL_OP_ALTERNATE_LEAVE:
                    if (frame->rsi || frame->rdx ||
                        !terminal_alternate_leave_process(process->pid))
                        result = MG_ERR_ACCESS_DENIED;
                    break;
                case MG_TERMINAL_OP_CURSOR_MOVE: {
                    mg_terminal_cursor_request_t request;
                    if (!frame->rsi || frame->rdx ||
                        !syscall_user_buffer_valid(
                            (const void *)(uintptr_t)frame->rsi,
                            sizeof(request))) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    memcpy(&request, (const void *)(uintptr_t)frame->rsi,
                           sizeof(request));
                    if (request.version != MG_TERMINAL_API_VERSION ||
                        !terminal_process_controls(process->pid) ||
                        !terminal_move_cursor(request.row, request.column))
                        result = MG_ERR_BAD_ARGUMENT;
                    break;
                }
                case MG_TERMINAL_OP_CURSOR_VISIBILITY: {
                    mg_terminal_visibility_request_t request;
                    if (!frame->rsi || frame->rdx ||
                        !syscall_user_buffer_valid(
                            (const void *)(uintptr_t)frame->rsi,
                            sizeof(request))) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    memcpy(&request, (const void *)(uintptr_t)frame->rsi,
                           sizeof(request));
                    if (request.version != MG_TERMINAL_API_VERSION ||
                        request.visible > 1U ||
                        !terminal_process_controls(process->pid))
                        result = MG_ERR_BAD_ARGUMENT;
                    else
                        terminal_set_cursor_visible(request.visible != 0U);
                    break;
                }
                case MG_TERMINAL_OP_CLEAR: {
                    mg_terminal_clear_request_t request;
                    if (!frame->rsi || frame->rdx ||
                        !syscall_user_buffer_valid(
                            (const void *)(uintptr_t)frame->rsi,
                            sizeof(request))) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    memcpy(&request, (const void *)(uintptr_t)frame->rsi,
                           sizeof(request));
                    if (request.version != MG_TERMINAL_API_VERSION ||
                        !terminal_process_controls(process->pid)) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    switch (request.mode) {
                        case MG_TERMINAL_CLEAR_LINE:
                            if (!terminal_clear_current_line())
                                result = MG_ERR_BAD_ARGUMENT;
                            break;
                        case MG_TERMINAL_CLEAR_TO_END:
                            if (!terminal_clear_current_to_end())
                                result = MG_ERR_BAD_ARGUMENT;
                            break;
                        case MG_TERMINAL_CLEAR_REGION:
                            if (!terminal_clear_cells(
                                    request.first_row, request.first_column,
                                    request.last_row, request.last_column))
                                result = MG_ERR_BAD_ARGUMENT;
                            break;
                        case MG_TERMINAL_CLEAR_SCREEN:
                            terminal_clear();
                            break;
                        default:
                            result = MG_ERR_BAD_ARGUMENT;
                            break;
                    }
                    break;
                }
                case MG_TERMINAL_OP_SIZE: {
                    mg_terminal_size_t size;
                    if (frame->rsi || !frame->rdx ||
                        !syscall_user_buffer_valid(
                            (void *)(uintptr_t)frame->rdx, sizeof(size))) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    size.version = MG_TERMINAL_API_VERSION;
                    u32 rows;
                    u32 columns;
                    terminal_get_dimensions(&rows, &columns);
                    size.rows = rows;
                    size.columns = columns;
                    memcpy((void *)(uintptr_t)frame->rdx, &size,
                           sizeof(size));
                    break;
                }
                case MG_TERMINAL_OP_CAPABILITIES: {
                    mg_terminal_capabilities_t capabilities;
                    u32 capability_mask;
                    if (frame->rsi || !frame->rdx ||
                        !syscall_user_buffer_valid(
                            (void *)(uintptr_t)frame->rdx,
                            sizeof(capabilities))) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    capabilities.version = MG_TERMINAL_API_VERSION;
                    terminal_get_capability_mask(&capability_mask);
                    capabilities.capabilities = capability_mask;
                    memcpy((void *)(uintptr_t)frame->rdx, &capabilities,
                           sizeof(capabilities));
                    break;
                }
                case MG_TERMINAL_OP_OVERLAY_SET: {
                    mg_terminal_overlay_request_t request;
                    const terminal_overlay_cell_t *cells =
                        (const terminal_overlay_cell_t *)(uintptr_t)frame->rdx;
                    u64 cell_bytes;

                    if (!frame->rsi || !frame->rdx ||
                        !syscall_user_buffer_valid(
                            (const void *)(uintptr_t)frame->rsi,
                            sizeof(request))) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    memcpy(&request, (const void *)(uintptr_t)frame->rsi,
                           sizeof(request));
                    if (request.version != MG_TERMINAL_API_VERSION ||
                        request.reserved || !request.rows ||
                        !request.columns || request.rows > 128U ||
                        request.columns > 256U ||
                        request.rows > (~(u64)0 / request.columns) ||
                        request.cell_count !=
                            (u64)request.rows * request.columns ||
                        request.cell_count > (~(u64)0 / sizeof(*cells))) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    cell_bytes = request.cell_count * sizeof(*cells);
                    if (!syscall_user_buffer_valid(cells, cell_bytes) ||
                        !terminal_overlay_set_for_process(
                            process->pid, request.rows, request.columns,
                            cells))
                        result = MG_ERR_BUSY;
                    break;
                }
                case MG_TERMINAL_OP_OVERLAY_CLEAR:
                    if (frame->rsi || frame->rdx ||
                        !terminal_overlay_clear_for_process(process->pid))
                        result = MG_ERR_ACCESS_DENIED;
                    break;
                case MG_TERMINAL_OP_READ_KEY: {
                    mg_terminal_key_request_t request;
                    mg_terminal_key_result_t key_result;
                    u32 key;
                    if (!frame->rsi || !frame->rdx ||
                        !syscall_user_buffer_valid(
                            (const void *)(uintptr_t)frame->rsi,
                            sizeof(request)) ||
                        !syscall_user_buffer_valid(
                            (void *)(uintptr_t)frame->rdx,
                            sizeof(key_result))) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    memcpy(&request, (const void *)(uintptr_t)frame->rsi,
                           sizeof(request));
                    if (request.version != MG_TERMINAL_API_VERSION) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    scheduler_syscall_enter();
                    result = terminal_read_key_for_process(process->pid,
                                               request.timeout_ms,
                                               &key);
                    scheduler_syscall_leave();
                    if (result == MG_OK) {
                        key_result.version = MG_TERMINAL_API_VERSION;
                        key_result.key = key;
                        memcpy((void *)(uintptr_t)frame->rdx, &key_result,
                               sizeof(key_result));
                    }
                    break;
                }
                case MG_TERMINAL_OP_UPDATE_BEGIN:
                    if (frame->rsi || frame->rdx ||
                        !terminal_begin_batch_for_process(process->pid))
                        result = MG_ERR_ACCESS_DENIED;
                    break;
                case MG_TERMINAL_OP_UPDATE_END:
                    if (frame->rsi || frame->rdx ||
                        !terminal_end_batch_for_process(process->pid))
                        result = MG_ERR_ACCESS_DENIED;
                    break;
                case MG_TERMINAL_OP_INPUT_MODE: {
                    mg_terminal_visibility_request_t request;
                    if (!frame->rsi || frame->rdx ||
                        !syscall_user_buffer_valid(
                            (const void *)(uintptr_t)frame->rsi,
                            sizeof(request))) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    memcpy(&request, (const void *)(uintptr_t)frame->rsi,
                           sizeof(request));
                    if (request.version != MG_TERMINAL_API_VERSION ||
                        request.visible > 1U)
                        result = MG_ERR_BAD_ARGUMENT;
                    else
                        result = terminal_set_raw_input_for_process(
                            process->pid, request.visible != 0U);
                    break;
                }
                case MG_TERMINAL_OP_STYLED_WRITE: {
                    mg_terminal_styled_write_request_t request;
                    const char *buffer = (const char *)(uintptr_t)frame->rdx;

                    if (!frame->rsi ||
                        !syscall_user_buffer_valid(
                            (const void *)(uintptr_t)frame->rsi,
                            sizeof(request))) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    memcpy(&request, (const void *)(uintptr_t)frame->rsi,
                           sizeof(request));
                    if (request.version != MG_TERMINAL_API_VERSION ||
                        request.reserved ||
                        request.foreground >= MG_TERMINAL_COLOR_COUNT ||
                        request.background >= MG_TERMINAL_COLOR_COUNT ||
                        !syscall_user_buffer_valid(buffer, request.length)) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    result = terminal_write_styled_for_process(
                        process->pid, buffer, request.length,
                        (terminal_color_t)request.foreground,
                        (terminal_color_t)request.background);
                    if (result < 0) {
                        syscall_fail(frame, result);
                        return;
                    }
                    frame->rax = (u64)result;
                    return;
                }
                case MG_TERMINAL_OP_SEMANTIC_WRITE: {
                    mg_terminal_semantic_write_request_t request;
                    const char *buffer = (const char *)(uintptr_t)frame->rdx;

                    if (!frame->rsi ||
                        !syscall_user_buffer_valid(
                            (const void *)(uintptr_t)frame->rsi,
                            sizeof(request))) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    memcpy(&request, (const void *)(uintptr_t)frame->rsi,
                           sizeof(request));
                    if (request.version != MG_TERMINAL_API_VERSION ||
                        request.reserved ||
                        request.style >= MG_TERMINAL_STYLE_COUNT ||
                        !syscall_user_buffer_valid(buffer, request.length)) {
                        result = MG_ERR_BAD_ARGUMENT;
                        break;
                    }
                    result = terminal_write_semantic_for_process(
                        process->pid, buffer, request.length,
                        (terminal_style_role_t)request.style);
                    if (result < 0) {
                        syscall_fail(frame, result);
                        return;
                    }
                    frame->rax = (u64)result;
                    return;
                }
                default:
                    result = MG_ERR_UNSUPPORTED;
                    break;
            }
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_UPTIME_MS:
            frame->rax = timer_uptime_ms();
            return;
        case SYSCALL_CLOCK_MONOTONIC: {
            mg_monotonic_time_t value;
            mg_monotonic_time_t *user_value =
                (mg_monotonic_time_t *)(uintptr_t)frame->rdi;

            if (!user_value || !syscall_user_buffer_valid(user_value,
                                                            sizeof(value))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            value.milliseconds = timekeeping_monotonic_ms();
            memcpy(user_value, &value, sizeof(value));
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_CLOCK_REALTIME: {
            mg_mangrove_time_t value;
            mg_mangrove_time_t *user_value =
                (mg_mangrove_time_t *)(uintptr_t)frame->rdi;

            if (!user_value || !syscall_user_buffer_valid(user_value,
                                                            sizeof(value))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            if (!timekeeping_realtime(&value)) {
                syscall_fail(frame, MG_ERR_TIME_UNAVAILABLE);
                return;
            }
            memcpy(user_value, &value, sizeof(value));
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_CLOCK_BOOT_ID:
            frame->rax = timekeeping_boot_id();
            return;
        case SYSCALL_NETWORK:
            scheduler_syscall_enter();
            syscall_network(process_current(), frame);
            scheduler_syscall_leave();
            return;
        case SYSCALL_POWER_OFF:
            frame->rax = (u64)platform_poweroff();
            return;
        case SYSCALL_REBOOT:
            frame->rax = (u64)platform_reboot();
            return;
        case SYSCALL_POWER_STATUS: {
            mg_power_status_t *status =
                (mg_power_status_t *)(uintptr_t)frame->rdi;
            if (!status || !syscall_user_buffer_valid(status, sizeof(*status))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            frame->rax = (u64)platform_power_status(status);
            return;
        }
        case SYSCALL_GET_IDENTITY: {
            process_credentials_t credentials;
            mg_identity_t account;
            mg_identity_t *identity =
                (mg_identity_t *)(uintptr_t)frame->rdi;

            if (!identity || !syscall_user_buffer_valid(identity,
                                                         sizeof(*identity))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            if (!process_get_credentials(process_current(), &credentials)) {
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            if (!identity_query_credentials(&credentials, &account)) {
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            *identity = account;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_ACCOUNT: {
            mg_account_request_t request;
            char username[MG_IDENTITY_USERNAME_CAPACITY];
            char password[IDENTITY_PASSWORD_MAX_LENGTH + 1U] = {0};
            mg_account_info_t *result_buffer;
            usize *out_count;
            mg_result_t result;

            if (!syscall_user_buffer_valid(
                    (const void *)(uintptr_t)frame->rdi, sizeof(request))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            memcpy(&request, (const void *)(uintptr_t)frame->rdi,
                   sizeof(request));
            if (request.operation != MG_ACCOUNT_OP_LIST &&
                (!request.username || !syscall_copy_text(request.username,
                                                         username,
                                                         sizeof(username)))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result_buffer = request.result;
            out_count = request.out_count;
            switch (request.operation) {
                case MG_ACCOUNT_OP_LIST:
                    if (request.result_capacity > MG_ACCOUNT_MAX_RECORDS ||
                        !out_count || !syscall_user_buffer_valid(
                            out_count, sizeof(*out_count)) ||
                        (request.result_capacity && (!result_buffer ||
                            !syscall_user_buffer_valid(result_buffer,
                                request.result_capacity * sizeof(*result_buffer))))) {
                        syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                        return;
                    }
                    result = identity_account_list(result_buffer,
                                                   request.result_capacity,
                                                   out_count);
                    frame->rax = (u64)result;
                    return;
                case MG_ACCOUNT_OP_SHOW:
                    if (!result_buffer || request.result_capacity != 1U ||
                        !syscall_user_buffer_valid(result_buffer,
                                                   sizeof(*result_buffer))) {
                        syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                        return;
                    }
                    result = identity_account_show(username, result_buffer);
                    frame->rax = (u64)result;
                    return;
                case MG_ACCOUNT_OP_CREATE:
                    if (request.flags || request.role || request.result ||
                        request.out_count || !request.password ||
                        !syscall_copy_text(request.password, password,
                                           sizeof(password))) {
                        password_secure_clear(password, sizeof(password));
                        syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                        return;
                    }
                    result = identity_account_create(username, password);
                    password_secure_clear(password, sizeof(password));
                    frame->rax = (u64)result;
                    return;
                case MG_ACCOUNT_OP_REMOVE:
                    if (request.flags & ~MG_ACCOUNT_REMOVE_PURGE ||
                        request.role || request.password || request.result ||
                        request.out_count) {
                        syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                        return;
                    }
                    frame->rax = (u64)identity_account_remove(
                        username,
                        (request.flags & MG_ACCOUNT_REMOVE_PURGE) != 0U);
                    return;
                case MG_ACCOUNT_OP_SET_ROLE:
                    if (request.flags || request.role > MG_IDENTITY_ROLE_ADMIN ||
                        request.password || request.result || request.out_count) {
                        syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                        return;
                    }
                    frame->rax = (u64)identity_account_set_role(
                        username, request.role);
                    return;
                case MG_ACCOUNT_OP_SET_PASSWORD:
                    if (request.flags || request.role || request.result ||
                        request.out_count || !request.password ||
                        !syscall_copy_text(request.password, password,
                                           sizeof(password))) {
                        password_secure_clear(password, sizeof(password));
                        syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                        return;
                    }
                    result = identity_account_set_password(username, password);
                    password_secure_clear(password, sizeof(password));
                    frame->rax = (u64)result;
                    return;
                default:
                    syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                    return;
            }
        }
        case SYSCALL_PASS_AUTHENTICATE: {
            char username[MG_IDENTITY_USERNAME_CAPACITY];
            char password[IDENTITY_PASSWORD_MAX_LENGTH + 1U];
            user_identity_t identity;
            mg_identity_t *user_identity =
                (mg_identity_t *)(uintptr_t)frame->rdx;
            int result;

            if (!syscall_is_logind(process_current()) || !user_identity ||
                !syscall_user_buffer_valid(user_identity, sizeof(*user_identity)) ||
                !syscall_copy_text((const char *)(uintptr_t)frame->rdi,
                                   username, sizeof(username)) ||
                !syscall_copy_text((const char *)(uintptr_t)frame->rsi,
                                   password, sizeof(password))) {
                password_secure_clear(password, sizeof(password));
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = pass_authenticate_account(username, password, &identity);
            password_secure_clear(password, sizeof(password));
            if (result == MG_OK) syscall_copy_identity(&identity, user_identity);
            frame->rax = (u64)result;
            return;
        }
        case SYSCALL_SESSION_AUTOLOGIN_IDENTITY: {
            mg_identity_t identity;
            mg_identity_t *user_identity =
                (mg_identity_t *)(uintptr_t)frame->rdi;
            int result;

            if (!user_identity || !syscall_user_buffer_valid(
                    user_identity, sizeof(*user_identity))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = session_autologin_identity_process(process_current(),
                                                        &identity);
            if (result == MG_OK) *user_identity = identity;
            frame->rax = (u64)result;
            return;
        }
        case SYSCALL_SESSION_CREATE: {
            char username[MG_IDENTITY_USERNAME_CAPACITY];
            mg_session_info_t session;
            mg_session_info_t *user_session =
                (mg_session_info_t *)(uintptr_t)frame->rdx;
            int result;

            if (!user_session || !syscall_user_buffer_valid(
                    user_session, sizeof(*user_session)) ||
                !syscall_copy_text((const char *)(uintptr_t)frame->rsi,
                                   username, sizeof(username))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = session_create_process(process_current(),
                                            (process_handle_t)frame->rdi,
                                            username, &session);
            if (result == MG_OK) *user_session = session;
            frame->rax = (u64)result;
            return;
        }
        case SYSCALL_SESSION_LAUNCH: {
            mg_handle_t *user_shell =
                (mg_handle_t *)(uintptr_t)frame->rsi;
            int result;

            if (!user_shell || !syscall_user_buffer_valid(user_shell,
                                                            sizeof(*user_shell))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = session_launch_process(process_current(),
                                            (mg_session_id_t)frame->rdi,
                                            user_shell);
            frame->rax = (u64)result;
            return;
        }
        case SYSCALL_SESSION_QUERY: {
            mg_session_status_t *status =
                (mg_session_status_t *)(uintptr_t)frame->rsi;
            int result;

            if (!status || !syscall_user_buffer_valid(status, sizeof(*status))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = session_query_process(process_current(),
                                           (mg_session_id_t)frame->rdi,
                                           status);
            frame->rax = (u64)result;
            return;
        }
        case SYSCALL_SESSION_LIST: {
            mg_session_list_request_t request;
            mg_session_list_request_t *user_request =
                (mg_session_list_request_t *)(uintptr_t)frame->rdi;
            u32 count = 0;
            u32 total = 0;
            int result;

            if (!user_request || !syscall_user_buffer_valid(user_request,
                                                              sizeof(request))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (!request.result || !request.out_count || !request.out_total ||
                request.capacity == 0U || request.capacity > 8U ||
                !syscall_user_buffer_valid(request.result,
                    (u64)request.capacity * sizeof(*request.result)) ||
                !syscall_user_buffer_valid(request.out_count,
                                            sizeof(*request.out_count)) ||
                !syscall_user_buffer_valid(request.out_total,
                                            sizeof(*request.out_total))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = session_list_process(process_current(), request.offset,
                                          request.result, request.capacity,
                                          &count, &total);
            if (result == MG_OK) {
                *request.out_count = count;
                *request.out_total = total;
            }
            frame->rax = (u64)result;
            return;
        }
        case SYSCALL_SESSION_END:
            frame->rax = (u64)session_end_process(
                process_current(), (mg_session_id_t)frame->rdi);
            return;
        case SYSCALL_SERVICE_START: {
            mg_handle_t handle;
            mg_handle_t *user_handle = (mg_handle_t *)(uintptr_t)frame->rsi;
            int result;

            if (!user_handle || !syscall_user_buffer_valid(user_handle,
                                                            sizeof(*user_handle))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = process_spawn_service_result(process_current(),
                                                  (u32)frame->rdi, &handle);
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            *user_handle = handle;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_SERVICE_REGISTER: {
            char name[MG_IPC_SERVICE_NAME_MAX];
            mg_handle_t handle;
            mg_handle_t *user_handle = (mg_handle_t *)(uintptr_t)frame->rsi;
            int result;

            if (!user_handle || !syscall_user_buffer_valid(user_handle,
                                                            sizeof(*user_handle)) ||
                !syscall_copy_text((const char *)(uintptr_t)frame->rdi,
                                   name, sizeof(name))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = ipc_service_register(process_current(), name, &handle);
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            *user_handle = handle;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_SERVICE_LOOKUP: {
            char name[MG_IPC_SERVICE_NAME_MAX];
            mg_handle_t handle;
            mg_handle_t *user_handle = (mg_handle_t *)(uintptr_t)frame->rsi;
            int result;

            if (!user_handle || !syscall_user_buffer_valid(user_handle,
                                                            sizeof(*user_handle)) ||
                !syscall_copy_text((const char *)(uintptr_t)frame->rdi,
                                   name, sizeof(name))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = ipc_service_lookup(process_current(), name, &handle);
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            *user_handle = handle;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_IPC_REQUEST: {
            mg_ipc_message_t request;
            mg_ipc_message_t reply;
            const mg_ipc_message_t *user_request =
                (const mg_ipc_message_t *)(uintptr_t)frame->rsi;
            mg_ipc_message_t *user_reply =
                (mg_ipc_message_t *)(uintptr_t)frame->rdx;
            int result;

            if (!user_request || !user_reply ||
                !syscall_user_buffer_valid(user_request, sizeof(request)) ||
                !syscall_user_buffer_valid(user_reply, sizeof(reply))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            scheduler_syscall_enter();
            result = ipc_kernel_request(process_current(),
                                        (process_handle_t)frame->rdi,
                                        &request, &reply);
            scheduler_syscall_leave();
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            memcpy(user_reply, &reply, sizeof(reply));
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_IPC_RECEIVE: {
            mg_ipc_received_t received;
            mg_ipc_received_t *user_received =
                (mg_ipc_received_t *)(uintptr_t)frame->rsi;
            int result;

            if (!user_received || !syscall_user_buffer_valid(user_received,
                                                              sizeof(received))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            scheduler_syscall_enter();
            result = ipc_kernel_receive(process_current(),
                                        (process_handle_t)frame->rdi,
                                        &received);
            scheduler_syscall_leave();
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            memcpy(user_received, &received, sizeof(received));
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_IPC_RECEIVE_TIMED: {
            mg_ipc_received_t received;
            mg_ipc_received_t *user_received =
                (mg_ipc_received_t *)(uintptr_t)frame->rsi;
            int result;

            if (!user_received || !syscall_user_buffer_valid(user_received,
                                                              sizeof(received))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            scheduler_syscall_enter();
            result = ipc_kernel_receive_timed(
                process_current(), (process_handle_t)frame->rdi,
                &received, (u32)frame->rdx);
            scheduler_syscall_leave();
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            memcpy(user_received, &received, sizeof(received));
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_IPC_REPLY: {
            mg_ipc_message_t message;
            const mg_ipc_message_t *user_message =
                (const mg_ipc_message_t *)(uintptr_t)frame->rsi;
            int result;

            if (!user_message || !syscall_user_buffer_valid(user_message,
                                                             sizeof(message))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            memcpy(&message, user_message, sizeof(message));
            scheduler_syscall_enter();
            result = ipc_kernel_reply(process_current(),
                                      (process_handle_t)frame->rdi, &message);
            scheduler_syscall_leave();
            frame->rax = (u64)result;
            return;
        }
        case SYSCALL_IPC_TRY_RECEIVE: {
            mg_ipc_received_t received;
            mg_ipc_received_t *user_received =
                (mg_ipc_received_t *)(uintptr_t)frame->rsi;
            int result;

            if (!user_received || !syscall_user_buffer_valid(user_received,
                                                              sizeof(received))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = ipc_kernel_try_receive(process_current(),
                                            (process_handle_t)frame->rdi,
                                            &received);
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            memcpy(user_received, &received, sizeof(received));
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_IPC_EVENT_SUBSCRIBE: {
            int result = ipc_kernel_event_subscribe(
                process_current(), (process_handle_t)frame->rdi,
                (u32)frame->rsi);
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_IPC_EVENT_UNSUBSCRIBE: {
            int result = ipc_kernel_event_unsubscribe(
                process_current(), (process_handle_t)frame->rdi);
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_PROCESS_POLL: {
            i32 status;
            i32 *user_status = (i32 *)(uintptr_t)frame->rsi;
            int result;

            if (!user_status || !syscall_user_buffer_valid(user_status,
                                                            sizeof(*user_status))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = process_poll(process_current(),
                                  (process_handle_t)frame->rdi, &status);
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            *user_status = status;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_SERVICE_STOP: {
            process_t *process = process_current();
            int result;

            if (!process || !process->system_service ||
                process->service_id != MG_SERVICE_SPROUT) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            result = process_terminate_child(
                process, (process_handle_t)frame->rdi, (i32)frame->rsi);
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_PROCESS_HANDLE_PID: {
            u64 pid = process_handle_pid(
                process_current(), (process_handle_t)frame->rdi);
            if (!pid) {
                syscall_fail(frame, MG_ERR_INVALID_HANDLE);
                return;
            }
            frame->rax = pid;
            return;
        }
        case SYSCALL_SERVICE_AUTHORIZE: {
            int result = service_authorize_control(
                process_current(), (process_handle_t)frame->rdi,
                (u32)frame->rsi, (u32)frame->rdx);
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_NETWORK_AUTHORIZE: {
            int result = syscall_authorize_network_request(
                process_current(), (process_handle_t)frame->rdi,
                (u32)frame->rsi);
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_DEVICE_SNAPSHOT: {
            mg_device_snapshot_request_t request;
            mg_device_snapshot_request_t *user_request =
                (mg_device_snapshot_request_t *)(uintptr_t)frame->rdi;
            u32 total = 0;
            u64 generation = 0;
            mg_result_t result;

            if (!user_request || !syscall_user_buffer_valid(user_request,
                                                              sizeof(request))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (request.reserved || request.result_capacity == 0U ||
                request.result_capacity > MG_DEVICE_RESPONSE_MAX ||
                !request.result || !request.out_total ||
                !syscall_user_buffer_valid(request.result,
                    (u64)request.result_capacity * sizeof(*request.result)) ||
                !syscall_user_buffer_valid(request.out_total,
                                            sizeof(*request.out_total)) ||
                (request.out_snapshot_generation &&
                 !syscall_user_buffer_valid(request.out_snapshot_generation,
                                            sizeof(*request.out_snapshot_generation))) ||
                (request.snapshot_generation &&
                 !request.out_snapshot_generation)) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            result = device_snapshot_read(request.filter, request.device_id,
                                          request.offset,
                                          request.snapshot_generation,
                                          request.result,
                                          request.result_capacity, &total,
                                          &generation);
            memcpy(request.out_total, &total, sizeof(total));
            if (request.out_snapshot_generation)
                memcpy(request.out_snapshot_generation, &generation,
                       sizeof(generation));
            if (result < 0) {
                syscall_fail(frame, result);
                return;
            }
            frame->rax = result;
            return;
        }
        case SYSCALL_VOLUME_MOUNT: {
            mg_volume_mount_request_t request;
            mg_volume_mount_request_t *user_request =
                (mg_volume_mount_request_t *)(uintptr_t)frame->rdi;
            block_device_t *device;
            vfs_node_t *parent = NULL;
            vfs_node_t *existing = NULL;
            char name[VFS_MOUNT_PATH_MAX];
            const char *filesystem;
            int lookup_result;
            int mount_result;

            if (!syscall_is_volumed(process_current()) || !user_request ||
                !syscall_user_buffer_valid(user_request, sizeof(request))) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (!request.instance_id || request.reserved ||
                (request.flags & ~MG_VOLUME_MOUNT_FLAG_READ_ONLY) ||
                !syscall_fixed_text_valid(request.filesystem,
                                          sizeof(request.filesystem), false) ||
                !syscall_volume_path_valid(request.mount_point, name,
                                            sizeof(name)) ||
                (strcmp(request.filesystem, "mgfs") != 0 &&
                 strcmp(request.filesystem, "fat32") != 0 &&
                 strcmp(request.filesystem, "exfat") != 0)) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            device = block_get_device_by_public_id(request.instance_id);
            if (!syscall_volume_device_allowed(device,
                                               request.parent_instance_id)) {
                syscall_fail(frame, MG_ERR_DEVICE_GONE);
                return;
            }
            filesystem = vfs_probe_filesystem(device);
            if (!filesystem || strcmp(filesystem, request.filesystem) != 0) {
                syscall_fail(frame, MG_ERR_IO);
                return;
            }
            if (vfs_mount_point_for_device(device, name, sizeof(name), NULL)) {
                syscall_fail(frame, MG_ERR_ALREADY_EXISTS);
                return;
            }
            lookup_result = vfs_lookup_trusted(request.mount_point, &existing);
            if (lookup_result == VFS_OK && existing) {
                syscall_fail(frame, MG_ERR_ALREADY_EXISTS);
                return;
            }
            if (lookup_result != VFS_ERR_NOT_FOUND) {
                syscall_fail(frame, syscall_vfs_error(lookup_result));
                return;
            }
            lookup_result = vfs_lookup_trusted("/vol", &parent);
            if (lookup_result != VFS_OK || !parent ||
                parent->type != VFS_TYPE_DIRECTORY) {
                syscall_fail(frame, syscall_vfs_error(lookup_result));
                return;
            }
            mount_result = vfs_mount_path(
                parent, request.mount_point + 5U, request.mount_point,
                request.filesystem, device, VFS_MOUNT_ROLE_VOLUME,
                (request.flags & MG_VOLUME_MOUNT_FLAG_READ_ONLY) != 0U);
            if (mount_result != VFS_OK) {
                syscall_fail(frame, syscall_vfs_error(mount_result));
                return;
            }
            (void)block_device_set_automount_suppressed(device->id, false);
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_VOLUME_UNMOUNT: {
            mg_volume_unmount_request_t request;
            mg_volume_unmount_request_t *user_request =
                (mg_volume_unmount_request_t *)(uintptr_t)frame->rdi;
            block_device_t *device;
            block_device_t *devices[VFS_MAX_MOUNTS];
            u32 device_count = 0;
            int result;

            if (!syscall_is_volumed(process_current()) || !user_request ||
                !syscall_user_buffer_valid(user_request, sizeof(request))) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (!request.instance_id || request.reserved ||
                (request.flags & ~(MG_VOLUME_UNMOUNT_FLAG_ALL_CHILDREN |
                                   MG_VOLUME_UNMOUNT_FLAG_PREFLIGHT))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            device = block_get_device_by_public_id(request.instance_id);
            if (!syscall_volume_device_allowed(device,
                                               request.parent_instance_id)) {
                syscall_fail(frame, MG_ERR_DEVICE_GONE);
                return;
            }
            if (request.flags & MG_VOLUME_UNMOUNT_FLAG_ALL_CHILDREN) {
                if (device->type != BLOCK_DEVICE_USB ||
                    request.parent_instance_id != 0ULL) {
                    syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                    return;
                }
                device_count = syscall_volume_collect_children(
                    device, devices, VFS_MAX_MOUNTS);
                if (!device_count) {
                    syscall_fail(frame, MG_ERR_NOT_FOUND);
                    return;
                }
                result = (request.flags & MG_VOLUME_UNMOUNT_FLAG_PREFLIGHT)
                    ? vfs_unmount_devices_preflight(devices, device_count)
                    : vfs_unmount_devices(devices, device_count);
            } else if (request.flags & MG_VOLUME_UNMOUNT_FLAG_PREFLIGHT) {
                result = vfs_unmount_device_preflight(device);
            } else {
                result = vfs_unmount_device(device);
            }
            if (result != VFS_OK) {
                syscall_fail(frame, syscall_vfs_error(result));
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_VOLUME_SUPPRESS: {
            mg_volume_suppression_request_t request;
            mg_volume_suppression_request_t *user_request =
                (mg_volume_suppression_request_t *)(uintptr_t)frame->rdi;
            block_device_t *device;

            if (!syscall_is_volumed(process_current()) || !user_request ||
                !syscall_user_buffer_valid(user_request, sizeof(request))) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (!request.instance_id || request.reserved ||
                request.suppressed > 1U) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            device = block_get_device_by_public_id(request.instance_id);
            if (!syscall_volume_device_allowed(device,
                                               request.parent_instance_id)) {
                syscall_fail(frame, MG_ERR_DEVICE_GONE);
                return;
            }
            if (!block_device_set_automount_suppressed(
                    device->id, request.suppressed != 0U)) {
                syscall_fail(frame, MG_ERR_DEVICE_GONE);
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_VOLUME_AUTHORIZE: {
            i64 result = syscall_authorize_volume_request(
                process_current(), (process_handle_t)frame->rdi,
                (u32)frame->rsi);
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_STORAGE_AUTHORIZE: {
            process_t *requester = process_current();
            u32 operation = (u32)frame->rdi;
            if (!syscall_is_diskutil(requester) ||
                !requester->storage_management_session ||
                (operation != MG_STORAGE_OP_FORMAT &&
                 operation != MG_STORAGE_OP_LABEL &&
                 operation != MG_STORAGE_OP_GPT_INITIALIZE &&
                 operation != MG_STORAGE_OP_GPT_CREATE &&
                 operation != MG_STORAGE_OP_GPT_DELETE)) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            requester->storage_authorized_operation = operation;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_STORAGE_AUTHORIZE_CANCEL: {
            process_t *requester = process_current();
            if (!requester) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            requester->storage_authorized_operation = 0U;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_STORAGE_SESSION_AUTHORIZE: {
            process_t *requester = process_current();
            i64 result;

            if (!syscall_is_diskutil(requester) ||
                requester->storage_management_session) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            result = pass_authorize_current(
                IDENTITY_PRIVILEGE_MANAGE_STORAGE,
                "Open disk administration.");
            if (result != MG_OK) {
                syscall_fail(frame, result);
                return;
            }
            requester->storage_management_session = true;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_STORAGE_FORMAT: {
            mg_storage_format_request_t request;
            mg_storage_format_request_t *user_request =
                (mg_storage_format_request_t *)(uintptr_t)frame->rdi;
            process_t *requester = process_current();
            block_device_t *device;
            const char *filesystem;
            int result;

            if (!syscall_is_diskutil(requester) ||
                !requester->storage_management_session ||
                requester->storage_authorized_operation != MG_STORAGE_OP_FORMAT ||
                !user_request ||
                !syscall_user_buffer_valid(user_request, sizeof(request))) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (!request.instance_id || request.reserved ||
                (request.filesystem != MG_STORAGE_FILESYSTEM_FAT32 &&
                 request.filesystem != MG_STORAGE_FILESYSTEM_MGFS &&
                 request.filesystem != MG_STORAGE_FILESYSTEM_EXFAT)) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            device = block_get_device_by_public_id(request.instance_id);
            if (!syscall_storage_device_matches(device,
                                                request.parent_instance_id)) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_DEVICE_GONE);
                return;
            }
            if (syscall_storage_system_managed(device)) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            filesystem = request.filesystem == MG_STORAGE_FILESYSTEM_FAT32
                ? "fat32" : request.filesystem == MG_STORAGE_FILESYSTEM_MGFS
                ? "mgfs" : "exfat";
            requester->storage_authorized_operation = 0U;
            result = storage_format_filesystem(device, filesystem);
            if (result != VFS_OK) {
                syscall_fail(frame, syscall_vfs_error(result));
                return;
            }
            /* Formatting intentionally leaves the exact current instance
             * suppressed.  It must stay unmounted until the user explicitly
             * mounts it or physically reinserts it as a fresh instance. */
            (void)block_device_set_automount_suppressed(device->id, true);
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_STORAGE_LABEL: {
            mg_storage_label_request_t request;
            mg_storage_label_request_t *user_request =
                (mg_storage_label_request_t *)(uintptr_t)frame->rdi;
            process_t *requester = process_current();
            block_device_t *device;
            int result;

            if (!syscall_is_diskutil(requester) ||
                !requester->storage_management_session ||
                requester->storage_authorized_operation != MG_STORAGE_OP_LABEL ||
                !user_request ||
                !syscall_user_buffer_valid(user_request, sizeof(request))) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (!request.instance_id || request.reserved || request.reserved2 ||
                !syscall_fixed_text_valid(request.filesystem,
                                          sizeof(request.filesystem), false) ||
                !syscall_fixed_text_valid(request.label, sizeof(request.label),
                                          true) ||
                (strcmp(request.filesystem, "fat32") != 0 &&
                 strcmp(request.filesystem, "mgfs") != 0 &&
                 strcmp(request.filesystem, "exfat") != 0)) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            device = block_get_device_by_public_id(request.instance_id);
            if (!syscall_storage_device_matches(device,
                                                request.parent_instance_id)) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_DEVICE_GONE);
                return;
            }
            if (syscall_storage_system_managed(device)) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            requester->storage_authorized_operation = 0U;
            result = storage_set_filesystem_label(
                device, request.filesystem, request.label);
            if (result != VFS_OK) {
                syscall_fail(frame, syscall_vfs_error(result));
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_STORAGE_GPT_INFO: {
            mg_storage_gpt_info_request_t request;
            mg_storage_gpt_info_t *user_info =
                (mg_storage_gpt_info_t *)(uintptr_t)frame->rsi;
            mg_storage_gpt_info_request_t *user_request =
                (mg_storage_gpt_info_request_t *)(uintptr_t)frame->rdi;
            block_device_t *device;
            gpt_table_info_t table;
            int result;

            if (!user_request || !user_info ||
                !syscall_user_buffer_valid(user_request, sizeof(request)) ||
                !syscall_user_buffer_valid(user_info, sizeof(*user_info))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (!request.instance_id || request.reserved || request.reserved2) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            device = block_get_device_by_public_id(request.instance_id);
            if (!device || device->type == BLOCK_DEVICE_PARTITION ||
                !block_device_is_live(device)) {
                syscall_fail(frame, MG_ERR_DEVICE_GONE);
                return;
            }
            result = gpt_get_table_info(device, &table);
            if (result != VFS_OK) {
                syscall_fail(frame, syscall_vfs_error(result));
                return;
            }
            memset(user_info, 0, sizeof(*user_info));
            user_info->table_type = (u32)table.type;
            user_info->partition_count = table.partition_count;
            user_info->entry_count = table.entry_count;
            user_info->entry_size = table.entry_size;
            user_info->first_usable_lba = table.first_usable_lba;
            user_info->last_usable_lba = table.last_usable_lba;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_STORAGE_GPT_PLAN: {
            mg_storage_gpt_plan_request_t request;
            mg_storage_gpt_plan_t *user_plan =
                (mg_storage_gpt_plan_t *)(uintptr_t)frame->rsi;
            mg_storage_gpt_plan_request_t *user_request =
                (mg_storage_gpt_plan_request_t *)(uintptr_t)frame->rdi;
            block_device_t *device;
            gpt_partition_plan_t plan;
            int result;

            if (!user_request || !user_plan ||
                !syscall_user_buffer_valid(user_request, sizeof(request)) ||
                !syscall_user_buffer_valid(user_plan, sizeof(*user_plan))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (!request.instance_id || request.reserved ||
                (request.flags & ~MG_STORAGE_GPT_PLAN_FLAG_REST) ||
                ((request.flags & MG_STORAGE_GPT_PLAN_FLAG_REST) &&
                 request.requested_bytes) ||
                (!(request.flags & MG_STORAGE_GPT_PLAN_FLAG_REST) &&
                 !request.requested_bytes)) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            device = block_get_device_by_public_id(request.instance_id);
            if (!device || device->type == BLOCK_DEVICE_PARTITION ||
                !block_device_is_live(device)) {
                syscall_fail(frame, MG_ERR_DEVICE_GONE);
                return;
            }
            result = gpt_plan_partition(
                device, request.requested_bytes,
                (request.flags & MG_STORAGE_GPT_PLAN_FLAG_REST) != 0U,
                &plan);
            if (result != VFS_OK) {
                syscall_fail(frame, syscall_vfs_error(result));
                return;
            }
            user_plan->first_lba = plan.first_lba;
            user_plan->last_lba = plan.last_lba;
            user_plan->size_bytes = plan.size_bytes;
            user_plan->partition_number = plan.partition_number;
            user_plan->reserved = 0;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_STORAGE_GPT_INITIALIZE: {
            process_t *requester = process_current();
            block_device_t *device;
            int result;

            if (!syscall_is_diskutil(requester) ||
                !requester->storage_management_session ||
                requester->storage_authorized_operation !=
                    MG_STORAGE_OP_GPT_INITIALIZE) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            device = block_get_device_by_public_id(frame->rdi);
            if (!device || device->type == BLOCK_DEVICE_PARTITION) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            if (syscall_storage_system_managed(device)) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            requester->storage_authorized_operation = 0U;
            result = gpt_initialize_device(device);
            if (result != VFS_OK) {
                syscall_fail(frame, syscall_vfs_error(result));
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_STORAGE_GPT_CREATE: {
            mg_storage_gpt_create_request_t request;
            mg_storage_gpt_create_request_t *user_request =
                (mg_storage_gpt_create_request_t *)(uintptr_t)frame->rdi;
            process_t *requester = process_current();
            block_device_t *device;
            int result;

            if (!syscall_is_diskutil(requester) ||
                !requester->storage_management_session ||
                requester->storage_authorized_operation !=
                    MG_STORAGE_OP_GPT_CREATE || !user_request ||
                !syscall_user_buffer_valid(user_request, sizeof(request))) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (!request.instance_id || request.reserved || !request.partition_number ||
                request.partition_number > GPT_MAX_PARTITION_ENTRIES ||
                request.first_lba > request.last_lba) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            device = block_get_device_by_public_id(request.instance_id);
            if (!device || device->type == BLOCK_DEVICE_PARTITION) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            if (syscall_storage_system_managed(device)) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            requester->storage_authorized_operation = 0U;
            result = gpt_create_partition(device, request.partition_number,
                                          request.first_lba, request.last_lba);
            if (result != VFS_OK) {
                syscall_fail(frame, syscall_vfs_error(result));
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_STORAGE_GPT_DELETE: {
            mg_storage_gpt_delete_request_t request;
            mg_storage_gpt_delete_request_t *user_request =
                (mg_storage_gpt_delete_request_t *)(uintptr_t)frame->rdi;
            process_t *requester = process_current();
            block_device_t *device;
            block_device_t *partition;
            int result;

            if (!syscall_is_diskutil(requester) ||
                !requester->storage_management_session ||
                requester->storage_authorized_operation != MG_STORAGE_OP_GPT_DELETE ||
                !user_request ||
                !syscall_user_buffer_valid(user_request, sizeof(request))) {
                syscall_fail(frame, MG_ERR_PRIVILEGE_REQUIRED);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (!request.instance_id || !request.partition_instance_id ||
                request.reserved || !request.partition_number ||
                request.partition_number > GPT_MAX_PARTITION_ENTRIES) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            device = block_get_device_by_public_id(request.instance_id);
            partition = block_get_device_by_public_id(request.partition_instance_id);
            if (!device || device->type == BLOCK_DEVICE_PARTITION || !partition ||
                partition->type != BLOCK_DEVICE_PARTITION) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_DEVICE_GONE);
                return;
            }
            if (syscall_storage_system_managed(device) ||
                syscall_storage_system_managed(partition)) {
                requester->storage_authorized_operation = 0U;
                syscall_fail(frame, MG_ERR_ACCESS_DENIED);
                return;
            }
            requester->storage_authorized_operation = 0U;
            result = gpt_delete_partition(device, partition,
                                          request.partition_number);
            if (result != VFS_OK) {
                syscall_fail(frame, syscall_vfs_error(result));
                return;
            }
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_PROCESS_SNAPSHOT: {
            mg_process_snapshot_request_t request;
            mg_process_snapshot_request_t *user_request =
                (mg_process_snapshot_request_t *)(uintptr_t)frame->rdi;
            u32 total = 0;
            u32 copied;

            if (!user_request || !syscall_user_buffer_valid(user_request,
                                                              sizeof(request))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (!request.result || !request.out_count || !request.out_total ||
                request.result_capacity == 0U ||
                request.result_capacity > MG_PROCESS_SNAPSHOT_PAGE_MAX ||
                !syscall_user_buffer_valid(request.result,
                    (u64)request.result_capacity * sizeof(*request.result)) ||
                !syscall_user_buffer_valid(request.out_count,
                                            sizeof(*request.out_count)) ||
                !syscall_user_buffer_valid(request.out_total,
                                            sizeof(*request.out_total))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            copied = process_snapshot_read(request.offset, request.result,
                                           request.result_capacity, &total);
            memcpy(request.out_count, &copied, sizeof(copied));
            memcpy(request.out_total, &total, sizeof(total));
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_MEMORY_INFO: {
            mg_system_memory_info_t *info =
                (mg_system_memory_info_t *)(uintptr_t)frame->rdi;

            if (!info || !syscall_user_buffer_valid(info, sizeof(*info))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            info->physical_total_bytes = pmm_get_total_memory();
            info->physical_used_bytes = pmm_get_used_memory();
            info->physical_free_bytes = pmm_get_free_memory();
            info->kernel_heap_total_bytes = heap_get_total_size();
            info->kernel_heap_used_bytes = heap_get_used_size();
            info->kernel_heap_free_bytes = heap_get_free_size();
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_CPU_SNAPSHOT: {
            mg_cpu_snapshot_request_t request;
            mg_cpu_snapshot_request_t *user_request =
                (mg_cpu_snapshot_request_t *)(uintptr_t)frame->rdi;
            u32 total = 0;
            u32 copied;

            if (!user_request || !syscall_user_buffer_valid(user_request,
                                                              sizeof(request))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            memcpy(&request, user_request, sizeof(request));
            if (!request.result || !request.out_count || !request.out_total ||
                request.result_capacity == 0U ||
                request.result_capacity > MG_CPU_SNAPSHOT_PAGE_MAX ||
                !syscall_user_buffer_valid(request.result,
                    (u64)request.result_capacity * sizeof(*request.result)) ||
                !syscall_user_buffer_valid(request.out_count,
                                            sizeof(*request.out_count)) ||
                !syscall_user_buffer_valid(request.out_total,
                                            sizeof(*request.out_total))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            copied = cpu_snapshot_read(request.offset, request.result,
                                       request.result_capacity, &total);
            memcpy(request.out_count, &copied, sizeof(copied));
            memcpy(request.out_total, &total, sizeof(total));
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_SYSTEM_INFO: {
            mg_system_info_t *info =
                (mg_system_info_t *)(uintptr_t)frame->rdi;

            if (!info || !syscall_user_buffer_valid(info, sizeof(*info))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            system_info_read(info);
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_PROCESS_SESSION_ID: {
            mg_session_id_t *user_session_id =
                (mg_session_id_t *)(uintptr_t)frame->rdi;
            process_t *current = process_current();

            if (!user_session_id || !current ||
                !syscall_user_buffer_valid(user_session_id,
                                            sizeof(*user_session_id))) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            *user_session_id = current->session_id;
            frame->rax = MG_OK;
            return;
        }
        case SYSCALL_PROCESS_CURRENT_PID: {
            u64 pid = process_current_pid();

            if (!pid) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            frame->rax = pid;
            return;
        }
        case SYSCALL_YIELD:
            frame->rax = scheduler_yield() ? (u64)MG_OK : (u64)MG_ERR_BUSY;
            return;
        case SYSCALL_EXIT:
            /* The current process has one userspace thread in this phase.
             * Mark it terminated, then hand execution to the scheduler.
             * Force-end any active terminal batch so output is not
             * permanently suppressed if the process dies mid-batch. */
            terminal_force_end_batch();
            if (!process_exit(process_current(), (i32)frame->rdi)) {
                syscall_fail(frame, MG_ERR_BAD_ARGUMENT);
                return;
            }
            frame->rax = scheduler_terminate() ? (u64)MG_OK :
                                                  (u64)MG_ERR_BUSY;
            return;
        default:
            syscall_fail(frame, MG_ERR_UNSUPPORTED);
            return;
    }
}
