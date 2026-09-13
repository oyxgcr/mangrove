# Identity, sessions, privileges, and PASS

Mangrove separates persistent account identity, process credentials, system
service capabilities, login authentication, and authorization of a protected
operation. There is no generic root or sudo mode.

## Identity classes and account lifetime

The canonical account database is `/sys/accounts/users`. The kernel parses it
into an identity registry with bounded usernames, UIDs, roles, home paths, and
password records. There are three identity classes:

- `system` is UID 0. It is a non-human identity, is not a login account, and
  is not an administrator account.
- administrator accounts are human accounts with the administrator role.
  They are peers; one administrator does not acquire access to another's
  private data merely from that role.
- regular accounts are human accounts without administrator authority.

The preinstalled developer account uses UID 1000. Newly created human
accounts start at UID 1001. Allocation is monotonic: removing an account does
not return its UID to the allocator. This prevents files retaining a retired
numeric owner from silently becoming owned by a different person. A removed
account's preserved files retain its now-unresolved UID until an explicit
future ownership policy exists.

A process carries only stable credentials: UID, role, and a service-privilege
mask. Normal children inherit effective human credentials. Role authority is
resolved against the live identity registry, so demotion affects existing
processes. Trusted services receive only the capabilities in the kernel
processes. UID 0 carries the distinct `system` role and may use only explicit
service capabilities. Human processes cannot acquire service capability bits.

Administrators may hold ordinary management privileges for users, network,
configuration, services, devices, and storage. Session management is reserved
for the designated services. Being system-owned does not itself bypass a
privilege check.

## Ordinary filesystem access

MGFS stores compact object facts: file or directory type, a stable monotonic
record identifier, logical size, owner UID, owner read/write bits, and other
read/write bits. It does not store owner names, roles, groups, ACLs, timestamps,
or a generic protected/system-managed flag. VFS nodes synthesize equivalent
owner/permission fields for FAT32 and exFAT at mount time; those filesystems do
not persist Mangrove ownership.

VFS access is owner-versus-other only. A caller whose UID equals the object's
owner uses the owner bits; every other caller uses the other bits. This applies
to human users, administrators, and ordinary system-service processes. There
is no root bypass and no execute/search bit. Directory read permits listing and
path traversal through that directory. Directory write permits creating,
deleting, or renaming entries in it; deletion is not granted by the target
file's write bit alone. Rename checks both source and destination directories,
does not cross mounted filesystems, preserves the moved object's owner and
permission bits, and does not replace an existing destination.

Path traversal checks each directory's read permission. A mount point resolves
to the mounted filesystem, so permissions and read-only state of that mounted
filesystem remain authoritative. A read-only mount rejects VFS writes,
including writes made through an authorized handle. FAT32 currently does not
enforce its on-disk read-only attribute; exFAT does enforce its read-only
attribute. MGFS persists the owner and four permission bits; FAT32/exFAT
ownership is shared-volume policy and is not a stable user-security identity.

Normal creation assigns the caller's UID and `rw:r-` to both files and
directories. Explicit administrative creation on behalf of a regular user
assigns that user's UID with the same native defaults. MGFS directories may
persist an `open` or `owner-restricted` child-mutation policy; the latter
requires ownership of the child or containing directory in addition to write
access to the directory. These policies do not alter stored owner or
permission bits and are not Unix umask, ACL, or sticky-bit semantics. Human
home directories are private, while `/temp` is shared and owner-restricted.

## Explicit administration of regular-user data

Human administrators may request the native administrative filesystem
operations only through the explicit `MANAGE_USER_DATA` PASS privilege. This is
not an administrator mode and does not change the caller UID, object owner, or
stored permission bits. Each request is one open/create/move/remove operation;
an administrative open creates a process-local handle whose authorization is
bound to the exact live MGFS node and is rechecked on every access. The handle
does not authorize another path or object, is not inherited by spawned
processes, and role changes invalidate its use. The kernel rechecks the live
owner role after PASS and binds path-based mutations to the resolved superblock
and record identifier, so replacing or renaming a path cannot redirect the
authorized operation.

The override relationship is deliberately downward only:

- an administrator may explicitly administer a live MGFS object owned by a
  current regular account;
- an administrator may not use this override for a peer administrator's
  object, a system-owned object, or a deleted/unresolved owner;
- ordinary owner/other access still applies without an override, so an
  administrator can read an object only when its ordinary other bits permit
  it.

Administrative delete requires both the containing directory and target to be
  eligible regular-user data. Administrative rename validates the source
  object, source directory, and destination directory; both directories must
  be eligible regular-user MGFS directories, the destination must be absent,
  and the source owner is preserved. An administrative move between regular
  users is therefore explicit but does not transfer ownership. Administrative
  create is allowed only in a regular-user-owned MGFS directory and assigns the
  new object that directory owner's UID with the native file or directory
  creation default.
  These checks are repeated after PASS. They do not grant recursive authority:
  a nested object or mounted filesystem must independently satisfy its own
  policy, and system/administrator directories cannot be used as an override
  boundary.

The administrative operation ABI is process-local and does not expose a
transferable capability. There is no user-facing handle duplication syscall;
normal spawn inherits only explicitly selected console/output handles. The
existing `/conf` write path remains separate: it uses
`MANAGE_CONFIGURATION`, applies only to an existing configuration file, and
does not authorize generic create/delete/rename or bypass a read-only mount.
Trusted kernel VFS operations remain separate for image, account, and service
maintenance and are not a userspace administrator escape hatch.

FAT32 and exFAT are not admitted to the regular-user override because their
ownership is synthesized and can change on remount. Their ordinary shared
volume permissions and filesystem-specific read-only behavior remain the
authoritative policy.

## Login and sessions

Password authentication is a kernel identity/PASS operation; account password
records are not exposed to logind or sessiond. Logind is the session frontend,
while sessiond is the backend that creates and ends kernel session records.
The kernel verifies their service identities and the authenticated origin of
cross-service requests.

A session has a monotonic boot-local ID, owner, user identity, lifecycle state,
activity state, and shell PID. The current table holds at most eight active
records. A launched shell and its children receive the session's credentials,
home/current-directory context, and session ID. Ending a session terminates
its member processes and releases the record.

Autologin policy is read from `/conf/session/config`. Eligibility is a
boot-scoped one-shot token consumed by logind; restarting a service cannot
silently repeat autologin after logout or shell failure.

## PASS authorization

PASS is the kernel-owned boundary for protected actions. The required
privilege and trusted description are selected by kernel code, not supplied by
the requesting client. For an IPC operation, PASS claims the kernel-recorded
request context and authorizes the original caller.

`/conf/security/config` selects the current provider:

- `password`: verify the current human administrator's password;
- `confirm`: present a trusted yes/no prompt;
- `scripts`: allow the current direct-admin script policy;
- `none`: allow after the privilege check.

A missing or malformed policy falls back to `confirm`. System services may
perform autonomous work only when their explicit service capability satisfies
the requested privilege; they do not trigger a human prompt.

PASS authorization is distinct from command-specific destructive confirmation.
For example, `diskutil` requires `MANAGE_STORAGE` and PASS once when the
process enters its management session. The kernel marks only that current
`diskutil` process. Individual format and GPT mutations arm one bounded
operation for that process and still require their exact `FORMAT`,
`INITIALIZE`, `CREATE`, or `DELETE` confirmation in userspace. The session
authorization cannot be transferred and disappears when the process exits.

Standalone mount, unmount, eject, network, account, and service-control paths
authorize their logical request through their trusted service or kernel
boundary. Client-supplied role or requester fields never grant authority.

## Authoritative code

- `kernel/include/identity.h`, `kernel/src/identity.c`, and
  `/sys/accounts/users`
- `kernel/include/pass.h`, `kernel/src/pass.c`, and `/conf/security/config`
- `kernel/include/session.h`, `kernel/src/session.c`, and
  `/conf/session/config`
- `kernel/src/service.c`, `kernel/src/syscall.c`, and
  `userspace/diskutil/main.c`
