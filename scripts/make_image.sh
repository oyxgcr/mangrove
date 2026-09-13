#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -e

BOOT_IMAGE=build/Mangrove/Boot.img
ROOT_IMAGE=build/Mangrove/Mangrove.img
MKMGFS=build/mkmgfs
PITH=build/Mangrove/pith.elf
SPROUT=build/sprout/sprout.elf
SPROUT_CMD=build/sproutcmd/sprout.elf
SESSIOND=build/sessiond/sessiond.elf
LOGIND=build/logind/logind.elf
LOGD=build/logd/logd.elf
NETWORKD=build/networkd/networkd.elf
DEVICED=build/deviced/deviced.elf
VOLUMED=build/volumed/volumed.elf
MOUNT=build/mount/mount.elf
UNMOUNT=build/unmount/unmount.elf
EJECT=build/eject/eject.elf
DISKUTIL=build/diskutil/diskutil.elf
LSPCI=build/lspci/lspci.elf
LSUSB=build/lsusb/lsusb.elf
LSDISK=build/lsdsk/lsdsk.elf
CREW=build/crew/crew.elf
MEM=build/mem/mem.elf
TIME=build/time/time.elf
TMON=build/tmon/tmon.elf
LOGV=build/logv/logv.elf
SHOOT=build/shoot/shoot.elf
CLEAR=build/clear/clear.elf
CP=build/cp/cp.elf
LS=build/ls/ls.elf
LOCATE=build/locate/locate.elf
MV=build/mv/mv.elf
PLANT=build/plant/plant.elf
TYPE=build/type/type.elf
RM=build/rm/rm.elf
MKDIR=build/mkdir/mkdir.elf
RMDIR=build/rmdir/rmdir.elf
SAY=build/say/say.elf
UPTIME=build/uptime/uptime.elf
DATE=build/date/date.elf
INFO=build/info/info.elf
PING=build/ping/ping.elf
RESOLVE=build/resolve/resolve.elf
FETCH=build/fetch/fetch.elf
NETINFO=build/netinfo/netinfo.elf
NETCFG=build/netcfg/netcfg.elf
POWER=build/power/power.elf
IDENTITY=build/identity/identity.elf
USER_CMD=build/user/user.elf
SHUTDOWN=build/shutdown/shutdown.elf
REBOOT=build/reboot/reboot.elf
VERSION=build/version/version.elf
WHERE=build/where/where.elf
PCI_IDS=share/hardware/pci.ids
USB_IDS=share/hardware/usb.ids
HARDWARE_README=share/hardware/README.txt
FRESH=0
AUTOLOGIN=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --fresh)
            FRESH=1
            ;;
        --root)
            shift
            if [ "$#" -eq 0 ]; then
                echo "Usage: $0 [--fresh] [--root image]" >&2
                exit 2
            fi
            ROOT_IMAGE=$1
            ;;
        --autologin)
            shift
            if [ "$#" -eq 0 ]; then
                echo "Usage: $0 [--fresh] [--root image] [--autologin user]" >&2
                exit 2
            fi
            AUTOLOGIN=$1
            ;;
        *)
            echo "Usage: $0 [--fresh] [--root image] [--autologin user]" >&2
            exit 2
            ;;
    esac
    shift
done

mkdir -p build/Mangrove
mkdir -p "$(dirname "$ROOT_IMAGE")"

# Keep the ordered payload list in one place for both fresh population and
# incremental updates.  The Python tools validate its length against their
# shared canonical manifest.
run_mgfs_tool() {
    tool="$1"
    shift
    python3 "tools/${tool}.py" "$ROOT_IMAGE" \
        "$PITH" "$SPROUT" "$SESSIOND" "$LOGIND" "$LOGD" "$NETWORKD" \
        "$DEVICED" "$VOLUMED" "$LSPCI" "$LSUSB" "$LSDISK" "$CREW" "$MEM" "$TIME" "$TMON" \
        "$LOGV" "$MOUNT" "$UNMOUNT" "$EJECT" "$DISKUTIL" \
        "$SHOOT" "$CLEAR" "$CP" "$SAY" "$UPTIME" "$LS" "$LOCATE" \
        "$MV" "$PLANT" "$TYPE" "$RM" "$VERSION" "$WHERE" "$PING" \
        "$RESOLVE" "$FETCH" "$NETINFO" "$NETCFG" "$SHUTDOWN" \
        "$REBOOT" "$POWER" \
        "$IDENTITY" "$USER_CMD" "$MKDIR" "$RMDIR" "$SPROUT_CMD" "$DATE" "$INFO" \
        "$PCI_IDS" "$USB_IDS" "$HARDWARE_README" \
        "$@"
}

rm -f "$BOOT_IMAGE"

# A zero-count seek creates the same sparse 64 MiB image with GNU or BSD dd.
dd if=/dev/zero of="$BOOT_IMAGE" bs=1 count=0 seek=67108864 2>/dev/null
mkfs.fat -F32 "$BOOT_IMAGE"

mmd -i "$BOOT_IMAGE" ::/EFI
mmd -i "$BOOT_IMAGE" ::/EFI/BOOT

mcopy -i "$BOOT_IMAGE" build/EFI/BOOT/BOOTX64.EFI ::/EFI/BOOT/

if [ "$FRESH" -eq 1 ]; then
    echo "[IMAGE] Resetting MGFS image: $ROOT_IMAGE"
    rm -f "$ROOT_IMAGE"
fi

if [ -f "$ROOT_IMAGE" ] && ! head -c 8 "$ROOT_IMAGE" | grep -a -q 'MGFSv1'; then
    echo "Discarding obsolete non-MGFS root image $ROOT_IMAGE"
    rm -f "$ROOT_IMAGE"
fi

if [ ! -f "$ROOT_IMAGE" ]; then
    echo "Creating fresh MGFS root image $ROOT_IMAGE..."
    "$MKMGFS" \
        --blocks 16384 \
        --uuid 00000000-0000-0000-0000-000000000001 \
        --format-time-ns 0 \
        "$ROOT_IMAGE"
    if [ -n "$AUTOLOGIN" ]; then
        run_mgfs_tool populate_mgfs "--autologin=$AUTOLOGIN"
    else
        run_mgfs_tool populate_mgfs
    fi
else
    if [ -n "$AUTOLOGIN" ]; then
        run_mgfs_tool update_mgfs "--autologin=$AUTOLOGIN"
    else
    run_mgfs_tool update_mgfs
    fi
fi
