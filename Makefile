UNAME       := $(shell uname -s)
HOST_ARCH   := $(shell uname -m)

BOOT_CC     := x86_64-w64-mingw32-gcc
BOOT_AS     := x86_64-w64-mingw32-gcc
BOOT_LD     := x86_64-w64-mingw32-ld

ifeq ($(UNAME),Darwin)
ELF_CC      := x86_64-elf-gcc
ELF_AS      := x86_64-elf-gcc
ELF_LD      := x86_64-elf-ld
ELF_AR      := x86_64-elf-ar
ELF_OBJCOPY := x86_64-elf-objcopy

# Homebrew keeps native GNU GCC versioned so it does not replace Apple's
# compiler.  Host tools run on macOS and therefore use this native compiler;
# kernel and userspace use the x86_64-elf cross compiler above.
HOST_GCC_PREFIX := $(shell brew --prefix gcc 2>/dev/null)
HOST_CC         := $(lastword $(sort $(wildcard $(HOST_GCC_PREFIX)/bin/gcc-[0-9]*)))
else
ELF_CC      := gcc
ELF_AS      := gcc
ELF_LD      := ld.bfd
ELF_AR      := ar
ELF_OBJCOPY := objcopy
HOST_CC     := gcc
endif

CC          := $(ELF_CC)
LD_KERNEL   := $(ELF_LD)
AR          := $(ELF_AR)
OBJCOPY     := $(ELF_OBJCOPY)

QEMU        := qemu-system-x86_64
QEMU_SMP    ?= 2

BOOT_TOOLS := $(BOOT_CC) $(BOOT_LD)
ELF_TOOLS  := $(ELF_CC) $(ELF_LD) $(ELF_AR) $(ELF_OBJCOPY)
HOST_TOOLS := $(HOST_CC)
MISSING_BOOT_TOOLS := $(foreach tool,$(BOOT_TOOLS),$(if $(shell command -v $(tool) 2>/dev/null),,$(tool)))
MISSING_ELF_TOOLS  := $(foreach tool,$(ELF_TOOLS),$(if $(shell command -v $(tool) 2>/dev/null),,$(tool)))
MISSING_HOST_TOOLS := $(foreach tool,$(HOST_TOOLS),$(if $(shell command -v $(tool) 2>/dev/null),,$(tool)))
ifneq ($(strip $(MISSING_BOOT_TOOLS)),)
$(error Missing required MinGW-w64 UEFI toolchain command(s): $(MISSING_BOOT_TOOLS). Install gcc-mingw-w64-x86-64 and binutils-mingw-w64-x86-64 on Linux, or mingw-w64 with Homebrew on macOS.)
endif
ifneq ($(strip $(MISSING_ELF_TOOLS)),)
ifeq ($(UNAME),Darwin)
$(error Missing required macOS x86_64-elf GNU toolchain command(s): $(MISSING_ELF_TOOLS). Install with: brew install x86_64-elf-gcc x86_64-elf-binutils)
else
$(error Missing required GNU ELF toolchain command(s): $(MISSING_ELF_TOOLS).)
endif
endif
ifneq ($(strip $(MISSING_HOST_TOOLS)),)
ifeq ($(UNAME),Darwin)
$(error Missing Homebrew GNU host GCC. Install with: brew install gcc)
else
$(error Missing host compiler: $(MISSING_HOST_TOOLS))
endif
endif

ifeq ($(UNAME),Darwin)
    QEMU_PREFIX       ?= $(shell brew --prefix qemu 2>/dev/null)
ifeq ($(HOST_ARCH),arm64)
    QEMU_ACCEL        := tcg
else
    QEMU_ACCEL        := hvf
endif
    QEMU_CPU          := max
    OVMF_CODE_SOURCE  := $(QEMU_PREFIX)/share/qemu/edk2-x86_64-code.fd
    OVMF_VARS_SOURCE  := $(QEMU_PREFIX)/share/qemu/edk2-i386-vars.fd
else
    QEMU_ACCEL        := kvm
    QEMU_CPU          := host
    OVMF_CODE_SOURCE := /usr/share/OVMF/OVMF_CODE_4M.fd
    OVMF_VARS_SOURCE := /usr/share/OVMF/OVMF_VARS_4M.fd
endif

QEMU_PLATFORM_ARGS := -accel $(QEMU_ACCEL) -cpu $(QEMU_CPU)

BUILD_DIR    := build
EFI_DIR      := $(BUILD_DIR)/EFI/BOOT
MANGROVE_DIR := $(BUILD_DIR)/Mangrove
STATE_DIR    ?= .mangrove
DEV_IMAGE    := $(STATE_DIR)/MangroveDev.img
DEV_ROOT_IMAGE := $(STATE_DIR)/MangroveDevRoot.img
LEGACY_DEV_IMAGE := $(MANGROVE_DIR)/Mangrove.img
FLASH_ROOT_IMAGE := $(MANGROVE_DIR)/MangroveFlash.img
USB_IMAGE    := $(MANGROVE_DIR)/MangroveUSB.img
SPROUT_DIR   := $(BUILD_DIR)/sprout
SPROUT_CMD_DIR := $(BUILD_DIR)/sproutcmd
SESSIOND_DIR := $(BUILD_DIR)/sessiond
LOGIND_DIR   := $(BUILD_DIR)/logind
LOGD_DIR     := $(BUILD_DIR)/logd
NETWORKD_DIR := $(BUILD_DIR)/networkd
DEVICED_DIR  := $(BUILD_DIR)/deviced
VOLUMED_DIR  := $(BUILD_DIR)/volumed
MOUNT_DIR    := $(BUILD_DIR)/mount
UNMOUNT_DIR  := $(BUILD_DIR)/unmount
EJECT_DIR    := $(BUILD_DIR)/eject
LSPCI_DIR    := $(BUILD_DIR)/lspci
LSUSB_DIR    := $(BUILD_DIR)/lsusb
LSDISK_DIR   := $(BUILD_DIR)/lsdsk
DISKUTIL_DIR := $(BUILD_DIR)/diskutil
CREW_DIR     := $(BUILD_DIR)/crew
INFO_DIR     := $(BUILD_DIR)/info
MEM_DIR      := $(BUILD_DIR)/mem
TIME_DIR     := $(BUILD_DIR)/time
TMON_DIR     := $(BUILD_DIR)/tmon
LOGV_DIR     := $(BUILD_DIR)/logv
HELLO_DIR    := $(BUILD_DIR)/hello
SHOOT_DIR    := $(BUILD_DIR)/shoot
CLEAR_DIR    := $(BUILD_DIR)/clear
CP_DIR       := $(BUILD_DIR)/cp
LS_DIR       := $(BUILD_DIR)/ls
LOCATE_DIR   := $(BUILD_DIR)/locate
MV_DIR       := $(BUILD_DIR)/mv
PLANT_DIR    := $(BUILD_DIR)/plant
TYPE_DIR     := $(BUILD_DIR)/type
RM_DIR       := $(BUILD_DIR)/rm
MKDIR_DIR    := $(BUILD_DIR)/mkdir
RMDIR_DIR    := $(BUILD_DIR)/rmdir
SAY_DIR      := $(BUILD_DIR)/say
UPTIME_DIR   := $(BUILD_DIR)/uptime
DATE_DIR     := $(BUILD_DIR)/date
VERSION_DIR  := $(BUILD_DIR)/version
WHERE_DIR    := $(BUILD_DIR)/where
FONT_SOURCE  := kernel/assets/font/unscii-16.hex
FONT_CONVERTER := tools/convert_unscii_hex.py
FONT_ASSET   := kernel/assets/font.psf
FSTEST_DIR   := $(BUILD_DIR)/fstest
NETTEST_DIR  := $(BUILD_DIR)/nettest
PING_DIR     := $(BUILD_DIR)/ping
RESOLVE_DIR  := $(BUILD_DIR)/resolve
FETCH_DIR    := $(BUILD_DIR)/fetch
NETINFO_DIR  := $(BUILD_DIR)/netinfo
NETCFG_DIR   := $(BUILD_DIR)/netcfg
POWER_DIR    := $(BUILD_DIR)/power
IDENTITY_DIR := $(BUILD_DIR)/identity
USER_CMD_DIR := $(BUILD_DIR)/user
SHUTDOWN_DIR := $(BUILD_DIR)/shutdown
REBOOT_DIR   := $(BUILD_DIR)/reboot
USER_LIBC_DIR := $(BUILD_DIR)/userspace/libc

EFI          := $(EFI_DIR)/BOOTX64.EFI
PITH         := $(MANGROVE_DIR)/pith.elf
KERNEL_MAP   := $(MANGROVE_DIR)/kernel.map
OVMF_CODE    := $(OVMF_CODE_SOURCE)
OVMF_VARS    ?= $(BUILD_DIR)/OVMF_VARS.fd
MKMGFS       := $(BUILD_DIR)/mkmgfs
SPROUT       := $(SPROUT_DIR)/sprout.elf
SPROUT_CMD   := $(SPROUT_CMD_DIR)/sprout.elf
SESSIOND     := $(SESSIOND_DIR)/sessiond.elf
LOGIND       := $(LOGIND_DIR)/logind.elf
LOGD         := $(LOGD_DIR)/logd.elf
NETWORKD     := $(NETWORKD_DIR)/networkd.elf
DEVICED      := $(DEVICED_DIR)/deviced.elf
VOLUMED      := $(VOLUMED_DIR)/volumed.elf
MOUNT        := $(MOUNT_DIR)/mount.elf
UNMOUNT      := $(UNMOUNT_DIR)/unmount.elf
EJECT        := $(EJECT_DIR)/eject.elf
LSPCI        := $(LSPCI_DIR)/lspci.elf
LSUSB        := $(LSUSB_DIR)/lsusb.elf
LSDISK       := $(LSDISK_DIR)/lsdsk.elf
DISKUTIL     := $(DISKUTIL_DIR)/diskutil.elf
CREW         := $(CREW_DIR)/crew.elf
INFO         := $(INFO_DIR)/info.elf
MEM          := $(MEM_DIR)/mem.elf
TIME         := $(TIME_DIR)/time.elf
TMON         := $(TMON_DIR)/tmon.elf
LOGV         := $(LOGV_DIR)/logv.elf
HELLO        := $(HELLO_DIR)/hello.elf
SHOOT        := $(SHOOT_DIR)/shoot.elf
CLEAR        := $(CLEAR_DIR)/clear.elf
CP           := $(CP_DIR)/cp.elf
LS           := $(LS_DIR)/ls.elf
LOCATE       := $(LOCATE_DIR)/locate.elf
MV           := $(MV_DIR)/mv.elf
PLANT        := $(PLANT_DIR)/plant.elf
TYPE         := $(TYPE_DIR)/type.elf
RM           := $(RM_DIR)/rm.elf
MKDIR        := $(MKDIR_DIR)/mkdir.elf
RMDIR        := $(RMDIR_DIR)/rmdir.elf
SAY          := $(SAY_DIR)/say.elf
UPTIME       := $(UPTIME_DIR)/uptime.elf
DATE         := $(DATE_DIR)/date.elf
VERSION      := $(VERSION_DIR)/version.elf
WHERE        := $(WHERE_DIR)/where.elf
FSTEST       := $(FSTEST_DIR)/fstest.elf
NETTEST      := $(NETTEST_DIR)/nettest.elf
PING         := $(PING_DIR)/ping.elf
RESOLVE      := $(RESOLVE_DIR)/resolve.elf
FETCH        := $(FETCH_DIR)/fetch.elf
NETINFO      := $(NETINFO_DIR)/netinfo.elf
NETCFG       := $(NETCFG_DIR)/netcfg.elf
POWER        := $(POWER_DIR)/power.elf
IDENTITY     := $(IDENTITY_DIR)/identity.elf
USER_CMD     := $(USER_CMD_DIR)/user.elf
SHUTDOWN     := $(SHUTDOWN_DIR)/shutdown.elf
REBOOT       := $(REBOOT_DIR)/reboot.elf
COMMAND_PATH_OBJ := $(BUILD_DIR)/userspace/command_path.o
HELP_OBJ     := $(BUILD_DIR)/userspace/help.o
STORAGE_SNAPSHOT_OBJ := $(BUILD_DIR)/userspace/storage_snapshot.o
USER_LIBC    := $(USER_LIBC_DIR)/libc.a
USER_CRT     := $(BUILD_DIR)/userspace/crt0.o

DEPFLAGS     := -MMD -MP

BOOT_CFLAGS  := -std=gnu11 -ffreestanding -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-stack-protector -Iboot/include -Iinclude $(DEPFLAGS)
BOOT_ASFLAGS :=
# GNU ld uses numeric subsystem 10 for EFI applications.  Direct linking
# intentionally omits MinGW CRT/startup objects and all default libraries.
BOOT_LDFLAGS := --subsystem 10 --entry efi_main --enable-reloc-section --dynamicbase --disable-auto-import --no-insert-timestamp


# The kernel remains free of compiler-generated FPU/SIMD instructions.  User
# threads own an eager FXSAVE/FXRSTOR context, so userspace may use the normal
# x86-64 floating-point/SSE ABI without exposing that state to kernel C code.
KERNEL_CFLAGS  := -std=gnu11 -ffreestanding -fno-asynchronous-unwind-tables -fno-stack-protector -fno-pic -fno-pie -mcmodel=kernel -Ikernel/include -Ikernel/include/usb -Ikernel/include/pci -Ikernel/include/storage -Iinclude -Ilibc/include -mno-red-zone -mno-sse -mno-sse2 -mno-mmx -msoft-float $(DEPFLAGS)
KERNEL_ASFLAGS := -m64
KERNEL_LDFLAGS := -z max-page-size=0x1000 -T kernel/linker.ld -Map=$(KERNEL_MAP)

USER_CFLAGS := -std=gnu11 -ffreestanding -fno-asynchronous-unwind-tables -fno-stack-protector \
               -fno-builtin -fno-pic -fno-pie -mno-red-zone -nostdinc \
               -I. -Iuserspace/shoot -Ikernel/include -Ilibc/include -Iinclude \
               $(DEPFLAGS)
USER_LINKER_SCRIPT := userspace/linker/userspace.ld

# Boot-time subsystem smoke tests are intentionally excluded from the normal
# Mangrove boot path.  Build with DEBUG_BOOT_TESTS=1 to include them.
ifneq ($(DEBUG_BOOT_TESTS),)
KERNEL_CFLAGS += -DPITH_DEBUG_BOOT_TESTS
endif

# Low-level kernel bring-up details are excluded from normal production boot.
# Use KERNEL_BOOT_DEBUG=1 when auditing the initialization path.
ifeq ($(KERNEL_BOOT_DEBUG),1)
KERNEL_CFLAGS += -DKERNEL_BOOT_DEBUG=1
endif

# Optional host-side TCP echo smoke test.  It is intentionally off in normal
# images and uses the DHCP-learned gateway at runtime.
ifeq ($(TCP_ECHO_TEST),1)
KERNEL_CFLAGS += -DPITH_TCP_ECHO_TEST=1
endif

# Optional one-shot kernel HTTP validation; disabled for normal images.
ifeq ($(HTTP_GET_TEST),1)
KERNEL_CFLAGS += -DPITH_HTTP_GET_TEST=1
endif

# Detailed USB/xHCI investigation traces are excluded from normal builds.
# Use `make -B XHCI_DEBUG=1` when the low-level controller traces are needed.
ifeq ($(XHCI_DEBUG),1)
KERNEL_CFLAGS += -DXHCI_DEBUG=1
endif

# Opt-in DHCP/boot-network milestone diagnostics.  Normal images remain
# silent; the stream is mirrored to QEMU serial output when enabled.
ifeq ($(NETWORK_BOOT_DIAG),1)
KERNEL_CFLAGS += -DNETWORK_BOOT_DIAG=1
endif

# Opt-in detailed ELF loader tracing.  Normal images do not print successful
# per-read or per-segment loader activity.
ifeq ($(ELF_LOADER_DEBUG),1)
KERNEL_CFLAGS += -DELF_LOADER_DEBUG=1
endif

# Opt-in ACPI battery/adapter discovery diagnostics for real-hardware tests.
# Normal images keep AML evaluation failures silent and report only the
# user-facing unavailable state.
ifeq ($(ACPI_POWER_DEBUG),1)
KERNEL_CFLAGS += -DACPI_POWER_DEBUG=1
endif

# Opt-in platform temperature diagnostics for real-hardware sensor tests.
ifeq ($(PLATFORM_THERMAL_DEBUG),1)
KERNEL_CFLAGS += -DPLATFORM_THERMAL_DEBUG=1
endif

# Opt-in CMOS RTC decoding diagnostics.  Normal boots do not expose raw RTC
# registers or mode details on the framebuffer.
ifeq ($(RTC_DEBUG),1)
KERNEL_CFLAGS += -DRTC_DEBUG=1
endif

# Automatic Source Discovery
BOOT_C_SRCS    := $(shell find boot/src -name '*.c')
BOOT_S_SRCS    := $(shell find boot/src -name '*.s')
KERNEL_C_SRCS  := $(shell find kernel/src -name '*.c')
KERNEL_S_SRCS  := $(shell find kernel/src -name '*.s')
LIBC_C_SRCS    := $(shell find libc/src -name '*.c' ! -name 'mangrove_syscall.c' ! -name 'allocator.c' ! -name 'stdio.c' ! -name 'native.c' ! -name 'line_editor.c' ! -name 'net.c' ! -name 'log.c' ! -name 'time.c' ! -name 'time_convert.c')

# Object Mappings
BOOT_OBJS := $(patsubst boot/src/%.c,$(BUILD_DIR)/boot/%.o,$(BOOT_C_SRCS))
BOOT_OBJS += $(patsubst boot/src/%.s,$(BUILD_DIR)/boot/%.o,$(BOOT_S_SRCS))

KERNEL_OBJS := $(patsubst kernel/src/%.c,$(BUILD_DIR)/kernel/%.o,$(KERNEL_C_SRCS))
KERNEL_OBJS += $(patsubst kernel/src/%.s,$(BUILD_DIR)/kernel/%.o,$(KERNEL_S_SRCS))
KERNEL_OBJS += $(BUILD_DIR)/kernel/font_blob.o
KERNEL_OBJS += $(BUILD_DIR)/kernel/time_convert.o

LIBC_OBJS    := $(patsubst libc/src/%.c,$(BUILD_DIR)/libc/%.o,$(LIBC_C_SRCS))

ALL_KERNEL_OBJS := $(KERNEL_OBJS) $(LIBC_OBJS)

DEPS := $(BOOT_OBJS:.o=.d) $(ALL_KERNEL_OBJS:.o=.d)

.PHONY: all help make fresh run fresh-run usb clean test exfat-upcase \
        binaries font sprout sessiond logind logd networkd deviced volumed mount unmount eject lspci lsusb lsdsk diskutil crew info mem time tmon logv hello shoot clear cp ls locate mv mkdir plant type rm rmdir say shutdown reboot uptime date version where fstest nettest ping resolve fetch netinfo netcfg power identity user \
        image fresh-image usb-image run-usb mkmgfs mgfsck test-time test-terminal test-mgfs-migration \
        check-image-deps check-usb-deps check-qemu-deps qemu-warning dev-image fresh-dev-image flash-image

# Everyday targets
all: image

exfat-upcase:
	python3 tools/generate_exfat_upcase.py
	python3 tools/generate_exfat_upcase.py --check

help:
	@echo "Everyday commands:"
	@echo "  make             Build/update the persistent development image"
	@echo "  make run         Build and boot the persistent USB/xHCI development image"
	@echo "  make fresh       Reset the persistent development image"
	@echo "  make fresh-run   Reset the development image and boot it"
	@echo "  make usb         Build build/Mangrove/MangroveUSB.img for hardware"
	@echo "  make clean       Remove disposable build artifacts; preserve .mangrove/"
	@echo "  make test        Run the available host-side test suites"
	@echo
	@echo "Specialist targets: binaries image fresh-image usb-image mkmgfs mgfsck"
	@echo "                    test-time test-terminal and individual programs"

make: image

fresh: fresh-dev-image

usb: flash-image

test:
	@status=0; \
	for target in test-time test-terminal test-mgfs-migration; do \
		if $(MAKE) --no-print-directory $$target; then :; else status=1; fi; \
	done; \
	exit $$status

binaries: $(EFI) $(PITH) $(SPROUT) $(SPROUT_CMD) $(SESSIOND) $(LOGIND) $(LOGD) $(NETWORKD) $(DEVICED) $(VOLUMED) $(MOUNT) $(UNMOUNT) $(EJECT) $(LSPCI) $(LSUSB) $(LSDISK) $(DISKUTIL) $(CREW) $(INFO) $(MEM) $(TIME) $(TMON) $(LOGV) $(SHOOT) $(CLEAR) $(CP) $(LS) $(LOCATE) $(MV) $(MKDIR) $(PLANT) $(TYPE) $(RM) $(RMDIR) $(SAY) $(SHUTDOWN) $(REBOOT) $(UPTIME) $(DATE) $(VERSION) $(WHERE) $(PING) $(RESOLVE) $(FETCH) $(NETINFO) $(NETCFG) $(POWER) $(IDENTITY) $(USER_CMD)

shoot: $(SHOOT)

clear: $(CLEAR)

cp: $(CP)

ls: $(LS)
locate: $(LOCATE)
mv: $(MV)
mkdir: $(MKDIR)
plant: $(PLANT)
type: $(TYPE)
rm: $(RM)
rmdir: $(RMDIR)

say: $(SAY)

shutdown: $(SHUTDOWN)

reboot: $(REBOOT)

uptime: $(UPTIME)

date: $(DATE)

version: $(VERSION)
where: $(WHERE)

sprout: $(SPROUT)

sessiond: $(SESSIOND)

logind: $(LOGIND)

logd: $(LOGD)

networkd: $(NETWORKD)

deviced: $(DEVICED)

mount: $(MOUNT)

unmount: $(UNMOUNT)

eject: $(EJECT)

volumed: $(VOLUMED)

lspci: $(LSPCI)

lsusb: $(LSUSB)

lsdsk: $(LSDISK)

diskutil: $(DISKUTIL)

crew: $(CREW)

info: $(INFO)

mem: $(MEM)

time: $(TIME)

tmon: $(TMON)

logv: $(LOGV)

hello: $(HELLO)

fstest: $(FSTEST)
nettest: $(NETTEST)
ping: $(PING)
resolve: $(RESOLVE)
fetch: $(FETCH)
netinfo: $(NETINFO)

netcfg: $(NETCFG)

power: $(POWER)

identity: $(IDENTITY)

user: $(USER_CMD)

mkmgfs: $(MKMGFS)

mgfsck: $(BUILD_DIR)/mgfsck

test-time:
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-Ilibc/include -Iinclude tests/timekeeping_test.c \
		libc/src/time_convert.c -o /tmp/mangrove-timekeeping-test
	/tmp/mangrove-timekeeping-test
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-Ikernel/include -Iinclude tests/rtc_decode_test.c \
		kernel/src/rtc_decode.c -o /tmp/mangrove-rtc-decode-test
	/tmp/mangrove-rtc-decode-test
	@echo timekeeping tests passed

test-terminal:
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-Ikernel/include -Iinclude tests/utf8_decode_test.c \
		kernel/src/utf8.c -o /tmp/mangrove-utf8-test
	/tmp/mangrove-utf8-test
	@echo terminal UTF-8 tests passed

test-mgfs-migration: $(MKMGFS) $(BUILD_DIR)/mgfsck
	python3 tests/mgfs_migration_test.py $(MKMGFS) $(BUILD_DIR)/mgfsck

check-image-deps:
	@missing=""; \
	for tool in mkfs.fat mmd mcopy python3; do \
		command -v "$$tool" >/dev/null 2>&1 || missing="$$missing $$tool"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "Missing image-build tools:$$missing" >&2; \
		if [ "$(UNAME)" = Darwin ]; then \
			echo "Install them with: brew install dosfstools mtools" >&2; \
		else \
			echo "On Debian/Ubuntu, install them with: sudo apt-get install dosfstools mtools python3" >&2; \
		fi; \
		exit 1; \
	fi; \
	if [ ! -f "$(OVMF_VARS_SOURCE)" ]; then \
		echo "Missing UEFI firmware: $(OVMF_VARS_SOURCE)" >&2; \
		if [ "$(UNAME)" = Darwin ]; then \
			echo "Install it with: brew install qemu" >&2; \
		else \
			echo "On Debian/Ubuntu, install it with: sudo apt-get install ovmf" >&2; \
		fi; \
		exit 1; \
	fi

check-usb-deps: check-image-deps
	@if [ "$(UNAME)" = Darwin ]; then \
		if ! command -v sgdisk >/dev/null 2>&1; then \
			echo "Missing macOS USB-image tool: sgdisk" >&2; \
			echo "Install it with: brew install gptfdisk" >&2; \
			exit 1; \
		fi; \
	elif [ "$(UNAME)" = Linux ]; then \
		if ! command -v parted >/dev/null 2>&1; then \
			echo "Missing Linux USB-image tool: parted" >&2; \
			echo "On Debian/Ubuntu, install it with: sudo apt-get install parted" >&2; \
			exit 1; \
		fi; \
	else \
		echo "Unsupported host OS for usb-image: $(UNAME)" >&2; \
		exit 1; \
	fi

check-qemu-deps:
	@if ! command -v "$(QEMU)" >/dev/null 2>&1; then \
		echo "Missing QEMU executable: $(QEMU)" >&2; \
		if [ "$(UNAME)" = Darwin ]; then \
			echo "Install it with: brew install qemu" >&2; \
		else \
			echo "On Debian/Ubuntu, install it with: sudo apt-get install qemu-system-x86 ovmf" >&2; \
		fi; \
		exit 1; \
	fi; \
	if ! "$(QEMU)" -accel help 2>/dev/null | grep -q "^[[:space:]]*$(QEMU_ACCEL)[[:space:]]*$$"; then \
		echo "$(QEMU) does not provide the required $(QEMU_ACCEL) accelerator on $(UNAME)." >&2; \
		echo "Available accelerators:" >&2; \
		"$(QEMU)" -accel help >&2; \
		exit 1; \
	fi; \
	if [ "$(UNAME)" = Linux ] && [ ! -r /dev/kvm -o ! -w /dev/kvm ]; then \
		echo "KVM is unavailable: /dev/kvm must exist and be readable and writable." >&2; \
		echo "Load the KVM module and add your user to the kvm group, then log in again." >&2; \
		exit 1; \
	fi; \
	if [ "$(UNAME)" = Darwin ] && [ "$(QEMU_ACCEL)" = hvf ] && [ "$$(sysctl -n kern.hv_support 2>/dev/null)" != 1 ]; then \
		echo "HVF is unavailable: this Mac does not report Hypervisor Framework support." >&2; \
		exit 1; \
	fi; \
	if [ ! -f "$(OVMF_CODE_SOURCE)" ]; then \
		echo "Missing UEFI firmware: $(OVMF_CODE_SOURCE)" >&2; \
		exit 1; \
	fi

ifeq ($(QEMU_ACCEL),tcg)
qemu-warning:
	@echo "Warning: Running x86_64 Mangrove under TCG software emulation on Apple Silicon; performance will be slower." >&2
else
qemu-warning:
endif

dev-image: check-usb-deps binaries $(MKMGFS) $(OVMF_VARS)
	@mkdir -p $(STATE_DIR)
	./scripts/update_dev_image.sh --disk "$(DEV_IMAGE)" --root "$(DEV_ROOT_IMAGE)"

fresh-dev-image: check-usb-deps binaries $(MKMGFS) $(OVMF_VARS)
	@mkdir -p $(STATE_DIR)
	@echo "[FRESH] Factory-resetting persistent development image $(DEV_IMAGE)"
	./scripts/update_dev_image.sh --fresh --disk "$(DEV_IMAGE)" --root "$(DEV_ROOT_IMAGE)"

flash-image: check-usb-deps binaries $(MKMGFS) $(OVMF_VARS)
	./scripts/make_image.sh --fresh --root "$(FLASH_ROOT_IMAGE)" --autologin developer
	@mkdir -p $(MANGROVE_DIR)
	@rm -f $(USB_IMAGE)
	@dd if=/dev/zero of=$(USB_IMAGE) bs=1 count=0 seek=135283200 2>/dev/null
ifeq ($(UNAME),Darwin)
	@sgdisk --zap-all \
		--new=1:2048:133119 --typecode=1:EF00 --change-name=1:MANGROVE_ESP \
		--new=2:133120:264191 --typecode=2:8300 --change-name=2:MANGROVE_ROOT \
		$(USB_IMAGE) >/dev/null 2>&1 || { \
			echo "sgdisk failed while creating the GPT in $(USB_IMAGE)" >&2; \
			exit 1; \
		}
else
	@parted -s -a minimal $(USB_IMAGE) mklabel gpt
	@parted -s -a minimal $(USB_IMAGE) mkpart MANGROVE_ESP fat32 2048s 133119s
	@parted -s -a minimal $(USB_IMAGE) set 1 esp on
	@parted -s -a minimal $(USB_IMAGE) mkpart MANGROVE_ROOT 133120s 264191s
endif
	@dd if=$(MANGROVE_DIR)/Boot.img of=$(USB_IMAGE) bs=512 seek=2048 conv=notrunc 2>/dev/null
	@dd if=$(FLASH_ROOT_IMAGE) of=$(USB_IMAGE) bs=512 seek=133120 conv=notrunc 2>/dev/null
	@echo "Created $(USB_IMAGE)"

# Specialist compatibility names.
image: dev-image
fresh-image: fresh-dev-image
usb-image: flash-image

QEMU_EXTRA_ARGS ?=
# Keep the old escape hatch usable without emitting two -smp options.  CPU
# topology is otherwise selected through QEMU_SMP.
QEMU_SMP_ARGS = $(if $(filter -smp -smp=%,$(QEMU_EXTRA_ARGS)),,-smp $(QEMU_SMP))

QEMU_RUN_ARGS = \
	-machine q35 \
	$(QEMU_PLATFORM_ARGS) \
	$(QEMU_SMP_ARGS) \
	-m 512M \
	-rtc base=utc,clock=vm \
	-drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
	-drive if=pflash,format=raw,file=$(OVMF_VARS) \
	-drive id=usb,file=$(DEV_IMAGE),format=raw,if=none \
	-netdev user,id=net0 \
	-device e1000,netdev=net0,mac=52:54:00:18:01:01 \
	-device qemu-xhci,id=xhci \
	-device usb-storage,id=boot-storage,bus=xhci.0,port=2,drive=usb,bootindex=1 \
	-device usb-kbd,id=boot-kbd,bus=xhci.0,port=1 \
	$(QEMU_EXTRA_ARGS)

run: check-qemu-deps qemu-warning dev-image
	$(QEMU) $(QEMU_RUN_ARGS)

run-usb: run

fresh-run: check-qemu-deps qemu-warning fresh-dev-image
	$(QEMU) $(QEMU_RUN_ARGS)

clean:
	@mkdir -p $(STATE_DIR)
	@if [ ! -f "$(DEV_IMAGE)" ] && [ ! -f "$(DEV_ROOT_IMAGE)" ] && [ -f "$(LEGACY_DEV_IMAGE)" ]; then \
		echo "[CLEAN] Preserving legacy MGFS state as $(DEV_ROOT_IMAGE)"; \
		cp "$(LEGACY_DEV_IMAGE)" "$(DEV_ROOT_IMAGE)"; \
	fi
	rm -rf $(BUILD_DIR)
	@echo "[CLEAN] Removed $(BUILD_DIR); preserved $(STATE_DIR)/"

# OVMF Variable
$(OVMF_VARS):
	@mkdir -p $(dir $@)
	cp $(OVMF_VARS_SOURCE) $@

# Bootloader Link
$(EFI): $(BOOT_OBJS)
	@mkdir -p $(dir $@)
	$(BOOT_LD) $(BOOT_LDFLAGS) -o $@ $^

# Kernel Link
$(PITH): $(ALL_KERNEL_OBJS) kernel/linker.ld
	@mkdir -p $(dir $@)
	$(LD_KERNEL) $(KERNEL_LDFLAGS) -o $@ $(ALL_KERNEL_OBJS)

$(MKMGFS): tools/mkmgfs.c
	@mkdir -p $(dir $@)
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -O2 $< -o $@

SHOOT_C_SRCS := userspace/shoot/main.c \
                userspace/shoot/shell.c \
                userspace/shoot/builtin.c \
                userspace/shoot/config.c \
                userspace/shoot/history.c \
                userspace/shoot/completion.c \
                userspace/shoot/help.c \
                userspace/shoot/commands/exit.c \
                userspace/shoot/commands/help.c \
                userspace/shoot/commands/cd.c \
                userspace/shoot/commands/reload.c \
                userspace/shoot/commands/history.c

SHOOT_OBJS := $(patsubst userspace/shoot/%.c,$(SHOOT_DIR)/%.o,$(SHOOT_C_SRCS))

USER_C_OBJS := $(SPROUT_DIR)/sprout.o \
               $(SPROUT_CMD_DIR)/sprout.o \
               $(SESSIOND_DIR)/sessiond.o \
               $(LOGIND_DIR)/main.o \
               $(LOGD_DIR)/main.o \
               $(NETWORKD_DIR)/networkd.o \
               $(DEVICED_DIR)/main.o \
               $(VOLUMED_DIR)/main.o \
               $(MOUNT_DIR)/main.o \
               $(UNMOUNT_DIR)/main.o \
               $(EJECT_DIR)/main.o \
               $(BUILD_DIR)/userspace/volume_client.o \
               $(LSPCI_DIR)/main.o \
               $(LSUSB_DIR)/main.o \
               $(BUILD_DIR)/userspace/device_query.o \
               $(BUILD_DIR)/userspace/hardware_ids.o \
               $(LSDISK_DIR)/main.o \
               $(BUILD_DIR)/userspace/network_client.o \
               $(DISKUTIL_DIR)/main.o \
               $(STORAGE_SNAPSHOT_OBJ) \
               $(CREW_DIR)/main.o \
               $(INFO_DIR)/main.o \
               $(MEM_DIR)/main.o \
               $(TIME_DIR)/main.o \
               $(TMON_DIR)/main.o \
               $(LOGV_DIR)/main.o \
               $(CLEAR_DIR)/clear.o \
               $(CP_DIR)/main.o \
               $(LS_DIR)/main.o \
               $(LOCATE_DIR)/locate.o \
               $(MV_DIR)/main.o \
               $(MKDIR_DIR)/main.o \
               $(PLANT_DIR)/plant.o \
               $(TYPE_DIR)/type.o \
               $(RM_DIR)/main.o \
               $(RMDIR_DIR)/main.o \
               $(SAY_DIR)/say.o \
               $(SHUTDOWN_DIR)/shutdown.o \
               $(REBOOT_DIR)/reboot.o \
               $(UPTIME_DIR)/uptime.o \
               $(DATE_DIR)/date.o \
               $(VERSION_DIR)/version.o \
               $(WHERE_DIR)/where.o \
               $(PING_DIR)/main.o \
               $(PING_DIR)/ping_args.o \
               $(RESOLVE_DIR)/main.o \
               $(FETCH_DIR)/main.o \
               $(FETCH_DIR)/fetch_url.o \
               $(NETINFO_DIR)/main.o \
               $(NETCFG_DIR)/main.o \
               $(POWER_DIR)/power.o \
               $(IDENTITY_DIR)/identity.o \
               $(USER_CMD_DIR)/user.o \
               $(USER_LIBC_DIR)/syscall_c.o \
               $(USER_LIBC_DIR)/string.o \
               $(USER_LIBC_DIR)/allocator.o \
               $(USER_LIBC_DIR)/stdio.o \
               $(USER_LIBC_DIR)/native.o \
               $(USER_LIBC_DIR)/line_editor.o \
               $(USER_LIBC_DIR)/net.o \
               $(USER_LIBC_DIR)/time.o \
               $(USER_LIBC_DIR)/time_convert.o \
               $(COMMAND_PATH_OBJ) \
               $(HELP_OBJ) \
               $(BUILD_DIR)/userspace/secret_input.o \
               $(SHOOT_OBJS)
USER_DEPS := $(USER_C_OBJS:.o=.d)

$(SPROUT_DIR)/sprout.o: userspace/sprout/main.c \
                              libc/include/mg/service.h \
                              $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/sprout -c $< -o $@

$(SPROUT_CMD_DIR)/sprout.o: userspace/sproutctl/main.c \
                             libc/include/mg/service.h \
                             userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/sproutctl -Iuserspace/common -c $< -o $@

$(BUILD_DIR)/userspace/secret_input.o: userspace/common/secret_input.c \
                                      userspace/common/secret_input.h \
                                      $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(HELP_OBJ): userspace/common/help.c userspace/common/help.h \
             libc/include/mg/filesystem.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(SPROUT): $(SPROUT_DIR)/sprout.o $(USER_CRT) $(USER_LIBC) \
           $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(SPROUT_DIR)/sprout.o \
		$(USER_LIBC)

$(SPROUT_CMD): $(SPROUT_CMD_DIR)/sprout.o $(HELP_OBJ) $(USER_CRT) \
               $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(SPROUT_CMD_DIR)/sprout.o $(HELP_OBJ) $(USER_LIBC)

$(SESSIOND_DIR)/sessiond.o: userspace/sessiond/main.c \
                                  libc/include/mg/session.h \
                                  libc/include/mg/session_service.h \
                                  include/mangrove_version.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/sessiond -Iuserspace/common -c $< -o $@

$(SESSIOND): $(SESSIOND_DIR)/sessiond.o $(USER_CRT) $(USER_LIBC) \
            $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(SESSIOND_DIR)/sessiond.o \
		$(USER_LIBC)

$(LOGIND_DIR)/main.o: userspace/logind/main.c \
                      userspace/common/secret_input.h \
                      libc/include/mg/pass.h \
                      libc/include/mg/session.h \
                      libc/include/mg/session_service.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/logind -Iuserspace/common -c $< -o $@

$(LOGIND): $(LOGIND_DIR)/main.o $(BUILD_DIR)/userspace/secret_input.o \
           $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(LOGIND_DIR)/main.o \
		$(BUILD_DIR)/userspace/secret_input.o $(USER_LIBC)

$(NETWORKD_DIR)/networkd.o: userspace/networkd/main.c \
                           libc/include/mg/network_service.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/networkd -c $< -o $@

$(NETWORKD): $(NETWORKD_DIR)/networkd.o $(USER_CRT) $(USER_LIBC) \
            $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(NETWORKD_DIR)/networkd.o $(USER_LIBC)

$(DEVICED_DIR)/main.o: userspace/deviced/main.c \
                       libc/include/mg/device_service.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/deviced -c $< -o $@

$(DEVICED): $(DEVICED_DIR)/main.o $(USER_CRT) $(USER_LIBC) \
            $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(DEVICED_DIR)/main.o $(USER_LIBC)

$(VOLUMED_DIR)/main.o: userspace/volumed/main.c \
                       libc/include/mg/device_service.h \
                       libc/include/mg/volume_service.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/volumed -c $< -o $@

$(VOLUMED): $(VOLUMED_DIR)/main.o $(USER_CRT) $(USER_LIBC) \
            $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(VOLUMED_DIR)/main.o $(USER_LIBC)

$(BUILD_DIR)/userspace/volume_client.o: userspace/common/volume_client.c \
                                       userspace/common/volume_client.h \
                                       libc/include/mg/volume_service.h \
                                       $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(MOUNT_DIR)/main.o: userspace/mount/main.c userspace/common/help.h \
                     userspace/common/volume_client.h \
                     libc/include/mg/volume_service.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/mount -Iuserspace/common -c $< -o $@

$(MOUNT): $(MOUNT_DIR)/main.o $(BUILD_DIR)/userspace/volume_client.o \
          $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(MOUNT_DIR)/main.o \
		$(BUILD_DIR)/userspace/volume_client.o $(HELP_OBJ) $(USER_LIBC)

$(UNMOUNT_DIR)/main.o: userspace/unmount/main.c userspace/common/help.h \
                       userspace/common/volume_client.h \
                       libc/include/mg/volume_service.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/unmount -Iuserspace/common -c $< -o $@

$(UNMOUNT): $(UNMOUNT_DIR)/main.o $(BUILD_DIR)/userspace/volume_client.o \
            $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(UNMOUNT_DIR)/main.o \
		$(BUILD_DIR)/userspace/volume_client.o $(HELP_OBJ) $(USER_LIBC)

$(EJECT_DIR)/main.o: userspace/eject/main.c userspace/common/help.h \
                     userspace/common/volume_client.h \
                     libc/include/mg/volume_service.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/eject -Iuserspace/common -c $< -o $@

$(EJECT): $(EJECT_DIR)/main.o $(BUILD_DIR)/userspace/volume_client.o \
          $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(EJECT_DIR)/main.o \
		$(BUILD_DIR)/userspace/volume_client.o $(HELP_OBJ) $(USER_LIBC)

$(BUILD_DIR)/userspace/device_query.o: userspace/common/device_query.c \
                                       userspace/common/device_query.h \
                                       libc/include/mg/device_service.h \
                                       $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(STORAGE_SNAPSHOT_OBJ): userspace/common/storage_snapshot.c \
                         userspace/common/storage_snapshot.h \
                         libc/include/mg/device_service.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(BUILD_DIR)/userspace/hardware_ids.o: userspace/common/hardware_ids.c \
                                      userspace/common/hardware_ids.h \
                                      libc/include/mg/device_service.h \
                                      libc/include/mg/object.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(LSPCI_DIR)/main.o: userspace/lspci/main.c \
                     userspace/common/device_query.h \
                     userspace/common/hardware_ids.h \
                     userspace/common/help.h userspace/common/table.h \
                     libc/include/mg/device_service.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/lspci -Iuserspace/common -c $< -o $@

$(LSPCI): $(LSPCI_DIR)/main.o $(BUILD_DIR)/userspace/device_query.o \
          $(BUILD_DIR)/userspace/hardware_ids.o $(HELP_OBJ) $(USER_CRT) \
          $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(LSPCI_DIR)/main.o \
		$(BUILD_DIR)/userspace/device_query.o \
		$(BUILD_DIR)/userspace/hardware_ids.o $(HELP_OBJ) $(USER_LIBC)

$(LSUSB_DIR)/main.o: userspace/lsusb/main.c \
                     userspace/common/device_query.h \
                     userspace/common/hardware_ids.h \
                     userspace/common/help.h userspace/common/table.h \
                     libc/include/mg/device_service.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/lsusb -Iuserspace/common -c $< -o $@

$(LSUSB): $(LSUSB_DIR)/main.o $(BUILD_DIR)/userspace/device_query.o \
          $(BUILD_DIR)/userspace/hardware_ids.o $(HELP_OBJ) $(USER_CRT) \
          $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(LSUSB_DIR)/main.o \
		$(BUILD_DIR)/userspace/device_query.o \
		$(BUILD_DIR)/userspace/hardware_ids.o $(HELP_OBJ) $(USER_LIBC)

$(LSDISK_DIR)/main.o: userspace/lsdsk/main.c \
                     userspace/common/help.h \
                     userspace/common/storage_snapshot.h \
                     userspace/common/table.h \
                     libc/include/mg/device_service.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/lsdsk -Iuserspace/common -c $< -o $@

$(LSDISK): $(LSDISK_DIR)/main.o $(STORAGE_SNAPSHOT_OBJ) $(HELP_OBJ) \
          $(USER_CRT) $(USER_LIBC) \
          $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(LSDISK_DIR)/main.o $(STORAGE_SNAPSHOT_OBJ) \
		$(HELP_OBJ) $(USER_LIBC)

$(BUILD_DIR)/userspace/network_client.o: userspace/common/network_client.c \
                                         userspace/common/network_client.h \
                                         userspace/common/help.h \
                                         userspace/common/table.h \
                                         libc/include/mg/network_service.h \
                                         $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(DISKUTIL_DIR)/main.o: userspace/diskutil/main.c \
                        userspace/common/help.h \
                        userspace/common/storage_snapshot.h \
                        userspace/common/table.h \
                        libc/include/mg/device_service.h \
                        libc/include/mg/line_editor.h \
                        libc/include/mg/storage.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/diskutil -Iuserspace/common -c $< -o $@

$(DISKUTIL): $(DISKUTIL_DIR)/main.o $(STORAGE_SNAPSHOT_OBJ) $(HELP_OBJ) \
            $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(DISKUTIL_DIR)/main.o $(STORAGE_SNAPSHOT_OBJ) \
		$(HELP_OBJ) $(USER_LIBC)

$(CREW_DIR)/main.o: userspace/crew/main.c userspace/common/help.h \
                    userspace/common/process_format.h \
                    userspace/common/table.h libc/include/mg/inspection.h \
                    libc/include/mg/process.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/crew -Iuserspace/common -c $< -o $@

$(CREW): $(CREW_DIR)/main.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) \
          $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(CREW_DIR)/main.o $(HELP_OBJ) $(USER_LIBC)

$(INFO_DIR)/main.o: userspace/info/main.c userspace/common/help.h \
                    include/mangrove_version.h libc/include/mg/inspection.h \
                    libc/include/mg/identity.h libc/include/mg/terminal.h \
                    $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/info -Iuserspace/common -c $< -o $@

$(INFO): $(INFO_DIR)/main.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) \
         $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(INFO_DIR)/main.o $(HELP_OBJ) $(USER_LIBC)

$(MEM_DIR)/main.o: userspace/mem/main.c userspace/common/help.h \
                      userspace/common/table.h \
                      libc/include/mg/inspection.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/mem -Iuserspace/common -c $< -o $@

$(MEM): $(MEM_DIR)/main.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) \
           $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(MEM_DIR)/main.o $(HELP_OBJ) $(USER_LIBC)

$(TIME_DIR)/main.o: userspace/time/main.c userspace/common/help.h \
                    userspace/common/path.h libc/include/mg/process.h \
                    libc/include/mg/time.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/time -Iuserspace/common -c $< -o $@

$(TIME): $(TIME_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_CRT) \
         $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(TIME_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) \
		$(USER_LIBC)

$(TMON_DIR)/main.o: userspace/tmon/main.c userspace/common/help.h \
                    userspace/common/process_format.h \
                    userspace/common/table.h libc/include/mg/inspection.h \
                    libc/include/mg/memory.h libc/include/mg/terminal.h \
                    libc/include/mg/time.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/tmon -Iuserspace/common -c $< -o $@

$(TMON): $(TMON_DIR)/main.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) \
         $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(TMON_DIR)/main.o $(HELP_OBJ) $(USER_LIBC)

$(LOGD_DIR)/main.o: userspace/logd/main.c libc/include/mg/log_service.h \
                    libc/include/mg/object.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/logd -c $< -o $@

$(LOGD): $(LOGD_DIR)/main.o $(USER_CRT) $(USER_LIBC) \
         $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(LOGD_DIR)/main.o $(USER_LIBC)

$(LOGV_DIR)/main.o: userspace/logv/main.c userspace/common/help.h \
                    libc/include/mg/log_service.h libc/include/mg/terminal.h \
                    $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/logv -Iuserspace/common -c $< -o $@

$(LOGV): $(LOGV_DIR)/main.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) \
         $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(LOGV_DIR)/main.o $(HELP_OBJ) $(USER_LIBC)

$(COMMAND_PATH_OBJ): userspace/common/path.c userspace/common/path.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(CLEAR_DIR)/clear.o: userspace/clear/main.c userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(CLEAR): $(CLEAR_DIR)/clear.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(CLEAR_DIR)/clear.o $(HELP_OBJ) $(USER_LIBC)

$(CP_DIR)/main.o: userspace/cp/main.c userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(CP): $(CP_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(CP_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_LIBC)

$(LS_DIR)/main.o: userspace/ls/main.c userspace/common/path.h \
                  userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(LS): $(LS_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(LS_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_LIBC)

$(LOCATE_DIR)/locate.o: userspace/locate/main.c userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(LOCATE): $(LOCATE_DIR)/locate.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(LOCATE_DIR)/locate.o $(HELP_OBJ) $(USER_LIBC)

$(MV_DIR)/main.o: userspace/mv/main.c userspace/common/path.h \
                  userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(MV): $(MV_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(MV_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_LIBC)

$(MKDIR_DIR)/main.o: userspace/mkdir/main.c userspace/common/path.h \
                     userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(MKDIR): $(MKDIR_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(MKDIR_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_LIBC)

$(PLANT_DIR)/plant.o: userspace/plant/main.c userspace/common/path.h \
                      userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(PLANT): $(PLANT_DIR)/plant.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(PLANT_DIR)/plant.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_LIBC)

$(TYPE_DIR)/type.o: userspace/type/main.c userspace/common/path.h \
                    userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(TYPE): $(TYPE_DIR)/type.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(TYPE_DIR)/type.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_LIBC)

$(RM_DIR)/main.o: userspace/rm/main.c userspace/common/path.h \
                  userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(RM): $(RM_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(RM_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_LIBC)

$(RMDIR_DIR)/main.o: userspace/rmdir/main.c userspace/common/path.h \
                     userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/common -c $< -o $@

$(RMDIR): $(RMDIR_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(RMDIR_DIR)/main.o $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_LIBC)

$(SAY_DIR)/say.o: userspace/say/main.c userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(SAY): $(SAY_DIR)/say.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(SAY_DIR)/say.o $(HELP_OBJ) $(USER_LIBC)

$(SHUTDOWN_DIR)/shutdown.o: userspace/shutdown/main.c userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(SHUTDOWN): $(SHUTDOWN_DIR)/shutdown.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(SHUTDOWN_DIR)/shutdown.o $(HELP_OBJ) $(USER_LIBC)

$(REBOOT_DIR)/reboot.o: userspace/reboot/main.c userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(REBOOT): $(REBOOT_DIR)/reboot.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(REBOOT_DIR)/reboot.o $(HELP_OBJ) $(USER_LIBC)

$(POWER_DIR)/power.o: userspace/power/main.c userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(POWER): $(POWER_DIR)/power.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(POWER_DIR)/power.o $(HELP_OBJ) $(USER_LIBC)

$(IDENTITY_DIR)/identity.o: userspace/identity/main.c userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(IDENTITY): $(IDENTITY_DIR)/identity.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(IDENTITY_DIR)/identity.o $(HELP_OBJ) $(USER_LIBC)

$(USER_CMD_DIR)/user.o: userspace/user/main.c userspace/common/help.h \
                        userspace/common/table.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(USER_CMD): $(USER_CMD_DIR)/user.o $(BUILD_DIR)/userspace/secret_input.o \
             $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(USER_CMD_DIR)/user.o \
		$(BUILD_DIR)/userspace/secret_input.o $(HELP_OBJ) $(USER_LIBC)

$(UPTIME_DIR)/uptime.o: userspace/uptime/main.c userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(UPTIME): $(UPTIME_DIR)/uptime.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(UPTIME_DIR)/uptime.o $(HELP_OBJ) $(USER_LIBC)

$(DATE_DIR)/date.o: userspace/date/main.c userspace/common/help.h \
                    libc/include/mg/time.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(DATE): $(DATE_DIR)/date.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(DATE_DIR)/date.o $(HELP_OBJ) $(USER_LIBC)

$(VERSION_DIR)/version.o: userspace/version/main.c include/mangrove_version.h userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -I. -c $< -o $@

$(VERSION): $(VERSION_DIR)/version.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(VERSION_DIR)/version.o $(HELP_OBJ) $(USER_LIBC)

$(WHERE_DIR)/where.o: userspace/where/main.c userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(WHERE): $(WHERE_DIR)/where.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(WHERE_DIR)/where.o $(HELP_OBJ) $(USER_LIBC)

$(BUILD_DIR)/Hello/hello.o: userspace/hello/main.c $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(HELLO): $(BUILD_DIR)/Hello/hello.o $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(BUILD_DIR)/Hello/hello.o $(USER_LIBC)

$(BUILD_DIR)/FsTest/fstest.o: userspace/fstest/main.c $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(FSTEST): $(BUILD_DIR)/FsTest/fstest.o $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(BUILD_DIR)/FsTest/fstest.o $(USER_LIBC)

$(NETTEST_DIR)/nettest.o: userspace/nettest/main.c $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(NETTEST): $(NETTEST_DIR)/nettest.o $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(NETTEST_DIR)/nettest.o $(USER_LIBC)

$(PING_DIR)/main.o: userspace/ping/main.c userspace/ping/ping_args.h \
                    userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/ping -c $< -o $@

$(PING_DIR)/ping_args.o: userspace/ping/ping_args.c userspace/ping/ping_args.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/ping -c $< -o $@

$(PING): $(PING_DIR)/main.o $(PING_DIR)/ping_args.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(PING_DIR)/main.o $(PING_DIR)/ping_args.o $(HELP_OBJ) $(USER_LIBC)

$(RESOLVE_DIR)/main.o: userspace/resolve/main.c userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(RESOLVE): $(RESOLVE_DIR)/main.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(RESOLVE_DIR)/main.o $(HELP_OBJ) $(USER_LIBC)

$(FETCH_DIR)/main.o: userspace/fetch/main.c userspace/fetch/fetch_url.h \
                    userspace/common/help.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/fetch -Wframe-larger-than=16384 -Werror -c $< -o $@

$(FETCH_DIR)/fetch_url.o: userspace/fetch/fetch_url.c userspace/fetch/fetch_url.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/fetch -c $< -o $@

$(FETCH): $(FETCH_DIR)/main.o $(FETCH_DIR)/fetch_url.o $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(FETCH_DIR)/main.o $(FETCH_DIR)/fetch_url.o $(HELP_OBJ) $(USER_LIBC)


$(NETINFO_DIR)/main.o: userspace/netinfo/main.c \
                       userspace/common/network_client.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/netinfo -Iuserspace/common -c $< -o $@


$(NETCFG_DIR)/main.o: userspace/netcfg/main.c \
                      userspace/common/network_client.h $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -Iuserspace/netcfg -Iuserspace/common -c $< -o $@

$(NETINFO): $(NETINFO_DIR)/main.o $(BUILD_DIR)/userspace/network_client.o \
            $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(NETINFO_DIR)/main.o \
		$(BUILD_DIR)/userspace/network_client.o $(HELP_OBJ) $(USER_LIBC)

$(NETCFG): $(NETCFG_DIR)/main.o $(BUILD_DIR)/userspace/network_client.o \
           $(HELP_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(NETCFG_DIR)/main.o \
		$(BUILD_DIR)/userspace/network_client.o $(HELP_OBJ) $(USER_LIBC)

$(USER_LIBC_DIR)/syscall.o: libc/src/mangrove_syscall.s
	@mkdir -p $(dir $@)
	$(ELF_AS) -m64 -mno-red-zone -c $< -o $@

$(USER_LIBC_DIR)/syscall_c.o: libc/src/mangrove_syscall.c libc/include/mangrove.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(USER_LIBC_DIR)/string.o: libc/src/string.c libc/include/string.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(USER_LIBC): $(USER_LIBC_DIR)/syscall.o $(USER_LIBC_DIR)/syscall_c.o $(USER_LIBC_DIR)/string.o $(USER_LIBC_DIR)/allocator.o $(USER_LIBC_DIR)/stdio.o $(USER_LIBC_DIR)/native.o $(USER_LIBC_DIR)/line_editor.o $(USER_LIBC_DIR)/net.o $(USER_LIBC_DIR)/time.o $(USER_LIBC_DIR)/time_convert.o $(USER_LIBC_DIR)/log.o
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(USER_LIBC_DIR)/allocator.o: libc/src/allocator.c libc/include/stdlib.h libc/include/mangrove.h libc/include/string.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(USER_LIBC_DIR)/stdio.o: libc/src/stdio.c libc/include/stdio.h libc/include/mangrove.h libc/include/string.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(USER_LIBC_DIR)/native.o: libc/src/native.c libc/include/mangrove.h libc/include/string.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(USER_LIBC_DIR)/line_editor.o: libc/src/line_editor.c libc/include/mg/line_editor.h libc/include/mg/object.h libc/include/mg/terminal.h libc/include/string.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(USER_LIBC_DIR)/net.o: libc/src/net.c libc/include/mg/net.h libc/include/mangrove_errors.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(USER_LIBC_DIR)/log.o: libc/src/log.c libc/include/mg/log_service.h libc/include/mangrove.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(USER_LIBC_DIR)/time.o: libc/src/time.c libc/include/mg/time.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(USER_LIBC_DIR)/time_convert.o: libc/src/time_convert.c libc/include/mg/time.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(USER_CRT): libc/crt/crt0.s
	@mkdir -p $(dir $@)
	$(ELF_AS) -m64 -mno-red-zone -c $< -o $@

$(SHOOT_DIR)/%.o: userspace/shoot/%.c $(USER_LIBC)
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(SHOOT): $(SHOOT_OBJS) $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_CRT) $(USER_LIBC) $(USER_LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD_KERNEL) -z max-page-size=0x1000 -T $(USER_LINKER_SCRIPT) -o $@ \
		$(USER_CRT) $(SHOOT_OBJS) $(HELP_OBJ) $(COMMAND_PATH_OBJ) $(USER_LIBC)

$(BUILD_DIR)/mgfsck: tools/mgfsck.c
	@mkdir -p $(dir $@)
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -Wno-parentheses -Wno-unused-parameter -O2 $< -o $@

# Bootloader Compilation
$(BUILD_DIR)/boot/%.o: boot/src/%.c
	@mkdir -p $(dir $@)
	$(BOOT_CC) $(BOOT_CFLAGS) -c $< -o $@

$(BUILD_DIR)/boot/%.o: boot/src/%.s
	@mkdir -p $(dir $@)
	$(BOOT_AS) $(BOOT_ASFLAGS) -c $< -o $@

# Kernel Compilation
$(BUILD_DIR)/kernel/time_convert.o: libc/src/time_convert.c libc/include/mg/time.h
	@mkdir -p $(dir $@)
	$(CC) $(KERNEL_CFLAGS) -c $< -o $@

$(BUILD_DIR)/kernel/%.o: kernel/src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(KERNEL_CFLAGS) -c $< -o $@

$(BUILD_DIR)/kernel/%.o: kernel/src/%.s
	@mkdir -p $(dir $@)
	$(ELF_AS) $(KERNEL_ASFLAGS) -c $< -o $@

# Upstream UNSCII conversion and font blob compilation
font: $(FONT_ASSET)

$(FONT_ASSET): $(FONT_SOURCE) $(FONT_CONVERTER)
	python3 $(FONT_CONVERTER) --source $(FONT_SOURCE) --output $@

$(BUILD_DIR)/kernel/font_blob.o: $(FONT_ASSET)
	@mkdir -p $(dir $@)
	$(OBJCOPY) -I binary -O elf64-x86-64 -B i386 $< $@

# Libc Compilation
$(BUILD_DIR)/libc/%.o: libc/src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(KERNEL_CFLAGS) -c $< -o $@

-include $(DEPS) $(USER_DEPS)
