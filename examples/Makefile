ARCH = $(shell uname -m)
OS = $(shell uname -s)
# Link against the in-tree target/release/ by default; override by installing
# and setting LIBDIR (e.g. LIBDIR=/usr/local/lib make -C examples).
LIBDIR ?= ../target/release
LDFLAGS_x86_64_Linux = -L$(LIBDIR) -lkrun -lkrun_init
LDFLAGS_aarch64_Linux = -L$(LIBDIR) -lkrun -lkrun_init
LDFLAGS_riscv64_Linux = -L$(LIBDIR) -lkrun -lkrun_init
LDFLAGS_arm64_Darwin = -L$(LIBDIR) -L/opt/homebrew/lib -lkrun -lkrun_init
LDFLAGS_sev = -L$(LIBDIR) -lkrun-sev
LDFLAGS_tdx = -L$(LIBDIR) -lkrun-tdx
LDFLAGS_nitro = -L$(LIBDIR) -lkrun-awsnitro
CFLAGS = -O2 -g -I../include
ROOTFS_DISTRO := fedora
ROOTFS_DIR = rootfs_$(ROOTFS_DISTRO)

.PHONY: clean rootfs

# boot_efi and gui_vm/launch-tee/nitro are not yet ported to the v2 API
EXAMPLES := chroot_vm external_kernel consoles
ifeq ($(SEV),1)
    EXAMPLES := launch-tee
endif
ifeq ($(TDX),1)
    EXAMPLES := launch-tee
endif

all: $(EXAMPLES)

chroot_vm: chroot_vm.c
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS_$(ARCH)_$(OS))
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

launch-tee: launch-tee.c
ifeq ($(SEV),1)
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS_sev)
endif
ifeq ($(TDX),1)
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS_tdx)
endif

boot_efi: boot_efi.c
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS_$(ARCH)_$(OS))
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

external_kernel: external_kernel.c
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS_$(ARCH)_$(OS))
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

consoles: consoles.c
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS_$(ARCH)_$(OS))

nitro: nitro.c
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS_nitro)

# Build the rootfs to be used with chroot_vm.
rootfs:
	mkdir -p $(ROOTFS_DIR)
	podman create --name libkrun_chroot_vm $(ROOTFS_DISTRO)
	podman export libkrun_chroot_vm | tar xpf - -C $(ROOTFS_DIR)
	podman rm libkrun_chroot_vm

clean:
	rm -rf chroot_vm $(ROOTFS_DIR) launch-tee boot_efi external_kernel nitro consoles
