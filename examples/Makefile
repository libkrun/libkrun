ARCH = $(shell uname -m)
OS = $(shell uname -s)
ABI_VERSION = 2
KRUN_INIT_ABI_VERSION = 0
FULL_VERSION = 2.0.0
KRUN_INIT_FULL_VERSION = 0.1.0
LIBDIR_Linux = $(shell if [ -e /etc/debian_version ]; then echo 'lib/$(ARCH)-linux-gnu'; else echo lib64; fi)
LIBDIR_Darwin = lib

LIBKRUN_BUILD_DIR ?= ../target/release

ifdef LIBKRUN_LOCAL_INSTALL
LIBKRUN_LOCAL_INSTALL_ABS = $(abspath $(LIBKRUN_LOCAL_INSTALL))
LIBKRUN_INCLUDE_DIR = $(LIBKRUN_LOCAL_INSTALL_ABS)/include
LIBKRUN_LIB_DIR = $(LIBKRUN_LOCAL_INSTALL_ABS)/$(LIBDIR_$(OS))
else
LIBKRUN_INCLUDE_DIR = ../include
LIBKRUN_LIB_DIR = $(abspath $(LIBKRUN_BUILD_DIR))
endif

LIBKRUN_LDFLAGS = -L$(LIBKRUN_LIB_DIR) -Wl,-rpath,$(LIBKRUN_LIB_DIR)
LDFLAGS_x86_64_Linux = $(LIBKRUN_LDFLAGS) -lkrun -lkrun_init
LDFLAGS_aarch64_Linux = $(LIBKRUN_LDFLAGS) -lkrun -lkrun_init
LDFLAGS_riscv64_Linux = $(LIBKRUN_LDFLAGS) -lkrun -lkrun_init
LDFLAGS_arm64_Darwin = $(LIBKRUN_LDFLAGS) -lkrun -lkrun_init
CHROOT_VM_LDFLAGS_Linux = -ldl
LDFLAGS_sev = $(LIBKRUN_LDFLAGS) -lkrun-sev
LDFLAGS_tdx = $(LIBKRUN_LDFLAGS) -lkrun-tdx
LDFLAGS_nitro = $(LIBKRUN_LDFLAGS) -lkrun-awsnitro
CFLAGS ?= -O2 -g
CPPFLAGS += -I$(LIBKRUN_INCLUDE_DIR)
ROOTFS_DISTRO := fedora
ROOTFS_DIR = rootfs_$(ROOTFS_DISTRO)

KRUN_SONAME_Linux = libkrun.so.$(ABI_VERSION)
KRUN_INIT_SONAME_Linux = libkrun_init.so.$(KRUN_INIT_ABI_VERSION)

KRUN_SONAME_Darwin = libkrun.$(ABI_VERSION).dylib
KRUN_INIT_SONAME_Darwin = libkrun_init.$(KRUN_INIT_ABI_VERSION).dylib

LIBKRUN_LIBRARY_LINKS = \
	$(LIBKRUN_LIB_DIR)/$(KRUN_SONAME_$(OS)) \
	$(LIBKRUN_LIB_DIR)/$(KRUN_INIT_SONAME_$(OS))

.PHONY: clean rootfs

EXAMPLES := boot_efi chroot_vm external_kernel consoles
ifeq ($(SEV),1)
    EXAMPLES := launch-tee
endif
ifeq ($(TDX),1)
    EXAMPLES := launch-tee
endif

all: $(EXAMPLES)

chroot_vm: chroot_vm.c $(LIBKRUN_LIBRARY_LINKS)
	gcc -o $@ $< $(CPPFLAGS) $(CFLAGS) $(LDFLAGS_$(ARCH)_$(OS)) $(CHROOT_VM_LDFLAGS_$(OS))
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

launch-tee: launch-tee.c
ifeq ($(SEV),1)
	gcc -o $@ $< $(CPPFLAGS) $(CFLAGS) $(LDFLAGS_sev)
endif
ifeq ($(TDX),1)
	gcc -o $@ $< $(CPPFLAGS) $(CFLAGS) $(LDFLAGS_tdx)
endif

boot_efi: boot_efi.c $(LIBKRUN_LIBRARY_LINKS)
	gcc -o $@ $< $(CPPFLAGS) $(CFLAGS) $(LDFLAGS_$(ARCH)_$(OS))
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

external_kernel: external_kernel.c $(LIBKRUN_LIBRARY_LINKS)
	gcc -o $@ $< $(CPPFLAGS) $(CFLAGS) $(LDFLAGS_$(ARCH)_$(OS))
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

consoles: consoles.c $(LIBKRUN_LIBRARY_LINKS)
	gcc -o $@ $< $(CPPFLAGS) $(CFLAGS) $(LDFLAGS_$(ARCH)_$(OS))

nitro: nitro.c
	gcc -o $@ $< $(CPPFLAGS) $(CFLAGS) $(LDFLAGS_nitro)

# Build the rootfs to be used with chroot_vm.
rootfs:
	mkdir -p $(ROOTFS_DIR)
	podman create --name libkrun_chroot_vm $(ROOTFS_DISTRO)
	podman export libkrun_chroot_vm | tar xpf - -C $(ROOTFS_DIR)
	podman rm libkrun_chroot_vm

clean:
	rm -rf chroot_vm $(ROOTFS_DIR) launch-tee boot_efi external_kernel nitro consoles
