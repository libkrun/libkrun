LIBRARY_HEADER = include/libkrun.h
LIBRARY_HEADER_DISPLAY = include/libkrun_display.h
LIBRARY_HEADER_INPUT = include/libkrun_input.h

ABI_VERSION=1
FULL_VERSION=1.18.0

AWS_NITRO_INIT_SRC = \
		init/aws-nitro/include/*        	  	\
        init/aws-nitro/main.c				\
        init/aws-nitro/archive.c				\
        init/aws-nitro/args_reader.c			\
        init/aws-nitro/fs.c				\
        init/aws-nitro/mod.c					\
		init/aws-nitro/device/include/*			\
		init/aws-nitro/device/app_stdio_output.c	\
		init/aws-nitro/device/device.c              \
		init/aws-nitro/device/net_tap_afvsock.c	\
		init/aws-nitro/device/signal.c		\

AWS_NITRO_INIT_LD_FLAGS = -larchive -lnsm

ifeq ($(SEV),1)
    VARIANT = -sev
    FEATURE_FLAGS := --features amd-sev
endif
ifeq ($(TDX),1)
    VARIANT = -tdx
    FEATURE_FLAGS := --features tdx
endif
ifeq ($(VIRGL_RESOURCE_MAP2),1)
	FEATURE_FLAGS += --features virgl_resource_map2
endif
# Test targets require the block device (BLK) feature for FreeBSD disk tests
# and the NET feature for gvproxy-based network tests.
# Enable automatically unless the user explicitly set them to a value.
ifeq ($(BLK),)
    ifneq ($(filter test test-prefix,$(MAKECMDGOALS)),)
        BLK := 1
    endif
endif
ifeq ($(NET),)
    ifneq ($(filter test test-prefix,$(MAKECMDGOALS)),)
        NET := 1
    endif
endif
ifeq ($(INIT_BLOB),0)
    FEATURE_FLAGS += --no-default-features
endif
ifeq ($(BLK),1)
    FEATURE_FLAGS += --features blk
endif
ifeq ($(NET),1)
    FEATURE_FLAGS += --features net
endif
ifeq ($(GPU),1)
    FEATURE_FLAGS += --features gpu
endif
ifeq ($(INPUT),1)
    FEATURE_FLAGS += --features input
endif
ifeq ($(VHOST_USER),1)
    FEATURE_FLAGS += --features vhost-user
endif
ifeq ($(TIMESYNC),1)
    FEATURE_FLAGS += --features timesync
endif
ifeq ($(AWS_NITRO),1)
	VARIANT = -awsnitro
	FEATURE_FLAGS := --features aws-nitro,net
endif

CLANG = /usr/bin/clang

OS = $(shell uname -s)
ARCH = $(shell uname -m)
DEBIAN_DIST ?= bookworm
ROOTFS_DIR = linux-sysroot
GCC_VERSION ?= 12
FREEBSD_VERSION ?= 14.3-RELEASE
FREEBSD_ROOTFS_DIR = freebsd-sysroot

KRUN_BINARY_Linux = libkrun$(VARIANT).so.$(FULL_VERSION)
KRUN_SONAME_Linux = libkrun$(VARIANT).so.$(ABI_VERSION)
KRUN_BASE_Linux = libkrun$(VARIANT).so

KRUN_BINARY_Darwin = libkrun$(VARIANT).$(FULL_VERSION).dylib
KRUN_SONAME_Darwin = libkrun$(VARIANT).$(ABI_VERSION).dylib
KRUN_BASE_Darwin = libkrun$(VARIANT).dylib

LIBRARY_RELEASE_Linux = target/release/$(KRUN_BINARY_Linux)
LIBRARY_DEBUG_Linux = target/debug/$(KRUN_BINARY_Linux)
LIBRARY_RELEASE_Darwin = target/release/$(KRUN_BINARY_Darwin)
LIBRARY_DEBUG_Darwin = target/debug/$(KRUN_BINARY_Darwin)

LIBDIR_Linux = $(shell if [ -e /etc/debian_version ]; then echo 'lib/$(ARCH)-linux-gnu'; else echo lib64; fi)
LIBDIR_Darwin = lib

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

.PHONY: install clean test test-prefix $(LIBRARY_RELEASE_$(OS)) $(LIBRARY_DEBUG_$(OS)) libkrun.pc clean-sysroot clean-all

all: $(LIBRARY_RELEASE_$(OS)) libkrun.pc

debug: $(LIBRARY_DEBUG_$(OS)) libkrun.pc

ifeq ($(OS),Darwin)
# If SYSROOT_LINUX is not set and we're on macOS, generate sysroot automatically
ifeq ($(SYSROOT_LINUX),)
    SYSROOT_LINUX = $(ROOTFS_DIR)
    SYSROOT_TARGET = $(ROOTFS_DIR)/.sysroot_ready
else
    SYSROOT_TARGET =
endif
    # The GCC runtime dir (e.g. usr/lib/gcc/aarch64-linux-gnu/12) holds crtbeginT.o,
    # crtend.o, libgcc.a and libgcc_eh.a. Apple clang does not search it
    # automatically, so we pass it via -B (startup files) and -L (libraries).
    GCC_TRIPLET = $(subst arm64,aarch64,$(ARCH))-linux-gnu
    GCC_LIB_DIR = $(abspath $(SYSROOT_LINUX))/usr/lib/gcc/$(GCC_TRIPLET)/$(GCC_VERSION)
    # Cross-compile on macOS with the LLVM linker (brew install lld)
    CC_LINUX=$(CLANG) -target $(GCC_TRIPLET) -fuse-ld=lld -Wl,-strip-debug --sysroot $(abspath $(SYSROOT_LINUX)) -B$(GCC_LIB_DIR) -L$(GCC_LIB_DIR) -Wno-c23-extensions
else
    # Build on Linux host
    CC_LINUX=$(CC)
    SYSROOT_TARGET =
endif

# Make the variable available to Rust build scripts.
export CC_LINUX

AWS_NITRO_INIT_BINARY= init/aws-nitro/init
$(AWS_NITRO_INIT_BINARY): $(AWS_NITRO_INIT_SRC)
	$(CC) -O2 -static -s -Wall $(AWS_NITRO_INIT_LD_FLAGS) -o $@ $(AWS_NITRO_INIT_SRC) $(AWS_NITRO_INIT_LD_FLAGS)

ifeq ($(OS),Darwin)
# macOS -> FreeBSD cross-compilation
ifeq ($(SYSROOT_BSD),)
    SYSROOT_BSD = $(FREEBSD_ROOTFS_DIR)
    SYSROOT_BSD_TARGET = $(FREEBSD_ROOTFS_DIR)/.sysroot_ready
else
    SYSROOT_BSD_TARGET =
endif
    # Cross-compile on macOS with the LLVM linker (brew install lld)
    CC_BSD=$(CLANG) -target $(ARCH)-unknown-freebsd -fuse-ld=lld -stdlib=libc++ -Wl,-strip-debug --sysroot $(SYSROOT_BSD)
    CARGO_BSD_RUSTFLAGS = -C linker=$(CLANG) -C link-arg=-target -C link-arg=$(ARCH)-unknown-freebsd -C link-arg=-fuse-ld=lld -C link-arg=-stdlib=libc++ -C link-arg=--sysroot=$(abspath $(SYSROOT_BSD)) -C target-feature=+crt-static
else ifeq ($(OS),Linux)
# Linux -> FreeBSD cross-compilation
ifeq ($(SYSROOT_BSD),)
    SYSROOT_BSD = $(FREEBSD_ROOTFS_DIR)
    SYSROOT_BSD_TARGET = $(FREEBSD_ROOTFS_DIR)/.sysroot_ready
else
    SYSROOT_BSD_TARGET =
endif
    # Cross-compile on Linux with clang
    CC_BSD=$(CLANG) -target $(ARCH)-unknown-freebsd -fuse-ld=lld -Wl,-strip-debug --sysroot $(SYSROOT_BSD)
    CARGO_BSD_RUSTFLAGS = -C linker=$(CLANG) -C link-arg=-target -C link-arg=$(ARCH)-unknown-freebsd -C link-arg=-fuse-ld=lld -C link-arg=--sysroot=$(abspath $(SYSROOT_BSD)) -C target-feature=+crt-static
else
    # Build on FreeBSD host
    CC_BSD=$(CC)
    SYSROOT_BSD_TARGET =
    CARGO_BSD_RUSTFLAGS = -C target-feature=+crt-static
endif

FREEBSD_RUST_TARGET = $(subst arm64,aarch64,$(ARCH))-unknown-freebsd

# aarch64-unknown-freebsd is Tier 3: no prebuilt std, requires nightly + build-std.
ifeq ($(FREEBSD_RUST_TARGET),aarch64-unknown-freebsd)
    CARGO_BSD_TOOLCHAIN = +nightly
    CARGO_BSD_EXTRA_FLAGS = -Z build-std
else
    CARGO_BSD_TOOLCHAIN =
    CARGO_BSD_EXTRA_FLAGS =
endif

ifeq ($(BUILD_BSD_INIT),1)
INIT_BINARY_BSD = init/init-freebsd
$(INIT_BINARY_BSD): $(shell find init/src -name '*.rs') init/Cargo.toml $(SYSROOT_BSD_TARGET)
	RUSTFLAGS="$(CARGO_BSD_RUSTFLAGS)" \
	cargo $(CARGO_BSD_TOOLCHAIN) build --release \
		$(CARGO_BSD_EXTRA_FLAGS) \
		--manifest-path init/Cargo.toml \
		--target $(FREEBSD_RUST_TARGET)
	cp target/$(FREEBSD_RUST_TARGET)/release/krun-init $@
endif

# Sysroot preparation rules for cross-compilation on macOS
DEBIAN_PACKAGES = libc6 libc6-dev libgcc-$(GCC_VERSION)-dev linux-libc-dev
ROOTFS_TMP = $(ROOTFS_DIR)/.tmp
PACKAGES_FILE = $(ROOTFS_TMP)/Packages.xz

.INTERMEDIATE: $(PACKAGES_FILE)

$(ROOTFS_DIR)/.sysroot_ready: $(PACKAGES_FILE)
	@echo "Extracting Debian packages to $(ROOTFS_DIR)..."
	@for pkg in $(DEBIAN_PACKAGES); do \
		DEB_PATH=$$(xzcat $(PACKAGES_FILE) | sed '1,/Package: '$$pkg'$$/d' | grep Filename: | sed 's/^Filename: //' | head -n1); \
		DEB_URL="https://deb.debian.org/debian/$$DEB_PATH"; \
		DEB_NAME=$$(basename "$$DEB_PATH"); \
		if [ ! -f "$(ROOTFS_TMP)/$$DEB_NAME" ]; then \
			echo "Downloading $$DEB_URL"; \
			curl -fL -o "$(ROOTFS_TMP)/$$DEB_NAME" "$$DEB_URL"; \
		fi; \
		cd $(ROOTFS_TMP) && ar x "$$DEB_NAME" && cd ../..; \
		tar xf $(ROOTFS_TMP)/data.tar.* -C $(ROOTFS_DIR); \
		rm -f $(ROOTFS_TMP)/*.deb $(ROOTFS_TMP)/data.tar.* $(ROOTFS_TMP)/control.tar.* $(ROOTFS_TMP)/debian-binary; \
	done
	@touch $@

$(PACKAGES_FILE):
	@echo "Downloading Debian package index for $(DEBIAN_DIST)/$(ARCH)..."
	@mkdir -p $(ROOTFS_TMP)
	@curl -fL -o $@ https://deb.debian.org/debian/dists/$(DEBIAN_DIST)/main/binary-$(ARCH)/Packages.xz

# FreeBSD sysroot preparation rules for cross-compilation on macOS
FREEBSD_BASE_TXZ = $(FREEBSD_ROOTFS_DIR)/base.txz

.INTERMEDIATE: $(FREEBSD_BASE_TXZ)

$(FREEBSD_ROOTFS_DIR)/.sysroot_ready: $(FREEBSD_BASE_TXZ)
	@echo "Extracting FreeBSD base to $(FREEBSD_ROOTFS_DIR)..."
	@cd $(FREEBSD_ROOTFS_DIR) && tar xJf base.txz 2>/dev/null || true
	@touch $@

BSD_ARCH=$(subst x86_64,amd64,$(subst aarch64,arm64,$(ARCH)))

$(FREEBSD_BASE_TXZ):
	@echo "Downloading FreeBSD $(FREEBSD_VERSION) base for $(BSD_ARCH)..."
	@mkdir -p $(FREEBSD_ROOTFS_DIR)
	@curl -fL -o $@ https://download.freebsd.org/releases/$(BSD_ARCH)/$(FREEBSD_VERSION)/base.txz

clean-sysroot:
	rm -rf $(ROOTFS_DIR)
	rm -rf $(FREEBSD_ROOTFS_DIR)


$(LIBRARY_RELEASE_$(OS)): $(SYSROOT_TARGET) $(INIT_BINARY_BSD)
	cargo build --release $(FEATURE_FLAGS)
ifeq ($(SEV),1)
	mv target/release/libkrun.so target/release/$(KRUN_BASE_$(OS))
endif
ifeq ($(AWS_NITRO),1)
	mv target/release/libkrun.so target/release/$(KRUN_BASE_$(OS))
endif
ifeq ($(TDX),1)
	mv target/release/libkrun.so target/release/$(KRUN_BASE_$(OS))
endif
ifeq ($(OS),Darwin)
	mv target/release/libkrun.dylib target/release/$(KRUN_BASE_$(OS))
endif
	cp target/release/$(KRUN_BASE_$(OS)) $(LIBRARY_RELEASE_$(OS))

$(LIBRARY_DEBUG_$(OS)): $(SYSROOT_TARGET) $(INIT_BINARY_BSD)
	cargo build $(FEATURE_FLAGS)
ifeq ($(SEV),1)
	mv target/debug/libkrun.so target/debug/$(KRUN_BASE_$(OS))
endif
ifeq ($(TDX),1)
	mv target/debug/libkrun.so target/debug/$(KRUN_BASE_$(OS))
endif
	cp target/debug/$(KRUN_BASE_$(OS)) $(LIBRARY_DEBUG_$(OS))

libkrun.pc: libkrun.pc.in Makefile
	rm -f $@ $@-t
	sed -e 's|@prefix@|$(PREFIX)|' \
	    -e 's|@libdir@|$(PREFIX)/$(LIBDIR_$(OS))|' \
	    -e 's|@includedir@|$(PREFIX)/include|' \
	    -e 's|@PACKAGE_NAME@|libkrun|' \
	    -e 's|@PACKAGE_VERSION@|$(FULL_VERSION)|' \
	    libkrun.pc.in > $@-t
	mv $@-t $@

install: libkrun.pc
	install -d $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/
	install -d $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/pkgconfig
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 $(LIBRARY_HEADER) $(DESTDIR)$(PREFIX)/include
	install -m 644 $(LIBRARY_HEADER_DISPLAY) $(DESTDIR)$(PREFIX)/include
	install -m 644 $(LIBRARY_HEADER_INPUT) $(DESTDIR)$(PREFIX)/include
	install -m 644 libkrun.pc $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/pkgconfig
	install -m 755 $(LIBRARY_RELEASE_$(OS)) $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/
	cd $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/ ; ln -sf $(KRUN_BINARY_$(OS)) $(KRUN_SONAME_$(OS)) ; ln -sf $(KRUN_SONAME_$(OS)) $(KRUN_BASE_$(OS))

clean:
ifeq ($(BUILD_BSD_INIT),1)
	rm -f $(INIT_BINARY_BSD)
endif
	cargo clean
	rm -rf test-prefix
	cd tests; cargo clean

clean-all: clean clean-sysroot

test-prefix/$(LIBDIR_$(OS))/libkrun.pc: $(LIBRARY_RELEASE_$(OS))
	mkdir -p test-prefix
	PREFIX="$$(realpath test-prefix)" make install

test-prefix: test-prefix/$(LIBDIR_$(OS))/libkrun.pc

TEST ?= all
TEST_FLAGS ?=

# Extra library paths needed for tests (libkrunfw, llvm)
EXTRA_LIBPATH_Linux =
EXTRA_LIBPATH_Darwin = /opt/homebrew/opt/libkrunfw/lib:/opt/homebrew/opt/llvm/lib

# On macOS, SIP strips DYLD_LIBRARY_PATH when executing scripts via a shebang,
# so we pass the path via LIBKRUN_LIB_PATH and let run.sh set the real variable.
test: test-prefix
	cd tests; RUST_LOG=trace LIBKRUN_LIB_PATH="$$(realpath ../test-prefix/$(LIBDIR_$(OS))/):$(EXTRA_LIBPATH_$(OS))" PKG_CONFIG_PATH="$$(realpath ../test-prefix/$(LIBDIR_$(OS))/pkgconfig/)" ./run.sh test --test-case "$(TEST)" $(TEST_FLAGS)
