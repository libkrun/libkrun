#!/bin/sh

# This script has to be run with the working directory being "test"
# This runs the tests on the libkrun instance found by pkg-config.
# Specify PKG_CONFIG_PATH env variable to test a non-system installation of libkurn.

set -e

OS=$(uname -s)
 # macOS uses the string "arm64" but Rust uses "aarch64"
ARCH=$(uname -m | sed 's/^arm64$/aarch64/')

# Set the OS-specific library path from LIBKRUN_LIB_PATH.
# On macOS, SIP strips DYLD_LIBRARY_PATH when executing scripts via a shebang,
# so the Makefile passes it through this alternative variable instead.
# We do the same on Linux for consistency.
if [ -n "${LIBKRUN_LIB_PATH}" ]; then
	if [ "$OS" = "Darwin" ]; then
		export DYLD_LIBRARY_PATH="${LIBKRUN_LIB_PATH}:${DYLD_LIBRARY_PATH}"
	else
		export LD_LIBRARY_PATH="${LIBKRUN_LIB_PATH}:${LD_LIBRARY_PATH}"
	fi
fi 

GUEST_TARGET="${ARCH}-unknown-linux-musl"

# Run the unit tests first (this tests the testing framework itself not libkrun).
# Guest code may use Linux-only libc calls that won't compile with other toolchains.
if [ "$OS" = "Linux" ]; then
	cargo test -p test_cases --features guest
fi

# On macOS, we need to cross-compile for Linux musl
if [ "$OS" = "Darwin" ]; then
	echo "Cross-compiling guest-agent for $GUEST_TARGET"

	# e2fsprogs is keg-only on macOS; add it to PATH for mke2fs.
	if [ -d "/opt/homebrew/opt/e2fsprogs/sbin" ]; then
		export PATH="/opt/homebrew/opt/e2fsprogs/sbin:$PATH"
	fi
fi

cargo build --target=$GUEST_TARGET -p guest-agent
cargo build -p runner

# On macOS, the runner needs entitlements to use Hypervisor.framework
if [ "$OS" = "Darwin" ]; then
	codesign --entitlements ../hvf-entitlements.plist --force -s - target/debug/runner
fi

export KRUN_TEST_GUEST_AGENT_PATH="target/$GUEST_TARGET/debug/guest-agent"

# --- FreeBSD guest support ---
FREEBSD_SYSROOT="../freebsd-sysroot"
FREEBSD_INIT="../init/init-freebsd"

RUST_NIGHTLY="nightly-2026-01-25"

# Download FreeBSD kernel if KRUN_TEST_FREEBSD_KERNEL_PATH is not already set.
# The kernel binary is cached in target/freebsd-kernel/ and reused on subsequent runs.
if [ -z "${KRUN_TEST_FREEBSD_KERNEL_PATH}" ]; then
	FREEBSD_KERNEL_DIR="target/freebsd-kernel"
	mkdir -p "${FREEBSD_KERNEL_DIR}"

	if [ "$ARCH" = "x86_64" ]; then
		# Use Firecracker-optimized FreeBSD kernel for x86_64
		FREEBSD_KERNEL_URL="https://github.com/acj/freebsd-firecracker/releases/download/v0.8.1/freebsd-kern.bin"
		FREEBSD_KERNEL_PATH="${FREEBSD_KERNEL_DIR}/freebsd-kern.bin"
	else
		# Use upstream FreeBSD kernel for aarch64
		FREEBSD_KERNEL_URL="https://download.freebsd.org/releases/arm64/aarch64/14.4-RELEASE/kernel.txz"
		FREEBSD_KERNEL_BIN="kernel.bin"
		FREEBSD_KERNEL_PATH="${FREEBSD_KERNEL_DIR}/boot/kernel/${FREEBSD_KERNEL_BIN}"
	fi

	if [ ! -f "${FREEBSD_KERNEL_PATH}" ]; then
		echo "Downloading FreeBSD kernel..."
		FREEBSD_KERNEL_TMP=$(mktemp)
		if curl -fL -o "${FREEBSD_KERNEL_TMP}" "${FREEBSD_KERNEL_URL}"; then
			if [ "$ARCH" = "x86_64" ]; then
				mv "${FREEBSD_KERNEL_TMP}" "${FREEBSD_KERNEL_PATH}"
			else
				tar xJf "${FREEBSD_KERNEL_TMP}" -C "${FREEBSD_KERNEL_DIR}" \
					"./boot/kernel/${FREEBSD_KERNEL_BIN}"
				rm -f "${FREEBSD_KERNEL_TMP}"
			fi
		else
			echo "WARNING: Failed to download FreeBSD kernel; FreeBSD tests will be skipped."
			rm -f "${FREEBSD_KERNEL_TMP}"
		fi
	fi
	if [ -f "${FREEBSD_KERNEL_PATH}" ]; then
		export KRUN_TEST_FREEBSD_KERNEL_PATH="${FREEBSD_KERNEL_PATH}"
		echo "FreeBSD kernel: ${KRUN_TEST_FREEBSD_KERNEL_PATH}"
	fi
fi

if [ -f "${FREEBSD_SYSROOT}/.sysroot_ready" ] && [ -f "${FREEBSD_INIT}" ]; then
	FREEBSD_TARGET="${ARCH}-unknown-freebsd"
	FREEBSD_SYSROOT_ABS=$(cd "${FREEBSD_SYSROOT}" && pwd)

	# Common FreeBSD linker configuration
	export CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_LINKER="clang"
	export CARGO_TARGET_AARCH64_UNKNOWN_FREEBSD_LINKER="clang"

	# Common RUSTFLAGS for FreeBSD targets
	FREEBSD_RUSTFLAGS_BASE="-C link-arg=-fuse-ld=lld -C link-arg=--sysroot=${FREEBSD_SYSROOT_ABS} -C target-feature=+crt-static"

	if [ "$ARCH" = "x86_64" ]; then
		export CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_RUSTFLAGS="-C link-arg=-target -C link-arg=x86_64-unknown-freebsd ${FREEBSD_RUSTFLAGS_BASE}"
		FREEBSD_CARGO_CMD="cargo build --target=${FREEBSD_TARGET} -p guest-agent"
	else
		# aarch64-unknown-freebsd has no prebuilt stdlib in rustup; build it from source with -Z build-std.
		FREEBSD_RUSTFLAGS="-C link-arg=-target -C link-arg=aarch64-unknown-freebsd ${FREEBSD_RUSTFLAGS_BASE}"
		[ "$OS" = "Darwin" ] && FREEBSD_RUSTFLAGS="${FREEBSD_RUSTFLAGS} -C link-arg=-stdlib=libc++"
		export CARGO_TARGET_AARCH64_UNKNOWN_FREEBSD_RUSTFLAGS="${FREEBSD_RUSTFLAGS}"
		FREEBSD_CARGO_CMD="cargo +${RUST_NIGHTLY} build -Z build-std=std,panic_abort --target=${FREEBSD_TARGET} -p guest-agent"
	fi

	echo "Cross-compiling guest-agent for ${FREEBSD_TARGET}"
	# A build failure here is a hard error: it means either the Rust target is
	# not installed (fix: see message below) or a #[guest] block contains code
	# that does not compile for FreeBSD (fix: gate it with
	# #[cfg(target_os = "linux")] and add a stub impl for non-Linux targets).
	if ! $FREEBSD_CARGO_CMD; then
		if [ "$ARCH" = "x86_64" ]; then
			echo "ERROR: guest-agent build for ${FREEBSD_TARGET} failed."
			echo "(Run: rustup target add ${FREEBSD_TARGET})"
		else
			echo "ERROR: guest-agent build for ${FREEBSD_TARGET} failed."
			echo "(Run: rustup +${RUST_NIGHTLY} component add rust-src)"
		fi
		exit 1
	fi

	# Build the FreeBSD test rootfs ISO: init-freebsd + FreeBSD guest-agent at the root.
	FREEBSD_ISO_STAGING=$(mktemp -d)
	mkdir -p "${FREEBSD_ISO_STAGING}/dev" "${FREEBSD_ISO_STAGING}/tmp" "${FREEBSD_ISO_STAGING}/mnt"
	cp "${FREEBSD_INIT}" "${FREEBSD_ISO_STAGING}/init-freebsd"
	cp "target/${FREEBSD_TARGET}/debug/guest-agent" "${FREEBSD_ISO_STAGING}/guest-agent"
	chmod +x "${FREEBSD_ISO_STAGING}/init-freebsd" "${FREEBSD_ISO_STAGING}/guest-agent"
	FREEBSD_ISO_PATH="target/freebsd-test-rootfs.iso"
	bsdtar cf "${FREEBSD_ISO_PATH}" --format=iso9660 -C "${FREEBSD_ISO_STAGING}" .
	rm -rf "${FREEBSD_ISO_STAGING}"
	echo "FreeBSD test rootfs ISO: ${FREEBSD_ISO_PATH}"
	export KRUN_TEST_FREEBSD_ISO_PATH="${FREEBSD_ISO_PATH}"
else
	echo "FreeBSD sysroot or init/init-freebsd not found; FreeBSD tests will be skipped."
	echo "(Run 'make' with BUILD_BSD_INIT=1 in the libkrun root to build FreeBSD assets.)"
fi

# Build runner args: pass through all arguments
RUNNER_ARGS="$*"

# Add --base-dir if KRUN_TEST_BASE_DIR is set
if [ -n "${KRUN_TEST_BASE_DIR}" ]; then
	RUNNER_ARGS="${RUNNER_ARGS} --base-dir ${KRUN_TEST_BASE_DIR}"
fi

# Resolve gvproxy path: prefer explicit env var, then cached binary in
# target/, then PATH; finally fall back to downloading a cached copy.
GV_DIR="target"
GV_FILE="${GV_DIR}/gvproxy"
mkdir -p "${GV_DIR}"

if [ -z "${KRUN_TEST_GVPROXY_PATH}" ]; then
	# 1) cached copy in target/
	if [ -x "${GV_FILE}" ]; then
		export KRUN_TEST_GVPROXY_PATH=$(realpath "${GV_FILE}")
		echo "gvproxy (cached): ${KRUN_TEST_GVPROXY_PATH}"
	else
		# 2) search PATH
		if [ "$OS" = "Darwin" ]; then
			GV_NAMES="gvproxy gvproxy-darwin"
		else
			GV_NAMES="gvproxy gvproxy-linux-amd64 gvproxy-linux-arm64"
		fi

		for name in $GV_NAMES; do
			if which "$name" >/dev/null 2>&1; then
				GV_PATH=$(which "$name")
				if [ -x "$GV_PATH" ]; then
					export KRUN_TEST_GVPROXY_PATH="$GV_PATH"
					echo "gvproxy: ${KRUN_TEST_GVPROXY_PATH}"
					break
				fi
			fi
		done

		# 3) download into cached location if still unset
		if [ -z "${KRUN_TEST_GVPROXY_PATH}" ]; then
			GV_VERSION="0.8.9"
			GV_URL_BASE="https://github.com/containers/gvisor-tap-vsock/releases/download/v${GV_VERSION}/gvproxy"

			if [ "$OS" = "Darwin" ]; then
				GV_URL="${GV_URL_BASE}-darwin"
			else
				if [ "$ARCH" = "x86_64" ]; then
					GV_URL="${GV_URL_BASE}-linux-amd64"
				else
					GV_URL="${GV_URL_BASE}-linux-arm64"
				fi
			fi

			echo "Downloading gvproxy to ${GV_FILE}..."
			if curl -fL -o "${GV_FILE}" "${GV_URL}"; then
				chmod +x "${GV_FILE}"
				export KRUN_TEST_GVPROXY_PATH=$(realpath "${GV_FILE}")
				echo "gvproxy: ${KRUN_TEST_GVPROXY_PATH}"
			else
				echo "WARNING: Failed to download gvproxy from ${GV_URL}; network tests may fail."
				rm -f "${GV_FILE}"
			fi
		fi
	fi
fi

target/debug/runner ${RUNNER_ARGS}
