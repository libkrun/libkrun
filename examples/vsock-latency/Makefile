ARCH = $(shell uname -m)
OS   = $(shell uname -s)

LDFLAGS_x86_64_Linux  = -lkrun -lpthread
LDFLAGS_aarch64_Linux = -lkrun -lpthread
LDFLAGS_riscv64_Linux = -lkrun -lpthread

CFLAGS_HOST  = -O2 -g -I../../include
CFLAGS_GUEST = -O2 -static

ROOTFS_DIR = rootfs

.PHONY: all demo clean

all: host $(ROOTFS_DIR)/guest

host: host.c
	gcc -o $@ $< $(CFLAGS_HOST) $(LDFLAGS_$(ARCH)_$(OS))

# Minimal rootfs: just the statically linked guest binary. No userland
# needed — the guest binary doesn't fork/exec or open anything outside
# vsock, and libkrunfw's init doesn't require /proc, /sys, or /dev to
# exist as mountpoints in the rootfs.
$(ROOTFS_DIR)/guest: guest.c
	mkdir -p $(ROOTFS_DIR)
	gcc -o $@ $< $(CFLAGS_GUEST)

# Run the host a few times at different per-probe timeouts and print
# just the per-attempt / first-roundtrip lines from each run. Shows
# the trade-off: shorter caller-side probe timeout → shorter observed
# cold start, because attempt[1] never completes regardless.
#
# Each iteration is one cold VM boot — they can't share a VM, since
# the whole point of the measurement is cold start. Override
# DEMO_TIMEOUTS to add/remove cases, e.g. `make demo DEMO_TIMEOUTS="'' 2000"`
# to see the 5 s reaper-TTL floor explicitly.
DEMO_TIMEOUTS = '' 2000 100 10
demo: host $(ROOTFS_DIR)/guest
	@exec </dev/null && \
	for t in $(DEMO_TIMEOUTS); do \
	  rm -f /tmp/vsock-latency-*.sock; \
	  label=$${t:-unset}; \
	  printf '\n=== PROBE_TIMEOUT_MS=%s  (cold-boot, ~%s)... ===\n' \
	    "$$label" \
	    "$$( case $$t in ''|0) echo 5s ;; 2000) echo 2.5s ;; *) echo 0.5s ;; esac )"; \
	  PROBE_TIMEOUT_MS=$$t timeout 25 ./host $(ROOTFS_DIR) >/dev/null 2>/tmp/vsock-demo.err; \
	  grep -E 'attempt\[|first-roundtrip-ok' /tmp/vsock-demo.err \
	    | grep -v 'deferring proxy'; \
	done
	@rm -f /tmp/vsock-demo.err
	@printf '\n'

clean:
	rm -rf host $(ROOTFS_DIR)
	rm -f /tmp/vsock-latency-*.sock
