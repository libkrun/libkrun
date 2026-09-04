# vsock-latency

Minimal reproducer for a multi-second one-time delay on the **first
host-to-guest vsock connection** through libkrun. After the first
round trip, all subsequent connections on the same VM are sub-millisecond.

## What it measures

`host.c` configures a libkrun microVM whose PID 1 is a tiny static
binary (`guest.c`). The guest binds an AF_VSOCK listener on port 1234
and writes one ack byte to each accepted connection. The host maps
that vsock port to a host UNIX socket via
`krun_add_vsock_port2(..., listen=true)`, then a timing thread breaks
startup into phases:

1. **socket-created**: time from `krun_start_enter` until libkrun's
   `UnixAcceptorProxy` binds the host-side UNIX socket.
2. **first-roundtrip-ok**: time until the first host `connect()` plus
   `read(1 byte)` completes end-to-end — i.e. the first byte actually
   arrives through the kernel's virtio-vsock RX path.
3. **warm-roundtrip[0..3]**: four more back-to-back round trips for
   comparison.

## Build

Prereqs: libkrun installed (`pkg-config --modversion libkrun` works),
`/dev/kvm` writable, gcc with `-static` support (`glibc-static` on
Fedora, `musl-dev` on Alpine, etc.).

```
make
```

Produces `./host` and `./rootfs/guest`. The rootfs is just the
single static guest binary — no userland, no `/proc` or `/dev`
mountpoints, no container image needed.

## Run

```
./host ./rootfs
```

The argument is the directory libkrun mounts as the VM's `/` (via
virtio-fs). It must contain a top-level `guest` binary; `make`
produces that at `./rootfs/guest`.

## Expected output

On an affected libkrunfw/kernel combination (e.g. libkrunfw 5.4.0 on
host kernel 6.18, libkrunfw-bundled kernel 6.12.87):

```
vsock-latency: rootfs=./rootfs sock=/tmp/vsock-latency-12345.sock
guest: listening on vsock:1234
phase: socket-created     + 343.10 ms
phase: first-roundtrip-ok +5365.22 ms  (delta-from-socket=5012.58 ms, attempts=2)
guest: accept[0] ack
warm-roundtrip[0]:           0.22 ms
guest: accept[1] ack
warm-roundtrip[1]:           0.28 ms
guest: accept[2] ack
warm-roundtrip[2]:           0.24 ms
guest: accept[3] ack
warm-roundtrip[3]:           0.22 ms
```

The diagnostic is **`delta-from-socket`**: the time between libkrun's
unix socket being ready and the first successful end-to-end round
trip. On this kernel it is ~5 seconds; warm round trips on the same
VM are ~0.3 ms.

With per-attempt timing enabled (uncomment the inner `fprintf` in
`host.c`) the pattern is:

```
  attempt[1] +5000.83 ms  connect=ok read=EOF
  attempt[2]   +0.39 ms   connect=ok read=ack
```

The first host `connect()` succeeds at the unix layer immediately, but
the `read()` blocks for **exactly 5 seconds** before libkrun closes
the unix socket with EOF. The second attempt — on a brand-new unix
connection — succeeds in under a millisecond.

The 5 s is hardcoded in libkrun: `src/devices/src/virtio/vsock/reaper.rs`
sets `TIMEOUT = Duration::new(5, 0)` for the vsock reaper thread,
which holds proxies in `released_map` for 5 s before actually
removing them. The first vsock leg was refused (guest's AF_VSOCK
accept() not yet ready when libkrun tried to forward), libkrun queued
the proxy for `ProxyRemoval::Deferred`, and the unix socket FD stays
associated with that not-yet-reaped proxy for the full 5 s.

The corresponding `deferring proxy removal: <id>` WARN messages are
visible at libkrun log level WARN or higher in the muxer thread
(`muxer_thread.rs:100`).

### Effect of a caller-side per-probe timeout

A caller that probes for agent readiness typically wraps each attempt
in some kind of deadline — for example `context.WithTimeout(ctx, X)`
around each round trip in a polling loop. That deadline caps how
long the caller waits for the doomed first attempt before retrying.

Set `PROBE_TIMEOUT_MS` to apply `SO_RCVTIMEO` to each probe attempt
(simulates a per-probe `WithTimeout(ctx, X)`). The reproducer prints
per-attempt outcomes plus the total wall-clock to first success.

| `PROBE_TIMEOUT_MS` | first-roundtrip-ok | attempts | attempt[1] outcome |
| --- | --- | --- | --- |
| unset (block to EOF) | ~5340 ms | 2 | EOF at 5007 ms |
| `2000`               | ~2355 ms | 2 | timeout at 2022 ms |
| `100`                |  ~425 ms | 2 | timeout at 101 ms |
| `10`                 |  ~373 ms | 3 | timeout, timeout, ack |

In every case attempt 1 never completes — it either EOFs at libkrun's
5 s reaper TTL or hits the per-attempt timeout earlier. Attempt 2 is
a fresh unix connection, fresh libkrun proxy, and succeeds in <1 ms.

A caller polling with a 2 s deadline observes a ~2.4 s cold start
that is entirely the duration of *its own* probe deadline — nothing
in the libkrun + guest path benefits from waiting that long. The
same caller switched to a 100 ms deadline observes ~400 ms total
cold start (vsock), matching console cold-start.

Run it yourself:

```
PROBE_TIMEOUT_MS=2000 ./host ./rootfs    # ~2.4s cold start
PROBE_TIMEOUT_MS=100  ./host ./rootfs    # ~400ms cold start
```

Or run all four columns of the table in one shot:

```
make demo
```

## Cleanup

```
make clean
```

Removes `host`, the staged `rootfs/`, and any leftover
`/tmp/vsock-latency-*.sock` from prior runs.
