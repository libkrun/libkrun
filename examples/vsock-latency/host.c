/*
 * Reproducer for a multi-second one-time delay on the first
 * host-to-guest vsock connection through libkrun.
 *
 * Observed at the downstream that reported this issue: vsock cold-start
 * (mgr.Start through first agent round trip) takes ~2.4 s, while the same
 * cold-start over virtio-console takes ~0.5 s. Once the VM is warm,
 * per-connection vsock cost matches console (~10 ms).
 *
 * Lifecycle:
 *   - configure a libkrun microVM with krun_add_vsock_port2(listen=true)
 *   - the guest binary (statically linked, staged by the Makefile into
 *     the rootfs at /guest) binds AF_VSOCK:1234 and accepts connections,
 *     writing one ack byte per connection
 *   - the host program spawns a timing thread, then calls krun_start_enter
 *   - the timing thread breaks startup into three phases (see "phase:" /
 *     "warm-roundtrip[]:" lines printed to stderr)
 *
 * On affected libkrunfw/kernel combos the "first-roundtrip-ok" phase
 * shows a multi-second jump relative to the "socket-created" phase,
 * even though warm-path round trips on the same VM are sub-millisecond.
 *
 * Usage:
 *   ./host <rootfs-dir>
 *
 * The rootfs dir must contain a `guest` binary at its top level
 * (libkrun mounts the dir as the guest VM's / via virtio-fs, so the
 * binary appears as /guest inside the guest). `make` produces a
 * suitable directory at ./rootfs.
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <libkrun.h>

#define VSOCK_PORT  1234
#define WARM_ITERS  4
#define RETRY_USEC  10000   /* 10 ms */

struct timing_args {
    char sock_path[108];    /* sun_path is 108 bytes on Linux */
};

static double ms_since(struct timespec *t0)
{
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (t1.tv_sec  - t0->tv_sec)  * 1e3 +
           (t1.tv_nsec - t0->tv_nsec) / 1e6;
}

static void *timing_thread(void *arg)
{
    struct timing_args *args = arg;
    const char *sock_path = args->sock_path;

    /* t_start = thread entry, very close to when krun_start_enter began. */
    struct timespec t_start;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    /* Phase 1: wait for libkrun's UnixAcceptorProxy to bind the socket. */
    while (access(sock_path, F_OK) != 0) {
        if (errno != ENOENT) {
            perror("timing: access");
            return NULL;
        }
        usleep(RETRY_USEC);
    }
    double ms_sock_exists = ms_since(&t_start);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof addr.sun_path - 1);

    /*
     * Phase 2: retry connect+ack-read until a full round trip succeeds.
     *
     * The host's connect() returns as soon as libkrun's
     * UnixAcceptorProxy on the host accepts, well before the guest's
     * AF_VSOCK accept(). If the guest's listener isn't up yet, the vsock
     * leg gets refused and the host's read() returns 0 (EOF). Only a
     * complete round trip (connect → byte from guest) proves the
     * connection actually traversed the virtio-vsock RX path.
     */
    /*
     * Per-attempt read timeout, simulating a caller that wraps each
     * probe in a deadline (e.g. context.WithTimeout). Set via env to
     * study the effect of shorter probe deadlines on observed
     * cold-start time. 0 = no timeout (block until libkrun closes
     * the socket via the reaper TTL).
     */
    int timeout_ms = 0;
    if (getenv("PROBE_TIMEOUT_MS"))
        timeout_ms = atoi(getenv("PROBE_TIMEOUT_MS"));
    struct timeval rcvto = {
        .tv_sec  = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };

    int attempts = 0;
    for (;;) {
        attempts++;
        struct timespec ta;
        clock_gettime(CLOCK_MONOTONIC, &ta);

        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) { perror("timing: socket"); return NULL; }
        if (timeout_ms > 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof rcvto);

        int connect_ok = connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0;
        const char *outcome = "skip";
        ssize_t n = -2;
        if (connect_ok) {
            char ack;
            n = read(fd, &ack, 1);
            if (n == 1)                                            outcome = "ack";
            else if (n == 0)                                       outcome = "EOF";
            else if (errno == EAGAIN || errno == EWOULDBLOCK)      outcome = "timeout";
            else                                                   outcome = "err";
        }
        close(fd);
        fprintf(stderr, "  attempt[%d] %+7.2f ms  read=%s\n",
                attempts, ms_since(&ta), outcome);
        if (n == 1) break;
        usleep(RETRY_USEC);
    }
    double ms_first_roundtrip = ms_since(&t_start);

    fprintf(stderr,
            "phase: socket-created     +%7.2f ms\n", ms_sock_exists);
    fprintf(stderr,
            "phase: first-roundtrip-ok +%7.2f ms"
            "  (delta-from-socket=%.2f ms, attempts=%d)\n",
            ms_first_roundtrip,
            ms_first_roundtrip - ms_sock_exists,
            attempts);

    /* Phase 3: warm-path round trips for comparison. */
    for (int i = 0; i < WARM_ITERS; i++) {
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) { perror("warm: socket"); return NULL; }
        if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
            perror("warm: connect"); close(fd); return NULL;
        }
        char ack;
        if (read(fd, &ack, 1) != 1) {
            fprintf(stderr, "warm: short read on iter %d\n", i);
            close(fd);
            return NULL;
        }
        close(fd);
        fprintf(stderr, "warm-roundtrip[%d]:        %7.2f ms\n",
                i, ms_since(&t0));
    }
    fflush(stderr);

    return NULL;
}

static int check(int err, const char *what)
{
    if (err) {
        errno = -err;
        perror(what);
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <rootfs-dir>\n", argv[0]);
        return 2;
    }
    const char *rootfs = argv[1];

    struct timing_args targs;
    snprintf(targs.sock_path, sizeof targs.sock_path,
             "/tmp/vsock-latency-%d.sock", (int)getpid());
    /* Clear any stale socket from a previous crashed run. */
    unlink(targs.sock_path);

    krun_set_log_level(2 /* KRUN_LOG_LEVEL_WARN */);

    int ctx = krun_create_ctx();
    if (ctx < 0) {
        errno = -ctx;
        perror("krun_create_ctx");
        return 1;
    }

    if (check(krun_set_vm_config(ctx, 1, 1024), "krun_set_vm_config")) return 1;
    if (check(krun_set_root(ctx, rootfs), "krun_set_root")) return 1;
    if (check(krun_add_vsock_port2(ctx, VSOCK_PORT, targs.sock_path, true),
              "krun_add_vsock_port2")) return 1;

    const char *guest_argv[] = { "guest", NULL };
    const char *guest_envp[] = { NULL };
    if (check(krun_set_exec(ctx, "/guest", guest_argv, guest_envp),
              "krun_set_exec")) return 1;

    pthread_t tid;
    if (pthread_create(&tid, NULL, timing_thread, &targs) != 0) {
        perror("pthread_create");
        return 1;
    }
    pthread_detach(tid);

    fprintf(stderr, "vsock-latency: rootfs=%s sock=%s\n",
            rootfs, targs.sock_path);

    /*
     * krun_start_enter never returns: it exits the process when the
     * guest exits. The unix socket and any leftover state are cleaned
     * up by `make clean`.
     */
    if (check(krun_start_enter(ctx), "krun_start_enter")) return 1;
    return 0;
}
