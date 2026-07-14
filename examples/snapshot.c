/*
 * Snapshot a running VM to a directory, then restore it and carry on.
 *
 * Usage:
 *   ./snapshot capture <snapshot_dir> <rootfs_dir>
 *   ./snapshot restore <snapshot_dir> <rootfs_dir>
 *
 * "capture" boots the guest, waits for it to settle, then asks libkrun to
 * serialize it and exit. "restore" builds a VM with the *same* configuration and
 * resumes the guest from where it was captured -- it picks up mid-command, so the
 * counter it prints continues rather than starting over.
 *
 * macOS/HVF only. Currently 1 vCPU (see "Limitations" in the README).
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libkrun.h>

#define VCPUS      1
#define RAM_MIB    512

/*
 * Capture and restore must describe the same machine: krun_restore() validates
 * the fresh config against the snapshot manifest and refuses a mismatch. Build
 * both from one function to guarantee that.
 */
static int configure_vm(uint32_t ctx, const char *rootfs)
{
    int err;

    if ((err = krun_set_vm_config(ctx, VCPUS, RAM_MIB)) < 0) {
        errno = -err;
        perror("krun_set_vm_config");
        return -1;
    }

    if ((err = krun_add_virtio_console_default(ctx, STDIN_FILENO, STDOUT_FILENO,
                                               STDERR_FILENO)) < 0) {
        errno = -err;
        perror("krun_add_virtio_console_default");
        return -1;
    }

    if ((err = krun_add_virtiofs3(ctx, "/dev/root", rootfs, 0, false)) < 0) {
        errno = -err;
        perror("krun_add_virtiofs3");
        return -1;
    }

    if ((err = krun_set_workdir(ctx, "/")) < 0) {
        errno = -err;
        perror("krun_set_workdir");
        return -1;
    }

    /* Print a counter forever, so a restored guest visibly resumes mid-count. */
    const char *argv[] = { "-c", "i=0; while :; do echo tick $i; i=$((i+1)); sleep 1; done", NULL };
    const char *envp[] = { NULL };
    if ((err = krun_set_exec(ctx, "/bin/sh", argv, envp)) < 0) {
        errno = -err;
        perror("krun_set_exec");
        return -1;
    }

    return 0;
}

struct trigger_args {
    uint32_t ctx;
    const char *dir;
};

/*
 * Out-of-band: must run on a thread other than the one in krun_start_enter().
 * The control channel isn't registered until the event loop is up, so retry past
 * the initial -ENOENT. Snapshot at a steady state (mid-boot won't restore).
 *
 * Args are heap-allocated (not on capture()'s stack): the success path never
 * returns here, but an error path can, while this thread still runs.
 */
static void *trigger_snapshot(void *arg)
{
    struct trigger_args *args = arg;
    int err;

    sleep(5);

    while ((err = krun_snapshot_request(args->ctx, args->dir, KRUN_SNAPSHOT_EXIT)) == -ENOENT)
        usleep(100000);

    if (err < 0) {
        errno = -err;
        perror("krun_snapshot_request");
    }
    free(args);
    return NULL;
}

static int capture(const char *dir, const char *rootfs)
{
    pthread_t thread;
    int32_t ctx = krun_create_ctx();
    if (ctx < 0) {
        errno = -ctx;
        perror("krun_create_ctx");
        return -1;
    }

    if (configure_vm(ctx, rootfs) < 0)
        return -1;

    struct trigger_args *args = malloc(sizeof(*args));
    if (!args) {
        perror("malloc");
        return -1;
    }
    args->ctx = ctx;
    args->dir = dir;

    if (pthread_create(&thread, NULL, trigger_snapshot, args) != 0) {
        perror("pthread_create");
        free(args);
        return -1;
    }
    pthread_detach(thread);

    /* Blocks: the thread above triggers the snapshot, which writes the files and
     * exits the process. Does not return. */
    int err = krun_start_enter(ctx);
    errno = -err;
    perror("krun_start_enter");
    return -1;
}

static int restore(const char *dir, const char *rootfs)
{
    int32_t ctx = krun_create_ctx();
    if (ctx < 0) {
        errno = -ctx;
        perror("krun_create_ctx");
        return -1;
    }

    /* Same machine as the one we captured, with fresh host fds. */
    if (configure_vm(ctx, rootfs) < 0)
        return -1;

    /* Blocks like krun_start_enter(), but the guest resumes instead of booting. */
    int err = krun_restore(ctx, dir, 0);
    errno = -err;
    perror("krun_restore");
    return -1;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s capture|restore <snapshot_dir> <rootfs_dir>\n", argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "capture"))
        return capture(argv[2], argv[3]) < 0 ? 1 : 0;
    if (!strcmp(argv[1], "restore"))
        return restore(argv[2], argv[3]) < 0 ? 1 : 0;

    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 1;
}
