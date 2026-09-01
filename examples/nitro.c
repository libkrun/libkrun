/*
 * This is an example implementing running an example AWS nitro enclave with
 * libkrun.
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libkrun.h>
#include <linux/vm_sockets.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#define MAX_ARGS_LEN 4096
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

#define VMADDR_CID_HYPERVISOR 0
#define CID_TO_CONSOLE_PORT_OFFSET 10000

#define BUFSIZE 512

static void print_help(char *const name)
{
    fprintf(
        stderr,
        "Usage: %s ENCLAVE_IMAGE NEWROOT NVCPUS RAM_MIB\n"
        "OPTIONS: \n"
        "        -h    --help                Show help\n"
        "              --net                 Enable networking with passt"
        "              --debug               Show kernel and initramfs debug "
        "output"
        "\n"
        "NEWROOT:           The root directory of the VM\n"
        "NVCPUS:            The amount of vCPUs for running the enclave\n"
        "RAM_MIB:           The amount of RAM (MiB) allocated for enclave\n",
        name);
}

static const struct option long_options[] = {{"help", no_argument, NULL, 'h'},
                                             {"net", no_argument, NULL, 'n'},
                                             {"debug", no_argument, NULL, 'd'},
                                             {NULL, 0, NULL, 0}};

struct cmdline {
    bool show_help;
    const char *new_root;
    unsigned int nvcpus;
    unsigned int ram_mib;
    bool net;
    bool debug;
};

bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    int c, option_index = 0;

    assert(cmdline != NULL);

    // set the defaults
    *cmdline = (struct cmdline){
        .show_help = false,
        .net = false,
        .debug = false,
    };

    // the '+' in optstring is a GNU extension that disables permutating argv
    while ((c = getopt_long(argc, argv, "+h", long_options, &option_index)) !=
           -1) {
        switch (c) {
        case 'h':
            cmdline->show_help = true;
            return true;
        case 'n':
            cmdline->net = true;
            break;
        case 'd':
            cmdline->debug = true;
            break;
        case '?':
            return false;
        default:
            fprintf(stderr,
                    "internal argument parsing error (returned character code "
                    "0x%x)\n",
                    c);
            return false;
        }
    }

    if (optind < argc - 2) {
        cmdline->new_root = argv[optind];
        cmdline->nvcpus = strtoul(argv[optind + 1], NULL, 10);
        cmdline->ram_mib = strtoul(argv[optind + 2], NULL, 10);
        return true;
    }

    if (optind >= argc - 2)
        fprintf(stderr, "Missing RAM_MIB argument\n");
    if (optind >= argc - 1)
        fprintf(stderr, "Missing VCPUS argument\n");
    if (optind == argc)
        fprintf(stderr, "Missing NEWROOT argument\n");

    return false;
}

const char *const default_argv[] = {"cat", "/etc/os-release", NULL};

#define DEFAULT_PATH_ENV "PATH=/sbin:/usr/sbin:/bin:/usr/bin"
const char *const default_envp[] = {
    DEFAULT_PATH_ENV,
    NULL,
};

int start_passt()
{
    int socket_fds[2];
    const int PARENT = 0;
    const int CHILD = 1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds) < 0) {
        perror("Failed to create passt socket fd");
        return -1;
    }

    int pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) { // child
        if (close(socket_fds[PARENT]) < 0) {
            perror("close PARENT");
        }

        char fd_as_str[16];
        snprintf(fd_as_str, sizeof(fd_as_str), "%d", socket_fds[CHILD]);

        printf("passing fd %s to passt", fd_as_str);

        if (execlp("passt", "passt", "-t", "all", "-f", "--fd", fd_as_str,
                   NULL) < 0) {
            perror("execlp");
            return -1;
        }

    } else { // parent
        if (close(socket_fds[CHILD]) < 0) {
            perror("close CHILD");
        }

        return socket_fds[PARENT];
    }
}

int main(int argc, char *const argv[])
{
    int ret, cid, ctx_id, err, passt_fd, log_level;
    struct cmdline cmdline;

    if (!parse_cmdline(argc, argv, &cmdline)) {
        putchar('\n');
        print_help(argv[0]);
        return -1;
    }

    if (cmdline.show_help) {
        print_help(argv[0]);
        return 0;
    }

    // Enable debug output if configured.
    log_level = (cmdline.debug) ? KRUN_LOG_LEVEL_DEBUG : KRUN_LOG_LEVEL_OFF;
    err = krun_init_log(KRUN_LOG_TARGET_DEFAULT, log_level, KRUN_LOG_STYLE_AUTO, 0);
    if (err) {
        errno = -err;
        perror("Error configuring log level");
        return -1;
    }

    // Create the configuration context.
    ctx_id = krun_create_ctx();
    if (ctx_id < 0) {
        errno = -ctx_id;
        perror("Error creating configuration context");
        return -1;
    }

    // Configure the number of vCPUs and amount of RAM.
    if (err = krun_set_vm_config(ctx_id, cmdline.nvcpus, cmdline.ram_mib)) {
        errno = -err;
        perror(
            "Error configuring the number of vCPUs and/or the amount of RAM");
        return -1;
    }

    if (err = krun_add_virtio_console_default(ctx_id, -1, STDOUT_FILENO, -1)) {
        errno = -err;
        perror("Error configuring the console");
        return -1;
    }

    // Configure the enclave's rootfs.
    if (err = krun_add_virtiofs3(ctx_id, KRUN_FS_ROOT_TAG, cmdline.new_root, 0, false)) {
        errno = -err;
        perror("Error configuring enclave rootfs");
        return -1;
    }

    // Configure the enclave's execution environment.
    if (err = krun_set_exec(ctx_id, default_argv[0], default_argv,
                            default_envp)) {
        errno = -err;
        perror("Error configuring enclave execution path");
        return -1;
    }

    if (cmdline.net) {
        uint8_t mac[] = {0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee};

        passt_fd = start_passt();
        if (passt_fd < 0) {
            printf("unable to start passt socket pair\n");
            return -1;
        }

        if (err = krun_add_net_unixstream(ctx_id, NULL, passt_fd, &mac[0],
                                          COMPAT_NET_FEATURES, 0)) {
            errno = -err;
            perror("Error configuring net mode");
            return -1;
        }
    }

    if (err = krun_set_console_output(ctx_id, "/dev/stdout")) {
        errno = -err;
        perror("Error configuring console output path");
        return -1;
    }

    /*
     * Start and enter the microVM. In the libkrun-awsnitro flavor, a positive
     * value returned by krun_start_enter() is the enclave's CID.
     */
    cid = krun_start_enter(ctx_id);
    if (cid < 0) {
        errno = -err;
        perror("Error creating the microVM");
        return -1;
    }
}
