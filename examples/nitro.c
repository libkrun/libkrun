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
#include <unistd.h>

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

static bool push_to_stderr(void *userdata, KrunStr s)
{
    (void)userdata;
    fwrite(s.data, 1, s.len, stderr);
    return true;
}

static KrunVtableHandle krun_stderr_writer = KRUN_VTABLE_HANDLE(
    KRUN_PUSH_STR_TYPE_TAG,
    ((KrunPushStrVtable){ .drop = NULL, .push = push_to_stderr }),
    NULL);

#define CHECK(call)                                                            \
    krun_err = NULL;                                                           \
    call;                                                                      \
    if (krun_err) {                                                            \
        flockfile(stderr);                                                     \
        fprintf(stderr, "%s failed: ", #call);                                 \
        krun_error_message(krun_err, &krun_stderr_writer);                     \
        fputc('\n', stderr);                                                   \
        funlockfile(stderr);                                                   \
        krun_error_destroy(krun_err);                                          \
        return -1;                                                             \
    }

int main(int argc, char *const argv[])
{
    KrunError krun_err;
    int passt_fd;
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
    uint32_t log_level = (cmdline.debug) ? KRUN_LOG_LEVEL_DEBUG : KRUN_LOG_LEVEL_OFF;
    CHECK(krun_init_log(-1, log_level, KRUN_LOG_STYLE_AUTO, 0, &krun_err));

    // Build the NitroConfig with rootfs, exec path, args, env, and debug.
    KrunNitroConfig nc = krun_nitro_config_new();
    krun_nitro_config_rootfs(&nc, KRUN_STR(cmdline.new_root));
    krun_nitro_config_exec_path(&nc, KRUN_STR(default_argv[0]));
    for (int i = 0; default_argv[i]; i++)
        krun_nitro_config_args(&nc, KRUN_STR(default_argv[i]));
    for (int i = 0; default_envp[i]; i++)
        krun_nitro_config_env(&nc, KRUN_STR(default_envp[i]));
    krun_nitro_config_debug(&nc, cmdline.debug);

    if (cmdline.net) {
        passt_fd = start_passt();
        if (passt_fd < 0) {
            printf("unable to start passt socket pair\n");
            return -1;
        }
        krun_nitro_config_net_fd(&nc, passt_fd);
    }

    // Wrap the NitroConfig in a Payload.
    CHECK(KrunPayload payload = krun_payload_nitro_enclave(nc, &krun_err));

    // Build the enclave.
    KrunVmmBuilder builder = krun_vmm_builder_new();
    CHECK(krun_vmm_builder_vcpus(&builder, cmdline.nvcpus, &krun_err));
    CHECK(krun_vmm_builder_ram_mib(&builder, cmdline.ram_mib, &krun_err));
    krun_vmm_builder_payload(&builder, payload);

    CHECK(KrunVmm vmm = krun_vmm_builder_build(&builder, &krun_err));
    krun_vmm_run(vmm);

    // Not reached.
    return 0;
}
