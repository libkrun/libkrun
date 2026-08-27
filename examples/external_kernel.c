/*
 * This is an example implementing chroot-like functionality with libkrun.
 *
 * It executes the requested command (relative to NEWROOT) inside a fresh
 * Virtual Machine created and managed by libkrun.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <libkrun.h>
#include <getopt.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>

#define MAX_ARGS_LEN 4096
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

// Net feature flags
#define COMPAT_NET_FEATURES ((1 << 0) | (1 << 1) | (1 << 7) | (1 << 10) | (1 << 11) | (1 << 14))

enum net_mode
{
    NET_MODE_PASST = 0,
    NET_MODE_TSI,
};

#if defined(__x86_64__)
#define KERNEL_FORMAT KRUN_KERNEL_FORMAT_ELF
#else
#define KERNEL_FORMAT KRUN_KERNEL_FORMAT_RAW
#endif

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

static void print_help(char *const name)
{
    fprintf(stderr,
            "Usage: %s [OPTIONS] KERNEL\n"
            "OPTIONS: \n"
            "        -b    --boot-disk           Path to a boot disk in raw format\n"
            "        -c    --kernel-cmdline      Kernel command line\n"
            "        -d    --data-disk           Path to a data disk in raw format\n"
            "        -h    --help                Show help\n"
            "        -i    --initrd              Path to initramfs\n"
            "        -n    --nested              Enabled nested virtualization\n"
            "              --net=NET_MODE        Set network mode\n"
            "              --passt-socket=PATH   Connect to passt socket at PATH"
            "\n"
            "NET_MODE can be either TSI (default) or PASST\n"
            "\n"
#if defined(__x86_64__)
            "KERNEL:   path to the kernel image in ELF format\n",
#else
            "KERNEL:   path to the kernel image in RAW format\n",
#endif
            name);
}

static const struct option long_options[] = {
    {"boot-disk", required_argument, NULL, 'b'},
    {"kernel-cmdline", required_argument, NULL, 'c'},
    {"data-disk", required_argument, NULL, 'd'},
    {"initrd-path", required_argument, NULL, 'i'},
    {"nested", no_argument, NULL, 'n'},
    {"help", no_argument, NULL, 'h'},
    {"passt-socket", required_argument, NULL, 'P'},
    {NULL, 0, NULL, 0}};

struct cmdline
{
    bool show_help;
    enum net_mode net_mode;
    char const *boot_disk;
    char const *data_disk;
    char const *passt_socket_path;
    char const *kernel_path;
    char const *kernel_cmdline;
    char const *initrd_path;
    bool nested;
};

bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    assert(cmdline != NULL);

    // set the defaults
    *cmdline = (struct cmdline){
        .show_help = false,
        .net_mode = NET_MODE_TSI,
        .passt_socket_path = "/tmp/network.sock",
        .boot_disk = NULL,
        .data_disk = NULL,
        .kernel_path = NULL,
        .kernel_cmdline = NULL,
        .initrd_path = NULL,
        .nested = false,
    };

    int option_index = 0;
    int c;
    // the '+' in optstring is a GNU extension that disables permutating argv
    while ((c = getopt_long(argc, argv, "+hb:c:d:i:n", long_options, &option_index)) != -1)
    {
        switch (c)
        {
        case 'b':
            cmdline->boot_disk = optarg;
            break;
        case 'c':
            cmdline->kernel_cmdline = optarg;
            break;
        case 'd':
            cmdline->data_disk = optarg;
            break;
        case 'h':
            cmdline->show_help = true;
            return true;
        case 'i':
            cmdline->initrd_path = optarg;
            break;
        case 'n':
            cmdline->nested = true;
            break;
        case 'P':
            cmdline->passt_socket_path = optarg;
            break;
        case '?':
            return false;
        default:
            fprintf(stderr, "internal argument parsing error (returned character code 0x%x)\n", c);
            return false;
        }
    }

    if (optind <= argc - 1)
    {
        cmdline->kernel_path = argv[optind];
        return true;
    }

    if (optind == argc)
    {
        fprintf(stderr, "Missing KERNEL argument\n");
    }

    return false;
}

int start_passt()
{
    int socket_fds[2];
    const int PARENT = 0;
    const int CHILD = 1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds) < 0)
    {
        perror("Failed to create passt socket fd");
        return -1;
    }

    int pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return -1;
    }

    if (pid == 0)
    { // child
        if (close(socket_fds[PARENT]) < 0)
        {
            perror("close PARENT");
        }

        char fd_as_str[16];
        snprintf(fd_as_str, sizeof(fd_as_str), "%d", socket_fds[CHILD]);

        printf("passing fd %s to passt", fd_as_str);

        if (execlp("passt", "passt", "-f", "--fd", fd_as_str, NULL) < 0)
        {
            perror("execlp");
            return -1;
        }
    }
    else
    { // parent
        if (close(socket_fds[CHILD]) < 0)
        {
            perror("close CHILD");
        }

        return socket_fds[PARENT];
    }
}

int main(int argc, char *const argv[])
{
    KrunError krun_err;
    pthread_t thread;
    struct cmdline cmdline;

    if (!parse_cmdline(argc, argv, &cmdline))
    {
        putchar('\n');
        print_help(argv[0]);
        return -1;
    }

    if (cmdline.show_help)
    {
        print_help(argv[0]);
        return 0;
    }

    // Set the log level to "off".
    CHECK(krun_init_log(-1, KRUN_LOG_LEVEL_OFF, KRUN_LOG_STYLE_AUTO, 0, &krun_err));

    // Create the device manager.
    KrunMmioDeviceManager devices = krun_mmio_device_manager_new();

    // Configure the console.
    {
        KrunConsoleBuilder cb = krun_console_device_builder();
        CHECK(krun_console_builder_add_default_console(cb, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, &krun_err));
        KrunConsoleDevice console = krun_console_builder_build(cb, &krun_err);
        krun_mmio_device_manager_add(devices, console);
    }

    if (cmdline.boot_disk)
    {
        CHECK(KrunBlockDevice blk = krun_block_device_new(KRUN_STR("boot"),
            KRUN_STR(cmdline.boot_disk), KRUN_DISK_FORMAT_RAW, false, &krun_err));
        krun_mmio_device_manager_add(devices, blk);
    }
    if (cmdline.data_disk)
    {
        CHECK(KrunBlockDevice blk = krun_block_device_new(KRUN_STR("data"),
            KRUN_STR(cmdline.data_disk), KRUN_DISK_FORMAT_RAW, false, &krun_err));
        krun_mmio_device_manager_add(devices, blk);
    }

    if (cmdline.net_mode == NET_MODE_PASST)
    {
        uint8_t mac[] = {0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee};
        KrunNetDevice net;
        if (cmdline.passt_socket_path != NULL) {
            net = krun_net_device_new_unixstream_path(KRUN_STR("net0"),
                KRUN_STR(cmdline.passt_socket_path), KRUN_BYTES(mac), COMPAT_NET_FEATURES, 0, &krun_err);
        } else {
            int passt_fd = start_passt();
            if (passt_fd < 0) {
                return -1;
            }
            net = krun_net_device_new_unixstream_fd(KRUN_STR("net0"),
                passt_fd, KRUN_BYTES(mac), COMPAT_NET_FEATURES, 0, &krun_err);
        }
        if (krun_err) {
            fprintf(stderr, "Error configuring net mode\n");
            krun_error_destroy(krun_err);
            return -1;
        }
        krun_mmio_device_manager_add(devices, net);
    }

    fprintf(stderr, "kernel_path: %s\n", cmdline.kernel_path);
    fprintf(stderr, "kernel_cmdline: %s\n", cmdline.kernel_cmdline);
    fflush(stderr);

    // Load the external kernel as the payload.
    CHECK(KrunPayload payload = krun_payload_load_external(KRUN_STR(cmdline.kernel_path),
        KERNEL_FORMAT, KRUN_STR(cmdline.initrd_path), KRUN_STR(cmdline.kernel_cmdline), &krun_err));

    {
        CHECK(KrunRngDevice rng = krun_rng_device_new(&krun_err));
        krun_mmio_device_manager_add(devices, rng);

        CHECK(KrunBalloonDevice balloon = krun_balloon_device_new(&krun_err));
        krun_mmio_device_manager_add(devices, balloon);
    }

    // Build the VM.
    KrunVmmBuilder builder = krun_vmm_builder_new();
    CHECK(krun_vmm_builder_vcpus(&builder, 2, &krun_err));
    CHECK(krun_vmm_builder_ram_mib(&builder, 2048, &krun_err));
    krun_vmm_builder_payload(&builder, payload);
    krun_vmm_builder_devices(&builder, devices);

    fprintf(stderr, "nested=%d\n", cmdline.nested);
    krun_vmm_builder_nested_virt(&builder, cmdline.nested);

    CHECK(KrunVmm vmm = krun_vmm_builder_build(&builder, &krun_err));
    krun_vmm_run(vmm); // never returns

    // Not reached.
    return 0;
}
