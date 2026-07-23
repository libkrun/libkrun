/*
 * This is an example loading an external (user-provided) kernel with libkrun.
 *
 * It boots the given kernel image with optional block disks, console, and
 * network connectivity.
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

#define MAX_ARGS_LEN 4096
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

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

static KrunVtableHandle stderr_writer = KRUN_VTABLE_HANDLE(
    KRUN_PUSH_STR_TYPE_TAG,
    ((KrunPushStrVtable){ .drop = NULL, .push = push_to_stderr }),
    NULL);

static void print_help(char *const name)
{
    fprintf(stderr,
            "Usage: %s [OPTIONS] KERNEL\n"
            "OPTIONS: \n"
            "        -b    --boot-disk           Path to a boot disk in raw format\n"
            "        -c    --kernel-cmdline      Kernel command line\n"
            "        -d    --data-disk           Path to a data disk in raw format\n"
            "        -h    --help                Show help\n"
            "              --passt-socket=PATH   Connect to passt socket at PATH"
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
};

bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    assert(cmdline != NULL);

    *cmdline = (struct cmdline){
        .show_help = false,
        .net_mode = NET_MODE_TSI,
        .passt_socket_path = "/tmp/network.sock",
        .boot_disk = NULL,
        .data_disk = NULL,
        .kernel_path = NULL,
        .kernel_cmdline = NULL,
    };

    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argv, "+hb:c:d:", long_options, &option_index)) != -1)
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
        case 'P':
            cmdline->passt_socket_path = optarg;
            cmdline->net_mode = NET_MODE_PASST;
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
    {
        if (close(socket_fds[PARENT]) < 0)
            perror("close PARENT");

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
    {
        if (close(socket_fds[CHILD]) < 0)
            perror("close CHILD");
        return socket_fds[PARENT];
    }
    return -1;
}

int main(int argc, char *const argv[])
{
    int ret = -1;
    struct cmdline cmdline;
    KrunError err = NULL;

    KrunMmioDeviceManager devices = NULL;
    KrunConsoleBuilder console_builder = NULL;
    KrunConsoleDevice console = NULL;
    KrunBlockDevice boot_disk = NULL;
    KrunBlockDevice data_disk = NULL;
    KrunNetDevice net = NULL;
    KrunPayload payload = NULL;
    KrunVmmBuilder vmm_builder = NULL;
    KrunVmm vmm = NULL;

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
    krun_init_log(KRUN_LOG_TARGET_DEFAULT, KRUN_LOG_LEVEL_OFF, KRUN_LOG_STYLE_AUTO, NULL);

    fprintf(stderr, "kernel_path: %s\n", cmdline.kernel_path);
    fprintf(stderr, "kernel_cmdline: %s\n", cmdline.kernel_cmdline ? cmdline.kernel_cmdline : "(none)");
    fflush(stderr);

    // Load external kernel
    payload = krun_payload_load_external(
        KRUN_STR(cmdline.kernel_path),
        KERNEL_FORMAT,
        KRUN_STR(cmdline.kernel_cmdline),
        &err);
    if (!payload) {
        fprintf(stderr, "krun_payload_load_external failed\n");
        goto cleanup;
    }

    // Console
    console_builder = krun_console_device_builder();
    if (krun_console_builder_add_default_console(console_builder, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, &err) != KRUN_RESULT_SUCCESS) {
        fprintf(stderr, "krun_console_builder_add_default_console failed\n");
        goto cleanup;
    }
    console = krun_console_builder_build(console_builder, &err);
    if (!console) {
        fprintf(stderr, "krun_console_builder_build failed\n");
        goto cleanup;
    }
    krun_console_builder_destroy(console_builder);
    console_builder = NULL;

    // Disk devices
    if (cmdline.boot_disk) {
        boot_disk = krun_block_device_new(KRUN_STR("boot"), KRUN_STR(cmdline.boot_disk), false, &err);
        if (!boot_disk) {
            fprintf(stderr, "krun_block_device_new (boot) failed\n");
            goto cleanup;
        }
    }
    if (cmdline.data_disk) {
        data_disk = krun_block_device_new(KRUN_STR("data"), KRUN_STR(cmdline.data_disk), false, &err);
        if (!data_disk) {
            fprintf(stderr, "krun_block_device_new (data) failed\n");
            goto cleanup;
        }
    }

    // Net device (PASST mode)
    if (cmdline.net_mode == NET_MODE_PASST) {
        uint8_t mac[] = {0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee};
        KrunBytes mac_bytes = KRUN_BYTES(mac);
        if (cmdline.passt_socket_path != NULL) {
            net = krun_net_device_new_unixstream_path(KRUN_STR("net0"), KRUN_STR(cmdline.passt_socket_path), mac_bytes, 0, &err);
        } else {
            int passt_fd = start_passt();
            if (passt_fd < 0) goto cleanup;
            net = krun_net_device_new_unixstream_fd(KRUN_STR("net0"), passt_fd, mac_bytes, 0, &err);
        }
        if (!net) {
            fprintf(stderr, "net device creation failed\n");
            goto cleanup;
        }
    }

    // Device manager
    devices = krun_mmio_device_manager_new();
    krun_mmio_device_manager_add(devices, (KrunAttachDevice)console);
    console = NULL;
    if (boot_disk) {
        krun_mmio_device_manager_add(devices, (KrunAttachDevice)boot_disk);
        boot_disk = NULL;
    }
    if (data_disk) {
        krun_mmio_device_manager_add(devices, (KrunAttachDevice)data_disk);
        data_disk = NULL;
    }
    if (net) {
        krun_mmio_device_manager_add(devices, (KrunAttachDevice)net);
        net = NULL;
    }

    // Build and run VM (2 vCPUs, 2 GiB)
    vmm_builder = krun_vmm_builder_new();
    if (krun_vmm_builder_vcpus(&vmm_builder, 2, &err) != KRUN_RESULT_SUCCESS) goto cleanup;
    if (krun_vmm_builder_ram_mib(&vmm_builder, 2048, &err) != KRUN_RESULT_SUCCESS) goto cleanup;
    krun_vmm_builder_payload(&vmm_builder, payload);
    payload = NULL;
    krun_vmm_builder_devices(&vmm_builder, devices);
    devices = NULL;

    vmm = krun_vmm_builder_build(&vmm_builder, &err);
    if (!vmm) {
        fprintf(stderr, "krun_vmm_builder_build failed\n");
        goto cleanup;
    }

    // This never returns.
    krun_vmm_run(vmm);
    ret = 0;

cleanup:
    if (err) {
        flockfile(stderr);
        fprintf(stderr, "Error: ");
        krun_error_message(err, (KrunPushStr)&stderr_writer);
        fputc('\n', stderr);
        funlockfile(stderr);
        krun_error_destroy(err);
    }
    if (vmm) krun_vmm_destroy(vmm);
    if (vmm_builder) krun_vmm_builder_destroy(vmm_builder);
    if (devices) krun_mmio_device_manager_destroy(devices);
    if (console_builder) krun_console_builder_destroy(console_builder);
    if (console) krun_console_device_destroy(console);
    if (boot_disk) krun_block_device_destroy(boot_disk);
    if (data_disk) krun_block_device_destroy(data_disk);
    if (net) krun_net_device_destroy(net);
    if (payload) krun_payload_destroy(payload);
    return ret;
}
