/*
 * This is an example implementing chroot-like functionality with libkrun.
 *
 * It executes the requested command (relative to NEWROOT) inside a fresh
 * Virtual Machine created and managed by libkrun.
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libkrun.h>

#define MAX_ARGS_LEN 4096
#ifndef MAX_PATH
#define MAX_PATH 4096
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

int main(int argc, char *const argv[])
{
    static const struct option long_opts[] = {
        { "td-shim", required_argument, 0, 's' },
        { 0, 0, 0, 0 }
    };
    const char *td_shim_path = NULL;
    int opt;
    KrunError krun_err;

    while ((opt = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (opt) {
        case 's':
            td_shim_path = optarg;
            break;
        default:
            printf("Usage: %s [--td-shim PATH] ROOT_DISK_IMAGE TEE_CONFIG_FILE DATA_DISK_IMAGE\n", argv[0]);
            return -1;
        }
    }

    if (argc - optind != 3) {
        printf("Invalid arguments\n");
        printf("Usage: %s [--td-shim PATH] ROOT_DISK_IMAGE TEE_CONFIG_FILE DATA_DISK_IMAGE\n", argv[0]);
        return -1;
    }

    // Set the log level to "error".
    CHECK(krun_init_log(-1, KRUN_LOG_LEVEL_ERROR, KRUN_LOG_STYLE_AUTO, 0, &krun_err));

    // Create the device manager.
    KrunMmioDeviceManager devices = krun_mmio_device_manager_new();

    // Configure the console.
    {
        KrunConsoleBuilder cb = krun_console_device_builder();
        CHECK(krun_console_builder_add_default_console(cb, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, &krun_err));
        KrunConsoleDevice console = krun_console_builder_build(cb, &krun_err);
        krun_mmio_device_manager_add(devices, console);
    }

    // Use the first positional argument as the disk image containing the root fs.
    {
        CHECK(KrunBlockDevice blk = krun_block_device_new(KRUN_STR("root"),
            KRUN_STR(argv[optind]), KRUN_DISK_FORMAT_RAW, &krun_err));
        krun_mmio_device_manager_add(devices, blk);
    }

    {
        CHECK(KrunBlockDevice blk = krun_block_device_new(KRUN_STR("data"),
            KRUN_STR(argv[optind + 2]), KRUN_DISK_FORMAT_RAW, &krun_err));
        krun_mmio_device_manager_add(devices, blk);
    }

    // Map port 18000 in the host to 8000 in the guest via TSI.
    {
        CHECK(KrunVsockDevice vsock = krun_vsock_device_new(3, 0, &krun_err));
        CHECK(krun_vsock_device_add_port_forward(vsock, KRUN_STR("18000:8000"), &krun_err));
        krun_mmio_device_manager_add(devices, vsock);
    }

    // Load the TEE payload from the config file.
    CHECK(KrunPayload payload = krun_payload_load_krunfw_tee(KRUN_STR(argv[optind + 1]), &krun_err));
    krun_payload_append_cmdline(payload, KRUN_STR("init=/init.krun KRUN_RLIMITS=6=4096:8192 KRUN_WORKDIR=/"));

    // Build the VM.
    KrunVmmBuilder builder = krun_vmm_builder_new();
    CHECK(krun_vmm_builder_vcpus(&builder, 1, &krun_err));
    CHECK(krun_vmm_builder_ram_mib(&builder, 2048, &krun_err));
    krun_vmm_builder_payload(&builder, payload);
    krun_vmm_builder_devices(&builder, devices);
    krun_vmm_builder_add_serial_console(&builder, -1, STDOUT_FILENO);
    CHECK(krun_vmm_builder_split_irqchip(&builder, true, &krun_err));

    CHECK(KrunVmm vmm = krun_vmm_builder_build(&builder, &krun_err));
    krun_vmm_run(vmm); // never returns

    // Not reached.
    return 0;
}
