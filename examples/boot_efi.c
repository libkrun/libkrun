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
        "Usage: %s [OPTIONS] EFI_FW DISK\n"
        "OPTIONS: \n"
        "        -h    --help                Show help\n"
        "              --passt-socket=PATH   Connect to passt socket at PATH"
        "\n"
        "EFI_FW: path to the EFI firmware to be loaded\n"
        "DISK:   path to the vm's disk image in raw format\n",
        name
    );
}

static const struct option long_options[] = {
    { "help", no_argument, NULL, 'h' },
    { "passt-socket", required_argument, NULL, 'P' },
    { NULL, 0, NULL, 0 }
};

struct cmdline {
    bool show_help;
    char const *passt_socket_path;
    char const *efi_fw;
    char const *disk_image;
};

bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    assert(cmdline != NULL);

    // set the defaults
    *cmdline = (struct cmdline){
        .show_help = false,
        .passt_socket_path = "/tmp/network.sock",
        .efi_fw = NULL,
        .disk_image = NULL,
    };

    int option_index = 0;
    int c;
    // the '+' in optstring is a GNU extension that disables permutating argv
    while ((c = getopt_long(argc, argv, "+h", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmdline->show_help = true;
            return true;
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

    if (optind <= argc - 2) {
        cmdline->efi_fw = argv[optind];
        cmdline->disk_image = argv[optind + 1];
        return true;
    }

    if (optind == argc) {
        fprintf(stderr, "Missing DISK argument\n");
    }

    return false;
}

#define SHUTDOWN_SOCK_PATH  "/tmp/krun_shutdown.sock"

void *listen_shutdown_request(void *opaque)
{
    int server_sock, client_sock, len, ret;
    KrunVmmHandle handle = (KrunVmmHandle) opaque;
    struct sockaddr_un server_sockaddr;
    struct sockaddr_un client_sockaddr;
    memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(&client_sockaddr, 0, sizeof(struct sockaddr_un));

    server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_sock == -1){
        perror("Error creating socket");
        exit(1);
    }

    server_sockaddr.sun_family = AF_UNIX;
    strcpy(server_sockaddr.sun_path, SHUTDOWN_SOCK_PATH);
    len = sizeof(server_sockaddr);

    unlink(SHUTDOWN_SOCK_PATH);
    ret = bind(server_sock, (struct sockaddr *) &server_sockaddr, len);
    if (ret == -1){
        perror("Error binding socket");
        close(server_sock);
        exit(1);
    }

    ret = listen(server_sock, 1);
    if (ret == -1){
        perror("Error listening on socket");
        close(server_sock);
        exit(1);
    }

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr *) &client_sockaddr, &len);
        if (client_sock == -1){
            perror("Error accepting connection");
            close(server_sock);
            close(client_sock);
            exit(1);
        }

        // Signal the guest to shut down via the VMM handle.
        KrunError krun_err = NULL;
        krun_vmm_handle_shutdown(handle, &krun_err);
        if (krun_err) {
            fprintf(stderr, "Error sending shutdown signal\n");
            krun_error_destroy(krun_err);
        }

        close(client_sock);
    }
}

int main(int argc, char *const argv[])
{
    KrunError krun_err;
    pthread_t thread;
    struct cmdline cmdline;

    if (!parse_cmdline(argc, argv, &cmdline)) {
        putchar('\n');
        print_help(argv[0]);
        return -1;
    }

    if (cmdline.show_help){
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

    // Load the EFI firmware as the payload.
    CHECK(KrunPayload payload = krun_payload_load_firmware(KRUN_STR(cmdline.efi_fw), KRUN_STR(""), &krun_err));

    {
        CHECK(KrunBlockDevice blk = krun_block_device_new(KRUN_STR("root"),
            KRUN_STR(cmdline.disk_image), KRUN_DISK_FORMAT_RAW, false, &krun_err));
        krun_mmio_device_manager_add(devices, blk);
    }

    {
        uint8_t mac[] = {0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee};
        CHECK(KrunNetDevice net = krun_net_device_new_unixgram_path(KRUN_STR("net0"),
            KRUN_STR(cmdline.passt_socket_path), KRUN_BYTES(mac), COMPAT_NET_FEATURES,
            KRUN_NET_FLAGS_VFKIT, &krun_err));
        krun_mmio_device_manager_add(devices, net);
    }

    {
        CHECK(KrunRngDevice rng = krun_rng_device_new(&krun_err));
        krun_mmio_device_manager_add(devices, rng);

        CHECK(KrunBalloonDevice balloon = krun_balloon_device_new(&krun_err));
        krun_mmio_device_manager_add(devices, balloon);
    }

    // Build the VM.
    KrunVmmBuilder builder = krun_vmm_builder_new();
    CHECK(krun_vmm_builder_vcpus(&builder, 2, &krun_err));
    CHECK(krun_vmm_builder_ram_mib(&builder, 1024, &krun_err));
    krun_vmm_builder_payload(&builder, payload);
    krun_vmm_builder_devices(&builder, devices);

    CHECK(KrunVmm vmm = krun_vmm_builder_build(&builder, &krun_err));

    // Get the VMM handle for shutdown signalling, then spawn the listener thread.
    CHECK(KrunVmmHandle handle = krun_vmm_handle(vmm, &krun_err));

    // Spawn a thread to listen on "/tmp/krun_shutdown.sock" for a request to send
    // a shutdown signal to the guest.
    pthread_create(&thread, NULL, listen_shutdown_request, (void*) handle);

    krun_vmm_run(vmm); // never returns

    // Not reached.
    return 0;
}
